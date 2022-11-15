// Copyright © 2021-2022 Dell Inc., or its subsidiaries. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Command deploy is used to install the application using embedded
// resources.
package main

import (
	"archive/tar"
	"compress/gzip"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/viper"
)

// Overrides for testing purposes.
var (
	gzipNewReader   = gzip.NewReader
	osRename        = os.Rename
	osChmod         = os.Chmod
	ioutilTempDir   = ioutil.TempDir
	ioutilReadFile  = ioutil.ReadFile
	ioutilWriteFile = ioutil.WriteFile
	osGeteuid       = os.Geteuid
	osLookupEnv     = os.LookupEnv
	configDir       = "$HOME/.karavi/"
)

const (
	// RootUID is the UID of the system root user.
	RootUID = 0
	// EnvSudoUID is the common envvar for the user invoking sudo.
	EnvSudoUID = "SUDO_UID"
	// EnvSudoGID is the common envvar for the group invoking sudo.
	EnvSudoGID = "SUDO_GID"
)

// Common errors.
var (
	ErrNeedRoot = errors.New("need to be run as root")
)

// Common Rancher constants, including the required dirs for installing
// k3s and preloading our application.
const (
	RancherImagesDir          = "/var/lib/rancher/k3s/agent/images"
	RancherManifestsDir       = "/var/lib/rancher/k3s/server/manifests"
	RancherK3sKubeConfigPath  = "/etc/rancher/k3s/k3s.yaml"
	EnvK3sInstallSkipDownload = "INSTALL_K3S_SKIP_DOWNLOAD=true"
	EnvK3sForceRestart        = "INSTALL_K3S_FORCE_RESTART=true"
	EnvK3sSkipSelinuxRpm      = "INSTALL_K3S_SKIP_SELINUX_RPM=true"
)

const (
	installedK3s           = "/usr/local/bin/k3s"
	arch                   = "amd64"
	k3SInstallScript       = "k3s-install.sh"
	k3sBinary              = "k3s"
	k3SImagesTar           = "k3s-airgap-images-" + arch + ".tar"
	k3SSELinuxRPM          = "-k3s-selinux.rpm"
	authImagesTar          = "credential-shield-images.tar"
	authDeploymentManifest = "deployment.yaml"
	authIngressManifest    = "ingress-traefik.yaml"
	certManagerManifest    = "cert-manager.yaml"
	certManagerImagesTar   = "cert-manager-images.tar"
	selfSignedCertManifest = "self-cert.yaml"
	certConfigManifest     = "signed-cert.yaml"
	bundleTarPath          = "dist/karavi-airgap-install.tar.gz"
	karavictl              = "karavictl"

	defaultProxyHostName = "temporary.Host.Name"
	defaultGrpcHostName  = "grpc.tenants.cluster"
	getVersion           = "DOCKER_TAG \\?= ([0-9]+(\\.[0-9]+)+)"
)

func main() {
	// see embed.go / embed_prod.go
	dp := NewDeploymentProcess(os.Stdout, os.Stderr, embedBundleTar)
	dp.cfg = config()

	if err := run(dp); err != nil {
		fmt.Fprintf(os.Stderr, "error: %+v\n", err)
		os.Exit(1)
	}
}

func config() *viper.Viper {
	cfgViper := viper.New()
	cfgViper.SetConfigName("config")
	cfgViper.SetConfigType("json")
	cfgViper.AddConfigPath(".")
	cfgViper.AddConfigPath(configDir)

	err := cfgViper.ReadInConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("Using config file:", cfgViper.ConfigFileUsed())

	return cfgViper
}

func run(dp *DeployProcess) error {
	err := dp.Execute()
	if err != nil {
		return err
	}
	return nil
}

// StepFunc represents a step in the deployment process.
type StepFunc func()

// DeployProcess acts as the process for deploying the application.
// On calling the Execute function, the configured slice of StepFuncs
// will be called in order.
// Following the sticky error pattern, each step should first check
// the Err field to determine if it should continue or return immediately.
type DeployProcess struct {
	Err             error // sticky error.
	cfg             *viper.Viper
	stdout          io.Writer
	stderr          io.Writer
	bundleTar       fs.FS
	tmpDir          string
	processOwnerUID int
	processOwnerGID int
	Steps           []StepFunc
	manifests       []string
}

// NewDeploymentProcess creates a new DeployProcess, pre-configured
// with an list of StepFuncs.
func NewDeploymentProcess(stdout, stderr io.Writer, bundle fs.FS) *DeployProcess {
	dp := &DeployProcess{
		bundleTar: bundle,
		stdout:    stdout,
		stderr:    stderr,
		manifests: []string{authDeploymentManifest, authIngressManifest, certManagerManifest},
	}
	dp.Steps = append(dp.Steps,
		dp.CheckRootPermissions,
		dp.CreateTempWorkspace,
		dp.UntarFiles,
		dp.AddCertificate,
		dp.AddHostName,
		dp.InstallKaravictl,
	)
	return dp
}

// Execute calls each step in order and returns any
// error encountered.
func (dp *DeployProcess) Execute() error {
	for _, step := range dp.Steps {
		step()
	}
	return dp.Err
}

// CheckRootPermissions checks that the effective user ID who is running the command
// is 0 (root). By default, the k3s KUBECONFIG file will have root permissions. If
// the user is running as sudo, attempt to determine the underlying user and use
// those permissions instead.
func (dp *DeployProcess) CheckRootPermissions() {
	if osGeteuid() != RootUID {
		dp.Err = ErrNeedRoot
		return
	}

	sudoUID, uidOK := osLookupEnv(EnvSudoUID)
	sudoGID, gidOK := osLookupEnv(EnvSudoGID)

	if !uidOK || !gidOK {
		return
	}
	// Both values exist at this point
	uid, err := strconv.Atoi(sudoUID)
	if err != nil {
		// ignore the error
		return
	}
	gid, err := strconv.Atoi(sudoGID)
	if err != nil {
		// ignore the error
		return
	}
	dp.processOwnerUID = uid
	dp.processOwnerGID = gid
}

// CreateTempWorkspace creates a temporary working directory
// to be used as part of deployment.
func (dp *DeployProcess) CreateTempWorkspace() {
	if dp.Err != nil {
		return
	}

	dir, err := ioutilTempDir("", "karavi-installer-*")
	if err != nil {
		dp.Err = fmt.Errorf("creating tmp directory: %w", err)
		return
	}
	dp.tmpDir = dir
}

// UntarFiles extracts the files from the embedded bundle tar file.
func (dp *DeployProcess) UntarFiles() {
	if dp.Err != nil {
		return
	}

	fmt.Fprintf(dp.stdout, "Extracting files...")
	defer fmt.Fprintln(dp.stdout, "Done!")

	gzipFile, err := dp.bundleTar.Open(bundleTarPath)
	if err != nil {
		dp.Err = fmt.Errorf("opening gzip file: %w", err)
		return
	}
	gzr, err := gzipNewReader(gzipFile)
	if err != nil {
		dp.Err = fmt.Errorf("creating gzip reader: %w", err)
		return
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	// Limit the tar reader to 1 GB incase of decompression bomb
	lr := io.LimitReader(tr, 1000000000)

loop:
	for {
		header, err := tr.Next()

		switch {
		// if no more files are found return
		case err == io.EOF:
			break loop
		// return any other error
		case err != nil:
			dp.Err = err
			return
		}

		switch header.Typeflag {
		case tar.TypeDir:
			// NOTE(ian): What if the tar file contains a directory.
		case tar.TypeReg:
			target, err := sanitizeExtractPath(header.Name, dp.tmpDir)
			if err != nil {
				dp.Err = fmt.Errorf("sanitizing extraction path %s, %w", target, err)
				return
			}

			f, err := os.OpenFile(filepath.Clean(target), os.O_CREATE|os.O_RDWR, os.FileMode(0755))
			if err != nil {
				dp.Err = fmt.Errorf("creating file %q: %w", target, err)
				return
			}

			if _, err := io.Copy(f, lr); err != nil {
				dp.Err = fmt.Errorf("copy contents of %q: %w", target, err)
				return
			}

			if err := f.Close(); err != nil {
				// ignore
			}
		}
	}
}

// InstallKaravictl moves the embedded/extracted karavictl binary
// to /usr/local/bin.
func (dp *DeployProcess) InstallKaravictl() {
	if dp.Err != nil {
		return
	}

	fmt.Fprintf(dp.stdout, "Installing karavictl into /usr/local/bin...")
	defer fmt.Fprintln(dp.stdout, "Done!")

	tmpPath := filepath.Join(dp.tmpDir, karavictl)
	tgtPath := filepath.Join("/usr/local/bin", karavictl)
	if err := osRename(tmpPath, tgtPath); err != nil {
		dp.Err = fmt.Errorf("installing karavictl: %w", err)
		return
	}
	if err := osChmod(tgtPath, 0755); err != nil {
		dp.Err = fmt.Errorf("chmod karavictl: %w", err)
		return
	}
}

// AddCertificate adds the certificate manifest
func (dp *DeployProcess) AddCertificate() {
	if dp.Err != nil {
		return
	}

	if !dp.cfg.IsSet("certificate") {
		//no certificate found, create self-signed certificate
		dp.manifests = append(dp.manifests, selfSignedCertManifest)
		return
	}
	certData := dp.cfg.GetStringMapString("certificate")
	var crtFile, keyFile string
	encodedCerts := make(map[string]string)
	if len(certData) < 3 {
		dp.Err = fmt.Errorf("missing certificate files")
		return
	}
	for k, v := range certData {
		switch {
		case k == "crtfile":
			crtFile = v
		case k == "keyfile":
			keyFile = v
		case k == "rootcertificate":
			continue
		default:
			dp.Err = fmt.Errorf("unknown certificate file format %s", k)
			return
		}
		content, err := ioutilReadFile(v)
		if err != nil {
			dp.Err = fmt.Errorf("failed to read file %s: %w", v, err)
			return
		}
		// Encode as base64.
		encodedCerts[k] = base64.StdEncoding.EncodeToString(content)
	}
	fmt.Fprintf(dp.stdout, "Provided Crtfile %s, KeyFile %s\n", crtFile, keyFile)

	//replace cert info in manifest file
	certFile := filepath.Join(dp.tmpDir, certConfigManifest)

	read, err := ioutilReadFile(certFile)
	if err != nil {
		dp.Err = fmt.Errorf("failed to read cert manifest file: %w", err)
		return
	}

	newContents := strings.Replace(string(read), "crtFile", encodedCerts["crtfile"], -1)
	newContents = strings.Replace(newContents, "keyFile", encodedCerts["keyfile"], -1)

	err = ioutilWriteFile(certFile, []byte(newContents), 0)
	if err != nil {
		dp.Err = fmt.Errorf("failed to write to cert manifest file: %w", err)
		return
	}
	dp.manifests = append(dp.manifests, certConfigManifest)

}

// AddHostName replaces the ingress hostname in the manifest
func (dp *DeployProcess) AddHostName() {
	if dp.Err != nil {
		return
	}

	if !dp.cfg.IsSet("hostname") {
		dp.Err = fmt.Errorf("missing hostname configuration")
		return
	}

	hostName := dp.cfg.GetString("hostname")

	//update hostnames in ingress manifest
	ingressFile := filepath.Join(dp.tmpDir, authIngressManifest)

	read, err := ioutilReadFile(ingressFile)
	if err != nil {
		dp.Err = fmt.Errorf("failed to read ingress manifest file: %w", err)
		return
	}

	newContents := strings.Replace(string(read), defaultProxyHostName, hostName, -1)
	newContents = strings.Replace(newContents, defaultGrpcHostName, "grpc."+hostName, -1)

	err = ioutilWriteFile(ingressFile, []byte(newContents), 0)
	if err != nil {
		dp.Err = fmt.Errorf("failed to write to ingress manifest file: %w", err)
		return
	}
}

func sanitizeExtractPath(filePath string, destination string) (string, error) {
	destpath := filepath.Join(destination, filePath)
	if !strings.HasPrefix(destpath, filepath.Clean(destination)+string(os.PathSeparator)) {
		return "", fmt.Errorf("illegal file path: %s", filePath)
	}
	return destpath, nil
}
