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

package main

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
)

func TestRun(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		dp := buildDeployProcess(nil, nil)
		dp.Steps = append(dp.Steps, func() {})

		err := run(dp)

		if err != nil {
			t.Fatal(err)
		}
	})
	t.Run("returns any error", func(t *testing.T) {
		dp := buildDeployProcess(nil, nil)
		wantErr := errors.New("test error")
		dp.Err = wantErr

		gotErr := run(dp)

		if gotErr != wantErr {
			t.Errorf("got err = %v, want %v", gotErr, wantErr)
		}
	})
}

func TestNewDeployProcess(t *testing.T) {
	got := NewDeploymentProcess(nil, nil, nil)

	if got == nil {
		t.Error("expected non-nil return value")
	}
}

func TestDeployProcess_CheckRootPermissions(t *testing.T) {
	var testOut, testErr bytes.Buffer
	sut := buildDeployProcess(&testOut, &testErr)
	afterEach := func() {
		osGeteuid = os.Geteuid
		testOut.Reset()
		testErr.Reset()
	}
	t.Run("it returns an error if not effectively ran as root", func(t *testing.T) {
		defer afterEach()
		osGeteuid = func() int {
			return 1000 // non-root.
		}

		sut.CheckRootPermissions()

		want := ErrNeedRoot
		if got := sut.Err; got != want {
			t.Errorf("got err = %v, want %v", got, want)
		}
	})
	t.Run("it determines the uid/gid when ran with sudo", func(t *testing.T) {
		defer afterEach()
		osGeteuid = func() int {
			return 0 // pretend to be effectively root.
		}
		var tests = []struct {
			name         string
			givenSudoUID string
			givenSudoGID string
			expectUID    int
			expectGID    int
		}{
			{"only SUDO_UID set", "1000", "", 0, 0},
			{"only SUDO_GID set", "", "1000", 0, 0},
			{"neither set", "", "", 0, 0},
			{"both set with valid values", "1000", "1000", 1000, 1000},
			{"SUDO_UID is NaN", "NaN", "1000", 0, 0},
			{"SUDO_GID is NaN", "1000", "NaN", 0, 0},
		}
		for _, tt := range tests {
			tt := tt
			t.Run(tt.name, func(t *testing.T) {
				defer func() {
					osLookupEnv = os.LookupEnv
					sut.processOwnerUID = 0
					sut.processOwnerGID = 0
				}()

				osLookupEnv = func(env string) (string, bool) {
					switch env {
					case EnvSudoUID:
						if tt.givenSudoUID == "" {
							return "", false
						}
						return tt.givenSudoUID, true
					case EnvSudoGID:
						if tt.givenSudoGID == "" {
							return "", false
						}
						return tt.givenSudoGID, true
					default:
						return "", false
					}
				}

				sut.CheckRootPermissions()

				gotUID, gotGID := sut.processOwnerUID, sut.processOwnerGID
				wantUID, wantGID := tt.expectUID, tt.expectGID
				if gotUID != wantUID && gotGID != wantGID {
					t.Errorf("%s: got [%v,%v], want [%v,%v]", tt.name, gotUID, gotGID, wantUID, wantGID)
				}
			})
		}
	})
}

func TestDeployProcess_CreateTempWorkspace(t *testing.T) {
	afterEach := func() {
		ioutilTempDir = ioutil.TempDir
	}
	t.Run("it is a noop on sticky error", func(t *testing.T) {
		defer afterEach()
		var callCount int
		ioutilTempDir = func(_, _ string) (string, error) {
			callCount++
			return "", nil
		}
		sut := buildDeployProcess(nil, nil)
		sut.Err = errors.New("test error")

		sut.CreateTempWorkspace()

		want := 0
		if got := callCount; got != want {
			t.Errorf("got callCount %d, want %v", got, want)
		}
	})
	t.Run("it stores the created tmp dir", func(t *testing.T) {
		defer afterEach()
		want := "/tmp/testing"
		ioutilTempDir = func(_, _ string) (string, error) {
			return want, nil
		}
		sut := buildDeployProcess(nil, nil)

		sut.CreateTempWorkspace()

		if got := sut.tmpDir; got != want {
			t.Errorf("got tmpDir = %s, want %s", got, want)
		}
	})
	t.Run("it stores the created tmp dir", func(t *testing.T) {
		want := errors.New("test error")
		ioutilTempDir = func(_, _ string) (string, error) {
			return "", want
		}
		defer func() {
			ioutilTempDir = ioutil.TempDir
		}()
		sut := buildDeployProcess(nil, nil)

		sut.CreateTempWorkspace()

		gotErr := errors.Unwrap(sut.Err)
		if gotErr != want {
			t.Errorf("got err = %s, want %s", gotErr, want)
		}
	})
}

func TestDeployProcess_UntarFiles(t *testing.T) {
	var testOut, testErr bytes.Buffer
	sut := buildDeployProcess(&testOut, &testErr)
	before := func() {
		testOut.Reset()
		testErr.Reset()
		sut.Err = nil
		sut.bundleTar = &FakeFS{}

		tmpDir, err := ioutil.TempDir("", "deployProcess_UntarFilesTest")
		if err != nil {
			t.Fatal(err)
		}
		sut.tmpDir = tmpDir
	}
	after := func(sut *DeployProcess) {
		if err := os.RemoveAll(sut.tmpDir); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("it handles failure to open the bundle file", func(t *testing.T) {
		before()
		defer after(sut)
		sut.bundleTar = &FakeFS{ReturnErr: errors.New("test error")}

		sut.UntarFiles()

		want := "opening gzip file: test error"
		if got := sut.Err.Error(); got != want {
			t.Errorf("got err = %+v, want %+v", got, want)
		}
	})
	t.Run("it handles failure reading the gzip file", func(t *testing.T) {
		before()
		defer after(sut)
		gzipNewReader = func(_ io.Reader) (*gzip.Reader, error) {
			return nil, errors.New("test error")
		}
		defer func() {
			gzipNewReader = gzip.NewReader
		}()

		sut.UntarFiles()

		want := "creating gzip reader: test error"
		if got := sut.Err.Error(); got != want {
			t.Errorf("got err = %+v, want %+v", got, want)
		}
	})
	t.Run("it is a noop when there is an error", func(t *testing.T) {
		before()
		defer after(sut)
		sut.Err = errors.New("test error")

		sut.UntarFiles()

		{
			want := 0
			if got := len(testOut.Bytes()); got != want {
				t.Errorf("len(stdout): got = %d, want %d", got, want)
			}
		}
		{
			want := 0
			if got := len(testErr.Bytes()); got != want {
				t.Errorf("len(stderr): got = %d, want %d", got, want)
			}
		}
	})
	t.Run("happy path", func(t *testing.T) {
		before()
		defer after(sut)

		sut.UntarFiles()

		want := "Extracting files...Done!\n"
		if got := string(testOut.Bytes()); got != want {
			t.Errorf("got %q, want %q", got, want)
		}
		_, err := os.Stat(filepath.Join(sut.tmpDir, "dummy"))
		if err != nil {
			t.Fatal(err)
		}
	})
}

func TestDeployProcess_InstallKaravictl(t *testing.T) {
	sut := buildDeployProcess(nil, nil)

	t.Run("it is a noop on sticky error", func(t *testing.T) {
		t.Cleanup(func() {
			sut.Err = nil
			osRename = os.Rename
		})
		sut.Err = errors.New("test error")
		var callCount int
		osRename = func(_ string, _ string) error {
			callCount++
			return nil
		}

		sut.InstallKaravictl()

		want := 0
		if got := callCount; got != want {
			t.Errorf("got callCount %d, want %d", got, want)
		}
	})
	t.Run("it moves karavictl to /usr/local/bin", func(t *testing.T) {
		t.Cleanup(func() {
			sut.tmpDir = ""
			osRename = os.Rename
			osChmod = os.Chmod
		})
		sut.tmpDir = "/tmp/testing"
		var gotSrc, gotTgt string
		osRename = func(src string, tgt string) error {
			gotSrc, gotTgt = src, tgt
			return nil
		}
		osChmod = func(_ string, _ fs.FileMode) error {
			return nil
		}

		sut.InstallKaravictl()

		wantSrc := filepath.Join(sut.tmpDir, "karavictl")
		if gotSrc != wantSrc {
			t.Errorf("got srcfile %s, want %s", gotSrc, wantSrc)
		}
		wantTgt := "/usr/local/bin/karavictl"
		if gotTgt != wantTgt {
			t.Errorf("got tgtfile %s, want %s", gotTgt, wantTgt)
		}
	})
	t.Run("error in karavictl move", func(t *testing.T) {
		t.Cleanup(func() {
			sut.Err = nil
			osRename = os.Rename
		})

		sut.tmpDir = "/tmp/testing"
		var callCount int
		osRename = func(_ string, _ string) error {
			callCount++
			return errors.New("moving karavictl")
		}

		sut.InstallKaravictl()

		want := 1
		if got := callCount; got != want {
			t.Errorf("got callCount %d, want %d", got, want)
		}
	})
	t.Run("error in karavictl chmod", func(t *testing.T) {
		t.Cleanup(func() {
			sut.Err = nil
			osRename = os.Rename
			osChmod = os.Chmod
		})

		sut.tmpDir = "/tmp/testing"
		var callCount int
		osRename = func(_ string, _ string) error {
			return nil
		}

		osChmod = func(_ string, _ fs.FileMode) error {
			callCount++
			return errors.New("chmod karavictl")
		}

		sut.InstallKaravictl()

		want := 1
		if got := callCount; got != want {
			t.Errorf("got callCount %d, want %d", got, want)
		}
	})
}

func buildDeployProcess(stdout, stderr io.Writer) *DeployProcess {
	if stdout == nil {
		stdout = ioutil.Discard
	}
	if stderr == nil {
		stderr = ioutil.Discard
	}

	return &DeployProcess{
		stdout:    stdout,
		stderr:    stderr,
		bundleTar: &FakeFS{},
		cfg:       viper.New(),
		Steps:     []StepFunc{},
		manifests: []string{},
	}
}

type FakeFS struct {
	ReturnErr error
}

// Open opens the named file.
//
// When Open returns an error, it should be of type *PathError
// with the Op field set to "open", the Path field set to name,
// and the Err field describing the problem.
//
// Open should reject attempts to open names that do not satisfy
// ValidPath(name), returning a *PathError with Err set to
// ErrInvalid or ErrNotExist.
func (f *FakeFS) Open(_ string) (fs.File, error) {
	if f.ReturnErr != nil {
		return nil, f.ReturnErr
	}
	return os.Open("testdata/fake-bundle.tar.gz")
}

func TestDeployProcess_AddCertificate(t *testing.T) {
	var testOut bytes.Buffer
	sut := buildDeployProcess(&testOut, nil)
	certData := make(map[string]string)
	certData["foo"] = "bar"
	certData["foo2"] = "bar2"
	certData["foo3"] = "bar3"

	t.Run("it is a noop on sticky error", func(t *testing.T) {
		t.Cleanup(func() {
			sut.Err = nil
		})
		sut.Err = errors.New("test error")

		sut.AddCertificate()

		want := 0
		if got := len(testOut.Bytes()); got != want {
			t.Errorf("len(stdout): got = %d, want %d", got, want)
		}

	})
	t.Run("no certificate info in config file", func(t *testing.T) {
		t.Cleanup(func() {
			sut.Err = nil
			sut.manifests = []string{}
		})
		sut.manifests = nil

		sut.AddCertificate()

		if got := sut.manifests; got == nil {
			t.Errorf("manifests: got = %s, want not nil", got)
		}

	})
	t.Run("certificate files not listed", func(t *testing.T) {
		t.Cleanup(func() {
			sut.Err = nil
		})
		sut.cfg.Set("certificate", "foo")

		sut.AddCertificate()

		if got := sut.Err; got == nil {
			t.Errorf("Error: got = %s, want not nil", got)
		}

	})
	t.Run("certificate file type unknown", func(t *testing.T) {
		t.Cleanup(func() {
			sut.Err = nil
		})
		sut.cfg.Set("certificate", certData)

		sut.AddCertificate()

		if got := sut.Err; got == nil {
			t.Errorf("Error: got = %s, want not nil", got)
		}
	})
	t.Run("certificate file read error", func(t *testing.T) {
		t.Cleanup(func() {
			sut.Err = nil
		})
		sut.cfg.Set("certificate", certData)

		sut.AddCertificate()

		if got := sut.Err; got == nil {
			t.Errorf("Error: got = %s, want not nil", got)
		}
	})
	t.Run("certificate file write error", func(t *testing.T) {
		t.Cleanup(func() {
			sut.Err = nil
			sut.tmpDir = ""
			ioutilReadFile = ioutil.ReadFile
		})
		sut.cfg.Set("certificate", certData)
		sut.tmpDir = "testData"
		ioutilReadFile = func(_ string) ([]byte, error) {
			return []byte{}, nil
		}

		sut.AddCertificate()

		if got := sut.Err; got == nil {
			t.Errorf("Error: got = %s, want not nil", got)
		}
	})
	t.Run("adds certificate to manifests", func(t *testing.T) {
		t.Cleanup(func() {
			sut.Err = nil
			sut.manifests = []string{}
			ioutilReadFile = ioutil.ReadFile
			ioutilWriteFile = ioutil.WriteFile
		})
		sut.cfg.Set("certificate", certData)
		ioutilReadFile = func(_ string) ([]byte, error) {
			return []byte{}, nil
		}
		ioutilWriteFile = func(_ string, _ []byte, _ os.FileMode) error {
			return nil
		}

		sut.AddCertificate()

		if got := sut.manifests; got == nil {
			t.Errorf("manifests: got = %s, want not nil", got)
		}
	})
}

func TestDeployProcess_AddHostName(t *testing.T) {
	var testOut bytes.Buffer
	sut := buildDeployProcess(&testOut, nil)
	hostName := "foo.com"

	t.Run("it is a noop on sticky error", func(t *testing.T) {
		t.Cleanup(func() {
			sut.Err = nil
		})
		sut.Err = errors.New("test error")

		sut.AddHostName()

		want := 0
		if got := len(testOut.Bytes()); got != want {
			t.Errorf("len(stdout): got = %d, want %d", got, want)
		}

	})
	t.Run("missing hostName configuration", func(t *testing.T) {
		t.Cleanup(func() {
			sut.Err = nil
		})

		sut.AddHostName()

		if got := sut.Err; got == nil {
			t.Errorf("Error: got = %s, want not nil", got)
		}

	})
	t.Run("ingress file read error", func(t *testing.T) {
		t.Cleanup(func() {
			sut.Err = nil
		})
		sut.cfg.Set("hostName", hostName)
		sut.tmpDir = "testData"

		sut.AddHostName()

		if got := sut.Err; got == nil {
			t.Errorf("Error: got = %s, want not nil", got)
		}
	})
	t.Run("ingress file write error", func(t *testing.T) {
		t.Cleanup(func() {
			sut.Err = nil
			ioutilReadFile = ioutil.ReadFile
		})
		sut.cfg.Set("hostName", hostName)
		sut.tmpDir = "testData"
		ioutilReadFile = func(_ string) ([]byte, error) {
			return []byte{}, nil
		}

		sut.AddHostName()

		if got := sut.Err; got == nil {
			t.Errorf("Error: got = %s, want not nil", got)
		}
	})
}
