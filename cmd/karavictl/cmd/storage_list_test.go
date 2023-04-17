// Copyright © 2021-2023 Dell Inc., or its subsidiaries. All Rights Reserved.
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

package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"karavi-authorization/cmd/karavictl/cmd/api"
	"karavi-authorization/cmd/karavictl/cmd/api/mocks"
	"net/url"
	"os"
	"os/exec"
	"testing"
)

func TestStorageListCmd(t *testing.T) {
	execCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		cmd := exec.CommandContext(
			context.Background(),
			os.Args[0],
			append([]string{
				"-test.run=TestK3sSubprocessStorageList",
				"--",
				name}, args...)...)
		cmd.Env = append(os.Environ(), "WANT_GO_TEST_SUBPROCESS=1")

		return cmd
	}
	defer func() {
		execCommandContext = exec.CommandContext
	}()

	ReadAccessAdminToken = func(afile string) (string, string, error) {
		return "AUnumberTokenIsNotWorkingman", "AUnumberTokenIsNotWorkingman", nil
	}

	t.Run("list all storage", func(t *testing.T) {
		cmd := NewRootCmd()
		cmd.SetArgs([]string{"--admin-token", "admin.yaml", "storage", "list", "--type="})
		cmd.Run(cmd, nil)
	})

	t.Run("list powerflex storage", func(t *testing.T) {
		cmd := NewRootCmd()
		cmd.SetArgs([]string{"--admin-token", "admin.yaml", "storage", "list", "--type=powerflex"})
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.Run(cmd, nil)

		var sysType SystemType
		err := json.Unmarshal(out.Bytes(), &sysType)
		if err != nil {
			t.Fatal(err)
		}

		if len(sysType) != 1 {
			t.Errorf("expected one storage response, got %d", len(sysType))
		}

		if _, ok := sysType["542a2d5f5122210f"]; !ok {
			t.Errorf("expected powerflex id 542a2d5f5122210f, id does not exist")
		}
	})

	t.Run("list powermax storage", func(t *testing.T) {
		cmd := NewRootCmd()
		cmd.SetArgs([]string{"--admin-token", "admin.yaml", "storage", "list", "--type=powermax"})
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.Run(cmd, nil)

		var sysType SystemType
		err := json.Unmarshal(out.Bytes(), &sysType)
		if err != nil {
			t.Fatal(err)
		}

		if len(sysType) != 1 {
			t.Errorf("expected one storage response, got %d", len(sysType))
		}

		if _, ok := sysType["000197900714"]; !ok {
			t.Errorf("expected powermax id 000197900714, id does not exist")
		}
	})
}

func TestK3sSubprocessStorageList(t *testing.T) {
	if v := os.Getenv("WANT_GO_TEST_SUBPROCESS"); v != "1" {
		t.Skip("not being run as a subprocess")
	}

	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = os.Args[i+1:]
			break
		}
	}
	defer os.Exit(0)

	// k3s kubectl [get,create,apply]
	switch os.Args[2] {
	case "get":
		b, err := ioutil.ReadFile("testdata/kubectl_get_secret_storage_powerflex_powermax.json")
		if err != nil {
			t.Fatal(err)
		}
		if _, err = io.Copy(os.Stdout, bytes.NewReader(b)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestStorageListHandler(t *testing.T) {
	afterFn := func() {
		CreateHTTPClient = createHTTPClient
		JSONOutput = jsonOutput
		osExit = os.Exit
		ReadAccessAdminToken = readAccessAdminToken
	}

	t.Run("it requests list of storage", func(t *testing.T) {
		defer afterFn()
		var gotCalled bool
		CreateHTTPClient = func(addr string, insecure bool) (api.Client, error) {
			return &mocks.FakeClient{
				GetFn: func(ctx context.Context, path string, headers map[string]string, query url.Values, resp interface{}) error {
					gotCalled = true
					storage := `{"powerflex":{"11e4e7d35817bd0f":{"User":"admin","Password":"test","Endpoint":"https://10.0.0.1","Insecure":false}}
					,"powerflex":{"11e4e7d35817bd0f":{"User":"admin","Password":"test","Endpoint":"https://10.0.0.1","Insecure":false}}}`
					err := json.Unmarshal([]byte(storage), resp)
					if err != nil {
						t.Fatal(err)
					}
					return nil
				},
			}, nil
		}
		ReadAccessAdminToken = func(afile string) (string, string, error) {
			return "AUnumberTokenIsNotWorkingman", "AUnumberTokenIsNotWorkingman", nil
		}

		var gotOutput bytes.Buffer

		cmd := NewRootCmd()
		cmd.SetOutput(&gotOutput)
		cmd.SetArgs([]string{"--admin-token", "afile.yaml", "storage", "list", "--addr", "storage-service.com", "--insecure"})
		cmd.Execute()

		if !gotCalled {
			t.Error("expected List to be called, but it wasn't")
		}
	})
	t.Run("it requires a valid role server connection", func(t *testing.T) {
		defer afterFn()
		CreateHTTPClient = func(addr string, insecure bool) (api.Client, error) {
			return nil, errors.New("failed to list storage: test error")
		}
		ReadAccessAdminToken = func(afile string) (string, string, error) {
			return "AUnumberTokenIsNotWorkingman", "AUnumberTokenIsNotWorkingman", nil
		}

		var gotCode int
		done := make(chan struct{})
		osExit = func(code int) {
			gotCode = code
			done <- struct{}{}
			done <- struct{}{} // we can't let this function return
		}
		var gotOutput bytes.Buffer

		cmd := NewRootCmd()
		cmd.SetErr(&gotOutput)
		cmd.SetArgs([]string{"--admin-token", "afile.yaml", "storage", "list", "--addr", "storage-service.com", "--insecure"})
		go cmd.Execute()
		<-done

		wantCode := 1
		if gotCode != wantCode {
			t.Errorf("got exit code %d, want %d", gotCode, wantCode)
		}
		var gotErr CommandError
		if err := json.NewDecoder(&gotOutput).Decode(&gotErr); err != nil {
			t.Fatal(err)
		}
		wantErrMsg := "failed to list storage: test error"
		if gotErr.ErrorMsg != wantErrMsg {
			t.Errorf("got err %q, want %q", gotErr.ErrorMsg, wantErrMsg)
		}
	})
	t.Run("it handles server errors", func(t *testing.T) {
		defer afterFn()
		CreateHTTPClient = func(addr string, insecure bool) (api.Client, error) {
			return nil, errors.New("failed to list storage: test error")
		}
		ReadAccessAdminToken = func(afile string) (string, string, error) {
			return "AUnumberTokenIsNotWorkingman", "AUnumberTokenIsNotWorkingman", nil
		}
		var gotCode int
		done := make(chan struct{})
		osExit = func(code int) {
			gotCode = code
			done <- struct{}{}
			done <- struct{}{} // we can't let this function return
		}
		var gotOutput bytes.Buffer

		rootCmd := NewRootCmd()
		rootCmd.SetErr(&gotOutput)
		rootCmd.SetArgs([]string{"--admin-token", "afile.yaml", "storage", "list", "--addr", "storage-service.com", "--insecure"})

		go rootCmd.Execute()
		<-done

		wantCode := 1
		if gotCode != wantCode {
			t.Errorf("got exit code %d, want %d", gotCode, wantCode)
		}
		var gotErr CommandError
		if err := json.NewDecoder(&gotOutput).Decode(&gotErr); err != nil {
			t.Fatal(err)
		}
		wantErrMsg := "failed to list storage: test error"
		if gotErr.ErrorMsg != wantErrMsg {
			t.Errorf("got err %q, want %q", gotErr.ErrorMsg, wantErrMsg)
		}
	})
}
