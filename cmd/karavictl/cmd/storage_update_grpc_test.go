// Copyright © 2022 Dell Inc., or its subsidiaries. All Rights Reserved.
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
	"errors"
	"io"
	"io/ioutil"
	mockStorage "karavi-authorization/internal/storage-service/mocks"
	"karavi-authorization/pb"
	"os"
	"testing"

	"google.golang.org/grpc"
)

func TestStorageUpdateGrpc(t *testing.T) {
	afterFn := func() {
		CreateStorageServiceClient = createStorageServiceClient
		JSONOutput = jsonOutput
		osExit = os.Exit
	}

	t.Run("it requests update of storage", func(t *testing.T) {
		defer afterFn()
		CreateStorageServiceClient = func(_ string, _ bool) (pb.StorageServiceClient, io.Closer, error) {
			return &mockStorage.FakeStorageServiceClient{}, ioutil.NopCloser(nil), nil
		}
		JSONOutput = func(w io.Writer, _ interface{}) error {
			return nil
		}
		osExit = func(code int) {
		}
		var gotOutput bytes.Buffer

		cmd := NewRootCmd()
		cmd.SetOutput(&gotOutput)
		cmd.SetArgs([]string{"storage", "update", "--addr", "https://storage-service.com", "--type=powerflex", "--insecure", "--endpoint=https://10.0.0.1", "--system-id=542a2d5f5122210f", "--user=admin", "--password=test", "--array-insecure"})
		cmd.Execute()

		if len(gotOutput.Bytes()) != 0 {
			t.Errorf("expected zero output but got %q", string(gotOutput.Bytes()))
		}
	})
	t.Run("it requires a valid storage server connection", func(t *testing.T) {
		defer afterFn()
		CreateStorageServiceClient = func(_ string, _ bool) (pb.StorageServiceClient, io.Closer, error) {
			return nil, ioutil.NopCloser(nil), errors.New("test error")
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
		cmd.SetArgs([]string{"storage", "update", "--addr", "https://storage-service.com", "--type=powerflex", "--insecure", "--endpoint=https://10.0.0.1", "--system-id=542a2d5f5122210f", "--user=admin", "--password=test", "--array-insecure"})
		go cmd.Execute()
		<-done

		wantCode := 1
		if gotCode != wantCode {
			t.Errorf("got exit code %d, want %d", gotCode, wantCode)
		}

		want := "error: test error\n"
		got := gotOutput.String()
		if want != got {
			t.Errorf("want %s, got %s", want, got)
		}
	})
	t.Run("it handles server errors", func(t *testing.T) {
		defer afterFn()
		CreateStorageServiceClient = func(_ string, _ bool) (pb.StorageServiceClient, io.Closer, error) {
			return &mockStorage.FakeStorageServiceClient{
				UpdateStorageFn: func(_ context.Context, _ *pb.StorageUpdateRequest, _ ...grpc.CallOption) (*pb.StorageUpdateResponse, error) {
					return nil, errors.New("test error")
				},
			}, ioutil.NopCloser(nil), nil
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
		rootCmd.SetArgs([]string{"storage", "update", "--addr", "https://storage-service.com", "--type=powerflex", "--insecure", "--endpoint=https://10.0.0.1", "--system-id=542a2d5f5122210f", "--user=admin", "--password=test", "--array-insecure"})

		go rootCmd.Execute()
		<-done

		wantCode := 1
		if gotCode != wantCode {
			t.Errorf("got exit code %d, want %d", gotCode, wantCode)
		}

		want := "error: test error\n"
		got := gotOutput.String()
		if want != got {
			t.Errorf("want %s, got %s", want, got)
		}
	})
}
