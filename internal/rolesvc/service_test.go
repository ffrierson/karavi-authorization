// Copyright © 2021 Dell Inc., or its subsidiaries. All Rights Reserved.
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

package rolesvc_test

import (
	"context"
	"fmt"
	"karavi-authorization/internal/rolesvc"
	"karavi-authorization/pb"
	"log"
	"os"
	"testing"

	"github.com/go-redis/redis"
	"github.com/orlangure/gnomock"
)


type AfterFunc func()

func TestRoleService(t *testing.T) {
	rdb := createRedisContainer(t)
	sur := rolesvc.NewRoleService(
		rolesvc.WithRedis(rdb),
		rolesvc.WithJWTSigningSecret("secret"))

	afterFn := func() {
		if _, err := rdb.FlushDB().Result(); err != nil {
			t.Fatalf("error flushing db: %+v", err)
		}
	}

	t.Run("CreateRole", testCreateRole(sur, afterFn))
	t.Run("GetRole", testGetRole(sur, afterFn))
	t.Run("DeleteRole", testDeleteRole(sur, afterFn))
	t.Run("ListRole", testListRole(sur, rdb, afterFn))
}

func testCreateRole(sur *rolesvc.RoleService, afterFn AfterFunc) func(*testing.T) {
	return func(t *testing.T) {
		t.Run("it creates a role entry", func(t *testing.T) {
			defer afterFn()

			wantName := "role"
			got, err := sur.CreateRole(context.Background(), &pb.CreateRoleRequest{
				Role: &pb.Role{
					Name:  wantName,
					SystemType: "PowerMax",
					SystemID: "123456789",
					Pool: "MyPool",
				},
			})
			checkError(t, err)

			if got.Name != wantName {
				t.Errorf("CreateRole: got name = %q, want %q", got.Name, wantName)
			}
		})
		t.Run("it errors on a duplicate role", func(t *testing.T) {
			first, err := sur.CreateRole(context.Background(), &pb.CreateRoleRequest{
				Role: &pb.Role{
					Name: "duplicateme",
					SystemType: "PowerMax",
					SystemID: "123456789",
					Pool: "MyPool",
				},
			})
			checkError(t, err)

			gotRole, gotErr := sur.CreateRole(context.Background(), &pb.CreateRoleRequest{
				Role: first,
			})

			wantErr := rolesvc.ErrRoleAlreadyExists
			if gotErr != rolesvc.ErrRoleAlreadyExists {
				t.Errorf("CreateRole: got err = %v, want %v", gotErr, wantErr)
			}
			if gotRole != nil {
				t.Error("CreateRole: expected returned tenant to be nil")
			}
		})
	}
}

func testGetRole(sur *rolesvc.RoleService, afterFn AfterFunc) func(*testing.T) {
	return func(t *testing.T) {
		t.Run("it gets a created role", func(t *testing.T) {
			defer afterFn()
			wantName := "role-1"
			_, err := sur.CreateRole(context.Background(), &pb.CreateRoleRequest{
				Role: &pb.Role{
					Name: wantName,
				},
			})
			if err != nil {
				t.Fatal(err)
			}

			got, err := sur.GetRole(context.Background(), &pb.GetRoleRequest{
				Name: wantName,
			})

			if got.Name != wantName {
				t.Errorf("GetRole: got name = %q, want %q", got.Name, wantName)
			}
		})
		t.Run("it returns redis errors", func(t *testing.T) {
			defer afterFn()
			_, err := sur.GetRole(context.Background(), &pb.GetRoleRequest{
				Name: "role",
			})

			if err == nil {
				t.Error("expected non-nil error")
			}
		})
	}
}

func testDeleteRole(sur *rolesvc.RoleService, afterFn AfterFunc) func(*testing.T) {
	return func(t *testing.T) {
		t.Run("it deletes an existing role", func(t *testing.T) {
			defer afterFn()
			name := "testname"
			createRole(t, sur, roleConfig{Name: name, SystemType: "PowerMax", SystemID: "123456789", Pool: "myPool",})

			_, err := sur.DeleteRole(context.Background(), &pb.DeleteRoleRequest{
				Name: name,
			})
			checkError(t, err)

			_, gotErr := sur.GetRole(context.Background(), &pb.GetRoleRequest{
				Name: name,
			})
			if gotErr == nil {
				t.Error("DeleteRole: expected non-nil error")
			}
		})
		t.Run("it errors on a non-existent role", func(t *testing.T) {
			defer afterFn()
			_, gotErr := sur.DeleteRole(context.Background(), &pb.DeleteRoleRequest{
				Name: "doesnotexist",
			})

			wantErr := rolesvc.ErrRoleNotFound
			if gotErr != wantErr {
				t.Errorf("DeleteRole: got err %v, want %v", gotErr, wantErr)
			}
		})
	}
}

func testListRole(sur *rolesvc.RoleService, rdb *redis.Client, afterFn AfterFunc) func(*testing.T) {
	return func(t *testing.T) {
		t.Run("it lists existing roles", func(t *testing.T) {
			defer afterFn()
			for i := 0; i < 5; i++ {
				createRole(t, sur, roleConfig{Name: fmt.Sprintf("tenant-%d", i), SystemType: "PowerMax", SystemID: "123456789", Pool: "myPool",})
			}

			res, err := sur.ListRole(context.Background(), &pb.ListRoleRequest{})
			checkError(t, err)

			wantLen := 5
			if gotLen := len(res.Roles); gotLen != wantLen {
				t.Errorf("got len = %d, want %d", gotLen, wantLen)
			}
		})
	}
}



func checkError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

type roleConfig struct {
	Name    string
	SystemType   string
	SystemID string
	Pool string
}

func createRole(t *testing.T, svc *rolesvc.RoleService, cfg roleConfig) {
	t.Helper()

	_, err := svc.CreateRole(context.Background(), &pb.CreateRoleRequest{
		Role: &pb.Role{
			Name: cfg.Name,
			SystemType: cfg.SystemType,
			SystemID: cfg.SystemID,
			Pool: cfg.Pool,
		},
	})
	checkError(t, err)
}

func getRole(t *testing.T, svc *rolesvc.RoleService, name string) *pb.Role {
	res, err := svc.GetRole(context.Background(), &pb.GetRoleRequest{
		Name: name,
	})
	checkError(t, err)
	return res
}

func createRedisContainer(t *testing.T) *redis.Client {
	var rdb *redis.Client

	redisHost := os.Getenv("REDIS_HOST")
	redistPort := os.Getenv("REDIS_PORT")

	if redisHost != "" && redistPort != "" {
		rdb = redis.NewClient(&redis.Options{
			Addr: fmt.Sprintf("%s:%s", redisHost, redistPort),
		})
	} else {
		redisContainer, err := gnomock.StartCustom(
			"docker.io/library/redis:latest",
			gnomock.NamedPorts{"db": gnomock.TCP(6379)},
			gnomock.WithDisableAutoCleanup())
		if err != nil {
			t.Fatalf("failed to start redis container: %+v", err)
		}
		rdb = redis.NewClient(&redis.Options{
			Addr: redisContainer.Address("db"),
		})
		t.Cleanup(func() {
			if err := rdb.Close(); err != nil {
				log.Printf("closing redis: %+v", err)
			}
			if err := gnomock.Stop(redisContainer); err != nil {
				log.Printf("stopping redis container: %+v", err)
			}
		})
	}
	return rdb
}
