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

package rolesvc

import (
	"context"
	"fmt"
	"karavi-authorization/pb"
	"strings"
	"time"

	"github.com/go-redis/redis"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Common errors.
var (
	ErrRoleAlreadyExists = status.Error(codes.InvalidArgument, "role already exists")
	ErrRoleNotFound      = status.Error(codes.InvalidArgument, "role not found")
	ErrNilRole           = status.Error(codes.InvalidArgument, "nil role")
	ErrNoRolesForTenant    = status.Error(codes.InvalidArgument, "tenant has no roles")
	ErrTenantIsRevoked     = status.Error(codes.InvalidArgument, "tenant has been revoked")
)

// Common Redis names.
const (
	FieldRefreshCount = "refresh_count"
	FieldCreatedAt    = "created_at"
	KeyRoleRevoked  = "role:revoked"
)

// RoleService is the gRPC implementation of the RoleServiceServer.
type RoleService struct {
	pb.UnimplementedRoleServiceServer

	log              *logrus.Entry
	rdb              *redis.Client
	jwtSigningSecret string
}

// Option allows for functional option arguments on the RoleService.
type Option func(*RoleService)

func defaultOptions() []Option {
	return []Option{
		WithLogger(logrus.NewEntry(logrus.New())),
	}
}

// WithLogger provides a logger.
func WithLogger(log *logrus.Entry) func(*RoleService) {
	return func(r *RoleService) {
		r.log = log
	}
}

// WithRedis provides a redis client.
func WithRedis(rdb *redis.Client) func(*RoleService) {
	return func(r *RoleService) {
		r.rdb = rdb
	}
}

// WithJWTSigningSecret provides the JWT signing secret.
func WithJWTSigningSecret(s string) func(*RoleService) {
	return func(r *RoleService) {
		r.jwtSigningSecret = s
	}
}

// NewRoleService allocates a new RoleService.
func NewRoleService(opts ...Option) *RoleService {
	var r RoleService
	for _, opt := range defaultOptions() {
		opt(&r)
	}
	for _, opt := range opts {
		opt(&r)
	}
	return &r
}

// CreateRole handles role creation requests.
func (r *RoleService) CreateRole(ctx context.Context, req *pb.CreateRoleRequest) (*pb.Role, error) {
	return r.createOrUpdateRole(ctx, req.Role, false)
}

// GetRole handles role query requests.
func (r *RoleService) GetRole(ctx context.Context, req *pb.GetRoleRequest) (*pb.Role, error) {
	m, err := r.rdb.HGetAll(roleKey(req.Name)).Result()
	if err != nil {
		return nil, err
	}

	if len(m) == 0 {
		return nil, ErrRoleNotFound
	}


	return &pb.Role{
		Name:  req.Name,
		SystemType: req.SystemType,
		SystemID: req.SystemID,
		Pool: req.Pool,
	}, nil
}

// DeleteRole handles tenant deletion requests.
func (r *RoleService) DeleteRole(ctx context.Context, req *pb.DeleteRoleRequest) (*empty.Empty, error) {
	var emp empty.Empty
	n, err := r.rdb.Del(roleKey(req.Name)).Result()
	if err != nil {
		return &emp, err
	}
	if n == 0 {
		return nil, ErrRoleNotFound
	}

	return &emp, nil
}

// ListRole handles tenant listing requests.
func (r *RoleService) ListRole(ctx context.Context, req *pb.ListRoleRequest) (*pb.ListRoleResponse, error) {
	var roles []*pb.Role

	var cursor uint64
	for {
		// TODO: Store roles in a Set to avoid the scan.
		keys, nextCursor, err := r.rdb.Scan(cursor, "role:*:data", 10).Result()
		if err != nil {
			return nil, err
		}
		for _, v := range keys {
			split := strings.Split(v, ":")
			roles = append(roles, &pb.Role{
				Name: split[1],
			})
		}

		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}

	return &pb.ListRoleResponse{
		Roles: roles,
	}, nil
}



func (r *RoleService) createOrUpdateRole(ctx context.Context, v *pb.Role, isUpdate bool) (*pb.Role, error) {
	if v == nil {
		return nil, ErrNilRole
	}

	exists, err := r.rdb.Exists(roleKey(v.Name)).Result()
	if err != nil {
		return nil, err
	}
	if isUpdate && exists == 0 {
		return nil, ErrRoleNotFound
	}
	if !isUpdate && exists == 1 {
		return nil, ErrRoleAlreadyExists
	}

	_, err = r.rdb.HSet(roleKey(v.Name), FieldCreatedAt, time.Now().Unix()).Result()
	if err != nil {
		return nil, err
	}

	return &pb.Role{
		Name:  v.Name,
		SystemType: v.SystemType,
		SystemID: v.SystemID,
		Pool: v.Pool,
	}, nil
}

func roleKey(name string) string {
	return fmt.Sprintf("role:%s:data", name)
}


func rolesTenantKey(name string) string {
	return fmt.Sprintf("role:%s:tenants", name)
}
