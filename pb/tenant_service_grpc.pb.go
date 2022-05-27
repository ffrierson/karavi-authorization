// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.2.0
// - protoc             v3.15.8
// source: pb/tenant_service.proto

package pb

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// TenantServiceClient is the client API for TenantService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type TenantServiceClient interface {
	CreateTenant(ctx context.Context, in *CreateTenantRequest, opts ...grpc.CallOption) (*Tenant, error)
	GetTenant(ctx context.Context, in *GetTenantRequest, opts ...grpc.CallOption) (*Tenant, error)
	DeleteTenant(ctx context.Context, in *DeleteTenantRequest, opts ...grpc.CallOption) (*DeleteTenantResponse, error)
	ListTenant(ctx context.Context, in *ListTenantRequest, opts ...grpc.CallOption) (*ListTenantResponse, error)
	BindRole(ctx context.Context, in *BindRoleRequest, opts ...grpc.CallOption) (*BindRoleResponse, error)
	ListBindRole(ctx context.Context, in *ListBindRoleRequest, opts ...grpc.CallOption) (*ListBindRoleResponse, error)
	UnbindRole(ctx context.Context, in *UnbindRoleRequest, opts ...grpc.CallOption) (*UnbindRoleResponse, error)
	GenerateToken(ctx context.Context, in *GenerateTokenRequest, opts ...grpc.CallOption) (*GenerateTokenResponse, error)
	RefreshToken(ctx context.Context, in *RefreshTokenRequest, opts ...grpc.CallOption) (*RefreshTokenResponse, error)
	RevokeTenant(ctx context.Context, in *RevokeTenantRequest, opts ...grpc.CallOption) (*RevokeTenantResponse, error)
	CancelRevokeTenant(ctx context.Context, in *CancelRevokeTenantRequest, opts ...grpc.CallOption) (*CancelRevokeTenantResponse, error)
}

type tenantServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewTenantServiceClient(cc grpc.ClientConnInterface) TenantServiceClient {
	return &tenantServiceClient{cc}
}

func (c *tenantServiceClient) CreateTenant(ctx context.Context, in *CreateTenantRequest, opts ...grpc.CallOption) (*Tenant, error) {
	out := new(Tenant)
	err := c.cc.Invoke(ctx, "/karavi.TenantService/CreateTenant", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *tenantServiceClient) GetTenant(ctx context.Context, in *GetTenantRequest, opts ...grpc.CallOption) (*Tenant, error) {
	out := new(Tenant)
	err := c.cc.Invoke(ctx, "/karavi.TenantService/GetTenant", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *tenantServiceClient) DeleteTenant(ctx context.Context, in *DeleteTenantRequest, opts ...grpc.CallOption) (*DeleteTenantResponse, error) {
	out := new(DeleteTenantResponse)
	err := c.cc.Invoke(ctx, "/karavi.TenantService/DeleteTenant", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *tenantServiceClient) ListTenant(ctx context.Context, in *ListTenantRequest, opts ...grpc.CallOption) (*ListTenantResponse, error) {
	out := new(ListTenantResponse)
	err := c.cc.Invoke(ctx, "/karavi.TenantService/ListTenant", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *tenantServiceClient) BindRole(ctx context.Context, in *BindRoleRequest, opts ...grpc.CallOption) (*BindRoleResponse, error) {
	out := new(BindRoleResponse)
	err := c.cc.Invoke(ctx, "/karavi.TenantService/BindRole", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *tenantServiceClient) ListBindRole(ctx context.Context, in *ListBindRoleRequest, opts ...grpc.CallOption) (*ListBindRoleResponse, error) {
	out := new(ListBindRoleResponse)
	err := c.cc.Invoke(ctx, "/karavi.TenantService/ListBindRole", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *tenantServiceClient) UnbindRole(ctx context.Context, in *UnbindRoleRequest, opts ...grpc.CallOption) (*UnbindRoleResponse, error) {
	out := new(UnbindRoleResponse)
	err := c.cc.Invoke(ctx, "/karavi.TenantService/UnbindRole", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *tenantServiceClient) GenerateToken(ctx context.Context, in *GenerateTokenRequest, opts ...grpc.CallOption) (*GenerateTokenResponse, error) {
	out := new(GenerateTokenResponse)
	err := c.cc.Invoke(ctx, "/karavi.TenantService/GenerateToken", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *tenantServiceClient) RefreshToken(ctx context.Context, in *RefreshTokenRequest, opts ...grpc.CallOption) (*RefreshTokenResponse, error) {
	out := new(RefreshTokenResponse)
	err := c.cc.Invoke(ctx, "/karavi.TenantService/RefreshToken", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *tenantServiceClient) RevokeTenant(ctx context.Context, in *RevokeTenantRequest, opts ...grpc.CallOption) (*RevokeTenantResponse, error) {
	out := new(RevokeTenantResponse)
	err := c.cc.Invoke(ctx, "/karavi.TenantService/RevokeTenant", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *tenantServiceClient) CancelRevokeTenant(ctx context.Context, in *CancelRevokeTenantRequest, opts ...grpc.CallOption) (*CancelRevokeTenantResponse, error) {
	out := new(CancelRevokeTenantResponse)
	err := c.cc.Invoke(ctx, "/karavi.TenantService/CancelRevokeTenant", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// TenantServiceServer is the server API for TenantService service.
// All implementations must embed UnimplementedTenantServiceServer
// for forward compatibility
type TenantServiceServer interface {
	CreateTenant(context.Context, *CreateTenantRequest) (*Tenant, error)
	GetTenant(context.Context, *GetTenantRequest) (*Tenant, error)
	DeleteTenant(context.Context, *DeleteTenantRequest) (*DeleteTenantResponse, error)
	ListTenant(context.Context, *ListTenantRequest) (*ListTenantResponse, error)
	BindRole(context.Context, *BindRoleRequest) (*BindRoleResponse, error)
	ListBindRole(context.Context, *ListBindRoleRequest) (*ListBindRoleResponse, error)
	UnbindRole(context.Context, *UnbindRoleRequest) (*UnbindRoleResponse, error)
	GenerateToken(context.Context, *GenerateTokenRequest) (*GenerateTokenResponse, error)
	RefreshToken(context.Context, *RefreshTokenRequest) (*RefreshTokenResponse, error)
	RevokeTenant(context.Context, *RevokeTenantRequest) (*RevokeTenantResponse, error)
	CancelRevokeTenant(context.Context, *CancelRevokeTenantRequest) (*CancelRevokeTenantResponse, error)
	mustEmbedUnimplementedTenantServiceServer()
}

// UnimplementedTenantServiceServer must be embedded to have forward compatible implementations.
type UnimplementedTenantServiceServer struct {
}

func (UnimplementedTenantServiceServer) CreateTenant(context.Context, *CreateTenantRequest) (*Tenant, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateTenant not implemented")
}
func (UnimplementedTenantServiceServer) GetTenant(context.Context, *GetTenantRequest) (*Tenant, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetTenant not implemented")
}
func (UnimplementedTenantServiceServer) DeleteTenant(context.Context, *DeleteTenantRequest) (*DeleteTenantResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteTenant not implemented")
}
func (UnimplementedTenantServiceServer) ListTenant(context.Context, *ListTenantRequest) (*ListTenantResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListTenant not implemented")
}
func (UnimplementedTenantServiceServer) BindRole(context.Context, *BindRoleRequest) (*BindRoleResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method BindRole not implemented")
}
func (UnimplementedTenantServiceServer) ListBindRole(context.Context, *ListBindRoleRequest) (*ListBindRoleResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListBindRole not implemented")
}
func (UnimplementedTenantServiceServer) UnbindRole(context.Context, *UnbindRoleRequest) (*UnbindRoleResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UnbindRole not implemented")
}
func (UnimplementedTenantServiceServer) GenerateToken(context.Context, *GenerateTokenRequest) (*GenerateTokenResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GenerateToken not implemented")
}
func (UnimplementedTenantServiceServer) RefreshToken(context.Context, *RefreshTokenRequest) (*RefreshTokenResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RefreshToken not implemented")
}
func (UnimplementedTenantServiceServer) RevokeTenant(context.Context, *RevokeTenantRequest) (*RevokeTenantResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RevokeTenant not implemented")
}
func (UnimplementedTenantServiceServer) CancelRevokeTenant(context.Context, *CancelRevokeTenantRequest) (*CancelRevokeTenantResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CancelRevokeTenant not implemented")
}
func (UnimplementedTenantServiceServer) mustEmbedUnimplementedTenantServiceServer() {}

// UnsafeTenantServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to TenantServiceServer will
// result in compilation errors.
type UnsafeTenantServiceServer interface {
	mustEmbedUnimplementedTenantServiceServer()
}

func RegisterTenantServiceServer(s grpc.ServiceRegistrar, srv TenantServiceServer) {
	s.RegisterService(&TenantService_ServiceDesc, srv)
}

func _TenantService_CreateTenant_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateTenantRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TenantServiceServer).CreateTenant(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/karavi.TenantService/CreateTenant",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TenantServiceServer).CreateTenant(ctx, req.(*CreateTenantRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _TenantService_GetTenant_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetTenantRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TenantServiceServer).GetTenant(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/karavi.TenantService/GetTenant",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TenantServiceServer).GetTenant(ctx, req.(*GetTenantRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _TenantService_DeleteTenant_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteTenantRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TenantServiceServer).DeleteTenant(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/karavi.TenantService/DeleteTenant",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TenantServiceServer).DeleteTenant(ctx, req.(*DeleteTenantRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _TenantService_ListTenant_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListTenantRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TenantServiceServer).ListTenant(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/karavi.TenantService/ListTenant",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TenantServiceServer).ListTenant(ctx, req.(*ListTenantRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _TenantService_BindRole_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(BindRoleRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TenantServiceServer).BindRole(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/karavi.TenantService/BindRole",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TenantServiceServer).BindRole(ctx, req.(*BindRoleRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _TenantService_ListBindRole_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListBindRoleRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TenantServiceServer).ListBindRole(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/karavi.TenantService/ListBindRole",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TenantServiceServer).ListBindRole(ctx, req.(*ListBindRoleRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _TenantService_UnbindRole_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UnbindRoleRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TenantServiceServer).UnbindRole(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/karavi.TenantService/UnbindRole",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TenantServiceServer).UnbindRole(ctx, req.(*UnbindRoleRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _TenantService_GenerateToken_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GenerateTokenRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TenantServiceServer).GenerateToken(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/karavi.TenantService/GenerateToken",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TenantServiceServer).GenerateToken(ctx, req.(*GenerateTokenRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _TenantService_RefreshToken_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RefreshTokenRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TenantServiceServer).RefreshToken(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/karavi.TenantService/RefreshToken",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TenantServiceServer).RefreshToken(ctx, req.(*RefreshTokenRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _TenantService_RevokeTenant_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RevokeTenantRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TenantServiceServer).RevokeTenant(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/karavi.TenantService/RevokeTenant",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TenantServiceServer).RevokeTenant(ctx, req.(*RevokeTenantRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _TenantService_CancelRevokeTenant_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CancelRevokeTenantRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TenantServiceServer).CancelRevokeTenant(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/karavi.TenantService/CancelRevokeTenant",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TenantServiceServer).CancelRevokeTenant(ctx, req.(*CancelRevokeTenantRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// TenantService_ServiceDesc is the grpc.ServiceDesc for TenantService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var TenantService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "karavi.TenantService",
	HandlerType: (*TenantServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "CreateTenant",
			Handler:    _TenantService_CreateTenant_Handler,
		},
		{
			MethodName: "GetTenant",
			Handler:    _TenantService_GetTenant_Handler,
		},
		{
			MethodName: "DeleteTenant",
			Handler:    _TenantService_DeleteTenant_Handler,
		},
		{
			MethodName: "ListTenant",
			Handler:    _TenantService_ListTenant_Handler,
		},
		{
			MethodName: "BindRole",
			Handler:    _TenantService_BindRole_Handler,
		},
		{
			MethodName: "ListBindRole",
			Handler:    _TenantService_ListBindRole_Handler,
		},
		{
			MethodName: "UnbindRole",
			Handler:    _TenantService_UnbindRole_Handler,
		},
		{
			MethodName: "GenerateToken",
			Handler:    _TenantService_GenerateToken_Handler,
		},
		{
			MethodName: "RefreshToken",
			Handler:    _TenantService_RefreshToken_Handler,
		},
		{
			MethodName: "RevokeTenant",
			Handler:    _TenantService_RevokeTenant_Handler,
		},
		{
			MethodName: "CancelRevokeTenant",
			Handler:    _TenantService_CancelRevokeTenant_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "pb/tenant_service.proto",
}
