// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.5.1
// - protoc             v5.26.0
// source: github.com/Microsoft/hcsshim/pkg/ncproxy/ncproxygrpc/v1/networkconfigproxy.proto

package v1

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.64.0 or later.
const _ = grpc.SupportPackageIsVersion9

const (
	NetworkConfigProxy_AddNIC_FullMethodName         = "/ncproxygrpc.v1.NetworkConfigProxy/AddNIC"
	NetworkConfigProxy_ModifyNIC_FullMethodName      = "/ncproxygrpc.v1.NetworkConfigProxy/ModifyNIC"
	NetworkConfigProxy_DeleteNIC_FullMethodName      = "/ncproxygrpc.v1.NetworkConfigProxy/DeleteNIC"
	NetworkConfigProxy_CreateNetwork_FullMethodName  = "/ncproxygrpc.v1.NetworkConfigProxy/CreateNetwork"
	NetworkConfigProxy_CreateEndpoint_FullMethodName = "/ncproxygrpc.v1.NetworkConfigProxy/CreateEndpoint"
	NetworkConfigProxy_AddEndpoint_FullMethodName    = "/ncproxygrpc.v1.NetworkConfigProxy/AddEndpoint"
	NetworkConfigProxy_DeleteEndpoint_FullMethodName = "/ncproxygrpc.v1.NetworkConfigProxy/DeleteEndpoint"
	NetworkConfigProxy_DeleteNetwork_FullMethodName  = "/ncproxygrpc.v1.NetworkConfigProxy/DeleteNetwork"
	NetworkConfigProxy_GetEndpoint_FullMethodName    = "/ncproxygrpc.v1.NetworkConfigProxy/GetEndpoint"
	NetworkConfigProxy_GetNetwork_FullMethodName     = "/ncproxygrpc.v1.NetworkConfigProxy/GetNetwork"
	NetworkConfigProxy_GetEndpoints_FullMethodName   = "/ncproxygrpc.v1.NetworkConfigProxy/GetEndpoints"
	NetworkConfigProxy_GetNetworks_FullMethodName    = "/ncproxygrpc.v1.NetworkConfigProxy/GetNetworks"
)

// NetworkConfigProxyClient is the client API for NetworkConfigProxy service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type NetworkConfigProxyClient interface {
	AddNIC(ctx context.Context, in *AddNICRequest, opts ...grpc.CallOption) (*AddNICResponse, error)
	ModifyNIC(ctx context.Context, in *ModifyNICRequest, opts ...grpc.CallOption) (*ModifyNICResponse, error)
	DeleteNIC(ctx context.Context, in *DeleteNICRequest, opts ...grpc.CallOption) (*DeleteNICResponse, error)
	CreateNetwork(ctx context.Context, in *CreateNetworkRequest, opts ...grpc.CallOption) (*CreateNetworkResponse, error)
	CreateEndpoint(ctx context.Context, in *CreateEndpointRequest, opts ...grpc.CallOption) (*CreateEndpointResponse, error)
	AddEndpoint(ctx context.Context, in *AddEndpointRequest, opts ...grpc.CallOption) (*AddEndpointResponse, error)
	DeleteEndpoint(ctx context.Context, in *DeleteEndpointRequest, opts ...grpc.CallOption) (*DeleteEndpointResponse, error)
	DeleteNetwork(ctx context.Context, in *DeleteNetworkRequest, opts ...grpc.CallOption) (*DeleteNetworkResponse, error)
	GetEndpoint(ctx context.Context, in *GetEndpointRequest, opts ...grpc.CallOption) (*GetEndpointResponse, error)
	GetNetwork(ctx context.Context, in *GetNetworkRequest, opts ...grpc.CallOption) (*GetNetworkResponse, error)
	GetEndpoints(ctx context.Context, in *GetEndpointsRequest, opts ...grpc.CallOption) (*GetEndpointsResponse, error)
	GetNetworks(ctx context.Context, in *GetNetworksRequest, opts ...grpc.CallOption) (*GetNetworksResponse, error)
}

type networkConfigProxyClient struct {
	cc grpc.ClientConnInterface
}

func NewNetworkConfigProxyClient(cc grpc.ClientConnInterface) NetworkConfigProxyClient {
	return &networkConfigProxyClient{cc}
}

func (c *networkConfigProxyClient) AddNIC(ctx context.Context, in *AddNICRequest, opts ...grpc.CallOption) (*AddNICResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(AddNICResponse)
	err := c.cc.Invoke(ctx, NetworkConfigProxy_AddNIC_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *networkConfigProxyClient) ModifyNIC(ctx context.Context, in *ModifyNICRequest, opts ...grpc.CallOption) (*ModifyNICResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(ModifyNICResponse)
	err := c.cc.Invoke(ctx, NetworkConfigProxy_ModifyNIC_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *networkConfigProxyClient) DeleteNIC(ctx context.Context, in *DeleteNICRequest, opts ...grpc.CallOption) (*DeleteNICResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(DeleteNICResponse)
	err := c.cc.Invoke(ctx, NetworkConfigProxy_DeleteNIC_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *networkConfigProxyClient) CreateNetwork(ctx context.Context, in *CreateNetworkRequest, opts ...grpc.CallOption) (*CreateNetworkResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(CreateNetworkResponse)
	err := c.cc.Invoke(ctx, NetworkConfigProxy_CreateNetwork_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *networkConfigProxyClient) CreateEndpoint(ctx context.Context, in *CreateEndpointRequest, opts ...grpc.CallOption) (*CreateEndpointResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(CreateEndpointResponse)
	err := c.cc.Invoke(ctx, NetworkConfigProxy_CreateEndpoint_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *networkConfigProxyClient) AddEndpoint(ctx context.Context, in *AddEndpointRequest, opts ...grpc.CallOption) (*AddEndpointResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(AddEndpointResponse)
	err := c.cc.Invoke(ctx, NetworkConfigProxy_AddEndpoint_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *networkConfigProxyClient) DeleteEndpoint(ctx context.Context, in *DeleteEndpointRequest, opts ...grpc.CallOption) (*DeleteEndpointResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(DeleteEndpointResponse)
	err := c.cc.Invoke(ctx, NetworkConfigProxy_DeleteEndpoint_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *networkConfigProxyClient) DeleteNetwork(ctx context.Context, in *DeleteNetworkRequest, opts ...grpc.CallOption) (*DeleteNetworkResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(DeleteNetworkResponse)
	err := c.cc.Invoke(ctx, NetworkConfigProxy_DeleteNetwork_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *networkConfigProxyClient) GetEndpoint(ctx context.Context, in *GetEndpointRequest, opts ...grpc.CallOption) (*GetEndpointResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(GetEndpointResponse)
	err := c.cc.Invoke(ctx, NetworkConfigProxy_GetEndpoint_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *networkConfigProxyClient) GetNetwork(ctx context.Context, in *GetNetworkRequest, opts ...grpc.CallOption) (*GetNetworkResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(GetNetworkResponse)
	err := c.cc.Invoke(ctx, NetworkConfigProxy_GetNetwork_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *networkConfigProxyClient) GetEndpoints(ctx context.Context, in *GetEndpointsRequest, opts ...grpc.CallOption) (*GetEndpointsResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(GetEndpointsResponse)
	err := c.cc.Invoke(ctx, NetworkConfigProxy_GetEndpoints_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *networkConfigProxyClient) GetNetworks(ctx context.Context, in *GetNetworksRequest, opts ...grpc.CallOption) (*GetNetworksResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(GetNetworksResponse)
	err := c.cc.Invoke(ctx, NetworkConfigProxy_GetNetworks_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// NetworkConfigProxyServer is the server API for NetworkConfigProxy service.
// All implementations must embed UnimplementedNetworkConfigProxyServer
// for forward compatibility.
type NetworkConfigProxyServer interface {
	AddNIC(context.Context, *AddNICRequest) (*AddNICResponse, error)
	ModifyNIC(context.Context, *ModifyNICRequest) (*ModifyNICResponse, error)
	DeleteNIC(context.Context, *DeleteNICRequest) (*DeleteNICResponse, error)
	CreateNetwork(context.Context, *CreateNetworkRequest) (*CreateNetworkResponse, error)
	CreateEndpoint(context.Context, *CreateEndpointRequest) (*CreateEndpointResponse, error)
	AddEndpoint(context.Context, *AddEndpointRequest) (*AddEndpointResponse, error)
	DeleteEndpoint(context.Context, *DeleteEndpointRequest) (*DeleteEndpointResponse, error)
	DeleteNetwork(context.Context, *DeleteNetworkRequest) (*DeleteNetworkResponse, error)
	GetEndpoint(context.Context, *GetEndpointRequest) (*GetEndpointResponse, error)
	GetNetwork(context.Context, *GetNetworkRequest) (*GetNetworkResponse, error)
	GetEndpoints(context.Context, *GetEndpointsRequest) (*GetEndpointsResponse, error)
	GetNetworks(context.Context, *GetNetworksRequest) (*GetNetworksResponse, error)
	mustEmbedUnimplementedNetworkConfigProxyServer()
}

// UnimplementedNetworkConfigProxyServer must be embedded to have
// forward compatible implementations.
//
// NOTE: this should be embedded by value instead of pointer to avoid a nil
// pointer dereference when methods are called.
type UnimplementedNetworkConfigProxyServer struct{}

func (UnimplementedNetworkConfigProxyServer) AddNIC(context.Context, *AddNICRequest) (*AddNICResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AddNIC not implemented")
}
func (UnimplementedNetworkConfigProxyServer) ModifyNIC(context.Context, *ModifyNICRequest) (*ModifyNICResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ModifyNIC not implemented")
}
func (UnimplementedNetworkConfigProxyServer) DeleteNIC(context.Context, *DeleteNICRequest) (*DeleteNICResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteNIC not implemented")
}
func (UnimplementedNetworkConfigProxyServer) CreateNetwork(context.Context, *CreateNetworkRequest) (*CreateNetworkResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateNetwork not implemented")
}
func (UnimplementedNetworkConfigProxyServer) CreateEndpoint(context.Context, *CreateEndpointRequest) (*CreateEndpointResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateEndpoint not implemented")
}
func (UnimplementedNetworkConfigProxyServer) AddEndpoint(context.Context, *AddEndpointRequest) (*AddEndpointResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AddEndpoint not implemented")
}
func (UnimplementedNetworkConfigProxyServer) DeleteEndpoint(context.Context, *DeleteEndpointRequest) (*DeleteEndpointResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteEndpoint not implemented")
}
func (UnimplementedNetworkConfigProxyServer) DeleteNetwork(context.Context, *DeleteNetworkRequest) (*DeleteNetworkResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteNetwork not implemented")
}
func (UnimplementedNetworkConfigProxyServer) GetEndpoint(context.Context, *GetEndpointRequest) (*GetEndpointResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetEndpoint not implemented")
}
func (UnimplementedNetworkConfigProxyServer) GetNetwork(context.Context, *GetNetworkRequest) (*GetNetworkResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetNetwork not implemented")
}
func (UnimplementedNetworkConfigProxyServer) GetEndpoints(context.Context, *GetEndpointsRequest) (*GetEndpointsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetEndpoints not implemented")
}
func (UnimplementedNetworkConfigProxyServer) GetNetworks(context.Context, *GetNetworksRequest) (*GetNetworksResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetNetworks not implemented")
}
func (UnimplementedNetworkConfigProxyServer) mustEmbedUnimplementedNetworkConfigProxyServer() {}
func (UnimplementedNetworkConfigProxyServer) testEmbeddedByValue()                            {}

// UnsafeNetworkConfigProxyServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to NetworkConfigProxyServer will
// result in compilation errors.
type UnsafeNetworkConfigProxyServer interface {
	mustEmbedUnimplementedNetworkConfigProxyServer()
}

func RegisterNetworkConfigProxyServer(s grpc.ServiceRegistrar, srv NetworkConfigProxyServer) {
	// If the following call pancis, it indicates UnimplementedNetworkConfigProxyServer was
	// embedded by pointer and is nil.  This will cause panics if an
	// unimplemented method is ever invoked, so we test this at initialization
	// time to prevent it from happening at runtime later due to I/O.
	if t, ok := srv.(interface{ testEmbeddedByValue() }); ok {
		t.testEmbeddedByValue()
	}
	s.RegisterService(&NetworkConfigProxy_ServiceDesc, srv)
}

func _NetworkConfigProxy_AddNIC_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AddNICRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(NetworkConfigProxyServer).AddNIC(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: NetworkConfigProxy_AddNIC_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(NetworkConfigProxyServer).AddNIC(ctx, req.(*AddNICRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _NetworkConfigProxy_ModifyNIC_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ModifyNICRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(NetworkConfigProxyServer).ModifyNIC(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: NetworkConfigProxy_ModifyNIC_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(NetworkConfigProxyServer).ModifyNIC(ctx, req.(*ModifyNICRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _NetworkConfigProxy_DeleteNIC_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteNICRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(NetworkConfigProxyServer).DeleteNIC(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: NetworkConfigProxy_DeleteNIC_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(NetworkConfigProxyServer).DeleteNIC(ctx, req.(*DeleteNICRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _NetworkConfigProxy_CreateNetwork_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateNetworkRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(NetworkConfigProxyServer).CreateNetwork(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: NetworkConfigProxy_CreateNetwork_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(NetworkConfigProxyServer).CreateNetwork(ctx, req.(*CreateNetworkRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _NetworkConfigProxy_CreateEndpoint_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateEndpointRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(NetworkConfigProxyServer).CreateEndpoint(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: NetworkConfigProxy_CreateEndpoint_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(NetworkConfigProxyServer).CreateEndpoint(ctx, req.(*CreateEndpointRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _NetworkConfigProxy_AddEndpoint_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AddEndpointRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(NetworkConfigProxyServer).AddEndpoint(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: NetworkConfigProxy_AddEndpoint_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(NetworkConfigProxyServer).AddEndpoint(ctx, req.(*AddEndpointRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _NetworkConfigProxy_DeleteEndpoint_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteEndpointRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(NetworkConfigProxyServer).DeleteEndpoint(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: NetworkConfigProxy_DeleteEndpoint_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(NetworkConfigProxyServer).DeleteEndpoint(ctx, req.(*DeleteEndpointRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _NetworkConfigProxy_DeleteNetwork_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteNetworkRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(NetworkConfigProxyServer).DeleteNetwork(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: NetworkConfigProxy_DeleteNetwork_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(NetworkConfigProxyServer).DeleteNetwork(ctx, req.(*DeleteNetworkRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _NetworkConfigProxy_GetEndpoint_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetEndpointRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(NetworkConfigProxyServer).GetEndpoint(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: NetworkConfigProxy_GetEndpoint_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(NetworkConfigProxyServer).GetEndpoint(ctx, req.(*GetEndpointRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _NetworkConfigProxy_GetNetwork_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetNetworkRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(NetworkConfigProxyServer).GetNetwork(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: NetworkConfigProxy_GetNetwork_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(NetworkConfigProxyServer).GetNetwork(ctx, req.(*GetNetworkRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _NetworkConfigProxy_GetEndpoints_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetEndpointsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(NetworkConfigProxyServer).GetEndpoints(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: NetworkConfigProxy_GetEndpoints_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(NetworkConfigProxyServer).GetEndpoints(ctx, req.(*GetEndpointsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _NetworkConfigProxy_GetNetworks_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetNetworksRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(NetworkConfigProxyServer).GetNetworks(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: NetworkConfigProxy_GetNetworks_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(NetworkConfigProxyServer).GetNetworks(ctx, req.(*GetNetworksRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// NetworkConfigProxy_ServiceDesc is the grpc.ServiceDesc for NetworkConfigProxy service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var NetworkConfigProxy_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "ncproxygrpc.v1.NetworkConfigProxy",
	HandlerType: (*NetworkConfigProxyServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "AddNIC",
			Handler:    _NetworkConfigProxy_AddNIC_Handler,
		},
		{
			MethodName: "ModifyNIC",
			Handler:    _NetworkConfigProxy_ModifyNIC_Handler,
		},
		{
			MethodName: "DeleteNIC",
			Handler:    _NetworkConfigProxy_DeleteNIC_Handler,
		},
		{
			MethodName: "CreateNetwork",
			Handler:    _NetworkConfigProxy_CreateNetwork_Handler,
		},
		{
			MethodName: "CreateEndpoint",
			Handler:    _NetworkConfigProxy_CreateEndpoint_Handler,
		},
		{
			MethodName: "AddEndpoint",
			Handler:    _NetworkConfigProxy_AddEndpoint_Handler,
		},
		{
			MethodName: "DeleteEndpoint",
			Handler:    _NetworkConfigProxy_DeleteEndpoint_Handler,
		},
		{
			MethodName: "DeleteNetwork",
			Handler:    _NetworkConfigProxy_DeleteNetwork_Handler,
		},
		{
			MethodName: "GetEndpoint",
			Handler:    _NetworkConfigProxy_GetEndpoint_Handler,
		},
		{
			MethodName: "GetNetwork",
			Handler:    _NetworkConfigProxy_GetNetwork_Handler,
		},
		{
			MethodName: "GetEndpoints",
			Handler:    _NetworkConfigProxy_GetEndpoints_Handler,
		},
		{
			MethodName: "GetNetworks",
			Handler:    _NetworkConfigProxy_GetNetworks_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "github.com/Microsoft/hcsshim/pkg/ncproxy/ncproxygrpc/v1/networkconfigproxy.proto",
}
