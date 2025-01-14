// Code generated by MockGen. DO NOT EDIT.
// Source: computeagent_ttrpc.pb.go
//
// Generated by this command:
//
//	mockgen -source=computeagent_ttrpc.pb.go -package=computeagent_mock -destination=mock\computeagent_mock.pb.go
//

// Package computeagent_mock is a generated GoMock package.
package computeagent_mock

import (
	context "context"
	reflect "reflect"

	computeagent "github.com/Microsoft/hcsshim/internal/computeagent"
	gomock "go.uber.org/mock/gomock"
)

// MockComputeAgentService is a mock of ComputeAgentService interface.
type MockComputeAgentService struct {
	ctrl     *gomock.Controller
	recorder *MockComputeAgentServiceMockRecorder
	isgomock struct{}
}

// MockComputeAgentServiceMockRecorder is the mock recorder for MockComputeAgentService.
type MockComputeAgentServiceMockRecorder struct {
	mock *MockComputeAgentService
}

// NewMockComputeAgentService creates a new mock instance.
func NewMockComputeAgentService(ctrl *gomock.Controller) *MockComputeAgentService {
	mock := &MockComputeAgentService{ctrl: ctrl}
	mock.recorder = &MockComputeAgentServiceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockComputeAgentService) EXPECT() *MockComputeAgentServiceMockRecorder {
	return m.recorder
}

// AddNIC mocks base method.
func (m *MockComputeAgentService) AddNIC(arg0 context.Context, arg1 *computeagent.AddNICInternalRequest) (*computeagent.AddNICInternalResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddNIC", arg0, arg1)
	ret0, _ := ret[0].(*computeagent.AddNICInternalResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AddNIC indicates an expected call of AddNIC.
func (mr *MockComputeAgentServiceMockRecorder) AddNIC(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddNIC", reflect.TypeOf((*MockComputeAgentService)(nil).AddNIC), arg0, arg1)
}

// AssignPCI mocks base method.
func (m *MockComputeAgentService) AssignPCI(arg0 context.Context, arg1 *computeagent.AssignPCIInternalRequest) (*computeagent.AssignPCIInternalResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AssignPCI", arg0, arg1)
	ret0, _ := ret[0].(*computeagent.AssignPCIInternalResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AssignPCI indicates an expected call of AssignPCI.
func (mr *MockComputeAgentServiceMockRecorder) AssignPCI(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AssignPCI", reflect.TypeOf((*MockComputeAgentService)(nil).AssignPCI), arg0, arg1)
}

// DeleteNIC mocks base method.
func (m *MockComputeAgentService) DeleteNIC(arg0 context.Context, arg1 *computeagent.DeleteNICInternalRequest) (*computeagent.DeleteNICInternalResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteNIC", arg0, arg1)
	ret0, _ := ret[0].(*computeagent.DeleteNICInternalResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DeleteNIC indicates an expected call of DeleteNIC.
func (mr *MockComputeAgentServiceMockRecorder) DeleteNIC(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteNIC", reflect.TypeOf((*MockComputeAgentService)(nil).DeleteNIC), arg0, arg1)
}

// ModifyNIC mocks base method.
func (m *MockComputeAgentService) ModifyNIC(arg0 context.Context, arg1 *computeagent.ModifyNICInternalRequest) (*computeagent.ModifyNICInternalResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ModifyNIC", arg0, arg1)
	ret0, _ := ret[0].(*computeagent.ModifyNICInternalResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ModifyNIC indicates an expected call of ModifyNIC.
func (mr *MockComputeAgentServiceMockRecorder) ModifyNIC(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ModifyNIC", reflect.TypeOf((*MockComputeAgentService)(nil).ModifyNIC), arg0, arg1)
}

// RemovePCI mocks base method.
func (m *MockComputeAgentService) RemovePCI(arg0 context.Context, arg1 *computeagent.RemovePCIInternalRequest) (*computeagent.RemovePCIInternalResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RemovePCI", arg0, arg1)
	ret0, _ := ret[0].(*computeagent.RemovePCIInternalResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// RemovePCI indicates an expected call of RemovePCI.
func (mr *MockComputeAgentServiceMockRecorder) RemovePCI(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RemovePCI", reflect.TypeOf((*MockComputeAgentService)(nil).RemovePCI), arg0, arg1)
}
