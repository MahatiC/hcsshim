//go: build windows

package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"sync"

	"github.com/Microsoft/go-winio"
	"github.com/Microsoft/go-winio/pkg/guid"
	"github.com/Microsoft/hcsshim/internal/gcs"


	"github.com/Microsoft/hcsshim/pkg/securitypolicy"
	"github.com/Microsoft/hcsshim/internal/guest/prot"
	"github.com/Microsoft/hcsshim/internal/protocol/guestresource"
)

// API for bridge events	
// TODO: Assign appropriate handlers

func (h *Host) SetConfidentialUVMOptions(ctx context.Context, r *guestresource.WCOWConfidentialOptions) error {
}

func (b *Bridge) startContainerV2(r *Request) (_ RequestResponse, err error) {
}

func (b *Bridge) createContainerV2(r *Request) (_ RequestResponse, err error) {
	// TODO: ExtendPolicyWithNetworkingMounts, EnforceCreateContainerPolicy
}

func (b *Bridge) killContainerV2(r *Request) (RequestResponse, error) {
	return b.signalContainerShutdownV2(ctx, span, r, false)
}

func (b *Bridge) shutdownContainerV2(r *Request) (RequestResponse, error) {
	return b.signalContainerShutdownV2(ctx, span, r, true)
}

func (b *Bridge) signalProcessV2(r *Request) (_ RequestResponse, err error) {
	if err := b.hostState.SignalContainerProcess(ctx, request.ContainerID, request.ProcessID, signal); err != nil {
		return nil, err
	}
}

func (b *Bridge) getPropertiesV2(r *Request) (_ RequestResponse, err error) {
	properties, err := b.hostState.GetProperties(ctx, request.ContainerID, query)
}

func (b *Bridge) waitOnProcessV2(r *Request) (_ RequestResponse, err error) {
	// TODO: Maintain pro
}

// signalContainerV2 is not a handler func. It is called from either `killContainerV2` or `shutdownContainerV2`
func (b *Bridge) signalContainerShutdownV2(ctx context.Context, span *trace.Span, r *Request, graceful bool) (_ RequestResponse, err error) {
	// If this is targeting the UVM send the request to the host itself.
	if request.ContainerID == hcsv2.UVMContainerID {
		// We are asking to shutdown the UVM itself.
		// This is a destructive call. We do not respond to the HCS
		b.quitChan <- true
		b.hostState.Shutdown()
	} else {
		err = b.hostState.ShutdownContainer(ctx, request.ContainerID, graceful)
		if err != nil {
			return nil, err
		}
	}
}

func (b *Bridge) resizeConsoleV2(r *Request) (_ RequestResponse, err error) {
	// TODO: Kirtana? Fetch process ID in WCOW
	p, err := c.GetProcess(request.ProcessID)
}

func (b *Bridge) dumpStacksV2(r *Request) (_ RequestResponse, err error) {
	// TODO: EnforceDumpStacksPolicy
}

func (b *Bridge) deleteContainerStateV2(r *Request) (_ RequestResponse, err error) {
	// Note: No policy enforcement in LCOW case for this
}

func (b *Bridge) modifySettingsV2(r *Request) (_ RequestResponse, err error) {
	// TODO: Call into modifySettings and enforce policy
}

// API for Supportive functions for bridge events
func (h *Host) CreateContainer(ctx context.Context, id string, settings *prot.VMHostedContainerSettingsV2) (_ *Container, err error) {
}

func (h *Host) ExecProcess(ctx context.Context, containerID string, params prot.ProcessParameters, conSettings stdio.ConnectionSettings) (_ int, err error) {
}

func (h *Host) ShutdownContainer(ctx context.Context, containerID string, graceful bool) error {
	// TODO: EnforceShutdownContainerPolicy and pass the request to inbox GCS if allowed
	// TODO: Maintain UVM/Container state in gcs-sidecar 
	c, err := h.GetCreatedContainer(containerID)
}

// Shutdown terminates this UVM. This is a destructive call and will destroy all
// state that has not been cleaned before calling this function.
func (*Host) Shutdown() {
}

func (h *Host) SignalContainerProcess(ctx context.Context, containerID string, processID uint32, signal syscall.Signal) error {
	// TODO: Maintain UVM/Container state in gcs-sidecar 
	// TODO: EnforceSignalContainerProcessPolicy
	c, err := h.GetCreatedContainer(containerID)
}

func (h *Host) GetProperties(ctx context.Context, containerID string, query prot.PropertyQuery) (*prot.PropertiesV2, error) {
}

func (h *Host) GetStacks(ctx context.Context) (string, error) {
}