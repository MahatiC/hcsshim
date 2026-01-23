//go:build windows

package uvm

import (
	"context"

	"github.com/Microsoft/hcsshim/internal/gcs"
	"github.com/Microsoft/hcsshim/internal/gcs/prot"
	"github.com/Microsoft/hcsshim/internal/log"
	"github.com/Microsoft/hcsshim/internal/protocol/guestrequest"
)

func (uvm *UtilityVM) StartLogForwarding(ctx context.Context) error {
	// Implementation for starting the log forwarding service
	if uvm.OS() != "windows" || uvm.gc == nil {
		return errNotSupported
	}

	wcaps := gcs.GetWCOWCapabilities(uvm.gc.Capabilities())
	if wcaps != nil && wcaps.IsLogForwardingSupported() {
		log.G(ctx).Debug("Starting log forwarding service in guest")
		req := guestrequest.LogForwardServiceRPCRequest{
			RPCType:  guestrequest.RPCStartLogForwarding,
			Settings: "",
		}
		err := uvm.gc.ModifyServiceSettings(ctx, prot.LogForwardService, req)
		if err != nil {
			log.G(ctx).WithError(err).Error("Failed to start log forwarding service")
			return err
		}
		log.G(ctx).Info("Log forwarding service started successfully")
	} else {
		log.G(ctx).WithField("os", uvm.operatingSystem).Error("Log forwarding not supported for this OS")
	}
	return nil
}

func (uvm *UtilityVM) StopLogForwarding(ctx context.Context) error {
	// Implementation for stopping the log forwarding service
	if uvm.OS() != "windows" || uvm.gc == nil {
		return errNotSupported
	}

	wcaps := gcs.GetWCOWCapabilities(uvm.gc.Capabilities())
	if wcaps != nil && wcaps.IsLogForwardingSupported() {
		req := guestrequest.LogForwardServiceRPCRequest{
			RPCType:  guestrequest.RPCStopLogForwarding,
			Settings: "",
		}
		err := uvm.gc.ModifyServiceSettings(ctx, prot.LogForwardService, req)
		if err != nil {
			return err
		}
	}
	return nil
}

func (uvm *UtilityVM) SetLogSources(ctx context.Context) error {
	// Implementation for setting the log sources
	if uvm.OS() != "windows" || uvm.gc == nil {
		return errNotSupported
	}

	wcaps := gcs.GetWCOWCapabilities(uvm.gc.Capabilities())
	if wcaps != nil && wcaps.IsLogForwardingSupported() {
		log.G(ctx).Debug("Setting log sources in guest")
		// Make a call to the GCS to set the ETW providers
		req := guestrequest.LogForwardServiceRPCRequest{
			RPCType:  guestrequest.RPCModifyServiceSettings,
			Settings: uvm.logSources,
		}
		err := uvm.gc.ModifyServiceSettings(ctx, prot.LogForwardService, req)
		if err != nil {
			log.G(ctx).WithError(err).Error("Failed to set log sources")
			return err
		}
		log.G(ctx).Info("Log sources configured successfully in guest")
	} else {
		log.G(ctx).Warn("Log forwarding not supported by guest - skipping SetLogSources")
	}
	return nil
}
