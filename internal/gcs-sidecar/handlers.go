//go:build windows
// +build windows

package bridge

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Microsoft/hcsshim/hcn"
	"github.com/Microsoft/hcsshim/internal/bridgeutils/commonutils"
	"github.com/Microsoft/hcsshim/internal/fsformatter"
	"github.com/Microsoft/hcsshim/internal/gcs/prot"
	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
	"github.com/Microsoft/hcsshim/internal/log"
	"github.com/Microsoft/hcsshim/internal/oc"
	"github.com/Microsoft/hcsshim/internal/oci"
	"github.com/Microsoft/hcsshim/internal/protocol/guestrequest"
	"github.com/Microsoft/hcsshim/internal/protocol/guestresource"
	"github.com/Microsoft/hcsshim/internal/windevice"
	"github.com/Microsoft/hcsshim/pkg/annotations"
	"github.com/Microsoft/hcsshim/pkg/cimfs"
	"github.com/Microsoft/hcsshim/pkg/securitypolicy"
	"github.com/pkg/errors"
)

const (
	sandboxStateDirName = "WcSandboxState"
	hivesDirName        = "Hives"
	UVMContainerID      = "00000000-0000-0000-0000-000000000000"
)

// - Handler functions handle the incoming message requests. It
// also enforces security policy for confidential cwcow containers.
// - These handler functions may do some additional processing before
// forwarding requests to inbox GCS or send responses back to hcsshim.
// - In case of any error encountered during processing, appropriate error
// messages are returned and responses are sent back to hcsshim from ListenAndServer().
// TODO (kiashok): Verbose logging is for WIP and will be removed eventually.
func (b *Bridge) createContainer(req *request) (err error) {
	ctx, span := oc.StartSpan(req.ctx, "sidecar::createContainer")
	defer span.End()
	defer func() { oc.SetSpanStatus(span, err) }()

	var createContainerRequest prot.ContainerCreate
	var containerConfig json.RawMessage
	createContainerRequest.ContainerConfig.Value = &containerConfig
	if err = commonutils.UnmarshalJSONWithHresult(req.message, &createContainerRequest); err != nil {
		return errors.Wrap(err, "failed to unmarshal createContainer")
	}

	// containerConfig can be of type uvnConfig or hcsschema.HostedSystem or guestresource.CWCOWHostedSystem
	var (
		uvmConfig               prot.UvmConfig
		hostedSystemConfig      hcsschema.HostedSystem
		cwcowHostedSystemConfig guestresource.CWCOWHostedSystem
	)
	if err = commonutils.UnmarshalJSONWithHresult(containerConfig, &uvmConfig); err == nil &&
		uvmConfig.SystemType != "" {
		systemType := uvmConfig.SystemType
		timeZoneInformation := uvmConfig.TimeZoneInformation
		log.G(ctx).Tracef("createContainer: uvmConfig: {systemType: %v, timeZoneInformation: %v}}", systemType, timeZoneInformation)
	} else if err = commonutils.UnmarshalJSONWithHresult(containerConfig, &hostedSystemConfig); err == nil &&
		hostedSystemConfig.SchemaVersion != nil && hostedSystemConfig.Container != nil {
		schemaVersion := hostedSystemConfig.SchemaVersion
		container := hostedSystemConfig.Container
		log.G(ctx).Tracef("rpcCreate: HostedSystemConfig: {schemaVersion: %v, container: %v}}", schemaVersion, container)
	} else if err = commonutils.UnmarshalJSONWithHresult(containerConfig, &cwcowHostedSystemConfig); err == nil &&
		cwcowHostedSystemConfig.Spec.Version != "" && cwcowHostedSystemConfig.CWCOWHostedSystem.Container != nil {
		cwcowHostedSystem := cwcowHostedSystemConfig.CWCOWHostedSystem
		schemaVersion := cwcowHostedSystem.SchemaVersion
		container := cwcowHostedSystem.Container
		spec := cwcowHostedSystemConfig.Spec
		containerID := createContainerRequest.ContainerID
		log.G(ctx).Tracef("rpcCreate: CWCOWHostedSystemConfig {spec: %v, schemaVersion: %v, container: %v}}", string(req.message), schemaVersion, container)
		if b.hostState.isSecurityPolicyEnforcerInitialized() {
			c := &Container{
				id:        containerID,
				spec:      spec,
				processes: make(map[uint32]*containerProcess),
			}

			if err := b.hostState.AddContainer(req.ctx, containerID, c); err != nil {
				log.G(ctx).Tracef("Container exists in the map!")
			}
			defer func(err error) {
				if err != nil {
					b.hostState.RemoveContainer(containerID)
				}
			}(err)

			user := securitypolicy.IDName{
				Name: spec.Process.User.Username,
			}
			log.G(ctx).Tracef("user test: %v", user)
			_, _, _, err := b.hostState.securityPolicyEnforcer.EnforceCreateContainerPolicyV2(req.ctx, containerID, spec.Process.Args, spec.Process.Env, spec.Process.Cwd, spec.Mounts, user, nil)

			if err != nil {
				return fmt.Errorf("CreateContainer operation is denied by policy: %v", err)
			}
			// Write security policy, signed UVM reference and host AMD certificate to
			// container's rootfs, so that application and sidecar containers can have
			// access to it. The security policy is required by containers which need to
			// extract init-time claims found in the security policy. The directory path
			// containing the files is exposed via UVM_SECURITY_CONTEXT_DIR env var.
			// It may be an error to have a security policy but not expose it to the
			// container as in that case it can never be checked as correct by a verifier.
			if oci.ParseAnnotationsBool(ctx, spec.Annotations, annotations.UVMSecurityPolicyEnv, true) {
				encodedPolicy := b.hostState.securityPolicyEnforcer.EncodedSecurityPolicy()
				hostAMDCert := spec.Annotations[annotations.HostAMDCertificate]
				if len(encodedPolicy) > 0 || len(hostAMDCert) > 0 || len(b.hostState.uvmReferenceInfo) > 0 {
					// Use os.MkdirTemp to make sure that the directory is unique.
					securityContextDir, err := os.MkdirTemp(spec.Root.Path, securitypolicy.SecurityContextDirTemplate)
					if err != nil {
						return fmt.Errorf("failed to create security context directory: %w", err)
					}
					// Make sure that files inside directory are readable
					if err := os.Chmod(securityContextDir, 0755); err != nil {
						return fmt.Errorf("failed to chmod security context directory: %w", err)
					}

					if len(encodedPolicy) > 0 {
						if err := writeFileInDir(securityContextDir, securitypolicy.PolicyFilename, []byte(encodedPolicy), 0777); err != nil {
							return fmt.Errorf("failed to write security policy: %w", err)
						}
					}
					if len(b.hostState.uvmReferenceInfo) > 0 {
						if err := writeFileInDir(securityContextDir, securitypolicy.ReferenceInfoFilename, []byte(b.hostState.uvmReferenceInfo), 0777); err != nil {
							return fmt.Errorf("failed to write UVM reference info: %w", err)
						}
					}

					if len(hostAMDCert) > 0 {
						if err := writeFileInDir(securityContextDir, securitypolicy.HostAMDCertFilename, []byte(hostAMDCert), 0777); err != nil {
							return fmt.Errorf("failed to write host AMD certificate: %w", err)
						}
					}

					containerCtxDir := fmt.Sprintf("/%s", filepath.Base(securityContextDir))
					secCtxEnv := fmt.Sprintf("UVM_SECURITY_CONTEXT_DIR=%s", containerCtxDir)
					spec.Process.Env = append(spec.Process.Env, secCtxEnv)
				}
			}
		}

		// Strip the spec field
		hostedSystemBytes, err := json.Marshal(cwcowHostedSystem)

		if err != nil {
			return fmt.Errorf("failed to marshal hostedSystem: %w", err)
		}

		// marshal it again into a JSON-escaped string which inbox GCS expects
		hostedSystemEscapedBytes, err := json.Marshal(string(hostedSystemBytes))
		if err != nil {
			return fmt.Errorf("failed to marshal hostedSystem JSON: %w", err)
		}

		// Prepare a fixed struct that takes in raw message
		type containerCreateModified struct {
			prot.RequestBase
			ContainerConfig json.RawMessage
		}
		createContainerRequestModified := containerCreateModified{
			RequestBase:     createContainerRequest.RequestBase,
			ContainerConfig: hostedSystemEscapedBytes,
		}

		buf, err := json.Marshal(createContainerRequestModified)
		log.G(ctx).Tracef("marshaled request buffer: %s", string(buf))
		if err != nil {
			return fmt.Errorf("failed to marshal rpcCreatecontainer: %v", err)
		}
		var newRequest request
		newRequest.ctx = req.ctx
		newRequest.header = req.header
		newRequest.header.Size = uint32(len(buf)) + prot.HdrSize
		newRequest.message = buf
		req = &newRequest
	} else {
		return fmt.Errorf("Invalid request to createContainer")
	}

	b.forwardRequestToGcs(req)
	return err
}

func writeFileInDir(dir string, filename string, data []byte, perm os.FileMode) error {
	st, err := os.Stat(dir)
	if err != nil {
		return err
	}

	if !st.IsDir() {
		return fmt.Errorf("not a directory %q", dir)
	}

	targetFilename := filepath.Join(dir, filename)
	return os.WriteFile(targetFilename, data, perm)
}

// processParamEnvToOCIEnv converts an Environment field from ProcessParameters
// (a map from environment variable to value) into an array of environment
// variable assignments (where each is in the form "<variable>=<value>") which
// can be used by an oci.Process.
func processParamEnvToOCIEnv(environment map[string]string) []string {
	environmentList := make([]string, 0, len(environment))
	for k, v := range environment {
		// TODO: Do we need to escape things like quotation marks in
		// environment variable values?
		environmentList = append(environmentList, fmt.Sprintf("%s=%s", k, v))
	}
	return environmentList
}

func (b *Bridge) startContainer(req *request) (err error) {
	_, span := oc.StartSpan(req.ctx, "sidecar::startContainer")
	defer span.End()
	defer func() { oc.SetSpanStatus(span, err) }()

	var r prot.RequestBase
	if err := commonutils.UnmarshalJSONWithHresult(req.message, &r); err != nil {
		return errors.Wrapf(err, "failed to unmarshal startContainer")
	}

	b.forwardRequestToGcs(req)
	return nil
}

func (b *Bridge) shutdownGraceful(req *request) (err error) {
	_, span := oc.StartSpan(req.ctx, "sidecar::shutdownGraceful")
	defer span.End()
	defer func() { oc.SetSpanStatus(span, err) }()

	var r prot.RequestBase
	if err := commonutils.UnmarshalJSONWithHresult(req.message, &r); err != nil {
		return errors.Wrap(err, "failed to unmarshal shutdownGraceful")
	}

	// TODO (kiashok/Mahati): Since gcs-sidecar can be used for all types of windows
	// containers, it is important to check if we want to
	// enforce policy or not.
	if b.hostState.isSecurityPolicyEnforcerInitialized() {
		b.hostState.securityPolicyEnforcer.EnforceShutdownContainerPolicy(req.ctx, r.ContainerID)
		if err != nil {
			return fmt.Errorf("shutdownGraceful operation not allowed: %v", err)
		}
	}

	b.forwardRequestToGcs(req)
	return nil
}

func (b *Bridge) shutdownForced(req *request) (err error) {
	_, span := oc.StartSpan(req.ctx, "sidecar::shutdownForced")
	defer span.End()
	defer func() { oc.SetSpanStatus(span, err) }()

	var r prot.RequestBase
	if err := commonutils.UnmarshalJSONWithHresult(req.message, &r); err != nil {
		return errors.Wrap(err, "failed to unmarshal shutdownForced")
	}

	b.forwardRequestToGcs(req)
	return nil
}

func (b *Bridge) executeProcess(req *request) (err error) {
	_, span := oc.StartSpan(req.ctx, "sidecar::executeProcess")
	defer span.End()
	defer func() { oc.SetSpanStatus(span, err) }()

	var r prot.ContainerExecuteProcess
	var processParamSettings json.RawMessage
	r.Settings.ProcessParameters.Value = &processParamSettings
	if err := commonutils.UnmarshalJSONWithHresult(req.message, &r); err != nil {
		return errors.Wrap(err, "failed to unmarshal executeProcess")
	}
	containerID := r.RequestBase.ContainerID
	var processParams hcsschema.ProcessParameters
	if err := commonutils.UnmarshalJSONWithHresult(processParamSettings, &processParams); err != nil {
		return errors.Wrap(err, "executeProcess: invalid params type for request")
	}

	if b.hostState.isSecurityPolicyEnforcerInitialized() {
		if containerID == UVMContainerID {
			_, _, err := b.hostState.securityPolicyEnforcer.EnforceExecExternalProcessPolicy(
				req.ctx,
				processParams.CommandArgs,
				processParamEnvToOCIEnv(processParams.Environment),
				processParams.WorkingDirectory,
			)
			if err != nil {
				return errors.Wrapf(err, "exec is denied due to policy")
			}
		} else {
			opts := &securitypolicy.ExecOptions{
				User: &securitypolicy.IDName{
					Name: processParams.User,
				},
			}
			_, _, _, err := b.hostState.securityPolicyEnforcer.EnforceExecInContainerPolicyV2(
				req.ctx,
				containerID,
				processParams.CommandArgs,
				processParamEnvToOCIEnv(processParams.Environment),
				processParams.WorkingDirectory,
				opts,
			)
			if err != nil {
				return errors.Wrapf(err, "exec in container denied due to policy")
			}
		}
	}

	b.forwardRequestToGcs(req)
	return nil
}

func (b *Bridge) waitForProcess(req *request) (err error) {
	_, span := oc.StartSpan(req.ctx, "sidecar::waitForProcess")
	defer span.End()
	defer func() { oc.SetSpanStatus(span, err) }()

	var r prot.ContainerWaitForProcess
	if err := commonutils.UnmarshalJSONWithHresult(req.message, &r); err != nil {
		return errors.Wrap(err, "failed to unmarshal waitForProcess")
	}

	b.forwardRequestToGcs(req)
	return nil
}

func (b *Bridge) signalProcess(req *request) (err error) {
	_, span := oc.StartSpan(req.ctx, "sidecar::signalProcess")
	defer span.End()
	defer func() { oc.SetSpanStatus(span, err) }()

	var r prot.ContainerSignalProcess
	var rawOpts json.RawMessage
	r.Options = &rawOpts
	if err := commonutils.UnmarshalJSONWithHresult(req.message, &r); err != nil {
		return errors.Wrap(err, "failed to unmarshal signalProcess")
	}
	var wcowOptions guestresource.SignalProcessOptionsWCOW
	if rawOpts != nil {
		if err := commonutils.UnmarshalJSONWithHresult(rawOpts, &wcowOptions); err != nil {
			return errors.Wrap(err, "signalProcess: invalid Options type for request")
		}
	}

	b.forwardRequestToGcs(req)
	return nil
}

func (b *Bridge) resizeConsole(req *request) (err error) {
	_, span := oc.StartSpan(req.ctx, "sidecar::resizeConsole")
	defer span.End()
	defer func() { oc.SetSpanStatus(span, err) }()

	var r prot.ContainerResizeConsole
	if err := commonutils.UnmarshalJSONWithHresult(req.message, &r); err != nil {
		return fmt.Errorf("failed to unmarshal resizeConsole: %v", req)
	}

	b.forwardRequestToGcs(req)
	return nil
}

func (b *Bridge) getProperties(req *request) (err error) {
	_, span := oc.StartSpan(req.ctx, "sidecar::getProperties")
	defer span.End()
	defer func() { oc.SetSpanStatus(span, err) }()

	if b.hostState.isSecurityPolicyEnforcerInitialized() {
		err := b.hostState.securityPolicyEnforcer.EnforceGetPropertiesPolicy(req.ctx)
		if err != nil {
			return errors.Wrapf(err, "get properties denied due to policy")
		}
	}

	var getPropReqV2 prot.ContainerGetPropertiesV2
	if err := commonutils.UnmarshalJSONWithHresult(req.message, &getPropReqV2); err != nil {
		return errors.Wrapf(err, "failed to unmarshal getProperties: %v", string(req.message))
	}
	log.G(req.ctx).Tracef("getProperties query: %v", getPropReqV2.Query.PropertyTypes)

	b.forwardRequestToGcs(req)
	return nil
}

func (b *Bridge) negotiateProtocol(req *request) (err error) {
	_, span := oc.StartSpan(req.ctx, "sidecar::negotiateProtocol")
	defer span.End()
	defer func() { oc.SetSpanStatus(span, err) }()

	var r prot.NegotiateProtocolRequest
	if err := commonutils.UnmarshalJSONWithHresult(req.message, &r); err != nil {
		return errors.Wrap(err, "failed to unmarshal negotiateProtocol")
	}

	b.forwardRequestToGcs(req)
	return nil
}

func (b *Bridge) dumpStacks(req *request) (err error) {
	_, span := oc.StartSpan(req.ctx, "sidecar::dumpStacks")
	defer span.End()
	defer func() { oc.SetSpanStatus(span, err) }()

	var r prot.DumpStacksRequest
	if err := commonutils.UnmarshalJSONWithHresult(req.message, &r); err != nil {
		return errors.Wrap(err, "failed to unmarshal dumpStacks")
	}

	b.forwardRequestToGcs(req)
	return nil
}

func (b *Bridge) deleteContainerState(req *request) (err error) {
	_, span := oc.StartSpan(req.ctx, "sidecar::deleteContainerState")
	defer span.End()
	defer func() { oc.SetSpanStatus(span, err) }()

	var r prot.DeleteContainerStateRequest
	if err := commonutils.UnmarshalJSONWithHresult(req.message, &r); err != nil {
		return errors.Wrap(err, "failed to unmarshal deleteContainerState")
	}

	b.forwardRequestToGcs(req)
	return nil
}

func (b *Bridge) updateContainer(req *request) (err error) {
	_, span := oc.StartSpan(req.ctx, "sidecar::updateContainer")
	defer span.End()
	defer func() { oc.SetSpanStatus(span, err) }()

	// No callers in the code for rpcUpdateContainer
	b.forwardRequestToGcs(req)
	return nil
}

func (b *Bridge) lifecycleNotification(req *request) (err error) {
	_, span := oc.StartSpan(req.ctx, "sidecar::lifecycleNotification")
	defer span.End()
	defer func() { oc.SetSpanStatus(span, err) }()

	// No callers in the code for rpcLifecycleNotification
	b.forwardRequestToGcs(req)
	return nil
}

func (b *Bridge) modifySettings(req *request) (err error) {
	ctx, span := oc.StartSpan(req.ctx, "sidecar::modifySettings")
	defer span.End()
	defer func() { oc.SetSpanStatus(span, err) }()

	log.G(ctx).Tracef("modifySettings: MsgType: %v, Payload: %v", req.header.Type, string(req.message))
	modifyRequest, err := unmarshalContainerModifySettings(req)
	if err != nil {
		return err
	}
	modifyGuestSettingsRequest := modifyRequest.Request.(*guestrequest.ModificationRequest)
	guestResourceType := modifyGuestSettingsRequest.ResourceType
	guestRequestType := modifyGuestSettingsRequest.RequestType
	log.G(ctx).Tracef("rpcModifySettings: resourceType: %v, requestType: %v", guestResourceType, guestRequestType)

	if guestRequestType == "" {
		guestRequestType = guestrequest.RequestTypeAdd
	}

	switch guestRequestType {
	case guestrequest.RequestTypeAdd:
	case guestrequest.RequestTypeRemove:
	case guestrequest.RequestTypePreAdd:
	case guestrequest.RequestTypeUpdate:
	default:
		return fmt.Errorf("invald guestRequestType %v", guestRequestType)
	}

	if guestResourceType != "" {
		switch guestResourceType {
		case guestresource.ResourceTypeCombinedLayers:
			settings := modifyGuestSettingsRequest.Settings.(*guestresource.WCOWCombinedLayers)
			log.G(ctx).Tracef("WCOWCombinedLayers: {%v}", settings)

		case guestresource.ResourceTypeNetworkNamespace:
			settings := modifyGuestSettingsRequest.Settings.(*hcn.HostComputeNamespace)
			log.G(ctx).Tracef("HostComputeNamespaces { %v}", settings)

		case guestresource.ResourceTypeNetwork:
			settings := modifyGuestSettingsRequest.Settings.(*guestrequest.NetworkModifyRequest)
			log.G(ctx).Tracef("NetworkModifyRequest { %v}", settings)

		case guestresource.ResourceTypeMappedVirtualDisk:
			wcowMappedVirtualDisk := modifyGuestSettingsRequest.Settings.(*guestresource.WCOWMappedVirtualDisk)
			log.G(ctx).Tracef("wcowMappedVirtualDisk { %v}", wcowMappedVirtualDisk)

		case guestresource.ResourceTypeHvSocket:
			hvSocketAddress := modifyGuestSettingsRequest.Settings.(*hcsschema.HvSocketAddress)
			log.G(ctx).Tracef("hvSocketAddress { %v }", hvSocketAddress)

		case guestresource.ResourceTypeMappedDirectory:
			settings := modifyGuestSettingsRequest.Settings.(*hcsschema.MappedDirectory)
			log.G(ctx).Tracef("hcsschema.MappedDirectory { %v }", settings)

		case guestresource.ResourceTypeSecurityPolicy:
			securityPolicyRequest := modifyGuestSettingsRequest.Settings.(*guestresource.WCOWConfidentialOptions)
			log.G(ctx).Tracef("WCOWConfidentialOptions: { %v}", securityPolicyRequest)
			err := b.hostState.SetWCOWConfidentialUVMOptions(req.ctx, securityPolicyRequest)
			if err != nil {
				return errors.Wrap(err, "error creating enforcer")
			}
			/*
				// ignore the returned err temporarily as it fails with "unknown policy rego" error
					; err != nil {
						return err
					}
			*/
			// Send response back to shim
			resp := &prot.ResponseBase{
				Result:     0, // 0 means success
				ActivityID: req.activityID,
			}
			err = b.sendResponseToShim(req.ctx, prot.RpcModifySettings, req.header.ID, resp)
			if err != nil {
				return errors.Wrap(err, "error sending response to hcsshim")
			}
			return nil

		case guestresource.ResourceTypeWCOWBlockCims:
			// This is request to mount the merged cim at given volumeGUID
			wcowBlockCimMounts := modifyGuestSettingsRequest.Settings.(*guestresource.WCOWBlockCIMMounts)
			containerID := wcowBlockCimMounts.ContainerID
			log.G(ctx).Tracef("WCOWBlockCIMMounts { %v}", wcowBlockCimMounts)

			// The block device takes some time to show up. Wait for a few seconds.
			time.Sleep(6 * time.Second)

			var layerCIMs []*cimfs.BlockCIM
			layerHashes := make([]string, len(wcowBlockCimMounts.BlockCIMs))
			ctx := req.ctx
			for i, blockCimDevice := range wcowBlockCimMounts.BlockCIMs {
				// Get the scsi device path for the blockCim lun
				/*scsiDevPath*/
				_, diskNumber, err := windevice.GetScsiDevicePathAndDiskNumberFromControllerLUN(
					ctx,
					0, /* controller is always 0 for wcow */
					uint8(blockCimDevice.Lun))
				if err != nil {
					return errors.Wrap(err, "err getting scsiDevPath")
				}
				physicalDevPath := fmt.Sprintf("\\\\.\\PHYSICALDRIVE%d", diskNumber)
				layerCim := cimfs.BlockCIM{
					Type:      cimfs.BlockCIMTypeDevice,
					BlockPath: physicalDevPath,
					CimName:   blockCimDevice.CimName,
				}
				layerCIMs = append(layerCIMs, &layerCim)
				log.G(ctx).Debugf("block CIM layer digest %s, path: %s\n", blockCimDevice.Digest, physicalDevPath)
				layerHashes[i] = blockCimDevice.Digest
			}

			// skip the merged cim and verify individual layer hashes
			hashesToVerify := layerHashes
			if len(layerHashes) > 1 {
				hashesToVerify = layerHashes[1:]
			}

			err := b.hostState.securityPolicyEnforcer.EnforceVerifiedCIMsPolicy(req.ctx, containerID, hashesToVerify)
			if err != nil {
				return errors.Wrap(err, "CIM mount is denied by policy")
			}

			if len(layerCIMs) > 1 {
				// Get the topmost merge CIM and invoke the MountMergedBlockCIMs
				_, err := cimfs.MountMergedBlockCIMs(layerCIMs[0], layerCIMs[1:], wcowBlockCimMounts.MountFlags, wcowBlockCimMounts.VolumeGuid)
				if err != nil {
					return errors.Wrap(err, "error mounting multilayer merged block cims")
				}
			} else {
				_, err := cimfs.Mount(filepath.Join(layerCIMs[0].BlockPath, layerCIMs[0].CimName), wcowBlockCimMounts.VolumeGuid, wcowBlockCimMounts.MountFlags)
				if err != nil {
					return errors.Wrap(err, "error mounting merged block cims")
				}
			}

			// Send response back to shim
			resp := &prot.ResponseBase{
				Result:     0, // 0 means success
				ActivityID: req.activityID,
			}
			err = b.sendResponseToShim(req.ctx, prot.RpcModifySettings, req.header.ID, resp)
			if err != nil {
				return errors.Wrap(err, "error sending response to hcsshim")
			}
			return nil

		case guestresource.ResourceTypeCWCOWCombinedLayers:
			settings := modifyGuestSettingsRequest.Settings.(*guestresource.CWCOWCombinedLayers)
			containerID := settings.ContainerID
			log.G(ctx).Tracef("CWCOWCombinedLayers:: ContainerID: %v, ContainerRootPath: %v, Layers: %v, ScratchPath: %v",
				containerID, settings.CombinedLayers.ContainerRootPath, settings.CombinedLayers.Layers, settings.CombinedLayers.ScratchPath)

			// check that this is not denied by policy
			// TODO: modify gcs-sidecar code to pass context across all calls
			// TODO: Update modifyCombinedLayers with verified CimFS API
			if b.hostState.isSecurityPolicyEnforcerInitialized() {
				policy_err := modifyCombinedLayers(req.ctx, containerID, guestRequestType, settings.CombinedLayers, b.hostState.securityPolicyEnforcer)
				if policy_err != nil {
					return errors.Wrapf(policy_err, "CimFS layer mount is denied by policy: %v", settings)
				}
			}

			// TODO: Update modifyCombinedLayers with verified CimFS API

			// The following two folders are expected to be present in the scratch.
			// But since we have just formatted the scratch we would need to
			// create them manually.
			sandboxStateDirectory := filepath.Join(settings.CombinedLayers.ContainerRootPath, sandboxStateDirName)
			err = os.Mkdir(sandboxStateDirectory, 0777)
			if err != nil {
				return errors.Wrap(err, "failed to create sandboxStateDirectory")
			}

			hivesDirectory := filepath.Join(settings.CombinedLayers.ContainerRootPath, hivesDirName)
			err = os.Mkdir(hivesDirectory, 0777)
			if err != nil {
				return errors.Wrap(err, "failed to create hivesDirectory")
			}

			// Reconstruct WCOWCombinedLayers{} req before forwarding to GCS
			// as GCS does not understand ResourceTypeCWCOWCombinedLayers
			modifyGuestSettingsRequest.ResourceType = guestresource.ResourceTypeCombinedLayers
			modifyGuestSettingsRequest.Settings = settings.CombinedLayers
			modifyRequest.Request = modifyGuestSettingsRequest
			buf, err := json.Marshal(modifyRequest)
			if err != nil {
				return errors.Wrap(err, "failed to marshal rpcModifySettings")
			}
			var newRequest request
			newRequest.ctx = req.ctx
			newRequest.header = req.header
			newRequest.header.Size = uint32(len(buf)) + prot.HdrSize
			newRequest.message = buf
			req = &newRequest

		case guestresource.ResourceTypeMappedVirtualDiskForContainerScratch:
			wcowMappedVirtualDisk := modifyGuestSettingsRequest.Settings.(*guestresource.WCOWMappedVirtualDisk)
			log.G(ctx).Tracef("ResourceTypeMappedVirtualDiskForContainerScratch: { %v }", wcowMappedVirtualDisk)

			// 1. TODO (Mahati): Need to enforce policy before calling into fsFormatter
			// 2. Call fsFormatter to format the scratch disk.
			// This will return the volume path of the mounted scratch.
			// Scratch disk should be >= 30 GB for refs formatter to work.

			// fsFormatter understands only virtualDevObjectPathFormat. Therefore fetch the
			// disk number for the corresponding lun
			var diskNumber uint64
			// It could take a few seconds for the attached scsi disk
			// to show up inside the UVM. Therefore adding retry logic
			// with delay here.
			for try := 0; try < 5; try++ {
				time.Sleep(1 * time.Second)
				_, diskNumber, err = windevice.GetScsiDevicePathAndDiskNumberFromControllerLUN(req.ctx,
					0, /* Only one controller allowed in wcow hyperv */
					uint8(wcowMappedVirtualDisk.Lun))
				if err != nil {
					if try == 4 {
						// bail out
						return errors.Wrapf(err, "error getting diskNumber for LUN %d", wcowMappedVirtualDisk.Lun)
					}
					continue
				} else {
					log.G(ctx).Tracef("DiskNumber of lun %d is:  %d", wcowMappedVirtualDisk.Lun, diskNumber)
					break
				}
			}
			diskPath := fmt.Sprintf(fsformatter.VirtualDevObjectPathFormat, diskNumber)
			log.G(ctx).Tracef("diskPath: %v, diskNumber: %v ", diskPath, diskNumber)
			mountedVolumePath, err := fsformatter.InvokeFsFormatter(req.ctx, diskPath)
			if err != nil {
				return errors.Wrap(err, "failed to invoke refsFormatter")
			}
			log.G(ctx).Tracef("mountedVolumePath returned from InvokeFsFormatter: %v", mountedVolumePath)

			// Forward the req as is to inbox gcs and let it retreive the volume.
			// While forwarding request to inbox gcs, make sure to replace the
			// resourceType to ResourceTypeMappedVirtualDisk that inbox GCS
			// understands.
			modifyGuestSettingsRequest.ResourceType = guestresource.ResourceTypeMappedVirtualDisk
			modifyRequest.Request = modifyGuestSettingsRequest
			buf, err := json.Marshal(modifyRequest)
			if err != nil {
				return errors.Wrap(err, "failed to marshal WCOWMappedVirtualDisk")
			}
			var newRequest request
			newRequest.ctx = req.ctx
			newRequest.header = req.header
			newRequest.header.Size = uint32(len(buf)) + prot.HdrSize
			newRequest.message = buf
			req = &newRequest

		default:
			// Invalid request
			return fmt.Errorf("invald modifySettingsRequest: %v", guestResourceType)
		}
	}

	b.forwardRequestToGcs(req)
	return nil
}
