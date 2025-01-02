//go:build windows
// +build windows

package bridge

import (
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/Microsoft/go-winio/pkg/guid"
	"github.com/Microsoft/hcsshim/cmd/gcs-sidecar/windowssecuritypolicy"
)

/*
	b.HandleFunc(rpcCreate, createContainer)
	b.HandleFunc(rpcStart, startContainer)
	b.HandleFunc(rpcShutdownGraceful, shutdownGraceful)
	b.HandleFunc(rpcShutdownForced, shutdownForced)
	b.HandleFunc(rpcExecuteProcess, createProcess)
	b.HandleFunc(rpcWaitForProcess, waitForProcess)
	b.HandleFunc(rpcSignalProcess, signalProcess)
	b.HandleFunc(rpcResizeConsole, resizeConsole)
	b.HandleFunc(rpcGetProperties, getProperties)
	b.HandleFunc(rpcModifySettings, modifySettings) // This will have the max request types to be validated like mounting container layers, data volumes etc
	b.HandleFunc(rpcNegotiateProtocol, negotiateProtocol)
	b.HandleFunc(rpcDumpStacks, dumpStacks)
	b.HandleFunc(rpcDeleteContainerState, deleteContainerState)
	b.HandleFunc(rpcUpdateContainer, updateContainer)
	b.HandleFunc(rpcLifecycleNotification, lifecycleNotification)
*/

// Current intent of these handler functions is to call the security policy
// enforcement code as needed and return nil if the operation is allowed.
// Else error is returned.
// Also, currently, the caller of this function is forwarding the request
// to inbox GCS if handler returns nil. This is because we want to process
// response from inbox GCS asynchronously.
// TODO: The caller, that is hcsshim, starts a 30 second timer and if response
// is not got by then, bridge is killed. Should we track responses from gcs by
// time in sidecar too? Maybe not.
func (b *Bridge) createContainer(req *request) error {
	// Do something
	/*
		err = securityPolicyEnforcer.EnforceShutdownContainerPolicy(ctx, containerID)
		if err != nil {
			return _, err
		}
	*/
	return nil
}

func (b *Bridge) startContainer(req *request) error {
	// Do something
	return nil
}

func (b *Bridge) shutdownGraceful(req *request) error {
	// Do something
	return nil
}

func (b *Bridge) shutdownForced(req *request) error {
	// Do something
	return nil
}

func (b *Bridge) createProcess(req *request) error {
	// Do something
	return nil
}

func (b *Bridge) waitForProcess(req *request) error {
	// Do something
	return nil
}

func (b *Bridge) signalProcess(req *request) error {
	// Do something
	return nil
}

func (b *Bridge) resizeConsole(req *request) error {
	// Do something
	return nil
}

func (b *Bridge) getProperties(req *request) error {
	// Do something
	return nil
}

func (b *Bridge) modifySettings(req *request) error {
	// Do something
	// Dereference the message payload
	switch rpcProc(req.typ &^ msgTypeMask) {

	}
	return nil
}

func (b *Bridge) sendMessage(typ msgType, id int64, msg []byte) {
	var h [hdrSize]byte
	binary.LittleEndian.PutUint32(h[:], uint32(typ))
	binary.LittleEndian.PutUint32(h[4:], uint32(len(msg)+16))
	binary.LittleEndian.PutUint64(h[8:], uint64(id))

	b.sendToShimCh <- request{
		header:  h,
		message: msg,
	}
	// time.Sleep(2 * time.Second)
}

func testEnforcer(expectedReturn bool) bool {
	return expectedReturn
}

func (b *Bridge) negotiateProtocol(req *request) error {
	// Do something
	expectedReturn := true
	// TESTING ONLY: being used to test err case during dev
	if testEnforcer(expectedReturn) {
		return nil
	} else {
		respType := msgTypeResponse | msgType(rpcNegotiateProtocol)
		activityID, _ := guid.FromString(req.activityID)
		resp := &negotiateProtocolResponse{
			responseBase: responseBase{
				Result:       1,
				ErrorMessage: fmt.Sprintf("Request %v not allowed", req.typ.String()),
				ActivityID:   activityID,
			},
		}
		msgb, err := json.Marshal(resp)
		if err != nil {
			return err
		}
		b.sendMessage(respType, req.id, msgb)

		return fmt.Errorf("request %v not allowed", req.typ.String())
	}
}

func (b *Bridge) SetConfidentialUVMOptions(r *WCOWConfidentialOptions) error {
	/*
	b.policyMutex.Lock()
	defer b.policyMutex.Unlock()
	if b.securityPolicyEnforcerSet {
		return errors.New("security policy has already been set")
	}
		*/
	// this limit ensures messages are below the character truncation limit that
	// can be imposed by an orchestrator
	maxErrorMessageLength := 3 * 1024

	// Initialize security policy enforcer for a given enforcer type and
	// encoded security policy.
	_, err := windowssecuritypolicy.CreateSecurityPolicyEnforcer(
		r.EnforcerType,
		r.EncodedSecurityPolicy,
		DefaultCRIMounts(),
		DefaultCRIPrivilegedMounts(),
		maxErrorMessageLength,
	)
	if err != nil {
		return err
	}

	// This is one of two points at which we might change our logging.
	// At this time, we now have a policy and can determine what the policy
	// author put as policy around runtime logging.
	// The other point is on startup where we take a flag to set the default
	// policy enforcer to use before a policy arrives. After that flag is set,
	// we use the enforcer in question to set up logging as well.
	/*if err = p.EnforceRuntimeLoggingPolicy(ctx); err == nil {
		//logrus.SetOutput(h.logWriter)
	} else {
		//logrus.SetOutput(io.Discard)
	}

	hostData, err := securitypolicy.NewSecurityPolicyDigest(r.EncodedSecurityPolicy)
	if err != nil {
		return err
	}*/
/*
	if err := validateHostData(hostData[:]); err != nil {
		return err
	}

	b.securityPolicyEnforcer = p
	b.securityPolicyEnforcerSet = true
	b.uvmReferenceInfo = r.EncodedUVMReference
*/
	return nil
}

func (b *Bridge) dumpStacks(req *request) error {
	// Do something
	return nil
}

func (b *Bridge) deleteContainerState(req *request) error {
	// Do something
	return nil
}

func (b *Bridge) updateContainer(req *request) error {
	// Do something
	return nil
}

func (b *Bridge) lifecycleNotification(req *request) error {
	// Do something
	return nil
}
