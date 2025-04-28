//go:build windows
// +build windows

package bridge

import (
	"context"
	"fmt"
	"sync"

	"github.com/Microsoft/hcsshim/internal/cow"
	"github.com/Microsoft/hcsshim/internal/log"
	"github.com/Microsoft/hcsshim/internal/protocol/guestresource"
	"github.com/Microsoft/hcsshim/internal/pspdriver"
	"github.com/Microsoft/hcsshim/pkg/securitypolicy"
	"github.com/pkg/errors"
)

type Host struct {
	containersMutex sync.Mutex
	containers      map[string]cow.Container

	// state required for the security policy enforcement
	policyMutex               sync.Mutex
	securityPolicyEnforcer    securitypolicy.SecurityPolicyEnforcer
	securityPolicyEnforcerSet bool
	uvmReferenceInfo          string
}

type SecurityPoliyEnforcer struct {
	// State required for the security policy enforcement
	policyMutex               sync.Mutex
	securityPolicyEnforcer    securitypolicy.SecurityPolicyEnforcer
	securityPolicyEnforcerSet bool
	uvmReferenceInfo          string
}

func NewHost(initialEnforcer securitypolicy.SecurityPolicyEnforcer) *Host {
	return &Host{
		securityPolicyEnforcer:    initialEnforcer,
		securityPolicyEnforcerSet: false,
	}
}

func (h *Host) isSecurityPolicyEnforcerInitialized() bool {
	return h.securityPolicyEnforcer != nil
}

func (h *Host) SetWCOWConfidentialUVMOptions(ctx context.Context, securityPolicyRequest *guestresource.WCOWConfidentialOptions) error {
	h.policyMutex.Lock()
	defer h.policyMutex.Unlock()

	if h.securityPolicyEnforcerSet {
		return errors.New("security policy has already been set")
	}

	log.G(ctx).Tracef("NoSecurtyHardware annotation: %v", securityPolicyRequest.NoSecurityHardware)
	if securityPolicyRequest.NoSecurityHardware {
		// start the psp driver
		if err := pspdriver.StartPSPDriver(ctx); err != nil {
			// failed to start psp driver, return prematurely
			return errors.Wrapf(err, "failed to start PSP driver")
		}
	} else {
		// TODO: Check if this is an SNP enabled VM.
		log.G(ctx).Tracef("TODO: Check if this is an SNO enabled VM before loading the PSP driver")
	}

	// This limit ensures messages are below the character truncation limit that
	// can be imposed by an orchestrator
	maxErrorMessageLength := 3 * 1024

	// Initialize security policy enforcer for a given enforcer type and
	// encoded security policy.
	p, err := securitypolicy.CreateSecurityPolicyEnforcer(
		"rego",
		securityPolicyRequest.EncodedSecurityPolicy,
		DefaultCRIMounts(),
		DefaultCRIPrivilegedMounts(),
		maxErrorMessageLength,
	)
	if err != nil {
		return fmt.Errorf("error creating security policy enforcer: %v", err)
	}

	h.securityPolicyEnforcer = p
	h.securityPolicyEnforcerSet = true

	return nil
}
