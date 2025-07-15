//go:build windows
// +build windows

package securitypolicy

import (
	"context"
	_ "embed"
	"fmt"
	"math/rand"
	"os"
	"testing"
	"testing/quick"

	oci "github.com/opencontainers/runtime-spec/specs-go"
)

const testOSType = "windows"

func Test_Rego_EnforceCreateContainer_Windows(t *testing.T) {
	f := func(p *generatedWindowsConstraints) bool {
		t.Logf("Testing with %d containers", len(p.containers))
		tc, err := setupSimpleRegoCreateContainerTestWindows(p)
		if err != nil {
			t.Errorf("Setup failed: %v", err)
			return false
		}

		t.Logf("Selected container ID: %s", tc.containerID)
		t.Logf("User config: %+v", tc.user)

		os.WriteFile("expected-policy.json", []byte(p.toPolicy().marshalWindowsRego()), 0644)

		_, _, _, err = tc.policy.EnforceCreateContainerPolicyV2(p.ctx, tc.containerID, tc.argList, tc.envList, tc.workingDir, tc.mounts, tc.user, nil)

		if err != nil {
			t.Errorf("Policy enforcement failed: %v", err)
		}
		// getting an error means something is broken
		return err == nil
	}

	if err := quick.Check(f, &quick.Config{MaxCount: 1, Rand: testRand}); err != nil {
		t.Errorf("Test_Rego_EnforceCreateContainer: %v", err)
	}
}

func Test_Rego_EnforceCommandPolicy_NoMatches_Windows(t *testing.T) {
	f := func(p *generatedWindowsConstraints) bool {
		tc, err := setupSimpleRegoCreateContainerTestWindows(p)
		if err != nil {
			t.Error(err)
			return false
		}

		//_, _, _, err = tc.policy.EnforceCreateContainerPolicy(p.ctx, tc.sandboxID, tc.containerID, generateCommand(testRand), tc.envList, tc.workingDir, tc.mounts, false, tc.noNewPrivileges, tc.user, tc.groups, tc.umask, tc.capabilities, tc.seccomp)

		_, _, _, err = tc.policy.EnforceCreateContainerPolicyV2(p.ctx, tc.containerID, generateCommand(testRand), tc.envList, tc.workingDir, tc.mounts, tc.user, nil)

		if err == nil {
			return false
		}

		t.Logf("Error value: %v", err)

		return assertDecisionJSONContains(t, err, "invalid command")
	}

	if err := quick.Check(f, &quick.Config{MaxCount: 50, Rand: testRand}); err != nil {
		t.Errorf("Test_EnforceCommandPolicy_NoMatches: %v", err)
	}
}

func Test_Rego_EnforceEnvironmentVariablePolicy_Re2Match_Windows(t *testing.T) {
	testFunc := func(gc *generatedWindowsConstraints) bool {
		container := selectWindowsContainerFromContainerList(gc.containers, testRand)
		// add a rule to re2 match
		re2MatchRule := EnvRuleConfig{
			Strategy: EnvVarRuleRegex,
			Rule:     "PREFIX_.+=.+",
		}

		container.EnvRules = append(container.EnvRules, re2MatchRule)

		tc, err := setupRegoCreateContainerTestWindows(gc, container, false)
		if err != nil {
			t.Error(err)
			return false
		}

		envList := append(tc.envList, "PREFIX_FOO=BAR")

		_, _, _, err = tc.policy.EnforceCreateContainerPolicyV2(gc.ctx, tc.containerID, tc.argList, envList, tc.workingDir, tc.mounts, tc.user, nil)

		// getting an error means something is broken
		if err != nil {
			t.Errorf("Expected container setup to be allowed. It wasn't: %v", err)
			return false
		}

		return true
	}

	if err := quick.Check(testFunc, &quick.Config{MaxCount: 50, Rand: testRand}); err != nil {
		t.Errorf("Test_Rego_EnforceEnvironmentVariablePolicy_Re2Match: %v", err)
	}
}

func Test_Rego_EnforceEnvironmentVariablePolicy_NotAllMatches_Windows(t *testing.T) {
	f := func(p *generatedWindowsConstraints) bool {
		tc, err := setupSimpleRegoCreateContainerTestWindows(p)
		if err != nil {
			t.Error(err)
			return false
		}

		envList := append(tc.envList, generateNeverMatchingEnvironmentVariable(testRand))

		_, _, _, err = tc.policy.EnforceCreateContainerPolicyV2(p.ctx, tc.containerID, tc.argList, envList, tc.workingDir, tc.mounts, tc.user, nil)

		// not getting an error means something is broken
		if err == nil {
			return false
		}

		return assertDecisionJSONContains(t, err, "invalid env list", envList[0])
	}

	if err := quick.Check(f, &quick.Config{MaxCount: 50, Rand: testRand}); err != nil {
		t.Errorf("Test_Rego_EnforceEnvironmentVariablePolicy_NotAllMatches: %v", err)
	}
}

// Windows-specific container selection function
func selectWindowsContainerFromContainerList(containers []*securityPolicyWindowsContainer, r *rand.Rand) *securityPolicyWindowsContainer {
	return containers[r.Intn(len(containers))]
}

// Windows-specific simple setup function
func setupSimpleRegoCreateContainerTestWindows(gc *generatedWindowsConstraints) (tc *regoContainerTestConfig, err error) {
	c := selectWindowsContainerFromContainerList(gc.containers, testRand)
	return setupRegoCreateContainerTestWindows(gc, c, false)
}

// Windows-specific container test setup
func setupRegoCreateContainerTestWindows(gc *generatedWindowsConstraints, testContainer *securityPolicyWindowsContainer, privilegedError bool) (tc *regoContainerTestConfig, err error) {
	securityPolicy := gc.toPolicy()
	defaultMounts := generateMounts(testRand)
	privilegedMounts := generateMounts(testRand)

	policy, err := newRegoPolicy(securityPolicy.marshalWindowsRego(),
		toOCIMounts(defaultMounts),
		toOCIMounts(privilegedMounts),
		testOSType)
	if err != nil {
		return nil, err
	}

	// Debug: print the OS type being used
	//fmt.Printf("OS type being used: %s\n", testOSType)

	// Debug: print the generated Rego policy
	//fmt.Printf("Generated Rego policy:\n%s\n", securityPolicy.marshalWindowsRego())

	containerID, err := mountImageForWindowsContainer(policy, testContainer)
	if err != nil {
		return nil, err
	}

	envList := buildEnvironmentVariablesFromEnvRules(testContainer.EnvRules, testRand)
	sandboxID := testDataGenerator.uniqueSandboxID()

	// Handle Windows user configuration
	user := IDName{}
	if testContainer.User != "" {
		user = IDName{Name: testContainer.User}
	} else {
		user = IDName{Name: generateIDNameName(testRand)}
	}

	return &regoContainerTestConfig{
		envList:         copyStrings(envList),
		argList:         copyStrings(testContainer.Command),
		workingDir:      testContainer.WorkingDir,
		containerID:     containerID,
		sandboxID:       sandboxID,
		mounts:          []oci.Mount{},
		noNewPrivileges: false,
		user:            user,
		groups:          []IDName{},
		umask:           "",
		capabilities:    nil,
		seccomp:         "",
		policy:          policy,
		ctx:             gc.ctx,
	}, nil
}

//nolint:unused
func mountImageForWindowsContainer(policy *regoEnforcer, container *securityPolicyWindowsContainer) (string, error) {
	ctx := context.Background()
	containerID := testDataGenerator.uniqueContainerID()

	// For Windows containers, we need to mount using CIMFS (container image mount)
	// The layerHashes_ok function expects hashes in reverse order compared to how they're stored
	layerHashes := make([]string, len(container.Layers))
	for i, layer := range container.Layers {
		// Reverse the order: last layer becomes first in the input
		layerHashes[len(container.Layers)-1-i] = layer
	}

	// Mount the CIMFS for the Windows container
	err := policy.EnforceVerifiedCIMsPolicy(ctx, containerID, layerHashes)
	if err != nil {
		return "", fmt.Errorf("error mounting CIMFS: %w", err)
	}

	//fmt.Printf("CIMFS mounted successfully for container %s with layers %v\n", containerID, layerHashes)

	return containerID, nil
}
