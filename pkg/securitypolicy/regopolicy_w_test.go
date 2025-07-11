//go:build windows
// +build windows

package securitypolicy

import (
	"context"
	_ "embed"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"testing/quick"

	"github.com/open-policy-agent/opa/rego"
)

func Test_RegoTemplates_W(t *testing.T) {
	query := rego.New(
		rego.Query("data.api"),
		rego.Module("api.rego", APICode))

	ctx := context.Background()
	resultSet, err := query.Eval(ctx)
	if err != nil {
		t.Fatalf("unable to query API enforcement points: %s", err)
	}

	apiRules := resultSet[0].Expressions[0].Value.(map[string]interface{})
	enforcementPoints := apiRules["enforcement_points"].(map[string]interface{})

	policyCode := strings.Replace(policyRegoTemplate, "@@OBJECTS@@", "", 1)
	policyCode = strings.Replace(policyCode, "@@API_VERSION@@", apiVersion, 1)
	policyCode = strings.Replace(policyCode, "@@FRAMEWORK_VERSION@@", frameworkVersion, 1)

	err = verifyPolicyRules(apiVersion, enforcementPoints, policyCode)
	if err != nil {
		t.Errorf("Policy Rego Template is invalid: %s", err)
	}

	err = verifyPolicyRules(apiVersion, enforcementPoints, openDoorRego)
	if err != nil {
		t.Errorf("Open Door Rego Template is invalid: %s", err)
	}
}

func Test_MarshalRego_Policy_W(t *testing.T) {
	f := func(p *generatedConstraints) bool {
		p.externalProcesses = generateExternalProcesses(testRand)
		for _, process := range p.externalProcesses {
			// arbitrary environment variable rules for external
			// processes are not currently handled by the config.
			process.envRules = []EnvRuleConfig{{
				Strategy: "string",
				Rule:     "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
				Required: true,
			}}
		}

		p.fragments = generateFragments(testRand, 1)

		securityPolicy := p.toPolicy()
		defaultMounts := toOCIMounts(generateMounts(testRand))
		privilegedMounts := toOCIMounts(generateMounts(testRand))

		expected := securityPolicy.marshalRego()

		containers := make([]*Container, len(p.containers))
		for i, container := range p.containers {
			containers[i] = container.toContainer()
		}

		externalProcesses := make([]ExternalProcessConfig, len(p.externalProcesses))
		for i, process := range p.externalProcesses {
			externalProcesses[i] = process.toConfig()
		}

		fragments := make([]FragmentConfig, len(p.fragments))
		for i, fragment := range p.fragments {
			fragments[i] = fragment.toConfig()
		}

		actual, err := MarshalPolicy(
			"rego",
			false,
			containers,
			externalProcesses,
			fragments,
			p.allowGetProperties,
			p.allowDumpStacks,
			p.allowRuntimeLogging,
			p.allowEnvironmentVariableDropping,
			p.allowUnencryptedScratch,
			p.allowCapabilityDropping,
		)
		if err != nil {
			t.Error(err)
			return false
		}

		if actual != expected {
			start := -1
			end := -1
			for i := 0; i < len(actual) && i < len(expected); i++ {
				if actual[i] != expected[i] {
					if start == -1 {
						start = i
					} else if i-start >= maxDiffLength {
						end = i
						break
					}
				} else if start != -1 {
					end = i
					break
				}
			}
			start = start - 512
			if start < 0 {
				start = 0
			}
			t.Errorf(`MarshalPolicy does not create the expected Rego policy [%d-%d]: "%s" != "%s"`, start, end, actual[start:end], expected[start:end])
			return false
		}

		//fmt.Printf("expected policy: %v", expected)
		os.WriteFile("expected-output.txt", []byte(expected), 0644)

		_, err = newRegoPolicy(expected, defaultMounts, privilegedMounts, osType)

		if err != nil {
			t.Errorf("unable to convert policy to rego: %v", err)
			return false
		}

		return true
	}

	if err := quick.Check(f, &quick.Config{MaxCount: 4, Rand: testRand}); err != nil {
		t.Errorf("Test_MarshalRego_Policy failed: %v", err)
	}
}

func Test_MarshalRego_Fragment_W(t *testing.T) {
	f := func(p *generatedConstraints) bool {
		p.externalProcesses = generateExternalProcesses(testRand)
		for _, process := range p.externalProcesses {
			// arbitrary environment variable rules for external
			// processes are not currently handled by the config.
			process.envRules = []EnvRuleConfig{{
				Strategy: "string",
				Rule:     "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
				Required: true,
			}}
		}

		p.fragments = generateFragments(testRand, 1)

		fragment := p.toFragment()
		expected := fragment.marshalRego()

		containers := make([]*Container, len(p.containers))
		for i, container := range p.containers {
			containers[i] = container.toContainer()
		}

		externalProcesses := make([]ExternalProcessConfig, len(p.externalProcesses))
		for i, process := range p.externalProcesses {
			externalProcesses[i] = process.toConfig()
		}

		fragments := make([]FragmentConfig, len(p.fragments))
		for i, fragment := range p.fragments {
			fragments[i] = fragment.toConfig()
		}

		actual, err := MarshalFragment(p.namespace, p.svn, containers, externalProcesses, fragments)
		if err != nil {
			t.Error(err)
			return false
		}

		if actual != expected {
			start := -1
			end := -1
			for i := 0; i < len(actual) && i < len(expected); i++ {
				if actual[i] != expected[i] {
					if start == -1 {
						start = i
					} else if i-start >= maxDiffLength {
						end = i
						break
					}
				} else if start != -1 {
					end = i
					break
				}
			}
			t.Errorf("MarshalFragment does not create the expected Rego fragment [%d-%d]: %s != %s", start, end, actual[start:end], expected[start:end])
			return false
		}

		return true
	}

	if err := quick.Check(f, &quick.Config{MaxCount: 4, Rand: testRand}); err != nil {
		t.Errorf("Test_MarshalRego_Fragment failed: %v", err)
	}
}

func Test_Rego_EnforceCommandPolicy_NoMatches_W(t *testing.T) {
	f := func(p *generatedConstraints) bool {
		tc, err := setupSimpleRegoCreateContainerTest(p)
		if err != nil {
			t.Error(err)
			return false
		}

		_, _, _, err = tc.policy.EnforceCreateContainerPolicy(p.ctx, tc.sandboxID, tc.containerID, generateCommand(testRand), tc.envList, tc.workingDir, tc.mounts, false, tc.noNewPrivileges, tc.user, tc.groups, tc.umask, tc.capabilities, tc.seccomp)

		if err == nil {
			return false
		}

		return assertDecisionJSONContains(t, err, "invalid command")
	}

	if err := quick.Check(f, &quick.Config{MaxCount: 50, Rand: testRand}); err != nil {
		t.Errorf("Test_EnforceCommandPolicy_NoMatches: %v", err)
	}
}

func Test_Rego_EnforceEnvironmentVariablePolicy_Re2Match_W(t *testing.T) {
	testFunc := func(gc *generatedConstraints) bool {
		container := selectContainerFromContainerList(gc.containers, testRand)
		// add a rule to re2 match
		re2MatchRule := EnvRuleConfig{
			Strategy: EnvVarRuleRegex,
			Rule:     "PREFIX_.+=.+",
		}

		container.EnvRules = append(container.EnvRules, re2MatchRule)

		tc, err := setupRegoCreateContainerTest(gc, container, false)
		if err != nil {
			t.Error(err)
			return false
		}

		envList := append(tc.envList, "PREFIX_FOO=BAR")
		_, _, _, err = tc.policy.EnforceCreateContainerPolicy(gc.ctx, tc.sandboxID, tc.containerID, tc.argList, envList, tc.workingDir, tc.mounts, false, tc.noNewPrivileges, tc.user, tc.groups, tc.umask, tc.capabilities, tc.seccomp)

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

func Test_Rego_EnforceEnvironmentVariablePolicy_NotAllMatches_W(t *testing.T) {
	f := func(p *generatedConstraints) bool {
		tc, err := setupSimpleRegoCreateContainerTest(p)
		if err != nil {
			t.Error(err)
			return false
		}

		envList := append(tc.envList, generateNeverMatchingEnvironmentVariable(testRand))
		_, _, _, err = tc.policy.EnforceCreateContainerPolicy(p.ctx, tc.sandboxID, tc.containerID, tc.argList, envList, tc.workingDir, tc.mounts, false, tc.noNewPrivileges, tc.user, tc.groups, tc.umask, tc.capabilities, tc.seccomp)

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

func Test_Rego_EnforceEnvironmentVariablePolicy_DropEnvs_W(t *testing.T) {
	testFunc := func(gc *generatedConstraints) bool {
		gc.allowEnvironmentVariableDropping = true
		container := selectContainerFromContainerList(gc.containers, testRand)

		tc, err := setupRegoCreateContainerTest(gc, container, false)
		if err != nil {
			t.Error(err)
			return false
		}

		extraRules := generateEnvironmentVariableRules(testRand)
		extraEnvs := buildEnvironmentVariablesFromEnvRules(extraRules, testRand)

		envList := append(tc.envList, extraEnvs...)
		actual, _, _, err := tc.policy.EnforceCreateContainerPolicy(gc.ctx, tc.sandboxID, tc.containerID, tc.argList, envList, tc.workingDir, tc.mounts, false, tc.noNewPrivileges, tc.user, tc.groups, tc.umask, tc.capabilities, tc.seccomp)

		// getting an error means something is broken
		if err != nil {
			t.Errorf("Expected container creation to be allowed. It wasn't: %v", err)
			return false
		}

		if !areStringArraysEqual(actual, tc.envList) {
			t.Errorf("environment variables were not dropped correctly.")
			return false
		}

		return true
	}

	if err := quick.Check(testFunc, &quick.Config{MaxCount: 50, Rand: testRand}); err != nil {
		t.Errorf("Test_Rego_EnforceEnvironmentVariablePolicy_DropEnvs: %v", err)
	}
}

func Test_Rego_EnforceEnvironmentVariablePolicy_DropEnvs_Multiple_W(t *testing.T) {
	tc, err := setupRegoDropEnvsTest(false)
	if err != nil {
		t.Fatalf("error setting up test: %v", err)
	}

	extraRules := generateEnvironmentVariableRules(testRand)
	extraEnvs := buildEnvironmentVariablesFromEnvRules(extraRules, testRand)

	envList := append(tc.envList, extraEnvs...)
	actual, _, _, err := tc.policy.EnforceCreateContainerPolicy(tc.ctx, tc.sandboxID, tc.containerID, tc.argList, envList, tc.workingDir, tc.mounts, false, tc.noNewPrivileges, tc.user, tc.groups, tc.umask, tc.capabilities, tc.seccomp)

	// getting an error means something is broken
	if err != nil {
		t.Errorf("Expected container creation to be allowed. It wasn't: %v", err)
	}

	if !areStringArraysEqual(actual, tc.envList) {
		t.Error("environment variables were not dropped correctly.")
	}
}

func Test_Rego_EnforceEnvironmentVariablePolicy_DropEnvs_Multiple_NoMatch_W(t *testing.T) {
	tc, err := setupRegoDropEnvsTest(true)
	if err != nil {
		t.Fatalf("error setting up test: %v", err)
	}

	extraRules := generateEnvironmentVariableRules(testRand)
	extraEnvs := buildEnvironmentVariablesFromEnvRules(extraRules, testRand)

	envList := append(tc.envList, extraEnvs...)
	actual, _, _, err := tc.policy.EnforceCreateContainerPolicy(tc.ctx, tc.sandboxID, tc.containerID, tc.argList, envList, tc.workingDir, tc.mounts, false, tc.noNewPrivileges, tc.user, tc.groups, tc.umask, tc.capabilities, tc.seccomp)

	// not getting an error means something is broken
	if err == nil {
		t.Error("expected container creation not to be allowed.")
	}

	if actual != nil {
		t.Error("envList should be nil")
	}
}

func Test_Rego_WorkingDirectoryPolicy_NoMatches_W(t *testing.T) {
	testFunc := func(gc *generatedConstraints) bool {
		tc, err := setupSimpleRegoCreateContainerTest(gc)
		if err != nil {
			t.Error(err)
			return false
		}

		_, _, _, err = tc.policy.EnforceCreateContainerPolicy(tc.ctx, tc.sandboxID, tc.containerID, tc.argList, tc.envList, randString(testRand, 20), tc.mounts, false, tc.noNewPrivileges, tc.user, tc.groups, tc.umask, tc.capabilities, tc.seccomp)
		// not getting an error means something is broken
		if err == nil {
			return false
		}

		return assertDecisionJSONContains(t, err, "invalid working directory")
	}

	if err := quick.Check(testFunc, &quick.Config{MaxCount: 50, Rand: testRand}); err != nil {
		t.Errorf("Test_Rego_WorkingDirectoryPolicy_NoMatches: %v", err)
	}
}

func Test_Rego_EnforceCreateContainer_W(t *testing.T) {
	f := func(p *generatedConstraints) bool {
		t.Logf("Testing with %d containers", len(p.containers))
		tc, err := setupSimpleRegoCreateContainerTest(p)
		if err != nil {
			t.Errorf("Setup failed: %v", err)
			return false
		}

		t.Logf("Selected container ID: %s", tc.containerID)
		t.Logf("User config: %+v", tc.user)
		t.Logf("All config: %+v", tc)

		os.WriteFile("expected-policy.json", []byte(p.toPolicy().marshalRego()), 0644)

		// Print the full test config as JSON for better debugging
		tcJSON, err := json.MarshalIndent(tc, "", "  ")
		t.Logf("Full test config (JSON):\n%s", string(tcJSON))

		//_, _, _, err = tc.policy.EnforceCreateContainerPolicy(p.ctx, tc.sandboxID, tc.containerID, tc.argList, tc.envList, tc.workingDir, tc.mounts, false, tc.noNewPrivileges, tc.user, tc.groups, tc.umask, tc.capabilities, tc.seccomp)
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

func Test_Rego_EnforceCreateContainer_Start_All_Containers_W(t *testing.T) {
	f := func(p *generatedConstraints) bool {
		securityPolicy := p.toPolicy()
		defaultMounts := generateMounts(testRand)
		privilegedMounts := generateMounts(testRand)

		policy, err := newRegoPolicy(securityPolicy.marshalRego(),
			toOCIMounts(defaultMounts),
			toOCIMounts(privilegedMounts), osType)
		if err != nil {
			t.Error(err)
			return false
		}

		for _, container := range p.containers {
			containerID, err := mountImageForContainer(policy, container)
			if err != nil {
				t.Error(err)
				return false
			}

			envList := buildEnvironmentVariablesFromEnvRules(container.EnvRules, testRand)
			user := buildIDNameFromConfig(container.User.UserIDName, testRand)
			groups := buildGroupIDNamesFromUser(container.User, testRand)

			sandboxID := testDataGenerator.uniqueSandboxID()
			mounts := container.Mounts
			mounts = append(mounts, defaultMounts...)
			if container.AllowElevated {
				mounts = append(mounts, privilegedMounts...)
			}
			mountSpec := buildMountSpecFromMountArray(mounts, sandboxID, testRand)
			capabilities := container.Capabilities.toExternal()
			seccomp := container.SeccompProfileSHA256

			_, _, _, err = policy.EnforceCreateContainerPolicy(p.ctx, sandboxID, containerID, container.Command, envList, container.WorkingDir, mountSpec.Mounts, false, container.NoNewPrivileges, user, groups, container.User.Umask, &capabilities, seccomp)

			// getting an error means something is broken
			if err != nil {
				t.Error(err)
				return false
			}
		}

		return true

	}

	if err := quick.Check(f, &quick.Config{MaxCount: 10, Rand: testRand}); err != nil {
		t.Errorf("Test_Rego_EnforceCreateContainer_Start_All_Containers: %v", err)
	}
}

func Test_Rego_EnforceCreateContainer_Invalid_ContainerID_W(t *testing.T) {
	f := func(p *generatedConstraints) bool {
		tc, err := setupSimpleRegoCreateContainerTest(p)
		if err != nil {
			t.Error(err)
			return false
		}

		containerID := testDataGenerator.uniqueContainerID()
		_, _, _, err = tc.policy.EnforceCreateContainerPolicy(p.ctx, tc.sandboxID, containerID, tc.argList, tc.envList, tc.workingDir, tc.mounts, false, tc.noNewPrivileges, tc.user, tc.groups, tc.umask, tc.capabilities, tc.seccomp)

		// not getting an error means something is broken
		return err != nil
	}

	if err := quick.Check(f, &quick.Config{MaxCount: 50, Rand: testRand}); err != nil {
		t.Errorf("Test_Rego_EnforceCreateContainer_Invalid_ContainerID: %v", err)
	}
}

func Test_Rego_EnforceCreateContainer_Same_Container_Twice_W(t *testing.T) {
	f := func(p *generatedConstraints) bool {
		tc, err := setupSimpleRegoCreateContainerTest(p)
		if err != nil {
			t.Error(err)
			return false
		}

		_, _, _, err = tc.policy.EnforceCreateContainerPolicy(p.ctx, tc.sandboxID, tc.containerID, tc.argList, tc.envList, tc.workingDir, tc.mounts, false, tc.noNewPrivileges, tc.user, tc.groups, tc.umask, tc.capabilities, tc.seccomp)
		if err != nil {
			t.Error("Unable to start valid container.")
			return false
		}
		_, _, _, err = tc.policy.EnforceCreateContainerPolicy(p.ctx, tc.sandboxID, tc.containerID, tc.argList, tc.envList, tc.workingDir, tc.mounts, false, tc.noNewPrivileges, tc.user, tc.groups, tc.umask, tc.capabilities, tc.seccomp)
		if err == nil {
			t.Error("Able to start a container with already used id.")
			return false
		}

		return true
	}

	if err := quick.Check(f, &quick.Config{MaxCount: 50, Rand: testRand}); err != nil {
		t.Errorf("Test_Rego_EnforceCreateContainer_Same_Container_Twice: %v", err)
	}
}
