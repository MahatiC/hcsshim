package securitypolicy

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"math/rand"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/Microsoft/hcsshim/internal/guestpath"
	rpi "github.com/Microsoft/hcsshim/internal/regopolicyinterpreter"
	"github.com/blang/semver/v4"
	"github.com/open-policy-agent/opa/rego"
	oci "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pkg/errors"
)

const (
	// variables that influence generated rego-only test fixtures
	maxDiffLength                              = 64
	maxExternalProcessesInGeneratedConstraints = 16
	maxFragmentsInGeneratedConstraints         = 4
	maxGeneratedExternalProcesses              = 12
	maxGeneratedSandboxIDLength                = 32
	maxGeneratedEnforcementPointLength         = 64
	maxGeneratedPlan9Mounts                    = 8
	maxGeneratedFragmentFeedLength             = 256
	maxGeneratedFragmentIssuerLength           = 16
	maxPlan9MountTargetLength                  = 64
	maxPlan9MountIndex                         = 16
)

func verifyPolicyRules(apiVersion string, enforcementPoints map[string]interface{}, policyCode string) error {
	query := rego.New(
		rego.Query("data.policy"),
		rego.Module("policy.rego", policyCode),
		rego.Module("framework.rego", FrameworkCode),
	)

	ctx := context.Background()
	resultSet, err := query.Eval(ctx)
	if err != nil {
		return fmt.Errorf("unable to query policy template rules: %w", err)
	}

	policyTemplateRules := resultSet[0].Expressions[0].Value.(map[string]interface{})
	policyTemplateAPIVersion := policyTemplateRules["api_version"].(string)

	if policyTemplateAPIVersion != apiVersion {
		return fmt.Errorf("Policy template version != api version: %s != %s", apiVersion, policyTemplateAPIVersion)
	}

	for rule := range enforcementPoints {
		if _, ok := policyTemplateRules[rule]; !ok {
			return fmt.Errorf("Rule %s in API is missing from policy template", rule)
		}
	}

	for rule := range policyTemplateRules {
		if rule == "api_version" || rule == "framework_version" || rule == "reason" {
			continue
		}

		if _, ok := enforcementPoints[rule]; !ok {
			return fmt.Errorf("Rule %s in policy template is missing from API", rule)
		}
	}

	return nil
}

func copyMounts(mounts []oci.Mount) []oci.Mount {
	bytes, err := json.Marshal(mounts)
	if err != nil {
		panic(err)
	}

	mountsCopy := make([]oci.Mount, len(mounts))
	err = json.Unmarshal(bytes, &mountsCopy)
	if err != nil {
		panic(err)
	}

	return mountsCopy
}

func copyMountsInternal(mounts []mountInternal) []mountInternal {
	var mountsCopy []mountInternal

	for _, in := range mounts {
		out := mountInternal{
			Source:      in.Source,
			Destination: in.Destination,
			Type:        in.Type,
			Options:     copyStrings(in.Options),
		}

		mountsCopy = append(mountsCopy, out)
	}

	return mountsCopy
}

func copyLinuxCapabilities(caps oci.LinuxCapabilities) oci.LinuxCapabilities {
	bytes, err := json.Marshal(caps)
	if err != nil {
		panic(err)
	}

	capsCopy := oci.LinuxCapabilities{}
	err = json.Unmarshal(bytes, &capsCopy)
	if err != nil {
		panic(err)
	}

	return capsCopy
}

func copyLinuxSeccomp(seccomp oci.LinuxSeccomp) oci.LinuxSeccomp {
	bytes, err := json.Marshal(seccomp)
	if err != nil {
		panic(err)
	}

	seccompCopy := oci.LinuxSeccomp{}
	err = json.Unmarshal(bytes, &seccompCopy)
	if err != nil {
		panic(err)
	}

	return seccompCopy
}

type regoOverlayTestConfig struct {
	layers      []string
	containerID string
	policy      *regoEnforcer
}

func setupRegoOverlayTest(gc *generatedConstraints, valid bool) (tc *regoOverlayTestConfig, err error) {
	securityPolicy := gc.toPolicy()
	policy, err := newRegoPolicy(securityPolicy.marshalRego(), []oci.Mount{}, []oci.Mount{}, testOSType)

	if err != nil {
		return nil, err
	}

	containerID := testDataGenerator.uniqueContainerID()
	c := selectContainerFromContainerList(gc.containers, testRand)

	var layerPaths []string
	if valid {
		layerPaths, err = testDataGenerator.createValidOverlayForContainer(policy, c)
		if err != nil {
			return nil, fmt.Errorf("error creating valid overlay: %w", err)
		}
	} else {
		layerPaths, err = testDataGenerator.createInvalidOverlayForContainer(policy, c)
		if err != nil {
			return nil, fmt.Errorf("error creating invalid overlay: %w", err)
		}
	}

	// see NOTE_TESTCOPY
	return &regoOverlayTestConfig{
		layers:      copyStrings(layerPaths),
		containerID: containerID,
		policy:      policy,
	}, nil
}

func setupPlan9MountTest(gc *generatedConstraints) (tc *regoPlan9MountTestConfig, err error) {
	securityPolicy := gc.toPolicy()
	defaultMounts := generateMounts(testRand)
	privilegedMounts := generateMounts(testRand)

	testContainer := selectContainerFromContainerList(gc.containers, testRand)
	mountIndex := atMost(testRand, int32(len(testContainer.Mounts)-1))
	testMount := &testContainer.Mounts[mountIndex]
	testMount.Source = plan9Prefix
	testMount.Type = "secret"

	policy, err := newRegoPolicy(securityPolicy.marshalRego(),
		toOCIMounts(defaultMounts),
		toOCIMounts(privilegedMounts),
		testOSType)
	if err != nil {
		return nil, err
	}

	containerID, err := mountImageForContainer(policy, testContainer)
	if err != nil {
		return nil, err
	}

	uvmPathForShare := generateUVMPathForShare(testRand, containerID)

	envList := buildEnvironmentVariablesFromEnvRules(testContainer.EnvRules, testRand)
	sandboxID := testDataGenerator.uniqueSandboxID()

	mounts := testContainer.Mounts
	mounts = append(mounts, defaultMounts...)

	if testContainer.AllowElevated {
		mounts = append(mounts, privilegedMounts...)
	}
	mountSpec := buildMountSpecFromMountArray(mounts, sandboxID, testRand)
	mountSpec.Mounts = append(mountSpec.Mounts, oci.Mount{
		Source:      uvmPathForShare,
		Destination: testMount.Destination,
		Options:     testMount.Options,
		Type:        testMount.Type,
	})

	user := buildIDNameFromConfig(testContainer.User.UserIDName, testRand)
	groups := buildGroupIDNamesFromUser(testContainer.User, testRand)
	umask := testContainer.User.Umask

	capabilities := testContainer.Capabilities.toExternal()
	seccomp := testContainer.SeccompProfileSHA256

	// see NOTE_TESTCOPY
	return &regoPlan9MountTestConfig{
		envList:         copyStrings(envList),
		argList:         copyStrings(testContainer.Command),
		workingDir:      testContainer.WorkingDir,
		containerID:     containerID,
		sandboxID:       sandboxID,
		mounts:          copyMounts(mountSpec.Mounts),
		noNewPrivileges: testContainer.NoNewPrivileges,
		user:            user,
		groups:          groups,
		umask:           umask,
		uvmPathForShare: uvmPathForShare,
		policy:          policy,
		capabilities:    &capabilities,
		seccomp:         seccomp,
	}, nil
}

type regoPlan9MountTestConfig struct {
	envList         []string
	argList         []string
	workingDir      string
	containerID     string
	sandboxID       string
	mounts          []oci.Mount
	uvmPathForShare string
	noNewPrivileges bool
	user            IDName
	groups          []IDName
	umask           string
	policy          *regoEnforcer
	capabilities    *oci.LinuxCapabilities
	seccomp         string
}

func mountImageForContainer(policy *regoEnforcer, container *securityPolicyContainer) (string, error) {
	ctx := context.Background()
	containerID := testDataGenerator.uniqueContainerID()

	layerPaths, err := testDataGenerator.createValidOverlayForContainer(policy, container)
	if err != nil {
		return "", fmt.Errorf("error creating valid overlay: %w", err)
	}

	// see NOTE_TESTCOPY
	err = policy.EnforceOverlayMountPolicy(ctx, containerID, copyStrings(layerPaths), testDataGenerator.uniqueMountTarget())
	if err != nil {
		return "", fmt.Errorf("error mounting filesystem: %w", err)
	}

	return containerID, nil
}

func buildMountSpecFromMountArray(mounts []mountInternal, sandboxID string, r *rand.Rand) *oci.Spec {
	mountSpec := new(oci.Spec)

	// Select some number of the valid, matching rules to be environment
	// variable
	numberOfMounts := int32(len(mounts))
	numberOfMatches := randMinMax(r, 1, numberOfMounts)
	usedIndexes := map[int]struct{}{}
	for numberOfMatches > 0 {
		anIndex := -1
		if (numberOfMatches * 2) > numberOfMounts {
			// if we have a lot of matches, randomly select
			exists := true

			for exists {
				anIndex = int(randMinMax(r, 0, numberOfMounts-1))
				_, exists = usedIndexes[anIndex]
			}
		} else {
			// we have a "smaller set of rules. we'll just iterate and select from
			// available
			exists := true

			for exists {
				anIndex++
				_, exists = usedIndexes[anIndex]
			}
		}

		mount := mounts[anIndex]

		source := substituteUVMPath(sandboxID, mount).Source
		mountSpec.Mounts = append(mountSpec.Mounts, oci.Mount{
			Source:      source,
			Destination: mount.Destination,
			Options:     mount.Options,
			Type:        mount.Type,
		})
		usedIndexes[anIndex] = struct{}{}

		numberOfMatches--
	}

	return mountSpec
}

func selectExecProcess(processes []containerExecProcess, r *rand.Rand) containerExecProcess {
	numProcesses := len(processes)
	return processes[r.Intn(numProcesses)]
}

func selectWindowsExecProcess(processes []windowsContainerExecProcess, r *rand.Rand) windowsContainerExecProcess {
	numProcesses := len(processes)
	return processes[r.Intn(numProcesses)]
}

func selectSignalFromSignals(r *rand.Rand, signals []syscall.Signal) syscall.Signal {
	numSignals := len(signals)
	return signals[r.Intn(numSignals)]
}

func generateUVMPathForShare(r *rand.Rand, containerID string) string {
	return fmt.Sprintf("%s/%s%s",
		guestpath.LCOWRootPrefixInUVM,
		containerID,
		fmt.Sprintf(guestpath.LCOWMountPathPrefixFmt, atMost(r, maxPlan9MountIndex)))
}

func generateLinuxID(r *rand.Rand) uint32 {
	return r.Uint32()
}

type regoScratchMountPolicyTestConfig struct {
	policy *regoEnforcer
}

func setupRegoScratchMountTest(
	gc *generatedConstraints,
	unencryptedScratch bool,
) (tc *regoScratchMountPolicyTestConfig, err error) {
	securityPolicy := gc.toPolicy()
	securityPolicy.AllowUnencryptedScratch = unencryptedScratch

	defaultMounts := generateMounts(testRand)
	privilegedMounts := generateMounts(testRand)
	policy, err := newRegoPolicy(securityPolicy.marshalRego(), toOCIMounts(defaultMounts), toOCIMounts(privilegedMounts), testOSType)

	if err != nil {
		return nil, err
	}
	return &regoScratchMountPolicyTestConfig{
		policy: policy,
	}, nil
}

func generateCapabilities(r *rand.Rand) *oci.LinuxCapabilities {
	return &oci.LinuxCapabilities{
		Bounding:    generateCapabilitiesSet(r, 0),
		Effective:   generateCapabilitiesSet(r, 0),
		Inheritable: generateCapabilitiesSet(r, 0),
		Permitted:   generateCapabilitiesSet(r, 0),
		Ambient:     generateCapabilitiesSet(r, 0),
	}
}

func alterCapabilitySet(r *rand.Rand, set []string) []string {
	newSet := copyStrings(set)

	if len(newSet) == 0 {
		return generateCapabilitiesSet(r, 1)
	}

	alterations := atLeastNAtMostM(r, 1, 4)
	for i := alterations; i > 0; i-- {
		if len(newSet) == 0 {
			newSet = generateCapabilitiesSet(r, 1)
		} else {
			action := atMost(r, 2)
			if action == 0 {
				newSet = superCapabilitySet(r, newSet)
			} else if action == 1 {
				newSet = subsetCapabilitySet(r, newSet)
			} else {
				replace := atMost(r, int32((len(newSet) - 1)))
				newSet[replace] = generateCapability(r)
			}
		}
	}

	return newSet
}

func subsetCapabilitySet(r *rand.Rand, set []string) []string {
	newSet := make([]string, 0)

	setSize := int32(len(set))
	if setSize == 0 {
		// no subset is possible
		return newSet
	} else if setSize == 1 {
		// only one possibility
		return newSet
	}

	// We need to remove at least 1 item, potentially all
	numberOfMatches := randMinMax(r, 0, setSize-1)
	usedIndexes := map[int]struct{}{}
	for i := numberOfMatches; i > 0; i-- {
		anIndex := -1
		if ((setSize - int32(len(usedIndexes))) * 2) > i {
			// the set is pretty large compared to our number to select,
			// we will gran randomly
			exists := true

			for exists {
				anIndex = int(randMinMax(r, 0, setSize-1))
				_, exists = usedIndexes[anIndex]
			}
		} else {
			// we have a "smaller set of capabilities. we'll just iterate and
			// select from available
			exists := true

			for exists {
				anIndex++
				_, exists = usedIndexes[anIndex]
			}
		}

		newSet = append(newSet, set[anIndex])
		usedIndexes[anIndex] = struct{}{}
	}

	return newSet
}

func superCapabilitySet(r *rand.Rand, set []string) []string {
	newSet := copyStrings(set)

	additions := atLeastNAtMostM(r, 1, 12)
	for i := additions; i > 0; i-- {
		newSet = append(newSet, generateCapability(r))
	}

	return newSet
}

func (c capabilitiesInternal) toExternal() oci.LinuxCapabilities {
	return oci.LinuxCapabilities{
		Bounding:    c.Bounding,
		Effective:   c.Effective,
		Inheritable: c.Inheritable,
		Permitted:   c.Permitted,
		Ambient:     c.Ambient,
	}
}

func buildIDNameFromConfig(config IDNameConfig, r *rand.Rand) IDName {
	switch config.Strategy {
	case IDNameStrategyName:
		return IDName{
			ID:   generateIDNameID(r),
			Name: config.Rule,
		}

	case IDNameStrategyID:
		return IDName{
			ID:   config.Rule,
			Name: generateIDNameName(r),
		}

	case IDNameStrategyAny:
		return generateIDName(r)

	default:
		panic(fmt.Sprintf("unsupported ID Name strategy: %v", config.Strategy))
	}
}

func buildGroupIDNamesFromUser(user UserConfig, r *rand.Rand) []IDName {
	groupIDNames := make([]IDName, 0)

	// Select some number of the valid, matching rules to be groups
	numberOfGroups := int32(len(user.GroupIDNames))
	numberOfMatches := randMinMax(r, 1, numberOfGroups)
	usedIndexes := map[int]struct{}{}
	for numberOfMatches > 0 {
		anIndex := -1
		if (numberOfMatches * 2) > numberOfGroups {
			// if we have a lot of matches, randomly select
			exists := true

			for exists {
				anIndex = int(randMinMax(r, 0, numberOfGroups-1))
				_, exists = usedIndexes[anIndex]
			}
		} else {
			// we have a "smaller set of rules. we'll just iterate and select from
			// available
			exists := true

			for exists {
				anIndex++
				_, exists = usedIndexes[anIndex]
			}
		}

		if user.GroupIDNames[anIndex].Strategy == IDNameStrategyRegex {
			// we don't match from regex groups or any groups
			numberOfMatches--
			continue
		}

		groupIDName := buildIDNameFromConfig(user.GroupIDNames[anIndex], r)
		groupIDNames = append(groupIDNames, groupIDName)
		usedIndexes[anIndex] = struct{}{}

		numberOfMatches--
	}

	return groupIDNames
}

func generateIDNameName(r *rand.Rand) string {
	return randVariableString(r, maxGeneratedNameLength)
}

func generateIDNameID(r *rand.Rand) string {
	id := r.Uint32()
	return strconv.FormatUint(uint64(id), 10)
}

func generateIDName(r *rand.Rand) IDName {
	return IDName{
		ID:   generateIDNameID(r),
		Name: generateIDNameName(r),
	}
}

func toOCIMounts(mounts []mountInternal) []oci.Mount {
	result := make([]oci.Mount, len(mounts))
	for i, mount := range mounts {
		result[i] = oci.Mount{
			Source:      mount.Source,
			Destination: mount.Destination,
			Options:     mount.Options,
			Type:        mount.Type,
		}
	}
	return result
}

func setupExternalProcessTest(gc *generatedConstraints) (tc *regoExternalPolicyTestConfig, err error) {
	gc.externalProcesses = generateExternalProcesses(testRand)
	securityPolicy := gc.toPolicy()
	defaultMounts := generateMounts(testRand)
	privilegedMounts := generateMounts(testRand)

	policy, err := newRegoPolicy(securityPolicy.marshalRego(),
		toOCIMounts(defaultMounts),
		toOCIMounts(privilegedMounts),
		testOSType)
	if err != nil {
		return nil, err
	}

	return &regoExternalPolicyTestConfig{
		policy: policy,
	}, nil
}

type regoExternalPolicyTestConfig struct {
	policy *regoEnforcer
}

func setupGetPropertiesTest(gc *generatedConstraints, allowPropertiesAccess bool) (tc *regoGetPropertiesTestConfig, err error) {
	gc.allowGetProperties = allowPropertiesAccess

	securityPolicy := gc.toPolicy()
	defaultMounts := generateMounts(testRand)
	privilegedMounts := generateMounts(testRand)

	policy, err := newRegoPolicy(securityPolicy.marshalRego(),
		toOCIMounts(defaultMounts),
		toOCIMounts(privilegedMounts),
		testOSType)
	if err != nil {
		return nil, err
	}

	return &regoGetPropertiesTestConfig{
		policy: policy,
	}, nil
}

type regoGetPropertiesTestConfig struct {
	policy *regoEnforcer
}

func setupDumpStacksTest(constraints *generatedConstraints, allowDumpStacks bool) (tc *regoGetPropertiesTestConfig, err error) {
	constraints.allowDumpStacks = allowDumpStacks

	securityPolicy := constraints.toPolicy()
	defaultMounts := generateMounts(testRand)
	privilegedMounts := generateMounts(testRand)

	policy, err := newRegoPolicy(securityPolicy.marshalRego(),
		toOCIMounts(defaultMounts),
		toOCIMounts(privilegedMounts),
		testOSType)
	if err != nil {
		return nil, err
	}

	return &regoGetPropertiesTestConfig{
		policy: policy,
	}, nil
}

type regoDumpStacksTestConfig struct {
	policy *regoEnforcer
}

type regoPolicyOnlyTestConfig struct {
	policy *regoEnforcer
}

func setupRegoPolicyOnlyTest(gc *generatedConstraints) (tc *regoPolicyOnlyTestConfig, err error) {
	securityPolicy := gc.toPolicy()
	policy, err := newRegoPolicy(securityPolicy.marshalRego(), []oci.Mount{}, []oci.Mount{}, testOSType)

	if err != nil {
		return nil, err
	}

	// see NOTE_TESTCOPY
	return &regoPolicyOnlyTestConfig{
		policy: policy,
	}, nil
}

type regoFragmentTestConfig struct {
	fragments         []*regoFragment
	containers        []*regoFragmentContainer
	externalProcesses []*externalProcess
	subFragments      []*regoFragment
	plan9Mounts       []string
	mountSpec         []string
	policy            *regoEnforcer
}

type regoFragmentContainer struct {
	container    *securityPolicyContainer
	envList      []string
	sandboxID    string
	mounts       []oci.Mount
	user         IDName
	groups       []IDName
	capabilities *oci.LinuxCapabilities
	seccomp      string
}

func setupSimpleRegoFragmentTestConfig(gc *generatedConstraints) (*regoFragmentTestConfig, error) {
	return setupRegoFragmentTestConfig(gc, 1, []string{"containers"}, []string{}, false, false, false, false)
}

func setupRegoFragmentTestConfigWithIncludes(gc *generatedConstraints, includes []string) (*regoFragmentTestConfig, error) {
	return setupRegoFragmentTestConfig(gc, 1, includes, []string{}, false, false, false, false)
}

func setupRegoFragmentTestConfigWithExcludes(gc *generatedConstraints, excludes []string) (*regoFragmentTestConfig, error) {
	return setupRegoFragmentTestConfig(gc, 1, []string{}, excludes, false, false, false, false)
}

func setupRegoFragmentSVNErrorTestConfig(gc *generatedConstraints) (*regoFragmentTestConfig, error) {
	return setupRegoFragmentTestConfig(gc, 1, []string{"containers"}, []string{}, true, false, false, false)
}

func setupRegoSubfragmentSVNErrorTestConfig(gc *generatedConstraints) (*regoFragmentTestConfig, error) {
	return setupRegoFragmentTestConfig(gc, 1, []string{"fragments"}, []string{}, true, false, false, false)
}

func setupRegoFragmentTwoFeedTestConfig(gc *generatedConstraints, sameIssuer bool, sameFeed bool) (*regoFragmentTestConfig, error) {
	return setupRegoFragmentTestConfig(gc, 2, []string{"containers"}, []string{}, false, sameIssuer, sameFeed, false)
}

func setupRegoFragmentSVNMismatchTestConfig(gc *generatedConstraints) (*regoFragmentTestConfig, error) {
	return setupRegoFragmentTestConfig(gc, 2, []string{"containers"}, []string{}, false, false, false, true)
}

func compareSVNs(lhs string, rhs string) int {
	lhs_int, err := strconv.Atoi(lhs)
	if err == nil {
		rhs_int, err := strconv.Atoi(rhs)
		if err == nil {
			return lhs_int - rhs_int
		}
	}

	panic("unable to compare SVNs")
}

func setupRegoFragmentTestConfig(gc *generatedConstraints, numFragments int, includes []string, excludes []string, svnError bool, sameIssuer bool, sameFeed bool, svnMismatch bool) (tc *regoFragmentTestConfig, err error) {
	gc.fragments = generateFragments(testRand, int32(numFragments))

	if sameIssuer {
		for _, fragment := range gc.fragments {
			fragment.issuer = gc.fragments[0].issuer
			if sameFeed {
				fragment.feed = gc.fragments[0].feed
			}
		}
	}

	subSVNError := svnError
	if len(includes) > 0 && includes[0] == "fragments" {
		svnError = false
	}
	fragments := selectFragmentsFromConstraints(gc, numFragments, includes, excludes, svnError, frameworkVersion, svnMismatch)

	containers := make([]*regoFragmentContainer, numFragments)
	subFragments := make([]*regoFragment, numFragments)
	externalProcesses := make([]*externalProcess, numFragments)
	plan9Mounts := make([]string, numFragments)
	for i, fragment := range fragments {
		container := fragment.selectContainer()

		envList := buildEnvironmentVariablesFromEnvRules(container.EnvRules, testRand)
		sandboxID := testDataGenerator.uniqueSandboxID()
		user := buildIDNameFromConfig(container.User.UserIDName, testRand)
		groups := buildGroupIDNamesFromUser(container.User, testRand)
		capabilities := copyLinuxCapabilities(container.Capabilities.toExternal())
		seccomp := container.SeccompProfileSHA256

		mounts := container.Mounts
		mountSpec := buildMountSpecFromMountArray(mounts, sandboxID, testRand)
		containers[i] = &regoFragmentContainer{
			container:    container,
			envList:      envList,
			sandboxID:    sandboxID,
			mounts:       mountSpec.Mounts,
			user:         user,
			groups:       groups,
			capabilities: &capabilities,
			seccomp:      seccomp,
		}

		for _, include := range fragment.info.includes {
			switch include {
			case "fragments":
				subFragments[i] = selectFragmentsFromConstraints(fragment.constraints, 1, []string{"containers"}, []string{}, subSVNError, frameworkVersion, false)[0]
				break

			case "external_processes":
				externalProcesses[i] = selectExternalProcessFromConstraints(fragment.constraints, testRand)
				break
			}
		}

		// now that we've explicitly added the excluded items to the fragment
		// we remove the include string so that the generated policy
		// does not include them.
		fragment.info.includes = removeStringsFromArray(fragment.info.includes, excludes)

		code := fragment.constraints.toFragment().marshalRego()
		fragment.code = setFrameworkVersion(code, frameworkVersion)
	}

	if sameFeed {
		includeSet := make(map[string]bool)
		minSVN := strconv.Itoa(maxGeneratedVersion)
		for _, fragment := range gc.fragments {
			svn := fragment.minimumSVN
			if compareSVNs(svn, minSVN) < 0 {
				minSVN = svn
			}
			for _, include := range fragment.includes {
				includeSet[include] = true
			}
		}
		frag := gc.fragments[0]
		frag.minimumSVN = minSVN
		frag.includes = make([]string, 0, len(includeSet))
		for include := range includeSet {
			frag.includes = append(frag.includes, include)
		}

		gc.fragments = []*fragment{frag}

	}

	securityPolicy := gc.toPolicy()
	defaultMounts := toOCIMounts(generateMounts(testRand))
	privilegedMounts := toOCIMounts(generateMounts(testRand))
	policy, err := newRegoPolicy(securityPolicy.marshalRego(), defaultMounts, privilegedMounts, testOSType)

	if err != nil {
		return nil, err
	}

	return &regoFragmentTestConfig{
		fragments:         fragments,
		containers:        containers,
		subFragments:      subFragments,
		externalProcesses: externalProcesses,
		plan9Mounts:       plan9Mounts,
		policy:            policy,
	}, nil
}

type regoDropEnvsTestConfig struct {
	envList      []string
	expected     []string
	argList      []string
	workingDir   string
	containerID  string
	sandboxID    string
	mounts       []oci.Mount
	policy       *regoEnforcer
	capabilities oci.LinuxCapabilities
}

func setupEnvRuleSets(count int) [][]EnvRuleConfig {
	numEnvRules := []int{int(randMinMax(testRand, 1, 4)),
		int(randMinMax(testRand, 1, 4)),
		int(randMinMax(testRand, 1, 4))}
	envRuleLookup := make(stringSet)
	envRules := make([][]EnvRuleConfig, count)

	for i := 0; i < count; i++ {
		rules := envRuleLookup.randUniqueArray(testRand, func(r *rand.Rand) string {
			return randVariableString(r, 10)
		}, int32(numEnvRules[i]))

		envRules[i] = make([]EnvRuleConfig, numEnvRules[i])
		for j, rule := range rules {
			envRules[i][j] = EnvRuleConfig{
				Strategy: "string",
				Rule:     rule,
			}
		}
	}

	return envRules
}

func setupRegoDropEnvsTest(disjoint bool) (*regoContainerTestConfig, error) {
	gc := generateConstraints(testRand, 1)
	gc.allowEnvironmentVariableDropping = true

	const numContainers int = 3
	envRules := setupEnvRuleSets(numContainers)
	containers := make([]*securityPolicyContainer, numContainers)
	envs := make([][]string, numContainers)

	for i := 0; i < numContainers; i++ {
		c, err := gc.containers[0].clone()
		if err != nil {
			return nil, err
		}
		containers[i] = c
		envs[i] = buildEnvironmentVariablesFromEnvRules(envRules[i], testRand)
		if i == 0 {
			c.EnvRules = envRules[i]
		} else if disjoint {
			c.EnvRules = append(envRules[0], envRules[i]...)
		} else {
			c.EnvRules = append(containers[i-1].EnvRules, envRules[i]...)
		}
	}

	gc.containers = containers
	securityPolicy := gc.toPolicy()
	defaultMounts := generateMounts(testRand)
	privilegedMounts := generateMounts(testRand)

	policy, err := newRegoPolicy(securityPolicy.marshalRego(),
		toOCIMounts(defaultMounts),
		toOCIMounts(privilegedMounts),
		testOSType)

	if err != nil {
		return nil, err
	}

	containerIDs := make([]string, numContainers)
	for i, c := range gc.containers {
		containerID, err := mountImageForContainer(policy, c)
		if err != nil {
			return nil, err
		}

		containerIDs[i] = containerID
	}

	var envList []string
	if disjoint {
		var extraLen int
		if len(envs[1]) < len(envs[2]) {
			extraLen = len(envs[1])
		} else {
			extraLen = len(envs[2])
		}
		envList = append(envs[0], envs[1][:extraLen]...)
		envList = append(envList, envs[2][:extraLen]...)
	} else {
		envList = append(envs[0], envs[1]...)
		envList = append(envList, envs[2]...)
	}

	user := buildIDNameFromConfig(containers[2].User.UserIDName, testRand)
	groups := buildGroupIDNamesFromUser(containers[2].User, testRand)
	umask := containers[2].User.Umask

	sandboxID := testDataGenerator.uniqueSandboxID()

	mounts := containers[2].Mounts
	mounts = append(mounts, defaultMounts...)
	if containers[2].AllowElevated {
		mounts = append(mounts, privilegedMounts...)
	}

	mountSpec := buildMountSpecFromMountArray(mounts, sandboxID, testRand)
	capabilities := copyLinuxCapabilities(containers[2].Capabilities.toExternal())
	seccomp := containers[2].SeccompProfileSHA256

	// see NOTE_TESTCOPY
	return &regoContainerTestConfig{
		envList:         copyStrings(envList),
		argList:         copyStrings(containers[2].Command),
		workingDir:      containers[2].WorkingDir,
		containerID:     containerIDs[2],
		sandboxID:       sandboxID,
		mounts:          copyMounts(mountSpec.Mounts),
		noNewPrivileges: containers[2].NoNewPrivileges,
		user:            user,
		groups:          groups,
		umask:           umask,
		policy:          policy,
		capabilities:    &capabilities,
		seccomp:         seccomp,
		ctx:             gc.ctx,
	}, nil
}

type regoFrameworkVersionTestConfig struct {
	policy    *regoEnforcer
	fragments []*regoFragment
}

func setFrameworkVersion(code string, version string) string {
	template := `framework_version := "%s"`
	old := fmt.Sprintf(template, frameworkVersion)
	if version == "" {
		return strings.Replace(code, old, "", 1)
	}

	new := fmt.Sprintf(template, version)
	return strings.Replace(code, old, new, 1)
}

func setupFrameworkVersionSimpleTest(gc *generatedConstraints, policyVersion string, version string) (*regoFrameworkVersionTestConfig, error) {
	return setupFrameworkVersionTest(gc, policyVersion, version, 0, "", []string{})
}

func setupFrameworkVersionTest(gc *generatedConstraints, policyVersion string, version string, numFragments int, fragmentVersion string, includes []string) (*regoFrameworkVersionTestConfig, error) {
	fragments := make([]*regoFragment, 0, numFragments)
	if numFragments > 0 {
		gc.fragments = generateFragments(testRand, int32(numFragments))
		fragments = selectFragmentsFromConstraints(gc, numFragments, includes, []string{}, false, fragmentVersion, false)
	}

	securityPolicy := gc.toPolicy()
	policy, err := newRegoPolicy(setFrameworkVersion(securityPolicy.marshalRego(), policyVersion), []oci.Mount{}, []oci.Mount{}, testOSType)

	if err != nil {
		return nil, err
	}

	code := strings.Replace(frameworkCodeTemplate, "@@FRAMEWORK_VERSION@@", version, 1)
	policy.rego.RemoveModule("framework.rego")
	policy.rego.AddModule("framework.rego", &rpi.RegoModule{Namespace: "framework", Code: code})
	err = policy.rego.Compile()
	if err != nil {
		return nil, err
	}

	return &regoFrameworkVersionTestConfig{policy: policy, fragments: fragments}, nil
}

type regoFragment struct {
	info        *fragment
	constraints *generatedConstraints
	code        string
}

func (f *regoFragment) selectContainer() *securityPolicyContainer {
	return selectContainerFromContainerList(f.constraints.containers, testRand)
}

func mustIncrementSVN(svn string) string {
	svn_semver, err := semver.Parse(svn)

	if err == nil {
		svn_semver.IncrementMajor()
		return svn_semver.String()
	}

	svn_int, err := strconv.Atoi(svn)

	if err == nil {
		return strconv.Itoa(svn_int + 1)
	}

	panic("Could not increment SVN")
}

func selectFragmentsFromConstraints(gc *generatedConstraints, numFragments int, includes []string, excludes []string, svnError bool, frameworkVersion string, svnMismatch bool) []*regoFragment {
	choices := randChoices(testRand, numFragments, len(gc.fragments))
	fragments := make([]*regoFragment, numFragments)
	for i, choice := range choices {
		config := gc.fragments[choice]
		config.includes = addStringsToArray(config.includes, includes)
		// since we want to test that the policy cannot include an excluded
		// quantity, we must first ensure they are in the fragment
		config.includes = addStringsToArray(config.includes, excludes)

		constraints := generateConstraints(testRand, maxContainersInGeneratedConstraints)
		for _, include := range config.includes {
			switch include {
			case "fragments":
				constraints.fragments = generateFragments(testRand, 1)
				for _, fragment := range constraints.fragments {
					fragment.includes = addStringsToArray(fragment.includes, []string{"containers"})
				}
				break

			case "external_processes":
				constraints.externalProcesses = generateExternalProcesses(testRand)
				break
			}
		}

		svn := config.minimumSVN
		if svnMismatch {
			if randBool(testRand) {
				svn = generateSemver(testRand)
			} else {
				config.minimumSVN = generateSemver(testRand)
			}
		}

		constraints.svn = svn
		if svnError {
			config.minimumSVN = mustIncrementSVN(config.minimumSVN)
		}

		code := constraints.toFragment().marshalRego()
		code = setFrameworkVersion(code, frameworkVersion)

		fragments[i] = &regoFragment{
			info:        config,
			constraints: constraints,
			code:        code,
		}
	}

	return fragments
}

func generateSandboxID(r *rand.Rand) string {
	return randVariableString(r, maxGeneratedSandboxIDLength)
}

func generateEnforcementPoint(r *rand.Rand) string {
	first := randChar(r)
	return first + randString(r, atMost(r, maxGeneratedEnforcementPointLength))
}

func (gen *dataGenerator) uniqueSandboxID() string {
	return gen.sandboxIDs.randUnique(gen.rng, generateSandboxID)
}

func (gen *dataGenerator) uniqueEnforcementPoint() string {
	return gen.enforcementPoints.randUnique(gen.rng, generateEnforcementPoint)
}

type regoContainerTestConfig struct {
	envList         []string
	argList         []string
	workingDir      string
	containerID     string
	sandboxID       string
	mounts          []oci.Mount
	noNewPrivileges bool
	user            IDName
	groups          []IDName
	umask           string
	capabilities    *oci.LinuxCapabilities
	seccomp         string
	policy          *regoEnforcer
	ctx             context.Context
}

func setupSimpleRegoCreateContainerTest(gc *generatedConstraints) (tc *regoContainerTestConfig, err error) {
	c := selectContainerFromContainerList(gc.containers, testRand)
	return setupRegoCreateContainerTest(gc, c, false)
}

func setupRegoPrivilegedMountTest(gc *generatedConstraints) (tc *regoContainerTestConfig, err error) {
	c := selectContainerFromContainerList(gc.containers, testRand)
	return setupRegoCreateContainerTest(gc, c, true)
}

func setupRegoCreateContainerTest(gc *generatedConstraints, testContainer *securityPolicyContainer, privilegedError bool) (tc *regoContainerTestConfig, err error) {
	securityPolicy := gc.toPolicy()
	defaultMounts := generateMounts(testRand)
	privilegedMounts := generateMounts(testRand)

	policy, err := newRegoPolicy(securityPolicy.marshalRego(),
		toOCIMounts(defaultMounts),
		toOCIMounts(privilegedMounts),
		testOSType)
	if err != nil {
		return nil, err
	}

	containerID, err := mountImageForContainer(policy, testContainer)
	if err != nil {
		return nil, err
	}

	envList := buildEnvironmentVariablesFromEnvRules(testContainer.EnvRules, testRand)
	sandboxID := testDataGenerator.uniqueSandboxID()

	mounts := testContainer.Mounts
	mounts = append(mounts, defaultMounts...)
	if privilegedError {
		testContainer.AllowElevated = false
	}

	if testContainer.AllowElevated || privilegedError {
		mounts = append(mounts, privilegedMounts...)
	}
	mountSpec := buildMountSpecFromMountArray(mounts, sandboxID, testRand)

	// Handle user configuration based on OS type
	user := IDName{}
	var groups []IDName
	var umask string
	var capabilities *oci.LinuxCapabilities

	if testOSType == "windows" {
		// For Windows, use the WindowsUser field from the test container if available
		/*if testContainer.WindowsUser != "" {
			user = IDName{Name: testContainer.WindowsUser}
		} else {
			user = IDName{Name: generateIDNameName(testRand)}
		}*/
	} else {
		// For Linux, use the full ID/Name strategy
		if testContainer.User.UserIDName.Strategy != IDNameStrategyRegex {
			user = buildIDNameFromConfig(testContainer.User.UserIDName, testRand)
		}
		groups = buildGroupIDNamesFromUser(testContainer.User, testRand)
		umask = testContainer.User.Umask

		if testContainer.Capabilities != nil {
			capsExternal := copyLinuxCapabilities(testContainer.Capabilities.toExternal())
			capabilities = &capsExternal
		} else {
			capabilities = nil
		}
	}

	seccomp := testContainer.SeccompProfileSHA256

	// Return full config for Linux
	return &regoContainerTestConfig{
		envList:         copyStrings(envList),
		argList:         copyStrings(testContainer.Command),
		workingDir:      testContainer.WorkingDir,
		containerID:     containerID,
		sandboxID:       sandboxID,
		mounts:          copyMounts(mountSpec.Mounts),
		noNewPrivileges: testContainer.NoNewPrivileges,
		user:            user,
		groups:          groups,
		umask:           umask,
		capabilities:    capabilities,
		seccomp:         seccomp,
		policy:          policy,
		ctx:             gc.ctx,
	}, nil

}

func setupRegoRunningContainerTest(gc *generatedConstraints, privileged bool) (tc *regoRunningContainerTestConfig, err error) {
	securityPolicy := gc.toPolicy()
	defaultMounts := generateMounts(testRand)
	privilegedMounts := generateMounts(testRand)

	policy, err := newRegoPolicy(securityPolicy.marshalRego(),
		toOCIMounts(defaultMounts),
		toOCIMounts(privilegedMounts),
		testOSType)
	if err != nil {
		return nil, err
	}

	var runningContainers []regoRunningContainer
	numOfRunningContainers := int(atLeastOneAtMost(testRand, int32(len(gc.containers))))
	containersToRun := randChoicesWithReplacement(testRand, numOfRunningContainers, len(gc.containers))
	for _, i := range containersToRun {
		containerToStart := gc.containers[i]
		r, err := runContainer(policy, containerToStart, defaultMounts, privilegedMounts, privileged)
		if err != nil {
			return nil, err
		}
		runningContainers = append(runningContainers, *r)
	}

	return &regoRunningContainerTestConfig{
		runningContainers: runningContainers,
		policy:            policy,
		defaultMounts:     copyMountsInternal(defaultMounts),
		privilegedMounts:  copyMountsInternal(privilegedMounts),
	}, nil
}

func runContainer(enforcer *regoEnforcer, container *securityPolicyContainer, defaultMounts []mountInternal, privilegedMounts []mountInternal, privileged bool) (*regoRunningContainer, error) {
	ctx := context.Background()
	containerID, err := mountImageForContainer(enforcer, container)
	if err != nil {
		return nil, err
	}

	envList := buildEnvironmentVariablesFromEnvRules(container.EnvRules, testRand)
	user := buildIDNameFromConfig(container.User.UserIDName, testRand)
	groups := buildGroupIDNamesFromUser(container.User, testRand)
	umask := container.User.Umask
	sandboxID := generateSandboxID(testRand)

	mounts := container.Mounts
	mounts = append(mounts, defaultMounts...)
	if container.AllowElevated {
		mounts = append(mounts, privilegedMounts...)
	}
	mountSpec := buildMountSpecFromMountArray(mounts, sandboxID, testRand)
	var capabilities oci.LinuxCapabilities
	if container.Capabilities == nil {
		if privileged {
			capabilities = capabilitiesInternal{
				Bounding:    DefaultPrivilegedCapabilities(),
				Inheritable: DefaultPrivilegedCapabilities(),
				Effective:   DefaultPrivilegedCapabilities(),
				Permitted:   DefaultPrivilegedCapabilities(),
				Ambient:     []string{},
			}.toExternal()
		} else {
			capabilities = capabilitiesInternal{
				Bounding:    DefaultUnprivilegedCapabilities(),
				Inheritable: []string{},
				Effective:   DefaultUnprivilegedCapabilities(),
				Permitted:   DefaultUnprivilegedCapabilities(),
				Ambient:     []string{},
			}.toExternal()
		}
	} else {
		capabilities = container.Capabilities.toExternal()
	}
	seccomp := container.SeccompProfileSHA256

	_, _, _, err = enforcer.EnforceCreateContainerPolicy(ctx, sandboxID, containerID, container.Command, envList, container.WorkingDir, mountSpec.Mounts, privileged, container.NoNewPrivileges, user, groups, umask, &capabilities, seccomp)
	if err != nil {
		return nil, err
	}

	return &regoRunningContainer{
		container:   container,
		envList:     envList,
		containerID: containerID,
	}, nil
}

type regoRunningContainerTestConfig struct {
	runningContainers []regoRunningContainer
	policy            *regoEnforcer
	defaultMounts     []mountInternal
	privilegedMounts  []mountInternal
}

type regoRunningContainer struct {
	container        *securityPolicyContainer
	windowsContainer *securityPolicyWindowsContainer
	envList          []string
	containerID      string
}

func setupRegoRunningWindowsContainerTest(gc *generatedWindowsConstraints) (tc *regoRunningContainerTestConfig, err error) {
	securityPolicy := gc.toPolicy()
	defaultMounts := generateMounts(testRand)
	privilegedMounts := generateMounts(testRand)

	//fmt.Printf("Generated Rego policy:\n%s\n", securityPolicy.marshalWindowsRego())

	policy, err := newRegoPolicy(securityPolicy.marshalWindowsRego(),
		toOCIMounts(defaultMounts),
		toOCIMounts(privilegedMounts),
		testOSType)
	if err != nil {
		return nil, err
	}

	var runningContainers []regoRunningContainer
	numOfRunningContainers := int(atLeastOneAtMost(testRand, int32(len(gc.containers))))
	containersToRun := randChoicesWithReplacement(testRand, numOfRunningContainers, len(gc.containers))
	for _, i := range containersToRun {
		containerToStart := gc.containers[i]
		r, err := runWindowsContainer(policy, containerToStart)
		if err != nil {
			return nil, err
		}
		runningContainers = append(runningContainers, *r)
	}

	return &regoRunningContainerTestConfig{
		runningContainers: runningContainers,
		policy:            policy,
		defaultMounts:     copyMountsInternal(defaultMounts),
		privilegedMounts:  copyMountsInternal(privilegedMounts),
	}, nil
}

func runWindowsContainer(enforcer *regoEnforcer, container *securityPolicyWindowsContainer) (*regoRunningContainer, error) {
	ctx := context.Background()
	containerID, err := mountImageForWindowsContainer(enforcer, container)
	if err != nil {
		return nil, err
	}

	envList := buildEnvironmentVariablesFromEnvRules(container.EnvRules, testRand)
	user := IDName{Name: container.User}

	_, _, _, err = enforcer.EnforceCreateContainerPolicyV2(ctx, containerID, container.Command, envList, container.WorkingDir, nil, user, nil)

	if err != nil {
		return nil, err
	}

	return &regoRunningContainer{
		windowsContainer: container,
		envList:          envList,
		containerID:      containerID,
	}, nil
}

func copyStrings(values []string) []string {
	valuesCopy := make([]string, len(values))
	copy(valuesCopy, values)
	return valuesCopy
}

//go:embed api_test.rego
var apiTestCode string

func (p *regoEnforcer) injectTestAPI() error {
	p.rego.RemoveModule("api.rego")
	p.rego.AddModule("api.rego", &rpi.RegoModule{Namespace: "api", Code: apiTestCode})

	return p.rego.Compile()
}

func selectContainerFromRunningContainers(containers []regoRunningContainer, r *rand.Rand) regoRunningContainer {
	numContainers := len(containers)
	return containers[r.Intn(numContainers)]
}

func idForRunningContainer(container *securityPolicyContainer, running []regoRunningContainer) (string, error) {
	for _, c := range running {
		if c.container == container {
			return c.containerID, nil
		}
	}

	return "", errors.New("Container isn't running")
}

func generateFragments(r *rand.Rand, minFragments int32) []*fragment {
	numFragments := randMinMax(r, minFragments, maxFragmentsInGeneratedConstraints)

	fragments := make([]*fragment, numFragments)
	for i := 0; i < int(numFragments); i++ {
		fragments[i] = generateFragment(r)
	}

	return fragments
}

func generateFragmentIssuer(r *rand.Rand) string {
	return randString(r, maxGeneratedFragmentIssuerLength)
}

func generateFragmentFeed(r *rand.Rand) string {
	return randString(r, maxGeneratedFragmentFeedLength)
}

func (gen *dataGenerator) uniqueFragmentNamespace() string {
	return gen.fragmentNamespaces.randUnique(gen.rng, generateFragmentNamespace)
}

func (gen *dataGenerator) uniqueFragmentIssuer() string {
	return gen.fragmentIssuers.randUnique(gen.rng, generateFragmentIssuer)
}

func (gen *dataGenerator) uniqueFragmentFeed() string {
	return gen.fragmentFeeds.randUnique(gen.rng, generateFragmentFeed)
}

func generateFragment(r *rand.Rand) *fragment {
	possibleIncludes := []string{"containers", "fragments", "external_processes"}
	numChoices := int(atLeastOneAtMost(r, int32(len(possibleIncludes))))
	includes := randChooseStrings(r, possibleIncludes, numChoices)
	return &fragment{
		issuer:     testDataGenerator.uniqueFragmentIssuer(),
		feed:       testDataGenerator.uniqueFragmentFeed(),
		minimumSVN: generateSVN(r),
		includes:   includes,
	}
}

func addStringsToArray(values []string, valuesToAdd []string) []string {
	toAdd := []string{}
	for _, valueToAdd := range valuesToAdd {
		add := true
		for _, value := range values {
			if value == valueToAdd {
				add = false
				break
			}
		}
		if add {
			toAdd = append(toAdd, valueToAdd)
		}
	}

	return append(values, toAdd...)
}

func removeStringsFromArray(values []string, valuesToRemove []string) []string {
	remain := make([]string, 0, len(values))
	for _, value := range values {
		keep := true
		for _, toRemove := range valuesToRemove {
			if value == toRemove {
				keep = false
				break
			}
		}
		if keep {
			remain = append(remain, value)
		}
	}

	return remain
}

func areStringArraysEqual(lhs []string, rhs []string) bool {
	if len(lhs) != len(rhs) {
		return false
	}

	sort.Strings(lhs)
	sort.Strings(rhs)

	for i, a := range lhs {
		if a != rhs[i] {
			return false
		}
	}

	return true
}

func (c securityPolicyContainer) clone() (*securityPolicyContainer, error) {
	contents, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}

	var clone securityPolicyContainer
	err = json.Unmarshal(contents, &clone)
	if err != nil {
		return nil, err
	}

	return &clone, nil
}

func (p externalProcess) clone() *externalProcess {
	envRules := make([]EnvRuleConfig, len(p.envRules))
	copy(envRules, p.envRules)

	return &externalProcess{
		command:          copyStrings(p.command),
		envRules:         envRules,
		workingDir:       p.workingDir,
		allowStdioAccess: p.allowStdioAccess,
	}
}

func (p containerExecProcess) clone() containerExecProcess {
	return containerExecProcess{
		Command: copyStrings(p.Command),
		Signals: p.Signals,
	}
}

func (c *securityPolicyContainer) toContainer() *Container {
	execProcesses := make([]ExecProcessConfig, len(c.ExecProcesses))
	for i, ep := range c.ExecProcesses {
		execProcesses[i] = ExecProcessConfig(ep)
	}

	capabilities := CapabilitiesConfig{
		Bounding:    c.Capabilities.Bounding,
		Effective:   c.Capabilities.Effective,
		Inheritable: c.Capabilities.Inheritable,
		Permitted:   c.Capabilities.Permitted,
		Ambient:     c.Capabilities.Ambient,
	}

	return &Container{
		Command:              CommandArgs(stringArrayToStringMap(c.Command)),
		EnvRules:             envRuleArrayToEnvRules(c.EnvRules),
		Layers:               Layers(stringArrayToStringMap(c.Layers)),
		WorkingDir:           c.WorkingDir,
		Mounts:               mountArrayToMounts(c.Mounts),
		AllowElevated:        c.AllowElevated,
		ExecProcesses:        execProcesses,
		Signals:              c.Signals,
		AllowStdioAccess:     c.AllowStdioAccess,
		NoNewPrivileges:      c.NoNewPrivileges,
		User:                 c.User,
		Capabilities:         &capabilities,
		SeccompProfileSHA256: c.SeccompProfileSHA256,
	}
}

func envRuleArrayToEnvRules(envRules []EnvRuleConfig) EnvRules {
	elements := make(map[string]EnvRuleConfig)
	for i, envRule := range envRules {
		elements[strconv.Itoa(i)] = envRule
	}
	return EnvRules{
		Elements: elements,
		Length:   len(envRules),
	}
}

func mountArrayToMounts(mounts []mountInternal) Mounts {
	elements := make(map[string]Mount)
	for i, mount := range mounts {
		elements[strconv.Itoa(i)] = Mount{
			Source:      mount.Source,
			Destination: mount.Destination,
			Type:        mount.Type,
			Options:     Options(stringArrayToStringMap(mount.Options)),
		}
	}

	return Mounts{
		Elements: elements,
		Length:   len(mounts),
	}
}

func (p externalProcess) toConfig() ExternalProcessConfig {
	return ExternalProcessConfig{
		Command:          p.command,
		WorkingDir:       p.workingDir,
		AllowStdioAccess: p.allowStdioAccess,
	}
}

func (f fragment) toConfig() FragmentConfig {
	return FragmentConfig{
		Issuer:     f.issuer,
		Feed:       f.feed,
		MinimumSVN: f.minimumSVN,
		Includes:   f.includes,
	}
}

func stringArrayToStringMap(values []string) StringArrayMap {
	elements := make(map[string]string)
	for i, value := range values {
		elements[strconv.Itoa(i)] = value
	}

	return StringArrayMap{
		Elements: elements,
		Length:   len(values),
	}
}

func (s *stringSet) randUniqueArray(r *rand.Rand, generator func(*rand.Rand) string, numItems int32) []string {
	items := make([]string, numItems)
	for i := 0; i < int(numItems); i++ {
		items[i] = s.randUnique(r, generator)
	}
	return items
}

func generateExternalProcesses(r *rand.Rand) []*externalProcess {
	var processes []*externalProcess

	numProcesses := atLeastOneAtMost(r, maxExternalProcessesInGeneratedConstraints)
	for i := 0; i < int(numProcesses); i++ {
		processes = append(processes, generateExternalProcess(r))
	}

	return processes
}

func generateExternalProcess(r *rand.Rand) *externalProcess {
	return &externalProcess{
		command:          generateCommand(r),
		envRules:         generateEnvironmentVariableRules(r),
		workingDir:       generateWorkingDir(r),
		allowStdioAccess: randBool(r),
	}
}

func randChoices(r *rand.Rand, numChoices int, numItems int) []int {
	shuffle := r.Perm(numItems)
	if numChoices > numItems {
		return shuffle
	}

	return shuffle[:numChoices]
}

func randChoicesWithReplacement(r *rand.Rand, numChoices int, numItems int) []int {
	choices := make([]int, numChoices)
	for i := 0; i < numChoices; i++ {
		choices[i] = r.Intn(numItems)
	}

	return choices
}

func randChooseStrings(r *rand.Rand, items []string, numChoices int) []string {
	numItems := len(items)
	choiceIndices := randChoices(r, numChoices, numItems)
	choices := make([]string, numChoices)
	for i, index := range choiceIndices {
		choices[i] = items[index]
	}
	return choices
}

func randChooseStringsWithReplacement(r *rand.Rand, items []string, numChoices int) []string {
	numItems := len(items)
	choiceIndices := randChoicesWithReplacement(r, numChoices, numItems)
	choices := make([]string, numChoices)
	for i, index := range choiceIndices {
		choices[i] = items[index]
	}
	return choices
}

func selectExternalProcessFromConstraints(constraints *generatedConstraints, r *rand.Rand) *externalProcess {
	numberOfProcessesInConstraints := len(constraints.externalProcesses)
	return constraints.externalProcesses[r.Intn(numberOfProcessesInConstraints)]
}

func (constraints *generatedConstraints) toPolicy() *securityPolicyInternal {
	return &securityPolicyInternal{
		Containers:                       constraints.containers,
		ExternalProcesses:                constraints.externalProcesses,
		Fragments:                        constraints.fragments,
		AllowPropertiesAccess:            constraints.allowGetProperties,
		AllowDumpStacks:                  constraints.allowDumpStacks,
		AllowRuntimeLogging:              constraints.allowRuntimeLogging,
		AllowEnvironmentVariableDropping: constraints.allowEnvironmentVariableDropping,
		AllowUnencryptedScratch:          constraints.allowUnencryptedScratch,
		AllowCapabilityDropping:          constraints.allowCapabilityDropping,
	}
}

func (constraints *generatedConstraints) toFragment() *securityPolicyFragment {
	return &securityPolicyFragment{
		Namespace:         constraints.namespace,
		SVN:               constraints.svn,
		Containers:        constraints.containers,
		ExternalProcesses: constraints.externalProcesses,
		Fragments:         constraints.fragments,
	}
}

func generateSemver(r *rand.Rand) string {
	major := randMinMax(r, 0, maxGeneratedVersion)
	minor := randMinMax(r, 0, maxGeneratedVersion)
	patch := randMinMax(r, 0, maxGeneratedVersion)
	return fmt.Sprintf("%d.%d.%d", major, minor, patch)
}

func assertKeyValue(object map[string]interface{}, key string, expectedValue interface{}) error {
	if actualValue, ok := object[key]; ok {
		if actualValue != expectedValue {
			return fmt.Errorf("incorrect value for no_new_privileges: %t != %t (expected)", actualValue, expectedValue)
		}
	} else {
		return fmt.Errorf("missing value for %s", key)
	}

	return nil
}

func assertDecisionJSONContains(t *testing.T, err error, expectedValues ...string) bool {
	if err == nil {
		t.Errorf("expected error to contain %v but got nil", expectedValues)
		return false
	}

	policyDecision, err := ExtractPolicyDecision(err.Error())
	if err != nil {
		t.Errorf("unable to extract policy decision from error: %v", err)
		return false
	}

	for _, expected := range expectedValues {
		if !strings.Contains(policyDecision, expected) {
			t.Errorf("expected error to contain %q", expected)
			return false
		}
	}

	return true
}

func assertDecisionJSONDoesNotContain(t *testing.T, err error, expectedValues ...string) bool {
	if err == nil {
		t.Errorf("expected error to contain %v but got nil", expectedValues)
		return false
	}

	policyDecision, err := ExtractPolicyDecision(err.Error())
	if err != nil {
		t.Errorf("unable to extract policy decision from error: %v", err)
		return false
	}

	for _, expected := range expectedValues {
		if strings.Contains(policyDecision, expected) {
			t.Errorf("expected error to not contain %q", expected)
			return false
		}
	}

	return true
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
