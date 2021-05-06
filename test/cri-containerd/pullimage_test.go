// +build functional

package cri_containerd

import (
	"context"
	"strings"
	"testing"
	"time"
)

const (
	// Go specific timestamp format which needs to be used for parsing the timestamps
	// generated by the `dir` command.
	timestampFormat = "01/02/2006 15:04 PM"
	// These values come from the Dockerfile for the test nanoserver image
	testDirName                     = "testdir"
	testLinkName                    = "fakelink"
	testDirPath                     = "C:\\Users\\Public"
	imageWindowsNanoserverTestImage = "cplatpublic.azurecr.io/timestamp:latest"
)

func Test_PullImageTimestamps(t *testing.T) {
	requireFeatures(t, featureWCOWHypervisor)

	client := newTestRuntimeClient(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// startTimestamp must be saved BEFORE pulling the image
	// We need the timestamp in UTC because container timestamps are in UTC.
	startTimestamp := time.Now().UTC()

	// Remove existing image first
	removeImages(t, []string{imageWindowsNanoserverTestImage})

	// Sleep at least 1 minute before pulling the image. This is because if the pull
	// image operation finishes in the same minute as that of the startTimestamp
	// the time.Before function in go will return false and the test will not catch
	// the bug.
	time.Sleep(1 * time.Minute)

	// Now pull the image
	pullRequiredImages(t, []string{imageWindowsNanoserverTestImage})
	defer removeImages(t, []string{imageWindowsNanoserverTestImage})

	sandboxRequest := getRunPodSandboxRequest(t, wcowHypervisor18362RuntimeHandler, nil)

	podID := runPodSandbox(t, client, ctx, sandboxRequest)
	defer removePodSandbox(t, client, ctx, podID)
	defer stopPodSandbox(t, client, ctx, podID)

	command := []string{
		"cmd",
		"/c",
		"ping",
		"-t",
		"127.0.0.1",
	}

	execCommand := []string{
		"cmd",
		"/c",
		"dir",
		testDirPath,
	}

	containerId := createContainerInSandbox(t, client, ctx, podID, t.Name()+"-Container", imageWindowsNanoserverTestImage, command, nil, nil, sandboxRequest.Config)
	defer removeContainer(t, client, ctx, containerId)

	startContainer(t, client, ctx, containerId)
	defer stopContainer(t, client, ctx, containerId)

	output, errorMsg, exitCode := execContainer(t, client, ctx, containerId, execCommand)

	if exitCode != 0 || len(errorMsg) > 0 {
		t.Fatalf("Failed to exec inside container: %s, exitcode: %v\n",
			errorMsg, exitCode)
	}

	lines := strings.Split(output, "\n")
	var fakelinkTimestamp, testdirTimestamp time.Time
	var err error
	for _, line := range lines {
		tokens := strings.Split(line, " ")
		if strings.Contains(line, testLinkName) {
			fakelinkTimestamp, err = time.Parse(timestampFormat, tokens[0]+" "+tokens[2]+" "+tokens[3])
			if err != nil {
				t.Fatalf("Failed to parse timestamp : %s\n", err)
			}
		} else if strings.Contains(line, testDirName) {
			testdirTimestamp, err = time.Parse(timestampFormat, tokens[0]+" "+tokens[2]+" "+tokens[3])
			if err != nil {
				t.Fatalf("Failed to parse timestamp : %s\n", err)
			}
		}
	}

	t.Logf("startTimestamp: %v, testdir last write timestamp: %v, fakelink last write timestamp: %v\n", startTimestamp, testdirTimestamp, fakelinkTimestamp)

	if startTimestamp.Before(testdirTimestamp) || startTimestamp.Before(fakelinkTimestamp) {
		t.Fatalf("Timestamps not in order. startTimestamp should be less than testdirTimestamp and fakelinkTimestamp")
	}
}
