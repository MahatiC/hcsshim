//go:build windows
// +build windows

package bridge

import (
	//"github.com/Microsoft/hcsshim/internal/protocol/guestrequest"
	//"github.com/opencontainers/runtime-spec/specs-go"

	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
)

const (
	// These are constants for v2 schema modify guest requests.

	// ResourceTypeMappedDirectory is the modify resource type for mapped
	// directories
	ResourceTypeMappedDirectory ResourceType = "MappedDirectory"
	// ResourceTypeSCSIDevice is the modify resources type for SCSI devices.
	// Note this type is not related to mounting a device in the guest, only
	// for operations on the SCSI device itself.
	// Currently it only supports Remove, to cleanly remove a SCSI device.
	ResourceTypeSCSIDevice ResourceType = "SCSIDevice"
	// ResourceTypeMappedVirtualDisk is the modify resource type for mapped
	// virtual disks
	ResourceTypeMappedVirtualDisk ResourceType = "MappedVirtualDisk"
	// ResourceTypeNetwork is the modify resource type for the `NetworkAdapterV2`
	// device.
	ResourceTypeNetwork          ResourceType = "Network"
	ResourceTypeNetworkNamespace ResourceType = "NetworkNamespace"
	// ResourceTypeCombinedLayers is the modify resource type for combined
	// layers
	ResourceTypeCombinedLayers ResourceType = "CombinedLayers"
	// ResourceTypeVPMemDevice is the modify resource type for VPMem devices
	ResourceTypeVPMemDevice ResourceType = "VPMemDevice"
	// ResourceTypeVPCIDevice is the modify resource type for vpci devices
	ResourceTypeVPCIDevice ResourceType = "VPCIDevice"
	// ResourceTypeContainerConstraints is the modify resource type for updating
	// container constraints
	ResourceTypeContainerConstraints ResourceType = "ContainerConstraints"
	ResourceTypeHvSocket             ResourceType = "HvSocket"
	// ResourceTypeSecurityPolicy is the modify resource type for updating the security
	// policy
	ResourceTypeSecurityPolicy ResourceType = "SecurityPolicy"
	// ResourceTypePolicyFragment is the modify resource type for injecting policy fragments.
	ResourceTypePolicyFragment ResourceType = "SecurityPolicyFragment"
)

// This class is used by a modify request to add or remove a combined layers
// structure in the guest. For windows, the GCS applies a filter in ContainerRootPath
// using the specified layers as the parent content. Ignores property ScratchPath
// since the container path is already the scratch path. For linux, the GCS unions
// the specified layers and ScratchPath together, placing the resulting union
// filesystem at ContainerRootPath.

type WCOWCombinedLayers struct {
	ContainerRootPath string            `json:"ContainerRootPath,omitempty"`
	Layers            []hcsschema.Layer `json:"Layers,omitempty"`
	ScratchPath       string            `json:"ScratchPath,omitempty"`
}

// Defines the schema for hosted settings passed to GCS

// SCSIDevice represents a SCSI device that is attached to the system.
type SCSIDevice struct {
	Controller uint8 `json:"Controller,omitempty"`
	Lun        uint8 `json:"Lun,omitempty"`
}

type WCOWMappedVirtualDisk struct {
	ContainerPath string `json:"ContainerPath,omitempty"`
	Lun           int32  `json:"Lun,omitempty"`
}

// SignalProcessOptionsWCOW is the options passed to WCOW to signal a given
// process.
type SignalProcessOptionsWCOW struct {
	Signal SignalValueWCOW `json:",omitempty"`
}

// LCOWConfidentialOptions is used to set various confidential container specific
// options.
type WCOWConfidentialOptions struct {
	EnforcerType          string `json:"EnforcerType,omitempty"`
	EncodedSecurityPolicy string `json:"EncodedSecurityPolicy,omitempty"`
	EncodedUVMReference   string `json:"EncodedUVMReference,omitempty"`
}

type WCOWSecurityPolicyFragment struct {
	Fragment string `json:"Fragment,omitempty"`
}
