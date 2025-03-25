//go:build windows
// +build windows

package main

import (
	"context"
	"fmt"
	"log"

	"github.com/Microsoft/hcsshim/internal/windevice"
)

const (
	// This is used to construct the disk path that fsFormatter
	// understands. `harddisk%d` here refers to the disk number
	// associated with the corresponding lun of the attached
	// scsi device.
	virtualDevObjectPathFormat = "\\Device\\Harddisk%d\\Partition0"
)

func main() {
	controller := 0
	lun := 1
	ctx := context.Background()
	devPath, diskNumber, err := windevice.GetScsiDevicePathAndDiskNumberFromControllerLUN(ctx,
		uint8(controller), //0, /* Only one controller allowed in wcow hyperv */
		uint8(lun))
	if err != nil {
		fmt.Printf("error getting diskNumber for LUN %d", lun)
	}
	fmt.Printf("devPath: %v diskNumber: %v \n", devPath, diskNumber)

	// just doing this for testing!!
	// diskNumber = 1
	diskPath := fmt.Sprintf(virtualDevObjectPathFormat, diskNumber)
	fmt.Printf("\n Disk path is %v", diskPath)

	mountedVolumePath, err := windevice.InvokeFsFormatter(ctx, diskPath)
	if err != nil {
		fmt.Printf("error invoking formatter %v", err)
	}
	log.Printf("\n mountedVolumePath returned from InvokeFsFormatter: %v", mountedVolumePath)
}

/*
	Size         uint32
	FsParameters KERNEL_FORMAT_VOLUME_FORMAT_FS_PARAMETERS
	Flags        KERNEL_FORMAT_VOLUME_FORMAT_INPUT_BUFFER_FLAGS
	Reserved     [4]uint32

	DiskPathLength uint16 // In bytes.
	//DiskPathBuffer string // uint16 ptr WCHAR [ANYSIZE_ARRAY]
	DiskPathBuffer []uint16
*/
