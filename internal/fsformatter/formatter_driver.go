package fsformatter

import (
	"fmt"
	"log"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	KERNEL_FORMAT_VOLUME_SERVICE_PATH                       = "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\KernelFSFormatter"
	REFS_CHECKSUM_TYPE                                      = "CHECKSUM_TYPE_SHA256"
	MAX_SIZE_OF_KERNEL_FORMAT_VOLUME_FORMAT_REFS_PARAMETERS = 16 * 8
	SIZE_OF_WCHAR                                           = int(unsafe.Sizeof(uint16(0)))
	KERNEL_FORMAT_VOLUME_MAX_VOLUME_LABEL_LENGTH            = (33 * SIZE_OF_WCHAR)
	KERNEL_FORMAT_PARTITION_SUFFIX_LENGTH                   = (15 * SIZE_OF_WCHAR)
	KERNEL_FORMAT_VOLUME_WIN32_DRIVER_PATH                  = "\\\\?\\KernelFSFormatter"

	KERNEL_FORMAT_MAX_ULONG_DECIMAL_LENGTH = uint32(10)
	KERNEL_FORMAT_ULONG_LENGTH             = uint32(KERNEL_FORMAT_MAX_ULONG_DECIMAL_LENGTH * uint32(SIZE_OF_WCHAR))
)

// Default KERNEL_FORMAT_VOLUME_DEFAULT_LABEL is L"" , that is wchar.
var KERNEL_FORMAT_VOLUME_DEFAULT_LABEL []uint16

type KERNEL_FORMAT_VOLUME_FILESYSTEM_TYPES uint32

const (
	KERNEL_FORMAT_VOLUME_FILESYSTEM_TYPE_INVALID = KERNEL_FORMAT_VOLUME_FILESYSTEM_TYPES(iota)
	KERNEL_FORMAT_VOLUME_FILESYSTEM_TYPE_REFS    = KERNEL_FORMAT_VOLUME_FILESYSTEM_TYPES(1)
	KERNEL_FORMAT_VOLUME_FILESYSTEM_TYPE_MAX     = KERNEL_FORMAT_VOLUME_FILESYSTEM_TYPES(2)
)

func (filesystemType KERNEL_FORMAT_VOLUME_FILESYSTEM_TYPES) String() string {
	switch filesystemType {
	case KERNEL_FORMAT_VOLUME_FILESYSTEM_TYPE_INVALID:
		return "KERNEL_FORMAT_VOLUME_FILESYSTEM_TYPE_INVALID"
	case KERNEL_FORMAT_VOLUME_FILESYSTEM_TYPE_REFS:
		return "KERNEL_FORMAT_VOLUME_FILESYSTEM_TYPE_REFS"
	case KERNEL_FORMAT_VOLUME_FILESYSTEM_TYPE_MAX:
		return "KERNEL_FORMAT_VOLUME_FILESYSTEM_TYPE_MAX"
	default:
		return "Unknown"
	}
}

type KERNEL_FORMAT_VOLUME_FORMAT_REFS_PARAMETERS struct {
	ClusterSize          uint64
	MetadataChecksumType uint16
	UseDataIntegrity     bool
	MajorVersion         uint16
	MinorVersion         uint16
}

type KERNEL_FORMAT_VOLUME_FORMAT_INPUT_BUFFER_FLAGS uint32

const KERNEL_FORMAT_VOLUME_FORMAT_INPUT_BUFFER_FLAG_NONE = KERNEL_FORMAT_VOLUME_FORMAT_INPUT_BUFFER_FLAGS(0x00000000)

func (flag KERNEL_FORMAT_VOLUME_FORMAT_INPUT_BUFFER_FLAGS) String() string {
	switch flag {
	case KERNEL_FORMAT_VOLUME_FORMAT_INPUT_BUFFER_FLAG_NONE:
		return "KERNEL_FORMAT_VOLUME_FORMAT_INPUT_BUFFER_FLAG_NONE"
	default:
		return "Unknown"
	}
}

type KERNEL_FORMAT_VOLUME_FORMAT_FS_PARAMETERS struct {
	FileSystemType KERNEL_FORMAT_VOLUME_FILESYSTEM_TYPES

	VolumeLabel       [KERNEL_FORMAT_VOLUME_MAX_VOLUME_LABEL_LENGTH / SIZE_OF_WCHAR]uint16 // utf16fromstring [KERNEL_FORMAT_VOLUME_MAX_VOLUME_LABEL_LENGTH / sizeof(WCHAR)];
	VolumeLabelLength uint16                                                               // In bytes.
	/*
	   union {

	       KERNEL_FORMAT_VOLUME_FORMAT_REFS_PARAMETERS RefsParameters;

	       //
	       //  This structure can't grow in size nor change in alignment. 16 ULONGLONGs
	       //  should be more than enough for supporting other filesystems down the
	       //  line. This also serves to enforce 8 byte alignment.
	       //
	       Reserved [16]uint64
	   };
	*/
	refsFormatterParams interface{} //KERNEL_FORMAT_VOLUME_FORMAT_REFS_PARAMETERS
	//Reserved            [16]uint64
}

type KERNEL_FORMAT_VOLUME_FORMAT_INPUT_BUFFER struct {
	Size         uint64
	FsParameters KERNEL_FORMAT_VOLUME_FORMAT_FS_PARAMETERS
	Flags        KERNEL_FORMAT_VOLUME_FORMAT_INPUT_BUFFER_FLAGS
	Reserved     [4]uint32

	DiskPathLength uint16 // In bytes.
	//DiskPathBuffer string // uint16 ptr WCHAR [ANYSIZE_ARRAY]
	DiskPathBuffer []uint16
}

type KERNEL_FORMAT_VOLUME_FORMAT_OUTPUT_BUFFER_FLAGS uint32

const KERNEL_FORMAT_VOLUME_FORMAT_OUTPUT_BUFFER_FLAG_NONE = KERNEL_FORMAT_VOLUME_FORMAT_OUTPUT_BUFFER_FLAGS(0x00000000)

func (flag KERNEL_FORMAT_VOLUME_FORMAT_OUTPUT_BUFFER_FLAGS) String() string {
	switch flag {
	case KERNEL_FORMAT_VOLUME_FORMAT_OUTPUT_BUFFER_FLAG_NONE:
		return "KERNEL_FORMAT_VOLUME_FORMAT_OUTPUT_BUFFER_FLAG_NONE"
	default:
		return "Unknown"
	}
}

type KERNEL_FORMAT_VOLUME_FORMAT_OUTPUT_BUFFER struct {
	Size uint32

	Flags KERNEL_FORMAT_VOLUME_FORMAT_OUTPUT_BUFFER_FLAGS

	Reserved [4]uint32

	VolumePathLength uint16   // In bytes.
	VolumePathBuffer []uint16 // wchar [ANYSIZE_ARRAY]
}

func KmFmtCreateFormatOutputBuffer(diskPath string) (*KERNEL_FORMAT_VOLUME_FORMAT_OUTPUT_BUFFER, error) {
	utf16DiskPath := utf16.Encode([]rune(diskPath))
	wcharDiskPathLength := uint16(len(utf16DiskPath) * SIZE_OF_WCHAR)
	log.Printf("Output: wchar disk path length is %v", wcharDiskPathLength)

	bufferSize := uint32(unsafe.Offsetof(KERNEL_FORMAT_VOLUME_FORMAT_OUTPUT_BUFFER{}.VolumePathLength)) + uint32(wcharDiskPathLength) + uint32(KERNEL_FORMAT_PARTITION_SUFFIX_LENGTH)
	log.Printf("output buffer size is %v", bufferSize)

	buf := make([]uint16, bufferSize)
	outputBuffer := (*KERNEL_FORMAT_VOLUME_FORMAT_OUTPUT_BUFFER)(unsafe.Pointer(&buf[0]))
	outputBuffer.Size = uint32(bufferSize)

	return outputBuffer, nil
}

/*
KERNEL_FORMAT_VOLUME_FORMAT_FS_PARAMETERS

	type KERNEL_FORMAT_VOLUME_FORMAT_INPUT_BUFFER struct {
	    Size         uint64
	    FsParameters KERNEL_FORMAT_VOLUME_FORMAT_FS_PARAMETERS
	    Flags        KERNEL_FORMAT_VOLUME_FORMAT_INPUT_BUFFER_FLAGS
	    Reserved     [4]uint32

	    DiskPathLength uint16 // In bytes.
	    //DiskPathBuffer string // uint16 ptr WCHAR [ANYSIZE_ARRAY]
	    DiskPathBuffer []uint16
	}
*/
func calculatDiskPathBufferSize(wcharDiskPathLength uint16) uint32 {
	bufferSize := uint32(unsafe.Sizeof(KERNEL_FORMAT_VOLUME_FORMAT_INPUT_BUFFER{}.Size) +
		unsafe.Offsetof(KERNEL_FORMAT_VOLUME_FORMAT_FS_PARAMETERS{}.refsFormatterParams) +
		/* this is for the union specifically */ MAX_SIZE_OF_KERNEL_FORMAT_VOLUME_FORMAT_REFS_PARAMETERS +
		unsafe.Sizeof(KERNEL_FORMAT_VOLUME_FORMAT_INPUT_BUFFER{}.Flags) +
		unsafe.Sizeof(KERNEL_FORMAT_VOLUME_FORMAT_INPUT_BUFFER{}.Reserved) +
		unsafe.Sizeof(KERNEL_FORMAT_VOLUME_FORMAT_INPUT_BUFFER{}.DiskPathLength))
	fmt.Printf("\n calculatDiskPathBufferSize offset calculation %v \n", bufferSize)
	fmt.Printf("\n calculatDiskPathBufferSize wcharDiskPathLength size %v \n", uint32(wcharDiskPathLength))
	bufferSize += uint32(wcharDiskPathLength)

	return bufferSize
}

func KmFmtCreateFormatInputBuffer(diskPath string) (*KERNEL_FORMAT_VOLUME_FORMAT_INPUT_BUFFER, error) {
	log.Printf("Constructing input buffer for fsFormatter \n")

	// Construct refs parameters and set inputBuffer.FsParameters.refsFormatterParams
	// TODO(kiashok): Confirm the max size with Yanran/Raj
	refsParametersBuf := make([]byte, MAX_SIZE_OF_KERNEL_FORMAT_VOLUME_FORMAT_REFS_PARAMETERS)
	refsParameters := (*KERNEL_FORMAT_VOLUME_FORMAT_REFS_PARAMETERS)(unsafe.Pointer(&refsParametersBuf[0]))

	// var refsParameters KERNEL_FORMAT_VOLUME_FORMAT_REFS_PARAMETERS
	refsParameters.ClusterSize = 0x1000
	uint16ChecksumType, err := windows.UTF16PtrFromString(REFS_CHECKSUM_TYPE)
	if err != nil {
		return nil, err
	}
	refsParameters.MetadataChecksumType = *uint16ChecksumType
	refsParameters.UseDataIntegrity = true
	refsParameters.MajorVersion = 3
	refsParameters.MinorVersion = 14

	// Construct required input buffer of format KERNEL_FORMAT_VOLUME_FORMAT_INPUT_BUFFER
	// volumeLabel := KERNEL_FORMAT_VOLUME_DEFAULT_LABEL // Scratch disk need not be partitioned. Therefore pass wchar empty string.
	utf16DiskPath := utf16.Encode([]rune(diskPath))
	wcharDiskPathLength := uint16(len(utf16DiskPath) * SIZE_OF_WCHAR)
	bufferSize := calculatDiskPathBufferSize(wcharDiskPathLength)
	log.Printf("input buffer size is %v", bufferSize)

	buf := make([]byte, bufferSize)
	//utf16DiskPath = utf16.Encode([]rune(diskPath))
	inputBuffer := (*KERNEL_FORMAT_VOLUME_FORMAT_INPUT_BUFFER)(unsafe.Pointer(&buf[0]))

	inputBuffer.Size = uint64(bufferSize)
	inputBuffer.FsParameters.FileSystemType = KERNEL_FORMAT_VOLUME_FILESYSTEM_TYPE_REFS
	// inputBuffer.FsParameters.VolumeLabel = volumeLabel
	// TODO: Ask Yanran if setting to 0 is ok
	// Not setting inputBuffer.FsParameters.VolumeLabel to leave it empty
	inputBuffer.FsParameters.VolumeLabelLength = 0 // Scratch disk need not be partitioned. Therefore pass wchar empty string.
	inputBuffer.Flags = KERNEL_FORMAT_VOLUME_FORMAT_INPUT_BUFFER_FLAG_NONE
	inputBuffer.DiskPathLength = wcharDiskPathLength
	inputBuffer.DiskPathBuffer = utf16DiskPath
	inputBuffer.FsParameters.refsFormatterParams = *refsParameters

	return inputBuffer, nil
}
