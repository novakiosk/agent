//go:build linux

package printer

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	zebraUSBVendorID  = "0a5f"
	zebraUSBProductID = "0185"

	usbIOCNRShift   = 0
	usbIOCTypeShift = 8
	usbIOCSizeShift = 16
	usbIOCDirShift  = 30
	usbIOCWrite     = 1
	usbIOCRead      = 2
)

type usbdevfsBulkTransfer struct {
	Endpoint uint32
	Length   uint32
	Timeout  uint32
	Data     unsafe.Pointer
}

var (
	usbdevfsBulkRequest             = usbIOC(usbIOCRead|usbIOCWrite, 'U', 2, unsafe.Sizeof(usbdevfsBulkTransfer{}))
	usbdevfsClaimInterfaceRequest   = usbIOC(usbIOCRead, 'U', 15, unsafe.Sizeof(uint32(0)))
	usbdevfsReleaseInterfaceRequest = usbIOC(usbIOCRead, 'U', 16, unsafe.Sizeof(uint32(0)))
)

type usbFSIoctlFunc func(uintptr, uintptr, unsafe.Pointer) (uintptr, error)

type linuxUSBHostStatusProber struct {
	sysfsRoot  string
	deviceRoot string
	ioctl      usbFSIoctlFunc
}

type zebraUSBDevice struct {
	path            string
	interfaceNumber uint32
	endpointOut     uint8
	endpointIn      uint8
}

func newUSBHostStatusProber() USBHostStatusProber {
	return &linuxUSBHostStatusProber{
		sysfsRoot:  "/sys/bus/usb/devices",
		deviceRoot: "/dev/bus/usb",
		ioctl:      systemUSBFSIoctl,
	}
}

func (p *linuxUSBHostStatusProber) ProbeZebraHostStatus(ctx context.Context, serial string, timeout time.Duration) ([]byte, PhysicalErrorCategory) {
	if p == nil || ctx == nil || !safeUSBSerial(serial) || timeout <= 0 {
		return nil, PhysicalErrorZebraUSBUnavailable
	}
	device, err := p.locate(serial)
	if err != nil {
		return nil, PhysicalErrorZebraUSBUnavailable
	}
	info, err := os.Lstat(device.path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeCharDevice == 0 {
		return nil, usbPhysicalError(err, PhysicalErrorZebraUSBUnavailable)
	}
	file, err := os.OpenFile(device.path, os.O_RDWR, 0)
	if err != nil {
		return nil, usbPhysicalError(err, PhysicalErrorZebraConnect)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || openedInfo.Mode()&os.ModeCharDevice == 0 || !os.SameFile(info, openedInfo) {
		return nil, usbPhysicalError(err, PhysicalErrorZebraUSBUnavailable)
	}

	ioctl := p.ioctl
	if ioctl == nil {
		ioctl = systemUSBFSIoctl
	}
	interfaceNumber := device.interfaceNumber
	if _, err := ioctl(file.Fd(), usbdevfsClaimInterfaceRequest, unsafe.Pointer(&interfaceNumber)); err != nil {
		return nil, usbPhysicalError(err, PhysicalErrorZebraConnect)
	}
	defer func() {
		_, _ = ioctl(file.Fd(), usbdevfsReleaseInterfaceRequest, unsafe.Pointer(&interfaceNumber))
	}()

	command := []byte("~HS")
	written, err := usbBulkTransfer(ctx, ioctl, file.Fd(), device.endpointOut, command, timeout)
	if err != nil || written != len(command) {
		return nil, PhysicalErrorZebraWrite
	}

	data := make([]byte, 0, maxZebraResponseBytes)
	for len(data) < maxZebraResponseBytes {
		if _, parseErr := parseZebraHS(data); parseErr == nil {
			return data, ""
		}
		buffer := make([]byte, min(512, maxZebraResponseBytes-len(data)))
		count, readErr := usbBulkTransfer(ctx, ioctl, file.Fd(), device.endpointIn, buffer, timeout)
		if count > 0 {
			data = append(data, buffer[:count]...)
		}
		if readErr != nil {
			if errors.Is(readErr, syscall.ETIMEDOUT) || errors.Is(readErr, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
				if len(data) == 0 {
					return nil, PhysicalErrorZebraNoResponse
				}
				return nil, PhysicalErrorZebraTimeout
			}
			return nil, usbPhysicalError(readErr, PhysicalErrorZebraConnect)
		}
	}
	return nil, PhysicalErrorZebraOversize
}

func usbPhysicalError(err error, fallback PhysicalErrorCategory) PhysicalErrorCategory {
	if errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) {
		return PhysicalErrorZebraUSBPermission
	}
	if errors.Is(err, syscall.EBUSY) {
		return PhysicalErrorZebraUSBBusy
	}
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENODEV) {
		return PhysicalErrorZebraUSBUnavailable
	}
	return fallback
}

func (p *linuxUSBHostStatusProber) locate(serial string) (zebraUSBDevice, error) {
	entries, err := os.ReadDir(p.sysfsRoot)
	if err != nil {
		return zebraUSBDevice{}, err
	}
	candidates := make([]zebraUSBDevice, 0, 1)
	for _, entry := range entries {
		devicePath := filepath.Join(p.sysfsRoot, entry.Name())
		if !strings.EqualFold(readUSBAttribute(devicePath, "idVendor"), zebraUSBVendorID) || !strings.EqualFold(readUSBAttribute(devicePath, "idProduct"), zebraUSBProductID) || readUSBAttribute(devicePath, "serial") != serial {
			continue
		}
		busNumber, busErr := strconv.Atoi(readUSBAttribute(devicePath, "busnum"))
		deviceNumber, deviceErr := strconv.Atoi(readUSBAttribute(devicePath, "devnum"))
		if busErr != nil || deviceErr != nil || busNumber < 1 || busNumber > 999 || deviceNumber < 1 || deviceNumber > 999 {
			continue
		}
		interfacePaths, _ := filepath.Glob(devicePath + ":*")
		for _, interfacePath := range interfacePaths {
			if readUSBAttribute(interfacePath, "bInterfaceNumber") != "00" || readUSBAttribute(interfacePath, "bInterfaceClass") != "07" || readUSBAttribute(interfacePath, "bInterfaceSubClass") != "01" || readUSBAttribute(interfacePath, "bInterfaceProtocol") != "02" {
				continue
			}
			endpointOut, endpointIn, endpointErr := zebraBulkEndpoints(interfacePath)
			if endpointErr != nil {
				continue
			}
			candidates = append(candidates, zebraUSBDevice{
				path:            filepath.Join(p.deviceRoot, fmt.Sprintf("%03d", busNumber), fmt.Sprintf("%03d", deviceNumber)),
				interfaceNumber: 0,
				endpointOut:     endpointOut,
				endpointIn:      endpointIn,
			})
		}
	}
	if len(candidates) != 1 {
		return zebraUSBDevice{}, errors.New("expected one eligible Zebra USB device")
	}
	return candidates[0], nil
}

func zebraBulkEndpoints(interfacePath string) (uint8, uint8, error) {
	endpointPaths, _ := filepath.Glob(filepath.Join(interfacePath, "ep_??"))
	var endpointOut uint8
	var endpointIn uint8
	for _, endpointPath := range endpointPaths {
		if readUSBAttribute(endpointPath, "bmAttributes") != "02" {
			continue
		}
		value, err := strconv.ParseUint(readUSBAttribute(endpointPath, "bEndpointAddress"), 16, 8)
		if err != nil || value == 0 {
			continue
		}
		endpoint := uint8(value)
		if endpoint&0x80 == 0 {
			if endpointOut != 0 {
				return 0, 0, errors.New("multiple bulk OUT endpoints")
			}
			endpointOut = endpoint
		} else {
			if endpointIn != 0 {
				return 0, 0, errors.New("multiple bulk IN endpoints")
			}
			endpointIn = endpoint
		}
	}
	if endpointOut == 0 || endpointIn == 0 {
		return 0, 0, errors.New("bidirectional bulk endpoints unavailable")
	}
	return endpointOut, endpointIn, nil
}

func readUSBAttribute(path string, name string) string {
	data, err := os.ReadFile(filepath.Join(path, name))
	if err != nil || len(data) == 0 || len(data) > 256 {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func usbBulkTransfer(ctx context.Context, ioctl usbFSIoctlFunc, fileDescriptor uintptr, endpoint uint8, buffer []byte, timeout time.Duration) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if len(buffer) == 0 {
		return 0, errors.New("empty USB transfer")
	}
	deadline := time.Now().Add(timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return 0, context.DeadlineExceeded
	}
	timeoutMilliseconds := (remaining + time.Millisecond - 1) / time.Millisecond
	transfer := usbdevfsBulkTransfer{
		Endpoint: uint32(endpoint),
		Length:   uint32(len(buffer)),
		Timeout:  uint32(timeoutMilliseconds),
		Data:     unsafe.Pointer(&buffer[0]),
	}
	result, err := ioctl(fileDescriptor, usbdevfsBulkRequest, unsafe.Pointer(&transfer))
	runtime.KeepAlive(buffer)
	if err != nil {
		return 0, err
	}
	if result > uintptr(len(buffer)) {
		return 0, errors.New("invalid USB transfer length")
	}
	return int(result), nil
}

func systemUSBFSIoctl(fileDescriptor uintptr, request uintptr, argument unsafe.Pointer) (uintptr, error) {
	result, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fileDescriptor, request, uintptr(argument))
	if errno != 0 {
		return result, errno
	}
	return result, nil
}

func usbIOC(direction uintptr, kind uintptr, number uintptr, size uintptr) uintptr {
	return direction<<usbIOCDirShift | kind<<usbIOCTypeShift | number<<usbIOCNRShift | size<<usbIOCSizeShift
}
