//go:build linux

package printer

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

func writeUSBAttribute(t *testing.T, path string, value string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(value+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLinuxZebraUSBDiscoveryRequiresExactBidirectionalDevice(t *testing.T) {
	root := t.TempDir()
	devicePath := filepath.Join(root, "1-7")
	interfacePath := filepath.Join(root, "1-7:1.0")
	endpointOutPath := filepath.Join(interfacePath, "ep_01")
	endpointInPath := filepath.Join(interfacePath, "ep_81")
	for _, path := range []string{devicePath, interfacePath, endpointOutPath, endpointInPath} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for name, value := range map[string]string{
		"idVendor": "0a5f", "idProduct": "0185", "serial": "FIXTURE00001", "busnum": "1", "devnum": "4",
	} {
		writeUSBAttribute(t, filepath.Join(devicePath, name), value)
	}
	for name, value := range map[string]string{
		"bInterfaceNumber": "00", "bInterfaceClass": "07", "bInterfaceSubClass": "01", "bInterfaceProtocol": "02",
	} {
		writeUSBAttribute(t, filepath.Join(interfacePath, name), value)
	}
	writeUSBAttribute(t, filepath.Join(endpointOutPath, "bmAttributes"), "02")
	writeUSBAttribute(t, filepath.Join(endpointOutPath, "bEndpointAddress"), "01")
	writeUSBAttribute(t, filepath.Join(endpointInPath, "bmAttributes"), "02")
	writeUSBAttribute(t, filepath.Join(endpointInPath, "bEndpointAddress"), "81")

	prober := &linuxUSBHostStatusProber{sysfsRoot: root, deviceRoot: "/dev/bus/usb"}
	device, err := prober.locate("FIXTURE00001")
	if err != nil {
		t.Fatal(err)
	}
	if device.path != "/dev/bus/usb/001/004" || device.interfaceNumber != 0 || device.endpointOut != 0x01 || device.endpointIn != 0x81 {
		t.Fatalf("device = %#v", device)
	}
	if _, err := prober.locate("OTHER"); err == nil {
		t.Fatal("accepted a non-matching serial")
	}
}

func TestUSBBulkTransferUsesBoundedUSBFSRequest(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) == 8 {
		if size := unsafe.Sizeof(usbdevfsBulkTransfer{}); size != 24 {
			t.Fatalf("amd64 usbdevfs bulk-transfer size = %d, want 24", size)
		}
		if usbdevfsBulkRequest != 0xc0185502 || usbdevfsClaimInterfaceRequest != 0x8004550f || usbdevfsReleaseInterfaceRequest != 0x80045510 {
			t.Fatalf("amd64 USBFS requests = %#x/%#x/%#x", usbdevfsBulkRequest, usbdevfsClaimInterfaceRequest, usbdevfsReleaseInterfaceRequest)
		}
	}
	buffer := make([]byte, 8)
	ioctl := func(_ uintptr, request uintptr, argument unsafe.Pointer) (uintptr, error) {
		if request != usbdevfsBulkRequest {
			t.Fatalf("request = %#x, want %#x", request, usbdevfsBulkRequest)
		}
		transfer := (*usbdevfsBulkTransfer)(argument)
		if transfer.Endpoint != 0x81 || transfer.Length != uint32(len(buffer)) || transfer.Timeout == 0 || transfer.Timeout > 1000 {
			t.Fatalf("transfer = %#v", transfer)
		}
		copy(unsafe.Slice((*byte)(transfer.Data), transfer.Length), []byte("reply"))
		return 5, nil
	}
	count, err := usbBulkTransfer(context.Background(), ioctl, 10, 0x81, buffer, time.Second)
	if err != nil || count != 5 || string(buffer[:count]) != "reply" {
		t.Fatalf("bulk transfer = %d, %q, %v", count, buffer[:count], err)
	}
}

func TestUSBPhysicalErrorsDistinguishPermissionBusyAndUnavailable(t *testing.T) {
	for _, test := range []struct {
		err  error
		want PhysicalErrorCategory
	}{{os.ErrPermission, PhysicalErrorZebraUSBPermission}, {syscall.EBUSY, PhysicalErrorZebraUSBBusy}, {os.ErrNotExist, PhysicalErrorZebraUSBUnavailable}, {errors.New("other"), PhysicalErrorZebraConnect}} {
		if got := usbPhysicalError(test.err, PhysicalErrorZebraConnect); got != test.want {
			t.Fatalf("usbPhysicalError(%v) = %q, want %q", test.err, got, test.want)
		}
	}
}

func TestUSBCancellationPreventsTransfer(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	ioctl := func(uintptr, uintptr, unsafe.Pointer) (uintptr, error) {
		t.Fatal("canceled probe touched the USB device")
		return 0, nil
	}
	if _, err := usbBulkTransfer(ctx, ioctl, 0, 0x01, []byte("~HS"), time.Second); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
}
