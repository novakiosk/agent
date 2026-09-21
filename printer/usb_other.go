//go:build !linux

package printer

func newUSBHostStatusProber() USBHostStatusProber {
	return nil
}
