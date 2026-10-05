package tpmsigner

import (
	"fmt"
	"github.com/google/go-tpm/tpm2/transport"
	"os"
	"syscall"
)

func openDevice() (transport.TPMCloser, error) {
	fd, err := syscall.Open("/dev/tpmrm0", syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open TPM resource manager: %w", err)
	}
	f := os.NewFile(uintptr(fd), "/dev/tpmrm0")
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if st.Mode()&os.ModeCharDevice == 0 {
		f.Close()
		return nil, fmt.Errorf("TPM resource manager is not a character device")
	}
	return transport.FromReadWriteCloser(f), nil
}
