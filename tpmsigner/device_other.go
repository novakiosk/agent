//go:build !linux

package tpmsigner

import (
	"errors"
	"github.com/google/go-tpm/tpm2/transport"
)

func openDevice() (transport.TPMCloser, error) {
	return nil, errors.New("TPM resource manager requires Linux")
}
