// Package tpmsigner owns a transient, TPM-generated P-256 signing key. Durable
// bundles contain only TPM-wrapped private material and must be kept secret by
// the identity owner because Auth authorizes use of the key.
package tpmsigner

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// Bundle is versioned metadata for one atomic identity record. Byte fields use
// Go's JSON base64 encoding. Public and Private include their TPM2B length prefix;
// ParentTemplate is the exact TPMT_PUBLIC input, names are raw TPM names.
type Bundle struct {
	Version         int    `json:"version"`
	ParentHierarchy uint32 `json:"parentHierarchy"`
	ParentTemplate  []byte `json:"parentTemplate"`
	ParentName      []byte `json:"parentName"`
	Public          []byte `json:"public"`
	Private         []byte `json:"private"`
	Name            []byte `json:"name"`
	Auth            []byte `json:"auth"`
}

// Signer serializes commands and owns its connection and loaded child handle.
// It never exports a private scalar. Public returns a defensive copy.
type Signer struct {
	mu       sync.Mutex
	t        transport.TPMCloser
	handle   tpm2.TPMHandle
	name     tpm2.TPM2BName
	auth     []byte
	public   *ecdsa.PublicKey
	closed   bool
	closeErr error
}

var _ crypto.Signer = (*Signer)(nil)

// The parent input is frozen here, independent of mutable upstream templates.
func parentTemplate() tpm2.TPMTPublic {
	return tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM: true, FixedParent: true, SensitiveDataOrigin: true,
			UserWithAuth: true, NoDA: true, Restricted: true, Decrypt: true,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			Symmetric: tpm2.TPMTSymDefObject{
				Algorithm: tpm2.TPMAlgAES,
				KeyBits:   tpm2.NewTPMUSymKeyBits(tpm2.TPMAlgAES, tpm2.TPMKeyBits(128)),
				Mode:      tpm2.NewTPMUSymMode(tpm2.TPMAlgAES, tpm2.TPMAlgCFB),
			},
			CurveID: tpm2.TPMECCNistP256,
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
			X: tpm2.TPM2BECCParameter{Buffer: make([]byte, 32)},
			Y: tpm2.TPM2BECCParameter{Buffer: make([]byte, 32)},
		}),
	}
}
func childTemplate() tpm2.TPMTPublic {
	return tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM: true, FixedParent: true, SensitiveDataOrigin: true,
			UserWithAuth: true, SignEncrypt: true,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			Symmetric: tpm2.TPMTSymDefObject{Algorithm: tpm2.TPMAlgNull},
			Scheme: tpm2.TPMTECCScheme{
				Scheme:  tpm2.TPMAlgECDSA,
				Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256}),
			},
			CurveID: tpm2.TPMECCNistP256,
			KDF:     tpm2.TPMTKDFScheme{Scheme: tpm2.TPMAlgNull},
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{}),
	}
}
func invalid() error { return errors.New("invalid or unsupported TPM identity bundle") }

// ValidateBundle performs bounded, canonical validation without opening the TPM.
// Authenticity of the opaque wrapped private blob is established only by Load.
func ValidateBundle(b Bundle) (*ecdsa.PublicKey, error) {
	if b.Version != 1 || b.ParentHierarchy != uint32(tpm2.TPMRHOwner) ||
		!bytes.Equal(b.ParentTemplate, tpm2.Marshal(parentTemplate())) ||
		len(b.ParentName) != 34 || b.ParentName[0] != 0 || b.ParentName[1] != byte(tpm2.TPMAlgSHA256) ||
		len(b.Name) != 34 || len(b.Auth) != 32 ||
		len(b.Public) < 2 || len(b.Public) > 1024 || len(b.Private) < 3 || len(b.Private) > 2048 {
		return nil, invalid()
	}
	priv, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](b.Private)
	if err != nil || !bytes.Equal(tpm2.Marshal(*priv), b.Private) || len(priv.Buffer) == 0 {
		return nil, invalid()
	}
	pub, err := tpm2.Unmarshal[tpm2.TPM2BPublic](b.Public)
	if err != nil || !bytes.Equal(tpm2.Marshal(*pub), b.Public) {
		return nil, invalid()
	}
	area, err := pub.Contents()
	if err != nil || !bytes.Equal(tpm2.Marshal(*area), pub.Bytes()) {
		return nil, invalid()
	}
	point, err := area.Unique.ECC()
	if err != nil || len(point.X.Buffer) != 32 || len(point.Y.Buffer) != 32 {
		return nil, invalid()
	}
	expected := childTemplate()
	expected.Unique = area.Unique
	if !bytes.Equal(tpm2.Marshal(expected), tpm2.Marshal(*area)) {
		return nil, invalid()
	}
	name, err := tpm2.ObjectName(area)
	if err != nil || !bytes.Equal(name.Buffer, b.Name) {
		return nil, invalid()
	}
	key := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(point.X.Buffer), Y: new(big.Int).SetBytes(point.Y.Buffer)}
	if !key.Curve.IsOnCurve(key.X, key.Y) {
		return nil, invalid()
	}
	return key, nil
}

// Create explicitly creates a new key on /dev/tpmrm0. It does not persist state.
func Create() (*Signer, Bundle, error) {
	t, err := openDevice()
	if err != nil {
		return nil, Bundle{}, err
	}
	return create(t)
}

// Load recreates the exact parent and loads the existing child, with no fallback.
func Load(b Bundle) (*Signer, error) {
	if _, err := ValidateBundle(b); err != nil {
		return nil, err
	}
	t, err := openDevice()
	if err != nil {
		return nil, err
	}
	return load(t, b)
}
func primary(t transport.TPMCloser) (*tpm2.CreatePrimaryResponse, error) {
	p, err := (tpm2.CreatePrimary{PrimaryHandle: tpm2.TPMRHOwner, InPublic: tpm2.New2B(parentTemplate())}).Execute(t)
	if err != nil {
		return nil, fmt.Errorf("TPM owner primary unavailable (existing hierarchy policy must permit creation): %w", err)
	}
	return p, nil
}
func flush(t transport.TPMCloser, h tpm2.TPMHandle) error {
	_, err := (tpm2.FlushContext{FlushHandle: h}).Execute(t)
	return err
}
func create(t transport.TPMCloser) (s *Signer, b Bundle, err error) {
	defer func() {
		if err != nil {
			b = Bundle{}
		}
	}()
	defer func() {
		if err != nil {
			if s != nil {
				err = errors.Join(err, s.Close())
				s = nil
			} else {
				err = errors.Join(err, t.Close())
			}
		}
	}()
	p, err := primary(t)
	if err != nil {
		return nil, b, err
	}
	defer func() {
		err = errors.Join(err, flush(t, p.ObjectHandle))
	}()
	auth := make([]byte, 32)
	if _, err = rand.Read(auth); err != nil {
		return nil, b, err
	}
	c, err := (tpm2.Create{
		ParentHandle: tpm2.NamedHandle{Handle: p.ObjectHandle, Name: p.Name},
		InSensitive: tpm2.TPM2BSensitiveCreate{Sensitive: &tpm2.TPMSSensitiveCreate{
			UserAuth: tpm2.TPM2BAuth{Buffer: auth},
			Data:     tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{}),
		}},
		InPublic: tpm2.New2B(childTemplate()),
	}).Execute(t)
	if err != nil {
		return nil, b, fmt.Errorf("TPM create signing key: %w", err)
	}
	area, err := c.OutPublic.Contents()
	if err != nil {
		return nil, b, err
	}
	name, err := tpm2.ObjectName(area)
	if err != nil {
		return nil, b, err
	}
	b = Bundle{Version: 1, ParentHierarchy: uint32(tpm2.TPMRHOwner), ParentTemplate: tpm2.Marshal(parentTemplate()), ParentName: bytes.Clone(p.Name.Buffer), Public: tpm2.Marshal(c.OutPublic), Private: tpm2.Marshal(c.OutPrivate), Name: bytes.Clone(name.Buffer), Auth: auth}
	s, err = loadChild(t, p, b)
	return s, b, err
}
func load(t transport.TPMCloser, b Bundle) (s *Signer, err error) {
	defer func() {
		if err != nil {
			if s != nil {
				err = errors.Join(err, s.Close())
				s = nil
			} else {
				err = errors.Join(err, t.Close())
			}
		}
	}()
	if _, err = ValidateBundle(b); err != nil {
		return nil, err
	}
	p, err := primary(t)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, flush(t, p.ObjectHandle))
	}()
	if !bytes.Equal(p.Name.Buffer, b.ParentName) {
		return nil, errors.New("TPM parent identity mismatch")
	}
	return loadChild(t, p, b)
}
func loadChild(t transport.TPMCloser, p *tpm2.CreatePrimaryResponse, b Bundle) (s *Signer, err error) {
	pub, err := ValidateBundle(b)
	if err != nil {
		return nil, err
	}
	pb, _ := tpm2.Unmarshal[tpm2.TPM2BPublic](b.Public)
	pr, _ := tpm2.Unmarshal[tpm2.TPM2BPrivate](b.Private)
	loaded, err := (tpm2.Load{ParentHandle: tpm2.NamedHandle{Handle: p.ObjectHandle, Name: p.Name}, InPublic: *pb, InPrivate: *pr}).Execute(t)
	if err != nil {
		return nil, fmt.Errorf("TPM load signing key: %w", err)
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, flush(t, loaded.ObjectHandle))
		}
	}()
	r, err := (tpm2.ReadPublic{ObjectHandle: loaded.ObjectHandle}).Execute(t)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(loaded.Name.Buffer, b.Name) || !bytes.Equal(r.Name.Buffer, b.Name) || !bytes.Equal(tpm2.Marshal(r.OutPublic), b.Public) {
		return nil, errors.New("TPM loaded signing key identity mismatch")
	}
	return &Signer{t: t, handle: loaded.ObjectHandle, name: tpm2.TPM2BName{Buffer: bytes.Clone(b.Name)}, auth: bytes.Clone(b.Auth), public: pub}, nil
}
func (s *Signer) Public() crypto.PublicKey {
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).Set(s.public.X), Y: new(big.Int).Set(s.public.Y)}
}

// Sign signs an already-computed SHA-256 digest once, using a one-shot HMAC
// authorization session. Authorization failures are never automatically retried.
// A failed TPM exchange closes the signer; its owner must explicitly reopen the
// stored bundle after resolving the error.
func (s *Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts == nil || opts.HashFunc() != crypto.SHA256 || len(digest) != 32 {
		return nil, errors.New("TPM signer requires a SHA-256 digest")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, errors.New("TPM signer is closed")
	}
	session := tpm2.HMAC(tpm2.TPMAlgSHA256, 32, tpm2.Auth(s.auth))
	r, err := (tpm2.Sign{
		KeyHandle: tpm2.AuthHandle{Handle: s.handle, Name: s.name, Auth: session},
		Digest:    tpm2.TPM2BDigest{Buffer: bytes.Clone(digest)},
		InScheme: tpm2.TPMTSigScheme{
			Scheme:  tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUSigScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSchemeHash{HashAlg: tpm2.TPMAlgSHA256}),
		},
		Validation: tpm2.TPMTTKHashCheck{Tag: tpm2.TPMSTHashCheck, Hierarchy: tpm2.TPMRHNull},
	}).Execute(s.t)
	if err != nil {
		// go-tpm cleans TPM error responses, but not every transport/parsing
		// failure. A known outstanding session still belongs to this connection.
		if session.Handle() != tpm2.TPMRHNull {
			err = errors.Join(err, session.CleanupFailure(s.t))
		}
		// A lost response leaves command/session state uncertain. Closing the
		// resource-manager connection releases even handles we never received.
		return nil, errors.Join(fmt.Errorf("TPM sign: %w", err), s.closeLocked())
	}
	sig, err := r.Signature.Signature.ECDSA()
	if err != nil {
		return nil, errors.Join(err, s.closeLocked())
	}
	a, b := new(big.Int).SetBytes(sig.SignatureR.Buffer), new(big.Int).SetBytes(sig.SignatureS.Buffer)
	n := elliptic.P256().Params().N
	if sig.Hash != tpm2.TPMAlgSHA256 || a.Sign() <= 0 || b.Sign() <= 0 || a.Cmp(n) >= 0 || b.Cmp(n) >= 0 || !ecdsa.Verify(s.public, digest, a, b) {
		return nil, errors.Join(errors.New("TPM returned invalid ECDSA signature"), s.closeLocked())
	}
	return asn1.Marshal(struct{ R, S *big.Int }{a, b})
}

// Close flushes only this signer's child and closes its resource-manager
// connection. It is idempotent, including after a transport failure.
func (s *Signer) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closeLocked()
}
func (s *Signer) closeLocked() error {
	if s.closed {
		return s.closeErr
	}
	s.closed = true
	s.closeErr = errors.Join(flush(s.t, s.handle), s.t.Close())
	clear(s.auth)
	return s.closeErr
}
