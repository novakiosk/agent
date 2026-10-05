package tpmsigner

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// swtpm's command socket uses raw TPM packets, unlike the Microsoft simulator
// framing. This transport and process launcher exist only in tests.
type socketTPM struct{ net.Conn }

func (s *socketTPM) Send(b []byte) ([]byte, error) {
	for i := 0; i < 12; i++ {
		r, err := s.send(b)
		if err != nil || len(r) < 10 || binary.BigEndian.Uint32(r[6:10]) != uint32(tpm2.TPMRCRetry) {
			return r, err
		}
		time.Sleep(time.Duration(1<<i) * time.Millisecond)
	}
	return nil, errors.New("TPM retry exhausted")
}
func (s *socketTPM) send(b []byte) ([]byte, error) {
	if err := s.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return nil, err
	}
	if _, err := s.Write(b); err != nil {
		return nil, err
	}
	header := make([]byte, 10)
	if _, err := io.ReadFull(s, header); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(header[2:6])
	if size < 10 || size > 65536 {
		return nil, errors.New("invalid TPM packet size")
	}
	reply := make([]byte, size)
	copy(reply, header)
	_, err := io.ReadFull(s, reply[10:])
	return reply, err
}

type fixture struct {
	t   *testing.T
	dir string
	cmd *exec.Cmd
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	if _, err := exec.LookPath("swtpm"); err != nil {
		t.Skip("integration requires external swtpm executable")
	}
	f := &fixture{t: t, dir: t.TempDir()}
	t.Cleanup(f.stop)
	f.start()
	return f
}
func (f *fixture) start() {
	f.t.Helper()
	f.cmd = exec.Command("swtpm", "socket", "--tpm2", "--tpmstate", "dir="+f.dir, "--ctrl", "type=unixio,path="+f.dir+"/ctrl", "--server", "type=unixio,path="+f.dir+"/sock", "--flags", "not-need-init,startup-clear")
	if err := f.cmd.Start(); err != nil {
		f.t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		c, e := net.Dial("unix", f.dir+"/sock")
		if e == nil {
			c.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	f.t.Fatal("swtpm startup timeout")
}
func (f *fixture) stop() {
	if f.cmd != nil && f.cmd.Process != nil {
		_ = f.cmd.Process.Signal(os.Interrupt)
		_ = f.cmd.Wait()
		f.cmd = nil
	}
}
func (f *fixture) open() transport.TPMCloser {
	f.t.Helper()
	c, err := net.Dial("unix", f.dir+"/sock")
	if err != nil {
		f.t.Fatal(err)
	}
	return &socketTPM{c}
}
func cloneBundle(b Bundle) Bundle {
	b.ParentTemplate = bytes.Clone(b.ParentTemplate)
	b.ParentName = bytes.Clone(b.ParentName)
	b.Public = bytes.Clone(b.Public)
	b.Private = bytes.Clone(b.Private)
	b.Name = bytes.Clone(b.Name)
	b.Auth = bytes.Clone(b.Auth)
	return b
}
func syntheticBundle(t *testing.T) Bundle {
	t.Helper()
	p := childTemplate()
	x, y := elliptic.P256().ScalarBaseMult([]byte{1})
	p.Unique = tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{X: tpm2.TPM2BECCParameter{Buffer: x.FillBytes(make([]byte, 32))}, Y: tpm2.TPM2BECCParameter{Buffer: y.FillBytes(make([]byte, 32))}})
	name, err := tpm2.ObjectName(&p)
	if err != nil {
		t.Fatal(err)
	}
	pn := make([]byte, 34)
	pn[1] = byte(tpm2.TPMAlgSHA256)
	return Bundle{Version: 1, ParentHierarchy: uint32(tpm2.TPMRHOwner), ParentTemplate: tpm2.Marshal(parentTemplate()), ParentName: pn, Public: tpm2.Marshal(tpm2.New2B(p)), Private: tpm2.Marshal(tpm2.TPM2BPrivate{Buffer: []byte{1}}), Name: name.Buffer, Auth: make([]byte, 32)}
}
func TestBundleValidation(t *testing.T) {
	base := syntheticBundle(t)
	if _, err := ValidateBundle(base); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*Bundle){"version": func(b *Bundle) { b.Version++ }, "hierarchy": func(b *Bundle) { b.ParentHierarchy++ }, "parent template": func(b *Bundle) { b.ParentTemplate[0] ^= 1 }, "parent name": func(b *Bundle) { b.ParentName[1] = 0 }, "missing auth": func(b *Bundle) { b.Auth = nil }, "missing private": func(b *Bundle) { b.Private = nil }, "truncated public": func(b *Bundle) { b.Public = b.Public[:len(b.Public)-1] }, "trailing public": func(b *Bundle) { b.Public = append(b.Public, 0) }, "trailing private": func(b *Bundle) { b.Private = append(b.Private, 0) }, "trailing template": func(b *Bundle) { b.ParentTemplate = append(b.ParentTemplate, 0) }, "wrong name": func(b *Bundle) { b.Name[3] ^= 1 }, "inner trailing public": func(b *Bundle) {
		b.Public = append(b.Public, 0)
		binary.BigEndian.PutUint16(b.Public, uint16(len(b.Public)-2))
	}, "attributes": func(b *Bundle) { changeArea(b, func(p *tpm2.TPMTPublic) { p.ObjectAttributes.NoDA = true }) }, "off curve": func(b *Bundle) {
		changeArea(b, func(p *tpm2.TPMTPublic) { point, _ := p.Unique.ECC(); clear(point.X.Buffer); clear(point.Y.Buffer) })
	}, "curve": func(b *Bundle) {
		changeArea(b, func(p *tpm2.TPMTPublic) { detail, _ := p.Parameters.ECCDetail(); detail.CurveID = tpm2.TPMECCNistP384 })
	}, "scheme": func(b *Bundle) {
		changeArea(b, func(p *tpm2.TPMTPublic) {
			detail, _ := p.Parameters.ECCDetail()
			detail.Scheme = tpm2.TPMTECCScheme{Scheme: tpm2.TPMAlgNull}
		})
	}, "policy": func(b *Bundle) {
		changeArea(b, func(p *tpm2.TPMTPublic) { p.AuthPolicy.Buffer = []byte{1} })
	}, "oversized": func(b *Bundle) { b.Private = make([]byte, 2049) }}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			b := cloneBundle(base)
			change(&b)
			if _, err := ValidateBundle(b); err == nil {
				t.Fatal("accepted invalid bundle")
			}
		})
	}
}
func changeArea(b *Bundle, change func(*tpm2.TPMTPublic)) {
	p, _ := tpm2.Unmarshal[tpm2.TPM2BPublic](b.Public)
	a, _ := p.Contents()
	change(a)
	b.Public = tpm2.Marshal(tpm2.New2B(*a))
	n, _ := tpm2.ObjectName(a)
	b.Name = n.Buffer
}
func checkSignature(t *testing.T, s *Signer) {
	t.Helper()
	message := []byte("NOVA TPM digest is hashed exactly once")
	digest := sha256.Sum256(message)
	signature, err := s.Sign(nil, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if !ecdsa.VerifyASN1(s.Public().(*ecdsa.PublicKey), digest[:], signature) {
		t.Fatal("signature invalid")
	}
	if _, err := exec.LookPath("openssl"); err == nil {
		dir := t.TempDir()
		der, err := x509.MarshalPKIXPublicKey(s.Public())
		if err != nil {
			t.Fatal(err)
		}
		for name, data := range map[string][]byte{"public.pem": pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), "message": message, "signature": signature} {
			if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
				t.Fatal(err)
			}
		}
		out, err := exec.Command("openssl", "dgst", "-sha256", "-verify", filepath.Join(dir, "public.pem"), "-signature", filepath.Join(dir, "signature"), filepath.Join(dir, "message")).CombinedOutput()
		if err != nil {
			t.Fatalf("openssl: %v %s", err, out)
		}
	}
}
func TestSimulatorLifecycle(t *testing.T) {
	f := newFixture(t)
	s, b, err := create(f.open())
	if err != nil {
		t.Fatal(err)
	}
	checkSignature(t, s)
	returned := s.Public().(*ecdsa.PublicKey)
	returned.X.SetInt64(0)
	checkSignature(t, s)
	if _, err := s.Sign(nil, make([]byte, 32), crypto.SHA384); err == nil {
		t.Fatal("accepted SHA384")
	}
	if _, err := s.Sign(nil, make([]byte, 31), crypto.SHA256); err == nil {
		t.Fatal("accepted short digest")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = load(f.open(), b)
	if err != nil {
		t.Fatal(err)
	}
	checkSignature(t, s)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	connection := f.open()
	if _, err := (tpm2.Shutdown{ShutdownType: tpm2.TPMSUClear}).Execute(connection); err != nil {
		t.Fatal(err)
	}
	connection.Close()
	f.stop()
	f.start()
	s, err = load(f.open(), b)
	if err != nil {
		t.Fatal(err)
	}
	checkSignature(t, s)
	s.Close()
	bad := cloneBundle(b)
	bad.Auth[0] ^= 1
	s, err = load(f.open(), bad)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("wrong auth"))
	if _, err = s.Sign(nil, digest[:], crypto.SHA256); err == nil {
		t.Fatal("wrong auth accepted")
	}
	s.Close()
	badParent := cloneBundle(b)
	badParent.ParentName[3] ^= 1
	if s, err = load(f.open(), badParent); err == nil {
		s.Close()
		t.Fatal("wrong parent name accepted")
	}
	corrupt := cloneBundle(b)
	corrupt.Private[len(corrupt.Private)-1] ^= 1
	if s, err = load(f.open(), corrupt); err == nil {
		s.Close()
		t.Fatal("corrupt private accepted")
	}
	foreign := newFixture(t)
	if s, err = load(foreign.open(), b); err == nil {
		s.Close()
		t.Fatal("foreign TPM accepted key")
	}
	s, err = load(f.open(), b)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = s.Sign(nil, digest[:], crypto.SHA256) }()
	}
	wg.Add(1)
	go func() { defer wg.Done(); _ = s.Close() }()
	wg.Wait()
	if _, err = s.Sign(nil, digest[:], crypto.SHA256); err == nil {
		t.Fatal("closed signer accepted sign")
	}
	s, err = load(f.open(), b)
	if err != nil {
		t.Fatal(err)
	}
	f.stop()
	if _, err = s.Sign(nil, digest[:], crypto.SHA256); err == nil {
		t.Fatal("disconnected transport accepted sign")
	}
	_ = s.Close()
}

type failTPM struct {
	inner   transport.TPMCloser
	command tpm2.TPMCC
	closed  bool
	fail    bool
	owned   map[uint32]bool
}

func (f *failTPM) Send(b []byte) ([]byte, error) {
	cmd := tpm2.TPMCC(binary.BigEndian.Uint32(b[6:10]))
	if cmd == f.command && !f.fail {
		f.fail = true
		return nil, errors.New("injected command failure")
	}
	reply, err := f.inner.Send(b)
	if err == nil && len(reply) >= 10 && binary.BigEndian.Uint32(reply[6:10]) == 0 {
		if cmd == tpm2.TPMCCCreatePrimary || cmd == tpm2.TPMCCLoad || cmd == tpm2.TPMCCStartAuthSession {
			f.owned[binary.BigEndian.Uint32(reply[10:14])] = true
		}
		if cmd == tpm2.TPMCCFlushContext {
			delete(f.owned, binary.BigEndian.Uint32(b[10:14]))
		}
	}
	return reply, err
}
func (f *failTPM) Close() error { f.closed = true; return f.inner.Close() }
func TestSimulatorFailureCleanup(t *testing.T) {
	f := newFixture(t)
	for _, cmd := range []tpm2.TPMCC{tpm2.TPMCCCreatePrimary, tpm2.TPMCCCreate, tpm2.TPMCCLoad, tpm2.TPMCCReadPublic} {
		t.Run(fmt.Sprintf("command_%x", cmd), func(t *testing.T) {
			ft := &failTPM{inner: f.open(), command: cmd, owned: map[uint32]bool{}}
			if s, _, err := create(ft); err == nil {
				s.Close()
				t.Fatal("injected failure accepted")
			}
			if !ft.closed || len(ft.owned) != 0 {
				t.Fatalf("resources leaked: closed=%v owned=%v", ft.closed, ft.owned)
			}
		})
	}
}

// The fixed production device is never needed for failure-path coverage.
type unavailableTPM struct{ closed int }

func (*unavailableTPM) Send([]byte) ([]byte, error) { return nil, io.ErrClosedPipe }
func (t *unavailableTPM) Close() error              { t.closed++; return nil }
func TestUnavailableTransport(t *testing.T) {
	transport := &unavailableTPM{}
	if s, b, err := create(transport); err == nil || s != nil || b.Version != 0 {
		t.Fatal("unavailable transport returned a key")
	}
	if transport.closed != 1 {
		t.Fatalf("transport closed %d times", transport.closed)
	}
	transport = &unavailableTPM{}
	if s, err := load(transport, syntheticBundle(t)); err == nil || s != nil {
		t.Fatal("unavailable transport loaded a key")
	}
	if transport.closed != 1 {
		t.Fatalf("transport closed %d times", transport.closed)
	}
}

func TestSimulatorSignFailureCleanup(t *testing.T) {
	f := newFixture(t)
	ft := &failTPM{inner: f.open(), command: tpm2.TPMCCSign, owned: map[uint32]bool{}}
	s, _, err := create(ft)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("session cleanup"))
	if _, err := s.Sign(nil, digest[:], crypto.SHA256); err == nil {
		t.Fatal("injected sign failure accepted")
	}
	if !ft.closed || len(ft.owned) != 0 {
		t.Fatalf("session/child leaked: closed=%v owned=%v", ft.closed, ft.owned)
	}
	if _, err := s.Sign(nil, digest[:], crypto.SHA256); err == nil {
		t.Fatal("failed signer reused")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}
