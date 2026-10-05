package runtimeipc

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testServer(t *testing.T) (*Server, *net.UnixConn) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	s, err := Listen(filepath.Join(dir, "runtime.sock"), uint32(os.Geteuid()), Binding{EnrollmentID: "enrollment", IdentityBindingID: "binding", DeviceID: "device", KeyGeneration: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	c, err := net.DialUnix("unix", nil, s.listener.Addr().(*net.UnixAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	deadline := time.Now().Add(time.Second)
	for s.currentPeer() == nil && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if s.currentPeer() == nil {
		t.Fatal("peer not accepted")
	}
	return s, c
}
func TestResponseAuthorityAndStrictFrames(t *testing.T) {
	for _, attack := range []string{"request-id", "generation", "epoch", "unknown-field", "oversize", "replay"} {
		t.Run(attack, func(t *testing.T) {
			s, c := testServer(t)
			go func() {
				var r request
				if readFrame(c, &r) != nil {
					return
				}
				reply := response{Lease: r.Lease, OK: true, Body: []byte("{}")}
				switch attack {
				case "request-id":
					reply.Lease.RequestID = randomID()
				case "generation":
					reply.Lease.Binding.KeyGeneration++
				case "epoch":
					reply.Lease.Epoch = randomID()
				case "unknown-field":
					writeFrame(c, map[string]any{"lease": r.Lease, "ok": true, "body": map[string]any{}, "extra": true})
					return
				case "oversize":
					var size [4]byte
					binary.BigEndian.PutUint32(size[:], MaxMessageBytes+1)
					c.Write(size[:])
					return
				case "replay":
					writeFrame(c, reply)
					if readFrame(c, &r) != nil {
						return
					}
				}
				writeFrame(c, reply)
			}()
			if attack == "replay" {
				if err := s.call(context.Background(), s.currentPeer(), "runtime.recover", empty{}, &empty{}); err != nil {
					t.Fatal(err)
				}
			}
			if err := s.call(context.Background(), s.currentPeer(), "runtime.recover", empty{}, &empty{}); err == nil {
				t.Fatal("accepted invalid response")
			}
			select {
			case <-s.currentPeer().done:
			default:
				t.Fatal("invalid peer remains usable")
			}
		})
	}
}
func TestPeerAndParentPermissions(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0770)
	if s, err := Listen(filepath.Join(dir, "socket"), uint32(os.Geteuid()), Binding{EnrollmentID: "e", IdentityBindingID: "i", DeviceID: "d"}); err == nil {
		s.Close()
		t.Fatal("accepted writable parent")
	}
	os.Chmod(dir, 0700)
	s, err := Listen(filepath.Join(dir, "socket"), uint32(os.Geteuid()+1), Binding{EnrollmentID: "e", IdentityBindingID: "i", DeviceID: "d"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c, err := net.DialUnix("unix", nil, s.listener.Addr().(*net.UnixAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, err = c.Read(b[:]); err == nil {
		t.Fatal("unexpected peer accepted")
	}
	if s.currentPeer() != nil {
		t.Fatal("wrong UID installed")
	}
}
func TestUnavailableAndReconnect(t *testing.T) {
	s, c := testServer(t)
	old := s.currentPeer()
	c.Close()
	if err := s.call(context.Background(), old, "runtime.recover", empty{}, &empty{}); err == nil {
		t.Fatal("disconnected peer worked")
	}
	c2, err := net.DialUnix("unix", nil, s.listener.Addr().(*net.UnixAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	deadline := time.Now().Add(time.Second)
	for s.currentPeer() == old && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if s.currentPeer() == old {
		t.Fatal("peer not replaced")
	}
	go func() {
		var r request
		if readFrame(c2, &r) == nil {
			writeFrame(c2, response{Lease: r.Lease, OK: true, Body: []byte("{}")})
		}
	}()
	if err := s.call(context.Background(), s.currentPeer(), "runtime.recover", empty{}, &empty{}); err != nil {
		t.Fatal(err)
	}
	if err := s.call(context.Background(), old, "runtime.recover", empty{}, &empty{}); err == nil {
		t.Fatal("old connection reused")
	}
}

func TestHealthyConnectionOutlivesReplayWindow(t *testing.T) {
	s, c := testServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stopped := make(chan error, 1)
	go func() { stopped <- serveConnection(ctx, c, uint32(os.Geteuid()), &Handler{}) }()
	// Requests expire after 100 milliseconds so this exercises eviction without
	// imposing a real 30-second lease delay on the suite. One midpoint wait
	// expires the first batch before the total crosses the 4096-entry bound.
	p := s.currentPeer()
	for i := 0; i < 4200; i++ {
		body := []byte("{}")
		hash := sha256.Sum256(body)
		l := lease{Version: 1, Epoch: p.epoch, Binding: s.binding, RequestID: randomID(), Kind: "idle.close", AuthorityHash: hex.EncodeToString(hash[:]), ExpiresAt: time.Now().Add(100 * time.Millisecond).UnixMilli()}
		if err := writeFrame(p.connection, request{Lease: l, Body: body}); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		var reply response
		if err := readFrame(p.connection, &reply); err != nil {
			t.Fatalf("response %d: %v", i, err)
		}
		if reply.Lease != l || !reply.OK {
			t.Fatalf("invalid response %d", i)
		}
		if i == 2100 {
			time.Sleep(110 * time.Millisecond)
		}
	}
	cancel()
	<-stopped
}

func TestCompanionRejectsWrongDaemonUIDAndCloses(t *testing.T) {
	s, c := testServer(t)
	if err := serveConnection(context.Background(), c, uint32(os.Geteuid()+1), &Handler{}); err == nil {
		t.Fatal("accepted wrong daemon UID")
	}
	p := s.currentPeer()
	p.connection.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, err := p.connection.Read(b[:]); err != io.EOF {
		t.Fatalf("mismatched peer socket not closed: %v", err)
	}
}
