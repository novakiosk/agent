// Package runtimeipc implements the authenticated, typed graphical boundary.
// Only daemon-created operations may cross this socket; responses are observations.
package runtimeipc

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

const MaxMessageBytes = 1024 * 1024

var ErrUnavailable = errors.New("graphical companion unavailable")

type Binding struct {
	EnrollmentID      string `json:"enrollmentId"`
	IdentityBindingID string `json:"identityBindingId"`
	DeviceID          string `json:"deviceId"`
	KeyGeneration     uint64 `json:"keyGeneration"`
}
type lease struct {
	Version       int     `json:"version"`
	Epoch         string  `json:"epoch"`
	Binding       Binding `json:"binding"`
	RequestID     string  `json:"requestId"`
	Kind          string  `json:"kind"`
	AuthorityHash string  `json:"authorityHash"`
	ExpiresAt     int64   `json:"expiresAt"`
}
type request struct {
	Lease lease           `json:"lease"`
	Body  json.RawMessage `json:"body"`
}
type response struct {
	Lease lease           `json:"lease"`
	OK    bool            `json:"ok"`
	Body  json.RawMessage `json:"body"`
}

type peer struct {
	connection *net.UnixConn
	epoch      string
	done       chan struct{}
	once       sync.Once
	calls      sync.Mutex
}

func (p *peer) close() { p.once.Do(func() { p.connection.Close(); close(p.done) }) }

type Server struct {
	listener    *net.UnixListener
	expectedUID uint32
	binding     Binding
	mu          sync.Mutex
	current     *peer
	closed      bool
}

// Listen expects a provisioned daemon-owned directory. It never creates/chowns
// parent directories. The kiosk group may connect but must not write the parent.
func Listen(path string, expectedUID uint32, binding Binding) (*Server, error) {
	if binding.EnrollmentID == "" || binding.IdentityBindingID == "" || binding.DeviceID == "" {
		return nil, errors.New("IPC binding required")
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	stat, ok := parent.Sys().(*syscall.Stat_t)
	if !ok || !parent.IsDir() || stat.Uid != uint32(os.Geteuid()) || parent.Mode().Perm()&0022 != 0 {
		return nil, errors.New("unsafe IPC parent directory")
	}
	if info, err := os.Lstat(path); err == nil {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != uint32(os.Geteuid()) || info.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("unsafe IPC socket")
		}
		// Startup serialization is held by agentd before removing its stale socket.
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0660); err != nil {
		listener.Close()
		return nil, err
	}
	server := &Server{listener: listener, expectedUID: expectedUID, binding: binding}
	go server.accept()
	return server, nil
}
func PeerUID(connection *net.UnixConn) (uint32, error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return 0, err
	}
	var uid uint32
	var check error
	err = raw.Control(func(fd uintptr) {
		credentials, e := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		check = e
		if e == nil {
			uid = credentials.Uid
		}
	})
	if err != nil {
		return 0, err
	}
	return uid, check
}
func randomID() string {
	var value [32]byte
	if _, err := rand.Read(value[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(value[:])
}
func (server *Server) accept() {
	for {
		connection, err := server.listener.AcceptUnix()
		if err != nil {
			return
		}
		uid, err := PeerUID(connection)
		if err != nil || uid != server.expectedUID {
			connection.Close()
			continue
		}
		p := &peer{connection: connection, epoch: randomID(), done: make(chan struct{})}
		server.mu.Lock()
		if server.closed {
			server.mu.Unlock()
			p.close()
			return
		}
		old := server.current
		server.current = p
		server.mu.Unlock()
		if old != nil {
			old.close()
		}
	}
}
func (server *Server) Close() error {
	server.mu.Lock()
	server.closed = true
	p := server.current
	server.current = nil
	server.mu.Unlock()
	if p != nil {
		p.close()
	}
	return server.listener.Close()
}
func (server *Server) currentPeer() *peer {
	server.mu.Lock()
	defer server.mu.Unlock()
	return server.current
}
func strict(data []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errors.New("trailing IPC data")
	}
	return nil
}
func writeFrame(connection net.Conn, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(data) == 0 || len(data) > MaxMessageBytes {
		return errors.New("IPC message exceeds limit")
	}
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(data)))
	if _, err = io.Copy(connection, bytes.NewReader(size[:])); err != nil {
		return err
	}
	_, err = io.Copy(connection, bytes.NewReader(data))
	return err
}
func readFrame(connection net.Conn, value any) error {
	var size [4]byte
	if _, err := io.ReadFull(connection, size[:]); err != nil {
		return err
	}
	length := binary.BigEndian.Uint32(size[:])
	if length == 0 || length > MaxMessageBytes {
		return errors.New("IPC frame exceeds limit")
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(connection, data); err != nil {
		return err
	}
	return strict(data, value)
}
func (server *Server) call(ctx context.Context, p *peer, kind string, input, output any) error {
	if p == nil {
		return ErrUnavailable
	}
	p.calls.Lock()
	defer p.calls.Unlock()
	select {
	case <-p.done:
		return ErrUnavailable
	default:
	}
	if server.currentPeer() != p {
		return ErrUnavailable
	}
	body, err := json.Marshal(input)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(body)
	deadline := time.Now().Add(30 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if !deadline.After(time.Now()) {
		return ctx.Err()
	}
	operation := lease{Version: 1, Epoch: p.epoch, Binding: server.binding, RequestID: randomID(), Kind: kind, AuthorityHash: hex.EncodeToString(hash[:]), ExpiresAt: deadline.UnixMilli()}
	if err = p.connection.SetDeadline(deadline); err != nil {
		p.close()
		return ErrUnavailable
	}
	stop := context.AfterFunc(ctx, p.close)
	defer stop()
	if err = writeFrame(p.connection, request{Lease: operation, Body: body}); err != nil {
		p.close()
		return ErrUnavailable
	}
	var reply response
	if err = readFrame(p.connection, &reply); err != nil || reply.Lease != operation || server.currentPeer() != p || !time.Now().Before(deadline) {
		p.close()
		return errors.New("invalid or stale graphical response")
	}
	if !reply.OK {
		if string(reply.Body) != "{}" {
			p.close()
			return errors.New("invalid graphical failure")
		}
		return ErrUnavailable
	}
	if err = strict(reply.Body, output); err != nil {
		p.close()
		return errors.New("invalid graphical observation")
	}
	return nil
}

// serveConnection accepts only bounded daemon requests. No companion-initiated
// operation, signing API, private path, executable or environment is supported.
func serveConnection(ctx context.Context, connection *net.UnixConn, expectedUID uint32, handler *Handler) error {
	defer connection.Close()
	uid, err := PeerUID(connection)
	if err != nil || uid != expectedUID {
		return errors.New("unexpected daemon UID")
	}
	run, cancel := context.WithCancel(ctx)
	handler.sessionCtx = run
	stop := context.AfterFunc(ctx, func() { connection.Close() })
	defer stop()
	defer func() { cancel(); handler.close() }()
	epoch := ""
	var binding Binding
	seen := map[string]int64{}
	for {
		var incoming request
		if err := readFrame(connection, &incoming); err != nil {
			return err
		}
		l := incoming.Lease
		now := time.Now().UnixMilli()
		for id, expires := range seen {
			if expires <= now {
				delete(seen, id)
			}
		}
		hash := sha256.Sum256(incoming.Body)
		if l.Version != 1 || len(l.Epoch) != 64 || len(l.RequestID) != 64 || l.Binding.EnrollmentID == "" || l.Binding.IdentityBindingID == "" || l.Binding.DeviceID == "" || l.ExpiresAt <= now || l.ExpiresAt > now+30000 || l.AuthorityHash != hex.EncodeToString(hash[:]) || seen[l.RequestID] != 0 || len(seen) >= 4096 {
			return errors.New("invalid graphical lease")
		}
		if epoch == "" {
			epoch = l.Epoch
			binding = l.Binding
		} else if epoch != l.Epoch || binding != l.Binding {
			return errors.New("graphical binding changed")
		}
		seen[l.RequestID] = l.ExpiresAt
		operation, cancel := context.WithDeadline(run, time.UnixMilli(l.ExpiresAt))
		result, err := handler.handle(operation, l.Kind, incoming.Body)
		cancel()
		body := json.RawMessage("{}")
		if err == nil {
			encoded, e := json.Marshal(result)
			if e != nil {
				return e
			}
			body = encoded
		}
		if err := writeFrame(connection, response{Lease: l, OK: err == nil, Body: body}); err != nil {
			return err
		}
	}
}

func Run(ctx context.Context, path string, expectedUID uint32, handler *Handler) error {
	for ctx.Err() == nil {
		connection, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
		if err == nil {
			_ = serveConnection(ctx, connection, expectedUID, handler)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return fmt.Errorf("runtime stopped: %w", ctx.Err())
}
