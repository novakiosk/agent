package operations

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"reflect"
	"regexp"
	"strings"
	"syscall"
)

const fleetKeyPath = "/etc/pki/containers/novakiosk.pub"

var fleetRepositoryPattern = regexp.MustCompile(`^ghcr\.io/[a-z0-9]+([._-][a-z0-9]+)*(/[a-z0-9]+([._-][a-z0-9]+)*)+$`)

func validFleetRepository(repository string) bool {
	return len(repository) <= 255 && fleetRepositoryPattern.MatchString(repository)
}

func fleetPolicyRepository(read func(string, int) ([]byte, error)) (string, error) {
	raw, err := read("/etc/containers/policy.json", 16384)
	if err != nil {
		return "", err
	}
	var value any
	err = json.Unmarshal(raw, &value)
	if err != nil {
		return "", err
	}
	policy, ok := value.(map[string]any)
	if !ok {
		return "", errors.New("invalid policy")
	}
	transports, _ := policy["transports"].(map[string]any)
	docker, _ := transports["docker"].(map[string]any)
	if len(docker) != 1 {
		return "", errors.New("ambiguous policy repository")
	}
	repository := ""
	for name := range docker {
		repository = name
	}
	if !validFleetRepository(repository) {
		return "", errors.New("invalid policy repository")
	}
	expected := map[string]any{"default": []any{map[string]any{"type": "reject"}}, "transports": map[string]any{"docker": map[string]any{repository: []any{map[string]any{"type": "sigstoreSigned", "keyPath": fleetKeyPath, "signedIdentity": map[string]any{"type": "matchRepository"}}}}}}
	if !reflect.DeepEqual(policy, expected) {
		return "", errors.New("unsafe image signature policy")
	}
	raw, err = read("/etc/containers/registries.d/novakiosk.yaml", 4096)
	if err != nil {
		return "", err
	}
	var registry any
	err = json.Unmarshal(raw, &registry)
	if err != nil {
		return "", err
	}
	if !reflect.DeepEqual(registry, map[string]any{"docker": map[string]any{repository: map[string]any{"use-sigstore-attachments": true}}}) {
		return "", errors.New("unsafe registry policy")
	}
	raw, err = read(fleetKeyPath, 2048)
	if err != nil {
		return "", err
	}
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return "", errors.New("invalid image key")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", err
	}
	ec, ok := key.(*ecdsa.PublicKey)
	if !ok || ec.Curve != elliptic.P256() {
		return "", errors.New("invalid image key")
	}
	return repository, nil
}
func readFleetPolicyFile(path string, limit int) ([]byte, error) {
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "/")
	defer func() { file.Close() }()
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, part := range parts {
		flags := syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK | syscall.O_CLOEXEC
		if i < len(parts)-1 {
			flags |= syscall.O_DIRECTORY
		}
		next, err := syscall.Openat(int(file.Fd()), part, flags, 0)
		if err != nil {
			return nil, err
		}
		file.Close()
		file = os.NewFile(uintptr(next), part)
		info, err := file.Stat()
		if err != nil || !fleetOwner(info, 0) || info.Mode().Perm()&0022 != 0 {
			return nil, errors.New("unsafe policy path")
		}
		if i == len(parts)-1 {
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !info.Mode().IsRegular() || info.Size() > int64(limit) || !ok || stat.Nlink != 1 {
				return nil, errors.New("unsafe policy file")
			}
		}
	}
	raw, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if len(raw) > limit {
		return nil, errors.New("oversized policy")
	}
	return raw, err
}
