// Package operations contains the agent's small, fixed operational seams.
// It intentionally has no generic shell or remotely supplied command path.
package operations

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"path"
	"sort"
	"strings"
)

const (
	InventoryVersion = 1
	InventoryType    = "host.inventory"

	InventoryMaxInterfaces = 16
	InventoryMaxJSONBytes  = 8 * 1024
	InventoryMaxNameBytes  = 15

	BootIDPath   = "/proc/sys/kernel/random/boot_id"
	NetClassPath = "/sys/class/net"
)

// Inventory is a bounded, local observation.  It deliberately contains no
// addresses or other network identity beyond physical interface MACs.
type Inventory struct {
	Version    int                    `json:"version"`
	Type       string                 `json:"type"`
	BootID     string                 `json:"bootId"`
	Interfaces []InterfaceObservation `json:"interfaces"`
}

// InterfaceObservation records only evidence available from sysfs.  A
// physical interface can report unknown when its operstate file is absent or
// malformed; that is preferable to inventing an up/down result.
type InterfaceObservation struct {
	Name      string `json:"name"`
	MAC       string `json:"mac"`
	OperState string `json:"operState"`
}

const (
	OperStateUp      = "up"
	OperStateDown    = "down"
	OperStateUnknown = "unknown"
)

// InventoryConfig controls collection through the complete read-only seam.
// A nil FS reads the host's proc/sysfs directly.
type InventoryConfig struct{ FS FileSystem }

// InventoryCollector reads a single bounded inventory snapshot.
type InventoryCollector struct {
	fileSystem FileSystem
}

// NewInventoryCollector creates a collector without reading the host.
func NewInventoryCollector(config ...InventoryConfig) *InventoryCollector {
	var value FileSystem
	if len(config) != 0 {
		value = config[0].FS
	}
	return &InventoryCollector{fileSystem: defaultFileSystem(value)}
}

// Collect returns a fresh inventory snapshot.  No command is executed.
func (collector *InventoryCollector) Collect() (Inventory, error) {
	if collector == nil || collector.fileSystem == nil {
		return Inventory{}, errors.New("operations: nil inventory collector")
	}
	bootIDBytes, err := collector.fileSystem.ReadFile(BootIDPath)
	if err != nil {
		return Inventory{}, fmt.Errorf("operations: read boot ID: %w", err)
	}
	bootID, err := canonicalBootID(string(bootIDBytes))
	if err != nil {
		return Inventory{}, fmt.Errorf("operations: read boot ID: %w", err)
	}

	entries, err := collector.fileSystem.ReadDir(NetClassPath)
	if err != nil {
		return Inventory{}, fmt.Errorf("operations: read network interfaces: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	interfaces := make([]InterfaceObservation, 0, InventoryMaxInterfaces)
	for _, entry := range entries {
		if len(interfaces) >= InventoryMaxInterfaces {
			break
		}
		name := entry.Name()
		if !safeInterfaceName(name) || name == "lo" {
			continue
		}
		interfacePath := path.Join(NetClassPath, name)
		resolvedInterfacePath, resolved := safeResolvedSysfsPath(collector.fileSystem, interfacePath)
		if !resolved {
			// /sys/class/net normally contains symlinks.  Resolve legitimate
			// class links but reject malformed links that escape /sys.
			continue
		}
		if hasWirelessMarker(collector.fileSystem, resolvedInterfacePath) || !hasBackingDevice(collector.fileSystem, resolvedInterfacePath) {
			continue
		}
		macBytes, err := collector.fileSystem.ReadFile(path.Join(interfacePath, "address"))
		if err != nil {
			continue
		}
		mac, err := canonicalMAC(string(macBytes))
		if err != nil {
			continue
		}
		operState := OperStateUnknown
		if stateBytes, stateErr := collector.fileSystem.ReadFile(path.Join(interfacePath, "operstate")); stateErr == nil {
			operState = canonicalOperState(string(stateBytes))
		}
		interfaces = append(interfaces, InterfaceObservation{Name: name, MAC: mac, OperState: operState})
	}
	return Inventory{Version: InventoryVersion, Type: InventoryType, BootID: bootID, Interfaces: interfaces}, nil
}

func safeInterfaceName(name string) bool {
	if len(name) == 0 || len(name) > InventoryMaxNameBytes || name == "." || name == ".." {
		return false
	}
	for index, character := range []byte(name) {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '_' || character == '.' {
			if index == 0 && character == '.' {
				return false
			}
			continue
		}
		return false
	}
	return true
}

func canonicalBootID(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return "", errors.New("invalid boot ID")
	}
	for index, character := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			continue
		}
		if !isLowerHex(character) {
			return "", errors.New("invalid boot ID")
		}
	}
	return value, nil
}

func canonicalMAC(value string) (string, error) {
	parsed, err := net.ParseMAC(strings.TrimSpace(value))
	if err != nil || len(parsed) != 6 {
		return "", errors.New("invalid MAC")
	}
	allZero := true
	for _, octet := range parsed {
		if octet != 0 {
			allZero = false
			break
		}
	}
	if allZero || parsed[0]&1 != 0 {
		return "", errors.New("invalid physical MAC")
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", parsed[0], parsed[1], parsed[2], parsed[3], parsed[4], parsed[5]), nil
}

func canonicalOperState(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case OperStateUp:
		return OperStateUp
	case OperStateDown:
		return OperStateDown
	default:
		return OperStateUnknown
	}
}

func hasBackingDevice(fileSystem FileSystem, interfacePath string) bool {
	devicePath := path.Join(interfacePath, "device")
	return hasSafeSysfsPath(fileSystem, devicePath)
}

func hasSafeSysfsPath(fileSystem FileSystem, name string) bool {
	_, ok := safeResolvedSysfsPath(fileSystem, name)
	return ok
}

func safeResolvedSysfsPath(fileSystem FileSystem, name string) (string, bool) {
	current := name
	for range 8 {
		info, err := fileSystem.Lstat(current)
		if err != nil || info == nil {
			return "", false
		}
		if info.Mode()&fs.ModeSymlink == 0 {
			return current, true
		}
		target, err := fileSystem.Readlink(current)
		if err != nil || target == "" {
			return "", false
		}
		resolved := target
		if !strings.HasPrefix(target, "/") {
			resolved = path.Join(path.Dir(current), target)
		}
		resolved = path.Clean(resolved)
		if !strings.HasPrefix(resolved, "/sys/") || strings.Contains(resolved, "\x00") {
			return "", false
		}
		current = resolved
	}
	return "", false
}

func hasWirelessMarker(fileSystem FileSystem, interfacePath string) bool {
	return filePresent(fileSystem, path.Join(interfacePath, "wireless")) || filePresent(fileSystem, path.Join(interfacePath, "phy80211"))
}

// Validate strictly checks the inventory shape, enum vocabulary, uniqueness,
// canonical values, and the hard JSON bound.  Input order is accepted and
// canonicalized for hashing.
func (inventory Inventory) Validate() error {
	if inventory.Version != InventoryVersion || inventory.Type != InventoryType {
		return errors.New("operations: invalid inventory version or type")
	}
	bootID, err := canonicalBootID(inventory.BootID)
	if err != nil || bootID != inventory.BootID {
		return errors.New("operations: inventory bootId is not canonical")
	}
	if len(inventory.Interfaces) > InventoryMaxInterfaces {
		return errors.New("operations: too many interfaces")
	}
	seen := make(map[string]struct{}, len(inventory.Interfaces))
	for index, observation := range inventory.Interfaces {
		if !safeInterfaceName(observation.Name) || observation.Name == "lo" {
			return fmt.Errorf("operations: interface %d has invalid name", index)
		}
		if _, ok := seen[observation.Name]; ok {
			return errors.New("operations: duplicate interface name")
		}
		seen[observation.Name] = struct{}{}
		mac, err := canonicalMAC(observation.MAC)
		if err != nil || mac != observation.MAC {
			return fmt.Errorf("operations: interface %q has non-canonical MAC", observation.Name)
		}
		if observation.OperState != OperStateUp && observation.OperState != OperStateDown && observation.OperState != OperStateUnknown {
			return fmt.Errorf("operations: interface %q has invalid operState", observation.Name)
		}
	}
	encoded, err := json.Marshal(inventory)
	if err != nil {
		return fmt.Errorf("operations: marshal inventory: %w", err)
	}
	if len(encoded) > InventoryMaxJSONBytes {
		return fmt.Errorf("operations: inventory exceeds %d bytes", InventoryMaxJSONBytes)
	}
	return nil
}

// Normalize validates and sorts a copy by safe interface name.
func (inventory Inventory) Normalize() (Inventory, error) {
	if err := inventory.Validate(); err != nil {
		return Inventory{}, err
	}
	normalized := inventory
	normalized.Interfaces = append([]InterfaceObservation(nil), inventory.Interfaces...)
	sort.SliceStable(normalized.Interfaces, func(i, j int) bool {
		return normalized.Interfaces[i].Name < normalized.Interfaces[j].Name
	})
	return normalized, nil
}

// CanonicalPayload returns the stable, line-oriented payload for
// inventory signatures.  Values are base64url encoded to make framing unambiguous.
func (inventory Inventory) CanonicalPayload() ([]byte, error) {
	normalized, err := inventory.Normalize()
	if err != nil {
		return nil, err
	}
	var builder strings.Builder
	builder.WriteString("host-inventory-canonical-v1\n")
	writeInventoryField(&builder, "version", fmt.Sprintf("%d", normalized.Version))
	writeInventoryField(&builder, "type", normalized.Type)
	writeInventoryField(&builder, "bootId", normalized.BootID)
	writeInventoryField(&builder, "interfaceCount", fmt.Sprintf("%d", len(normalized.Interfaces)))
	for _, observation := range normalized.Interfaces {
		builder.WriteString("interface=")
		builder.WriteString(encodeInventoryValue(observation.Name))
		builder.WriteByte('\t')
		builder.WriteString(encodeInventoryValue(observation.MAC))
		builder.WriteByte('\t')
		builder.WriteString(observation.OperState)
		builder.WriteByte('\n')
	}
	canonical := []byte(builder.String())
	if len(canonical) > InventoryMaxJSONBytes {
		return nil, fmt.Errorf("operations: canonical inventory exceeds %d bytes", InventoryMaxJSONBytes)
	}
	return canonical, nil
}

func writeInventoryField(builder *strings.Builder, name, value string) {
	builder.WriteString(name)
	builder.WriteByte('=')
	builder.WriteString(encodeInventoryValue(value))
	builder.WriteByte('\n')
}

func encodeInventoryValue(value string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(value))
}
