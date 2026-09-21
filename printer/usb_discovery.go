package printer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// USBDiscovery contains only supported Zebra ZPL devices. Serial numbers and
// CUPS device URIs stay on the machine; commands select a hashed identity.
type USBDiscovery struct {
	Devices       []USBDevice `json:"devices"`
	ErrorCategory *string     `json:"errorCategory"`
}
type USBDevice struct {
	ID              string  `json:"id"`
	Name            string  `json:"name"`
	ConfiguredQueue *string `json:"configuredQueue"`
}

const MaxUSBDevices = 8

var usbIDPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var usbNamePattern = regexp.MustCompile(`^[\x20-\x7e]{1,128}$`)

func USBDeviceID(serial string) string {
	sum := sha256.Sum256([]byte("zebra-usb-v1\n" + serial))
	return hex.EncodeToString(sum[:])
}
func USBQueueName(id string) string { return "NOVA_USB_" + id }

// ZebraUSBURI identifies a supported local device without accepting an arbitrary
// backend, credentials, network destination, or backend query option.
func ZebraUSBURI(raw string) (serial, model string, ok bool) {
	if !strings.HasPrefix(raw, "usb://") || len(raw) > 1024 || strings.ContainsAny(raw, "\r\n\t #") {
		return
	}
	parts := strings.Split(strings.TrimPrefix(raw, "usb://"), "?")
	if len(parts) != 2 {
		return
	}
	device := strings.Split(parts[0], "/")
	if len(device) != 2 {
		return
	}
	manufacturer, err := url.PathUnescape(device[0])
	if err != nil || !strings.EqualFold(manufacturer, "Zebra Technologies") {
		return
	}
	model, err = url.PathUnescape(device[1])
	if err != nil || !usbNamePattern.MatchString(model) || strings.ContainsAny(model, "/\\") || !strings.HasSuffix(strings.ToUpper(model), " ZPL") {
		return "", "", false
	}
	query, err := url.ParseQuery(parts[1])
	if err != nil || len(query) != 1 || len(query["serial"]) != 1 || !safeUSBSerial(query["serial"][0]) {
		return "", "", false
	}
	return query["serial"][0], model, true
}

func (p *Probe) discoverUSB(ctx context.Context) *USBDiscovery {
	result := &USBDiscovery{Devices: []USBDevice{}}
	fail := func(category string) *USBDiscovery {
		result.Devices = []USBDevice{}
		result.ErrorCategory = &category
		return result
	}
	entries, err := os.ReadDir(p.USBSysfsRoot)
	if err != nil {
		return fail("unavailable")
	}
	enumerated, _, err, _ := p.command(ctx, []string{"-e"})
	if err != nil {
		return fail("unavailable")
	}
	var configured []byte
	if len(strings.TrimSpace(string(enumerated))) > 0 {
		configured, _, err, _ = p.command(ctx, []string{"-v"})
		if err != nil {
			return fail("unavailable")
		}
	}
	queues := map[string]string{}
	for line := range strings.SplitSeq(string(configured), "\n") {
		if !strings.HasPrefix(line, "device for ") {
			continue
		}
		pair := strings.SplitN(strings.TrimPrefix(line, "device for "), ": ", 2)
		if len(pair) != 2 || !isSafeQueueName(pair[0]) {
			continue
		}
		if serial, _, ok := ZebraUSBURI(strings.TrimSpace(pair[1])); ok {
			queues[USBDeviceID(serial)] = pair[0]
		}
	}
	seen := map[string]bool{}
	for _, entry := range entries {
		if ctx.Err() != nil {
			return fail("unavailable")
		}
		read := func(name string) string {
			data, err := os.ReadFile(filepath.Join(p.USBSysfsRoot, entry.Name(), name))
			if err != nil || len(data) > 256 {
				return ""
			}
			return strings.TrimSpace(string(data))
		}
		if read("idVendor") != "0a5f" {
			continue
		}
		serial, model := read("serial"), read("product")
		if !safeUSBSerial(serial) || !usbNamePattern.MatchString(model) || !strings.HasSuffix(strings.ToUpper(model), " ZPL") {
			continue
		}
		id := USBDeviceID(serial)
		if seen[id] {
			return fail("unavailable")
		}
		seen[id] = true
		device := USBDevice{ID: id, Name: model}
		if queue, ok := queues[id]; ok {
			device.ConfiguredQueue = &queue
		}
		result.Devices = append(result.Devices, device)
		if len(result.Devices) > MaxUSBDevices {
			return fail("limit")
		}
	}
	slices.SortFunc(result.Devices, func(a, b USBDevice) int { return strings.Compare(a.ID, b.ID) })
	return result
}
func validUSBDiscovery(value USBDiscovery) bool {
	if value.Devices == nil || len(value.Devices) > MaxUSBDevices {
		return false
	}
	if value.ErrorCategory != nil && (*value.ErrorCategory != "unavailable" && *value.ErrorCategory != "limit" || len(value.Devices) != 0) {
		return false
	}
	seen := map[string]bool{}
	for _, device := range value.Devices {
		if !usbIDPattern.MatchString(device.ID) || seen[device.ID] || !usbNamePattern.MatchString(device.Name) || device.ConfiguredQueue != nil && !isSafeQueueName(*device.ConfiguredQueue) {
			return false
		}
		seen[device.ID] = true
	}
	return true
}
func writeUSBCanonical(builder *strings.Builder, value USBDiscovery) {
	category := ""
	if value.ErrorCategory != nil {
		category = *value.ErrorCategory
	}
	writeCanonicalField(builder, "usbDiscoveryError", category)
	devices := slices.Clone(value.Devices)
	slices.SortFunc(devices, func(a, b USBDevice) int { return strings.Compare(a.ID, b.ID) })
	for _, device := range devices {
		queue := ""
		if device.ConfiguredQueue != nil {
			queue = *device.ConfiguredQueue
		}
		builder.WriteString("usbDevice=" + device.ID + "\t" + encodeCanonical(device.Name) + "\t" + encodeCanonical(queue) + "\n")
	}
}
