package cupsreconcile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDesiredV2CustomMediaHashMatchesSharedFixture(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "fixtures", "printer-desired-v2-custom-media.json"))
	if err != nil {
		t.Fatal(err)
	}
	var desired DesiredV2
	if err := json.Unmarshal(data, &desired); err != nil {
		t.Fatal(err)
	}
	hash, err := desired.PayloadHash()
	if err != nil {
		t.Fatal(err)
	}
	if hash != desired.DesiredHash {
		t.Fatalf("custom-media fixture hash = %s, want %s", hash, desired.DesiredHash)
	}
	if desired.Queues[0].CustomMedia == nil || desired.Queues[0].CustomMedia.Width != 90 || desired.Queues[0].CustomMedia.Height != 65 {
		t.Fatalf("custom media did not decode independent of JSON field order: %#v", desired.Queues[0].CustomMedia)
	}
	if _, err := DecodeDesiredV2(data, desired.SessionID, desired.DeviceID); err != nil {
		t.Fatalf("direct queue rejected reordered custom media fixture: %v", err)
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func testDesired(t *testing.T) Desired {
	t.Helper()
	desired := Desired{Version: Version, Type: DesiredType, SessionID: "session-1", DeviceID: "device-1", Queues: []Queue{
		{PrinterID: "printer-b", LocalName: "NOVA_wireless", Mode: ModeRemote, RemoteURI: "ipps://print.local:631/printers/wireless", Options: []Option{}},
		{PrinterID: "printer-a", LocalName: "usb", Mode: ModeExisting, Options: []Option{{Name: "PageSize", Value: "4x6"}}},
	}}
	hash, err := desired.PayloadHash()
	if err != nil {
		t.Fatal(err)
	}
	desired.DesiredHash = hash
	return desired
}

func TestDesiredHashValidationAndNormalization(t *testing.T) {
	desired := testDesired(t)
	if err := desired.Validate(); err != nil {
		t.Fatal(err)
	}
	if desired.DesiredHash != "36d817ed9e2e8a1311b6359fc6a78c0b5ab8c968670788832cab4bb381ccf1bb" {
		t.Fatalf("desired hash = %s", desired.DesiredHash)
	}
	decoded, err := DecodeDesired(mustJSON(t, desired), desired.SessionID, desired.DeviceID)
	if err != nil || decoded.Queues[0].PrinterID != "printer-a" {
		t.Fatalf("decoded = %+v, %v", decoded, err)
	}
	changed := desired
	changed.Queues = append([]Queue(nil), desired.Queues...)
	changed.Queues[0].RemoteURI = "ipp://other.local/printers/wireless"
	if changed.Validate() == nil {
		t.Fatal("changed remote URI retained desired hash")
	}
	unsafe := desired
	unsafe.Queues = []Queue{{PrinterID: "p", LocalName: "NOVA_bad", Mode: ModeRemote, RemoteURI: "https://example.test/printers/a"}}
	unsafe.DesiredHash, err = unsafe.PayloadHash()
	if err != nil {
		t.Fatal(err)
	}
	if unsafe.Validate() == nil {
		t.Fatal("unsafe remote URI accepted")
	}
}

func TestDesiredV2StrictDirectProfileAndPrivateIPv4(t *testing.T) {
	desired := DesiredV2{Version: Version2, Type: DesiredType, SessionID: "session-2", DeviceID: "bridge-1", Queues: []Queue{{
		PrinterID: "printer-a", LocalName: "NOVA_ZEBRA_WIRELESS_1", Mode: ModeDirect,
		PrivateIP: "192.168.102.250", ConnectionProfile: ConnectionZebraAppSocket, DriverProfile: DriverZebraZPL,
		DisplayName: "Zebra ZD421 Wireless 1", Location: "Central print server",
		CustomMedia: &CustomMedia{Width: 90, Height: 65, Unit: "mm"}, Options: []Option{{Name: "Resolution", Value: "203dpi"}},
	}}}
	hash, err := desired.PayloadHash()
	if err != nil {
		t.Fatal(err)
	}
	desired.DesiredHash = hash
	if err := desired.Validate(); err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeDesiredV2(mustJSON(t, desired), desired.SessionID, desired.DeviceID)
	if err != nil || decoded.Version != Version2 || decoded.Queues[0].CustomMedia == nil {
		t.Fatalf("decoded direct desired = %+v, %v", decoded, err)
	}
	for _, ip := range []string{"192.168.102.250", "10.0.0.4", "172.16.0.8"} {
		candidate := desired
		candidate.Queues = append([]Queue(nil), desired.Queues...)
		candidate.Queues[0].PrivateIP = ip
		candidate.DesiredHash, _ = candidate.PayloadHash()
		if err := candidate.Validate(); err != nil {
			t.Errorf("private IPv4 %q rejected: %v", ip, err)
		}
	}
	for _, ip := range []string{"192.168.102.0250", "192.167.102.1", "8.8.8.8", "192.168.102.999"} {
		candidate := desired
		candidate.Queues = append([]Queue(nil), desired.Queues...)
		candidate.Queues[0].PrivateIP = ip
		candidate.DesiredHash, _ = candidate.PayloadHash()
		if candidate.Validate() == nil {
			t.Errorf("unsafe private IPv4 %q accepted", ip)
		}
	}
	var unknown map[string]any
	if err := json.Unmarshal(mustJSON(t, desired), &unknown); err != nil {
		t.Fatal(err)
	}
	unknown["unexpected"] = true
	if _, err := DecodeDesiredV2(mustJSON(t, unknown), desired.SessionID, desired.DeviceID); err == nil {
		t.Fatal("v2 decoder accepted an unknown field")
	}
}

func TestDesiredV2RejectsOutOfBoundCustomMedia(t *testing.T) {
	desired := DesiredV2{Version: Version2, Type: DesiredType, SessionID: "session-2", DeviceID: "bridge-1", Queues: []Queue{{PrinterID: "p", LocalName: "NOVA_P", Mode: ModeDirect, PrivateIP: "10.0.0.4", ConnectionProfile: ConnectionZebraAppSocket, DriverProfile: DriverZebraZPL, DisplayName: "Zebra", Location: "Room", CustomMedia: &CustomMedia{Width: 203.21, Height: 65, Unit: "mm"}}}}
	desired.DesiredHash, _ = desired.PayloadHash()
	if desired.Validate() == nil {
		t.Fatal("custom media above installed width bound accepted")
	}
}

func TestDirectTextUTF16Boundaries(t *testing.T) {
	for _, test := range []struct {
		name, value string
		valid       bool
	}{{"ASCII128", strings.Repeat("a", 128), true}, {"ASCII129", strings.Repeat("a", 129), false},
		{"BMP128", strings.Repeat("界", 128), true}, {"BMP129", strings.Repeat("界", 129), false},
		{"supplementary64", strings.Repeat("😀", 64), true}, {"supplementary65", strings.Repeat("😀", 65), false},
		{"mixed128", strings.Repeat("界", 126) + "😀", true}, {"mixed129", strings.Repeat("界", 127) + "😀", false},
		{"empty", "", false}, {"newline", "a\nb", false}, {"carriage-return", "a\rb", false}, {"leading-space", " a", false}, {"trailing-space", "a ", false}} {
		t.Run(test.name, func(t *testing.T) {
			if got := boundedText(test.value, 128); got != test.valid {
				t.Fatalf("validation = %t, want %t", got, test.valid)
			}
		})
	}
}
func TestDirectUnicodeServerPayloads(t *testing.T) {
	// These exact payloads/hashes are exported by the TypeScript printer normalizer.
	for _, payload := range []string{
		`{"version":2,"type":"printer.desired","sessionId":"session-test","deviceId":"device-test","desiredHash":"25a7e2426625f741fe70fc7523777e6ba8e60a12ab9dd8692fa59355e52a1aea","queues":[{"printerId":"printer-test","localName":"NOVA_test","mode":"direct","privateIp":"192.168.1.10","connectionProfile":"zebra-appsocket-9100","driverProfile":"zebra-zpl","displayName":"界界界界界界界界界界界界界界界界界界界界界界界界界界界界界界界界界界界界界界界界界界界","location":"Reception","options":[]}]}`,
		`{"version":2,"type":"printer.desired","sessionId":"session-test","deviceId":"device-test","desiredHash":"ce065495e9dc0c6395c423d28238935ca929cb451cfb4ad7d5afc6970eac608e","queues":[{"printerId":"printer-test","localName":"NOVA_test","mode":"direct","privateIp":"192.168.1.10","connectionProfile":"zebra-appsocket-9100","driverProfile":"zebra-zpl","displayName":"Printer","location":"界界界界界界界界界界界界界界界界界界界界界界界界界界界界界界界界界界界界界界界界界界界","options":[]}]}`,
	} {
		var desired DesiredV2
		if err := json.Unmarshal([]byte(payload), &desired); err != nil {
			t.Fatal(err)
		}
		hash, err := desired.PayloadHash()
		if err != nil || hash != desired.DesiredHash {
			t.Fatalf("server hash changed: %s, %v", hash, err)
		}
		if _, err := DecodeDesiredV2([]byte(payload), desired.SessionID, desired.DeviceID); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCustomMediaRejectsUnroundedPrecision(t *testing.T) {
	for _, width := range []float64{90, 90.01, 90.00001, 90.001, 90.000000001} {
		want := width == 90 || width == 90.01
		if got := validCustomMedia(CustomMedia{Unit: "mm", Width: width, Height: 65}); got != want {
			t.Fatalf("width %g accepted=%v want=%v", width, got, want)
		}
	}
}
func TestDesiredV2RejectsCaseAliasQueues(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "fixtures", "printer-desired-v2-custom-media.json"))
	if err != nil {
		t.Fatal(err)
	}
	var desired DesiredV2
	if err := json.Unmarshal(data, &desired); err != nil {
		t.Fatal(err)
	}
	alias := desired.Queues[0]
	alias.PrinterID = "printer-b"
	alias.LocalName = "NOVA_ZEBRA_1"
	desired.Queues = append(desired.Queues, alias)
	desired.DesiredHash, err = desired.PayloadHash()
	if err != nil {
		t.Fatal(err)
	}
	if err := desired.Validate(); err == nil || !strings.Contains(err.Error(), "duplicate local queue") {
		t.Fatalf("case alias accepted: %v", err)
	}
}
