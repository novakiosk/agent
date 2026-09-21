package enrollment

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPresentationPlaylistPayloadHashFixture(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "fixtures", "presentation-playlist-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Items        []PlaylistItem `json:"items"`
		ExpectedHash string         `json:"expectedHash"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if got := PresentationPlaylistPayloadHash(fixture.Items); got != fixture.ExpectedHash {
		t.Fatalf("hash=%s expected=%s", got, fixture.ExpectedHash)
	}
}

func TestPlaylistLabelUTF16Boundaries(t *testing.T) {
	for _, test := range []struct {
		name, label string
		valid       bool
	}{{"ASCII128", strings.Repeat("a", 128), true}, {"ASCII129", strings.Repeat("a", 129), false},
		{"BMP128", strings.Repeat("界", 128), true}, {"BMP129", strings.Repeat("界", 129), false},
		{"supplementary64", strings.Repeat("😀", 64), true}, {"supplementary65", strings.Repeat("😀", 65), false},
		{"mixed128", strings.Repeat("界", 126) + "😀", true}, {"mixed129", strings.Repeat("界", 127) + "😀", false},
		{"empty", "", false}, {"newline", "a\nb", false}, {"carriage-return", "a\rb", false}, {"nul", "a\x00b", false}} {
		t.Run(test.name, func(t *testing.T) {
			items := []PlaylistItem{{Label: test.label, URL: "https://example.com/one", DurationSeconds: 5}, {Label: "Second", URL: "https://example.com/two", DurationSeconds: 5}}
			if err := validatePlaylistItems(items); (err == nil) != test.valid {
				t.Fatalf("validation error = %v, want valid %t", err, test.valid)
			}
		})
	}
}

func TestPlaylistUnicodeServerSnapshot(t *testing.T) {
	// Exported by the TypeScript presentation normalizer; retain its signed hash.
	const payload = `{"version":1,"type":"desired.snapshot","sessionId":"session-test","deviceId":"device-test","desired":{"type":"playlist-v1","groupId":"group-test","revisionId":"revision-test","revision":1,"payloadHash":"4a6cee26da825c530ef661555ae0b3ed73f6e04b060f98b2ea9f18cb344828bb","items":[{"label":"界界界界界界界界界界界界界界界界界界界界界界界界界界界界界界界界界界界界界界界界界界界","url":"https://example.com/one","durationSeconds":5},{"label":"Second","url":"https://example.com/two","durationSeconds":5}]},"idle":null,"runtime":null,"operation":null,"remoteDesktop":null,"browserCommand":null,"printerJobCommand":null,"printerQueueCommand":null}`
	var snapshot DesiredSnapshot
	if err := json.Unmarshal([]byte(payload), &snapshot); err != nil {
		t.Fatal(err)
	}
	if got := PresentationPlaylistPayloadHash(snapshot.Desired.Items); got != snapshot.Desired.PayloadHash {
		t.Fatalf("server hash changed: %s", got)
	}
	if err := validateDesiredSnapshot(snapshot, snapshot.SessionID, snapshot.DeviceID); err != nil {
		t.Fatal(err)
	}
}
