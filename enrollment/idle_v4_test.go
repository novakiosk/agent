package enrollment

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The checked-in fixture preserves the TypeScript canonical payload contract.
func TestIdleScreenV4PayloadHashMatchesSharedFixture(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "fixtures", "idle-screen-v4.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Type            string          `json:"type"`
		IdleScreenID    string          `json:"idleScreenId"`
		RevisionID      string          `json:"revisionId"`
		Revision        uint64          `json:"revision"`
		TimeoutSeconds  uint64          `json:"timeoutSeconds"`
		BackgroundColor string          `json:"backgroundColor"`
		Logos           []IdleLogo      `json:"logos"`
		VideoURL        *string         `json:"videoUrl"`
		CanvasAspect    string          `json:"canvasAspect"`
		Texts           []IdleTextBlock `json:"texts"`
		ExpectedHash    string          `json:"expectedHash"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	desired := IdleDesired{
		Type: fixture.Type, IdleScreenID: fixture.IdleScreenID, RevisionID: fixture.RevisionID,
		Revision: fixture.Revision, TimeoutSeconds: fixture.TimeoutSeconds,
		BackgroundColor: fixture.BackgroundColor, Logos: fixture.Logos, VideoURL: fixture.VideoURL,
		CanvasAspect: fixture.CanvasAspect, Texts: fixture.Texts, PayloadHash: fixture.ExpectedHash,
	}
	if got := IdleScreenPayloadHash(desired); got != fixture.ExpectedHash {
		t.Fatalf("idle v4 hash = %s, want %s", got, fixture.ExpectedHash)
	}
	if err := ValidateIdleDesired(desired); err != nil {
		t.Fatal(err)
	}
}

func TestIdleScreenV4HTMLRendersOrderedBlocksWithEscapedText(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "fixtures", "idle-screen-v4.json"))
	if err != nil {
		t.Fatal(err)
	}
	var desired IdleDesired
	var fixture struct {
		Type            string          `json:"type"`
		IdleScreenID    string          `json:"idleScreenId"`
		RevisionID      string          `json:"revisionId"`
		Revision        uint64          `json:"revision"`
		TimeoutSeconds  uint64          `json:"timeoutSeconds"`
		BackgroundColor string          `json:"backgroundColor"`
		Logos           []IdleLogo      `json:"logos"`
		VideoURL        *string         `json:"videoUrl"`
		CanvasAspect    string          `json:"canvasAspect"`
		Texts           []IdleTextBlock `json:"texts"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	desired = IdleDesired{Type: fixture.Type, IdleScreenID: fixture.IdleScreenID, RevisionID: fixture.RevisionID, Revision: fixture.Revision, TimeoutSeconds: fixture.TimeoutSeconds, BackgroundColor: fixture.BackgroundColor, Logos: fixture.Logos, VideoURL: fixture.VideoURL, CanvasAspect: fixture.CanvasAspect, Texts: fixture.Texts}
	desired.Texts[0].Text = "A&B"
	desired.PayloadHash = IdleScreenPayloadHash(desired)
	html, err := IdleHTML(desired)
	if err != nil {
		t.Fatal(err)
	}
	markup := string(html)
	if strings.Count(markup, `class="text-block"`) != 2 || !strings.Contains(markup, "A&amp;B") || !strings.Contains(markup, `color:#FFFFFF`) || !strings.Contains(markup, `color:#9FE3EC`) {
		t.Fatalf("v4 text blocks were not rendered as expected: %s", markup)
	}
}
