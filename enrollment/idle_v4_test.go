package enrollment

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
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

func logoFixtureDesired(t *testing.T, filename string) IdleDesired {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", filename))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		IdleDesired
		ExpectedHash string `json:"expectedHash"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	fixture.IdleDesired.PayloadHash = fixture.ExpectedHash
	return fixture.IdleDesired
}

func TestIdleSharedLogoAnchorsHashAndValidation(t *testing.T) {
	desired := logoFixtureDesired(t, "idle-screen-v4-shared-logos.json")
	if got := IdleScreenPayloadHash(desired); got != desired.PayloadHash {
		t.Fatalf("hash %s != %s", got, desired.PayloadHash)
	}
	if err := ValidateIdleDesired(desired); err != nil {
		t.Fatal(err)
	}
	desired.Logos[0], desired.Logos[2] = desired.Logos[2], desired.Logos[0]
	if IdleScreenPayloadHash(desired) == desired.PayloadHash {
		t.Fatal("row order must affect hash")
	}
	for _, position := range []string{"top-left", "top-center", "top-right", "middle-left", "middle-center", "middle-right", "bottom-left", "bottom-center", "bottom-right"} {
		for index := range desired.Logos {
			desired.Logos[index].Position = position
		}
		desired.PayloadHash = IdleScreenPayloadHash(desired)
		if err := ValidateIdleDesired(desired); err != nil {
			t.Fatalf("anchor %s: %v", position, err)
		}
	}
	for _, tc := range []struct {
		name   string
		mutate func(*IdleDesired)
	}{
		{"too many logos", func(d *IdleDesired) { d.Logos = append(d.Logos, d.Logos[0]) }},
		{"unknown anchor", func(d *IdleDesired) { d.Logos[0].Position = "outside" }},
		{"width above maximum", func(d *IdleDesired) { d.Logos[0].WidthPercent = 51 }},
		{"width below minimum", func(d *IdleDesired) { d.Logos[0].WidthPercent = 4 }},
		{"unsupported SVG", func(d *IdleDesired) { d.Logos[0].MIME = "image/svg+xml" }},
		{"empty asset", func(d *IdleDesired) { d.Logos[0].SizeBytes = 0 }},
		{"invalid digest", func(d *IdleDesired) { d.Logos[0].SHA256 = "invalid" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			invalid := logoFixtureDesired(t, "idle-screen-v4-shared-logos.json")
			tc.mutate(&invalid)
			invalid.PayloadHash = IdleScreenPayloadHash(invalid)
			if ValidateIdleDesired(invalid) == nil {
				t.Fatal("invalid logo accepted")
			}
		})
	}
}

func TestIdleSharedLogoHTMLGroupsAndPreservesRowOrder(t *testing.T) {
	desired := logoFixtureDesired(t, "idle-screen-v4-shared-logos.json")
	data, err := IdleHTML(desired)
	if err != nil {
		t.Fatal(err)
	}
	markup := string(data)
	if strings.Count(markup, `class="logo-group `) != 3 || strings.Count(markup, `class="logo"`) != 8 {
		t.Fatal("incorrect group or logo count")
	}
	if strings.Contains(markup, `class="logo-bar"`) {
		t.Fatal("disabled bar rendered behind logos")
	}
	encoded, err := json.Marshal(desired)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), `"logoBar"`) {
		t.Fatal("off must preserve the previous wire shape")
	}
	groupStart := strings.Index(markup, `<div class="logo-group middle-center"`)
	if groupStart < 0 {
		t.Fatal("missing middle-center group")
	}
	group := strings.SplitN(markup[groupStart:], "</div>", 2)[0]
	previous := -1
	for _, name := range []string{"Logo 1", "Logo 3", "Logo 5", "Logo 7", "Logo 8"} {
		index := strings.Index(group, `alt="`+name+`"`)
		if index <= previous {
			t.Fatal("group order changed")
		}
		previous = index
	}
}

func TestIdleLogoBarHashValidationAndRendering(t *testing.T) {
	desired := logoFixtureDesired(t, "idle-screen-v4-logo-bar.json")
	if got := IdleScreenPayloadHash(desired); got != desired.PayloadHash {
		t.Fatalf("hash %s != %s", got, desired.PayloadHash)
	}
	markup, err := IdleHTML(desired)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(markup), `class="logo-bar"`) != 3 {
		t.Fatal("expected one bar for each occupied vertical row")
	}
	// Multiple left/center/right groups in one row share exactly one bar.
	desired.Logos[1].Position = "middle-right"
	desired.Logos[3].Position = "middle-left"
	desired.Logos[5].Position = "middle-right"
	desired.PayloadHash = IdleScreenPayloadHash(desired)
	markup, err = IdleHTML(desired)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(markup), `class="logo-bar"`) != 1 {
		t.Fatal("same row must not stack bars")
	}
	desired.Logos = []IdleLogo{}
	desired.PayloadHash = IdleScreenPayloadHash(desired)
	markup, err = IdleHTML(desired)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(markup), `class="logo-bar"`) {
		t.Fatal("empty rows must not render a bar")
	}
}

func TestIdleLogoBarValidation(t *testing.T) {
	for _, bar := range []IdleLogoBar{{Color: "red", OpacityPercent: 50}, {Color: "#abcdef", OpacityPercent: 50}, {Color: "#123ABC", OpacityPercent: 101}} {
		t.Run(bar.Color+"/"+strconv.FormatUint(bar.OpacityPercent, 10), func(t *testing.T) {
			desired := logoFixtureDesired(t, "idle-screen-v4-logo-bar.json")
			desired.LogoBar = &bar
			desired.PayloadHash = IdleScreenPayloadHash(desired)
			if ValidateIdleDesired(desired) == nil {
				t.Fatal("invalid bar accepted")
			}
		})
	}
	for _, input := range []string{`{"color":"#000000"}`, `{"opacityPercent":50}`, `{"color":null,"opacityPercent":50}`, `{"color":"#000000","opacityPercent":null}`, `{"color":"#000000","opacityPercent":-1}`, `{"color":"#000000","opacityPercent":1.5}`, `{"color":"#000000","opacityPercent":50,"extra":true}`} {
		t.Run(input, func(t *testing.T) {
			var bar IdleLogoBar
			if json.Unmarshal([]byte(input), &bar) == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
	for _, tc := range []struct{ input, style string }{
		{`{"color":"#123ABC","opacityPercent":0}`, `background-color:#123ABC;opacity:0"`},
		{`{"color":"#456DEF","opacityPercent":50}`, `background-color:#456DEF;opacity:0.5"`},
		{`{"color":"#123ABC","opacityPercent":100}`, `background-color:#123ABC;opacity:1"`},
	} {
		t.Run(tc.input, func(t *testing.T) {
			desired := logoFixtureDesired(t, "idle-screen-v4-logo-bar.json")
			if err := json.Unmarshal([]byte(tc.input), &desired.LogoBar); err != nil {
				t.Fatal(err)
			}
			desired.PayloadHash = IdleScreenPayloadHash(desired)
			markup, err := IdleHTML(desired)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Count(string(markup), tc.style) != 3 {
				t.Fatalf("expected configured bar style %s in every occupied row", tc.style)
			}
		})
	}
}

func TestIdleLogoBarChangesAffectHash(t *testing.T) {
	for _, field := range []string{"color", "opacity", "disabled"} {
		t.Run(field, func(t *testing.T) {
			desired := logoFixtureDesired(t, "idle-screen-v4-logo-bar.json")
			switch field {
			case "color":
				desired.LogoBar.Color = "#456DEF"
			case "opacity":
				desired.LogoBar.OpacityPercent = 66
			case "disabled":
				desired.LogoBar = nil
			}
			if IdleScreenPayloadHash(desired) == desired.PayloadHash {
				t.Fatal("changed bar must affect hash")
			}
			if ValidateIdleDesired(desired) == nil {
				t.Fatal("stale payload hash accepted")
			}
		})
	}
}
