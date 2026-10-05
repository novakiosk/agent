package enrollment

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"html"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// IdleRuntime owns only the separate idle surface. Implementations must never
// close or mutate the main content browser/profile.
type IdleRuntime interface {
	Apply(context.Context, *IdleDesired) error
	Close() error
}

type idleProcess interface {
	Wait() error
	Kill() error
	Alive() bool
	PID() int
}

type idleCommandRunner interface {
	Start(context.Context, string, []string, []string) (idleProcess, error)
}

type execIdleCommandRunner struct{}

type idleExecProcess struct {
	process        *os.Process
	processGroupID int
	done           chan struct{}
	result         error
}

func (process *idleExecProcess) Wait() error { <-process.done; return process.result }
func (process *idleExecProcess) Kill() error {
	if process.processGroupID > 0 {
		if err := syscall.Kill(-process.processGroupID, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
			return err
		}
		return nil
	}
	return process.process.Kill()
}
func (process *idleExecProcess) Alive() bool {
	select {
	case <-process.done:
		return false
	default:
		return true
	}
}
func (process *idleExecProcess) PID() int { return process.process.Pid }

func (execIdleCommandRunner) Start(ctx context.Context, name string, args, environment []string) (idleProcess, error) {
	command := exec.Command(name, args...)
	command.Env = environment
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Start(); err != nil {
		return nil, err
	}
	process := &idleExecProcess{process: command.Process, processGroupID: command.Process.Pid, done: make(chan struct{})}
	go func() {
		waitResult := make(chan error, 1)
		go func() { waitResult <- command.Wait() }()
		select {
		case process.result = <-waitResult:
			// The supervisor can exit while its shell or Chromium survives.
			// Tear down the owned group before Wait/Alive report completion.
			_ = process.Kill()
		case <-ctx.Done():
			// The timeout command is a process group: killing only swayidle can
			// leave its shell, helper, and Chromium child behind. Always tear down
			// the exact group on cancellation.
			_ = process.Kill()
			process.result = <-waitResult
		}
		close(process.done)
	}()
	return process, nil
}

type IdleRuntimeOptions struct {
	// LifecycleContext owns the persistent supervisor separately from bounded Apply work.
	LifecycleContext context.Context
	StateDir         string
	SwayidleBinary   string
	AgentBinary      string
	ChromiumBinary   string
	CommandRunner    idleCommandRunner
	InstanceURL      string
	CAPath           string
	HTTPClient       *http.Client
	// environment is a deterministic test seam. Production resolves and
	// validates the kiosk's current Wayland and Sway sockets.
	environment []string
}

type SwayIdleRuntime struct {
	options  IdleRuntimeOptions
	runner   idleCommandRunner
	swayidle idleProcess
	current  string
	closed   bool
}

func NewSwayIdleRuntime(options IdleRuntimeOptions) (*SwayIdleRuntime, error) {
	if err := validateIdleStateRoot(options.StateDir); err != nil {
		return nil, err
	}
	if options.SwayidleBinary == "" {
		options.SwayidleBinary = "/usr/bin/swayidle"
	}
	if options.AgentBinary == "" {
		options.AgentBinary = resolveAgentBinary()
	}
	for _, binary := range []string{options.AgentBinary, options.SwayidleBinary} {
		if !safeIdleBinary(binary) {
			return nil, fmt.Errorf("idle runtime binary path is invalid")
		}
	}
	if options.ChromiumBinary != "" && !safeIdleBinary(options.ChromiumBinary) {
		return nil, fmt.Errorf("idle Chromium binary path is invalid")
	}
	if options.CommandRunner == nil {
		options.CommandRunner = execIdleCommandRunner{}
	}
	return &SwayIdleRuntime{options: options, runner: options.CommandRunner}, nil
}

func IdleHTML(desired IdleDesired) ([]byte, error) {
	if err := ValidateIdleDesired(desired); err != nil {
		return nil, err
	}
	markup := idleMarkup(desired)
	const inputScript = `(function(){
  var havePointer = false;
  var lastX = 0;
  var lastY = 0;
  function trusted(event) { return event && event.isTrusted !== false; }
  function dismiss(event) {
    if (trusted(event)) window.__novaIdleInputSeen = true;
  }
  function pointerMove(event) {
    var x = Number(event.clientX);
    var y = Number(event.clientY);
    if (!Number.isFinite(x) || !Number.isFinite(y)) return;
    if (!havePointer) {
      havePointer = true;
      lastX = x;
      lastY = y;
      return;
    }
    var dx = x - lastX;
    var dy = y - lastY;
    lastX = x;
    lastY = y;
    if (trusted(event) && (event.movementX !== 0 || event.movementY !== 0 || dx * dx + dy * dy >= 4)) {
      window.__novaIdleInputSeen = true;
    }
  }
  window.addEventListener("pointermove", pointerMove, true);
  window.addEventListener("pointerdown", dismiss, true);
  window.addEventListener("touchstart", dismiss, true);
  window.addEventListener("wheel", dismiss, true);
  window.addEventListener("keydown", dismiss, true);
  function focusCapture() {
    var capture = document.getElementById("nova-idle-input-capture");
    if (capture) capture.focus({preventScroll:true});
  }
  if (document.readyState === "loading") {
    window.addEventListener("DOMContentLoaded", focusCapture, {once:true});
  } else {
    focusCapture();
  }
})() `
	aspectClass := "aspect-landscape"
	if desired.CanvasAspect == "9:16" {
		aspectClass = "aspect-portrait"
	}
	content := `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self' data:; media-src https://*.b-cdn.net; frame-src https://iframe.mediadelivery.net;"><title>Nova idle screen</title><style>html,body{width:100%;height:100%;margin:0}body{background:` + desired.BackgroundColor + `;overflow:hidden;position:relative;display:flex;align-items:center;justify-content:center}.idle-canvas{position:relative;flex:none;max-width:100vw;max-height:100vh;overflow:hidden;container-type:size}.idle-canvas.aspect-landscape{width:min(100vw,177.7777778vh);aspect-ratio:16/9}.idle-canvas.aspect-portrait{width:min(100vw,56.25vh);aspect-ratio:9/16}.media{position:absolute;inset:0;width:100%;height:100%;border:0;object-fit:cover;z-index:0;pointer-events:none}.logos{position:absolute;inset:0;z-index:2;pointer-events:none}.logo-row{position:absolute;left:0;width:100%;display:grid;grid-template-columns:minmax(0,1fr)}.row-top{top:3%;align-items:start}.row-middle{top:50%;transform:translateY(-50%);align-items:center}.row-bottom{bottom:3%;align-items:end}.logo-bar{position:absolute;inset:-1cqh 0;pointer-events:none}.logo-group{grid-area:1/1;display:flex;align-items:center;gap:2cqw;width:max-content;max-width:94%;z-index:1}.logo-group[data-column="left"]{justify-self:start;margin-left:3cqw}.logo-group[data-column="center"]{justify-self:center}.logo-group[data-column="right"]{justify-self:end;margin-right:3cqw}.logo{min-width:0;flex-shrink:1;height:auto;max-height:30cqh;object-fit:contain}.text-block{position:absolute;z-index:3;width:max-content;max-width:none;transform:translate(-50%,-50%);white-space:pre;overflow-wrap:normal;line-height:1.1;text-shadow:0 2px 8px #0008}.input-capture{position:fixed;inset:0;z-index:2147483647;display:block;background:transparent;outline:none;cursor:default;pointer-events:auto;user-select:none}</style><script>` + inputScript + `</script></head><body data-canvas-aspect="` + desired.CanvasAspect + `"><div class="idle-canvas ` + aspectClass + `" data-canvas-aspect="` + desired.CanvasAspect + `">` + markup + `</div><div id="nova-idle-input-capture" class="input-capture" tabindex="0" autofocus aria-hidden="true"></div></body></html>`
	return []byte(content), nil
}

func idleMarkup(desired IdleDesired) string {
	var content strings.Builder
	if desired.VideoURL != nil {
		if strings.HasPrefix(*desired.VideoURL, "https://iframe.mediadelivery.net/") {
			content.WriteString("<iframe class=\"media\" src=\"" + html.EscapeString(*desired.VideoURL) + "\" sandbox=\"allow-scripts allow-same-origin\" allow=\"autoplay\" referrerpolicy=\"no-referrer\"></iframe>")
		} else {
			content.WriteString("<video class=\"media\" autoplay loop muted playsinline src=\"" + html.EscapeString(*desired.VideoURL) + "\"></video>")
		}
	}
	for _, text := range desired.Texts {
		font, ok := idleFontCSSStack(text.Font)
		if !ok {
			font = "sans-serif"
		}
		fontSize := strconv.FormatUint(text.FontSizePercent, 10)
		content.WriteString("<main class=\"text-block\" style=\"left:" + strconv.FormatUint(text.XPercent, 10) + "%;top:" + strconv.FormatUint(text.YPercent, 10) + "%;color:" + text.Color + ";font-family:" + font + ";font-size:" + fontSize + "vmin;font-size:" + fontSize + "cqmin;font-weight:" + html.EscapeString(text.FontWeight) + ";text-align:" + html.EscapeString(text.TextAlign) + "\">" + html.EscapeString(text.Text) + "</main>")
	}
	content.WriteString("<section class=\"logos\">")
	for _, row := range []string{"top", "middle", "bottom"} {
		occupied := false
		for _, logo := range desired.Logos {
			if strings.HasPrefix(logo.Position, row+"-") {
				occupied = true
				break
			}
		}
		if !occupied {
			continue
		}
		content.WriteString("<div class=\"logo-row row-" + row + "\">")
		if desired.LogoBar != nil {
			content.WriteString("<div class=\"logo-bar\" style=\"background-color:" + desired.LogoBar.Color + ";opacity:" + strconv.FormatFloat(float64(desired.LogoBar.OpacityPercent)/100, 'f', -1, 64) + "\"></div>")
		}
		// Preserve array order within each anchor: it is also part of the payload hash.
		for _, column := range []string{"left", "center", "right"} {
			position := row + "-" + column
			opened := false
			for _, logo := range desired.Logos {
				if logo.Position != position {
					continue
				}
				if !opened {
					content.WriteString("<div class=\"logo-group " + position + "\" data-column=\"" + column + "\">")
					opened = true
				}
				extension := strings.TrimPrefix(logo.MIME, "image/")
				if extension == "jpeg" {
					extension = "jpg"
				}
				content.WriteString("<img class=\"logo\" style=\"width:" + strconv.FormatUint(logo.WidthPercent, 10) + "cqw\" src=\"assets/" + html.EscapeString(logo.SHA256) + "." + extension + "\" alt=\"" + html.EscapeString(logo.DisplayName) + "\">")
			}
			if opened {
				content.WriteString("</div>")
			}
		}
		content.WriteString("</div>")
	}
	return content.String() + "</section>"
}

func (runtime *SwayIdleRuntime) cacheIdleAssets(ctx context.Context, directory string, desired *IdleDesired) error {
	if desired == nil || len(desired.Logos) == 0 {
		return nil
	}
	if err := ensureIdleDirectory(directory); err != nil {
		return fmt.Errorf("idle asset parent directory: %w", err)
	}
	if strings.TrimSpace(runtime.options.InstanceURL) == "" {
		return errors.New("idle asset file origin is unavailable")
	}
	origin, err := CanonicalInstanceURL(runtime.options.InstanceURL)
	if err != nil {
		return fmt.Errorf("idle asset file origin: %w", err)
	}
	client := runtime.options.HTTPClient
	if client == nil {
		client, err = (Client{StateDir: runtime.options.StateDir, CAPath: runtime.options.CAPath}).httpClient()
		if err != nil {
			return fmt.Errorf("idle asset file client: %w", err)
		}
	}
	parsedOrigin, parseOriginErr := url.Parse(origin)
	if parseOriginErr != nil {
		return fmt.Errorf("idle asset file origin: %w", parseOriginErr)
	}
	clientCopy := *client
	previousRedirect := client.CheckRedirect
	clientCopy.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("idle asset file redirect limit exceeded")
		}
		if request.URL.Scheme != parsedOrigin.Scheme || request.URL.Host != parsedOrigin.Host {
			return errors.New("idle asset file redirect was not same-origin")
		}
		if previousRedirect != nil {
			return previousRedirect(request, via)
		}
		return nil
	}
	client = &clientCopy
	assets := filepath.Join(directory, "assets")
	if err := ensureIdleDirectory(assets); err != nil {
		return fmt.Errorf("idle asset directory: %w", err)
	}
	for _, logo := range desired.Logos {
		ext := "bin"
		switch logo.MIME {
		case "image/png":
			ext = "png"
		case "image/jpeg":
			ext = "jpg"
		case "image/webp":
			ext = "webp"
		}
		target := filepath.Join(assets, logo.SHA256+"."+ext)
		if info, statErr := os.Lstat(target); statErr == nil && info.Mode()&os.ModeSymlink == 0 && info.Mode().IsRegular() {
			if data, readErr := os.ReadFile(target); readErr == nil && uint64(len(data)) == logo.SizeBytes && hex.EncodeToString(func() []byte { sum := sha256.Sum256(data); return sum[:] }()) == logo.SHA256 && validIdleAssetBytes(data, logo.MIME) {
				if chmodErr := os.Chmod(target, 0o600); chmodErr != nil {
					return fmt.Errorf("protect cached idle asset: %w", chmodErr)
				}
				continue
			}
		}
		assetURL := origin + "/v1/idle-assets/" + url.PathEscape(logo.ID) + "/" + logo.SHA256
		req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, assetURL, nil)
		if reqErr != nil {
			return fmt.Errorf("idle asset file request: %w", reqErr)
		}
		response, doErr := client.Do(req)
		if doErr != nil {
			return fmt.Errorf("idle asset file unavailable: %w", doErr)
		}
		if response == nil {
			return errors.New("idle asset file response was empty")
		}
		if response.Body == nil {
			return errors.New("idle asset file response had no body")
		}
		if response.StatusCode != http.StatusOK || response.Request == nil || response.Request.URL.Scheme != "https" || response.Request.URL.Host != req.URL.Host {
			_ = response.Body.Close()
			return errors.New("idle asset file response was not same-origin")
		}
		if response.ContentLength > int64(2*1024*1024) {
			_ = response.Body.Close()
			return errors.New("idle asset file exceeds size limit")
		}
		data, readErr := io.ReadAll(io.LimitReader(response.Body, 2*1024*1024+1))
		closeErr := response.Body.Close()
		if closeErr != nil && readErr == nil {
			readErr = closeErr
		}
		if readErr != nil {
			return fmt.Errorf("read idle asset file: %w", readErr)
		}
		if len(data) > 2*1024*1024 || uint64(len(data)) != logo.SizeBytes || response.Header.Get("Content-Type") != logo.MIME {
			return errors.New("idle asset file metadata mismatch")
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != logo.SHA256 {
			return errors.New("idle asset file hash mismatch")
		}
		if !validIdleAssetBytes(data, logo.MIME) {
			return errors.New("idle asset file magic mismatch")
		}
		tmp, createErr := os.CreateTemp(assets, ".asset-*.tmp")
		if createErr != nil {
			return fmt.Errorf("create idle asset file: %w", createErr)
		}
		tmpName := tmp.Name()
		if chmodErr := tmp.Chmod(0o600); chmodErr != nil {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
			return fmt.Errorf("protect idle asset file: %w", chmodErr)
		}
		if _, writeErr := tmp.Write(data); writeErr != nil {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
			return fmt.Errorf("write idle asset file: %w", writeErr)
		}
		assetCloseErr := tmp.Close()
		if assetCloseErr != nil {
			_ = os.Remove(tmpName)
			return fmt.Errorf("write idle asset file: %w", assetCloseErr)
		}
		if err := os.Rename(tmpName, target); err != nil {
			_ = os.Remove(tmpName)
			return fmt.Errorf("install idle asset file: %w", err)
		}
		if chmodErr := os.Chmod(target, 0o600); chmodErr != nil {
			return fmt.Errorf("protect idle asset file: %w", chmodErr)
		}
	}
	return nil
}

func validIdleAssetBytes(data []byte, mime string) bool {
	switch mime {
	case "image/jpeg":
		return validIdleJPEG(data)
	case "image/webp":
		return validIdleWebP(data)
	case "image/png":
		return validIdlePNG(data)
	}
	return false
}

const (
	maxIdleImageDimension uint32 = 16384
	maxIdleImagePixels    uint64 = 64 * 1024 * 1024
)

func validIdleImageDimensions(width, height uint32) bool {
	return width >= 1 && height >= 1 && width <= maxIdleImageDimension && height <= maxIdleImageDimension && uint64(width)*uint64(height) <= maxIdleImagePixels
}

func validIdlePNG(data []byte) bool {
	signature := []byte{0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a}
	if len(data) < len(signature) || !bytes.Equal(data[:len(signature)], signature) {
		return false
	}
	offset, sawIHDR, sawPLTE, sawIDAT, sawIEND := 8, false, false, false, false
	colorType := byte(255)
	for offset < len(data) {
		if len(data)-offset < 12 {
			return false
		}
		chunkLength := uint64(binary.BigEndian.Uint32(data[offset : offset+4]))
		if chunkLength > uint64(len(data)-offset-12) {
			return false
		}
		chunkStart := offset + 8
		chunkEnd := chunkStart + int(chunkLength)
		end := chunkEnd + 4
		chunkType := data[offset+4 : offset+8]
		for _, value := range chunkType {
			if (value < 'A' || value > 'Z') && (value < 'a' || value > 'z') {
				return false
			}
		}
		if crc32.ChecksumIEEE(data[offset+4:chunkEnd]) != binary.BigEndian.Uint32(data[chunkEnd:end]) {
			return false
		}
		name := string(chunkType)
		critical := chunkType[0] >= 'A' && chunkType[0] <= 'Z'
		if !sawIHDR && name != "IHDR" {
			return false
		}
		switch name {
		case "IHDR":
			if sawIHDR || chunkLength != 13 {
				return false
			}
			width := binary.BigEndian.Uint32(data[chunkStart : chunkStart+4])
			height := binary.BigEndian.Uint32(data[chunkStart+4 : chunkStart+8])
			depth, color := data[chunkStart+8], data[chunkStart+9]
			legalDepth := map[byte]bool{1: true, 2: true, 4: true, 8: true, 16: true}
			if color == 2 || color == 4 || color == 6 {
				legalDepth = map[byte]bool{8: true, 16: true}
			} else if color == 3 {
				legalDepth = map[byte]bool{1: true, 2: true, 4: true, 8: true}
			} else if color != 0 {
				return false
			}
			if !validIdleImageDimensions(width, height) || !legalDepth[depth] || data[chunkStart+10] != 0 || data[chunkStart+11] != 0 || data[chunkStart+12] > 1 {
				return false
			}
			colorType, sawIHDR = color, true
		case "PLTE":
			if sawPLTE || sawIDAT || chunkLength < 3 || chunkLength > 768 || chunkLength%3 != 0 {
				return false
			}
			sawPLTE = true
		case "IDAT":
			if chunkLength == 0 {
				return false
			}
			sawIDAT = true
		case "IEND":
			if sawIEND || chunkLength != 0 || end != len(data) {
				return false
			}
			sawIEND = true
		default:
			if critical {
				return false
			}
		}
		offset = end
		if sawIEND {
			break
		}
	}
	return sawIHDR && sawIDAT && sawIEND && (colorType != 3 || sawPLTE)
}

func idleJPEGMarker(data []byte, offset int) (byte, int, bool) {
	if offset >= len(data) || data[offset] != 0xff {
		return 0, offset, false
	}
	offset++
	for offset < len(data) && data[offset] == 0xff {
		offset++
	}
	if offset >= len(data) || data[offset] == 0 {
		return 0, offset, false
	}
	return data[offset], offset + 1, true
}

func validIdleJPEG(data []byte) bool {
	if len(data) < 4 || data[0] != 0xff || data[1] != 0xd8 {
		return false
	}
	offset, sawSOF, sawSOS := 2, false, false
	componentCount := byte(0)
	for offset < len(data) {
		markerStart := offset
		marker, next, ok := idleJPEGMarker(data, offset)
		if !ok {
			return false
		}
		offset = next
		if marker == 0xd9 || marker == 0xd8 || marker == 0x01 || marker >= 0xd0 && marker <= 0xd7 {
			return false
		}
		if marker == 0xda {
			if !sawSOF || offset+2 > len(data) {
				return false
			}
			length := int(binary.BigEndian.Uint16(data[offset : offset+2]))
			if length < 8 || length > len(data)-offset {
				return false
			}
			segment := offset + 2
			count := data[segment]
			if count < 1 || count > 4 || length != 6+int(count)*2 || count > componentCount {
				return false
			}
			spectral := segment + 1 + int(count)*2
			if spectral+3 > offset+length || data[spectral] > 63 || data[spectral+1] > 63 || data[spectral] > data[spectral+1] || data[spectral+2] > 0x77 {
				return false
			}
			offset += length
			sawSOS = true
			entropyBytes := 0
			for offset < len(data) {
				if data[offset] != 0xff {
					offset++
					entropyBytes++
					continue
				}
				entropyMarkerStart := offset
				offset++
				for offset < len(data) && data[offset] == 0xff {
					offset++
				}
				if offset >= len(data) {
					return false
				}
				entropyMarker := data[offset]
				if entropyMarker == 0 {
					offset++
					entropyBytes++
					continue
				}
				if entropyMarker >= 0xd0 && entropyMarker <= 0xd7 {
					offset++
					continue
				}
				if entropyBytes == 0 {
					return false
				}
				if entropyMarker == 0xd9 {
					return offset+1 == len(data) && sawSOF && sawSOS
				}
				offset = entropyMarkerStart
				break
			}
			continue
		}
		isSOF := marker == 0xc0 || marker == 0xc1 || marker == 0xc2
		if isSOF {
			if sawSOF || offset+2 > len(data) {
				return false
			}
			length := int(binary.BigEndian.Uint16(data[offset : offset+2]))
			if length < 8 || length > len(data)-offset {
				return false
			}
			segment := offset + 2
			count := data[segment+5]
			if data[segment] != 8 || count < 1 || count > 4 || length != 8+int(count)*3 || !validIdleImageDimensions(uint32(binary.BigEndian.Uint16(data[segment+1:segment+3])), uint32(binary.BigEndian.Uint16(data[segment+3:segment+5]))) {
				return false
			}
			componentCount, sawSOF = count, true
		}
		if marker >= 0xc0 && marker <= 0xcf && !isSOF && marker != 0xc4 && marker != 0xc8 && marker != 0xcc {
			return false
		}
		if offset+2 > len(data) {
			return false
		}
		length := int(binary.BigEndian.Uint16(data[offset : offset+2]))
		if length < 2 || length > len(data)-offset {
			return false
		}
		offset += length
		if offset <= markerStart {
			return false
		}
	}
	return false
}

func validIdleWebP(data []byte) bool {
	if len(data) < 12 || !bytes.Equal(data[:4], []byte("RIFF")) || !bytes.Equal(data[8:12], []byte("WEBP")) || uint64(binary.LittleEndian.Uint32(data[4:8]))+8 != uint64(len(data)) {
		return false
	}
	offset, imagePrimary, extended := 12, "", false
	canvasWidth, canvasHeight := uint32(0), uint32(0)
	alpha, animation, sawAlpha, sawAnim, sawFrame := false, false, false, false, false
	seen := make(map[string]bool)
	for offset < len(data) {
		if len(data)-offset < 8 {
			return false
		}
		name := string(data[offset : offset+4])
		length := uint64(binary.LittleEndian.Uint32(data[offset+4 : offset+8]))
		if length > uint64(len(data)-offset-8) || length+uint64(offset)+8+(length%2) > uint64(len(data)) {
			return false
		}
		payload := data[offset+8 : offset+8+int(length)]
		end := offset + 8 + int(length) + int(length%2)
		if length%2 == 1 && data[end-1] != 0 {
			return false
		}
		switch name {
		case "VP8 ", "VP8L":
			if imagePrimary != "" {
				return false
			}
			imagePrimary = name
			width, height := uint32(0), uint32(0)
			if name == "VP8 " {
				if length < 10 || payload[3] != 0x9d || payload[4] != 0x01 || payload[5] != 0x2a || payload[0]&1 != 0 {
					return false
				}
				width, height = uint32(binary.LittleEndian.Uint16(payload[6:8])&0x3fff), uint32(binary.LittleEndian.Uint16(payload[8:10])&0x3fff)
			} else {
				if length < 5 || payload[0] != 0x2f {
					return false
				}
				width = 1 + uint32((uint32(payload[1])|uint32(payload[2]&0x3f)<<8)&0x3fff)
				height = 1 + uint32((uint32(payload[2]>>6)|uint32(payload[3])<<2|uint32(payload[4]&0x0f)<<10)&0x3fff)
			}
			if !validIdleImageDimensions(width, height) || extended && (width > canvasWidth || height > canvasHeight) {
				return false
			}
		case "VP8X":
			if extended || imagePrimary != "" || length != 10 || payload[0]&^byte(0x3e) != 0 || payload[1] != 0 || payload[2] != 0 || payload[3] != 0 {
				return false
			}
			extended, alpha, animation = true, payload[0]&0x10 != 0, payload[0]&0x02 != 0
			canvasWidth = 1 + uint32(payload[4]) + uint32(payload[5])<<8 + uint32(payload[6])<<16
			canvasHeight = 1 + uint32(payload[7]) + uint32(payload[8])<<8 + uint32(payload[9])<<16
			if !validIdleImageDimensions(canvasWidth, canvasHeight) {
				return false
			}
		case "ALPH":
			if sawAlpha || length == 0 {
				return false
			}
			sawAlpha = true
		case "ANIM":
			if sawAnim || length != 6 {
				return false
			}
			sawAnim = true
		case "ANMF":
			if length < 16 {
				return false
			}
			sawFrame = true
		case "ICCP", "EXIF", "XMP ":
			if seen[name] {
				return false
			}
			seen[name] = true
		default:
			if name[0] >= 'A' && name[0] <= 'Z' {
				return false
			}
		}
		offset = end
	}
	if imagePrimary == "" || offset != len(data) {
		return false
	}
	if extended {
		if animation != sawAnim || animation != sawFrame || !alpha && sawAlpha || alpha && imagePrimary == "VP8 " && !sawAlpha {
			return false
		}
	} else if sawAlpha || sawAnim || sawFrame {
		return false
	}
	return true
}

func (runtime *SwayIdleRuntime) pruneIdleAssets(desired *IdleDesired) error {
	if err := validateIdleStateRoot(runtime.options.StateDir); err != nil {
		return err
	}
	directory := filepath.Join(runtime.options.StateDir, "idle")
	assets := filepath.Join(directory, "assets")
	for _, path := range []string{directory, assets} {
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err := ensureIdleDirectory(path); err != nil {
			return fmt.Errorf("idle asset cleanup directory: %w", err)
		}
	}
	keep := make(map[string]bool)
	if desired != nil {
		for _, logo := range desired.Logos {
			extension := strings.TrimPrefix(logo.MIME, "image/")
			if extension == "jpeg" {
				extension = "jpg"
			}
			keep[logo.SHA256+"."+extension] = true
		}
	}
	root, err := os.OpenRoot(assets)
	if err != nil {
		return fmt.Errorf("open idle asset cleanup root: %w", err)
	}
	defer root.Close()
	dir, err := root.Open(".")
	if err != nil {
		return err
	}
	defer dir.Close()
	entries, err := dir.ReadDir(-1)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		if keep[name] {
			continue
		}
		digest, extension, _ := strings.Cut(name, ".")
		owned := len(digest) == 64 && strings.Trim(digest, "0123456789abcdef") == "" && (extension == "png" || extension == "jpg" || extension == "webp")
		temporary := strings.HasPrefix(name, ".asset-") && strings.HasSuffix(name, ".tmp")
		if !owned && !temporary {
			continue
		}
		if entry.IsDir() {
			return errors.New("idle asset cleanup found an unexpected directory")
		}
		if err := root.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove idle asset: %w", err)
		}
	}
	return nil
}

func (runtime *SwayIdleRuntime) Apply(ctx context.Context, desired *IdleDesired) error {
	if runtime.closed {
		return errors.New("idle runtime is closed")
	}
	if desired == nil {
		if err := runtime.stop(); err != nil {
			return err
		}
		runtime.current = ""
		return runtime.pruneIdleAssets(nil)
	}
	if err := ValidateIdleDesired(*desired); err != nil {
		return fmt.Errorf("idle desired validation: %w", err)
	}
	if runtime.current == desired.PayloadHash && runtime.swayidle != nil && runtime.swayidle.Alive() {
		return runtime.pruneIdleAssets(desired)
	}
	directory := filepath.Join(runtime.options.StateDir, "idle")
	if err := ensureIdleDirectory(directory); err != nil {
		return fmt.Errorf("idle state directory: %w", err)
	}
	if err := runtime.cacheIdleAssets(ctx, directory, desired); err != nil {
		return err
	}
	environment, err := runtime.runtimeEnvironment()
	if err != nil {
		return err
	}
	htmlData, err := IdleHTML(*desired)
	if err != nil {
		return err
	}
	if err := runtime.stop(); err != nil {
		return err
	}
	if err := installIdleFile(directory, "idle.html", htmlData); err != nil {
		return err
	}
	if err := runtime.startSwayidle(ctx, desired.TimeoutSeconds, environment); err != nil {
		_ = runtime.stop()
		return err
	}
	runtime.current = desired.PayloadHash
	return runtime.pruneIdleAssets(desired)
}

func installIdleFile(directory, name string, data []byte) error {
	if name != "idle.html" {
		return errors.New("idle document name is invalid")
	}
	if err := ensureIdleDirectory(directory); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(directory, "."+name+"-*.tmp")
	if err != nil {
		return fmt.Errorf("create idle document: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("protect idle document: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write idle document: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close idle document: %w", err)
	}
	path := filepath.Join(directory, name)
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("install idle document: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("protect idle document: %w", err)
	}
	return nil
}

func (runtime *SwayIdleRuntime) startSwayidle(ctx context.Context, timeout uint64, environment []string) error {
	command := idleShellQuote(runtime.options.AgentBinary) + " idle-surface --state-dir " + idleShellQuote(runtime.options.StateDir)
	if runtime.options.ChromiumBinary != "" {
		command += " --chromium " + idleShellQuote(runtime.options.ChromiumBinary)
	}
	swayArgs := []string{"-w", "timeout", strconv.FormatUint(timeout, 10), command}
	if runtime.options.LifecycleContext != nil {
		ctx = runtime.options.LifecycleContext
	}
	process, err := runtime.runner.Start(ctx, runtime.options.SwayidleBinary, swayArgs, environment)
	if err != nil {
		return fmt.Errorf("idle inactivity supervisor unavailable: %w", err)
	}
	runtime.swayidle = process
	return nil
}

func (runtime *SwayIdleRuntime) runtimeEnvironment() ([]string, error) {
	if runtime.options.environment != nil {
		return append([]string(nil), runtime.options.environment...), nil
	}
	environment, err := browserEnvironment(ChromiumOptions{Environment: os.Environ(), RequireGraphicalSession: true})
	if err != nil {
		return nil, fmt.Errorf("idle graphical environment unavailable: %w", err)
	}
	socket, err := discoverSwaySocket()
	if err != nil {
		return nil, fmt.Errorf("idle Sway environment unavailable: %w", err)
	}
	return mergeRuntimeEnvironment(environment, []string{"SWAYSOCK=" + socket}), nil
}

func safeIdleBinary(value string) bool {
	if value == "" || !filepath.IsAbs(value) || filepath.Clean(value) != value {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || strings.ContainsRune("/._-", character) {
			continue
		}
		return false
	}
	return true
}

func (runtime *SwayIdleRuntime) stop() error {
	var first error
	if runtime.swayidle != nil {
		if runtime.swayidle.Alive() {
			if err := runtime.swayidle.Kill(); err != nil {
				first = err
			}
		}
		_ = runtime.swayidle.Wait()
	}
	runtime.swayidle = nil
	return first
}

func (runtime *SwayIdleRuntime) Close() error {
	if runtime.closed {
		return nil
	}
	runtime.closed = true
	runtime.current = ""
	return runtime.stop()
}
