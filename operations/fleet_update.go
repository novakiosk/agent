package operations

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

const FleetUpdateCapability = "fleet-update-v1"
const FleetJournalName = "fleet-update.json"
const updateUnit = "novakiosk-system-update@rpm-ostree.service"

type Release struct {
	Version         int    `json:"version"`
	Compatibility   string `json:"compatibility"`
	ImageRepository string `json:"imageRepository"`
	ImageDigest     string `json:"imageDigest"`
}
type BootVersions struct {
	OS       string `json:"os"`
	Agent    string `json:"agent"`
	Novakeys string `json:"novakeys"`
}

func (v BootVersions) Valid() bool {
	for _, value := range []string{v.OS, v.Agent, v.Novakeys} {
		if len(value) > 80 {
			return false
		}
		if valid, _ := regexp.MatchString(`^[A-Za-z0-9._+-]*$`, value); !valid {
			return false
		}
	}
	return true
}

type BootRelease struct {
	Versions   *BootVersions `json:"versions,omitempty"`
	UpdateMode string        `json:"updateMode"`
	BootID     string        `json:"bootId"`
	Release    Release       `json:"release"`
}
type UpdateCommand struct {
	Action       string  `json:"action"`
	Version      int     `json:"version"`
	Type         string  `json:"type"`
	CommandID    string  `json:"commandId"`
	IssuedAt     string  `json:"issuedAt"`
	ExpiresAt    string  `json:"expiresAt"`
	ObserveUntil string  `json:"observeUntil"`
	BootIDBefore string  `json:"bootIdBefore"`
	Release      Release `json:"release"`
	PayloadHash  string  `json:"payloadHash"`
}

func FleetCanonical(kind string, fields [][2]string) []byte {
	var b strings.Builder
	b.WriteString("nova-canonical-v1\ntype=" + base64.RawURLEncoding.EncodeToString([]byte(kind)) + "\n")
	for _, f := range fields {
		b.WriteString(f[0] + "=" + base64.RawURLEncoding.EncodeToString([]byte(f[1])) + "\n")
	}
	return []byte(b.String())
}
func (r Release) Hash() string {
	hash := sha256.Sum256(FleetCanonical("fleet-update.release", [][2]string{{"compatibility", r.Compatibility}, {"imageDigest", r.ImageDigest}, {"imageRepository", r.ImageRepository}, {"version", fmt.Sprint(r.Version)}}))
	return hex.EncodeToString(hash[:])
}
func (r Release) Validate() error {
	valid, _ := regexp.MatchString(`^sha256:[a-f0-9]{64}$`, r.ImageDigest)
	if r.Version != 1 || r.Compatibility != FleetUpdateCapability || !validFleetRepository(r.ImageRepository) || !valid {
		return errors.New("invalid OS image")
	}
	return nil
}
func (c UpdateCommand) Hash() string {
	sum := sha256.Sum256(FleetCanonical("fleet-update.command", [][2]string{{"version", "1"}, {"commandId", c.CommandID}, {"issuedAt", c.IssuedAt}, {"expiresAt", c.ExpiresAt}, {"observeUntil", c.ObserveUntil}, {"bootIdBefore", c.BootIDBefore}, {"action", c.Action}, {"releaseHash", c.Release.Hash()}}))
	return hex.EncodeToString(sum[:])
}
func (c UpdateCommand) Validate(now time.Time, replay bool) error {
	issued, e1 := time.Parse(time.RFC3339Nano, c.IssuedAt)
	expires, e2 := time.Parse(time.RFC3339Nano, c.ExpiresAt)
	until, e3 := time.Parse(time.RFC3339Nano, c.ObserveUntil)
	if (c.Action != "update" && c.Action != "rollback" && c.Action != "resume") || c.Version != 1 || c.Type != "fleet-update.command" || !validCommandID(c.CommandID) || !validCommandID(c.BootIDBefore) || c.Release.Validate() != nil || c.Hash() != c.PayloadHash || e1 != nil || e2 != nil || e3 != nil || !expires.After(issued) || expires.Sub(issued) > 5*time.Minute || !until.After(expires) || until.Sub(issued) > 2*time.Hour || issued.After(now.Add(2*time.Minute)) || (!replay && !expires.After(now)) {
		return errors.New("invalid fleet update command")
	}
	return nil
}

type FleetSystem interface {
	Observe(context.Context) (BootRelease, string, error)
	Stage(context.Context, UpdateCommand) error
	Reboot(context.Context) error
	Active(context.Context) (bool, error)
}

// LinuxFleetSystem has no caller-controlled paths, executable, repository or arguments.
type LinuxFleetSystem struct{ AgentVersion string }

func FleetUpdateSupported() bool {
	return fleetUpdateSupported(func(path string) ([]byte, error) { return readFleetImageFile(path, 8192) }, os.Lstat)
}
func fleetUpdateSupported(read func(string) ([]byte, error), stat func(string) (os.FileInfo, error)) bool {
	data, err := read("/usr/share/novakiosk/fleet-update-protocol")
	if err != nil || string(data) != "fleet-update-v1\n" {
		return false
	}
	for _, p := range []string{"/usr/share/novakiosk/fleet-update-protocol", "/usr/bin/rpm-ostree", "/usr/libexec/novakiosk-system-update", "/run/ostree-booted"} {
		info, err := stat(p)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || !fleetOwner(info, 0) {
			return false
		}
	}
	return true
}
func limitedCommand(ctx context.Context, timeout time.Duration, path string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	command := exec.CommandContext(ctx, path, args...)
	command.Env = []string{"LC_ALL=C", "LANG=C", "PATH=/usr/bin:/bin"}
	out := &boundedFleetBuffer{limit: 1024 * 1024}
	command.Stdout = out
	command.Stderr = out
	err := command.Run()
	if out.exceeded {
		return nil, errors.New("output limit")
	}
	return out.Bytes(), err
}

type boundedFleetBuffer struct {
	bytes.Buffer
	limit    int
	exceeded bool
}

func (b *boundedFleetBuffer) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.Len() {
		b.exceeded = true
		return 0, errors.New("output limit")
	}
	return b.Buffer.Write(p)
}
func (s *LinuxFleetSystem) Active(ctx context.Context) (bool, error) {
	out, err := limitedCommand(ctx, 10*time.Second, "/usr/bin/systemctl", "show", updateUnit, "--property=ActiveState", "--value")
	if err != nil {
		return false, err
	}
	state := strings.TrimSpace(string(out))
	if state == "inactive" || state == "failed" {
		return false, nil
	}
	return true, nil
}
func (s *LinuxFleetSystem) Observe(ctx context.Context) (BootRelease, string, error) {
	if !FleetUpdateSupported() {
		return BootRelease{}, "", errors.New("unsupported image")
	}
	out, err := limitedCommand(ctx, 15*time.Second, "/usr/bin/rpm-ostree", "status", "--json")
	if err != nil {
		return BootRelease{}, "", err
	}
	repository, err := fleetPolicyRepository(readFleetPolicyFile)
	if err != nil {
		return BootRelease{}, "", err
	}
	digest, pending, err := fleetDeployments(out, repository)
	if err != nil {
		return BootRelease{}, "", err
	}
	bootBytes, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	bootID := strings.TrimSpace(string(bootBytes))
	if err != nil || !validCommandID(bootID) {
		return BootRelease{}, "", errors.New("boot observation unavailable")
	}
	versions := &BootVersions{OS: bootOSVersion(out), Agent: s.AgentVersion}
	if raw, err := readFleetImageFile("/usr/share/novakiosk/novakeys-version", 80); err == nil {
		versions.Novakeys = strings.TrimSpace(string(raw))
	}
	if !versions.Valid() {
		versions = nil
	}
	return BootRelease{BootID: bootID, Versions: versions, UpdateMode: bootUpdateMode(out), Release: Release{Version: 1, Compatibility: FleetUpdateCapability, ImageRepository: repository, ImageDigest: digest}}, pending, nil
}

func (s *LinuxFleetSystem) Stage(ctx context.Context, c UpdateCommand) error {
	repository, err := fleetPolicyRepository(readFleetPolicyFile)
	if err != nil || c.Release.Validate() != nil || c.Release.ImageRepository != repository {
		return errors.New("target does not match installed image policy")
	}
	if !FleetUpdateSupported() {
		return errors.New("unsupported image")
	}
	data, _ := json.Marshal(struct {
		Version     int    `json:"version"`
		CommandID   string `json:"commandId"`
		ImageDigest string `json:"imageDigest"`
		Action      string `json:"action"`
	}{1, c.CommandID, c.Release.ImageDigest, c.Action})
	if len(data) > 4096 {
		return errors.New("oversized helper request")
	}
	if err := fleetAtomic("/var/lib/novakiosk-agentd-helpers/kiosk/system-update.json", data); err != nil {
		return err
	}
	_, err = limitedCommand(ctx, 30*time.Minute, "/usr/bin/systemctl", "start", "--wait", updateUnit)
	return err
}
func (s *LinuxFleetSystem) Reboot(ctx context.Context) error {
	r := NewExecutor(OperationConfig{}).Execute(ctx, CommandReboot)
	if r.Result != ResultScheduled {
		return errors.New("reboot failed")
	}
	return nil
}

type FleetJournal struct {
	Version      int           `json:"version"`
	Command      UpdateCommand `json:"command"`
	Phase        string        `json:"phase"`
	Error        *string       `json:"error"`
	Boot         *BootRelease  `json:"boot"`
	Acknowledged bool          `json:"acknowledged"`
}
type FleetCoordinator struct {
	mu       sync.Mutex
	stateDir string
	system   FleetSystem
	clock    func() time.Time
	journal  *FleetJournal
	running  bool
}

func NewFleetCoordinator(stateDir string, system FleetSystem, clock func() time.Time) (*FleetCoordinator, error) {
	if err := validateStateDirectory(stateDir); err != nil {
		return nil, err
	}
	if system == nil {
		system = &LinuxFleetSystem{}
	}
	if clock == nil {
		clock = time.Now
	}
	c := &FleetCoordinator{stateDir: stateDir, system: system, clock: clock}
	j, err := loadFleetJournal(stateDir, clock())
	if err != nil {
		return nil, err
	}
	c.journal = j
	return c, nil
}
func loadFleetJournal(dir string, now time.Time) (*FleetJournal, error) {
	raw, err := fleetRead(filepath.Join(dir, FleetJournalName), 16384)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return decodeFleetJournal(raw, now)
}
func decodeFleetJournal(raw []byte, now time.Time) (*FleetJournal, error) {
	if len(raw) > 16384 {
		return nil, errors.New("oversized fleet journal")
	}
	var j FleetJournal
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&j) != nil || decoder.Decode(new(any)) != io.EOF || j.Version != 1 || j.Command.Validate(now, true) != nil || !strings.Contains("|accepted|executing|staged|reboot-intent|applied|already-current|failed|unknown|", "|"+j.Phase+"|") {
		return nil, errors.New("invalid fleet update journal")
	}
	if j.Acknowledged && !fleetTerminal(j.Phase) {
		return nil, errors.New("invalid acknowledged update")
	}
	if j.Boot != nil && j.Boot.Versions != nil && !j.Boot.Versions.Valid() {
		return nil, errors.New("invalid boot versions")
	}
	if j.Boot != nil && (!validCommandID(j.Boot.BootID) || j.Boot.Release.Validate() != nil || (j.Boot.UpdateMode != "automatic" && j.Boot.UpdateMode != "held")) {
		return nil, errors.New("invalid boot evidence")
	}
	if (j.Phase == "failed" || j.Phase == "unknown") != (j.Error != nil) {
		return nil, errors.New("invalid update outcome")
	}
	if j.Error != nil {
		ok, _ := regexp.MatchString(`^[a-z_]{1,80}$`, *j.Error)
		if !ok {
			return nil, errors.New("invalid update error")
		}
	}
	if j.Phase == "applied" || j.Phase == "already-current" {
		if j.Error != nil || j.Boot == nil || !j.Command.MatchesBoot(*j.Boot) || (j.Phase == "applied" && j.Boot.BootID == j.Command.BootIDBefore) || (j.Phase == "already-current" && j.Boot.BootID != j.Command.BootIDBefore) {
			return nil, errors.New("invalid completed update")
		}
	}
	return &j, nil
}
func fleetOwner(info os.FileInfo, uid uint32) bool {
	if info == nil {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == uid
}

// Anchor reads and renames to a checked, private directory. Parent components
// cannot be symlinks; writable shared ancestors must have the sticky bit.
func fleetDirectory(path string) (*os.File, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	dir := os.NewFile(uintptr(fd), "/")
	for _, part := range strings.Split(strings.TrimPrefix(abs, "/"), "/") {
		next, err := syscall.Openat(int(dir.Fd()), part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		dir.Close()
		if err != nil {
			return nil, err
		}
		dir = os.NewFile(uintptr(next), part)
		info, err := dir.Stat()
		if err != nil || (!fleetOwner(info, 0) && !fleetOwner(info, uint32(os.Geteuid()))) || (info.Mode().Perm()&0022 != 0 && info.Mode()&os.ModeSticky == 0) {
			dir.Close()
			return nil, errors.New("unsafe update parent")
		}
	}
	info, err := dir.Stat()
	if err != nil || !fleetOwner(info, uint32(os.Geteuid())) || info.Mode().Perm() != 0700 {
		dir.Close()
		return nil, errors.New("unsafe update directory")
	}
	return dir, nil
}
func fleetReadAt(dir *os.File, name string, limit int) ([]byte, error) {
	fd, err := syscall.Openat(int(dir.Fd()), name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || !fleetOwner(info, uint32(os.Geteuid())) || info.Size() > int64(limit) {
		return nil, errors.New("unsafe fleet update record")
	}
	raw, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if len(raw) > limit {
		return nil, errors.New("oversized fleet update record")
	}
	return raw, err
}
func fleetRead(path string, limit int) ([]byte, error) {
	dir, err := fleetDirectory(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	return fleetReadAt(dir, filepath.Base(path), limit)
}
func fleetAtomic(path string, data []byte) error {
	if len(data) > 16384 {
		return errors.New("oversized fleet update record")
	}
	dir, err := fleetDirectory(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	name := filepath.Base(path)
	if _, err := fleetReadAt(dir, name, 16384); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	// CreateTemp selects an unpredictable name, but all subsequent operations
	// are descriptor-relative to prevent a renamed parent redirecting writes.
	random := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, random); err != nil {
		return err
	}
	tmp := ".fleet-" + hex.EncodeToString(random)
	fd, err := syscall.Openat(int(dir.Fd()), tmp, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	defer syscall.Unlinkat(int(dir.Fd()), tmp)
	f := os.NewFile(uintptr(fd), tmp)
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = syscall.Renameat(int(dir.Fd()), tmp, int(dir.Fd()), name); err != nil {
		return err
	}
	return dir.Sync()
}

func fleetTerminal(phase string) bool {
	return phase == "applied" || phase == "already-current" || phase == "failed"
}
func (c *FleetCoordinator) persist(j FleetJournal) error {
	raw, err := json.Marshal(j)
	if err != nil {
		return err
	}
	if _, err := decodeFleetJournal(raw, c.clock()); err != nil {
		return err
	}
	if err = fleetAtomic(filepath.Join(c.stateDir, FleetJournalName), raw); err != nil {
		return err
	}
	c.journal = &j
	return nil
}
func (c *FleetCoordinator) Busy() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.journal != nil && !c.journal.Acknowledged
}
func (c *FleetCoordinator) Current() *FleetJournal {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.journal == nil {
		return nil
	}
	j := *c.journal
	return &j
}
func (c *FleetCoordinator) Observe(ctx context.Context) (BootRelease, error) {
	boot, _, err := c.system.Observe(ctx)
	return boot, err
}
func (c *FleetCoordinator) Accept(command UpdateCommand) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.journal != nil && c.journal.Command.CommandID == command.CommandID {
		if c.journal.Command.PayloadHash != command.PayloadHash || command.Validate(c.clock(), true) != nil {
			return ErrCommandConflict
		}
		return nil
	}
	if c.journal != nil && !c.journal.Acknowledged {
		return ErrCommandBusy
	}
	if err := command.Validate(c.clock(), false); err != nil {
		return err
	}
	return c.persist(FleetJournal{Version: 1, Command: command, Phase: "accepted"})
}
func (c *FleetCoordinator) Acknowledge(commandID, phase string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.journal == nil || c.journal.Command.CommandID != commandID || c.journal.Phase != phase {
		return ErrCommandConflict
	}
	if !fleetTerminal(phase) {
		return nil
	}
	j := *c.journal
	j.Acknowledged = true
	return c.persist(j)
}

// Step advances at most one durable effect boundary. Replaying a journal never
// repeats an uncertain stage or reboot. Unknown remains busy until exact boot evidence.
func (c *FleetCoordinator) Step(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.journal == nil || c.journal.Acknowledged || fleetTerminal(c.journal.Phase) {
		return nil
	}
	j := *c.journal
	// Check the service before taking the deployment snapshot. A snapshot taken
	// while the helper is finishing could otherwise falsely prove no pending work.
	active, activeErr := c.system.Active(ctx)
	if activeErr != nil || active {
		return nil
	}
	boot, pending, observeErr := c.system.Observe(ctx)
	if observeErr == nil && boot.BootID != j.Command.BootIDBefore {
		j.Boot = &boot
		if pending != "" {
			j.Phase = "unknown"
			reason := "boot_pending"
			j.Error = &reason
			return c.persist(j)
		}
		if j.Command.MatchesBoot(boot) && pending == "" {
			j.Phase = "applied"
			j.Error = nil
		} else {
			j.Phase = "failed"
			reason := "boot_release_mismatch"
			j.Error = &reason
		}
		return c.persist(j)
	}
	switch j.Phase {
	case "accepted":
		if err := j.Command.Validate(c.clock(), true); err != nil {
			return err
		}
		if observeErr != nil || boot.Release.ImageRepository != j.Command.Release.ImageRepository {
			j.Phase = "failed"
			reason := "preflight_failed"
			j.Error = &reason
			return c.persist(j)
		}
		if pending != "" {
			j.Phase = "failed"
			reason := "pending_deployment"
			j.Error = &reason
			return c.persist(j)
		}
		if j.Command.MatchesBoot(boot) {
			j.Phase = "already-current"
			j.Boot = &boot
			return c.persist(j)
		}
		j.Phase = "executing"
		if err := c.persist(j); err != nil {
			return err
		}
		c.running = true
		go func(command UpdateCommand) {
			_ = c.system.Stage(context.Background(), command)
			c.mu.Lock()
			defer c.mu.Unlock()
			c.running = false
		}(j.Command)
	case "executing", "unknown":
		if c.running {
			return nil
		}
		if j.Error != nil && *j.Error == "reboot_unresolved" {
			return nil
		}
		if observeErr == nil && pending == j.Command.PendingIdentity() {
			j.Phase = "staged"
			j.Error = nil
			return c.persist(j)
		}
		if observeErr == nil && pending == "" {
			j.Phase = "failed"
			reason := "stage_not_pending"
			j.Error = &reason
			return c.persist(j)
		}
		j.Phase = "unknown"
		reason := "execution_unresolved"
		j.Error = &reason
		return c.persist(j)
	case "staged":
		if observeErr != nil || pending != j.Command.PendingIdentity() {
			j.Phase = "unknown"
			reason := "staged_deployment_unresolved"
			j.Error = &reason
			return c.persist(j)
		}
		j.Phase = "reboot-intent"
		if err := c.persist(j); err != nil {
			return err
		}
		// Intent is durable before the one reboot call. Restart never repeats it.
		if err := c.system.Reboot(ctx); err != nil {
			j.Phase = "unknown"
			reason := "reboot_unresolved"
			j.Error = &reason
			return c.persist(j)
		}
	case "reboot-intent":
		until, _ := time.Parse(time.RFC3339Nano, j.Command.ObserveUntil)
		if c.clock().After(until) {
			j.Phase = "unknown"
			reason := "reboot_unresolved"
			j.Error = &reason
			return c.persist(j)
		}
	}
	return nil
}

func ValidateResolvedFleetJournal(raw []byte, now time.Time) error {
	j, err := decodeFleetJournal(raw, now)
	if err != nil {
		return err
	}
	if !j.Acknowledged {
		return errors.New("resolve outstanding fleet update before migration")
	}
	return nil
}

func fleetDeployments(out []byte, repository string) (string, string, error) {
	var status struct {
		Transaction json.RawMessage `json:"transaction"`
		Deployments []struct {
			Booted    bool   `json:"booted"`
			Staged    bool   `json:"staged"`
			Digest    string `json:"container-image-reference-digest"`
			Reference string `json:"container-image-reference"`
		} `json:"deployments"`
	}
	if json.Unmarshal(out, &status) != nil || len(status.Deployments) > 16 || (len(status.Transaction) > 0 && string(status.Transaction) != "null") {
		return "", "", errors.New("deployment observation invalid")
	}
	digest, pending := "", ""
	booted := 0
	for i, d := range status.Deployments {
		allowed := signedFleetReference(d.Reference, d.Digest, repository)
		if d.Booted {
			if !allowed {
				return "", "", errors.New("untrusted booted image reference")
			}
			digest = d.Digest
			booted++
		}
		// A deployment before the booted deployment is the next boot default, even
		// when rpm-ostree no longer labels it staged.
		if !d.Booted && (d.Staged || i == 0) {
			if !allowed {
				pending = "conflicting"
			} else {
				pending = repository + "|" + d.Digest + "|" + referenceMode(d.Reference)
			}
		}
	}
	if booted != 1 {
		return "", "", errors.New("ambiguous booted deployment")
	}
	return digest, pending, nil
}

// The observed reference may retain an installer tag. Trust only the actual
// local deployment digest; never resolve a tag over the network.
func signedFleetReference(reference, digest, repository string) bool {
	if !validFleetRepository(repository) {
		return false
	}
	if ok, _ := regexp.MatchString(`^sha256:[a-f0-9]{64}$`, digest); !ok {
		return false
	}
	for _, prefix := range []string{"ostree-image-signed:docker://" + repository, "ostree-image-signed:registry:" + repository} {
		if !strings.HasPrefix(reference, prefix) {
			continue
		}
		suffix := strings.TrimPrefix(reference, prefix)
		if strings.HasPrefix(suffix, "@") {
			return suffix == "@"+digest
		}
		return suffix == ":latest"
	}
	return false
}

func readFleetImageFile(path string, limit int) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || !fleetOwner(info, 0) || info.Mode().Perm()&0022 != 0 || info.Size() > int64(limit) {
		return nil, errors.New("unsafe image metadata")
	}
	raw, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if len(raw) > limit {
		return nil, errors.New("oversized image metadata")
	}
	return raw, err
}

// An attended reset must not leave an old enrollment's operation executable
// after new authority is established, or forget an uncertain root effect.
func RequireResolvedFleetUpdate(stateDir string, now time.Time) error {
	journal, err := loadFleetJournal(stateDir, now)
	if err != nil {
		return err
	}
	if journal != nil && !journal.Acknowledged {
		return errors.New("resolve outstanding fleet update before changing authority")
	}
	return nil
}

func referenceMode(reference string) string {
	if strings.HasSuffix(reference, ":latest") {
		return "automatic"
	}
	return "held"
}
func bootUpdateMode(raw []byte) string {
	var status struct {
		Deployments []struct {
			Booted    bool   `json:"booted"`
			Reference string `json:"container-image-reference"`
		} `json:"deployments"`
	}
	_ = json.Unmarshal(raw, &status)
	for _, deployment := range status.Deployments {
		if deployment.Booted {
			return referenceMode(deployment.Reference)
		}
	}
	return ""
}
func (c UpdateCommand) UpdateMode() string {
	if c.Action == "rollback" {
		return "held"
	}
	return "automatic"
}
func (c UpdateCommand) PendingIdentity() string {
	return c.Release.ImageRepository + "|" + c.Release.ImageDigest + "|" + c.UpdateMode()
}
func (c UpdateCommand) MatchesBoot(boot BootRelease) bool {
	return boot.Release.Hash() == c.Release.Hash() && boot.UpdateMode == c.UpdateMode()
}

func bootOSVersion(raw []byte) string {
	var status struct {
		Deployments []struct {
			Booted  bool   `json:"booted"`
			Version string `json:"version"`
		} `json:"deployments"`
	}
	_ = json.Unmarshal(raw, &status)
	for _, deployment := range status.Deployments {
		if deployment.Booted {
			return deployment.Version
		}
	}
	return ""
}
