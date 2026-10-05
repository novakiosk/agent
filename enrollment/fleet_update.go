package enrollment

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/gorilla/websocket"
	"github.com/novakiosk/agent/operations"
)

// FleetUpdateReport binds the observed image digest and update mode to this authority
// and session. A lost reply leaves the durable command available for replay.
type FleetUpdateReport struct {
	Version     int                     `json:"version"`
	Type        string                  `json:"type"`
	Profile     string                  `json:"profile"`
	SessionID   string                  `json:"sessionId"`
	DeviceID    string                  `json:"deviceId"`
	CommandID   string                  `json:"commandId"`
	PayloadHash string                  `json:"payloadHash"`
	Phase       string                  `json:"phase"`
	Boot        *operations.BootRelease `json:"boot"`
	Error       *string                 `json:"error"`
	ObservedAt  string                  `json:"observedAt"`
	Sequence    uint64                  `json:"sequence"`
	Signature   string                  `json:"signature"`
}

func FleetUpdateCanonical(r FleetUpdateReport) []byte {
	bootID, releaseHash, reason, updateMode := "", "", "", ""
	versions := operations.BootVersions{}
	if r.Boot != nil {
		bootID = r.Boot.BootID
		updateMode = r.Boot.UpdateMode
		releaseHash = r.Boot.Release.Hash()
		if r.Boot.Versions != nil {
			versions = *r.Boot.Versions
		}
	}
	if r.Error != nil {
		reason = *r.Error
	}
	return operations.FleetCanonical(r.Type, [][2]string{{"version", "1"}, {"profile", r.Profile}, {"sessionId", r.SessionID}, {"deviceId", r.DeviceID}, {"commandId", r.CommandID}, {"payloadHash", r.PayloadHash}, {"phase", r.Phase}, {"bootId", bootID}, {"releaseHash", releaseHash}, {"updateMode", updateMode}, {"osVersion", versions.OS}, {"agentVersion", versions.Agent}, {"novakeysVersion", versions.Novakeys}, {"error", reason}, {"observedAt", r.ObservedAt}, {"sequence", strconv.FormatUint(r.Sequence, 10)}})
}

// Acknowledged evidence can be quiet within one session. Refresh observations
// before the server's 90-second admission freshness bound; never cache a lost ACK.
type fleetReportCache struct {
	session, key   string
	acknowledgedAt time.Time
}

func fleetReportKey(j *operations.FleetJournal) string {
	if j == nil || j.Acknowledged {
		return "observation"
	}
	raw, _ := json.Marshal(j)
	return string(raw)
}
func (c *fleetReportCache) quiet(session, key string, now time.Time) bool {
	return c != nil && c.session == session && c.key == key && !now.Before(c.acknowledgedAt) && now.Sub(c.acknowledgedAt) < 60*time.Second
}

func (client Client) handleFleetUpdate(ctx context.Context, state *State, identity Identity, connection *websocket.Conn, command *operations.UpdateCommand, fleet *operations.FleetCoordinator, power *operations.Coordinator, timeout time.Duration, cache *fleetReportCache) error {
	if fleet == nil {
		if command != nil {
			return fmt.Errorf("fleet updates unsupported")
		}
		return nil
	}
	if command != nil && fleet.Current() != nil && !fleet.Current().Acknowledged && fleet.Current().Command.CommandID != command.CommandID {
		command = nil
	}
	if command != nil {
		_, phase, present, err := power.CurrentCommand()
		if err != nil {
			return err
		}
		if present && phase != operations.PhaseResultAccepted {
			return nil
		}
		if err := fleet.Accept(*command); err != nil {
			return err
		}
	}
	journal := fleet.Current()
	key := fleetReportKey(journal)
	if cache.quiet(state.SessionID, key, client.now()) {
		return nil
	}
	report := FleetUpdateReport{Version: 1, Type: "fleet-update.report", Profile: identity.Profile(), SessionID: state.SessionID, DeviceID: state.DeviceID, Phase: "observation", ObservedAt: client.now().UTC().Format(time.RFC3339Nano)}
	if journal != nil && !journal.Acknowledged {
		report.CommandID = journal.Command.CommandID
		report.PayloadHash = journal.Command.PayloadHash
		report.Phase = journal.Phase
		report.Boot = journal.Boot
		report.Error = journal.Error
	} else {
		boot, err := fleet.Observe(ctx)
		if err != nil {
			return nil
		}
		report.Boot = &boot
	}
	if state.FleetUpdateSequence >= 9007199254740991 {
		return fmt.Errorf("fleet update sequence exhausted")
	}
	state.FleetUpdateSequence++
	report.Sequence = state.FleetUpdateSequence
	if err := SaveStateAtomic(client.StateDir, *state); err != nil {
		return err
	}
	var err error
	report.Signature, err = encodeIdentitySignature(identity, FleetUpdateCanonical(report))
	if err != nil {
		return err
	}
	if err = writeSessionMessage(connection, report, timeout); err != nil {
		return err
	}
	var ack struct {
		Version     int    `json:"version"`
		Type        string `json:"type"`
		SessionID   string `json:"sessionId"`
		DeviceID    string `json:"deviceId"`
		CommandID   string `json:"commandId"`
		Sequence    uint64 `json:"sequence"`
		Disposition string `json:"disposition"`
	}
	if err = readSessionMessage(ctx, connection, &ack); err != nil {
		return err
	}
	if ack.Version != 1 || ack.Type != "fleet-update.accepted" || ack.SessionID != report.SessionID || ack.DeviceID != report.DeviceID || ack.CommandID != report.CommandID || ack.Sequence != report.Sequence || (ack.Disposition != "accepted" && ack.Disposition != "duplicate") {
		return fmt.Errorf("fleet evidence was not accepted")
	}
	if cache != nil {
		*cache = fleetReportCache{session: state.SessionID, key: key, acknowledgedAt: client.now()}
	}
	if journal != nil && !journal.Acknowledged {
		// A background step may have advanced since this report was captured.
		// Only terminal evidence can resolve the durable journal.
		if report.Phase == "applied" || report.Phase == "already-current" || report.Phase == "failed" {
			return fleet.Acknowledge(report.CommandID, report.Phase)
		}
	}
	return nil
}
