package store

import (
	"bytes"
	"context"
	"encoding/json"
	"sort"
	"time"

	"github.com/erwsim/android-telemetry/server/collector/internal/model"
)

// DeviceSummary is one entry of GET /devices.
type DeviceSummary struct {
	DeviceID        string          `json:"device_id"`
	Name            string          `json:"name"`
	EnrolledAt      string          `json:"enrolled_at"`
	LastSeen        *string         `json:"last_seen,omitempty"`
	AgentVersion    *string         `json:"agent_version,omitempty"`
	Revoked         bool            `json:"revoked"`
	RevokedAt       *string         `json:"revoked_at,omitempty"`
	LastHeartbeat   json.RawMessage `json:"last_heartbeat,omitempty"`
	LastHeartbeatTS *string         `json:"last_heartbeat_ts,omitempty"`
	LastLocation    *LastLocation   `json:"last_location,omitempty"`
	LastPosture     json.RawMessage `json:"last_posture,omitempty"`
	LastPostureTS   *string         `json:"last_posture_ts,omitempty"`
}

// LastLocation is the last known position of a device.
type LastLocation struct {
	TS   string   `json:"ts"`
	Lat  float64  `json:"lat"`
	Lon  float64  `json:"lon"`
	AccM *float64 `json:"acc_m,omitempty"`
}

func strPtr(s string) *string { return &s }

// DeviceSummaries builds the /devices answer.
func (s *Store) DeviceSummaries(ctx context.Context) ([]DeviceSummary, error) {
	devs, err := s.ListDevices(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]DeviceSummary, 0, len(devs))
	for _, d := range devs {
		ds := DeviceSummary{
			DeviceID: d.DeviceID, Name: d.Name, EnrolledAt: model.FormatTS(d.EnrolledAt), Revoked: d.Revoked(),
		}
		if d.LastSeen != nil {
			ds.LastSeen = strPtr(model.FormatTS(*d.LastSeen))
		}
		if d.AgentVersion != "" {
			ds.AgentVersion = strPtr(d.AgentVersion)
		}
		if d.RevokedAt != nil {
			ds.RevokedAt = strPtr(model.FormatTS(*d.RevokedAt))
		}
		latest, err := s.Latest(ctx, d.DeviceID)
		if err != nil {
			return nil, err
		}
		if hb, ok := latest[LatestHeartbeat]; ok {
			ds.LastHeartbeat = hb.Data
			ds.LastHeartbeatTS = strPtr(fmtMS(hb.TSms))
		}
		if p, ok := latest[LatestPosture]; ok {
			ds.LastPosture = p.Data
			ds.LastPostureTS = strPtr(fmtMS(p.TSms))
		}
		if l, ok := latest[LatestLocation]; ok {
			var m map[string]any
			dec := json.NewDecoder(bytes.NewReader(l.Data))
			dec.UseNumber()
			if dec.Decode(&m) == nil {
				lat, ok1 := model.Num(m, "lat")
				lon, ok2 := model.Num(m, "lon")
				if ok1 && ok2 {
					ll := &LastLocation{TS: fmtMS(l.TSms), Lat: lat, Lon: lon}
					if acc, ok := model.Num(m, "acc_m"); ok {
						ll.AccM = &acc
					}
					ds.LastLocation = ll
				}
			}
		}
		out = append(out, ds)
	}
	return out, nil
}

// AppsSnapshot is the answer of GET /apps.
type AppsSnapshot struct {
	TS            *string `json:"ts,omitempty"`
	Parts         int64   `json:"parts"`
	PartsReceived int     `json:"parts_received"`
	Complete      bool    `json:"complete"`
	Apps          []any   `json:"apps"`
}

// inventoryWindow bounds how far apart the parts of one inventory may be when
// they carry no inventory_id (older agents).
const inventoryWindow = time.Hour

// maxInventoryParts bounds the number of part events read for one inventory.
const maxInventoryParts = 1000

// LatestApps reassembles the most recent app inventory from its parts.
// Parts are grouped by data.inventory_id (contract §2) when the newest part
// carries one. Otherwise (older agents) they are grouped heuristically: the
// newest event of each "part" value with the same "parts" count, within one
// hour before the newest inventory event, ignoring parts that belong to an
// identified inventory.
func (s *Store) LatestApps(ctx context.Context, deviceID string) (*AppsSnapshot, error) {
	snap := &AppsSnapshot{Apps: []any{}}
	last, err := s.EventsOfType(ctx, deviceID, "app.inventory", 0, 1<<62, 1)
	if err != nil || len(last) == 0 {
		return snap, err
	}
	l := last[0]
	snap.TS = strPtr(fmtMS(l.TSms))
	lm := decode(l.Data)
	parts, _ := model.Int(lm, "parts")
	snap.Parts = parts
	invID, _ := model.Str(lm, "inventory_id")
	var evs []StoredEvent
	if invID != "" {
		evs, err = s.inventoryParts(ctx, deviceID, invID)
	} else {
		evs, err = s.EventsOfType(ctx, deviceID, "app.inventory", l.TSms-inventoryWindow.Milliseconds(), l.TSms, maxInventoryParts)
	}
	if err != nil {
		return nil, err
	}
	byPart := map[int64]map[string]any{}
	for _, e := range evs { // newest first
		m := decode(e.Data)
		if id, _ := model.Str(m, "inventory_id"); id != invID {
			continue
		}
		p, _ := model.Int(m, "parts")
		if p != parts {
			continue
		}
		part, _ := model.Int(m, "part")
		if _, seen := byPart[part]; !seen {
			byPart[part] = m
		}
	}
	keys := make([]int64, 0, len(byPart))
	for k := range byPart {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	seen := map[string]bool{}
	for _, k := range keys {
		apps, _ := byPart[k]["apps"].([]any)
		for _, a := range apps {
			if am, ok := a.(map[string]any); ok {
				if p, _ := model.Str(am, "package"); p != "" {
					if seen[p] {
						continue
					}
					seen[p] = true
				}
			}
			snap.Apps = append(snap.Apps, a)
		}
	}
	snap.PartsReceived = len(byPart)
	snap.Complete = parts <= 0 || int64(len(byPart)) >= parts
	return snap, nil
}

// inventoryParts returns the app.inventory events of one inventory, newest first.
func (s *Store) inventoryParts(ctx context.Context, deviceID, inventoryID string) ([]StoredEvent, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT `+eventCols+` FROM events INDEXED BY events_dev_type_ts
		WHERE device_id = ? AND type = 'app.inventory' AND json_extract(data, '$.inventory_id') = ?
		ORDER BY ts_ms DESC, pk DESC LIMIT ?`, deviceID, inventoryID, maxInventoryParts)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []StoredEvent
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// PostureChange is one field change between consecutive posture events.
type PostureChange struct {
	TS    string          `json:"ts"`
	Field string          `json:"field"`
	Old   json.RawMessage `json:"old"`
	New   json.RawMessage `json:"new"`
}

// PostureAnswer is the answer of GET /posture.
type PostureAnswer struct {
	Current json.RawMessage `json:"current"`
	TS      *string         `json:"ts,omitempty"`
	Changes []PostureChange `json:"changes"`
}

// Posture returns the current posture and the field changes in [from, to], newest first.
func (s *Store) Posture(ctx context.Context, deviceID string, fromMS, toMS int64, maxChanges int) (*PostureAnswer, error) {
	ans := &PostureAnswer{Current: json.RawMessage("{}"), Changes: []PostureChange{}}
	latest, err := s.Latest(ctx, deviceID)
	if err != nil {
		return nil, err
	}
	if p, ok := latest[LatestPosture]; ok {
		ans.Current = p.Data
		ans.TS = strPtr(fmtMS(p.TSms))
	}
	evs, err := s.EventsOfType(ctx, deviceID, "security.posture", fromMS, toMS, 2000)
	if err != nil {
		return nil, err
	}
	// Include the posture just before the window so the first change inside it is detected.
	if prev, err := s.EventsOfType(ctx, deviceID, "security.posture", 0, fromMS-1, 1); err == nil && len(prev) == 1 {
		evs = append(evs, prev[0])
	}
	// evs is newest first; walk oldest to newest.
	var prevFields map[string]json.RawMessage
	for i := len(evs) - 1; i >= 0; i-- {
		var cur map[string]json.RawMessage
		if json.Unmarshal(evs[i].Data, &cur) != nil {
			continue
		}
		if prevFields != nil {
			var names []string
			for k := range cur {
				names = append(names, k)
			}
			for k := range prevFields {
				if _, ok := cur[k]; !ok {
					names = append(names, k)
				}
			}
			sort.Strings(names)
			for _, k := range names {
				o, n := prevFields[k], cur[k]
				if bytes.Equal(o, n) || postureNoise[k] {
					continue
				}
				if o == nil {
					o = json.RawMessage("null")
				}
				if n == nil {
					n = json.RawMessage("null")
				}
				ans.Changes = append(ans.Changes, PostureChange{TS: fmtMS(evs[i].TSms), Field: k, Old: o, New: n})
			}
		}
		prevFields = cur
	}
	// Newest first, bounded.
	for i, j := 0, len(ans.Changes)-1; i < j; i, j = i+1, j-1 {
		ans.Changes[i], ans.Changes[j] = ans.Changes[j], ans.Changes[i]
	}
	if len(ans.Changes) > maxChanges {
		ans.Changes = ans.Changes[:maxChanges]
	}
	return ans, nil
}

// postureNoise lists derived fields that change without a posture change.
var postureNoise = map[string]bool{"patch_age_days": true}

func decode(raw json.RawMessage) map[string]any {
	var m map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	_ = dec.Decode(&m)
	return m
}
