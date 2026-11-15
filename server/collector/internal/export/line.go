// Package export writes accepted events to an NDJSON file read by the Wazuh
// manager (contract §5).
package export

import (
	"bytes"
	"encoding/json"
	"strconv"

	"github.com/erwsim/android-telemetry/server/collector/internal/model"
	"github.com/erwsim/android-telemetry/server/collector/internal/store"
)

// MaxLineBytes is the maximum size of one exported line, newline included.
const MaxLineBytes = 32 << 10

// derivedTypes lists the array fields exploded into one line per element.
var derivedTypes = map[string]struct{ key, derived string }{
	"app.inventory": {"apps", "app.inventory.app"},
	"net.usage":     {"apps", "net.usage.app"},
	"net.wifi_scan": {"aps", "net.wifi_scan.ap"},
}

type lineBody struct {
	DeviceID   string `json:"device_id"`
	DeviceName string `json:"device_name"`
	ID         string `json:"id"`
	TS         string `json:"ts"`
	ReceivedAt string `json:"received_at"`
	Seq        int64  `json:"seq"`
	Type       string `json:"type"`
	Domain     string `json:"domain"`
	Sev        int    `json:"sev"`
	Data       any    `json:"data"`
}

type line struct {
	Vigie lineBody `json:"vigie"`
}

var truncatedData = map[string]any{"truncated": true}

// Lines renders the export lines of one stored event: the event itself and,
// for the types of derivedTypes, one line per array element. Every returned
// line ends with '\n', starts with `{"` and is at most MaxLineBytes long.
func Lines(ev store.StoredEvent, deviceName string) [][]byte {
	data := decode(ev.Data)
	base := lineBody{
		DeviceID: ev.DeviceID, DeviceName: deviceName, ID: ev.ID, TS: model.FormatMS(ev.TSms),
		ReceivedAt: model.FormatMS(ev.ReceivedMS), Seq: ev.Seq, Type: ev.Type, Domain: model.Domain(ev.Type), Sev: ev.Sev,
	}
	var out [][]byte

	var elements []any
	der, hasDerived := derivedTypes[ev.Type]
	if hasDerived {
		elements, _ = data[der.key].([]any)
	}

	main := base
	clean := sanitize(data, 0)
	// data.location is reserved for the collector's geo point (mapped as
	// geo_point by the indexer): a device-supplied value of another shape would
	// make the indexer reject the whole document.
	delete(clean, "location")
	if ev.Type == "location.fix" {
		lat, ok1 := model.Num(data, "lat")
		lon, ok2 := model.Num(data, "lon")
		if ok1 && ok2 && lat >= -90 && lat <= 90 && lon >= -180 && lon <= 180 {
			clean["location"] = map[string]any{"lat": lat, "lon": lon}
		}
	}
	main.Data = clean
	out = append(out, render(main))

	if hasDerived {
		for i, el := range elements {
			m, ok := el.(map[string]any)
			if !ok {
				continue
			}
			flat := sanitize(m, 0)
			delete(flat, "location")
			if ev.Type == "net.usage" {
				for _, k := range []string{"from", "to"} {
					if v, ok := data[k]; ok && isScalar(v) {
						flat[k] = v
					}
				}
			}
			d := base
			d.ID = ev.ID + "#" + strconv.Itoa(i)
			d.Type = der.derived
			d.Domain = model.Domain(der.derived)
			d.Data = flat
			out = append(out, render(d))
		}
	}
	return out
}

func render(b lineBody) []byte {
	buf := encode(line{Vigie: b})
	if len(buf) > MaxLineBytes {
		b.Data = truncatedData
		buf = encode(line{Vigie: b})
	}
	return buf
}

func encode(v any) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		// Cannot happen with decoded JSON values; emit a minimal valid line.
		return []byte(`{"vigie":{"error":"encode"}}` + "\n")
	}
	return buf.Bytes() // Encode appends '\n'
}

// sanitize returns a copy of m where every array that is not an array of
// scalars is removed and replaced by "<key>_count" (Wazuh's JSON decoder does
// not decode arrays of objects).
func sanitize(m map[string]any, depth int) map[string]any {
	out := make(map[string]any, len(m))
	counts := map[string]int{}
	for k, v := range m {
		switch t := v.(type) {
		case map[string]any:
			if depth >= model.MaxDataDepth {
				continue
			}
			out[k] = sanitize(t, depth+1)
		case []any:
			if scalarArray(t) {
				out[k] = t
			} else {
				counts[k+"_count"] = len(t)
			}
		default:
			out[k] = v
		}
	}
	// A generated "<key>_count" wins over a sibling field of the same name.
	for k, n := range counts {
		out[k] = n
	}
	return out
}

func scalarArray(a []any) bool {
	for _, x := range a {
		if !isScalar(x) {
			return false
		}
	}
	return true
}

func isScalar(v any) bool {
	switch v.(type) {
	case map[string]any, []any:
		return false
	}
	return true
}

func decode(raw json.RawMessage) map[string]any {
	var m map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if dec.Decode(&m) != nil || m == nil {
		return map[string]any{}
	}
	return m
}
