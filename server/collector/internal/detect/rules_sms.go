package detect

import (
	"fmt"
	"sort"
	"strings"
)

// Detections of contract §11.4, computed without app.ops: SMS do not use the IP network,
// and app.ops is experimental and may never be available on the phone. They read app.inventory,
// app.permission_changed and app.role.

// SMSHolder is an application holding SEND_SMS.
type SMSHolder struct {
	Package string
	// SinceMS is the start of the current holding: the grant that followed the last revocation, or the first
	// observation (event or inventory) when it was never revoked.
	SinceMS int64
	// Source: "inventory" (app.inventory.granted_dangerous) or "permission_changed".
	Source    string
	Installer string
}

// SMSPermissionInput is the state of SEND_SMS on a device.
type SMSPermissionInput struct {
	Holders []SMSHolder
	// SMSApps are the holders of the default SMS role (nil: unknown).
	SMSApps map[string]bool
	// System are the system applications (inventory claims contradicted by the history excluded).
	System map[string]bool
	// Risks gives the latest app.risk of an application (score, level, reasons, granted).
	Risks  map[string]Risk
	Labels Labels
}

// SMSPermission: an application that is neither the default SMS app nor a system application holds SEND_SMS
// (contract §11.4). One finding per holding: its window starts at SinceMS; the engine skips a holding already
// reported (a new one only after the permission was revoked and granted again).
func SMSPermission(in SMSPermissionInput) []Finding {
	hs := append([]SMSHolder(nil), in.Holders...)
	sort.Slice(hs, func(i, j int) bool { return hs[i].Package < hs[j].Package })
	var out []Finding
	for _, h := range hs {
		if h.Package == "" || OwnPackage(h.Package) || in.System[h.Package] || in.SMSApps[h.Package] {
			continue
		}
		ev := map[string]any{"permission": "SEND_SMS", "source": h.Source, "since": fmtMS(h.SinceMS)}
		if h.Installer != "" {
			ev["installer"] = h.Installer
		}
		if in.SMSApps != nil {
			ev["default_sms_app"] = toAny(sortedKeys(in.SMSApps))
		}
		risk := ""
		if r, ok := in.Risks[h.Package]; ok {
			ev["score"], ev["level"], ev["reasons"] = r.Score, r.Level, toAny(r.Reasons)
			risk = fmt.Sprintf("; risk profile %s (%d)", r.Level, r.Score)
		}
		out = append(out, Finding{Type: TypeSMSPermission, Package: h.Package, Subject: h.Package, FromMS: h.SinceMS, ToMS: h.SinceMS + hourMS, Sev: 2,
			Summary: fmt.Sprintf("%s can send SMS (SEND_SMS permission) without being the default SMS app or a system application%s. "+
				"Without the SMS guard, any messages it sends are not counted (app.ops)", in.Labels.of(h.Package), risk),
			Evidence: ev, Items: []string{"SEND_SMS"}})
	}
	return out
}

// RoleChange is an app.role event.
type RoleChange struct {
	Role, Old, New string
	TS             int64
}

// defaultAppRoles are the roles followed by detect.default_app_changed, with their severity.
var defaultAppRoles = map[string]int{"sms": 3, "dialer": 2, "keyboard": 2, "assistant": 2}

var roleNames = map[string]string{"sms": "SMS app", "dialer": "dialer app", "keyboard": "keyboard", "assistant": "assistant"}

// DefaultAppChanged: the default application of the sms, dialer, keyboard or assistant role changed (the
// usual way of SMS trojans: being made the default SMS app). One finding per change.
func DefaultAppChanged(changes []RoleChange, risks map[string]Risk, labels Labels) []Finding {
	var out []Finding
	for _, c := range changes {
		sev, ok := defaultAppRoles[c.Role]
		if !ok || c.New == "" || c.New == c.Old || OwnPackage(c.New) {
			continue
		}
		ev := map[string]any{"role": c.Role, "new": c.New}
		old := "unknown"
		if c.Old != "" {
			ev["old"] = c.Old
			old = labels.of(c.Old)
		}
		risk := ""
		if r, ok := risks[c.New]; ok {
			ev["score"], ev["level"], ev["reasons"] = r.Score, r.Level, toAny(r.Reasons)
			if len(r.Granted) > 0 {
				ev["granted"] = toAny(r.Granted)
			}
			risk = fmt.Sprintf(" (risk profile %s, %d)", r.Level, r.Score)
		}
		out = append(out, Finding{Type: TypeDefaultAppChanged, Package: c.New, Subject: c.Role, FromMS: c.TS, ToMS: c.TS + hourMS, Sev: sev,
			Summary:  fmt.Sprintf("Default %s changed: %s replaces %s%s", roleNames[c.Role], labels.of(c.New), old, risk),
			Evidence: ev, Items: []string{c.New}})
	}
	return out
}

// SideloadInstallers are installers that never install a system application.
var SideloadInstallers = map[string]bool{"com.google.android.packageinstaller": true, "com.android.packageinstaller": true,
	"com.android.shell": true, "adb": true}

// SystemClaim is an application the latest inventory declares "system".
type SystemClaim struct {
	Package, Installer string
	Installed          bool // an app.installed event exists for it (system applications are preinstalled)
}

// Contradicted returns why a "system" claim is contradicted ("" when it is not).
func (c SystemClaim) Contradicted() []string {
	var why []string
	if SideloadInstallers[c.Installer] {
		why = append(why, "installer:"+c.Installer)
	}
	if c.Installed {
		why = append(why, "app.installed")
	}
	return why
}

// InventoryMismatch: an inventory declares "system" an application that its installer or its history show
// was installed (contract §11.4). The application is then treated as not system by the other detections.
func InventoryMismatch(dayMS int64, claims []SystemClaim, labels Labels) []Finding {
	var out []Finding
	for _, c := range claims {
		why := c.Contradicted()
		if len(why) == 0 {
			continue
		}
		out = append(out, Finding{Type: TypeInventoryMismatch, Package: c.Package, Subject: c.Package, FromMS: dayMS, ToMS: dayMS + dayMS, Sev: 3,
			Summary: fmt.Sprintf("The inventory declares %s a system application, which %s contradict: it is treated as an ordinary application",
				labels.of(c.Package), strings.Join(why, ", ")),
			Evidence: map[string]any{"installer": c.Installer, "contradictions": toAny(why)}, Items: why})
	}
	return out
}

// grantedCapabilities maps the codes of app.risk (granted list) to the capabilities of detect.new_app_risky.
var grantedCapabilities = map[string]string{
	"sms_send": "permission:SEND_SMS", "sms_read": "permission:READ_SMS", "calls": "permission:CALL_PHONE",
	"accessibility_service": "accessibility", "notification_listener": "notification_listener", "device_admin": "device_admin",
	"overlay": "overlay", "install_packages": "unknown_sources", "vpn_service": "vpn",
}

// GrantedCapabilities returns the capabilities obtained according to the granted list of an app.risk.
func GrantedCapabilities(r Risk) []Capability {
	var out []Capability
	for _, g := range r.Granted {
		if k, ok := grantedCapabilities[strings.TrimSuffix(g, ":granted")]; ok {
			out = append(out, Capability{Package: r.Package, Kind: k, TS: r.TS})
		}
	}
	return out
}
