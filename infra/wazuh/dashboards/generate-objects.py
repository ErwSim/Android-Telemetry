#!/usr/bin/env python3
"""Generates watchpost-saved-objects.ndjson: "Watchpost" saved objects of the Wazuh dashboard
(OpenSearch Dashboards): 2 index patterns, 6 saved searches, 10 visualisations, 3 dashboards.
Imported by install.sh (_import API, overwrite=true). Usage: python3 generate-objects.py > watchpost-saved-objects.ndjson
"""
import json

ARCH, ALERTS = "watchpost-archives", "watchpost-alerts"
objs = []


def ss(query, index, filters=None):
    return {"searchSourceJSON": json.dumps({"query": {"query": query, "language": "kuery"},
                                            "filter": filters or [],
                                            "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"})}


def ref(index):
    return [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": index}]


def pattern(id_, title):
    objs.append({"type": "index-pattern", "id": id_, "attributes": {"title": title, "timeFieldName": "timestamp"},
                 "references": []})


def search(id_, title, index, query, columns):
    objs.append({"type": "search", "id": id_, "attributes": {
        "title": title, "description": "", "hits": 0, "columns": columns,
        "sort": [["timestamp", "desc"]], "version": 1, "kibanaSavedObjectMeta": ss(query, index)},
        "references": ref(index)})


def count():
    return {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}}


def terms(field, size=20, id_="2", schema="bucket"):
    return {"id": id_, "enabled": True, "type": "terms", "schema": schema,
            "params": {"field": field, "orderBy": "1", "order": "desc", "size": size, "otherBucket": False,
                       "otherBucketLabel": "Other", "missingBucket": False, "missingBucketLabel": "Missing"}}


def vis(id_, title, index, query, vis_type, params, aggs, desc=""):
    objs.append({"type": "visualization", "id": id_, "attributes": {
        "title": title, "description": desc, "version": 1, "uiStateJSON": "{}",
        "visState": json.dumps({"title": title, "type": vis_type, "params": params, "aggs": aggs}),
        "kibanaSavedObjectMeta": ss(query, index)}, "references": ref(index)})


TABLE = {"perPage": 15, "showPartialRows": False, "showMetricsAtAllLevels": False, "showTotal": False,
         "totalFunc": "sum", "percentageCol": ""}

pattern(ARCH, "wazuh-archives-*")
pattern(ALERTS, "wazuh-alerts-*")

search("watchpost-search-alerts", "Watchpost — alerts", ALERTS, "rule.groups:watchpost",
       ["rule.level", "rule.description", "data.watchpost.device_name", "data.watchpost.type", "data.watchpost.ts"])
search("watchpost-search-events", "Watchpost — all device events", ARCH, "data.watchpost.type:*",
       ["data.watchpost.type", "data.watchpost.sev", "data.watchpost.device_name", "data.watchpost.ts"])
search("watchpost-search-dns-blocked", "Watchpost — blocked DNS queries (AdGuard)", ARCH,
       "data.Result.IsFiltered:true", ["data.QH", "data.IP", "data.CP"])
search("watchpost-search-telemetry", "Watchpost — apps that contact telemetry", ARCH, "rule.id:100148",
       ["data.watchpost.data.package", "data.watchpost.data.hostname"])

vis("watchpost-vis-alerts-over-time", "Watchpost — alerts over time", ALERTS, "rule.groups:watchpost", "histogram",
    {"type": "histogram", "addTooltip": True, "addLegend": True, "legendPosition": "right", "times": [],
     "addTimeMarker": False},
    [count(), {"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment",
               "params": {"field": "timestamp", "interval": "auto", "min_doc_count": 1, "extended_bounds": {}}},
     terms("rule.level", 10, "3", "group")])
vis("watchpost-vis-alerts-by-rule", "Watchpost — alerts by rule", ALERTS, "rule.groups:watchpost", "table", TABLE,
    [count(), terms("rule.description", 25)])
vis("watchpost-vis-types", "Watchpost — events by type", ARCH, "data.watchpost.type:*", "table", TABLE,
    [count(), terms("data.watchpost.type", 50)])
vis("watchpost-vis-telemetry-apps", "Watchpost — telemetry by app", ARCH, "rule.id:100148", "table", TABLE,
    [count(), terms("data.watchpost.data.package", 20), terms("data.watchpost.data.hostname", 5, "3")])
vis("watchpost-vis-dns-blocked", "Watchpost — domains blocked by AdGuard", ARCH, "data.Result.IsFiltered:true", "table",
    TABLE, [count(), terms("data.QH", 30)])
vis("watchpost-vis-mitre", "Watchpost — ATT&CK Mobile techniques", ALERTS, "rule.groups:attack_mobile_*", "table", TABLE,
    [count(), terms("rule.groups", 30)],
    "attack_mobile_<ID> groups of the Watchpost rules (the Wazuh MITRE database does not cover the Mobile matrix).")
vis("watchpost-vis-map", "Watchpost — positions (location.fix)", ARCH, "data.watchpost.type:location.fix", "tile_map",
    {"colorSchema": "Yellow to Red", "mapType": "Scaled Circle Markers", "isDesaturated": True, "addTooltip": True,
     "heatClusterSize": 1.5, "legendPosition": "bottomright", "mapZoom": 11, "mapCenter": [48.8566, 2.3522],
     "wms": {"enabled": False, "options": {"format": "image/png", "transparent": True}}},
    [count(), {"id": "2", "enabled": True, "type": "geohash_grid", "schema": "segment",
               "params": {"field": "data.watchpost.data.location", "autoPrecision": True, "precision": 6,
                          "useGeocentroid": True, "isFilteredByCollar": True}}],
    "Base map loaded by the browser from the OpenSearch tile service (third party).")

# v1.2: collector detections, risk profile, guards
search("watchpost-search-detections", "Watchpost — collector detections", ALERTS, "rule.groups:watchpost_detect",
       ["rule.level", "rule.description", "data.watchpost.device_name", "data.watchpost.type", "data.watchpost.data.package"])
search("watchpost-search-risk", "Watchpost — risk profile of the applications (app.risk)", ARCH,
       "data.watchpost.type:app.risk and not data.watchpost.data.level:low",
       ["data.watchpost.data.label", "data.watchpost.data.package", "data.watchpost.data.level", "data.watchpost.data.score",
        "data.watchpost.data.reasons", "data.watchpost.device_name"])
vis("watchpost-vis-detections", "Watchpost — detections by type and application", ALERTS, "rule.groups:watchpost_detect",
    "table", TABLE, [count(), terms("data.watchpost.type", 20), terms("data.watchpost.data.package", 10, "3")])
vis("watchpost-vis-risk", "Watchpost — applications with a medium or high risk", ARCH,
    "data.watchpost.type:app.risk and not data.watchpost.data.level:low", "table", TABLE,
    [count(), terms("data.watchpost.data.package", 30), terms("data.watchpost.data.level", 3, "3")])
vis("watchpost-vis-guards", "Watchpost — guard refusals and actions", ARCH, "rule.groups:watchpost_guard", "table", TABLE,
    [count(), terms("rule.description", 30)],
    "Refused SMS sending (app.ops), guard actions (security.policy, profile guard:…).")


def dashboard(id_, title, panels, desc):
    pj, refs = [], []
    for i, (vid, x, y, w, h, typ) in enumerate(panels):
        pj.append({"version": "2.19.0", "gridData": {"x": x, "y": y, "w": w, "h": h, "i": str(i + 1)},
                   "panelIndex": str(i + 1), "embeddableConfig": {}, "panelRefName": "panel_%d" % i})
        refs.append({"name": "panel_%d" % i, "type": typ, "id": vid})
    objs.append({"type": "dashboard", "id": id_, "attributes": {
        "title": title, "description": desc, "hits": 0, "version": 1, "timeRestore": False,
        "panelsJSON": json.dumps(pj), "optionsJSON": json.dumps({"hidePanelTitles": False, "useMargins": True}),
        "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"},
                                                                  "filter": []})}},
        "references": refs})


dashboard("watchpost-dashboard-security", "Watchpost — phone security", [
    ("watchpost-vis-alerts-over-time", 0, 0, 48, 12, "visualization"),
    ("watchpost-vis-alerts-by-rule", 0, 12, 24, 16, "visualization"),
    ("watchpost-vis-mitre", 24, 12, 24, 16, "visualization"),
    ("watchpost-search-alerts", 0, 28, 48, 16, "search"),
    ("watchpost-vis-map", 0, 44, 48, 20, "visualization")],
    "Wazuh alerts from the Watchpost rules, ATT&CK Mobile techniques, positions.")
dashboard("watchpost-dashboard-tracking", "Watchpost — tracking and DNS", [
    ("watchpost-vis-telemetry-apps", 0, 0, 24, 18, "visualization"),
    ("watchpost-vis-dns-blocked", 24, 0, 24, 18, "visualization"),
    ("watchpost-vis-types", 0, 18, 24, 18, "visualization"),
    ("watchpost-search-dns-blocked", 24, 18, 24, 18, "search")],
    "Who contacts Google/Samsung telemetry, what AdGuard blocks, volume per event type.")
dashboard("watchpost-dashboard-detections", "Watchpost — detections and applications", [
    ("watchpost-vis-detections", 0, 0, 24, 18, "visualization"),
    ("watchpost-vis-risk", 24, 0, 24, 18, "visualization"),
    ("watchpost-search-detections", 0, 18, 48, 16, "search"),
    ("watchpost-vis-guards", 0, 34, 24, 16, "visualization"),
    ("watchpost-search-risk", 24, 34, 24, 16, "search")],
    "Behavioural detections of the collector (detect.*), risk profile of the applications, guards.")

for o in objs:
    print(json.dumps(o, ensure_ascii=False, separators=(",", ":")))
