#!/usr/bin/env python3
"""Génère watchpost-saved-objects.ndjson : objets sauvegardés « Watchpost » du dashboard Wazuh
(OpenSearch Dashboards) : 2 modèles d'index, 6 recherches, 10 visualisations, 3 tableaux de bord.
Importés par install.sh (API _import, overwrite=true). Usage : python3 generer-objets.py > watchpost-saved-objects.ndjson
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
                       "otherBucketLabel": "Autres", "missingBucket": False, "missingBucketLabel": "Absent"}}


def vis(id_, title, index, query, vis_type, params, aggs, desc=""):
    objs.append({"type": "visualization", "id": id_, "attributes": {
        "title": title, "description": desc, "version": 1, "uiStateJSON": "{}",
        "visState": json.dumps({"title": title, "type": vis_type, "params": params, "aggs": aggs}),
        "kibanaSavedObjectMeta": ss(query, index)}, "references": ref(index)})


TABLE = {"perPage": 15, "showPartialRows": False, "showMetricsAtAllLevels": False, "showTotal": False,
         "totalFunc": "sum", "percentageCol": ""}

pattern(ARCH, "wazuh-archives-*")
pattern(ALERTS, "wazuh-alerts-*")

search("watchpost-recherche-alertes", "Watchpost — alertes", ALERTS, "rule.groups:watchpost",
       ["rule.level", "rule.description", "data.watchpost.device_name", "data.watchpost.type", "data.watchpost.ts"])
search("watchpost-recherche-evenements", "Watchpost — tous les événements de l'appareil", ARCH, "data.watchpost.type:*",
       ["data.watchpost.type", "data.watchpost.sev", "data.watchpost.device_name", "data.watchpost.ts"])
search("watchpost-recherche-dns-bloques", "Watchpost — requêtes DNS bloquées (AdGuard)", ARCH,
       "data.Result.IsFiltered:true", ["data.QH", "data.IP", "data.CP"])
search("watchpost-recherche-telemetrie", "Watchpost — apps qui contactent la télémétrie", ARCH, "rule.id:100148",
       ["data.watchpost.data.package", "data.watchpost.data.hostname"])

vis("watchpost-vis-alertes-temps", "Watchpost — alertes dans le temps", ALERTS, "rule.groups:watchpost", "histogram",
    {"type": "histogram", "addTooltip": True, "addLegend": True, "legendPosition": "right", "times": [],
     "addTimeMarker": False},
    [count(), {"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment",
               "params": {"field": "timestamp", "interval": "auto", "min_doc_count": 1, "extended_bounds": {}}},
     terms("rule.level", 10, "3", "group")])
vis("watchpost-vis-alertes-regles", "Watchpost — alertes par règle", ALERTS, "rule.groups:watchpost", "table", TABLE,
    [count(), terms("rule.description", 25)])
vis("watchpost-vis-types", "Watchpost — événements par type", ARCH, "data.watchpost.type:*", "table", TABLE,
    [count(), terms("data.watchpost.type", 50)])
vis("watchpost-vis-telemetrie-apps", "Watchpost — télémétrie : apps", ARCH, "rule.id:100148", "table", TABLE,
    [count(), terms("data.watchpost.data.package", 20), terms("data.watchpost.data.hostname", 5, "3")])
vis("watchpost-vis-dns-bloques", "Watchpost — domaines bloqués par AdGuard", ARCH, "data.Result.IsFiltered:true", "table",
    TABLE, [count(), terms("data.QH", 30)])
vis("watchpost-vis-mitre", "Watchpost — techniques ATT&CK Mobile", ALERTS, "rule.groups:attack_mobile_*", "table", TABLE,
    [count(), terms("rule.groups", 30)],
    "Groupes attack_mobile_<ID> des règles Watchpost (la base MITRE de Wazuh ne couvre pas la matrice Mobile).")
vis("watchpost-vis-carte", "Watchpost — positions (location.fix)", ARCH, "data.watchpost.type:location.fix", "tile_map",
    {"colorSchema": "Yellow to Red", "mapType": "Scaled Circle Markers", "isDesaturated": True, "addTooltip": True,
     "heatClusterSize": 1.5, "legendPosition": "bottomright", "mapZoom": 11, "mapCenter": [48.8566, 2.3522],
     "wms": {"enabled": False, "options": {"format": "image/png", "transparent": True}}},
    [count(), {"id": "2", "enabled": True, "type": "geohash_grid", "schema": "segment",
               "params": {"field": "data.watchpost.data.location", "autoPrecision": True, "precision": 6,
                          "useGeocentroid": True, "isFilteredByCollar": True}}],
    "Fond de carte chargé par le navigateur depuis le service de tuiles d'OpenSearch (tiers).")

# v1.2 : détections du collecteur, profil de risque, gardes
search("watchpost-recherche-detections", "Watchpost — détections du collecteur", ALERTS, "rule.groups:watchpost_detect",
       ["rule.level", "rule.description", "data.watchpost.device_name", "data.watchpost.type", "data.watchpost.data.package"])
search("watchpost-recherche-risque", "Watchpost — profil de risque des applications (app.risk)", ARCH,
       "data.watchpost.type:app.risk and not data.watchpost.data.level:low",
       ["data.watchpost.data.label", "data.watchpost.data.package", "data.watchpost.data.level", "data.watchpost.data.score",
        "data.watchpost.data.reasons", "data.watchpost.device_name"])
vis("watchpost-vis-detections", "Watchpost — détections par type et application", ALERTS, "rule.groups:watchpost_detect",
    "table", TABLE, [count(), terms("data.watchpost.type", 20), terms("data.watchpost.data.package", 10, "3")])
vis("watchpost-vis-risque", "Watchpost — applications à risque moyen ou élevé", ARCH,
    "data.watchpost.type:app.risk and not data.watchpost.data.level:low", "table", TABLE,
    [count(), terms("data.watchpost.data.package", 30), terms("data.watchpost.data.level", 3, "3")])
vis("watchpost-vis-gardes", "Watchpost — gardes : refus et actions", ARCH, "rule.groups:watchpost_guard", "table", TABLE,
    [count(), terms("rule.description", 30)],
    "Envois de SMS refusés (app.ops), actions des gardes (security.policy, profile guard:…).")


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


dashboard("watchpost-tableau-securite", "Watchpost — sécurité du téléphone", [
    ("watchpost-vis-alertes-temps", 0, 0, 48, 12, "visualization"),
    ("watchpost-vis-alertes-regles", 0, 12, 24, 16, "visualization"),
    ("watchpost-vis-mitre", 24, 12, 24, 16, "visualization"),
    ("watchpost-recherche-alertes", 0, 28, 48, 16, "search"),
    ("watchpost-vis-carte", 0, 44, 48, 20, "visualization")],
    "Alertes Wazuh issues des règles Watchpost, techniques ATT&CK Mobile, positions.")
dashboard("watchpost-tableau-pistage", "Watchpost — pistage et DNS", [
    ("watchpost-vis-telemetrie-apps", 0, 0, 24, 18, "visualization"),
    ("watchpost-vis-dns-bloques", 24, 0, 24, 18, "visualization"),
    ("watchpost-vis-types", 0, 18, 24, 18, "visualization"),
    ("watchpost-recherche-dns-bloques", 24, 18, 24, 18, "search")],
    "Qui contacte la télémétrie Google/Samsung, ce qu'AdGuard bloque, volume par type d'événement.")
dashboard("watchpost-tableau-detections", "Watchpost — détections et applications", [
    ("watchpost-vis-detections", 0, 0, 24, 18, "visualization"),
    ("watchpost-vis-risque", 24, 0, 24, 18, "visualization"),
    ("watchpost-recherche-detections", 0, 18, 48, 16, "search"),
    ("watchpost-vis-gardes", 0, 34, 24, 16, "visualization"),
    ("watchpost-recherche-risque", 24, 34, 24, 16, "search")],
    "Détections comportementales du collecteur (detect.*), profil de risque des applications, gardes.")

for o in objs:
    print(json.dumps(o, ensure_ascii=False, separators=(",", ":")))
