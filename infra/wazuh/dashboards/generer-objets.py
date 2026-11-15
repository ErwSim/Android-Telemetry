#!/usr/bin/env python3
"""Génère vigie-saved-objects.ndjson : objets sauvegardés « Vigie » du dashboard Wazuh
(OpenSearch Dashboards) : 2 modèles d'index, 4 recherches, 7 visualisations, 2 tableaux de bord.
Importés par install.sh (API _import, overwrite=true). Usage : python3 generer-objets.py > vigie-saved-objects.ndjson
"""
import json

ARCH, ALERTS = "vigie-archives", "vigie-alerts"
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

search("vigie-recherche-alertes", "Vigie — alertes", ALERTS, "rule.groups:vigie",
       ["rule.level", "rule.description", "data.vigie.device_name", "data.vigie.type", "data.vigie.ts"])
search("vigie-recherche-evenements", "Vigie — tous les événements de l'appareil", ARCH, "data.vigie.type:*",
       ["data.vigie.type", "data.vigie.sev", "data.vigie.device_name", "data.vigie.ts"])
search("vigie-recherche-dns-bloques", "Vigie — requêtes DNS bloquées (AdGuard)", ARCH,
       "data.Result.IsFiltered:true", ["data.QH", "data.IP", "data.CP"])
search("vigie-recherche-telemetrie", "Vigie — apps qui contactent la télémétrie", ARCH, "rule.id:100148",
       ["data.vigie.data.package", "data.vigie.data.hostname"])

vis("vigie-vis-alertes-temps", "Vigie — alertes dans le temps", ALERTS, "rule.groups:vigie", "histogram",
    {"type": "histogram", "addTooltip": True, "addLegend": True, "legendPosition": "right", "times": [],
     "addTimeMarker": False},
    [count(), {"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment",
               "params": {"field": "timestamp", "interval": "auto", "min_doc_count": 1, "extended_bounds": {}}},
     terms("rule.level", 10, "3", "group")])
vis("vigie-vis-alertes-regles", "Vigie — alertes par règle", ALERTS, "rule.groups:vigie", "table", TABLE,
    [count(), terms("rule.description", 25)])
vis("vigie-vis-types", "Vigie — événements par type", ARCH, "data.vigie.type:*", "table", TABLE,
    [count(), terms("data.vigie.type", 50)])
vis("vigie-vis-telemetrie-apps", "Vigie — télémétrie : apps", ARCH, "rule.id:100148", "table", TABLE,
    [count(), terms("data.vigie.data.package", 20), terms("data.vigie.data.hostname", 5, "3")])
vis("vigie-vis-dns-bloques", "Vigie — domaines bloqués par AdGuard", ARCH, "data.Result.IsFiltered:true", "table",
    TABLE, [count(), terms("data.QH", 30)])
vis("vigie-vis-mitre", "Vigie — techniques ATT&CK Mobile", ALERTS, "rule.groups:attack_mobile_*", "table", TABLE,
    [count(), terms("rule.groups", 30)],
    "Groupes attack_mobile_<ID> des règles Vigie (la base MITRE de Wazuh ne couvre pas la matrice Mobile).")
vis("vigie-vis-carte", "Vigie — positions (location.fix)", ARCH, "data.vigie.type:location.fix", "tile_map",
    {"colorSchema": "Yellow to Red", "mapType": "Scaled Circle Markers", "isDesaturated": True, "addTooltip": True,
     "heatClusterSize": 1.5, "legendPosition": "bottomright", "mapZoom": 11, "mapCenter": [48.8566, 2.3522],
     "wms": {"enabled": False, "options": {"format": "image/png", "transparent": True}}},
    [count(), {"id": "2", "enabled": True, "type": "geohash_grid", "schema": "segment",
               "params": {"field": "data.vigie.data.location", "autoPrecision": True, "precision": 6,
                          "useGeocentroid": True, "isFilteredByCollar": True}}],
    "Fond de carte chargé par le navigateur depuis le service de tuiles d'OpenSearch (tiers).")


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


dashboard("vigie-tableau-securite", "Vigie — sécurité du téléphone", [
    ("vigie-vis-alertes-temps", 0, 0, 48, 12, "visualization"),
    ("vigie-vis-alertes-regles", 0, 12, 24, 16, "visualization"),
    ("vigie-vis-mitre", 24, 12, 24, 16, "visualization"),
    ("vigie-recherche-alertes", 0, 28, 48, 16, "search"),
    ("vigie-vis-carte", 0, 44, 48, 20, "visualization")],
    "Alertes Wazuh issues des règles Vigie, techniques ATT&CK Mobile, positions.")
dashboard("vigie-tableau-pistage", "Vigie — pistage et DNS", [
    ("vigie-vis-telemetrie-apps", 0, 0, 24, 18, "visualization"),
    ("vigie-vis-dns-bloques", 24, 0, 24, 18, "visualization"),
    ("vigie-vis-types", 0, 18, 24, 18, "visualization"),
    ("vigie-recherche-dns-bloques", 24, 18, 24, 18, "search")],
    "Qui contacte la télémétrie Google/Samsung, ce qu'AdGuard bloque, volume par type d'événement.")

for o in objs:
    print(json.dumps(o, ensure_ascii=False, separators=(",", ":")))
