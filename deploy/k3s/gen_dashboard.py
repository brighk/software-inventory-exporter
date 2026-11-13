"""Generates grafana-dashboard.yaml (a ConfigMap picked up by the Grafana sidecar)."""
import json, pathlib

DS = {"type": "prometheus", "uid": "prometheus"}
HIDE = ["Time", "Value", "__name__", "job", "instance", "namespace", "pod",
        "service", "endpoint", "container", "host_id"]

def target(expr, ref="A", fmt="table", instant=True):
    return {"datasource": DS, "expr": expr, "refId": ref, "format": fmt,
            "instant": instant, "range": not instant}

def stat(pid, title, expr, x, unit="none", thresholds=None, desc="", mapping=None):
    p = {"id": pid, "type": "stat", "title": title, "description": desc, "datasource": DS,
         "gridPos": {"h": 4, "w": 3, "x": x * 3 // 4, "y": 0},
         "targets": [target(expr, fmt="time_series")],
         "options": {"reduceOptions": {"calcs": ["lastNotNull"]}, "colorMode": "background",
                     "graphMode": "none", "textMode": "value"},
         "fieldConfig": {"defaults": {"unit": unit, "noValue": "0",
             "thresholds": {"mode": "absolute", "steps": thresholds or [{"color": "green", "value": None}]},
             "mappings": mapping or []}, "overrides": []}}
    return p

def table(pid, title, expr, y, h, rename, order, desc, overrides, sort):
    exclude = {k: True for k in HIDE}
    return {"id": pid, "type": "table", "title": title, "description": desc, "datasource": DS,
            "gridPos": {"h": h, "w": 24, "x": 0, "y": y},
            "targets": [target(expr)],
            "transformations": [
                {"id": "convertFieldType", "options": {"conversions": [
                    {"targetField": "cvss_score", "destinationType": "number"}]}},
                {"id": "organize", "options": {
                    "excludeByName": exclude, "renameByName": rename, "indexByName": order}}],
            "options": {"showHeader": True, "cellHeight": "sm", "sortBy": sort,
                        "footer": {"show": True, "reducer": ["count"], "countRows": True, "fields": ""}},
            "fieldConfig": {"defaults": {"custom": {"filterable": True, "align": "auto"}},
                            "overrides": overrides}}

def color_map(field, values):
    return {"matcher": {"id": "byName", "options": field}, "properties": [
        {"id": "custom.cellOptions", "value": {"type": "color-text"}},
        {"id": "mappings", "value": [{"type": "value", "options": {
            k: {"color": c, "index": i} for i, (k, c) in enumerate(values.items())}}]}]}

SEL = 'hostname=~"$host"'
panels = [
    stat(1, "Hosts reporting", f'count(software_inventory_host_last_seen_timestamp_seconds{{{SEL}}})', 0),
    stat(2, "Installed packages", f'count(software_inventory_package_info{{{SEL}}})', 4),
    stat(3, "Patch available", f'count(software_inventory_vulnerability_info{{{SEL},patch_available="true"}}) or vector(0)', 8,
         thresholds=[{"color": "green", "value": None}, {"color": "red", "value": 1}],
         desc="Findings where the Arch tracker lists a fixed version newer than the installed one: update (pacman -Syu)."),
    stat(4, "Open advisories, no fix", f'count(software_inventory_vulnerability_info{{{SEL},patch_available="false"}}) or vector(0)', 12,
         thresholds=[{"color": "green", "value": None}, {"color": "orange", "value": 1}],
         desc="Tracker marks the package vulnerable but has no fixed version. Often stale tracker entries; review."),
    stat(5, "Oldest host report", f'time() - min(software_inventory_host_last_seen_timestamp_seconds{{{SEL}}})', 16, unit="s",
         thresholds=[{"color": "green", "value": None}, {"color": "orange", "value": 13 * 3600}, {"color": "red", "value": 25 * 3600}],
         desc="Agents report every 12h. Orange after 13h, red after a missed cycle."),
    stat(6, "CVE feed", 'software_inventory_assessment_success', 20,
         thresholds=[{"color": "red", "value": None}, {"color": "green", "value": 1}],
         mapping=[{"type": "value", "options": {"0": {"text": "FAILED"}, "1": {"text": "OK"}}}],
         desc="Whether the latest Arch security tracker import and assessment succeeded."),
    stat(9, "CVSS ≥ 7", f'count(software_inventory_vulnerability_cvss_score{{{SEL}}} >= 7) or vector(0)', 24,
         thresholds=[{"color": "green", "value": None}, {"color": "red", "value": 1}],
         desc="Findings whose highest NVD CVSS base score is High (7.0) or Critical (9.0+)."),
    stat(10, "NVD lookup", 'software_inventory_nvd_success', 28,
         thresholds=[{"color": "red", "value": None}, {"color": "green", "value": 1}],
         mapping=[{"type": "value", "options": {"0": {"text": "FAILED"}, "1": {"text": "OK"}}}],
         desc="Whether the latest NIST NVD CVSS enrichment pass completed. New CVEs are looked up "
              "every 10 minutes (about 6 s per CVE without an API key) and refreshed weekly."),
]
sev = color_map("Severity", {"Critical": "dark-red", "High": "red", "Medium": "orange", "Low": "yellow", "Unknown": "text"})
patch = color_map("Patch available", {"true": "red", "false": "orange"})
cvss_sev = color_map("CVSS severity", {"CRITICAL": "dark-red", "HIGH": "red", "MEDIUM": "orange", "LOW": "yellow"})
cvss = {"matcher": {"id": "byName", "options": "CVSS"}, "properties": [
    {"id": "decimals", "value": 1}, {"id": "noValue", "value": "–"},
    {"id": "custom.cellOptions", "value": {"type": "color-background", "mode": "basic"}},
    {"id": "thresholds", "value": {"mode": "absolute", "steps": [
        {"color": "transparent", "value": None}, {"color": "yellow", "value": 0.1},
        {"color": "orange", "value": 4}, {"color": "red", "value": 7}, {"color": "dark-red", "value": 9}]}}]}
cve_link = {"matcher": {"id": "byName", "options": "Scored CVE"}, "properties": [{"id": "links", "value": [
    {"title": "NVD", "url": "https://nvd.nist.gov/vuln/detail/${__value.raw}", "targetBlank": True}]}]}
link = {"matcher": {"id": "byName", "options": "Advisory"}, "properties": [{"id": "links", "value": [
    {"title": "Arch security tracker", "url": "https://security.archlinux.org/${__value.raw}", "targetBlank": True}]}]}
panels.append(table(7, "Software that needs a patch",
    f'software_inventory_vulnerability_info{{{SEL}}}', 4, 12,
    {"hostname": "Host", "name": "Package", "version": "Installed", "fixed_version": "Fixed in",
     "patch_available": "Patch available", "severity": "Arch severity", "advisory": "Advisory", "cves": "CVEs",
     "finding_status": "Match", "tracker_status": "Tracker status", "cvss_score": "CVSS",
     "cvss_severity": "CVSS severity", "cvss_version": "CVSS ver.", "cvss_cve": "Scored CVE"},
    {"hostname": 0, "name": 1, "version": 2, "cvss_score": 3, "cvss_severity": 4, "fixed_version": 5,
     "patch_available": 6, "severity": 7, "advisory": 8, "cves": 9, "cvss_cve": 10, "cvss_version": 11,
     "finding_status": 12, "tracker_status": 13},
    "Packages matching an Arch security advisory. CVSS = highest NIST NVD base score among the advisory's CVEs "
    "(empty until looked up, or when NVD has not scored it). 'Patch available' = the tracker lists a fixed version: "
    "upgrade. Match 'affected' = exact affected version; 'needs_review' = possible match. Click an advisory or CVE.",
    [sev, cvss_sev, patch, link, cvss, cve_link], [{"displayName": "CVSS", "desc": True}]))
status = color_map("Status", {"affected": "red", "needs_review": "orange", "no_known_match": "green",
                              "pending": "blue", "not_assessed": "text", "stale_inventory": "purple", "unsupported": "text"})
panels.append(table(8, "All software",
    f'software_inventory_package_info{{{SEL},name=~"(?i).*$search.*"}}', 16, 16,
    {"hostname": "Host", "name": "Package", "version": "Version", "status": "Status", "collector": "Collector"},
    {"hostname": 0, "name": 1, "version": 2, "status": 3, "collector": 4},
    "Every installed package reported by agents (pacman, including dependencies). Status is the assessment against the "
    "Arch security tracker; 'no_known_match' is not proof of safety; 'pending' clears after the next hourly assessment.",
    [status], [{"displayName": "Package", "desc": False}]))

dashboard = {
    "uid": "software-inventory", "title": "Software Inventory", "tags": ["inventory", "security"],
    "timezone": "browser", "schemaVersion": 39, "editable": True, "refresh": "5m",
    "time": {"from": "now-1h", "to": "now"},
    "templating": {"list": [
        {"name": "host", "label": "Host", "type": "query", "datasource": DS,
         "query": {"query": "label_values(software_inventory_host_last_seen_timestamp_seconds, hostname)", "refId": "host"},
         "definition": "label_values(software_inventory_host_last_seen_timestamp_seconds, hostname)",
         "multi": True, "includeAll": True, "allValue": ".*", "current": {"text": "All", "value": "$__all"}, "refresh": 2},
        {"name": "search", "label": "Package contains", "type": "textbox", "query": "", "current": {"text": "", "value": ""}},
    ]},
    "panels": panels,
}
cm = {"apiVersion": "v1", "kind": "ConfigMap",
      "metadata": {"name": "software-inventory-dashboard", "namespace": "software-inventory",
                   "labels": {"grafana_dashboard": "1"}},
      "data": {"software-inventory.json": json.dumps(dashboard, indent=1)}}
out = pathlib.Path(__file__).with_name("grafana-dashboard.yaml")
out.write_text("# Generated by gen_dashboard.py; edit that file and rerun it.\n" + json.dumps(cm, indent=1) + "\n")
print("wrote", out)
