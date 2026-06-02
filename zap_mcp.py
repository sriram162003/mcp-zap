# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "mcp[cli]",
#   "requests",
# ]
# ///

import subprocess
import time
import requests
import secrets
import os
from datetime import datetime
from pathlib import Path
from mcp.server.fastmcp import FastMCP

ZAP_PORT = 8090
ZAP_BASE = f"http://localhost:{ZAP_PORT}"
ZAP_APP = "/Applications/ZAP.app/Contents/Java/zap.sh"

# Persist the API key so it survives across Claude sessions
_KEY_FILE = Path.home() / "mcp-zap" / ".zap_api_key"
_KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
if _KEY_FILE.exists():
    ZAP_API_KEY = _KEY_FILE.read_text().strip()
else:
    ZAP_API_KEY = secrets.token_hex(16)
    _KEY_FILE.write_text(ZAP_API_KEY)

mcp = FastMCP("zap")
_zap_proc = None


def _start_zap():
    global _zap_proc
    # Already up with the right key?
    try:
        r = requests.get(f"{ZAP_BASE}/JSON/core/view/version/", params={"apikey": ZAP_API_KEY}, timeout=3)
        if r.status_code == 200:
            return
    except Exception:
        pass

    # Kill any stale ZAP process on our port before starting fresh
    subprocess.run(["pkill", "-f", f"zap.*-port {ZAP_PORT}"], capture_output=True)
    time.sleep(2)

    _zap_proc = subprocess.Popen(
        [
            ZAP_APP,
            "-daemon",
            "-port", str(ZAP_PORT),
            "-config", f"api.key={ZAP_API_KEY}",
            "-config", "api.addrs.addr.name=.*",
            "-config", "api.addrs.addr.regex=true",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    for _ in range(40):
        time.sleep(1)
        try:
            r = requests.get(f"{ZAP_BASE}/JSON/core/view/version/", params={"apikey": ZAP_API_KEY}, timeout=2)
            if r.status_code == 200:
                return
        except Exception:
            pass
    raise RuntimeError("ZAP did not start in time")


def _zap(path: str, params: dict = None):
    _start_zap()
    p = {"apikey": ZAP_API_KEY}
    if params:
        p.update(params)
    r = requests.get(f"{ZAP_BASE}{path}", params=p, timeout=60)
    r.raise_for_status()
    return r.json()


@mcp.tool()
def zap_version() -> str:
    """Get the running ZAP version (also confirms ZAP is up)."""
    data = _zap("/JSON/core/view/version/")
    return data.get("version", str(data))


@mcp.tool()
def zap_spider(url: str) -> str:
    """Start a spider crawl on the given URL and wait for it to finish. Returns discovered URLs."""
    data = _zap("/JSON/spider/action/scan/", {"url": url})
    scan_id = data["scan"]
    while True:
        prog = _zap("/JSON/spider/view/status/", {"scanId": scan_id})
        if int(prog["status"]) >= 100:
            break
        time.sleep(2)
    results = _zap("/JSON/spider/view/results/", {"scanId": scan_id})
    urls = results.get("results", [])
    return f"Spider found {len(urls)} URLs:\n" + "\n".join(urls[:50]) + ("\n..." if len(urls) > 50 else "")


@mcp.tool()
def zap_active_scan(url: str) -> str:
    """Run an active vulnerability scan against the given URL. Waits for completion and returns alert summary."""
    data = _zap("/JSON/ascan/action/scan/", {"url": url})
    scan_id = data["scan"]
    while True:
        prog = _zap("/JSON/ascan/view/status/", {"scanId": scan_id})
        if int(prog["status"]) >= 100:
            break
        time.sleep(3)
    alerts = _zap("/JSON/core/view/alerts/", {"baseurl": url})
    items = alerts.get("alerts", [])
    if not items:
        return "Active scan complete. No alerts found."
    summary = f"Active scan complete. {len(items)} alert(s):\n"
    for a in items:
        summary += f"  [{a.get('risk')}] {a.get('name')} — {a.get('url')}\n"
    return summary


@mcp.tool()
def zap_get_alerts(url: str = "") -> str:
    """Get all current alerts from ZAP. Optionally filter by base URL."""
    params = {}
    if url:
        params["baseurl"] = url
    alerts = _zap("/JSON/core/view/alerts/", params)
    items = alerts.get("alerts", [])
    if not items:
        return "No alerts found."
    out = f"{len(items)} alert(s):\n"
    for a in items:
        out += f"  [{a.get('risk')}] {a.get('name')}\n    URL: {a.get('url')}\n    Desc: {a.get('description','')[:120]}\n\n"
    return out


@mcp.tool()
def zap_passive_scan_wait() -> str:
    """Wait for ZAP's passive scanner to finish processing queued records."""
    while True:
        data = _zap("/JSON/pscan/view/recordsToScan/")
        remaining = int(data.get("recordsToScan", 0))
        if remaining == 0:
            break
        time.sleep(2)
    return "Passive scan queue is empty."


@mcp.tool()
def zap_open_url(url: str) -> str:
    """Force ZAP to send an HTTP request to a URL (adds it to the sites tree for passive scanning)."""
    _zap("/JSON/core/action/accessUrl/", {"url": url})
    return f"ZAP accessed: {url}"


@mcp.tool()
def zap_sites() -> str:
    """List all sites currently in ZAP's sites tree."""
    data = _zap("/JSON/core/view/sites/")
    sites = data.get("sites", [])
    return "\n".join(sites) if sites else "No sites in tree yet."


@mcp.tool()
def zap_generate_report(format: str = "html", title: str = "ZAP Scan Report") -> str:
    """
    Generate a ZAP scan report and save it to ~/mcp-zap/reports/.
    format: one of 'html', 'json', 'md', 'xml', 'pdf'
    Returns the full file path of the saved report.
    """
    format = format.lower().strip()
    template_map = {
        "html": "traditional-html-plus",
        "json": "traditional-json-plus",
        "md":   "traditional-md",
        "xml":  "traditional-xml-plus",
        "pdf":  "traditional-pdf",
    }
    if format not in template_map:
        return f"Unknown format '{format}'. Choose from: html, json, md, xml, pdf"

    template = template_map[format]
    ext = format if format != "md" else "md"
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    reports_dir = Path.home() / "mcp-zap" / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    out_path = str(reports_dir / f"zap_report_{timestamp}.{ext}")

    _zap("/JSON/reports/action/generate/", {
        "title": title,
        "template": template,
        "reportFileName": f"zap_report_{timestamp}",
        "reportDir": str(reports_dir),
    })

    # Find the file (ZAP may append its own extension)
    matches = sorted(reports_dir.glob(f"zap_report_{timestamp}*"))
    if matches:
        out_path = str(matches[-1])

    return f"Report saved to: {out_path}"


@mcp.tool()
def zap_list_reports() -> str:
    """List all previously generated ZAP reports in ~/mcp-zap/reports/."""
    reports_dir = Path.home() / "mcp-zap" / "reports"
    files = sorted(reports_dir.glob("*"), reverse=True)
    if not files:
        return "No reports found in ~/mcp-zap/reports/"
    return "\n".join(str(f) for f in files)


@mcp.tool()
def zap_read_report(file_path: str) -> str:
    """Read and return the contents of a ZAP report file (best for json/md/xml formats)."""
    p = Path(file_path)
    if not p.exists():
        return f"File not found: {file_path}"
    if p.stat().st_size > 500_000:
        return f"File is too large to read directly ({p.stat().st_size} bytes). Open it in a browser instead."
    return p.read_text(errors="replace")


@mcp.tool()
def zap_create_context(name: str) -> str:
    """Create a new ZAP context with the given name. Returns the context ID."""
    data = _zap("/JSON/context/action/newContext/", {"contextName": name})
    return f"Context '{name}' created with ID: {data.get('contextId')}"


@mcp.tool()
def zap_include_in_context(context_name: str, url_pattern: str) -> str:
    """Include a URL pattern (regex) in the named context scope."""
    _zap("/JSON/context/action/includeInContext/", {
        "contextName": context_name,
        "regex": url_pattern,
    })
    return f"Included '{url_pattern}' in context '{context_name}'"


@mcp.tool()
def zap_list_contexts() -> str:
    """List all ZAP contexts."""
    data = _zap("/JSON/context/view/contextList/")
    contexts = data.get("contextList", [])
    return "\n".join(contexts) if contexts else "No contexts found."


@mcp.tool()
def zap_generate_report_for_context(context_name: str, format: str = "pdf", title: str = "") -> str:
    """
    Generate a scoped report for a specific context.
    format: one of 'html', 'json', 'md', 'xml', 'pdf'
    """
    format = format.lower().strip()
    template_map = {
        "html": "traditional-html-plus",
        "json": "traditional-json-plus",
        "md":   "traditional-md",
        "xml":  "traditional-xml-plus",
        "pdf":  "traditional-pdf",
    }
    if format not in template_map:
        return f"Unknown format '{format}'. Choose from: html, json, md, xml, pdf"

    report_title = title or f"ZAP Report — {context_name}"
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    reports_dir = Path.home() / "mcp-zap" / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    safe_name = context_name.replace("://", "_").replace("/", "_").replace(".", "_")
    filename = f"zap_{safe_name}_{timestamp}"

    _zap("/JSON/reports/action/generate/", {
        "title": report_title,
        "template": template_map[format],
        "reportFileName": filename,
        "reportDir": str(reports_dir),
        "contexts": context_name,
    })

    matches = sorted(reports_dir.glob(f"{filename}*"))
    out_path = str(matches[-1]) if matches else str(reports_dir / filename)
    return f"Report saved to: {out_path}"


# Load target URLs from ~/mcp-zap/checklist_urls.txt (one URL per line)
# If file doesn't exist, falls back to urls passed directly to the tool
def _load_checklist_urls():
    url_file = Path.home() / "mcp-zap" / "checklist_urls.txt"
    if url_file.exists():
        lines = [l.strip() for l in url_file.read_text().splitlines()]
        return [l for l in lines if l and not l.startswith("#")]
    return []


@mcp.tool()
def zap_run_weekly_checklist(urls: str = "") -> str:
    """
    Run the full weekly ZAP checklist: for each URL, create a context, spider it,
    run active scan, generate a PDF report.
    URLs are loaded from ~/mcp-zap/checklist_urls.txt (one per line).
    Optionally pass a comma-separated list of URLs to override the file.
    Returns a summary with all report paths.
    """
    if urls.strip():
        target_urls = [u.strip() for u in urls.split(",")]
    else:
        target_urls = _load_checklist_urls()
    if not target_urls:
        return "No URLs found. Add URLs to ~/mcp-zap/checklist_urls.txt (one per line) or pass them directly."
    summary = []
    reports_dir = Path.home() / "mcp-zap" / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    for url in target_urls:
        summary.append(f"\n{'='*50}")
        summary.append(f"Processing: {url}")

        # 1. Create context
        context_name = url.replace("https://", "").replace("http://", "").rstrip("/")
        context_id = None
        try:
            data = _zap("/JSON/context/action/newContext/", {"contextName": context_name})
            context_id = data.get("contextId")
        except Exception:
            pass  # context may already exist — fetch its ID below

        # If context already existed, look up its numeric ID
        if not context_id:
            try:
                info = _zap("/JSON/context/view/context/", {"contextName": context_name})
                context_id = info.get("context", {}).get("id")
            except Exception:
                pass

        # 2. Include URL in context
        pattern = url.replace(".", r"\.").rstrip("/") + ".*"
        try:
            _zap("/JSON/context/action/includeInContext/", {
                "contextName": context_name,
                "regex": pattern,
            })
        except Exception as e:
            summary.append(f"  Warning (include in context): {e}")

        # 3. Spider
        summary.append(f"  Spidering...")
        try:
            data = _zap("/JSON/spider/action/scan/", {"url": url, "contextName": context_name})
            scan_id = data["scan"]
            for _ in range(120):
                prog = _zap("/JSON/spider/view/status/", {"scanId": scan_id})
                if int(prog["status"]) >= 100:
                    break
                time.sleep(3)
            results = _zap("/JSON/spider/view/results/", {"scanId": scan_id})
            url_count = len(results.get("results", []))
            summary.append(f"  Spider done — {url_count} URLs found")
        except Exception as e:
            summary.append(f"  Spider error: {e}")

        # 4. Active scan
        summary.append(f"  Active scanning...")
        try:
            ascan_params = {"url": url}
            if context_id:
                ascan_params["contextId"] = context_id  # must be numeric ID, not name
            data = _zap("/JSON/ascan/action/scan/", ascan_params)
            scan_id = data["scan"]
            for _ in range(300):
                prog = _zap("/JSON/ascan/view/status/", {"scanId": scan_id})
                if int(prog["status"]) >= 100:
                    break
                time.sleep(6)
            alerts = _zap("/JSON/core/view/alerts/", {"baseurl": url})
            alert_count = len(alerts.get("alerts", []))
            summary.append(f"  Active scan done — {alert_count} alert(s)")
        except Exception as e:
            summary.append(f"  Active scan error: {e}")

        # 5. Generate PDF report scoped to this context
        summary.append(f"  Generating PDF report...")
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_name = context_name.replace("/", "_").replace(".", "_")
            filename = f"zap_{safe_name}_{timestamp}"
            _zap("/JSON/reports/action/generate/", {
                "title": f"ZAP Report — {context_name}",
                "template": "traditional-pdf",
                "reportFileName": filename,
                "reportDir": str(reports_dir),
                "contexts": context_name,
            })
            matches = sorted(reports_dir.glob(f"{filename}*"))
            report_path = str(matches[-1]) if matches else str(reports_dir / filename)
            summary.append(f"  Report: {report_path}")
        except Exception as e:
            summary.append(f"  Report error: {e}")

    summary.append(f"\n{'='*50}")
    summary.append(f"Weekly checklist complete. Reports saved to: {reports_dir}")
    return "\n".join(summary)


@mcp.tool()
def zap_shutdown() -> str:
    """Shut down the ZAP daemon cleanly."""
    try:
        _zap("/JSON/core/action/shutdown/")
    except Exception:
        pass
    return "ZAP shutdown requested."


if __name__ == "__main__":
    mcp.run(transport="stdio")
