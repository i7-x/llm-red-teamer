"""
Dashboard Backend — FastAPI
============================
Serves the web dashboard and exposes API routes for scan result management.
Frontend path is resolved via DASHBOARD_FRONTEND_PATH env var (set by run_dashboard.py)
or falls back to ../frontend relative to this file.

Routes:
    GET  /                      → Serve frontend HTML
    POST /api/upload            → Upload a scan JSON report
    GET  /api/scans             → List all uploaded scans
    GET  /api/scans/{scan_id}   → Get full scan detail
    GET  /api/compare           → Compare multiple scans
    GET  /api/stats             → Aggregate stats across all scans
    DELETE /api/scans/{scan_id} → Delete a scan
"""

import json
import os
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, UploadFile, File, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
import uvicorn

app = FastAPI(
    title="LLM Red Teamer Dashboard",
    description="Web dashboard for viewing and comparing LLM scan results",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory scan store (replace with SQLite for persistence)
SCANS: dict[str, dict] = {}

FRONTEND_PATH = Path(__file__).parent / "frontend"


# ── STATIC FILES ──────────────────────────────────────────────────────────────
static_path = FRONTEND_PATH / "static"
if static_path.exists():
    app.mount("/static", StaticFiles(directory=str(static_path)), name="static")


# ── FRONTEND ──────────────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def serve_frontend():
    """Serve the dashboard frontend."""
    html_path = FRONTEND_PATH / "index.html"
    if html_path.exists():
        return HTMLResponse(content=html_path.read_text(encoding="utf-8"))
    return HTMLResponse(content="<h1>Frontend not found. Check frontend/index.html</h1>", status_code=404)


# ── API ROUTES ────────────────────────────────────────────────────────────────
@app.post("/api/upload")
async def upload_scan(file: UploadFile = File(...)):
    """
    Upload a scan JSON report.

    Accepts the JSON output from `main.py scan --output scan.json`.
    Validates required fields before storing.
    """
    if not file.filename.endswith(".json"):
        raise HTTPException(status_code=400, detail="File must be a .json report")

    try:
        content = await file.read()
        data = json.loads(content)
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=400, detail=f"Invalid JSON: {e}")

    # Validate required fields
    required = ["scan_meta", "aggregate_risk", "findings"]
    missing = [f for f in required if f not in data]
    if missing:
        raise HTTPException(
            status_code=400,
            detail=f"Missing required fields: {missing}. Is this a valid LLM Red Teamer report?",
        )

    scan_id = str(uuid.uuid4())[:8]
    data["_id"] = scan_id
    data["_uploaded_at"] = datetime.utcnow().isoformat()
    data["_filename"] = file.filename

    SCANS[scan_id] = data

    return JSONResponse({
        "scan_id": scan_id,
        "message": f"Scan uploaded successfully. {len(data.get('findings', []))} findings.",
        "model": data["scan_meta"].get("model"),
        "success_rate": data["scan_meta"].get("success_rate"),
    })


@app.get("/api/scans")
async def list_scans():
    """List all uploaded scans with summary metadata."""
    scans = []
    for scan_id, data in SCANS.items():
        meta = data.get("scan_meta", {})
        agg = data.get("aggregate_risk", {})
        scans.append({
            "scan_id": scan_id,
            "filename": data.get("_filename"),
            "uploaded_at": data.get("_uploaded_at"),
            "model": meta.get("model"),
            "provider": meta.get("provider"),
            "target_url": meta.get("target_url"),
            "total_payloads": meta.get("total_payloads"),
            "successful_attacks": meta.get("successful_attacks"),
            "success_rate": meta.get("success_rate"),
            "duration_seconds": meta.get("duration_seconds"),
            "aggregate_severity": agg.get("severity"),
            "aggregate_score": agg.get("score"),
            "findings_count": len(data.get("findings", [])),
        })

    # Sort by upload time, newest first
    scans.sort(key=lambda s: s.get("uploaded_at") or "", reverse=True)
    return {"scans": scans, "total": len(scans)}


@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: str):
    """Get the full detail of a specific scan."""
    if scan_id not in SCANS:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found")
    return SCANS[scan_id]


@app.delete("/api/scans/{scan_id}")
async def delete_scan(scan_id: str):
    """Delete a scan from the store."""
    if scan_id not in SCANS:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found")
    del SCANS[scan_id]
    return {"message": f"Scan '{scan_id}' deleted"}


@app.get("/api/compare")
async def compare_scans(scan_ids: str = Query(..., description="Comma-separated scan IDs")):
    """
    Compare multiple scans side by side.
    Returns summary metrics for each scan for chart rendering.
    """
    ids = [s.strip() for s in scan_ids.split(",")]
    missing = [i for i in ids if i not in SCANS]
    if missing:
        raise HTTPException(status_code=404, detail=f"Scans not found: {missing}")

    comparison = []
    for scan_id in ids:
        data = SCANS[scan_id]
        meta = data.get("scan_meta", {})
        agg = data.get("aggregate_risk", {})
        cat_summary = data.get("category_summary", {})

        category_success_rates = {
            cat: (
                info["successful"] / info["total"]
                if info.get("total", 0) > 0 else 0.0
            )
            for cat, info in cat_summary.items()
        }

        comparison.append({
            "scan_id": scan_id,
            "model": meta.get("model"),
            "provider": meta.get("provider"),
            "success_rate": meta.get("success_rate"),
            "aggregate_score": agg.get("score"),
            "aggregate_severity": agg.get("severity"),
            "findings_count": len(data.get("findings", [])),
            "category_success_rates": category_success_rates,
        })

    return {"comparison": comparison}


@app.get("/api/stats")
async def global_stats():
    """Aggregate stats across all uploaded scans."""
    if not SCANS:
        return {"message": "No scans uploaded yet", "stats": {}}

    all_findings = []
    for data in SCANS.values():
        all_findings.extend(data.get("findings", []))

    severity_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    category_counts: dict[str, int] = {}

    for f in all_findings:
        sev = f.get("severity", "LOW")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

        cat = f.get("category", "unknown")
        category_counts[cat] = category_counts.get(cat, 0) + 1

    most_vulnerable_model = None
    highest_rate = 0.0
    for data in SCANS.values():
        rate = data.get("scan_meta", {}).get("success_rate", 0)
        if rate > highest_rate:
            highest_rate = rate
            most_vulnerable_model = data.get("scan_meta", {}).get("model")

    return {
        "stats": {
            "total_scans": len(SCANS),
            "total_findings": len(all_findings),
            "severity_breakdown": severity_counts,
            "category_breakdown": category_counts,
            "most_vulnerable_model": most_vulnerable_model,
            "highest_success_rate": highest_rate,
        }
    }


@app.get("/api/health")
async def health():
    return {"status": "ok", "scans_loaded": len(SCANS)}


if __name__ == "__main__":
    uvicorn.run("dashboard.backend.app:app", host="0.0.0.0", port=8080, reload=True)
