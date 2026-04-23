#!/usr/bin/env python3
"""
Dashboard Launcher
==================
Starts the LLM Red Teamer web dashboard.

Usage:
    python run_dashboard.py
    python run_dashboard.py --port 8080 --host 0.0.0.0

Then open: http://localhost:8080
"""

import sys
import os
import argparse
import shutil

sys.path.insert(0, os.path.dirname(__file__))


def main():
    parser = argparse.ArgumentParser(description="Start LLM Red Teamer Dashboard")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8080, help="Port to bind (default: 8080)")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload (development)")
    args = parser.parse_args()

    # Copy frontend files into the backend's serving path
    src_frontend = os.path.join(os.path.dirname(__file__), "dashboard", "frontend")
    dst_frontend = os.path.join(os.path.dirname(__file__), "dashboard", "backend", "frontend")

    if os.path.exists(src_frontend):
        if os.path.exists(dst_frontend):
            shutil.rmtree(dst_frontend)
        shutil.copytree(src_frontend, dst_frontend)

    try:
        import uvicorn
    except ImportError:
        print("Error: uvicorn not installed. Run: pip install uvicorn")
        sys.exit(1)

    # Override frontend path in the app to use absolute paths
    os.environ["DASHBOARD_FRONTEND_PATH"] = src_frontend

    print(f"\n⚡ LLM Red Teamer Dashboard")
    print(f"   → http://{args.host}:{args.port}\n")

    uvicorn.run(
        "dashboard.backend.app:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
    )


if __name__ == "__main__":
    main()
