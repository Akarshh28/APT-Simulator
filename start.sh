#!/bin/bash
# APT Simulator - Render Deployment Entrypoint
# Runs HES and MDMS in the background, and Detector in the foreground

# Ensure data directories exist
mkdir -p data/baseline

# Start HES on port 8001 (internal)
uvicorn hes.main:app --host 127.0.0.1 --port 8001 &

# Start MDMS on port 8002 (internal)
uvicorn mdms.main:app --host 127.0.0.1 --port 8002 &

# Wait a couple of seconds for services to initialize
sleep 2

# Start Detector on the public PORT exposed by Render (defaults to 8003 if not set)
# We use exec so that the detector process replaces the shell and handles SIGTERM
PORT=${PORT:-8003}
exec uvicorn detector.main:app --host 0.0.0.0 --port $PORT
