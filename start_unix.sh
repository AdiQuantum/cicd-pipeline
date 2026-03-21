#!/bin/bash
echo "============================================"
echo "  CI/CD Pipeline - Starting All Services"
echo "============================================"

# Load .env if it exists
[ -f .env ] && export $(cat .env | grep -v '#' | xargs)

echo "[1/5] Log Analyzer      → port 5001"
python log_analyzer.py &
sleep 2

echo "[2/5] Failure Classifier → port 8000"
uvicorn failure_classifier:app --host 0.0.0.0 --port 8000 &
sleep 2

echo "[3/5] Recovery Manager  → port 6000"
uvicorn recovery_manager:app --host 0.0.0.0 --port 6000 &
sleep 2

echo "[4/5] Notification      → port 7000"
uvicorn notification_service:app --host 0.0.0.0 --port 7000 &
sleep 2

echo "[5/5] Pipeline Controller → port 9000"
uvicorn pipeline_controller:app --host 0.0.0.0 --port 9000 &
sleep 2

echo ""
echo "All services running. Press Ctrl+C to stop all."
echo "Open http://localhost:3000 for the UI"
wait
