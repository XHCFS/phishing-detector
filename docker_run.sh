#!/bin/bash
set -e

# Build Docker image and run with database persistence
IMAGE_NAME="python_zinad"
PORT=${PORT:-8501}

echo "🔨 Building Docker image..."
docker build -t "$IMAGE_NAME" .

echo ""
echo "🚀 Starting container with database persistence..."
echo "   📁 Database directory: app/database (mounted from host)"
echo "   🌐 Dashboard port: $PORT"
echo ""

docker run -it --rm \
    --name "$IMAGE_NAME" \
    -v "$(pwd)/app/database:/app/app/database" \
    -p "$PORT:$PORT" \
    -p 8000:8000 \
    "$IMAGE_NAME" bash
