#!/usr/bin/env bash

IMAGE_NAME="python_zinad"
CONTAINER_NAME="phishing_detector"

show_help() {
    echo "🐳 Docker Helper for Phishing Detector"
    echo ""
    echo "Usage: ./docker_helper.sh [command]"
    echo ""
    echo "Commands:"
    echo "  build          Build the Docker image"
    echo "  run            Run interactive container (databases saved to host)"
    echo "  setup          Setup database (saved to host)"
    echo "  dashboard      Run dashboard on port 8501"
    echo "  clean          Remove stopped containers and dangling images"
    echo "  help           Show this help"
    echo ""
    echo "Note: All commands mount app/database to persist data on host"
    echo ""
    echo "Examples:"
    echo "  ./docker_helper.sh build       # Build image"
    echo "  ./docker_helper.sh setup       # Setup database"
    echo "  ./docker_helper.sh run         # Interactive shell"
    echo "  ./docker_helper.sh dashboard   # Run dashboard"
}

build_image() {
    echo "🔨 Building Docker image: $IMAGE_NAME"
    docker build -t "$IMAGE_NAME" .
}

run_interactive() {
    echo "🚀 Running interactive container..."
    echo "   📁 Database: app/database (mounted from host)"
    echo "   🌐 Ports: 8501 (dashboard), 8000 (api)"
    echo ""
    docker run -it --rm \
        --name "$CONTAINER_NAME" \
        -p 8501:8501 \
        -p 8000:8000 \
        -v "$(pwd)/app/database:/app/app/database" \
        "$IMAGE_NAME" bash
}

cleanup() {
    echo "🧹 Cleaning up Docker resources..."
    docker container prune -f
    docker image prune -f
    echo "✅ Cleanup complete"
}

run_dashboard() {
    echo "📊 Starting dashboard on http://localhost:8501"
    docker run -it --rm \
        -p 8501:8501 \
        -v "$(pwd)/app/database:/app/app/database" \
        "$IMAGE_NAME" python3 run.py dashboard --host 0.0.0.0
}

run_setup() {
    echo "⚙️  Running database setup..."
    echo "   📁 Database will be saved to: app/database/"
    echo ""
    docker run --rm \
        -v "$(pwd)/app/database:/app/app/database" \
        "$IMAGE_NAME" python3 run.py setup --fast
    
    if [ $? -eq 0 ]; then
        echo ""
        echo "✅ Setup complete! Database saved to host at:"
        echo "   - app/database/threat_feeds.db"
        echo "   - app/database/threat_feeds_raw.db"
    fi
}

if [ $# -eq 0 ]; then
    show_help
    exit 0
fi

case "$1" in
    build)
        build_image
        ;;
    run)
        run_interactive
        ;;
    clean)
        cleanup
        ;;
    dashboard)
        run_dashboard
        ;;
    setup)
        run_setup
        ;;
    help)
        show_help
        ;;
    *)
        echo "❌ Unknown command: $1"
        echo ""
        show_help
        exit 1
        ;;
esac
