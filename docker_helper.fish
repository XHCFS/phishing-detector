#!/usr/bin/env fish
# Docker helper script for phishing detector (Fish shell version)
# Usage: ./docker_helper.fish [command]

set IMAGE_NAME "python_zinad"
set CONTAINER_NAME "phishing_detector"

function show_help
    echo "🐳 Docker Helper for Phishing Detector"
    echo ""
    echo "Usage: ./docker_helper.fish [command]"
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
    echo "  ./docker_helper.fish build       # Build image"
    echo "  ./docker_helper.fish setup       # Setup database"
    echo "  ./docker_helper.fish run         # Interactive shell"
    echo "  ./docker_helper.fish dashboard   # Run dashboard"
end

function build_image
    echo "🔨 Building Docker image: $IMAGE_NAME"
    docker build -t $IMAGE_NAME .
end

function run_interactive
    echo "🚀 Running interactive container..."
    echo "   📁 Database: app/database (mounted from host)"
    echo "   🌐 Ports: 8501 (dashboard), 8000 (api)"
    echo ""
    docker run -it --rm \
        --name $CONTAINER_NAME \
        -p 8501:8501 \
        -p 8000:8000 \
        -v (pwd)/app/database:/app/app/database \
        $IMAGE_NAME bash
end

function cleanup
    echo "🧹 Cleaning up Docker resources..."
    docker container prune -f
    docker image prune -f
    echo "✅ Cleanup complete"
end

function run_dashboard
    echo "📊 Starting dashboard on http://localhost:8501"
    docker run -it --rm \
        -p 8501:8501 \
        -v (pwd)/app/database:/app/app/database \
        $IMAGE_NAME python3 run.py dashboard --host 0.0.0.0
end

function run_setup
    echo "⚙️  Running database setup..."
    echo "   📁 Database will be saved to: app/database/"
    echo ""
    docker run --rm \
        -v (pwd)/app/database:/app/app/database \
        $IMAGE_NAME python3 run.py setup --fast
    
    if test $status -eq 0
        echo ""
        echo "✅ Setup complete! Database saved to host at:"
        echo "   - app/database/threat_feeds.db"
        echo "   - app/database/threat_feeds_raw.db"
    end
end

# Main script
if test (count $argv) -eq 0
    show_help
    exit 0
end

switch $argv[1]
    case build
        build_image
    case run
        run_interactive
    case clean
        cleanup
    case dashboard
        run_dashboard
    case setup
        run_setup
    case help
        show_help
    case '*'
        echo "❌ Unknown command: $argv[1]"
        echo ""
        show_help
        exit 1
end
