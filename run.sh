#!/bin/bash

# SAML-LDAP Bridge Run Script
# Convenient script to run the application with various options

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print colored output
print_color() {
    printf "${1}${2}${NC}\n"
}

print_header() {
    echo ""
    print_color $BLUE "🔗 SAML-LDAP Bridge"
    print_color $BLUE "==================="
    echo ""
}

print_usage() {
    echo "Usage: $0 [OPTION]"
    echo ""
    echo "Options:"
    echo "  setup       Run initial setup"
    echo "  run         Start the application (default)"
    echo "  demo        Run demo interface"
    echo "  test        Run tests"
    echo "  status      Show system status"
    echo "  docker      Run with Docker"
    echo "  help        Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0           # Start application"
    echo "  $0 setup     # Run setup first time"
    echo "  $0 demo      # Interactive demo"
    echo "  $0 docker    # Run with Docker"
}

check_python() {
    if ! command -v python3 &> /dev/null; then
        print_color $RED "❌ Python 3 is not installed"
        exit 1
    fi
    
    python_version=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
    required_version="3.8"
    
    if python3 -c "import sys; exit(0 if sys.version_info >= (3, 8) else 1)"; then
        print_color $GREEN "✅ Python $python_version found"
    else
        print_color $RED "❌ Python $required_version+ required, found $python_version"
        exit 1
    fi
}

check_requirements() {
    if [ ! -f "requirements.txt" ]; then
        print_color $RED "❌ requirements.txt not found"
        exit 1
    fi
    
    print_color $YELLOW "📦 Checking Python dependencies..."
    if pip3 show flask > /dev/null 2>&1; then
        print_color $GREEN "✅ Dependencies appear to be installed"
    else
        print_color $YELLOW "⚠️  Installing dependencies..."
        pip3 install -r requirements.txt
    fi
}

setup_application() {
    print_color $BLUE "🚀 Running setup..."
    check_python
    
    if [ ! -f "setup.py" ]; then
        print_color $RED "❌ setup.py not found"
        exit 1
    fi
    
    python3 setup.py
}

run_application() {
    print_color $BLUE "🌟 Starting SAML-LDAP Bridge..."
    check_python
    check_requirements
    
    if [ ! -f ".env" ]; then
        print_color $YELLOW "⚠️  .env file not found, creating from template..."
        if [ -f ".env.example" ]; then
            cp .env.example .env
            print_color $YELLOW "📝 Please edit .env file with your configuration"
        fi
    fi
    
    if [ ! -f "app.py" ]; then
        print_color $RED "❌ app.py not found"
        exit 1
    fi
    
    # Check for SSL certificates
    if [ ! -f "certs/cert.pem" ] || [ ! -f "certs/key.pem" ]; then
        print_color $YELLOW "⚠️  SSL certificates not found, application will run without HTTPS"
    fi
    
    print_color $GREEN "🚀 Starting application..."
    print_color $BLUE "   Main interface: https://localhost:5000"
    print_color $BLUE "   Demo interface: https://localhost:5000/demo"
    print_color $BLUE "   Health check:   https://localhost:5000/health"
    echo ""
    print_color $YELLOW "   Press Ctrl+C to stop"
    echo ""
    
    python3 app.py
}

run_demo() {
    print_color $BLUE "🧪 Starting Demo Interface..."
    check_python
    check_requirements
    
    if [ ! -f "demo_main.py" ]; then
        print_color $RED "❌ demo_main.py not found"
        exit 1
    fi
    
    python3 demo_main.py interactive
}

run_test() {
    print_color $BLUE "🧪 Running Tests..."
    check_python
    check_requirements
    
    # Configuration test
    if [ -f "cli.py" ]; then
        print_color $YELLOW "Testing configuration..."
        python3 cli.py test
    fi
    
    # Demo test
    if [ -f "demo_main.py" ]; then
        print_color $YELLOW "Running demo tests..."
        python3 demo_main.py auto
    fi
    
    print_color $GREEN "✅ Tests completed"
}

show_status() {
    print_color $BLUE "📊 System Status..."
    check_python
    check_requirements
    
    if [ -f "cli.py" ]; then
        python3 cli.py status
    else
        print_color $RED "❌ cli.py not found"
        exit 1
    fi
}

run_docker() {
    print_color $BLUE "🐳 Running with Docker..."
    
    if ! command -v docker &> /dev/null; then
        print_color $RED "❌ Docker is not installed"
        exit 1
    fi
    
    if ! command -v docker-compose &> /dev/null; then
        print_color $RED "❌ Docker Compose is not installed"
        exit 1
    fi
    
    if [ ! -f "docker-compose.yml" ]; then
        print_color $RED "❌ docker-compose.yml not found"
        exit 1
    fi
    
    if [ ! -f ".env" ]; then
        print_color $YELLOW "⚠️  Creating .env file..."
        if [ -f ".env.example" ]; then
            cp .env.example .env
            print_color $YELLOW "📝 Please edit .env file with your configuration"
        fi
    fi
    
    print_color $GREEN "🚀 Starting Docker containers..."
    # Rebuild to ensure container picks up local code changes (use --build)
    docker-compose up -d --build
    
    print_color $GREEN "✅ Containers started successfully"
    print_color $BLUE "   Application: https://localhost:5000"
    print_color $BLUE "   Demo:        https://localhost:5000/demo"
    echo ""
    print_color $YELLOW "   View logs:   docker-compose logs -f"
    print_color $YELLOW "   Stop:        docker-compose down"
}

# Main script logic
main() {
    print_header
    
    case "${1:-run}" in
        "setup")
            setup_application
            ;;
        "run"|"start")
            run_application
            ;;
        "demo")
            run_demo
            ;;
        "test")
            run_test
            ;;
        "status")
            show_status
            ;;
        "docker")
            run_docker
            ;;
        "help"|"--help"|"-h")
            print_usage
            ;;
        *)
            print_color $RED "❌ Unknown option: $1"
            print_usage
            exit 1
            ;;
    esac
}

# Handle Ctrl+C gracefully
trap 'echo ""; print_color $YELLOW "👋 Shutting down..."; exit 0' INT

# Run main function
main "$@"