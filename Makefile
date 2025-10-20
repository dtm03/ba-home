# SAML-LDAP Bridge Makefile
# Quick commands for development and deployment

.PHONY: help install dev run test clean docker-build docker-run docker-stop setup status

help:  ## Show this help message
	@echo "SAML-LDAP Bridge - Available Commands"
	@echo "===================================="
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

install: ## Install Python dependencies
	pip install -r requirements.txt
	@echo "✅ Dependencies installed"

setup: ## Run initial setup
	python setup.py
	@echo "✅ Setup completed"

dev: ## Install development dependencies and setup
	pip install -r requirements.txt
	python setup.py
	@echo "✅ Development environment ready"

run: ## Run the application
	python app.py

run-demo: ## Run demo interface only
	python demo_main.py interactive

test: ## Run tests and configuration check
	python cli.py test
	python demo_main.py auto

status: ## Show system status
	python cli.py status

clean: ## Clean up temporary files and logs
	rm -rf __pycache__/
	rm -rf *.pyc
	rm -rf .pytest_cache/
	rm -rf logs/*.log
	@echo "✅ Cleanup completed"

# Docker commands
docker-build: ## Build Docker image
	docker build -t saml-ldap-bridge .
	@echo "✅ Docker image built"

docker-run: ## Run with Docker
	docker-compose up -d
	@echo "✅ Docker containers started"

docker-stop: ## Stop Docker containers
	docker-compose down
	@echo "✅ Docker containers stopped"

docker-logs: ## Show Docker logs
	docker-compose logs -f

docker-demo: ## Run with demo LDAP server
	docker-compose --profile demo up -d
	@echo "✅ Docker with demo LDAP started"

# SSL certificate management
ssl-certs: ## Generate SSL certificates
	mkdir -p certs
	openssl genrsa -out certs/key.pem 2048
	openssl req -new -x509 -key certs/key.pem -out certs/cert.pem -days 365 -subj '/CN=localhost'
	@echo "✅ SSL certificates generated"

# Environment management
env: ## Create .env file from template
	cp .env.example .env
	@echo "✅ .env file created - please edit with your configuration"

# Credential management
list-creds: ## List active credentials
	python cli.py list

cleanup-creds: ## Clean up expired credentials
	python cli.py cleanup

# Configuration export
export-config: ## Export current configuration
	python cli.py config

# Health checks
health: ## Check application health
	curl -f http://localhost:5000/health || echo "❌ Health check failed"

# Full deployment workflow
deploy: env ssl-certs install docker-build docker-run ## Complete deployment setup
	@echo "✅ Deployment completed"
	@echo "🌐 Application available at: https://localhost:5000"
	@echo "🧪 Demo interface at: https://localhost:5000/demo"

# Development workflow  
dev-setup: dev env ssl-certs ## Complete development setup
	@echo "✅ Development setup completed"
	@echo "🚀 Start development with: make run"

# Production checks
prod-check: ## Check production readiness
	@echo "🔍 Production Readiness Check"
	@echo "============================="
	@if [ -f ".env" ]; then echo "✅ .env file exists"; else echo "❌ .env file missing"; fi
	@if [ -f "certs/cert.pem" ] && [ -f "certs/key.pem" ]; then echo "✅ SSL certificates present"; else echo "❌ SSL certificates missing"; fi
	@python cli.py test
	@echo ""
	@echo "⚠️  Production Checklist:"
	@echo "   - Review .env configuration"  
	@echo "   - Use proper SSL certificates"
	@echo "   - Configure firewall rules"
	@echo "   - Set up monitoring"
	@echo "   - Review security settings"