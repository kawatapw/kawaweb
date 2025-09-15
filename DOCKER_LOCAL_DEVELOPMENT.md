# 🐳 KawaWeb Local Docker Development Environment

This guide helps you set up a complete local Docker development environment for KawaWeb that runs on different ports to avoid conflicts with your existing local development setup.

## 📋 Prerequisites

- **Docker Desktop** installed and running
- **Git** for version control
- **Basic terminal/command line knowledge**

## 🚀 Quick Start

### 1. Start the Complete Environment

```bash
./start_docker_local.sh
```

This will:
- Build the KawaWeb application container
- Start MySQL database (port 3307)
- Start Redis cache (port 6380)
- Start the web application (port 8002)
- Show connection information and useful commands

### 2. Access Your Application

- **Web Application**: http://localhost:8002
- **Default Login**: admin / admin123

## 🛠️ Docker Utilities

Use the `docker_utils.sh` script for common operations:

```bash
# Start services
./docker_utils.sh start

# Stop services
./docker_utils.sh stop

# View logs
./docker_utils.sh logs

# View web application logs only
./docker_utils.sh logs-web

# Open shell in web container
./docker_utils.sh shell

# Connect to MySQL database
./docker_utils.sh mysql

# Connect to Redis
./docker_utils.sh redis

# Show service status
./docker_utils.sh status

# Rebuild everything
./docker_utils.sh rebuild

# Clean up (removes data)
./docker_utils.sh clean

# Complete reset
./docker_utils.sh reset

# Import database schema
./docker_utils.sh import-db

# Backup database
./docker_utils.sh backup-db

# Show help
./docker_utils.sh help
```

## 📊 Service Information

### Ports (Different from your local development)
- **Web Application**: 8002 (instead of 8001)
- **MySQL Database**: 3307 (instead of 3306)
- **Redis Cache**: 6380 (instead of 6379)

### Container Names
- **Web App**: `kawaweb-app-local`
- **MySQL**: `kawaweb-mysql-local`
- **Redis**: `kawaweb-redis-local`

### Docker Network
- **Network Name**: `kawaweb-local-network`

## 🗄️ Database Management

### Import Database Schema
If you have a `kawata_Prod_Gulag.sql` file:
```bash
./docker_utils.sh import-db
```

### Manual Database Import
```bash
docker exec -i kawaweb-mysql-local mysql -u kawata -pkawata_password kawata < your_schema.sql
```

### Backup Database
```bash
./docker_utils.sh backup-db
```

### Connect to Database
```bash
./docker_utils.sh mysql
```

## 🔍 Debugging and Development

### View Application Logs
```bash
# All services
./docker_utils.sh logs

# Web application only
./docker_utils.sh logs-web

# Database only
./docker_utils.sh logs-db
```

### Access Container Shell
```bash
./docker_utils.sh shell
```

### Docker Desktop Integration
- Open Docker Desktop to see all containers
- Use the GUI to view logs, stats, and manage containers
- Inspect container details and environment variables

## 🔧 Configuration Files

### Local Docker Files (Added to .gitignore)
- `docker-compose.local.yml` - Docker Compose configuration
- `Dockerfile.local` - Local development Dockerfile
- `.env.docker.local` - Environment variables for Docker
- `start_docker_local.sh` - Startup script
- `docker_utils.sh` - Utility commands
- `DOCKER_LOCAL_DEVELOPMENT.md` - This documentation

### Environment Variables
The Docker environment uses different settings optimized for containerized development:
- Database host: `mysql` (Docker service name)
- Redis host: `redis` (Docker service name)
- Debug mode: Enabled
- Port: 8002 (external), 8001 (internal)

## 🚨 Troubleshooting

### Services Won't Start
```bash
# Check Docker is running
docker info

# Check for port conflicts
lsof -i :8002
lsof -i :3307
lsof -i :6380

# View detailed logs
./docker_utils.sh logs
```

### Database Connection Issues
```bash
# Check MySQL container
docker logs kawaweb-mysql-local

# Test database connection
./docker_utils.sh mysql
```

### Application Not Loading
```bash
# Check web container logs
./docker_utils.sh logs-web

# Restart web service
docker-compose -f docker-compose.local.yml restart web
```

### Clean Start
```bash
# Stop everything and start fresh
./docker_utils.sh stop
./docker_utils.sh start
```

### Complete Reset
```bash
# Remove everything and start over
./docker_utils.sh reset
./start_docker_local.sh
```

## 📁 File Structure

```
kawaweb-v2/
├── docker-compose.local.yml    # Local Docker Compose config
├── Dockerfile.local            # Local development Dockerfile
├── .env.docker.local          # Docker environment variables
├── start_docker_local.sh      # Main startup script
├── docker_utils.sh            # Utility commands
├── DOCKER_LOCAL_DEVELOPMENT.md # This documentation
└── ... (original project files)
```

## 🔒 Security Notes

- This setup is for **local development only**
- Uses default passwords and keys (change for production)
- Runs on different ports to avoid conflicts
- All local Docker files are in `.gitignore`

## 🎯 Benefits of This Setup

1. **Isolated Environment**: Runs separately from your local development
2. **Production-like**: Mirrors the production Docker environment
3. **Easy Debugging**: Full Docker Desktop integration
4. **No Conflicts**: Uses different ports than local development
5. **Preserves Original**: Doesn't modify original Docker files
6. **Complete Stack**: Includes MySQL, Redis, and web application
7. **Easy Management**: Simple scripts for common operations

## 🤝 Contributing

This local Docker setup is designed to help you understand and debug the KawaWeb application without affecting the original project files. All local Docker configurations are ignored by Git to keep your changes separate.

Happy coding! 🚀
