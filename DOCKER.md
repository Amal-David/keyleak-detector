# Docker Deployment Guide

This guide covers running KeyLeak Detector using Docker.

## 🐳 Quick Start

### Using Docker Compose (Recommended)

```bash
# Build and start the container
docker compose up -d

# View logs
docker compose logs -f

# Stop the container
docker compose down
```

The application will be available at **http://localhost:5002**

---

### Using Docker CLI

```bash
# Build the image
docker build -t keyleak-detector .

# Run the container
docker run -d \
  --name keyleak-detector \
  -p 5002:5002 \
  --restart unless-stopped \
  keyleak-detector

# View logs
docker logs -f keyleak-detector

# Stop and remove
docker stop keyleak-detector
docker rm keyleak-detector
```

---

## 📋 Prerequisites

- Docker 20.10+
- Docker Compose 2.0+ (for docker compose.yml)
- 2GB RAM minimum
- 5GB disk space for image

---

## 🔧 Configuration

### Environment Variables

You can customize the application using environment variables:

```yaml
# docker compose.yml
environment:
  - PORT=5002                    # Application port
  - PYTHONUNBUFFERED=1           # Python output buffering
```

### Port Mapping

Change the exposed port by modifying `compose.yml`:

```yaml
ports:
  - "8080:5002"  # Access on localhost:8080
```

---

## 🎯 Resource Limits

Default resource limits (adjust in `compose.yml`):

```yaml
deploy:
  resources:
    limits:
      cpus: '2'      # Maximum CPU cores
      memory: 2G     # Maximum RAM
    reservations:
      cpus: '0.5'    # Minimum CPU
      memory: 512M   # Minimum RAM
```

**Recommended for production:**
- CPU: 2-4 cores
- RAM: 2-4GB
- Disk: 10GB

---

## 📊 Monitoring

### Health Checks

The container includes automatic health checks:

```bash
# Check container health
docker inspect --format='{{.State.Health.Status}}' keyleak-detector

# View health check logs
docker inspect keyleak-detector | jq '.[0].State.Health'
```

### View Logs

```bash
# Follow logs
docker compose logs -f

# Last 100 lines
docker compose logs --tail=100

# Specific service logs
docker compose logs keyleak-detector
```

### Resource Usage

```bash
# Real-time stats
docker stats keyleak-detector

# One-time stats
docker stats --no-stream keyleak-detector
```

---

## 🔐 Security Considerations

### Running as Non-Root (Production)

For production, add a non-root user to the Dockerfile:

```dockerfile
# Add after WORKDIR /app
RUN useradd -m -u 1000 appuser && \
    chown -R appuser:appuser /app
USER appuser
```

### Network Isolation

Run in a custom network for better isolation:

```bash
# Create network
docker network create keyleak-net

# Run container in network
docker run -d \
  --name keyleak-detector \
  --network keyleak-net \
  -p 5002:5002 \
  keyleak-detector
```

### Read-Only Filesystem

Add to `docker compose.yml` for extra security:

```yaml
read_only: true
tmpfs:
  - /tmp
  - /app/logs
```

---

## 🚀 Production Deployment

### Using Docker Swarm

```bash
# Initialize swarm
docker swarm init

# Deploy stack
docker stack deploy -c docker compose.yml keyleak

# List services
docker stack services keyleak

# Remove stack
docker stack rm keyleak
```

### Using Kubernetes

See `k8s/` directory for Kubernetes manifests (if available).

---

## 🔄 Updates and Maintenance

### Rebuild After Code Changes

```bash
# Rebuild and restart
docker compose up -d --build

# Force rebuild without cache
docker compose build --no-cache
docker compose up -d
```

### Backup and Restore

```bash
# Backup logs
docker cp keyleak-detector:/app/logs ./backup-logs

# Export image
docker save keyleak-detector > keyleak-detector.tar

# Import image
docker load < keyleak-detector.tar
```

### Clean Up

```bash
# Remove stopped containers
docker compose down

# Remove with volumes
docker compose down -v

# Clean up unused images
docker image prune -a
```

---

## 🐛 Troubleshooting

### Container Won't Start

```bash
# Check logs for errors
docker compose logs

# Inspect container
docker inspect keyleak-detector

# Check resource usage
docker stats
```

### Port Already in Use

```bash
# Find process using port 5002
lsof -i :5002

# Or change port in docker compose.yml
ports:
  - "5003:5002"
```

### Playwright Issues

If Playwright fails to start:

```bash
# Rebuild with --no-cache
docker compose build --no-cache

# Check Playwright installation
docker compose exec keyleak-detector playwright --version
```

### Memory Issues

If container is killed due to OOM:

```bash
# Increase memory limit in docker compose.yml
deploy:
  resources:
    limits:
      memory: 4G
```

---

## 📦 Image Size Optimization

Current image size: ~1.5GB (due to Chromium browser)

To reduce size:
1. Use multi-stage builds
2. Remove unnecessary dependencies
3. Use alpine-based images (if compatible)

---

## 🌐 Reverse Proxy Setup

### Nginx

```nginx
server {
    listen 80;
    server_name keyleak.example.com;

    location / {
        proxy_pass http://localhost:5002;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Increase timeout for long scans
        proxy_read_timeout 300s;
        proxy_connect_timeout 300s;
    }
}
```

### Caddy

```caddy
keyleak.example.com {
    reverse_proxy localhost:5002
    
    # Increase timeout for scans
    timeout 5m
}
```

---

## 📝 Docker Hub (Optional)

### Build and Push

```bash
# Tag image
docker tag keyleak-detector yourusername/keyleak-detector:latest

# Push to Docker Hub
docker push yourusername/keyleak-detector:latest

# Pull from Docker Hub
docker pull yourusername/keyleak-detector:latest
```

---

## 🔗 References

- [Docker Documentation](https://docs.docker.com/)
- [Docker Compose Documentation](https://docs.docker.com/compose/)
- [Playwright in Docker](https://playwright.dev/docs/docker)

---

## 💡 Tips

1. **First Run:** Initial build takes 3-5 minutes (downloads Chromium)
2. **Subsequent Runs:** Start in ~10 seconds using cached layers
3. **Memory:** Allocate at least 2GB for smooth operation
4. **Scanning:** Each scan takes 30-60 seconds depending on website complexity
5. **Parallel Scans:** Not recommended - run one scan at a time

---

## ✅ Verification

After starting the container, verify it's working:

```bash
# Check container is running
docker compose ps

# Check health status
docker compose ps | grep healthy

# Test the application
curl http://localhost:5002

# Run a test scan
curl -X POST http://localhost:5002/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

---

## 🆘 Support

If you encounter issues:

1. Check logs: `docker compose logs -f`
2. Verify resources: `docker stats`
3. Check health: `docker inspect keyleak-detector`
4. Open an issue: [GitHub Issues](https://github.com/Amal-David/keyleak-detector/issues)

---

**Happy Scanning!** 🔍🐳

