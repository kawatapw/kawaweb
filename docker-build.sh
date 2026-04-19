#!/bin/bash
set -e

# Build the Docker image using uv
docker build -t kawaweb .

echo "Build completed successfully!"
echo "You can run the container with: docker-compose up -d"
