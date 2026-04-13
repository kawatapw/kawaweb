FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1
# Set UV environment variables for virtual environment
ENV UV_PROJECT_ENVIRONMENT=/srv/root/.venv
ENV PATH="/srv/root/.venv/bin:$PATH"

WORKDIR /srv/root

RUN apt update && apt install --no-install-recommends -y \
    git curl build-essential \
    nginx \
    && rm -rf /var/lib/apt/lists/* 

# Install uv
RUN pip install --no-cache-dir uv

# Copy pyproject.toml and uv.lock for better layer caching
COPY pyproject.toml ./
COPY uv.lock ./

# Create and use a virtual environment inside the container
RUN uv venv /srv/root/.venv && \
    uv pip install --no-cache-dir -r pyproject.toml

# Copy your service files to the appropriate location
COPY . .

ENTRYPOINT [ "scripts/start_server.sh" ]
