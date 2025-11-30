# Valkyrie File Security Scanner - Docker Image
#
# This Dockerfile creates a containerized version of Valkyrie for easy deployment.

FROM ubuntu:22.04

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Set labels
LABEL maintainer="Valkyrie Team"
LABEL description="Valkyrie File Security Scanner - Production Image"
LABEL version="0.2.0"

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    build-essential \
    clamav \
    clamav-daemon \
    yara \
    file \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Update ClamAV signatures
RUN freshclam

# Create app user
RUN useradd -m -s /bin/bash valkyrie

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Create virtual environment and install Python dependencies
RUN python3 -m venv /opt/valkyrie/venv && \
    /opt/valkyrie/venv/bin/pip install --upgrade pip && \
    /opt/valkyrie/venv/bin/pip install -r requirements.txt

# Copy application code
COPY valkyrie/ /app/valkyrie/
COPY watcher/ /app/watcher/
COPY gui/backend/ /app/gui/backend/
COPY yara_rules/ /app/yara_rules/
COPY config/ /app/config/

# Create necessary directories
RUN mkdir -p /app/reports /app/quarantine /app/processed /app/logs && \
    chown -R valkyrie:valkyrie /app

# Set environment variables
ENV PYTHONPATH=/app
ENV PATH="/opt/valkyrie/venv/bin:$PATH"

# Switch to non-root user
USER valkyrie

# Expose dashboard port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -m valkyrie.cli status || exit 1

# Default command - start dashboard
CMD ["python", "gui/backend/app.py"]
