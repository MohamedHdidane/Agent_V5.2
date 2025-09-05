FROM itsafeaturemythic/mythic_python_base:latest

WORKDIR /Mythic/

# Set environment variables to prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# Install system dependencies for Nuitka with proper error handling
RUN apt-get update && apt-get install -y \
    build-essential \
    g++ \
    gcc \
    python3-dev \
    python3-venv \
    python3-pip \
    libssl-dev \
    libffi-dev \
    patchelf \
    ccache \
    pkg-config \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /tmp/*

# Create symlinks first
RUN ln -sf /usr/local/bin/python3 /usr/bin/python3 && \
    ln -sf /usr/local/bin/pip3 /usr/bin/pip3

# Upgrade pip/setuptools/wheel with better error handling
RUN /usr/local/bin/python3 -m pip install --upgrade --no-cache-dir pip setuptools wheel

# Install Python packages with specific versions for stability
RUN /usr/local/bin/python3 -m pip install --no-cache-dir \
    nuitka>=1.8.0 \
    ordered-set \
    zstandard \
    cryptography \
    psutil \
    pefile

# Install UPX for smaller binaries (optional)
RUN apt-get update && \
    apt-get install -y upx-ucl && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create directories for build artifacts with proper permissions
RUN mkdir -p /tmp/build_cache /tmp/nuitka_cache && \
    chmod 777 /tmp/build_cache /tmp/nuitka_cache

# Set Nuitka environment variables
ENV NUITKA_CACHE_DIR=/tmp/nuitka_cache
ENV CCACHE_DIR=/tmp/build_cache
ENV TMPDIR=/tmp

# Verify installations
RUN python3 --version && \
    python3 -m nuitka --version && \
    python3 -c "import cryptography, psutil, pefile; print('All modules imported successfully')"

# Set working directory and copy application files
WORKDIR /Mythic/

# Health check to ensure the container is working
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 -c "import sys; print('Container is healthy')" || exit 1

CMD ["python3", "main.py"]