FROM itsafeaturemythic/mythic_python_base:latest

WORKDIR /Mythic/

# Install Nuitka and dependencies for Linux builds
RUN apt-get update && apt-get install -y \
    g++ \
    python3-dev \
    python3-venv \
    python3-pip \
    && pip3 install --upgrade pip setuptools wheel \
    && pip3 install nuitka orderedset zstandard

# (Optional) install UPX for binary compression
RUN apt-get update && apt-get install -y upx-ucl && rm -rf /var/lib/apt/lists/*

# Create directory for build artifacts
RUN mkdir -p /tmp/build_cache

# Nuitka caches compiled C files; point it to tmp
ENV NUITKA_CACHE_DIR=/tmp/build_cache

CMD ["python3", "main.py"]
