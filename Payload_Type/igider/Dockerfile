FROM itsafeaturemythic/mythic_python_base:latest

WORKDIR /Mythic/

# Install system dependencies for Nuitka
RUN apt-get update && apt-get install -y \
    g++ \
    python3-dev \
    python3-venv \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Upgrade pip/setuptools/wheel
RUN pip3 install --upgrade pip setuptools wheel

# Install Nuitka with correct deps (ordered-set, zstandard)
RUN pip3 install nuitka ordered-set zstandard

# (Optional) UPX for smaller binaries
RUN apt-get update && apt-get install -y upx-ucl && rm -rf /var/lib/apt/lists/*

# Create directory for build artifacts
RUN mkdir -p /tmp/build_cache
ENV NUITKA_CACHE_DIR=/tmp/build_cache

CMD ["python3", "main.py"]
