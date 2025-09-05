FROM itsafeaturemythic/mythic_python_base:latest

WORKDIR /Mythic/

# Install system dependencies for Nuitka
RUN apt-get update && apt-get install -y \
    g++ \
    python3-dev \
    python3-venv \
    python3-pip \
    libssl-dev \
    libffi-dev \
    patchelf \
    && rm -rf /var/lib/apt/lists/*

# Upgrade pip/setuptools/wheel
RUN python3 -m pip install --upgrade pip setuptools wheel

# Explicitly install Nuitka + dependencies into Python3
RUN python3 -m pip install nuitka ordered-set zstandard cryptography psutil pefile

# (Optional) UPX for smaller binaries
RUN apt-get update && apt-get install -y upx-ucl && rm -rf /var/lib/apt/lists/*

# Create directory for build artifacts
RUN mkdir -p /tmp/build_cache
ENV NUITKA_CACHE_DIR=/tmp/build_cache

CMD ["python3", "main.py"]
