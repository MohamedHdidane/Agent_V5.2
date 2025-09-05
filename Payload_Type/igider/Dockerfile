FROM itsafeaturemythic/mythic_python_base:latest

WORKDIR /Mythic/

# Install system dependencies for Nuitka
RUN apt-get update && apt-get install -y \
    g++ \
    python3-dev \
    python3-venv \
    python3-pip \
    patchelf \
    && rm -rf /var/lib/apt/lists/*

# Upgrade pip/setuptools/wheel
RUN pip3 install --upgrade pip setuptools wheel

# Install Nuitka with correct deps
RUN pip3 install nuitka ordered-set zstandard

# Install Python packages that Nuitka needs when you use --include-module/--include-package
RUN pip3 install --no-cache-dir cryptography psutil pefile

# (Optional) UPX for smaller binaries
RUN apt-get update && apt-get install -y upx-ucl && rm -rf /var/lib/apt/lists/*

# Create directory for build artifacts
RUN mkdir -p /tmp/build_cache
ENV NUITKA_CACHE_DIR=/tmp/build_cache

CMD ["python3", "main.py"]
