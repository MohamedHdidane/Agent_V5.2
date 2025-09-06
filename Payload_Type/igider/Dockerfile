FROM itsafeaturemythic/mythic_python_base:latest

WORKDIR /Mythic/
RUN apt-get update 
# Install PyInstaller and dependencies for executable building
RUN pip3 install pyinstaller
RUN pip3 install --no-cache-dir \
    ordered-set \
    zstandard \
    cryptography \
    psutil \
    pefile



# Install UPX for executable compression
RUN apt-get update && apt-get install -y upx-ucl && rm -rf /var/lib/apt/lists/*

# Create directory for build artifacts
RUN mkdir -p /tmp/build_cache

# Set environment variables for PyInstaller
ENV PYINSTALLER_CACHE_DIR=/tmp/build_cache
ENV WINE_PREFIX=/root/.wine

CMD ["python3", "main.py"]