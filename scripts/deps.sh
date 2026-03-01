#!/bin/bash

# Minimal installation script for Linux kernel development on Ubuntu
# Installs essential tools for building kernel modules and full kernels.
# Run as non-root; uses sudo where needed.

set -euo pipefail  # Exit on error, undefined vars, pipe failures

echo "Updating package lists..."
sudo apt-get update

echo "Installing minimal kernel dev tools..."
sudo apt-get install -y \
    build-essential \
    linux-headers-$(uname -r) \
    flex \
    libssl-dev \
    bc \
    bison \
    git \
    ccache \
    indent \
    libelf-dev

echo "Kernel development environment ready!"