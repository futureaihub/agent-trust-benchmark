#!/usr/bin/env bash
set -euo pipefail

OPA_VERSION="1.19.0"
OPA_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OPA_BIN="${OPA_DIR}/opa"

# Detect OS and architecture
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
    Linux)  PLATFORM="linux" ;;
    Darwin) PLATFORM="darwin" ;;
    *)      echo "ERROR: Unsupported OS: $OS"; exit 1 ;;
esac

case "$ARCH" in
    x86_64|amd64) ARCH_NORM="amd64" ;;
    arm64|aarch64) ARCH_NORM="arm64" ;;
    *)            echo "ERROR: Unsupported architecture: $ARCH"; exit 1 ;;
esac

FILENAME="opa_${PLATFORM}_${ARCH_NORM}_static"
URL="https://openpolicyagent.org/downloads/v${OPA_VERSION}/${FILENAME}"

echo "OPA Setup"
echo "  Version:  ${OPA_VERSION}"
echo "  Platform: ${PLATFORM}/${ARCH_NORM}"
echo "  URL:      ${URL}"
echo ""

# Skip download if binary already exists with correct version
if [ -x "$OPA_BIN" ]; then
    EXISTING_VERSION=$("$OPA_BIN" version 2>/dev/null | head -1 | awk '{print $2}' || true)
    if [ "$EXISTING_VERSION" = "$OPA_VERSION" ]; then
        echo "OPA v${OPA_VERSION} already present at ${OPA_BIN}"
        exit 0
    fi
    echo "Found OPA v${EXISTING_VERSION}, upgrading to v${OPA_VERSION}..."
fi

echo "Downloading OPA v${OPA_VERSION}..."
if command -v curl &>/dev/null; then
    curl -fsSL -o "$OPA_BIN" "$URL"
elif command -v wget &>/dev/null; then
    wget -q -O "$OPA_BIN" "$URL"
else
    echo "ERROR: Neither curl nor wget found. Install one and retry."
    exit 1
fi

chmod +x "$OPA_BIN"

# Verify
if "$OPA_BIN" version &>/dev/null; then
    echo "OPA v${OPA_VERSION} installed successfully at ${OPA_BIN}"
else
    echo "ERROR: Downloaded binary failed verification."
    rm -f "$OPA_BIN"
    exit 1
fi
