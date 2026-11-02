#!/usr/bin/env bash
set -euo pipefail

# fitproxy build script for Linux musl targets:
# - x86_64-unknown-linux-musl
# - aarch64-unknown-linux-musl

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST_DIR="${SCRIPT_DIR}/dist"
mkdir -p "${DIST_DIR}"

TARGETS=(
    "x86_64-unknown-linux-musl"
    "aarch64-unknown-linux-musl"
)

# Allow passing specific target as argument, e.g.: ./build.sh x86_64-unknown-linux-musl
if [ $# -gt 0 ]; then
    TARGETS=("$@")
fi

echo "==> Building fitproxy for targets: ${TARGETS[*]}"

# Check if cross is installed
BUILD_CMD="cargo"
if command -v cross &>/dev/null; then
    BUILD_CMD="cross"
    echo "Using 'cross' for cross-compilation."
else
    echo "'cross' not found, using 'cargo'. (For cross-compiling, install cross: cargo install cross)"
fi

for TARGET in "${TARGETS[@]}"; do
    echo "----------------------------------------------------"
    echo "==> Building target: ${TARGET}"
    rustup target add "${TARGET}" 2>/dev/null || true

    ${BUILD_CMD} build --release --target "${TARGET}"

    SRC_BIN="${SCRIPT_DIR}/target/${TARGET}/release/fitproxy"
    DST_BIN="${DIST_DIR}/fitproxy-${TARGET}"

    if [ -f "${SRC_BIN}" ]; then
        cp "${SRC_BIN}" "${DST_BIN}"
        chmod +x "${DST_BIN}"

        # Try to strip if appropriate strip tool exists
        if [[ "${TARGET}" == *"x86_64"* ]] && command -v strip &>/dev/null; then
            strip "${DST_BIN}" 2>/dev/null || true
        elif [[ "${TARGET}" == *"aarch64"* ]] && command -v aarch64-linux-gnu-strip &>/dev/null; then
            aarch64-linux-gnu-strip "${DST_BIN}" 2>/dev/null || true
        fi

        # Generate SHA256 checksum
        (cd "${DIST_DIR}" && sha256sum "fitproxy-${TARGET}" > "fitproxy-${TARGET}.sha256")

        echo "==> Artifact created: ${DST_BIN}"
        echo "    SHA256: $(cat "${DST_BIN}.sha256")"
    else
        echo "Error: Output binary ${SRC_BIN} not found!" >&2
        exit 1
    fi
done

echo "----------------------------------------------------"
echo "==> Build complete! Output files in ${DIST_DIR}:"
ls -la "${DIST_DIR}"
