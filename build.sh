#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

DIST_DIR="$SCRIPT_DIR/dist"
PUSH_DIR="$SCRIPT_DIR/target/push"
BIN_NAME="lgz_compress"

TARGET_X64="x86_64-unknown-linux-musl"
TARGET_X86="i686-unknown-linux-musl"
TARGET_ARM64="aarch64-unknown-linux-musl"
TARGET_ARM32="armv7-unknown-linux-musleabihf"
# Windows (lean/unpack-only flavor; MinGW for x64, llvm-mingw for ARM64 —
# distro mingw has no aarch64 Windows linker, same as bootsmasher).
WIN_X64="x86_64-pc-windows-gnu"
WIN_ARM64="aarch64-pc-windows-gnullvm"
# macOS (full + lean universal binaries via cargo-zigbuild on Linux,
# plain cargo on a Mac).
MAC_X64="x86_64-apple-darwin"
MAC_ARM64="aarch64-apple-darwin"

# llvm-mingw (mstorsjo) provides the only native aarch64 Windows linker.
LLVM_MINGW_CLANG="/opt/llvm-mingw/bin/aarch64-w64-mingw32-clang"

ALL_TARGETS=("$TARGET_X64" "$TARGET_X86" "$TARGET_ARM64" "$TARGET_ARM32")

# Default parameters
METHOD="auto"         # auto | cargo | cross
SELECTED_ARCH="all"   # all | x64 | x86 | arm64 | arm32 | windows | win64 | winarm64 | mac | mac64 | macarm64

usage() {
    cat <<EOF
Usage:
  $0 [OPTIONS]

Build method options:
  --cargo          Force local cargo (requires system gcc linkers)
  --cross          Force cross (requires Docker or Podman)
  --auto           Auto-select: cross (if containers available), else cargo (default)

Architecture selection:
  --arch <type>    Build a specific architecture:
                     all   - All 4 Linux platforms (default)
                     x64   - x86_64-unknown-linux-musl
                     x86   - i686-unknown-linux-musl
                     arm64 - aarch64-unknown-linux-musl
                     arm32 - armv7-unknown-linux-musleabihf
                     windows  - both Windows lean (unpack-only) .exe
                              (x64 gnu + ARM64 gnullvm)
                     win64    - lean x86_64-pc-windows-gnu .exe
                     winarm64 - lean aarch64-pc-windows-gnullvm .exe
                     mac      - macOS full + lean universal binaries
                              (fat x86_64+arm64, like fastboot)
                     mac64    - macOS x86_64 slices (full + lean)
                     macarm64 - macOS arm64 slices (full + lean)
  -h, --help       Show this message

  Windows/macOS notes:
    Windows ships lean (decompress-only) builds only; win64 needs
    mingw-w64, winarm64 links with llvm-mingw from /opt/llvm-mingw.
    macOS cross from Linux needs cargo-zigbuild + zig (on a Mac plain
    cargo is enough); the fat binary is glued with llvm-lipo (Linux)
    or lipo (Xcode).

Examples:
  $0 --cargo --arch x64
  $0 --cross --arch arm64
  $0 --arch all

Outputs:
  dist/                      Static binaries lgz_compress-linux-*
                             (full build: compress + pack + unpack)
                             Windows lean .exe: lgz_compress-windows-*.exe
                             (decompress-only; no push copies for Windows)
                             macOS: lgz_compress-macos-* slices plus
                             lgz_compress-macos-universal and
                             lgz_compress-lean-macos-universal
                             (fat x86_64+arm64)
  target/push/               8 push-ready copies, both flavors per arch:
                             {name}_full_{x64,x86,arm64,arm32} (full),
                             {name}_lean_{x64,x86,arm64,arm32}
                             (decompress-only: unpack/inspect for ramdisk),
                             e.g. for: adb push
                             target/push/lgz_compress_lean_arm64 /data/local/
EOF
    exit 0
}

# CLI argument parsing
while [[ $# -gt 0 ]]; do
    case "$1" in
        --cargo)
            METHOD="cargo"
            shift
            ;;
        --cross)
            METHOD="cross"
            shift
            ;;
        --auto)
            METHOD="auto"
            shift
            ;;
        --arch)
            SELECTED_ARCH="${2:-}"
            if [[ -z "$SELECTED_ARCH" ]]; then
                echo "Error: --arch requires an architecture argument"
                exit 1
            fi
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Unknown parameter: $1"
            usage
            ;;
    esac
done

# Detect distro package manager
detect_pkg_manager() {
    if command -v apt-get &>/dev/null; then
        echo "apt"
    elif command -v dnf &>/dev/null; then
        echo "dnf"
    elif command -v pacman &>/dev/null; then
        echo "pacman"
    else
        echo "unknown"
    fi
}

# Install recommendations
suggest_install() {
    local missing_type="$1"
    local pm
    pm="$(detect_pkg_manager)"

    echo ""
    echo "============================================================"
    echo "Warning: missing required dependencies!"
    echo "============================================================"

    if [[ "$missing_type" == "container" ]]; then
        echo "Building with '--cross' requires Podman or Docker."
        echo "Recommended install command:"
        case "$pm" in
            apt)    echo "  sudo apt update && sudo apt install -y podman" ;;
            dnf)    echo "  sudo dnf install -y podman" ;;
            pacman) echo "  sudo pacman -S --needed podman" ;;
            *)      echo "  Install Podman or Docker with your package manager." ;;
        esac
        echo ""
        echo "Also make sure cross is installed: cargo install cross --git https://github.com/cross-rs/cross"
    elif [[ "$missing_type" == "cargo-tools" ]]; then
        echo "Building with '--cargo' requires cross linkers and musl toolchains."
        echo "Recommended install command:"
        case "$pm" in
            apt)
                echo "  sudo apt update && sudo apt install -y musl-tools gcc-i686-linux-gnu gcc-aarch64-linux-gnu gcc-arm-linux-gnueabihf"
                ;;
            dnf)
                echo "  sudo dnf install -y musl-gcc gcc-arm-linux-gnu gcc-aarch64-linux-gnu"
                ;;
            pacman)
                echo "  sudo pacman -S --needed musl aarch64-linux-gnu-gcc arm-linux-gnueabihf-gcc lib32-glibc"
                ;;
            *)
                echo "  Install cross compilers for x86, aarch64, armv7 and musl-tools."
                ;;
        esac
    fi
    echo "Windows x86_64 also needs: mingw-w64 (rustup target add $WIN_X64)"
    echo "Windows ARM64 links via llvm-mingw (mstorsjo), not distro mingw:"
    echo "  curl -LO https://github.com/mstorsjo/llvm-mingw/releases/download/20240619/llvm-mingw-20240619-ucrt-ubuntu-20.04-x86_64.tar.xz"
    echo "  sudo tar -xf llvm-mingw-20240619-ucrt-ubuntu-20.04-x86_64.tar.xz -C /opt/ && sudo mv /opt/llvm-mingw-20240619-ucrt-ubuntu-20.04-x86_64 /opt/llvm-mingw"
    echo "macOS cross from Linux needs: cargo-zigbuild + zig (pip install ziglang), llvm-lipo for the fat binary"
    echo "============================================================"
    echo ""
}

# Container engine check
has_container_engine() {
    command -v podman &>/dev/null || (command -v docker &>/dev/null && docker info &>/dev/null)
}

# Linker check for cargo builds
check_cargo_linker() {
    local target="$1"
    local linker=""

    case "$target" in
        "$TARGET_X86")
            linker="i686-linux-gnu-gcc"
            ;;
        "$TARGET_ARM64")
            linker="aarch64-linux-gnu-gcc"
            ;;
        "$TARGET_ARM32")
            linker="arm-linux-gnueabihf-gcc"
            ;;
        "$TARGET_X64")
            return 0
            ;;
    esac

    if ! command -v "$linker" &>/dev/null; then
        echo "Error: cross linker '$linker' for $target not found!"
        suggest_install "cargo-tools"
        return 1
    fi
    return 0
}

# Graceful skip for optional (Windows/macOS) targets: a missing
# toolchain skips the target instead of failing the whole run.
check_opt_linker() {
    case "$1" in
        "$WIN_X64")
            command -v x86_64-w64-mingw32-gcc &>/dev/null || [[ -x /usr/bin/x86_64-w64-mingw32-gcc ]]
            ;;
        "$WIN_ARM64")
            [[ -x "$LLVM_MINGW_CLANG" ]]
            ;;
        "$MAC_X64"|"$MAC_ARM64")
            [[ "$(uname -s)" == "Darwin" ]] && return 0
            command -v cargo-zigbuild &>/dev/null && command -v zig &>/dev/null
            ;;
    esac
}

# Resolve final builder
BUILDER=""
if [[ "$METHOD" == "cross" ]]; then
    if ! command -v cross &>/dev/null || ! has_container_engine; then
        suggest_install "container"
        exit 1
    fi
    BUILDER="cross"
elif [[ "$METHOD" == "cargo" ]]; then
    BUILDER="cargo"
else
    # auto
    if command -v cross &>/dev/null && has_container_engine; then
        BUILDER="cross"
    else
        BUILDER="cargo"
    fi
fi

echo "==> Build mode: $BUILDER (selected by rule: $METHOD)"

# Prepare rustup targets for cargo
if [[ "$BUILDER" == "cargo" ]]; then
    echo "==> Checking rustup targets..."
    rustup target add "${ALL_TARGETS[@]}" "$WIN_X64" "$WIN_ARM64" "$MAC_X64" "$MAC_ARM64" >/dev/null 2>&1 || true
fi

mkdir -p "$DIST_DIR"
# NOTE: dist/ is accumulative across runs (each build overwrites its own
# files); delete it by hand for a from-scratch release set.

build_target() {
    local target="$1"
    local output_name="$2"
    local short_arch="$3"

    echo ""
    echo "------------------------------------------------------------"
    echo "Building [$output_name] -> $target"
    echo "------------------------------------------------------------"

    setup_linkers "$target"

    # 1) Full build (default features): host utility for dist/.
    run_builder "$target"
    local src_bin="$SCRIPT_DIR/target/$target/release/$BIN_NAME"
    local dst_bin="$DIST_DIR/${BIN_NAME}-${output_name}"

    if [[ -f "$src_bin" ]]; then
        cp "$src_bin" "$dst_bin"

        # Strip debug info
        if command -v strip &>/dev/null; then
            strip "$dst_bin" 2>/dev/null || true
        fi

        local size
        size=$(stat -c%s "$dst_bin" 2>/dev/null || stat -f%z "$dst_bin")
        echo "Success: $dst_bin ($size bytes) [full]"
    else
        echo "Error: compiled binary not found: $src_bin"
        exit 1
    fi

    # 2) Decompress-only build (--no-default-features): lean binary for
    # adb push to the device (ramdisk only unpacks/inspects).
    # Post-process: adb-push-ready copies into target/push/ — BOTH flavors:
    #   {name}_full_{arch}  full build (compress + unpack, host work)
    #   {name}_lean_{arch}  decompress-only build (ramdisk on device)
    # (e.g. `adb push target/push/lgz_compress_lean_arm64 /data/local`).
    # target/ is gitignored; push/ is kept across runs (only overwritten
    # per built arch).
    run_builder "$target" "--no-default-features"

    if [[ -f "$src_bin" ]]; then
        mkdir -p "$PUSH_DIR"
        local push_full="$PUSH_DIR/${BIN_NAME}_full_${short_arch}"
        local push_lean="$PUSH_DIR/${BIN_NAME}_lean_${short_arch}"
        cp "$dst_bin" "$push_full"

        if command -v strip &>/dev/null; then
            strip "$push_full" 2>/dev/null || true
        fi

        cp "$src_bin" "$push_lean"

        # Cross-strip: host `strip` silently fails on foreign ELFs,
        # leaving debug sections in place. Pick the matching binutils.
        local strip_tool=""
        case "$target" in
            "$TARGET_ARM64") strip_tool="aarch64-linux-gnu-strip" ;;
            "$TARGET_ARM32") strip_tool="arm-linux-gnueabihf-strip" ;;
            "$TARGET_X86")   strip_tool="i686-linux-gnu-strip" ;;
            "$TARGET_X64")   strip_tool="strip" ;;
        esac

        if [[ -n "$strip_tool" ]] && command -v "$strip_tool" &>/dev/null; then
            "$strip_tool" --strip-all -R .comment -R .note* "$push_lean" 2>/dev/null || true
        fi

        local full_size lean_size
        full_size=$(stat -c%s "$push_full" 2>/dev/null || stat -f%z "$push_full")
        lean_size=$(stat -c%s "$push_lean" 2>/dev/null || stat -f%z "$push_lean")
        echo "Push copy: $push_full ($full_size bytes) [full]"
        echo "Push copy: $push_lean ($lean_size bytes) [decompress-only]"
    else
        echo "Error: compiled binary not found: $src_bin"
        exit 1
    fi
}

# Set cross linkers for local cargo builds (no-op for cross).
setup_linkers() {
    local target="$1"
    if [[ "$BUILDER" != "cargo" ]]; then
        return 0
    fi
    case "$target" in
        "$WIN_X64")
            # Absolute distro path: /opt/llvm-mingw shadows the gcc name
            # with a clang shim when it leaks into PATH.
            if [[ -x /usr/bin/x86_64-w64-mingw32-gcc ]]; then
                export CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER="/usr/bin/x86_64-w64-mingw32-gcc"
            fi
            return 0
            ;;
        "$WIN_ARM64")
            export CARGO_TARGET_AARCH64_PC_WINDOWS_GNULLVM_LINKER="$LLVM_MINGW_CLANG"
            return 0
            ;;
        "$MAC_X64"|"$MAC_ARM64")
            # zigbuild drives its own linker.
            return 0
            ;;
    esac
    if ! check_cargo_linker "$target"; then
        exit 1
    fi
    case "$target" in
        "$TARGET_ARM64")
            export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="aarch64-linux-gnu-gcc"
            ;;
        "$TARGET_ARM32")
            export CARGO_TARGET_ARMV7_UNKNOWN_LINUX_MUSLEABIHF_LINKER="arm-linux-gnueabihf-gcc"
            ;;
        "$TARGET_X86")
            export CARGO_TARGET_I686_UNKNOWN_LINUX_MUSL_LINKER="i686-linux-gnu-gcc"
            ;;
        "$TARGET_X64")
            if command -v musl-gcc &>/dev/null; then
                export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER="musl-gcc"
            fi
            ;;
    esac
}

# Run the selected builder for one target; extra args (feature flags)
# are appended to the build command. macOS cross from Linux always goes
# through cargo-zigbuild (cross has no macOS images); Windows ARM64
# always uses host cargo (cross has no winarm64 image either).
run_builder() {
    local target="$1"
    shift
    local b="$BUILDER"
    if [[ "$target" == *apple-darwin* && "$(uname -s)" != "Darwin" ]]; then
        b="zigbuild"
    fi
    if [[ "$target" == "$WIN_ARM64" ]]; then
        b="cargo"
    fi
    if [[ "$b" == "cross" ]]; then
        cross build --release --target "$target" "$@"
    elif [[ "$b" == "zigbuild" ]]; then
        cargo zigbuild --release --target "$target" "$@"
    else
        cargo build --release --target "$target" "$@"
    fi
}

# Windows lean-only build (decompress-only: unpack/inspect for the
# desktop side). No push copies: those are adb/device-bound (Linux).
build_lean_windows() {
    local target="$1"
    local output_name="$2"

    echo ""
    echo "------------------------------------------------------------"
    echo "Building [$output_name] -> $target (lean)"
    echo "------------------------------------------------------------"

    if [[ "$BUILDER" == "cargo" ]] && ! check_opt_linker "$target"; then
        suggest_install "cargo-tools"
        echo "Skipping $target (no linker)."
        return 0
    fi
    setup_linkers "$target"
    run_builder "$target" "--no-default-features"

    local src_bin="$SCRIPT_DIR/target/$target/release/${BIN_NAME}.exe"
    local dst_bin="$DIST_DIR/${BIN_NAME}-${output_name}.exe"
    if [[ -f "$src_bin" ]]; then
        cp "$src_bin" "$dst_bin"
        local size
        size=$(stat -c%s "$dst_bin" 2>/dev/null || stat -f%z "$dst_bin")
        echo "Success: $dst_bin ($size bytes) [lean]"
    else
        echo "Error: compiled binary not found: $src_bin"
        exit 1
    fi
}

# Glue two per-arch Mach-O slices into one universal binary, exactly
# like Google's own fastboot/adb. Needs llvm-lipo (Linux) or lipo
# (Xcode); without either the slices stay as-is and nothing fails.
combine_universal() {
    local kind="$1" # full | lean
    local a b out
    if [[ "$kind" == "lean" ]]; then
        a="$DIST_DIR/${BIN_NAME}-lean-macos-x86_64"
        b="$DIST_DIR/${BIN_NAME}-lean-macos-arm64"
        out="$DIST_DIR/${BIN_NAME}-lean-macos-universal"
    else
        a="$DIST_DIR/${BIN_NAME}-macos-x86_64"
        b="$DIST_DIR/${BIN_NAME}-macos-arm64"
        out="$DIST_DIR/${BIN_NAME}-macos-universal"
    fi
    [[ -f "$a" && -f "$b" ]] || return 0
    local tool=""
    command -v llvm-lipo &>/dev/null && tool="llvm-lipo"
    if [[ -z "$tool" ]]; then command -v lipo &>/dev/null && tool="lipo"; fi
    if [[ -z "$tool" ]]; then
        echo "no llvm-lipo/lipo: leaving per-arch macOS slices ($a, $b)"
        return 0
    fi
    "$tool" -create -output "$out" "$a" "$b"
    local size
    size=$(stat -c%s "$out" 2>/dev/null || stat -f%z "$out")
    echo "Universal: $out ($size bytes)"
}

# One macOS arch, both flavors (full + lean) into dist/.
build_macos_slice() {
    local target="$1"
    local output_name="$2"

    echo ""
    echo "------------------------------------------------------------"
    echo "Building [$output_name] -> $target (full + lean)"
    echo "------------------------------------------------------------"

    if [[ "$BUILDER" == "cargo" ]] && ! check_opt_linker "$target"; then
        suggest_install "cargo-tools"
        echo "Skipping $target (no toolchain)."
        return 0
    fi
    setup_linkers "$target"

    run_builder "$target"
    local src_bin="$SCRIPT_DIR/target/$target/release/$BIN_NAME"
    if [[ -f "$src_bin" ]]; then
        cp "$src_bin" "$DIST_DIR/${BIN_NAME}-${output_name}"
        echo "Success: $DIST_DIR/${BIN_NAME}-${output_name} [full]"
    else
        echo "Error: compiled binary not found: $src_bin"
        exit 1
    fi

    run_builder "$target" "--no-default-features"
    if [[ -f "$src_bin" ]]; then
        cp "$src_bin" "$DIST_DIR/${BIN_NAME}-lean-${output_name}"
        echo "Success: $DIST_DIR/${BIN_NAME}-lean-${output_name} [lean]"
    else
        echo "Error: compiled binary not found: $src_bin"
        exit 1
    fi
}

build_macos() {
    build_macos_slice "$MAC_X64" "macos-x86_64"
    build_macos_slice "$MAC_ARM64" "macos-arm64"
    combine_universal full
    combine_universal lean
}

# Build tasks (3rd arg = short arch for target/push/{name}_{full,lean}_{arch})
case "$SELECTED_ARCH" in
    all)
        build_target "$TARGET_X64"   "linux-x86_64" "x64"
        build_target "$TARGET_X86"   "linux-x86"    "x86"
        build_target "$TARGET_ARM64" "linux-arm64"  "arm64"
        build_target "$TARGET_ARM32" "linux-arm32"  "arm32"
        ;;
    x64)
        build_target "$TARGET_X64"   "linux-x86_64" "x64"
        ;;
    x86)
        build_target "$TARGET_X86"   "linux-x86"    "x86"
        ;;
    arm64)
        build_target "$TARGET_ARM64" "linux-arm64"  "arm64"
        ;;
    arm32)
        build_target "$TARGET_ARM32" "linux-arm32"  "arm32"
        ;;
    windows)
        build_lean_windows "$WIN_X64" "windows-x64"
        build_lean_windows "$WIN_ARM64" "windows-arm64"
        ;;
    win64)
        build_lean_windows "$WIN_X64" "windows-x64"
        ;;
    winarm64)
        build_lean_windows "$WIN_ARM64" "windows-arm64"
        ;;
    mac)
        build_macos
        ;;
    mac64)
        build_macos_slice "$MAC_X64" "macos-x86_64"
        ;;
    macarm64)
        build_macos_slice "$MAC_ARM64" "macos-arm64"
        ;;
    *)
        echo "Error: unknown architecture '$SELECTED_ARCH'"
        usage
        ;;
esac

echo ""
echo "============================================================"
echo "Done! Generated binaries in dist/ (full flavor):"
ls -lh "$DIST_DIR"
if [[ -d "$PUSH_DIR" ]]; then
    echo "Push-ready copies in target/push/ (full + decompress-only per arch):"
    ls -lh "$PUSH_DIR" | awk '{print $9, "(" $5 ")"}'
fi
echo "============================================================"
