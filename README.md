# ![daze logo](/logo.svg)

**Daze** is a lightweight DOS runtime for running legacy command-line tools on modern Linux systems.

Designed primarily for old compilers, assemblers and other build tools, Daze provides a minimal DOS environment with fast startup, without requiring DOS itself, disk images or a full PC emulator.

Daze is deliberately **not a general-purpose DOS emulator**. It focuses on the DOS, BIOS and DPMI functionality needed to run supported command-line applications.

See the [test corpus](https://github.com/mkst/daze-tests) for supported tool versions
and [known workload limits](https://github.com/mkst/daze-tests/blob/main/KNOWN-LIMITS.md).

## Quick start

### Download a release

Download `daze` from [GitHub Releases](https://github.com/mkst/daze/releases/latest).

Run a DOS application directly from your working directory:

```sh
chmod +x daze
./daze ASPSX.EXE -o FOO.O MIPS.S
```

By default, the current directory is exposed to the DOS program as `C:`.

### Docker

Alternatively, run Daze without installing it locally:

```sh
docker run --rm \
  -v "$PWD:/work" -w /work \
  ghcr.io/mkst/daze:latest \
  ASPSX.EXE -o FOO.O MIPS.S
```

This mounts your current directory into the container, making your tools and source files available to Daze.

To use KVM acceleration, pass through the host's KVM device:

```sh
docker run --rm \
  --device /dev/kvm \
  -v "$PWD:/work" -w /work \
  ghcr.io/mkst/daze:latest \
  ASPSX.EXE -o FOO.O MIPS.S
```

## Usage

### Mounting directories

Daze maps host directories to DOS drive letters. The first mounted directory becomes `C:`, the second `D:`, and so on.

```sh
# Current directory becomes C:
daze ASPSX.EXE -o FOO.O MIPS.S

# Toolchain becomes C:, source directory becomes D:
daze --mount-ro toolchain --mount source \
  ASPSX.EXE -o D:/FOO.O D:/MIPS.S

# Explicitly assign a drive letter
daze --mount K:source ASPSX.EXE -o K:/FOO.O K:/MIPS.S
```

Mounts are writable by default. Use `--mount-ro` for directories that should be read-only, such as compiler installations.

DOS applications can read and write files within their mounted directories. Only mount directories you intend to make available to the application.

### Execution backends

Daze supports two execution backends:

- **KVM** - hardware-assisted execution on Linux x86 systems with available KVM support.
- **Unicorn** - software-based CPU emulation, allowing execution without KVM and on other host architectures.

By default, Daze prefers KVM and falls back to Unicorn when available. Backend fallback occurs only during initialization; failures during DOS program execution do not trigger a retry on another backend.

You can explicitly select a backend:

```sh
daze --backend kvm ASPSX.EXE
daze --backend unicorn ASPSX.EXE
```

Use `--metrics` to inspect execution statistics and identify the backend used.

For all available options:

```sh
daze --help
```

See the [diagnostics guide](docs/diagnostics.md) for troubleshooting.

## Building from source

### Requirements

- C compiler (GCC or Clang)
- CMake 3.25 or newer
- Ninja
- Linux x86 with KVM support, or Unicorn 2.1.4 or newer

### Build

```sh
cmake --preset release
cmake --build --preset release
# the daze binary can be found at ./build/release/daze
```

Other presets are available:

| Preset     | Description                     |
| ---------- | ------------------------------- |
| `debug`    | Development build               |
| `release`  | Optimized build                 |
| `kvm-only` | Linux x86 build without Unicorn |

Append `-static` for a statically linked executable, e.g. `release-static` or `kvm-only-static`.

CMake automatically detects Unicorn when available. On Linux x86, builds without Unicorn use KVM only. Other platforms require Unicorn.

For a custom Unicorn installation, configure with:

```sh
cmake --preset release \
  -DUNICORN_INCLUDE_DIR=/path/to/unicorn/include \
  -DCMAKE_LIBRARY_PATH=/path/to/unicorn/lib
```

Static builds using Unicorn require its combined `libunicorn.a` archive.
AddressSanitizer requires a dynamically linked executable; it can still use
a static Unicorn archive, which remains uninstrumented.

## Testing

### Built-in tests

After building, run the standard test suite:

```sh
# cmake --preset debug
# cmake --build --preset debug
ctest --preset debug
```

### Integration tests

Daze also maintains a separate [daze-tests](https://github.com/mkst/daze-tests) repository containing real DOS tools and regression fixtures.

Prepare the test corpus:

```sh
python3 tools/external_tests.py prepare
```

Configure, build and run the external suite:

```sh
cmake --preset debug \
  -DDAZE_EXTERNAL_TESTS=ON \
  -DDAZE_TESTS_DIR="$PWD/build/daze-tests" \
  -DPython3_EXECUTABLE="$PWD/build/daze-tests-venv/bin/python"

cmake --build --preset debug
python3 tools/external_tests.py run --build build/debug
```

The preparation step clones the pinned corpus and installs its Python requirements.
CTest fixture setup downloads and verifies tool releases when the external suite runs.
Normal local configuration does not require network access.

KVM tests require usable `/dev/kvm`. Required external test runs treat skipped tests as failures, and integration presets execute tests serially.

See the [testing guide](tests/README.md) for backend selection, sanitizers, coverage and additional testing options.

## Alternatives

Daze is intentionally limited in scope. For more general DOS compatibility, consider:

- [DOSBox-X](https://github.com/joncampbell123/dosbox-x) - a comprehensive DOS/PC emulator supporting games and applications.
- [DOSEMU2](https://github.com/dosemu2/dosemu2) - a mature DOS compatibility environment for Linux.
- [kvikdos](https://github.com/pts/kvikdos) - a lightweight solution for running DOS command-line applications on Linux.

## License

Daze's source is [MIT licensed](LICENSE.md). Releases include Unicorn and are
distributed under GPLv2, with dependency notices. Daze's source is the
release's published source archive; Unicorn and glibc sources are identified
by revision in `BUILD-INFO.txt`.
See [distribution licenses](THIRD_PARTY_NOTICES.md).
