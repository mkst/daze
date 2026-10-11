# Release packaging

Push a numeric version tag after development checks pass. The Release workflow
runs the existing Build workflow on that commit. After all jobs pass, it builds
and publishes Linux x86_64 and ARM64 executables, a standalone macOS ARM64
package, and a multi-platform Docker image. Missing KVM access, failed tests or
skipped required cases block publication through the Build workflow.

Branch pushes build the executable and container and upload the release files as a
workflow artifact; GitHub releases and registry images are published only for tags.
The x86_64 Linux release download is the standalone `daze` executable. The
ARM64 Linux download is `daze-linux-arm64.tar.gz` and contains the static
executable, notices and build information. macOS does not support the Linux
static-link mode; `daze-macos-arm64.tar.gz` contains a standalone ARM64
executable linked to the macOS system runtime, with Unicorn statically linked,
notices and build information. The multi-platform Docker image tags select
Linux x86_64 or ARM64 automatically.

The runnable container retains the Ubuntu base and includes small license notices
under `/usr/share/daze/`. It contains no DOS tools or fixture assets.

## Build locally

```sh
docker buildx build --platform linux/amd64 --build-arg DAZE_VERSION=local \
  --target export --output type=local,dest=dist .
docker buildx build --platform linux/amd64 --build-arg DAZE_VERSION=local \
  --target daze --tag daze:local --load .
```

`BUILD-INFO.txt` records the dependency and compiler versions used in the build.
The export creates `dist/daze`, notices and `BUILD-INFO.txt` in `dist/`, and
dependency license texts in `dist/licenses/`. CI uploads these files directly;
no tarball is created.

## Rebuild or relink

Daze's own source comes from the release's published source archive. Take the
Unicorn revision and the libc/libgcc versions from the release's `BUILD-INFO.txt`:
clone that Unicorn revision upstream, and fetch the matching
glibc source with `apt-get source` for the recorded version. On Linux
x86_64 with GCC, CMake 3.25+, Ninja and libc development files installed, run:

```sh
git clone --branch 2.1.4 https://github.com/unicorn-engine/unicorn.git
cmake -S unicorn -B build/unicorn -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON -DUNICORN_ARCH=x86 \
  -DUNICORN_LEGACY_STATIC_ARCHIVE=ON -DUNICORN_BUILD_TESTS=OFF \
  -DBUILD_SHARED_LIBS=OFF
cmake --build build/unicorn --parallel 2
cmake -S daze -B build/daze -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON -DDAZE_BUILD_STATIC=ON \
  -DBUILD_TESTING=OFF -DDAZE_UNICORN_BACKEND=ON \
  -DDAZE_VERSION="<release version>" -DUNICORN_INCLUDE_DIR="$PWD/unicorn/include" \
  -DUNICORN_LIBRARY="$PWD/build/unicorn/libunicorn.a"
cmake --build build/daze --parallel 2
./build/daze/daze --version
```

These commands build from the published Daze sources and upstream Unicorn
using the host's libc development files. For the shipped glibc source, run
`dpkg-source -x` on the `.dsc` file fetched above; its accompanying archives
include Ubuntu's patches. Follow the extracted glibc `INSTALL` instructions
to build and install a modified library into a separate sysroot. Pass the
corresponding toolchain/sysroot flags to both CMake configure commands (for
example, `-DCMAKE_SYSROOT=/path/to/sysroot`) to recompile and relink both
Unicorn and Daze with it. Use the recorded compiler versions when reproducing
the release build. The source licenses permit modification, rebuilding and
debugging; no signing key is needed to run a rebuilt executable.
