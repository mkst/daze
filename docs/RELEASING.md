# Release packaging

Push a numeric version tag to publish after checks pass. The Release workflow
runs Build first; missing KVM access, failed tests, or skipped required cases
block publication. Branches upload workflow artifacts; tags publish GitHub
release assets and registry images.

Linux assets are the standalone x86_64 `daze` and `daze-linux-amd64.tar.gz`,
plus `daze-linux-arm64.tar.gz`; both archives include the static executable,
notices, and build information. `daze-macos-arm64.tar.gz` contains a standalone
ARM64 executable linked to the macOS system runtime, with Unicorn statically
linked. Docker tags select Linux x86_64 or ARM64; the Ubuntu-based image
contains license notices under `/usr/share/daze/`, but no DOS tools or fixtures.

## Build locally

```sh
docker buildx build --platform linux/amd64 --build-arg DAZE_VERSION=local \
  --target export --output type=local,dest=dist .
docker buildx build --platform linux/amd64 --build-arg DAZE_VERSION=local \
  --target daze --tag daze:local --load .
```

`BUILD-INFO.txt` records dependency and compiler versions. Export writes
`dist/daze`, notices, build info, and dependency licenses under `dist/`; CI
uploads these files and packages them in `daze-linux-amd64.tar.gz`.

## Rebuild or relink

Use Daze's published source archive and the Unicorn revision and libc/libgcc
versions in `BUILD-INFO.txt`. Clone that Unicorn revision and fetch its matching
glibc source with `apt-get source`. On Linux x86_64 with GCC, CMake 3.25+, Ninja,
and libc development files, run:

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

These commands use the host's libc development files. To rebuild the shipped
glibc, run `dpkg-source -x` on the fetched `.dsc` (the accompanying archives
contain Ubuntu patches), then follow its `INSTALL` instructions to install it
in a separate sysroot. Pass matching toolchain/sysroot flags (for example,
`-DCMAKE_SYSROOT=/path/to/sysroot`) to both CMake configure commands. Use the
recorded compiler versions for reproduction. Licenses permit modifying,
rebuilding, and debugging; no signing key is needed to run the result.
