FROM ubuntu:24.04 AS dependencies

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    cmake \
    git \
    ninja-build \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*


FROM dependencies AS unicorn

RUN git clone --depth 1 --branch 2.1.4 https://github.com/unicorn-engine/unicorn.git /tmp/unicorn \
    && cmake -S /tmp/unicorn -B /tmp/unicorn/build \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON \
    -DUNICORN_ARCH=x86 \
    -DUNICORN_LEGACY_STATIC_ARCHIVE=ON \
    -DUNICORN_BUILD_TESTS=OFF \
    -DBUILD_SHARED_LIBS=OFF \
    && cmake --build /tmp/unicorn/build -j$(nproc) \
    && mkdir -p /unicorn/lib /unicorn/include \
    && cp /tmp/unicorn/build/libunicorn.a /unicorn/lib/ \
    && cp -r /tmp/unicorn/include/* /unicorn/include/ \
    && rm -rf /tmp/unicorn/build


FROM dependencies AS build

WORKDIR /daze

COPY --from=unicorn /unicorn /daze/unicorn

COPY CMakeLists.txt /daze/CMakeLists.txt
COPY CMakePresets.json /daze/CMakePresets.json
COPY cmake /daze/cmake
COPY src /daze/src
COPY tests/CMakeLists.txt /daze/tests/CMakeLists.txt

ARG DAZE_VERSION=unknown
ARG DAZE_PRESET=release-static
RUN cmake --preset "${DAZE_PRESET}" \
    -DDAZE_VERSION="${DAZE_VERSION}" \
    -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON \
    -DBUILD_TESTING=OFF
RUN cmake --build --preset "${DAZE_PRESET}"


FROM build AS package

COPY --from=unicorn /tmp/unicorn/.git /dependency-sources/unicorn/.git
COPY --from=unicorn /tmp/unicorn/COPYING* /dependency-sources/unicorn/
COPY --from=unicorn /tmp/unicorn/qemu/LICENSE /dependency-sources/unicorn/qemu/LICENSE
COPY tools/package_release.sh /daze/tools/package_release.sh
COPY LICENSE.md THIRD_PARTY_NOTICES.md /daze/

RUN bash tools/package_release.sh /dist "${DAZE_VERSION}"


# Export release artifacts (usage: docker build --target export --output dist .)
FROM scratch AS export

COPY --from=package /dist/ /


# Runnable container
FROM ubuntu:24.04 AS daze

ARG DAZE_VERSION=unknown
LABEL org.opencontainers.image.source="https://github.com/mkst/daze" \
    org.opencontainers.image.licenses="GPL-2.0-only" \
    org.opencontainers.image.version="${DAZE_VERSION}" \
    org.opencontainers.image.documentation="https://github.com/mkst/daze/releases/tag/${DAZE_VERSION}"

COPY --from=package /dist/daze /usr/bin/daze
COPY --from=package /dist/licenses/ /usr/share/daze/licenses/
COPY --from=package /dist/LICENSE.md /dist/THIRD_PARTY_NOTICES.md /dist/BUILD-INFO.txt /usr/share/daze/
ENTRYPOINT [ "/usr/bin/daze" ]
