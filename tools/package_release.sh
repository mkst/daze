#!/usr/bin/env bash
set -euo pipefail

output=$(realpath -m "${1:?output directory required}")
version=${2:?version required}
root=$(cd "$(dirname "$0")/.." && pwd)
unicorn=/dependency-sources/unicorn
test -f "$unicorn/COPYING"
test ! -e "$output"
mkdir -p "$output/licenses"
binary_dir="$output"

cp "$root/build/release-static/daze" "$binary_dir/daze"
cp "$root/LICENSE.md" "$root/THIRD_PARTY_NOTICES.md" "$binary_dir/"
cp "$unicorn/COPYING" "$binary_dir/licenses/GPL-2.0.txt"
cp "$unicorn/COPYING_GLIB" "$binary_dir/licenses/unicorn-glib.txt"
cp "$unicorn/COPYING.LGPL2" "$binary_dir/licenses/unicorn-LGPL-2.0.txt"
cp "$unicorn/qemu/LICENSE" "$binary_dir/licenses/unicorn-qemu.txt"
cp /usr/share/common-licenses/LGPL-2.1 "$binary_dir/licenses/LGPL-2.1.txt"
cp /usr/share/common-licenses/GPL-3 "$binary_dir/licenses/GPL-3.0.txt"
cp /usr/share/doc/libc6/copyright "$binary_dir/licenses/glibc-copyright"
gcc_major=$(gcc -dumpversion | cut -d. -f1)
cp "/usr/share/doc/gcc-$gcc_major-base/copyright" "$binary_dir/licenses/gcc-copyright"

{
  printf 'Daze version: %s\n' "$version"
  printf 'Unicorn revision: %s\n' "$(git -C "$unicorn" rev-parse HEAD)"
  gcc --version
  cmake --version
  dpkg-query -W libc6 libc6-dev "libgcc-$gcc_major-dev"
} > "$binary_dir/BUILD-INFO.txt"
