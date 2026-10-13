# Reproduce the CC1PSX KVM measurements

Run these commands from the Daze repository root on Linux x86_64 with usable
`/dev/kvm`. They reproduce the Randy workload: CC1PSX 2.7.2 compiling the pinned
`cc1psx-2.7.2-xlarge` case, without `-O2`, in a Release build. The input is
1,509 lines / 29,256 bytes of preprocessed C. The DOS command is:

```text
CC1PSX.EXE -o BAZ.S foo.i
```

Randy used Daze revision `a38e44551fa6893eb4eb7f314dee5d9a7e086593` and corpus
revision `259f372d2ee8d1f94b2136159c91ba49c4e12c8b`. Use the same revisions for
the closest comparison. The commands record the actual revisions and build
settings; preserve existing local changes.

## Prepare and build

Prepare a dedicated corpus checkout and Python environment once. Fixture
downloads happen on demand and are verified against the corpus catalogue.
If these two directories already exist from this recipe, skip `prepare` and
run `check` instead. Preparation preserves existing directories by refusing
to overwrite them.

```sh
python3 tools/external_tests.py prepare \
  --corpus "$PWD/build/cc1psx-corpus" \
  --venv "$PWD/build/cc1psx-venv"
python3 tools/external_tests.py check --corpus "$PWD/build/cc1psx-corpus"

cmake --preset release
cmake --build --preset release --target daze
python3 tools/external_tests.py probe-kvm
```

The probe must print `KVM API 12; VM creation succeeded`. All measurements
below force KVM; a failed probe needs resolving before proceeding.

## Measure

Run this block in one Bash session. It creates a new results directory for
each invocation. Runs are serial, and the corpus stages a fresh temporary
mount for every run. Keep the laptop's power mode consistent and record
whether it is on AC power. Leave tracing and debug logging off for timing.

```sh
export DAZE_PROFILE_CORPUS="$PWD/build/cc1psx-corpus"
export DAZE_PROFILE_BINARY="$PWD/build/release/daze"
export DAZE_PROFILE_RESULTS
mkdir -p build/profiling-cc1psx
DAZE_PROFILE_RESULTS="$(mktemp -d "$PWD/build/profiling-cc1psx/run-XXXXXX")"
profile_python="$PWD/build/cc1psx-venv/bin/python"

git rev-parse HEAD > "$DAZE_PROFILE_RESULTS/daze-revision.txt"
git status --short > "$DAZE_PROFILE_RESULTS/daze-status.txt"
git -C "$DAZE_PROFILE_CORPUS" rev-parse HEAD > "$DAZE_PROFILE_RESULTS/corpus-revision.txt"
git -C "$DAZE_PROFILE_CORPUS" status --short > "$DAZE_PROFILE_RESULTS/corpus-status.txt"
uname -a > "$DAZE_PROFILE_RESULTS/kernel.txt"
lscpu > "$DAZE_PROFILE_RESULTS/cpu.txt"
cp build/release/CMakeCache.txt "$DAZE_PROFILE_RESULTS/CMakeCache.txt"
sha256sum "$DAZE_PROFILE_BINARY" > "$DAZE_PROFILE_RESULTS/binary-sha256.txt"
env | sort | rg '^DAZE_' > "$DAZE_PROFILE_RESULTS/daze-environment.txt"

# Correctness and completion: normal golden run, then a fresh debug/metrics run.
"$profile_python" "$DAZE_PROFILE_CORPUS/daze_tests.py" regress \
  --case cc1psx-2.7.2-xlarge --backend kvm --required \
  --daze "$DAZE_PROFILE_BINARY" \
  --evidence-dir "$DAZE_PROFILE_RESULTS/regression"

# Seven baseline runs without metrics; each must pass golden verification.
"$profile_python" "$DAZE_PROFILE_CORPUS/daze_tests.py" bench \
  --case cc1psx-2.7.2-xlarge --only kvm --iterations 7 \
  --daze "$DAZE_PROFILE_BINARY" \
  --output "$DAZE_PROFILE_RESULTS/benchmark.json"

# Wrapper adds only --metrics to the corpus runner's normal Daze command.
cat > "$DAZE_PROFILE_RESULTS/metrics-daze" <<'SH'
#!/bin/sh
exec "$DAZE_PROFILE_BINARY" --metrics "$@"
SH
chmod +x "$DAZE_PROFILE_RESULTS/metrics-daze"

cat > "$DAZE_PROFILE_RESULTS/profile.py" <<'PY'
import json
import os
import resource
import statistics
import sys
from pathlib import Path

sys.path.insert(0, os.environ['DAZE_PROFILE_CORPUS'])
import daze_tests as corpus

root = Path(os.environ['DAZE_PROFILE_RESULTS'])
case = corpus.get_case('cc1psx-2.7.2-xlarge')
samples = []
for index in range(7):
    tmp, work = corpus.stage_case(case)
    try:
        before = resource.getrusage(resource.RUSAGE_CHILDREN)
        result, elapsed = corpus.run_daze(
            case, work, str(root / 'metrics-daze'), 'kvm',
            evidence=root / f'metrics-{index + 1}')
        after = resource.getrusage(resource.RUSAGE_CHILDREN)
        # Metrics changes stderr; still verify exit, stdout, and artifact goldens.
        assert corpus.verify_result(case, work, result, diagnostic=True)
        assert b'metrics: backend=kvm selection=kvm-completed\n' in result.stderr
        artifact = work / 'BAZ.S'
        sample = dict(
            elapsed_ms=elapsed * 1000,
            user_ms=(after.ru_utime - before.ru_utime) * 1000,
            system_ms=(after.ru_stime - before.ru_stime) * 1000,
            host_status=result.returncode,
            output_size=artifact.stat().st_size,
            output_sha256=corpus.sha256_file(artifact))
        samples.append(sample)
        print(json.dumps(sample), flush=True)
    finally:
        tmp.cleanup()
(root / 'metrics-summary.json').write_text(json.dumps(samples, indent=2) + '\n')
baseline = json.loads((root / 'benchmark.json').read_text())['targets']['kvm']
mean = statistics.mean(sample['elapsed_ms'] for sample in samples)
print(f"Baseline: mean={baseline['mean_ms']:.3f}ms "
      f"median={baseline['median_ms']:.3f}ms")
print(f"Metrics: mean={mean:.3f}ms "
      f"median={statistics.median(sample['elapsed_ms'] for sample in samples):.3f}ms")
print(f"Metrics group difference: {(mean / baseline['mean_ms'] - 1) * 100:.2f}%")
PY

"$profile_python" "$DAZE_PROFILE_RESULTS/profile.py"
printf 'Results: %s\n' "$DAZE_PROFILE_RESULTS"
```

Stop if any command fails. The required regression should print
`PASS cc1psx-2.7.2-xlarge [kvm]`; its diagnostic record confirms DOS exit 0
independently of host success. The metrics run uses the same shell-wrapper
approach as Randy; its measured interval includes the wrapper's startup.

## Results to keep

Keep the entire printed results directory. In particular:

- `benchmark.json`: seven metrics-off samples and aggregate timings.
- `metrics-summary.json`: seven metrics-on timings, child CPU time, status,
  output size, and hash.
- `metrics-*/step-0-stderr`: full KVM counters and timers; stdout is separate.
- `metrics-*/step-0.json`: command, host status, backend selection, and artifact
  evidence. The recorded executable is the wrapper, which adds `--metrics`.
- `regression/`: normal golden comparison and separate diagnostic run recording
  DOS completion and backend selection.
- Revision, CPU, kernel, build, binary identity, and environment records.

Expected `BAZ.S`: 191,663 bytes, SHA256
`0c1a98a40e359d2c6cdcf8c76c02f7cafe720904d9e8ea31d3d1ff24f59c3778`.

Randy's reference results used GCC 13.3.0, `-O3 -DNDEBUG`, an Intel Xeon
D-1541, and Linux `6.8.0-142-generic`:

| Seven runs | Mean | Median | Range |
|---|---:|---:|---:|
| Metrics off | 903.510 ms | 907.009 ms | 874.875–923.228 ms |
| Metrics on | 944.374 ms | 942.999 ms | 921.092–976.870 ms |

The groups were measured consecutively, so their difference includes host
variation as well as instrumentation. KVM timers overlap, and `KVM_RUN` time
includes guest execution, kernel work, and scheduling; retain the raw records
for the subsequent analysis.

## Attribute date/time callback cost

After rebuilding with the callback-cost metrics, repeat the Measure block above
to collect a fresh baseline and metrics group. To display the new lines:

```sh
rg '^metrics: kvm-rm-procedure-cost ' "$DAZE_PROFILE_RESULTS"/metrics-*/step-0-stderr
```

The three groups are `date-2ah`, `time-2ch`, and `other`. A detour is assigned to
date or time only if it serviced exactly one real-mode runner boundary, and
that boundary was the corresponding DOS function. Procedures with no serviced
boundary, multiple boundaries, or another function are assigned to `other`.
Classification uses observed service counters, not the procedure's initial AX
or its target address. The groups partition the detours included in the existing
`kvm-rm-procedure total`; early failures remain outside that existing total.

Each line reports calls, total time, average time, setup, reflection, cleanup,
resume, reflection/resume `KVM_RUN`, and DOS broker service time. For a clock
group, `total - dos-service` measures time surrounding the handler, including
guest code and KVM execution. It is not exclusively host overhead. The phase
and nested `KVM_RUN`/service timers overlap; do not add every field together.
The collector reuses existing timestamps and counters and adds no KVM ioctls,
stepping, or guest hooks. Collection remains conditional on `--metrics`.

## KVM time reply experiment (parked)

The experimental KVM real-mode DOS gate answered AH=2Ch in guest code using the existing
shared DOS policy: CX=DX=0, AX preserved, and carry cleared. It preserves the
other saved flags, the upper halves of ECX/EDX, BP, and the stack. It does not
cache the live date or replace the DOS extender's callback routine. The clock
reply stays in the original DOS segment, after the default IRET stub and before
InDOS storage. Its bytes are included in the guest layout's reserved ranges.

The experimental return follows the real-mode interrupt frame and IRET semantics described
in the [Intel instruction reference](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2a-manual.pdf).
There is no change to KVM exit interpretation or register capture/restore.
Hardware validation uses the Intel host recorded above; AMD remains untested.

For the default case, the experiment reduced host-serviced AH=2Ch calls from
4,221 to zero and real-mode callback `KVM_RUN` calls from 20,501 to 16,280.
The DPMI callback routine still ran; those clock callbacks appeared in the cost
collector's `other` group because the clock reply had no hosted boundary.

A consecutive, serial comparison on Randy, with metrics disabled and seven
fresh mounts per binary, produced:

| Binary | Mean | Median | Range |
|---|---:|---:|---:|
| Before guest time reply | 912.986 ms | 917.806 ms | 879.943–940.734 ms |
| With guest time reply | 832.648 ms | 813.339 ms | 809.946–875.386 ms |

The mean improvement was 80.337 ms (8.8%). All runs passed corpus golden
verification. These timings are one-host evidence; they do not establish an
AMD or laptop speedup. Full callback removal would require preserving the
extender's guest stack/register/memory effects, which this change avoids.

The experiment is parked rather than integrated. Its patch and working Release
binary are preserved locally under `build/profiling-cc1psx/parked-clock-gate.patch`
and `build/profiling-cc1psx/daze-clock-experiment`; the callback-cost metrics remain
in the working source. The experimental Debug suite and external acceptance
passed, but its KVM/local coverage gate fell slightly below the existing branch
baseline (85.89% versus 85.91%). That gate was not waived or its baseline changed.

## Quiet workload

Passing `-quiet` removes the compiler's timing requests entirely:

```text
CC1PSX.EXE -quiet -o BAZ.S foo.i
```

Using the same pinned input and fresh corpus mounts, seven serial measurements
per binary with metrics off produced:

| Binary with `-quiet` | Mean | Median | Range |
|---|---:|---:|---:|
| Before guest time reply | 186.011 ms | 178.736 ms | 168.098–205.353 ms |
| Experimental guest time reply | 179.719 ms | 171.414 ms | 167.324–209.045 ms |

Both binaries serviced zero date/time calls. The small difference between these
overlapping ranges does not establish a benefit from the clock path, which is
never taken. This motivated parking the optimization and measuring with `-quiet`.

The only assembly difference from the default golden was its argument comment:
` # -o` became ` # -quiet -o`. The raw quiet output was 191,670 bytes, SHA256
`e43f41dc5decd952c77a5c8ae50783909f2ff7278393b5289bda0da92b852229`.
Removing only that exact comment token produced the default golden hash. All
runs checked host success, empty normal stdout/stderr, and the normalized assembly
hash; separate diagnostic runs confirmed DOS exit 0 and strict KVM completion.
No pinned case or golden was modified.

The quiet diagnostic run before the experimental optimization recorded:

- Date/time DOS calls: 0/0, previously 4,221/4,221.
- Virtual-interrupt disable/enable: 565/565, previously 9,330/9,330.
- Real-mode callbacks: 943, previously 9,711; total callback time 83.075 ms.
- Protected `continue-once`: 2,339 calls / 86.545 ms.
- Callback reflection `KVM_RUN`: 2,968 calls / 35.460 ms.
- DOS file writes: 1,666 / 191,670 bytes; reads: 311 / 1,237,592 bytes.
- DOS broker service: 12.779 ms; gate replies: 7.896 ms.

These timers overlap. File reads/writes account for 1,977 of 2,031 DOS calls
(97.3%). The 1,130 virtual-interrupt requests remain a possible target, but their
host mediation is only 0.671 ms: a useful optimization would need to reduce the
crossings rather than make the scalar handler faster. The shared contract returns
the previous software-enabled bit in AL and updates the process's bit. A guest
implementation would need to preserve that state across host mediation and EXEC,
handle both client frame widths, and retain the existing register/flag contract.
