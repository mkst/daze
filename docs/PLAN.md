# Daze plan

## Product contract

Daze runs a historical DOS command-line MZ tool and its supported child
processes against host mounts. Supported hosts are Linux amd64 and arm64, and
macOS arm64. It supplies only the DOS, BIOS, and DPMI surface proved by
accepted fixtures. No general DOS shell, boot process, graphics, sound, mouse,
networking, device emulation, or disk images without a newly accepted fixture
and explicit approval. DOSEMU2 is an oracle, not a runtime dependency.

## Current state

The pinned integration corpus covers accepted ASPSX and CC1PSX versions, BCC
2.0/3.1, MSC 5.1, and the Cygnus 2.7-96Q3 CPP -> CC1 -> AS pipeline. Linux
amd64 validates Unicorn, strict KVM, automatic selection, and omitted-backend
selection. Linux arm64 and macOS arm64 validate Unicorn. BCC 3.1 passes strict
KVM, including its DPMI exception handler and return. CC1PSX 2.6.0 `-O2` has a
focused regression on both explicit backends. These are accepted workloads,
not a claim that every input or option of each tool is supported.

The pinned `daze-tests` repository owns the executable application
compatibility record: cases, inputs, goldens, release assets and benchmarks.
`tools/daze-tests.json` records the accepted revision; external CTest/CI runs
use verified release downloads and reject missing or skipped required tests.
Historical fixture trees and their harness have been removed from Daze.
Local contracts and synthetic runtime smokes register and run offline,
independently of historical tools. External integration is opt-in for local
builds and enabled as a CI gate; see `tests/README.md` for setup and validation.

Contract-only and all-local coverage have separate measured baselines and
regression gates in CI. Both profiles currently exceed the 90% line and 80%
branch goals. The tracked [coverage baseline](coverage-baseline.json) records
the accepted measurements; tests and coverage workflow details are in
[`tests/README.md`](../tests/README.md).

Investigation-code cleanup is ongoing. Exception, continuation, real-mode
return, overlay, and child EXEC lifecycle mechanics remain required by accepted
workloads. Lack of execution in a sampled run alone does not establish that a
failure, teardown, or alternate-backend path is disposable. Supported tracing
and failure records are documented in [diagnostics.md](diagnostics.md).

Completed-run performance measurements already exist. Further measurement
should use the fixed workloads and result tooling in `daze-tests`, with both
the runtime and corpus revisions recorded. Larger external cases expose
documented Unicorn instruction-guard and timeout limits; the configurable
`DAZE_UNICORN_INSTRUCTION_LIMIT` raises the per-emulation instruction guard,
but does not resolve host timeouts or establish compatibility for those cases.
See [`diagnostics.md`](diagnostics.md) and the corpus's known-limits record.

## Runtime and backend policy

- On Linux/x86, omitted `--backend` or `auto` prefers usable KVM. Explicit
  `unicorn` forces Unicorn; explicit `kvm` is strict and never falls back.
- With no mount, the host current directory is guest `C:`. Mounts may pin a
  drive; otherwise the first is `C:`, then `D:`, etc. The guest environment is
  deterministic; mounts are writable user data unless mounted read-only with
  `--mount-ro` (also spelled `--mount_ro`), which serves reads while guest
  creates, write-mode opens, and deletes fail with DOS access denied.
  `--no-tmp` skips automatic `C:\TMP` directory setup; the deterministic
  `TEMP` and `TMP` defaults remain `C:\TMP` unless overridden with `--env`.
- CMake uses Unicorn when found. A build without Unicorn is supported only when
  the target has Linux/x86 KVM support; otherwise configuration fails rather
  than producing a binary with no execution backend. `kvm-only` is the native
  Linux/x86 preset for builds that deliberately omit Unicorn.
- Automatic fallback is allowed only after a pre-start KVM rejection.
  Post-start failures are terminal. DOS `INT 21h/AH=4Ch` terminates with status
  in `AL`; neither case may be disguised as a successful fallback.
- DOS/DPMI/filesystem and process-state policy is shared. Backend adapters
  own CPU execution and boundary transport. Share code when the same contract
  is established; avoid speculative abstractions and duplicated service policy.

## Compatibility workflow

1. Reproduce in a fresh temporary mount; never generate outputs in `tests/`.
2. Capture the first causal interrupt, DPMI operation, fault, or probe,
   including registers, execution address, and output.
3. Establish the expected contract from an oracle, documentation, disassembly,
   or a focused spike.
4. Implement the smallest explicit response, add a useful focused regression,
   and rerun the relevant established suites.

Do not invent guessed capabilities or catch-all successes. Preserve real-mode
segments, protected selectors, and GDT/LDT distinctions. Spikes stay
experimental until their evidenced contract is deliberately integrated.

## Validation and next direction

Build with `cmake --preset debug` and `cmake --build --preset debug`.
Run `ctest --preset debug`. The default local suite is offline; CI also runs
the pinned external suite across the native compiler/host combinations
documented in [`tests/README.md`](../tests/README.md). Prepare the pinned corpus
with `python3 tools/external_tests.py prepare` and configure the external
options documented in `tests/README.md`, then run
`python3 tools/external_tests.py run --build build/debug` for full acceptance.
KVM-only native Linux/x86 builds use `cmake --preset kvm-only` and
`cmake --build --preset kvm-only`; validate with `ctest --preset kvm-only` and
`python3 tools/external_tests.py run --build build/kvm-only`.
KVM coverage requires real `/dev/kvm` access; unavailable access is a validation
blocker and must be escalated rather than silently skipped. Required external
tests reject skips; the acceptance gate compares discovery and execution with
the pinned selection.
An integration preset without enabled external tests fails with setup guidance.

After changes to allocation, pointer ownership across callbacks, or teardown,
also configure/build the `asan` preset and run `ctest --preset asan` and
serial `ctest --preset asan-integration -j1`. ASan covers Daze-owned heap;
the prebuilt Unicorn archive is uninstrumented. Bounds checks also need focused
regressions for the invalid range or size that triggered the defect.

Preserve stdout and stderr separately, host and DOS exit status, artifact
presence/size/hash, and the `--metrics` backend-selection line across backend
comparisons. Use timings only for completed equivalent workloads, and record
build settings and dependencies so an unoptimized Unicorn is not mistaken for
a runtime regression. Oracle differences and intentional normalization need
explicit evidence; backend agreement alone does not prove correctness.
Trace/history hooks stay opt-in; normal execution keeps required narrow hooks.

## Next priorities

1. Investigate the known larger-workload limits at their first causal boundary.
   Distinguish Unicorn instruction-guard exhaustion, host timeout, and
   unsupported guest behavior before changing policy or adding compatibility
   responses. Keep the limits visible and preserve passing required cases.
2. Maintain the external compatibility record in `daze-tests`; update the pin
   only after validating representative pipelines, overlay/EXEC/exception
   coverage, filesystem behavior, and backend selection. The corpus remains
   the source of truth for accepted real-tool cases and known workload limits.
3. Continue evidence-led investigation-code cleanup while preserving lifecycle
   and failure behavior required by accepted workloads. Sampled non-execution
   alone is not evidence that a failure or teardown path is disposable.
4. Keep the public support and release documentation aligned with the tested
   host/architecture matrix and known limits. Linux amd64 CI covers GCC and
   Clang plus KVM; Linux arm64 uses GCC/Unicorn; macOS arm64 uses Apple
   Clang/Unicorn. ASan, static variants, exported-binary smoke checks, and
   release tests are described in the relevant workflow docs.
5. Optimize only measured costs in completed equivalent workloads, recording
   runtime and corpus revisions and build settings. Additional build-tool
   support follows the compatibility workflow; broader DOS support requires a
   newly accepted fixture and explicit approval.

Correctness, portability across the supported target matrix, and existing
regressions precede performance work or expansion of the supported surface.
This plan records the product boundary and current priorities; detailed
investigation history belongs in supporting records.
