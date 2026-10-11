# Known differences vs the dosemu2 oracle

Divergences between daze output and real-DOS (dosemu2) output that have been
investigated and judged **not bugs**. Each entry records the symptom, the
established cause, and why no change was made. New entries must meet the same
bar: reproduced in a fresh mount, first causal boundary captured, expected
contract established.

## 1. ASPSX 1.05 object section segments (2026-10-06)

- **Symptom:** `ASPSX.EXE -o FOO.O MIPS.S` assembles cleanly everywhere, but
  the 101-byte object differs in 8 two-byte section-record fields.
  Unicorn and KVM are byte-identical (`sha1 c8b6714c…`, matching the
  fixture-pinned SHA256); dosemu2 agrees with itself across runs but not
  with daze. Assembled code bytes are identical; only section metadata
  differs.
- **Cause:** ASPSX allocates one `0x7000`-paragraph DOS buffer (`INT
21h/48h`) and writes per-section slots at buffer segment `+0x10+i`
  into the object. daze's bump allocator hands out `0x3000` (arena
  floor), so sections land at `0x3010…`; FreeDOS hands out whatever its
  MCB chain has (`0x10CD` direct, `0x10CB` under a batch file), so
  sections land at `0x10DD…` / `0x10DB…`. Verified by instrumenting
  daze's `48h` path (since reverted) and by the exact `base+0x10+i`
  arithmetic on all three runs.
- **Ruled out along the way:** timestamps (dosemu self-agrees across
  minutes), DOS date (a `DATE 01-01-1980` batch red herring — the
  date-less batch control hashed identically; also daze serves the
  same host date), output filename (daze is name-invariant),
  uninitialized memory (both sides structured).
- **Verdict:** explained divergence, no change. The values are guest
  addresses that legitimately vary with MCB layout; the objects link
  identically. Chasing FreeDOS's exact base segment would trade
  determinism-by-construction for mimicry.
- **Side observation (not investigated):** dosemu writes the output
  name lowercase (`foo.o` for `-o FOO.O`); daze preserves case.

## 2. Placeholder DOS clock: 2Ch frozen at midnight, 2Ah serves host date (2026-10-06)

- **Symptom:** compiler phase timers that read DOS time always report
  zero (e.g. CC1PSX 2.7.2 prints `time in parse: 0.000000` for every
  phase even after minutes of wall time). `INT 21h/AH=2Ch` always
  returns `CX=DX=0` (00:00:00.00), while `AH=2Ah` serves the real host
  date. dosemu2 advances both.
- **Cause:** the frozen time is a deliberate deterministic placeholder,
  pinned by the `int21_service` contract test (`clock` requires
  `cx == dx == 0`; `date` requires year `>= 2000` with nonzero
  month/day). The DOS/DPMI/file service is shared, so Unicorn and KVM
  agree exactly.
- **Ruled out along the way:** a guest spin on the frozen clock — 2Ah/2Ch
  arrive as bounded start/end pairs per compilation unit (1129 each for
  the 80-function stress input), never as a polling loop; every measured
  workload completes.
- **Verdict:** deliberate, no change. Whether 2Ah should also be a fixed
  placeholder for consistency is open: it would keep the existing
  contract green (2000-01-01 satisfies `cx >= 2000`) but would change
  guest-visible dates, so it needs its own fixture and approval.

## 3. Unicorn vs KVM wall time on compiler workloads (2026-10-06)

The timings and implementation experiments below are historical measurements
from that investigation, not benchmarks of the current revision. Current
workload comparisons belong to the pinned `daze-tests` corpus.

- **Symptom:** identical completed runs take far longer under
  `--backend unicorn` than `--backend kvm` (same DOS exit status,
  byte-identical outputs). Measured with the release artifact
  (Dockerfile `release-static`; now exported as
  `dist/daze`): `CC1PSX.EXE -o BAZ.S
simple.c` (the former local tiny source, now `daze-tests/sources/tiny/simple.c`): 1.73s vs 0.09s (~19x).
  The same tool on an 80-function stress input: 15.4s vs 0.43s
  (~36x, DOS status 33 both sides, `sha256 1e28119d…`, 50639 bytes).
- **Cause:** cold-translation throughput, not slow execution. In-process
  sampling of the Unicorn run attributes ~59% of wall time to the TCG
  translator (optimizer/liveness/regalloc), ~7% to TB invalidation, and
  ~1% to executing translated code. A compiler exercises megabytes of
  mostly-distinct code (fresh DPMI selector bases retire cached
  translations), which this TCG translates at roughly 1M guest
  instructions/s on the measured host. KVM executes the same code
  natively and pays no translation cost.
- **Build sensitivity (not a second cause):** the local `debug`-preset
  numbers are ~2-3.5x worse again (3.89s / 129.4s) because this
  worktree's ignored `/unicorn/` copy was built without optimization
  (`-O0` codegen: frame pointers and spill-everything throughout
  `tcg*.o`/`translate*.o`/`optimize*.o`). The Dockerfile already does
  the right thing (`CMAKE_BUILD_TYPE=Release`, x86-only); no flag
  changes needed there. Local perf comparisons must use a Release-built
  Unicorn, such as `dist/daze`, rather than assuming
  the dev `build/debug` binary has an optimized dependency.
- **Ruled out along the way:** `--metrics` overhead (132.7s off vs
  129–132s on), stop/resume transport (~1ms total over 8,346
  `uc_emu_start`s), narrow gate hooks and the `UC_HOOK_INTR` observer
  (bare-Unicorn spike with identical hooks: same throughput), targeted
  `uc_ctl_remove_cache` ranges (spike-proven range-scoped: a 1MB hot
  blob re-runs at 14.6 MIPS after nuking an unrelated range vs 0.13
  after a real full flush; default TCG buffer is already 1GiB, so
  capacity eviction is not the driver), the 10M `uc_emu_start` count
  guard (counterfactual `count=0` build: 3.96s vs 3.87s, identical
  counters), and mid-run full translation-cache flushes (counterfactual
  skipping all 24 post-startup flushes: identical hash, no speedup).
- **Verdict:** explained gap, no further change. Fresh-slot LDT writes
  (non-present old descriptor, identical rewrite) now skip the global
  flush under `unicorn_ldt_flush_scope_contract_test`; on the stress
  input that cut full flushes 82 -> 35 with identical output and no
  wall change, as expected — the eliminated flushes discarded dead
  translations. Live-selector mutations keep the conservative flush.
  Separately, the protected-DOS-continuation decline hook (installed
  catch-all per vectored INT 21h delivery) used to linger until the
  _next_ delivery; a one-shot exact-address return hook now retires it
  at the delivery's IRET, which cut the stress input 37.4s -> 15.4s
  with identical output — the lingering hook had cost ~4% directly and
  degraded translation/execution around it. `auto` already prefers KVM,
  which is the right backend for these workloads.

## Entry template

```md
## N. Title (YYYY-MM-DD)

- **Symptom:** what differs, exact commands, hashes/sizes.
- **Cause:** first causal boundary and mechanism.
- **Ruled out along the way:** dead-end theories with the evidence
  that killed them.
- **Verdict:** explained divergence / fixture updated / behavior fixed
  (with commit).
```
