# Local and external tests

Daze keeps contract tests, synthetic MZ runtime smokes, CLI checks and shared
test drivers here and under `src/`. They need no historical DOS binaries,
Python environment, fixture downloads or sibling checkout.

```sh
cmake --preset debug
cmake --build --preset debug
ctest --preset debug
```

Historical application cases, inputs, goldens and release assets are owned by
[daze-tests](https://github.com/mkst/daze-tests). The repository and accepted
commit are pinned in [`tools/daze-tests.json`](../tools/daze-tests.json).

## External regression setup

From Daze's root, prepare a new isolated checkout and virtual environment:

```sh
python3 tools/external_tests.py prepare
cmake --preset debug -DDAZE_EXTERNAL_TESTS=ON \
  -DDAZE_TESTS_DIR="$PWD/build/daze-tests" \
  -DPython3_EXECUTABLE="$PWD/build/daze-tests-venv/bin/python"
cmake --build --preset debug
ctest --preset debug
python3 tools/external_tests.py run --build build/debug
```

The setup command reads the pin, clones that revision and installs its Python
requirements. It refuses to overwrite existing directories; use `--corpus`
and `--venv` to prepare another location. Configuration checks the revision
and clean test contents, and generates registrations without downloading
fixtures. To check a checkout against the pin at any time, without side
effects (and to confirm a configured build's registrations are current):

```sh
python3 tools/external_tests.py check
python3 tools/external_tests.py check --build build/debug
```

A default `build/daze-tests` clone left behind by an earlier pin revision
fails this check, and fails configuration and `run` the same way. The
failure names the expected revision and the refresh commands for the
disposable helper clone; reconfigure afterwards so registrations match
the pin again. CTest setup downloads assets into `build/debug/fixture-cache` and
checks archive/content digests. `DAZE_TEST_CACHE` is a CMake cache path you can
change to force cold provisioning. Test environments unset local fixture
overrides, including `DAZE_FIXTURE_SOURCES`.

Integration presets run serially. Required cases cannot skip. The Python
acceptance command also compares discovered and executed tests with the
required set, rejects skipped/missing/duplicate executions, and saves evidence
in fresh `build/debug/external-evidence/run-*` directories. `latest` points
to the most recently started invocation, including failed preflight checks.
Discovery, logs, JUnit, regression evidence and the acceptance report all
belong to that invocation. CI uses this command as its gate. To check
local tests with the same no-skip policy, add `--suite local`; `--portable`
excludes hardware-dependent local tests when measuring a portable build.
The acceptance command streams CTest progress live and saves its log as it
runs. Local tests without an explicit timeout have a 60-second default;
existing per-test timeouts and external workload limits remain in force.

Use the acceptance command once for full validation. Direct CTest is useful
for filtering and rerunning individual tests; it does not perform the final
discovery/JUnit acceptance checks:

```sh
ctest --preset integration -R '^compat.aspsx-2.34-tiny.unicorn$' -j1
```

Direct CTest regressions create their own invocation directories. The corpus
emitter supplies registrations, selection metadata, evidence paths and fixture
override properties through its command-line interface; Daze validates the pin,
selects supported backends, and checks acceptance.

With both backends compiled, external selection covers 42 pairs: 20 explicit
Unicorn, 20 strict KVM, plus automatic and omitted backend selection. Actual
KVM VM creation is required for KVM and automatic selection. Probe it with
`python3 tools/external_tests.py probe-kvm`; inaccessible KVM blocks validation.
For a portable Unicorn-only run, configure
`-DDAZE_EXTERNAL_BACKENDS=unicorn`. This selects 20 required pairs and does not
claim KVM validation. Unsupported backend selections are configuration errors.

Use the same external options with `asan`, `coverage` or `kvm-only` configure
presets. Their corresponding integration presets select the external suite;
KVM-only selects 22 KVM/automatic/omitted pairs. External tests default to OFF;
an integration preset then fails with setup instructions, instead of silently
passing an empty suite. Disable them with `-DDAZE_EXTERNAL_TESTS=OFF` to restore
an offline local-only configuration.

Static variants use the same configure/build/test preset name:
`debug-static`, `release-static` and `kvm-only-static`.
Their integration presets append `-integration`, for example
`ctest --preset kvm-only-static-integration`. External checkout/Python options
are unchanged. Static means the Daze executable is fully linked statically;
the local test executables follow their existing link policy. ASan has no
fully static variant because AddressSanitizer does not support it.

## Coverage and CI

Labels distinguish `contract`, `smoke`, `check` and `external`; all local tests
carry `local`, and external regressions/setup carry `integration`. Contract
tests should provide high coverage independently of real applications: the
goals remain 90% line and 80% branch coverage, with measured non-regression
gates against the tracked [baseline](../docs/coverage-baseline.json).

After configuring and building `coverage` with both backends, install
[`tools/coverage-requirements.txt`](../tools/coverage-requirements.txt) in a
virtual environment and run `tools/coverage.py --profile portable` or
`--profile kvm` with that environment's Python. Reports are written to
`build/coverage/reports/<profile>/`. The KVM profile requires usable `/dev/kvm`.
Compiled production sources with executable lines must appear in the reports,
even when unexecuted. Data-only translation units have no executable coverage
lines; the gate verifies their GCC metadata before accepting their omission.

CI uses `threeal/gcovr-action` to generate reports with the same pinned gcovr
version and configuration as local runs. For each suite, `coverage.py --suite
contracts --stage prepare` (or `--suite local`) clears counters, runs tests
and writes `gcovr.cfg` in the report directory. The action runs there, then
`--stage report` checks the generated report against the production-source
inventory and subsystem baselines. Contract reports are checked before local
tests reset the counters. The default local command still performs all stages.

CI runs portable Unicorn regressions and coverage, dual-backend KVM coverage
and all 42 required pairs, and KVM-only local/external suites.
Ubuntu ARM64 and macOS ARM64 jobs build Unicorn's
x86 guest engine and run portable local tests and Unicorn external regressions.
They validate host portability without claiming KVM coverage. KVM jobs require
a runner with usable `/dev/kvm` and fail if VM creation is unavailable. Reports
and failed-run evidence are uploaded; benchmarks remain outside build gates.
`EnricoMi/publish-unit-test-result-action` publishes JUnit test summaries, and
`irongut/CodeCoverageSummary` renders line/branch coverage from gcovr's Cobertura
reports. These summaries run after failures when reports exist and write only
to the job summary. Contract and all-local results remain separate because
the suites overlap. Acceptance/preflight errors remain in the validation logs
and uploaded `acceptance.json`; subsystem baseline results remain in the
coverage gate logs and `subsystems.json`.
JUnit XML remains available for other report consumers. To browse full coverage,
download and extract the coverage artifact, then open `contracts/index.html`
or `local/index.html` locally with its accompanying files.

Tagged releases run these CI suites before building and publishing the binary
and Docker image. See [release packaging](../docs/RELEASING.md).
