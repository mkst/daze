#define ioctl drain_ioctl
#include "machine.c"
#undef ioctl

#include <stdio.h>

#define CHECK(c)                                                                                   \
  do {                                                                                             \
    if (!(c)) {                                                                                    \
      fprintf(stderr, "I/O drain contract line=%d\n", __LINE__);                                   \
      abort();                                                                                     \
    }                                                                                              \
  } while (0)

#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
static struct kvm_run run;
static int run_status, run_errno;
static unsigned calls;

int drain_ioctl(int fd, unsigned long request, ...) {
  CHECK(fd == 3 && request == KVM_RUN && run.immediate_exit == 1);
  calls++;
  errno = run_errno;
  return run_status;
}

int main(void) {
  for (unsigned kind = 0; kind < 7; ++kind) {
    run = (struct kvm_run){0};
    DazeKvmMachine machine = {
      .vcpu = 3, .run = &run, .run_size = sizeof(run), .immediate_exit_supported = 1};
    calls = 0;
    if (kind == 1) machine.vcpu = -1;
    if (kind == 2) machine.run = NULL;
    if (kind == 3) machine.run_size = 1;
    if (kind == 4) machine.immediate_exit_supported = 0;
    if (kind == 5) run.immediate_exit = 1;
    if (kind == 6) run.kvm_dirty_regs = KVM_SYNC_X86_REGS;
    CHECK(daze_kvm_machine_drain_io(kind == 0 ? NULL : &machine) == DAZE_KVM_MACHINE_INVALID);
    CHECK(calls == 0 && run.immediate_exit == (kind == 5));
    CHECK(run.kvm_dirty_regs == (kind == 6 ? KVM_SYNC_X86_REGS : 0));
    CHECK(errno == (kind >= 5 ? EBUSY : EINVAL));
  }
  for (unsigned metrics_mode = 0; metrics_mode < 3; ++metrics_mode) {
    for (unsigned kind = 0; kind < 3; ++kind) {
      run = (struct kvm_run){.exit_reason = KVM_EXIT_DEBUG};
      DazeRunMetrics metrics = {.enabled = metrics_mode == 2};
      DazeKvmMachine machine = {.vcpu = 3,
                                .run = &run,
                                .run_size = sizeof(run),
                                .immediate_exit_supported = 1,
                                .run_metrics = metrics_mode == 0 ? NULL : &metrics,
                                .debug_breakpoint_known = 1,
                                .debug_io_exit = 1};
      calls = 0;
      run_status = kind == 2 ? 0 : -1;
      run_errno = kind == 1 ? EIO : EINTR;
      CHECK(daze_kvm_machine_drain_io(&machine) ==
            (kind == 0 ? DAZE_KVM_MACHINE_OK : DAZE_KVM_MACHINE_FAILED));
      CHECK(calls == 1 && run.immediate_exit == 0);
      CHECK(!machine.debug_breakpoint_known && !machine.debug_io_exit);
      CHECK(metrics.kvm_io_drain_calls == (metrics_mode == 2));
      CHECK(metrics.kvm_io_drain_failures == (uint64_t)(metrics_mode == 2 && kind != 0));
      CHECK(errno == (kind == 2 ? EPROTO : run_errno));
    }
  }
  return 0;
}
#else
int main(void) {
  return 0;
}
#endif
