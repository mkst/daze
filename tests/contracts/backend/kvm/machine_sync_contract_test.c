/* Sync-regs vs ioctl equivalence: after a real KVM_RUN the shared sync area
 * must match fresh ioctl reads, pushes via dirty bits must take effect, and
 * a cleared capability mask must fall back to ioctls transparently. */
#include "machine.h"
#include "machine_access.h"

#include <stdio.h>
#include <string.h>

#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
#include <linux/kvm.h>
#include <sys/ioctl.h>

static int check(const char *label, int ok) {
  if (!ok) fprintf(stderr, "KVM sync contract: FAIL %s\n", label);
  return ok;
}

int main(void) {
  DazeKvmMachine machine;
  const int init = daze_kvm_machine_init(&machine, 0x10000);
  if (init == DAZE_KVM_MACHINE_UNAVAILABLE) return 77;
  if (init != DAZE_KVM_MACHINE_OK) return 1;
  int pass = 1;
  DazeRunMetrics metrics = {.enabled = 1};
  daze_kvm_machine_set_run_metrics(&machine, &metrics);
  if (machine.sync_regs_mask == 0) {
    /* Nothing to compare on kernels without the capability; the fallback
     * path is the long-covered ioctl behavior. */
    daze_kvm_machine_destroy(&machine);
    return 77;
  }
  uint8_t *const guest = machine.guest;
  /* mov ax,0x1234; hlt */
  guest[0] = 0xb8;
  guest[1] = 0x34;
  guest[2] = 0x12;
  guest[3] = 0xf4;
  if (daze_kvm_machine_set_real_mode(&machine, 0, 0, 0, 0x8000, 0, 0) != DAZE_KVM_MACHINE_OK) {
    daze_kvm_machine_destroy(&machine);
    return 1;
  }
  struct kvm_run *const run = machine.run;
  if (ioctl(machine.vcpu, KVM_RUN, 0) < 0 || run->exit_reason != KVM_EXIT_HLT) {
    fprintf(stderr, "KVM sync contract: FAIL setup run\n");
    daze_kvm_machine_destroy(&machine);
    return 1;
  }
  /* Sync reads match fresh ioctl reads after a real exit. */
  struct kvm_regs via_sync, via_ioctl;
  struct kvm_sregs via_sync_s, via_ioctl_s;
  pass = check("sync get regs", daze_kvm_machine_get_regs(&machine, &via_sync) == 0) && pass;
  pass = check("sync get sregs", daze_kvm_machine_get_sregs(&machine, &via_sync_s) == 0) && pass;
  pass = check("ioctl get regs", ioctl(machine.vcpu, KVM_GET_REGS, &via_ioctl) == 0) && pass;
  pass = check("ioctl get sregs", ioctl(machine.vcpu, KVM_GET_SREGS, &via_ioctl_s) == 0) && pass;
  pass = check("regs match", memcmp(&via_sync, &via_ioctl, sizeof(via_sync)) == 0) && pass;
  pass = check("sregs match", memcmp(&via_sync_s, &via_ioctl_s, sizeof(via_sync_s)) == 0) && pass;
  pass = check("sync gets counted", metrics.kvm_regs_sync_get_calls == 2) && pass;
  pass = check("halted past hlt", via_sync.rip == 4 && (via_sync.rax & 0xffffu) == 0x1234) && pass;
  /* Push via dirty bits only, verify through the ioctl path. */
  via_sync.rip = 0;
  via_sync.rax = 0;
  pass = check("sync set regs", daze_kvm_machine_set_regs(&machine, &via_sync) == 0) && pass;
  pass = check("sync sets counted", metrics.kvm_regs_sync_set_calls == 1) && pass;
  if (ioctl(machine.vcpu, KVM_RUN, 0) < 0 || run->exit_reason != KVM_EXIT_HLT) {
    fprintf(stderr, "KVM sync contract: FAIL rerun\n");
    daze_kvm_machine_destroy(&machine);
    return 1;
  }
  pass = check("push took effect", ioctl(machine.vcpu, KVM_GET_REGS, &via_ioctl) == 0 &&
                                     via_ioctl.rip == 4 && (via_ioctl.rax & 0xffffu) == 0x1234) &&
         pass;
  /* Cleared mask falls back to ioctls transparently. */
  machine.sync_regs_mask = 0;
  pass = check("fallback get regs", daze_kvm_machine_get_regs(&machine, &via_sync) == 0) && pass;
  pass = check("fallback matches", ioctl(machine.vcpu, KVM_GET_REGS, &via_ioctl) == 0 &&
                                     memcmp(&via_sync, &via_ioctl, sizeof(via_sync)) == 0) &&
         pass;
  daze_kvm_machine_destroy(&machine);
  fprintf(stderr, "KVM sync contract: %s\n", pass ? "passed" : "failed");
  return pass ? 0 : 1;
}
#else
int main(void) {
  fprintf(stderr, "KVM sync contract: no KVM build\n");
  return 77;
}
#endif
