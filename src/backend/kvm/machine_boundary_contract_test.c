#include "machine.h"
#include "machine_access.h"

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
#include <linux/kvm.h>
#include <sys/ioctl.h>

static void debug_exit(DazeKvmMachine *m, uint32_t expected) {
  const int status = daze_kvm_machine_run(m);
  const struct kvm_run *run = m->run;
  if (status == 0 && run->exit_reason == expected) return;
  struct kvm_regs regs = {0};
  struct kvm_sregs sregs = {0};
  const int r = ioctl(m->vcpu, KVM_GET_REGS, &regs);
  const int s = ioctl(m->vcpu, KVM_GET_SREGS, &sregs);
  fprintf(stderr,
          "debug cache: run=%d exit=%u expected=%u regs=%d/%d cs:ip=%04x:%llx "
          "ax=%llx flags=%llx\n",
          status, run->exit_reason, expected, r, s, sregs.cs.selector, (unsigned long long)regs.rip,
          (unsigned long long)regs.rax, (unsigned long long)regs.rflags);
  abort();
}

static void debugging(DazeKvmMachine *m) {
  struct kvm_guest_debug debug = {.control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_HW_BP};
  debug.arch.debugreg[0] = 5;
  debug.arch.debugreg[7] = 3;
  assert(daze_kvm_machine_set_guest_debug(NULL, &debug) == -1);
  assert(daze_kvm_machine_set_guest_debug(m, NULL) == -1);
  DazeKvmMachine invalid = *m;
  invalid.vcpu = -1;
  assert(daze_kvm_machine_set_guest_debug(&invalid, &debug) == -1);
  for (unsigned mode = 0; mode < 3; ++mode) {
    DazeRunMetrics metrics = {.enabled = mode == 2};
    daze_kvm_machine_set_run_metrics(m, mode == 0 ? NULL : &metrics);
    const uint8_t code[] = {0xe6, 0xf4, /* out 0xf4,al */
                            0x90,       /* nop */
                            0xe6, 0xf4, /* out 0xf4,al */
                            0x90,       /* nop */
                            0xf4};      /* hlt */
    memcpy(m->guest, code, sizeof(code));
    assert(daze_kvm_machine_set_real_mode(m, 0, 0, 0, 0x8000, 0, 0) == 0);
    assert(daze_kvm_machine_set_guest_debug(m, &debug) == 0);
    assert(daze_kvm_machine_set_guest_debug(m, &debug) == 0);
    assert(metrics.kvm_dpmi_debug_update_calls == (mode == 2 ? 2u : 0u));
    debug_exit(m, KVM_EXIT_IO);
    assert(daze_kvm_machine_set_guest_debug(m, &debug) == 0);
    assert(metrics.kvm_debug_update_elisions == (mode == 2 ? 1u : 0u));
    debug.arch.debugreg[0] = 6;
    assert(daze_kvm_machine_set_guest_debug(m, &debug) == 0);
    debug.arch.debugreg[0] = 5;
    assert(daze_kvm_machine_set_guest_debug(m, &debug) == 0);
    assert(metrics.kvm_dpmi_debug_update_calls == (mode == 2 ? 4u : 0u));
    debug_exit(m, KVM_EXIT_IO);
    assert(daze_kvm_machine_set_guest_debug(m, &debug) == 0);
    assert(metrics.kvm_debug_update_elisions == (mode == 2 ? 2u : 0u));
    debug_exit(m, KVM_EXIT_DEBUG);
    assert(((struct kvm_run *)m->run)->debug.arch.pc == 5);
    assert(!m->debug_breakpoint_known && !m->debug_io_exit);
    assert(daze_kvm_machine_set_guest_debug(m, &debug) == 0);
    struct kvm_guest_debug disabled = {0};
    assert(daze_kvm_machine_set_guest_debug(m, &disabled) == 0);
    assert(daze_kvm_machine_set_guest_debug(m, &disabled) == 0);
    assert(metrics.kvm_dpmi_debug_update_calls == (mode == 2 ? 7u : 0u));
    debug_exit(m, KVM_EXIT_HLT);
    assert(!m->debug_breakpoint_known && !m->debug_io_exit);
    struct kvm_guest_debug stepping = {.control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_SINGLESTEP};
    assert(daze_kvm_machine_set_guest_debug(m, &stepping) == 0);
    assert(daze_kvm_machine_set_guest_debug(m, &stepping) == 0);
    assert(metrics.kvm_dpmi_debug_update_calls == (mode == 2 ? 9u : 0u));
    assert(daze_kvm_machine_set_guest_debug(m, &disabled) == 0);
  }
  daze_kvm_machine_set_run_metrics(m, NULL);
  DazeKvmMachine failed = *m;
  failed.vcpu = m->kvm;
  failed.debug_breakpoint_known = failed.debug_io_exit = 1;
  failed.debug_breakpoint = 6;
  assert(daze_kvm_machine_set_guest_debug(&failed, &debug) == -1);
  assert(!failed.debug_breakpoint_known);
  failed.debug_breakpoint_known = failed.debug_io_exit = 1;
  assert(daze_kvm_machine_run(&failed) == -1);
  assert(!failed.debug_breakpoint_known && !failed.debug_io_exit);
}

static void registers(DazeKvmMachine *m) {
  struct kvm_regs r, before, after;
  struct kvm_sregs s, sbefore, safter;
  assert(ioctl(m->vcpu, KVM_GET_REGS, &before) == 0);
  assert(ioctl(m->vcpu, KVM_GET_SREGS, &sbefore) == 0);
  for (unsigned kind = 0; kind < 4; ++kind) {
    DazeKvmMachine bad = *m;
    if (kind == 2) bad.vcpu = -1;
    if (kind == 3) bad.run = NULL;
    DazeKvmMachine *arg = kind == 0 ? NULL : &bad;
    memset(&r, 0xa5, sizeof(r));
    memset(&s, 0x5a, sizeof(s));
    struct kvm_regs saved = r;
    struct kvm_sregs ssaved = s;
    assert(daze_kvm_machine_get_regs(arg, kind == 1 ? NULL : &r) == DAZE_KVM_MACHINE_INVALID);
    assert(daze_kvm_machine_get_sregs(arg, kind == 1 ? NULL : &s) == DAZE_KVM_MACHINE_INVALID);
    assert(daze_kvm_machine_set_regs(arg, kind == 1 ? NULL : &r) == DAZE_KVM_MACHINE_INVALID);
    assert(daze_kvm_machine_set_sregs(arg, kind == 1 ? NULL : &s) == DAZE_KVM_MACHINE_INVALID);
    assert(memcmp(&saved, &r, sizeof(r)) == 0 && memcmp(&ssaved, &s, sizeof(s)) == 0);
    if (kind != 1) assert(daze_kvm_machine_sync_refresh(arg) == DAZE_KVM_MACHINE_INVALID);
  }
  assert(ioctl(m->vcpu, KVM_GET_REGS, &after) == 0 && memcmp(&before, &after, sizeof(after)) == 0);
  assert(ioctl(m->vcpu, KVM_GET_SREGS, &safter) == 0 &&
         memcmp(&sbefore, &safter, sizeof(safter)) == 0);
  const int mask = m->sync_regs_mask;
  for (unsigned mode = 0; mode < 3; ++mode) {
    DazeRunMetrics metrics = {.enabled = mode == 2};
    daze_kvm_machine_set_run_metrics(m, mode == 0 ? NULL : &metrics);
    for (unsigned sync = 0; sync < 2; ++sync) {
      m->sync_regs_mask = sync ? mask : 0;
      assert(daze_kvm_machine_sync_refresh(m) == DAZE_KVM_MACHINE_OK);
      assert(daze_kvm_machine_get_regs(m, &r) == DAZE_KVM_MACHINE_OK);
      assert(daze_kvm_machine_get_sregs(m, &s) == DAZE_KVM_MACHINE_OK);
      assert(ioctl(m->vcpu, KVM_GET_REGS, &before) == 0 && memcmp(&r, &before, sizeof(r)) == 0);
      assert(ioctl(m->vcpu, KVM_GET_SREGS, &sbefore) == 0 && memcmp(&s, &sbefore, sizeof(s)) == 0);
      r.rax = 0x4321 + mode * 2 + sync;
      r.rip = 0;
      s.ds.selector = (uint16_t)(0x123 + mode * 2 + sync);
      s.ds.base = (uint64_t)s.ds.selector << 4;
      m->debug_breakpoint_known = m->debug_io_exit = 1;
      assert(daze_kvm_machine_set_regs(m, &r) == DAZE_KVM_MACHINE_OK);
      assert(!m->debug_breakpoint_known && !m->debug_io_exit);
      m->debug_breakpoint_known = m->debug_io_exit = 1;
      assert(daze_kvm_machine_set_sregs(m, &s) == DAZE_KVM_MACHINE_OK);
      assert(!m->debug_breakpoint_known && !m->debug_io_exit);
      ((uint8_t *)m->guest)[0] = 0xf4; /* hlt */
      assert(ioctl(m->vcpu, KVM_RUN, 0) == 0);
      assert(((struct kvm_run *)m->run)->exit_reason == KVM_EXIT_HLT);
      assert(ioctl(m->vcpu, KVM_GET_REGS, &after) == 0 && after.rax == r.rax && after.rip == 1);
      assert(ioctl(m->vcpu, KVM_GET_SREGS, &safter) == 0 && safter.ds.selector == s.ds.selector &&
             safter.ds.base == s.ds.base);
    }
    const unsigned classes = !!(mask & KVM_SYNC_X86_REGS) + !!(mask & KVM_SYNC_X86_SREGS);
    assert(metrics.kvm_regs_sync_get_calls == (mode == 2 ? classes : 0));
    assert(metrics.kvm_regs_sync_set_calls == (mode == 2 ? classes : 0));
  }
  m->sync_regs_mask = mask;
  daze_kvm_machine_set_run_metrics(m, NULL);
  daze_kvm_machine_set_run_metrics(NULL, NULL);
}

static void snapshots(DazeKvmMachine *m) {
  DazeKvmMachineSnapshot snapshot = {0};
  assert(daze_kvm_machine_snapshot_take(m, &snapshot) == DAZE_KVM_MACHINE_OK);
  ((uint8_t *)m->guest)[0x500] = 0x7b;
  assert(daze_kvm_machine_set_general_registers(m, 1, 2, 3, 4, 5, 6) == DAZE_KVM_MACHINE_OK);
  assert(daze_kvm_machine_snapshot_take(m, &snapshot) == DAZE_KVM_MACHINE_OK);
  assert(snapshot.valid && snapshot.guest_size == m->guest_size &&
         ((uint8_t *)snapshot.guest_bytes)[0x500] == 0x7b);
  struct kvm_regs before, after;
  struct kvm_sregs sbefore, safter;
  assert(ioctl(m->vcpu, KVM_GET_REGS, &before) == 0);
  assert(ioctl(m->vcpu, KVM_GET_SREGS, &sbefore) == 0);
  for (unsigned kind = 0; kind < 9; ++kind) {
    DazeKvmMachine machine = *m;
    DazeKvmMachineSnapshot bad = snapshot;
    if (kind == 2) bad.valid = 0;
    if (kind == 3) machine.guest = NULL;
    if (kind == 4) machine.vcpu = -1;
    if (kind == 5) bad.guest_bytes = NULL;
    if (kind == 6) bad.cpu_state = NULL;
    if (kind == 7) bad.guest_size--;
    if (kind == 8) machine.guest_size = 0;
    assert(daze_kvm_machine_snapshot_restore(kind == 0 ? NULL : &machine,
                                             kind == 1 ? NULL : &bad) == DAZE_KVM_MACHINE_INVALID);
    assert(ioctl(m->vcpu, KVM_GET_REGS, &after) == 0 &&
           memcmp(&before, &after, sizeof(after)) == 0);
    assert(ioctl(m->vcpu, KVM_GET_SREGS, &safter) == 0 &&
           memcmp(&sbefore, &safter, sizeof(safter)) == 0);
    assert(memcmp(m->guest, snapshot.guest_bytes, m->guest_size) == 0);
  }
  for (unsigned kind = 0; kind < 5; ++kind) {
    DazeKvmMachine bad = *m;
    if (kind == 2) bad.guest = NULL;
    if (kind == 3) bad.vcpu = -1;
    if (kind == 4) bad.guest_size = 0;
    const DazeKvmMachineSnapshot saved = snapshot;
    assert(daze_kvm_machine_snapshot_take(kind == 0 ? NULL : &bad, kind == 1 ? NULL : &snapshot) ==
           DAZE_KVM_MACHINE_INVALID);
    assert(memcmp(&snapshot, &saved, sizeof(saved)) == 0);
  }
  ((uint8_t *)m->guest)[0x500] = 0;
  assert(daze_kvm_machine_set_general_registers(m, 9, 9, 9, 9, 9, 9) == DAZE_KVM_MACHINE_OK);
  m->debug_breakpoint_known = m->debug_io_exit = 1;
  assert(daze_kvm_machine_snapshot_restore(m, &snapshot) == DAZE_KVM_MACHINE_OK);
  assert(!m->debug_breakpoint_known && !m->debug_io_exit);
  assert(memcmp(m->guest, snapshot.guest_bytes, m->guest_size) == 0);
  assert(ioctl(m->vcpu, KVM_GET_REGS, &after) == 0 && memcmp(&before, &after, sizeof(after)) == 0);
  assert(daze_kvm_machine_sync_refresh(m) == DAZE_KVM_MACHINE_OK);
  assert(daze_kvm_machine_get_regs(m, &after) == DAZE_KVM_MACHINE_OK &&
         memcmp(&before, &after, sizeof(after)) == 0);
  daze_kvm_machine_snapshot_dispose(&snapshot);
  assert(!snapshot.valid && !snapshot.guest_bytes && !snapshot.cpu_state && !snapshot.guest_size);
  daze_kvm_machine_snapshot_dispose(&snapshot);
  daze_kvm_machine_snapshot_dispose(NULL);
}

static void ports(DazeKvmMachine *m) {
  const uint8_t programs[][9] = {
    {0xf4},             /* hlt */
    {0xe7, 0x21, 0xf4}, /* out 0x21,ax; hlt */
  };
  for (unsigned kind = 0; kind < 2; ++kind) {
    memcpy(m->guest, programs[kind], sizeof(programs[kind]));
    assert(daze_kvm_machine_set_real_mode(m, 0, 0, 0, 0x8000, 0, 0) == DAZE_KVM_MACHINE_OK);
    DazeKvmPortAccess access;
    memset(&access, 0xa5, sizeof(access));
    assert(daze_kvm_machine_run_port_access(m, &access) == DAZE_KVM_MACHINE_FAILED);
    assert(access.direction == 0 && access.port == 0 && access.value == 0);
    struct kvm_run *run = m->run;
    assert(kind == 0 ? run->exit_reason == KVM_EXIT_HLT : run->exit_reason == KVM_EXIT_IO);
    if (kind == 1) assert(run->io.size == 2);
    assert(daze_kvm_machine_supply_port_in(m, 0x7b) == DAZE_KVM_MACHINE_FAILED);
    if (kind == 1) {
      /* Complete the pending OUT before installing another independent guest. */
      assert(ioctl(m->vcpu, KVM_RUN, 0) == 0);
      assert(run->exit_reason == KVM_EXIT_HLT);
    }
  }
  const uint8_t input[] = {0xe4, 0x21, 0xa2, 0, 5, 0xf4}; /* in al,0x21; mov [0x500],al; hlt */
  memcpy(m->guest, input, sizeof(input));
  assert(daze_kvm_machine_set_real_mode(m, 0, 0, 0, 0x8000, 0, 0) == DAZE_KVM_MACHINE_OK);
  DazeKvmPortAccess access;
  assert(daze_kvm_machine_run_port_access(m, &access) == DAZE_KVM_MACHINE_OK);
  struct kvm_run *run = m->run;
  const unsigned size = run->io.size;
  const unsigned count = run->io.count;
  uint8_t *data = (uint8_t *)run + run->io.data_offset;
  const uint8_t saved = *data;
  run->io.size = 2;
  assert(daze_kvm_machine_supply_port_in(m, 0x7b) == DAZE_KVM_MACHINE_FAILED && *data == saved);
  run->io.size = size;
  run->io.count = 2;
  assert(daze_kvm_machine_supply_port_in(m, 0x7b) == DAZE_KVM_MACHINE_FAILED && *data == saved);
  run->io.count = count;
  assert(daze_kvm_machine_supply_port_in(m, 0x7b) == DAZE_KVM_MACHINE_OK);
  assert(daze_kvm_machine_run_port_access(m, &access) == DAZE_KVM_MACHINE_FAILED);
  assert(((uint8_t *)m->guest)[0x500] == 0x7b);
  DazeKvmMachine absent = *m;
  absent.run = NULL;
  assert(daze_kvm_machine_run_port_access(NULL, &access) == DAZE_KVM_MACHINE_INVALID);
  assert(daze_kvm_machine_run_port_access(&absent, &access) == DAZE_KVM_MACHINE_INVALID);
  assert(daze_kvm_machine_run_port_access(m, NULL) == DAZE_KVM_MACHINE_INVALID);
  assert(daze_kvm_machine_supply_port_in(NULL, 0) == DAZE_KVM_MACHINE_INVALID);
  assert(daze_kvm_machine_supply_port_in(&absent, 0) == DAZE_KVM_MACHINE_INVALID);
}

int main(void) {
  DazeKvmMachine m;
  const int status = daze_kvm_machine_init(&m, 0x10000);
  if (status == DAZE_KVM_MACHINE_UNAVAILABLE) return 77;
  assert(status == DAZE_KVM_MACHINE_OK);
  assert(daze_kvm_machine_set_real_mode(&m, 0, 0, 0, 0x8000, 0, 0) == DAZE_KVM_MACHINE_OK);
  registers(&m);
  snapshots(&m);
  ports(&m);
  debugging(&m);
  daze_kvm_machine_destroy(&m);
  daze_kvm_machine_destroy(&m);
  daze_kvm_machine_destroy(NULL);
  return 0;
}
#else
int main(void) {
  return 77;
}
#endif
