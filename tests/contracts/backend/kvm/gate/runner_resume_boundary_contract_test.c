#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
#include <linux/kvm.h>
#include <stdarg.h>
#include <sys/ioctl.h>

static unsigned set_sregs_calls;

static int counted_ioctl(int fd, unsigned long request, ...) {
  va_list args;
  va_start(args, request);
  const unsigned long argument = va_arg(args, unsigned long);
  va_end(args);
  if (request == KVM_SET_SREGS) set_sregs_calls++;
  return ioctl(fd, request, argument);
}

#define ioctl counted_ioctl
#endif

#include "backend/kvm/gate/runner_resume.c"

#undef ioctl

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

#define CHECK(c)                                                                                   \
  do {                                                                                             \
    if (!(c)) {                                                                                    \
      fprintf(stderr, "resume boundary failed at %d\n", __LINE__);                                 \
      abort();                                                                                     \
    }                                                                                              \
  } while (0)

#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
static void guest_ax_reply(void) {
  uint8_t guest[0x2000] = {0}, reply[16] = {0};
  struct kvm_run run = {0};
  DazeKvmMachine machine = {.vcpu = INT_MAX,
                            .guest = guest,
                            .guest_size = sizeof(guest),
                            .run = &run,
                            .sync_regs_mask = KVM_SYNC_X86_REGS | KVM_SYNC_X86_SREGS};
  run.s.regs.regs = (struct kvm_regs){.rip = 3, .rsp = 0x100, .rax = 0x12340021};
  run.s.regs.sregs.cs.base = 0x1000;
  run.s.regs.sregs.ss = (struct kvm_segment){.selector = 0x20, .base = 0x200};
  real_data_segment(&run.s.regs.sregs.es, 0x40);
  const uint8_t gate[] = {
    0x50,       /* push ax */
    0xb0, 0x21, /* mov al,21h */
    0xe6, 0xf4, /* out f4h,al */
    0x58,       /* pop ax */
    0xcf,       /* iret */
  };
  memcpy(guest + 0x1000, gate, sizeof(gate));
  const DazeKvmRunnerGateFrame frame = {.vector = 0x21, .ss = 0x20, .sp = 0x100};
  daze_write_u16(reply, 0xabcd);
  daze_write_u16(reply + 12, 0x40);
  daze_write_u16(reply + 14, 0x246);
  const struct kvm_regs before = run.s.regs.regs;
  CHECK(daze_kvm_runner_gate_frame_reply(&machine, &frame, reply) ==
        DAZE_KVM_RUNNER_GATE_RESUME_OK);
  CHECK(daze_read_u16(guest + 0x300) == 0xabcd && daze_read_u16(guest + 0x306) == 0x246);
  CHECK(memcmp(&run.s.regs.regs, &before, sizeof(before)) == 0 && run.kvm_dirty_regs == 0);
  for (unsigned kind = 0; kind < 17; ++kind) {
    real_data_segment(&run.s.regs.sregs.es, 0x40);
    run.s.regs.sregs.es.dpl = 0;
    run.s.regs.sregs.cr0 = kind == 2 ? 1 : 0;
    run.s.regs.regs.rflags = kind == 3 ? 1u << 17 : 0;
    switch (kind) {
    case 1:
      run.s.regs.sregs.es.dpl = 3;
      break;
    case 4:
      run.s.regs.sregs.es.dpl = 1;
      break;
    case 5:
      run.s.regs.sregs.es.dpl = 2;
      break;
    case 6:
      run.s.regs.sregs.es.base++;
      break;
    case 7:
      run.s.regs.sregs.es.limit++;
      break;
    case 8:
      run.s.regs.sregs.es.selector++;
      break;
    case 9:
      run.s.regs.sregs.es.type = 7;
      break;
    case 10:
      run.s.regs.sregs.es.present = 0;
      break;
    case 11:
      run.s.regs.sregs.es.db = 1;
      break;
    case 12:
      run.s.regs.sregs.es.unusable = 1;
      break;
    case 13:
      run.s.regs.sregs.es.g = 1;
      break;
    case 14:
      run.s.regs.sregs.es.l = 1;
      break;
    case 15:
      run.s.regs.sregs.es.avl = 1;
      break;
    case 16:
      run.s.regs.sregs.es.s = 0;
      break;
    }
    const struct kvm_sregs saved = run.s.regs.sregs;
    const unsigned setters = set_sregs_calls;
    CHECK(daze_kvm_runner_gate_frame_reply(&machine, &frame, reply) ==
          (kind < 2 ? DAZE_KVM_RUNNER_GATE_RESUME_OK : DAZE_KVM_RUNNER_GATE_RESUME_FAILED));
    CHECK(set_sregs_calls == setters + (kind >= 2));
    CHECK(memcmp(&saved, &run.s.regs.sregs, sizeof(saved)) == 0 && run.kvm_dirty_regs == 0);
  }
  run.s.regs.regs = before;
  run.s.regs.sregs.cr0 = 0;
  real_data_segment(&run.s.regs.sregs.es, 0x40);
  daze_write_u16(reply + 2, 1);
  CHECK(daze_kvm_runner_gate_frame_reply(&machine, &frame, reply) ==
        DAZE_KVM_RUNNER_GATE_RESUME_FAILED);
  daze_write_u16(reply + 2, 0);
  for (int kind = 0; kind < 4; ++kind) {
    run.s.regs.regs.rip = kind == 0 ? 2 : 3;
    run.s.regs.sregs.cs.base = kind == 1 ? UINT64_C(0x100000000) : 0x1000;
    machine.guest_size = kind == 2 ? 0x1006 : sizeof(guest);
    if (kind == 3) guest[0x1005] = 0x90;
    CHECK(daze_kvm_runner_gate_frame_reply(&machine, &frame, reply) ==
          DAZE_KVM_RUNNER_GATE_RESUME_FAILED);
  }
}

static void rejected_inputs(void) {
  uint8_t guest[256] = {0}, reply[16] = {0};
  struct kvm_run run = {0};
  DazeKvmMachine machine = {
    .vcpu = INT_MAX, .guest = guest, .guest_size = sizeof(guest), .run = &run};
  DazeKvmRunnerGateFrame frame = {0};
  for (int kind = 0; kind < 5; ++kind) {
    DazeKvmMachine bad = machine;
    if (kind == 1) bad.vcpu = -1;
    if (kind == 2) bad.guest = NULL;
    DazeKvmMachine *m = kind == 0 ? NULL : &bad;
    if (kind < 4) {
      memset(&frame, 0xa5, sizeof(frame));
      CHECK(daze_kvm_runner_gate_frame_capture(m, 0x21, kind == 3 ? NULL : &frame) ==
            DAZE_KVM_RUNNER_GATE_RESUME_INVALID);
      if (kind != 3) CHECK(frame.ax == 0 && frame.return_ip == 0);
    }
    CHECK(
      daze_kvm_runner_gate_frame_reply(m, kind == 3 ? NULL : &frame, kind == 4 ? NULL : reply) ==
      DAZE_KVM_RUNNER_GATE_RESUME_INVALID);
    if (kind < 3)
      CHECK(daze_kvm_runner_gate_frame_retire_out(m) == DAZE_KVM_RUNNER_GATE_RESUME_INVALID);
    if (kind < 2)
      CHECK(daze_kvm_runner_gate_frame_set_ds(m, 0x1234) == DAZE_KVM_RUNNER_GATE_RESUME_INVALID);
  }
  CHECK(daze_kvm_runner_gate_frame_capture(&machine, 0x21, &frame) ==
        DAZE_KVM_RUNNER_GATE_RESUME_FAILED);
  CHECK(daze_kvm_runner_gate_frame_reply(&machine, &frame, reply) ==
        DAZE_KVM_RUNNER_GATE_RESUME_INVALID);
  CHECK(daze_kvm_runner_gate_frame_retire_out(&machine) == DAZE_KVM_RUNNER_GATE_RESUME_FAILED);
  CHECK(daze_kvm_runner_gate_frame_set_ds(&machine, 0x1234) == DAZE_KVM_RUNNER_GATE_RESUME_FAILED);
  DazeKvmRunnerDpmiHandoff handoff = {.valid = 1};
  DazeKvmRunnerGateResumeInput input = {
    .machine = &machine, .handoff = &handoff, .mailbox_address = 32};
  for (int kind = 0; kind < 8; ++kind) {
    DazeKvmRunnerGateResumeInput bad = input;
    DazeKvmMachine bad_machine = machine;
    DazeKvmRunnerDpmiHandoff bad_handoff = handoff;
    bad.machine = &bad_machine;
    bad.handoff = &bad_handoff;
    switch (kind) {
    case 0:
      bad.machine = NULL;
      break;
    case 1:
      bad_machine.vcpu = -1;
      break;
    case 2:
      bad_machine.run = NULL;
      break;
    case 3:
      bad.handoff = NULL;
      break;
    case 4:
      bad_handoff.valid = 0;
      break;
    case 5:
      bad_machine.guest = NULL;
      break;
    case 6:
      bad.mailbox_address = sizeof(guest) - 15;
      break;
    case 7:
      bad.mailbox_address = UINT32_MAX;
      break;
    }
    uint8_t before[256];
    memcpy(before, guest, sizeof(guest));
    CHECK(!daze_kvm_runner_gate_resume_input_valid(&bad));
    CHECK(daze_kvm_runner_gate_reply(&bad) == DAZE_KVM_RUNNER_GATE_RESUME_INVALID);
    DazeKvmRunnerGateResumeResult result;
    memset(&result, 0xa5, sizeof(result));
    CHECK(daze_kvm_runner_gate_resume_hlt(&bad, &result) == DAZE_KVM_RUNNER_GATE_RESUME_INVALID);
    CHECK(result.ax == 0 && result.rip == 0 && memcmp(before, guest, sizeof(guest)) == 0);
  }
  CHECK(!daze_kvm_runner_gate_resume_input_valid(NULL));
  CHECK(daze_kvm_runner_gate_resume_hlt(&input, NULL) == DAZE_KVM_RUNNER_GATE_RESUME_INVALID);
  DazeKvmRunnerGateResumeResult result;
  CHECK(daze_kvm_runner_gate_resume_hlt(&input, &result) == DAZE_KVM_RUNNER_GATE_RESUME_FAILED);
  CHECK(result.rip == 0 && result.ax == 0);
  uint64_t calls = 0, elapsed = 7;
  DazeRunMetrics metrics = {0};
  record_gate_time(NULL, 0, &calls, &elapsed);
  record_gate_time(&metrics, 0, &calls, &elapsed);
  CHECK(calls == 0 && elapsed == 7);
  metrics.enabled = 1;
  record_gate_time(&metrics, UINT64_MAX, &calls, &elapsed);
  CHECK(calls == 1 && elapsed == 7);
}

static int cpu_boundaries(void) {
  DazeKvmMachine machine;
  int status = daze_kvm_machine_init(&machine, 0x20000);
  if (status == DAZE_KVM_MACHINE_UNAVAILABLE) return 77;
  CHECK(status == DAZE_KVM_MACHINE_OK);
  CHECK(daze_kvm_machine_set_real_mode(&machine, 0x100, 0, 0x200, 0x100, 0x300, 0x400) ==
        DAZE_KVM_MACHINE_OK);
  uint8_t *guest = machine.guest;
  const uint8_t frame_bytes[8] = {0x34, 0x12, 0x78, 0x56, 0xbc, 0x9a, 0x46, 0x02};
  memcpy(guest + 0x2100, frame_bytes, 8);
  struct kvm_regs regs;
  struct kvm_sregs sregs;
  CHECK(ioctl(machine.vcpu, KVM_GET_REGS, &regs) == 0);
  regs.rax = UINT64_C(0x123456780001);
  regs.rbx = UINT64_C(0x223456780002);
  regs.rcx = UINT64_C(0x323456780003);
  regs.rdx = UINT64_C(0x423456780004);
  regs.rsi = UINT64_C(0x523456780005);
  regs.rdi = UINT64_C(0x623456780006);
  CHECK(ioctl(machine.vcpu, KVM_SET_REGS, &regs) == 0);
  CHECK(daze_kvm_machine_sync_refresh(&machine) == DAZE_KVM_MACHINE_OK);
  DazeRunMetrics metrics = {.enabled = 1};
  machine.run_metrics = &metrics;
  DazeKvmRunnerGateFrame frame;
  CHECK(daze_kvm_runner_gate_frame_capture(&machine, 0x21, &frame) ==
        DAZE_KVM_RUNNER_GATE_RESUME_OK);
  CHECK(frame.ax == 0x1234 && frame.return_ip == 0x5678 && frame.return_cs == 0x9abc &&
        frame.flags == 0x246);
  CHECK(metrics.kvm_gate_frame_capture_calls == 1);
  uint8_t reply[16] = {0};
  for (size_t i = 0; i < 8; ++i)
    daze_write_u16(reply + 2 * i, 0x1100 + i);
  struct kvm_regs before = regs;
  uint8_t saved[8];
  memcpy(saved, guest + 0x2100, 8);
  for (int kind = 0; kind < 3; ++kind) {
    DazeKvmRunnerGateFrame bad = frame;
    if (kind == 0) bad.ss++;
    if (kind == 1) bad.sp++;
    size_t saved_size = machine.guest_size;
    if (kind == 2) machine.guest_size = 0x2107;
    CHECK(daze_kvm_runner_gate_frame_reply(&machine, &bad, reply) ==
          DAZE_KVM_RUNNER_GATE_RESUME_INVALID);
    CHECK(memcmp(saved, guest + 0x2100, 8) == 0);
    CHECK(ioctl(machine.vcpu, KVM_GET_REGS, &regs) == 0 &&
          memcmp(&regs, &before, sizeof(regs)) == 0);
    machine.guest_size = saved_size;
  }
  CHECK(daze_kvm_runner_gate_frame_reply(&machine, &frame, reply) ==
        DAZE_KVM_RUNNER_GATE_RESUME_OK);
  CHECK(ioctl(machine.vcpu, KVM_GET_REGS, &regs) == 0 &&
        ioctl(machine.vcpu, KVM_GET_SREGS, &sregs) == 0);
  CHECK(regs.rax == UINT64_C(0x123456781100) && regs.rbx == UINT64_C(0x223456781101) &&
        regs.rcx == UINT64_C(0x323456781102) && regs.rdx == UINT64_C(0x423456781103) &&
        regs.rsi == UINT64_C(0x523456781104) && regs.rdi == UINT64_C(0x623456781105));
  CHECK(sregs.es.selector == 0x1106 && sregs.es.base == 0x11060 && sregs.es.limit == 0xffff);
  CHECK(daze_read_u16(guest + 0x2100) == 0x1100 && memcmp(guest + 0x2102, saved + 2, 4) == 0 &&
        daze_read_u16(guest + 0x2106) == 0x1107);
  CHECK(metrics.kvm_gate_frame_reply_calls == 1);
  metrics.enabled = 0;
  CHECK(daze_kvm_machine_sync_refresh(&machine) == DAZE_KVM_MACHINE_OK);
  CHECK(daze_kvm_runner_gate_frame_capture(&machine, 0x21, &frame) ==
        DAZE_KVM_RUNNER_GATE_RESUME_OK);
  const unsigned unchanged_calls = set_sregs_calls;
  CHECK(daze_kvm_runner_gate_frame_reply(&machine, &frame, reply) ==
        DAZE_KVM_RUNNER_GATE_RESUME_OK);
  CHECK(set_sregs_calls == unchanged_calls);
  CHECK(ioctl(machine.vcpu, KVM_GET_SREGS, &sregs) == 0);
  sregs.es.base++;
  CHECK(ioctl(machine.vcpu, KVM_SET_SREGS, &sregs) == 0);
  CHECK(daze_kvm_machine_sync_refresh(&machine) == DAZE_KVM_MACHINE_OK);
  CHECK(daze_kvm_runner_gate_frame_reply(&machine, &frame, reply) ==
        DAZE_KVM_RUNNER_GATE_RESUME_OK);
  CHECK(set_sregs_calls == unchanged_calls + 1);
  CHECK(ioctl(machine.vcpu, KVM_GET_SREGS, &sregs) == 0 && sregs.es.base == 0x11060);
  CHECK(metrics.kvm_gate_frame_capture_calls == 1 && metrics.kvm_gate_frame_reply_calls == 1);
  regs.rsp = 0xfff9;
  CHECK(ioctl(machine.vcpu, KVM_SET_REGS, &regs) == 0 &&
        daze_kvm_machine_sync_refresh(&machine) == DAZE_KVM_MACHINE_OK);
  CHECK(daze_kvm_runner_gate_frame_capture(&machine, 0x21, &frame) ==
        DAZE_KVM_RUNNER_GATE_RESUME_FAILED);
  CHECK(frame.ax == 0 && frame.sp == 0);
  regs.rsp = 0x100;
  CHECK(ioctl(machine.vcpu, KVM_SET_REGS, &regs) == 0 &&
        daze_kvm_machine_sync_refresh(&machine) == DAZE_KVM_MACHINE_OK);
  machine.guest_size = 0x2107;
  CHECK(daze_kvm_runner_gate_frame_capture(&machine, 0x21, &frame) ==
        DAZE_KVM_RUNNER_GATE_RESUME_INVALID);
  machine.guest_size = 0x20000;
  CHECK(daze_kvm_runner_gate_frame_set_ds(&machine, 0x4321) == DAZE_KVM_RUNNER_GATE_RESUME_OK);
  CHECK(ioctl(machine.vcpu, KVM_GET_SREGS, &sregs) == 0 && sregs.ds.selector == 0x4321 &&
        sregs.ds.base == 0x43210 && sregs.ds.limit == 0xffff);
  for (int kind = 0; kind < 3; ++kind) {
    guest[0x1000] = kind == 0 ? 0x90 : 0xe6;
    guest[0x1001] = kind == 1 ? 0x99 : 0xf4;
    if (kind == 2) machine.guest_size = 0x1001;
    CHECK(daze_kvm_runner_gate_frame_retire_out(&machine) == DAZE_KVM_RUNNER_GATE_RESUME_INVALID);
    CHECK(ioctl(machine.vcpu, KVM_GET_REGS, &regs) == 0 && regs.rip == 0);
    machine.guest_size = 0x20000;
  }
  CHECK(daze_kvm_runner_gate_frame_retire_out(&machine) == DAZE_KVM_RUNNER_GATE_RESUME_OK);
  CHECK(ioctl(machine.vcpu, KVM_GET_REGS, &regs) == 0 && regs.rip == 2);
  CHECK(daze_kvm_machine_set_real_mode(&machine, 0x100, 0, 0x200, 0x100, 0, 0) ==
        DAZE_KVM_MACHINE_OK);
  guest[0x1000] = 0xe6;
  guest[0x1001] = 0x99; /* out 99h,al */
  DazeKvmRunnerDpmiHandoff handoff = {.valid = 1};
  DazeKvmRunnerGateResumeInput input = {
    .machine = &machine, .handoff = &handoff, .mailbox_address = 0x3000};
  DazeKvmRunnerGateResumeResult result;
  CHECK(daze_kvm_runner_gate_resume_hlt(&input, &result) == DAZE_KVM_RUNNER_GATE_RESUME_FAILED);
  CHECK(((struct kvm_run *)machine.run)->exit_reason == KVM_EXIT_IO && result.ax == 0 &&
        result.rip == 0);
  daze_kvm_machine_destroy(&machine);
  return 0;
}

int main(int argc, char **argv) {
  if (argc == 2 && strcmp(argv[1], "--kvm") == 0) return cpu_boundaries();
  rejected_inputs();
  guest_ax_reply();
  puts("runner resume boundary: passed");
  return 0;
}
#else
int main(int argc, char **argv) {
  if (argc == 2 && strcmp(argv[1], "--kvm") == 0) return 77;
  DazeKvmRunnerGateFrame frame;
  CHECK(daze_kvm_runner_gate_frame_capture(NULL, 0x21, &frame) ==
        DAZE_KVM_RUNNER_GATE_RESUME_UNAVAILABLE);
  CHECK(daze_kvm_runner_gate_frame_set_ds(NULL, 0) == DAZE_KVM_RUNNER_GATE_RESUME_UNAVAILABLE);
  return 0;
}
#endif
