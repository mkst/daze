#include "runner_resume.c"

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
  CHECK(memcmp(guest + 0x2100, saved, 6) == 0 && daze_read_u16(guest + 0x2106) == 0x1107);
  CHECK(metrics.kvm_gate_frame_reply_calls == 1);
  metrics.enabled = 0;
  CHECK(daze_kvm_machine_sync_refresh(&machine) == DAZE_KVM_MACHINE_OK);
  CHECK(daze_kvm_runner_gate_frame_capture(&machine, 0x21, &frame) ==
        DAZE_KVM_RUNNER_GATE_RESUME_OK);
  CHECK(daze_kvm_runner_gate_frame_reply(&machine, &frame, reply) ==
        DAZE_KVM_RUNNER_GATE_RESUME_OK);
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
