#include "runner_private.h"

#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
#include "machine_access.h"
#include "kvm_bytes.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>

#define CHECK(c)                                                                                   \
  do {                                                                                             \
    if (!(c)) {                                                                                    \
      fprintf(stderr, "runner execution failed at %d\n", __LINE__);                                \
      abort();                                                                                     \
    }                                                                                              \
  } while (0)

static int run_case(int kind) {
  const uint8_t port_reads[] = {0xe4, 0x21,                  /* in al,21h */
                                0xa2, 0x00, 0x02,            /* mov [0200h],al */
                                0xe4, 0xa1,                  /* in al,a1h */
                                0xa2, 0x01, 0x02,            /* mov [0201h],al */
                                0xe6, 0x00,                  /* out 0,al */
                                0xb8, 0x7b, 0x4c,            /* mov ax,4c7bh */
                                0xcd, 0x21};                 /* int 21h */
  const uint8_t unknown_read[] = {0xe4, 0x99};               /* in al,99h */
  const uint8_t unknown_write[] = {0xb0, 0x60, 0xe6, 0x99};  /* mov al,60h; out 99h,al */
  const uint8_t unknown_marker[] = {0xb0, 0x60, 0xe6, 0xf4}; /* mov al,60h; out f4h,al */
  const uint8_t raw_switch[] = {0xb0, 0x18, 0xe6, 0xf4};     /* mov al,18h; out f4h,al */
  const uint8_t dbcs[] = {0xb8, 0x00, 0x63,                  /* mov ax,6300h */
                          0xcd, 0x21,                        /* int 21h */
                          0xb8, 0x42, 0x4c,                  /* mov ax,4c42h */
                          0xcd, 0x21};                       /* int 21h */
  const uint8_t bad_frame[] = {0xbc, 0xff, 0xff,             /* mov sp,ffffh */
                               0xb0, 0x2f,                   /* mov al,2fh */
                               0xe6, 0xf4};                  /* out f4h,al */
  const uint8_t failed_service[] = {0xb8, 0xff, 0xff,        /* mov ax,ffffh */
                                    0x8e, 0xd8,              /* mov ds,ax */
                                    0xb8, 0x00, 0x3d,        /* mov ax,3d00h */
                                    0xba, 0xff, 0xff,        /* mov dx,ffffh */
                                    0xcd, 0x21};             /* int 21h */
  const uint8_t *codes[] = {port_reads, unknown_read, unknown_write, unknown_marker,
                            raw_switch, dbcs,         bad_frame,     failed_service};
  const size_t sizes[] = {sizeof(port_reads),     sizeof(unknown_read),  sizeof(unknown_write),
                          sizeof(unknown_marker), sizeof(raw_switch),    sizeof(dbcs),
                          sizeof(bad_frame),      sizeof(failed_service)};
  uint8_t bytes[64] = {'M', 'Z'};
  memcpy(bytes + 32, codes[kind], sizes[kind]);
  DazeImage image = {bytes, 32 + sizes[kind]};
  DazeMzHeader header = {
    .image_offset = 32, .image_size = sizes[kind], .initial_sp = 0xfffe, .relocation_offset = 0x1c};
  DazeDosfsMounts mounts;
  DazeDosfsHandles handles;
  DazeDosfsFileService files;
  DazeRunMetrics metrics = {.enabled = 1};
  daze_dosfs_mounts_init(&mounts);
  daze_dosfs_handles_init(&handles);
  daze_dosfs_file_service_init(&files, &mounts, &handles);
  files.run_metrics = &metrics;
  DazeKvmRunnerGenericPreflightRequest request = {.process = {.image = &image,
                                                              .header = &header,
                                                              .command_tail = "",
                                                              .guest_path = "C:\\TOOL.EXE",
                                                              .psp_segment = 0x100,
                                                              .environment_segment = 0x200,
                                                              .dpmi_entry_segment = 0x300,
                                                              .dos_vector_segment = 0x400,
                                                              .load_segment = 0x500,
                                                              .guest_size = 0x40000,
                                                              .mounts = &mounts,
                                                              .handles = &handles,
                                                              .files = &files}};
  DazeKvmMachine machine;
  int status = daze_kvm_machine_init(&machine, request.process.guest_size);
  if (status == DAZE_KVM_MACHINE_UNAVAILABLE) return 77;
  CHECK(status == DAZE_KVM_MACHINE_OK);
  DazeKvmRunnerGenericPreflightResult result;
  status = daze_kvm_runner_preflight_to_generic_boundary(&machine, &request, &result);
  CHECK(result.guest_execution_may_have_started);
  if (kind == 0 || kind == 5) {
    CHECK(status == DAZE_KVM_GENERIC_PREFLIGHT_TERMINATED && result.request_vector == 0x21);
    CHECK(result.request_ax == (kind == 0 ? 0x4c7b : 0x4c42));
    if (kind == 0) {
      CHECK(((uint8_t *)machine.guest)[0x1200] == 0 && ((uint8_t *)machine.guest)[0x1201] == 0);
      CHECK(metrics.kvm_boundary_broker_calls == 1);
    } else {
      CHECK(result.request_ds == 0x600 && metrics.kvm_boundary_broker_calls == 2);
      struct kvm_sregs sregs;
      CHECK(ioctl(machine.vcpu, KVM_GET_SREGS, &sregs) == 0 && sregs.ds.selector == 0x600 &&
            sregs.ds.base == 0x6000);
      CHECK(((uint8_t *)machine.guest)[0x6000] == 0 && ((uint8_t *)machine.guest)[0x6001] == 0);
    }
  } else if (kind == 4) {
    CHECK(status == DAZE_KVM_GENERIC_PREFLIGHT_RAW_SWITCH && result.request_vector == 0 &&
          !result.dpmi_handoff.valid);
  } else {
    CHECK(status == DAZE_KVM_GENERIC_PREFLIGHT_FAILED && !result.dpmi_handoff.valid);
    if (kind < 4 || kind == 7) {
      CHECK(result.terminal_observation_status == DAZE_KVM_MACHINE_OK &&
            result.terminal_observation.present);
      CHECK(result.terminal_observation.exit_reason == KVM_EXIT_IO);
      if (kind < 4) {
        CHECK(result.terminal_observation.cs == 0x500);
        /* KVM completes the pending I/O instruction on the next KVM_RUN. */
        CHECK(result.terminal_observation.rip == (kind == 1 ? 0 : 2));
      }
    }
  }
  daze_kvm_machine_destroy(&machine);
  CHECK(machine.kvm == -1 && machine.vm == -1 && machine.vcpu == -1);
  return 0;
}

static void snapshot_rejection(void) {
  DazeKvmMachine machine;
  CHECK(daze_kvm_machine_init(&machine, 0x40000) == DAZE_KVM_MACHINE_OK);
  CHECK(daze_kvm_machine_set_real_mode(&machine, 0x500, 0, 0x100, 0xfffe, 0x100, 0x100) ==
        DAZE_KVM_MACHINE_OK);
  DazeKvmRunnerDpmiHandoff handoff = {.ax = 0x1234};
  DazeKvmRunnerDpmiHandoff before = handoff;
  CHECK(!capture_real_mode_entry_snapshot(&machine, &handoff));
  CHECK(memcmp(&handoff, &before, sizeof(before)) == 0);
  struct kvm_regs regs;
  CHECK(ioctl(machine.vcpu, KVM_GET_REGS, &regs) == 0);
  regs.rsp = 0x100;
  CHECK(ioctl(machine.vcpu, KVM_SET_REGS, &regs) == 0);
  size_t saved = machine.guest_size;
  machine.guest_size = 0x1109;
  CHECK(!capture_real_mode_entry_snapshot(&machine, &handoff));
  CHECK(memcmp(&handoff, &before, sizeof(before)) == 0);
  machine.guest_size = saved;
  daze_kvm_machine_destroy(&machine);
}

int main(void) {
  for (int kind = 0; kind < 8; ++kind) {
    int status = run_case(kind);
    if (status) return status;
  }
  snapshot_rejection();
  puts("runner execution boundary contract: passed");
  return 0;
}
#else
int main(void) {
  return 77;
}
#endif
