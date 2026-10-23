#define _POSIX_C_SOURCE 200809L
#include "backend/kvm/runner/runner.c"

#include <limits.h>
#include <unistd.h>

#define CHECK(c)                                                                                   \
  do {                                                                                             \
    if (!(c)) {                                                                                    \
      fprintf(stderr, "runner boundary failed at %d\n", __LINE__);                                 \
      abort();                                                                                     \
    }                                                                                              \
  } while (0)

int main(void) {
  uint8_t bytes[64] = {'M', 'Z'};
  DazeImage image = {bytes, sizeof(bytes)};
  DazeMzHeader header = {.image_offset = 32, .image_size = 16, .initial_sp = 0xfffe};
  DazeDosfsMounts mounts;
  DazeDosfsHandles handles;
  DazeDosfsFileService files;
  DazeDosProcessState process;
  DazeDosMemory allocator;
  daze_dosfs_mounts_init(&mounts);
  daze_dosfs_handles_init(&handles);
  daze_dosfs_file_service_init(&files, &mounts, &handles);
  daze_dos_process_state_init(&process, 0x100);
  daze_dos_memory_init(&allocator, 0x3000, 0xa000);
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
  DazeKvmRunnerRequestCommon good = request.process;
  for (int kind = 0; kind < 11; ++kind) {
    DazeKvmRunnerRequestCommon bad = good;
    DazeImage missing = image;
    char tail[128];
    memset(tail, 'X', sizeof(tail));
    tail[127] = 0;
    switch (kind) {
    case 0:
      bad.image = NULL;
      break;
    case 1:
      bad.header = NULL;
      break;
    case 2:
      missing.bytes = NULL;
      bad.image = &missing;
      break;
    case 3:
      missing.size = 0;
      bad.image = &missing;
      break;
    case 4:
      bad.command_tail = NULL;
      break;
    case 5:
      bad.guest_path = NULL;
      break;
    case 6:
      bad.mounts = NULL;
      break;
    case 7:
      bad.handles = NULL;
      break;
    case 8:
      bad.files = NULL;
      break;
    case 9:
      bad.guest_size = 0;
      break;
    case 10:
      bad.command_tail = tail;
      break;
    }
    CHECK(!daze_kvm_runner_process_valid(&bad));
  }
  DazeKvmGuestRange ranges[3];
  CHECK(runner_reserved_ranges(0x40000, NULL) == 0);
  CHECK(runner_reserved_ranges(0, ranges) == 3);
  CHECK(runner_reserved_ranges(SIZE_MAX, ranges) == 3);
  uint8_t *guest = calloc(1, good.guest_size);
  CHECK(guest != NULL);
  DazeKvmMachine machine = {
    .kvm = -1, .vm = -1, .vcpu = INT_MAX, .guest = guest, .guest_size = good.guest_size};
  CHECK(runner_record(&machine) == guest + daze_kvm_runner_gate_record_linear(machine.guest_size));
  CHECK(runner_mailbox(&machine) ==
        guest + daze_kvm_runner_gate_mailbox_linear(machine.guest_size));
  DazeKvmRunnerGenericPreflightResult result;
  for (int kind = 0; kind < 6; ++kind) {
    DazeKvmMachine *m = kind == 0 ? NULL : &machine;
    const DazeKvmRunnerGenericPreflightRequest *r = kind == 1 ? NULL : &request;
    DazeDosProcessState *p = kind == 2 ? NULL : &process;
    DazeDosMemory *a = kind == 3 ? NULL : &allocator;
    DazeKvmRunnerGenericPreflightResult *out = kind == 4 ? NULL : &result;
    DazeKvmRunnerGenericPreflightRequest invalid = request;
    if (kind == 5) {
      invalid.process.image = NULL;
      r = &invalid;
    }
    memset(&result, 0xa5, sizeof(result));
    CHECK(daze_kvm_runner_resume_to_generic_boundary(m, r, p, a, out) ==
          DAZE_KVM_GENERIC_PREFLIGHT_INVALID);
    if (out != NULL)
      CHECK(result.guest_execution_may_have_started == 0 && result.dpmi_handoff.valid == 0);
    CHECK(daze_kvm_runner_bootstrap_to_generic_boundary(m, r, p, a, out) ==
          DAZE_KVM_GENERIC_PREFLIGHT_INVALID);
    if (kind != 2 && kind != 3)
      CHECK(daze_kvm_runner_preflight_to_generic_boundary(m, r, out) ==
            DAZE_KVM_GENERIC_PREFLIGHT_INVALID);
  }
  DazeKvmRunnerDpmiHandoff handoff = {.ax = 0x1234};
  DazeKvmRunnerDpmiHandoff before = handoff;
  CHECK(!capture_real_mode_entry_snapshot(&machine, &handoff));
  CHECK(memcmp(&handoff, &before, sizeof(handoff)) == 0);
  DazeKvmRunnerGateFrame frame;
  uint8_t record[24] = {0}, mailbox[16];
  CHECK(!runner_frame_record(&machine, 0x21, &frame, record));
  for (int kind = 0; kind < 5; ++kind) {
    memset(mailbox, 0xa5, sizeof(mailbox));
    DazeKvmPreflightBoundaryResult boundary;
    void *saved_guest = machine.guest;
    if (kind == 4) machine.guest = NULL;
    CHECK(daze_kvm_preflight_boundary_broker(kind == 0 ? NULL : &machine, kind == 1 ? NULL : &files,
                                             &process, &allocator, 0x300, kind == 2 ? NULL : record,
                                             kind == 3 ? NULL : mailbox,
                                             &boundary) == DAZE_KVM_PREFLIGHT_BOUNDARY_FAILED);
    CHECK(boundary.reply_ds_present == 0 && mailbox[0] == 0xa5);
    machine.guest = saved_guest;
  }
  DazeRunMetrics metrics = {.enabled = 1};
  files.run_metrics = &metrics;
  const uint16_t multiplex[][3] = {{0xfb43, 0x100, 0}, {0xfb43, 0x101, 0}, {0xfb42, 0x14, 1},
                                   {0xfb42, 0x15, 1},  {0xfb42, 0x14, 2},  {0x4300, 0, 0},
                                   {0x1600, 0, 0}};
  for (size_t i = 0; i < sizeof(multiplex) / sizeof(multiplex[0]); ++i) {
    daze_write_u16(record, multiplex[i][0]);
    daze_write_u16(record + 2, multiplex[i][1]);
    daze_write_u16(record + 4, multiplex[i][2]);
    daze_write_u16(record + 16, 0x2f);
    daze_write_u16(record + 22, 0x203);
    memset(mailbox, 0xa5, sizeof(mailbox));
    int handled = i == 0 || i == 2 || i >= 5;
    CHECK(
      daze_kvm_preflight_boundary_broker(&machine, &files, &process, &allocator, 0x300, record,
                                         mailbox, NULL) ==
      (handled ? DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED : DAZE_KVM_PREFLIGHT_BOUNDARY_UNSUPPORTED));
    if (!handled)
      CHECK(mailbox[0] == 0xa5);
    else if (i == 2)
      CHECK(daze_read_u16(mailbox + 2) == 1 && daze_read_u16(mailbox + 14) == 0x203);
    else if (i == 0)
      CHECK(daze_read_u16(mailbox) == 0xfb43 && daze_read_u16(mailbox + 14) == 0x203);
    else
      CHECK((daze_read_u16(mailbox + 14) & 1) == 0);
  }
  daze_write_u16(record + 16, 0xfe);
  CHECK(daze_kvm_preflight_boundary_broker(&machine, &files, &process, &allocator, 0x300, record,
                                           mailbox,
                                           NULL) == DAZE_KVM_PREFLIGHT_BOUNDARY_DPMI_ENTRY);
  CHECK(metrics.kvm_boundary_broker_calls == 8 && metrics.kvm_other_boundary_broker_calls == 7 &&
        metrics.kvm_dpmi_entry_boundary_broker_calls == 1 &&
        metrics.kvm_boundary_vectors[0xfe] == 1);
  metrics.enabled = 0;
  DazeRunMetrics metrics_before = metrics;
  daze_kvm_preflight_boundary_broker(&machine, &files, &process, &allocator, 0x300, record, mailbox,
                                     NULL);
  CHECK(memcmp(&metrics, &metrics_before, sizeof(metrics)) == 0);
  CHECK(!runner_vector_hosted(0x60));
  CHECK(daze_kvm_runner_gated_port_read(0x21, NULL));
  DazeKvmPortAccess access = {.direction = DAZE_KVM_PORT_IN, .port = 0x99};
  CHECK(!serve_gated_port_read(&machine, &access));
  CHECK(!install_gate(&machine, 0x21, 0xffff, 0xffff));
  machine.guest_size = 4;
  CHECK(!install_gate(&machine, 0x21, 0, 0));
  machine.guest_size = good.guest_size;
  DazeMzHeader oversized = header;
  oversized.image_size = machine.guest_size;
  CHECK(!load_mz(&machine, &image, &oversized, good.load_segment));
  for (int kind = 0; kind < 4; ++kind) {
    DazeKvmRunnerGenericPreflightRequest bad = request;
    DazeMzHeader bad_header = header;
    char tail[128];
    memset(tail, 'X', sizeof(tail));
    tail[127] = 0;
    if (kind == 0) bad_header.image_size = machine.guest_size;
    if (kind == 1) bad.process.env_var_count = 1;
    if (kind == 2) bad.process.exec_child = 1;
    bad.process.header = &bad_header;
    if (kind == 1) {
      CHECK(!bootstrap_real_mode_runner(&machine, &image, &bad_header, tail, good.guest_path,
                                        good.psp_segment, good.environment_segment,
                                        good.dpmi_entry_segment, good.dos_vector_segment,
                                        good.load_segment, NULL, &bad.process));
    } else if (kind == 0) {
      CHECK(!bootstrap_real_mode_runner(&machine, &image, &bad_header, "", good.guest_path,
                                        good.psp_segment, good.environment_segment,
                                        good.dpmi_entry_segment, good.dos_vector_segment,
                                        good.load_segment, NULL, &bad.process));
    } else {
      CHECK(daze_kvm_runner_bootstrap_to_generic_boundary(
              &machine, &bad, &process, &allocator, &result) == DAZE_KVM_GENERIC_PREFLIGHT_FAILED);
      CHECK(!result.guest_execution_may_have_started && !result.dpmi_handoff.valid &&
            !result.terminal_observation.present);
    }
  }

  FILE *capture = tmpfile();
  CHECK(capture != NULL);
  fflush(stderr);
  int saved = dup(STDERR_FILENO);
  CHECK(saved >= 0 && dup2(fileno(capture), STDERR_FILENO) >= 0);
  DazeKvmProcessLayoutFailure failure = {
    DAZE_KVM_PROCESS_LAYOUT_RANGE_OUT_OF_GUEST, {0x40000, 0}, {0, 0}};
  report_process_layout_failure(&good, &failure);
  failure.kind = DAZE_KVM_PROCESS_LAYOUT_RESERVED_EMPTY;
  report_process_layout_failure(&good, &failure);
  failure.kind = DAZE_KVM_PROCESS_LAYOUT_BAD_INPUT;
  report_process_layout_failure(&good, &failure);
  CHECK(runner_reserved_ranges(good.guest_size, ranges) == 3);
  for (size_t i = 0; i < 3; ++i) {
    failure = (DazeKvmProcessLayoutFailure){DAZE_KVM_PROCESS_LAYOUT_RANGE_OVERLAP,
                                            {(uint32_t)good.load_segment << 4, header.image_size},
                                            ranges[i]};
    report_process_layout_failure(&good, &failure);
  }
  fflush(stderr);
  CHECK(dup2(saved, STDERR_FILENO) >= 0);
  close(saved);
  rewind(capture);
  char diagnostic[4096] = {0};
  CHECK(fread(diagnostic, 1, sizeof(diagnostic) - 1, capture) > 0);
  fclose(capture);
  CHECK(strstr(diagnostic, "process segment 4000 lies outside the 00040000-byte guest") != NULL);
  CHECK(strstr(diagnostic, "empty KVM runner reservation") != NULL);
  CHECK(strstr(diagnostic, "internal error") != NULL);
  CHECK(strstr(diagnostic, "image") != NULL && strstr(diagnostic, "mailbox") != NULL &&
        strstr(diagnostic, "record") != NULL);
  daze_dos_process_state_dispose(&process);
  free(guest);
  puts("runner boundary contract: passed");
  return 0;
}
