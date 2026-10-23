#include "owner.h"
#include "boundary.h"
#include "kvm_bytes.h"
#include "guest_memory_layout.h"
#include "runner/runner_private.h"
#include "normal_config.h"
#include "result.h"
#include "rm_frame.h"

#include <poll.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static DazeKvmRunnerGenericPreflightRequest generic_request(void) {
  static uint8_t bytes[0x2f] = {
    'M',  'Z',  0x2f, 0,    1,    0, 0,    0, 2, 0, 0, 0, 0, 0, 0,    0,    0xfe, 0xff,
    0,    0,    0,    0,    0,    0, 0x1c, 0, 0, 0, 0, 0, 0, 0, 0xb8, 0x00, 0x01, /* mov ax,0x100 */
    0x8e, 0xd0,                                                                   /* mov ss,ax */
    0xb8, 0x87, 0x16, /* mov ax,0x1687 */
    0xcd, 0x2f,       /* int 0x2f */
    0x9a, 0x00, 0x00, 0x00, 0x03, /* call far 0300h:0000 */};
  static DazeImage image = {bytes, sizeof(bytes)};
  static DazeMzHeader header = {.header_paragraphs = 2,
                                .initial_sp = 0xfffe,
                                .module_size = sizeof(bytes),
                                .image_offset = 0x20,
                                .image_size = 15,
                                .relocation_offset = 0x1c};
  static DazeDosfsMounts mounts;
  static DazeDosfsHandles handles;
  static DazeDosfsFileService files;
  daze_dosfs_mounts_init(&mounts);
  daze_dosfs_handles_init(&handles);
  daze_dosfs_file_service_init(&files, &mounts, &handles);
  return (DazeKvmRunnerGenericPreflightRequest){.process = {.image = &image,
                                                            .header = &header,
                                                            .command_tail = "",
                                                            .guest_path = "C:\\TOOL.EXE",
                                                            .psp_segment = 0x0100,
                                                            .environment_segment = 0x0200,
                                                            .dpmi_entry_segment = 0x0300,
                                                            .dos_vector_segment = 0x0400,
                                                            .load_segment = 0x0500,
                                                            .guest_size = 0x80000,
                                                            .mounts = &mounts,
                                                            .handles = &handles,
                                                            .files = &files}};
}

static DazeKvmCommandOwnerTransitionLayout transition_layout(void) {
  return (DazeKvmCommandOwnerTransitionLayout){.resident_image_end = 0x500f,
                                               .gdt_address = 0x48000,
                                               .ldt_address = 0x58000,
                                               .idt_address = 0x70000,
                                               .idt_limit = 0x07ff,
                                               .linear_min_address = 0x6000,
                                               .linear_limit = 0x40000,
                                               .default_vector_alias_selector = 0x0060,
                                               .default_vector_alias_offset = 0x1c8};
}

static int kvm_available(void) {
  DazeKvmMachine machine;
  const int status = daze_kvm_machine_init(&machine, 0x80000);
  if (status == DAZE_KVM_MACHINE_OK) daze_kvm_machine_destroy(&machine);
  return status == DAZE_KVM_MACHINE_OK ? 1 : status == DAZE_KVM_MACHINE_UNAVAILABLE ? 0 : -1;
}

/* A valid state-save boundary must hand its successor back to the dispatcher:
 * the protected-DOS marker then belongs to the runner path and the raw-switch
 * marker to the raw-switch path. This contract covers the marker half of that
 * ordering. Gate execution needs a real guest frame and is covered by the
 * raw-switch contracts; a synthetic PIO marker cannot exercise it. */
static int state_save_successor_ordering_contract(void) {
  static const struct {
    uint8_t marker;
    DazeKvmCommandBoundaryKind boundary;
  } ordered[] = {
    {DAZE_KVM_STATE_SAVE_GATE_MARKER, DAZE_KVM_COMMAND_BOUNDARY_STATE},
    {DAZE_KVM_PROTECTED_DOS_MARKER, DAZE_KVM_COMMAND_BOUNDARY_RUNNER},
    {DAZE_KVM_RAW_SWITCH_GATE_MARKER, DAZE_KVM_COMMAND_BOUNDARY_RAW},
  };
  int failed = 0;
  for (size_t index = 0; index < sizeof(ordered) / sizeof(ordered[0]); ++index) {
    DazeKvmDpmiEntryResult boundary = {.cr0 = 1,
                                       .observation = {.kind = DAZE_KVM_DPMI_ENTRY_EXIT_PIO,
                                                       .pio_direction = DAZE_KVM_DPMI_ENTRY_PIO_OUT,
                                                       .pio_size = 1,
                                                       .pio_count = 1,
                                                       .pio_port = DAZE_KVM_DPMI_MEDIATOR_PORT,
                                                       .pio_value = ordered[index].marker,
                                                       .pio_value_present = 1}};
    if (daze_kvm_command_boundary_classify(&boundary) != ordered[index].boundary) failed = 1;
  }
  return failed;
}

/* A resident transition can rebuild its IDT after a client has registered an
 * exception handler. The projection is mechanics only: it must reproduce the
 * saved 0203h target without changing the shared vector state. */
static int resident_exception_projection_contract(void) {
  uint8_t guest[0x1000] = {0};
  DazeKvmMachine machine = {.guest = guest, .guest_size = sizeof(guest)};
  const DazeKvmProtectedGateLayout gate = {.idt_address = 0x200,
                                           .idt_limit = 0x7ff,
                                           .exception_gate_vector = 0x0d,
                                           .exception_gate_type = 0x8e};
  DazeKvmDpmiMediator mediator = {
    .gdt_address = 0x300,
    .gdt_size = 0x100,
    .ldt_address = 0x500,
    .ldt_size = 0x100,
    .exception_vectors = {[0x0d] = {.segment = 0x0008, .offset = 0x00002fdf}}};
  static const uint8_t code16[] = {0xff, 0xff, 0, 0, 0, 0x9a, 0x00, 0};
  memcpy(guest + mediator.gdt_address + 8, code16, sizeof(code16));
  const uint32_t entry = gate.idt_address + (uint32_t)gate.exception_gate_vector * 8u;
  if (!daze_kvm_protected_gate_project_exception_vector(&machine, &mediator, &gate)) return 1;
  static const uint8_t expected[] = {0xdf, 0x2f, 0x08, 0x00, 0x00, 0x86, 0x00, 0x00};
  if (memcmp(guest + entry, expected, sizeof(expected)) != 0) return 2;
  if (mediator.exception_vectors[0x0d].segment != 0x0008 ||
      mediator.exception_vectors[0x0d].offset != 0x00002fdf)
    return 3;
  return 0;
}

/* Put different strings at descriptor-base + DX and DS<<4 + DX, so the
 * wrong protected-address calculation cannot pass. Guest memory is a buffer;
 * DOS handle 1 is a pipe, with no running vCPU. */
static int protected_display_string_contract(void) {
  enum { k_ds_base = 0x00010100, k_dx = 0x0129a };
  static uint8_t guest[0x20000];
  memset(guest, 'Z', sizeof(guest));
  const uint32_t shifted = ((uint32_t)0x0010 << 4) + k_dx;
  memcpy(guest + k_ds_base + k_dx, "descriptor$", 11);
  memcpy(guest + shifted, "segment$", 8);

  uint8_t record[24] = {0};
  daze_write_u16(record, 0x0900);
  daze_write_u16(record + 2, 0x1111);
  daze_write_u16(record + 4, 0x2222);
  daze_write_u16(record + 6, (uint16_t)k_dx);
  daze_write_u16(record + 8, 0x0010);
  daze_write_u16(record + 10, 0x0018);
  daze_write_u16(record + 12, 0x3333);
  daze_write_u16(record + 14, 0x4444);
  daze_write_u16(record + 16, 0x0021);
  daze_write_u16(record + 22, 0x0203);
  const DazeKvmRunnerRequestImage request = {.vector = 0x21,
                                             .ax = 0x0900,
                                             .bx = 0x1111,
                                             .cx = 0x2222,
                                             .dx = (uint16_t)k_dx,
                                             .ds = 0x0010,
                                             .es = 0x0018,
                                             .si = 0x3333,
                                             .di = 0x4444,
                                             .flags = 0x0203};
  const DazeKvmDpmiEntryResult boundary = {.ds = 0x0010, .ds_base = k_ds_base};
  const DazeKvmMachine machine = {.guest = guest, .guest_size = sizeof(guest)};

  int output_pipe[2] = {-1, -1};
  if (pipe(output_pipe) != 0) return 1;
  DazeDosfsHandles handles;
  daze_dosfs_handles_init(&handles);
  const int bound =
    daze_dosfs_handles_bind_standard(&handles, STDIN_FILENO, output_pipe[1], STDERR_FILENO, NULL);
  close(output_pipe[1]);
  if (bound != DAZE_DOSFS_OK) {
    close(output_pipe[0]);
    return 1;
  }
  DazeDosfsFileService files = {.handles = &handles};

  uint8_t reply[DAZE_KVM_RUNNER_GATE_REPLY_SIZE] = {0};
  uint8_t written[16] = {0};
  int failed = daze_kvm_command_owner_protected_dos_display_string(&machine, &files, &boundary,
                                                                   &request, record, reply) !=
                 DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED ||
               daze_read_u16(reply) != 0x0900 || daze_read_u16(reply + 2) != 0x1111 ||
               daze_read_u16(reply + 4) != 0x2222 || daze_read_u16(reply + 6) != k_dx ||
               daze_read_u16(reply + 8) != 0x3333 || daze_read_u16(reply + 10) != 0x4444 ||
               daze_read_u16(reply + 12) != 0x0018 || (daze_read_u16(reply + 14) & 1u) != 0 ||
               (daze_read_u16(reply + 14) & 0x200u) == 0 ||
               read(output_pipe[0], written, 10) != 10 || memcmp(written, "descriptor", 10) != 0;

  /* An unterminated string must fail without output, using the invalid-handle convention. */
  memset(guest + k_ds_base + k_dx, 'Z', sizeof(guest) - (k_ds_base + k_dx));
  struct pollfd pending = {.fd = output_pipe[0], .events = POLLIN};
  memset(reply, 0, sizeof(reply));
  if (daze_kvm_command_owner_protected_dos_display_string(&machine, &files, &boundary, &request,
                                                          record, reply) !=
        DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED ||
      daze_read_u16(reply) != 0x0006 || (daze_read_u16(reply + 14) & 1u) == 0 ||
      poll(&pending, 1, 0) != 0)
    failed = 1;

  for (int kind = 0; kind < 11; ++kind) {
    DazeKvmMachine invalid_machine = machine;
    DazeKvmDpmiEntryResult invalid_boundary = boundary;
    DazeKvmRunnerRequestImage invalid_request = request;
    if (kind == 1) invalid_machine.guest = NULL;
    if (kind == 7) invalid_boundary.ds_base = UINT32_MAX;
    if (kind == 8) invalid_boundary.ds_base = sizeof(guest) - 1;
    if (kind == 9) invalid_request.ax = 0xff00;
    if (kind == 10) invalid_request.ax = 0x4c00;
    memset(reply, 0xa5, sizeof(reply));
    const int status = daze_kvm_command_owner_protected_dos_display_string(
      kind == 0 ? NULL : &invalid_machine, kind == 2 ? NULL : &files,
      kind == 3 ? NULL : &invalid_boundary, kind == 4 ? NULL : &invalid_request,
      kind == 5 ? NULL : record, kind == 6 ? NULL : reply);
    if (kind == 7 || kind == 8) {
      failed |= status != DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED || daze_read_u16(reply) != 6 ||
                !(daze_read_u16(reply + 14) & 1);
    } else {
      failed |= status != DAZE_KVM_PREFLIGHT_BOUNDARY_FAILED;
      for (size_t i = 0; i < sizeof(reply); ++i)
        failed |= reply[i] != 0xa5;
    }
    failed |= poll(&pending, 1, 0) != 0;
  }

  close(output_pipe[0]);
  daze_dosfs_handles_close_all(&handles);
  return failed;
}

static int begin_rejections(void) {
  DazeKvmRunnerGenericPreflightRequest request = generic_request();
  DazeKvmMachine machine;
  if (daze_kvm_machine_init(&machine, request.process.guest_size) != DAZE_KVM_MACHINE_OK) return 1;
  const DazeKvmMachine before = machine;
  DazeKvmCommandOwnerHandoff handoff = {0};
  DazeKvmRunnerGenericPreflightResult observation;
  DazeMzHeader bad_header = *request.process.header;
  int failed = 0;
  for (int kind = 0; kind < 7; ++kind) {
    DazeKvmRunnerGenericPreflightRequest invalid = request;
    if (kind == 0) invalid.process.header = NULL;
    if (kind == 1) invalid.process.image = NULL;
    if (kind == 2) invalid.process.guest_size = 0;
    if (kind == 3) invalid.process.command_tail = NULL;
    if (kind == 4) invalid.process.files = NULL;
    if (kind == 5) invalid.process.guest_size--;
    if (kind == 6) {
      bad_header.image_size = SIZE_MAX;
      invalid.process.header = &bad_header;
    }
    memset(&observation, 0xa5, sizeof(observation));
    if (daze_kvm_command_owner_begin_observe(&invalid, &machine, &handoff, &observation) !=
          DAZE_KVM_COMMAND_OWNER_HANDOFF_PRESTART_REJECTED ||
        handoff.active || observation.guest_execution_may_have_started ||
        memcmp(&machine, &before, sizeof(machine)) != 0)
      failed = 1;
  }
  daze_kvm_machine_destroy(&machine);
  return failed;
}

static int begin_outcomes(void) {
  const uint8_t programs[][5] = {
    {0xb8, 0, 0x4c, 0xcd, 0x21},
    {0xb8, 0x25, 0x4c, 0xcd, 0x21},
    {0xf4},
    {0xb8, 0, 0x4b, 0xcd, 0x21},
  };
  for (size_t i = 0; i < sizeof(programs) / sizeof(programs[0]); ++i) {
    uint8_t bytes[0x25] = {0};
    memcpy(bytes + 0x20, programs[i], 5);
    DazeImage image = {bytes, sizeof(bytes)};
    DazeMzHeader header = {.header_paragraphs = 2,
                           .initial_sp = 0xfffe,
                           .module_size = sizeof(bytes),
                           .image_offset = 0x20,
                           .image_size = 5,
                           .relocation_offset = 0x1c};
    DazeKvmRunnerGenericPreflightRequest request = generic_request();
    request.process.image = &image;
    request.process.header = &header;
    DazeKvmMachine machine;
    if (daze_kvm_machine_init(&machine, request.process.guest_size) != DAZE_KVM_MACHINE_OK)
      return 1;
    const int vm = machine.vm, vcpu = machine.vcpu;
    DazeKvmCommandOwnerHandoff handoff = {0};
    DazeKvmRunnerGenericPreflightResult observation;
    const int status =
      daze_kvm_command_owner_begin_observe(&request, &machine, &handoff, &observation);
    int failed =
      machine.vm != -1 || machine.guest != NULL || !observation.guest_execution_may_have_started;
    if (i < 2) {
      failed |= status != DAZE_KVM_COMMAND_OWNER_HANDOFF_TERMINATED || handoff.active ||
                observation.request_vector != 0x21 ||
                observation.request_ax != (uint16_t)(0x4c00 | programs[i][1]);
    } else if (i == 2) {
      failed |= status != DAZE_KVM_COMMAND_OWNER_HANDOFF_POSTSTART_FAILED || handoff.active ||
                !observation.terminal_observation.present;
    } else {
      failed |= status != DAZE_KVM_COMMAND_OWNER_HANDOFF_EXEC || !handoff.active ||
                observation.request_ax != 0x4b00 || handoff.machine.vm != vm;
    }
    daze_kvm_command_owner_handoff_destroy(&handoff);
    daze_kvm_command_owner_handoff_destroy(&handoff);
    daze_kvm_machine_destroy(&machine);
    if (fcntl(vm, F_GETFD) != -1 || errno != EBADF || fcntl(vcpu, F_GETFD) != -1 ||
        errno != EBADF || failed) {
      fprintf(stderr, "owner begin outcome %zu failed: status=%d disposition=%d\n", i, status,
              observation.disposition);
      return 1;
    }
  }
  return 0;
}

static int rejected_continuations(DazeKvmCommandOwnerHandoff *handoff,
                                  const DazeKvmCommandOwnerInput *input) {
  DazeKvmMachineSnapshot snapshot = {0};
  if (daze_kvm_machine_snapshot_take(&handoff->machine, &snapshot) != DAZE_KVM_MACHINE_OK) return 1;
  const DazeDpmiProcessState state = *input->state;
  const DazeKvmStateSaveGateLayout state_gate = {0};
  int failed = 0;
  for (int kind = 0; kind < 45; ++kind) {
    if (kind >= 19 && input->transition_layout.protected_gate == NULL) continue;
    DazeKvmCommandOwnerInput invalid = *input;
    DazeKvmCommandOwnerHandoff parked = *handoff;
    DazeKvmProtectedGateLayout protected_gate = {0};
    DazeKvmStateSaveGateLayout changed_state_gate = {0};
    DazeKvmRawSwitchGateLayout raw_gate = {0};
    if (kind >= 19) {
      protected_gate = *input->transition_layout.protected_gate;
      changed_state_gate = *input->transition_layout.state_save_gate;
      raw_gate = *input->transition_layout.raw_switch_gate;
      invalid.transition_layout.protected_gate = &protected_gate;
      invalid.transition_layout.state_save_gate = &changed_state_gate;
      invalid.transition_layout.raw_switch_gate = &raw_gate;
    }
    if (kind == 0) invalid.state = NULL;
    if (kind == 1) invalid.preflight.process.load_segment++;
    if (kind == 2) invalid.preflight.process.files = NULL;
    if (kind == 3) invalid.transition_layout.resident_image_end--;
    if (kind == 4) invalid.transition_layout.state_save_gate = &state_gate;
    if (kind == 5)
      invalid.transition_layout.gdt_address = invalid.preflight.process.load_segment << 4;
    if (kind == 6)
      invalid.transition_layout.linear_limit = invalid.transition_layout.linear_min_address;
    if (kind == 7) invalid.preflight.process.image = NULL;
    if (kind == 8) invalid.preflight.process.header = NULL;
    if (kind == 9) invalid.preflight.process.command_tail = NULL;
    if (kind == 10) invalid.preflight.process.guest_path = NULL;
    if (kind == 11) invalid.preflight.process.psp_segment++;
    if (kind == 12) invalid.preflight.process.environment_segment++;
    if (kind == 13) invalid.preflight.process.dpmi_entry_segment++;
    if (kind == 14) invalid.preflight.process.dos_vector_segment++;
    if (kind == 15) invalid.preflight.process.guest_size--;
    if (kind == 16) invalid.preflight.process.mounts = NULL;
    if (kind == 17) invalid.preflight.process.handles = NULL;
    if (kind == 18) parked.preflight.dpmi_handoff.entry_snapshot.sp = 1;
    if (kind == 19) invalid.transition_layout.state_save_endpoints.state_buffer_size = 0;
    if (kind == 20) invalid.transition_layout.state_save_endpoints.pm_selector = 0;
    if (kind == 21) invalid.transition_layout.raw_switch_endpoints.pm_selector = 0;
    if (kind == 22) invalid.transition_layout.raw_switch_linear = 0;
    if (kind == 23)
      invalid.transition_layout.raw_switch_linear = input->preflight.process.guest_size;
    if (kind == 24) protected_gate.handler_selector = 0;
    if (kind == 25) changed_state_gate.handler_selector = 0;
    if (kind == 26) raw_gate.handler_selector = 0;
    if (kind == 27) protected_gate.handler_address = input->preflight.process.guest_size;
    if (kind == 28) protected_gate.dos_handler_address = input->preflight.process.guest_size;
    if (kind == 29) protected_gate.default_dos_stub_address = input->preflight.process.guest_size;
    if (kind == 30) protected_gate.idt_address = input->preflight.process.guest_size;
    if (kind == 31) protected_gate.handler_address = input->transition_layout.gdt_address;
    if (kind == 32) protected_gate.dos_handler_address = input->transition_layout.gdt_address;
    if (kind == 33) protected_gate.default_dos_stub_address = input->transition_layout.gdt_address;
    if (kind == 34) protected_gate.idt_address = input->transition_layout.gdt_address;
    if (kind == 35) changed_state_gate.handler_address = input->preflight.process.guest_size;
    if (kind == 36) changed_state_gate.idt_address = input->preflight.process.guest_size;
    if (kind == 37) changed_state_gate.handler_address = input->transition_layout.gdt_address;
    if (kind == 38) changed_state_gate.idt_address = input->transition_layout.gdt_address;
    if (kind == 39) raw_gate.handler_address = input->preflight.process.guest_size;
    if (kind == 40) raw_gate.real_handler_address = input->preflight.process.guest_size;
    if (kind == 41) raw_gate.idt_address = input->preflight.process.guest_size;
    if (kind == 42) raw_gate.handler_address = input->transition_layout.gdt_address;
    if (kind == 43) raw_gate.real_handler_address = 0x2080;
    if (kind == 44) raw_gate.idt_address = input->transition_layout.gdt_address;
    const DazeKvmCommandOwnerHandoff parked_before = parked;
    DazeKvmCommandOwnerResult result;
    memset(&result, 0xa5, sizeof(result));
    if (daze_kvm_command_owner_continue(&parked, &invalid, &result) !=
          DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED ||
        result.disposition != DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED ||
        result.guest_exit_status_present || memcmp(&parked, &parked_before, sizeof(parked)) != 0 ||
        memcmp(input->state, &state, sizeof(state)) != 0 ||
        memcmp(handoff->machine.guest, snapshot.guest_bytes, snapshot.guest_size) != 0) {
      fprintf(stderr, "rejected continuation kind=%d disposition=%d stage=%d\n", kind,
              result.disposition, result.transition_stage);
      failed = 1;
    }
  }
  DazeKvmCommandOwnerResult result;
  if (daze_kvm_command_owner_continue(NULL, input, &result) !=
        DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED ||
      daze_kvm_command_owner_continue(handoff, NULL, &result) !=
        DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED ||
      daze_kvm_command_owner_continue(handoff, input, NULL) !=
        DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED ||
      daze_kvm_command_owner_start_exec(handoff, &input->preflight, input->state, &result) !=
        DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED ||
      result.disposition != DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED ||
      !result.guest_execution_may_have_started || handoff->child.active)
    failed = 1;
  daze_kvm_machine_snapshot_dispose(&snapshot);
  return failed;
}

static int protected_owner_outcome(int halt) {
  uint8_t bytes[0x200] = {0};
  const uint8_t code[] = {
    0xb8, 0x87, 0x16,       /* mov ax,0x1687 */
    0xcd, 0x2f,             /* int 0x2f */
    0x9a, 0,    0,    0, 2, /* call far 0200h:0000 */
    0xb8, 0,    4,          /* mov ax,0x400 */
    0xcd, 0x31,             /* int 0x31 */
    0xb8, 0x2a, 0x4c,       /* mov ax,0x4c2a */
    0xcd, 0x21,             /* int 0x21 */
    0xf4,                   /* hlt */
  };
  memcpy(bytes + 0x20, code, sizeof(code));
  size_t code_size = sizeof(code);
  if (halt == 1) bytes[0x20 + 15] = 0xf4;
  if (halt == 2) {
    const uint8_t state_cycle[] = {
      0xb8, 0x87, 0x16,       /* mov ax,0x1687 */
      0xcd, 0x2f,             /* int 0x2f */
      0x9a, 0,    0,    0, 2, /* call far 0200h:0000 */
      0xb8, 5,    3,          /* mov ax,0x305 */
      0xcd, 0x31,             /* int 0x31 */
      0x89, 0x3e, 0,    6,    /* mov [0600h],di */
      0x89, 0x36, 2,    6,    /* mov [0602h],si */
      0xb8, 0x10, 0,          /* mov ax,0x10 */
      0x8e, 0xc0,             /* mov es,ax */
      0xbf, 0,    5,          /* mov di,0x500 */
      0x31, 0xc0,             /* xor ax,ax */
      0xff, 0x1e, 0,    6,    /* call far [0600h] */
      0xb8, 1,    0,          /* mov ax,1 */
      0xff, 0x1e, 0,    6,    /* call far [0600h] */
      0xb8, 0x2a, 0x4c,       /* mov ax,0x4c2a */
      0xcd, 0x21,             /* int 0x21 */
      0xf4,                   /* hlt */
    };
    memcpy(bytes + 0x20, state_cycle, sizeof(state_cycle));
    code_size = sizeof(state_cycle);
  }
  if (halt == 3 || halt == 6) {
    const uint8_t leave[] = {
      0xb8, 0x87, 0x16,       /* mov ax,0x1687 */
      0xcd, 0x2f,             /* int 0x2f */
      0x9a, 0,    0,    0, 2, /* call far 0200h:0000 */
      0xb8, 0xf0, 0x0f,       /* mov ax,0xff0 */
      0xb9, 0xf0, 0x0f,       /* mov cx,0xff0 */
      0xba, 0xf0, 0x0f,       /* mov dx,0xff0 */
      0xbb, 0,    0xff,       /* mov bx,0xff00 */
      0xbe, 0,    0x10,       /* mov si,0x1000 */
      0xbf, 0x60, 0,          /* mov di,0x60 */
      0xcd, 0xfc,             /* int 0xfc */
    };
    const uint8_t real[] = {
      0xc6, 6,    0,    7, 0xa1, /* mov byte [0700h],0xa1 */
      0xb8, 0x10, 0,             /* mov ax,0x10 */
      0xb9, 0x18, 0,             /* mov cx,0x18 */
      0xba, 0x40, 0,             /* mov dx,0x40 */
      0xbb, 0,    0xff,          /* mov bx,0xff00 */
      0xbe, 8,    0,             /* mov si,8 */
      0xbf, 0x80, 0,             /* mov di,0x80 */
      0xcd, 0xfc,                /* int 0xfc */
      0xf4,                      /* hlt */
    };
    const uint8_t returned[] = {
      0xc6, 6,    1,    7, 0xb2, /* mov byte [0701h],0xb2 */
      0xb8, 0x2a, 0x4c,          /* mov ax,0x4c2a */
      0xcd, 0x21,                /* int 0x21 */
    };
    memcpy(bytes + 0x20, leave, sizeof(leave));
    memcpy(bytes + 0x20 + 0x60, real, sizeof(real));
    if (halt == 6) {
      const uint8_t service[] = {
        0xb8, 0,    0x30, /* mov ax,0x3000 */
        0xcd, 0x21,       /* int 0x21 */
        0xa3, 2,    7,    /* mov [0702h],ax */
        0xb8, 0x10, 0,    /* mov ax,0x10 */
        0xb9, 0x18, 0,    /* mov cx,0x18 */
        0xba, 0x40, 0,    /* mov dx,0x40 */
        0xbb, 0,    0xff, /* mov bx,0xff00 */
        0xbe, 8,    0,    /* mov si,8 */
        0xbf, 0xa0, 0,    /* mov di,0xa0 */
        0xcd, 0xfc,       /* int 0xfc */
      };
      memcpy(bytes + 0x20 + 0x60, service, sizeof(service));
    }
    memcpy(bytes + 0x20 + 0x80, returned, sizeof(returned));
    if (halt == 6) memcpy(bytes + 0x20 + 0xa0, returned, sizeof(returned));
    code_size = halt == 6 ? 0xb0 : 0x90;
  }
  if (halt == 4) {
    const uint8_t reflected[] = {
      0xb8, 0x87, 0x16,       /* mov ax,0x1687 */
      0xcd, 0x2f,             /* int 0x2f */
      0x9a, 0,    0,    0, 2, /* call far 0200h:0000 */
      0xb8, 5,    3,          /* mov ax,0x305 */
      0xcd, 0x31,             /* int 0x31 */
      0x89, 0x3e, 0,    6,    /* mov [0600h],di */
      0x89, 0x36, 2,    6,    /* mov [0602h],si */
      0xb8, 0x10, 0,          /* mov ax,0x10 */
      0x8e, 0xc0,             /* mov es,ax */
      0xbf, 0,    7,          /* mov di,0x700 */
      0x31, 0xc0,             /* xor ax,ax */
      0xff, 0x1e, 0,    6,    /* call far [0600h] */
      0xbf, 0,    5,          /* mov di,0x500 */
      0xbb, 0x21, 0,          /* mov bx,0x21 */
      0x31, 0xc9,             /* xor cx,cx */
      0xb8, 0,    3,          /* mov ax,0x300 */
      0xcd, 0x31,             /* int 0x31 */
      0xb8, 0x2a, 0x4c,       /* mov ax,0x4c2a */
      0xcd, 0x21,             /* int 0x21 */
      0xf4,                   /* hlt */
    };
    memcpy(bytes + 0x20, reflected, sizeof(reflected));
    code_size = sizeof(reflected);
  }
  if (halt == 5) {
    const uint8_t services[] = {
      0xb8, 0,    0x30, /* mov ax,0x3000 */
      0xcd, 0x21,       /* int 0x21 */
      0xa3, 0,    6,    /* mov [0600h],ax */
      0xb8, 0,    0x30, /* mov ax,0x3000 */
      0xcd, 0x21,       /* int 0x21 */
      0xa3, 2,    6,    /* mov [0602h],ax */
      0xb8, 0x2a, 0x4c, /* mov ax,0x4c2a */
      0xcd, 0x21,       /* int 0x21 */
    };
    memcpy(bytes + 0x20 + 15, services, sizeof(services));
    code_size = 15 + sizeof(services);
  }
  if (halt == 7) {
    bytes[0x20 + 11] = 0x99;
    bytes[0x20 + 12] = 0x99;
  }
  if (halt == 8) {
    const uint8_t terminal[] = {
      0xb8, 0,    0x30, /* mov ax,0x3000 */
      0xcd, 0x21,       /* int 0x21 */
      0xb8, 0x2a, 0x4c, /* mov ax,0x4c2a */
      0xcd, 0x31,       /* int 0x31 */
    };
    memcpy(bytes + 0x20 + 15, terminal, sizeof(terminal));
    code_size = 15 + sizeof(terminal);
  }
  DazeImage image = {bytes, sizeof(bytes)};
  DazeMzHeader header = {.header_paragraphs = 2,
                         .initial_sp = 0xfffe,
                         .image_offset = 0x20,
                         .image_size = code_size,
                         .module_size = sizeof(bytes),
                         .relocation_offset = 0x1c};
  DazeKvmRunnerGenericPreflightRequest request = generic_request();
  request.process.image = &image;
  request.process.header = &header;
  request.process.psp_segment = 0x0ff0;
  request.process.load_segment = 0x1000;
  request.process.environment_segment = 0x700;
  request.process.dpmi_entry_segment = 0x200;
  request.process.dos_vector_segment = 0x300;
  request.process.guest_size = k_memory_size;
  DazeKvmCommandOwnerHandoff handoff = {0};
  if (daze_kvm_command_owner_begin(&request, &handoff) != DAZE_KVM_COMMAND_OWNER_HANDOFF_OK)
    return 1;
  if (halt == 4) {
    uint8_t *frame = (uint8_t *)handoff.machine.guest + 0x10400;
    memset(frame, 0, DAZE_DPMI_RM_FRAME_SIZE);
    daze_write_u32(frame + DAZE_DPMI_RM_EAX, 0xa5a53000);
    daze_write_u16(frame + DAZE_DPMI_RM_DS, 0xff0);
    daze_write_u16(frame + DAZE_DPMI_RM_ES, 0xff0);
    daze_write_u16(frame + DAZE_DPMI_RM_FLAGS, 0x202);
  }
  const DazeKvmRunnerDpmiHandoff *entry = &handoff.preflight.dpmi_handoff;
  DazeKvmNormalTransitionConfig config;
  DazeKvmGuestRange reserved[3];
  const size_t count = runner_reserved_ranges(request.process.guest_size, reserved);
  const DazeKvmNormalTransitionConfigInput config_input = {
    .guest_size = request.process.guest_size,
    .resident_image_end = 0x10000 + (uint32_t)code_size,
    .load_segment = 0x1000,
    .psp_segment = 0x0ff0,
    .environment_segment = 0x700,
    .dpmi_entry_segment = 0x200,
    .dos_int21_vector_segment = 0x300,
    .handoff_ds = entry->entry_snapshot.ds,
    .handoff_ss = entry->entry_snapshot.ss,
    .handoff_return_ip = entry->caller_return_ip,
    .handoff_return_cs = entry->caller_return_cs,
    .reserved_ranges = reserved,
    .reserved_range_count = count};
  DazeDpmiProcessState state = {0};
  DazeKvmCommandOwnerResult result;
  int failed = !daze_kvm_normal_transition_config_build(&config_input, &config, NULL);
  if (!failed) {
    const DazeKvmCommandOwnerInput input = {
      .preflight = request, .transition_layout = config.transition_layout, .state = &state};
    failed = rejected_continuations(&handoff, &input);
    if (failed) goto out;
    const int status = daze_kvm_command_owner_continue(
      &handoff,
      &(DazeKvmCommandOwnerInput){
        .preflight = request, .transition_layout = config.transition_layout, .state = &state},
      &result);
    failed = status != (halt == 1   ? DAZE_KVM_COMMAND_OWNER_POST_SUCCESSOR_BOUNDARY
                        : halt == 7 ? DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED
                                    : DAZE_KVM_COMMAND_OWNER_TERMINATED) ||
             status != (int)result.disposition || !result.guest_execution_may_have_started ||
             !result.handoff_present || !handoff.active || !result.transition_boundary_present ||
             !result.protected_gate_present || !state.real_mode_state_valid;
    if (halt != 1 && halt != 7 && halt != 8)
      failed |= !result.guest_exit_status_present || result.guest_exit_status != 0x2a ||
                !result.terminal_runner_request_present ||
                result.terminal_runner_request.ax != 0x4c2a;
    if (halt == 3)
      failed |= ((const uint8_t *)handoff.machine.guest)[0x10600] != 0xa1 ||
                ((const uint8_t *)handoff.machine.guest)[0x10601] != 0xb2;
    if (halt == 5)
      failed |= daze_read_u16((const uint8_t *)handoff.machine.guest + 0x10500) != 5 ||
                daze_read_u16((const uint8_t *)handoff.machine.guest + 0x10502) != 5;
    if (halt == 6) failed |= daze_read_u16((const uint8_t *)handoff.machine.guest + 0x10602) != 5;
    if (halt == 7) failed |= result.guest_exit_status_present;
    if (halt == 8)
      failed |= !result.guest_exit_status_present || result.guest_exit_status != 0x2a ||
                result.post_return_function != 0x4c2a;
    if (halt == 2) {
      DpmiAlternateState saved;
      failed |= !daze_dpmi_alternate_state_unpack((const uint8_t *)handoff.machine.guest + 0x10400,
                                                  &saved) ||
                memcmp(&saved, &state.real_mode_state, sizeof(saved)) != 0;
    }
    if (halt == 4)
      failed |= daze_read_u32((const uint8_t *)handoff.machine.guest + 0x10400 +
                              DAZE_DPMI_RM_EAX) != 0xa5a50005 ||
                !result.post_return_request_present || result.post_return_function != 0x0300;
    if (halt == 1) {
      const DazeCommandResult normalized =
        daze_kvm_command_result_normalize(&(DazeKvmCommandNormalizerInput){
          .disposition = status,
          .guest_execution_started = result.guest_execution_may_have_started,
          .exit_status_present = result.guest_exit_status_present});
      failed |= result.guest_exit_status_present || !result.post_successor_present ||
                result.post_successor.observation.raw_exit_reason != 5 ||
                normalized.disposition != DAZE_COMMAND_POSTSTART_FAILED ||
                !normalized.guest_execution_started;
    }
    if (failed)
      fprintf(stderr, "protected owner outcome halt=%d status=%d exit=%d/%u terminal=%d/%04x\n",
              halt, status, result.guest_exit_status_present, result.guest_exit_status,
              result.terminal_runner_request_present, result.terminal_runner_request.ax);
  }
out:
  daze_kvm_command_owner_handoff_destroy(&handoff);
  daze_kvm_command_owner_handoff_destroy(&handoff);
  return failed;
}

static int contract_suite(void) {
  if (state_save_successor_ordering_contract() != 0) {
    fputs("KVM command owner state-save successor ordering broke\n", stderr);
    return 1;
  }
  if (resident_exception_projection_contract() != 0) {
    fputs("KVM command owner resident exception projection broke\n", stderr);
    return 1;
  }
  if (protected_display_string_contract() != 0) {
    fputs("KVM command owner protected AH=09h display string broke its contract\n", stderr);
    return 1;
  }
  const int available = kvm_available();
  if (available == 0) return 77;
  if (available < 0) return 1;
  if (begin_rejections() || begin_outcomes() || protected_owner_outcome(0) ||
      protected_owner_outcome(1) || protected_owner_outcome(2) || protected_owner_outcome(3) ||
      protected_owner_outcome(4) || protected_owner_outcome(5) || protected_owner_outcome(6) ||
      protected_owner_outcome(7) || protected_owner_outcome(8))
    return 1;

  DazeDpmiProcessState state = {0};
  const DazeKvmCommandOwnerInput input = {
    .preflight = generic_request(), .transition_layout = transition_layout(), .state = &state};
  /* The published default vector-21 pair is the caller's alias identity, and
   * never the gate's flat absolute address. */
  const DazeDpmiInterruptVector published =
    daze_kvm_command_owner_default_vector21(&input.transition_layout);
  if (published.segment != 0x0060 || published.offset != 0x000001c8 ||
      daze_kvm_command_owner_default_vector21(NULL).segment != 0 ||
      daze_kvm_command_owner_default_vector21(NULL).offset != 0) {
    fputs("published default vector-21 pair differs from contract\n", stderr);
    return 1;
  }

  DazeKvmTransitionPlan plan;
  DazeKvmGuestRange owner_runner_reserved[3];
  const size_t owner_runner_reserved_count =
    runner_reserved_ranges(input.preflight.process.guest_size, owner_runner_reserved);
  const DazeKvmTransitionPlanInput plan_input = {
    .guest_size = input.preflight.process.guest_size,
    .resident_image_end = input.transition_layout.resident_image_end,
    .client_ds = 0x0100,
    .client_ss = 0x0100,
    .return_ip = 15,
    .return_cs = 0x0500,
    .psp_segment = input.preflight.process.psp_segment,
    .entry_segment = input.preflight.process.dpmi_entry_segment,
    .gdt_address = input.transition_layout.gdt_address,
    .ldt_address = input.transition_layout.ldt_address,
    .idt_address = input.transition_layout.idt_address,
    .idt_limit = input.transition_layout.idt_limit,
    .linear_min_address = input.transition_layout.linear_min_address,
    .linear_limit = input.transition_layout.linear_limit,
    .reserved_ranges = owner_runner_reserved,
    .reserved_range_count = owner_runner_reserved_count,
  };
  if (!daze_kvm_transition_plan_build(&plan_input, &plan, NULL)) {
    fputs("constructed command-owner plan rejected\n", stderr);
    return 1;
  }
  DazeKvmCommandOwnerHandoff handoff = {0};
  DazeKvmCommandOwnerResult result = {0};
  DazeKvmMachine admitted;
  if (daze_kvm_machine_init(&admitted, input.preflight.process.guest_size) != DAZE_KVM_MACHINE_OK)
    return 1;
  const int admitted_vm = admitted.vm;
  const int admitted_vcpu = admitted.vcpu;
  void *const admitted_guest = admitted.guest;
  DazeKvmRunnerGenericPreflightRequest wrong_size = input.preflight;
  wrong_size.process.guest_size--;
  if (daze_kvm_command_owner_begin_observe(&wrong_size, &admitted, &handoff, NULL) !=
        DAZE_KVM_COMMAND_OWNER_HANDOFF_PRESTART_REJECTED ||
      admitted.vm != admitted_vm || admitted.vcpu != admitted_vcpu ||
      admitted.guest != admitted_guest || handoff.active) {
    daze_kvm_machine_destroy(&admitted);
    return 1;
  }
  if (daze_kvm_command_owner_begin_observe(&input.preflight, &admitted, &handoff, NULL) !=
        DAZE_KVM_COMMAND_OWNER_HANDOFF_OK ||
      admitted.kvm != -1 || admitted.vm != -1 || admitted.vcpu != -1 || admitted.guest != NULL ||
      admitted.run != NULL || handoff.machine.vm != admitted_vm ||
      handoff.machine.vcpu != admitted_vcpu || handoff.machine.guest != admitted_guest ||
      !handoff.active || !handoff.preflight.dpmi_handoff.entry_snapshot.valid ||
      handoff.preflight.guest_execution_may_have_started == 0) {
    fputs("KVM command owner did not retain the generic handoff\n", stderr);
    daze_kvm_machine_destroy(&admitted);
    daze_kvm_command_owner_handoff_destroy(&handoff);
    return 1;
  }
  DazeKvmMachine second;
  if (daze_kvm_machine_init(&second, input.preflight.process.guest_size) != DAZE_KVM_MACHINE_OK) {
    daze_kvm_command_owner_handoff_destroy(&handoff);
    return 1;
  }
  const DazeKvmMachine second_before = second;
  const DazeKvmCommandOwnerHandoff owner_before = handoff;
  const int active_rejected =
    daze_kvm_command_owner_begin_observe(&input.preflight, &second, &handoff, NULL) ==
      DAZE_KVM_COMMAND_OWNER_HANDOFF_PRESTART_REJECTED &&
    memcmp(&second, &second_before, sizeof(second)) == 0 &&
    memcmp(&handoff, &owner_before, sizeof(handoff)) == 0;
  daze_kvm_machine_destroy(&second);
  if (!active_rejected || rejected_continuations(&handoff, &input)) {
    daze_kvm_command_owner_handoff_destroy(&handoff);
    return 1;
  }
  DazeKvmCommandOwnerInput rejected = input;
  rejected.transition_layout.resident_image_end--;
  if (daze_kvm_command_owner_continue(&handoff, &rejected, &result) !=
        DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED ||
      result.disposition != DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED || !handoff.active) {
    fputs("KVM command owner did not retain the parked handoff after rejection\n", stderr);
    daze_kvm_command_owner_handoff_destroy(&handoff);
    return 1;
  }
  const int status = daze_kvm_command_owner_continue(&handoff, &input, &result);
  daze_kvm_command_owner_handoff_destroy(&handoff);
  daze_kvm_machine_destroy(&admitted);
  if (fcntl(admitted_vm, F_GETFD) != -1 || errno != EBADF || fcntl(admitted_vcpu, F_GETFD) != -1 ||
      errno != EBADF)
    return 1;
  const int valid =
    status == DAZE_KVM_COMMAND_OWNER_TRANSITION_BOUNDARY &&
    result.disposition == DAZE_KVM_COMMAND_OWNER_TRANSITION_BOUNDARY &&
    result.guest_execution_may_have_started && result.handoff_present &&
    result.transition_boundary_present &&
    result.transition_successor.observation.kind == DAZE_KVM_DPMI_ENTRY_EXIT_MATCHING_DEBUG &&
    (result.transition_successor.cr0 & 1u) != 0 && result.transition_successor.cs == 0x0008 &&
    result.transition_successor.rip == 15 && result.transition_successor.ax == 0 &&
    result.transition_successor.bx == 1 && result.transition_successor.cx == 3 &&
    result.transition_successor.dx == 0x005a && result.transition_successor.si == 0 &&
    result.transition_successor.di == 0 && result.transition_successor.es == 0x0018 &&
    state.real_mode_state_valid && state.real_mode_state.cs == 0x0300 &&
    state.real_mode_state.eip == 2 && state.linear_memory.first_base == 0x6000;
  if (!valid) {
    fprintf(stderr,
            "KVM command owner status=%d disposition=%d started=%d handoff=%d boundary=%d "
            "successor=%04x:%08x ax=%04x bx=%04x cx=%04x dx=%04x si=%04x di=%04x ds=%04x es=%04x "
            "stage=%d status=%d exit=%d raw=%u state=%d %04x:%x linear=%x\n",
            status, result.disposition, result.guest_execution_may_have_started,
            result.handoff_present, result.transition_boundary_present,
            result.transition_successor.cs, result.transition_successor.rip,
            result.transition_successor.ax, result.transition_successor.bx,
            result.transition_successor.cx, result.transition_successor.dx,
            result.transition_successor.si, result.transition_successor.di,
            result.transition_successor.ds, result.transition_successor.es, result.transition_stage,
            result.transition_status, result.transition_successor.observation.kind,
            result.transition_successor.observation.raw_exit_reason, state.real_mode_state_valid,
            state.real_mode_state.cs, state.real_mode_state.eip, state.linear_memory.first_base);
    return 1;
  }
  puts("KVM command owner: passed");
  return 0;
}

int main(int argc, char **argv) {
  if (argc != 2 || strcmp(argv[1], "--trace-contract") != 0) return contract_suite();
  FILE *trace = tmpfile();
  int saved_stderr = dup(STDERR_FILENO);
  if (trace == NULL || saved_stderr < 0 || setenv("DAZE_EXEC_TRACE", "1", 1) != 0 ||
      dup2(fileno(trace), STDERR_FILENO) < 0)
    return 1;
  int status = contract_suite();
  fflush(stderr);
  if (dup2(saved_stderr, STDERR_FILENO) < 0) status = 1;
  close(saved_stderr);
  rewind(trace);
  char bytes[65536];
  size_t size = fread(bytes, 1, sizeof(bytes) - 1, trace);
  bytes[size] = 0;
  fclose(trace);
  if (status == 77) return status;
  if (size == sizeof(bytes) - 1 || strstr(bytes, "exec: live-owner reject") == NULL ||
      strstr(bytes, "state-restore: continue=") == NULL ||
      strstr(bytes, "raw-switch: status=") == NULL ||
      strstr(bytes, "runner: request=21/4c2a") == NULL)
    status = 1;
  if (status != 0) fprintf(stderr, "owner trace contract failed: %s\n", bytes);
  return status;
}
