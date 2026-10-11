#include "runner_private.h"

#include "../bios_adapter.h"
#include "int21_adapter.h"
#include "kvm_bytes.h"
#include "machine_access.h"
#include "port.h"
#include "runner_resume.h"
#include "protected.h"
#include "raw_switch.h"

#include "exec_psp.h"
#include "memory.h"
#include "advertisement.h"
#include "process_layout.h"
#include "kvm_range.h"
#include "guest_memory_layout.h"
#include "interrupt_vector.h"
#include "monotonic_clock.h"

#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
#include <linux/kvm.h>
#include <sys/ioctl.h>
#endif

enum {
  RUNNER_RECORD_OFFSET = 0,
  RUNNER_GATE_MARKER = 0xa5,
};

size_t runner_reserved_ranges(size_t guest_size, DazeKvmGuestRange ranges[3]) {
  if (ranges == NULL) return 0;
  const uint32_t size32 = guest_size > UINT32_MAX ? UINT32_MAX : (uint32_t)guest_size;
  DazeGuestLayout layout;
  if (!daze_guest_layout_init(&layout) || !daze_guest_layout_add_kvm_runner(&layout, size32) ||
      layout.count != 3)
    return 0;
  for (size_t index = 0; index < 3; ++index)
    ranges[index] = (DazeKvmGuestRange){layout.ranges[index].address, layout.ranges[index].size};
  return 3;
}

const uint8_t *runner_record(const DazeKvmMachine *machine) {
  return (const uint8_t *)machine->guest + daze_kvm_runner_gate_record_linear(machine->guest_size);
}

static int runner_vector_hosted(uint8_t vector) {
  switch (vector) {
  case DAZE_INT_BIOS_VIDEO:
  case DAZE_INT_BIOS_EQUIPMENT:
  case DAZE_INT_BIOS_TIME:
  case DAZE_INT_DOS:
  case DAZE_INT_MULTIPLEX:
  case DAZE_INT_DPMI:
  case DAZE_INT_DPMI_ENTRY:
    return 1;
  default:
    return 0;
  }
}

static int runner_frame_record(DazeKvmMachine *machine, uint8_t vector,
                               DazeKvmRunnerGateFrame *frame, uint8_t record[24]) {
  if (daze_kvm_runner_gate_frame_capture(machine, vector, frame) != DAZE_KVM_RUNNER_GATE_RESUME_OK)
    return 0;
  daze_write_u16(record, frame->ax);
  daze_write_u16(record + 2, frame->bx);
  daze_write_u16(record + 4, frame->cx);
  daze_write_u16(record + 6, frame->dx);
  daze_write_u16(record + 8, frame->ds);
  daze_write_u16(record + 10, frame->es);
  daze_write_u16(record + 12, frame->si);
  daze_write_u16(record + 14, frame->di);
  daze_write_u16(record + 16, frame->vector);
  daze_write_u16(record + 18, frame->return_ip);
  daze_write_u16(record + 20, frame->return_cs);
  daze_write_u16(record + 22, frame->flags);
  return 1;
}

static int install_gate(DazeKvmMachine *machine, uint8_t vector, uint16_t segment,
                        uint16_t offset) {
  const uint8_t gate[] = {
    0x50,                       /* push ax */
    0xb0, vector,               /* mov al, vector */
    0xe6, DAZE_PORT_GATE,       /* out 0xf4,al */
    0x83, 0xc4,           0x02, /* add sp,0x2 */
    0xcf                        /* iret */
  };
  uint8_t ivt[4] = {(uint8_t)offset, (uint8_t)(offset >> 8), (uint8_t)segment,
                    (uint8_t)(segment >> 8)};
  return daze_kvm_machine_write(machine, ((uint32_t)segment << 4) + offset, gate, sizeof(gate)) &&
         daze_kvm_machine_write(machine, (uint32_t)vector * 4u, ivt, sizeof(ivt));
}

static int load_mz(DazeKvmMachine *machine, const DazeImage *image, const DazeMzHeader *header,
                   uint16_t load_segment) {
  const uint32_t load = (uint32_t)load_segment << 4;
  if (header->image_size > machine->guest_size - load) return 0;
  memcpy((uint8_t *)machine->guest + load, image->bytes + header->image_offset, header->image_size);
  return daze_mz_relocate_image(image->bytes, image->size, header, load_segment,
                                (uint8_t *)machine->guest + load, header->image_size);
}

uint8_t *runner_mailbox(DazeKvmMachine *machine) {
  return (uint8_t *)machine->guest + daze_kvm_runner_gate_mailbox_linear(machine->guest_size);
}

void daze_kvm_runner_gate_reply_init(const uint8_t *record, uint8_t *mailbox) {
  daze_write_u16(mailbox, daze_read_u16(record));
  daze_write_u16(mailbox + 2, daze_read_u16(record + 2));
  daze_write_u16(mailbox + 4, daze_read_u16(record + 4));
  daze_write_u16(mailbox + 6, daze_read_u16(record + 6));
  daze_write_u16(mailbox + 8, daze_read_u16(record + 12));
  daze_write_u16(mailbox + 10, daze_read_u16(record + 14));
  daze_write_u16(mailbox + 12, daze_read_u16(record + 10));
  daze_write_u16(mailbox + 14, daze_read_u16(record + 22));
}

static void reply_carry(uint8_t *mailbox, int carry) {
  uint16_t flags = daze_read_u16(mailbox + 14);
  flags = carry ? (uint16_t)(flags | 1u) : (uint16_t)(flags & ~1u);
  daze_write_u16(mailbox + 14, flags);
}

static DazeKvmPreflightBoundaryDisposition preflight_boundary_broker_impl(
  DazeKvmMachine *machine, DazeDosfsFileService *files, DazeDosProcessState *process_state,
  DazeDosMemory *dos_memory, uint16_t dpmi_entry_segment, const uint8_t record[24],
  uint8_t mailbox[DAZE_KVM_RUNNER_GATE_MAILBOX_SIZE], DazeKvmPreflightBoundaryResult *result) {
  if (result != NULL) *result = (DazeKvmPreflightBoundaryResult){0};
  if (machine == NULL || machine->guest == NULL || files == NULL || record == NULL ||
      mailbox == NULL)
    return DAZE_KVM_PREFLIGHT_BOUNDARY_FAILED;
  const uint8_t vector = (uint8_t)daze_read_u16(record + 16);
  const uint16_t ax = daze_read_u16(record);
  const uint16_t bx = daze_read_u16(record + 2);
  const uint16_t cx = daze_read_u16(record + 4);
  if (vector == DAZE_INT_DPMI_ENTRY) return DAZE_KVM_PREFLIGHT_BOUNDARY_DPMI_ENTRY;
  const DazeKvmPreflightBoundaryDisposition bios_reply = daze_kvm_bios_dispatch(record, mailbox);
  if (bios_reply != DAZE_KVM_PREFLIGHT_BOUNDARY_UNSUPPORTED) return bios_reply;
  if (vector == DAZE_INT_MULTIPLEX && (ax == 0x1687 || ax == 0x1600)) {
    const DazeDpmiHostAdvertisementInput input = {
      .installed = 1,
      .flags = 1,
      .processor = 3,
      .major = 0,
      .minor = 0x5a,
      .private_data_paragraphs = 0,
      .entry_segment = dpmi_entry_segment,
      .entry_offset = 0,
    };
    DazeDpmiHostAdvertisement advertisement;
    if (!daze_dpmi_host_advertisement_build(&input, &advertisement))
      return DAZE_KVM_PREFLIGHT_BOUNDARY_FAILED;
    daze_kvm_runner_gate_reply_init(record, mailbox);
    if (ax == 0x1687) {
      daze_write_u16(mailbox, advertisement.ax);
      daze_write_u16(mailbox + 2, advertisement.bx);
      daze_write_u16(mailbox + 4, advertisement.cx);
      daze_write_u16(mailbox + 6, advertisement.dx);
      daze_write_u16(mailbox + 8, advertisement.si);
      daze_write_u16(mailbox + 10, advertisement.di);
      daze_write_u16(mailbox + 12, advertisement.es);
      reply_carry(mailbox, advertisement.carry);
    } else {
      uint16_t reply_ax;
      int carry;
      if (!daze_dpmi_host_windows_reply(&advertisement, &reply_ax, &carry))
        return DAZE_KVM_PREFLIGHT_BOUNDARY_FAILED;
      daze_write_u16(mailbox, reply_ax);
      reply_carry(mailbox, carry);
    }
    return DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED;
  }
  if (vector == DAZE_INT_MULTIPLEX && ax == 0x4300) {
    daze_kvm_runner_gate_reply_init(record, mailbox);
    reply_carry(mailbox, 0);
    return DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED;
  }
  if (vector == DAZE_INT_MULTIPLEX && ax == 0xfb43 && bx == 0x0100) {
    daze_kvm_runner_gate_reply_init(record, mailbox);
    return DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED;
  }
  if (vector == DAZE_INT_MULTIPLEX && ax == 0xfb42 && bx == 0x0014 && cx == 0x0001) {
    daze_kvm_runner_gate_reply_init(record, mailbox);
    daze_write_u16(mailbox + 2, 1);
    return DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED;
  }
  if (vector != DAZE_INT_DOS) return DAZE_KVM_PREFLIGHT_BOUNDARY_UNSUPPORTED;
  return daze_kvm_int21_dispatch(machine, files, process_state, dos_memory, record, mailbox,
                                 result);
}

DazeKvmPreflightBoundaryDisposition daze_kvm_preflight_boundary_broker(
  DazeKvmMachine *machine, DazeDosfsFileService *files, DazeDosProcessState *process_state,
  DazeDosMemory *dos_memory, uint16_t dpmi_entry_segment, const uint8_t record[24],
  uint8_t mailbox[DAZE_KVM_RUNNER_GATE_MAILBOX_SIZE], DazeKvmPreflightBoundaryResult *result) {
  DazeRunMetrics *metrics =
    files != NULL && files->run_metrics != NULL && files->run_metrics->enabled ? files->run_metrics
                                                                               : NULL;
  const uint8_t vector = record != NULL ? (uint8_t)daze_read_u16(record + 16) : 0;
  const uint8_t function = record != NULL ? (uint8_t)(daze_read_u16(record) >> 8) : 0;
  const uint64_t started = metrics != NULL ? monotonic_nanoseconds() : 0;
  const DazeKvmPreflightBoundaryDisposition disposition = preflight_boundary_broker_impl(
    machine, files, process_state, dos_memory, dpmi_entry_segment, record, mailbox, result);
  if (disposition == DAZE_KVM_PREFLIGHT_BOUNDARY_UNSUPPORTED && vector == DAZE_INT_DOS) {
    /* The gate's live CS:IP points into the transport stub; report the saved
     * guest return address and registers instead. */
    fprintf(stderr,
            "unsupported DOS 21h function %02xh (AX=%04x BX=%04x CX=%04x DX=%04x) "
            "at CS:IP=%04x:%04x DS=%04x\n",
            function, daze_read_u16(record), daze_read_u16(record + 2), daze_read_u16(record + 4),
            daze_read_u16(record + 6), daze_read_u16(record + 20), daze_read_u16(record + 18),
            daze_read_u16(record + 8));
  }
  if (metrics != NULL) {
    metrics->kvm_boundary_broker_calls++;
    metrics->kvm_boundary_vectors[vector]++;
    if (vector == DAZE_INT_DOS) {
      metrics->kvm_dos_boundary_broker_calls++;
      metrics->kvm_dos_functions[function]++;
    } else if (vector == DAZE_INT_DPMI_ENTRY) {
      metrics->kvm_dpmi_entry_boundary_broker_calls++;
    } else {
      metrics->kvm_other_boundary_broker_calls++;
    }
    const uint64_t finished = monotonic_nanoseconds();
    if (finished >= started) {
      const uint64_t elapsed = finished - started;
      metrics->kvm_boundary_broker_nanoseconds += elapsed;
      if (vector == DAZE_INT_DOS) metrics->kvm_dos_function_nanoseconds[function] += elapsed;
    }
  }
  return disposition;
}

int capture_real_mode_entry_snapshot(DazeKvmMachine *machine, DazeKvmRunnerDpmiHandoff *handoff) {
#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
  struct kvm_regs regs;
  struct kvm_sregs sregs;
  if (ioctl(machine->vcpu, KVM_GET_REGS, &regs) < 0 ||
      ioctl(machine->vcpu, KVM_GET_SREGS, &sregs) < 0 || regs.rsp > UINT16_MAX - 2u)
    return 0;
  const uint32_t saved_bp_address = (uint32_t)sregs.ss.base + (uint16_t)regs.rsp;
  const uint32_t caller_return_address = saved_bp_address + 8;
  if (caller_return_address < saved_bp_address || saved_bp_address < sregs.ss.base ||
      !daze_kvm_range_fits(machine->guest_size, saved_bp_address, sizeof(uint16_t)) ||
      !daze_kvm_range_fits(machine->guest_size, caller_return_address, 4))
    return 0;
  handoff->caller_return_ip =
    daze_read_u16((const uint8_t *)machine->guest + caller_return_address);
  handoff->caller_return_cs =
    daze_read_u16((const uint8_t *)machine->guest + caller_return_address + 2);
  handoff->entry_snapshot = (DazeKvmRealModeEntrySnapshot){
    .valid = 1,
    .cr0 = (uint32_t)sregs.cr0,
    .ax = handoff->ax,
    .bx = handoff->bx,
    .cx = handoff->cx,
    .dx = handoff->dx,
    .si = handoff->si,
    .di = handoff->di,
    .bp = daze_read_u16((const uint8_t *)machine->guest + saved_bp_address),
    .cs = handoff->return_cs,
    .ip = handoff->return_ip,
    .ds = handoff->ds,
    .es = handoff->es,
    .fs = sregs.fs.selector,
    .gs = sregs.gs.selector,
    .ss = sregs.ss.selector,
    .sp = (uint16_t)regs.rsp + 2u,
    .flags = handoff->flags,
  };
  return 1;
#else
  (void)machine;
  (void)handoff;
  return 0;
#endif
}

int bootstrap_real_mode_runner(DazeKvmMachine *machine, const DazeImage *image,
                               const DazeMzHeader *header, const char *command_tail,
                               const char *guest_path, uint16_t psp_segment,
                               uint16_t environment_segment, uint16_t dpmi_entry_segment,
                               uint16_t dos_vector_segment, uint16_t load_segment,
                               const uint8_t *psp_override,
                               const DazeKvmRunnerRequestCommon *process) {
  const int image_ok = load_mz(machine, image, header, load_segment);
  const int process_ok =
    image_ok && (process->exec_child ||
                 daze_image_write_process_with_memory(daze_kvm_machine_write, machine, command_tail,
                                                      guest_path, psp_segment, environment_segment,
                                                      dpmi_entry_segment, dos_vector_segment,
                                                      process->env_vars, process->env_var_count));
  const int psp_ok = process_ok && ((!process->exec_child && psp_override == NULL) ||
                                    daze_kvm_machine_write(machine, (uint32_t)psp_segment << 4,
                                                           psp_override, DAZE_DOS_EXEC_PSP_SIZE));
  const int cpu_ok =
    psp_ok && daze_kvm_machine_set_real_mode(
                machine, (uint16_t)(load_segment + header->initial_cs), header->initial_ip,
                (uint16_t)(load_segment + header->initial_ss), header->initial_sp, psp_segment,
                psp_segment) == DAZE_KVM_MACHINE_OK;
  const int registers_ok =
    cpu_ok && (!process->preserve_initial_gprs ||
               daze_kvm_machine_set_general_registers(machine, process->initial_ax,
                                                      process->initial_bx, process->initial_cx,
                                                      process->initial_dx, process->initial_si,
                                                      process->initial_di) == DAZE_KVM_MACHINE_OK);
  if (!image_ok || !process_ok || !psp_ok || !cpu_ok || !registers_ok) {
    return 0;
  }
  static const uint8_t host_vectors[] = {
    DAZE_INT_BIOS_VIDEO, DAZE_INT_BIOS_EQUIPMENT, DAZE_INT_BIOS_TIME, DAZE_INT_DOS,
    DAZE_INT_MULTIPLEX,  DAZE_INT_DPMI,           DAZE_INT_DPMI_ENTRY};
  for (unsigned i = 0; i < sizeof(host_vectors) / sizeof(host_vectors[0]); ++i) {
    const uint8_t vector = host_vectors[i];
    const uint16_t segment = vector == DAZE_INT_DOS
                               ? dos_vector_segment
                               : (uint16_t)(daze_kvm_runner_gate_linear(machine->guest_size) >> 4);
    const uint16_t offset =
      vector == DAZE_INT_DOS ? 0 : (uint16_t)vector * DAZE_KVM_RUNNER_GATE_STRIDE;
    if (!install_gate(machine, vector, segment, offset)) return 0;
  }
  return 1;
}

int daze_kvm_runner_gated_port_read(uint16_t port, uint8_t *value) {
  if (port != DAZE_PORT_PIC_MASTER && port != DAZE_PORT_PIC_SLAVE) return 0;
  if (value != NULL) *value = 0;
  return 1;
}

int serve_gated_port_read(DazeKvmMachine *machine, const DazeKvmPortAccess *access) {
  if (access->direction != DAZE_KVM_PORT_IN) return 0;
  uint8_t value = 0;
  if (!daze_kvm_runner_gated_port_read(access->port, &value)) return 0;
  return daze_kvm_machine_supply_port_in(machine, value) == DAZE_KVM_MACHINE_OK;
}

static int process_layout_valid(const DazeKvmRunnerRequestCommon *process,
                                DazeKvmProcessLayoutFailure *failure) {
  DazeKvmGuestRange reserved[3];
  const size_t reserved_count = runner_reserved_ranges(process->guest_size, reserved);
  const DazeKvmProcessLayout layout = {
    .guest_size = process->guest_size,
    .image_size = process->header->image_size,
    .psp_segment = process->psp_segment,
    .environment_segment = process->environment_segment,
    .dpmi_entry_segment = process->dpmi_entry_segment,
    .dos_vector_segment = process->dos_vector_segment,
    .load_segment = process->load_segment,
    .reserved_ranges = reserved,
    .reserved_range_count = reserved_count,
  };
  return daze_kvm_process_layout_valid(&layout, failure);
}

static DazeGuestOwner runner_failure_range_owner(const DazeKvmGuestRange *triple,
                                                 size_t triple_count, uint32_t image_address,
                                                 uint32_t image_size, DazeKvmGuestRange range) {
  static const DazeGuestOwner roles[] = {DAZE_GUEST_OWNER_KVM_RUNNER_GATE_ARENA,
                                         DAZE_GUEST_OWNER_KVM_RUNNER_RECORD,
                                         DAZE_GUEST_OWNER_KVM_RUNNER_MAILBOX};
  if (range.address == image_address && range.size == image_size) return DAZE_GUEST_OWNER_IMAGE;
  for (size_t index = 0; index < triple_count && index < 3; ++index)
    if (range.address == triple[index].address && range.size == triple[index].size)
      return roles[index];
  return DAZE_GUEST_OWNER_NONE;
}

/* Reject layout collisions before guest execution, while backend fallback is still
 * permitted. */
static void report_process_layout_failure(const DazeKvmRunnerRequestCommon *process,
                                          const DazeKvmProcessLayoutFailure *failure) {
  DazeKvmGuestRange reserved[3];
  const size_t reserved_count = runner_reserved_ranges(process->guest_size, reserved);
  const uint32_t image_address = (uint32_t)process->load_segment << 4;
  const uint32_t image_size =
    process->header->image_size > UINT32_MAX ? UINT32_MAX : (uint32_t)process->header->image_size;
  const DazeGuestRange first = {failure->first.address, (uint32_t)failure->first.size,
                                runner_failure_range_owner(reserved, reserved_count, image_address,
                                                           image_size, failure->first)};
  const DazeGuestRange second = {failure->second.address, (uint32_t)failure->second.size,
                                 runner_failure_range_owner(reserved, reserved_count, image_address,
                                                            image_size, failure->second)};
  char first_text[64], second_text[64];
  daze_guest_layout_format_range(first_text, sizeof(first_text), first);
  daze_guest_layout_format_range(second_text, sizeof(second_text), second);
  switch (failure->kind) {
  case DAZE_KVM_PROCESS_LAYOUT_RANGE_OVERLAP:
    fprintf(stderr, "kvm: runner process layout rejected at preflight: %s overlaps %s\n",
            first_text, second_text);
    break;
  case DAZE_KVM_PROCESS_LAYOUT_RANGE_OUT_OF_GUEST:
    if (failure->first.size == 0)
      fprintf(stderr,
              "kvm: runner process layout rejected at preflight: process segment %04x lies "
              "outside the %08x-byte guest\n",
              failure->first.address >> 4, process->guest_size);
    else
      fprintf(stderr,
              "kvm: runner process layout rejected at preflight: %s does not fit the %08x-byte "
              "guest\n",
              first_text, process->guest_size);
    break;
  case DAZE_KVM_PROCESS_LAYOUT_RESERVED_EMPTY:
    fprintf(stderr,
            "kvm: runner process layout rejected at preflight: empty KVM runner reservation at "
            "%08x\n",
            failure->first.address);
    break;
  case DAZE_KVM_PROCESS_LAYOUT_VALID:
  case DAZE_KVM_PROCESS_LAYOUT_BAD_INPUT:
  default:
    fprintf(stderr, "kvm: runner process layout rejected at preflight: internal error\n");
    break;
  }
}

int daze_kvm_runner_process_valid(const DazeKvmRunnerRequestCommon *process) {
  if (process == NULL || process->image == NULL || process->header == NULL ||
      process->image->bytes == NULL || process->image->size == 0 || process->command_tail == NULL ||
      process->guest_path == NULL || process->mounts == NULL || process->handles == NULL ||
      process->files == NULL || process->guest_size == 0 ||
      process->stop_linear >= process->guest_size || strlen(process->command_tail) > 126)
    return 0;
  DazeKvmProcessLayoutFailure failure;
  if (process_layout_valid(process, &failure)) return 1;
  report_process_layout_failure(process, &failure);
  return 0;
}

static int generic_preflight_valid(const DazeKvmRunnerGenericPreflightRequest *request) {
  return request != NULL && daze_kvm_runner_process_valid(&request->process);
}

int daze_kvm_runner_resume_to_generic_boundary(DazeKvmMachine *machine,
                                               const DazeKvmRunnerGenericPreflightRequest *request,
                                               DazeDosProcessState *process_state,
                                               DazeDosMemory *dos_memory,
                                               DazeKvmRunnerGenericPreflightResult *result) {
  if (result != NULL) *result = (DazeKvmRunnerGenericPreflightResult){0};
  if (machine == NULL || result == NULL || process_state == NULL || dos_memory == NULL ||
      !generic_preflight_valid(request))
    return DAZE_KVM_GENERIC_PREFLIGHT_INVALID;
  daze_kvm_machine_set_run_metrics(machine, request->process.files->run_metrics);
  result->guest_execution_may_have_started = 1;
  for (;;) {
    uint16_t port;
    uint8_t marker;
    DazeKvmPortAccess access;
    if (daze_kvm_machine_run_port_access(machine, &access) != DAZE_KVM_MACHINE_OK) {
      result->terminal_observation_status =
        daze_kvm_machine_capture_exit(machine, &result->terminal_observation);
      result->disposition = DAZE_KVM_GENERIC_PREFLIGHT_FAILED;
      return result->disposition;
    }
    if (serve_gated_port_read(machine, &access)) continue;
    if (access.direction != DAZE_KVM_PORT_OUT) {
      result->terminal_observation_status =
        daze_kvm_machine_capture_exit(machine, &result->terminal_observation);
      result->disposition = DAZE_KVM_GENERIC_PREFLIGHT_FAILED;
      return result->disposition;
    }
    port = access.port;
    marker = access.value;
    if (port == 0x00) continue;
    if (port == DAZE_PORT_GATE && marker == DAZE_KVM_RAW_SWITCH_GATE_MARKER) {
      result->disposition = DAZE_KVM_GENERIC_PREFLIGHT_RAW_SWITCH;
      return result->disposition;
    }
    if (port != DAZE_PORT_GATE || !runner_vector_hosted(marker)) {
      result->terminal_observation_status =
        daze_kvm_machine_capture_exit(machine, &result->terminal_observation);
      result->disposition = DAZE_KVM_GENERIC_PREFLIGHT_FAILED;
      return result->disposition;
    }
    if (marker == DAZE_KVM_PROTECTED_DOS_MARKER) {
#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
      struct kvm_sregs sregs;
      if (daze_kvm_machine_get_sregs(machine, &sregs) != DAZE_KVM_MACHINE_OK) {
        result->disposition = DAZE_KVM_GENERIC_PREFLIGHT_FAILED;
        return result->disposition;
      }
      if ((sregs.cr0 & 1u) != 0) {
        result->disposition = DAZE_KVM_GENERIC_PREFLIGHT_PROTECTED_BOUNDARY;
        return result->disposition;
      }
#endif
    }
    DazeKvmRunnerGateFrame frame;
    uint8_t record[24] = {0};
    if (!runner_frame_record(machine, marker, &frame, record)) {
      result->disposition = DAZE_KVM_GENERIC_PREFLIGHT_FAILED;
      return result->disposition;
    }
    result->request_vector = (uint8_t)daze_read_u16(record + 16);
    result->request_ax = daze_read_u16(record);
    result->request_bx = daze_read_u16(record + 2);
    result->request_cx = daze_read_u16(record + 4);
    result->request_dx = daze_read_u16(record + 6);
    result->request_ds = daze_read_u16(record + 8);
    result->request_es = daze_read_u16(record + 10);
    result->request_si = daze_read_u16(record + 12);
    result->request_di = daze_read_u16(record + 14);
    uint8_t mailbox_before[DAZE_KVM_RUNNER_GATE_MAILBOX_SIZE] = {0};
    uint8_t mailbox_after[DAZE_KVM_RUNNER_GATE_MAILBOX_SIZE] = {0};
    DazeKvmPreflightBoundaryResult boundary;
    const DazeKvmPreflightBoundaryDisposition disposition = daze_kvm_preflight_boundary_broker(
      machine, request->process.files, process_state, dos_memory,
      request->process.dpmi_entry_segment, record, mailbox_after, &boundary);
    if (disposition == DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED) {
      const int reply_status = daze_kvm_runner_gate_frame_reply(machine, &frame, mailbox_after);
      if (reply_status != DAZE_KVM_RUNNER_GATE_RESUME_OK) {
        result->disposition = DAZE_KVM_GENERIC_PREFLIGHT_FAILED;
        return result->disposition;
      }
      if (boundary.reply_ds_present) {
        const int ds_status = daze_kvm_runner_gate_frame_set_ds(machine, boundary.reply_ds);
        if (ds_status != DAZE_KVM_RUNNER_GATE_RESUME_OK) {
          result->disposition = DAZE_KVM_GENERIC_PREFLIGHT_FAILED;
          return result->disposition;
        }
      }
      continue;
    }
    result->mailbox_unchanged = memcmp(mailbox_before, mailbox_after, sizeof(mailbox_before)) == 0;
    if (disposition == DAZE_KVM_PREFLIGHT_BOUNDARY_TERMINATED) {
      result->disposition = DAZE_KVM_GENERIC_PREFLIGHT_TERMINATED;
      return result->disposition;
    }
    if (disposition == DAZE_KVM_PREFLIGHT_BOUNDARY_EXEC) {
      result->disposition = DAZE_KVM_GENERIC_PREFLIGHT_EXEC;
      return result->disposition;
    }
    if (disposition != DAZE_KVM_PREFLIGHT_BOUNDARY_DPMI_ENTRY) {
      result->terminal_observation_status =
        daze_kvm_machine_capture_exit(machine, &result->terminal_observation);
      result->disposition = disposition == DAZE_KVM_PREFLIGHT_BOUNDARY_UNSUPPORTED
                              ? DAZE_KVM_GENERIC_PREFLIGHT_UNSUPPORTED
                              : DAZE_KVM_GENERIC_PREFLIGHT_FAILED;
      return result->disposition;
    }
    result->dpmi_handoff = (DazeKvmRunnerDpmiHandoff){
      .valid = 1,
      .vector = result->request_vector,
      .ax = result->request_ax,
      .bx = result->request_bx,
      .cx = result->request_cx,
      .dx = result->request_dx,
      .si = daze_read_u16(record + 12),
      .di = daze_read_u16(record + 14),
      .ds = result->request_ds,
      .es = daze_read_u16(record + 10),
      .flags = daze_read_u16(record + 22),
      .return_cs = daze_read_u16(record + 20),
      .return_ip = daze_read_u16(record + 18),
    };
    if (!capture_real_mode_entry_snapshot(machine, &result->dpmi_handoff)) {
      result->dpmi_handoff = (DazeKvmRunnerDpmiHandoff){0};
      result->disposition = DAZE_KVM_GENERIC_PREFLIGHT_FAILED;
      return result->disposition;
    }
    result->disposition = DAZE_KVM_GENERIC_PREFLIGHT_DPMI_ENTRY;
    return result->disposition;
  }
}

int daze_kvm_runner_preflight_to_generic_boundary(
  DazeKvmMachine *machine, const DazeKvmRunnerGenericPreflightRequest *request,
  DazeKvmRunnerGenericPreflightResult *result) {
  if (result != NULL) *result = (DazeKvmRunnerGenericPreflightResult){0};
  if (machine == NULL || result == NULL || !generic_preflight_valid(request))
    return DAZE_KVM_GENERIC_PREFLIGHT_INVALID;
  DazeDosProcessState process_state;
  daze_dos_process_state_init(&process_state, request->process.psp_segment);
  daze_dos_process_state_seed_vectors(&process_state, request->process.dos_vector_segment);
  const uint32_t image_address = (uint32_t)request->process.load_segment << 4;
  uint32_t allocation_start = (image_address + request->process.header->image_size + 15u) >> 4;
  if (allocation_start < 0x3000) allocation_start = 0x3000;
  DazeDosMemory dos_memory;
  daze_dos_memory_init(&dos_memory, allocation_start < 0xa000 ? (uint16_t)allocation_start : 0xa000,
                       0xa000);
  /* The local process state owns any open find directory; callers do not retain it. */
  const int disposition = daze_kvm_runner_bootstrap_to_generic_boundary(
    machine, request, &process_state, &dos_memory, result);
  daze_dos_process_state_dispose(&process_state);
  return disposition;
}

int daze_kvm_runner_bootstrap_to_generic_boundary(
  DazeKvmMachine *machine, const DazeKvmRunnerGenericPreflightRequest *request,
  DazeDosProcessState *process_state, DazeDosMemory *dos_memory,
  DazeKvmRunnerGenericPreflightResult *result) {
  if (result != NULL) *result = (DazeKvmRunnerGenericPreflightResult){0};
  if (machine == NULL || result == NULL || process_state == NULL || dos_memory == NULL ||
      !generic_preflight_valid(request))
    return DAZE_KVM_GENERIC_PREFLIGHT_INVALID;
  daze_kvm_machine_set_run_metrics(machine, request->process.files->run_metrics);
  if (!bootstrap_real_mode_runner(
        machine, request->process.image, request->process.header, request->process.command_tail,
        request->process.guest_path, request->process.psp_segment,
        request->process.environment_segment, request->process.dpmi_entry_segment,
        request->process.dos_vector_segment, request->process.load_segment,
        request->process.psp_override, &request->process)) {
    result->disposition = DAZE_KVM_GENERIC_PREFLIGHT_FAILED;
    return result->disposition;
  }
  return daze_kvm_runner_resume_to_generic_boundary(machine, request, process_state, dos_memory,
                                                    result);
}
