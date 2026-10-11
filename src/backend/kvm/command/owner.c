#include "owner.h"
#include "interrupt_vector.h"
#include "legacy_exception.h"

#include "kvm_bytes.h"
#include "port.h"
#include "boundary.h"
#include "normal_config.h"
#include "kvm_range.h"
#include "rm_procedure.h"
#include "runner_resume.h"
#include "runner/runner_private.h"
#include "exec_loader.h"
#include "exec_psp.h"
#include "exec_request.h"
#include "int21_service.h"
#include "mz_layout.h"
#include "guest_memory_layout.h"
#include "selector.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int continue_from_handoff(DazeKvmCommandOwnerHandoff *handoff,
                                 const DazeKvmCommandOwnerInput *input,
                                 const DazeKvmDpmiEntryResult *live_boundary,
                                 int restore_transition_artifacts,
                                 const DazeKvmResidentGdtState *resident_gdt,
                                 DazeKvmCommandOwnerResult *result);

static int resume_exec_parent(DazeKvmCommandOwnerHandoff *handoff,
                              DazeDosProcessState *process_state, DazeDosMemory *dos_memory,
                              uint8_t child_exit_status, uint8_t child_termination_type,
                              uint16_t resident_paragraphs,
                              const DazeKvmCommandOwnerInput *resident_input,
                              DazeKvmCommandOwnerResult *result);

int daze_kvm_command_owner_reply_exec_success(DazeKvmMachine *machine) {
  DazeKvmRunnerGateFrame frame;
  uint8_t reply[DAZE_KVM_RUNNER_GATE_REPLY_SIZE] = {0};
  const int capture = daze_kvm_runner_gate_frame_capture(machine, DAZE_INT_DOS, &frame);
  if (capture != DAZE_KVM_RUNNER_GATE_RESUME_OK) return capture;
  if (frame.ax != 0x4b00) return DAZE_KVM_RUNNER_GATE_RESUME_INVALID;
  /* The gate discards its saved AX before IRET. Supply the successful EXEC
   * return while preserving every other reply register from its captured
   * frame, and change only CF in the already-pushed FLAGS word. */
  daze_write_u16(reply, 0);
  daze_write_u16(reply + 2, frame.bx);
  daze_write_u16(reply + 4, frame.cx);
  daze_write_u16(reply + 6, frame.dx);
  daze_write_u16(reply + 8, frame.si);
  daze_write_u16(reply + 10, frame.di);
  daze_write_u16(reply + 12, frame.es);
  daze_write_u16(reply + 14, (uint16_t)(frame.flags & ~1u));
  return daze_kvm_runner_gate_frame_reply(machine, &frame, reply);
}

static int resident_end_for_request(const DazeKvmRunnerRequestCommon *process,
                                    uint32_t *resident_image_end) {
  if (process->header == NULL || resident_image_end == NULL) return 0;
  const uint32_t image_start = (uint32_t)process->load_segment << 4;
  if (process->header->image_size > UINT32_MAX - image_start) return 0;
  *resident_image_end = image_start + (uint32_t)process->header->image_size;
  return 1;
}

static int layout_agrees_with_request(const DazeKvmCommandOwnerInput *input) {
  uint32_t resident_image_end = 0;
  return input != NULL && input->preflight.process.guest_size != 0 &&
         resident_end_for_request(&input->preflight.process, &resident_image_end) &&
         input->transition_layout.resident_image_end == resident_image_end;
}

static int endpoint_layout_valid(const DazeKvmCommandOwnerInput *input) {
  const DazeKvmCommandOwnerTransitionLayout *layout = &input->transition_layout;
  if (layout->state_save_gate == NULL) return 1;
  return layout->state_save_endpoints.state_buffer_size == DAZE_DPMI_ALTERNATE_STATE_SIZE &&
         layout->state_save_endpoints.pm_selector != 0 &&
         layout->raw_switch_endpoints.pm_selector != 0 && layout->raw_switch_linear != 0 &&
         layout->raw_switch_linear < input->preflight.process.guest_size;
}

static int handoff_agrees_with_request(const DazeKvmRunnerRequestCommon *process,
                                       const DazeKvmRunnerDpmiHandoff *handoff) {
  if (process == NULL || handoff == NULL) return 0;
  const uint16_t trampoline_return_ip = (uint16_t)((uint32_t)process->dpmi_entry_segment << 4) + 2;
  const int canonical_entry =
    handoff->return_cs == process->dpmi_entry_segment && handoff->return_ip == 2;
  /* A real-mode far pointer may name the configured trampoline through its
   * segment-zero physical alias. Admit only that exact alias. */
  const int zero_segment_trampoline_alias =
    handoff->return_cs == 0 && handoff->return_ip == trampoline_return_ip;
  return handoff->valid && (canonical_entry || zero_segment_trampoline_alias) &&
         handoff->entry_snapshot.valid && handoff->entry_snapshot.cs == handoff->return_cs &&
         handoff->entry_snapshot.ip == handoff->return_ip &&
         handoff->entry_snapshot.ds == handoff->ds && handoff->caller_return_cs != 0;
}

static int process_matches(const DazeKvmRunnerRequestCommon *first,
                           const DazeKvmRunnerRequestCommon *second) {
  return first != NULL && second != NULL && first->image == second->image &&
         first->header == second->header && first->command_tail == second->command_tail &&
         first->guest_path == second->guest_path && first->psp_segment == second->psp_segment &&
         first->environment_segment == second->environment_segment &&
         first->dpmi_entry_segment == second->dpmi_entry_segment &&
         first->dos_vector_segment == second->dos_vector_segment &&
         first->load_segment == second->load_segment && first->guest_size == second->guest_size &&
         first->mounts == second->mounts && first->handles == second->handles &&
         first->files == second->files;
}

static int plan_entry_layout(const DazeKvmTransitionPlan *plan,
                             const DazeKvmProtectedGateLayout *gate,
                             const DazeKvmProtectedGateArtifacts *gate_artifacts,
                             const DazeKvmStateSaveGateLayout *state_gate,
                             const DazeKvmStateSaveGateArtifacts *state_gate_artifacts,
                             const DazeKvmRawSwitchGateLayout *raw_gate,
                             const DazeKvmRawSwitchGateArtifacts *raw_gate_artifacts,
                             DazeKvmGuestWrite *writes, DazeKvmDpmiEntryLayout *layout,
                             uint32_t terminal_linear, size_t guest_size) {
  if (plan == NULL || writes == NULL || layout == NULL ||
      plan->write_count > DAZE_KVM_TRANSITION_PLAN_WRITE_COUNT)
    return 0;
  for (size_t index = 0; index < plan->write_count; ++index)
    writes[index] = plan->writes[index];
  size_t write_count = plan->write_count;
  if (gate != NULL && gate_artifacts != NULL) {
    writes[write_count++] = (DazeKvmGuestWrite){.address = gate->handler_address,
                                                .bytes = gate_artifacts->handler,
                                                .size = gate_artifacts->handler_size};
    writes[write_count++] = (DazeKvmGuestWrite){.address = gate->dos_handler_address,
                                                .bytes = gate_artifacts->dos_handler,
                                                .size = gate_artifacts->dos_handler_size};
    writes[write_count++] = (DazeKvmGuestWrite){.address = gate->default_dos_stub_address,
                                                .bytes = gate_artifacts->default_dos_stub,
                                                .size = gate_artifacts->default_dos_stub_size};
    writes[write_count++] = (DazeKvmGuestWrite){.address = gate->idt_address + DAZE_INT_DPMI * 8u,
                                                .bytes = gate_artifacts->idt_entry,
                                                .size = sizeof(gate_artifacts->idt_entry)};
    writes[write_count++] = (DazeKvmGuestWrite){.address = gate->idt_address + DAZE_INT_DOS * 8u,
                                                .bytes = gate_artifacts->dos_idt_entry,
                                                .size = sizeof(gate_artifacts->dos_idt_entry)};
  }
  if (state_gate != NULL && state_gate_artifacts != NULL) {
    writes[write_count++] = (DazeKvmGuestWrite){.address = state_gate->handler_address,
                                                .bytes = state_gate_artifacts->handler,
                                                .size = sizeof(state_gate_artifacts->handler)};
    writes[write_count++] =
      (DazeKvmGuestWrite){.address = state_gate->idt_address + DAZE_KVM_STATE_SAVE_GATE_VECTOR * 8u,
                          .bytes = state_gate_artifacts->idt_entry,
                          .size = sizeof(state_gate_artifacts->idt_entry)};
  }
  if (raw_gate != NULL && raw_gate_artifacts != NULL) {
    writes[write_count++] = (DazeKvmGuestWrite){.address = raw_gate->handler_address,
                                                .bytes = raw_gate_artifacts->handler,
                                                .size = sizeof(raw_gate_artifacts->handler)};
    writes[write_count++] = (DazeKvmGuestWrite){.address = raw_gate->real_handler_address,
                                                .bytes = raw_gate_artifacts->handler,
                                                .size = sizeof(raw_gate_artifacts->handler)};
    writes[write_count++] = (DazeKvmGuestWrite){.address = DAZE_KVM_RAW_SWITCH_GATE_VECTOR * 4u,
                                                .bytes = raw_gate_artifacts->ivt_entry,
                                                .size = sizeof(raw_gate_artifacts->ivt_entry)};
    writes[write_count++] =
      (DazeKvmGuestWrite){.address = raw_gate->idt_address + DAZE_KVM_RAW_SWITCH_GATE_VECTOR * 8u,
                          .bytes = raw_gate_artifacts->idt_entry,
                          .size = sizeof(raw_gate_artifacts->idt_entry)};
  }
  *layout =
    (DazeKvmDpmiEntryLayout){.writes = writes,
                             .write_count = write_count,
                             .mailbox_address = daze_kvm_runner_gate_mailbox_linear(guest_size),
                             .terminal_linear = terminal_linear};
  return 1;
}

static int gate_writes_valid(const DazeKvmTransitionPlan *plan,
                             const DazeKvmProtectedGateLayout *gate,
                             const DazeKvmProtectedGateArtifacts *artifacts, uint32_t guest_size) {
  if (gate == NULL) return 1;
  if (artifacts == NULL || artifacts->handler_size == 0 || artifacts->dos_handler_size == 0 ||
      artifacts->default_dos_stub_size == 0 || gate->dos_handler_address == 0 ||
      gate->default_dos_stub_address == 0 ||
      !daze_kvm_range_fits_nonempty(guest_size, gate->handler_address, artifacts->handler_size) ||
      !daze_kvm_range_fits_nonempty(guest_size, gate->dos_handler_address,
                                    artifacts->dos_handler_size) ||
      !daze_kvm_range_fits_nonempty(guest_size, gate->default_dos_stub_address,
                                    artifacts->default_dos_stub_size) ||
      !daze_kvm_range_fits_nonempty(guest_size, gate->idt_address + DAZE_INT_DPMI * 8u,
                                    sizeof(artifacts->idt_entry)) ||
      !daze_kvm_range_fits_nonempty(guest_size, gate->idt_address + DAZE_INT_DOS * 8u,
                                    sizeof(artifacts->dos_idt_entry)))
    return 0;
  for (size_t index = 0; index < plan->write_count; ++index) {
    const DazeKvmTransitionWrite *write = plan->writes + index;
    if (daze_kvm_ranges_overlap(gate->handler_address, artifacts->handler_size, write->address,
                                write->size) ||
        daze_kvm_ranges_overlap(gate->dos_handler_address, artifacts->dos_handler_size,
                                write->address, write->size) ||
        daze_kvm_ranges_overlap(gate->default_dos_stub_address, artifacts->default_dos_stub_size,
                                write->address, write->size) ||
        daze_kvm_ranges_overlap(gate->idt_address + DAZE_INT_DPMI * 8u,
                                sizeof(artifacts->idt_entry), write->address, write->size) ||
        daze_kvm_ranges_overlap(gate->idt_address + DAZE_INT_DOS * 8u,
                                sizeof(artifacts->dos_idt_entry), write->address, write->size))
      return 0;
  }
  for (size_t index = 0; index < plan->reserved_range_count; ++index) {
    const DazeKvmTransitionReservedRange *range = plan->reserved_ranges + index;
    if (daze_kvm_ranges_overlap(gate->handler_address, artifacts->handler_size, range->address,
                                range->size) ||
        daze_kvm_ranges_overlap(gate->dos_handler_address, artifacts->dos_handler_size,
                                range->address, range->size) ||
        daze_kvm_ranges_overlap(gate->default_dos_stub_address, artifacts->default_dos_stub_size,
                                range->address, range->size) ||
        daze_kvm_ranges_overlap(gate->idt_address + DAZE_INT_DPMI * 8u,
                                sizeof(artifacts->idt_entry), range->address, range->size) ||
        daze_kvm_ranges_overlap(gate->idt_address + DAZE_INT_DOS * 8u,
                                sizeof(artifacts->dos_idt_entry), range->address, range->size))
      return 0;
  }
  return 1;
}

static int state_gate_writes_valid(const DazeKvmTransitionPlan *plan,
                                   const DazeKvmStateSaveGateLayout *gate,
                                   const DazeKvmStateSaveGateArtifacts *artifacts,
                                   uint32_t guest_size) {
  if (gate == NULL) return 1;
  const uint32_t entry = gate->idt_address + DAZE_KVM_STATE_SAVE_GATE_VECTOR * 8u;
  if (artifacts == NULL || entry < gate->idt_address ||
      !daze_kvm_range_fits_nonempty(guest_size, gate->handler_address,
                                    sizeof(artifacts->handler)) ||
      !daze_kvm_range_fits_nonempty(guest_size, entry, sizeof(artifacts->idt_entry)))
    return 0;
  for (size_t index = 0; index < plan->write_count; ++index)
    if (daze_kvm_ranges_overlap(gate->handler_address, sizeof(artifacts->handler),
                                plan->writes[index].address, plan->writes[index].size) ||
        daze_kvm_ranges_overlap(entry, sizeof(artifacts->idt_entry), plan->writes[index].address,
                                plan->writes[index].size))
      return 0;
  return 1;
}

static int raw_gate_writes_valid(const DazeKvmTransitionPlan *plan,
                                 const DazeKvmRawSwitchGateLayout *gate,
                                 const DazeKvmRawSwitchGateArtifacts *artifacts,
                                 uint32_t guest_size) {
  if (gate == NULL) return 1;
  const uint32_t entry = gate->idt_address + DAZE_KVM_RAW_SWITCH_GATE_VECTOR * 8u;
  if (artifacts == NULL || entry < gate->idt_address ||
      !daze_kvm_range_fits_nonempty(guest_size, gate->handler_address,
                                    sizeof(artifacts->handler)) ||
      !daze_kvm_range_fits_nonempty(guest_size, gate->real_handler_address,
                                    sizeof(artifacts->handler)) ||
      !daze_kvm_range_fits_nonempty(guest_size, DAZE_KVM_RAW_SWITCH_GATE_VECTOR * 4u,
                                    sizeof(artifacts->ivt_entry)) ||
      !daze_kvm_range_fits_nonempty(guest_size, entry, sizeof(artifacts->idt_entry)))
    return 0;
  for (size_t index = 0; index < plan->write_count; ++index)
    if (daze_kvm_ranges_overlap(gate->handler_address, sizeof(artifacts->handler),
                                plan->writes[index].address, plan->writes[index].size) ||
        daze_kvm_ranges_overlap(gate->real_handler_address, sizeof(artifacts->handler),
                                plan->writes[index].address, plan->writes[index].size) ||
        daze_kvm_ranges_overlap(entry, sizeof(artifacts->idt_entry), plan->writes[index].address,
                                plan->writes[index].size))
      return 0;
  return 1;
}

/* The parked runner still needs its BP-framed INT return while it consumes the
 * reply mailbox.  Plan bytes are installed before that one IRET, so reject a
 * caller-owned table placement that would overwrite this live generic frame. */
static int plan_preserves_handoff_frame(const DazeKvmTransitionPlan *plan,
                                        const DazeKvmRunnerDpmiHandoff *handoff,
                                        uint32_t guest_size) {
  if (plan == NULL || handoff == NULL || !handoff->entry_snapshot.valid ||
      handoff->entry_snapshot.sp < 2)
    return 0;
  const uint32_t frame_address =
    ((uint32_t)handoff->entry_snapshot.ss << 4) + handoff->entry_snapshot.sp - 2;
  enum { FRAME_SIZE = 10 };
  if (!daze_kvm_range_fits(guest_size, frame_address, FRAME_SIZE)) return 0;
  for (size_t index = 0; index < plan->write_count; ++index)
    if (daze_kvm_ranges_overlap(plan->writes[index].address, plan->writes[index].size,
                                frame_address, FRAME_SIZE))
      return 0;
  return 1;
}

DazeDpmiInterruptVector
daze_kvm_command_owner_default_vector21(const DazeKvmCommandOwnerTransitionLayout *layout) {
  if (layout == NULL) return (DazeDpmiInterruptVector){0};
  return (DazeDpmiInterruptVector){.segment = layout->default_vector_alias_selector,
                                   .offset = layout->default_vector_alias_offset};
}

static DazeKvmDpmiMediator mediator_for_gate(DazeKvmMachine *machine,
                                             const DazeKvmTransitionPlanInput *plan_input,
                                             const DazeKvmProtectedGateLayout *gate,
                                             const DazeKvmCommandOwnerTransitionLayout *layout,
                                             DazeDpmiProcessState *state,
                                             DazeDosMemory *dos_memory) {
  DazeKvmDpmiMediator mediator = {.guest = machine->guest,
                                  .guest_size = machine->guest_size,
                                  .record_address = gate->record_address,
                                  .mailbox_address = gate->mailbox_address,
                                  .gdt_address = plan_input->gdt_address,
                                  .gdt_size = DAZE_DPMI_TRANSITION_GDT_SIZE,
                                  .ldt_address = plan_input->ldt_address,
                                  .ldt_size = DAZE_DPMI_TRANSITION_LDT_SIZE,
                                  .ldt_used = state->ldt_used,
                                  .ldt_used_count = sizeof(state->ldt_used),
                                  .ldt_first_index = state->next_ldt_index,
                                  .linear_memory = &state->linear_memory,
                                  .dos_memory = dos_memory,
                                  .real_mode_vector_segment = state->real_mode_vector_segment,
                                  .real_mode_vector_offset = state->real_mode_vector_offset,
                                  .real_mode_vector_count =
                                    sizeof(state->real_mode_vector_segment) /
                                    sizeof(state->real_mode_vector_segment[0]),
                                  .virtual_interrupts_enabled = &state->virtual_interrupts_enabled,
                                  .state_save_endpoints = layout->state_save_endpoints,
                                  .raw_switch_endpoints = layout->raw_switch_endpoints};
  for (size_t index = 0; index < 32; ++index)
    mediator.exception_vectors[index] =
      (DazeDpmiExceptionVector){.segment = state->exception_vector_segment[index],
                                .offset = state->exception_vector_offset[index]};
  memcpy(mediator.interrupt_vectors, state->interrupt_vectors, sizeof(mediator.interrupt_vectors));
  /* A 16-bit far jump truncates an absolute linear address; publish the gate-relative
   * selector:offset pair. */
  mediator.default_interrupt_vectors[DAZE_INT_DOS] =
    daze_kvm_command_owner_default_vector21(layout);
  return mediator;
}

/* The mediator copies vector tables, so its updated DPMI state must be committed
 * explicitly. */
static void mediator_commit(const DazeKvmDpmiMediator *mediator, DazeDpmiProcessState *state) {
  if (mediator == NULL || state == NULL) return;
  for (size_t index = 0; index < 32; ++index) {
    state->exception_vector_segment[index] = mediator->exception_vectors[index].segment;
    state->exception_vector_offset[index] = mediator->exception_vectors[index].offset;
  }
  memcpy(state->interrupt_vectors, mediator->interrupt_vectors, sizeof(state->interrupt_vectors));
}

/* Capture at the post-return marker while the gate's saved request is still intact. */
static int capture_mediator_request(const DazeKvmMachine *machine,
                                    const DazeKvmProtectedGateLayout *gate,
                                    const DazeKvmDpmiEntryResult *boundary, uint16_t *function,
                                    uint16_t *selector, uint32_t *operand) {
  if (machine == NULL || gate == NULL || boundary == NULL || function == NULL || selector == NULL ||
      operand == NULL || boundary->observation.kind != DAZE_KVM_DPMI_ENTRY_EXIT_PIO ||
      boundary->observation.pio_direction != DAZE_KVM_DPMI_ENTRY_PIO_OUT ||
      boundary->observation.pio_size != 1 || boundary->observation.pio_count != 1 ||
      !boundary->observation.pio_value_present ||
      boundary->observation.pio_port != DAZE_KVM_DPMI_MEDIATOR_PORT ||
      (uint8_t)boundary->observation.pio_value != DAZE_KVM_DPMI_MEDIATOR_MARKER ||
      !daze_kvm_range_fits(machine->guest_size, gate->record_address, DAZE_KVM_DPMI_RECORD_SIZE))
    return 0;
  const uint8_t *record = (const uint8_t *)machine->guest + gate->record_address;
  *function = daze_read_u16(record);
  *selector = daze_read_u16(record + 4);
  *operand = ((uint32_t)daze_read_u16(record + 8) << 16) | daze_read_u16(record + 12);
  return 1;
}

static int capture_state_restore_request(const DazeKvmMachine *machine,
                                         const DazeKvmDpmiEntryResult *boundary,
                                         DpmiAlternateState *state, uint32_t *buffer_address) {
  if (machine == NULL || boundary == NULL || state == NULL || buffer_address == NULL ||
      boundary->observation.kind != DAZE_KVM_DPMI_ENTRY_EXIT_PIO ||
      boundary->observation.pio_port != DAZE_PORT_GATE ||
      !boundary->observation.pio_value_present ||
      (uint8_t)boundary->observation.pio_value != DAZE_KVM_STATE_SAVE_GATE_MARKER)
    return 0;
  const uint32_t stack = boundary->ss_base + boundary->esp;
  const uint32_t buffer = boundary->es_base + boundary->di;
  if (stack < boundary->ss_base || buffer < boundary->es_base ||
      !daze_kvm_range_fits(machine->guest_size, stack, sizeof(uint32_t)) ||
      !daze_kvm_range_fits(machine->guest_size, buffer, DAZE_DPMI_ALTERNATE_STATE_SIZE) ||
      daze_read_u16((const uint8_t *)machine->guest + stack) != 1 ||
      !daze_dpmi_alternate_state_unpack((const uint8_t *)machine->guest + buffer, state))
    return 0;
  *buffer_address = buffer;
  return 1;
}

static int capture_runner_request(const DazeKvmMachine *machine,
                                  const DazeKvmDpmiEntryResult *boundary,
                                  DazeKvmRunnerRequestImage *request) {
  if (machine == NULL || boundary == NULL || request == NULL ||
      boundary->observation.kind != DAZE_KVM_DPMI_ENTRY_EXIT_PIO ||
      boundary->observation.pio_direction != DAZE_KVM_DPMI_ENTRY_PIO_OUT ||
      boundary->observation.pio_port != DAZE_PORT_GATE ||
      !boundary->observation.pio_value_present ||
      !daze_kvm_range_fits(machine->guest_size, boundary->ss_base + boundary->esp, 8))
    return 0;
  const uint8_t vector = (uint8_t)boundary->observation.pio_value;
  if (vector != DAZE_INT_BIOS_VIDEO && vector != DAZE_INT_BIOS_EQUIPMENT &&
      vector != DAZE_INT_BIOS_TIME && vector != DAZE_INT_DOS && vector != DAZE_INT_MULTIPLEX &&
      vector != DAZE_INT_DPMI && vector != DAZE_INT_DPMI_ENTRY)
    return 0;
  const uint8_t *stack = (const uint8_t *)machine->guest + boundary->ss_base + boundary->esp;
  *request = (DazeKvmRunnerRequestImage){
    .vector = vector,
    .ax = daze_read_u16(stack),
    .bx = boundary->bx,
    .cx = boundary->cx,
    .dx = boundary->dx,
    .ds = boundary->ds,
    .es = boundary->es,
    .si = boundary->si,
    .di = boundary->di,
    .return_ip = daze_read_u16(stack + 2),
    .return_cs = daze_read_u16(stack + 4),
    .flags = daze_read_u16(stack + 6),
  };
  return 1;
}

/* Install the host DOS gate only while the client has no vector-21 target. */
static int capture_protected_dos_request(const DazeKvmMachine *machine,
                                         const DazeKvmProtectedGateLayout *gate,
                                         const DazeKvmDpmiEntryResult *boundary,
                                         DazeKvmRunnerRequestImage *request) {
  if (machine == NULL || gate == NULL || boundary == NULL || request == NULL ||
      boundary->observation.kind != DAZE_KVM_DPMI_ENTRY_EXIT_PIO ||
      boundary->observation.pio_direction != DAZE_KVM_DPMI_ENTRY_PIO_OUT ||
      boundary->observation.pio_port != DAZE_KVM_DPMI_MEDIATOR_PORT ||
      !boundary->observation.pio_value_present ||
      (uint8_t)boundary->observation.pio_value != DAZE_KVM_PROTECTED_DOS_MARKER ||
      boundary->cs != gate->handler_selector ||
      !daze_kvm_range_fits(machine->guest_size, gate->record_address, DAZE_KVM_DPMI_RECORD_SIZE))
    return 0;
  const uint8_t *record = (const uint8_t *)machine->guest + gate->record_address;
  *request = (DazeKvmRunnerRequestImage){.vector = DAZE_INT_DOS,
                                         .ax = daze_read_u16(record),
                                         .bx = daze_read_u16(record + 4),
                                         .cx = daze_read_u16(record + 8),
                                         .dx = daze_read_u16(record + 12),
                                         .ds = boundary->ds,
                                         .es = daze_read_u16(record + 20),
                                         .si = daze_read_u16(record + 24),
                                         .di = daze_read_u16(record + 16),
                                         .return_ip = daze_read_u16(record + 28),
                                         .return_cs = daze_read_u16(record + 32),
                                         .flags = daze_read_u16(record + 36)};
  return 1;
}

typedef struct {
  const DazeKvmMachine *machine;
  uint32_t base;
  uint16_t selector;
} ProtectedDisplayMemory;

static int read_protected_display(void *context, uint16_t selector, uint16_t offset, void *bytes,
                                  size_t size) {
  const ProtectedDisplayMemory *memory = context;
  if (selector != memory->selector || memory->base > UINT32_MAX - offset ||
      !daze_kvm_range_fits(memory->machine->guest_size, memory->base + offset, size))
    return 0;
  memcpy(bytes, (const uint8_t *)memory->machine->guest + memory->base + offset, size);
  return 1;
}

int daze_kvm_command_owner_protected_dos_display_string(
  const DazeKvmMachine *machine, DazeDosfsFileService *files,
  const DazeKvmDpmiEntryResult *boundary, const DazeKvmRunnerRequestImage *request,
  const uint8_t record[24], uint8_t reply[DAZE_KVM_RUNNER_GATE_REPLY_SIZE]) {
  if (machine == NULL || machine->guest == NULL || files == NULL || boundary == NULL ||
      request == NULL || record == NULL || reply == NULL)
    return DAZE_KVM_PREFLIGHT_BOUNDARY_FAILED;
  /* The boundary retains the client's descriptor base after the transport has
   * changed DS. Never derive a protected-mode address from the selector. */
  ProtectedDisplayMemory memory = {machine, boundary->ds_base, request->ds};
  const DazeDosInt21Context context = {
    .files = files,
    .guest_memory = {.context = &memory, .read = read_protected_display},
  };
  const DazeDosInt21Request dos_request = {
    .ax = request->ax,
    .ds = request->ds,
    .dx = request->dx,
  };
  DazeDosInt21Result result;
  if (daze_dos_int21_dispatch(&context, &dos_request, &result) != DAZE_DOS_INT21_DISPATCH_OK ||
      result.disposition != DAZE_DOS_INT21_HANDLED)
    return DAZE_KVM_PREFLIGHT_BOUNDARY_FAILED;
  daze_kvm_runner_gate_reply_init(record, reply);
  if ((result.register_write_mask & DAZE_DOS_INT21_REG_AX) != 0) daze_write_u16(reply, result.ax);
  const uint16_t flags = daze_read_u16(reply + 14);
  daze_write_u16(reply + 14, (uint16_t)((flags & ~result.flag_write_mask) |
                                        (result.flag_values & result.flag_write_mask)));
  return DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED;
}

static int reply_protected_dos_request(DazeKvmMachine *machine,
                                       const DazeKvmProtectedGateLayout *gate,
                                       const uint8_t reply[16]) {
  const int valid =
    machine != NULL && gate != NULL && reply != NULL &&
    daze_kvm_range_fits(machine->guest_size, gate->record_address, DAZE_KVM_DPMI_RECORD_SIZE) &&
    daze_kvm_range_fits(machine->guest_size, gate->mailbox_address, DAZE_KVM_DPMI_MAILBOX_SIZE);
  if (!valid) {
    if (getenv("DAZE_EXEC_TRACE") != NULL && machine != NULL && gate != NULL)
      fprintf(stderr, "protected-dos-reply: invalid guest=%zu record=%08x mailbox=%08x\n",
              machine->guest_size, gate->record_address, gate->mailbox_address);
    return 0;
  }
  const uint8_t *record = (const uint8_t *)machine->guest + gate->record_address;
  uint8_t *mailbox = (uint8_t *)machine->guest + gate->mailbox_address;
  const size_t sources[] = {0, 4, 8, 12, 24, 16, 20, 36};
  const size_t destinations[] = {0, 4, 8, 24, 12, 16, 20, 28};
  for (size_t index = 0; index < sizeof(sources) / sizeof(sources[0]); ++index) {
    uint32_t value = daze_read_u32(record + sources[index]);
    value = (value & 0xffff0000u) | daze_read_u16(reply + index * 2);
    daze_write_u32(mailbox + destinations[index], value);
  }
  uint16_t returned_ds = daze_read_u16(record + 40);
  if (daze_read_u16(record) == 0x5d06) returned_ds = 0x0300;
  daze_write_u32(mailbox + 20,
                 (daze_read_u32(mailbox + 20) & 0xffffu) | ((uint32_t)returned_ds << 16));
  return 1;
}

/* The generic gate normally IRETs to the HLT byte after its two-byte INT FE
 * stub.  This transition artifact begins at offset zero instead.  Patch only
 * that already-captured IP word, after validating the exact live frame; the
 * gate still restores its own register image and performs the sole guest IRET. */
static int redirect_handoff_to_trampoline(DazeKvmMachine *machine,
                                          const DazeKvmRunnerDpmiHandoff *handoff) {
  if (machine == NULL || machine->guest == NULL || handoff == NULL ||
      !handoff->entry_snapshot.valid || handoff->entry_snapshot.sp < 2)
    return 0;
  const uint32_t frame_address =
    ((uint32_t)handoff->entry_snapshot.ss << 4) + handoff->entry_snapshot.sp - 2;
  const uint32_t return_ip_address = frame_address + 2;
  if (return_ip_address < frame_address ||
      !daze_kvm_range_fits(machine->guest_size, return_ip_address, sizeof(uint16_t)))
    return 0;
  uint8_t *return_ip = (uint8_t *)machine->guest + return_ip_address;
  if (return_ip[0] != (uint8_t)handoff->return_ip ||
      return_ip[1] != (uint8_t)(handoff->return_ip >> 8))
    return 0;
  return_ip[0] = 0;
  return_ip[1] = 0;
  return 1;
}

static int guest_range(const DazeKvmMachine *machine, uint16_t segment, uint16_t offset,
                       size_t size, const uint8_t **bytes) {
  const uint32_t address = ((uint32_t)segment << 4) + offset;
  if (machine == NULL || bytes == NULL || !daze_kvm_range_fits(machine->guest_size, address, size))
    return 0;
  *bytes = (const uint8_t *)machine->guest + address;
  return 1;
}

/* Decode EXEC from the parked request before replacing child state; retain the parent
 * for termination. */
static int launch_exec_child(DazeKvmCommandOwnerHandoff *handoff,
                             const DazeKvmCommandOwnerInput *parent_input,
                             DazeDosProcessState *process_state, DazeDosMemory *dos_memory,
                             DazeKvmCommandOwnerResult *result) {
  DazeKvmMachine *machine = &handoff->machine;
  const DazeKvmRunnerGenericPreflightResult *preflight = &handoff->preflight;
  const uint16_t ax = preflight->request_ax;
  const uint16_t bx = preflight->request_bx;
  const uint16_t dx = preflight->request_dx;
  const uint16_t ds = preflight->request_ds;
  const uint16_t es = preflight->request_es;
  const uint8_t *parameter, *tail, *fcb1, *fcb2;
  char path[128];
  DazeDosExecRequest exec;
  uint8_t fcb1_bytes[16], fcb2_bytes[16];
  DazeImage image = {0};
  DazeMzHeader header;
  int host_errno = 0;
  if (preflight->disposition != DAZE_KVM_GENERIC_PREFLIGHT_EXEC ||
      preflight->request_vector != DAZE_INT_DOS || (ax >> 8) != 0x4b || (uint8_t)ax != 0 ||
      handoff->child.active || !guest_range(machine, es, bx, 14, &parameter)) {
    return DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED;
  }
  size_t path_length = 0;
  while (path_length + 1 < sizeof(path) &&
         guest_range(machine, ds, (uint16_t)(dx + path_length), 1, &tail)) {
    path[path_length] = (char)*tail;
    if (path[path_length++] == '\0') break;
  }
  if (path_length == 0 || path_length == sizeof(path) || path[path_length - 1] != '\0') {
    return DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED;
  }
  const uint16_t tail_offset = daze_read_u16(parameter + 2);
  const uint16_t tail_segment = daze_read_u16(parameter + 4);
  if (!guest_range(machine, tail_segment, tail_offset, 127, &tail) ||
      !daze_dos_exec_request_decode((uint8_t)ax, 0, parameter, tail, &exec) ||
      !guest_range(machine, exec.fcb1_segment, exec.fcb1_offset, sizeof(fcb1_bytes), &fcb1) ||
      !guest_range(machine, exec.fcb2_segment, exec.fcb2_offset, sizeof(fcb2_bytes), &fcb2) ||
      !daze_dos_exec_load_mounted(parent_input->preflight.process.mounts, path, &image,
                                  &host_errno) ||
      !daze_mz_parse_header(image.bytes, image.size, &header)) {
    daze_image_free(&image);
    return DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED;
  }
  const size_t tail_length = tail[0];
  memcpy(fcb1_bytes, fcb1, sizeof(fcb1_bytes));
  memcpy(fcb2_bytes, fcb2, sizeof(fcb2_bytes));
  if (getenv("DAZE_EXEC_TRACE") != NULL) {
    fprintf(stderr, "exec: request ds:dx=%04x:%04x es:bx=%04x:%04x path=%s parameter", ds, dx, es,
            bx, path);
    for (size_t index = 0; index < 14; ++index)
      fprintf(stderr, " %02x", parameter[index]);
    fprintf(stderr, " tail");
    for (size_t index = 0; index <= tail_length; ++index)
      fprintf(stderr, " %02x", tail[index]);
    fputc('\n', stderr);
  }
  const size_t child_paragraphs = 0x10u + (header.image_size + 15u) / 16u;
  const DazeDosMemory parent_memory = *dos_memory;
  DazeDosAllocation *child_allocation =
    child_paragraphs <= UINT16_MAX
      ? daze_dos_memory_allocate(dos_memory, (uint16_t)child_paragraphs)
      : NULL;
  if (child_allocation == NULL) {
    daze_image_free(&image);
    return DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED;
  }
  const uint16_t child_psp_segment = child_allocation->segment;
  const uint16_t child_load_segment = (uint16_t)(child_psp_segment + 0x10);
  const uint16_t parent_psp_segment = process_state->psp_segment;
  const DazeDosMemory child_memory = *dos_memory;
  /* The parent snapshot must exclude the allocation owned by this EXEC child. */
  *dos_memory = parent_memory;
  if (!daze_kvm_child_context_capture(&handoff->child, machine, &handoff->process, process_state,
                                      dos_memory, parent_input->state)) {
    daze_image_free(&image);
    return DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED;
  }
  handoff->parent_process = handoff->process;
  handoff->parent_preflight = handoff->preflight;
  handoff->parent_input = *parent_input;
  handoff->parent_input_valid = 1;
  handoff->child.child_image = image;
  if (daze_dosfs_exec_handles_begin(&handoff->child_handles,
                                    parent_input->preflight.process.files->handles,
                                    &host_errno) != DAZE_DOSFS_OK)
    return DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED;
  handoff->child.child_header = header;
  memcpy(handoff->child.child_path, path, path_length);
  memcpy(handoff->child.child_tail, tail + 1, tail_length);
  handoff->child.child_tail[tail_length] = '\0';
  if (!daze_dos_exec_psp_build(child_psp_segment, parent_psp_segment, exec.environment_segment,
                               handoff->child.parent_layout.dos_vector_segment, tail, fcb1_bytes,
                               fcb2_bytes, handoff->child.child_psp)) {
    return DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED;
  }

  const uint32_t image_address = (uint32_t)child_load_segment << 4;
  if (header.image_size > machine->guest_size - image_address) {
    return DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED;
  }
  *dos_memory = child_memory;
  daze_dos_process_state_init(process_state, child_psp_segment);
  daze_dos_process_state_seed_vectors(process_state,
                                      handoff->child.parent_layout.dos_vector_segment);
  DazeKvmRunnerRequestCommon child_process = handoff->child.parent_layout;
  child_process.image = &handoff->child.child_image;
  child_process.header = &handoff->child.child_header;
  child_process.command_tail = handoff->child.child_tail;
  child_process.guest_path = handoff->child.child_path;
  child_process.psp_override = handoff->child.child_psp;
  child_process.initial_ax = ax;
  child_process.initial_bx = bx;
  child_process.initial_cx = preflight->request_cx;
  child_process.initial_dx = dx;
  child_process.initial_si = preflight->request_si;
  child_process.initial_di = preflight->request_di;
  child_process.preserve_initial_gprs = 1;
  child_process.exec_child = 1;
  child_process.psp_segment = child_psp_segment;
  child_process.load_segment = child_load_segment;
  child_process.environment_segment = exec.environment_segment;
  if (getenv("DAZE_EXEC_TRACE") != NULL)
    fprintf(stderr, "exec: child PSP=%04x load=%04x entry=%04x:%04x\n", child_process.psp_segment,
            child_process.load_segment,
            (uint16_t)(child_process.load_segment + child_process.header->initial_cs),
            child_process.header->initial_ip);
  DazeKvmRunnerGenericPreflightResult child_preflight;
  const DazeKvmRunnerGenericPreflightRequest preflight_request = {.process = child_process};
  const int child_preflight_status = daze_kvm_runner_bootstrap_to_generic_boundary(
    machine, &preflight_request, process_state, dos_memory, &child_preflight);
  handoff->process = child_process;
  handoff->preflight = child_preflight;
  if (child_preflight_status == DAZE_KVM_GENERIC_PREFLIGHT_TERMINATED &&
      child_preflight.request_vector == DAZE_INT_DOS &&
      ((child_preflight.request_ax >> 8) == 0x4c || (child_preflight.request_ax >> 8) == 0x31)) {
    return resume_exec_parent(
      handoff, process_state, dos_memory, (uint8_t)child_preflight.request_ax,
      (child_preflight.request_ax >> 8) == 0x31 ? 3 : 0, child_preflight.request_dx, NULL, result);
  }
  if (child_preflight_status != DAZE_KVM_GENERIC_PREFLIGHT_DPMI_ENTRY) {
    return DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED;
  }
  DazeKvmNormalTransitionConfig config;
  DazeKvmGuestRange child_runner_reserved[3];
  const size_t child_runner_reserved_count =
    runner_reserved_ranges(child_process.guest_size, child_runner_reserved);
  const DazeKvmNormalTransitionConfigInput child_config_input = {
    .guest_size = child_process.guest_size,
    .resident_image_end = image_address + (uint32_t)header.image_size,
    .load_segment = child_process.load_segment,
    .psp_segment = child_process.psp_segment,
    .environment_segment = child_process.environment_segment,
    .dpmi_entry_segment = child_process.dpmi_entry_segment,
    .dos_int21_vector_segment = child_process.dos_vector_segment,
    .handoff_ds = child_preflight.dpmi_handoff.entry_snapshot.ds,
    .handoff_ss = child_preflight.dpmi_handoff.entry_snapshot.ss,
    .handoff_return_ip = child_preflight.dpmi_handoff.caller_return_ip,
    .handoff_return_cs = child_preflight.dpmi_handoff.caller_return_cs,
    .reserved_ranges = child_runner_reserved,
    .reserved_range_count = child_runner_reserved_count,
  };
  DazeKvmNormalTransitionConfigFailure child_config_failure = {
    DAZE_KVM_NORMAL_TRANSITION_CONFIG_VALID, {0, 0}, {0, 0}};
  if (!daze_kvm_normal_transition_config_build(&child_config_input, &config,
                                               &child_config_failure)) {
    if (child_config_failure.kind != DAZE_KVM_NORMAL_TRANSITION_CONFIG_VALID)
      daze_kvm_normal_transition_config_report(&child_config_input, &child_config_failure);
    if (getenv("DAZE_EXEC_TRACE") != NULL)
      fprintf(stderr,
              "exec: child normal-transition config rejected guest=%x resident=%x psp=%04x "
              "load=%04x env=%04x dos-vector=%04x handoff ds:ss=%04x:%04x return=%04x:%04x\n",
              child_process.guest_size, image_address + (uint32_t)header.image_size,
              child_process.psp_segment, child_process.load_segment,
              child_process.environment_segment, child_process.dos_vector_segment,
              child_preflight.dpmi_handoff.entry_snapshot.ds,
              child_preflight.dpmi_handoff.entry_snapshot.ss,
              child_preflight.dpmi_handoff.caller_return_cs,
              child_preflight.dpmi_handoff.caller_return_ip);
    return DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED;
  }
  const int disposition =
    continue_from_handoff(handoff,
                          &(DazeKvmCommandOwnerInput){.preflight = preflight_request,
                                                      .transition_layout = config.transition_layout,
                                                      .state = parent_input->state},
                          NULL, 0, NULL, result);
  if (getenv("DAZE_EXEC_TRACE") != NULL)
    fprintf(stderr,
            "exec: child owner disposition=%d stage=%d transition=%d gate=%d exchanges=%zu "
            "terminal kind=%d raw=%u pio=%04x/%u/%u/%u fail=%llu\n",
            disposition, result->transition_stage, result->transition_status,
            result->protected_gate_status, result->protected_gate.exchange_count,
            result->transition_successor.observation.kind,
            result->transition_successor.observation.raw_exit_reason,
            result->transition_successor.observation.pio_port,
            result->transition_successor.observation.pio_direction,
            result->transition_successor.observation.pio_size,
            result->transition_successor.observation.pio_value,
            (unsigned long long)result->transition_successor.observation.fail_entry_reason);
  if (getenv("DAZE_EXEC_TRACE") != NULL && result->transition_status != DAZE_KVM_DPMI_ENTRY_OK)
    fprintf(stderr,
            "exec: child terminal cs:ip=%04x:%08x ax=%04x bx=%04x cx=%04x dx=%04x "
            "ds=%04x es=%04x ss:sp=%04x:%04x cr0=%08x gdt=%08x idt=%08x bytes"
            " %02x %02x %02x %02x\n",
            result->transition_successor.cs, result->transition_successor.rip,
            result->transition_successor.ax, result->transition_successor.bx,
            result->transition_successor.cx, result->transition_successor.dx,
            result->transition_successor.ds, result->transition_successor.es,
            result->transition_successor.ss, result->transition_successor.sp,
            result->transition_successor.cr0, result->transition_successor.gdt_base,
            result->transition_successor.idt_base, result->transition_successor.instruction[0],
            result->transition_successor.instruction[1],
            result->transition_successor.instruction[2],
            result->transition_successor.instruction[3]);
  if (getenv("DAZE_EXEC_TRACE") != NULL && result->protected_gate_present) {
    const DazeKvmDpmiEntryResult *terminal = &result->protected_gate.terminal;
    fprintf(stderr,
            "exec: child protected terminal kind=%d raw=%u internal=%u cs:ip=%04x:%08x "
            "ax=%04x bx=%04x cx=%04x dx=%04x ds=%04x es=%04x ss:sp=%04x:%04x "
            "gdt=%08x idt=%08x bytes %02x %02x %02x %02x\n",
            terminal->observation.kind, terminal->observation.raw_exit_reason,
            terminal->observation.internal_suberror, terminal->cs, terminal->rip, terminal->ax,
            terminal->bx, terminal->cx, terminal->dx, terminal->ds, terminal->es, terminal->ss,
            terminal->sp, terminal->gdt_base, terminal->idt_base, terminal->instruction[0],
            terminal->instruction[1], terminal->instruction[2], terminal->instruction[3]);
  }
  return disposition;
}

/* Restore the parent snapshot before replying to its parked EXEC gate. */
static int resume_exec_parent(DazeKvmCommandOwnerHandoff *handoff,
                              DazeDosProcessState *process_state, DazeDosMemory *dos_memory,
                              uint8_t child_exit_status, uint8_t child_termination_type,
                              uint16_t resident_paragraphs,
                              const DazeKvmCommandOwnerInput *resident_input,
                              DazeKvmCommandOwnerResult *result) {
  if (handoff == NULL || process_state == NULL || dos_memory == NULL || result == NULL ||
      !handoff->child.active || !handoff->parent_input_valid)
    return DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED;
  const DazeKvmRunnerRequestCommon parent_process = handoff->parent_process;
  const DazeKvmRunnerGenericPreflightResult parent_preflight = handoff->parent_preflight;
  const DazeKvmRunnerGenericPreflightResult resident_preflight = handoff->preflight;
  const DazeKvmCommandOwnerInput parent_input = handoff->parent_input;
  /* restore_resident frees child launch storage, but the following raw switch still
   * needs the image extent. */
  DazeMzHeader resident_header = {0};
  DazeKvmRunnerRequestCommon resident_process = {0};
  DazeKvmResidentGdtState resident_gdt = {0};
  if (child_termination_type == 3) {
    if (resident_input == NULL || handoff->process.header == NULL)
      return DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED;
    resident_header = *handoff->process.header;
    resident_process = resident_input->preflight.process;
    resident_process.header = &resident_header;
  }
  /* KVM requires an observed OUT to be resumed before replacing the vCPU
   * context. Retire this child-side protected DOS marker at its exact observed
   * successor; otherwise the next KVM_RUN resumes the child after restore. */
  const DazeKvmDpmiEntryResult child_boundary = result->post_successor;
  if (child_boundary.observation.kind == DAZE_KVM_DPMI_ENTRY_EXIT_PIO &&
      child_boundary.observation.pio_direction == DAZE_KVM_DPMI_ENTRY_PIO_OUT &&
      child_boundary.observation.pio_port == DAZE_KVM_DPMI_MEDIATOR_PORT &&
      child_boundary.observation.pio_value_present &&
      (uint8_t)child_boundary.observation.pio_value == DAZE_KVM_PROTECTED_DOS_MARKER &&
      daze_kvm_dpmi_entry_retire_mediator_out(&handoff->machine, child_boundary.cs_base,
                                              child_boundary.rip,
                                              &result->post_successor) != DAZE_KVM_DPMI_ENTRY_OK) {
    fprintf(stderr, "KVM EXEC parent resume: child protected gate retire failed\n");
    return DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED;
  }
  const int restored =
    child_termination_type == 3
      ? daze_kvm_child_context_restore_resident(&handoff->child, &handoff->machine, process_state,
                                                dos_memory, parent_input.state, resident_paragraphs,
                                                &resident_gdt)
      : daze_kvm_child_context_restore(&handoff->child, &handoff->machine, process_state,
                                       dos_memory, parent_input.state);
  if (!restored) {
    fprintf(stderr, "KVM EXEC parent resume: child-context restore failed\n");
    return DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED;
  }
  daze_dosfs_exec_handles_restore(&handoff->child_handles);
  handoff->process = parent_process;
  handoff->preflight = parent_preflight;
  handoff->parent_input_valid = 0;
  daze_dos_process_state_record_child_termination(process_state, child_exit_status,
                                                  child_termination_type);
  const int reply_status = daze_kvm_command_owner_reply_exec_success(&handoff->machine);
  if (reply_status != DAZE_KVM_RUNNER_GATE_RESUME_OK) {
    fprintf(stderr, "KVM EXEC parent resume: 4B00h reply failed (%d)\n", reply_status);
    return DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED;
  }
  if (daze_kvm_runner_gate_frame_retire_out(&handoff->machine) != DAZE_KVM_RUNNER_GATE_RESUME_OK) {
    fprintf(stderr, "KVM EXEC parent resume: 4B00h retire failed\n");
    return DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED;
  }
  DazeKvmRunnerGenericPreflightResult resumed;
  const int resume_status = daze_kvm_runner_resume_to_generic_boundary(
    &handoff->machine, &(DazeKvmRunnerGenericPreflightRequest){.process = parent_process},
    process_state, dos_memory, &resumed);
  if (resume_status != DAZE_KVM_GENERIC_PREFLIGHT_PROTECTED_BOUNDARY &&
      resume_status != DAZE_KVM_GENERIC_PREFLIGHT_RAW_SWITCH)
    handoff->preflight = resumed;
  if (resume_status == DAZE_KVM_GENERIC_PREFLIGHT_TERMINATED) {
    result->guest_exit_status = (uint8_t)resumed.request_ax;
    result->guest_exit_status_present = 1;
    return DAZE_KVM_COMMAND_OWNER_TERMINATED;
  }
  if (resume_status == DAZE_KVM_GENERIC_PREFLIGHT_EXEC)
    return launch_exec_child(handoff, &parent_input, process_state, dos_memory, result);
  if (resume_status == DAZE_KVM_GENERIC_PREFLIGHT_DPMI_ENTRY)
    return continue_from_handoff(handoff, &parent_input, NULL, 0, NULL, result);
  if (resume_status == DAZE_KVM_GENERIC_PREFLIGHT_PROTECTED_BOUNDARY) {
    DazeKvmDpmiEntryResult protected_boundary;
    if (daze_kvm_dpmi_entry_capture_state(&handoff->machine, &protected_boundary) !=
        DAZE_KVM_DPMI_ENTRY_OK)
      return DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED;
    return continue_from_handoff(handoff, &parent_input, &protected_boundary, 0, NULL, result);
  }
  if (resume_status == DAZE_KVM_GENERIC_PREFLIGHT_RAW_SWITCH) {
    DazeKvmDpmiEntryResult raw_boundary;
    if (daze_kvm_dpmi_entry_capture_state(&handoff->machine, &raw_boundary) !=
        DAZE_KVM_DPMI_ENTRY_OK)
      return DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED;
    raw_boundary.observation = (DazeKvmDpmiEntryObservation){
      .kind = DAZE_KVM_DPMI_ENTRY_EXIT_PIO,
      .pio_port = DAZE_PORT_GATE,
      .pio_direction = DAZE_KVM_DPMI_ENTRY_PIO_OUT,
      .pio_size = 1,
      .pio_count = 1,
      .pio_value_present = 1,
      .pio_value = DAZE_KVM_RAW_SWITCH_GATE_MARKER,
    };
    if (getenv("DAZE_EXEC_TRACE") != NULL)
      fprintf(stderr,
              "exec: resident raw boundary kind=%d raw=%u pio=%04x/%u cs:ip=%04x:%08x cr0=%08x "
              "ss:sp=%04x:%04x\n",
              raw_boundary.observation.kind, raw_boundary.observation.raw_exit_reason,
              raw_boundary.observation.pio_port, raw_boundary.observation.pio_value,
              raw_boundary.cs, raw_boundary.rip, raw_boundary.cr0, raw_boundary.ss,
              raw_boundary.sp);
    if (resident_input == NULL) {
      if (getenv("DAZE_EXEC_TRACE") != NULL)
        fputs("exec: resident raw switch has no resident transition input\n", stderr);
      return DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED;
    }
    /* The marker belongs to DPMILOAD's resident DPMI host.  The suspended
     * BCC EXEC parent has no DPMI handoff; resume with the still-live child
     * handoff and caller-owned transition layout from this dispatch frame. */
    handoff->process = resident_process;
    handoff->preflight = resident_preflight;
    if (getenv("DAZE_EXEC_TRACE") != NULL)
      fprintf(stderr,
              "exec: resident raw resumes child DPMI handoff ds:ss=%04x:%04x return=%04x:%04x\n",
              resident_preflight.dpmi_handoff.entry_snapshot.ds,
              resident_preflight.dpmi_handoff.entry_snapshot.ss,
              resident_preflight.dpmi_handoff.caller_return_cs,
              resident_preflight.dpmi_handoff.caller_return_ip);
    DazeKvmCommandOwnerInput resident_owner_input = *resident_input;
    resident_owner_input.preflight.process = resident_process;
    handoff->resident_gdt = resident_gdt;
    handoff->resident_gdt_valid = 1;
    return continue_from_handoff(handoff, &resident_owner_input, &raw_boundary, 1, &resident_gdt,
                                 result);
  }
  fprintf(stderr, "KVM EXEC parent resume: generic status=%d request=%02x/%04x\n", resume_status,
          resumed.request_vector, resumed.request_ax);
  return DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED;
}

static int
dispatch_boundaries(DazeKvmCommandOwnerHandoff *handoff, const DazeKvmCommandOwnerInput *input,
                    const DazeKvmTransitionPlanInput *plan_input,
                    const DazeKvmRunnerGenericPreflightResult *preflight,
                    const DazeKvmTransitionPlan *plan, const DazeKvmProtectedGateLayout *gate,
                    const DazeKvmStateSaveGateLayout *state_gate,
                    const DazeKvmRawSwitchGateLayout *raw_gate, DazeDosProcessState *process_state,
                    DazeDosMemory *dos_memory, const DazeKvmDpmiEntryResult *initial_boundary,
                    DazeKvmCommandOwnerResult *result) {
  DazeKvmMachine *machine = &handoff->machine;
  DazeKvmLegacyExceptionState legacy = {0};
  DazeKvmDpmiEntryResult boundary =
    initial_boundary != NULL ? *initial_boundary : result->protected_gate.terminal;
  int first_boundary = 1;
  for (;;) {
    if (!daze_kvm_resident_vector_projections_refresh(machine, &handoff->resident_gdt, dos_memory))
      return DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED;
    result->post_successor = boundary;
    result->post_successor_present = 1;
    if (gate->legacy_np_capture_address != 0) {
      int legacy_status =
        daze_kvm_legacy_exception_boundary(machine, gate, input->state, &legacy, &boundary);
      if (legacy_status < 0) {
        fprintf(stderr, "KVM legacy #NP refused at %04x:%08x ss:sp=%04x:%04x\n", boundary.cs,
                boundary.rip, boundary.ss, boundary.sp);
        return DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED;
      }
      if (legacy_status > 0) continue;
      if (!daze_kvm_legacy_exception_rearm(machine, &legacy))
        return DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED;
    }
    /* One bounded record per owner boundary, taken at the loop top so the
     * unclassified boundary that ends the run is captured like every other. */
    const DazeKvmCommandBoundaryKind classification = daze_kvm_command_boundary_classify(&boundary);
    if (getenv("DAZE_EXEC_TRACE") != NULL && initial_boundary != NULL && first_boundary)
      fprintf(stderr,
              "exec: live-dispatch class=%d kind=%d raw=%u pio=%04x/%u cs:ip=%04x:%08x cr0=%08x\n",
              classification, boundary.observation.kind, boundary.observation.raw_exit_reason,
              boundary.observation.pio_port, boundary.observation.pio_value, boundary.cs,
              boundary.rip, boundary.cr0);
    first_boundary = 0;
    if (boundary.observation.kind == DAZE_KVM_DPMI_ENTRY_EXIT_MATCHING_DEBUG) {
      const int continue_status = daze_kvm_dpmi_entry_continue_once(machine, &boundary);
      if (continue_status != DAZE_KVM_DPMI_ENTRY_OK) {
        if (getenv("DAZE_EXEC_TRACE") != NULL)
          fprintf(stderr,
                  "exec: matching-debug continue=%d kind=%d raw=%u cs:ip=%04x:%08x cr0=%08x "
                  "ax=%04x bx=%04x cx=%04x dx=%04x ss:sp=%04x:%04x bytes=%02x%02x%02x%02x\\n",
                  continue_status, boundary.observation.kind, boundary.observation.raw_exit_reason,
                  boundary.cs, boundary.rip, boundary.cr0, boundary.ax, boundary.bx, boundary.cx,
                  boundary.dx, boundary.ss, boundary.sp, boundary.instruction[0],
                  boundary.instruction[1], boundary.instruction[2], boundary.instruction[3]);

        return DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED;
      }

      continue;
    }
    switch (classification) {
    case DAZE_KVM_COMMAND_BOUNDARY_MEDIATOR: {
      uint16_t function, selector;
      uint32_t operand;
      if (!capture_mediator_request(machine, gate, &boundary, &function, &selector, &operand)) {
        return DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED;
      }
      result->post_return_function = function;
      result->post_return_selector = selector;
      result->post_return_operand = operand;
      result->post_return_request_present = 1;
      if ((function >> 8) == 0x4c) {
        result->guest_exit_status = (uint8_t)function;
        result->guest_exit_status_present = 1;

        return DAZE_KVM_COMMAND_OWNER_TERMINATED;
      }
      DazeKvmDpmiMediator mediator = mediator_for_gate(
        machine, plan_input, gate, &input->transition_layout, input->state, dos_memory);
      DazeKvmProtectedGateExchange exchange;
      DazeKvmDpmiEntryResult successor;
      result->post_return_gate_status = daze_kvm_protected_gate_resume_mediator_boundary(
        machine, &mediator, gate, &boundary, &exchange, &successor);

      if (result->post_return_gate_status == DAZE_KVM_PROTECTED_GATE_RM_PROCEDURE) {
        const DazeKvmRmProcedureInput reflect = {
          .machine = machine,
          .mediator = &mediator,
          .files = input->preflight.process.files,
          .process_state = process_state,
          .dpmi_entry_segment = input->preflight.process.dpmi_entry_segment,
          .protected_return_linear =
            legacy.depth == 0 ? 0 : legacy.deliveries[legacy.depth - 1].return_linear,
        };
        result->post_return_gate_status = daze_kvm_rm_procedure_reflect(&reflect, &successor)
                                            ? DAZE_KVM_PROTECTED_GATE_OK
                                            : DAZE_KVM_PROTECTED_GATE_FAILED;
      }
      if (result->post_return_gate_status != DAZE_KVM_PROTECTED_GATE_OK) {
        return DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED;
      }

      mediator_commit(&mediator, input->state);

      boundary = successor;
      break;
    }
    case DAZE_KVM_COMMAND_BOUNDARY_STATE: {
      DpmiAlternateState restored;
      uint32_t buffer;
      if (capture_state_restore_request(machine, &boundary, &restored, &buffer)) {
        if (getenv("DAZE_EXEC_TRACE") != NULL)
          fprintf(stderr,
                  "state-restore: buffer=%08x gate=%04x:%08x stack=%04x:%04x "
                  "eip=%08x esp=%08x flags=%08x "
                  "cs=%04x ds=%04x es=%04x fs=%04x gs=%04x ss=%04x "
                  "eax=%08x ebx=%08x ecx=%08x edx=%08x esi=%08x edi=%08x ebp=%08x\n",
                  buffer, boundary.cs, boundary.rip, boundary.ss, boundary.esp, restored.eip,
                  restored.esp, restored.eflags, restored.cs, restored.ds, restored.es, restored.fs,
                  restored.gs, restored.ss, restored.eax, restored.ebx, restored.ecx, restored.edx,
                  restored.esi, restored.edi, restored.ebp);
        input->state->real_mode_state = restored;
        input->state->real_mode_state_valid = 1;
        /* Operation one saves alternate-mode state without replacing the protected CPU
         * state needed by the live return frame. */
        const int widen_status = daze_kvm_state_save_gate_widen_caller_frame(machine, &boundary);
        if (widen_status != DAZE_KVM_STATE_SAVE_GATE_OK) {
          return DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED;
        }
        const int continue_status = daze_kvm_dpmi_entry_continue_once(machine, &boundary);
        if (getenv("DAZE_EXEC_TRACE") != NULL)
          fprintf(stderr, "state-restore: continue=%d kind=%d raw=%u pio=%04x/%u cs:ip=%04x:%08x\n",
                  continue_status, boundary.observation.kind, boundary.observation.raw_exit_reason,
                  boundary.observation.pio_port, boundary.observation.pio_value, boundary.cs,
                  boundary.rip);
        if (continue_status != DAZE_KVM_DPMI_ENTRY_OK) {
          return DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED;
        }
        break;
      }
      DazeKvmStateSaveGateResult saved;
      const int state_status = daze_kvm_state_save_gate_run(
        machine, state_gate, &input->state->real_mode_state, &boundary, &saved);
      if (getenv("DAZE_EXEC_TRACE") != NULL)
        fprintf(
          stderr,
          "state-save: status=%d valid=%d es:di=%04x:%08x ss:esp=%04x:%08x op=%04x widen=%d\n",
          state_status, daze_dpmi_alternate_state_valid(&input->state->real_mode_state),
          boundary.es, boundary.di, boundary.ss, boundary.esp, saved.operation,
          saved.caller_frame_widened);
      if (state_status != DAZE_KVM_STATE_SAVE_GATE_OK) {
        return DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED;
      }

      const int step_status = daze_kvm_dpmi_entry_continue_once(machine, &boundary);
      if (step_status != DAZE_KVM_DPMI_ENTRY_OK) {
        return DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED;
      }
      break;
    }
    case DAZE_KVM_COMMAND_BOUNDARY_RUNNER: {
      uint8_t record[24] = {0};
      uint8_t reply[DAZE_KVM_RUNNER_GATE_REPLY_SIZE] = {0};
      DazeKvmPreflightBoundaryResult broker;
      result->terminal_runner_request_present =
        capture_protected_dos_request(machine, gate, &boundary, &result->terminal_runner_request) ||
        capture_runner_request(machine, &boundary, &result->terminal_runner_request);

      if (getenv("DAZE_EXEC_TRACE") != NULL)
        fprintf(stderr,
                "runner: request-present=%d marker=%02x cs:ip=%04x:%08x ax=%04x ss:sp=%04x:%04x\n",
                result->terminal_runner_request_present, (uint8_t)boundary.observation.pio_value,
                boundary.cs, boundary.rip, boundary.ax, boundary.ss, boundary.sp);
      if (!result->terminal_runner_request_present) return DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED;
      const DazeKvmRunnerRequestImage *request = &result->terminal_runner_request;
      const int protected_dos =
        boundary.cs == gate->handler_selector &&
        (uint8_t)boundary.observation.pio_value == DAZE_KVM_PROTECTED_DOS_MARKER;
      daze_write_u16(record, request->ax);
      daze_write_u16(record + 2, request->bx);
      daze_write_u16(record + 4, request->cx);
      daze_write_u16(record + 6, request->dx);
      daze_write_u16(record + 8, request->ds);
      daze_write_u16(record + 10, request->es);
      daze_write_u16(record + 12, request->si);
      daze_write_u16(record + 14, request->di);
      daze_write_u16(record + 16, request->vector);
      daze_write_u16(record + 18, request->return_ip);
      daze_write_u16(record + 20, request->return_cs);
      daze_write_u16(record + 22, request->flags);
      /* Protected strings use the captured DS descriptor base; the real-mode broker uses
       * segment:offset. */
      const int protected_display_string =
        request->vector == DAZE_INT_DOS && (request->ax >> 8) == 0x09 &&
        (uint8_t)boundary.observation.pio_value == DAZE_KVM_PROTECTED_DOS_MARKER;
      result->terminal_runner_broker_status =
        protected_display_string
          ? daze_kvm_command_owner_protected_dos_display_string(
              machine, input->preflight.process.files, &boundary, request, record, reply)
          : daze_kvm_preflight_boundary_broker(
              machine, input->preflight.process.files, process_state, dos_memory,
              input->preflight.process.dpmi_entry_segment, record, reply, &broker);
      if (getenv("DAZE_EXEC_TRACE") != NULL)
        fprintf(stderr, "runner: request=%02x/%04x protected=%d broker=%d\n", request->vector,
                request->ax, protected_dos, result->terminal_runner_broker_status);
      if (result->terminal_runner_broker_status == DAZE_KVM_PREFLIGHT_BOUNDARY_EXEC) {
        return launch_exec_child(handoff, input, process_state, dos_memory, result);
      }
      if (result->terminal_runner_broker_status != DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED) {
        if (result->terminal_runner_broker_status == DAZE_KVM_PREFLIGHT_BOUNDARY_TERMINATED &&
            result->terminal_runner_request_present &&
            result->terminal_runner_request.vector == DAZE_INT_DOS &&
            ((result->terminal_runner_request.ax >> 8) == 0x4c ||
             (result->terminal_runner_request.ax >> 8) == 0x31)) {
          const uint8_t termination_type =
            (result->terminal_runner_request.ax >> 8) == 0x31 ? 3 : 0;
          if (handoff->child.active)
            return resume_exec_parent(handoff, process_state, dos_memory,
                                      (uint8_t)result->terminal_runner_request.ax, termination_type,
                                      result->terminal_runner_request.dx, input, result);
          result->guest_exit_status = (uint8_t)result->terminal_runner_request.ax;
          result->guest_exit_status_present = 1;
          return DAZE_KVM_COMMAND_OWNER_TERMINATED;
        }

        return DAZE_KVM_COMMAND_OWNER_POST_SUCCESSOR_BOUNDARY;
      }
      const DazeKvmRunnerGateFrame frame = {
        .vector = request->vector, .ss = boundary.ss, .sp = boundary.sp};
      if (!daze_kvm_resident_vector_projections_refresh(machine, &handoff->resident_gdt,
                                                        dos_memory))
        return DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED;
      result->terminal_runner_resume_status =
        protected_dos ? (reply_protected_dos_request(machine, gate, reply)
                           ? DAZE_KVM_RUNNER_GATE_RESUME_OK
                           : DAZE_KVM_RUNNER_GATE_RESUME_INVALID)
                      : daze_kvm_runner_gate_frame_reply(machine, &frame, reply);

      if (result->terminal_runner_resume_status != DAZE_KVM_RUNNER_GATE_RESUME_OK) {
        return DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED;
      }
      result->terminal_runner_continue_status =
        daze_kvm_dpmi_entry_continue_once(machine, &boundary);
      if (getenv("DAZE_EXEC_TRACE") != NULL)
        fprintf(
          stderr,
          "runner: reply=%d continue=%d successor kind=%d raw=%u pio=%04x/%u cs:ip=%04x:%08x\n",
          result->terminal_runner_resume_status, result->terminal_runner_continue_status,
          boundary.observation.kind, boundary.observation.raw_exit_reason,
          boundary.observation.pio_port, boundary.observation.pio_value, boundary.cs, boundary.rip);

      if (result->terminal_runner_continue_status != DAZE_KVM_DPMI_ENTRY_OK)
        return DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED;
      break;
    }
    case DAZE_KVM_COMMAND_BOUNDARY_RAW: {
      DazeKvmRawSwitchGateResult raw;
      const int raw_status =
        daze_kvm_raw_switch_gate_run_from_boundary(machine, raw_gate, &boundary, &raw);
      if (getenv("DAZE_EXEC_TRACE") != NULL) {
        const DazeKvmDpmiEntryResult *b = &raw.boundary;
        fprintf(stderr, "raw-switch: status=%d kind=%d raw=%d cs:ip=%04x:%08x pio=%04x/%02x\n",
                raw_status, b->observation.kind, b->observation.raw_exit_reason, b->cs, b->rip,
                b->observation.pio_port, (unsigned)b->observation.pio_value);
        fprintf(stderr,
                "raw-switch: gpr ax=%04x bx=%04x cx=%04x dx=%04x si=%04x di=%04x "
                "sp=%04x flags=%08x cr0=%08x csdb=%u ssdb=%u\n",
                b->ax, b->bx, b->cx, b->dx, b->si, b->di, b->sp, b->rflags, b->cr0, b->cs_db,
                b->ss_db);
        fprintf(stderr,
                "raw-switch: seg cs=%04x/%08x ss=%04x/%08x/%08x/%x/%x ds=%04x/%08x es=%04x/%08x "
                "fs=%04x/%08x gs=%04x/%08x gdt=%08x/%04x idt=%08x/%04x\n",
                b->cs, b->cs_base, b->ss, b->ss_base, b->ss_limit, b->ss_type, b->ss_present, b->ds,
                b->ds_base, b->es, b->es_base, b->fs, b->fs_base, b->gs, b->gs_base, b->gdt_base,
                b->gdt_limit, b->idt_base, b->idt_limit);
        fprintf(stderr, "raw-switch: bytes");
        for (size_t byte = 0; byte < b->instruction_size; ++byte)
          fprintf(stderr, " %02x", b->instruction[byte]);
        fputc('\n', stderr);
        const uint32_t idt21 = raw_gate->idt_address + DAZE_INT_DOS * 8u;
        if (daze_kvm_range_fits(machine->guest_size, idt21, 8)) {
          const uint8_t *image = (const uint8_t *)machine->guest;
          fprintf(stderr, "raw-switch: idt21");
          for (size_t byte = 0; byte < 8; ++byte)
            fprintf(stderr, " %02x", image[idt21 + byte]);
          fputc('\n', stderr);
        }
      }
      if (raw_status != DAZE_KVM_RAW_SWITCH_GATE_OK) {
        return DAZE_KVM_COMMAND_OWNER_POST_SUCCESSOR_BOUNDARY;
      }

      if (raw.real_mode_state_valid) {
        const DazeKvmRawSwitchReturnLayout layout = {
          .wrapper_address = plan->trampoline_address + 0x180,
          .state_address = plan->trampoline_address + 0x200,
          .protected_code_base = plan->trampoline_address,
          .wrapper_selector = DAZE_SEL_GATE,
          .gdt_address = input->transition_layout.gdt_address,
          .gdt_limit = 0xffff,
          .ldt_address = input->transition_layout.ldt_address,
          .ldt_limit = DAZE_DPMI_TRANSITION_LDT_SIZE - 1};
        const int return_status =
          daze_kvm_raw_switch_gate_return_to_protected(machine, raw_gate, &layout, &raw.request);
        const int continue_status =
          return_status == DAZE_KVM_RAW_SWITCH_GATE_OK
            ? daze_kvm_dpmi_entry_continue_to_linear(
                machine, ((uint32_t)preflight->dpmi_handoff.caller_return_cs << 4) + raw.request.di,
                &boundary)
            : DAZE_KVM_DPMI_ENTRY_INVALID;
        if (getenv("DAZE_EXEC_TRACE") != NULL)
          fprintf(stderr,
                  "raw-switch: return-protected=%d continue=%d successor kind=%d raw=%u "
                  "cs:ip=%04x:%08x cr0=%08x bytes=%02x%02x%02x%02x\n",
                  return_status, continue_status, boundary.observation.kind,
                  boundary.observation.raw_exit_reason, boundary.cs, boundary.rip, boundary.cr0,
                  boundary.instruction[0], boundary.instruction[1], boundary.instruction[2],
                  boundary.instruction[3]);
        if (return_status != DAZE_KVM_RAW_SWITCH_GATE_OK ||
            continue_status != DAZE_KVM_DPMI_ENTRY_OK) {
          return DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED;
        }
      } else {
        if (daze_kvm_dpmi_entry_continue_to_linear(machine,
                                                   ((uint32_t)raw.request.si << 4) + raw.request.di,
                                                   &boundary) != DAZE_KVM_DPMI_ENTRY_OK) {
          return DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED;
        }
      }
      break;
    }
    default: {
      if (getenv("DAZE_EXEC_TRACE") != NULL)
        fprintf(stderr,
                "exec: unclassified boundary kind=%d raw=%u pio=%04x/%u cs:ip=%04x:%08x cr0=%08x "
                "ax=%04x bx=%04x cx=%04x dx=%04x ds=%04x es=%04x ss:sp=%04x:%04x "
                "bytes=%02x%02x%02x%02x\\n",
                boundary.observation.kind, boundary.observation.raw_exit_reason,
                boundary.observation.pio_port, boundary.observation.pio_value, boundary.cs,
                boundary.rip, boundary.cr0, boundary.ax, boundary.bx, boundary.cx, boundary.dx,
                boundary.ds, boundary.es, boundary.ss, boundary.sp, boundary.instruction[0],
                boundary.instruction[1], boundary.instruction[2], boundary.instruction[3]);
      if (getenv("DAZE_EXEC_TRACE") != NULL && boundary.instruction_size >= 4 &&
          boundary.instruction[0] == 0xff && boundary.instruction[1] == 0x1e) {
        const uint16_t offset =
          (uint16_t)boundary.instruction[2] | (uint16_t)boundary.instruction[3] << 8;
        const uint64_t pointer = (uint64_t)boundary.ds_base + offset;
        if (pointer <= UINT32_MAX &&
            daze_kvm_range_fits(machine->guest_size, (uint32_t)pointer, 4)) {
          const uint8_t *const bytes = (const uint8_t *)machine->guest + pointer;
          fprintf(stderr, "exec: far-indirect ds-base=%08x operand=%04x target=%04x:%04x\\n",
                  boundary.ds_base, offset, (uint16_t)(bytes[2] | (uint16_t)bytes[3] << 8),
                  (uint16_t)(bytes[0] | (uint16_t)bytes[1] << 8));
        }
      }
      result->terminal_vector21 = input->state->interrupt_vectors[DAZE_INT_DOS];
      if (boundary.esp >= boundary.ss_base &&
          daze_kvm_range_fits(machine->guest_size, boundary.ss_base + boundary.esp,
                              sizeof(result->terminal_fault_stack))) {
        memcpy(result->terminal_fault_stack,
               (const uint8_t *)machine->guest + boundary.ss_base + boundary.esp,
               sizeof(result->terminal_fault_stack));
        result->terminal_fault_stack_present = 1;
      }
      if (gate != NULL &&
          daze_kvm_range_fits(machine->guest_size, gate->idt_address + DAZE_INT_DOS * 8u,
                              sizeof(result->terminal_vector21_idt_entry))) {
        memcpy(result->terminal_vector21_idt_entry,
               (const uint8_t *)machine->guest + gate->idt_address + DAZE_INT_DOS * 8u,
               sizeof(result->terminal_vector21_idt_entry));
        result->terminal_vector21_idt_entry_present = 1;
      }
      return DAZE_KVM_COMMAND_OWNER_POST_SUCCESSOR_BOUNDARY;
    }
    }
  }
}

static int continue_from_handoff(DazeKvmCommandOwnerHandoff *handoff,
                                 const DazeKvmCommandOwnerInput *input,
                                 const DazeKvmDpmiEntryResult *live_boundary,
                                 int restore_transition_artifacts,
                                 const DazeKvmResidentGdtState *resident_gdt,
                                 DazeKvmCommandOwnerResult *result) {
  if (result != NULL) *result = (DazeKvmCommandOwnerResult){0};
  if (handoff == NULL || !handoff->active || input == NULL || result == NULL ||
      input->state == NULL || !process_matches(&handoff->process, &input->preflight.process) ||
      !layout_agrees_with_request(input) || !endpoint_layout_valid(input)) {
    if (getenv("DAZE_EXEC_TRACE") != NULL)
      fprintf(stderr,
              "exec: live-owner reject active=%d input=%d result=%d state=%d process=%d layout=%d "
              "endpoints=%d live=%d\n",
              handoff != NULL && handoff->active, input != NULL, result != NULL,
              input != NULL && input->state != NULL,
              handoff != NULL && input != NULL &&
                process_matches(&handoff->process, &input->preflight.process),
              input != NULL && layout_agrees_with_request(input),
              input != NULL && endpoint_layout_valid(input), live_boundary != NULL);
    if (result != NULL) result->disposition = DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED;
    return DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED;
  }

  DazeKvmMachine *machine_ptr = &handoff->machine;
  DazeDosProcessState *process_state_ptr = &handoff->process_state;
  DazeDosMemory *dos_memory_ptr = &handoff->dos_memory;
#define machine (*machine_ptr)
#define process_state (*process_state_ptr)
#define dos_memory (*dos_memory_ptr)
  const DazeKvmRunnerGenericPreflightResult preflight = handoff->preflight;
  result->guest_execution_may_have_started = preflight.guest_execution_may_have_started;
  result->handoff_present = 1;

  DazeKvmGuestRange runner_reserved[3];
  const size_t runner_reserved_count =
    runner_reserved_ranges(input->preflight.process.guest_size, runner_reserved);
  const uint32_t environment_pointer = ((uint32_t)input->preflight.process.psp_segment << 4) + 0x2c;
  if (!daze_kvm_range_fits(machine.guest_size, environment_pointer, 2)) {
    result->disposition = DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED;
    goto out;
  }
  const DazeKvmTransitionPlanInput plan_input = {
    .guest_size = input->preflight.process.guest_size,
    .resident_image_end = input->transition_layout.resident_image_end,
    .client_ds = preflight.dpmi_handoff.entry_snapshot.ds,
    .client_ss = preflight.dpmi_handoff.entry_snapshot.ss,
    .return_ip = preflight.dpmi_handoff.caller_return_ip,
    .return_cs = preflight.dpmi_handoff.caller_return_cs,
    .psp_segment = input->preflight.process.psp_segment,
    .environment_segment = daze_read_u16((const uint8_t *)machine.guest + environment_pointer),
    .convert_environment = live_boundary == NULL,
    .entry_segment = input->preflight.process.dpmi_entry_segment,
    .gdt_address = input->transition_layout.gdt_address,
    .ldt_address = input->transition_layout.ldt_address,
    .idt_address = input->transition_layout.idt_address,
    .idt_limit = input->transition_layout.idt_limit,
    .linear_min_address = input->transition_layout.linear_min_address,
    .linear_limit = input->transition_layout.linear_limit,
    .additions = input->transition_layout.additions,
    .addition_count = input->transition_layout.addition_count,
    .reserved_ranges = runner_reserved,
    .reserved_range_count = runner_reserved_count,
  };
  DazeKvmTransitionPlan plan;
  DazeKvmTransitionPlanFailure plan_failure = {DAZE_KVM_TRANSITION_PLAN_VALID, {0, 0}, {0, 0}};
  const uint32_t terminal_linear = ((uint32_t)preflight.dpmi_handoff.caller_return_cs << 4) +
                                   preflight.dpmi_handoff.caller_return_ip;
  DazeKvmProtectedGateArtifacts gate_artifacts;
  const DazeKvmProtectedGateLayout *gate = input->transition_layout.protected_gate;
  DazeKvmStateSaveGateArtifacts state_gate_artifacts;
  const DazeKvmStateSaveGateLayout *state_gate = input->transition_layout.state_save_gate;
  DazeKvmRawSwitchGateArtifacts raw_gate_artifacts;
  const DazeKvmRawSwitchGateLayout *raw_gate = input->transition_layout.raw_switch_gate;
  if (gate != NULL && !daze_kvm_protected_gate_build(gate, &gate_artifacts)) {
    result->disposition = DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED;
    goto out;
  }
  if (state_gate != NULL && !daze_kvm_state_save_gate_build(state_gate, &state_gate_artifacts)) {
    result->disposition = DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED;
    goto out;
  }
  if (raw_gate != NULL && !daze_kvm_raw_switch_gate_build(raw_gate, &raw_gate_artifacts)) {
    result->disposition = DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED;
    goto out;
  }
  DazeKvmGuestWrite writes[DAZE_KVM_TRANSITION_PLAN_WRITE_COUNT + 11];
  DazeKvmDpmiEntryLayout entry_layout;
  const DazeKvmTransitionWriterInput writer = {
    &machine,
    &preflight.dpmi_handoff.entry_snapshot,
    plan_input.resident_image_end,
    plan_input.linear_min_address,
    plan_input.linear_limit,
    NULL,
    0,
    NULL,
    0,
  };
  if (daze_kvm_transition_plan_build(&plan_input, &plan, &plan_failure) &&
      plan_preserves_handoff_frame(&plan, &preflight.dpmi_handoff,
                                   input->preflight.process.guest_size) &&
      gate_writes_valid(&plan, gate, gate == NULL ? NULL : &gate_artifacts,
                        input->preflight.process.guest_size) &&
      state_gate_writes_valid(&plan, state_gate, state_gate == NULL ? NULL : &state_gate_artifacts,
                              input->preflight.process.guest_size) &&
      raw_gate_writes_valid(&plan, raw_gate, raw_gate == NULL ? NULL : &raw_gate_artifacts,
                            input->preflight.process.guest_size) &&
      plan_entry_layout(&plan, gate, gate == NULL ? NULL : &gate_artifacts, state_gate,
                        state_gate == NULL ? NULL : &state_gate_artifacts, raw_gate,
                        raw_gate == NULL ? NULL : &raw_gate_artifacts, writes, &entry_layout,
                        terminal_linear, input->preflight.process.guest_size)) {
    if (live_boundary != NULL) {
      if (restore_transition_artifacts) {
        DazeKvmTransitionWriterInput bound_writer = writer;
        bound_writer.writes = entry_layout.writes;
        bound_writer.write_count = entry_layout.write_count;
        bound_writer.reserved_ranges = plan.reserved_ranges;
        bound_writer.reserved_range_count = plan.reserved_range_count;
        /* A resident child returns through a raw gate after its parent's
         * machine snapshot has been restored. Reinstall only the already
         * validated child transition artifacts before its gate reloads the
         * protected selectors; do not redirect or re-run the DPMI handoff. */
        result->transition_stage = 2;
        result->transition_status = daze_kvm_transition_writer_apply(&bound_writer, input->state);
        if (result->transition_status == DAZE_KVM_TRANSITION_WRITER_OK &&
            (resident_gdt == NULL || !resident_gdt->valid ||
             resident_gdt->base != input->transition_layout.gdt_address ||
             resident_gdt->limit != 0xffff ||
             !daze_kvm_range_fits(machine.guest_size, resident_gdt->base,
                                  (size_t)resident_gdt->limit + 1))) {
          result->transition_status = DAZE_KVM_TRANSITION_WRITER_INVALID;
        }
        if (result->transition_status == DAZE_KVM_TRANSITION_WRITER_OK &&
            (!resident_gdt->ldt_valid || resident_gdt->ldt_bytes == NULL ||
             resident_gdt->ldt_base != input->transition_layout.ldt_address ||
             !daze_kvm_range_fits(machine.guest_size, resident_gdt->ldt_base,
                                  (size_t)resident_gdt->ldt_limit + 1))) {
          result->transition_status = DAZE_KVM_TRANSITION_WRITER_INVALID;
        }
        if (result->transition_status == DAZE_KVM_TRANSITION_WRITER_OK) {
          uint8_t *const gdt = (uint8_t *)machine.guest + resident_gdt->base;
          memcpy(gdt + 0x08, resident_gdt->code, sizeof(resident_gdt->code));
          memcpy(gdt + 0x10, resident_gdt->ds, sizeof(resident_gdt->ds));
          memcpy(gdt + 0x18, resident_gdt->es, sizeof(resident_gdt->es));
          memcpy(gdt + 0x28, resident_gdt->transition, sizeof(resident_gdt->transition));
          memcpy(gdt + 0x40, resident_gdt->stack, sizeof(resident_gdt->stack));
          memcpy((uint8_t *)machine.guest + resident_gdt->ldt_base, resident_gdt->ldt_bytes,
                 (size_t)resident_gdt->ldt_limit + 1);
          input->state->next_ldt_index = resident_gdt->next_ldt_index;
          memcpy(input->state->ldt_used, resident_gdt->ldt_used, sizeof(input->state->ldt_used));
          DazeKvmDpmiMediator resident_mediator = mediator_for_gate(
            &machine, &plan_input, gate, &input->transition_layout, input->state, &dos_memory);
          if (!daze_kvm_protected_gate_project_exception_vector(&machine, &resident_mediator,
                                                                gate) ||
              !daze_kvm_protected_gate_project_interrupt_vector(&machine, &resident_mediator, gate,
                                                                DAZE_INT_MULTIPLEX))
            result->transition_status = DAZE_KVM_TRANSITION_WRITER_INVALID;
        }
        if (getenv("DAZE_EXEC_TRACE") != NULL &&
            daze_kvm_range_fits(machine.guest_size, input->transition_layout.gdt_address + 8, 8) &&
            daze_kvm_range_fits(machine.guest_size,
                                input->transition_layout.idt_address + DAZE_INT_DOS * 8u, 8)) {
          const uint8_t *image = (const uint8_t *)machine.guest;
          const uint32_t gdt8 = input->transition_layout.gdt_address + 8;
          const uint32_t idt21 = input->transition_layout.idt_address + DAZE_INT_DOS * 8u;
          fprintf(
            stderr,
            "exec: resident transition restore status=%d gdt8=%02x%02x%02x%02x%02x%02x%02x%02x "
            "idt21=%02x%02x%02x%02x%02x%02x%02x%02x\n",
            result->transition_status, image[gdt8], image[gdt8 + 1], image[gdt8 + 2],
            image[gdt8 + 3], image[gdt8 + 4], image[gdt8 + 5], image[gdt8 + 6], image[gdt8 + 7],
            image[idt21], image[idt21 + 1], image[idt21 + 2], image[idt21 + 3], image[idt21 + 4],
            image[idt21 + 5], image[idt21 + 6], image[idt21 + 7]);
        }
      } else {
        result->transition_status = DAZE_KVM_TRANSITION_WRITER_OK;
      }
      if (result->transition_status == DAZE_KVM_TRANSITION_WRITER_OK) {
        result->transition_stage = 4;
        result->transition_status = DAZE_KVM_DPMI_ENTRY_OK;
        result->transition_successor = *live_boundary;
      }
    } else {
      result->transition_stage = 1;
      DazeKvmTransitionWriterInput bound_writer = writer;
      bound_writer.writes = plan.writes;
      bound_writer.write_count = plan.write_count;
      bound_writer.reserved_ranges = plan.reserved_ranges;
      bound_writer.reserved_range_count = plan.reserved_range_count;
      result->transition_stage = 2;
      result->transition_status = daze_kvm_transition_writer_apply(&bound_writer, input->state);
      if (result->transition_status == DAZE_KVM_TRANSITION_WRITER_OK) {
        if (!redirect_handoff_to_trampoline(&machine, &preflight.dpmi_handoff)) {
          result->transition_status = DAZE_KVM_DPMI_ENTRY_INVALID;
        } else {
          result->transition_stage = 3;
          result->transition_status = daze_kvm_dpmi_entry_run(
            &machine, &preflight.dpmi_handoff, &entry_layout, &result->transition_successor);
          result->transition_stage = 4;
        }
      } else {
        result->transition_status = DAZE_KVM_DPMI_ENTRY_INVALID;
      }
    }
    if (result->transition_status == DAZE_KVM_DPMI_ENTRY_OK) {
      result->transition_boundary_present = 1;
      if (live_boundary != NULL && state_gate != NULL && raw_gate != NULL) {
        result->disposition =
          dispatch_boundaries(handoff, input, &plan_input, &preflight, &plan, gate, state_gate,
                              raw_gate, &process_state, &dos_memory, live_boundary, result);
        goto out;
      }
      if (gate != NULL) {
        DazeKvmDpmiMediator mediator = mediator_for_gate(
          &machine, &plan_input, gate, &input->transition_layout, input->state, &dos_memory);
        result->protected_gate_status =
          daze_kvm_protected_gate_run(&machine, &mediator, gate, &result->protected_gate);
        mediator_commit(&mediator, input->state);
        result->protected_gate_present = 1;
        if (result->protected_gate_status == DAZE_KVM_PROTECTED_GATE_OK ||
            result->protected_gate_status == DAZE_KVM_PROTECTED_GATE_LIMIT_REACHED) {
          result->post_successor = result->protected_gate.terminal;
          result->post_successor_present = 1;
          /* Filling the diagnostic exchange record does not end the command;
           * its parked successor remains owned by the normal dispatcher. */
          if (state_gate != NULL && raw_gate != NULL) {
            result->disposition =
              dispatch_boundaries(handoff, input, &plan_input, &preflight, &plan, gate, state_gate,
                                  raw_gate, &process_state, &dos_memory, NULL, result);
            goto out;
          }
          result->disposition = DAZE_KVM_COMMAND_OWNER_POST_SUCCESSOR_BOUNDARY;
        } else {
          result->disposition = DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED;
        }
      } else {
        result->disposition = DAZE_KVM_COMMAND_OWNER_TRANSITION_BOUNDARY;
      }
    }
    goto out;
  }
  if (plan_failure.kind != DAZE_KVM_TRANSITION_PLAN_VALID)
    daze_kvm_transition_plan_report(&plan_input, &plan_failure);
  result->disposition = DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED;
out:
#undef process_state
#undef dos_memory
#undef machine
  return result->disposition;
}

int daze_kvm_command_owner_begin_observe(const DazeKvmRunnerGenericPreflightRequest *request,
                                         DazeKvmMachine *machine,
                                         DazeKvmCommandOwnerHandoff *handoff,
                                         DazeKvmRunnerGenericPreflightResult *observation) {
  if (observation != NULL) *observation = (DazeKvmRunnerGenericPreflightResult){0};
  if (request == NULL || handoff == NULL || handoff->active ||
      !daze_kvm_runner_process_valid(&request->process))
    return DAZE_KVM_COMMAND_OWNER_HANDOFF_PRESTART_REJECTED;
  DazeKvmCommandOwnerHandoff candidate = {0};
  if (machine != NULL) {
    if (machine->guest_size != request->process.guest_size || machine->kvm < 0 || machine->vm < 0 ||
        machine->vcpu < 0 || machine->guest == NULL || machine->run == NULL)
      return DAZE_KVM_COMMAND_OWNER_HANDOFF_PRESTART_REJECTED;
    candidate.machine = *machine;
    *machine = (DazeKvmMachine){.kvm = -1, .vm = -1, .vcpu = -1};
  } else if (daze_kvm_machine_init(&candidate.machine, request->process.guest_size) !=
             DAZE_KVM_MACHINE_OK) {
    return DAZE_KVM_COMMAND_OWNER_HANDOFF_PRESTART_REJECTED;
  }
  daze_dos_process_state_init(&candidate.process_state, request->process.psp_segment);
  daze_dos_process_state_seed_vectors(&candidate.process_state,
                                      request->process.dos_vector_segment);
  const uint32_t image_address = (uint32_t)request->process.load_segment << 4;
  const uint32_t allocation_start =
    (image_address + (uint32_t)request->process.header->image_size + 15u) >> 4;
  daze_dos_memory_init(&candidate.dos_memory,
                       allocation_start < 0x3000   ? 0x3000
                       : allocation_start < 0xa000 ? (uint16_t)allocation_start
                                                   : 0xa000,
                       0xa000);
  const int status = daze_kvm_runner_bootstrap_to_generic_boundary(
    &candidate.machine, request, &candidate.process_state, &candidate.dos_memory,
    &candidate.preflight);
  if (observation != NULL) *observation = candidate.preflight;
  if (status == DAZE_KVM_GENERIC_PREFLIGHT_TERMINATED) {
    daze_dos_process_state_dispose(&candidate.process_state);
    daze_kvm_machine_destroy(&candidate.machine);
    return DAZE_KVM_COMMAND_OWNER_HANDOFF_TERMINATED;
  }
  if (status == DAZE_KVM_GENERIC_PREFLIGHT_EXEC) {
    candidate.process = request->process;
    candidate.active = 1;
    *handoff = candidate;
    return DAZE_KVM_COMMAND_OWNER_HANDOFF_EXEC;
  }
  if (status != DAZE_KVM_GENERIC_PREFLIGHT_DPMI_ENTRY ||
      !handoff_agrees_with_request(&request->process, &candidate.preflight.dpmi_handoff)) {
    daze_dos_process_state_dispose(&candidate.process_state);
    daze_kvm_machine_destroy(&candidate.machine);
    return status == DAZE_KVM_GENERIC_PREFLIGHT_INVALID ||
               !candidate.preflight.guest_execution_may_have_started
             ? DAZE_KVM_COMMAND_OWNER_HANDOFF_PRESTART_REJECTED
             : DAZE_KVM_COMMAND_OWNER_HANDOFF_POSTSTART_FAILED;
  }
  candidate.process = request->process;
  candidate.active = 1;
  *handoff = candidate;
  return DAZE_KVM_COMMAND_OWNER_HANDOFF_OK;
}

int daze_kvm_command_owner_begin(const DazeKvmRunnerGenericPreflightRequest *request,
                                 DazeKvmCommandOwnerHandoff *handoff) {
  return daze_kvm_command_owner_begin_observe(request, NULL, handoff, NULL);
}

int daze_kvm_command_owner_continue(DazeKvmCommandOwnerHandoff *handoff,
                                    const DazeKvmCommandOwnerInput *input,
                                    DazeKvmCommandOwnerResult *result) {
  return continue_from_handoff(handoff, input, NULL, 0, NULL, result);
}

int daze_kvm_command_owner_start_exec(DazeKvmCommandOwnerHandoff *handoff,
                                      const DazeKvmRunnerGenericPreflightRequest *request,
                                      DazeDpmiProcessState *state,
                                      DazeKvmCommandOwnerResult *result) {
  const int started =
    handoff != NULL && handoff->active && handoff->preflight.guest_execution_may_have_started;
  if (result != NULL) {
    *result = (DazeKvmCommandOwnerResult){.guest_execution_may_have_started = started,
                                          .handoff_present = handoff != NULL && handoff->active};
  }
  if (handoff == NULL || !handoff->active || request == NULL || state == NULL || result == NULL ||
      !process_matches(&handoff->process, &request->process)) {
    if (result != NULL) result->disposition = DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED;
    return DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED;
  }
  const int status =
    launch_exec_child(handoff, &(DazeKvmCommandOwnerInput){.preflight = *request, .state = state},
                      &handoff->process_state, &handoff->dos_memory, result);
  result->disposition = status;
  result->guest_execution_may_have_started |= started;
  result->handoff_present = 1;
  return status;
}

void daze_kvm_command_owner_handoff_destroy(DazeKvmCommandOwnerHandoff *handoff) {
  if (handoff == NULL || !handoff->active) return;
  daze_dosfs_exec_handles_dispose(&handoff->child_handles);
  daze_kvm_child_context_dispose(&handoff->child);
  daze_kvm_resident_gdt_state_dispose(&handoff->resident_gdt);
  daze_dos_process_state_dispose(&handoff->process_state);
  daze_kvm_machine_destroy(&handoff->machine);
  *handoff = (DazeKvmCommandOwnerHandoff){0};
}
