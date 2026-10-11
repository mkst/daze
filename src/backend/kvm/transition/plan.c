#include "plan.h"

#include "linear_memory.h"
#include "kvm_range.h"
#include "guest_memory_layout.h"

#include <stdio.h>

static void set_failure(DazeKvmTransitionPlanFailure *failure,
                        DazeKvmTransitionPlanFailureKind kind, DazeKvmGuestRange first,
                        DazeKvmGuestRange second) {
  if (failure == NULL) return;
  failure->kind = kind;
  failure->first = first;
  failure->second = second;
}

static const DazeKvmGuestRange k_no_range = {0, 0};

static DazeKvmGuestRange write_range(const DazeKvmTransitionWrite *write) {
  return (DazeKvmGuestRange){write->address, write->size};
}

static int writes_valid(const DazeKvmTransitionWrite *writes, size_t write_count,
                        uint32_t guest_size, DazeKvmTransitionPlanFailure *failure) {
  for (size_t index = 0; index < write_count; ++index) {
    if (!daze_kvm_range_fits_nonempty(guest_size, writes[index].address, writes[index].size)) {
      set_failure(failure, DAZE_KVM_TRANSITION_PLAN_WRITE_OUT_OF_GUEST, write_range(writes + index),
                  k_no_range);
      return 0;
    }
    for (size_t previous = 0; previous < index; ++previous)
      if (daze_kvm_ranges_overlap(writes[index].address, writes[index].size,
                                  writes[previous].address, writes[previous].size)) {
        set_failure(failure, DAZE_KVM_TRANSITION_PLAN_WRITE_OVERLAP, write_range(writes + previous),
                    write_range(writes + index));
        return 0;
      }
  }
  return 1;
}

static int reserved_avoided_and_fitting(const DazeKvmTransitionWrite *writes, size_t write_count,
                                        const DazeKvmTransitionReservedRange *ranges,
                                        size_t range_count, uint32_t guest_size,
                                        DazeKvmTransitionPlanFailure *failure) {
  for (size_t index = 0; index < range_count; ++index) {
    if (!daze_kvm_range_fits_nonempty(guest_size, ranges[index].address, ranges[index].size)) {
      set_failure(failure, DAZE_KVM_TRANSITION_PLAN_RESERVED_OUT_OF_GUEST, ranges[index],
                  k_no_range);
      return 0;
    }
    for (size_t write = 0; write < write_count; ++write)
      if (daze_kvm_ranges_overlap(writes[write].address, writes[write].size, ranges[index].address,
                                  ranges[index].size)) {
        set_failure(failure, DAZE_KVM_TRANSITION_PLAN_RESERVED_COLLISION,
                    write_range(writes + write), ranges[index]);
        return 0;
      }
  }
  return 1;
}

static int linear_memory_has_room(const DazeKvmTransitionPlanInput *input) {
  if (input->linear_min_address >= input->linear_limit) return 0;
  uint32_t first_base = 0;
  return daze_dpmi_linear_memory_first_base_after(
    input->resident_image_end, input->linear_min_address, input->linear_limit, &first_base);
}

int daze_kvm_transition_plan_build(const DazeKvmTransitionPlanInput *input,
                                   DazeKvmTransitionPlan *output,
                                   DazeKvmTransitionPlanFailure *failure) {
  if (input == NULL || output == NULL || input->guest_size == 0 ||
      input->resident_image_end > input->guest_size || input->linear_limit > input->guest_size ||
      input->linear_min_address > input->linear_limit || input->idt_address == 0 ||
      input->idt_limit < 0x18f) {
    set_failure(failure, DAZE_KVM_TRANSITION_PLAN_BAD_INPUT, k_no_range, k_no_range);
    return 0;
  }
  if (!linear_memory_has_room(input)) {
    set_failure(failure, DAZE_KVM_TRANSITION_PLAN_NO_LINEAR_ARENA,
                (DazeKvmGuestRange){input->resident_image_end, 0}, k_no_range);
    return 0;
  }
  const uint32_t trampoline_address = (uint32_t)input->entry_segment << 4;
  if (trampoline_address > UINT32_MAX - DAZE_KVM_TRANSITION_PLAN_RAW_SWITCH_OFFSET) {
    set_failure(failure, DAZE_KVM_TRANSITION_PLAN_BAD_INPUT, k_no_range, k_no_range);
    return 0;
  }
  const uint32_t trampoline_end = trampoline_address + DAZE_KVM_TRANSITION_PLAN_RAW_SWITCH_OFFSET +
                                  DAZE_KVM_TRANSITION_PLAN_RAW_SWITCH_SIZE;
  if (trampoline_end < trampoline_address) {
    set_failure(failure, DAZE_KVM_TRANSITION_PLAN_BAD_INPUT, k_no_range, k_no_range);
    return 0;
  }
  const DazeKvmTransitionWrite writes[] = {
    {.address = input->gdt_address, .bytes = NULL, .size = DAZE_DPMI_TRANSITION_GDT_SIZE},
    {.address = input->ldt_address, .bytes = NULL, .size = DAZE_DPMI_TRANSITION_LDT_SIZE},
    {.address = trampoline_address, .bytes = NULL, .size = DAZE_DPMI_TRANSITION_TRAMPOLINE_SIZE},
    {.address = trampoline_address + DAZE_KVM_TRANSITION_PLAN_GDTR_OFFSET,
     .bytes = NULL,
     .size = DAZE_KVM_TRANSITION_PLAN_GDTR_SIZE},
    {.address = trampoline_address + DAZE_KVM_TRANSITION_PLAN_IDTR_OFFSET,
     .bytes = NULL,
     .size = DAZE_KVM_TRANSITION_PLAN_IDTR_SIZE},
    {.address = trampoline_address + DAZE_KVM_TRANSITION_PLAN_STATE_STUB_OFFSET,
     .bytes = NULL,
     .size = DAZE_KVM_TRANSITION_PLAN_STATE_STUB_SIZE},
    {.address = trampoline_address + DAZE_KVM_TRANSITION_PLAN_RAW_SWITCH_OFFSET,
     .bytes = NULL,
     .size = DAZE_KVM_TRANSITION_PLAN_RAW_SWITCH_SIZE},
    {.address = ((uint32_t)input->psp_segment << 4) + 0x2c, .bytes = NULL, .size = 2},
  };
  const size_t write_count = sizeof(writes) / sizeof(writes[0]) - !input->convert_environment;
  if (input->reserved_range_count > DAZE_KVM_TRANSITION_PLAN_MAX_RESERVED_RANGES ||
      (input->reserved_range_count != 0 && input->reserved_ranges == NULL)) {
    set_failure(failure, DAZE_KVM_TRANSITION_PLAN_BAD_INPUT, k_no_range, k_no_range);
    return 0;
  }
  if (writes_valid(writes, write_count, input->guest_size, failure) == 0 ||
      reserved_avoided_and_fitting(writes, write_count, input->reserved_ranges,
                                   input->reserved_range_count, input->guest_size, failure) == 0)
    return 0;

  DazeDpmiTransitionArtifacts artifacts;
  if (!daze_dpmi_transition_artifacts_build(
        &(DazeDpmiTransitionArtifactInput){.client_ds = input->client_ds,
                                           .client_ss = input->client_ss,
                                           .return_ip = input->return_ip,
                                           .return_cs = input->return_cs,
                                           .psp_segment = input->psp_segment,
                                           .environment_segment = input->environment_segment,
                                           .convert_environment = input->convert_environment,
                                           .entry_segment = input->entry_segment,
                                           .gdt_address = input->gdt_address,
                                           .ldt_address = input->ldt_address,
                                           .idt_address = input->idt_address,
                                           .idt_limit = input->idt_limit,
                                           .additions = input->additions,
                                           .addition_count = input->addition_count},
        &artifacts)) {
    set_failure(failure, DAZE_KVM_TRANSITION_PLAN_BAD_INPUT, k_no_range, k_no_range);
    return 0;
  }

  DazeKvmTransitionPlan plan = {.trampoline_address = trampoline_address,
                                .resident_image_end = input->resident_image_end,
                                .linear_min_address = input->linear_min_address,
                                .linear_limit = input->linear_limit,
                                .artifacts = artifacts,
                                .write_count = write_count,
                                .reserved_range_count = input->reserved_range_count};
  for (size_t index = 0; index < input->reserved_range_count; ++index)
    plan.reserved_ranges[index] = input->reserved_ranges[index];
  *output = plan;
  output->writes[0] = (DazeKvmTransitionWrite){.address = input->gdt_address,
                                               .bytes = output->artifacts.gdt,
                                               .size = sizeof(output->artifacts.gdt)};
  output->writes[1] = (DazeKvmTransitionWrite){.address = input->ldt_address,
                                               .bytes = output->artifacts.ldt,
                                               .size = sizeof(output->artifacts.ldt)};
  output->writes[2] = (DazeKvmTransitionWrite){.address = trampoline_address,
                                               .bytes = output->artifacts.trampoline,
                                               .size = sizeof(output->artifacts.trampoline)};
  output->writes[3] =
    (DazeKvmTransitionWrite){.address = trampoline_address + DAZE_KVM_TRANSITION_PLAN_GDTR_OFFSET,
                             .bytes = output->artifacts.gdtr,
                             .size = sizeof(output->artifacts.gdtr)};
  output->writes[4] =
    (DazeKvmTransitionWrite){.address = trampoline_address + DAZE_KVM_TRANSITION_PLAN_IDTR_OFFSET,
                             .bytes = output->artifacts.idtr,
                             .size = sizeof(output->artifacts.idtr)};
  output->writes[5] = (DazeKvmTransitionWrite){
    .address = trampoline_address + DAZE_KVM_TRANSITION_PLAN_STATE_STUB_OFFSET,
    .bytes = output->artifacts.state_stub,
    .size = sizeof(output->artifacts.state_stub)};
  output->writes[6] = (DazeKvmTransitionWrite){
    .address = trampoline_address + DAZE_KVM_TRANSITION_PLAN_RAW_SWITCH_OFFSET,
    .bytes = output->artifacts.raw_switch_stub,
    .size = sizeof(output->artifacts.raw_switch_stub)};
  if (input->convert_environment)
    output->writes[7] =
      (DazeKvmTransitionWrite){.address = ((uint32_t)input->psp_segment << 4) + 0x2c,
                               .bytes = output->artifacts.environment_pointer,
                               .size = sizeof(output->artifacts.environment_pointer)};
  set_failure(failure, DAZE_KVM_TRANSITION_PLAN_VALID, k_no_range, k_no_range);
  return 1;
}

static const char *plan_failure_range_name(const DazeKvmTransitionPlanInput *input,
                                           uint32_t address, size_t size) {
  static const char *const runner_roles[] = {"KVM runner gate arena", "KVM runner record",
                                             "KVM runner mailbox"};
  const uint32_t trampoline = (uint32_t)input->entry_segment << 4;
  if (address == input->gdt_address && size == DAZE_DPMI_TRANSITION_GDT_SIZE) return "DPMI GDT";
  if (address == input->ldt_address && size == DAZE_DPMI_TRANSITION_LDT_SIZE) return "DPMI LDT";
  if (address == trampoline && size == DAZE_DPMI_TRANSITION_TRAMPOLINE_SIZE)
    return "DPMI entry trampoline";
  if (address == trampoline + DAZE_KVM_TRANSITION_PLAN_GDTR_OFFSET &&
      size == DAZE_KVM_TRANSITION_PLAN_GDTR_SIZE)
    return "DPMI GDTR";
  if (address == trampoline + DAZE_KVM_TRANSITION_PLAN_IDTR_OFFSET &&
      size == DAZE_KVM_TRANSITION_PLAN_IDTR_SIZE)
    return "DPMI IDTR";
  if (address == trampoline + DAZE_KVM_TRANSITION_PLAN_STATE_STUB_OFFSET &&
      size == DAZE_KVM_TRANSITION_PLAN_STATE_STUB_SIZE)
    return "DPMI state stub";
  if (address == trampoline + DAZE_KVM_TRANSITION_PLAN_RAW_SWITCH_OFFSET &&
      size == DAZE_KVM_TRANSITION_PLAN_RAW_SWITCH_SIZE)
    return "DPMI raw-switch stub";
  if (input->reserved_ranges != NULL)
    for (size_t index = 0; index < input->reserved_range_count && index < 3; ++index)
      if (address == input->reserved_ranges[index].address &&
          size == input->reserved_ranges[index].size)
        return runner_roles[index];
  return "transition range";
}

void daze_kvm_transition_plan_report(const DazeKvmTransitionPlanInput *input,
                                     const DazeKvmTransitionPlanFailure *failure) {
  if (input == NULL || failure == NULL) return;
  char first_text[64], second_text[64];
  daze_guest_layout_format_named(
    first_text, sizeof(first_text),
    plan_failure_range_name(input, failure->first.address, failure->first.size),
    failure->first.address, (uint32_t)failure->first.size);
  daze_guest_layout_format_named(
    second_text, sizeof(second_text),
    plan_failure_range_name(input, failure->second.address, failure->second.size),
    failure->second.address, (uint32_t)failure->second.size);
  switch (failure->kind) {
  case DAZE_KVM_TRANSITION_PLAN_WRITE_OVERLAP:
  case DAZE_KVM_TRANSITION_PLAN_RESERVED_COLLISION:
    fprintf(stderr, "kvm: transition plan rejected at DPMI transition: %s overlaps %s\n",
            first_text, second_text);
    break;
  case DAZE_KVM_TRANSITION_PLAN_WRITE_OUT_OF_GUEST:
  case DAZE_KVM_TRANSITION_PLAN_RESERVED_OUT_OF_GUEST:
    fprintf(stderr,
            "kvm: transition plan rejected at DPMI transition: %s does not fit the %08x-byte "
            "guest\n",
            first_text, input->guest_size);
    break;
  case DAZE_KVM_TRANSITION_PLAN_NO_LINEAR_ARENA:
    fprintf(stderr,
            "kvm: transition plan rejected at DPMI transition: no linear arena after resident "
            "image end %08x (limit %08x)\n",
            failure->first.address, input->linear_limit);
    break;
  case DAZE_KVM_TRANSITION_PLAN_VALID:
  case DAZE_KVM_TRANSITION_PLAN_BAD_INPUT:
  default:
    fprintf(stderr, "kvm: transition plan rejected at DPMI transition: internal error\n");
    break;
  }
}
