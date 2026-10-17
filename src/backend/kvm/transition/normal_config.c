#include "normal_config.h"

#include "interrupt_vector.h"
#include "kvm_range.h"
#include "guest_memory_layout.h"
#include "selector.h"

#include <stdio.h>
#include <string.h>

enum {
  k_idt_size = 256 * 8,
  k_idt_limit = k_idt_size - 1,
  k_idt_address = k_dpmi_ldt_address - k_idt_size,
  /* A 16-bit client far jump needs a gate-relative offset. */
  k_protected_default_dos_stub_offset = 0x01c8,
  k_gate_base = k_idt_address - 0x1000,
  k_protected_handler = k_gate_base,
  k_protected_dos_handler = k_protected_handler + 0x100,
  k_protected_default_dos_stub = k_protected_handler + k_protected_default_dos_stub_offset,
  k_protected_record = k_protected_dos_handler + 0x100,
  k_protected_mailbox = k_protected_record + 0x40,
  k_state_save_handler = k_protected_mailbox + 0x40,
  k_raw_switch_handler = k_state_save_handler + 0x20,
  k_gate_end = k_gate_base + 0x540,
  /* 0040h and 0048h belong to client and exception stacks. Private gates must avoid
   * them; the 0060h alias is 32-bit for the default DOS stub's far jump. */
  k_gate_code_selector = DAZE_SEL_GATE_CODE,
  k_gate_data_selector = DAZE_SEL_GATE_DATA,
  k_gate_alias_code_selector = DAZE_SEL_GATE_ALIAS,
  k_raw_switch_linear = (k_dpmi_entry_segment << 4) + DAZE_KVM_TRANSITION_PLAN_RAW_SWITCH_OFFSET,
};

typedef struct {
  DazeDpmiTransitionDescriptorAddition items[DAZE_KVM_NORMAL_TRANSITION_CONFIG_MAX_ADDITIONS];
  size_t count;
} NormalInventory;

static int add(NormalInventory *inventory, DazeDpmiTransitionDescriptorAddition addition) {
  if (addition.table != DAZE_DPMI_TRANSITION_GDT && addition.table != DAZE_DPMI_TRANSITION_LDT)
    return 0;
  for (size_t index = 0; index < inventory->count; ++index) {
    if (inventory->items[index].table == addition.table &&
        inventory->items[index].selector == addition.selector) {
      inventory->items[index] = addition;
      return 1;
    }
  }
  if (inventory->count == DAZE_KVM_NORMAL_TRANSITION_CONFIG_MAX_ADDITIONS) return 0;
  inventory->items[inventory->count++] = addition;
  return 1;
}

static int has_gdt_selector(const NormalInventory *inventory, uint16_t selector) {
  for (size_t index = 0; index < inventory->count; ++index)
    if (inventory->items[index].table == DAZE_DPMI_TRANSITION_GDT &&
        inventory->items[index].selector == selector)
      return 1;
  return 0;
}

static void set_failure(DazeKvmNormalTransitionConfigFailure *failure,
                        DazeKvmNormalTransitionConfigFailureKind kind, DazeKvmGuestRange first,
                        DazeKvmGuestRange second) {
  if (failure == NULL) return;
  failure->kind = kind;
  failure->first = first;
  failure->second = second;
}

static const DazeKvmGuestRange k_no_range = {0, 0};

static int disjoint(uint32_t first_address, size_t first_size, uint32_t second_address,
                    size_t second_size) {
  return !daze_kvm_ranges_overlap(first_address, first_size, second_address, second_size);
}

static int fits_or_report(uint32_t guest_size, uint32_t address, size_t size,
                          DazeKvmNormalTransitionConfigFailure *failure) {
  if (daze_kvm_range_fits_nonempty(guest_size, address, size)) return 1;
  set_failure(failure, DAZE_KVM_NORMAL_TRANSITION_CONFIG_RANGE_OUT_OF_GUEST,
              (DazeKvmGuestRange){address, size}, k_no_range);
  return 0;
}

static int overlap_or_report(uint32_t first_address, size_t first_size, uint32_t second_address,
                             size_t second_size, DazeKvmNormalTransitionConfigFailure *failure) {
  if (disjoint(first_address, first_size, second_address, second_size)) return 1;
  set_failure(failure, DAZE_KVM_NORMAL_TRANSITION_CONFIG_RANGE_OVERLAP,
              (DazeKvmGuestRange){first_address, first_size},
              (DazeKvmGuestRange){second_address, second_size});
  return 0;
}

static int runner_ranges_avoided(const DazeKvmNormalTransitionConfigInput *input,
                                 DazeKvmNormalTransitionConfigFailure *failure) {
  if (input->reserved_range_count != 0 && input->reserved_ranges == NULL) {
    set_failure(failure, DAZE_KVM_NORMAL_TRANSITION_CONFIG_BAD_INPUT, k_no_range, k_no_range);
    return 0;
  }
  for (size_t index = 0; index < input->reserved_range_count; ++index)
    if (!overlap_or_report(k_gate_base, (size_t)k_gate_end - k_gate_base,
                           input->reserved_ranges[index].address,
                           input->reserved_ranges[index].size, failure))
      return 0;
  return 1;
}

static int normal_input_valid(const DazeKvmNormalTransitionConfigInput *input) {
  return input != NULL && input->guest_size == k_memory_size && input->psp_segment != 0 &&
         input->psp_segment <= UINT16_MAX - 0x10 &&
         input->load_segment == (uint16_t)(input->psp_segment + 0x10) &&
         input->environment_segment != 0 && input->dpmi_entry_segment == k_dpmi_entry_segment &&
         input->dos_int21_vector_segment == k_dos_int21_vector_segment && input->handoff_ds != 0 &&
         input->handoff_ss != 0 && input->handoff_return_cs != 0;
}

static int layout_valid(const DazeKvmNormalTransitionConfigInput *input,
                        DazeKvmNormalTransitionConfigFailure *failure) {
  const uint32_t image_address = (uint32_t)input->load_segment << 4;
  const size_t image_size = input->resident_image_end - image_address;
  const size_t gate_size = k_gate_end - k_gate_base;
  if (input->resident_image_end <= image_address) {
    set_failure(failure, DAZE_KVM_NORMAL_TRANSITION_CONFIG_BAD_INPUT, k_no_range, k_no_range);
    return 0;
  }
  return fits_or_report(input->guest_size, image_address, image_size, failure) &&
         fits_or_report(input->guest_size, k_dpmi_gdt_address, DAZE_DPMI_TRANSITION_GDT_SIZE,
                        failure) &&
         fits_or_report(input->guest_size, k_dpmi_ldt_address, DAZE_DPMI_TRANSITION_LDT_SIZE,
                        failure) &&
         fits_or_report(input->guest_size, k_idt_address, k_idt_size, failure) &&
         fits_or_report(input->guest_size, k_gate_base, gate_size, failure) &&
         fits_or_report(input->guest_size, k_dpmi_rm_gate_linear,
                        DAZE_KVM_RAW_SWITCH_GATE_HANDLER_SIZE, failure) &&
         overlap_or_report(k_idt_address, k_idt_size, k_dpmi_gdt_address,
                           DAZE_DPMI_TRANSITION_GDT_SIZE, failure) &&
         overlap_or_report(k_idt_address, k_idt_size, k_dpmi_ldt_address,
                           DAZE_DPMI_TRANSITION_LDT_SIZE, failure) &&
         overlap_or_report(k_dpmi_ldt_address, DAZE_DPMI_TRANSITION_LDT_SIZE, k_dpmi_gdt_address,
                           DAZE_DPMI_TRANSITION_GDT_SIZE, failure) &&
         overlap_or_report(k_gate_base, gate_size, image_address, image_size, failure) &&
         overlap_or_report(k_gate_base, gate_size, k_idt_address, k_idt_size, failure) &&
         overlap_or_report(k_gate_base, gate_size, k_dpmi_ldt_address,
                           DAZE_DPMI_TRANSITION_LDT_SIZE, failure) &&
         overlap_or_report(k_gate_base, gate_size, k_dpmi_gdt_address,
                           DAZE_DPMI_TRANSITION_GDT_SIZE, failure) &&
         overlap_or_report(k_gate_base, gate_size, 0, k_raw_switch_linear, failure) &&
         runner_ranges_avoided(input, failure) &&
         overlap_or_report(k_gate_base, gate_size, k_dpmi_rm_gate_linear,
                           DAZE_KVM_RAW_SWITCH_GATE_HANDLER_SIZE, failure);
}

int daze_kvm_normal_transition_config_build(const DazeKvmNormalTransitionConfigInput *input,
                                            DazeKvmNormalTransitionConfig *output,
                                            DazeKvmNormalTransitionConfigFailure *failure) {
  if (output == NULL || input == NULL) {
    set_failure(failure, DAZE_KVM_NORMAL_TRANSITION_CONFIG_BAD_INPUT, k_no_range, k_no_range);
    return 0;
  }
  if (!normal_input_valid(input)) {
    set_failure(failure, DAZE_KVM_NORMAL_TRANSITION_CONFIG_BAD_INPUT, k_no_range, k_no_range);
    return 0;
  }
  if (!layout_valid(input, failure)) return 0;

  NormalInventory inventory = {0};
  const DazeDpmiTransitionDescriptorAddition normal_additions[] = {
    {DAZE_DPMI_TRANSITION_GDT, DAZE_SEL_GDT_DESC, 0x0500, 7, 0x92, 0x00},
    {DAZE_DPMI_TRANSITION_GDT, input->dos_int21_vector_segment,
     (uint32_t)input->dos_int21_vector_segment << 4, 0xffff, 0xf2, 0x00},
    {DAZE_DPMI_TRANSITION_GDT, (uint16_t)(input->handoff_ds & (uint16_t)~7u),
     (uint32_t)input->handoff_ds << 4, 0xffff, 0xf2, 0x00},
    {DAZE_DPMI_TRANSITION_GDT, (uint16_t)(input->handoff_ss & (uint16_t)~7u),
     (uint32_t)input->handoff_ss << 4, 0xffff, 0xf2, 0x00},
    {DAZE_DPMI_TRANSITION_GDT, (uint16_t)(input->handoff_return_cs & (uint16_t)~7u),
     (uint32_t)input->handoff_return_cs << 4, 0xffff, 0xf2, 0x00},
    /* DPMILOAD reloads real-mode data and stack values as TI=1 selectors; their LDT
     * entries must preserve the published bases. */
    {DAZE_DPMI_TRANSITION_LDT, (uint16_t)(input->handoff_ds & (uint16_t)~7u),
     (uint32_t)input->handoff_ds << 4, 0xffff, 0xf2, 0x00},
    {DAZE_DPMI_TRANSITION_GDT, 0x1010, 0x10100, 0xffff, 0x92, 0x00},
    {DAZE_DPMI_TRANSITION_GDT, 0x0ff0, 0x0ff00, 0xffff, 0xf2, 0x00},
    {DAZE_DPMI_TRANSITION_LDT, DAZE_SEL_LDT, 0x00000, 0xffff, 0xf2, 0x00},
    {DAZE_DPMI_TRANSITION_LDT, 0x2e68, 0x2e6c0, 0xffff, 0xf2, 0x00},
    {DAZE_DPMI_TRANSITION_LDT, 0xfff8, 0xffff0, 0xffff, 0xf2, 0x00},
  };
  for (size_t index = 0; index < sizeof(normal_additions) / sizeof(normal_additions[0]); ++index)
    if (!add(&inventory, normal_additions[index])) {
      set_failure(failure, DAZE_KVM_NORMAL_TRANSITION_CONFIG_BAD_INPUT, k_no_range, k_no_range);
      return 0;
    }
  if ((input->handoff_ss & (uint16_t)~7u) != (input->handoff_ds & (uint16_t)~7u) &&
      !add(&inventory, (DazeDpmiTransitionDescriptorAddition){
                         DAZE_DPMI_TRANSITION_LDT, (uint16_t)(input->handoff_ss & (uint16_t)~7u),
                         (uint32_t)input->handoff_ss << 4, 0xffff, 0xf2, 0})) {
    set_failure(failure, DAZE_KVM_NORMAL_TRANSITION_CONFIG_BAD_INPUT, k_no_range, k_no_range);
    return 0;
  }
  /* A client parking its own selectors on the host-owned gate slots cannot
   * enter the normal transition; name the colliding selector for the
   * DPMI-transition diagnostic. */
  uint16_t colliding_selector = 0;
  if (has_gdt_selector(&inventory, k_gate_code_selector))
    colliding_selector = k_gate_code_selector;
  else if (has_gdt_selector(&inventory, k_gate_data_selector))
    colliding_selector = k_gate_data_selector;
  else if (has_gdt_selector(&inventory, k_gate_alias_code_selector))
    colliding_selector = k_gate_alias_code_selector;
  else if (has_gdt_selector(&inventory, DAZE_SEL_EXCEPTION_RETURN))
    colliding_selector = DAZE_SEL_EXCEPTION_RETURN;
  if (colliding_selector != 0) {
    set_failure(failure, DAZE_KVM_NORMAL_TRANSITION_CONFIG_BAD_INPUT,
                (DazeKvmGuestRange){colliding_selector, 0}, k_no_range);
    return 0;
  }
  if (!add(&inventory,
           (DazeDpmiTransitionDescriptorAddition){DAZE_DPMI_TRANSITION_GDT, k_gate_code_selector, 0,
                                                  0xfffff, 0x9a, 0x0c}) ||
      !add(&inventory,
           (DazeDpmiTransitionDescriptorAddition){DAZE_DPMI_TRANSITION_GDT, k_gate_data_selector, 0,
                                                  0xfffff, 0x92, 0x0c}) ||
      !add(&inventory, (DazeDpmiTransitionDescriptorAddition){DAZE_DPMI_TRANSITION_GDT,
                                                              k_gate_alias_code_selector,
                                                              k_gate_base, 0xffff, 0x9a, 0x0c}) ||
      !add(&inventory, (DazeDpmiTransitionDescriptorAddition){
                         DAZE_DPMI_TRANSITION_GDT, DAZE_SEL_EXCEPTION_RETURN,
                         k_dpmi_exception_locked_stack_base,
                         k_memory_size - k_dpmi_exception_locked_stack_base - 1, 0x9a, 0x04})) {
    set_failure(failure, DAZE_KVM_NORMAL_TRANSITION_CONFIG_BAD_INPUT, k_no_range, k_no_range);
    return 0;
  }

  DazeKvmNormalTransitionConfig candidate = {0};
  memcpy(candidate.additions, inventory.items, inventory.count * sizeof(inventory.items[0]));
  candidate.addition_count = inventory.count;
  candidate.protected_gate = (DazeKvmProtectedGateLayout){
    .idt_address = k_idt_address,
    .idt_limit = k_idt_limit,
    .handler_address = k_protected_handler,
    .dos_handler_address = k_protected_dos_handler,
    .default_dos_stub_address = k_protected_default_dos_stub,
    .record_address = k_protected_record,
    .mailbox_address = k_protected_mailbox,
    .handler_selector = k_gate_code_selector,
    .handler_data_selector = k_gate_data_selector,
    .interrupt_gate_type = 0x8e,
    .exchange_limit = DAZE_KVM_PROTECTED_GATE_MAX_EXCHANGES,
    .exception_gate_vector = DAZE_INT_GP_FAULT,
    .exception_gate_type = 0x8e,
    .legacy_np_capture_address = k_gate_base + 0x400,
    .virtual_handler_address = k_gate_base + 0x500,
    .virtual_control_address = k_protected_record + DAZE_KVM_DPMI_RECORD_SIZE,
    .rm_entry_address = k_dpmi_rm_entry_linear,
  };
  candidate.state_save_gate = (DazeKvmStateSaveGateLayout){k_idt_address, k_state_save_handler,
                                                           k_idt_limit, k_gate_code_selector};
  candidate.raw_switch_gate = (DazeKvmRawSwitchGateLayout){
    k_idt_address, k_raw_switch_handler, k_dpmi_rm_gate_linear, k_idt_limit, k_gate_code_selector};
  candidate.transition_layout = (DazeKvmCommandOwnerTransitionLayout){
    .resident_image_end = input->resident_image_end,
    .gdt_address = k_dpmi_gdt_address,
    .ldt_address = k_dpmi_ldt_address,
    .idt_address = k_idt_address,
    .idt_limit = k_idt_limit,
    .linear_min_address = k_dpmi_linear_min_address,
    .linear_limit = k_dpmi_exception_locked_stack_base,
    .additions = candidate.additions,
    .addition_count = candidate.addition_count,
    .state_save_endpoints = {.state_buffer_size = DAZE_DPMI_ALTERNATE_STATE_SIZE,
                             .rm_segment = input->dpmi_entry_segment,
                             .rm_offset = 0x0100,
                             .pm_selector = DAZE_SEL_GATE,
                             .pm_offset = 0x0100},
    .raw_switch_endpoints = {.rm_segment = input->dpmi_entry_segment,
                             .rm_offset = 0x0120,
                             .pm_selector = DAZE_SEL_GATE,
                             .pm_offset = 0x0120},
    .protected_gate = &candidate.protected_gate,
    .state_save_gate = &candidate.state_save_gate,
    .raw_switch_gate = &candidate.raw_switch_gate,
    .raw_switch_linear = k_raw_switch_linear,
    .default_vector_alias_selector = k_gate_alias_code_selector,
    .default_vector_alias_offset = k_protected_default_dos_stub_offset,
  };

  /* Repair self-references after copying the complete owned object. */
  *output = candidate;
  output->transition_layout.additions = output->additions;
  output->transition_layout.protected_gate = &output->protected_gate;
  output->transition_layout.state_save_gate = &output->state_save_gate;
  output->transition_layout.raw_switch_gate = &output->raw_switch_gate;
  set_failure(failure, DAZE_KVM_NORMAL_TRANSITION_CONFIG_VALID, k_no_range, k_no_range);
  return 1;
}

static const char *config_failure_range_name(const DazeKvmNormalTransitionConfigInput *input,
                                             uint32_t address, size_t size) {
  static const char *const runner_roles[] = {"KVM runner gate arena", "KVM runner record",
                                             "KVM runner mailbox"};
  const uint32_t image_address = (uint32_t)input->load_segment << 4;
  if (address == image_address && size == input->resident_image_end - image_address)
    return "MZ image";
  if (input->reserved_ranges != NULL)
    for (size_t index = 0; index < input->reserved_range_count && index < 3; ++index)
      if (address == input->reserved_ranges[index].address &&
          size == input->reserved_ranges[index].size)
        return runner_roles[index];
  return "transition range";
}

void daze_kvm_normal_transition_config_report(const DazeKvmNormalTransitionConfigInput *input,
                                              const DazeKvmNormalTransitionConfigFailure *failure) {
  if (input == NULL || failure == NULL) return;
  char first_text[64], second_text[64];
  daze_guest_layout_format_named(
    first_text, sizeof(first_text),
    config_failure_range_name(input, failure->first.address, failure->first.size),
    failure->first.address, (uint32_t)failure->first.size);
  daze_guest_layout_format_named(
    second_text, sizeof(second_text),
    config_failure_range_name(input, failure->second.address, failure->second.size),
    failure->second.address, (uint32_t)failure->second.size);
  switch (failure->kind) {
  case DAZE_KVM_NORMAL_TRANSITION_CONFIG_RANGE_OVERLAP:
    fprintf(stderr, "kvm: normal transition config rejected at DPMI transition: %s overlaps %s\n",
            first_text, second_text);
    break;
  case DAZE_KVM_NORMAL_TRANSITION_CONFIG_RANGE_OUT_OF_GUEST:
    fprintf(stderr,
            "kvm: normal transition config rejected at DPMI transition: %s does not fit the "
            "%08x-byte guest\n",
            first_text, input->guest_size);
    break;
  case DAZE_KVM_NORMAL_TRANSITION_CONFIG_VALID:
  case DAZE_KVM_NORMAL_TRANSITION_CONFIG_BAD_INPUT:
  default:
    if (failure->first.size == 0 && failure->first.address != 0)
      fprintf(stderr,
              "kvm: normal transition config rejected at DPMI transition: client selector %04x "
              "collides with a host-owned gate slot (ds=%04x ss=%04x return=%04x:%04x)\n",
              failure->first.address, input->handoff_ds, input->handoff_ss,
              input->handoff_return_cs, input->handoff_return_ip);
    else
      fprintf(stderr,
              "kvm: normal transition config rejected at DPMI transition: invalid input "
              "(guest=%08x image-end=%08x load=%04x psp=%04x entry=%04x)\n",
              input->guest_size, input->resident_image_end, input->load_segment, input->psp_segment,
              input->dpmi_entry_segment);
    break;
  }
}
