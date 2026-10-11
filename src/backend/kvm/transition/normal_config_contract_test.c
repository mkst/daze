#include "normal_config.h"
#include "guest_memory_layout.h"
#include "runner/runner_private.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <assert.h>
#ifdef NDEBUG
#undef assert
#define assert(expression) ((expression) ? (void)0 : abort())
#endif

static DazeKvmNormalTransitionConfigInput normal_input(void) {
  /* Runner-owned ranges from the real computation; the config only avoids
   * them. Static storage because the input borrows the ranges. */
  static DazeKvmGuestRange runner_reserved[3];
  DazeKvmNormalTransitionConfigInput input = {
    .guest_size = k_memory_size,
    .resident_image_end = 0x00180000,
    .load_segment = k_load_segment,
    .psp_segment = k_psp_segment,
    .environment_segment = k_environment_segment,
    .dpmi_entry_segment = k_dpmi_entry_segment,
    .dos_int21_vector_segment = k_dos_int21_vector_segment,
    .handoff_ds = 0x1010,
    .handoff_ss = 0x1010,
    .handoff_return_ip = 0x37b2,
    .handoff_return_cs = 0x107f,
  };
  input.reserved_ranges = runner_reserved;
  input.reserved_range_count = runner_reserved_ranges(k_memory_size, runner_reserved);
  return input;
}

static const DazeDpmiTransitionDescriptorAddition *
find_addition(const DazeKvmNormalTransitionConfig *config, uint8_t table, uint16_t selector) {
  for (size_t index = 0; index < config->addition_count; ++index)
    if (config->additions[index].table == table && config->additions[index].selector == selector)
      return &config->additions[index];
  return NULL;
}

static int inventory_unique(const DazeKvmNormalTransitionConfig *config) {
  for (size_t first = 0; first < config->addition_count; ++first)
    for (size_t second = first + 1; second < config->addition_count; ++second)
      if (config->additions[first].table == config->additions[second].table &&
          config->additions[first].selector == config->additions[second].selector)
        return 0;
  return 1;
}

static void rejection_and_diagnostic_contract(void) {
  DazeKvmNormalTransitionConfig output;
  memset(&output, 0xa5, sizeof(output));
  DazeKvmNormalTransitionConfig before = output;
  DazeKvmNormalTransitionConfigInput valid = normal_input();
  const DazeKvmGuestRange collision = {0xfde800, 0x420};
  DazeKvmNormalTransitionConfigFailure failure;
  assert(!daze_kvm_normal_transition_config_build(NULL, &output, &failure));
  assert(failure.kind == DAZE_KVM_NORMAL_TRANSITION_CONFIG_BAD_INPUT);
  assert(!daze_kvm_normal_transition_config_build(&valid, NULL, &failure));
  for (int kind = 0; kind < 17; ++kind) {
    DazeKvmNormalTransitionConfigInput bad = valid;
    DazeKvmNormalTransitionConfigFailureKind expected = DAZE_KVM_NORMAL_TRANSITION_CONFIG_BAD_INPUT;
    switch (kind) {
    case 0:
      bad.guest_size--;
      break;
    case 1:
      bad.psp_segment = 0;
      break;
    case 2:
      bad.psp_segment = 0xffff;
      break;
    case 3:
      bad.load_segment++;
      break;
    case 4:
      bad.environment_segment = 0;
      break;
    case 5:
      bad.dpmi_entry_segment++;
      break;
    case 6:
      bad.dos_int21_vector_segment++;
      break;
    case 7:
      bad.handoff_ds = 0;
      break;
    case 8:
      bad.handoff_ss = 0;
      break;
    case 9:
      bad.handoff_return_cs = 0;
      break;
    case 10:
      bad.resident_image_end = (uint32_t)bad.load_segment << 4;
      break;
    case 11:
      bad.resident_image_end = k_memory_size + 1;
      expected = DAZE_KVM_NORMAL_TRANSITION_CONFIG_RANGE_OUT_OF_GUEST;
      break;
    case 12:
      bad.reserved_ranges = NULL;
      bad.reserved_range_count = 1;
      break;
    case 13:
      bad.handoff_ss = 0x0058;
      break;
    case 14:
      bad.handoff_return_cs = 0x0060;
      break;
    case 15:
      bad.resident_image_end = 0xfde801;
      expected = DAZE_KVM_NORMAL_TRANSITION_CONFIG_RANGE_OVERLAP;
      break;
    case 16:
      bad.reserved_ranges = &collision;
      bad.reserved_range_count = 1;
      expected = DAZE_KVM_NORMAL_TRANSITION_CONFIG_RANGE_OVERLAP;
      break;
    }
    assert(!daze_kvm_normal_transition_config_build(&bad, &output, &failure));
    assert(failure.kind == expected && memcmp(&before, &output, sizeof(output)) == 0);
  }
  valid.handoff_ss = 0x1110;
  assert(daze_kvm_normal_transition_config_build(&valid, &output, NULL));
  const DazeDpmiTransitionDescriptorAddition *stack =
    find_addition(&output, DAZE_DPMI_TRANSITION_LDT, 0x1110);
  assert(stack != NULL && stack->base == 0x11100 && stack->access == 0xf2 &&
         inventory_unique(&output));

  FILE *capture = tmpfile();
  assert(capture != NULL);
  int saved = dup(STDERR_FILENO);
  assert(saved >= 0 && dup2(fileno(capture), STDERR_FILENO) >= 0);
  daze_kvm_normal_transition_config_report(NULL, &failure);
  daze_kvm_normal_transition_config_report(&valid, NULL);
  assert(fflush(stderr) == 0 && ftell(capture) == 0);
  valid = normal_input();
  valid.resident_image_end = 0xfde801;
  assert(!daze_kvm_normal_transition_config_build(&valid, &output, &failure));
  daze_kvm_normal_transition_config_report(&valid, &failure);
  valid = normal_input();
  valid.resident_image_end = k_memory_size + 1;
  assert(!daze_kvm_normal_transition_config_build(&valid, &output, &failure));
  daze_kvm_normal_transition_config_report(&valid, &failure);
  valid = normal_input();
  valid.handoff_ss = 0x58;
  assert(!daze_kvm_normal_transition_config_build(&valid, &output, &failure));
  daze_kvm_normal_transition_config_report(&valid, &failure);
  valid = normal_input();
  valid.handoff_ds = 0;
  assert(!daze_kvm_normal_transition_config_build(&valid, &output, &failure));
  daze_kvm_normal_transition_config_report(&valid, &failure);
  valid = normal_input();
  /* Each borrowed runner range has a distinct diagnostic role. */
  for (size_t role = 0; role < 3; ++role) {
    failure = (DazeKvmNormalTransitionConfigFailure){
      .kind = DAZE_KVM_NORMAL_TRANSITION_CONFIG_RANGE_OVERLAP,
      .first = {0xfde800, 0x420},
      .second = valid.reserved_ranges[role]};
    daze_kvm_normal_transition_config_report(&valid, &failure);
  }
  valid.reserved_ranges = NULL;
  valid.reserved_range_count = 0;
  daze_kvm_normal_transition_config_report(&valid, &failure);
  assert(fflush(stderr) == 0 && dup2(saved, STDERR_FILENO) >= 0);
  close(saved);
  rewind(capture);
  char text[8192];
  size_t size = fread(text, 1, sizeof(text) - 1, capture);
  text[size] = 0;
  assert(strstr(text, "overlaps MZ image") != NULL && strstr(text, "does not fit") != NULL &&
         strstr(text, "client selector 0058") != NULL && strstr(text, "invalid input") != NULL &&
         strstr(text, "KVM runner gate arena") != NULL &&
         strstr(text, "KVM runner record") != NULL && strstr(text, "KVM runner mailbox") != NULL);
  assert(fclose(capture) == 0);
}

int main(void) {
  rejection_and_diagnostic_contract();
  DazeKvmNormalTransitionConfig config;
  DazeKvmNormalTransitionConfigInput input = normal_input();
  if (!daze_kvm_normal_transition_config_build(&input, &config, NULL)) {
    fprintf(stderr, "normal configuration did not build\n");
    return 1;
  }
  const DazeDpmiTransitionDescriptorAddition *compat =
    find_addition(&config, DAZE_DPMI_TRANSITION_GDT, 0x0038);
  const DazeDpmiTransitionDescriptorAddition *code =
    find_addition(&config, DAZE_DPMI_TRANSITION_GDT, 0x0050);
  const DazeDpmiTransitionDescriptorAddition *data =
    find_addition(&config, DAZE_DPMI_TRANSITION_GDT, 0x0058);
  const DazeDpmiTransitionDescriptorAddition *alias =
    find_addition(&config, DAZE_DPMI_TRANSITION_GDT, 0x0060);
  const DazeDpmiTransitionDescriptorAddition *dynamic =
    find_addition(&config, DAZE_DPMI_TRANSITION_GDT, 0x1078);
  const DazeDpmiTransitionDescriptorAddition *dynamic_ldt_data =
    find_addition(&config, DAZE_DPMI_TRANSITION_LDT, 0x1010);
  if (config.addition_count != 12 || !inventory_unique(&config) || compat == NULL ||
      compat->base != 0x0500 || compat->limit != 7 || compat->access != 0x92 || code == NULL ||
      data == NULL || code->access != 0x9a || data->access != 0x92 || code->flags != 0x0c ||
      data->flags != 0x0c || dynamic == NULL || dynamic->base != 0x107f0 ||
      dynamic_ldt_data == NULL || dynamic_ldt_data->base != 0x10100 ||
      dynamic_ldt_data->access != 0xf2 || config.transition_layout.additions != config.additions ||
      config.transition_layout.protected_gate != &config.protected_gate ||
      config.transition_layout.state_save_gate != &config.state_save_gate ||
      config.transition_layout.raw_switch_gate != &config.raw_switch_gate ||
      config.transition_layout.gdt_address != 0xff0000 ||
      config.transition_layout.ldt_address != 0xfe0000 ||
      config.transition_layout.idt_address != 0xfdf800 ||
      config.transition_layout.idt_limit != 0x07ff ||
      config.protected_gate.handler_address != 0xfde800 ||
      config.protected_gate.dos_handler_address != 0xfde900 ||
      config.protected_gate.default_dos_stub_address != 0xfde9c8 ||
      config.protected_gate.record_address != 0xfdea00 ||
      config.protected_gate.mailbox_address != 0xfdea40 ||
      config.state_save_gate.handler_address != 0xfdea80 ||
      config.raw_switch_gate.handler_address != 0xfdeaa0 ||
      config.raw_switch_gate.real_handler_address != 0x2300 ||
      config.transition_layout.raw_switch_linear != 0x2120 ||
      config.transition_layout.linear_min_address != k_dpmi_linear_min_address ||
      config.transition_layout.linear_limit != 0xfd0000 ||
      config.protected_gate.legacy_np_capture_address != 0xfdec00 ||
      config.transition_layout.state_save_endpoints.state_buffer_size !=
        DAZE_DPMI_ALTERNATE_STATE_SIZE ||
      config.transition_layout.state_save_endpoints.rm_segment != 0x0200 ||
      config.transition_layout.state_save_endpoints.pm_selector != 0x0028 ||
      config.transition_layout.raw_switch_endpoints.rm_segment != 0x0200 ||
      config.transition_layout.raw_switch_endpoints.pm_selector != 0x0028) {
    fprintf(stderr, "normal configuration differs from accepted layout\n");
    return 1;
  }
  /* The alias code selector must map the explicit gate base as 32-bit DPL-0
   * code, keep the flat 0050h entrypoints untouched, and be published with the
   * gate-relative stub offset rather than the stub's absolute linear. */
  if (alias == NULL || alias->base != 0xfde800 || alias->limit != 0xffff || alias->access != 0x9a ||
      alias->flags != 0x0c || code->base != 0 || data->base != 0 ||
      config.transition_layout.default_vector_alias_selector != 0x0060 ||
      config.transition_layout.default_vector_alias_offset != 0x000001c8 ||
      config.protected_gate.default_dos_stub_address !=
        alias->base + config.transition_layout.default_vector_alias_offset ||
      config.protected_gate.handler_selector != 0x0050) {
    fprintf(stderr, "gate-base alias selector differs from contract\n");
    return 1;
  }

  DazeKvmNormalTransitionConfig unchanged;
  memset(&unchanged, 0xa5, sizeof(unchanged));
  DazeKvmNormalTransitionConfig before = unchanged;
  DazeKvmNormalTransitionConfigInput invalid = normal_input();
  invalid.resident_image_end = 0xfde900;
  if (daze_kvm_normal_transition_config_build(&invalid, &unchanged, NULL) ||
      memcmp(&unchanged, &before, sizeof(unchanged)) != 0) {
    fprintf(stderr, "image/gate collision was accepted or changed output\n");
    return 1;
  }
  invalid = normal_input();
  invalid.handoff_ds = 0x0050;
  if (daze_kvm_normal_transition_config_build(&invalid, &unchanged, NULL)) {
    fprintf(stderr, "dynamic host-selector collision was accepted\n");
    return 1;
  }
  invalid = normal_input();
  invalid.handoff_ds = 0x0060;
  if (daze_kvm_normal_transition_config_build(&invalid, &unchanged, NULL)) {
    fprintf(stderr, "gate-alias selector collision was accepted\n");
    return 1;
  }
  invalid = normal_input();
  invalid.guest_size = k_memory_size - 1;
  if (daze_kvm_normal_transition_config_build(&invalid, &unchanged, NULL)) {
    fprintf(stderr, "non-normal process placement was accepted\n");
    return 1;
  }
  invalid = normal_input();
  invalid.reserved_ranges = &(DazeKvmGuestRange){0xfde800, 0x420};
  invalid.reserved_range_count = 1;
  if (daze_kvm_normal_transition_config_build(&invalid, &unchanged, NULL)) {
    fprintf(stderr, "runner-reserved gate collision was accepted\n");
    return 1;
  }
  /* Failures name their kind and ranges for the DPMI-transition diagnostic:
   * image/gate overlap, selector collision, and reserved collision. */
  DazeKvmNormalTransitionConfigFailure failure = {
    DAZE_KVM_NORMAL_TRANSITION_CONFIG_VALID, {0, 0}, {0, 0}};
  invalid = normal_input();
  invalid.resident_image_end = 0xfde900;
  if (daze_kvm_normal_transition_config_build(&invalid, &unchanged, &failure) != 0 ||
      failure.kind != DAZE_KVM_NORMAL_TRANSITION_CONFIG_RANGE_OVERLAP ||
      failure.first.address != 0xfde800 || failure.second.address != 0x10000) {
    fprintf(stderr, "image/gate overlap misreported\n");
    return 1;
  }
  invalid = normal_input();
  invalid.handoff_ds = 0x0050;
  if (daze_kvm_normal_transition_config_build(&invalid, &unchanged, &failure) != 0 ||
      failure.kind != DAZE_KVM_NORMAL_TRANSITION_CONFIG_BAD_INPUT) {
    fprintf(stderr, "selector collision misreported\n");
    return 1;
  }
  return 0;
}
