#define _POSIX_C_SOURCE 200809L
#include "plan.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#define CHECK(condition)                                                                           \
  do {                                                                                             \
    if (!(condition)) {                                                                            \
      fprintf(stderr, "plan boundary failed at %d\n", __LINE__);                                   \
      abort();                                                                                     \
    }                                                                                              \
  } while (0)

static DazeKvmTransitionPlanInput valid_input(void) {
  static const DazeDpmiTransitionDescriptorAddition additions[] = {
    {DAZE_DPMI_TRANSITION_GDT, 0x0040, 0x12345000, 0xabcd, 0x92, 0x04},
    {DAZE_DPMI_TRANSITION_LDT, 0x0018, 0, 0xffff, 0xf2, 0},
  };
  /* The real 8 MiB runner placements (gate arena, record, mailbox), borrowed
   * for validation. Hardcoded on purpose, with the computation cited:
   * runner_reserved_ranges() in runner/runner.c. A runner placement change
   * must fail this test loudly, not drift past it. */
  static const DazeKvmTransitionReservedRange runner[] = {
    {0xa0000, 256 * 180}, {0x9f000, 24}, {0x9f020, 16}};
  return (DazeKvmTransitionPlanInput){
    .guest_size = 0x800000,
    .resident_image_end = 0x14000,
    .client_ds = 0x1010,
    .client_ss = 0x1010,
    .return_ip = 0x0040,
    .return_cs = 0x0ff0,
    .psp_segment = 0x0ff0,
    .environment_segment = 0x1623,
    .convert_environment = 1,
    .entry_segment = 0x2200,
    .gdt_address = 0x7f0000,
    .ldt_address = 0x7e0000,
    .idt_address = 0x7d0000,
    .idt_limit = 0x07ff,
    .linear_min_address = 0x50000,
    .linear_limit = 0x7e0000,
    .additions = additions,
    .addition_count = sizeof(additions) / sizeof(additions[0]),
    .reserved_ranges = runner,
    .reserved_range_count = sizeof(runner) / sizeof(runner[0]),
  };
}

static int rejected_unchanged(const DazeKvmTransitionPlanInput *input) {
  DazeKvmTransitionPlan output;
  memset(&output, 0xa5, sizeof(output));
  const DazeKvmTransitionPlan before = output;
  return daze_kvm_transition_plan_build(input, &output, NULL) == 0 &&
         memcmp(&output, &before, sizeof(output)) == 0;
}

static int check_kind(const DazeKvmTransitionPlanInput *input,
                      DazeKvmTransitionPlanFailureKind kind, const char *message) {
  DazeKvmTransitionPlan output;
  DazeKvmTransitionPlanFailure failure = {DAZE_KVM_TRANSITION_PLAN_VALID, {0, 0}, {0, 0}};
  if (daze_kvm_transition_plan_build(input, &output, &failure) != 0 || failure.kind != kind) {
    fprintf(stderr, "transition plan failure misreported: %s\n", message);
    return 0;
  }
  return 1;
}

static void boundary_contract(void) {
  DazeKvmTransitionPlan output;
  DazeKvmTransitionPlanFailure failure;
  DazeKvmTransitionPlanInput input = valid_input();
  CHECK(!daze_kvm_transition_plan_build(NULL, &output, &failure));
  CHECK(failure.kind == DAZE_KVM_TRANSITION_PLAN_BAD_INPUT);
  CHECK(!daze_kvm_transition_plan_build(&input, NULL, &failure));
  for (int kind = 0; kind < 8; ++kind) {
    input = valid_input();
    switch (kind) {
    case 0:
      input.guest_size = 0;
      break;
    case 1:
      input.resident_image_end = input.guest_size + 1;
      break;
    case 2:
      input.linear_limit = input.guest_size + 1;
      break;
    case 3:
      input.linear_min_address = input.linear_limit + 1;
      break;
    case 4:
      input.idt_address = 0;
      break;
    case 5:
      input.reserved_range_count = DAZE_KVM_TRANSITION_PLAN_MAX_RESERVED_RANGES + 1;
      break;
    case 6:
      input.reserved_ranges = NULL;
      break;
    case 7:
      input.idt_limit = 0x18e;
      break;
    }
    CHECK(rejected_unchanged(&input));
    CHECK(check_kind(&input, DAZE_KVM_TRANSITION_PLAN_BAD_INPUT, "input bounds"));
  }
  input = valid_input();
  DazeKvmTransitionReservedRange outside = {input.guest_size - 1, 2};
  input.reserved_ranges = &outside;
  input.reserved_range_count = 1;
  CHECK(rejected_unchanged(&input));
  CHECK(!daze_kvm_transition_plan_build(&input, &output, &failure));
  CHECK(failure.kind == DAZE_KVM_TRANSITION_PLAN_RESERVED_OUT_OF_GUEST);
  CHECK(failure.first.address == outside.address && failure.first.size == outside.size);
  CHECK(failure.second.address == 0 && failure.second.size == 0);
  input = valid_input();
  input.convert_environment = 0;
  input.reserved_ranges = NULL;
  input.reserved_range_count = 0;
  CHECK(daze_kvm_transition_plan_build(&input, &output, NULL));
  CHECK(output.write_count == 7 && output.reserved_range_count == 0);

  input = valid_input();
  CHECK(daze_kvm_transition_plan_build(&input, &output, NULL));
  FILE *capture = tmpfile();
  CHECK(capture != NULL);
  fflush(stderr);
  int saved = dup(STDERR_FILENO);
  CHECK(saved >= 0 && dup2(fileno(capture), STDERR_FILENO) >= 0);
  daze_kvm_transition_plan_report(NULL, &failure);
  daze_kvm_transition_plan_report(&input, NULL);
  for (size_t i = 0; i < 7; ++i) {
    failure = (DazeKvmTransitionPlanFailure){DAZE_KVM_TRANSITION_PLAN_WRITE_OUT_OF_GUEST,
                                             {output.writes[i].address, output.writes[i].size},
                                             {0, 0}};
    daze_kvm_transition_plan_report(&input, &failure);
    failure.first.size++;
    daze_kvm_transition_plan_report(&input, &failure);
  }
  for (size_t i = 0; i < 3; ++i) {
    failure = (DazeKvmTransitionPlanFailure){DAZE_KVM_TRANSITION_PLAN_RESERVED_COLLISION,
                                             {input.gdt_address, DAZE_DPMI_TRANSITION_GDT_SIZE},
                                             input.reserved_ranges[i]};
    daze_kvm_transition_plan_report(&input, &failure);
  }
  failure.kind = DAZE_KVM_TRANSITION_PLAN_WRITE_OVERLAP;
  daze_kvm_transition_plan_report(&input, &failure);
  failure.kind = DAZE_KVM_TRANSITION_PLAN_RESERVED_OUT_OF_GUEST;
  daze_kvm_transition_plan_report(&input, &failure);
  failure.kind = DAZE_KVM_TRANSITION_PLAN_NO_LINEAR_ARENA;
  daze_kvm_transition_plan_report(&input, &failure);
  failure.kind = DAZE_KVM_TRANSITION_PLAN_BAD_INPUT;
  input.reserved_ranges = NULL;
  daze_kvm_transition_plan_report(&input, &failure);
  fflush(stderr);
  CHECK(dup2(saved, STDERR_FILENO) >= 0);
  close(saved);
  rewind(capture);
  char text[8192] = {0};
  CHECK(fread(text, 1, sizeof(text) - 1, capture) > 0);
  fclose(capture);
  const char *names[] = {"DPMI GDT",
                         "DPMI LDT",
                         "DPMI entry trampoline",
                         "DPMI GDTR",
                         "DPMI IDTR",
                         "DPMI state stub",
                         "DPMI raw-switch stub",
                         "KVM runner gate arena",
                         "KVM runner record",
                         "KVM runner mailbox",
                         "transition range",
                         "overlaps",
                         "does not fit the 00800000-byte guest",
                         "no linear arena",
                         "internal error"};
  for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i)
    CHECK(strstr(text, names[i]) != NULL);
}

int main(void) {
  boundary_contract();
  DazeKvmTransitionPlanInput input = valid_input();
  DazeKvmTransitionPlan output;
  DazeKvmTransitionPlanFailure failure = {DAZE_KVM_TRANSITION_PLAN_VALID, {0, 0}, {0, 0}};
  if (!daze_kvm_transition_plan_build(&input, &output, &failure) ||
      failure.kind != DAZE_KVM_TRANSITION_PLAN_VALID) {
    fprintf(stderr, "valid transition plan rejected\n");
    return 1;
  }
  const uint32_t trampoline = (uint32_t)input.entry_segment << 4;
  const int valid =
    output.trampoline_address == trampoline &&
    output.resident_image_end == input.resident_image_end &&
    output.linear_min_address == input.linear_min_address &&
    output.linear_limit == input.linear_limit &&
    output.write_count == DAZE_KVM_TRANSITION_PLAN_WRITE_COUNT &&
    output.reserved_range_count == 3 && output.writes[0].address == input.gdt_address &&
    output.writes[0].size == DAZE_DPMI_TRANSITION_GDT_SIZE &&
    output.writes[0].bytes == output.artifacts.gdt &&
    output.writes[1].address == input.ldt_address &&
    output.writes[1].size == DAZE_DPMI_TRANSITION_LDT_SIZE &&
    output.writes[1].bytes == output.artifacts.ldt && output.writes[2].address == trampoline &&
    output.writes[2].bytes == output.artifacts.trampoline &&
    output.writes[3].address == trampoline + DAZE_KVM_TRANSITION_PLAN_GDTR_OFFSET &&
    output.writes[3].bytes == output.artifacts.gdtr &&
    output.writes[4].address == trampoline + DAZE_KVM_TRANSITION_PLAN_IDTR_OFFSET &&
    output.writes[4].bytes == output.artifacts.idtr &&
    output.writes[5].address == trampoline + DAZE_KVM_TRANSITION_PLAN_STATE_STUB_OFFSET &&
    output.writes[5].bytes == output.artifacts.state_stub &&
    output.writes[6].address == trampoline + DAZE_KVM_TRANSITION_PLAN_RAW_SWITCH_OFFSET &&
    output.writes[6].bytes == output.artifacts.raw_switch_stub &&
    output.writes[7].address == 0xff2c &&
    output.writes[7].bytes == output.artifacts.environment_pointer && output.writes[7].size == 2 &&
    output.artifacts.environment_pointer[0] == DAZE_DPMI_TRANSITION_ENVIRONMENT_SELECTOR &&
    output.reserved_ranges[0].address == 0xa0000 && output.reserved_ranges[0].size == 256 * 180 &&
    output.reserved_ranges[1].address == 0x9f000 && output.reserved_ranges[1].size == 24 &&
    output.reserved_ranges[2].address == 0x9f020 && output.reserved_ranges[2].size == 16 &&
    output.artifacts.gdt[8 + 5] == 0x9a && output.artifacts.gdt[0x40 + 2] == 0 &&
    output.artifacts.gdt[0x40 + 3] == 0x50 && output.artifacts.ldt[0x18 + 5] == 0xf2 &&
    output.artifacts.trampoline[0] == 0xfa && output.artifacts.gdtr[0] == 0xff &&
    output.artifacts.state_stub[0] == 0xcd && output.artifacts.raw_switch_stub[2] == 0xf4;
  if (!valid) {
    fprintf(stderr, "valid transition plan fields differ\n");
    return 1;
  }

  input = valid_input();
  input.gdt_address = input.ldt_address;
  if (!rejected_unchanged(&input)) return 1;
  input = valid_input();
  input.gdt_address = input.guest_size;
  if (!rejected_unchanged(&input)) return 1;
  input = valid_input();
  input.idt_limit = 0x18e;
  if (!rejected_unchanged(&input)) return 1;
  input = valid_input();
  input.entry_segment = 0xa000;
  if (!rejected_unchanged(&input)) return 1;
  input = valid_input();
  input.entry_segment = 0;
  if (!rejected_unchanged(&input)) return 1;
  input = valid_input();
  input.client_ds = 0;
  if (!rejected_unchanged(&input)) return 1;
  input = valid_input();
  input.linear_min_address = input.linear_limit;
  if (!rejected_unchanged(&input)) return 1;
  input = valid_input();
  input.resident_image_end = 0x7dffff;
  if (!rejected_unchanged(&input)) return 1;
  input = valid_input();
  input.additions =
    &(DazeDpmiTransitionDescriptorAddition){DAZE_DPMI_TRANSITION_GDT, 3, 0, 0, 0, 0};
  input.addition_count = 1;
  if (!rejected_unchanged(&input)) return 1;
  /* Injected reservations are honored, not ignored: a runner range over the
   * GDT rejects the plan, and a dangling range list is invalid input. */
  input = valid_input();
  input.reserved_ranges = &(DazeKvmTransitionReservedRange){input.gdt_address, 0x1000};
  input.reserved_range_count = 1;
  if (!rejected_unchanged(&input)) return 1;
  input = valid_input();
  input.reserved_ranges = NULL;
  if (!rejected_unchanged(&input)) return 1;

  /* Failures name their kind and ranges for the DPMI-transition diagnostic:
   * write/write overlap, write/runner collision, and a missing arena. */
  input = valid_input();
  input.gdt_address = input.ldt_address;
  if (!check_kind(&input, DAZE_KVM_TRANSITION_PLAN_WRITE_OVERLAP, "gdt/ldt overlap")) return 1;
  input = valid_input();
  input.entry_segment = 0xa000;
  if (!check_kind(&input, DAZE_KVM_TRANSITION_PLAN_RESERVED_COLLISION, "trampoline/runner"))
    return 1;
  {
    DazeKvmTransitionPlan probe;
    DazeKvmTransitionPlanFailure probe_failure = {DAZE_KVM_TRANSITION_PLAN_VALID, {0, 0}, {0, 0}};
    daze_kvm_transition_plan_build(&input, &probe, &probe_failure);
    if (probe_failure.first.address != 0xa0000 || probe_failure.second.address != 0xa0000) {
      fprintf(stderr, "trampoline/runner collision misaddressed\n");
      return 1;
    }
  }
  input = valid_input();
  input.resident_image_end = 0x7e0000;
  if (!check_kind(&input, DAZE_KVM_TRANSITION_PLAN_NO_LINEAR_ARENA, "missing arena")) return 1;

  DazeKvmTransitionPlanInput distinct = valid_input();
  distinct.gdt_address = 0x6f0000;
  DazeKvmTransitionPlan second;
  if (!daze_kvm_transition_plan_build(&distinct, &second, NULL) ||
      second.writes[0].address == output.writes[0].address ||
      second.artifacts.gdtr[4] == output.artifacts.gdtr[4]) {
    fprintf(stderr, "distinct transition plan did not differ\n");
    return 1;
  }
  puts("KVM transition plan: passed");
  return 0;
}
