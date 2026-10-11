#include "transition_artifacts.h"

#include <stdio.h>
#include <string.h>

int main(void) {
  DazeDpmiTransitionArtifacts output;
  memset(&output, 0xa5, sizeof(output));
  const DazeDpmiTransitionArtifacts before = output;
  if (daze_dpmi_transition_artifacts_build(NULL, &output) != 0 ||
      memcmp(&output, &before, sizeof(output)) != 0)
    return 1;
  const DazeDpmiTransitionDescriptorAddition additions[] = {
    {DAZE_DPMI_TRANSITION_GDT, 0x0048, 0x12345000, 0xabcd, 0x92, 0x04},
    {DAZE_DPMI_TRANSITION_GDT, 0x0700, 0x00007000, 0xffff, 0x92, 0x00},
    {DAZE_DPMI_TRANSITION_LDT, 0x0018, 0x00000000, 0xffff, 0xf2, 0x00},
  };
  const DazeDpmiTransitionArtifactInput input = {
    .client_ds = 0x1234,
    .client_ss = 0x4321,
    .return_ip = 0x4567,
    .return_cs = 0x2345,
    .psp_segment = 0x0ff0,
    .entry_segment = 0x0200,
    .gdt_address = 0x7f0000,
    .ldt_address = 0x7e0000,
    .idt_address = 0x7d0000,
    .idt_limit = 0x07ff,
    .additions = additions,
    .addition_count = sizeof(additions) / sizeof(additions[0]),
  };
  if (!daze_dpmi_transition_artifacts_build(&input, &output) || output.gdt[8 + 2] != 0x50 ||
      output.gdt[16 + 2] != 0x40 || output.gdt[16 + 6] != 0x00 || output.gdt[0x40 + 2] != 0x10 ||
      output.gdt[0x40 + 3] != 0x32 || output.gdt[0x48 + 2] != 0x00 ||
      output.gdt[0x48 + 3] != 0x50 || output.gdt[0x700 + 0] != 0xff ||
      output.gdt[0x700 + 1] != 0xff || output.gdt[0x700 + 2] != 0x00 ||
      output.gdt[0x700 + 3] != 0x70 || output.gdt[0x700 + 5] != 0x92 ||
      output.ldt[0x18 + 5] != 0xf2 || output.idtr[0] != 0xff || output.idtr[2] != 0x00 ||
      output.idtr[4] != 0x7d || output.trampoline[0x20 + 15] != 0x40 ||
      output.trampoline[0x20 + 16] != 0x00 || output.trampoline[0x20 + 19] != 0x2e ||
      output.trampoline[0x20 + 20] != 0x67 || output.trampoline[0x20 + 21] != 0x0f ||
      output.trampoline[0x20 + 22] != 0x01 || output.trampoline[0x20 + 23] != 0x1e ||
      output.trampoline[0x20 + 24] != 0x86 || output.trampoline[0x20 + 25] != 0x00 ||
      output.state_stub[0] != 0xcd || output.state_stub[1] != 0xfb ||
      output.state_stub[2] != 0x66 || output.state_stub[3] != 0xcb ||
      output.raw_switch_stub[2] != 0xf4)
    return 1;
  DazeDpmiTransitionArtifactInput invalid = input;
  invalid.additions =
    &(DazeDpmiTransitionDescriptorAddition){DAZE_DPMI_TRANSITION_GDT, 3, 0, 0, 0, 0};
  invalid.addition_count = 1;
  const DazeDpmiTransitionArtifacts built = output;
  if (daze_dpmi_transition_artifacts_build(&invalid, &output) != 0 ||
      memcmp(&output, &built, sizeof(output)) != 0)
    return 1;
  DazeDpmiTransitionArtifactInput environment = input;
  environment.psp_segment = 0x2494;
  environment.environment_segment = 0x1623;
  environment.convert_environment = 1;
  if (!daze_dpmi_transition_artifacts_build(&environment, &output) ||
      output.gdt[0x18 + 2] != 0x40 || output.gdt[0x18 + 3] != 0x49 ||
      output.gdt[0x18 + 4] != 0x02 ||
      output.gdt[DAZE_DPMI_TRANSITION_ENVIRONMENT_SELECTOR + 2] != 0x30 ||
      output.gdt[DAZE_DPMI_TRANSITION_ENVIRONMENT_SELECTOR + 3] != 0x62 ||
      output.gdt[DAZE_DPMI_TRANSITION_ENVIRONMENT_SELECTOR + 4] != 0x01 ||
      output.gdt[DAZE_DPMI_TRANSITION_ENVIRONMENT_SELECTOR + 5] != 0x92 ||
      output.environment_pointer[0] != DAZE_DPMI_TRANSITION_ENVIRONMENT_SELECTOR ||
      output.environment_pointer[1] != 0)
    return 1;
  environment.environment_segment = 0;
  if (!daze_dpmi_transition_artifacts_build(&environment, &output) ||
      output.environment_pointer[0] != 0 || output.environment_pointer[1] != 0 ||
      output.gdt[DAZE_DPMI_TRANSITION_ENVIRONMENT_SELECTOR + 5] != 0)
    return 1;
  environment.additions = &(DazeDpmiTransitionDescriptorAddition){
    DAZE_DPMI_TRANSITION_GDT, DAZE_DPMI_TRANSITION_ENVIRONMENT_SELECTOR, 0x1234, 0xffff, 0x92, 0};
  environment.addition_count = 1;
  const DazeDpmiTransitionArtifacts absent_environment = output;
  if (daze_dpmi_transition_artifacts_build(&environment, &output) ||
      memcmp(&output, &absent_environment, sizeof(output)) != 0)
    return 1;
  puts("DPMI transition artifacts: passed");
  return 0;
}
