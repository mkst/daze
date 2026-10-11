#ifndef DAZE_DPMI_TRANSITION_ARTIFACTS_H
#define DAZE_DPMI_TRANSITION_ARTIFACTS_H

#include <stddef.h>
#include <stdint.h>

enum {
  DAZE_DPMI_TRANSITION_GDT_SIZE = 65536,
  DAZE_DPMI_TRANSITION_LDT_SIZE = 65536,
  DAZE_DPMI_TRANSITION_TRAMPOLINE_SIZE = 96,
  DAZE_DPMI_TRANSITION_GDT = 0,
  DAZE_DPMI_TRANSITION_LDT = 1,
  DAZE_DPMI_TRANSITION_ENVIRONMENT_SELECTOR = 0x0068,
};

/* Descriptor bases must be explicit; selector numbers do not imply addresses. */
typedef struct {
  uint8_t table;
  uint16_t selector;
  uint32_t base, limit;
  uint8_t access, flags;
} DazeDpmiTransitionDescriptorAddition;

typedef struct {
  uint16_t client_ds, client_ss, return_ip, return_cs;
  uint16_t psp_segment, entry_segment;
  uint16_t environment_segment;
  int convert_environment;
  uint32_t gdt_address, ldt_address, idt_address;
  uint16_t idt_limit;
  const DazeDpmiTransitionDescriptorAddition *additions;
  size_t addition_count;
} DazeDpmiTransitionArtifactInput;

typedef struct {
  uint8_t gdt[DAZE_DPMI_TRANSITION_GDT_SIZE];
  uint8_t ldt[DAZE_DPMI_TRANSITION_LDT_SIZE];
  uint8_t gdtr[6];
  uint8_t idtr[6];
  uint8_t trampoline[DAZE_DPMI_TRANSITION_TRAMPOLINE_SIZE];
  uint8_t state_stub[4];
  uint8_t raw_switch_stub[3];
  uint8_t environment_pointer[2];
} DazeDpmiTransitionArtifacts;

/* Pure construction. On invalid input, output remains unchanged. */
int daze_dpmi_transition_artifacts_build(const DazeDpmiTransitionArtifactInput *input,
                                         DazeDpmiTransitionArtifacts *output);

#endif
