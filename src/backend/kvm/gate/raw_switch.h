#ifndef DAZE_KVM_RAW_SWITCH_GATE_H
#define DAZE_KVM_RAW_SWITCH_GATE_H

#include "entry.h"
#include "alternate_state.h"
#include "interrupt_vector.h"

#include <stdint.h>

enum {
  DAZE_KVM_RAW_SWITCH_GATE_OK = 0,
  DAZE_KVM_RAW_SWITCH_GATE_INVALID = 1,
  DAZE_KVM_RAW_SWITCH_GATE_FAILED = 2,
  DAZE_KVM_RAW_SWITCH_GATE_HANDLER_SIZE = 6,
  DAZE_KVM_RAW_SWITCH_GATE_VECTOR = DAZE_INT_RAW_SWITCH_GATE,
  DAZE_KVM_RAW_SWITCH_GATE_MARKER = 0x18,
};

/* The caller supplies the IDT and flat handler placement. The bridge has no
 * endpoint-address policy; it transfers the guest's live protected-to-real
 * raw-switch request after preserving AX across its PIO marker. */
typedef struct {
  uint32_t idt_address, handler_address, real_handler_address;
  uint16_t idt_limit, handler_selector;
} DazeKvmRawSwitchGateLayout;

typedef struct {
  uint8_t handler[DAZE_KVM_RAW_SWITCH_GATE_HANDLER_SIZE];
  uint8_t ivt_entry[4];
  uint8_t idt_entry[8];
} DazeKvmRawSwitchGateArtifacts;

typedef struct {
  uint16_t ax, bx, cx, dx, si, di, bp, flags;
} DazeKvmRawSwitchRequest;

typedef struct {
  DazeKvmDpmiEntryResult boundary;
  DazeKvmRawSwitchRequest request;
  DpmiAlternateState real_mode_state;
  int real_mode_state_valid;
} DazeKvmRawSwitchGateResult;

typedef struct {
  uint32_t wrapper_address, state_address, protected_code_base, gdt_address, ldt_address;
  uint16_t wrapper_selector, gdt_limit, ldt_limit;
} DazeKvmRawSwitchReturnLayout;

int daze_kvm_raw_switch_gate_build(const DazeKvmRawSwitchGateLayout *layout,
                                   DazeKvmRawSwitchGateArtifacts *output);
/* Consume a raw marker which a caller has already observed during its one
 * bounded continuation. This avoids discarding that PIO exit by running again. */
int daze_kvm_raw_switch_gate_run_from_boundary(DazeKvmMachine *machine,
                                               const DazeKvmRawSwitchGateLayout *layout,
                                               const DazeKvmDpmiEntryResult *boundary,
                                               DazeKvmRawSwitchGateResult *result);
int daze_kvm_raw_switch_gate_return_to_protected(DazeKvmMachine *machine,
                                                 const DazeKvmRawSwitchGateLayout *gate,
                                                 const DazeKvmRawSwitchReturnLayout *layout,
                                                 const DazeKvmRawSwitchRequest *request);

#endif
