#ifndef DAZE_KVM_STATE_SAVE_GATE_H
#define DAZE_KVM_STATE_SAVE_GATE_H

#include "alternate_state.h"
#include "entry.h"
#include "interrupt_vector.h"

#include <stddef.h>
#include <stdint.h>

enum {
  DAZE_KVM_STATE_SAVE_GATE_OK = 0,
  DAZE_KVM_STATE_SAVE_GATE_INVALID = 1,
  DAZE_KVM_STATE_SAVE_GATE_FAILED = 2,
  DAZE_KVM_STATE_SAVE_GATE_HANDLER_SIZE = 7,
  DAZE_KVM_STATE_SAVE_GATE_VECTOR = DAZE_INT_STATE_SAVE_GATE,
  DAZE_KVM_STATE_SAVE_GATE_MARKER = 0x17,
};

/* The endpoint address and handler selector are caller-owned transition
 * facts. This bridge answers only operation zero of the DPMI 0305h procedure
 * and copies the existing alternate-state wire image to ES:EDI. */
typedef struct {
  uint32_t idt_address, handler_address;
  uint16_t idt_limit, handler_selector;
} DazeKvmStateSaveGateLayout;

typedef struct {
  uint8_t handler[DAZE_KVM_STATE_SAVE_GATE_HANDLER_SIZE];
  uint8_t idt_entry[8];
} DazeKvmStateSaveGateArtifacts;

typedef struct {
  DazeKvmDpmiEntryResult boundary;
  uint16_t operation;
  uint32_t buffer_address;
  int caller_frame_widened;
} DazeKvmStateSaveGateResult;

int daze_kvm_state_save_gate_build(const DazeKvmStateSaveGateLayout *layout,
                                   DazeKvmStateSaveGateArtifacts *output);
int daze_kvm_state_save_gate_run(DazeKvmMachine *machine, const DazeKvmStateSaveGateLayout *layout,
                                 const DpmiAlternateState *state,
                                 const DazeKvmDpmiEntryResult *boundary,
                                 DazeKvmStateSaveGateResult *result);

/* The protected state stub returns with operand-size RETF.  When a 16-bit
 * client called it through a narrow far frame, widen that live caller frame
 * before the gate resumes.  The operation-one path records alternate state;
 * it deliberately does not load that record into the vCPU. */
int daze_kvm_state_save_gate_widen_caller_frame(DazeKvmMachine *machine,
                                                const DazeKvmDpmiEntryResult *boundary);


#endif
