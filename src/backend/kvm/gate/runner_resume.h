#ifndef DAZE_KVM_RUNNER_GATE_RESUME_H
#define DAZE_KVM_RUNNER_GATE_RESUME_H

#include "machine.h"
#include "runner_request_common.h"

#include <stdint.h>

enum {
  DAZE_KVM_RUNNER_GATE_REPLY_SIZE = 16,
  DAZE_KVM_RUNNER_GATE_RESUME_OK = 0,
  DAZE_KVM_RUNNER_GATE_RESUME_FAILED = 1,
  DAZE_KVM_RUNNER_GATE_RESUME_INVALID = 2,
  DAZE_KVM_RUNNER_GATE_RESUME_UNAVAILABLE = 77,
};

typedef struct {
  DazeKvmMachine *machine;
  const DazeKvmRunnerDpmiHandoff *handoff;
  uint32_t mailbox_address;
  uint8_t reply[DAZE_KVM_RUNNER_GATE_REPLY_SIZE];
} DazeKvmRunnerGateResumeInput;

typedef struct {
  uint32_t cr0, rip, rflags;
  uint16_t cs, ss, sp, ax, bx, cx, dx, si, di, ds, es;
} DazeKvmRunnerGateResumeResult;

/* A real-mode gate can save AX on its interrupt stack, emit its vector through
 * a PIO marker, then park.  This is the host-owned representation of that
 * boundary; unlike the legacy runner record it has no guest-memory address. */
typedef struct {
  uint8_t vector;
  uint16_t ax, bx, cx, dx, si, di, ds, es, flags;
  uint16_t return_ip, return_cs;
  uint16_t ss, sp;
} DazeKvmRunnerGateFrame;

/* Capture a parked real-mode gate frame after its vector marker has been
 * observed.  The gate must have pushed AX immediately before the marker. */
int daze_kvm_runner_gate_frame_capture(DazeKvmMachine *machine, uint8_t vector,
                                       DazeKvmRunnerGateFrame *frame);

/* Apply the canonical 16-byte broker reply to a captured frame.  The gate
 * discards its saved AX and IRETs; this helper supplies the reply registers
 * and patches only the interrupt frame's flags word. */
int daze_kvm_runner_gate_frame_reply(DazeKvmMachine *machine, const DazeKvmRunnerGateFrame *frame,
                                     const uint8_t reply[DAZE_KVM_RUNNER_GATE_REPLY_SIZE]);
/* A restored parent snapshot was parked at the runner gate's OUT 0xf4. KVM
 * does not retain that old I/O-exit state across a register restore, so retire
 * the already-serviced instruction by advancing only its validated successor. */
int daze_kvm_runner_gate_frame_retire_out(DazeKvmMachine *machine);
int daze_kvm_runner_gate_frame_set_ds(DazeKvmMachine *machine, uint16_t ds);

int daze_kvm_runner_gate_resume_input_valid(const DazeKvmRunnerGateResumeInput *input);

/* Install one validated reply at an already-parked gate. This deliberately
 * does not run the vCPU: callers that need the next boundary use their own
 * one-run observation and retain its exact exit kind. */
int daze_kvm_runner_gate_reply(const DazeKvmRunnerGateResumeInput *input);

/* Copy one validated reply to a parked runner gate and run exactly once until
 * its guest-owned IRET reaches HLT. The helper borrows the machine and never
 * changes registers, arms debug, or destroys it. */
int daze_kvm_runner_gate_resume_hlt(const DazeKvmRunnerGateResumeInput *input,
                                    DazeKvmRunnerGateResumeResult *result);

#endif
