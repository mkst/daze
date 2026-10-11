#ifndef DAZE_KVM_DPMI_ENTRY_H
#define DAZE_KVM_DPMI_ENTRY_H

#include "dpmi_function.h"
#include "interrupt_vector.h"
#include "kvm_guest_write.h"
#include "machine.h"
#include "runner_request_common.h"

#include <stddef.h>
#include <stdint.h>

enum {
  DAZE_KVM_DPMI_ENTRY_OK = 0,
  DAZE_KVM_DPMI_ENTRY_FAILED = 1,
  DAZE_KVM_DPMI_ENTRY_INVALID = 2,
  DAZE_KVM_DPMI_ENTRY_UNAVAILABLE = 77,
};

typedef struct {
  const DazeKvmGuestWrite *writes;
  size_t write_count;
  uint32_t mailbox_address;
  uint32_t terminal_linear;
} DazeKvmDpmiEntryLayout;

/* Captures one KVM_RUN exit. clear_error records cleanup failure separately
 * from the primary exit/run error; an observation does not authorize recovery. */
typedef enum {
  DAZE_KVM_DPMI_ENTRY_EXIT_NONE,
  DAZE_KVM_DPMI_ENTRY_EXIT_MATCHING_DEBUG,
  DAZE_KVM_DPMI_ENTRY_EXIT_UNEXPECTED_DEBUG,
  DAZE_KVM_DPMI_ENTRY_EXIT_UNEXPECTED_PIO,
  DAZE_KVM_DPMI_ENTRY_EXIT_UNEXPECTED_HLT,
  DAZE_KVM_DPMI_ENTRY_EXIT_UNEXPECTED_FAIL_ENTRY,
  DAZE_KVM_DPMI_ENTRY_EXIT_UNEXPECTED_OTHER,
  DAZE_KVM_DPMI_ENTRY_EXIT_RUN_FAILED,
  DAZE_KVM_DPMI_ENTRY_EXIT_CAPTURE_FAILED,
  DAZE_KVM_DPMI_ENTRY_EXIT_DEBUG,
  DAZE_KVM_DPMI_ENTRY_EXIT_PIO,
  DAZE_KVM_DPMI_ENTRY_EXIT_HLT,
  DAZE_KVM_DPMI_ENTRY_EXIT_FAIL_ENTRY,
  DAZE_KVM_DPMI_ENTRY_EXIT_OTHER,
} DazeKvmDpmiEntryExitKind;

typedef enum {
  DAZE_KVM_DPMI_ENTRY_PIO_NONE,
  DAZE_KVM_DPMI_ENTRY_PIO_IN,
  DAZE_KVM_DPMI_ENTRY_PIO_OUT,
} DazeKvmDpmiEntryPioDirection;

typedef struct {
  DazeKvmDpmiEntryExitKind kind;
  uint32_t raw_exit_reason;
  int run_error, clear_error;
  uint16_t pio_port;
  uint8_t pio_direction, pio_size;
  uint32_t pio_count, pio_value;
  uint32_t internal_suberror;
  int pio_value_present;
  uint64_t fail_entry_reason;
} DazeKvmDpmiEntryObservation;

typedef struct {
  uint32_t cr0, cr4, rip, rflags, cs_base, ss_base, ds_base, es_base, fs_base, gs_base, esp,
    gdt_base, idt_base, ldt_base, tr_base;
  uint64_t efer;
  uint16_t gdt_limit, idt_limit, ldt_limit, tr_limit;
  uint32_t ss_limit;
  uint16_t cs, ss, sp, ax, bx, cx, dx, si, di, ds, es, fs, gs;
  uint16_t ldt, tr;
  uint8_t cs_db, ss_db, ss_type, ss_present, ldt_type, tr_type, ldt_present, tr_present;
  uint8_t instruction[8];
  size_t instruction_size;
  DazeKvmDpmiEntryObservation observation;
} DazeKvmDpmiEntryResult;

int daze_kvm_dpmi_entry_run(DazeKvmMachine *machine, const DazeKvmRunnerDpmiHandoff *handoff,
                            const DazeKvmDpmiEntryLayout *layout, DazeKvmDpmiEntryResult *result);

/* Continue a parked vCPU for one KVM_RUN and capture its boundary state.
 * Callers supply any required guest writes/replies before continuing. */
int daze_kvm_dpmi_entry_continue_once(DazeKvmMachine *machine, DazeKvmDpmiEntryResult *result);

/* Omits CPU-state capture for ordinary mediator PIO. Other exits carry the
 * same full boundary state as continue_once; inspect the exit before using fields. */
int daze_kvm_dpmi_entry_continue_mediator_or_capture(DazeKvmMachine *machine,
                                                     DazeKvmDpmiEntryResult *result);

/* One KVM_RUN with exit observation only. Register/segment fields remain
 * unfilled until capture_state is called while parked at that same boundary. */
int daze_kvm_dpmi_entry_continue_observe(DazeKvmMachine *machine, DazeKvmDpmiEntryResult *result);

/* Requires the vCPU still parked at the observed boundary. Fills CPU state
 * without changing the exit observation. */
int daze_kvm_dpmi_entry_capture_state(DazeKvmMachine *machine, DazeKvmDpmiEntryResult *result);

/* One KVM_RUN with a hardware breakpoint at the supplied linear address.
 * A nonmatching exit fails; the caller owns guest writes and service replies. */
int daze_kvm_dpmi_entry_continue_to_linear(DazeKvmMachine *machine, uint32_t linear,
                                           DazeKvmDpmiEntryResult *result);

/* Requires a parked mediator OUT f4h (one-byte OUT with the expected marker).
 * Derives its successor from cs_base/rip and runs once to retire deferred I/O
 * before an RM detour. Returns the post-PIO boundary only on a matching stop;
 * unexpected exits fail without further continuation or a fabricated reply. */
int daze_kvm_dpmi_entry_retire_mediator_out(DazeKvmMachine *machine, uint32_t cs_base, uint32_t rip,
                                            DazeKvmDpmiEntryResult *result);

/* Software retirement advances only RIP by two and executes no guest code. No boundary
 * state is captured on success. */
int daze_kvm_dpmi_entry_retire_mediator_out_observe(DazeKvmMachine *machine, uint32_t cs_base,
                                                    uint32_t rip, DazeKvmDpmiEntryResult *result);

/* DAZE_KVM_FAIL_ENTRY_TRACE=1 enables at most one terminal record per process:
 * exit reason, optional entry-failure reason, and bounded guest state. Reads
 * the parked guest without resuming, re-arming, or changing its state. */
enum {
  DAZE_KVM_FAIL_ENTRY_TRACE_WORDS = 8,
  DAZE_KVM_FAIL_ENTRY_TRACE_EXCEPTION_VECTOR = DAZE_INT_GP_FAULT,
  DAZE_KVM_FAIL_ENTRY_TRACE_IDT_GATE_BYTES = 8,
  DAZE_KVM_FAIL_ENTRY_TRACE_HANDLER_INDEX = 0x01,
  DAZE_KVM_FAIL_ENTRY_TRACE_CODE_INDEX = 0x16,
  DAZE_KVM_FAIL_ENTRY_TRACE_TARGET_INDEX = 0x1a,
};

/* One segment as KVM reports it: the packed type carries the present bit in
 * bit 15 and the descriptor type in bits 0-3. */
typedef struct {
  uint16_t selector;
  uint32_t base, limit;
  uint16_t type;
  uint8_t db;
} DazeKvmFailEntryTraceSegment;

typedef struct {
  uint32_t raw_exit_reason;
  uint64_t hardware_entry_failure_reason;
  int hardware_entry_failure_reason_present;
  uint64_t cr0, cr4, efer, rflags, rip, rsp;
  DazeKvmFailEntryTraceSegment cs, ds, es, ss;
  uint32_t gdt_base, idt_base;
  uint16_t gdt_limit, idt_limit;
  DazeKvmFailEntryTraceSegment ldt, tr;
  uint32_t stack_linear;
  int stack_linear_valid;
  uint16_t stack_words[DAZE_KVM_FAIL_ENTRY_TRACE_WORDS];
  uint32_t stack_word_count;
  uint8_t exception_gate[DAZE_KVM_FAIL_ENTRY_TRACE_IDT_GATE_BYTES];
  int exception_gate_valid;
  uint8_t instruction_bytes[16];
  uint32_t instruction_count;
  uint8_t context_bytes[0x40];
  uint32_t context_count;
  uint8_t handler_descriptor[DAZE_KVM_FAIL_ENTRY_TRACE_IDT_GATE_BYTES];
  int handler_descriptor_valid;
  uint8_t code_descriptor[DAZE_KVM_FAIL_ENTRY_TRACE_IDT_GATE_BYTES];
  int code_descriptor_valid;
  uint8_t target_descriptor[DAZE_KVM_FAIL_ENTRY_TRACE_IDT_GATE_BYTES];
  int target_descriptor_valid;
  uint8_t handler_code[16];
  uint32_t handler_code_count;
  int handler_code_valid;
} DazeKvmFailEntryTrace;

int daze_kvm_dpmi_entry_fail_entry_trace_enabled(void);

const char *daze_kvm_dpmi_entry_fail_entry_trace_exit_name(uint32_t raw_exit_reason);

/* Adds bounded guest-memory context to caller-filled KVM state, including
 * stack words at SS:RSP. Preserves the supplied register/descriptor fields. */
void daze_kvm_dpmi_entry_fail_entry_trace_capture(DazeKvmFailEntryTrace *trace,
                                                  const uint8_t *guest, size_t guest_size);

void daze_kvm_dpmi_entry_fail_entry_trace_report(const DazeKvmFailEntryTrace *trace);

#endif
