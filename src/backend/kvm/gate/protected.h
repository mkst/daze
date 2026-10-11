#ifndef DAZE_KVM_PROTECTED_GATE_H
#define DAZE_KVM_PROTECTED_GATE_H

#include "entry.h"
#include "interrupt_vector.h"
#include "mediator.h"

#include <stddef.h>
#include <stdint.h>

enum {
  DAZE_KVM_PROTECTED_GATE_OK = 0,
  DAZE_KVM_PROTECTED_GATE_FAILED = 1,
  DAZE_KVM_PROTECTED_GATE_INVALID = 2,
  DAZE_KVM_PROTECTED_GATE_MEDIATOR_FAILED = 3,
  DAZE_KVM_PROTECTED_GATE_LIMIT_REACHED = 4,
  /* The consumed mediator record is a valid 0301h request. The gate has
   * answered its mailbox and parked the guest for a caller-owned real-mode
   * reflection; the caller resumes the protected gate after completion. */
  DAZE_KVM_PROTECTED_GATE_RM_PROCEDURE = 5,
  DAZE_KVM_PROTECTED_GATE_UNAVAILABLE = 77,
  /* The 16-bit CPU frame needs three MOVZX loads and operand-size prefixes. */
  DAZE_KVM_PROTECTED_GATE_HANDLER_MAX_SIZE = 197,
  /* A client-installed 16-bit vector handler chains here with the processor's
   * six-byte IP:CS:FLAGS frame.  The adapter expands that exact frame for the
   * 32-bit protected DOS gate before jumping to it. */
  DAZE_KVM_PROTECTED_GATE_DEFAULT_DOS_STUB_SIZE = 31,
  DAZE_KVM_PROTECTED_GATE_MAX_EXCHANGES = 512,
  /* The DOS and DPMI gates need distinct markers so the dispatcher can distinguish their
   * requests. */
  DAZE_KVM_PROTECTED_DOS_MARKER = 0x21,
};

typedef struct {
  uint32_t idt_address;
  uint16_t idt_limit;
  uint32_t handler_address;
  uint32_t dos_handler_address;
  uint32_t default_dos_stub_address;
  uint32_t record_address;
  uint32_t mailbox_address;
  uint16_t handler_selector;
  uint16_t handler_data_selector;
  uint8_t interrupt_gate_type;
  uint16_t exchange_limit;
  /* Zero disables it; otherwise the exact caller-selected vector is installed
   * from the shared 0203h result. Its D/B bit selects the matching 86h/8Eh
   * hardware gate width; this value validates the enabled gate family. */
  uint8_t exception_gate_vector;
  uint8_t exception_gate_type;
  uint32_t legacy_np_capture_address;
} DazeKvmProtectedGateLayout;

typedef struct {
  uint8_t handler[DAZE_KVM_PROTECTED_GATE_HANDLER_MAX_SIZE];
  size_t handler_size;
  uint8_t idt_entry[8];
  uint8_t dos_handler[DAZE_KVM_PROTECTED_GATE_HANDLER_MAX_SIZE];
  size_t dos_handler_size;
  uint8_t dos_idt_entry[8];
  uint8_t default_dos_stub[DAZE_KVM_PROTECTED_GATE_DEFAULT_DOS_STUB_SIZE];
  size_t default_dos_stub_size;
} DazeKvmProtectedGateArtifacts;

typedef struct {
  DazeKvmDpmiEntryResult boundary;
  uint16_t function, selector;
  uint16_t client_ip, client_cs;
  uint32_t request_cx, request_dx;
  uint32_t reply_ax, reply_bx, reply_cx, reply_dx;
} DazeKvmProtectedGateExchange;

typedef struct {
  DazeKvmProtectedGateExchange exchanges[DAZE_KVM_PROTECTED_GATE_MAX_EXCHANGES];
  size_t exchange_count;
  DazeKvmDpmiEntryResult terminal;
  uint16_t terminal_function, terminal_selector;
  int terminal_request_present;
} DazeKvmProtectedGateResult;

/* Pure artifact construction. Invalid input leaves output unchanged. */
int daze_kvm_protected_gate_build(const DazeKvmProtectedGateLayout *layout,
                                  DazeKvmProtectedGateArtifacts *output);

/* The target descriptor's D/B bit selects an 86h or 8Eh gate. Invalid or non-executable
 * targets leave entry unchanged. */
int daze_kvm_protected_gate_client_entry(const uint8_t *guest, uint32_t guest_size,
                                         uint32_t gdt_base, uint16_t gdt_limit, uint32_t ldt_base,
                                         uint16_t ldt_limit, const DazeDpmiInterruptVector *target,
                                         uint8_t *entry);

/* Project the caller-selected exception vector into the live hardware IDT.
 * This is required when a transition rebuilds that IDT after the client has
 * already completed DPMI 0203h; it does not alter the shared vector state. */
int daze_kvm_protected_gate_project_exception_vector(DazeKvmMachine *machine,
                                                     const DazeKvmDpmiMediator *mediator,
                                                     const DazeKvmProtectedGateLayout *layout);

/* Re-project one client-owned protected interrupt vector after a resident
 * transition rebuilt the hardware IDT. The supplied vector remains in the
 * mediator's 0205h table; this only restores its mechanical IDT entry. */
int daze_kvm_protected_gate_project_interrupt_vector(DazeKvmMachine *machine,
                                                     const DazeKvmDpmiMediator *mediator,
                                                     const DazeKvmProtectedGateLayout *layout,
                                                     uint8_t vector);

/* Consume at most layout->exchange_limit mediator PIO records from an
 * already-live protected guest. Each record has one shared semantic result
 * and one guest-owned resume. A non-PIO successor returns OK; a valid next
 * request at the caller's limit returns LIMIT_REACHED without answering it. */
int daze_kvm_protected_gate_run(DazeKvmMachine *machine, DazeKvmDpmiMediator *mediator,
                                const DazeKvmProtectedGateLayout *layout,
                                DazeKvmProtectedGateResult *result);

/* Answer one mediator PIO boundary which a caller has already observed. This
 * deliberately does not select a request policy: callers must inspect the
 * saved record and choose whether its function is authorized before calling.
 * On success, successor is the next KVM boundary after the guest epilogue. */
int daze_kvm_protected_gate_resume_mediator_boundary(DazeKvmMachine *machine,
                                                     DazeKvmDpmiMediator *mediator,
                                                     const DazeKvmProtectedGateLayout *layout,
                                                     const DazeKvmDpmiEntryResult *boundary,
                                                     DazeKvmProtectedGateExchange *exchange,
                                                     DazeKvmDpmiEntryResult *successor);

#endif
