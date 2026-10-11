#ifndef DAZE_KVM_COMMAND_OWNER_H
#define DAZE_KVM_COMMAND_OWNER_H

#include "owner_result.h"
#include "child_context.h"
#include "entry.h"
#include "interrupt_vector.h"
#include "protected.h"
#include "raw_switch.h"
#include "runner_resume.h"
#include "kvm_state_save_gate.h"
#include "plan.h"
#include "runner_private.h"
#include "process_state.h"

/* Process placements are caller-owned; selector numbers do not imply descriptor bases. */
typedef struct {
  uint32_t resident_image_end;
  uint32_t gdt_address, ldt_address, idt_address;
  uint16_t idt_limit;
  uint32_t linear_min_address, linear_limit;
  const DazeDpmiTransitionDescriptorAddition *additions;
  size_t addition_count;
  DazeKvmDpmiStateSaveEndpoints state_save_endpoints;
  DazeKvmDpmiRawSwitchEndpoints raw_switch_endpoints;
  const DazeKvmProtectedGateLayout *protected_gate;
  const DazeKvmStateSaveGateLayout *state_save_gate;
  const DazeKvmRawSwitchGateLayout *raw_switch_gate;
  /* The default vector is an alias selector plus gate-relative offset, since a 16-bit
   * far jump cannot retain a flat linear address. */
  uint16_t default_vector_alias_selector;
  uint32_t default_vector_alias_offset;
  uint32_t raw_switch_linear;
} DazeKvmCommandOwnerTransitionLayout;

/* Borrows launch/service state and owns one KVM machine until destruction. */
typedef struct {
  DazeKvmRunnerGenericPreflightRequest preflight;
  DazeKvmCommandOwnerTransitionLayout transition_layout;
  DazeDpmiProcessState *state;
  int observe_post_successor;
} DazeKvmCommandOwnerInput;

/* The caller must destroy the handoff after using its retained machine. */
typedef struct {
  DazeKvmMachine machine;
  DazeDosProcessState process_state;
  DazeDosMemory dos_memory;
  DazeKvmChildContext child;
  DazeDosfsExecHandles child_handles;
  DazeKvmRunnerRequestCommon process;
  DazeKvmRunnerGenericPreflightResult preflight;
  /* One active EXEC child is supported. Parent state must survive until its parked gate
   * is restored. */
  DazeKvmRunnerRequestCommon parent_process;
  DazeKvmRunnerGenericPreflightResult parent_preflight;
  DazeKvmCommandOwnerInput parent_input;
  DazeKvmResidentGdtState resident_gdt;
  int resident_gdt_valid;
  int parent_input_valid;
  int active;
} DazeKvmCommandOwnerHandoff;

typedef enum {
  DAZE_KVM_COMMAND_OWNER_HANDOFF_OK = 0,
  DAZE_KVM_COMMAND_OWNER_HANDOFF_PRESTART_REJECTED = 1,
  DAZE_KVM_COMMAND_OWNER_HANDOFF_POSTSTART_FAILED = 2,
  /* Top-level AH=4Ch produces an exit code but no DPMI handoff. */
  DAZE_KVM_COMMAND_OWNER_HANDOFF_TERMINATED = 3,
  DAZE_KVM_COMMAND_OWNER_HANDOFF_EXEC = 4,
} DazeKvmCommandOwnerHandoffStatus;

typedef struct {
  DazeKvmCommandOwnerDisposition disposition;
  int guest_execution_may_have_started;
  int handoff_present;
  int transition_boundary_present;
  int post_successor_present;
  int transition_stage;
  int transition_status;
  int protected_gate_status;
  DazeKvmDpmiEntryResult transition_successor;
  DazeKvmDpmiEntryResult post_successor;
  DazeKvmRunnerRequestImage terminal_runner_request;
  int terminal_runner_request_present, terminal_runner_broker_status, terminal_runner_resume_status,
    terminal_runner_continue_status;
  uint8_t terminal_vector21_idt_entry[8];
  int terminal_vector21_idt_entry_present;
  DazeDpmiInterruptVector terminal_vector21;
  uint8_t terminal_fault_stack[16];
  int terminal_fault_stack_present;
  uint8_t guest_exit_status;
  int guest_exit_status_present;
  DazeKvmProtectedGateResult protected_gate;
  int protected_gate_present;
  DazeKvmStateSaveGateResult state_save_gate;
  int state_save_gate_status, state_save_gate_present;
  DazeKvmRawSwitchGateResult raw_switch_gate;
  int raw_switch_gate_status, raw_switch_gate_present;
  DazeKvmRawSwitchGateResult real_mode_raw_switch_gate;
  int real_mode_raw_switch_gate_status, real_mode_raw_switch_gate_present;
  DazeKvmRunnerRequestImage real_mode_boundary_request;
  int real_mode_boundary_request_present;
  DazeKvmDpmiEntryResult real_mode_boundary_successor;
  int real_mode_boundary_resume_status, real_mode_boundary_successor_present;
  DazeKvmRawSwitchGateResult real_mode_return_raw_switch_gate;
  int real_mode_return_raw_switch_gate_status, real_mode_return_raw_switch_gate_present;
  int real_mode_return_compose_status, real_mode_return_successor_present;
  DazeKvmDpmiEntryResult real_mode_return_successor;
  int real_mode_return_next_successor_present;
  DazeKvmDpmiEntryResult real_mode_return_next_successor;
  DazeKvmStateSaveGateResult live_state_save_gate;
  int live_state_save_gate_status, live_state_save_gate_present;
  int live_state_save_differs_from_initial;
  DpmiAlternateState live_state_restore;
  int live_state_restore_present;
  DazeKvmDpmiEntryResult live_state_restore_successor;
  int live_state_restore_successor_present;
  uint16_t live_state_restore_function, live_state_restore_selector;
  uint32_t live_state_restore_operand;
  int live_state_restore_request_present;
  DazeKvmProtectedGateExchange live_state_restore_exchange;
  int live_state_restore_gate_status, live_state_restore_exchange_present;
  DazeKvmDpmiEntryResult live_state_restore_next_successor;
  int live_state_restore_next_successor_present;
  DazeKvmStateSaveGateResult live_state_restore_next_state_save;
  int live_state_restore_next_state_save_status, live_state_restore_next_state_save_present;
  DazeKvmRawSwitchGateResult post_cycle_raw_switch_gate;
  int post_cycle_raw_switch_gate_status, post_cycle_raw_switch_gate_present;
  DazeKvmDpmiEntryResult post_cycle_successor;
  int post_cycle_successor_present;
  DazeKvmDpmiEntryResult post_cycle_real_boundary;
  DazeKvmRunnerRequestImage post_cycle_real_request;
  int post_cycle_real_boundary_present, post_cycle_real_request_present;
  int post_cycle_read_resume_status, post_cycle_read_successor_present;
  uint16_t post_cycle_read_copied_byte_count;
  DazeKvmDpmiEntryResult post_cycle_read_successor;
  DazeKvmRawSwitchGateResult post_cycle_read_raw_switch_gate;
  int post_cycle_read_raw_switch_gate_status, post_cycle_read_raw_switch_gate_present;
  int post_cycle_read_return_compose_status, post_cycle_read_return_successor_present;
  DazeKvmDpmiEntryResult post_cycle_read_return_successor;
  int post_cycle_read_return_next_successor_present;
  DazeKvmDpmiEntryResult post_cycle_read_return_next_successor;
  DpmiAlternateState final_read_state;
  int final_read_state_present;
  DazeKvmDpmiEntryResult final_read_mediator_boundary;
  int final_read_mediator_boundary_present;
  DazeKvmProtectedGateExchange final_read_mediator_exchange;
  int final_read_mediator_status, final_read_mediator_exchange_present;
  DazeKvmDpmiEntryResult final_read_state_save_boundary;
  int final_read_state_save_boundary_present;
  DazeKvmStateSaveGateResult final_read_state_save_gate;
  int final_read_state_save_gate_status, final_read_state_save_gate_present;
  DazeKvmRawSwitchGateResult final_read_raw_switch_gate;
  int final_read_raw_switch_gate_status, final_read_raw_switch_gate_present;
  DazeKvmDpmiEntryResult final_read_boundary;
  DazeKvmDpmiEntryResult final_read_runner_boundary;
  DazeKvmRunnerRequestImage final_read_request;
  int final_read_boundary_present, final_read_runner_boundary_present, final_read_request_present;
  uint16_t final_read_copied_byte_count;
  int final_read_resume_status, final_read_successor_present;
  DazeKvmDpmiEntryResult final_read_successor;
  DazeKvmRawSwitchGateResult final_close_raw_switch_gate;
  int final_close_raw_switch_gate_status, final_close_raw_switch_gate_present;
  int final_close_return_compose_status, final_close_return_successor_present;
  DazeKvmDpmiEntryResult final_close_return_successor;
  int final_close_return_next_successor_present;
  DazeKvmDpmiEntryResult final_close_return_next_successor;
  int post_close_state_present;
  DazeKvmDpmiEntryResult post_close_mediator_boundary;
  uint16_t post_close_mediator_function, post_close_mediator_selector;
  int post_close_mediator_request_present, post_close_mediator_boundary_present,
    post_close_mediator_status;
  DazeKvmProtectedGateResult post_close_sequence;
  int post_close_sequence_present, post_close_sequence_status;
  DazeKvmDpmiEntryResult post_close_state_save_boundary;
  int post_close_state_save_boundary_present, post_close_state_save_status;
  DazeKvmRawSwitchGateResult post_close_raw_switch_gate;
  int post_close_raw_switch_gate_present, post_close_raw_switch_gate_status;
  DazeKvmDpmiEntryResult post_close_real_boundary;
  DazeKvmRunnerRequestImage post_close_real_request;
  int post_close_real_boundary_present, post_close_real_request_present;
  DazeKvmDpmiEntryResult post_close_real_successor;
  int post_close_real_resume_status, post_close_real_successor_present;
  DazeKvmRawSwitchGateResult post_close_real_return_raw_switch_gate;
  int post_close_real_return_raw_switch_gate_status, post_close_real_return_raw_switch_gate_present;
  int post_close_real_return_compose_status;
  DazeKvmDpmiEntryResult post_close_real_return_successor;
  DazeKvmDpmiEntryResult post_close_real_return_next_successor;
  int post_close_real_return_successor_present, post_close_real_return_next_successor_present;
  uint16_t post_close_real_followup_function, post_close_real_followup_selector;
  int post_close_real_followup_request_present;
  DpmiAlternateState post_close_real_followup_state;
  int post_close_real_followup_state_present;
  DazeKvmDpmiEntryResult post_close_real_followup_mediator_boundary;
  uint16_t post_close_real_followup_mediator_function, post_close_real_followup_mediator_selector;
  int post_close_real_followup_mediator_boundary_present,
    post_close_real_followup_mediator_request_present;
  DazeKvmProtectedGateResult post_close_real_followup_sequence;
  int post_close_real_followup_sequence_status, post_close_real_followup_sequence_present;
  DazeKvmStateSaveGateResult post_close_real_followup_state_save_gate;
  int post_close_real_followup_state_save_status, post_close_real_followup_state_save_present;
  DazeKvmRawSwitchGateResult post_close_real_followup_raw_switch_gate;
  int post_close_real_followup_raw_switch_gate_status,
    post_close_real_followup_raw_switch_gate_present;
  DazeKvmDpmiEntryResult post_close_real_followup_real_boundary;
  DazeKvmRunnerRequestImage post_close_real_followup_real_request;
  int post_close_real_followup_real_boundary_present, post_close_real_followup_real_request_present;
  DazeKvmDpmiEntryResult post_close_real_followup_real_successor;
  int post_close_real_followup_real_resume_status, post_close_real_followup_real_successor_present;
  DazeKvmRawSwitchGateResult post_close_real_followup_return_raw_switch_gate;
  int post_close_real_followup_return_raw_switch_gate_status,
    post_close_real_followup_return_raw_switch_gate_present;
  int post_close_real_followup_return_compose_status;
  DazeKvmDpmiEntryResult post_close_real_followup_return_successor;
  DazeKvmDpmiEntryResult post_close_real_followup_return_next_successor;
  int post_close_real_followup_return_successor_present,
    post_close_real_followup_return_next_successor_present;
  DpmiAlternateState post_close_real_followup_return_state;
  uint32_t post_close_real_followup_return_state_buffer_address;
  int post_close_real_followup_return_state_present;
  DazeKvmDpmiEntryResult post_close_real_followup_return_restore_successor;
  int post_close_real_followup_return_restore_successor_present;
  uint16_t post_close_real_followup_return_function, post_close_real_followup_return_selector;
  uint32_t post_close_real_followup_return_operand;
  int post_close_real_followup_return_request_present;
  DazeKvmProtectedGateExchange post_close_real_followup_return_exchange;
  int post_close_real_followup_return_gate_status, post_close_real_followup_return_exchange_present;
  DazeKvmDpmiEntryResult post_close_real_followup_return_next_boundary;
  int post_close_real_followup_return_next_boundary_present;
  uint16_t post_close_real_followup_return_next_function,
    post_close_real_followup_return_next_selector;
  uint32_t post_close_real_followup_return_next_operand;
  int post_close_real_followup_return_next_request_present;
  DazeKvmRawSwitchGateResult live_state_raw_switch_gate;
  int live_state_raw_switch_gate_status, live_state_raw_switch_gate_present;
  uint8_t raw_reentry_gdtr[DAZE_KVM_TRANSITION_PLAN_GDTR_SIZE];
  int raw_reentry_gdtr_present;
  /* Latest mediator request, captured before service. Request presence is an
   * observation, not service completion; gate status is recorded separately. */
  uint16_t post_return_function, post_return_selector;
  uint32_t post_return_operand;
  int post_return_request_present;
  DazeKvmProtectedGateExchange post_return_exchange;
  int post_return_gate_status, post_return_exchange_present;
  uint16_t post_return_successor_function, post_return_successor_selector;
  uint32_t post_return_successor_operand;
  int post_return_successor_request_present;
  DazeKvmProtectedGateResult post_return_sequence;
  int post_return_sequence_status, post_return_sequence_present;
  uint16_t post_return_terminal_function, post_return_terminal_selector;
  uint32_t post_return_terminal_operand;
  int post_return_terminal_request_present;
  DazeKvmStateSaveGateResult post_return_state_save_gate;
  int post_return_state_save_gate_status, post_return_state_save_gate_present;
  int post_return_state_save_matches_initial;
  DazeKvmRawSwitchGateResult post_return_raw_switch_gate;
  int post_return_raw_switch_gate_status, post_return_raw_switch_gate_present;
  DazeKvmDpmiEntryResult post_return_raw_successor;
  int post_return_raw_successor_present;
} DazeKvmCommandOwnerResult;

/* A zero selector:offset means no default vector is published. */
DazeDpmiInterruptVector
daze_kvm_command_owner_default_vector21(const DazeKvmCommandOwnerTransitionLayout *layout);
/* Protected AH=09h scans up to 4096 bytes for '$' at captured DS base + DX,
 * never DS << 4, and writes through DOS handle 1. Success preserves request
 * registers and clears carry; invalid/unwritable strings or handles return
 * AX=0006h with carry set. Returns a broker disposition and mailbox reply
 * without running the vCPU. */
int daze_kvm_command_owner_protected_dos_display_string(
  const DazeKvmMachine *machine, DazeDosfsFileService *files,
  const DazeKvmDpmiEntryResult *boundary, const DazeKvmRunnerRequestImage *request,
  const uint8_t record[24], uint8_t reply[DAZE_KVM_RUNNER_GATE_REPLY_SIZE]);

int daze_kvm_command_owner_begin(const DazeKvmRunnerGenericPreflightRequest *request,
                                 DazeKvmCommandOwnerHandoff *handoff);
int daze_kvm_command_owner_begin_observe(const DazeKvmRunnerGenericPreflightRequest *request,
                                         DazeKvmMachine *machine,
                                         DazeKvmCommandOwnerHandoff *handoff,
                                         DazeKvmRunnerGenericPreflightResult *observation);
int daze_kvm_command_owner_continue(DazeKvmCommandOwnerHandoff *handoff,
                                    const DazeKvmCommandOwnerInput *input,
                                    DazeKvmCommandOwnerResult *result);
int daze_kvm_command_owner_start_exec(DazeKvmCommandOwnerHandoff *handoff,
                                      const DazeKvmRunnerGenericPreflightRequest *request,
                                      DazeDpmiProcessState *state,
                                      DazeKvmCommandOwnerResult *result);
int daze_kvm_command_owner_reply_exec_success(DazeKvmMachine *machine);
void daze_kvm_command_owner_handoff_destroy(DazeKvmCommandOwnerHandoff *handoff);

#endif
