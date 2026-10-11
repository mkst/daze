#ifndef DAZE_KVM_NORMAL_OPERATION_H
#define DAZE_KVM_NORMAL_OPERATION_H

#include "command_result.h"
#include "machine.h"
#include "runner_request_common.h"

/* Copied terminal diagnostic state; no retained machine ownership. */
typedef struct {
  int present;
  int source;
  int capture_status;
  int owner_disposition;
  int exit_kind;
  uint32_t raw_exit_reason;
  uint16_t pio_port;
  uint8_t pio_direction, pio_size;
  int pio_value_present;
  uint32_t pio_value;
  uint16_t cs;
  uint32_t rip;
  uint32_t cs_base, ss_base, es_base;
  uint32_t gdt_base, idt_base;
  int transition_stage, transition_status;
  int protected_gate_status;
  int post_return_request_present;
  uint16_t post_return_function, post_return_selector;
  uint32_t post_return_operand;
  int post_return_gate_status;
  int runner_request_present;
  uint8_t runner_vector;
  uint16_t runner_ax, runner_bx, runner_cx, runner_dx, runner_ds, runner_es, runner_si, runner_di;
  uint16_t ax, bx, cx, dx, ds, es, ss, sp;
  uint8_t request_vector;
  uint16_t request_ax, request_bx, request_cx, request_dx, request_ds;
} DazeKvmNormalOperationObservation;

int daze_kvm_normal_operation_request_valid(const DazeKvmRunnerRequestCommon *request);

/* A supplied admission machine is consumed when bootstrap begins. NULL creates
 * a machine locally. A rejected request leaves the caller's machine untouched. */
DazeCommandResult
daze_kvm_normal_operation_run_observe(const DazeKvmRunnerRequestCommon *request,
                                      DazeKvmMachine *machine,
                                      DazeKvmNormalOperationObservation *observation);

#endif
