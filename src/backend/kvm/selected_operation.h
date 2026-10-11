#ifndef DAZE_KVM_SELECTED_OPERATION_H
#define DAZE_KVM_SELECTED_OPERATION_H

#include "backend_selection.h"
#include "command_result.h"
#include "normal_operation.h"
#include "runner_request_common.h"

typedef DazeCommandResult (*DazeKvmSelectedOperationUnicornRun)(void *context);

typedef struct {
  DazeBackendSelection selection;
  const DazeKvmRunnerRequestCommon *kvm_request;
  /* Optional initialized machine; ownership moves to the KVM command owner. */
  DazeKvmMachine *kvm_machine;
  DazeKvmSelectedOperationUnicornRun run_unicorn;
  void *unicorn_context;
  DazeKvmNormalOperationObservation *kvm_observation;
} DazeKvmSelectedOperationInput;

typedef struct {
  DazeCommandResult command;
  int kvm_attempted;
  int kvm_prestart_rejected;
  int unicorn_attempted;
} DazeKvmSelectedOperationResult;

/* Resolves an action/result using the execution and fallback rules below.
 * May invoke the caller's Unicorn operation; post-start KVM results are terminal. */
DazeCommandResult
daze_kvm_selected_operation_resolve(const DazeBackendSelection *selection,
                                    DazeKvmSelectedOperationUnicornRun run_unicorn,
                                    void *unicorn_context, DazeCommandResult kvm_result);

DazeKvmSelectedOperationResult
daze_kvm_selected_operation_run_record(const DazeKvmSelectedOperationInput *input);

#endif
