#ifndef DAZE_KVM_RM_PROCEDURE_H
#define DAZE_KVM_RM_PROCEDURE_H

#include "file_service.h"
#include "entry.h"
#include "mediator.h"
#include "machine.h"
#include "process_state.h"

#include <stdint.h>

/* The guest is parked at the mediator boundary. Reflection must restore protected state
 * after the real-mode procedure returns. */
typedef struct {
  DazeKvmMachine *machine;
  DazeKvmDpmiMediator *mediator;
  DazeDosfsFileService *files;
  DazeDosProcessState *process_state;
  uint16_t dpmi_entry_segment;
  /* An enclosing legacy exception owns this return boundary. Reflection
   * temporarily replaces hardware debug state; restore it before resuming. */
  uint32_t protected_return_linear;
} DazeKvmRmProcedureInput;

/* Reflect once. On success, successor is the next boundary after the gate's
 * IRET to the protected client. Real-mode INTs are served through the same
 * runner gate contract as the preflight phase; anything else stops loudly. */
int daze_kvm_rm_procedure_reflect(const DazeKvmRmProcedureInput *input,
                                  DazeKvmDpmiEntryResult *successor);

int daze_kvm_rm_entry_install(DazeKvmMachine *machine, uint32_t epilogue, uint32_t ldt_address,
                              size_t ldt_size);
int daze_kvm_rm_entry_continue(const DazeKvmRmProcedureInput *input,
                               DazeKvmDpmiEntryResult *successor);

#endif
