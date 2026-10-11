#ifndef DAZE_KVM_CHILD_CONTEXT_H
#define DAZE_KVM_CHILD_CONTEXT_H

#include "memory.h"
#include "../../dpmi/transition_artifacts.h"
#include "dpmi_process_state.h"
#include "image.h"
#include "machine.h"
#include "runner_request_common.h"
#include "mz_layout.h"
#include "process_state.h"
#include "raw_vector_projection.h"

#include <stdint.h>

/* Exact GDT entries consumed by DPMILOAD's retained raw return. These are
 * captured from the child's live table; callers must validate the table base
 * and limit before restoring them. */
typedef struct {
  uint32_t base;
  uint16_t limit;
  uint8_t code[8], ds[8], es[8], transition[8], stack[8];
  uint32_t real_transition_address, real_transition_gdtr_address;
  uint8_t real_transition_code[22], real_transition_gdtr[6];
  int real_transition_valid;
  /* A resident DPMI client owns its live LDT.  The parent snapshot and the
   * generic transition writer both replace that image, so retain the exact
   * child image and allocator state until the raw return has rebuilt the
   * shared transition artifacts. */
  uint32_t ldt_base;
  uint16_t ldt_limit;
  uint8_t *ldt_bytes;
  uint16_t next_ldt_index;
  uint8_t ldt_used[DAZE_DPMI_TRANSITION_LDT_SIZE / 8];
  int ldt_valid;
  DazeRawVectorProjection raw_vector_projections[DAZE_RAW_VECTOR_PROJECTION_MAX];
  int valid;
} DazeKvmResidentGdtState;

void daze_kvm_resident_gdt_state_dispose(DazeKvmResidentGdtState *state);
/* Withdraw owned vector projections as soon as their DOS allocation is
 * released or resized, before any guest continuation can reload them. */
int daze_kvm_resident_vector_projections_refresh(DazeKvmMachine *machine,
                                                 DazeKvmResidentGdtState *resident,
                                                 const DazeDosMemory *memory);

/* Capturing moves parent DOS state out of the live slots; restoration disposes child
 * state and moves it back. */
typedef struct {
  DazeKvmMachineSnapshot machine;
  DazeKvmRunnerRequestCommon parent_layout;
  DazeDosProcessState parent_dos;
  DazeDosMemory parent_memory;
  void *parent_dpmi;
  /* Child launch storage must outlive the runner record that supplies it. */
  DazeImage child_image;
  DazeMzHeader child_header;
  char child_path[128];
  char child_tail[127];
  uint8_t child_psp[256];
  int active;
} DazeKvmChildContext;

int daze_kvm_child_context_capture(DazeKvmChildContext *context, const DazeKvmMachine *machine,
                                   const DazeKvmRunnerRequestCommon *layout,
                                   DazeDosProcessState *dos_state, DazeDosMemory *dos_memory,
                                   DazeDpmiProcessState *dpmi_state);
int daze_kvm_child_context_restore(DazeKvmChildContext *context, DazeKvmMachine *machine,
                                   DazeDosProcessState *dos_state, DazeDosMemory *dos_memory,
                                   DazeDpmiProcessState *dpmi_state);
/* Return an EXEC child which used INT 21h/AH=31h.  Unlike ordinary child
 * termination, retain only the declared PSP-relative resident range and DOS
 * interrupt vectors the child explicitly changed. */
int daze_kvm_child_context_restore_resident(DazeKvmChildContext *context, DazeKvmMachine *machine,
                                            DazeDosProcessState *dos_state,
                                            DazeDosMemory *dos_memory,
                                            DazeDpmiProcessState *dpmi_state,
                                            uint16_t resident_paragraphs,
                                            DazeKvmResidentGdtState *resident_gdt);
void daze_kvm_child_context_dispose(DazeKvmChildContext *context);

#endif
