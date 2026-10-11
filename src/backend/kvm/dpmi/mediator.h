#ifndef DAZE_KVM_DPMI_MEDIATOR_H
#define DAZE_KVM_DPMI_MEDIATOR_H

#include "dpmi_function.h"
#include "linear_memory.h"
#include "port.h"
#include "rm_frame.h"
#include "request.h"

#include <stddef.h>
#include <stdint.h>

enum {
  DAZE_KVM_DPMI_MEDIATOR_PORT = DAZE_PORT_GATE,
  DAZE_KVM_DPMI_MEDIATOR_MARKER = 0x31,
  DAZE_KVM_DPMI_RECORD_SIZE = 44,
  DAZE_KVM_DPMI_MAILBOX_SIZE = 32,
};

typedef enum {
  DAZE_KVM_DPMI_MEDIATOR_OK = 0,
  DAZE_KVM_DPMI_MEDIATOR_INVALID = 1,
  DAZE_KVM_DPMI_MEDIATOR_UNSUPPORTED = 2,
  /* A valid real-mode request leaves the guest parked; the caller must reflect it before
   * resuming. */
  DAZE_KVM_DPMI_MEDIATOR_RM_PROCEDURE = 3,
} DazeKvmDpmiMediatorStatus;

/* 0305h returns caller-supplied endpoints; the state procedure runs separately. */
typedef struct {
  uint16_t state_buffer_size;
  uint16_t rm_segment;
  uint16_t rm_offset;
  uint16_t pm_selector;
  uint32_t pm_offset;
} DazeKvmDpmiStateSaveEndpoints;

/* 0306h returns caller-supplied endpoints without invoking them. */
typedef struct {
  uint16_t rm_segment;
  uint16_t rm_offset;
  uint16_t pm_selector;
  uint32_t pm_offset;
} DazeKvmDpmiRawSwitchEndpoints;

typedef struct {
  uint8_t *guest;
  size_t guest_size;
  uint32_t record_address;
  uint32_t mailbox_address;
  uint32_t gdt_address;
  size_t gdt_size;
  uint32_t ldt_address;
  size_t ldt_size;
  uint8_t *ldt_used;
  size_t ldt_used_count;
  uint16_t ldt_first_index;
  DazeDpmiLinearMemory *linear_memory;
  DazeDosMemory *dos_memory;
  DazeDpmiExceptionVector exception_vectors[32];
  uint16_t *real_mode_vector_segment;
  uint16_t *real_mode_vector_offset;
  size_t real_mode_vector_count;
  DazeDpmiInterruptVector interrupt_vectors[256];
  /* Backend-owned defaults are returned only while the corresponding client
   * slot remains empty. They never become an explicit 0205h table write. */
  DazeDpmiInterruptVector default_interrupt_vectors[256];
  int *virtual_interrupts_enabled;
  DazeKvmDpmiStateSaveEndpoints state_save_endpoints;
  DazeKvmDpmiRawSwitchEndpoints raw_switch_endpoints;
  /* Valid only for the last consumed 0300h or 0301h record. */
  DazeDpmiRmProcedure rm_procedure;
  int rm_procedure_present;
  int rm_procedure_is_interrupt;
} DazeKvmDpmiMediator;

/* Selectors resolve through their TI-selected table; invalid indexes return zero. */
int daze_kvm_dpmi_mediator_descriptor_address(const DazeKvmDpmiMediator *mediator,
                                              uint16_t selector, uint32_t *address);
int daze_kvm_dpmi_mediator_gdt_descriptor_address(const DazeKvmDpmiMediator *mediator,
                                                  uint16_t selector, uint32_t *address);

/* Consume exactly one fixed PIO record. On a supported request, writes only
 * the result mailbox; a guest epilogue owns register loads and IRETD. Invalid
 * and unsupported records leave the mailbox, LDT, vectors, and allocator
 * untouched. */
DazeKvmDpmiMediatorStatus daze_kvm_dpmi_mediator_process(DazeKvmDpmiMediator *mediator,
                                                         uint16_t port, uint8_t marker);

#endif
