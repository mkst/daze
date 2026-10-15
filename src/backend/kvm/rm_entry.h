#ifndef DAZE_KVM_RM_ENTRY_H
#define DAZE_KVM_RM_ENTRY_H

#include "machine.h"
#include "kvm_bytes.h"
#include "kvm_range.h"
#include "guest_memory_layout.h"
#include "mediator.h"

enum {
  DAZE_KVM_RM_ENTRY_LINEAR = k_dpmi_rm_entry_linear,
  DAZE_KVM_RM_ENTRY_LOW_LINEAR = 0x2720,
  DAZE_KVM_RM_ENTRY_CONTROL = 0x5800,
  DAZE_KVM_RM_ENTRY_CONTROL_SIZE = 0x800,
  DAZE_KVM_RM_ENTRY_ACTIVE_OFFSET = 0x40,
  DAZE_KVM_RM_ENTRY_COUNT_OFFSET = 0x44,
  DAZE_KVM_RM_ENTRY_SIGNATURE_OFFSET = 0x68,
  DAZE_KVM_RM_ENTRY_SIGNATURE = 0x44524d45,
  DAZE_KVM_RM_ENTRY_LDT_OFFSET = 0x6c,
  DAZE_KVM_RM_ENTRY_LDT_LAST_OFFSET = 0x70,
  DAZE_KVM_RM_ENTRY_DESCRIPTOR_COUNT_OFFSET = 0x74,
  DAZE_KVM_RM_ENTRY_VECTOR_TABLE_OFFSET = 0x80,
  DAZE_KVM_RM_ENTRY_VECTOR_STRIDE = 6,
  DAZE_KVM_RM_ENTRY_VECTOR_COUNT = 256,
  DAZE_KVM_RM_ENTRY_VECTOR_COUNT_OFFSET = 0x680,
  DAZE_KVM_RM_ENTRY_VECTOR_VALID_OFFSET = 0x684,
  DAZE_KVM_RM_ENTRY_VECTOR_ENABLED_OFFSET = 0x688,
  DAZE_KVM_RM_ENTRY_VECTOR_SIGNATURE = 0x02040204,
  DAZE_KVM_RM_ENTRY_PARKED = 0x2a00,
};

_Static_assert(DAZE_KVM_RM_ENTRY_VECTOR_TABLE_OFFSET +
                   DAZE_KVM_RM_ENTRY_VECTOR_COUNT * DAZE_KVM_RM_ENTRY_VECTOR_STRIDE ==
                 DAZE_KVM_RM_ENTRY_VECTOR_COUNT_OFFSET,
               "vector table stays below counters");
_Static_assert(DAZE_KVM_RM_ENTRY_VECTOR_ENABLED_OFFSET + 4 <= DAZE_KVM_RM_ENTRY_CONTROL_SIZE,
               "vector state stays inside reserved control storage");

static inline void daze_kvm_rm_entry_publish_vectors(DazeKvmDpmiMediator *mediator) {
  if (mediator == NULL || mediator->guest == NULL || mediator->record_address != 0xfdea00 ||
      mediator->mailbox_address != 0xfdea40 ||
      !daze_kvm_range_fits(mediator->guest_size, DAZE_KVM_RM_ENTRY_CONTROL,
                           DAZE_KVM_RM_ENTRY_CONTROL_SIZE))
    return;
  uint8_t *control = mediator->guest + DAZE_KVM_RM_ENTRY_CONTROL;
  if (daze_read_u32(control + DAZE_KVM_RM_ENTRY_SIGNATURE_OFFSET) != DAZE_KVM_RM_ENTRY_SIGNATURE ||
      daze_read_u32(control + DAZE_KVM_RM_ENTRY_VECTOR_ENABLED_OFFSET) != 1)
    return;
  daze_write_u32(control + DAZE_KVM_RM_ENTRY_VECTOR_VALID_OFFSET, 0);
  /* The software default is not necessarily the target currently projected into the IDT. */
  for (unsigned i = 0; i < DAZE_KVM_RM_ENTRY_VECTOR_COUNT; ++i) {
    DazeDpmiInterruptVector vector = mediator->interrupt_vectors[i];
    if (vector.segment == 0 && vector.offset == 0) vector = mediator->default_interrupt_vectors[i];
    uint8_t *slot =
      control + DAZE_KVM_RM_ENTRY_VECTOR_TABLE_OFFSET + i * DAZE_KVM_RM_ENTRY_VECTOR_STRIDE;
    daze_write_u16(slot, vector.segment);
    daze_write_u32(slot + 2, vector.offset);
  }
  daze_write_u32(control + DAZE_KVM_RM_ENTRY_VECTOR_VALID_OFFSET,
                 DAZE_KVM_RM_ENTRY_VECTOR_SIGNATURE);
}

static inline int daze_kvm_rm_entry_installed(const DazeKvmMachine *machine) {
  return machine != NULL && machine->guest != NULL &&
         daze_kvm_range_fits(machine->guest_size, DAZE_KVM_RM_ENTRY_CONTROL,
                             DAZE_KVM_RM_ENTRY_CONTROL_SIZE) &&
         daze_read_u32((const uint8_t *)machine->guest + DAZE_KVM_RM_ENTRY_CONTROL +
                       DAZE_KVM_RM_ENTRY_SIGNATURE_OFFSET) == DAZE_KVM_RM_ENTRY_SIGNATURE;
}

static inline uint32_t daze_kvm_rm_entry_count(const DazeKvmMachine *machine) {
  return daze_kvm_rm_entry_installed(machine)
           ? daze_read_u32((const uint8_t *)machine->guest + DAZE_KVM_RM_ENTRY_CONTROL +
                           DAZE_KVM_RM_ENTRY_COUNT_OFFSET)
           : 0;
}

static inline int daze_kvm_rm_entry_active(const DazeKvmMachine *machine) {
  return daze_kvm_rm_entry_installed(machine) &&
         daze_read_u32((const uint8_t *)machine->guest + DAZE_KVM_RM_ENTRY_CONTROL +
                       DAZE_KVM_RM_ENTRY_ACTIVE_OFFSET) == 1;
}

static inline void daze_kvm_rm_entry_invalidate(DazeKvmMachine *machine) {
  if (daze_kvm_rm_entry_installed(machine))
    daze_write_u32((uint8_t *)machine->guest + DAZE_KVM_RM_ENTRY_CONTROL, 0);
}

static inline void daze_kvm_rm_entry_sync_metrics(DazeKvmMachine *machine) {
  if (machine != NULL && machine->run_metrics != NULL && machine->run_metrics->enabled) {
    machine->run_metrics->kvm_rm_procedure_native_calls += daze_kvm_rm_entry_count(machine);
    if (daze_kvm_rm_entry_installed(machine)) {
      uint8_t *vector_counter = (uint8_t *)machine->guest + DAZE_KVM_RM_ENTRY_CONTROL +
                                DAZE_KVM_RM_ENTRY_VECTOR_COUNT_OFFSET;
      machine->run_metrics->kvm_guest_vector_queries += daze_read_u32(vector_counter);
      daze_write_u32(vector_counter, 0);
      daze_write_u32(
        (uint8_t *)machine->guest + DAZE_KVM_RM_ENTRY_CONTROL + DAZE_KVM_RM_ENTRY_COUNT_OFFSET, 0);
      for (unsigned i = 0; i < 3; ++i) {
        uint8_t *counter = (uint8_t *)machine->guest + DAZE_KVM_RM_ENTRY_CONTROL +
                           DAZE_KVM_RM_ENTRY_DESCRIPTOR_COUNT_OFFSET + i * 4;
        machine->run_metrics->kvm_guest_descriptor_calls[i] += daze_read_u32(counter);
        daze_write_u32(counter, 0);
      }
    }
  }
}

#endif
