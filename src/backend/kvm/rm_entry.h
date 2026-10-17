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
  DAZE_KVM_RM_ENTRY_CONTROL_SIZE = k_dpmi_rm_entry_reserved_linear + k_dpmi_rm_entry_size -
    DAZE_KVM_RM_ENTRY_CONTROL,
  DAZE_KVM_RM_ENTRY_ES_BASE_OFFSET = 0x04,
  DAZE_KVM_RM_ENTRY_DESCRIPTORS_OFFSET = 0x08,
  DAZE_KVM_RM_ENTRY_EPILOGUE_OFFSET = 0x30,
  DAZE_KVM_RM_ENTRY_GS_SELECTOR_OFFSET = 0x34,
  DAZE_KVM_RM_ENTRY_GS_DESCRIPTOR_ADDRESS_OFFSET = 0x38,
  DAZE_KVM_RM_ENTRY_ACTIVE_OFFSET = 0x40,
  DAZE_KVM_RM_ENTRY_COUNT_OFFSET = 0x44,
  DAZE_KVM_RM_ENTRY_GS_DESCRIPTOR_OFFSET = 0x48,
  DAZE_KVM_RM_ENTRY_RESERVED_DESCRIPTORS_OFFSET = 0x50,
  DAZE_KVM_RM_ENTRY_GDT_LIMIT_OFFSET = 0x54,
  DAZE_KVM_RM_ENTRY_GDT_BASE_OFFSET = 0x56,
  DAZE_KVM_RM_ENTRY_LDT_SELECTOR_OFFSET = 0x5a,
  DAZE_KVM_RM_ENTRY_IDT_LIMIT_OFFSET = 0x5c,
  DAZE_KVM_RM_ENTRY_IDT_BASE_OFFSET = 0x5e,
  DAZE_KVM_RM_ENTRY_CR0_OFFSET = 0x64,
  DAZE_KVM_RM_ENTRY_SIGNATURE_OFFSET = 0x68,
  DAZE_KVM_RM_ENTRY_SIGNATURE = 0x44524d45,
  DAZE_KVM_RM_ENTRY_LDT_OFFSET = 0x6c,
  DAZE_KVM_RM_ENTRY_LDT_LAST_OFFSET = 0x70,
  DAZE_KVM_RM_ENTRY_DESCRIPTOR_COUNT_OFFSET = 0x74,
  DAZE_KVM_RM_ENTRY_VECTOR_TABLE_OFFSET = 0x80,
  DAZE_KVM_RM_ENTRY_SAVED_SREGS = k_dpmi_rm_entry_reserved_linear,
  DAZE_KVM_RM_ENTRY_VECTOR_STRIDE = 6,
  DAZE_KVM_RM_ENTRY_VECTOR_COUNT = 256,
  DAZE_KVM_RM_ENTRY_VECTOR_COUNT_OFFSET = 0x680,
  DAZE_KVM_RM_ENTRY_VECTOR_VALID_OFFSET = 0x684,
  DAZE_KVM_RM_ENTRY_VECTOR_ENABLED_OFFSET = 0x688,
  DAZE_KVM_RM_ENTRY_VECTOR_SIGNATURE = 0x02040204,
  DAZE_KVM_RM_ENTRY_SET_DESCRIPTOR_COUNT_OFFSET = 0x68c,
  DAZE_KVM_RM_ENTRY_SET_DESCRIPTOR_GDT_OFFSET = 0x690,
  DAZE_KVM_RM_ENTRY_SET_DESCRIPTOR_GDT_LAST_OFFSET = 0x694,
  DAZE_KVM_RM_ENTRY_SET_DESCRIPTOR_RAM_LAST_OFFSET = 0x698,
  DAZE_KVM_RM_ENTRY_SET_DESCRIPTOR_VALID_OFFSET = 0x69c,
  DAZE_KVM_RM_ENTRY_SET_DESCRIPTOR_SIGNATURE = 0x000c000c,
  DAZE_KVM_RM_ENTRY_SET_DESCRIPTOR_LINEAR = 0x5ea0,
  DAZE_KVM_RM_ENTRY_GET_BASE_LINEAR = 0x2800,
  DAZE_KVM_RM_ENTRY_GET_BASE_COUNT_OFFSET = 0x7fc,
  DAZE_KVM_RM_ENTRY_PARKED = 0x2a00,
};

_Static_assert(DAZE_KVM_RM_ENTRY_VECTOR_TABLE_OFFSET +
                   DAZE_KVM_RM_ENTRY_VECTOR_COUNT * DAZE_KVM_RM_ENTRY_VECTOR_STRIDE ==
                 DAZE_KVM_RM_ENTRY_VECTOR_COUNT_OFFSET,
               "vector table stays below counters");
_Static_assert(DAZE_KVM_RM_ENTRY_VECTOR_ENABLED_OFFSET + 4 <= DAZE_KVM_RM_ENTRY_CONTROL_SIZE,
               "vector state stays inside reserved control storage");
_Static_assert(DAZE_KVM_RM_ENTRY_SET_DESCRIPTOR_VALID_OFFSET + 4 <=
                 DAZE_KVM_RM_ENTRY_SET_DESCRIPTOR_LINEAR - DAZE_KVM_RM_ENTRY_CONTROL,
               "descriptor metadata stays below helper code");
_Static_assert(DAZE_KVM_RM_ENTRY_GET_BASE_COUNT_OFFSET + 4 <= DAZE_KVM_RM_ENTRY_CONTROL_SIZE,
               "get base counter stays inside reserved control storage");

static inline void daze_kvm_rm_entry_publish_descriptors(const DazeKvmDpmiMediator *mediator) {
  if (mediator == NULL || mediator->guest == NULL ||
      mediator->guest_size < DAZE_KVM_RM_ENTRY_CONTROL + DAZE_KVM_RM_ENTRY_CONTROL_SIZE)
    return;
  uint8_t *control = mediator->guest + DAZE_KVM_RM_ENTRY_CONTROL;
  if (daze_read_u32(control + DAZE_KVM_RM_ENTRY_SIGNATURE_OFFSET) != DAZE_KVM_RM_ENTRY_SIGNATURE)
    return;
  daze_write_u32(control + DAZE_KVM_RM_ENTRY_SET_DESCRIPTOR_VALID_OFFSET, 0);
  if (mediator->record_address != 0xfdea00 || mediator->mailbox_address != 0xfdea40 ||
      mediator->guest_size > UINT32_MAX || mediator->gdt_size < 8 || mediator->gdt_size > 0x10000 ||
      mediator->gdt_size % 8 != 0 || mediator->ldt_size < 16 || mediator->ldt_size > 0x10000 ||
      mediator->ldt_size % 8 != 0 ||
      !daze_kvm_range_fits(mediator->guest_size, mediator->gdt_address, mediator->gdt_size) ||
      !daze_kvm_range_fits(mediator->guest_size, mediator->ldt_address, mediator->ldt_size) ||
      daze_read_u32(control + DAZE_KVM_RM_ENTRY_LDT_OFFSET) != mediator->ldt_address ||
      daze_read_u32(control + DAZE_KVM_RM_ENTRY_LDT_LAST_OFFSET) != mediator->ldt_size - 8)
    return;
  daze_write_u32(control + DAZE_KVM_RM_ENTRY_SET_DESCRIPTOR_GDT_OFFSET, mediator->gdt_address);
  daze_write_u32(control + DAZE_KVM_RM_ENTRY_SET_DESCRIPTOR_GDT_LAST_OFFSET,
                 (uint32_t)mediator->gdt_size - 8);
  daze_write_u32(control + DAZE_KVM_RM_ENTRY_SET_DESCRIPTOR_RAM_LAST_OFFSET,
                 (uint32_t)mediator->guest_size - 8);
  daze_write_u32(control + DAZE_KVM_RM_ENTRY_SET_DESCRIPTOR_VALID_OFFSET,
                 DAZE_KVM_RM_ENTRY_SET_DESCRIPTOR_SIGNATURE);
}

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
      uint8_t *set_counter = (uint8_t *)machine->guest + DAZE_KVM_RM_ENTRY_CONTROL +
                             DAZE_KVM_RM_ENTRY_SET_DESCRIPTOR_COUNT_OFFSET;
      machine->run_metrics->kvm_guest_descriptor_calls[3] += daze_read_u32(set_counter);
      daze_write_u32(set_counter, 0);
      uint8_t *get_counter = (uint8_t *)machine->guest + DAZE_KVM_RM_ENTRY_CONTROL +
                             DAZE_KVM_RM_ENTRY_GET_BASE_COUNT_OFFSET;
      machine->run_metrics->kvm_guest_descriptor_calls[4] += daze_read_u32(get_counter);
      daze_write_u32(get_counter, 0);
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
