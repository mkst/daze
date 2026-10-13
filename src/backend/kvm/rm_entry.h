#ifndef DAZE_KVM_RM_ENTRY_H
#define DAZE_KVM_RM_ENTRY_H

#include "machine.h"
#include "kvm_bytes.h"
#include "kvm_range.h"
#include "guest_memory_layout.h"

enum {
  DAZE_KVM_RM_ENTRY_LINEAR = k_dpmi_rm_entry_linear,
  DAZE_KVM_RM_ENTRY_LOW_LINEAR = 0x2720,
  DAZE_KVM_RM_ENTRY_CONTROL = 0x5800,
  DAZE_KVM_RM_ENTRY_CONTROL_SIZE = 0x800,
  DAZE_KVM_RM_ENTRY_SIGNATURE = 0x44524d45,
};

static inline int daze_kvm_rm_entry_installed(const DazeKvmMachine *machine) {
  return machine != NULL && machine->guest != NULL &&
         daze_kvm_range_fits(machine->guest_size, DAZE_KVM_RM_ENTRY_CONTROL,
                             DAZE_KVM_RM_ENTRY_CONTROL_SIZE) &&
         daze_read_u32((const uint8_t *)machine->guest + DAZE_KVM_RM_ENTRY_CONTROL + 0x68) ==
           DAZE_KVM_RM_ENTRY_SIGNATURE;
}

static inline uint32_t daze_kvm_rm_entry_count(const DazeKvmMachine *machine) {
  return daze_kvm_rm_entry_installed(machine)
           ? daze_read_u32((const uint8_t *)machine->guest + DAZE_KVM_RM_ENTRY_CONTROL + 0x44)
           : 0;
}

static inline int daze_kvm_rm_entry_active(const DazeKvmMachine *machine) {
  return daze_kvm_rm_entry_installed(machine) &&
         daze_read_u32((const uint8_t *)machine->guest + DAZE_KVM_RM_ENTRY_CONTROL + 0x40) == 1;
}

static inline void daze_kvm_rm_entry_invalidate(DazeKvmMachine *machine) {
  if (daze_kvm_rm_entry_installed(machine))
    daze_write_u32((uint8_t *)machine->guest + DAZE_KVM_RM_ENTRY_CONTROL, 0);
}

static inline void daze_kvm_rm_entry_sync_metrics(DazeKvmMachine *machine) {
  if (machine != NULL && machine->run_metrics != NULL && machine->run_metrics->enabled) {
    machine->run_metrics->kvm_rm_procedure_native_calls += daze_kvm_rm_entry_count(machine);
    if (daze_kvm_rm_entry_installed(machine))
      daze_write_u32((uint8_t *)machine->guest + DAZE_KVM_RM_ENTRY_CONTROL + 0x44, 0);
  }
}

#endif
