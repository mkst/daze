#ifndef DAZE_KVM_WRITE_BATCH_H
#define DAZE_KVM_WRITE_BATCH_H

#include "machine.h"
#include "file_service.h"
#include "guest_memory_layout.h"
#include "kvm_range.h"
#include "kvm_bytes.h"

static inline int daze_kvm_write_batch_pending(const DazeKvmMachine *machine) {
  return machine != NULL && machine->write_batch_installed && machine->guest != NULL &&
         daze_kvm_range_fits(machine->guest_size, k_kvm_write_batch_control, 0x40) &&
         (daze_read_u16((const uint8_t *)machine->guest + k_kvm_write_batch_control + 4) != 0 ||
          daze_read_u32((const uint8_t *)machine->guest + k_kvm_write_batch_control + 8) != 0);
}

static inline void daze_kvm_write_batch_revoke(DazeKvmMachine *machine) {
  if (machine != NULL) {
    machine->write_batch_credit = 0;
    if (machine->write_batch_installed && machine->guest != NULL &&
        daze_kvm_range_fits(machine->guest_size, k_kvm_write_batch_control, 2))
      daze_write_u16((uint8_t *)machine->guest + k_kvm_write_batch_control, 0);
  }
}

/* The owner drains before host handle/mode changes, snapshots and guest-memory teardown. */
int daze_kvm_write_batch_drain(DazeKvmMachine *machine, DazeDosfsFileService *files);
void daze_kvm_write_batch_arm(DazeKvmMachine *machine, DazeDosfsFileService *files,
                              const uint8_t record[24], const uint8_t reply[16]);

#endif
