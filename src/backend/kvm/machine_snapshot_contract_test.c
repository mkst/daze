#include "machine.h"

#include <stdio.h>
#include <string.h>

static int restore_variants(DazeKvmMachine *machine, const DazeKvmMachineSnapshot *snapshot) {
  uint8_t *const guest = machine->guest;
  for (unsigned variant = 0; variant < 5; ++variant) {
    if (variant == 1) {
      guest[4095] ^= 1;
      guest[4096] ^= 2;
      guest[machine->guest_size - 1] ^= 4;
    } else if (variant == 2) {
      memset(guest, 0xa5, machine->guest_size);
    } else if (variant == 3) {
      memset(guest, 0, machine->guest_size);
    } else if (variant == 4) {
      for (size_t offset = 0; offset < machine->guest_size; offset += 8192)
        guest[offset] ^= 0xff;
    }
    const int status = daze_kvm_machine_snapshot_restore(machine, snapshot);
    if (status != DAZE_KVM_MACHINE_OK ||
        memcmp(guest, snapshot->guest_bytes, machine->guest_size) != 0) {
      fprintf(stderr, "snapshot restore variant=%u status=%d\n", variant, status);
      return 0;
    }
  }
  DazeKvmMachine partial = *machine;
  DazeKvmMachineSnapshot saved = *snapshot;
  partial.guest_size = saved.guest_size = 4096 + 17;
  guest[partial.guest_size - 1] ^= 0xff;
  guest[partial.guest_size] = 0x6d;
  const int status = daze_kvm_machine_snapshot_restore(&partial, &saved);
  if (status != DAZE_KVM_MACHINE_OK || memcmp(guest, saved.guest_bytes, partial.guest_size) != 0 ||
      guest[partial.guest_size] != 0x6d) {
    fprintf(stderr, "snapshot partial restore status=%d\n", status);
    return 0;
  }
  return daze_kvm_machine_snapshot_restore(machine, snapshot) == DAZE_KVM_MACHINE_OK &&
         memcmp(guest, snapshot->guest_bytes, machine->guest_size) == 0;
}

int main(void) {
  DazeKvmMachine machine;
  const int init = daze_kvm_machine_init(&machine, 0x10000);
  if (init == DAZE_KVM_MACHINE_UNAVAILABLE) return 77;
  if (init != DAZE_KVM_MACHINE_OK) return 1;
  uint8_t *guest = machine.guest;
  const uint8_t first[] = {
    0xb0, 0x11, /* mov al,0x11 */
    0xe6, 0xf4  /* out 0xf4,al */
  };
  const uint8_t second[] = {
    0xb0, 0x22, /* mov al,0x22 */
    0xe6, 0xf4  /* out 0xf4,al */
  };
  DazeKvmMachineSnapshot snapshot = {0};
  int result = 1;
  memcpy(guest, first, sizeof(first));
  memcpy(guest + 8, second, sizeof(second));
  if (daze_kvm_machine_set_real_mode(&machine, 0, 0, 0, 0xfffe, 0, 0) != DAZE_KVM_MACHINE_OK ||
      daze_kvm_machine_snapshot_take(&machine, &snapshot) != DAZE_KVM_MACHINE_OK) {
    goto out;
  }
  guest[0] = 0xf4;
  if (daze_kvm_machine_set_real_mode(&machine, 0, 8, 0, 0xfffe, 0, 0) != DAZE_KVM_MACHINE_OK ||
      daze_kvm_machine_snapshot_restore(&machine, &snapshot) != DAZE_KVM_MACHINE_OK) {
    goto out;
  }
  if (!restore_variants(&machine, &snapshot)) goto out;
  DazeKvmPortAccess access = {0};
  if (daze_kvm_machine_run_port_access(&machine, &access) == DAZE_KVM_MACHINE_OK &&
      access.direction == DAZE_KVM_PORT_OUT && access.port == 0xf4 && access.value == 0x11 &&
      guest[0] == first[0]) {
    result = 0;
  }
out:
  daze_kvm_machine_snapshot_dispose(&snapshot);
  daze_kvm_machine_destroy(&machine);
  return result;
}
