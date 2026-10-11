#include "machine.h"

#include <string.h>

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
