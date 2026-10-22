#include "machine.h"
#include "image.h"
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
  (void)argv;
  DazeKvmMachine m;
  if (argc > 1) {
    return daze_kvm_machine_init(&m, 0) == DAZE_KVM_MACHINE_INVALID ? 0 : 1;
  }
  int s = daze_kvm_machine_init(&m, 0x10000);
  if (s == 77) return 77;
  if (s) return 1;
  int image = daze_image_write_process_with_memory(daze_kvm_machine_write, &m, "", "ASPSX.EXE",
                                                   0xff0, 0x700, 0x200, 0x300, NULL, 0);
  uint8_t *p = m.guest;
  int ok = image && p[0x2000] == 0xcd && p[0x2001] == 0xfe && p[0x2002] == 0xf4;
  /* The gate must observe a 1-byte IN, accept the caller's byte, and resume to
   * the following OUT without losing the guest store. */
  p[0] = 0xe4;
  p[1] = 0x21;
  p[2] = 0xa2;
  p[3] = 0x00;
  p[4] = 0x30;
  p[5] = 0xb0;
  p[6] = 0x5a;
  p[7] = 0xe6;
  p[8] = 0xf4;
  p[9] = 0xf4;
  DazeKvmPortAccess access = {0};
  int in_ok = daze_kvm_machine_set_real_mode(&m, 0, 0, 0, 0x8000, 0, 0) == DAZE_KVM_MACHINE_OK &&
              daze_kvm_machine_run_port_access(&m, &access) == DAZE_KVM_MACHINE_OK &&
              access.direction == DAZE_KVM_PORT_IN && access.port == 0x21 &&
              daze_kvm_machine_supply_port_in(&m, 0) == DAZE_KVM_MACHINE_OK &&
              daze_kvm_machine_run_port_access(&m, &access) == DAZE_KVM_MACHINE_OK &&
              access.direction == DAZE_KVM_PORT_OUT && access.port == 0xf4 &&
              access.value == 0x5a && p[0x3000] == 0;
  ok = ok && in_ok;
  daze_kvm_machine_destroy(&m);
  fprintf(stderr, "KVM machine contract: %s\n", ok ? "passed" : "failed");
  return ok ? 0 : 1;
}
