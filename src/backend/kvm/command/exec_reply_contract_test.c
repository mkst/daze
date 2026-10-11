#include "owner.h"

#include "kvm_bytes.h"

#include <stdio.h>
#include <string.h>

#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
#include <linux/kvm.h>
#include <sys/ioctl.h>

int main(void) {
  enum { GUEST_SIZE = 0x10000, CODE = 0x1000, GATE = 0x1100 };
  DazeKvmMachine machine;
  const int init = daze_kvm_machine_init(&machine, GUEST_SIZE);
  if (init == DAZE_KVM_MACHINE_UNAVAILABLE) return 77;
  if (init != DAZE_KVM_MACHINE_OK) return 1;
  uint8_t *const guest = machine.guest;
  const uint8_t code[] = {0xcd, 0x21, 0xf4};
  const uint8_t gate[] = {0x50, 0xb0, 0x21, 0xe6, 0xf4, 0x83, 0xc4, 0x02, 0xcf};
  memcpy(guest + CODE, code, sizeof(code));
  memcpy(guest + GATE, gate, sizeof(gate));
  daze_write_u16(guest + 0x21 * 4u, 0);
  daze_write_u16(guest + 0x21 * 4u + 2, 0x0110);
  if (daze_kvm_machine_set_real_mode(&machine, 0x0100, 0, 0x0200, 0x0100, 0x0300, 0x0400) !=
      DAZE_KVM_MACHINE_OK) {
    daze_kvm_machine_destroy(&machine);
    return 1;
  }
  struct kvm_regs initial;
  if (ioctl(machine.vcpu, KVM_GET_REGS, &initial) < 0) {
    daze_kvm_machine_destroy(&machine);
    return 1;
  }
  initial.rax = 0x4b00;
  initial.rbx = 0x0102;
  initial.rcx = 0x0304;
  initial.rdx = 0x0506;
  initial.rsi = 0x0708;
  initial.rdi = 0x090a;
  initial.rflags |= 1;
  if (ioctl(machine.vcpu, KVM_SET_REGS, &initial) < 0) {
    daze_kvm_machine_destroy(&machine);
    return 1;
  }
  DazeKvmPortAccess access;
  const int parked = daze_kvm_machine_run_port_access(&machine, &access) == DAZE_KVM_MACHINE_OK &&
                     access.direction == DAZE_KVM_PORT_OUT && access.port == 0xf4 &&
                     access.value == 0x21;
  const int replied =
    parked &&
    daze_kvm_command_owner_reply_exec_success(&machine) == DAZE_KVM_RUNNER_GATE_RESUME_OK &&
    ioctl(machine.vcpu, KVM_RUN, 0) == 0 &&
    ((const struct kvm_run *)machine.run)->exit_reason == KVM_EXIT_HLT;
  struct kvm_regs regs;
  struct kvm_sregs sregs;
  const int valid =
    replied && ioctl(machine.vcpu, KVM_GET_REGS, &regs) == 0 &&
    ioctl(machine.vcpu, KVM_GET_SREGS, &sregs) == 0 && regs.rip == 3 && (uint16_t)regs.rax == 0 &&
    ((uint16_t)regs.rflags & 1u) == 0 && (uint16_t)regs.rbx == 0x0102 &&
    (uint16_t)regs.rcx == 0x0304 && (uint16_t)regs.rdx == 0x0506 && (uint16_t)regs.rsi == 0x0708 &&
    (uint16_t)regs.rdi == 0x090a && sregs.ds.selector == 0x0300 && sregs.es.selector == 0x0400;
  daze_kvm_machine_destroy(&machine);
  if (!valid) {
    fprintf(stderr, "KVM EXEC success reply contract failed parked=%d replied=%d\n", parked,
            replied);
    return 1;
  }
  return 0;
}
#else
int main(void) {
  return 77;
}
#endif
