#include "runner_resume.h"

#include "kvm_bytes.h"

#include <stdio.h>
#include <string.h>

#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
#include <linux/kvm.h>
#include <sys/ioctl.h>

static int frame_contract(uint16_t initial_sp, int restores_ax, int ax_only, int dpl_zero) {
  enum { GUEST_SIZE = 0x12000, CODE = 0x1000, GATE = 0x1100 };
  DazeKvmMachine machine;
  if (daze_kvm_machine_init(&machine, GUEST_SIZE) != DAZE_KVM_MACHINE_OK) return 0;
  if (dpl_zero == 2) machine.sync_regs_mask = 0;
  uint8_t *const guest = machine.guest;
  const uint8_t code[] = {
    0xcd,
    0x60, /* int 0x60 */
    0xf4, /* hlt */
  };
  const uint8_t gate[] = {
    0x50,             /* push ax */
    0xb0, 0x60,       /* mov al,0x60 */
    0xe6, 0xf4,       /* out 0xf4,al */
    0x83, 0xc4, 0x02, /* add sp,2 */
    0xcf,             /* iret */
  };
  memcpy(guest + CODE, code, sizeof(code));
  memcpy(guest + GATE, gate, sizeof(gate));
  if (restores_ax) {
    guest[GATE + 5] = 0x58;
    guest[GATE + 6] = 0xcf;
  }
  daze_write_u16(guest + 0x60 * 4u, 0);
  daze_write_u16(guest + 0x60 * 4u + 2, 0x0110);
  if (daze_kvm_machine_set_real_mode(&machine, 0x0100, 0, 0x0200, initial_sp, 0x0300, 0x0400) !=
      DAZE_KVM_MACHINE_OK) {
    daze_kvm_machine_destroy(&machine);
    return 0;
  }
  struct kvm_regs initial;
  struct kvm_sregs initial_sregs;
  if (dpl_zero && (ioctl(machine.vcpu, KVM_GET_SREGS, &initial_sregs) < 0)) {
    daze_kvm_machine_destroy(&machine);
    return 0;
  }
  if (dpl_zero) {
    initial_sregs.es.dpl = 0;
    if (ioctl(machine.vcpu, KVM_SET_SREGS, &initial_sregs) < 0) {
      daze_kvm_machine_destroy(&machine);
      return 0;
    }
  }
  if (ioctl(machine.vcpu, KVM_GET_REGS, &initial) < 0) {
    daze_kvm_machine_destroy(&machine);
    return 0;
  }
  initial.rax = UINT64_C(0x1234ab12);
  initial.rbx = 0x0102;
  initial.rcx = 0x0304;
  initial.rdx = 0x0506;
  initial.rsi = 0x0708;
  initial.rdi = 0x090a;
  if (ioctl(machine.vcpu, KVM_SET_REGS, &initial) < 0) {
    daze_kvm_machine_destroy(&machine);
    return 0;
  }
  DazeKvmPortAccess access;
  DazeKvmRunnerGateFrame frame;
  uint8_t reply[DAZE_KVM_RUNNER_GATE_REPLY_SIZE] = {0};
  daze_write_u16(reply, 0x1111);
  daze_write_u16(reply + 2, 0x2222);
  daze_write_u16(reply + 4, 0x3333);
  daze_write_u16(reply + 6, 0x4444);
  daze_write_u16(reply + 8, 0x5555);
  daze_write_u16(reply + 10, 0x6666);
  daze_write_u16(reply + 12, 0x0700);
  daze_write_u16(reply + 14, 0x0246);
  if (ax_only) {
    daze_write_u16(reply + 2, initial.rbx);
    daze_write_u16(reply + 4, initial.rcx);
    daze_write_u16(reply + 6, initial.rdx);
    daze_write_u16(reply + 8, initial.rsi);
    daze_write_u16(reply + 10, initial.rdi);
    daze_write_u16(reply + 12, 0x0400);
  }
  const int parked = daze_kvm_machine_run_port_access(&machine, &access) == DAZE_KVM_MACHINE_OK &&
                     access.direction == DAZE_KVM_PORT_OUT && access.port == 0xf4 &&
                     access.value == 0x60;
  const int captured = parked &&
                       daze_kvm_runner_gate_frame_capture(&machine, access.value, &frame) ==
                         DAZE_KVM_RUNNER_GATE_RESUME_OK &&
                       frame.vector == 0x60 && frame.ax == 0xab12 && frame.bx == 0x0102 &&
                       frame.cx == 0x0304 && frame.dx == 0x0506 && frame.si == 0x0708 &&
                       frame.di == 0x090a && frame.ds == 0x0300 && frame.es == 0x0400 &&
                       frame.return_cs == 0x0100 && frame.return_ip == 2 &&
                       frame.sp == (uint16_t)(initial_sp - 8);
  struct kvm_sregs parked_sregs = {0};
  const int replied =
    captured && ioctl(machine.vcpu, KVM_GET_SREGS, &parked_sregs) == 0 &&
    daze_kvm_runner_gate_frame_reply(&machine, &frame, reply) == DAZE_KVM_RUNNER_GATE_RESUME_OK &&
    ioctl(machine.vcpu, KVM_RUN, 0) == 0 &&
    ((const struct kvm_run *)machine.run)->exit_reason == KVM_EXIT_HLT;
  struct kvm_regs regs = {0};
  struct kvm_sregs sregs = {0};
  const int completed =
    replied && ioctl(machine.vcpu, KVM_GET_REGS, &regs) == 0 &&
    ioctl(machine.vcpu, KVM_GET_SREGS, &sregs) == 0 && regs.rip == 3 &&
    regs.rax == UINT64_C(0x12341111) && (uint16_t)regs.rbx == daze_read_u16(reply + 2) &&
    (uint16_t)regs.rcx == daze_read_u16(reply + 4) &&
    (uint16_t)regs.rdx == daze_read_u16(reply + 6) &&
    (uint16_t)regs.rsi == daze_read_u16(reply + 8) &&
    (uint16_t)regs.rdi == daze_read_u16(reply + 10) && sregs.ds.selector == 0x0300 &&
    sregs.es.selector == daze_read_u16(reply + 12) && (uint16_t)regs.rflags == 0x0246 &&
    (uint16_t)regs.rsp == initial_sp &&
    (!dpl_zero || memcmp(&sregs.es, &parked_sregs.es, sizeof(sregs.es)) == 0);
  if (!completed)
    fprintf(stderr,
            "ES reply sp=%04x restoring=%d ax-only=%d dpl-zero=%d exit=%u "
            "cs=%04x ip=%llx es=%04x base=%llx limit=%x dpl=%u flags=%llx\n",
            initial_sp, restores_ax, ax_only, dpl_zero,
            ((const struct kvm_run *)machine.run)->exit_reason, sregs.cs.selector,
            (unsigned long long)regs.rip, sregs.es.selector, (unsigned long long)sregs.es.base,
            sregs.es.limit, sregs.es.dpl, (unsigned long long)regs.rflags);
  daze_kvm_machine_destroy(&machine);
  return completed;
}
#else
static int frame_contract(uint16_t initial_sp, int restores_ax, int ax_only, int dpl_zero) {
  (void)initial_sp;
  (void)restores_ax;
  (void)ax_only;
  (void)dpl_zero;
  return 1;
}
#endif

int main(void) {
  enum { GUEST_SIZE = 0x10000, GATE = 0x1000, MAILBOX = 0x3000, STACK = 0x2100 };
  DazeKvmMachine machine;
  const int init = daze_kvm_machine_init(&machine, GUEST_SIZE);
  if (init == DAZE_KVM_MACHINE_UNAVAILABLE) return 77;
  if (init != DAZE_KVM_MACHINE_OK) return 1;
  uint8_t *guest = machine.guest;
  /* Save BP, restore the reply words, patch the existing IRET flags, and
   * execute IRET. HLT is caller-installed at the frame's successor. */
  const uint8_t gate[] = {
    0x55,                   /* push bp */
    0x89, 0xe5,             /* mov bp,sp */
    0xb8, 0x00, 0x03,       /* mov ax,0x300 */
    0x8e, 0xd8,             /* mov ds,ax */
    0x8b, 0x1e, 0x02, 0x00, /* mov bx,[0002h] */
    0x8b, 0x0e, 0x04, 0x00, /* mov cx,[0004h] */
    0x8b, 0x16, 0x06, 0x00, /* mov dx,[0006h] */
    0x8b, 0x36, 0x08, 0x00, /* mov si,[0008h] */
    0x8b, 0x3e, 0x0a, 0x00, /* mov di,[000ah] */
    0x8e, 0x06, 0x0c, 0x00, /* mov es,[000ch] */
    0xa1, 0x0e, 0x00,       /* mov ax,[000eh] */
    0x89, 0x46, 0x06,       /* mov [bp+6],ax */
    0xa1, 0x00, 0x00,       /* mov ax,[0000h] */
    0x5d,                   /* pop bp */
    0xcf,                   /* iret */
  };
  memcpy(guest + GATE, gate, sizeof(gate));
  guest[GATE + 0x80] = 0xf4;
  daze_write_u16(guest + STACK, 0x0080);
  daze_write_u16(guest + STACK + 2, 0x0100);
  daze_write_u16(guest + STACK + 4, 0x0202);
  if (daze_kvm_machine_set_real_mode(&machine, 0x0100, 0, 0x0200, 0x0100, 0, 0) !=
      DAZE_KVM_MACHINE_OK) {
    daze_kvm_machine_destroy(&machine);
    return 1;
  }
  const DazeKvmRunnerDpmiHandoff handoff = {.valid = 1};
  DazeKvmRunnerGateResumeInput input = {
    .machine = &machine, .handoff = &handoff, .mailbox_address = MAILBOX};
  daze_write_u16(input.reply, 0x1111);
  daze_write_u16(input.reply + 2, 0x2222);
  daze_write_u16(input.reply + 4, 0x3333);
  daze_write_u16(input.reply + 6, 0x4444);
  daze_write_u16(input.reply + 8, 0x5555);
  daze_write_u16(input.reply + 10, 0x6666);
  daze_write_u16(input.reply + 12, 0x0700);
  daze_write_u16(input.reply + 14, 0x0246);
  DazeKvmRunnerGateResumeResult result;
  int status = daze_kvm_runner_gate_resume_hlt(&input, &result);
  /* KVM may retain the architectural, fixed ET bit in real mode. */
  const int valid = status == DAZE_KVM_RUNNER_GATE_RESUME_OK && (result.cr0 & ~0x10u) == 0 &&
                    result.cs == 0x0100 && result.rip == 0x81 && result.ss == 0x0200 &&
                    result.sp == 0x0106 && result.ax == 0x1111 && result.bx == 0x2222 &&
                    result.cx == 0x3333 && result.dx == 0x4444 && result.si == 0x5555 &&
                    result.di == 0x6666 && result.es == 0x0700 && result.rflags == 0x246 &&
                    memcmp(guest + MAILBOX, input.reply, sizeof(input.reply)) == 0;
  if (!valid) {
    fprintf(stderr,
            "KVM gate resume initial state: status=%d cr0=%08x cs:ip=%04x:%x ss:sp=%04x:%04x "
            "ax=%04x bx=%04x cx=%04x dx=%04x si=%04x di=%04x es=%04x flags=%08x mailbox=%d\n",
            status, result.cr0, result.cs, result.rip, result.ss, result.sp, result.ax, result.bx,
            result.cx, result.dx, result.si, result.di, result.es, result.rflags,
            memcmp(guest + MAILBOX, input.reply, sizeof(input.reply)) == 0);
  }
  uint8_t before[DAZE_KVM_RUNNER_GATE_REPLY_SIZE];
  memcpy(before, guest + MAILBOX, sizeof(before));
  input.mailbox_address = GUEST_SIZE;
  status = daze_kvm_runner_gate_resume_hlt(&input, &result);
  const int invalid = status == DAZE_KVM_RUNNER_GATE_RESUME_INVALID &&
                      memcmp(guest + MAILBOX, before, sizeof(before)) == 0;
  daze_kvm_machine_destroy(&machine);
  const int frame_valid = frame_contract(0x0100, 0, 0, 0) && frame_contract(0, 0, 0, 0) &&
                          frame_contract(0x0100, 1, 0, 0) && frame_contract(0, 1, 0, 0) &&
                          frame_contract(0x0100, 1, 1, 0) && frame_contract(0, 1, 1, 0) &&
                          frame_contract(0x0100, 1, 1, 1) && frame_contract(0, 1, 1, 1) &&
                          frame_contract(0x0100, 1, 1, 2);
  if (!valid || !invalid || !frame_valid) {
    fprintf(stderr, "KVM runner gate resume contract failed valid=%d invalid=%d frame=%d\n", valid,
            invalid, frame_valid);
    return 1;
  }
  return 0;
}
