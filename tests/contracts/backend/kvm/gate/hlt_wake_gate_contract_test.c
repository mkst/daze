#include "entry.h"
#include "machine.h"
#include "runner_resume.h"

#include "kvm_bytes.h"

#include <stdio.h>
#include <string.h>

#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
#include <linux/kvm.h>
#include <sys/ioctl.h>

static int init_case_machine(DazeKvmMachine *machine) {
  const int status = daze_kvm_machine_init(machine, 0x40000);
  if (status == DAZE_KVM_MACHINE_OK) return 0;
  return status == DAZE_KVM_MACHINE_UNAVAILABLE ? -1 : 1;
}

/* Preinstalled IVT wake handler marks delivery and IRETs a gate-equivalent
 * frame into the transition. The initial gate frame instead lands at the HLT successor. */
static void install_wake_route(uint8_t *guest) {
  const uint8_t successor[] = {
    0x90, /* nop */
    0x90, /* nop */
    0xf4, /* hlt */
    0x90, /* nop */
    0x90, /* nop */
    0xf4  /* hlt */
  };
  /* mov si,0x3500; mov ax,0xeeee; mov [si],ax; push 0x0246; push 0x2200;
     push 0x0002; iret */
  const uint8_t handler[] = {0xbe, 0x00, 0x35, 0xb8, 0xee, 0xee, 0x89, 0x04, 0x68,
                             0x46, 0x02, 0x68, 0x00, 0x22, 0x68, 0x02, 0x00, 0xcf};
  daze_write_u16(guest + 0x00c0, 0x0000);
  daze_write_u16(guest + 0x00c2, 0x2500);
  memcpy(guest + 0x23000, successor, sizeof(successor));
  memcpy(guest + 0x25000, handler, sizeof(handler));
  guest[0x30000] = 0xcf;
  daze_write_u16(guest + 0x21100, 0x0000);
  daze_write_u16(guest + 0x21102, 0x2300);
  daze_write_u16(guest + 0x21104, 0x0246);
}

static void install_gate_successor_frame(uint8_t *guest) {
  daze_write_u16(guest + 0x21100, 0x0000);
  daze_write_u16(guest + 0x21102, 0x2300);
  daze_write_u16(guest + 0x21104, 0x0246);
}

static const DazeKvmRunnerDpmiHandoff handoff = {.valid = 1,
                                                 .ax = 0x1111,
                                                 .bx = 0x2222,
                                                 .cx = 0x3333,
                                                 .dx = 0x4444,
                                                 .si = 0x5555,
                                                 .di = 0x6666,
                                                 .es = 0x0700,
                                                 .flags = 0x0246};

/* Guest wake delivery must re-present the gate on the same vCPU and reach a protected terminal. */
static int run_wake_probe_case(void) {
  DazeKvmMachine machine;
  const int init = init_case_machine(&machine);
  if (init != 0) return init;
  uint8_t *guest = machine.guest;
  install_wake_route(guest);

  uint8_t gdt[16] = {0};
  gdt[8] = 0xff;
  gdt[9] = 0xff;
  gdt[10] = 0x00;
  gdt[11] = 0x20;
  gdt[12] = 0x02;
  gdt[13] = 0x9a;
  const uint8_t gdtr[] = {0x0f, 0x00, 0x00, 0x10, 0x00, 0x00};
  const uint8_t transition[] = {
    0x90,                               /* nop */
    0x90,                               /* nop */
    0x2e, 0x0f, 0x01, 0x16, 0x80, 0x00, /* lgdt cs:[0x80] */
    0x0f, 0x20, 0xc0,                   /* mov eax,cr0 */
    0x66, 0x83, 0xc8, 0x01,             /* or eax,0x1 */
    0x0f, 0x22, 0xc0,                   /* mov cr0,eax */
    0xea, 0x20, 0x00, 0x08, 0x00,       /* jmp far 0x8:0x20 */
  };
  memcpy(guest + 0x1000, gdt, sizeof(gdt));
  memcpy(guest + 0x22000, transition, sizeof(transition));
  memcpy(guest + 0x22080, gdtr, sizeof(gdtr));
  memset(guest + 0x22020, 0x90, 0x0f);
  guest[0x2202f] = 0xf4;

  int fail = 0;
  if (daze_kvm_machine_set_real_mode(&machine, 0x3000, 0, 0x2100, 0x0100, 0, 0) !=
      DAZE_KVM_MACHINE_OK)
    fail = 1;
  DazeKvmRunnerGateResumeResult resume;
  DazeKvmRunnerGateResumeInput in = {
    .machine = &machine, .handoff = &handoff, .mailbox_address = 0x3f020};
  memset(in.reply, 0, sizeof(in.reply));
  if (!fail && daze_kvm_runner_gate_resume_hlt(&in, &resume) != DAZE_KVM_RUNNER_GATE_RESUME_OK) {
    fprintf(stderr, "wake probe: gate-resume HLT successor not reached\n");
    fail = 1;
  }

  struct kvm_interrupt intr = {.irq = 0x30};
  if (!fail && ioctl(machine.vcpu, KVM_INTERRUPT, &intr) < 0) {
    fprintf(stderr, "wake probe: KVM_INTERRUPT failed\n");
    fail = 1;
  }
  if (!fail && ioctl(machine.vcpu, KVM_RUN, 0) < 0) {
    fprintf(stderr, "wake probe: wake KVM_RUN failed\n");
    fail = 1;
  }
  const struct kvm_run *run = (const struct kvm_run *)machine.run;
  if (!fail && run->exit_reason != KVM_EXIT_HLT) {
    fprintf(stderr, "wake probe: terminal exit=%d not HLT\n", run->exit_reason);
    fail = 1;
  }
  if (!fail && *(uint16_t *)(guest + 0x3500) != 0xeeee) {
    fprintf(stderr, "wake probe: IVT handler marker missing\n");
    fail = 1;
  }
  struct kvm_regs regs;
  struct kvm_sregs sregs;
  if (!fail && (ioctl(machine.vcpu, KVM_GET_REGS, &regs) < 0 ||
                ioctl(machine.vcpu, KVM_GET_SREGS, &sregs) < 0)) {
    fprintf(stderr, "wake probe: register read failed\n");
    fail = 1;
  }
  if (!fail && ((sregs.cr0 & 1u) == 0 || sregs.cs.selector != 8 || regs.rip != 0x30)) {
    fprintf(stderr, "wake probe: protected terminal state cr0=%llx cs=%x rip=%llx\n",
            (unsigned long long)sregs.cr0, sregs.cs.selector, (unsigned long long)regs.rip);
    fail = 1;
  }
  daze_kvm_machine_destroy(&machine);
  return fail;
}

/* Use a byte-distinct protected terminal. The IVT marker must change during
 * the single wake/entry run, ruling out accidental direct entry without wake delivery. */
static int run_entry_after_wake_case(void) {
  DazeKvmMachine machine;
  const int init = init_case_machine(&machine);
  if (init != 0) return init;
  uint8_t *guest = machine.guest;
  install_wake_route(guest);
  install_gate_successor_frame(guest);

  uint8_t gdt[16] = {0};
  gdt[8] = 0xff;
  gdt[9] = 0xff;
  gdt[10] = 0x00;
  gdt[11] = 0x40;
  gdt[12] = 0x02;
  gdt[13] = 0x9a;
  const uint8_t gdtr[] = {0x0f, 0x00, 0x00, 0x10, 0x00, 0x00};
  const uint8_t transition[] = {
    0x90,                               /* nop */
    0x90,                               /* nop */
    0x2e, 0x0f, 0x01, 0x16, 0x80, 0x00, /* lgdt cs:[0x80] */
    0x0f, 0x20, 0xc0,                   /* mov eax,cr0 */
    0x66, 0x83, 0xc8, 0x01,             /* or eax,0x1 */
    0x0f, 0x22, 0xc0,                   /* mov cr0,eax */
    0xea, 0x20, 0x00, 0x08, 0x00,       /* jmp far 0x8:0x20 */
  };
  const uint8_t terminal[] = {
    0x90 /* nop */
  };
  const DazeKvmGuestWrite writes[] = {
    {0x1000, gdt, sizeof(gdt)},
    {0x22000, transition, sizeof(transition)},
    {0x22080, gdtr, sizeof(gdtr)},
    {0x24020, terminal, sizeof(terminal)},
  };

  int fail = 0;
  if (daze_kvm_machine_set_real_mode(&machine, 0x3000, 0, 0x2100, 0x0100, 0, 0) !=
      DAZE_KVM_MACHINE_OK)
    fail = 1;
  DazeKvmRunnerGateResumeResult resume;
  DazeKvmRunnerGateResumeInput in = {
    .machine = &machine, .handoff = &handoff, .mailbox_address = 0x3f020};
  memset(in.reply, 0, sizeof(in.reply));
  if (!fail && daze_kvm_runner_gate_resume_hlt(&in, &resume) != DAZE_KVM_RUNNER_GATE_RESUME_OK) {
    fprintf(stderr, "entry-after-wake: gate-resume HLT successor not reached\n");
    fail = 1;
  }

  struct kvm_interrupt intr = {.irq = 0x30};
  if (!fail && ioctl(machine.vcpu, KVM_INTERRUPT, &intr) < 0) {
    fprintf(stderr, "entry-after-wake: KVM_INTERRUPT failed\n");
    fail = 1;
  }

  const uint16_t marker_before = *(uint16_t *)(guest + 0x3500);
  DazeKvmDpmiEntryResult entry_result;
  if (!fail) {
    const DazeKvmDpmiEntryLayout layout = {
      .writes = writes, .write_count = 4, .mailbox_address = 0x3f080, .terminal_linear = 0x24020};
    const int status = daze_kvm_dpmi_entry_run(&machine, &handoff, &layout, &entry_result);
    if (status != DAZE_KVM_DPMI_ENTRY_OK) {
      fprintf(stderr, "entry-after-wake: entry status=%d\n", status);
      fail = 1;
    }
  }
  if (!fail && ((entry_result.cr0 & 1u) == 0 || entry_result.cs != 8 || entry_result.rip != 0x20)) {
    fprintf(stderr, "entry-after-wake: entry state cr0=%x cs=%x rip=%x\n", entry_result.cr0,
            entry_result.cs, entry_result.rip);
    fail = 1;
  }
  const uint16_t marker_after = *(uint16_t *)(guest + 0x3500);
  if (!fail && (marker_before != 0x0000 || marker_after != 0xeeee)) {
    fprintf(stderr, "entry-after-wake: IVT handler marker before=%04x after=%04x\n", marker_before,
            marker_after);
    fail = 1;
  }
  daze_kvm_machine_destroy(&machine);
  return fail;
}

#if !(defined(__linux__) && (defined(__x86_64__) || defined(__i386__)))
static int run_wake_probe_case(void) {
  return -1;
}
static int run_entry_after_wake_case(void) {
  return -1;
}
#endif

int main(void) {
  const int a = run_wake_probe_case();
  const int b = run_entry_after_wake_case();
  if (a < 0 || b < 0) return 1;
  if (a > 0 || b > 0) return 1;
  return 0;
}
#else
int main(void) {
  return 77;
}
#endif
