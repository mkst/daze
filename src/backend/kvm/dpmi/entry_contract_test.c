#include "entry.h"

#include "kvm_bytes.h"
#include "mediator.h"
#include "protected.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
#include <linux/kvm.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>

static int init_case_machine(DazeKvmMachine *machine) {
  const int status = daze_kvm_machine_init(machine, 0x40000);
  if (status == DAZE_KVM_MACHINE_OK) return 0;
  return status == DAZE_KVM_MACHINE_UNAVAILABLE ? -1 : 1;
}

static void place_gate(uint8_t *guest) {
  const uint32_t stack = 0x21000 + 0x0100;
  daze_write_u16(guest + stack, 0x0002);
  daze_write_u16(guest + stack + 2, 0x2200);
  daze_write_u16(guest + stack + 4, 0x0002);
  guest[0x30000] = 0xcf;
}

static int position_real_mode(DazeKvmMachine *machine) {
  return daze_kvm_machine_set_real_mode(machine, 0x3000, 0, 0x2100, 0x0100, 0x3000, 0x1543) ==
         DAZE_KVM_MACHINE_OK;
}

static const DazeKvmRunnerDpmiHandoff handoff = {
  .valid = 1, .ax = 1, .bx = 2, .cx = 3, .dx = 4, .si = 5, .di = 6, .es = 0x1543, .flags = 2};

static int run_matching_success_case(void) {
  DazeKvmMachine machine;
  const int init = init_case_machine(&machine);
  if (init != 0) return init;
  DazeRunMetrics metrics = {.enabled = 1};
  machine.run_metrics = &metrics;
  uint8_t *guest = machine.guest;
  place_gate(guest);
  uint8_t gdt[16] = {0};
  gdt[8] = 0xff;
  gdt[9] = 0xff;
  gdt[10] = 0x00;
  gdt[11] = 0x20;
  gdt[12] = 0x02;
  gdt[13] = 0x9a;
  const uint8_t gdtr[] = {0x0f, 0x00, 0x00, 0x10, 0x00, 0x00};
  const uint8_t transition[] = {
    0x90, 0x90,                         /* nop; nop */
    0x2e, 0x0f, 0x01, 0x16, 0x80, 0x00, /* lgdt cs:[0x80] */
    0x0f, 0x20, 0xc0,                   /* mov eax,cr0 */
    0x66, 0x83, 0xc8, 0x01,             /* or eax,0x1 */
    0x0f, 0x22, 0xc0,                   /* mov cr0,eax */
    0xea, 0x20, 0x00, 0x08, 0x00,       /* jmp far 0x08:0x20 */
  };
  const uint8_t terminal[] = {0x90, 0xf4}; /* nop; hlt */
  const DazeKvmGuestWrite writes[] = {
    {0x1000, gdt, sizeof(gdt)},
    {0x22000, transition, sizeof(transition)},
    {0x22080, gdtr, sizeof(gdtr)},
    {0x22020, terminal, sizeof(terminal)},
  };
  int fail = 0;
  if (!position_real_mode(&machine)) fail = 1;
  DazeKvmDpmiEntryResult result;
  const int status = daze_kvm_dpmi_entry_run(
    &machine, &handoff,
    &(DazeKvmDpmiEntryLayout){
      .writes = writes, .write_count = 4, .mailbox_address = 0x3f020, .terminal_linear = 0x22020},
    &result);
  if (status != DAZE_KVM_DPMI_ENTRY_OK || (result.cr0 & 1u) == 0 || result.cs != 8 ||
      result.rip != 0x20 || result.observation.kind != DAZE_KVM_DPMI_ENTRY_EXIT_MATCHING_DEBUG ||
      result.observation.raw_exit_reason != KVM_EXIT_DEBUG || result.observation.clear_error != 0) {
    fprintf(stderr, "matching case failed status=%d cr0=%x cs:ip=%04x:%x\n", status, result.cr0,
            result.cs, result.rip);
    fail = 1;
  }
  if (!fail && (daze_kvm_dpmi_entry_continue_once(&machine, &result) != DAZE_KVM_DPMI_ENTRY_OK ||
                result.observation.kind != DAZE_KVM_DPMI_ENTRY_EXIT_HLT ||
                result.observation.raw_exit_reason != KVM_EXIT_HLT || result.cs != 8 ||
                result.rip != 0x22)) {
    fprintf(stderr, "continuation case failed exit=%d cs:ip=%04x:%x\n", result.observation.kind,
            result.cs, result.rip);
    fail = 1;
  }
  fail |= metrics.kvm_dpmi_debug_update_calls != 2 ||
          metrics.kvm_dpmi_run_calls[DAZE_RUN_METRICS_DPMI_RUN_ENTRY] != 1 ||
          metrics.kvm_dpmi_run_calls[DAZE_RUN_METRICS_DPMI_RUN_CONTINUE_ONCE] != 1;
  daze_kvm_machine_destroy(&machine);
  return fail;
}

static int run_unexpected_hlt_case(void) {
  DazeKvmMachine machine;
  const int init = init_case_machine(&machine);
  if (init != 0) return init;
  uint8_t *guest = machine.guest;
  place_gate(guest);
  const uint8_t code[] = {0x90, 0x90, 0xf4}; /* nop; nop; hlt */
  const DazeKvmGuestWrite writes[] = {{0x22000, code, sizeof(code)}};
  int fail = 0;
  if (!position_real_mode(&machine)) fail = 1;
  DazeKvmDpmiEntryResult result;
  const int status = daze_kvm_dpmi_entry_run(
    &machine, &handoff,
    &(DazeKvmDpmiEntryLayout){
      .writes = writes, .write_count = 1, .mailbox_address = 0x3f020, .terminal_linear = 0x22020},
    &result);
  if (status != DAZE_KVM_DPMI_ENTRY_FAILED || result.rip != 0 || result.cs != 0 ||
      result.observation.kind != DAZE_KVM_DPMI_ENTRY_EXIT_UNEXPECTED_HLT ||
      result.observation.raw_exit_reason != KVM_EXIT_HLT || result.observation.clear_error != 0) {
    fprintf(stderr, "unexpected HLT case failed status=%d rip=%x cs=%x\n", status, result.rip,
            result.cs);
    fail = 1;
  }
  if (!fail) {
    memset(guest + 0x22000, 0x90, 0x23);
    guest[0x22023] = 0xf4;
    if (ioctl(machine.vcpu, KVM_RUN, 0) < 0 ||
        ((const struct kvm_run *)machine.run)->exit_reason != KVM_EXIT_HLT) {
      fprintf(stderr, "unexpected-HLT clear not proven: guest did not reach HLT\n");
      fail = 1;
    }
  }
  daze_kvm_machine_destroy(&machine);
  return fail;
}

static int run_unexpected_pio_case(void) {
  DazeKvmMachine machine;
  const int init = init_case_machine(&machine);
  if (init != 0) return init;
  uint8_t *guest = machine.guest;
  place_gate(guest);
  const uint8_t code[] = {0x90, 0x90, 0xb0, 0xa5, 0xe6, 0xf4, 0xf4};
  const DazeKvmGuestWrite writes[] = {{0x22000, code, sizeof(code)}};
  int fail = 0;
  if (!position_real_mode(&machine)) fail = 1;
  DazeKvmDpmiEntryResult result;
  const int status = daze_kvm_dpmi_entry_run(
    &machine, &handoff,
    &(DazeKvmDpmiEntryLayout){
      .writes = writes, .write_count = 1, .mailbox_address = 0x3f020, .terminal_linear = 0x22020},
    &result);
  if (status != DAZE_KVM_DPMI_ENTRY_FAILED ||
      result.observation.kind != DAZE_KVM_DPMI_ENTRY_EXIT_UNEXPECTED_PIO ||
      result.observation.raw_exit_reason != KVM_EXIT_IO || result.observation.pio_port != 0xf4 ||
      result.observation.pio_direction != DAZE_KVM_DPMI_ENTRY_PIO_OUT ||
      result.observation.pio_size != 1 || result.observation.pio_count != 1 ||
      !result.observation.pio_value_present || result.observation.pio_value != 0xa5 ||
      result.observation.clear_error != 0) {
    fprintf(stderr, "unexpected PIO case failed status=%d kind=%d exit=%u port=%x value=%x\n",
            status, result.observation.kind, result.observation.raw_exit_reason,
            result.observation.pio_port, result.observation.pio_value);
    fail = 1;
  }
  daze_kvm_machine_destroy(&machine);
  return fail;
}

/* Synthetic execution of the generated gate, stopped before the first
 * post-IRET client instruction to check mailbox EAX and carry-only flag changes. */
#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
static int run_gate_post_iret_contract(void) {
  DazeKvmMachine machine;
  const int init = init_case_machine(&machine);
  if (init != 0) return init;
  uint8_t *guest = machine.guest;
  int fail = 0;
  place_gate(guest);
  /* The synthetic client CS has base 22000h; the generated handler needs valid
   * data descriptors for ES and FS. IDT placement is a linear address, not a selector. */
  uint8_t gdt[0x108] = {0};
  gdt[8] = 0xff;
  gdt[9] = 0xff;
  gdt[10] = 0x00;
  gdt[11] = 0x20;
  gdt[12] = 0x02;
  gdt[13] = 0x9a;
  gdt[14] = 0xc0;
  gdt[0x20] = 0xff;
  gdt[0x21] = 0xff;
  gdt[0x25] = 0x92;
  gdt[0x26] = 0xc0;
  const uint8_t gdtr[] = {0x3f, 0x00, 0x00, 0x10, 0x00, 0x00};
  const uint8_t transition[] = {
    0x90, 0x90,                         /* nop; nop */
    0x2e, 0x0f, 0x01, 0x16, 0x80, 0x00, /* lgdt cs:[0x80] */
    0x0f, 0x20, 0xc0,                   /* mov eax,cr0 */
    0x66, 0x83, 0xc8, 0x01,             /* or eax,0x1 */
    0x0f, 0x22, 0xc0,                   /* mov cr0,eax */
    0xea, 0x20, 0x00, 0x08, 0x00,       /* jmp far 0x08:0x20 */
  };
  const uint8_t previous_terminal[] = {0x90, 0xf4}; /* nop; hlt */
  const DazeKvmGuestWrite writes[] = {
    {0x1000, gdt, sizeof(gdt)},
    {0x22000, transition, sizeof(transition)},
    {0x22080, gdtr, sizeof(gdtr)},
    {0x22020, previous_terminal, sizeof(previous_terminal)},
  };
  if (!position_real_mode(&machine)) fail = 1;
  DazeKvmDpmiEntryResult result;
  if (!fail && daze_kvm_dpmi_entry_run(&machine, &handoff,
                                       &(DazeKvmDpmiEntryLayout){
                                         .writes = writes,
                                         .write_count = 4,
                                         .mailbox_address = 0x3f020,
                                         .terminal_linear = 0x22020,
                                       },
                                       &result) != DAZE_KVM_DPMI_ENTRY_OK) {
    fprintf(stderr, "post-iret contract: entry not at client int31\n");
    fail = 1;
  }
  if (!fail && (result.cs != 8 || result.rip != 0x20)) {
    fprintf(stderr, "post-iret contract: client not parked at 8:0020 (got %04x:%x)\n", result.cs,
            result.rip);
    fail = 1;
  }
  if (fail) {
    daze_kvm_machine_destroy(&machine);
    return fail;
  }
  const uint8_t client[] = {0xcd, 0x31, 0x90, 0xf4}; /* int 31h; nop; hlt */
  memcpy(guest + 0x22020, client, sizeof(client));
  const DazeKvmProtectedGateLayout gate = {
    .idt_address = 0x10000,
    .idt_limit = 0x3ff,
    .handler_address = 0x18000,
    .dos_handler_address = 0x18100,
    .default_dos_stub_address = 0x181c8,
    .record_address = 0x3e000,
    .mailbox_address = 0x3f020,
    .handler_selector = 0x8,
    .handler_data_selector = 0x20,
    .interrupt_gate_type = 0x8e,
    .exchange_limit = 1,
  };
  DazeKvmProtectedGateArtifacts artifacts;
  if (!daze_kvm_protected_gate_build(&gate, &artifacts)) {
    fprintf(stderr, "post-iret contract: cannot build production gate\n");
    fail = 1;
  } else {
    /* The built IDT offset is the raw handler linear; with CS base 0x22000
     * the handler bytes go to guest[cs_base + handler_address]. */
    memcpy(guest + result.cs_base + gate.handler_address, artifacts.handler,
           artifacts.handler_size);
    memcpy(guest + gate.idt_address + 0x31 * 8, artifacts.idt_entry, sizeof(artifacts.idt_entry));
    uint8_t *mailbox = guest + gate.mailbox_address;
    daze_write_u32(mailbox + 0, 0x0301);
    daze_write_u32(mailbox + 4, 0);
    daze_write_u32(mailbox + 8, 0);
    daze_write_u32(mailbox + 12, 0);
    daze_write_u32(mailbox + 16, 0);
    daze_write_u32(mailbox + 20, 0x20);
    daze_write_u32(mailbox + 24, 0);
    daze_write_u32(mailbox + 28, 2);
    struct kvm_regs regs;
    struct kvm_sregs sregs;
    if (ioctl(machine.vcpu, KVM_GET_REGS, &regs) < 0 ||
        ioctl(machine.vcpu, KVM_GET_SREGS, &sregs) < 0) {
      fprintf(stderr, "post-iret contract: cannot capture client state\n");
      fail = 1;
    } else {
      regs.rflags = 0x0242;
      regs.rsp = 0x1f00;
      sregs.idt.base = gate.idt_address;
      sregs.idt.limit = gate.idt_limit;
      const struct kvm_segment flat = {.selector = 0x20,
                                       .base = 0,
                                       .limit = 0xfffff,
                                       .type = 3,
                                       .present = 1,
                                       .dpl = 0,
                                       .db = 1,
                                       .s = 1,
                                       .g = 1};
      sregs.ss = sregs.ds = sregs.es = sregs.gs = flat;
      sregs.fs = flat;
      sregs.fs.type = 2;
      if (ioctl(machine.vcpu, KVM_SET_REGS, &regs) < 0 ||
          ioctl(machine.vcpu, KVM_SET_SREGS, &sregs) < 0) {
        fprintf(stderr, "post-iret contract: cannot arm client state\n");
        fail = 1;
      } else {
        DazeKvmDpmiEntryResult step;
        for (int tries = 0; tries < 8; ++tries) {
          const int status = daze_kvm_dpmi_entry_continue_to_linear(&machine, 0x22022, &step);
          if (status == DAZE_KVM_DPMI_ENTRY_OK &&
              step.observation.kind == DAZE_KVM_DPMI_ENTRY_EXIT_MATCHING_DEBUG &&
              step.rip == 0x22 && step.cs == 8) {
            if (step.ax != 0x0301)
              fprintf(stderr, "post-iret contract: EAX delivered 0x%04x\n", step.ax), fail = 1;
            if ((step.rflags & 1u) != 0)
              fprintf(stderr, "post-iret contract: carry not cleared\n"), fail = 1;
            if ((step.rflags & 0x40u) == 0)
              fprintf(stderr, "post-iret contract: ZF lost\n"), fail = 1;
            if ((step.rflags & 0x200u) == 0)
              fprintf(stderr, "post-iret contract: IF lost\n"), fail = 1;
            if (step.instruction[0] != 0x90)
              fprintf(stderr, "post-iret contract: first client instruction not nop\n"), fail = 1;
            if (!fail)
              fprintf(stderr, "post-iret contract: ok ax=%04x rflags=%08x ip=%x\n", step.ax,
                      step.rflags, step.rip);
            break;
          }
          const DazeKvmDpmiEntryObservation *obs = &step.observation;
          /* continue_to_linear arms no PIO tolerance, so the gate handler's
           * mediator marker surfaces as an "unexpected" PIO boundary. Resume
           * over it exactly like the production owner's mediator PIO check. */
          const int mediator_pio = obs->kind == DAZE_KVM_DPMI_ENTRY_EXIT_PIO ||
                                   obs->kind == DAZE_KVM_DPMI_ENTRY_EXIT_UNEXPECTED_PIO;
          if (status == DAZE_KVM_DPMI_ENTRY_FAILED && mediator_pio &&
              obs->pio_direction == DAZE_KVM_DPMI_ENTRY_PIO_OUT && obs->pio_size == 1 &&
              obs->pio_count == 1 && obs->pio_value_present && obs->pio_port == 0xf4 &&
              (uint8_t)obs->pio_value == 0x31) {
            continue;
          }
          fprintf(stderr, "post-iret contract: unexpected boundary status=%d kind=%d raw=%u\n",
                  status, step.observation.kind, step.observation.raw_exit_reason);
          fail = 1;
          break;
        }
      }
    }
  }
  daze_kvm_machine_destroy(&machine);
  return fail;
}
#endif

#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
/* Park the generated gate at its mediator OUT, restore captured regs/sregs,
 * and check whether continuation replays the marker or completes mailbox/IRET
 * delivery. This synthetic witness is independent of fixture bytes. */
static int run_parked_pio_resume_contract(void) {
  DazeKvmMachine machine;
  const int init = init_case_machine(&machine);
  if (init != 0) return init;
  uint8_t *guest = machine.guest;
  int fail = 0;
  place_gate(guest);
  uint8_t gdt[0x108] = {0};
  gdt[8] = 0xff;
  gdt[9] = 0xff;
  gdt[10] = 0x00;
  gdt[11] = 0x20;
  gdt[12] = 0x02;
  gdt[13] = 0x9a;
  gdt[14] = 0xc0;
  gdt[0x20] = 0xff;
  gdt[0x21] = 0xff;
  gdt[0x25] = 0x92;
  gdt[0x26] = 0xc0;
  const uint8_t gdtr[] = {0x3f, 0x00, 0x00, 0x10, 0x00, 0x00};
  const uint8_t transition[] = {
    0x90, 0x90,                         /* nop; nop */
    0x2e, 0x0f, 0x01, 0x16, 0x80, 0x00, /* lgdt cs:[0x80] */
    0x0f, 0x20, 0xc0,                   /* mov eax,cr0 */
    0x66, 0x83, 0xc8, 0x01,             /* or eax,0x1 */
    0x0f, 0x22, 0xc0,                   /* mov cr0,eax */
    0xea, 0x20, 0x00, 0x08, 0x00,       /* jmp far 0x08:0x20 */
  };
  const uint8_t previous_terminal[] = {0x90, 0xf4}; /* nop; hlt */
  const DazeKvmGuestWrite writes[] = {
    {0x1000, gdt, sizeof(gdt)},
    {0x22000, transition, sizeof(transition)},
    {0x22080, gdtr, sizeof(gdtr)},
    {0x22020, previous_terminal, sizeof(previous_terminal)},
  };
  if (!position_real_mode(&machine)) fail = 1;
  DazeKvmDpmiEntryResult result;
  if (!fail && daze_kvm_dpmi_entry_run(&machine, &handoff,
                                       &(DazeKvmDpmiEntryLayout){
                                         .writes = writes,
                                         .write_count = 4,
                                         .mailbox_address = 0x3f020,
                                         .terminal_linear = 0x22020,
                                       },
                                       &result) != DAZE_KVM_DPMI_ENTRY_OK) {
    fprintf(stderr, "parked-pio resume: entry not at client int31\n");
    fail = 1;
  }
  if (!fail && (result.cs != 8 || result.rip != 0x20)) {
    fprintf(stderr, "parked-pio resume: client not parked at 8:0020 (got %04x:%x)\n", result.cs,
            result.rip);
    fail = 1;
  }
  if (fail) {
    daze_kvm_machine_destroy(&machine);
    return fail;
  }
  const uint8_t client[] = {0xcd, 0x31, 0x90, 0xf4}; /* int 31h; nop; hlt */
  memcpy(guest + 0x22020, client, sizeof(client));
  const DazeKvmProtectedGateLayout gate = {
    .idt_address = 0x10000,
    .idt_limit = 0x3ff,
    .handler_address = 0x18000,
    .dos_handler_address = 0x18100,
    .default_dos_stub_address = 0x181c8,
    .record_address = 0x3e000,
    .mailbox_address = 0x3f020,
    .handler_selector = 0x8,
    .handler_data_selector = 0x20,
    .interrupt_gate_type = 0x8e,
    .exchange_limit = 1,
  };
  DazeKvmProtectedGateArtifacts artifacts;
  if (!daze_kvm_protected_gate_build(&gate, &artifacts)) {
    fprintf(stderr, "parked-pio resume: cannot build production gate\n");
    fail = 1;
  }
  if (!fail) {
    memcpy(guest + result.cs_base + gate.handler_address, artifacts.handler,
           artifacts.handler_size);
    memcpy(guest + gate.idt_address + 0x31 * 8, artifacts.idt_entry, sizeof(artifacts.idt_entry));
    uint8_t *mailbox = guest + gate.mailbox_address;
    daze_write_u32(mailbox + 0, 0x0301);
    daze_write_u32(mailbox + 4, 0);
    daze_write_u32(mailbox + 8, 0);
    daze_write_u32(mailbox + 12, 0);
    daze_write_u32(mailbox + 16, 0);
    daze_write_u32(mailbox + 20, 0x20);
    daze_write_u32(mailbox + 24, 0);
    daze_write_u32(mailbox + 28, 2);
    struct kvm_regs regs;
    struct kvm_sregs sregs;
    if (ioctl(machine.vcpu, KVM_GET_REGS, &regs) < 0 ||
        ioctl(machine.vcpu, KVM_GET_SREGS, &sregs) < 0) {
      fprintf(stderr, "parked-pio resume: cannot capture client state\n");
      fail = 1;
    } else {
      regs.rflags = 0x0242;
      regs.rsp = 0x1f00;
      sregs.idt.base = gate.idt_address;
      sregs.idt.limit = gate.idt_limit;
      const struct kvm_segment flat = {.selector = 0x20,
                                       .base = 0,
                                       .limit = 0xfffff,
                                       .type = 3,
                                       .present = 1,
                                       .dpl = 0,
                                       .db = 1,
                                       .s = 1,
                                       .g = 1};
      sregs.ss = sregs.ds = sregs.es = sregs.gs = flat;
      sregs.fs = flat;
      sregs.fs.type = 2;
      if (ioctl(machine.vcpu, KVM_SET_REGS, &regs) < 0 ||
          ioctl(machine.vcpu, KVM_SET_SREGS, &sregs) < 0) {
        fprintf(stderr, "parked-pio resume: cannot arm client state\n");
        fail = 1;
      } else {
        /* Run to the production mediator marker and stop there. */
        const int boundary_status =
          daze_kvm_dpmi_entry_continue_to_linear(&machine, 0x22022, &result);
        const DazeKvmDpmiEntryObservation *obs = &result.observation;
        const int mediator_pio = boundary_status == DAZE_KVM_DPMI_ENTRY_FAILED &&
                                 obs->kind == DAZE_KVM_DPMI_ENTRY_EXIT_UNEXPECTED_PIO &&
                                 obs->pio_direction == DAZE_KVM_DPMI_ENTRY_PIO_OUT &&
                                 obs->pio_size == 1 && obs->pio_count == 1 &&
                                 obs->pio_value_present && obs->pio_port == 0xf4 &&
                                 (uint8_t)obs->pio_value == 0x31;
        if (!mediator_pio) {
          fprintf(stderr, "parked-pio resume: did not stop at mediator marker\n");
          fail = 1;
        }
        if (!fail) {
          /* Snapshot the exact vCPU state at the marker and restore it
           * through the reflect sequence (SET_SREGS/SET_REGS then run). */
          struct kvm_regs parked_regs;
          struct kvm_sregs parked_sregs;
          if (ioctl(machine.vcpu, KVM_GET_REGS, &parked_regs) < 0 ||
              ioctl(machine.vcpu, KVM_GET_SREGS, &parked_sregs) < 0) {
            fprintf(stderr, "parked-pio resume: cannot snapshot parked state\n");
            fail = 1;
          } else if (ioctl(machine.vcpu, KVM_SET_SREGS, &parked_sregs) < 0 ||
                     ioctl(machine.vcpu, KVM_SET_REGS, &parked_regs) < 0) {
            fprintf(stderr, "parked-pio resume: cannot restore parked state\n");
            fail = 1;
          } else {
            const int resumed =
              daze_kvm_dpmi_entry_continue_once(&machine, &result) == DAZE_KVM_DPMI_ENTRY_OK;
            const DazeKvmDpmiEntryObservation *post = &result.observation;
            /* The client trailer is {int31; nop; hlt}; after the gate IRET the
             * guest reaches the nop then HLTs. A completed reflection retires
             * the marker, delivers the 0301h mailbox as ax, and reaches that
             * client HLT with carry cleared, ZF/IF preserved. A replay instead
             * re-emits the mediator OUT. */
            const int client_reached = resumed &&
                                       (post->kind == DAZE_KVM_DPMI_ENTRY_EXIT_HLT ||
                                        post->kind == DAZE_KVM_DPMI_ENTRY_EXIT_DEBUG) &&
                                       result.ax == 0x0301 && (result.rflags & 1u) == 0 &&
                                       (result.rflags & 0x40u) != 0 &&
                                       (result.rflags & 0x200u) != 0;
            const int replay = resumed && post->kind == DAZE_KVM_DPMI_ENTRY_EXIT_PIO &&
                               post->pio_port == 0xf4 &&
                               post->pio_direction == DAZE_KVM_DPMI_ENTRY_PIO_OUT &&
                               post->pio_value_present && (uint8_t)post->pio_value == 0x31;
            if (client_reached) {
              fprintf(stderr,
                      "parked-pio resume: ok marker retired, client reached kind=%d ip=%x "
                      "ax=%04x rflags=%08x\n",
                      post->kind, result.rip, result.ax, result.rflags);
            } else {
              fprintf(stderr,
                      "parked-pio resume: %s marker=%s kind=%d raw=%u cs:ip=%04x:%x ax=%04x "
                      "rflags=%08x\n",
                      replay ? "REPLAY" : "no-retire-advance", replay ? "re-emitted" : "not-seen",
                      post->kind, post->raw_exit_reason, result.cs, result.rip, result.ax,
                      result.rflags);
              fail = 1;
            }
          }
        }
      }
    }
  }
  daze_kvm_machine_destroy(&machine);
  return fail;
}
#endif

#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
/* Parks a synthetic generated gate at the mediator OUT. Fills parked state
 * and the immediate mailbox-load successor address. Returns -1 without KVM,
 * 0 on success, or 1 on failure. */
static int park_gate_at_mediator(DazeKvmMachine *machine, DazeKvmProtectedGateArtifacts *artifacts,
                                 uint32_t *successor_linear, DazeKvmDpmiEntryResult *parked) {
  const int init = init_case_machine(machine);
  if (init != 0) return init;
  uint8_t *guest = machine->guest;
  int fail = 0;
  place_gate(guest);
  uint8_t gdt[0x108] = {0};
  gdt[8] = 0xff;
  gdt[9] = 0xff;
  gdt[10] = 0x00;
  gdt[11] = 0x20;
  gdt[12] = 0x02;
  gdt[13] = 0x9a;
  gdt[14] = 0xc0;
  gdt[0x20] = 0xff;
  gdt[0x21] = 0xff;
  gdt[0x25] = 0x92;
  gdt[0x26] = 0xc0;
  const uint8_t gdtr[] = {0x3f, 0x00, 0x00, 0x10, 0x00, 0x00};
  const uint8_t transition[] = {
    0x90, 0x90,                         /* nop; nop */
    0x2e, 0x0f, 0x01, 0x16, 0x80, 0x00, /* lgdt cs:[0x80] */
    0x0f, 0x20, 0xc0,                   /* mov eax,cr0 */
    0x66, 0x83, 0xc8, 0x01,             /* or eax,0x1 */
    0x0f, 0x22, 0xc0,                   /* mov cr0,eax */
    0xea, 0x20, 0x00, 0x08, 0x00,       /* jmp far 0x08:0x20 */
  };
  const uint8_t previous_terminal[] = {0x90, 0xf4}; /* nop; hlt */
  const DazeKvmGuestWrite writes[] = {
    {0x1000, gdt, sizeof(gdt)},
    {0x22000, transition, sizeof(transition)},
    {0x22080, gdtr, sizeof(gdtr)},
    {0x22020, previous_terminal, sizeof(previous_terminal)},
  };
  if (!position_real_mode(machine)) fail = 1;
  DazeKvmDpmiEntryResult result;
  if (!fail && daze_kvm_dpmi_entry_run(machine, &handoff,
                                       &(DazeKvmDpmiEntryLayout){
                                         .writes = writes,
                                         .write_count = 4,
                                         .mailbox_address = 0x3f020,
                                         .terminal_linear = 0x22020,
                                       },
                                       &result) != DAZE_KVM_DPMI_ENTRY_OK) {
    fprintf(stderr, "post-pio checkpoint: entry not at client int31\n");
    fail = 1;
  }
  if (!fail && (result.cs != 8 || result.rip != 0x20)) {
    fprintf(stderr, "post-pio checkpoint: client not parked at 8:0020 (got %04x:%x)\n", result.cs,
            result.rip);
    fail = 1;
  }
  if (fail) return 1;
  const uint8_t client[] = {0xcd, 0x31, 0x90, 0xf4}; /* int 31h; nop; hlt */
  memcpy(guest + 0x22020, client, sizeof(client));
  const DazeKvmProtectedGateLayout gate = {
    .idt_address = 0x10000,
    .idt_limit = 0x3ff,
    .handler_address = 0x18000,
    .dos_handler_address = 0x18100,
    .default_dos_stub_address = 0x181c8,
    .record_address = 0x3e000,
    .mailbox_address = 0x3f020,
    .handler_selector = 0x8,
    .handler_data_selector = 0x20,
    .interrupt_gate_type = 0x8e,
    .exchange_limit = 1,
  };
  DazeKvmProtectedGateArtifacts built;
  if (!daze_kvm_protected_gate_build(&gate, &built)) {
    fprintf(stderr, "post-pio checkpoint: cannot build production gate\n");
    return 1;
  }
  memcpy(guest + result.cs_base + gate.handler_address, built.handler, built.handler_size);
  memcpy(guest + gate.idt_address + 0x31 * 8, built.idt_entry, sizeof(built.idt_entry));
  uint8_t *mailbox = guest + gate.mailbox_address;
  daze_write_u32(mailbox + 0, 0x0301);
  daze_write_u32(mailbox + 4, 0);
  daze_write_u32(mailbox + 8, 0);
  daze_write_u32(mailbox + 12, 0);
  daze_write_u32(mailbox + 16, 0);
  daze_write_u32(mailbox + 20, 0x20);
  daze_write_u32(mailbox + 24, 0);
  daze_write_u32(mailbox + 28, 2);
  struct kvm_regs regs;
  struct kvm_sregs sregs;
  if (ioctl(machine->vcpu, KVM_GET_REGS, &regs) < 0 ||
      ioctl(machine->vcpu, KVM_GET_SREGS, &sregs) < 0) {
    fprintf(stderr, "post-pio checkpoint: cannot capture client state\n");
    return 1;
  }
  regs.rflags = 0x0242;
  regs.rsp = 0x1f00;
  sregs.idt.base = gate.idt_address;
  sregs.idt.limit = gate.idt_limit;
  const struct kvm_segment flat = {.selector = 0x20,
                                   .base = 0,
                                   .limit = 0xfffff,
                                   .type = 3,
                                   .present = 1,
                                   .dpl = 0,
                                   .db = 1,
                                   .s = 1,
                                   .g = 1};
  sregs.ss = sregs.ds = sregs.es = sregs.gs = flat;
  sregs.fs = flat;
  sregs.fs.type = 2;
  if (ioctl(machine->vcpu, KVM_SET_REGS, &regs) < 0 ||
      ioctl(machine->vcpu, KVM_SET_SREGS, &sregs) < 0) {
    fprintf(stderr, "post-pio checkpoint: cannot arm client state\n");
    return 1;
  }
  const int boundary_status = daze_kvm_dpmi_entry_continue_to_linear(machine, 0x22022, &result);
  const DazeKvmDpmiEntryObservation *obs = &result.observation;
  const int mediator_pio = boundary_status == DAZE_KVM_DPMI_ENTRY_FAILED &&
                           obs->kind == DAZE_KVM_DPMI_ENTRY_EXIT_UNEXPECTED_PIO &&
                           obs->pio_direction == DAZE_KVM_DPMI_ENTRY_PIO_OUT &&
                           obs->pio_size == 1 && obs->pio_count == 1 && obs->pio_value_present &&
                           obs->pio_port == 0xf4 && (uint8_t)obs->pio_value == 0x31;
  if (!mediator_pio) {
    fprintf(stderr, "post-pio checkpoint: did not stop at mediator marker\n");
    return 1;
  }
  /* The failed continue_to_linear leaves result state empty; read the parked
   * vCPU image directly so the pre-execution OUT RIP and code base are exact. */
  struct kvm_regs parked_regs;
  struct kvm_sregs parked_sregs;
  if (ioctl(machine->vcpu, KVM_GET_REGS, &parked_regs) < 0 ||
      ioctl(machine->vcpu, KVM_GET_SREGS, &parked_sregs) < 0) {
    fprintf(stderr, "post-pio checkpoint: cannot capture parked image\n");
    return 1;
  }
  /* Find the OUT 0xf4 (e6 f4) in the emitted handler and verify the parked RIP
   * points at it; the successor is the mailbox load (64 a1 ..) that follows. */
  size_t out_offset = built.handler_size;
  for (size_t index = 0; index + 2 <= built.handler_size; ++index) {
    if (built.handler[index] == 0xe6 && built.handler[index + 1] == 0xf4) {
      out_offset = index;
      break;
    }
  }
  if (out_offset == built.handler_size || parked_regs.rip != gate.handler_address + out_offset ||
      parked_sregs.cs.base != 0x22000) {
    fprintf(stderr,
            "post-pio checkpoint: parked state not at gate OUT (rip=%llx base=%llx "
            "ins=%02x%02x"
            "%02x%02x)\n",
            parked_regs.rip, parked_sregs.cs.base, guest[parked_sregs.cs.base + parked_regs.rip],
            guest[parked_sregs.cs.base + parked_regs.rip + 1],
            guest[parked_sregs.cs.base + parked_regs.rip + 2],
            guest[parked_sregs.cs.base + parked_regs.rip + 3]);
    return 1;
  }
  *successor_linear = parked_sregs.cs.base + parked_regs.rip + 2;
  *artifacts = built;
  result.rip = (uint32_t)parked_regs.rip;
  result.cs_base = (uint32_t)parked_sregs.cs.base;
  result.cs = parked_sregs.cs.selector;
  result.cr0 = (uint32_t)parked_sregs.cr0;
  result.ax = (uint16_t)parked_regs.rax;
  result.rflags = (uint32_t)parked_regs.rflags;
  *parked = result;
  return 0;
}

static int run_guest_detour(DazeKvmMachine *machine, const DazeKvmDpmiEntryResult *at) {
  /* Synthetic detour in a distinct part of the flat code segment; no fixture bytes. */
  const uint8_t detour[] = {0x90, 0x90, 0xf4}; /* nop; nop; hlt */
  const uint32_t detour_linear = 0x3a200;
  memcpy((uint8_t *)machine->guest + detour_linear, detour, sizeof(detour));
  struct kvm_regs regs;
  if (ioctl(machine->vcpu, KVM_GET_REGS, &regs) < 0) return 0;
  regs.rip = detour_linear - at->cs_base;
  if (ioctl(machine->vcpu, KVM_SET_REGS, &regs) < 0) return 0;
  DazeKvmDpmiEntryResult step = {0};
  if (daze_kvm_dpmi_entry_continue_once(machine, &step) != DAZE_KVM_DPMI_ENTRY_OK) return 0;
  if (step.observation.kind != DAZE_KVM_DPMI_ENTRY_EXIT_HLT) {
    fprintf(stderr, "post-pio checkpoint: detour terminal not reached (kind=%d raw=%u)\n",
            step.observation.kind, step.observation.raw_exit_reason);
    return 0;
  }
  return 1;
}

static int run_post_pio_checkpoint_contract(void) {
  DazeKvmMachine machine;
  DazeKvmProtectedGateArtifacts artifacts;
  uint32_t successor_linear;
  DazeKvmDpmiEntryResult parked;
  const int park = park_gate_at_mediator(&machine, &artifacts, &successor_linear, &parked);
  if (park != 0) {
    if (park > 0) daze_kvm_machine_destroy(&machine);
    return park;
  }
  int fail = 0;
  /* Retire the OUT before taking the post-PIO snapshot; no mailbox loads may run yet. */
  DazeKvmDpmiEntryResult after_pio = {0};
  if (daze_kvm_dpmi_entry_continue_to_linear(&machine, successor_linear, &after_pio) !=
        DAZE_KVM_DPMI_ENTRY_OK ||
      after_pio.rip != parked.rip + 2 ||
      after_pio.observation.kind != DAZE_KVM_DPMI_ENTRY_EXIT_MATCHING_DEBUG ||
      after_pio.instruction[0] != 0x64 || after_pio.instruction[1] != 0xa1) {
    fprintf(
      stderr,
      "post-pio checkpoint: OUT did not retire at successor (kind=%d raw=%u rip=%x ins=%02x%02x)\n",
      after_pio.observation.kind, after_pio.observation.raw_exit_reason, after_pio.rip,
      after_pio.instruction[0], after_pio.instruction[1]);
    fail = 1;
  }
  struct kvm_regs post_regs;
  struct kvm_sregs post_sregs;
  if (!fail && (ioctl(machine.vcpu, KVM_GET_REGS, &post_regs) < 0 ||
                ioctl(machine.vcpu, KVM_GET_SREGS, &post_sregs) < 0)) {
    fprintf(stderr, "post-pio checkpoint: cannot capture post-PIO state\n");
    fail = 1;
  }
  /* Restoring post-PIO state after the detour must complete the gate without
   * re-emitting its mediator marker. */
  if (!fail && !run_guest_detour(&machine, &after_pio)) fail = 1;
  if (!fail && (ioctl(machine.vcpu, KVM_SET_SREGS, &post_sregs) < 0 ||
                ioctl(machine.vcpu, KVM_SET_REGS, &post_regs) < 0)) {
    fprintf(stderr, "post-pio checkpoint: cannot restore post-PIO state\n");
    fail = 1;
  }
  if (!fail) {
    DazeKvmDpmiEntryResult successor = {0};
    const int resumed =
      daze_kvm_dpmi_entry_continue_once(&machine, &successor) == DAZE_KVM_DPMI_ENTRY_OK;
    const DazeKvmDpmiEntryObservation *obs = &successor.observation;
    const int replay = obs->kind == DAZE_KVM_DPMI_ENTRY_EXIT_PIO && obs->pio_port == 0xf4 &&
                       obs->pio_direction == DAZE_KVM_DPMI_ENTRY_PIO_OUT && obs->pio_size == 1 &&
                       obs->pio_count == 1 && obs->pio_value_present &&
                       (uint8_t)obs->pio_value == 0x31;
    const int client_reached = resumed && obs->kind == DAZE_KVM_DPMI_ENTRY_EXIT_HLT &&
                               successor.ax == 0x0301 && (successor.rflags & 1u) == 0 &&
                               (successor.rflags & 0x40u) != 0 && (successor.rflags & 0x200u) != 0;
    if (client_reached) {
      fprintf(stderr,
              "post-pio checkpoint: PASS marker retired, detour survived, client reached "
              "kind=%d ip=%x ax=%04x rflags=%08x\n",
              obs->kind, successor.rip, successor.ax, successor.rflags);
    } else {
      fprintf(stderr, "post-pio checkpoint: FAIL %s kind=%d raw=%u cs:ip=%04x:%x ax=%04x\n",
              replay ? "marker re-emitted" : "no clean retire", obs->kind, obs->raw_exit_reason,
              successor.cs, successor.rip, successor.ax);
      fail = 1;
    }
  }
  daze_kvm_machine_destroy(&machine);
  return fail;
}

static int run_pre_pio_negative_control(void) {
  DazeKvmMachine machine;
  DazeKvmProtectedGateArtifacts artifacts;
  uint32_t successor_linear;
  DazeKvmDpmiEntryResult parked;
  const int park = park_gate_at_mediator(&machine, &artifacts, &successor_linear, &parked);
  if (park != 0) {
    if (park > 0) daze_kvm_machine_destroy(&machine);
    return park;
  }
  (void)successor_linear;
  /* Negative control: restoring PRE-PIO state after a detour re-emits the
   * mediator marker. Production reflection restores POST-PIO state to avoid
   * replaying the OUT. */
  struct kvm_regs pre_regs;
  struct kvm_sregs pre_sregs;
  int fail = 0;
  if (ioctl(machine.vcpu, KVM_GET_REGS, &pre_regs) < 0 ||
      ioctl(machine.vcpu, KVM_GET_SREGS, &pre_sregs) < 0) {
    fprintf(stderr, "pre-PIO control: cannot capture pre-PIO state\n");
    fail = 1;
  }
  if (!fail && !run_guest_detour(&machine, &parked)) fail = 1;
  if (!fail && (ioctl(machine.vcpu, KVM_SET_SREGS, &pre_sregs) < 0 ||
                ioctl(machine.vcpu, KVM_SET_REGS, &pre_regs) < 0)) {
    fprintf(stderr, "pre-PIO control: cannot restore pre-PIO state\n");
    fail = 1;
  }
  if (!fail) {
    DazeKvmDpmiEntryResult successor = {0};
    const int resumed =
      daze_kvm_dpmi_entry_continue_once(&machine, &successor) == DAZE_KVM_DPMI_ENTRY_OK;
    const DazeKvmDpmiEntryObservation *obs = &successor.observation;
    const int replay = resumed && obs->kind == DAZE_KVM_DPMI_ENTRY_EXIT_PIO &&
                       obs->pio_port == 0xf4 && obs->pio_direction == DAZE_KVM_DPMI_ENTRY_PIO_OUT &&
                       obs->pio_size == 1 && obs->pio_count == 1 && obs->pio_value_present &&
                       (uint8_t)obs->pio_value == 0x31 && successor.rip == parked.rip;
    if (replay) {
      fprintf(stderr,
              "pre-PIO control: PASS marker re-emitted after detour (matches live replay)\n");
    } else {
      fprintf(stderr, "pre-PIO control: FAIL no replay (kind=%d raw=%u cs:ip=%04x:%x)\n", obs->kind,
              obs->raw_exit_reason, successor.cs, successor.rip);
      fail = 1;
    }
  }
  daze_kvm_machine_destroy(&machine);
  return fail;
}

/* The reflection helper must retire a validated mediator OUT to its derived
 * successor before mailbox loads execute. Invalid markers/preconditions must
 * fail without running or fabricating a reply. */
static int run_retire_mediator_out_contract(void) {
  int fail = 0;
  DazeKvmMachine machine;
  DazeKvmProtectedGateArtifacts artifacts;
  uint32_t successor_linear;
  DazeKvmDpmiEntryResult parked;
  DazeKvmDpmiEntryResult rejected;
  struct kvm_regs after;
  int status;
  {
    const int park = park_gate_at_mediator(&machine, &artifacts, &successor_linear, &parked);
    if (park != 0) {
      if (park > 0) daze_kvm_machine_destroy(&machine);
      return park;
    }
    DazeKvmDpmiEntryResult retired;
    status =
      daze_kvm_dpmi_entry_retire_mediator_out(&machine, parked.cs_base, parked.rip, &retired);
    const DazeKvmDpmiEntryObservation *obs = &retired.observation;
    const uint8_t *successor_bytes = (const uint8_t *)machine.guest + parked.cs_base + retired.rip;
    const int ok =
      status == DAZE_KVM_DPMI_ENTRY_OK && obs->kind == DAZE_KVM_DPMI_ENTRY_EXIT_MATCHING_DEBUG &&
      retired.rip == parked.rip + 2 && retired.cs_base == parked.cs_base &&
      retired.instruction_size >= 2 && successor_bytes[0] == 0x64 && successor_bytes[1] == 0xa1;
    if (!ok)
      fprintf(
        stderr, "retire contract: FAIL success (status=%d kind=%d rip=%x base=%x ins=%02x%02x)\n",
        status, obs->kind, retired.rip, retired.cs_base, successor_bytes[0], successor_bytes[1]);
    else
      fprintf(stderr, "retire contract: PASS retired to mailbox-load successor rip=%x\n",
              retired.rip);
    if (!ok) fail = 1;
    daze_kvm_machine_destroy(&machine);
  }
  {
    const int park = park_gate_at_mediator(&machine, &artifacts, &successor_linear, &parked);
    if (park != 0) {
      if (park > 0) daze_kvm_machine_destroy(&machine);
      return park;
    }
    struct kvm_regs regs;
    int ok = ioctl(machine.vcpu, KVM_GET_REGS, &regs) == 0;
    regs.rax &= ~0xffull;
    if (ok && ioctl(machine.vcpu, KVM_SET_REGS, &regs) < 0) ok = 0;
    status =
      ok ? daze_kvm_dpmi_entry_retire_mediator_out(&machine, parked.cs_base, parked.rip, &rejected)
         : DAZE_KVM_DPMI_ENTRY_INVALID;
    ok = ok && ioctl(machine.vcpu, KVM_GET_REGS, &after) == 0;
    const int rejected_ok = status == DAZE_KVM_DPMI_ENTRY_INVALID && ok && after.rip == parked.rip;
    if (!rejected_ok)
      fprintf(stderr, "retire contract: FAIL marker mismatch (status=%d rip=%llx parked=%x)\n",
              status, after.rip, parked.rip);
    else
      fprintf(stderr, "retire contract: PASS rejected non-marker without continuing\n");
    if (!rejected_ok) fail = 1;
    daze_kvm_machine_destroy(&machine);
  }
  {
    const int park = park_gate_at_mediator(&machine, &artifacts, &successor_linear, &parked);
    if (park != 0) {
      if (park > 0) daze_kvm_machine_destroy(&machine);
      return park;
    }
    ((uint8_t *)machine.guest)[parked.cs_base + parked.rip] = 0x90;
    status =
      daze_kvm_dpmi_entry_retire_mediator_out(&machine, parked.cs_base, parked.rip, &rejected);
    const int ok = ioctl(machine.vcpu, KVM_GET_REGS, &after) == 0;
    const int rejected_ok = status == DAZE_KVM_DPMI_ENTRY_INVALID && ok && after.rip == parked.rip;
    if (!rejected_ok)
      fprintf(stderr, "retire contract: FAIL byte mismatch (status=%d rip=%llx parked=%x)\n",
              status, after.rip, parked.rip);
    else
      fprintf(stderr, "retire contract: PASS rejected non-OUT without continuing\n");
    if (!rejected_ok) fail = 1;
    daze_kvm_machine_destroy(&machine);
  }
  return fail;
}

static int run_retire_mediator_out_observe_case(int use_sync) {
  DazeKvmMachine machine;
  DazeKvmProtectedGateArtifacts artifacts;
  uint32_t successor_linear;
  DazeKvmDpmiEntryResult parked;
  const int park = park_gate_at_mediator(&machine, &artifacts, &successor_linear, &parked);
  if (park != 0) {
    if (park > 0) daze_kvm_machine_destroy(&machine);
    return park;
  }
  if (!use_sync) machine.sync_regs_mask = 0;
  DazeRunMetrics metrics = {.enabled = 1};
  machine.run_metrics = &metrics;
  struct kvm_regs expected_regs = {0};
  struct kvm_sregs expected_sregs = {0};
  if (ioctl(machine.vcpu, KVM_GET_REGS, &expected_regs) < 0 ||
      ioctl(machine.vcpu, KVM_GET_SREGS, &expected_sregs) < 0) {
    daze_kvm_machine_destroy(&machine);
    return 1;
  }
  expected_regs.rip += 2;
  DazeKvmDpmiEntryResult retired;
  const int status =
    daze_kvm_dpmi_entry_retire_mediator_out_observe(&machine, parked.cs_base, parked.rip, &retired);
  /* The software retire advances RIP past the validated OUT without running
   * the guest, so there is no exit to observe: pin the retired registers,
   * the absence of execution, and the absence of capture instead. */
  struct kvm_regs after_regs = {0};
  struct kvm_sregs after_sregs = {0};
  const int read_ok = ioctl(machine.vcpu, KVM_GET_REGS, &after_regs) == 0 &&
                      ioctl(machine.vcpu, KVM_GET_SREGS, &after_sregs) == 0;
  const int ok =
    status == DAZE_KVM_DPMI_ENTRY_OK && read_ok && after_regs.rip == (uint64_t)parked.rip + 2 &&
    memcmp(&after_regs, &expected_regs, sizeof(after_regs)) == 0 &&
    memcmp(&after_sregs, &expected_sregs, sizeof(after_sregs)) == 0 &&
    metrics.kvm_dpmi_run_calls[DAZE_RUN_METRICS_DPMI_RUN_CONTINUE_TO_LINEAR] == 0 &&
    metrics.kvm_dpmi_state_capture_calls[DAZE_RUN_METRICS_DPMI_CAPTURE_CONTINUE_TO_LINEAR] == 0;
  if (!ok)
    fprintf(
      stderr,
      "retire observe contract: FAIL status=%d rip=%llx parked=%x runs=%llu captures=%llu\n",
      status, read_ok ? (unsigned long long)after_regs.rip : 0, parked.rip,
      (unsigned long long)metrics.kvm_dpmi_run_calls[DAZE_RUN_METRICS_DPMI_RUN_CONTINUE_TO_LINEAR],
      (unsigned long long)
        metrics.kvm_dpmi_state_capture_calls[DAZE_RUN_METRICS_DPMI_CAPTURE_CONTINUE_TO_LINEAR]);
  else
    fprintf(stderr, "retire observe contract: PASS retired without guest execution\n");
  if (!ok) {
    daze_kvm_machine_destroy(&machine);
    return 1;
  }
  /* An _observe retire over a corrupted OUT must fail closed with RIP unmoved,
   * mirroring the capture=1 rejection above. */
  ((uint8_t *)machine.guest)[parked.cs_base + parked.rip] = 0x90;
  DazeKvmDpmiEntryResult rejected;
  const int rejected_status = daze_kvm_dpmi_entry_retire_mediator_out_observe(
    &machine, parked.cs_base, parked.rip, &rejected);
  const int rejected_ok = rejected_status == DAZE_KVM_DPMI_ENTRY_INVALID && read_ok &&
                          ioctl(machine.vcpu, KVM_GET_REGS, &after_regs) == 0 &&
                          after_regs.rip == (uint64_t)parked.rip + 2;
  if (!rejected_ok)
    fprintf(stderr, "retire observe contract: FAIL byte mismatch (status=%d rip=%llx parked=%x)\n",
            rejected_status, (unsigned long long)after_regs.rip, parked.rip);
  else
    fprintf(stderr, "retire observe contract: PASS rejected non-OUT without continuing\n");
  daze_kvm_machine_destroy(&machine);
  return rejected_ok ? 0 : 1;
}

static int run_retire_mediator_out_observe_contract(void) {
  const int sync = run_retire_mediator_out_observe_case(1);
  return sync != 0 ? sync : run_retire_mediator_out_observe_case(0);
}
#endif

#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
static int run_rearm_success_case(void) {
  DazeKvmMachine machine;
  const int init = init_case_machine(&machine);
  if (init != 0) return init;
  const uint8_t sled[4] = {0x90, 0x90, 0x90, 0x90};
  const DazeKvmGuestWrite writes[] = {{0x31000, sled, sizeof(sled)}};
  int fail = 0;
  if (daze_kvm_machine_set_real_mode(&machine, 0x3100, 0, 0x2100, 0x0100, 0x3100, 0x0000) !=
      DAZE_KVM_MACHINE_OK)
    fail = 1;
  DazeKvmDpmiEntryResult result;
  DazeKvmDpmiEntryLayout layout = {.writes = writes, .write_count = 1, .mailbox_address = 0x3f020};
  layout.terminal_linear = 0x31000;
  if (daze_kvm_dpmi_entry_run(&machine, &handoff, &layout, &result) != DAZE_KVM_DPMI_ENTRY_OK) {
    fprintf(stderr, "re-arm first run not OK\n");
    fail = 1;
  }
  layout.terminal_linear = 0x31001;
  if (!fail &&
      daze_kvm_dpmi_entry_run(&machine, &handoff, &layout, &result) != DAZE_KVM_DPMI_ENTRY_OK) {
    fprintf(stderr, "re-arm second run not OK\n");
    fail = 1;
  }
  daze_kvm_machine_destroy(&machine);
  return fail;
}

static int run_nonmatching_debug_case(void) {
  DazeKvmMachine machine;
  const int init = init_case_machine(&machine);
  if (init != 0) return init;
  uint8_t *guest = machine.guest;
  place_gate(guest);
  /* TF generates an intercepted #DB on both VMX and SVM; SVM delivers
   * ICEBP's #DB to the guest instead of reporting a hardware-debug exit. */
  daze_write_u16(guest + 0x21000 + 0x0100 + 4, 0x0102);
  uint8_t code[34];
  memset(code, 0x90, sizeof(code));
  code[33] = 0xf4;
  const DazeKvmGuestWrite writes[] = {{0x22000, code, sizeof(code)}};
  int fail = 0;
  if (!position_real_mode(&machine)) fail = 1;
  DazeKvmDpmiEntryResult result;
  const int status = daze_kvm_dpmi_entry_run(
    &machine, &handoff,
    &(DazeKvmDpmiEntryLayout){
      .writes = writes, .write_count = 1, .mailbox_address = 0x3f020, .terminal_linear = 0x22020},
    &result);
  if (status != DAZE_KVM_DPMI_ENTRY_FAILED || result.rip != 0 || result.cs != 0 ||
      result.observation.kind != DAZE_KVM_DPMI_ENTRY_EXIT_UNEXPECTED_DEBUG ||
      result.observation.raw_exit_reason != KVM_EXIT_DEBUG || result.observation.clear_error != 0) {
    fprintf(stderr, "nonmatching debug case failed status=%d rip=%x cs=%x\n", status, result.rip,
            result.cs);
    fail = 1;
  }
  if (!fail) {
    struct kvm_regs regs;
    if (ioctl(machine.vcpu, KVM_GET_REGS, &regs) < 0 || (regs.rflags & 0x100u) == 0) {
      fprintf(stderr, "nonmatching debug case: guest TF not observed\n");
      fail = 1;
    } else {
      /* Stop guest-requested stepping; reaching HLT past the original
       * breakpoint still proves the helper cleared its debug configuration. */
      regs.rflags &= ~UINT64_C(0x100);
      if (ioctl(machine.vcpu, KVM_SET_REGS, &regs) < 0) fail = 1;
    }
  }
  if (!fail) {
    if (ioctl(machine.vcpu, KVM_RUN, 0) < 0 ||
        ((const struct kvm_run *)machine.run)->exit_reason != KVM_EXIT_HLT) {
      fprintf(stderr, "clear not proven: guest did not continue to HLT\n");
      fail = 1;
    }
  }
  daze_kvm_machine_destroy(&machine);
  return fail;
}
#endif

/* The terminal-entry diagnostic must stay off unless it is asked for, and it
 * must report the state it was handed without editing any of it. */
static int fail_entry_trace_disabled_contract(void) {
  unsetenv("DAZE_KVM_FAIL_ENTRY_TRACE");
  if (daze_kvm_dpmi_entry_fail_entry_trace_enabled() != 0) return 1;
  setenv("DAZE_KVM_FAIL_ENTRY_TRACE", "0", 1);
  if (daze_kvm_dpmi_entry_fail_entry_trace_enabled() != 0) return 2;
  setenv("DAZE_KVM_FAIL_ENTRY_TRACE", "", 1);
  if (daze_kvm_dpmi_entry_fail_entry_trace_enabled() != 0) return 3;
  setenv("DAZE_KVM_FAIL_ENTRY_TRACE", "true", 1);
  if (daze_kvm_dpmi_entry_fail_entry_trace_enabled() != 0) return 4;
  return 0;
}

static DazeKvmFailEntryTrace synthetic_fail_entry_observation(void) {
  return (DazeKvmFailEntryTrace){
    .raw_exit_reason = 9,
    .hardware_entry_failure_reason = 0x0000000300000002ull,
    .hardware_entry_failure_reason_present = 1,
    .cr0 = 0x80050033ull,
    .cr4 = 0x0000000000000020ull,
    .efer = 0x0000000000000d01ull,
    .rflags = 0x0000000000020247ull,
    .rip = 0x00123456ull,
    .rsp = 0x0000000cull,
    .cs = {.selector = 0x0010, .base = 0x00011000u, .limit = 0x0000ffffu, .type = 0x8bu, .db = 1},
    .ds = {.selector = 0x0020, .base = 0x00022000u, .limit = 0x0000ffffu, .type = 0x93u, .db = 1},
    .es = {.selector = 0x0024, .base = 0x00032000u, .limit = 0x0000ffffu, .type = 0x93u, .db = 1},
    .ss = {.selector = 0x0030, .base = 0x00000400u, .limit = 0x0000ffffu, .type = 0x93u, .db = 1},
    .gdt_base = 0x00050000u,
    .gdt_limit = 0x0027u,
    .idt_base = 0x00000200u,
    .idt_limit = 0x03ffu,
    .ldt = {.selector = 0x0038, .base = 0x00070000u, .limit = 0x0000007fu, .type = 0x82u, .db = 0},
    .tr = {.selector = 0x0040, .base = 0x00080000u, .limit = 0x00000067u, .type = 0x8bu, .db = 0}};
}

static int fail_entry_trace_preservation_contract(void) {
  uint8_t guest[0x1000];
  for (size_t index = 0; index < sizeof guest; ++index)
    guest[index] = (uint8_t)(index ^ 0x5au);
  const DazeKvmFailEntryTrace expected = synthetic_fail_entry_observation();
  DazeKvmFailEntryTrace trace = expected;
  daze_kvm_dpmi_entry_fail_entry_trace_capture(&trace, guest, sizeof guest);

  if (trace.raw_exit_reason != expected.raw_exit_reason ||
      trace.hardware_entry_failure_reason != expected.hardware_entry_failure_reason ||
      trace.hardware_entry_failure_reason_present !=
        expected.hardware_entry_failure_reason_present ||
      trace.cr0 != expected.cr0 || trace.cr4 != expected.cr4 || trace.efer != expected.efer ||
      trace.rflags != expected.rflags || trace.rip != expected.rip || trace.rsp != expected.rsp ||
      trace.gdt_base != expected.gdt_base || trace.gdt_limit != expected.gdt_limit ||
      trace.idt_base != expected.idt_base || trace.idt_limit != expected.idt_limit)
    return 1;
  const uint32_t exception_gate =
    expected.idt_base +
    (uint32_t)DAZE_KVM_FAIL_ENTRY_TRACE_EXCEPTION_VECTOR * DAZE_KVM_FAIL_ENTRY_TRACE_IDT_GATE_BYTES;
  if (trace.exception_gate_valid != 1) return 13;
  if (memcmp(trace.exception_gate, guest + exception_gate, sizeof(trace.exception_gate)) != 0)
    return 14;
  const DazeKvmFailEntryTraceSegment *const reported[] = {&trace.cs, &trace.ds,  &trace.es,
                                                          &trace.ss, &trace.ldt, &trace.tr};
  const DazeKvmFailEntryTraceSegment *const given[] = {&expected.cs, &expected.ds,  &expected.es,
                                                       &expected.ss, &expected.ldt, &expected.tr};
  for (size_t index = 0; index < sizeof reported / sizeof *reported; ++index)
    if (reported[index]->selector != given[index]->selector ||
        reported[index]->base != given[index]->base ||
        reported[index]->limit != given[index]->limit ||
        reported[index]->type != given[index]->type || reported[index]->db != given[index]->db)
      return 2;

  if (trace.stack_linear_valid != 1) return 3;
  if (trace.stack_linear != expected.ss.base + (uint32_t)expected.rsp) return 4;
  const uint32_t available = (uint32_t)(sizeof guest - trace.stack_linear);
  const uint32_t bounded = available / 2 < DAZE_KVM_FAIL_ENTRY_TRACE_WORDS
                             ? available / 2
                             : DAZE_KVM_FAIL_ENTRY_TRACE_WORDS;
  if (trace.stack_word_count != bounded) return 5;
  for (uint32_t index = 0; index < bounded; ++index)
    if (trace.stack_words[index] != daze_read_u16(guest + trace.stack_linear + index * 2)) return 6;

  /* A stack past the end of the guest buffer reports no words, and no guest
   * pointer is required to observe the rest of the state. */
  DazeKvmFailEntryTrace beyond = expected;
  beyond.rsp = (uint32_t)sizeof guest + 0x1000u;
  daze_kvm_dpmi_entry_fail_entry_trace_capture(&beyond, guest, sizeof guest);
  if (beyond.stack_linear_valid != 1 || beyond.stack_word_count != 0) return 7;
  if (beyond.rip != expected.rip || beyond.tr.selector != expected.tr.selector) return 8;

  DazeKvmFailEntryTrace none = expected;
  daze_kvm_dpmi_entry_fail_entry_trace_capture(&none, NULL, 0);
  if (none.stack_linear_valid != 0 || none.stack_word_count != 0 ||
      none.exception_gate_valid != 0 || none.rsp != expected.rsp)
    return 9;

  /* The raw exit number is reported with the name this project's headers give
   * it, so a numeric record can never be read as a different exit. */
  if (strcmp(daze_kvm_dpmi_entry_fail_entry_trace_exit_name(8), "KVM_EXIT_SHUTDOWN") != 0)
    return 10;
  if (strcmp(daze_kvm_dpmi_entry_fail_entry_trace_exit_name(9), "KVM_EXIT_FAIL_ENTRY") != 0)
    return 11;
  if (strcmp(daze_kvm_dpmi_entry_fail_entry_trace_exit_name(4095), "KVM_EXIT_?") != 0) return 12;
  return 0;
}

static int run_case(const char *name, int (*test)(void)) {
  fprintf(stderr, "DPMI entry contract: starting %s\n", name);
  const int status = test();
  fprintf(stderr, "DPMI entry contract: finished %s status=%d\n", name, status);
  return status;
}

static int trace_contents_contract(void) {
  uint8_t guest[0x1000];
  for (size_t i = 0; i < sizeof(guest); ++i)
    guest[i] = (uint8_t)i;
  DazeKvmFailEntryTrace trace = {.raw_exit_reason = 9,
                                 .hardware_entry_failure_reason_present = 1,
                                 .hardware_entry_failure_reason = 0x123456789abcdef0ull,
                                 .cs = {.selector = 8, .base = 0x200, .type = 0x9b, .db = 1},
                                 .ss = {.selector = 0x10, .base = 0x300, .type = 0x93},
                                 .rip = 0x20,
                                 .rsp = 0x40,
                                 .gdt_base = 0x400,
                                 .idt_base = 0x500,
                                 .idt_limit = 0x7ff,
                                 .ldt = {.base = 0x600}};
  const uint32_t gate = 0x500 + DAZE_KVM_FAIL_ENTRY_TRACE_EXCEPTION_VECTOR * 8;
  daze_write_u16(guest + gate, 0x10);
  const uint8_t handler[8] = {0xff, 0xff, 0, 7, 0, 0x9a, 0, 0};
  memcpy(guest + 0x408, handler, 8);
  daze_kvm_dpmi_entry_fail_entry_trace_capture(&trace, guest, sizeof(guest));
  int fail = trace.stack_linear != 0x340 || trace.stack_word_count != 8 ||
             !trace.exception_gate_valid || !trace.handler_descriptor_valid ||
             !trace.code_descriptor_valid || !trace.target_descriptor_valid ||
             !trace.handler_code_valid || trace.handler_code_count != sizeof(trace.handler_code) ||
             trace.instruction_count != 16 || trace.context_count != 0x40 ||
             memcmp(trace.instruction_bytes, guest + 0x220, 16) ||
             memcmp(trace.context_bytes, guest + 0x1e0, 0x40) ||
             memcmp(trace.handler_descriptor, handler, 8) ||
             memcmp(trace.handler_code, guest + 0x710, sizeof(trace.handler_code)) ||
             memcmp(trace.code_descriptor, guest + 0x600 + 0x16 * 8, 8) ||
             memcmp(trace.target_descriptor, guest + 0x600 + 0x1a * 8, 8);
  for (size_t i = 0; i < 8; ++i)
    fail |= trace.stack_words[i] != daze_read_u16(guest + 0x340 + 2 * i);
  FILE *output = tmpfile();
  const int saved = dup(STDERR_FILENO);
  if (output == NULL || saved < 0) return 1;
  fflush(stderr);
  if (dup2(fileno(output), STDERR_FILENO) < 0) return 1;
  daze_kvm_dpmi_entry_fail_entry_trace_report(&trace);
  DazeKvmFailEntryTrace absent = {.raw_exit_reason = 8};
  daze_kvm_dpmi_entry_fail_entry_trace_report(&absent);
  daze_kvm_dpmi_entry_fail_entry_trace_report(NULL);
  fflush(stderr);
  if (dup2(saved, STDERR_FILENO) < 0) return 1;
  close(saved);
  rewind(output);
  char text[8192];
  const size_t count = fread(text, 1, sizeof(text) - 1, output);
  text[count] = 0;
  fclose(output);
  fail |= count == sizeof(text) - 1 ||
          strstr(text, "exit=9/KVM_EXIT_FAIL_ENTRY fail-entry-reason=123456789abcdef0") == NULL ||
          strstr(text, "stack=present:00000340: 4140") == NULL ||
          strstr(text, "instruction@00000220:20212223") == NULL ||
          strstr(text, "handler-code:10111213") == NULL ||
          strstr(text, "gdt[01]=ffff0007009a0000") == NULL ||
          strstr(text, "exit=8/KVM_EXIT_SHUTDOWN fail-entry-reason=absent") == NULL ||
          strstr(text, "idt[0d]=absent stack=absent") == NULL;
  static const char *const names[] = {"UNKNOWN",
                                      "EXCEPTION",
                                      "IO",
                                      "HYPERCALL",
                                      "DEBUG",
                                      "HLT",
                                      "MMIO",
                                      "IRQ_WINDOW_OPEN",
                                      "SHUTDOWN",
                                      "FAIL_ENTRY",
                                      "INTR",
                                      "SET_TPR",
                                      "TPR_ACCESS",
                                      "S390_SIEIC",
                                      "S390_RESET",
                                      "DCR",
                                      "NMI",
                                      "INTERNAL_ERROR",
                                      "OSI",
                                      "PAPR_HCALL",
                                      "S390_UCONTROL",
                                      "WATCHDOG",
                                      "S390_TSCH",
                                      "EPR",
                                      "SYSTEM_EVENT",
                                      "S390_STSI"};
  for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
    char expected[64];
    snprintf(expected, sizeof(expected), "KVM_EXIT_%s", names[i]);
    fail |= strcmp(daze_kvm_dpmi_entry_fail_entry_trace_exit_name(i), expected) != 0;
  }
  DazeKvmFailEntryTrace short_trace = {.cs = {.base = 0xffc},
                                       .ss = {.base = 0xffe},
                                       .idt_base = UINT32_MAX,
                                       .idt_limit = 0xffff,
                                       .gdt_base = 0xfff,
                                       .ldt = {.base = 0xfff}};
  daze_kvm_dpmi_entry_fail_entry_trace_capture(&short_trace, guest, sizeof(guest));
  fail |= short_trace.instruction_count != 4 || short_trace.stack_word_count != 1 ||
          short_trace.exception_gate_valid || short_trace.handler_descriptor_valid ||
          short_trace.code_descriptor_valid || short_trace.target_descriptor_valid;
  short_trace = (DazeKvmFailEntryTrace){.ss = {.base = UINT32_MAX}, .rsp = 1};
  daze_kvm_dpmi_entry_fail_entry_trace_capture(&short_trace, guest, sizeof(guest));
  fail |= short_trace.stack_linear_valid || short_trace.stack_word_count;
  daze_kvm_dpmi_entry_fail_entry_trace_capture(NULL, guest, sizeof(guest));
  return fail;
}

static int terminal_trace_contract(void) {
  DazeKvmMachine machine;
  const int init = init_case_machine(&machine);
  if (init) return init;
  int fail = !position_real_mode(&machine);
  struct kvm_sregs sregs;
  fail |= ioctl(machine.vcpu, KVM_GET_SREGS, &sregs) < 0;
  sregs.cr0 |= 1;
  sregs.idt.limit = 0;
  fail |= ioctl(machine.vcpu, KVM_SET_SREGS, &sregs) < 0;
  ((uint8_t *)machine.guest)[0x30000] = 0xcc; /* int3 */
  FILE *output = tmpfile();
  const int saved = dup(STDERR_FILENO);
  if (output == NULL || saved < 0) fail = 1;
  DazeKvmDpmiEntryResult boundary;
  if (!fail) {
    fail |= setenv("DAZE_KVM_FAIL_ENTRY_TRACE", "1", 1) != 0;
    fflush(stderr);
    fail |= dup2(fileno(output), STDERR_FILENO) < 0;
    fail |= daze_kvm_dpmi_entry_continue_once(&machine, &boundary) != DAZE_KVM_DPMI_ENTRY_OK ||
            boundary.observation.raw_exit_reason != KVM_EXIT_SHUTDOWN ||
            boundary.observation.kind != DAZE_KVM_DPMI_ENTRY_EXIT_OTHER;
    /* AMD KVM resets the vCPU on shutdown; validate the returned state, not the faulting state. */
    fail |= ioctl(machine.vcpu, KVM_GET_SREGS, &sregs) < 0;
    fail |= boundary.cr0 != (uint32_t)sregs.cr0 || boundary.idt_base != (uint32_t)sregs.idt.base ||
            boundary.idt_limit != sregs.idt.limit;
    const DazeKvmDpmiEntryResult before = boundary;
    fail |= daze_kvm_dpmi_entry_capture_state(&machine, &boundary) != DAZE_KVM_DPMI_ENTRY_OK ||
            memcmp(&before, &boundary, sizeof(boundary)) != 0;
    fflush(stderr);
    fail |= dup2(saved, STDERR_FILENO) < 0;
    unsetenv("DAZE_KVM_FAIL_ENTRY_TRACE");
    rewind(output);
    char text[8192];
    const size_t count = fread(text, 1, sizeof(text) - 1, output);
    text[count] = 0;
    const char *record = strstr(text, "terminal-entry exit=8/KVM_EXIT_SHUTDOWN");
    char expected_idt[64], expected_cr0[64];
    snprintf(expected_idt, sizeof(expected_idt), "idt=%08x:%04x", (uint32_t)sregs.idt.base,
             sregs.idt.limit);
    snprintf(expected_cr0, sizeof(expected_cr0), "cr0=%016llx", (unsigned long long)sregs.cr0);
    fail |= record == NULL ||
            (record != NULL && strstr(record + 1, "terminal-entry exit=") != NULL) ||
            strstr(text, "fail-entry-reason=absent") == NULL ||
            strstr(text, expected_idt) == NULL || strstr(text, expected_cr0) == NULL;
    if (fail)
      fprintf(stderr, "terminal trace contract failed: kind=%d exit=%u cr0=%08x idt=%08x:%04x\n%s",
              boundary.observation.kind, boundary.observation.raw_exit_reason, boundary.cr0,
              boundary.idt_base, boundary.idt_limit, text);
  }
  if (saved >= 0) close(saved);
  if (output != NULL) fclose(output);
  daze_kvm_machine_destroy(&machine);
  return fail;
}

static int mediator_elision_contract(void) {
  DazeKvmMachine machine;
  const int init = init_case_machine(&machine);
  if (init) return init;
  DazeRunMetrics metrics = {.enabled = 1};
  machine.run_metrics = &metrics;
  const uint8_t code[] = {0xb0, 0x31, 0xe6, 0xf4, 0xf4}; /* mov al,31h; out f4h,al; hlt */
  memcpy((uint8_t *)machine.guest + 0x30000, code, sizeof(code));
  int fail = !position_real_mode(&machine);
  DazeKvmDpmiEntryResult result;
  fail |=
    daze_kvm_dpmi_entry_continue_mediator_or_capture(&machine, &result) != DAZE_KVM_DPMI_ENTRY_OK ||
    result.observation.kind != DAZE_KVM_DPMI_ENTRY_EXIT_PIO ||
    result.observation.pio_value != 0x31 || result.observation.pio_port != 0xf4 || result.cs ||
    result.rip || metrics.kvm_dpmi_mediator_capture_elisions != 1;
  fail |= daze_kvm_dpmi_entry_capture_state(&machine, &result) != DAZE_KVM_DPMI_ENTRY_OK ||
          result.cs != 0x3000 || result.rip != 2 || result.ax != 0x31;
  fail |=
    daze_kvm_dpmi_entry_continue_mediator_or_capture(&machine, &result) != DAZE_KVM_DPMI_ENTRY_OK ||
    result.observation.kind != DAZE_KVM_DPMI_ENTRY_EXIT_HLT || result.rip != 5 ||
    result.cs != 0x3000 || metrics.kvm_dpmi_mediator_capture_elisions != 1;
  daze_kvm_machine_destroy(&machine);
  return fail;
}

#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
static int run_rejected_layouts(void) {
  DazeKvmMachine machine;
  const int init = init_case_machine(&machine);
  if (init) return init;
  uint8_t *guest = machine.guest;
  const uint8_t bytes[] = {0x90, 0xf4}; /* nop; hlt */
  const DazeKvmGuestWrite write = {0x22000, bytes, sizeof(bytes)};
  const DazeKvmDpmiEntryLayout valid = {
    .writes = &write, .write_count = 1, .mailbox_address = 0x3f020, .terminal_linear = 0x22000};
  int fail = 0;
  struct kvm_regs before, after;
  position_real_mode(&machine);
  if (ioctl(machine.vcpu, KVM_GET_REGS, &before) < 0) fail = 1;
  for (int kind = 0; kind < 10; ++kind) {
    DazeKvmDpmiEntryLayout layout = valid;
    DazeKvmGuestWrite bad = write;
    DazeKvmRunnerDpmiHandoff bad_handoff = handoff;
    if (kind == 0) layout.writes = NULL;
    if (kind == 1) layout.write_count = 0;
    if (kind == 2) layout.mailbox_address = machine.guest_size - 1;
    if (kind == 3) layout.terminal_linear = machine.guest_size;
    if (kind == 4) bad.bytes = NULL;
    if (kind == 5) bad.size = 0;
    if (kind == 6) bad.address = UINT32_MAX;
    if (kind == 7) bad.size = SIZE_MAX;
    if (kind == 8) bad_handoff.valid = 0;
    if (kind >= 4 && kind <= 7) layout.writes = &bad;
    memset(guest + 0x22000, 0xa5, sizeof(bytes));
    DazeKvmDpmiEntryResult result;
    memset(&result, 0xa5, sizeof(result));
    const int status =
      daze_kvm_dpmi_entry_run(&machine, &bad_handoff, kind == 9 ? NULL : &layout, &result);
    fail |= status != DAZE_KVM_DPMI_ENTRY_INVALID || guest[0x22000] != 0xa5 ||
            result.observation.kind != DAZE_KVM_DPMI_ENTRY_EXIT_NONE ||
            ioctl(machine.vcpu, KVM_GET_REGS, &after) < 0 ||
            memcmp(&before, &after, sizeof(before));
  }
  const int vcpu = machine.vcpu;
  const int non_vcpu = open("/dev/null", O_RDONLY);
  machine.vcpu = non_vcpu;
  DazeKvmDpmiEntryResult result;
  fail |= daze_kvm_dpmi_entry_continue_once(&machine, &result) != DAZE_KVM_DPMI_ENTRY_FAILED ||
          result.observation.kind != DAZE_KVM_DPMI_ENTRY_EXIT_RUN_FAILED ||
          result.observation.run_error == 0;
  machine.vcpu = vcpu;
  if (non_vcpu >= 0) close(non_vcpu);
  daze_kvm_machine_destroy(&machine);
  return fail;
}
#endif

int main(void) {
  const int a = run_case("matching success", run_matching_success_case);
  const int b = run_case("unexpected HLT", run_unexpected_hlt_case);
  const int e = run_case("unexpected PIO", run_unexpected_pio_case);
  const int d = run_case("rearm success", run_rearm_success_case);
#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
  const int c = run_case("nonmatching debug", run_nonmatching_debug_case);
  const int f = run_case("gate post IRET", run_gate_post_iret_contract);
  const int g = run_case("parked PIO resume", run_parked_pio_resume_contract);
  const int h = run_case("post PIO checkpoint", run_post_pio_checkpoint_contract);
  const int i = run_case("pre PIO negative control", run_pre_pio_negative_control);
  const int j = run_case("retire mediator OUT", run_retire_mediator_out_contract);
  const int m = run_case("retire mediator OUT observe", run_retire_mediator_out_observe_contract);
  const int n = run_case("rejected layouts", run_rejected_layouts);
  if (run_case("trace contents", trace_contents_contract)) return 1;
  if (run_case("terminal trace", terminal_trace_contract) ||
      run_case("mediator capture elision", mediator_elision_contract))
    return 1;
#else
  const int c = 0;
  const int f = 0;
  const int g = 0;
  const int h = 0;
  const int i = 0;
  const int j = 0;
  const int m = 0;
  const int n = 0;
#endif
  const int k = run_case("fail entry trace disabled", fail_entry_trace_disabled_contract);
  const int l = run_case("fail entry trace preservation", fail_entry_trace_preservation_contract);
  if (a < 0 || b < 0 || c < 0 || d < 0 || e < 0 || f < 0 || g < 0 || h < 0 || i < 0 || j < 0 ||
      k < 0 || l < 0 || m < 0 || n < 0)
    return 1;
  if (a > 0 || b > 0 || c > 0 || d > 0 || e > 0 || f > 0 || g > 0 || h > 0 || i > 0 || j > 0 ||
      k > 0 || l > 0 || m > 0 || n > 0)
    return 1;
  return 0;
}
#else
int main(void) {
  return 77;
}
#endif
