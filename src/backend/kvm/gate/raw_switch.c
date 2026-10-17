#include "interrupt_vector.h"
#include "raw_switch.h"
#include "machine_access.h"

#include "idt_gate.h"
#include "kvm_range.h"
#include "port.h"
#include "selector.h"

#include <string.h>

#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
#include <linux/kvm.h>
#include <sys/ioctl.h>

static int layout_valid(const DazeKvmRawSwitchGateLayout *layout) {
  const uint32_t entry =
    layout == NULL ? 0 : layout->idt_address + DAZE_KVM_RAW_SWITCH_GATE_VECTOR * 8u;
  return layout != NULL && layout->handler_address != 0 && layout->real_handler_address != 0 &&
         layout->real_handler_address <= 0x10ffefu && layout->handler_selector != 0 &&
         (layout->handler_selector & 7u) == 0 && layout->idt_limit >= 0x7e7 &&
         entry >= layout->idt_address;
}

int daze_kvm_raw_switch_gate_build(const DazeKvmRawSwitchGateLayout *layout,
                                   DazeKvmRawSwitchGateArtifacts *output) {
  if (!layout_valid(layout) || output == NULL) return 0;
  DazeKvmRawSwitchGateArtifacts built = {
    /* Preserve AX: the protected-to-real request uses it for raw DS, while
     * the marker necessarily writes AL. The host consumes the saved value
     * and replaces CPU mode/state before this temporary stack word returns. */
    .handler = {0x50, 0xb0, DAZE_KVM_RAW_SWITCH_GATE_MARKER, 0xe6, DAZE_PORT_GATE, 0xf4},
  };
  daze_kvm_encode_idt_gate(built.idt_entry, layout->handler_address, layout->handler_selector,
                           0x8e);
  /* Real-mode INT FCh must reach the same bounded marker through the IVT.
   * The caller gives the low-memory placement explicitly; no segment is
   * inferred from the protected handler's selector. */
  built.ivt_entry[0] = 0;
  built.ivt_entry[1] = 0;
  built.ivt_entry[2] = (uint8_t)(layout->real_handler_address >> 4);
  built.ivt_entry[3] = (uint8_t)(layout->real_handler_address >> 12);
  *output = built;
  return 1;
}

static int raw_boundary(const DazeKvmDpmiEntryResult *boundary) {
  const DazeKvmDpmiEntryObservation *observation = &boundary->observation;
  return observation->kind == DAZE_KVM_DPMI_ENTRY_EXIT_PIO &&
         observation->pio_direction == DAZE_KVM_DPMI_ENTRY_PIO_OUT &&
         observation->pio_port == DAZE_PORT_GATE && observation->pio_size == 1 &&
         observation->pio_count == 1 && observation->pio_value_present &&
         (uint8_t)observation->pio_value == DAZE_KVM_RAW_SWITCH_GATE_MARKER;
}

static struct kvm_segment real_segment(uint16_t selector) {
  struct kvm_segment segment = {0};
  segment.base = (uint64_t)selector << 4;
  segment.limit = 0xffff;
  segment.selector = selector;
  segment.type = 3;
  segment.present = 1;
  segment.s = 1;
  return segment;
}

static int consume_boundary(DazeKvmMachine *machine, const DazeKvmRawSwitchGateLayout *layout,
                            const DazeKvmDpmiEntryResult *boundary,
                            DazeKvmRawSwitchGateResult *result) {
  if (machine == NULL || machine->guest == NULL || boundary == NULL || result == NULL ||
      !layout_valid(layout))
    return DAZE_KVM_RAW_SWITCH_GATE_INVALID;
  result->boundary = *boundary;
  if (!raw_boundary(boundary)) return DAZE_KVM_RAW_SWITCH_GATE_FAILED;
  struct kvm_sregs sregs;
  struct kvm_regs regs;
  const uint32_t saved_eax_address = boundary->ss_base + boundary->esp;
  if (saved_eax_address < boundary->ss_base ||
      !daze_kvm_range_fits(machine->guest_size, saved_eax_address, 8) ||
      ioctl(machine->vcpu, KVM_GET_SREGS, &sregs) < 0 ||
      ioctl(machine->vcpu, KVM_GET_REGS, &regs) < 0)
    return DAZE_KVM_RAW_SWITCH_GATE_FAILED;
  const uint32_t saved_eax =
    (uint32_t)((const uint8_t *)machine->guest)[saved_eax_address] |
    (uint32_t)((const uint8_t *)machine->guest)[saved_eax_address + 1] << 8 |
    (uint32_t)((const uint8_t *)machine->guest)[saved_eax_address + 2] << 16 |
    (uint32_t)((const uint8_t *)machine->guest)[saved_eax_address + 3] << 24;
  result->request = (DazeKvmRawSwitchRequest){.ax = (uint16_t)saved_eax,
                                              .bx = (uint16_t)regs.rbx,
                                              .cx = (uint16_t)regs.rcx,
                                              .dx = (uint16_t)regs.rdx,
                                              .si = (uint16_t)regs.rsi,
                                              .di = (uint16_t)regs.rdi,
                                              .bp = (uint16_t)regs.rbp,
                                              .flags = (uint16_t)regs.rflags};
  /* A real-mode marker captures the caller's return state without switching
   * CPU modes. The owner decides how to service the next boundary. */
  if ((boundary->cr0 & 1u) == 0) {
    const uint8_t *stack = (const uint8_t *)machine->guest + saved_eax_address;
    result->real_mode_state = (DpmiAlternateState){
      .eax = (uint32_t)(regs.rax & ~UINT64_C(0xffff)) | result->request.ax,
      .ebx = (uint32_t)regs.rbx,
      .ecx = (uint32_t)regs.rcx,
      .edx = (uint32_t)regs.rdx,
      .esi = (uint32_t)regs.rsi,
      .edi = (uint32_t)regs.rdi,
      .ebp = (uint32_t)regs.rbp,
      .esp = (uint16_t)(regs.rsp + 8),
      .eip = (uint16_t)(stack[2] | ((uint16_t)stack[3] << 8)),
      .eflags = (uint16_t)(stack[6] | ((uint16_t)stack[7] << 8)),
      .cs = (uint16_t)(stack[4] | ((uint16_t)stack[5] << 8)),
      .ds = sregs.ds.selector,
      .es = sregs.es.selector,
      .fs = sregs.fs.selector,
      .gs = sregs.gs.selector,
      .ss = sregs.ss.selector,
    };
    result->real_mode_state_valid = daze_dpmi_alternate_state_valid(&result->real_mode_state);
    return result->real_mode_state_valid ? DAZE_KVM_RAW_SWITCH_GATE_OK
                                         : DAZE_KVM_RAW_SWITCH_GATE_FAILED;
  }
  sregs.cs = real_segment(result->request.si);
  sregs.ds = real_segment(result->request.ax);
  sregs.es = real_segment(result->request.cx);
  sregs.fs = real_segment(0);
  sregs.gs = real_segment(0);
  sregs.ss = real_segment(result->request.dx);
  sregs.cr0 &= ~1u;
  sregs.cr4 = 0;
  sregs.efer = 0;
  /* Once PE is clear, INT vectors are the real-mode IVT. The protected IDT
   * remains a cached CPU register across CR0 writes, so reset it explicitly
   * instead of letting a later real-mode INT FC index the protected table. */
  sregs.idt.base = 0;
  sregs.idt.limit = 0x03ff;
  regs.rip = result->request.di;
  regs.rsp = result->request.bx;
  regs.rax = saved_eax;
  regs.rflags = result->request.flags;
  daze_kvm_machine_debug_invalidate(machine);
  return ioctl(machine->vcpu, KVM_SET_SREGS, &sregs) == 0 &&
             ioctl(machine->vcpu, KVM_SET_REGS, &regs) == 0
           ? DAZE_KVM_RAW_SWITCH_GATE_OK
           : DAZE_KVM_RAW_SWITCH_GATE_FAILED;
}

int daze_kvm_raw_switch_gate_run_from_boundary(DazeKvmMachine *machine,
                                               const DazeKvmRawSwitchGateLayout *layout,
                                               const DazeKvmDpmiEntryResult *boundary,
                                               DazeKvmRawSwitchGateResult *result) {
  if (result != NULL) *result = (DazeKvmRawSwitchGateResult){0};
  return consume_boundary(machine, layout, boundary, result);
}

static struct kvm_segment protected_code_segment(uint16_t selector, uint32_t base) {
  struct kvm_segment segment = {0};
  segment.base = base;
  segment.limit = 0xffff;
  segment.selector = selector;
  segment.type = 0x0a;
  segment.present = 1;
  segment.s = 1;
  return segment;
}

static struct kvm_segment ldt_segment(uint32_t base, uint16_t limit) {
  struct kvm_segment segment = {0};
  segment.base = base;
  segment.limit = limit;
  segment.selector = DAZE_SEL_RAW_SWITCH;
  segment.type = 2;
  segment.present = 1;
  return segment;
}

int daze_kvm_raw_switch_gate_return_to_protected(DazeKvmMachine *machine,
                                                 const DazeKvmRawSwitchGateLayout *gate,
                                                 const DazeKvmRawSwitchReturnLayout *layout,
                                                 const DazeKvmRawSwitchRequest *request) {
  static const uint8_t wrapper[] = {
    0x2e, 0xa1, 0x00, 0x02,       /* mov ax,cs:[0200] */
    0x8e, 0xd8,                   /* mov ds,ax */
    0x2e, 0xa1, 0x02, 0x02,       /* mov ax,cs:[0202] */
    0x8e, 0xc0,                   /* mov es,ax */
    0x2e, 0xa1, 0x04, 0x02,       /* mov ax,cs:[0204] */
    0x8e, 0xd0,                   /* mov ss,ax */
    0x2e, 0x8b, 0x26, 0x06, 0x02, /* mov sp,cs:[0206] */
    0x66, 0x0f, 0xb7, 0xe4,       /* movzx esp,sp */
    0x2e, 0xa1, 0x08, 0x02,       /* mov ax,cs:[0208] */
    0x8e, 0xe0,                   /* mov fs,ax */
    0x2e, 0xa1, 0x0a, 0x02,       /* mov ax,cs:[020a] */
    0x8e, 0xe8,                   /* mov gs,ax */
    0x2e, 0xa1, 0x0c, 0x02,       /* mov ax,cs:[020c] */
    0x2e, 0x8b, 0x1e, 0x0e, 0x02, /* mov bx,cs:[020e] */
    0x2e, 0x8b, 0x0e, 0x10, 0x02, /* mov cx,cs:[0210] */
    0x2e, 0x8b, 0x16, 0x12, 0x02, /* mov dx,cs:[0212] */
    0x2e, 0x8b, 0x36, 0x14, 0x02, /* mov si,cs:[0214] */
    0x2e, 0x8b, 0x3e, 0x16, 0x02, /* mov di,cs:[0216] */
    0x2e, 0x8b, 0x2e, 0x18, 0x02, /* mov bp,cs:[0218] */
    0x2e, 0xff, 0x36, 0x1a, 0x02, /* push cs:[021a] */
    0x9d,                         /* popf */
    0x2e, 0xff, 0x2e, 0x1c, 0x02, /* jmp far cs:[021c] */
  };
  if (machine == NULL || gate == NULL || layout == NULL || request == NULL || !layout_valid(gate) ||
      layout->wrapper_selector == 0 || layout->wrapper_address < layout->protected_code_base ||
      layout->gdt_address == 0 || layout->gdt_limit < 0x47 || layout->ldt_address == 0 ||
      !daze_kvm_range_fits(machine->guest_size, layout->wrapper_address, sizeof(wrapper)) ||
      !daze_kvm_range_fits(machine->guest_size, layout->state_address, 32))
    return DAZE_KVM_RAW_SWITCH_GATE_INVALID;
  const uint16_t state[] = {request->ax, request->cx, request->dx, request->bx,    0,
                            0,           request->ax, request->bx, request->cx,    request->dx,
                            request->si, request->di, request->bp, request->flags, request->di,
                            request->si};
  struct kvm_sregs sregs;
  struct kvm_regs regs;
  if (!daze_kvm_machine_write(machine, layout->wrapper_address, wrapper, sizeof(wrapper)) ||
      !daze_kvm_machine_write(machine, layout->state_address, state, sizeof(state)) ||
      ioctl(machine->vcpu, KVM_GET_SREGS, &sregs) < 0 ||
      ioctl(machine->vcpu, KVM_GET_REGS, &regs) < 0)
    return DAZE_KVM_RAW_SWITCH_GATE_FAILED;
  /* A restored EXEC parent has CR0 clear; resident protected selectors require the
   * real-mode CR0.ET baseline as well as PE. */
  sregs.cr0 |= 0x11u;
  sregs.gdt.base = layout->gdt_address;
  sregs.gdt.limit = layout->gdt_limit;
  /* This route bypasses the client's LLDT, so reinstall the transition LDT before
   * loading TI=1 selectors. */
  sregs.ldt = ldt_segment(layout->ldt_address, layout->ldt_limit);
  sregs.idt.base = gate->idt_address;
  sregs.idt.limit = gate->idt_limit;
  sregs.cs = protected_code_segment(layout->wrapper_selector, layout->protected_code_base);
  regs.rip = layout->wrapper_address - layout->protected_code_base;
  daze_kvm_machine_debug_invalidate(machine);
  return ioctl(machine->vcpu, KVM_SET_SREGS, &sregs) == 0 &&
             ioctl(machine->vcpu, KVM_SET_REGS, &regs) == 0
           ? DAZE_KVM_RAW_SWITCH_GATE_OK
           : DAZE_KVM_RAW_SWITCH_GATE_FAILED;
}
#else
int daze_kvm_raw_switch_gate_build(const DazeKvmRawSwitchGateLayout *layout,
                                   DazeKvmRawSwitchGateArtifacts *output) {
  (void)layout;
  (void)output;
  return 0;
}
int daze_kvm_raw_switch_gate_run_from_boundary(DazeKvmMachine *machine,
                                               const DazeKvmRawSwitchGateLayout *layout,
                                               const DazeKvmDpmiEntryResult *boundary,
                                               DazeKvmRawSwitchGateResult *result) {
  (void)machine;
  (void)layout;
  (void)boundary;
  if (result != NULL) *result = (DazeKvmRawSwitchGateResult){0};
  return DAZE_KVM_RAW_SWITCH_GATE_FAILED;
}
int daze_kvm_raw_switch_gate_return_to_protected(DazeKvmMachine *machine,
                                                 const DazeKvmRawSwitchGateLayout *gate,
                                                 const DazeKvmRawSwitchReturnLayout *layout,
                                                 const DazeKvmRawSwitchRequest *request) {
  (void)machine;
  (void)gate;
  (void)layout;
  (void)request;
  return DAZE_KVM_RAW_SWITCH_GATE_FAILED;
}
#endif
