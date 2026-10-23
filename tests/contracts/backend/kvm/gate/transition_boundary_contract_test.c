#include "raw_switch.h"
#include "kvm_state_save_gate.h"
#include "descriptor.h"
#include "byte_order.h"
#include "port.h"

#include <stdio.h>
#include <string.h>
#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
#include <linux/kvm.h>
#include <sys/ioctl.h>

static const DazeKvmRawSwitchGateLayout raw_layout = {.idt_address = 0x4000,
                                                      .handler_address = 0x6000,
                                                      .real_handler_address = 0x7000,
                                                      .idt_limit = 0x7ff,
                                                      .handler_selector = 8};
static const DazeKvmStateSaveGateLayout save_layout = {
  .idt_address = 0x4000, .handler_address = 0x6000, .idt_limit = 0x7ff, .handler_selector = 8};

static struct kvm_segment segment(uint16_t selector, uint32_t base, int code, int wide) {
  return (struct kvm_segment){.selector = selector,
                              .base = base,
                              .limit = 0xffff,
                              .type = code ? 0xb : 3,
                              .present = 1,
                              .s = 1,
                              .db = wide};
}

static int park(DazeKvmMachine *machine, uint8_t marker, int protected_mode,
                DazeKvmDpmiEntryResult *boundary) {
  uint8_t *guest = machine->guest;
  const uint8_t code[] = {0x50, 0xb0, marker, 0xe6, DAZE_PORT_GATE, 0xf4};
  memcpy(guest + 0x6000, code, sizeof(code));
  if (daze_kvm_machine_set_real_mode(machine, 0x600, 0, 0x1800, 0x100, 0x1234, 0x2345) !=
      DAZE_KVM_MACHINE_OK)
    return 0;
  struct kvm_sregs sr;
  struct kvm_regs r = {.rax = 0xa5a51000,
                       .rbx = 0x0100,
                       .rcx = 0x2000,
                       .rdx = 0x1800,
                       .rsi = 0x800,
                       .rdi = 0x20,
                       .rbp = 0x55,
                       .rsp = 0x100,
                       .rflags = 2};
  if (ioctl(machine->vcpu, KVM_GET_SREGS, &sr) < 0) return 0;
  if (protected_mode) {
    sr.cr0 |= 0x11;
    sr.cs = segment(8, 0x6000, 1, 1);
    sr.ss = segment(0x10, 0x18000, 0, 1);
    sr.es = segment(0x18, 0x26000, 0, 1);
    sr.ds = sr.ss;
    sr.gdt.base = 0x2000;
    sr.gdt.limit = 0x47;
    sr.ldt = (struct kvm_segment){
      .selector = 0x40, .base = 0x3000, .limit = 0x3f, .type = 2, .present = 1};
  }
  return ioctl(machine->vcpu, KVM_SET_SREGS, &sr) == 0 &&
         ioctl(machine->vcpu, KVM_SET_REGS, &r) == 0 &&
         daze_kvm_dpmi_entry_continue_once(machine, boundary) == DAZE_KVM_DPMI_ENTRY_OK &&
         boundary->observation.kind == DAZE_KVM_DPMI_ENTRY_EXIT_PIO &&
         boundary->observation.pio_value == marker;
}

static int raw_case(DazeKvmMachine *m, int protected_mode) {
  DazeKvmDpmiEntryResult b;
  if (!park(m, DAZE_KVM_RAW_SWITCH_GATE_MARKER, protected_mode, &b)) return 0;
  uint8_t *guest = m->guest;
  if (!protected_mode) {
    daze_write_u16(guest + 0x18100, 0x1234);
    daze_write_u16(guest + 0x18102, 0x3456);
    daze_write_u16(guest + 0x18104, 0x0203);
  }
  struct kvm_regs before, after;
  struct kvm_sregs sbefore, safter;
  if (ioctl(m->vcpu, KVM_GET_REGS, &before) < 0 || ioctl(m->vcpu, KVM_GET_SREGS, &sbefore) < 0)
    return 0;
  DazeKvmRawSwitchGateResult result;
  for (int kind = 0; kind < 8; ++kind) {
    DazeKvmDpmiEntryResult invalid = b;
    if (kind == 0) invalid.observation.kind = DAZE_KVM_DPMI_ENTRY_EXIT_HLT;
    if (kind == 1) invalid.observation.pio_direction = DAZE_KVM_DPMI_ENTRY_PIO_IN;
    if (kind == 2) invalid.observation.pio_size = 2;
    if (kind == 3) invalid.observation.pio_count = 2;
    if (kind == 4) invalid.observation.pio_value_present = 0;
    if (kind == 5) invalid.observation.pio_port = 0x21;
    if (kind == 6) invalid.ss_base = UINT32_MAX;
    if (kind == 7) invalid.esp = m->guest_size;
    if (daze_kvm_raw_switch_gate_run_from_boundary(m, &raw_layout, &invalid, &result) !=
        DAZE_KVM_RAW_SWITCH_GATE_FAILED)
      return 0;
    if (ioctl(m->vcpu, KVM_GET_REGS, &after) < 0 || memcmp(&before, &after, sizeof(before)) != 0)
      return 0;
  }
  if (daze_kvm_raw_switch_gate_run_from_boundary(m, &raw_layout, &b, &result) !=
        DAZE_KVM_RAW_SWITCH_GATE_OK ||
      result.request.ax != 0x1000 || result.request.si != 0x800 || result.request.bp != 0x55)
    return 0;
  if (ioctl(m->vcpu, KVM_GET_REGS, &after) < 0 || ioctl(m->vcpu, KVM_GET_SREGS, &safter) < 0)
    return 0;
  if (!protected_mode)
    return result.real_mode_state_valid && result.real_mode_state.cs == 0x3456 &&
           result.real_mode_state.eip == 0x1234 && result.real_mode_state.eflags == 0x203 &&
           result.real_mode_state.esp == 0x106 && result.real_mode_state.eax == 0xa5a51000 &&
           memcmp(&before, &after, sizeof(before)) == 0 &&
           memcmp(&sbefore, &safter, sizeof(sbefore)) == 0;
  guest[0x8020] = 0xf4;
  return !(safter.cr0 & 1) && safter.idt.base == 0 && safter.idt.limit == 0x3ff &&
         safter.cs.selector == 0x800 && safter.cs.base == 0x8000 && safter.ds.base == 0x10000 &&
         safter.es.base == 0x20000 && safter.ss.base == 0x18000 && after.rip == 0x20 &&
         after.rsp == 0x100 && after.rax == 0xa5a51000 &&
         daze_kvm_dpmi_entry_continue_once(m, &b) == DAZE_KVM_DPMI_ENTRY_OK &&
         b.observation.kind == DAZE_KVM_DPMI_ENTRY_EXIT_HLT && b.rip == 0x21;
}

static int return_case(DazeKvmMachine *m) {
  uint8_t *guest = m->guest;
  const DazeKvmRawSwitchReturnLayout layout = {.wrapper_address = 0x5180,
                                               .state_address = 0x5200,
                                               .protected_code_base = 0x5000,
                                               .gdt_address = 0x2000,
                                               .ldt_address = 0x3000,
                                               .wrapper_selector = 8,
                                               .gdt_limit = 0x47,
                                               .ldt_limit = 0x3f};
  const DazeKvmRawSwitchRequest request = {
    .ax = 0x10, .cx = 0x10, .dx = 0x10, .bx = 0x100, .si = 8, .di = 0x400, .bp = 0x55, .flags = 2};
  daze_dpmi_descriptor_encode(guest + 0x2008, 0x5000, 0xffff, 0x9a, 0);
  daze_dpmi_descriptor_encode(guest + 0x2010, 0x26000, 0xffff, 0x92, 0);
  guest[0x5400] = 0xf4;
  if (daze_kvm_raw_switch_gate_return_to_protected(m, &raw_layout, &layout, &request) !=
      DAZE_KVM_RAW_SWITCH_GATE_OK)
    return 0;
  struct kvm_sregs sr;
  struct kvm_regs r;
  if (ioctl(m->vcpu, KVM_GET_REGS, &r) < 0 || ioctl(m->vcpu, KVM_GET_SREGS, &sr) < 0 ||
      !(sr.cr0 & 1) || sr.cs.base != 0x5000 || r.rip != 0x180 || sr.ldt.base != 0x3000 ||
      sr.gdt.base != 0x2000 || sr.idt.base != 0x4000)
    return 0;
  DazeKvmDpmiEntryResult b;
  return daze_kvm_dpmi_entry_continue_once(m, &b) == DAZE_KVM_DPMI_ENTRY_OK &&
         b.observation.kind == DAZE_KVM_DPMI_ENTRY_EXIT_HLT && b.cs == 8 && b.rip == 0x401 &&
         b.ds_base == 0x26000 && b.ax == 0x10 && b.bx == 0x100 &&
         ioctl(m->vcpu, KVM_GET_REGS, &r) == 0 && r.rbp == 0x55;
}

static int save_case(DazeKvmMachine *m, int narrow) {
  DazeKvmDpmiEntryResult b;
  if (!park(m, DAZE_KVM_STATE_SAVE_GATE_MARKER, 1, &b)) return 0;
  uint8_t *guest = m->guest;
  daze_write_u32(guest + 0x18100, 0x20);
  daze_write_u32(guest + 0x18104, 0x14);
  daze_write_u32(guest + 0x18108, 2);
  daze_dpmi_descriptor_encode(guest + 0x3010, 0x9000, 0xffff, 0x9a, 0);
  daze_dpmi_descriptor_encode(guest + 0x2008, 0x5000, 0xffff, 0x9a, 0);
  guest[0x9020] = 0x66;
  guest[0x9021] = 0xcb;
  daze_write_u16(guest + 0x1810c, 0x1234);
  daze_write_u16(guest + 0x1810e, narrow ? 8 : 0);
  daze_write_u16(guest + 0x18110, narrow ? 0 : 8);
  daze_write_u16(guest + 0x180fc, 0);
  const DpmiAlternateState state = {
    .eax = 0xaabbccdd, .esp = 0x100, .cs = 0x1234, .ds = 0x1000, .ss = 0x1800, .eflags = 2};
  uint8_t packed[DAZE_DPMI_ALTERNATE_STATE_SIZE];
  if (!daze_dpmi_alternate_state_pack(&state, packed)) return 0;
  DazeKvmStateSaveGateResult result;
  for (int kind = 0; kind < 7; ++kind) {
    DazeKvmDpmiEntryResult bad = b;
    if (kind == 0) bad.observation.pio_port = 0x21;
    if (kind == 1) bad.observation.pio_size = 2;
    if (kind == 2) bad.ss_base = UINT32_MAX;
    if (kind == 3) bad.es_base = UINT32_MAX;
    if (kind == 4) bad.es_base = m->guest_size - 1;
    if (kind == 5) bad.esp = m->guest_size;
    if (kind == 6) daze_write_u16(guest + 0x180fc, 1);
    memset(guest + 0x26020, 0xa5, sizeof(packed));
    if (daze_kvm_state_save_gate_run(m, &save_layout, &state, &bad, &result) !=
          DAZE_KVM_STATE_SAVE_GATE_FAILED ||
        guest[0x26020] != 0xa5)
      return 0;
    daze_write_u16(guest + 0x180fc, 0);
  }
  if (daze_kvm_state_save_gate_run(m, &save_layout, &state, &b, &result) !=
        DAZE_KVM_STATE_SAVE_GATE_OK ||
      result.caller_frame_widened != narrow || result.buffer_address != 0x26020 ||
      memcmp(guest + 0x26020, packed, sizeof(packed)))
    return 0;
  struct kvm_regs r;
  if (ioctl(m->vcpu, KVM_GET_REGS, &r) < 0 || r.rsp != (unsigned)(narrow ? 0xf8 : 0xfc)) return 0;
  if (narrow)
    return daze_read_u32(guest + 0x18108) == 0x1234 && daze_read_u32(guest + 0x1810c) == 8;
  return daze_read_u32(guest + 0x1810c) == 0x1234 && daze_read_u32(guest + 0x18110) == 8;
}

static int stale_frame_case(DazeKvmMachine *m) {
  DazeKvmDpmiEntryResult b;
  if (!park(m, DAZE_KVM_STATE_SAVE_GATE_MARKER, 1, &b)) return 0;
  uint8_t *guest = m->guest;
  daze_write_u32(guest + 0x18100, 0x20);
  daze_write_u32(guest + 0x18104, 0x14);
  daze_write_u32(guest + 0x18108, 2);
  daze_write_u16(guest + 0x1810c, 0x1234);
  daze_write_u16(guest + 0x1810e, 8);
  daze_write_u16(guest + 0x18110, 0);
  daze_dpmi_descriptor_encode(guest + 0x3010, 0x9000, 0xffff, 0x9a, 0);
  daze_dpmi_descriptor_encode(guest + 0x2008, 0x5000, 0xffff, 0x9a, 0);
  guest[0x9020] = 0x66;
  guest[0x9021] = 0xcb;
  struct kvm_regs r;
  if (ioctl(m->vcpu, KVM_GET_REGS, &r) < 0) return 0;
  r.rsp = 0x80;
  if (ioctl(m->vcpu, KVM_SET_REGS, &r) < 0) return 0;
  uint8_t before[32];
  memcpy(before, guest + 0x180f8, sizeof(before));
  return daze_kvm_state_save_gate_widen_caller_frame(m, &b) == DAZE_KVM_STATE_SAVE_GATE_FAILED &&
         memcmp(before, guest + 0x180f8, sizeof(before)) == 0;
}

static int save_rejection_matrix(DazeKvmMachine *m) {
  DazeKvmDpmiEntryResult original;
  if (!park(m, DAZE_KVM_STATE_SAVE_GATE_MARKER, 1, &original)) return 0;
  uint8_t *guest = m->guest;
  struct kvm_regs regs, after;
  if (ioctl(m->vcpu, KVM_GET_REGS, &regs) < 0) return 0;
  for (unsigned kind = 0; kind < 27; ++kind) {
    DazeKvmDpmiEntryResult b = original;
    daze_write_u32(guest + 0x18100, 0x20);
    daze_write_u32(guest + 0x18104, 0x14);
    daze_write_u32(guest + 0x18108, 2);
    daze_write_u16(guest + 0x1810c, 0x1234);
    daze_write_u16(guest + 0x1810e, 8);
    daze_write_u16(guest + 0x18110, 0);
    daze_dpmi_descriptor_encode(guest + 0x3010, 0x9000, 0xffff, 0x9a, 0);
    daze_dpmi_descriptor_encode(guest + 0x2008, 0x5000, 0xffff, 0x9a, 0);
    guest[0x9020] = 0x66;
    guest[0x9021] = 0xcb;
    int expected = DAZE_KVM_STATE_SAVE_GATE_OK;
    switch (kind) {
    case 0:
      b.cs_db = 0;
      break;
    case 1:
      b.ss_base = m->guest_size + 1;
      break;
    case 2:
      b.esp = UINT32_MAX;
      break;
    case 3:
      b.esp = UINT32_MAX - 7;
      break;
    case 4:
      b.esp = 3;
      break;
    case 5:
      b.esp = m->guest_size;
      break;
    case 6:
      b.ss_base = m->guest_size - 0x110;
      break;
    case 7:
      daze_write_u16(guest + 0x18104, 0);
      break;
    case 8:
      b.ldt_base = UINT32_MAX - 8;
      break;
    case 9:
      b.ldt_limit = 0xf;
      break;
    case 10:
      b.ldt_limit = 0x16;
      break;
    case 11:
      b.ldt_base = m->guest_size - 0x14;
      break;
    case 12:
      guest[0x3015] = 0x92;
      break;
    case 13:
      daze_dpmi_descriptor_encode(guest + 0x3010, m->guest_size, 0xffff, 0x9a, 0);
      break;
    case 14:
      daze_dpmi_descriptor_encode(guest + 0x3010, m->guest_size - 0x21, 0xffff, 0x9a, 0);
      break;
    case 15:
      guest[0x9020] = 0x90;
      break;
    case 16:
      guest[0x9021] = 0x90;
      break;
    case 17:
      daze_write_u16(guest + 0x1810e, 0);
      break;
    case 18:
      daze_write_u16(guest + 0x18110, 8);
      break;
    case 19:
      b.observation.kind = DAZE_KVM_DPMI_ENTRY_EXIT_HLT;
      expected = DAZE_KVM_STATE_SAVE_GATE_INVALID;
      break;
    case 20:
      b.observation.pio_direction = DAZE_KVM_DPMI_ENTRY_PIO_IN;
      expected = DAZE_KVM_STATE_SAVE_GATE_INVALID;
      break;
    case 21:
      b.observation.pio_port = 0;
      expected = DAZE_KVM_STATE_SAVE_GATE_INVALID;
      break;
    case 22:
      b.observation.pio_size = 2;
      expected = DAZE_KVM_STATE_SAVE_GATE_INVALID;
      break;
    case 23:
      b.observation.pio_count = 2;
      expected = DAZE_KVM_STATE_SAVE_GATE_INVALID;
      break;
    case 24:
      b.observation.pio_value_present = 0;
      b.ax = 0;
      expected = DAZE_KVM_STATE_SAVE_GATE_INVALID;
      break;
    case 25:
      b.observation.pio_value = 0;
      b.ax = 0;
      expected = DAZE_KVM_STATE_SAVE_GATE_INVALID;
      break;
    case 26:
      b.observation.pio_value_present = 0;
      b.cs_db = 0;
      break;
    }
    uint8_t saved[32];
    memcpy(saved, guest + 0x180f8, sizeof(saved));
    int status = daze_kvm_state_save_gate_widen_caller_frame(m, &b);
    if (status != expected || memcmp(saved, guest + 0x180f8, sizeof(saved)) ||
        ioctl(m->vcpu, KVM_GET_REGS, &after) < 0 || memcmp(&regs, &after, sizeof(regs))) {
      fprintf(stderr, "state-save rejection %u failed: %d\n", kind, status);
      return 0;
    }
  }
  DazeKvmStateSaveGateResult result;
  const DpmiAlternateState state = {.eflags = 2};
  DazeKvmMachine absent = *m;
  absent.guest = NULL;
  if (daze_kvm_state_save_gate_widen_caller_frame(NULL, &original) !=
        DAZE_KVM_STATE_SAVE_GATE_INVALID ||
      daze_kvm_state_save_gate_widen_caller_frame(&absent, &original) !=
        DAZE_KVM_STATE_SAVE_GATE_INVALID ||
      daze_kvm_state_save_gate_widen_caller_frame(m, NULL) != DAZE_KVM_STATE_SAVE_GATE_INVALID)
    return 0;
  for (unsigned kind = 0; kind < 6; ++kind) {
    memset(&result, 0xa5, sizeof(result));
    if (daze_kvm_state_save_gate_run(kind == 0   ? NULL
                                     : kind == 1 ? &absent
                                                 : m,
                                     kind == 4 ? NULL : &save_layout, kind == 5 ? NULL : &state,
                                     kind == 3 ? NULL : &original, kind == 2 ? NULL : &result) !=
        DAZE_KVM_STATE_SAVE_GATE_INVALID)
      return 0;
    const DazeKvmStateSaveGateResult zero = {0};
    if (kind != 2 && memcmp(&result, &zero, sizeof(result))) return 0;
  }
  DazeKvmStateSaveGateArtifacts artifact;
  return !daze_kvm_state_save_gate_build(NULL, &artifact) &&
         !daze_kvm_state_save_gate_build(&save_layout, NULL);
}

static int rejected_layouts(DazeKvmMachine *m) {
  DazeKvmRawSwitchGateArtifacts raw, raw_before;
  DazeKvmStateSaveGateArtifacts save, save_before;
  memset(&raw, 0xa5, sizeof(raw));
  raw_before = raw;
  memset(&save, 0x5a, sizeof(save));
  save_before = save;
  for (int kind = 0; kind < 7; ++kind) {
    DazeKvmRawSwitchGateLayout r = raw_layout;
    DazeKvmStateSaveGateLayout s = save_layout;
    if (kind == 0) {
      r.handler_address = 0;
      s.handler_address = 0;
    }
    if (kind == 1) {
      r.handler_selector = 0;
      s.handler_selector = 0;
    }
    if (kind == 2) {
      r.handler_selector = 4;
      s.handler_selector = 4;
    }
    if (kind == 3) {
      r.idt_limit = 0;
      s.idt_limit = 0;
    }
    if (kind == 4) {
      r.idt_address = UINT32_MAX;
      s.idt_address = UINT32_MAX;
    }
    if (kind == 5) r.real_handler_address = 0;
    if (kind == 6) r.real_handler_address = UINT32_MAX;
    if (daze_kvm_raw_switch_gate_build(&r, &raw) || memcmp(&raw, &raw_before, sizeof(raw)))
      return 0;
    if (kind < 5 &&
        (daze_kvm_state_save_gate_build(&s, &save) || memcmp(&save, &save_before, sizeof(save))))
      return 0;
  }
  const DazeKvmRawSwitchReturnLayout valid = {.wrapper_address = 0x5180,
                                              .state_address = 0x5200,
                                              .protected_code_base = 0x5000,
                                              .gdt_address = 0x2000,
                                              .ldt_address = 0x3000,
                                              .wrapper_selector = 8,
                                              .gdt_limit = 0x47,
                                              .ldt_limit = 0x3f};
  const DazeKvmRawSwitchRequest request = {0};
  uint8_t before[0x400];
  memcpy(before, (uint8_t *)m->guest + 0x5000, sizeof(before));
  for (int kind = 0; kind < 7; ++kind) {
    DazeKvmRawSwitchReturnLayout bad = valid;
    if (kind == 0) bad.wrapper_selector = 0;
    if (kind == 1) bad.wrapper_address = 0x4fff;
    if (kind == 2) bad.gdt_address = 0;
    if (kind == 3) bad.gdt_limit = 0x46;
    if (kind == 4) bad.ldt_address = 0;
    if (kind == 5) bad.wrapper_address = m->guest_size;
    if (kind == 6) bad.state_address = UINT32_MAX;
    if (daze_kvm_raw_switch_gate_return_to_protected(m, &raw_layout, &bad, &request) !=
          DAZE_KVM_RAW_SWITCH_GATE_INVALID ||
        memcmp(before, (uint8_t *)m->guest + 0x5000, sizeof(before)))
      return 0;
  }
  return 1;
}

int main(void) {
  DazeKvmMachine m;
  const int init = daze_kvm_machine_init(&m, 0x40000);
  if (init == DAZE_KVM_MACHINE_UNAVAILABLE) return 77;
  if (init != DAZE_KVM_MACHINE_OK) return 1;
  int pass = raw_case(&m, 0);
  if (!pass) fprintf(stderr, "raw real failed\n");
  int next = raw_case(&m, 1);
  if (!next) fprintf(stderr, "raw protected failed\n");
  pass &= next;
  next = return_case(&m);
  if (!next) fprintf(stderr, "raw return failed\n");
  pass &= next;
  next = save_case(&m, 0);
  if (!next) fprintf(stderr, "save wide failed\n");
  pass &= next;
  next = save_case(&m, 1);
  if (!next) fprintf(stderr, "save narrow failed\n");
  pass &= next;
  next = stale_frame_case(&m);
  if (!next) fprintf(stderr, "stale frame changed guest stack\n");
  pass &= next;
  next = save_rejection_matrix(&m);
  if (!next) fprintf(stderr, "save rejection matrix failed\n");
  pass &= next;
  next = rejected_layouts(&m);
  if (!next) fprintf(stderr, "rejected layout changed artifacts\n");
  pass &= next;
  daze_kvm_machine_destroy(&m);
  return pass ? 0 : 1;
}
#else
int main(void) {
  return 77;
}
#endif
