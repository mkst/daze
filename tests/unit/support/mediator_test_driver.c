#include "mediator_test_driver.h"

#include "kvm_bytes.h"
#include "memory.h"

#include <string.h>

#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
#include <linux/kvm.h>
#include <sys/ioctl.h>

enum {
  k_guest_size = 0x4000,
  k_gdt = 0x0600,
  k_idt = 0x0800,
  k_ldt = 0x1000,
  k_record = 0x1800,
  k_mailbox = 0x1900,
  k_capture = 0x1a00,
  k_caller = 0x0200,
  k_handler = 0x0300,
};

enum {
  k_capture_ax = DAZE_KVM_DPMI_TEST_CAPTURE_AX_OFFSET,
  k_capture_di = DAZE_KVM_DPMI_TEST_CAPTURE_DI_OFFSET,
  k_capture_es = DAZE_KVM_DPMI_TEST_CAPTURE_ES_OFFSET,
  k_capture_flags = DAZE_KVM_DPMI_TEST_CAPTURE_FLAGS_OFFSET,
  k_capture_bx = DAZE_KVM_DPMI_TEST_CAPTURE_BX_OFFSET,
  k_capture_cx = DAZE_KVM_DPMI_TEST_CAPTURE_CX_OFFSET,
  k_capture_si = DAZE_KVM_DPMI_TEST_CAPTURE_SI_OFFSET,
  k_capture_dx = DAZE_KVM_DPMI_TEST_CAPTURE_DX_OFFSET,
};

static const DazeKvmDpmiMediatorTestLayout k_layout = {
  .guest_size = k_guest_size,
  .gdt_address = k_gdt,
  .gdt_size = 0x18,
  .idt_address = k_idt,
  .ldt_address = k_ldt,
  .ldt_size = DAZE_KVM_DPMI_TEST_LDT_SIZE,
  .record_address = k_record,
  .mailbox_address = k_mailbox,
  .capture_address = k_capture,
};

static struct kvm_segment segment(uint16_t selector, uint8_t type) {
  struct kvm_segment value;
  memset(&value, 0, sizeof(value));
  value.base = 0;
  value.limit = 0xffff;
  value.selector = selector;
  value.type = type;
  value.present = 1;
  value.s = 1;
  value.db = 1;
  return value;
}

static void emit32(uint8_t *code, size_t *size, uint8_t opcode, uint32_t address) {
  code[(*size)++] = opcode;
  daze_write_u32(code + *size, address);
  *size += 4;
}

static void emit_store(uint8_t *code, size_t *size, uint8_t modrm, uint32_t address) {
  code[(*size)++] = 0x89;
  code[(*size)++] = modrm;
  daze_write_u32(code + *size, address);
  *size += 4;
}

static void emit_load(uint8_t *code, size_t *size, uint8_t modrm, uint32_t address) {
  code[(*size)++] = 0x8b;
  code[(*size)++] = modrm;
  daze_write_u32(code + *size, address);
  *size += 4;
}

static int install_guest(DazeKvmMachine *machine) {
  uint8_t *guest = machine->guest;
  static const uint8_t gdt[] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0x9a, 0xcf, 0, 0xff, 0xff, 0, 0, 0, 0x92, 0xcf, 0,
  };
  uint8_t caller[80] = {0};
  size_t caller_size = 0;
  caller[caller_size++] = 0xcd;
  caller[caller_size++] = 0x31;
  emit32(caller, &caller_size, 0xa3, k_capture + k_capture_ax);
  emit_store(caller, &caller_size, 0x1d, k_capture + k_capture_bx);
  emit_store(caller, &caller_size, 0x0d, k_capture + k_capture_cx);
  emit_store(caller, &caller_size, 0x15, k_capture + k_capture_dx);
  emit_store(caller, &caller_size, 0x35, k_capture + k_capture_si);
  emit_store(caller, &caller_size, 0x3d, k_capture + k_capture_di);
  caller[caller_size++] = 0x8c;
  caller[caller_size++] = 0xc0;
  emit32(caller, &caller_size, 0xa3, k_capture + k_capture_es);
  caller[caller_size++] = 0x9c;
  caller[caller_size++] = 0x58;
  emit32(caller, &caller_size, 0xa3, k_capture + k_capture_flags);
  caller[caller_size++] = 0xb0;
  caller[caller_size++] = 0x7e;
  caller[caller_size++] = 0xe6;
  caller[caller_size++] = 0xf4;
  caller[caller_size++] = 0xf4;

  uint8_t handler[160] = {0};
  size_t handler_size = 0;
  emit32(handler, &handler_size, 0xa3, k_record);
  emit_store(handler, &handler_size, 0x1d, k_record + 4);
  emit_store(handler, &handler_size, 0x0d, k_record + 8);
  emit_store(handler, &handler_size, 0x15, k_record + 12);
  emit_store(handler, &handler_size, 0x3d, k_record + 16);
  emit_store(handler, &handler_size, 0x35, k_record + 24);
  handler[handler_size++] = 0x8c;
  handler[handler_size++] = 0xc0;
  emit32(handler, &handler_size, 0xa3, k_record + 20);
  handler[handler_size++] = 0x8b;
  handler[handler_size++] = 0x04;
  handler[handler_size++] = 0x24;
  emit32(handler, &handler_size, 0xa3, k_record + 28);
  handler[handler_size++] = 0x8b;
  handler[handler_size++] = 0x44;
  handler[handler_size++] = 0x24;
  handler[handler_size++] = 0x04;
  emit32(handler, &handler_size, 0xa3, k_record + 32);
  handler[handler_size++] = 0x8b;
  handler[handler_size++] = 0x44;
  handler[handler_size++] = 0x24;
  handler[handler_size++] = 0x08;
  emit32(handler, &handler_size, 0xa3, k_record + 36);
  handler[handler_size++] = 0xb0;
  handler[handler_size++] = DAZE_KVM_DPMI_MEDIATOR_MARKER;
  handler[handler_size++] = 0xe6;
  handler[handler_size++] = 0xf4;
  emit32(handler, &handler_size, 0xa1, k_mailbox);
  emit_load(handler, &handler_size, 0x1d, k_mailbox + 4);
  emit_load(handler, &handler_size, 0x0d, k_mailbox + 8);
  emit_load(handler, &handler_size, 0x35, k_mailbox + 12);
  handler[handler_size++] = 0x8b;
  handler[handler_size++] = 0x3d;
  daze_write_u32(handler + handler_size, k_mailbox + 16);
  handler_size += 4;
  handler[handler_size++] = 0x52;
  handler[handler_size++] = 0x8b;
  handler[handler_size++] = 0x15;
  daze_write_u32(handler + handler_size, k_mailbox + 20);
  handler_size += 4;
  handler[handler_size++] = 0x8e;
  handler[handler_size++] = 0xc2;
  handler[handler_size++] = 0x5a;
  emit_load(handler, &handler_size, 0x15, k_mailbox + 24);
  handler[handler_size++] = 0x50;
  handler[handler_size++] = 0xa1;
  daze_write_u32(handler + handler_size, k_mailbox + 28);
  handler_size += 4;
  handler[handler_size++] = 0x89;
  handler[handler_size++] = 0x44;
  handler[handler_size++] = 0x24;
  handler[handler_size++] = 0x0c;
  handler[handler_size++] = 0x58;
  handler[handler_size++] = 0xcf;
  if (caller_size > sizeof(caller) || handler_size > sizeof(handler)) return 0;
  memcpy(guest + k_caller, caller, caller_size);
  memcpy(guest + k_handler, handler, handler_size);
  memcpy(guest + k_gdt, gdt, sizeof(gdt));
  daze_write_u16(guest + k_idt + 0x31 * 8, k_handler);
  daze_write_u16(guest + k_idt + 0x31 * 8 + 2, 0x0008);
  guest[k_idt + 0x31 * 8 + 5] = 0x8e;
  daze_write_u16(guest + k_idt + 0x31 * 8 + 6, 0);
  return 1;
}

int daze_kvm_dpmi_mediator_test_fixture_init(DazeKvmDpmiMediatorTestFixture *fixture,
                                             DazeKvmDpmiStateSaveEndpoints state_save_endpoints,
                                             DazeKvmDpmiRawSwitchEndpoints raw_switch_endpoints) {
  if (fixture == NULL) return DAZE_KVM_MACHINE_INVALID;
  memset(fixture, 0, sizeof(*fixture));
  fixture->layout = k_layout;
  const int status = daze_kvm_machine_init(&fixture->machine, fixture->layout.guest_size);
  if (status != DAZE_KVM_MACHINE_OK) return status;
  fixture->machine_initialized = 1;
  if (!install_guest(&fixture->machine)) {
    daze_kvm_dpmi_mediator_test_fixture_destroy(fixture);
    return DAZE_KVM_MACHINE_FAILED;
  }

  daze_dos_memory_init(&fixture->dos_memory, 0x3000, 0x3100);
  daze_dpmi_linear_memory_init(&fixture->linear_memory, 0x50000, 0x70000);
  fixture->virtual_interrupts_enabled = 1;
  fixture->mediator = (DazeKvmDpmiMediator){
    .guest = fixture->machine.guest,
    .guest_size = fixture->layout.guest_size,
    .record_address = fixture->layout.record_address,
    .mailbox_address = fixture->layout.mailbox_address,
    .gdt_address = fixture->layout.gdt_address,
    .gdt_size = fixture->layout.gdt_size,
    .ldt_address = fixture->layout.ldt_address,
    .ldt_size = fixture->layout.ldt_size,
    .ldt_used = fixture->ldt_used,
    .ldt_used_count = sizeof(fixture->ldt_used),
    .ldt_first_index = 16,
    .linear_memory = &fixture->linear_memory,
    .dos_memory = &fixture->dos_memory,
    .real_mode_vector_segment = fixture->real_mode_vector_segment,
    .real_mode_vector_offset = fixture->real_mode_vector_offset,
    .real_mode_vector_count =
      sizeof(fixture->real_mode_vector_segment) / sizeof(fixture->real_mode_vector_segment[0]),
    .virtual_interrupts_enabled = &fixture->virtual_interrupts_enabled,
    .state_save_endpoints = state_save_endpoints,
    .raw_switch_endpoints = raw_switch_endpoints,
  };
  return DAZE_KVM_MACHINE_OK;
}

void daze_kvm_dpmi_mediator_test_fixture_destroy(DazeKvmDpmiMediatorTestFixture *fixture) {
  if (fixture == NULL) return;
  if (fixture->machine_initialized) daze_kvm_machine_destroy(&fixture->machine);
  memset(fixture, 0, sizeof(*fixture));
}

static int enter_protected(DazeKvmMachine *machine, const DazeDpmiRequest *request) {
  struct kvm_sregs sregs;
  struct kvm_regs regs;
  if (ioctl(machine->vcpu, KVM_GET_SREGS, &sregs) < 0) return 0;
  sregs.cs = segment(0x0008, 0x0b);
  sregs.ds = segment(0x0010, 0x03);
  const uint16_t initial_es = (request->function == 0x0201 || request->function == 0x0203) ? 0x0010
                              : request->vector_segment == 0 ? 0x0010
                                                             : request->vector_segment;
  sregs.es = segment(initial_es, 0x03);
  sregs.ss = segment(0x0010, 0x03);
  sregs.ss.db = 0;
  sregs.fs = segment(0x0010, 0x03);
  sregs.gs = segment(0x0010, 0x03);
  sregs.idt.base = k_idt;
  sregs.idt.limit = 0x7ff;
  sregs.gdt.base = k_gdt;
  sregs.gdt.limit = 0x17;
  sregs.cr0 = 1;
  sregs.cr4 = 0;
  sregs.efer = 0;
  if (ioctl(machine->vcpu, KVM_SET_SREGS, &sregs) < 0) return 0;
  memset(&regs, 0, sizeof(regs));
  regs.rip = k_caller;
  regs.rsp = 0x1f00;
  regs.rflags = 0x202;
  const int transition = request->function == 0x0305 || request->function == 0x0306;
  const int scalar =
    request->function == 0x0400 || request->function == 0x0900 || request->function == 0x0901;
  regs.rax = (request->function == 0x0200 || request->function == 0x0204 || transition || scalar)
               ? 0xc3c30000u | request->function
               : request->function;
  regs.rbx = transition || request->function == 0x0400                      ? 0xb1b10000u
             : (request->function == 0x0501 || request->function == 0x0503) ? request->size >> 16
             : request->function == 0x0102                                  ? request->size >> 4
             : request->function == 0x0100 ? 0xb1b10000u | request->count
                                           : request->selector;
  regs.rcx = (request->function == 0x0200 || request->function == 0x0202 ||
              request->function == 0x0204 || transition)
               ? 0xa5a50000u
             : (request->function == 0x0201 || request->function == 0x0203)
               ? 0xa5a50000u | request->vector_segment
             : request->function == 0x0205 ? 0xa5a50000u | request->interrupt_segment
             : request->function == 0x0400 ? 0xa5a5be00u
             : (request->function == 0x0501 || request->function == 0x0503)
               ? (uint16_t)request->size
             : request->function == 0x0000 ? request->count
             : request->function == 0x0009 ? request->rights
             : request->function == 0x0203 ? request->vector_segment
             : request->function == 0x0205 ? request->interrupt_segment
                                           : request->operand >> 16;
  regs.rdx = (request->function == 0x0200 || request->function == 0x0202 ||
              request->function == 0x0204 || request->function == 0x0400)
               ? 0x5a5a0000u
             : (request->function == 0x0201 || request->function == 0x0203)
               ? 0x5a5a0000u | request->vector_offset
             : request->function == 0x0205 ? request->interrupt_offset
                                           : request->operand;
  regs.rdi = request->function == 0x0503 || request->function == 0x0502 ? request->operand
                                                                        : request->vector_offset;
  regs.rsi = transition                                                   ? 0xd4d40000u
             : request->function == 0x0503 || request->function == 0x0502 ? request->operand >> 16
                                                                          : 0;
  return ioctl(machine->vcpu, KVM_SET_REGS, &regs) == 0;
}

int daze_kvm_dpmi_mediator_test_begin(DazeKvmDpmiMediatorTestFixture *fixture,
                                      const DazeDpmiRequest *request, uint16_t *port,
                                      uint8_t *marker) {
  if (fixture == NULL || !fixture->machine_initialized || request == NULL || port == NULL ||
      marker == NULL)
    return 0;
  DazeKvmPortAccess access = {0};
  if (!enter_protected(&fixture->machine, request) ||
      daze_kvm_machine_run_port_access(&fixture->machine, &access) != DAZE_KVM_MACHINE_OK ||
      access.direction != DAZE_KVM_PORT_OUT || access.port != DAZE_KVM_DPMI_MEDIATOR_PORT ||
      access.value != DAZE_KVM_DPMI_MEDIATOR_MARKER)
    return 0;
  *port = access.port;
  *marker = access.value;
  return 1;
}

int daze_kvm_dpmi_mediator_test_run(DazeKvmDpmiMediatorTestFixture *fixture,
                                    const DazeDpmiRequest *request,
                                    DazeKvmDpmiMediatorTestSnapshot *snapshot) {
  uint16_t port;
  uint8_t marker;
  DazeKvmPortAccess access = {0};
  if (fixture == NULL || snapshot == NULL ||
      !daze_kvm_dpmi_mediator_test_begin(fixture, request, &port, &marker) ||
      daze_kvm_dpmi_mediator_process(&fixture->mediator, port, marker) !=
        DAZE_KVM_DPMI_MEDIATOR_OK ||
      daze_kvm_machine_run_port_access(&fixture->machine, &access) != DAZE_KVM_MACHINE_OK ||
      access.direction != DAZE_KVM_PORT_OUT || access.port != 0xf4 || access.value != 0x7e)
    return 0;
  const uint8_t *capture = (const uint8_t *)fixture->machine.guest + k_capture;
  const uint8_t *record = (const uint8_t *)fixture->machine.guest + k_record;
  snapshot->initial_edi = daze_read_u32(record + 16);
  snapshot->initial_es = daze_read_u16(record + 20);
  snapshot->eax = daze_read_u32(capture + k_capture_ax);
  snapshot->ebx = daze_read_u32(capture + k_capture_bx);
  snapshot->ecx = daze_read_u32(capture + k_capture_cx);
  snapshot->edx = daze_read_u32(capture + k_capture_dx);
  snapshot->esi = daze_read_u32(capture + k_capture_si);
  snapshot->edi = daze_read_u32(capture + k_capture_di);
  snapshot->es = daze_read_u16(capture + k_capture_es);
  snapshot->eflags = daze_read_u32(capture + k_capture_flags);
  return 1;
}

#else

int daze_kvm_dpmi_mediator_test_fixture_init(DazeKvmDpmiMediatorTestFixture *fixture,
                                             DazeKvmDpmiStateSaveEndpoints state_save_endpoints,
                                             DazeKvmDpmiRawSwitchEndpoints raw_switch_endpoints) {
  (void)fixture;
  (void)state_save_endpoints;
  (void)raw_switch_endpoints;
  return DAZE_KVM_MACHINE_UNAVAILABLE;
}
void daze_kvm_dpmi_mediator_test_fixture_destroy(DazeKvmDpmiMediatorTestFixture *fixture) {
  (void)fixture;
}
int daze_kvm_dpmi_mediator_test_begin(DazeKvmDpmiMediatorTestFixture *fixture,
                                      const DazeDpmiRequest *request, uint16_t *port,
                                      uint8_t *marker) {
  (void)fixture;
  (void)request;
  (void)port;
  (void)marker;
  return 0;
}
int daze_kvm_dpmi_mediator_test_run(DazeKvmDpmiMediatorTestFixture *fixture,
                                    const DazeDpmiRequest *request,
                                    DazeKvmDpmiMediatorTestSnapshot *snapshot) {
  (void)fixture;
  (void)request;
  (void)snapshot;
  return 0;
}

#endif
