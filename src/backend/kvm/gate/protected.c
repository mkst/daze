#include "interrupt_vector.h"
#include "protected.h"
#include "legacy_exception.h"

#include "idt_gate.h"
#include "kvm_bytes.h"
#include "kvm_range.h"
#include "monotonic_clock.h"
#include "selector.h"

#include <stdlib.h>
#include <string.h>

#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
#include <linux/kvm.h>
#include <sys/ioctl.h>
#endif

static int layout_valid(const DazeKvmProtectedGateLayout *layout) {
  const uint32_t exception_entry_end =
    layout == NULL ? 0 : (uint32_t)layout->exception_gate_vector * 8u + 7u;
  const uint32_t required_idt_limit =
    layout != NULL && layout->exception_gate_type != 0 && exception_entry_end > 0x18f
      ? exception_entry_end
      : 0x18f;
  if (layout == NULL || layout->idt_address > UINT32_MAX - required_idt_limit ||
      layout->idt_limit < required_idt_limit || layout->handler_address == 0 ||
      layout->default_dos_stub_address == 0 || layout->record_address == 0 ||
      layout->mailbox_address == 0 || (layout->handler_selector & 7u) != 0 ||
      (layout->handler_data_selector & 7u) != 0 || layout->handler_selector == 0 ||
      layout->handler_data_selector == 0 ||
      (layout->interrupt_gate_type != 0x86 && layout->interrupt_gate_type != 0x8e) ||
      layout->exchange_limit == 0 || layout->exchange_limit > DAZE_KVM_PROTECTED_GATE_MAX_EXCHANGES)
    return 0;
  if (layout->exception_gate_type != 0 && layout->exception_gate_type != 0x8e) return 0;
  return !daze_kvm_ranges_overlap(layout->handler_address, DAZE_KVM_PROTECTED_GATE_HANDLER_MAX_SIZE,
                                  layout->record_address, DAZE_KVM_DPMI_RECORD_SIZE) &&
         (layout->dos_handler_address == 0 ||
          (!daze_kvm_ranges_overlap(
             layout->handler_address, DAZE_KVM_PROTECTED_GATE_HANDLER_MAX_SIZE,
             layout->dos_handler_address, DAZE_KVM_PROTECTED_GATE_HANDLER_MAX_SIZE) &&
           !daze_kvm_ranges_overlap(layout->dos_handler_address,
                                    DAZE_KVM_PROTECTED_GATE_HANDLER_MAX_SIZE,
                                    layout->record_address, DAZE_KVM_DPMI_RECORD_SIZE) &&
           !daze_kvm_ranges_overlap(layout->dos_handler_address,
                                    DAZE_KVM_PROTECTED_GATE_HANDLER_MAX_SIZE,
                                    layout->mailbox_address, DAZE_KVM_DPMI_MAILBOX_SIZE))) &&
         !daze_kvm_ranges_overlap(
           layout->default_dos_stub_address, DAZE_KVM_PROTECTED_GATE_DEFAULT_DOS_STUB_SIZE,
           layout->handler_address, DAZE_KVM_PROTECTED_GATE_HANDLER_MAX_SIZE) &&
         !daze_kvm_ranges_overlap(
           layout->default_dos_stub_address, DAZE_KVM_PROTECTED_GATE_DEFAULT_DOS_STUB_SIZE,
           layout->dos_handler_address, DAZE_KVM_PROTECTED_GATE_HANDLER_MAX_SIZE) &&
         !daze_kvm_ranges_overlap(layout->default_dos_stub_address,
                                  DAZE_KVM_PROTECTED_GATE_DEFAULT_DOS_STUB_SIZE,
                                  layout->record_address, DAZE_KVM_DPMI_RECORD_SIZE) &&
         !daze_kvm_ranges_overlap(layout->default_dos_stub_address,
                                  DAZE_KVM_PROTECTED_GATE_DEFAULT_DOS_STUB_SIZE,
                                  layout->mailbox_address, DAZE_KVM_DPMI_MAILBOX_SIZE) &&
         !daze_kvm_ranges_overlap(layout->handler_address, DAZE_KVM_PROTECTED_GATE_HANDLER_MAX_SIZE,
                                  layout->mailbox_address, DAZE_KVM_DPMI_MAILBOX_SIZE) &&
         !daze_kvm_ranges_overlap(layout->record_address, DAZE_KVM_DPMI_RECORD_SIZE,
                                  layout->mailbox_address, DAZE_KVM_DPMI_MAILBOX_SIZE);
}

static void emit_address(uint8_t *code, size_t *size, uint8_t opcode, uint32_t address) {
  code[(*size)++] = 0x64;
  code[(*size)++] = opcode;
  daze_write_u32(code + *size, address);
  *size += 4;
}

static void emit_memory_register(uint8_t *code, size_t *size, uint8_t opcode, uint8_t modrm,
                                 uint32_t address) {
  code[(*size)++] = 0x64;
  code[(*size)++] = opcode;
  code[(*size)++] = modrm;
  daze_write_u32(code + *size, address);
  *size += 4;
}

int daze_kvm_protected_gate_build(const DazeKvmProtectedGateLayout *layout,
                                  DazeKvmProtectedGateArtifacts *output) {
  if (output == NULL || !layout_valid(layout)) return 0;
  DazeKvmProtectedGateArtifacts built = {0};
  size_t size = 0;
  /* Preserve the client FS and use an explicitly writable flat selector for
   * the fixed linear mediator buffers. CS is flat but intentionally cannot
   * be used for stores through a code descriptor. */
  built.handler[size++] = 0x55;
  built.handler[size++] = 0x8d;
  built.handler[size++] = 0x6c;
  built.handler[size++] = 0x24;
  built.handler[size++] = 0x04;
  built.handler[size++] = 0x0f;
  built.handler[size++] = 0xa0;
  built.handler[size++] = 0x50;
  built.handler[size++] = 0x66;
  built.handler[size++] = 0xb8;
  built.handler[size++] = (uint8_t)layout->handler_data_selector;
  built.handler[size++] = (uint8_t)(layout->handler_data_selector >> 8);
  built.handler[size++] = 0x8e;
  built.handler[size++] = 0xe0;
  built.handler[size++] = 0x58;
  emit_address(built.handler, &size, 0xa3, layout->record_address + 0);
  emit_memory_register(built.handler, &size, 0x89, 0x1d, layout->record_address + 4);
  emit_memory_register(built.handler, &size, 0x89, 0x0d, layout->record_address + 8);
  emit_memory_register(built.handler, &size, 0x89, 0x15, layout->record_address + 12);
  emit_memory_register(built.handler, &size, 0x89, 0x3d, layout->record_address + 16);
  emit_memory_register(built.handler, &size, 0x89, 0x35, layout->record_address + 24);
  built.handler[size++] = 0x8c;
  built.handler[size++] = 0xc0;
  emit_address(built.handler, &size, 0xa3, layout->record_address + 20);
  built.handler[size++] = 0x8c;
  built.handler[size++] = 0xd8;
  emit_address(built.handler, &size, 0xa3, layout->record_address + 40);
  if (layout->interrupt_gate_type == 0x86) {
    built.handler[size++] = 0x0f;
    built.handler[size++] = 0xb7;
  } else {
    built.handler[size++] = 0x8b;
  }
  built.handler[size++] = 0x45;
  built.handler[size++] = 0x00;
  emit_address(built.handler, &size, 0xa3, layout->record_address + 28);
  if (layout->interrupt_gate_type == 0x86) {
    built.handler[size++] = 0x0f;
    built.handler[size++] = 0xb7;
  } else {
    built.handler[size++] = 0x8b;
  }
  built.handler[size++] = 0x45;
  built.handler[size++] = layout->interrupt_gate_type == 0x86 ? 0x02 : 0x04;
  emit_address(built.handler, &size, 0xa3, layout->record_address + 32);
  if (layout->interrupt_gate_type == 0x86) {
    built.handler[size++] = 0x0f;
    built.handler[size++] = 0xb7;
  } else {
    built.handler[size++] = 0x8b;
  }
  built.handler[size++] = 0x45;
  built.handler[size++] = layout->interrupt_gate_type == 0x86 ? 0x04 : 0x08;
  emit_address(built.handler, &size, 0xa3, layout->record_address + 36);
  built.handler[size++] = 0xb0;
  built.handler[size++] = DAZE_KVM_DPMI_MEDIATOR_MARKER;
  built.handler[size++] = 0xe6;
  built.handler[size++] = 0xf4;
  emit_address(built.handler, &size, 0xa1, layout->mailbox_address + 0);
  emit_memory_register(built.handler, &size, 0x8b, 0x1d, layout->mailbox_address + 4);
  emit_memory_register(built.handler, &size, 0x8b, 0x0d, layout->mailbox_address + 8);
  emit_memory_register(built.handler, &size, 0x8b, 0x35, layout->mailbox_address + 12);
  emit_memory_register(built.handler, &size, 0x8b, 0x3d, layout->mailbox_address + 16);
  emit_memory_register(built.handler, &size, 0x8b, 0x15, layout->mailbox_address + 20);
  /* Mailbox +20 packs ES low / DS high. Compare only ES before reloading:
   * DPMI 0001h may have freed that selector while cached ES remains usable,
   * so reloading an unchanged value would fault. */
  built.handler[size++] = 0x66;
  emit_memory_register(built.handler, &size, 0x3b, 0x15, layout->record_address + 20);
  built.handler[size++] = 0x74;
  built.handler[size++] = 0x02;
  built.handler[size++] = 0x8e;
  built.handler[size++] = 0xc2;
  built.handler[size++] = 0x50;
  built.handler[size++] = 0x89;
  built.handler[size++] = 0xd0;
  built.handler[size++] = 0xc1;
  built.handler[size++] = 0xe8;
  built.handler[size++] = 0x10;
  built.handler[size++] = 0x8e;
  built.handler[size++] = 0xd8;
  built.handler[size++] = 0x58;
  emit_memory_register(built.handler, &size, 0x8b, 0x15, layout->mailbox_address + 24);
  /* EBP retains the CPU frame while ESP changes during the handler. Frame words follow
   * gate width; only carry may change. */
  built.handler[size++] = 0x50;
  emit_address(built.handler, &size, 0xa1, layout->mailbox_address + 28);
  if (layout->interrupt_gate_type == 0x86) built.handler[size++] = 0x66;
  built.handler[size++] = 0x83;
  built.handler[size++] = 0x65;
  built.handler[size++] = layout->interrupt_gate_type == 0x86 ? 0x04 : 0x08;
  built.handler[size++] = 0xfe;
  if (layout->interrupt_gate_type == 0x86) built.handler[size++] = 0x66;
  built.handler[size++] = 0x09;
  built.handler[size++] = 0x45;
  built.handler[size++] = layout->interrupt_gate_type == 0x86 ? 0x04 : 0x08;
  built.handler[size++] = 0x58;
  built.handler[size++] = 0x0f;
  built.handler[size++] = 0xa1;
  built.handler[size++] = 0x5d;
  if (layout->interrupt_gate_type == 0x86) built.handler[size++] = 0x66;
  built.handler[size++] = 0xcf;
  if (size > sizeof(built.handler)) return 0;
  built.handler_size = size;
  daze_kvm_encode_idt_gate(built.idt_entry, layout->handler_address, layout->handler_selector,
                           layout->interrupt_gate_type);
  memcpy(built.dos_handler, built.handler, built.handler_size);
  for (size_t index = 0; index + 3 < built.handler_size; ++index)
    if (built.dos_handler[index] == 0xb0 &&
        built.dos_handler[index + 1] == DAZE_KVM_DPMI_MEDIATOR_MARKER &&
        built.dos_handler[index + 2] == 0xe6 && built.dos_handler[index + 3] == 0xf4) {
      built.dos_handler[index + 1] = DAZE_KVM_PROTECTED_DOS_MARKER;
      built.dos_handler_size = built.handler_size;
      break;
    }
  if (built.dos_handler_size == 0) return 0;
  daze_kvm_encode_idt_gate(built.dos_idt_entry, layout->dos_handler_address,
                           layout->handler_selector, layout->interrupt_gate_type);
  /* A BCC-installed 16-bit handler chains with IP:CS:FLAGS at ESP.  Push
   * high and low words separately so each source word is read before its
   * final DWORD is complete: [ESP+6], [ESP+8], and [ESP+10] name FLAGS, CS,
   * and IP after the preceding two DWORDs respectively.  The DOS gate's
   * IRETD consumes these three DWORDs and restores the original context. */
  size = 0;
  const uint8_t frame_adapter[] = {
    0x66, 0x6a, 0x00,             /* push word 0: EFLAGS high */
    0x66, 0xff, 0x74, 0x24, 0x06, /* push word [esp+6]: FLAGS low */
    0x66, 0x6a, 0x00,             /* push word 0: CS high */
    0x66, 0xff, 0x74, 0x24, 0x08, /* push word [esp+8]: CS low */
    0x66, 0x6a, 0x00,             /* push word 0: EIP high */
    0x66, 0xff, 0x74, 0x24, 0x0a, /* push word [esp+10]: IP low */
    0xea,                         /* jmp far (target patched below) */
  };
  memcpy(built.default_dos_stub, frame_adapter, sizeof(frame_adapter));
  size = sizeof(frame_adapter);
  daze_write_u32(built.default_dos_stub + size, layout->dos_handler_address);
  size += 4;
  built.default_dos_stub[size++] = (uint8_t)layout->handler_selector;
  built.default_dos_stub[size++] = (uint8_t)(layout->handler_selector >> 8);
  if (size != sizeof(built.default_dos_stub)) return 0;
  built.default_dos_stub_size = size;
  *output = built;
  return 1;
}

static int mediator_pio(const DazeKvmDpmiEntryResult *boundary) {
  const DazeKvmDpmiEntryObservation *observation = &boundary->observation;
  return observation->kind == DAZE_KVM_DPMI_ENTRY_EXIT_PIO &&
         observation->pio_direction == DAZE_KVM_DPMI_ENTRY_PIO_OUT && observation->pio_size == 1 &&
         observation->pio_count == 1 && observation->pio_value_present &&
         observation->pio_port == DAZE_KVM_DPMI_MEDIATOR_PORT &&
         (uint8_t)observation->pio_value == DAZE_KVM_DPMI_MEDIATOR_MARKER;
}

static int target_gate_type(const uint8_t *guest, uint32_t guest_size, uint32_t gdt_base,
                            uint16_t gdt_limit, uint32_t ldt_base, uint16_t ldt_limit,
                            uint16_t selector, uint8_t *gate_type);

static int install_exception_gate(DazeKvmMachine *machine, const DazeKvmDpmiMediator *mediator,
                                  const DazeKvmProtectedGateLayout *layout) {
  if (layout->exception_gate_type == 0) return 1;
  const DazeDpmiExceptionVector vector = mediator->exception_vectors[layout->exception_gate_vector];
  const uint32_t address = layout->idt_address + (uint32_t)layout->exception_gate_vector * 8u;
  if (!daze_kvm_range_fits_nonempty(machine->guest_size, address, 8)) return 0;
  uint8_t *entry = (uint8_t *)machine->guest + address;
  /* Clearing a client exception vector must also clear its hardware IDT projection. */
  if (vector.segment == 0) {
    memset(entry, 0, 8);
    return 1;
  }
  uint8_t gate_type;
  if (!target_gate_type((const uint8_t *)machine->guest, (uint32_t)machine->guest_size,
                        mediator->gdt_address, (uint16_t)(mediator->gdt_size - 1u),
                        mediator->ldt_address, (uint16_t)(mediator->ldt_size - 1u), vector.segment,
                        &gate_type))
    return 0;
  daze_kvm_encode_idt_gate(entry, vector.offset, vector.segment, gate_type);
  return 1;
}

int daze_kvm_protected_gate_project_exception_vector(DazeKvmMachine *machine,
                                                     const DazeKvmDpmiMediator *mediator,
                                                     const DazeKvmProtectedGateLayout *layout) {
  if (machine == NULL || mediator == NULL || layout == NULL) return 0;
  return install_exception_gate(machine, mediator, layout) &&
         (layout->legacy_np_capture_address == 0 ||
          daze_kvm_legacy_exception_install(machine, layout));
}

/* Gate width follows the target descriptor's D/B bit. Selectors identify a table entry,
 * not a width. */
static int target_gate_type(const uint8_t *guest, uint32_t guest_size, uint32_t gdt_base,
                            uint16_t gdt_limit, uint32_t ldt_base, uint16_t ldt_limit,
                            uint16_t selector, uint8_t *gate_type) {
  if (selector == 0 || (selector & 3u) != 0) return 0;
  const int use_ldt = (selector & 4u) != 0;
  const uint32_t table_base = use_ldt ? ldt_base : gdt_base;
  const uint32_t table_limit = use_ldt ? ldt_limit : gdt_limit;
  const uint32_t index = (uint32_t)(selector & ~7u);
  if (index > table_limit || table_limit - index < 7u) return 0;
  const uint32_t address = table_base + index;
  if (address < table_base || !daze_kvm_range_fits_nonempty(guest_size, address, 8)) return 0;
  const uint8_t *descriptor = guest + address;
  /* Architectural x86 descriptor: access/type at byte 5, high-limit/flags at
   * byte 6, base-high at byte 7. D/B is bit 6 of the flags byte. */
  const uint8_t access = descriptor[5];
  const uint8_t flags = descriptor[6];
  /* Only a present, non-system, executable code descriptor can be an INT
   * target. Anything else leaves the installed gate undecidable. */
  if ((access & 0x80u) == 0 || (access & 0x10u) == 0 || (access & 0x08u) == 0) return 0;
  *gate_type = (flags & 0x40u) != 0 ? 0x8e : 0x86;
  return 1;
}

int daze_kvm_protected_gate_client_entry(const uint8_t *guest, uint32_t guest_size,
                                         uint32_t gdt_base, uint16_t gdt_limit, uint32_t ldt_base,
                                         uint16_t ldt_limit, const DazeDpmiInterruptVector *target,
                                         uint8_t *entry) {
  if (guest == NULL || target == NULL || entry == NULL) return 0;
  uint8_t gate_type;
  if (!target_gate_type(guest, guest_size, gdt_base, gdt_limit, ldt_base, ldt_limit,
                        target->segment, &gate_type))
    return 0;
  daze_kvm_encode_idt_gate(entry, target->offset, target->segment, gate_type);
  return 1;
}

static int install_interrupt_gate(DazeKvmMachine *machine, const DazeKvmDpmiMediator *mediator,
                                  const DazeKvmProtectedGateLayout *layout, uint8_t vector) {
  const uint32_t address = layout->idt_address + (uint32_t)vector * 8u;
  if (address < layout->idt_address ||
      !daze_kvm_range_fits_nonempty(machine->guest_size, address, 8))
    return 0;
  const DazeDpmiInterruptVector target = mediator->interrupt_vectors[vector];
  uint8_t *entry = (uint8_t *)machine->guest + address;
  if (target.segment == 0) {
    /* ASPSX clears its protected vector 21 before its final protected INT 21h.
     * Unicorn routes that exact DOS termination through its host interrupt
     * hook; hardware would instead #GP on an empty IDT slot. Keep only the
     * existing record-only gate installed so the owner can observe 4Ch. */
    if (vector == DAZE_INT_DOS) {
      daze_kvm_encode_idt_gate(entry, layout->dos_handler_address, layout->handler_selector,
                               layout->interrupt_gate_type);
      return 1;
    }
    memset(entry, 0, 8);
    return 1;
  }
  /* DPMILOAD's INT 2Fh reflector runs in 16-bit code and ends with plain
   * IRET. Its client gate must follow the reflector descriptor rather than
   * the host mediator's 32-bit ABI. The vector-21 chain's existing high-offset
   * projection uses the same descriptor validation. Ordinary low-offset
   * vector-21 handlers retain their established gate shape. */
  if (vector == DAZE_INT_MULTIPLEX || (vector == DAZE_INT_DOS && (target.offset >> 16) != 0)) {
    if (!daze_kvm_protected_gate_client_entry(
          (const uint8_t *)machine->guest, (uint32_t)machine->guest_size, mediator->gdt_address,
          (uint16_t)(mediator->gdt_size - 1u), mediator->ldt_address,
          (uint16_t)(mediator->ldt_size - 1u), &target, entry))
      return 0;
    return 1;
  }
  daze_kvm_encode_idt_gate(entry, target.offset, target.segment, layout->interrupt_gate_type);
  return 1;
}

int daze_kvm_protected_gate_project_interrupt_vector(DazeKvmMachine *machine,
                                                     const DazeKvmDpmiMediator *mediator,
                                                     const DazeKvmProtectedGateLayout *layout,
                                                     uint8_t vector) {
  if (machine == NULL || mediator == NULL || layout == NULL || !layout_valid(layout)) return 0;
  return install_interrupt_gate(machine, mediator, layout, vector);
}

static int process_mediator_boundary_impl(DazeKvmMachine *machine, DazeKvmDpmiMediator *mediator,
                                          const DazeKvmProtectedGateLayout *layout,
                                          const DazeKvmDpmiEntryResult *boundary,
                                          DazeKvmProtectedGateExchange *exchange) {
  if (!mediator_pio(boundary)) return 0;
  const uint8_t *record = mediator->guest + mediator->record_address;
  exchange->boundary = *boundary;
  exchange->function = daze_read_u16(record);
  exchange->selector = daze_read_u16(record + 4);
  exchange->client_ip = daze_read_u16(record + 28);
  exchange->client_cs = daze_read_u16(record + 32);
  exchange->request_cx = daze_read_u32(record + 8);
  exchange->request_dx = daze_read_u32(record + 12);
  if (daze_kvm_dpmi_mediator_process(mediator, boundary->observation.pio_port,
                                     (uint8_t)boundary->observation.pio_value) !=
        DAZE_KVM_DPMI_MEDIATOR_OK &&
      mediator->rm_procedure_present == 0)
    return 0;
  const uint8_t *mailbox = mediator->guest + mediator->mailbox_address;
  /* No separate DS mailbox slot exists. Pack preserved DS above reply ES,
   * matching the handler's low-word ES comparison and high-word DS reload. */
  uint8_t *mutable_mailbox = mediator->guest + mediator->mailbox_address;
  daze_write_u32(mutable_mailbox + 20, (daze_read_u32(mailbox + 20) & 0xffffu) |
                                         ((uint32_t)daze_read_u16(record + 40) << 16));
  exchange->reply_ax = daze_read_u32(mailbox + 0);
  exchange->reply_bx = daze_read_u32(mailbox + 4);
  exchange->reply_cx = daze_read_u32(mailbox + 8);
  exchange->reply_dx = daze_read_u32(mailbox + 24);
  if (layout->legacy_np_capture_address != 0 && exchange->function == 0x0203 &&
      (uint8_t)exchange->selector == 0x0b && !daze_kvm_legacy_exception_install(machine, layout))
    return 0;
  if (exchange->function == 0x0203 &&
      (uint8_t)exchange->selector == layout->exception_gate_vector &&
      !install_exception_gate(machine, mediator, layout))
    return 0;
  /* Project the shared 0205h target into hardware IDT mechanics, except where
   * an exception vector has precedence: exceptions and INTs share an IDT slot. */
  if (exchange->function != 0x0205 || (uint8_t)exchange->selector == layout->exception_gate_vector)
    return 1;
  return install_interrupt_gate(machine, mediator, layout, (uint8_t)exchange->selector);
}

static void record_dpmi_function(DazeRunMetrics *metrics, uint16_t function, uint64_t nanoseconds) {
  for (size_t index = 0; index < metrics->kvm_dpmi_function_count; ++index) {
    DazeRunMetricsDpmiFunction *entry = &metrics->kvm_dpmi_functions[index];
    if (entry->function == function) {
      entry->calls++;
      entry->mediator_nanoseconds += nanoseconds;
      return;
    }
  }
  if (metrics->kvm_dpmi_function_count == DAZE_RUN_METRICS_DPMI_FUNCTION_CAPACITY) {
    metrics->kvm_dpmi_function_overflow_calls++;
    return;
  }
  metrics->kvm_dpmi_functions[metrics->kvm_dpmi_function_count++] = (DazeRunMetricsDpmiFunction){
    .function = function, .calls = 1, .mediator_nanoseconds = nanoseconds};
}

static void record_virtual_interrupt_site(DazeRunMetrics *metrics,
                                          const DazeKvmProtectedGateExchange *exchange) {
  if (exchange->function != 0x0900 && exchange->function != 0x0901) return;
  for (size_t index = 0; index < metrics->kvm_virtual_interrupt_site_count; ++index) {
    DazeRunMetricsVirtualInterruptSite *site = &metrics->kvm_virtual_interrupt_sites[index];
    if (site->function == exchange->function && site->cs == exchange->client_cs &&
        site->ip == exchange->client_ip) {
      site->calls++;
      return;
    }
  }
  if (metrics->kvm_virtual_interrupt_site_count ==
      DAZE_RUN_METRICS_VIRTUAL_INTERRUPT_SITE_CAPACITY) {
    metrics->kvm_virtual_interrupt_site_overflow_calls++;
    return;
  }
  metrics->kvm_virtual_interrupt_sites[metrics->kvm_virtual_interrupt_site_count++] =
    (DazeRunMetricsVirtualInterruptSite){.function = exchange->function,
                                         .cs = exchange->client_cs,
                                         .ip = exchange->client_ip,
                                         .calls = 1};
}

static int process_mediator_boundary(DazeKvmMachine *machine, DazeKvmDpmiMediator *mediator,
                                     const DazeKvmProtectedGateLayout *layout,
                                     const DazeKvmDpmiEntryResult *boundary,
                                     DazeKvmProtectedGateExchange *exchange) {
  DazeRunMetrics *const metrics = machine->run_metrics;
  const uint64_t started = metrics != NULL && metrics->enabled ? monotonic_nanoseconds() : 0;
  const int status = process_mediator_boundary_impl(machine, mediator, layout, boundary, exchange);
  if (metrics != NULL && metrics->enabled && mediator_pio(boundary)) {
    const uint64_t finished = monotonic_nanoseconds();
    const uint64_t elapsed = finished >= started ? finished - started : 0;
    metrics->kvm_dpmi_mediator_calls++;
    metrics->kvm_dpmi_mediator_nanoseconds += elapsed;
    record_dpmi_function(metrics, exchange->function, elapsed);
    record_virtual_interrupt_site(metrics, exchange);
  }
  return status;
}

int daze_kvm_protected_gate_resume_mediator_boundary(DazeKvmMachine *machine,
                                                     DazeKvmDpmiMediator *mediator,
                                                     const DazeKvmProtectedGateLayout *layout,
                                                     const DazeKvmDpmiEntryResult *boundary,
                                                     DazeKvmProtectedGateExchange *exchange,
                                                     DazeKvmDpmiEntryResult *successor) {
  if (exchange != NULL) *exchange = (DazeKvmProtectedGateExchange){0};
  if (successor != NULL) *successor = (DazeKvmDpmiEntryResult){0};
  if (machine == NULL || mediator == NULL || layout == NULL || boundary == NULL ||
      exchange == NULL || successor == NULL || mediator->guest != machine->guest ||
      mediator->guest_size != machine->guest_size || !layout_valid(layout))
    return DAZE_KVM_PROTECTED_GATE_INVALID;
  if (!process_mediator_boundary(machine, mediator, layout, boundary, exchange))
    return mediator_pio(boundary) ? DAZE_KVM_PROTECTED_GATE_MEDIATOR_FAILED
                                  : DAZE_KVM_PROTECTED_GATE_INVALID;
  if (mediator->rm_procedure_present) return DAZE_KVM_PROTECTED_GATE_RM_PROCEDURE;
  return daze_kvm_dpmi_entry_continue_once(machine, successor) == DAZE_KVM_DPMI_ENTRY_OK
           ? DAZE_KVM_PROTECTED_GATE_OK
           : DAZE_KVM_PROTECTED_GATE_FAILED;
}

/* Observation-only exits omit CPU state; terminal diagnostics need it captured before
 * the vCPU resumes. */
static int capture_parked_terminal(DazeKvmMachine *machine, DazeKvmDpmiEntryResult *boundary) {
  return daze_kvm_dpmi_entry_capture_state(machine, boundary) == DAZE_KVM_DPMI_ENTRY_OK;
}

static int run_from_boundary(DazeKvmMachine *machine, DazeKvmDpmiMediator *mediator,
                             const DazeKvmProtectedGateLayout *layout,
                             const DazeKvmDpmiEntryResult *boundary,
                             DazeKvmProtectedGateResult *result) {
  DazeKvmDpmiEntryResult current = *boundary;
  for (size_t index = 0; index < layout->exchange_limit; ++index) {
    DazeKvmProtectedGateExchange *exchange = result->exchanges + index;
    exchange->boundary = current;
    if (!mediator_pio(&exchange->boundary)) {
      if (!capture_parked_terminal(machine, &current)) return DAZE_KVM_PROTECTED_GATE_FAILED;
      result->terminal = current;
      return DAZE_KVM_PROTECTED_GATE_OK;
    }
    if (!process_mediator_boundary(machine, mediator, layout, &exchange->boundary, exchange))
      return DAZE_KVM_PROTECTED_GATE_MEDIATOR_FAILED;
    result->exchange_count = index + 1;
    if (mediator->rm_procedure_present) {
      /* A 0301h request is decided by a caller-owned real-mode reflection;
       * the gate adapter stops here without resuming the parked guest. */
      const uint8_t *terminal_record = mediator->guest + mediator->record_address;
      if (!capture_parked_terminal(machine, &current)) return DAZE_KVM_PROTECTED_GATE_FAILED;
      result->terminal = current;
      result->terminal_function = daze_read_u16(terminal_record);
      result->terminal_selector = daze_read_u16(terminal_record + 4);
      result->terminal_request_present = 1;
      return DAZE_KVM_PROTECTED_GATE_OK;
    }
    if (daze_kvm_dpmi_entry_continue_observe(machine, &current) != DAZE_KVM_DPMI_ENTRY_OK)
      return DAZE_KVM_PROTECTED_GATE_FAILED;
    result->terminal = current;
    if (!mediator_pio(&current)) {
      if (!capture_parked_terminal(machine, &current)) return DAZE_KVM_PROTECTED_GATE_FAILED;
      result->terminal = current;
      return DAZE_KVM_PROTECTED_GATE_OK;
    }
  }
  if (!capture_parked_terminal(machine, &current)) return DAZE_KVM_PROTECTED_GATE_FAILED;
  result->terminal = current;
  const uint8_t *record = mediator->guest + mediator->record_address;
  result->terminal_function = daze_read_u16(record);
  result->terminal_selector = daze_read_u16(record + 4);
  result->terminal_request_present = 1;
  return DAZE_KVM_PROTECTED_GATE_LIMIT_REACHED;
}

int daze_kvm_protected_gate_run(DazeKvmMachine *machine, DazeKvmDpmiMediator *mediator,
                                const DazeKvmProtectedGateLayout *layout,
                                DazeKvmProtectedGateResult *result) {
  if (result != NULL) *result = (DazeKvmProtectedGateResult){0};
  if (machine == NULL || mediator == NULL || result == NULL || mediator->guest != machine->guest ||
      mediator->guest_size != machine->guest_size || !layout_valid(layout))
    return DAZE_KVM_PROTECTED_GATE_INVALID;
  DazeKvmDpmiEntryResult boundary;
  if (daze_kvm_dpmi_entry_continue_observe(machine, &boundary) != DAZE_KVM_DPMI_ENTRY_OK)
    return DAZE_KVM_PROTECTED_GATE_FAILED;
  return run_from_boundary(machine, mediator, layout, &boundary, result);
}
