#include "interrupt_vector.h"
#include "kvm_state_save_gate.h"
#include "machine_access.h"

#include "idt_gate.h"
#include "kvm_bytes.h"
#include "kvm_range.h"
#include "port.h"
#include "selector.h"

#include <string.h>

#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
#include <linux/kvm.h>
#include <sys/ioctl.h>

static int descriptor_at(const DazeKvmMachine *machine, const DazeKvmDpmiEntryResult *boundary,
                         uint16_t selector, const uint8_t **descriptor) {
  if (machine == NULL || boundary == NULL || descriptor == NULL || (selector & ~7u) == 0) return 0;
  const uint32_t table_base = (selector & 4u) != 0 ? boundary->ldt_base : boundary->gdt_base;
  const uint16_t table_limit = (selector & 4u) != 0 ? boundary->ldt_limit : boundary->gdt_limit;
  const uint32_t offset = (uint32_t)(selector & (uint16_t)~7u);
  const uint32_t address = table_base + offset;
  if (address < table_base || offset > table_limit || table_limit - offset < 7u ||
      !daze_kvm_range_fits(machine->guest_size, address, 8))
    return 0;
  *descriptor = (const uint8_t *)machine->guest + address;
  return 1;
}

static int code_descriptor(const DazeKvmMachine *machine, const DazeKvmDpmiEntryResult *boundary,
                           uint16_t selector, uint32_t *base) {
  const uint8_t *descriptor = NULL;
  if (!descriptor_at(machine, boundary, selector, &descriptor) || (descriptor[5] & 0x98u) != 0x98u)
    return 0;
  if (base != NULL)
    *base = (uint32_t)descriptor[2] | ((uint32_t)descriptor[3] << 8) |
            ((uint32_t)descriptor[4] << 16) | ((uint32_t)descriptor[7] << 24);
  return 1;
}

/* The shared 16-bit state stub ends in operand-size RETF (66 CB). A 16-bit
 * client can reach it through a four-byte IP:CS far-call frame, whereas that
 * RETF consumes an eight-byte EIP:CS-slot frame. Widen only the exact, live
 * state-gate return shape: a 32-bit gate IRET frame returning to 66 CB and a
 * caller frame whose second word is a code selector but whose third word is
 * not. A genuine wide frame is left byte-for-byte unchanged. */
static int widen_16bit_caller_frame(DazeKvmMachine *machine,
                                    const DazeKvmDpmiEntryResult *boundary) {
  enum {
    k_saved_eax_bytes = 4,
    k_iretd_frame_bytes = 12,
    k_widened_frame_bytes = 8,
    k_shifted_gate_frame_bytes = k_saved_eax_bytes + k_iretd_frame_bytes,
    k_total_rewritten_bytes = k_shifted_gate_frame_bytes + k_widened_frame_bytes,
  };
  if (machine == NULL || machine->guest == NULL || boundary == NULL || boundary->cs_db == 0 ||
      boundary->ss_base > machine->guest_size)
    return 0;
  const uint32_t iret_stack = boundary->esp + k_saved_eax_bytes;
  const uint32_t caller_stack = iret_stack + k_iretd_frame_bytes;
  if (iret_stack < boundary->esp || caller_stack < iret_stack || boundary->esp < 4 ||
      !daze_kvm_range_fits(machine->guest_size, boundary->ss_base + iret_stack,
                           k_iretd_frame_bytes) ||
      boundary->ss_base + iret_stack < boundary->ss_base ||
      !daze_kvm_range_fits(machine->guest_size, boundary->ss_base + boundary->esp - 4,
                           k_total_rewritten_bytes) ||
      boundary->ss_base + boundary->esp - 4 < boundary->ss_base)
    return 0;
  const uint8_t *const guest = (const uint8_t *)machine->guest;
  const uint32_t return_ip = daze_read_u32(guest + boundary->ss_base + iret_stack);
  const uint16_t return_cs = daze_read_u16(guest + boundary->ss_base + iret_stack + 4);
  uint32_t return_base = 0;
  if (!code_descriptor(machine, boundary, return_cs, &return_base) ||
      return_base > machine->guest_size - return_ip ||
      !daze_kvm_range_fits(machine->guest_size, return_base + return_ip, 2) ||
      guest[return_base + return_ip] != 0x66 || guest[return_base + return_ip + 1] != 0xcb)
    return 0;
  const uint8_t *const caller = guest + boundary->ss_base + caller_stack;
  const uint16_t caller_ip = daze_read_u16(caller);
  const uint16_t caller_cs = daze_read_u16(caller + 2);
  const uint16_t third_word = daze_read_u16(caller + 4);
  if (!code_descriptor(machine, boundary, caller_cs, NULL) ||
      code_descriptor(machine, boundary, third_word, NULL))
    return 0;
  struct kvm_regs regs;
  if (ioctl(machine->vcpu, KVM_GET_REGS, &regs) < 0) return -1;
  if ((uint32_t)regs.rsp != boundary->esp) return -1;
  const uint16_t widened[] = {caller_ip, 0, caller_cs, 0};
  /* KVM is stopped inside the real gate, before POP EAX; unlike Unicorn's
   * hook-mode INT, the gate frame is still live. Shift that complete frame
   * down with the widened caller frame so POP+IRETD subsequently leave ESP at
   * the new frame head rather than skipping over it. */
  memmove((uint8_t *)machine->guest + boundary->ss_base + boundary->esp - 4,
          (uint8_t *)machine->guest + boundary->ss_base + boundary->esp,
          k_shifted_gate_frame_bytes);
  memcpy((uint8_t *)machine->guest + boundary->ss_base + caller_stack - 4, widened,
         sizeof(widened));
  regs.rsp = boundary->esp - 4;
  daze_kvm_machine_debug_invalidate(machine);
  return ioctl(machine->vcpu, KVM_SET_REGS, &regs) < 0 ? -1 : 1;
}
#endif

static int layout_valid(const DazeKvmStateSaveGateLayout *layout) {
  const uint32_t entry =
    layout == NULL ? 0 : layout->idt_address + DAZE_KVM_STATE_SAVE_GATE_VECTOR * 8u;
  return layout != NULL && layout->handler_address != 0 && layout->handler_selector != 0 &&
         (layout->handler_selector & 7u) == 0 && layout->idt_limit >= 0x7df &&
         entry >= layout->idt_address;
}

int daze_kvm_state_save_gate_build(const DazeKvmStateSaveGateLayout *layout,
                                   DazeKvmStateSaveGateArtifacts *output) {
  if (!layout_valid(layout) || output == NULL) return 0;
  DazeKvmStateSaveGateArtifacts built = {
    .handler = {0x50, 0xb0, DAZE_KVM_STATE_SAVE_GATE_MARKER, 0xe6, DAZE_PORT_GATE, 0x58, 0xcf},
  };
  daze_kvm_encode_idt_gate(built.idt_entry, layout->handler_address, layout->handler_selector,
                           0x8e);
  *output = built;
  return 1;
}

static int boundary_is_state_save(const DazeKvmDpmiEntryResult *boundary) {
  const DazeKvmDpmiEntryObservation *observation = &boundary->observation;
  return observation->kind == DAZE_KVM_DPMI_ENTRY_EXIT_PIO &&
         observation->pio_direction == DAZE_KVM_DPMI_ENTRY_PIO_OUT &&
         observation->pio_port == DAZE_PORT_GATE && observation->pio_size == 1 &&
         observation->pio_count == 1 &&
         ((observation->pio_value_present &&
           (uint8_t)observation->pio_value == DAZE_KVM_STATE_SAVE_GATE_MARKER) ||
          (uint8_t)boundary->ax == DAZE_KVM_STATE_SAVE_GATE_MARKER);
}

int daze_kvm_state_save_gate_widen_caller_frame(DazeKvmMachine *machine,
                                                const DazeKvmDpmiEntryResult *boundary) {
  if (machine == NULL || machine->guest == NULL || boundary == NULL ||
      !boundary_is_state_save(boundary))
    return DAZE_KVM_STATE_SAVE_GATE_INVALID;
#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
  const int widened = widen_16bit_caller_frame(machine, boundary);
  return widened < 0 ? DAZE_KVM_STATE_SAVE_GATE_FAILED : DAZE_KVM_STATE_SAVE_GATE_OK;
#else
  return DAZE_KVM_STATE_SAVE_GATE_FAILED;
#endif
}

int daze_kvm_state_save_gate_run(DazeKvmMachine *machine, const DazeKvmStateSaveGateLayout *layout,
                                 const DpmiAlternateState *state,
                                 const DazeKvmDpmiEntryResult *boundary,
                                 DazeKvmStateSaveGateResult *result) {
  if (result != NULL) *result = (DazeKvmStateSaveGateResult){0};
  if (machine == NULL || machine->guest == NULL || result == NULL || boundary == NULL ||
      !layout_valid(layout) || !daze_dpmi_alternate_state_valid(state))
    return DAZE_KVM_STATE_SAVE_GATE_INVALID;
  result->boundary = *boundary;
  if (!boundary_is_state_save(&result->boundary)) return DAZE_KVM_STATE_SAVE_GATE_FAILED;
  const uint32_t stack = result->boundary.ss_base + result->boundary.esp;
  const uint32_t buffer = result->boundary.es_base + (uint32_t)result->boundary.di;
  if (stack < result->boundary.ss_base || buffer < result->boundary.es_base ||
      !daze_kvm_range_fits(machine->guest_size, stack, sizeof(uint32_t)) ||
      !daze_kvm_range_fits(machine->guest_size, buffer, DAZE_DPMI_ALTERNATE_STATE_SIZE))
    return DAZE_KVM_STATE_SAVE_GATE_FAILED;
  result->operation = daze_read_u16((const uint8_t *)machine->guest + stack);
  if (result->operation != 0 ||
      !daze_dpmi_alternate_state_pack(state, (uint8_t *)machine->guest + buffer))
    return DAZE_KVM_STATE_SAVE_GATE_FAILED;
  result->buffer_address = buffer;
#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
  const int widened = widen_16bit_caller_frame(machine, boundary);
  if (widened < 0) return DAZE_KVM_STATE_SAVE_GATE_FAILED;
  result->caller_frame_widened = widened;
#endif
  return DAZE_KVM_STATE_SAVE_GATE_OK;
}
