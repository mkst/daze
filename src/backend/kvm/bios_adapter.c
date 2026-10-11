#include "bios_adapter.h"

#include "interrupt_vector.h"
#include "kvm_bytes.h"
#include "timer.h"

static void reply_carry(uint8_t *mailbox, int carry) {
  uint16_t flags = daze_read_u16(mailbox + 14);
  flags = carry ? (uint16_t)(flags | 1u) : (uint16_t)(flags & ~1u);
  daze_write_u16(mailbox + 14, flags);
}

DazeKvmPreflightBoundaryDisposition
daze_kvm_bios_dispatch(const uint8_t record[24],
                       uint8_t mailbox[DAZE_KVM_RUNNER_GATE_MAILBOX_SIZE]) {
  if (record == NULL || mailbox == NULL) return DAZE_KVM_PREFLIGHT_BOUNDARY_FAILED;
  const uint8_t vector = (uint8_t)daze_read_u16(record + 16);
  const uint16_t ax = daze_read_u16(record);
  const uint16_t bx = daze_read_u16(record + 2);
  if (vector == DAZE_INT_BIOS_TIME && (ax >> 8) == 0x00) {
    DazeBiosTimerTick reply;
    if (!daze_bios_timer_ticks(&reply)) return DAZE_KVM_PREFLIGHT_BOUNDARY_FAILED;
    daze_kvm_runner_gate_reply_init(record, mailbox);
    daze_write_u16(mailbox, reply.ax);
    daze_write_u16(mailbox + 4, reply.cx);
    daze_write_u16(mailbox + 6, reply.dx);
    reply_carry(mailbox, reply.carry);
    return DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED;
  }
  if (vector == DAZE_INT_BIOS_EQUIPMENT) {
    daze_kvm_runner_gate_reply_init(record, mailbox);
    daze_write_u16(mailbox, 0x0020);
    reply_carry(mailbox, 0);
    return DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED;
  }
  if (vector == DAZE_INT_BIOS_VIDEO && (ax >> 8) == 0x0f) {
    daze_kvm_runner_gate_reply_init(record, mailbox);
    daze_write_u16(mailbox, 0x5003);
    daze_write_u16(mailbox + 2, (uint16_t)(bx & 0x00ffu));
    reply_carry(mailbox, 0);
    return DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED;
  }
  if (vector == DAZE_INT_BIOS_VIDEO && ax == 0x1200 && (bx & 0x00ffu) == 0x10) {
    daze_kvm_runner_gate_reply_init(record, mailbox);
    daze_write_u16(mailbox + 2, 0x0003);
    daze_write_u16(mailbox + 4, 0x0001);
    reply_carry(mailbox, 0);
    return DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED;
  }
  return DAZE_KVM_PREFLIGHT_BOUNDARY_UNSUPPORTED;
}
