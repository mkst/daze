#include "bios_adapter.h"

#include "kvm_bytes.h"
#include "probe_service.h"

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
  DazeBiosProbeReply reply;
  const DazeBiosProbeKind kind = daze_bios_probe_dispatch(vector, ax, bx, &reply);
  if (kind == DAZE_BIOS_PROBE_UNSUPPORTED) return DAZE_KVM_PREFLIGHT_BOUNDARY_UNSUPPORTED;
  daze_kvm_runner_gate_reply_init(record, mailbox);
  if ((reply.register_write_mask & DAZE_BIOS_PROBE_REG_AX) != 0) daze_write_u16(mailbox, reply.ax);
  if ((reply.register_write_mask & DAZE_BIOS_PROBE_REG_BX) != 0)
    daze_write_u16(mailbox + 2, reply.bx);
  if ((reply.register_write_mask & DAZE_BIOS_PROBE_REG_CX) != 0)
    daze_write_u16(mailbox + 4, reply.cx);
  if ((reply.register_write_mask & DAZE_BIOS_PROBE_REG_DX) != 0)
    daze_write_u16(mailbox + 6, reply.dx);
  reply_carry(mailbox, reply.carry);
  return DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED;
}
