#include "protected.h"

#include "kvm_bytes.h"

#include <stdio.h>
#include <string.h>

/* Pins the emitted record/mailbox ABI and measured BCC 3.1 5D06h reply composition. */

static int contains(const uint8_t *bytes, size_t size, const uint8_t *pattern,
                    size_t pattern_size) {
  for (size_t offset = 0; offset + pattern_size <= size; ++offset)
    if (memcmp(bytes + offset, pattern, pattern_size) == 0) return (int)offset;
  return -1;
}

/* Each row is the register source, the store opcode, and the record slot the
 * gate writes. The source is empty for a direct register store. */
static int record_store_at(const uint8_t *handler, size_t size, uint32_t record,
                           const uint8_t *source, size_t source_size, uint8_t store,
                           uint32_t slot) {
  uint8_t pattern[16];
  size_t length = 0;
  if (source_size > 0) {
    memcpy(pattern, source, source_size);
    length = source_size;
  }
  pattern[length++] = 0x64;
  if (store == 0xa3) {
    pattern[length++] = 0xa3;
  } else {
    pattern[length++] = 0x89;
    pattern[length++] = store;
  }
  daze_write_u32(pattern + length, record + slot);
  length += 4;
  return contains(handler, size, pattern, length);
}

static int mailbox_load_present(const uint8_t *handler, size_t size, uint32_t mailbox, uint8_t load,
                                uint8_t reg, uint32_t slot) {
  uint8_t pattern[8];
  size_t length = 0;
  pattern[length++] = 0x64;
  if (load == 0xa1) {
    pattern[length++] = 0xa1;
  } else {
    pattern[length++] = 0x8b;
    pattern[length++] = reg;
  }
  daze_write_u32(pattern + length, mailbox + slot);
  length += 4;
  return contains(handler, size, pattern, length);
}

int main(void) {
  const DazeKvmProtectedGateLayout normal = {
    .idt_address = 0x7df800,
    .idt_limit = 0x07ff,
    .handler_address = 0x7de800,
    .dos_handler_address = 0x7de900,
    .default_dos_stub_address = 0x7de9c8,
    .record_address = 0x7dea00,
    .mailbox_address = 0x7dea40,
    .handler_selector = 0x0050,
    .handler_data_selector = 0x0058,
    .interrupt_gate_type = 0x8e,
    .exchange_limit = 1,
  };
  DazeKvmProtectedGateArtifacts artifacts;
  if (!daze_kvm_protected_gate_build(&normal, &artifacts)) {
    fprintf(stderr, "accepted normal gate artifacts did not build\n");
    return 1;
  }
  const uint8_t *handler = artifacts.dos_handler;
  const size_t size = artifacts.dos_handler_size;
  const uint32_t record = normal.record_address;
  const uint32_t mailbox = normal.mailbox_address;

  /* The boundary marker is a distinct protected DOS value, not the DPMI
   * mediator marker, so the owner can route only that DOS request. */
  static const uint8_t marker[] = {0xb0, DAZE_KVM_PROTECTED_DOS_MARKER, 0xe6, 0xf4};
  const int marker_at = contains(handler, size, marker, sizeof(marker));
  if (marker_at < 0) {
    fprintf(stderr, "protected DOS marker is missing\n");
    return 1;
  }

  /* Record +12 holds BP, not DX; saved ES is at +20 and DS at +40. */
  static const uint8_t plain_source[] = {0};
  static const uint8_t eax_from_ebp0[] = {0x8b, 0x45, 0x00};
  static const uint8_t eax_from_ebp4[] = {0x8b, 0x45, 0x04};
  static const uint8_t eax_from_ebp8[] = {0x8b, 0x45, 0x08};
  static const uint8_t eax_from_es[] = {0x8c, 0xc0};
  static const uint8_t eax_from_ds[] = {0x8c, 0xd8};
  static const size_t record_slots[] = {0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40};
  const int stores_present =
    record_store_at(handler, size, record, plain_source, 0, 0xa3, record_slots[0]) < marker_at &&
    record_store_at(handler, size, record, plain_source, 0, 0x1d, record_slots[1]) < marker_at &&
    record_store_at(handler, size, record, plain_source, 0, 0x0d, record_slots[2]) < marker_at &&
    record_store_at(handler, size, record, plain_source, 0, 0x15, record_slots[3]) < marker_at &&
    record_store_at(handler, size, record, plain_source, 0, 0x3d, record_slots[4]) < marker_at &&
    record_store_at(handler, size, record, eax_from_es, sizeof(eax_from_es), 0xa3,
                    record_slots[5]) < marker_at &&
    record_store_at(handler, size, record, plain_source, 0, 0x35, record_slots[6]) < marker_at &&
    record_store_at(handler, size, record, eax_from_ebp0, sizeof(eax_from_ebp0), 0xa3,
                    record_slots[7]) < marker_at &&
    record_store_at(handler, size, record, eax_from_ebp4, sizeof(eax_from_ebp4), 0xa3,
                    record_slots[8]) < marker_at &&
    record_store_at(handler, size, record, eax_from_ebp8, sizeof(eax_from_ebp8), 0xa3,
                    record_slots[9]) < marker_at &&
    record_store_at(handler, size, record, eax_from_ds, sizeof(eax_from_ds), 0xa3,
                    record_slots[10]) < marker_at &&
    record_slots[10] + 4 == DAZE_KVM_DPMI_RECORD_SIZE;
  if (!stores_present) {
    fprintf(stderr, "protected record stores differ from the accepted ABI\n");
    return 1;
  }

  /* DX loads from mailbox +24; +20 packs returned DS high / ES low.
   * FLAGS are merged into the CPU frame. */
  const int loads_present = mailbox_load_present(handler, size, mailbox, 0xa1, 0, 0) &&
                            mailbox_load_present(handler, size, mailbox, 0x8b, 0x1d, 4) &&
                            mailbox_load_present(handler, size, mailbox, 0x8b, 0x0d, 8) &&
                            mailbox_load_present(handler, size, mailbox, 0x8b, 0x35, 12) &&
                            mailbox_load_present(handler, size, mailbox, 0x8b, 0x3d, 16) &&
                            mailbox_load_present(handler, size, mailbox, 0x8b, 0x15, 20) &&
                            mailbox_load_present(handler, size, mailbox, 0x8b, 0x15, 24) &&
                            mailbox_load_present(handler, size, mailbox, 0xa1, 0, 28);
  /* Saved ES at record +20 gates its reload; returned DS comes from mailbox +20 high. */
  uint8_t es_compare[8] = {0x66, 0x64, 0x3b, 0x15};
  daze_write_u32(es_compare + 4, record + 20);
  static const uint8_t segment_restore[] = {
    0x8e, 0xc2,       /* mov es,dx */
    0x50,             /* push ax */
    0x89, 0xd0,       /* mov ax,dx */
    0xc1, 0xe8, 0x10, /* shr ax,16 */
    0x8e, 0xd8,       /* mov ds,ax */
    0x58,             /* pop ax */
  };
  static const uint8_t carry_and_flags[] = {
    0x83, 0x65, 0x08, 0xfe, /* and word [di+8],0xfffe */
    0x09, 0x45, 0x08,       /* or [di+8],ax */
  };
  static const uint8_t return_tail[] = {
    0x58,       /* pop ax */
    0x0f, 0xa1, /* pop fs */
    0x5d,       /* pop bp */
    0xcf,       /* iret */
  };
  if (!loads_present || contains(handler, size, es_compare, sizeof(es_compare)) < marker_at ||
      contains(handler, size, segment_restore, sizeof(segment_restore)) < 0 ||
      contains(handler, size, carry_and_flags, sizeof(carry_and_flags)) < 0 ||
      memcmp(handler + size - sizeof(return_tail), return_tail, sizeof(return_tail)) != 0) {
    fprintf(stderr, "protected mailbox, segment, carry or return ABI differs from the contract\n");
    return 1;
  }

  /* Measured BCC 5D06h reply preserves record high halves, except packed DS
   * comes from the broker's segment reply rather than a register record slot. */
  uint8_t record_bytes[DAZE_KVM_DPMI_RECORD_SIZE] = {0};
  uint8_t reply[16] = {0};
  daze_write_u16(record_bytes, 0x5d06);
  daze_write_u32(record_bytes + 12, 0x0000005a);
  daze_write_u32(record_bytes + 20, 0x00000300);
  daze_write_u32(record_bytes + 36, 0x00000006);
  daze_write_u32(record_bytes + 40, 0x00000010);
  daze_write_u16(reply, 0x5d06);
  daze_write_u16(reply + 4, 0x0002);
  daze_write_u16(reply + 6, 0x0002);
  daze_write_u16(reply + 8, 0x001f);
  daze_write_u16(reply + 12, 0x0300);
  daze_write_u16(reply + 14, 0x0006);

  static const uint8_t sources[] = {0, 4, 8, 12, 24, 16, 20, 36};
  static const uint8_t destinations[] = {0, 4, 8, 24, 12, 16, 20, 28};
  uint8_t composed[DAZE_KVM_DPMI_MAILBOX_SIZE] = {0};
  for (size_t index = 0; index < 8; ++index) {
    uint8_t value[4];
    memcpy(value, record_bytes + sources[index], sizeof(value));
    daze_write_u16(value, daze_read_u16(reply + index * 2));
    memcpy(composed + destinations[index], value, sizeof(value));
  }
  /* The gate reads DS from the high half of slot 20, so that is where the
   * broker's segment reply must land. */
  daze_write_u16(composed + 22, 0x0300);
  if (daze_read_u32(composed) != 0x00005d06 || daze_read_u32(composed + 4) != 0 ||
      daze_read_u32(composed + 8) != 0x00000002 || daze_read_u32(composed + 12) != 0x0000001f ||
      daze_read_u32(composed + 16) != 0 || daze_read_u32(composed + 20) != 0x03000300 ||
      daze_read_u32(composed + 24) != 0x00000002 || daze_read_u32(composed + 28) != 0x00000006) {
    fprintf(stderr, "one BCC 5D06h composition differs from the observed host mailbox\n");
    return 1;
  }
  puts("protected record/mailbox contract: ok");
  return 0;
}
