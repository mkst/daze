#include "protected.h"

#include <stdio.h>
#include <string.h>

enum {
  GUEST_SIZE = 0x10000,
  GDT_BASE = 0x1000,
  LDT_BASE = 0x2000,
  /* GDT index 1 and 2, LDT index 1. */
  GDT_CODE_16 = 0x08,
  GDT_CODE_32 = 0x10,
  LDT_CODE_16 = 0x04 | 0x08,
  GDT_DATA = 0x18,
  GDT_NOT_PRESENT = 0x20,
  GDT_SYSTEM = 0x28,
  TARGET_OFFSET = 0x39bc,
};

/* Architectural x86 descriptor layout: access/type at byte 5, high-limit and
 * flags at byte 6, base-high at byte 7. D/B is descriptor[6] & 0x40. */
static void put_descriptor(uint8_t *table, uint32_t base, uint16_t limit, uint32_t offset,
                           uint8_t access, uint8_t flags) {
  uint8_t *const descriptor = table + base + offset;
  descriptor[0] = (uint8_t)limit;
  descriptor[1] = (uint8_t)(limit >> 8);
  descriptor[2] = 0;
  descriptor[3] = 0;
  descriptor[4] = 0;
  descriptor[5] = access;
  descriptor[6] = flags;
  descriptor[7] = 0;
}

static int check(const char *name, int condition) {
  if (!condition) fprintf(stderr, "CHECK FAILED: %s\n", name);
  return condition;
}

int main(void) {
  static uint8_t guest[GUEST_SIZE];
  memset(guest, 0, sizeof(guest));
  const uint16_t gdt_limit = 0x7f, ldt_limit = 0x0f;
  put_descriptor(guest, GDT_BASE, gdt_limit, GDT_CODE_16, 0x9a, 0x00);
  put_descriptor(guest, GDT_BASE, gdt_limit, GDT_CODE_32, 0x9a, 0x40);
  put_descriptor(guest, LDT_BASE, ldt_limit, GDT_CODE_16, 0x9a, 0x00);
  put_descriptor(guest, GDT_BASE, gdt_limit, GDT_DATA, 0x92, 0x00);
  put_descriptor(guest, GDT_BASE, gdt_limit, GDT_NOT_PRESENT, 0x1a, 0x00);
  put_descriptor(guest, GDT_BASE, gdt_limit, GDT_SYSTEM, 0x82, 0x00);

  int passed = 1;
  DazeDpmiInterruptVector target = {.segment = GDT_CODE_16, .offset = TARGET_OFFSET};
  uint8_t entry16[8] = {0}, entry32[8] = {0}, entry_ldt[8] = {0};

  passed &= check("16-bit GDT target builds an entry",
                  daze_kvm_protected_gate_client_entry(guest, sizeof(guest), GDT_BASE, gdt_limit,
                                                       LDT_BASE, ldt_limit, &target, entry16));
  target.segment = GDT_CODE_32;
  passed &= check("32-bit GDT target builds an entry",
                  daze_kvm_protected_gate_client_entry(guest, sizeof(guest), GDT_BASE, gdt_limit,
                                                       LDT_BASE, ldt_limit, &target, entry32));
  /* The TI bit selects the LDT; the same descriptor bytes give the same width. */
  target.segment = LDT_CODE_16;
  passed &= check("16-bit LDT target builds an entry",
                  daze_kvm_protected_gate_client_entry(guest, sizeof(guest), GDT_BASE, gdt_limit,
                                                       LDT_BASE, ldt_limit, &target, entry_ldt));

  passed &= check("16-bit gate type is 86h", entry16[5] == 0x86);
  passed &= check("32-bit gate type is 8Eh", entry32[5] == 0x8e);
  passed &= check("16-bit LDT gate type is 86h", entry_ldt[5] == 0x86);

  passed &= check("offset low is preserved for both widths",
                  entry16[0] == entry32[0] && entry16[1] == entry32[1]);
  passed &= check("offset high is preserved for both widths",
                  entry16[6] == entry32[6] && entry16[7] == entry32[7]);
  passed &= check("offset bytes carry 39bch", entry16[0] == 0xbc && entry16[1] == 0x39);
  passed &= check("selector byte is preserved", entry32[2] == (uint8_t)GDT_CODE_32);
  passed &= check("IST byte is zero", entry16[4] == 0 && entry32[4] == 0);
  passed &= check("the LDT entry matches the GDT 16-bit entry apart from the selector",
                  entry16[5] == entry_ldt[5] && entry16[0] == entry_ldt[0] &&
                    entry16[1] == entry_ldt[1] && entry_ldt[2] == (uint8_t)LDT_CODE_16);

  /* Hold one selector and one target fixed and flip only the descriptor's D/B
   * bit. The installed entry must then differ in the type byte alone, which is
   * what proves the width is read from the descriptor and not from the
   * selector. */
  target.segment = GDT_CODE_16;
  uint8_t before[8] = {0}, after[8] = {0};
  passed &= check("fixed selector builds a 16-bit entry",
                  daze_kvm_protected_gate_client_entry(guest, sizeof(guest), GDT_BASE, gdt_limit,
                                                       LDT_BASE, ldt_limit, &target, before) &&
                    before[5] == 0x86);
  guest[GDT_BASE + GDT_CODE_16 + 6] = 0x40;
  passed &= check("the same selector with D/B set builds a 32-bit entry",
                  daze_kvm_protected_gate_client_entry(guest, sizeof(guest), GDT_BASE, gdt_limit,
                                                       LDT_BASE, ldt_limit, &target, after) &&
                    after[5] == 0x8e);
  passed &= check("only the type byte differs across widths",
                  memcmp(before, after, 5) == 0 && before[6] == after[6] && before[7] == after[7] &&
                    before[5] != after[5]);
  guest[GDT_BASE + GDT_CODE_16 + 6] = 0x00;

  /* Exercise the production projection, not just its entry encoder. The
   * mediator is 32-bit but DPMILOAD's multiplex reflector uses plain IRET;
   * using the mediator layout's gate type would leave a 12-byte frame on the
   * reflector's stack instead of its six-byte IP:CS:FLAGS frame. */
  {
    const DazeKvmProtectedGateLayout layout = {
      .idt_address = 0x3000,
      .idt_limit = 0x7ff,
      .handler_address = 0x4000,
      .dos_handler_address = 0x4100,
      .default_dos_stub_address = 0x4200,
      .record_address = 0x4300,
      .mailbox_address = 0x4400,
      .handler_selector = 0x08,
      .handler_data_selector = 0x18,
      .interrupt_gate_type = 0x8e,
      .exchange_limit = 1,
    };
    DazeKvmMachine machine = {.guest = guest, .guest_size = sizeof(guest), .vcpu = -1};
    DazeKvmDpmiMediator mediator = {
      .guest = guest,
      .guest_size = sizeof(guest),
      .gdt_address = GDT_BASE,
      .gdt_size = gdt_limit + 1u,
      .ldt_address = LDT_BASE,
      .ldt_size = ldt_limit + 1u,
    };
    mediator.interrupt_vectors[0x2f] =
      (DazeDpmiInterruptVector){.segment = GDT_CODE_16, .offset = 0x2950};
    passed &=
      check("production INT 2Fh projection uses a 16-bit client frame",
            daze_kvm_protected_gate_project_interrupt_vector(&machine, &mediator, &layout, 0x2f) &&
              guest[layout.idt_address + 0x2f * 8 + 5] == 0x86);
    mediator.interrupt_vectors[0x2f].segment = GDT_CODE_32;
    passed &=
      check("production INT 2Fh projection retains a 32-bit client frame",
            daze_kvm_protected_gate_project_interrupt_vector(&machine, &mediator, &layout, 0x2f) &&
              guest[layout.idt_address + 0x2f * 8 + 5] == 0x8e);
  }

  const uint8_t guard[8] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11};
  const uint16_t refusals[] = {GDT_DATA, GDT_NOT_PRESENT, GDT_SYSTEM, 0x00, 0x03};
  for (size_t index = 0; index < sizeof(refusals) / sizeof(refusals[0]); ++index) {
    uint8_t entry[8];
    memcpy(entry, guard, sizeof(entry));
    target.segment = refusals[index];
    char name[64];
    snprintf(name, sizeof(name), "selector %04x is refused and entry is untouched",
             refusals[index]);
    passed &=
      check(name, daze_kvm_protected_gate_client_entry(guest, sizeof(guest), GDT_BASE, gdt_limit,
                                                       LDT_BASE, ldt_limit, &target, entry) == 0 &&
                    memcmp(entry, guard, sizeof(entry)) == 0);
  }

  {
    uint8_t entry[8];
    target.segment = 0x7c;
    passed &= check("a selector past the GDT limit is refused",
                    daze_kvm_protected_gate_client_entry(guest, sizeof(guest), GDT_BASE, gdt_limit,
                                                         LDT_BASE, ldt_limit, &target, entry) == 0);
    target.segment = 0x7f;
    passed &= check("the last in-limit GDT selector has no code descriptor and is refused",
                    daze_kvm_protected_gate_client_entry(guest, sizeof(guest), GDT_BASE, gdt_limit,
                                                         LDT_BASE, ldt_limit, &target, entry) == 0);
  }

  if (!passed) {
    fprintf(stderr, "client gate width contract: FAILED\n");
    return 1;
  }
  printf("client gate width contract: ok\n");
  return 0;
}
