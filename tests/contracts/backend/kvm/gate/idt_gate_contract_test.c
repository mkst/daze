#include "idt_gate.h"

#include <stdio.h>
#include <string.h>

static int check(const char *name, int condition) {
  if (!condition) fprintf(stderr, "CHECK FAILED: %s\n", name);
  return condition;
}

int main(void) {
  uint8_t entry[8];
  memset(entry, 0xff, sizeof(entry));
  daze_kvm_encode_idt_gate(entry, 0x89abcdefu, 0x1234, 0x86);
  const uint8_t expected[] = {0xef, 0xcd, 0x34, 0x12, 0, 0x86, 0xab, 0x89};
  if (!check("IDT gate has the architectural byte layout",
             memcmp(entry, expected, sizeof(entry)) == 0))
    return 1;
  puts("KVM IDT gate contract: ok");
  return 0;
}
