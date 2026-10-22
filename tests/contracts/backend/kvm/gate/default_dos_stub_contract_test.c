#include "protected.h"

#include "kvm_bytes.h"

#include <stdio.h>
#include <string.h>

int main(void) {
  const DazeKvmProtectedGateLayout layout = {
    .idt_address = 0x1000,
    .idt_limit = 0x07ff,
    .handler_address = 0x2000,
    .dos_handler_address = 0x2100,
    .default_dos_stub_address = 0x21c8,
    .record_address = 0x2200,
    .mailbox_address = 0x2240,
    .handler_selector = 0x0050,
    .handler_data_selector = 0x0058,
    .interrupt_gate_type = 0x8e,
    .exchange_limit = 1,
  };
  DazeKvmProtectedGateArtifacts artifacts;
  if (!daze_kvm_protected_gate_build(&layout, &artifacts)) {
    fprintf(stderr, "default DOS stub artifacts did not build\n");
    return 1;
  }
  static const uint8_t expected_prefix[] = {
    0x66, 0x6a, 0x00,             /* pushw 0x0 */
    0x66, 0xff, 0x74, 0x24, 0x06, /* push WORD PTR [esp+0x6] */
    0x66, 0x6a, 0x00,             /* pushw 0x0 */
    0x66, 0xff, 0x74, 0x24, 0x08, /* push WORD PTR [esp+0x8] */
    0x66, 0x6a, 0x00,             /* pushw 0x0 */
    0x66, 0xff, 0x74, 0x24, 0x0a, /* push WORD PTR [esp+0xa] */
    0xea,                         /* jmp far ptr16:32 (offset and selector appended below) */
  };
  if (artifacts.default_dos_stub_size != DAZE_KVM_PROTECTED_GATE_DEFAULT_DOS_STUB_SIZE ||
      memcmp(artifacts.default_dos_stub, expected_prefix, sizeof(expected_prefix)) != 0 ||
      daze_read_u32(artifacts.default_dos_stub + sizeof(expected_prefix)) !=
        layout.dos_handler_address ||
      daze_read_u16(artifacts.default_dos_stub + sizeof(expected_prefix) + 4) !=
        layout.handler_selector) {
    fprintf(stderr, "default DOS stub frame adapter differs from contract\n");
    return 1;
  }
  /* The accepted normal-transition gate places the stub at gate_base + 01c8
   * and its own 32-bit far jump must keep naming the flat protected-DOS gate
   * at 0050:007de900, independent of any alias selector. */
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
  DazeKvmProtectedGateArtifacts normal_artifacts;
  if (!daze_kvm_protected_gate_build(&normal, &normal_artifacts)) {
    fprintf(stderr, "accepted normal gate artifacts did not build\n");
    return 1;
  }
  static const uint8_t expected_normal_suffix[] = {
    0xea, 0x00, 0xe9, 0x7d, 0x00, 0x50, 0x00 /* jmp far 0x50:0x7de900 */
  };
  if (normal.default_dos_stub_address != normal.handler_address + 0x01c8 ||
      normal_artifacts.default_dos_stub_size != DAZE_KVM_PROTECTED_GATE_DEFAULT_DOS_STUB_SIZE ||
      memcmp(normal_artifacts.default_dos_stub + sizeof(expected_prefix) - 1,
             expected_normal_suffix, sizeof(expected_normal_suffix)) != 0) {
    fprintf(stderr, "accepted default DOS stub moved or changed its flat target\n");
    return 1;
  }
  puts("default DOS stub contract: ok");
  return 0;
}
