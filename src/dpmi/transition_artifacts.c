#include "transition_artifacts.h"

#include <string.h>

#include "interrupt_vector.h"

static void descriptor(uint8_t *bytes, uint32_t base, uint32_t limit, uint8_t access,
                       uint8_t flags) {
  bytes[0] = (uint8_t)limit;
  bytes[1] = (uint8_t)(limit >> 8);
  bytes[2] = (uint8_t)base;
  bytes[3] = (uint8_t)(base >> 8);
  bytes[4] = (uint8_t)(base >> 16);
  bytes[5] = access;
  bytes[6] = (uint8_t)((limit >> 16) & 0x0f) | (uint8_t)(flags << 4);
  bytes[7] = (uint8_t)(base >> 24);
}

static int additions_valid(const DazeDpmiTransitionArtifactInput *input) {
  if (input->addition_count != 0 && input->additions == NULL) return 0;
  for (size_t index = 0; index < input->addition_count; ++index) {
    const DazeDpmiTransitionDescriptorAddition *addition = input->additions + index;
    if ((addition->table != DAZE_DPMI_TRANSITION_GDT &&
         addition->table != DAZE_DPMI_TRANSITION_LDT) ||
        (addition->selector & 7u) != 0 || addition->selector > 65528 ||
        (input->convert_environment && addition->table == DAZE_DPMI_TRANSITION_GDT &&
         addition->selector == DAZE_DPMI_TRANSITION_ENVIRONMENT_SELECTOR))
      return 0;
  }
  return 1;
}

int daze_dpmi_transition_artifacts_build(const DazeDpmiTransitionArtifactInput *input,
                                         DazeDpmiTransitionArtifacts *output) {
  if (input == NULL || output == NULL || input->client_ds == 0 || input->client_ss == 0 ||
      input->return_cs == 0 || input->psp_segment == 0 || input->entry_segment == 0 ||
      input->gdt_address == 0 || input->ldt_address == 0 ||
      ((input->idt_address == 0) != (input->idt_limit == 0)) ||
      (input->idt_address != 0 && input->idt_limit < 0x18f) || !additions_valid(input))
    return 0;
  DazeDpmiTransitionArtifacts built = {0};
  descriptor(built.gdt + 8, (uint32_t)input->return_cs << 4, 0xffff, 0x9a, 0x00);
  /* ASPSX's real-mode client stack becomes selector 0010h.  Keep that
   * descriptor's stack-address size at 16 bits: its protected exception
   * path deliberately wraps a low SP within this 64 KiB segment. */
  descriptor(built.gdt + 16, (uint32_t)input->client_ds << 4, 0xffff, 0x92, 0x00);
  const uint16_t stack_selector = input->client_ds == input->client_ss ? 0x0010 : 0x0040;
  if (stack_selector != 0x0010)
    descriptor(built.gdt + stack_selector, (uint32_t)input->client_ss << 4, 0xffff, 0x92, 0x00);
  descriptor(built.gdt + 24, (uint32_t)input->psp_segment << 4, 0xff, 0x92, 0x00);
  descriptor(built.gdt + 32, (uint32_t)input->entry_segment << 4, 0xffff, 0x9a, 0x04);
  descriptor(built.gdt + 40, (uint32_t)input->entry_segment << 4, 0xffff, 0x9a, 0x00);
  descriptor(built.gdt + 48, input->ldt_address, DAZE_DPMI_TRANSITION_LDT_SIZE - 1, 0x82, 0x00);
  for (size_t index = 0; index < input->addition_count; ++index) {
    const DazeDpmiTransitionDescriptorAddition *addition = input->additions + index;
    uint8_t *table = addition->table == DAZE_DPMI_TRANSITION_GDT ? built.gdt : built.ldt;
    descriptor(table + addition->selector, addition->base, addition->limit, addition->access,
               addition->flags);
  }
  if (input->convert_environment && input->environment_segment != 0) {
    /* DPMI entry replaces the active PSP's environment segment with a selector. */
    descriptor(built.gdt + DAZE_DPMI_TRANSITION_ENVIRONMENT_SELECTOR,
               (uint32_t)input->environment_segment << 4, 0xffff, 0x92, 0);
    built.environment_pointer[0] = DAZE_DPMI_TRANSITION_ENVIRONMENT_SELECTOR;
  }
  const uint8_t gdtr[] = {0xff,
                          0xff,
                          (uint8_t)input->gdt_address,
                          (uint8_t)(input->gdt_address >> 8),
                          (uint8_t)(input->gdt_address >> 16),
                          (uint8_t)(input->gdt_address >> 24)};
  memcpy(built.gdtr, gdtr, sizeof(gdtr));
  if (input->idt_address != 0) {
    const uint8_t idtr[] = {
      (uint8_t)input->idt_limit,           (uint8_t)(input->idt_limit >> 8),
      (uint8_t)input->idt_address,         (uint8_t)(input->idt_address >> 8),
      (uint8_t)(input->idt_address >> 16), (uint8_t)(input->idt_address >> 24)};
    memcpy(built.idtr, idtr, sizeof(idtr));
  }
  const uint8_t real_mode_setup[] = {
    0xfa,                               /* cli */
    0x2e, 0x0f, 0x01, 0x16, 0x80, 0x00, /* lgdt cs:[0x80] */
    0x0f, 0x20, 0xc0,                   /* mov eax,cr0 */
    0x66, 0x83, 0xc8, 0x01,             /* or eax,0x1 */
    0x0f, 0x22, 0xc0,                   /* mov cr0,eax */
    0xea, 0x20, 0x00, 0x20, 0x00        /* jmp far 0x20:0x20 */
  };
  uint8_t protected_mode_setup_without_idtr[] = {
    0x66, 0xb8, 0x30, 0x00, /* mov ax,0x30 */
    0x0f, 0x00, 0xd0,       /* lldt ax */
    0x66, 0xb8, 0x10, 0x00, /* mov ax,0x10 */
    0x8e, 0xd8,             /* mov ds,ax */
    0x66, 0xb8, 0x10, 0x00, /* mov ax,0x10 */
    0x8e, 0xd0,             /* mov ss,ax */
    0x83, 0xc4, 0x04,       /* add esp,0x4 */
    0x0f, 0xb7, 0xe4,       /* movzx esp,sp */
    0x66, 0xb8, 0x18, 0x00, /* mov ax,0x18 */
    0x8e, 0xc0,             /* mov es,ax */
    0x33, 0xc0,             /* xor eax,eax */
    0x8e, 0xe0,             /* mov fs,ax */
    0x8e, 0xe8,             /* mov gs,ax */
    0xea                    /* jmp far ptr16:32 (offset and selector appended below) */
  };
  uint8_t protected_mode_setup_with_idtr[] = {
    0x66, 0xb8, 0x30, 0x00,                   /* mov ax,0x30 */
    0x0f, 0x00, 0xd0,                         /* lldt ax */
    0x66, 0xb8, 0x10, 0x00,                   /* mov ax,0x10 */
    0x8e, 0xd8,                               /* mov ds,ax */
    0x66, 0xb8, 0x10, 0x00,                   /* mov ax,0x10 */
    0x8e, 0xd0,                               /* mov ss,ax */
    0x2e, 0x67, 0x0f, 0x01, 0x1e, 0x86, 0x00, /* lidt cs:[0x86] */
    0x83, 0xc4, 0x04,                         /* add esp,0x4 */
    0x0f, 0xb7, 0xe4,                         /* movzx esp,sp */
    0x66, 0xb8, 0x18, 0x00,                   /* mov ax,0x18 */
    0x8e, 0xc0,                               /* mov es,ax */
    0x33, 0xc0,                               /* xor eax,eax */
    0x8e, 0xe0,                               /* mov fs,ax */
    0x8e, 0xe8,                               /* mov gs,ax */
    0xea /* jmp far ptr16:32 (offset and selector appended below) */
  };
  protected_mode_setup_without_idtr[15] = (uint8_t)stack_selector;
  protected_mode_setup_without_idtr[16] = (uint8_t)(stack_selector >> 8);
  protected_mode_setup_with_idtr[15] = (uint8_t)stack_selector;
  protected_mode_setup_with_idtr[16] = (uint8_t)(stack_selector >> 8);
  memcpy(built.trampoline, real_mode_setup, sizeof(real_mode_setup));
  const uint8_t *protected_mode_setup =
    input->idt_address == 0 ? protected_mode_setup_without_idtr : protected_mode_setup_with_idtr;
  const size_t protected_mode_setup_size = input->idt_address == 0
                                             ? sizeof(protected_mode_setup_without_idtr)
                                             : sizeof(protected_mode_setup_with_idtr);
  memcpy(built.trampoline + 0x20, protected_mode_setup, protected_mode_setup_size);
  const uint32_t entry = input->return_ip;
  const uint16_t selector = 0x0008;
  memcpy(built.trampoline + 0x20 + protected_mode_setup_size, &entry, sizeof(entry));
  memcpy(built.trampoline + 0x20 + protected_mode_setup_size + sizeof(entry), &selector,
         sizeof(selector));
  memcpy(built.state_stub,
         (const uint8_t[]){0xcd, DAZE_INT_STATE_SAVE_GATE, /* int 0xfb */
                           0x66, 0xcb /* retfd (32-bit far return in 16-bit code) */},
         sizeof(built.state_stub));
  memcpy(built.raw_switch_stub,
         (const uint8_t[]){0xcd, DAZE_INT_RAW_SWITCH_GATE, /* int 0xfc */
                           0xf4 /* hlt */},
         sizeof(built.raw_switch_stub));
  *output = built;
  return 1;
}
