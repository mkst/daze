#include "int31_adapter.c"
#include "byte_order.h"
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>

static void call(uc_engine *uc, DazeUnicornContext *context, uint16_t ax, uint16_t bx, uint16_t cx,
                 uint16_t dx, uint16_t expected, int carry) {
  set_reg32(uc, UC_X86_REG_EAX, 0xa5a50000u | ax);
  set_reg16(uc, UC_X86_REG_BX, bx);
  set_reg16(uc, UC_X86_REG_CX, cx);
  set_reg16(uc, UC_X86_REG_DX, dx);
  set_reg16(uc, UC_X86_REG_IP, 0x100);
  set_reg32(uc, UC_X86_REG_EFLAGS, 0x202);
  assert(daze_int31_dispatch(uc, &context->engine, &context->run, &context->process));
  assert(get_reg32(uc, UC_X86_REG_EAX) == (0xa5a50000u | expected));
  assert((get_reg32(uc, UC_X86_REG_EFLAGS) & 1) == (unsigned)carry);
  assert(get_reg16(uc, UC_X86_REG_IP) == 0x102);
}

int main(void) {
  uc_engine *uc;
  assert(uc_open(UC_ARCH_X86, UC_MODE_16, &uc) == UC_ERR_OK);
  assert(uc_mem_map(uc, 0, k_memory_size, UC_PROT_ALL) == UC_ERR_OK);
  DazeUnicornContext context = {0};
  daze_dos_memory_init(&context.process.dos_memory, 0x3000, 0xa000);
  daze_dpmi_linear_memory_init(&context.process.dpmi.linear_memory, 0x50000, 0xfd0000);
  uc_x86_mmr ldtr = {.base = k_dpmi_ldt_address, .limit = k_dpmi_ldt_size - 1};
  uc_x86_mmr gdtr = {.base = k_dpmi_gdt_address, .limit = 0xff};
  assert(uc_reg_write(uc, UC_X86_REG_LDTR, &ldtr) == UC_ERR_OK);
  assert(uc_reg_write(uc, UC_X86_REG_GDTR, &gdtr) == UC_ERR_OK);
  uint8_t descriptor[8];
  daze_dpmi_descriptor_encode(descriptor, 0x10000, 0xffff, 0x9a, 0);
  assert(uc_mem_write(uc, k_dpmi_gdt_address + 8, descriptor, 8) == UC_ERR_OK);
  call(uc, &context, 0x0100, 8, 0, 0, 0x3000, 0);
  uint16_t selector = get_reg16(uc, UC_X86_REG_DX);
  assert(context.process.dpmi.ldt_used[selector >> 3]);
  assert(uc_mem_read(uc, k_dpmi_ldt_address + (selector & ~7u), descriptor, 8) == UC_ERR_OK);
  assert(daze_read_u16(descriptor + 2) == 0 && descriptor[4] == 3);
  call(uc, &context, 0x0101, 0, 0, selector, 0x0101, 0);
  assert(!context.process.dpmi.ldt_used[selector >> 3]);
  uint8_t empty[8] = {0}, after[8];
  assert(uc_mem_read(uc, k_dpmi_ldt_address + (selector & ~7u), after, 8) == UC_ERR_OK);
  assert(memcmp(after, empty, 8) == 0);
  call(uc, &context, 0x0101, 0, 0, selector, 9, 1);
  call(uc, &context, 0x0100, 0xffff, 0, 0, 8, 1);
  call(uc, &context, 0x000a, 8, 0, 0, (k_dpmi_first_ldt_index << 3) | 4, 0);
  selector = get_reg16(uc, UC_X86_REG_AX);
  assert(uc_mem_read(uc, k_dpmi_ldt_address + (selector & ~7u), after, 8) == UC_ERR_OK);
  assert((after[5] & 0x18) == 0x10 && after[4] == 1);
  call(uc, &context, 0x000a, 0x80, 0, 0, DAZE_DPMI_ERR_INVALID_SELECTOR, 1);
  call(uc, &context, 0x000a, 0, 0, 0, DAZE_DPMI_ERR_INVALID_SELECTOR, 1);
  call(uc, &context, 0x0008, selector, 0x000f, 0xffff, 0x0008, 0);
  assert(uc_mem_read(uc, k_dpmi_ldt_address + (selector & ~7u), after, 8) == UC_ERR_OK);
  assert(daze_read_u16(after) == 0xffff && (after[6] & 15) == 15);
  set_reg16(uc, UC_X86_REG_ES, 0);
  set_reg16(uc, UC_X86_REG_DI, 0x1000);
  call(uc, &context, 0x0500, 0, 0, 0, 0x0500, 0);
  uint8_t info[48];
  assert(uc_mem_read(uc, 0x1000, info, sizeof(info)) == UC_ERR_OK);
  assert(daze_read_u32(info) ==
         daze_dpmi_linear_memory_largest_available(&context.process.dpmi.linear_memory));
  for (size_t i = 4; i < sizeof(info); ++i)
    assert(info[i] == 0xff);
  assert(uc_mem_unmap(uc, 0x1000, 0x1000) == UC_ERR_OK);
  call(uc, &context, 0x0500, 0, 0, 0, DAZE_DPMI_ERR_INVALID_SELECTOR, 1);
  call(uc, &context, 0x000b, selector, 0, 0, DAZE_DPMI_ERR_INVALID_SELECTOR_ALIAS, 1);
  call(uc, &context, 0x000c, selector, 0, 0, DAZE_DPMI_ERR_INVALID_SELECTOR_ALIAS, 1);
  assert(uc_mem_map(uc, 0x1000, 0x1000, UC_PROT_ALL) == UC_ERR_OK);
  memset(descriptor, 0, 8);
  assert(uc_mem_write(uc, 0x1000, descriptor, 8) == UC_ERR_OK);
  call(uc, &context, 0x000c, selector, 0, 0, DAZE_DPMI_ERR_INVALID_SEGMENT, 1);
  daze_dpmi_descriptor_encode(descriptor, 0x234000, 0xfffff, 0x92, 8);
  assert(uc_mem_write(uc, 0x1000, descriptor, 8) == UC_ERR_OK);
  call(uc, &context, 0x000c, selector, 0, 0, 0x000c, 0);
  assert(uc_mem_read(uc, k_dpmi_ldt_address + (selector & ~7u), after, 8) == UC_ERR_OK);
  assert(memcmp(after, descriptor, 8) == 0);
  call(uc, &context, 0x0102, 8, 0, 0xffff, 9, 1);
  call(uc, &context, 0x0501, 0, 0x100, 0, 0x0501, 0);
  uint16_t token = get_reg16(uc, UC_X86_REG_DI);
  call(uc, &context, 0x0102, 0x20, 0, token, 0x0102, 0);
  call(uc, &context, 0x0101, 0, 0, token, 0x0101, 0);
  uint16_t slot;
  FILE *capture = tmpfile();
  assert(capture != NULL);
  int saved = dup(STDERR_FILENO);
  assert(saved >= 0 && dup2(fileno(capture), STDERR_FILENO) >= 0);
  const char *existing_record = getenv("DAZE_DPMI_VECTOR_RECORD");
  char *saved_record = existing_record == NULL ? NULL : strdup(existing_record);
  assert(existing_record == NULL || saved_record != NULL);
  assert(setenv("DAZE_DPMI_VECTOR_RECORD", "1", 1) == 0);
  for (int kind = 0; kind < 3; ++kind) {
    daze_dpmi_descriptor_encode(descriptor, 0x10000, 0xffff, kind == 0 ? 0x92 : 0x9a,
                                kind == 2 ? 4 : 0);
    assert(uc_mem_write(uc, k_dpmi_gdt_address + 8, descriptor, 8) == UC_ERR_OK);
    set_reg32(uc, UC_X86_REG_CR0, 1);
    set_reg16(uc, UC_X86_REG_CS, 8);
    assert(dpmi_code_default_size(uc, 8) == kind - 1);
    DazeDpmiResult result = {.vector_segment = 8,
                             .vector_offset = 0x1234,
                             .interrupt_segment = 8,
                             .interrupt_offset = 0x12345678};
    dpmi_vector_record(uc, &context.process.dpmi, 0x0202, 0xb, (DazeDpmiVectorInputs){0}, &result);
    dpmi_vector_record(uc, &context.process.dpmi, 0x0204, 0x2f, (DazeDpmiVectorInputs){0}, &result);
  }
  if (saved_record != NULL) {
    assert(setenv("DAZE_DPMI_VECTOR_RECORD", saved_record, 1) == 0);
    free(saved_record);
  } else
    assert(unsetenv("DAZE_DPMI_VECTOR_RECORD") == 0);
  fflush(stderr);
  assert(dup2(saved, STDERR_FILENO) >= 0);
  close(saved);
  rewind(capture);
  char text[8192] = {0};
  assert(fread(text, 1, sizeof(text) - 1, capture) > 0);
  assert(strstr(text, "backend=unicorn") != NULL && strstr(text, "12345678") != NULL);
  fclose(capture);
  set_reg32(uc, UC_X86_REG_CR0, 0);
  assert(uc_mem_unmap(uc, k_dpmi_gdt_address, 0x10000) == UC_ERR_OK);
  call(uc, &context, 0x000a, 8, 0, 0, DAZE_DPMI_ERR_INVALID_SELECTOR, 1);
  assert(!dpmi_ldt_slot(&context.process.dpmi, 8, &slot));
  assert(!dpmi_ldt_slot(&context.process.dpmi, 4, &slot));
  assert(!dpmi_ldt_slot(&context.process.dpmi, 0xfffc, &slot));
  assert(uc_mem_unmap(uc, k_dpmi_ldt_address, 0x10000) == UC_ERR_OK);
  DazeDpmiProcessState before = context.process.dpmi;
  assert(
    !dpmi_allocate_ldt_descriptors(uc, &context.process.dpmi, &context.engine.metrics, 1, &slot));
  assert(memcmp(before.ldt_used, context.process.dpmi.ldt_used, sizeof(before.ldt_used)) == 0);
  assert(!dpmi_write_ldt_descriptor(uc, &context.process.dpmi, &context.engine.metrics, selector,
                                    descriptor));
  uc_close(uc);
  return 0;
}
