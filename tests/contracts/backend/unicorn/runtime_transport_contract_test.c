#include "unicorn_services.h"
#include "byte_order.h"
#include "descriptor.h"
#include "interrupt_vector.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CHECK(condition)                                                                           \
  do {                                                                                             \
    if (!(condition)) {                                                                            \
      fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #condition);                              \
      pass = 0;                                                                                    \
      goto out;                                                                                    \
    }                                                                                              \
  } while (0)

static int descriptor(uc_engine *uc, uint16_t selector, uint32_t base, uint8_t access, int wide) {
  uint8_t bytes[8];
  daze_dpmi_descriptor_encode(bytes, base, 0xffff, access, wide ? 4 : 0);
  return uc_mem_write(uc, k_dpmi_gdt_address + selector, bytes, 8) == UC_ERR_OK;
}

static int fixture(uc_engine **uc, int source_wide, int target_wide) {
  if (uc_open(UC_ARCH_X86, UC_MODE_16, uc) != UC_ERR_OK ||
      uc_mem_map(*uc, 0, k_memory_size, UC_PROT_ALL) != UC_ERR_OK)
    return 0;
  if (!descriptor(*uc, 8, 0x10000, 0x9a, source_wide) || !descriptor(*uc, 0x10, 0x20000, 0x92, 0) ||
      !descriptor(*uc, 0x18, 0x30000, 0x92, 0) ||
      !descriptor(*uc, 0x20, 0x40000, 0x9a, target_wide))
    return 0;
  uc_x86_mmr gdtr = {.base = k_dpmi_gdt_address, .limit = 0x27};
  if (uc_reg_write(*uc, UC_X86_REG_GDTR, &gdtr) != UC_ERR_OK) return 0;
  set_reg32(*uc, UC_X86_REG_CR0, 1);
  set_reg16(*uc, UC_X86_REG_CS, 8);
  set_reg16(*uc, UC_X86_REG_DS, 0x10);
  set_reg16(*uc, UC_X86_REG_ES, 0x10);
  set_reg16(*uc, UC_X86_REG_SS, 0x18);
  set_reg32(*uc, UC_X86_REG_ESP, 0x800);
  set_reg32(*uc, UC_X86_REG_EIP, 0x100);
  set_reg32(*uc, UC_X86_REG_EFLAGS, 0x303);
  set_reg32(*uc, UC_X86_REG_EAX, 0x12345678);
  return 1;
}

static void dispose(uc_engine *uc, DazeUnicornContext *context) {
  if (uc == NULL) return;
  daze_protected_dos_continuation_clear(&context->run);
  daze_dpmi_exception_transfer_disarm(uc, &context->run);
  uc_close(uc);
}

static int protected_delivery(int source_wide, int target_wide, int advanced, int kind) {
  int pass = 1;
  uc_engine *uc = NULL;
  DazeUnicornContext context = {0};
  CHECK(fixture(&uc, source_wide, target_wide));
  context.run.interrupt_already_advanced = advanced;
  context.process.dpmi.interrupt_vectors[DAZE_INT_MULTIPLEX] =
    (DazeDpmiInterruptVector){.segment = 0x20, .offset = 0x200};
  if (kind == 1) CHECK(descriptor(uc, 8, 0x10000, 0x92, source_wide));
  if (kind == 2) CHECK(descriptor(uc, 0x20, 0x40000, 0x92, target_wide));
  if (kind == 3) set_reg16(uc, UC_X86_REG_SS, 0);
  if (kind == 4) set_reg32(uc, UC_X86_REG_ESP, 5);
  if (kind == 5) CHECK(descriptor(uc, 0x18, k_memory_size - 1, 0x92, 0));
  if (kind == 6) CHECK(uc_mem_unmap(uc, 0x30000, 0x1000) == UC_ERR_OK);
  uint32_t before_cs = get_reg16(uc, UC_X86_REG_CS);
  uint32_t before_ip = get_reg32(uc, UC_X86_REG_EIP);
  uint32_t before_sp = get_reg32(uc, UC_X86_REG_ESP);
  int handled = daze_dispatch_interrupt(uc, DAZE_INT_MULTIPLEX, &context.engine, &context.run,
                                        &context.process, NULL);
  CHECK(handled == (kind == 0));
  CHECK(get_reg32(uc, UC_X86_REG_EAX) == 0x12345678);
  if (kind != 0) {
    CHECK(get_reg16(uc, UC_X86_REG_CS) == before_cs && get_reg32(uc, UC_X86_REG_EIP) == before_ip);
    CHECK(get_reg32(uc, UC_X86_REG_ESP) == before_sp && !context.run.use_resume_address);
    goto out;
  }
  uint32_t size = source_wide ? 12 : 6;
  CHECK(get_reg32(uc, UC_X86_REG_ESP) == 0x800 - size);
  CHECK(get_reg16(uc, UC_X86_REG_CS) == 0x20 && get_reg32(uc, UC_X86_REG_EIP) == 0x200);
  CHECK(get_reg32(uc, UC_X86_REG_EFLAGS) == 3 && context.run.resume_address == 0x400);
  uint8_t bytes[12];
  CHECK(uc_mem_read(uc, 0x30800 - size, bytes, size) == UC_ERR_OK);
  CHECK((source_wide ? daze_read_u32(bytes) : daze_read_u16(bytes)) ==
        (advanced ? 0x100u : 0x102u));
  CHECK((source_wide ? daze_read_u32(bytes + 4) : daze_read_u16(bytes + 2)) == 8);
  CHECK((source_wide ? daze_read_u32(bytes + 8) : daze_read_u16(bytes + 4)) == 0x303);
out:
  dispose(uc, &context);
  return pass;
}

static int fault_diagnostic(int protected_mode, int kind) {
  int pass = 1;
  uc_engine *uc = NULL;
  FILE *trace = NULL;
  int saved_stderr = -1;
  DazeUnicornContext context = {0};
  DazeUnicornInterruptContext hook = {.context = &context};
  CHECK(fixture(&uc, 0, 0));
  const uint8_t instructions[][8] = {
    {0x8e, 0x06, 0x8c, 1}, {0x26, 0x8e, 0x1e, 0, 1}, {0x2e, 0x8e, 0x2e, 0x1e, 0},
    {0xc4, 0x3e, 0, 1},    {0xc5, 0x16, 0, 1},       {0x90},
  };
  const char *messages[] = {"attempted ES selector", "MOV DS, ES:0100", "attempted GS selector",
                            "LES DS:0100",           "LDS DS:0100",     "fault-site bytes:"};
  CHECK(uc_mem_write(uc, 0x10100, instructions[kind], 8) == UC_ERR_OK);
  uint8_t pointer[4];
  daze_write_u16(pointer, 0x1234);
  daze_write_u16(pointer + 2, 0x10);
  CHECK(uc_mem_write(uc, 0x20100, pointer, 4) == UC_ERR_OK);
  CHECK(uc_mem_write(uc, 0x2018c, pointer, 2) == UC_ERR_OK);
  CHECK(uc_mem_write(uc, 0x1001e, pointer, 2) == UC_ERR_OK);
  context.process.dpmi.client_data_base = 0x20000;
  context.process.dpmi.client_code_base = 0x10000;
  context.engine.have_code = 1;
  context.engine.full_code_hook = 1;
  context.engine.last_code_address = 0x10100;
  context.engine.recent_code_count = 1;
  context.engine.recent_code_next = 1;
  context.engine.recent_code[0] = (CodeTrace){.cs = 8, .ip = 0x100, .linear_address = 0x10100};
  context.engine.metrics.enabled = 1;
  if (!protected_mode) {
    set_reg32(uc, UC_X86_REG_CR0, 0);
    set_reg16(uc, UC_X86_REG_CS, 0x1000);
    set_reg16(uc, UC_X86_REG_DS, 0x2000);
    set_reg16(uc, UC_X86_REG_ES, 0x2000);
  }
  trace = tmpfile();
  CHECK(trace != NULL);
  saved_stderr = dup(STDERR_FILENO);
  CHECK(saved_stderr >= 0 && dup2(fileno(trace), STDERR_FILENO) >= 0);
  daze_on_interrupt(uc, DAZE_INT_GP_FAULT, &hook);
  fflush(stderr);
  CHECK(dup2(saved_stderr, STDERR_FILENO) >= 0);
  close(saved_stderr);
  saved_stderr = -1;
  CHECK(context.run.stopped && context.run.interrupt_number == DAZE_INT_GP_FAULT);
  CHECK(!context.run.terminated && !context.run.use_resume_address);
  rewind(trace);
  char bytes[8192];
  size_t size = fread(bytes, 1, sizeof(bytes) - 1, trace);
  bytes[size] = 0;
  CHECK(size < sizeof(bytes) - 1 && strstr(bytes, "#GP fault at") != NULL);
  if (protected_mode || (kind != 1 && kind != 3 && kind != 4))
    CHECK(strstr(bytes, messages[kind]) != NULL);
  CHECK(strstr(bytes, "linear=00010100 bytes=") != NULL);
  CHECK(strstr(bytes, "interrupt 0dh encountered (stopping probe)") != NULL);
out:
  if (saved_stderr >= 0) {
    fflush(stderr);
    dup2(saved_stderr, STDERR_FILENO);
    close(saved_stderr);
  }
  if (trace != NULL) fclose(trace);
  dispose(uc, &context);
  return pass;
}

int main(void) {
  int pass = 1;
  for (int source_wide = 0; source_wide < 2; ++source_wide)
    for (int target_wide = 0; target_wide < 2; ++target_wide)
      for (int advanced = 0; advanced < 2; ++advanced)
        for (int kind = 0; kind < 7; ++kind)
          pass &= protected_delivery(source_wide, target_wide, advanced, kind);
  for (int protected_mode = 0; protected_mode < 2; ++protected_mode)
    for (int kind = 0; kind < 6; ++kind)
      pass &= fault_diagnostic(protected_mode, kind);
  return pass ? 0 : 1;
}
