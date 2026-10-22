#include "bios_adapter.h"
#include "byte_order.h"
#include "descriptor.h"
#include "interrupt_vector.h"
#include "unicorn_image.h"
#include "unicorn_services.h"
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static uc_engine *fixture(void) {
  uc_engine *uc;
  assert(uc_open(UC_ARCH_X86, UC_MODE_16, &uc) == UC_ERR_OK);
  assert(uc_mem_map(uc, 0, k_memory_size, UC_PROT_ALL) == UC_ERR_OK);
  return uc;
}

static void probes(void) {
  uc_engine *uc = fixture();
  DazeUnicornContext context = {0};
  struct {
    uint8_t interrupt;
    uint16_t ax, bx, reply_ax, reply_bx, reply_cx, reply_dx;
    int carry;
  } cases[] = {
    {0x11, 0xffff, 0xabcd, 0x20, 0xabcd, 0x1234, 0x5678, 0},
    {0x10, 0x0fff, 0xabcd, 0x5003, 0xcd, 0x1234, 0x5678, 0},
    {0x10, 0x1200, 0xab10, 0x1200, 3, 1, 0x5678, 0},
    {0x67, 0xdeff, 0xabcd, 0x100, 0xabcd, 0x1234, 0x5678, 1},
    {0x1a, 0x00ff, 0xabcd, 0, 0xabcd, 0, 0, 0},
  };
  FILE *capture = tmpfile();
  assert(capture != NULL);
  int saved = dup(STDERR_FILENO);
  assert(saved >= 0 && dup2(fileno(capture), STDERR_FILENO) >= 0);
  for (int debug = 0; debug < 2; ++debug)
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
      for (int advanced = 0; advanced < 2; ++advanced) {
        context.engine.debug = debug;
        context.run = (DazeUnicornRunState){.interrupt_already_advanced = advanced};
        set_reg16(uc, UC_X86_REG_AX, cases[i].ax);
        set_reg16(uc, UC_X86_REG_BX, cases[i].bx);
        set_reg16(uc, UC_X86_REG_CX, 0x1234);
        set_reg16(uc, UC_X86_REG_DX, 0x5678);
        set_reg16(uc, UC_X86_REG_IP, 0x100);
        set_reg32(uc, UC_X86_REG_EFLAGS, 0x203);
        assert(daze_bios_dispatch(uc, cases[i].interrupt, &context.engine, &context.run));
        assert(get_reg16(uc, UC_X86_REG_AX) == cases[i].reply_ax);
        assert(get_reg16(uc, UC_X86_REG_BX) == cases[i].reply_bx);
        assert(get_reg16(uc, UC_X86_REG_CX) == cases[i].reply_cx);
        assert(get_reg16(uc, UC_X86_REG_DX) == cases[i].reply_dx);
        assert((get_reg32(uc, UC_X86_REG_EFLAGS) & 1) == (unsigned)cases[i].carry);
        assert(get_reg16(uc, UC_X86_REG_IP) == (advanced ? 0x100 : 0x102));
      }
  fflush(stderr);
  assert(dup2(saved, STDERR_FILENO) >= 0);
  close(saved);
  rewind(capture);
  char text[4096] = {0};
  assert(fread(text, 1, sizeof(text) - 1, capture) > 0);
  assert(strstr(text, "equipment word: 0020") != NULL);
  assert(strstr(text, "video mode: 80-column color text") != NULL);
  assert(strstr(text, "EGA capability: color, 256 KiB") != NULL);
  assert(strstr(text, "EMS not present") != NULL);
  assert(strstr(text, "timer ticks: 00000000") != NULL);
  fclose(capture);
  const uint8_t interrupts[] = {0x10, 0x10, 0x67, 0x1a, 0x15, 0xff};
  const uint16_t functions[] = {0x0000, 0x1200, 0xdd00, 0x0100, 0xc100, 0};
  for (size_t i = 0; i < sizeof(interrupts); ++i) {
    set_reg16(uc, UC_X86_REG_AX, functions[i]);
    set_reg16(uc, UC_X86_REG_BX, 0x11);
    set_reg16(uc, UC_X86_REG_IP, 0x100);
    context.run = (DazeUnicornRunState){0};
    assert(!daze_bios_dispatch(uc, interrupts[i], &context.engine, &context.run));
    assert(get_reg16(uc, UC_X86_REG_AX) == functions[i]);
    assert(get_reg16(uc, UC_X86_REG_BX) == 0x11 && get_reg16(uc, UC_X86_REG_IP) == 0x100);
    assert(!context.run.continue_run && !context.run.use_resume_address);
  }
  uc_close(uc);
}

static void configuration(void) {
  for (int kind = 0; kind < 3; ++kind) {
    uc_engine *uc = fixture();
    DazeUnicornContext context = {0};
    uint8_t bytes[8];
    const uint16_t selectors[] = {8, 0x10, 0x18, 0x28};
    const uint32_t bases[] = {0x10000, 0x10100, 0x30000, 0x2000};
    for (size_t i = 0; i < 4; ++i) {
      daze_dpmi_descriptor_encode(bytes, bases[i], 0xffff, i == 0 || i == 3 ? 0x9a : 0x92, 0);
      assert(uc_mem_write(uc, k_dpmi_gdt_address + selectors[i], bytes, 8) == UC_ERR_OK);
    }
    uc_x86_mmr gdtr = {.base = k_dpmi_gdt_address, .limit = 0x2f};
    assert(uc_reg_write(uc, UC_X86_REG_GDTR, &gdtr) == UC_ERR_OK);
    set_reg32(uc, UC_X86_REG_CR0, 1);
    set_reg16(uc, UC_X86_REG_CS, 8);
    set_reg16(uc, UC_X86_REG_SS, 0x18);
    set_reg16(uc, UC_X86_REG_SP, 0x800);
    set_reg16(uc, UC_X86_REG_IP, 0x100);
    set_reg16(uc, UC_X86_REG_AX, 0xc000);
    set_reg16(uc, UC_X86_REG_BX, 0x1234);
    set_reg32(uc, UC_X86_REG_EFLAGS, 0x203);
    if (kind == 1) assert(uc_mem_unmap(uc, 0x1f000, 0x1000) == UC_ERR_OK);
    if (kind == 2) assert(uc_mem_unmap(uc, 0x2000, 0x1000) == UC_ERR_OK);
    assert(daze_bios_dispatch(uc, 0x15, &context.engine, &context.run) == (kind == 0));
    if (kind != 0) {
      assert(get_reg16(uc, UC_X86_REG_CS) == 8 && get_reg16(uc, UC_X86_REG_IP) == 0x100);
      assert(!context.run.use_resume_address);
      if (kind == 1) assert(get_reg16(uc, UC_X86_REG_BX) == 0x1234);
    } else {
      uint8_t table[8];
      const uint8_t expected[8] = {8, 0, 0, 0, 0, 2, 0, 0};
      assert(uc_mem_read(uc, k_bios_config_table, table, 8) == UC_ERR_OK);
      assert(memcmp(table, expected, 8) == 0);
      assert(context.run.resume_address == 0x3c0 && context.run.use_resume_address);
      const uint8_t code[] = {0x26, 0x8a, 0x57, 0x05, /* mov dl,es:[bx+5] */
                              0xf4};                  /* hlt */
      assert(uc_mem_write(uc, 0x10102, code, sizeof(code)) == UC_ERR_OK);
      assert(uc_emu_start(uc, context.run.resume_address, 0, 0, 20) == UC_ERR_OK);
      assert(get_reg16(uc, UC_X86_REG_ES) == 0x10);
      assert(get_reg16(uc, UC_X86_REG_AX) == 0xc000);
      assert(get_reg16(uc, UC_X86_REG_SP) == 0x800);
      assert((get_reg16(uc, UC_X86_REG_DX) & 0xff) == 2);
      assert(!(get_reg32(uc, UC_X86_REG_EFLAGS) & 1));
    }
    uc_close(uc);
  }
}

static void image_wrapper(void) {
  assert(!daze_unicorn_image_write_process(NULL, "", "TEST.EXE", k_psp_segment,
                                           k_environment_segment, k_dpmi_entry_segment,
                                           k_dos_int21_vector_segment, NULL, 0));
  uc_engine *uc;
  assert(uc_open(UC_ARCH_X86, UC_MODE_16, &uc) == UC_ERR_OK);
  assert(!daze_unicorn_image_write_process(uc, "", "TEST.EXE", k_psp_segment, k_environment_segment,
                                           k_dpmi_entry_segment, k_dos_int21_vector_segment, NULL,
                                           0));
  assert(uc_mem_map(uc, 0, k_memory_size, UC_PROT_ALL) == UC_ERR_OK);
  const char *env[] = {"TEST=value"};
  assert(daze_unicorn_image_write_process(uc, " abc", "TEST.EXE", k_psp_segment,
                                          k_environment_segment, k_dpmi_entry_segment,
                                          k_dos_int21_vector_segment, env, 1));
  uint8_t psp[256];
  assert(uc_mem_read(uc, (uint32_t)k_psp_segment << 4, psp, sizeof(psp)) == UC_ERR_OK);
  assert(psp[0] == 0xcd && psp[1] == 0x20);
  assert(daze_read_u16(psp + 0x2c) == k_environment_segment);
  assert(psp[0x80] == 4 && memcmp(psp + 0x81, " abc\r", 5) == 0);
  uc_close(uc);
}

int main(void) {
  probes();
  configuration();
  image_wrapper();
  return 0;
}
