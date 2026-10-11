#include "bios_adapter.h"
#include "timer.h"

#include <stdarg.h>
#include <stdio.h>

#include "interrupt_vector.h"

static void bios_debug(const DazeUnicornEngine *engine, const char *format, ...) {
  if (!engine->debug) return;
  va_list args;
  va_start(args, format);
  vfprintf(stderr, format, args);
  va_end(args);
}

int daze_bios_dispatch(uc_engine *uc, uint8_t interrupt, const DazeUnicornEngine *engine,
                       DazeUnicornRunState *run) {
  if (interrupt == DAZE_INT_BIOS_EQUIPMENT) {
    /* Equipment-list probe: bits 4-5 identify 80x25 color text. Leave all
     * peripheral bits clear; this is a compatibility identity, not hardware
     * emulation. */
    bios_debug(engine, "  BIOS 11h equipment word: 0020 (80-column color text)\n");
    set_reg16(uc, UC_X86_REG_AX, 0x0020);
    set_carry(uc, 0);
    skip_interrupt_instruction(uc, run);
    return 1;
  }
  if (interrupt == DAZE_INT_BIOS_VIDEO && (get_reg16(uc, UC_X86_REG_AX) >> 8) == 0x0f) {
    /* Current video mode query. A fixed 80-column color text identity is
     * enough for command-line tools which probe display capabilities; Daze
     * still exposes no framebuffer or mode-setting surface. */
    bios_debug(engine, "  BIOS 10h/0Fh video mode: 80-column color text\n");
    set_reg16(uc, UC_X86_REG_AX, 0x5003); // AH=columns, AL=mode 3.
    set_reg16(uc, UC_X86_REG_BX, (uint16_t)(get_reg16(uc, UC_X86_REG_BX) & 0x00ffu));
    set_carry(uc, 0);
    skip_interrupt_instruction(uc, run);
    return 1;
  }
  if (interrupt == DAZE_INT_BIOS_VIDEO && get_reg16(uc, UC_X86_REG_AX) == 0x1200 &&
      (get_reg16(uc, UC_X86_REG_BX) & 0x00ffu) == 0x10) {
    /* EGA/VGA capability query, not a graphics operation. Report a minimal
     * color EGA-compatible adapter with 256 KiB and nonzero configuration
     * bits so probing DOS extenders select their non-CGA path. No VGA memory,
     * modes, palette, or display device is emulated. */
    bios_debug(engine, "  BIOS 10h/12h/10h EGA capability: color, 256 KiB\n");
    set_reg16(uc, UC_X86_REG_BX, 0x0003);
    set_reg16(uc, UC_X86_REG_CX, 0x0001);
    set_carry(uc, 0);
    skip_interrupt_instruction(uc, run);
    return 1;
  }
  if (interrupt == 0x67 && (get_reg16(uc, UC_X86_REG_AX) >> 8) == 0xde) {
    bios_debug(engine, "  EMS probe (INT 67h/DEh): EMS not present\n");
    set_reg16(uc, UC_X86_REG_AX, 0x0100);
    skip_interrupt_instruction(uc, run);
    return 1;
  }
  if (interrupt == DAZE_INT_BIOS_TIME && (get_reg16(uc, UC_X86_REG_AX) >> 8) == 0x00) {
    DazeBiosTimerTick reply;
    if (!daze_bios_timer_ticks(&reply)) return 0;
    bios_debug(engine, "  BIOS 1Ah/00h timer ticks: %04x%04x\n", reply.cx, reply.dx);
    set_reg16(uc, UC_X86_REG_CX, reply.cx);
    set_reg16(uc, UC_X86_REG_DX, reply.dx);
    set_reg16(uc, UC_X86_REG_AX, reply.ax);
    set_carry(uc, reply.carry);
    skip_interrupt_instruction(uc, run);
    return 1;
  }
  if (interrupt == 0x15 && (get_reg16(uc, UC_X86_REG_AX) >> 8) == 0xc0) {
    /* AT-style configuration table. The DPMI client observes feature byte 5
     * and takes the supported path when bit 1 is set; all other machine
     * detail remains deliberately unspecified. */
    const uint8_t configuration[] = {8, 0, 0, 0, 0, 2, 0, 0};
    if (uc_mem_write(uc, k_bios_config_table, configuration, sizeof(configuration)) != UC_ERR_OK) {
      return 0;
    }
    uint8_t feature = 0;
    if (uc_mem_read(uc, k_bios_config_table + 5, &feature, sizeof(feature)) != UC_ERR_OK) return 0;
    bios_debug(engine, "  BIOS 15h/C0h configuration query: table 0010:f000 feature=%02x\n",
               feature);
    set_reg16(uc, UC_X86_REG_BX, 0xf000);
    set_carry(uc, 0);
    /* Unicorn can retain a hidden real-mode segment cache after a host ES
     * update. Reload ES through guest instructions before returning. */
    const uint16_t return_ip = (uint16_t)(get_reg16(uc, UC_X86_REG_IP) + 2);
    // clang-format off
    const uint8_t reload_es[] = {
      0x50,                   /* push ax */
      0xb8, 0x10, 0x00,       /* mov ax,0x10 */
      0x8e, 0xc0,             /* mov es,ax */
      0x58,                   /* pop ax */
      0xea, (uint8_t)return_ip, (uint8_t)(return_ip >> 8),
      0x08, 0x00,             /* jmp far 0x08:return_ip */
    };
    // clang-format on
    /* The BIOS reload stub shares the DPMI trampoline reservation. */
    _Static_assert(sizeof(reload_es) <= k_dpmi_rm_trampoline_max_size,
                   "BIOS reload stub exceeds the trampoline scratch span");
    if (uc_mem_write(uc, 0x2140, reload_es, sizeof(reload_es)) != UC_ERR_OK ||
        uc_ctl_flush_tb(uc) != UC_ERR_OK) {
      return 0;
    }
    set_reg16(uc, UC_X86_REG_CS, 0x0028);
    set_reg16(uc, UC_X86_REG_IP, 0x0140);
    run->resume_address = 0x0280 + 0x0140;
    run->use_resume_address = 1;
    return 1;
  }
  return 0;
}
