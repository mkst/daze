#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dpmi_process_state.h"
#include "byte_order.h"
#include "descriptor.h"
#include "exec_image.h"
#include "exec_loader.h"
#include "exec_psp.h"
#include "exec_request.h"
#include "image.h"
#include "interrupt_vector.h"
#include "mz_layout.h"
#include "rm_frame.h"
#include "unicorn_services.h"
#include "transition_artifacts.h"
#include "dpmi_function.h"
#include "selector.h"

static int write_exec_psp(uc_engine *uc, uint16_t psp_segment, uint16_t parent_psp_segment,
                          uint16_t environment_segment, const uint8_t tail[127],
                          const uint8_t fcb1[16], const uint8_t fcb2[16]) {
  uint8_t psp[DAZE_DOS_EXEC_PSP_SIZE];
  if (!daze_dos_exec_psp_build(psp_segment, parent_psp_segment, environment_segment,
                               k_dos_int21_vector_segment, tail, fcb1, fcb2, psp))
    return 0;
  return uc_mem_write(uc, (uint32_t)psp_segment << 4, psp, sizeof(psp)) == UC_ERR_OK;
}

int daze_setup_start_exec_child(uc_engine *uc, DazeUnicornEngine *engine, DazeUnicornRunState *run,
                                DazeDosRuntimeProcessState *process, DazeDosfsFileService *files,
                                char *diagnostic, size_t diagnostic_size) {
  const uint16_t ds = get_reg16(uc, UC_X86_REG_DS);
  const uint16_t dx = get_reg16(uc, UC_X86_REG_DX);
  const uint16_t es = get_reg16(uc, UC_X86_REG_ES);
  const uint16_t bx = get_reg16(uc, UC_X86_REG_BX);
  uint32_t cr0 = get_reg32(uc, UC_X86_REG_CR0);
  char path[128];
  uint8_t parameter[14];
  uint8_t tail[127];
  uint8_t fcb1[16];
  uint8_t fcb2[16];
  DazeDosExecRequest exec_request;
  DazeImage image = {0};
  int host_errno = 0;
  if ((cr0 & 1u) != 0 || !daze_read_guest_asciiz(uc, ds, dx, path, sizeof(path)) ||
      !daze_read_guest_bytes(uc, es, bx, parameter, sizeof(parameter)) ||
      !daze_read_guest_bytes(uc, daze_read_u16(parameter + 4), daze_read_u16(parameter + 2), tail,
                             sizeof(tail)) ||
      !daze_read_guest_bytes(uc, daze_read_u16(parameter + 8), daze_read_u16(parameter + 6), fcb1,
                             sizeof(fcb1)) ||
      !daze_read_guest_bytes(uc, daze_read_u16(parameter + 12), daze_read_u16(parameter + 10), fcb2,
                             sizeof(fcb2)) ||
      !daze_dos_exec_request_decode((uint8_t)get_reg16(uc, UC_X86_REG_AX),
                                    process->child_process.active, parameter, tail,
                                    &exec_request)) {
    snprintf(diagnostic, diagnostic_size, "invalid EXEC request");
    return 0;
  }
  if (getenv("DAZE_EXEC_TRACE") != NULL) {
    fprintf(stderr, "exec: request ds:dx=%04x:%04x es:bx=%04x:%04x path=%s parameter", ds, dx, es,
            bx, path);
    for (size_t index = 0; index < sizeof(parameter); ++index)
      fprintf(stderr, " %02x", parameter[index]);
    fprintf(stderr, " tail");
    for (size_t index = 0; index <= tail[0]; ++index)
      fprintf(stderr, " %02x", tail[index]);
    fprintf(stderr, " fcb1");
    for (size_t index = 0; index < sizeof(fcb1); ++index)
      fprintf(stderr, " %02x", fcb1[index]);
    fprintf(stderr, " fcb2");
    for (size_t index = 0; index < sizeof(fcb2); ++index)
      fprintf(stderr, " %02x", fcb2[index]);
    fputc('\n', stderr);
  }
  if (!daze_dos_exec_load_mounted(files->mounts, path, &image, &host_errno)) {
    snprintf(diagnostic, diagnostic_size, "%s (DOS error %u)", path,
             daze_dosfs_errno_to_dos_error(host_errno));
    return 0;
  }
  DazeMzHeader header;
  if (!daze_mz_parse_header(image.bytes, image.size, &header)) {
    snprintf(diagnostic, diagnostic_size, "%s is not a supported MZ child", path);
    daze_image_free(&image);
    return 0;
  }
  const size_t image_size = header.image_size;
  const size_t paragraphs_needed = 0x10u + (image_size + 15u) / 16u;
  if (paragraphs_needed > UINT16_MAX) {
    snprintf(diagnostic, diagnostic_size, "%s is not a supported MZ child", path);
    daze_image_free(&image);
    return 0;
  }
  const DazeDosMemory parent_memory = process->dos_memory;
  DazeDosAllocation *allocation =
    daze_dos_memory_allocate(&process->dos_memory, (uint16_t)paragraphs_needed);
  if (allocation == NULL) {
    snprintf(diagnostic, diagnostic_size, "%s needs %zu paragraphs", path, paragraphs_needed);
    daze_image_free(&image);
    return 0;
  }
  const uint16_t psp_segment = allocation->segment;
  const uint16_t load_segment = (uint16_t)(psp_segment + 0x10);
  const uint32_t image_address = (uint32_t)load_segment << 4;
  uint8_t *prepared_image = NULL;
  size_t prepared_image_size = 0;
  /* Each EXEC child negotiates DPMI anew; a client trampoline carries its own
   * selectors and far-return target. */
  const uint8_t dpmi_entry[] = {0xcd, DAZE_INT_DPMI_ENTRY, 0xf4};
  const uint32_t dpmi_entry_address = (uint32_t)k_dpmi_entry_segment << 4;
  if (!daze_dos_exec_image_prepare(&image, &header, load_segment, k_memory_size, &prepared_image,
                                   &prepared_image_size) ||
      !write_exec_psp(uc, psp_segment, process->dos_process.psp_segment,
                      exec_request.environment_segment, tail, fcb1, fcb2) ||
      uc_mem_write(uc, image_address, prepared_image, prepared_image_size) != UC_ERR_OK ||
      uc_mem_write(uc, dpmi_entry_address, dpmi_entry, sizeof(dpmi_entry)) != UC_ERR_OK ||
      !daze_invalidate_translation_cache(uc, &engine->metrics, dpmi_entry_address,
                                         dpmi_entry_address + sizeof(dpmi_entry))) {
    free(prepared_image);
    process->dos_memory = parent_memory;
    daze_image_free(&image);
    snprintf(diagnostic, diagnostic_size, "%s cannot be placed in guest memory", path);
    return 0;
  }
  free(prepared_image);
  if (uc_context_alloc(uc, &process->child_process.parent_context) != UC_ERR_OK ||
      uc_context_save(uc, process->child_process.parent_context) != UC_ERR_OK) {
    if (process->child_process.parent_context != NULL) {
      uc_context_free(process->child_process.parent_context);
      process->child_process.parent_context = NULL;
    }
    process->dos_memory = parent_memory;
    daze_image_free(&image);
    snprintf(diagnostic, diagnostic_size, "cannot save EXEC parent context");
    return 0;
  }
  daze_image_free(&image);
  if (daze_dosfs_exec_handles_begin(&process->child_process.handles, files->handles, &host_errno) !=
      DAZE_DOSFS_OK) {
    uc_context_free(process->child_process.parent_context);
    process->child_process.parent_context = NULL;
    process->dos_memory = parent_memory;
    snprintf(diagnostic, diagnostic_size, "cannot inherit EXEC file handles (host error %d)",
             host_errno);
    return 0;
  }
  process->child_process.psp_segment = psp_segment;
  process->child_process.allocation_segment = allocation->segment;
  process->child_process.parent_psp_segment = process->dos_process.psp_segment;
  process->child_process.parent_dta_segment = process->dos_process.dta_segment;
  process->child_process.parent_dta_offset = process->dos_process.dta_offset;
  process->child_process.parent_resident_image_end = process->resident_image_end;
  process->child_process.parent_memory = parent_memory;
  process->resident_image_end = image_address + (uint32_t)image_size;
  process->child_process.active = 1;
  process->child_process.status_available = 0;
  process->child_process.termination_type = 0;
  uint32_t flags = 0x00000202;
  set_reg16(uc, UC_X86_REG_CS, (uint16_t)(load_segment + header.initial_cs));
  set_reg16(uc, UC_X86_REG_IP, header.initial_ip);
  set_reg16(uc, UC_X86_REG_SS, (uint16_t)(load_segment + header.initial_ss));
  set_reg16(uc, UC_X86_REG_SP, header.initial_sp);
  set_reg16(uc, UC_X86_REG_DS, psp_segment);
  set_reg16(uc, UC_X86_REG_ES, psp_segment);
  set_reg16(uc, UC_X86_REG_FS, 0);
  set_reg16(uc, UC_X86_REG_GS, 0);
  uc_reg_write(uc, UC_X86_REG_EFLAGS, &flags);
  daze_dos_process_state_reinit_for_exec(&process->dos_process, psp_segment);
  run->resume_address = ((uint32_t)(load_segment + header.initial_cs) << 4) + header.initial_ip;
  run->use_resume_address = 1;
  daze_trace_debug(engine, "  DOS 21h/4B00h EXEC: %s -> PSP %04x, entry %04x:%04x\n", path,
                   psp_segment, (uint16_t)(load_segment + header.initial_cs), header.initial_ip);
  return 1;
}

int daze_setup_prepare_dpmi_transition(uc_engine *uc, DazeUnicornEngine *engine,
                                       DazeDosRuntimeProcessState *process) {
  enum {
    k_gdt_address = k_dpmi_gdt_address,
    k_gdtr_offset = 0x0080,
    k_ldt_address = k_dpmi_ldt_address,
  };
  const uint16_t ax = get_reg16(uc, UC_X86_REG_AX);
  const uint16_t ds = get_reg16(uc, UC_X86_REG_DS);
  const uint16_t ss = get_reg16(uc, UC_X86_REG_SS);
  const uint16_t sp = get_reg16(uc, UC_X86_REG_SP);
  uint16_t return_ip = 0;
  uint16_t return_cs = 0;
  uint8_t environment[2];
  const uint32_t environment_pointer = ((uint32_t)process->dos_process.psp_segment << 4) + 0x2c;
  /* DPMI 0305h's protected-mode procedure saves the state that was parked
   * when the client entered DPMI. Keep a host-owned copy from that point,
   * rather than treating the client buffer as a live register frame. */
  DpmiAlternateState snapshot;
  daze_dpmi_capture_state(uc, &snapshot);
  /* DPMI 0.9 admits AX=0 for a 16-bit client and AX=1 for a 32-bit
   * client. The common entry trampoline begins with the 16-bit extender
   * setup in either case; clients create wider descriptors later if needed. */
  if (ax > 1 ||
      uc_mem_read(uc, ((uint32_t)ss << 4) + sp, &return_ip, sizeof(return_ip)) != UC_ERR_OK ||
      uc_mem_read(uc, ((uint32_t)ss << 4) + sp + 2, &return_cs, sizeof(return_cs)) != UC_ERR_OK ||
      uc_mem_read(uc, environment_pointer, environment, sizeof(environment)) != UC_ERR_OK) {
    return 0;
  }

  DazeDpmiTransitionArtifacts artifacts;
  const uint16_t environment_segment = daze_read_u16(environment);
  const DazeDpmiTransitionDescriptorAddition additions[] = {
    {DAZE_DPMI_TRANSITION_GDT, DAZE_SEL_GDT_DESC, 0x0500, 7, 0x92, 0x00},
    {DAZE_DPMI_TRANSITION_GDT, k_dpmi_exception_locked_stack_selector,
     k_dpmi_exception_locked_stack_base, k_dpmi_exception_locked_stack_limit, 0x92, 0x00},
    {DAZE_DPMI_TRANSITION_GDT, k_dos_int21_vector_segment,
     (uint32_t)k_dos_int21_vector_segment << 4, 0xffff, 0x9a, 0x00},
    {DAZE_DPMI_TRANSITION_GDT, (uint16_t)(ds & (uint16_t)~7u), (uint32_t)ds << 4, 0xffff, 0xf2,
     0x00},
    {DAZE_DPMI_TRANSITION_GDT, (uint16_t)(ss & (uint16_t)~7u), (uint32_t)ss << 4, 0xffff, 0xf2,
     0x00},
    {DAZE_DPMI_TRANSITION_GDT, (uint16_t)(return_cs & (uint16_t)~7u), (uint32_t)return_cs << 4,
     0xffff, 0xf2, 0x00},
    /* BCC 3.1's loader runs its client in raw mode: it reloads DS with the
     * client's real-mode segment value as a protected LDT selector (e.g.
     * 1485h, whose natural bit 2 selects the LDT).  Mirror the client data
     * descriptor in the LDT at the same index so that exact-value reload
     * resolves; the GDT twin keeps selector `ds & ~7` for other fixtures. */
    {DAZE_DPMI_TRANSITION_LDT, (uint16_t)(ds & (uint16_t)~7u), (uint32_t)ds << 4, 0xffff, 0xf2,
     0x00},
    {DAZE_DPMI_TRANSITION_GDT, 0x1010, 0x10100, 0xffff, 0x92, 0x00},
    {DAZE_DPMI_TRANSITION_GDT, 0x0ff0, 0x0ff00, 0xffff, 0xf2, 0x00},
    {DAZE_DPMI_TRANSITION_LDT, DAZE_SEL_LDT, 0x00000, 0xffff, 0xf2, 0x00},
    {DAZE_DPMI_TRANSITION_LDT, 0x2e68, 0x2e6c0, 0xffff, 0xf2, 0x00},
    {DAZE_DPMI_TRANSITION_LDT, 0xfff8, 0xffff0, 0xffff, 0xf2, 0x00},
  };
  if (!daze_dpmi_transition_artifacts_build(
        &(DazeDpmiTransitionArtifactInput){.client_ds = ds,
                                           .client_ss = ss,
                                           .return_ip = return_ip,
                                           .return_cs = return_cs,
                                           .psp_segment = process->dos_process.psp_segment,
                                           .environment_segment = environment_segment,
                                           .convert_environment = 1,
                                           .entry_segment = k_dpmi_entry_segment,
                                           .gdt_address = k_gdt_address,
                                           .ldt_address = k_ldt_address,
                                           .additions = additions,
                                           .addition_count =
                                             sizeof(additions) / sizeof(additions[0])},
        &artifacts))
    return 0;
  const uint32_t trampoline_address = (uint32_t)k_dpmi_entry_segment << 4;
  if (uc_mem_write(uc, k_gdt_address, artifacts.gdt, sizeof(artifacts.gdt)) != UC_ERR_OK ||
      uc_mem_write(uc, k_ldt_address, artifacts.ldt, sizeof(artifacts.ldt)) != UC_ERR_OK ||
      uc_mem_write(uc, trampoline_address, artifacts.trampoline, sizeof(artifacts.trampoline)) !=
        UC_ERR_OK ||
      uc_mem_write(uc, trampoline_address + 0x0100, artifacts.state_stub,
                   sizeof(artifacts.state_stub)) != UC_ERR_OK ||
      uc_mem_write(uc, trampoline_address + 0x0120, artifacts.raw_switch_stub,
                   sizeof(artifacts.raw_switch_stub)) != UC_ERR_OK ||
      uc_mem_write(uc, trampoline_address + k_gdtr_offset, artifacts.gdtr,
                   sizeof(artifacts.gdtr)) != UC_ERR_OK ||
      uc_mem_write(uc, environment_pointer, artifacts.environment_pointer,
                   sizeof(artifacts.environment_pointer)) != UC_ERR_OK ||
      !daze_flush_translation_cache(uc, &engine->metrics)) {
    return 0;
  }
  set_carry(uc, 0);
  if (!daze_dpmi_process_state_init(&process->dpmi, process->resident_image_end, ds, return_cs,
                                    &snapshot, k_dpmi_linear_min_address,
                                    k_dpmi_linear_arena_limit)) {
    fprintf(stderr,
            "  DPMI transition rejected at DPMI transition: no linear arena after resident image "
            "end %08" PRIx32 " (limit %08x)\n",
            process->resident_image_end, k_dpmi_linear_arena_limit);
    return 0;
  }
  daze_trace_debug(engine, "  DPMI transition prepared: client CS=%04x IP=%04x DS:SS=%04x:%04x\n",
                   return_cs, return_ip, ds, ss);
  return 1;
}

/* Guest MOV SS and a far jump reload Unicorn's locked-stack hidden base;
 * host segment writes do not. CS-relative scratch preserves AX without using
 * client DS or writable client memory. The handler target remains a far pointer;
 * gateway writes use its descriptor base plus offset.
 * Unicorn 2.1.4 can re-enter one byte late after MOV SS. Keep the filler after
 * each instruction: this encoding also settles the stack cache before the jump. */
int daze_setup_write_exception_gateway(uc_engine *uc, DazeMetrics *metrics,
                                       uint16_t handler_segment, uint16_t handler_offset,
                                       uint16_t locked_stack_sp, uint32_t *gateway_linear) {
  uint8_t route[30];
  size_t index = 0;
  route[index++] = 0xfa; /* cli */
  route[index++] = 0x90;
  /* Unicorn 2.1.4 mis-decodes the absolute 16-bit cell form. Use DI-relative cells
   * without modifying the client's DI. */
  route[index++] = 0x2e; /* mov cs:[saved_ax], ax */
  route[index++] = 0x89;
  route[index++] = 0x06;
  daze_write_u16(route + index, k_dpmi_exception_saved_ax_offset);
  index += 2;
  route[index++] = 0x90;
  route[index++] = 0xb8; /* mov ax, locked stack selector */
  daze_write_u16(route + index, k_dpmi_exception_locked_stack_selector);
  index += 2;
  route[index++] = 0x90;
  route[index++] = 0x8e; /* mov ss, ax */
  route[index++] = 0xd0;
  route[index++] = 0x90;
  route[index++] = 0xbc; /* mov sp, locked stack sp */
  daze_write_u16(route + index, locked_stack_sp);
  index += 2;
  route[index++] = 0x90;
  route[index++] = 0x2e; /* mov ax, cs:[saved_ax] */
  route[index++] = 0x8b;
  route[index++] = 0x06;
  daze_write_u16(route + index, k_dpmi_exception_saved_ax_offset);
  index += 2;
  route[index++] = 0x90;
  route[index++] = 0x2e; /* jmp far cs:[installed handler] */
  route[index++] = 0xff;
  route[index++] = 0x2e;
  daze_write_u16(route + index, k_dpmi_exception_handler_pointer_offset);
  index += 2;
  if (index != sizeof(route)) return 0;
  uint32_t base = 0;
  if (!daze_dpmi_selector_base(uc, k_dpmi_exception_gateway_selector, &base)) return 0;
  const uint32_t linear = base + k_dpmi_exception_gateway_offset;
  uint8_t pointer[4];
  daze_write_u16(pointer, handler_offset);
  daze_write_u16(pointer + 2, handler_segment);
  if (uc_mem_write(uc, linear, route, sizeof(route)) != UC_ERR_OK ||
      uc_mem_write(uc, base + k_dpmi_exception_handler_pointer_offset, pointer, sizeof(pointer)) !=
        UC_ERR_OK ||
      !daze_invalidate_translation_cache(uc, metrics, linear,
                                         linear + k_dpmi_exception_gateway_span)) {
    return 0;
  }
  if (gateway_linear != NULL) *gateway_linear = linear;
  return 1;
}

/* Host segment writes can leave Unicorn's real-mode hidden bases cached.
 * Guest MOV Sreg and a far JMP reload them before returning to the client. */
int daze_setup_write_raw_pm_reentry_wrapper(uc_engine *uc, DazeUnicornRunState *run,
                                            DazeMetrics *metrics, uint16_t ds, uint16_t es,
                                            uint16_t ss, uint16_t sp, uint16_t fs, uint16_t gs,
                                            uint16_t ax, uint16_t bx, uint16_t cx, uint16_t dx,
                                            uint16_t si, uint16_t di, uint16_t bp, uint16_t flags,
                                            uint16_t target_ip, uint16_t target_cs) {
  const uint8_t wrapper[] = {
    0x2e, 0xa1, 0x00, 0x02,       // mov ax, cs:[0200] (DS)
    0x8e, 0xd8,                   // mov ds, ax
    0x2e, 0xa1, 0x02, 0x02,       // mov ax, cs:[0202] (ES)
    0x8e, 0xc0,                   // mov es, ax
    0x2e, 0xa1, 0x04, 0x02,       // mov ax, cs:[0204] (SS)
    0x8e, 0xd0,                   // mov ss, ax
    0x2e, 0x8b, 0x26, 0x06, 0x02, // mov sp, cs:[0206]
    0x66, 0x0f, 0xb7, 0xe4,       // movzx esp, sp (client SS is 32-bit)
    0x2e, 0xa1, 0x08, 0x02,       // mov ax, cs:[0208] (FS)
    0x8e, 0xe0,                   // mov fs, ax
    0x2e, 0xa1, 0x0a, 0x02,       // mov ax, cs:[020a] (GS)
    0x8e, 0xe8,                   // mov gs, ax
    0x2e, 0xa1, 0x0c, 0x02,       // mov ax, cs:[020c]
    0x2e, 0x8b, 0x1e, 0x0e, 0x02, // mov bx, cs:[020e]
    0x2e, 0x8b, 0x0e, 0x10, 0x02, // mov cx, cs:[0210]
    0x2e, 0x8b, 0x16, 0x12, 0x02, // mov dx, cs:[0212]
    0x2e, 0x8b, 0x36, 0x14, 0x02, // mov si, cs:[0214]
    0x2e, 0x8b, 0x3e, 0x16, 0x02, // mov di, cs:[0216]
    0x2e, 0x8b, 0x2e, 0x18, 0x02, // mov bp, cs:[0218]
    0x2e, 0xff, 0x36, 0x1a, 0x02, // push word cs:[021a] (FLAGS)
    0x9d,                         // popf
    0x2e, 0xff, 0x2e, 0x1c, 0x02, // jmp far cs:[021c] (IP:CS)
  };
  const uint16_t state[] = {
    ds, es, ss, sp, fs, gs, ax, bx, cx, dx, si, di, bp, flags, target_ip, target_cs,
  };
  _Static_assert(sizeof(wrapper) == k_pm_reentry_wrapper_size,
                 "16-bit re-entry wrapper exceeds its reserved span");
  _Static_assert(sizeof(state) == k_pm_reentry_state_size,
                 "16-bit re-entry state exceeds its reserved span");
  /* The wrapper instructions are invariant.  Its separate state block is
   * read by normal guest loads, so changing it does not require a code-cache
   * invalidation after the one-time wrapper installation. */
  if (!run->raw_pm_wrapper_written) {
    if (uc_mem_write(uc, k_pm_reentry_wrapper, wrapper, sizeof(wrapper)) != UC_ERR_OK ||
        !daze_invalidate_translation_cache(uc, metrics, k_pm_reentry_wrapper,
                                           k_pm_reentry_wrapper + sizeof(wrapper))) {
      return 0;
    }
    run->raw_pm_wrapper_written = 1;
  }
  return uc_mem_write(uc, k_pm_reentry_state, state, sizeof(state)) == UC_ERR_OK;
}

/* Enter through host selector 0020h (D=1) to restore full-width EIP, ESP, and
 * GPRs. Guest instructions reload segment caches before the return far jump. */
int daze_setup_write_raw_pm_reentry32_wrapper(uc_engine *uc, DazeUnicornRunState *run,
                                              DazeMetrics *metrics, uint16_t ds, uint16_t es,
                                              uint16_t ss, uint16_t fs, uint16_t gs, uint32_t eax,
                                              uint32_t ebx, uint32_t ecx, uint32_t edx,
                                              uint32_t esi, uint32_t edi, uint32_t ebp,
                                              uint32_t esp, uint32_t eflags, uint32_t target_eip,
                                              uint16_t target_cs) {
  enum {
    k_state_ds = 0x00,
    k_state_es = 0x02,
    k_state_ss = 0x04,
    k_state_fs = 0x06,
    k_state_gs = 0x08,
    k_state_eax = 0x0c,
    k_state_ebx = 0x10,
    k_state_ecx = 0x14,
    k_state_edx = 0x18,
    k_state_esi = 0x1c,
    k_state_edi = 0x20,
    k_state_ebp = 0x24,
    k_state_esp = 0x28,
    k_state_eflags = 0x2c,
    k_state_eip = 0x30,
    k_state_cs = 0x34,
  };
  const uint8_t wrapper[] = {
    0x2e, 0x66, 0xa1, 0xc0, 0x02, 0x00, 0x00, // mov ax, cs:[000002c0] (DS)
    0x8e, 0xd8,                               // mov ds, ax
    0x2e, 0x66, 0xa1, 0xc2, 0x02, 0x00, 0x00, // mov ax, cs:[000002c2] (ES)
    0x8e, 0xc0,                               // mov es, ax
    0x2e, 0x66, 0xa1, 0xc4, 0x02, 0x00, 0x00, // mov ax, cs:[000002c4] (SS)
    0x8e, 0xd0,                               // mov ss, ax
    0x2e, 0x8b, 0x25, 0xe8, 0x02, 0x00, 0x00, // mov esp, cs:[000002e8]
    0x2e, 0x66, 0xa1, 0xc6, 0x02, 0x00, 0x00, // mov ax, cs:[000002c6] (FS)
    0x8e, 0xe0,                               // mov fs, ax
    0x2e, 0x66, 0xa1, 0xc8, 0x02, 0x00, 0x00, // mov ax, cs:[000002c8] (GS)
    0x8e, 0xe8,                               // mov gs, ax
    0x2e, 0x8b, 0x1d, 0xd0, 0x02, 0x00, 0x00, // mov ebx, cs:[000002d0]
    0x2e, 0x8b, 0x0d, 0xd4, 0x02, 0x00, 0x00, // mov ecx, cs:[000002d4]
    0x2e, 0x8b, 0x15, 0xd8, 0x02, 0x00, 0x00, // mov edx, cs:[000002d8]
    0x2e, 0x8b, 0x35, 0xdc, 0x02, 0x00, 0x00, // mov esi, cs:[000002dc]
    0x2e, 0x8b, 0x3d, 0xe0, 0x02, 0x00, 0x00, // mov edi, cs:[000002e0]
    0x2e, 0x8b, 0x2d, 0xe4, 0x02, 0x00, 0x00, // mov ebp, cs:[000002e4]
    0x2e, 0xff, 0x35, 0xec, 0x02, 0x00, 0x00, // push dword cs:[000002ec] (EFLAGS)
    0x9d,                                     // popfd
    0x2e, 0xa1, 0xcc, 0x02, 0x00, 0x00,       // mov eax, cs:[000002cc]
    0x2e, 0xff, 0x2d, 0xf0, 0x02, 0x00, 0x00, // jmp far cs:[000002f0] (EIP:CS)
  };
  uint8_t state[0x36] = {0};
  daze_write_u16(state + k_state_ds, ds);
  daze_write_u16(state + k_state_es, es);
  daze_write_u16(state + k_state_ss, ss);
  daze_write_u16(state + k_state_fs, fs);
  daze_write_u16(state + k_state_gs, gs);
  daze_write_u32(state + k_state_eax, eax);
  daze_write_u32(state + k_state_ebx, ebx);
  daze_write_u32(state + k_state_ecx, ecx);
  daze_write_u32(state + k_state_edx, edx);
  daze_write_u32(state + k_state_esi, esi);
  daze_write_u32(state + k_state_edi, edi);
  daze_write_u32(state + k_state_ebp, ebp);
  daze_write_u32(state + k_state_esp, esp);
  daze_write_u32(state + k_state_eflags, eflags);
  daze_write_u32(state + k_state_eip, target_eip);
  daze_write_u16(state + k_state_cs, target_cs);
  _Static_assert(sizeof(wrapper) == k_pm_reentry32_wrapper_size,
                 "32-bit re-entry wrapper exceeds its reserved span");
  _Static_assert(sizeof(state) == k_pm_reentry32_state_size,
                 "32-bit re-entry state exceeds its reserved span");
  if (!run->raw_pm_32_wrapper_written) {
    if (uc_mem_write(uc, k_pm_reentry32_wrapper, wrapper, sizeof(wrapper)) != UC_ERR_OK ||
        !daze_invalidate_translation_cache(uc, metrics, k_pm_reentry32_wrapper,
                                           k_pm_reentry32_wrapper + sizeof(wrapper))) {
      return 0;
    }
    run->raw_pm_32_wrapper_written = 1;
  }
  return uc_mem_write(uc, k_pm_reentry32_state, state, sizeof(state)) == UC_ERR_OK;
}

static int dpmi_rm_frame_address(uc_engine *uc, uint16_t segment, uint32_t offset,
                                 uint32_t *address) {
  uint32_t base = 0;
  if (!daze_dpmi_selector_base(uc, segment, &base) ||
      offset > k_memory_size - k_dpmi_rm_frame_size ||
      base > k_memory_size - k_dpmi_rm_frame_size - offset) {
    return 0;
  }
  *address = base + offset;
  return 1;
}

int daze_setup_start_dpmi_rm_procedure(uc_engine *uc, DazeUnicornEngine *engine,
                                       DazeUnicornRunState *run) {
  uint8_t frame[k_dpmi_rm_frame_size];
  const uint16_t bx = get_reg16(uc, UC_X86_REG_BX);
  const uint16_t cx = get_reg16(uc, UC_X86_REG_CX);
  const uint16_t es = get_reg16(uc, UC_X86_REG_ES);
  const uint32_t edi = get_reg32(uc, UC_X86_REG_EDI);
  uint32_t frame_address = 0;
  if (!dpmi_rm_frame_address(uc, es, edi, &frame_address) ||
      uc_mem_read(uc, frame_address, frame, sizeof(frame)) != UC_ERR_OK) {
    fprintf(stderr, "  DPMI 31h/0301h invalid ES:EDI frame %04x:%08" PRIx32 "\n", es, edi);
    set_reg16(uc, UC_X86_REG_AX, 0x8021);
    set_carry(uc, 1);
    skip_interrupt_instruction(uc, run);
    return 1;
  }
  const uint16_t frame_ss = daze_read_u16(frame + k_dpmi_rm_ss);
  const uint16_t frame_sp = daze_read_u16(frame + k_dpmi_rm_sp);
  const uint16_t target_cs = daze_read_u16(frame + k_dpmi_rm_cs);
  const uint16_t target_ip = daze_read_u16(frame + k_dpmi_rm_ip);
  const uint32_t parameter_bytes = (uint32_t)cx * 2u;
  uint16_t procedure_sp = frame_sp;
  uint32_t stack_address = 0;
  if ((bx >> 8) != 0 || target_cs == 0 ||
      daze_dpmi_selector_code_width(uc, get_reg16(uc, UC_X86_REG_CS)) != 16) {
    fprintf(stderr, "  DPMI 31h/0301h unsupported BX=%04x CX=%04x\n", bx, cx);
    set_reg16(uc, UC_X86_REG_AX, 0x8021);
    set_carry(uc, 1);
    skip_interrupt_instruction(uc, run);
    return 1;
  }
  if (frame_ss == 0 && frame_sp == 0) {
    procedure_sp = k_dpmi_return_stack_sp;
    stack_address = ((uint32_t)k_dpmi_return_stack_segment << 4) + procedure_sp;
  } else {
    if (frame_sp < 4 ||
        (uint32_t)frame_ss << 4 > (uint32_t)k_memory_size - (uint32_t)frame_sp - parameter_bytes) {
      fprintf(stderr, "  DPMI 31h/0301h invalid real-mode stack %04x:%04x\n", frame_ss, frame_sp);
      set_reg16(uc, UC_X86_REG_AX, 0x8021);
      set_carry(uc, 1);
      skip_interrupt_instruction(uc, run);
      return 1;
    }
    procedure_sp = (uint16_t)(frame_sp - 4);
    stack_address = ((uint32_t)frame_ss << 4) + procedure_sp;
  }
  if (((uint32_t)target_cs << 4) + target_ip >= k_memory_size ||
      stack_address > k_memory_size - 4 - parameter_bytes) {
    fprintf(stderr, "  DPMI 31h/0301h target or stack outside guest memory\n");
    set_reg16(uc, UC_X86_REG_AX, 0x8021);
    set_carry(uc, 1);
    skip_interrupt_instruction(uc, run);
    return 1;
  }
  daze_dpmi_capture_state(uc, &run->rm_procedure_pm_state);
  if (run->rm_procedure_pm_state.esp > UINT16_MAX || run->rm_procedure_pm_state.eip > UINT16_MAX) {
    fprintf(stderr, "  DPMI 31h/0301h requires a 16-bit protected continuation\n");
    set_reg16(uc, UC_X86_REG_AX, 0x8021);
    set_carry(uc, 1);
    skip_interrupt_instruction(uc, run);
    return 1;
  }
  const uint8_t trampoline[] = {
    0xfa,                         /* cli */
    0x0f, 0x20, 0xc0,             /* mov eax, cr0 */
    0x83, 0xe0, 0xfe,             /* and ax, 0fffeh */
    0x0f, 0x22, 0xc0,             /* mov cr0, eax */
    0x2e, 0xff, 0x2e, 0x60, 0x01, /* jmp far cs:[0160h] */
  };
  const uint8_t gate[] = {
    0xfa,                                  /* cli */
    0x0f, 0x20, 0xc0,                      /* mov eax, cr0 */
    0x83, 0xc8, 0x01,                      /* or ax, 1 */
    0x0f, 0x22, 0xc0,                      /* mov cr0, eax */
    0xea, 0x80, 0x01, DAZE_SEL_GATE, 0x00, /* jmp far 0028:0180h */
  };
  _Static_assert(sizeof(trampoline) <= k_dpmi_rm_trampoline_max_size,
                 "0301h trampoline exceeds its reserved span");
  _Static_assert(sizeof(gate) <= k_dpmi_rm_gate_max_size, "0301h gate exceeds its reserved span");
  uint8_t target[4];
  uint8_t return_gate[4];
  daze_write_u16(target, target_ip);
  daze_write_u16(target + 2, target_cs);
  daze_write_u16(return_gate, 0);
  daze_write_u16(return_gate + 2, k_dpmi_rm_gate_segment);
  uint32_t protected_stack_base = 0;
  const uint16_t protected_sp = get_reg16(uc, UC_X86_REG_SP);
  if ((parameter_bytes != 0 &&
       (!daze_dpmi_selector_base(uc, get_reg16(uc, UC_X86_REG_SS), &protected_stack_base) ||
        protected_stack_base > k_memory_size - protected_sp - parameter_bytes)) ||
      uc_mem_write(uc, k_dpmi_rm_trampoline_linear, trampoline, sizeof(trampoline)) != UC_ERR_OK ||
      uc_mem_write(uc, k_dpmi_rm_target_linear, target, sizeof(target)) != UC_ERR_OK ||
      uc_mem_write(uc, k_dpmi_rm_gate_linear, gate, sizeof(gate)) != UC_ERR_OK ||
      uc_mem_write(uc, stack_address, return_gate, sizeof(return_gate)) != UC_ERR_OK ||
      !daze_invalidate_translation_cache(uc, &engine->metrics, k_dpmi_rm_trampoline_linear,
                                         k_dpmi_rm_trampoline_linear + sizeof(trampoline)) ||
      !daze_invalidate_translation_cache(uc, &engine->metrics, k_dpmi_rm_gate_linear,
                                         k_dpmi_rm_gate_linear + sizeof(gate))) {
    return 0;
  }
  for (uint16_t word = 0; word < cx; ++word) {
    uint16_t value = 0;
    if (uc_mem_read(uc, protected_stack_base + protected_sp + (uint32_t)word * 2u, &value,
                    sizeof(value)) != UC_ERR_OK ||
        uc_mem_write(uc, stack_address + 4u + (uint32_t)word * 2u, &value, sizeof(value)) !=
          UC_ERR_OK) {
      return 0;
    }
  }
  set_reg32(uc, UC_X86_REG_EDI, daze_read_u32(frame + k_dpmi_rm_edi));
  set_reg32(uc, UC_X86_REG_ESI, daze_read_u32(frame + k_dpmi_rm_esi));
  set_reg32(uc, UC_X86_REG_EBP, daze_read_u32(frame + k_dpmi_rm_ebp));
  set_reg32(uc, UC_X86_REG_EBX, daze_read_u32(frame + k_dpmi_rm_ebx));
  set_reg32(uc, UC_X86_REG_EDX, daze_read_u32(frame + k_dpmi_rm_edx));
  set_reg32(uc, UC_X86_REG_ECX, daze_read_u32(frame + k_dpmi_rm_ecx));
  set_reg32(uc, UC_X86_REG_EAX, daze_read_u32(frame + k_dpmi_rm_eax));
  set_reg32(uc, UC_X86_REG_EFLAGS, (uint32_t)daze_read_u16(frame + k_dpmi_rm_flags) | 2u);
  set_reg16(uc, UC_X86_REG_ES, daze_read_u16(frame + k_dpmi_rm_es));
  set_reg16(uc, UC_X86_REG_DS, daze_read_u16(frame + k_dpmi_rm_ds));
  set_reg16(uc, UC_X86_REG_FS, daze_read_u16(frame + k_dpmi_rm_fs));
  set_reg16(uc, UC_X86_REG_GS, daze_read_u16(frame + k_dpmi_rm_gs));
  set_reg16(uc, UC_X86_REG_SS, frame_ss == 0 ? k_dpmi_return_stack_segment : frame_ss);
  set_reg32(uc, UC_X86_REG_ESP, procedure_sp);
  set_reg16(uc, UC_X86_REG_CS, DAZE_SEL_GATE);
  set_reg16(uc, UC_X86_REG_IP, 0x0140);
  run->rm_procedure_active = 1;
  run->rm_procedure_frame_address = frame_address;
  run->resume_address = 0x0280 + 0x0140;
  run->use_resume_address = 1;
  daze_trace_debug(engine, "  DPMI 31h/0301h call %04x:%04x stack %04x:%04x words=%u\n", target_cs,
                   target_ip, frame_ss, frame_sp, cx);
  return 1;
}

/* 0300h returns through IRET, so its real-mode stack needs FLAGS:CS:IP rather than the
 * 0301h far-return frame. */
int daze_setup_start_dpmi_rm_interrupt(uc_engine *uc, DazeUnicornEngine *engine,
                                       DazeUnicornRunState *run,
                                       DazeDosRuntimeProcessState *process) {
  uint8_t frame[k_dpmi_rm_frame_size];
  const uint16_t bx = get_reg16(uc, UC_X86_REG_BX);
  const uint16_t cx = get_reg16(uc, UC_X86_REG_CX);
  const uint16_t es = get_reg16(uc, UC_X86_REG_ES);
  const uint32_t edi = get_reg32(uc, UC_X86_REG_EDI);
  const uint8_t vector = (uint8_t)bx;
  uint32_t frame_address = 0;
  if (!dpmi_rm_frame_address(uc, es, edi, &frame_address) ||
      uc_mem_read(uc, frame_address, frame, sizeof(frame)) != UC_ERR_OK) {
    fprintf(stderr, "  DPMI 31h/0300h invalid ES:EDI frame %04x:%08" PRIx32 "\n", es, edi);
    set_reg16(uc, UC_X86_REG_AX, 0x8021);
    set_carry(uc, 1);
    skip_interrupt_instruction(uc, run);
    return 1;
  }
  const uint16_t target_cs = process->dos_process.dos_vector_segment[vector];
  const uint16_t target_ip = process->dos_process.dos_vector_offset[vector];
  const uint16_t frame_ss = daze_read_u16(frame + k_dpmi_rm_ss);
  const uint16_t frame_sp = daze_read_u16(frame + k_dpmi_rm_sp);
  uint16_t interrupt_sp = frame_sp;
  uint32_t stack_address = 0;
  const int code_width = daze_dpmi_selector_code_width(uc, get_reg16(uc, UC_X86_REG_CS));
  if (cx != 0 || (bx >> 8) != 0 || target_cs == 0 || (code_width != 16 && code_width != 32)) {
    fprintf(stderr, "  DPMI 31h/0300h unsupported BX=%04x CX=%04x\n", bx, cx);
    set_reg16(uc, UC_X86_REG_AX, 0x8021);
    set_carry(uc, 1);
    skip_interrupt_instruction(uc, run);
    return 1;
  }
  if (frame_ss == 0 && frame_sp == 0) {
    interrupt_sp = (uint16_t)(k_dpmi_return_stack_sp - 6);
    stack_address = ((uint32_t)k_dpmi_return_stack_segment << 4) + interrupt_sp;
  } else {
    if (frame_sp < 6 || ((uint32_t)frame_ss << 4) > (uint32_t)k_memory_size - frame_sp) {
      fprintf(stderr, "  DPMI 31h/0300h invalid real-mode stack %04x:%04x\n", frame_ss, frame_sp);
      set_reg16(uc, UC_X86_REG_AX, 0x8021);
      set_carry(uc, 1);
      skip_interrupt_instruction(uc, run);
      return 1;
    }
    interrupt_sp = (uint16_t)(frame_sp - 6);
    stack_address = ((uint32_t)frame_ss << 4) + interrupt_sp;
  }
  if (((uint32_t)target_cs << 4) + target_ip >= k_memory_size ||
      stack_address > k_memory_size - 6) {
    fprintf(stderr, "  DPMI 31h/0300h target or stack outside guest memory\n");
    set_reg16(uc, UC_X86_REG_AX, 0x8021);
    set_carry(uc, 1);
    skip_interrupt_instruction(uc, run);
    return 1;
  }
  daze_dpmi_capture_state(uc, &run->rm_procedure_pm_state);
  const uint8_t trampoline[] = {
    0xfa,                         /* cli */
    0x2e, 0x66, 0xa3, 0x70, 0x01, /* mov cs:[0170h], eax */
    0x0f, 0x20, 0xc0,             /* mov eax, cr0 */
    0x83, 0xe0, 0xfe,             /* and ax, 0fffeh */
    0x0f, 0x22, 0xc0,             /* mov cr0, eax */
    0x2e, 0x66, 0xa1, 0x70, 0x01, /* mov eax, cs:[0170h] */
    0x2e, 0xff, 0x2e, 0x60, 0x01, /* jmp far cs:[0160h] */
  };
  const uint8_t gate_32[] = {
    0xfa,                         /* cli */
    0x0f, 0x20, 0xc0,             /* mov eax, cr0 */
    0x83, 0xc8, 0x01,             /* or ax, 1 */
    0x0f, 0x22, 0xc0,             /* mov cr0, eax */
    0xea, 0x40, 0x02, 0x20, 0x00, /* jmp far 0020:0240h */
  };
  _Static_assert(sizeof(trampoline) <= k_dpmi_rm_trampoline_max_size,
                 "0300h trampoline exceeds its reserved span");
  _Static_assert(sizeof(gate_32) <= k_dpmi_rm_gate_max_size,
                 "0300h gate exceeds its reserved span");
  /* The simulated-interrupt completion writes the DPMI register frame through
   * the 32-bit host route even when the interrupted client is 16-bit. Its
   * eventual client continuation is selected separately by the saved state. */
  const uint8_t *const gate = gate_32;
  const size_t gate_size = sizeof(gate_32);
  uint8_t target[4];
  const uint16_t return_frame[] = {0, k_dpmi_rm_gate_segment,
                                   daze_read_u16(frame + k_dpmi_rm_flags)};
  daze_write_u16(target, target_ip);
  daze_write_u16(target + 2, target_cs);
  if (uc_mem_write(uc, k_dpmi_rm_trampoline_linear, trampoline, sizeof(trampoline)) != UC_ERR_OK ||
      uc_mem_write(uc, k_dpmi_rm_target_linear, target, sizeof(target)) != UC_ERR_OK ||
      uc_mem_write(uc, k_dpmi_rm_gate_linear, gate, gate_size) != UC_ERR_OK ||
      uc_mem_write(uc, stack_address, return_frame, sizeof(return_frame)) != UC_ERR_OK ||
      !daze_invalidate_translation_cache(uc, &engine->metrics, k_dpmi_rm_trampoline_linear,
                                         k_dpmi_rm_trampoline_linear + sizeof(trampoline)) ||
      !daze_invalidate_translation_cache(uc, &engine->metrics, k_dpmi_rm_gate_linear,
                                         k_dpmi_rm_gate_linear + gate_size)) {
    return 0;
  }
  set_reg32(uc, UC_X86_REG_EDI, daze_read_u32(frame + k_dpmi_rm_edi));
  set_reg32(uc, UC_X86_REG_ESI, daze_read_u32(frame + k_dpmi_rm_esi));
  set_reg32(uc, UC_X86_REG_EBP, daze_read_u32(frame + k_dpmi_rm_ebp));
  set_reg32(uc, UC_X86_REG_EBX, daze_read_u32(frame + k_dpmi_rm_ebx));
  set_reg32(uc, UC_X86_REG_EDX, daze_read_u32(frame + k_dpmi_rm_edx));
  set_reg32(uc, UC_X86_REG_ECX, daze_read_u32(frame + k_dpmi_rm_ecx));
  set_reg32(uc, UC_X86_REG_EAX, daze_read_u32(frame + k_dpmi_rm_eax));
  set_reg32(uc, UC_X86_REG_EFLAGS, (uint32_t)daze_read_u16(frame + k_dpmi_rm_flags) | 2u);
  set_reg16(uc, UC_X86_REG_ES, daze_read_u16(frame + k_dpmi_rm_es));
  set_reg16(uc, UC_X86_REG_DS, daze_read_u16(frame + k_dpmi_rm_ds));
  set_reg16(uc, UC_X86_REG_FS, daze_read_u16(frame + k_dpmi_rm_fs));
  set_reg16(uc, UC_X86_REG_GS, daze_read_u16(frame + k_dpmi_rm_gs));
  set_reg16(uc, UC_X86_REG_SS, frame_ss == 0 ? k_dpmi_return_stack_segment : frame_ss);
  set_reg32(uc, UC_X86_REG_ESP, interrupt_sp);
  set_reg16(uc, UC_X86_REG_CS, DAZE_SEL_GATE);
  set_reg16(uc, UC_X86_REG_IP, 0x0140);
  run->rm_procedure_active = 1;
  run->rm_procedure_32bit_reentry = 1;
  run->rm_procedure_frame_address = frame_address;
  run->resume_address = 0x0280 + 0x0140;
  run->use_resume_address = 1;
  daze_trace_debug(engine, "  DPMI 31h/0300h simulate real-mode INT %02x -> %04x:%04x\n", vector,
                   target_cs, target_ip);
  return 1;
}

int daze_setup_complete_dpmi_rm_procedure(uc_engine *uc, DazeUnicornEngine *engine,
                                          DazeUnicornRunState *run) {
  uint8_t frame[k_dpmi_rm_frame_size];
  const DpmiAlternateState *state = &run->rm_procedure_pm_state;
  if (uc_mem_read(uc, run->rm_procedure_frame_address, frame, sizeof(frame)) != UC_ERR_OK) {
    return 0;
  }
  daze_write_u32(frame + k_dpmi_rm_edi, get_reg32(uc, UC_X86_REG_EDI));
  daze_write_u32(frame + k_dpmi_rm_esi, get_reg32(uc, UC_X86_REG_ESI));
  daze_write_u32(frame + k_dpmi_rm_ebp, get_reg32(uc, UC_X86_REG_EBP));
  daze_write_u32(frame + k_dpmi_rm_ebx, get_reg32(uc, UC_X86_REG_EBX));
  daze_write_u32(frame + k_dpmi_rm_edx, get_reg32(uc, UC_X86_REG_EDX));
  daze_write_u32(frame + k_dpmi_rm_ecx, get_reg32(uc, UC_X86_REG_ECX));
  daze_write_u32(frame + k_dpmi_rm_eax, get_reg32(uc, UC_X86_REG_EAX));
  daze_write_u16(frame + k_dpmi_rm_flags, (uint16_t)get_reg32(uc, UC_X86_REG_EFLAGS));
  daze_write_u16(frame + k_dpmi_rm_es, get_reg16(uc, UC_X86_REG_ES));
  daze_write_u16(frame + k_dpmi_rm_ds, get_reg16(uc, UC_X86_REG_DS));
  daze_write_u16(frame + k_dpmi_rm_fs, get_reg16(uc, UC_X86_REG_FS));
  daze_write_u16(frame + k_dpmi_rm_gs, get_reg16(uc, UC_X86_REG_GS));
  const int reentry_ok =
    run->rm_procedure_32bit_reentry
      ? daze_setup_write_raw_pm_reentry32_wrapper(
          uc, run, &engine->metrics, state->ds, state->es, state->ss, state->fs, state->gs,
          state->eax, state->ebx, state->ecx, state->edx, state->esi, state->edi, state->ebp,
          state->esp, state->eflags & ~1u, state->eip, state->cs)
      : daze_setup_write_raw_pm_reentry_wrapper(
          uc, run, &engine->metrics, state->ds, state->es, state->ss, (uint16_t)state->esp,
          state->fs, state->gs, (uint16_t)state->eax, (uint16_t)state->ebx, (uint16_t)state->ecx,
          (uint16_t)state->edx, (uint16_t)state->esi, (uint16_t)state->edi, (uint16_t)state->ebp,
          (uint16_t)(state->eflags & ~1u), (uint16_t)state->eip, state->cs);
  if (uc_mem_write(uc, run->rm_procedure_frame_address, frame, sizeof(frame)) != UC_ERR_OK ||
      !reentry_ok) {
    return 0;
  }
  run->rm_procedure_active = 0;
  run->rm_procedure_32bit_reentry = 0;
  run->resume_address = k_dpmi_rm_gate_linear;
  run->use_resume_address = 1;
  daze_trace_debug(engine, "  DPMI 31h/0301h real-mode RETF -> protected continuation\n");
  return 1;
}
