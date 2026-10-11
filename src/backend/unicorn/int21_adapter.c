#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>

#include "bios_adapter.h"
#include "int21_service.h"
#include "descriptor.h"
#include "file_service.h"
#include "image.h"
#include "mz_layout.h"
#include "runtime.h"
#include "unicorn_context.h"
#include "unicorn_services.h"

static int write_dos_character(DazeMetrics *metrics, DazeDosfsFileService *files,
                               uint8_t character) {
  if (daze_dosfs_file_write_character(files, character, NULL) != DAZE_DOSFS_OK) return 0;
  metrics->host_write_calls++;
  metrics->host_write_bytes++;
  return 1;
}

static DazeDosInt21Request capture_int21_request(uc_engine *uc) {
  uint32_t flags = 0;
  (void)uc_reg_read(uc, UC_X86_REG_EFLAGS, &flags);
  return (DazeDosInt21Request){
    .ax = get_reg16(uc, UC_X86_REG_AX),
    .bx = get_reg16(uc, UC_X86_REG_BX),
    .cx = get_reg16(uc, UC_X86_REG_CX),
    .dx = get_reg16(uc, UC_X86_REG_DX),
    .si = get_reg16(uc, UC_X86_REG_SI),
    .di = get_reg16(uc, UC_X86_REG_DI),
    .ds = get_reg16(uc, UC_X86_REG_DS),
    .es = get_reg16(uc, UC_X86_REG_ES),
    .flags = (uint16_t)flags,
  };
}

static int apply_int21_result(uc_engine *uc, const DazeDosInt21Result *result) {
  if ((result->register_write_mask & DAZE_DOS_INT21_REG_AX) != 0)
    set_reg16(uc, UC_X86_REG_AX, result->ax);
  if ((result->register_write_mask & DAZE_DOS_INT21_REG_BX) != 0)
    set_reg16(uc, UC_X86_REG_BX, result->bx);
  if ((result->register_write_mask & DAZE_DOS_INT21_REG_CX) != 0)
    set_reg16(uc, UC_X86_REG_CX, result->cx);
  if ((result->register_write_mask & DAZE_DOS_INT21_REG_DX) != 0)
    set_reg16(uc, UC_X86_REG_DX, result->dx);
  if ((result->register_write_mask & DAZE_DOS_INT21_REG_SI) != 0)
    set_reg16(uc, UC_X86_REG_SI, result->si);
  if ((result->register_write_mask & DAZE_DOS_INT21_REG_DI) != 0)
    set_reg16(uc, UC_X86_REG_DI, result->di);
  if ((result->register_write_mask & DAZE_DOS_INT21_REG_DS) != 0)
    set_reg16(uc, UC_X86_REG_DS, result->ds);
  if ((result->register_write_mask & DAZE_DOS_INT21_REG_ES) != 0)
    set_reg16(uc, UC_X86_REG_ES, result->es);
  if (result->flag_write_mask != 0) {
    uint32_t flags = 0;
    if (uc_reg_read(uc, UC_X86_REG_EFLAGS, &flags) != UC_ERR_OK) return 0;
    flags = (flags & ~(uint32_t)result->flag_write_mask) |
            (result->flag_values & result->flag_write_mask);
    if (uc_reg_write(uc, UC_X86_REG_EFLAGS, &flags) != UC_ERR_OK) return 0;
  }
  return 1;
}

static int int21_unicorn_guest_read(void *context, uint16_t segment, uint16_t offset, void *bytes,
                                    size_t size) {
  return daze_read_guest_bytes(context, segment, offset, bytes, size);
}

static int int21_unicorn_guest_write(void *context, uint16_t segment, uint16_t offset,
                                     const void *bytes, size_t size) {
  return daze_write_guest_bytes(context, segment, offset, bytes, size);
}

typedef struct {
  uc_engine *uc;
  DazeUnicornRunState *run;
  DazeUnicornEngine *engine;
} DazeInt21UnicornPreReleaseContext;

static int int21_unicorn_pre_release(void *context, uint16_t allocation_segment) {
  DazeInt21UnicornPreReleaseContext *hook = context;
  return hook != NULL && hook->uc != NULL && hook->run != NULL && hook->engine != NULL &&
         daze_withdraw_raw_vector_projections(hook->uc, hook->run, &hook->engine->metrics,
                                              allocation_segment);
}

static void int21_unicorn_transfer_observed(void *context, const DazeDosInt21Request *request,
                                            const DazeDosfsFileResult *file) {
  DazeInt21UnicornPreReleaseContext *hook = context;
  if (hook == NULL || hook->engine == NULL || request == NULL || file == NULL) return;
  DazeMetrics *metrics = &hook->engine->metrics;
  if ((uint8_t)(request->ax >> 8) == 0x3f && file->host_read_attempted) {
    metrics->host_read_calls++;
    metrics->host_read_bytes += file->byte_count;
  }
  if (((uint8_t)(request->ax >> 8) == 0x40 || (uint8_t)(request->ax >> 8) == 0x09) &&
      file->host_write_attempted) {
    metrics->host_write_calls++;
    metrics->host_write_bytes += file->byte_count;
  }
}

static void int21_unicorn_transfer_completed(void *context, const DazeDosInt21Request *request,
                                             const DazeDosfsFileResult *file) {
  DazeInt21UnicornPreReleaseContext *hook = context;
  if (hook == NULL || hook->uc == NULL || hook->engine == NULL || !hook->engine->debug ||
      request == NULL || file == NULL)
    return;
  if ((uint8_t)(request->ax >> 8) == 0x3f) {
    fprintf(stderr, "  DOS 21h/3Fh read: handle %u, %u bytes -> %u bytes at %04x:%04x\n",
            request->bx, request->cx, file->byte_count, request->ds, request->dx);
  } else if ((uint8_t)(request->ax >> 8) == 0x40) {
    fprintf(stderr, "  DOS 21h/40h write: handle %u, %u bytes", request->bx, file->byte_count);
    if (hook->engine->diagnostic_trace.enabled)
      fprintf(stderr, " from %04x:%04x", get_reg16(hook->uc, UC_X86_REG_CS),
              get_reg16(hook->uc, UC_X86_REG_IP));
    fputc('\n', stderr);
  }
}

static int dispatch_shared_int21_reply(uc_engine *uc, DazeUnicornEngine *engine,
                                       DazeUnicornRunState *run, DazeDosProcessState *dos_process,
                                       DazeDosMemory *dos_memory, DazeDosfsFileService *files,
                                       uint8_t function) {
  if (!daze_dos_int21_is_shared_function(function)) return 0;
  const DazeDosInt21Request request = capture_int21_request(uc);
  DazeInt21UnicornPreReleaseContext pre_release = {.uc = uc, .run = run, .engine = engine};
  const DazeDosInt21Context int21_context = {
    .files = files,
    .process_state = dos_process,
    .dos_memory = dos_memory,
    .pre_release = int21_unicorn_pre_release,
    .pre_release_context = &pre_release,
    .guest_memory = {.context = uc,
                     .read = int21_unicorn_guest_read,
                     .write = int21_unicorn_guest_write},
    .transfer_observed = int21_unicorn_transfer_observed,
    .transfer_completed = int21_unicorn_transfer_completed,
    .transfer_context = &pre_release,
    .indos_segment = k_dos_int21_vector_segment,
    .indos_offset = k_dos_indos_offset,
    .dbcs_table_segment = k_dos_dbcs_table_segment,
    .sda_segment = k_dos_int21_vector_segment,
    .sda_offset = k_dos_sda_offset,
  };
  DazeDosInt21Result result;
  if (daze_dos_int21_dispatch(&int21_context, &request, &result) != DAZE_DOS_INT21_DISPATCH_OK)
    return -1;
  if (result.disposition == DAZE_DOS_INT21_UNSUPPORTED) return 0;
  if (result.disposition != DAZE_DOS_INT21_HANDLED || !apply_int21_result(uc, &result)) return -1;

  switch (function) {
  case 0x09:
    daze_trace_debug(engine, "  DOS 21h/09h display string: %s\n",
                     (result.flag_values & DAZE_DOS_INT21_FLAG_CF) != 0 ? "failed" : "ok");
    break;
  case 0x06:
    daze_trace_debug(engine, "  DOS 21h/06h console poll: no character\n");
    break;
  case 0x5d:
    daze_trace_debug(engine, "  DOS 21h/5D06h get swappable data area: %04x:%04x (2 bytes)\n",
                     k_dos_int21_vector_segment, k_dos_sda_offset);
    break;
  case 0x0b:
    daze_trace_debug(engine, "  DOS 21h/0Bh console status: no character\n");
    break;
  case 0x1a:
    daze_trace_debug(engine, "  DOS 21h/1Ah set DTA: %04x:%04x\n", dos_process->dta_segment,
                     dos_process->dta_offset);
    break;
  case 0x2f:
    daze_trace_debug(engine, "  DOS 21h/2Fh get DTA: %04x:%04x\n", dos_process->dta_segment,
                     dos_process->dta_offset);
    break;
  case 0x2a:
  case 0x2c:
  case 0x30:
  case 0x34:
  case 0x63:
    break;
  case 0x3c:
  case 0x3d:
    daze_trace_debug(
      engine, "  DOS 21h/%02Xh %s: %s %u\n", function, function == 0x3c ? "create" : "open",
      (result.flag_values & DAZE_DOS_INT21_FLAG_CF) != 0 ? "failed (DOS error)" : "handle",
      result.ax);
    break;
  case 0x3e:
    daze_trace_debug(engine, "  DOS 21h/3Eh close: handle %u %s\n", request.bx,
                     (result.flag_values & DAZE_DOS_INT21_FLAG_CF) != 0 ? "failed" : "ok");
    break;
  case 0x42:
    daze_trace_debug(engine, "  DOS 21h/42h seek: handle %u %s\n", request.bx,
                     (result.flag_values & DAZE_DOS_INT21_FLAG_CF) != 0 ? "failed" : "ok");
    break;
  case 0x44:
    /* An invalid-handle reply is a handled DOS error, not an unsupported-function
     * failure. */
    if ((result.flag_values & DAZE_DOS_INT21_FLAG_CF) != 0)
      daze_trace_debug(engine, "  DOS 21h/4400h device info: invalid handle %u\n", request.bx);
    else
      daze_trace_debug(engine, "  DOS 21h/4400h device info: handle %u is a file\n", request.bx);
    break;
  case 0x46:
    if ((result.flag_values & DAZE_DOS_INT21_FLAG_CF) != 0)
      daze_trace_debug(engine, "  DOS 21h/46h force duplicate: handle %u -> %u failed (%u)\n",
                       request.bx, request.cx, result.ax);
    else
      daze_trace_debug(engine, "  DOS 21h/46h force duplicate: handle %u -> %u\n", request.bx,
                       request.cx);
    break;
  case 0x4e:
  case 0x4f:
    daze_trace_debug(engine, "  DOS 21h/%02Xh find: carry %u\n", function,
                     (result.flag_values & DAZE_DOS_INT21_FLAG_CF) != 0);
    break;
  case 0x57:
    if ((result.flag_values & DAZE_DOS_INT21_FLAG_CF) != 0)
      daze_trace_debug(engine, "  DOS 21h/57h invalid handle %u\n", request.bx);
    else if ((uint8_t)request.ax == 0)
      daze_trace_debug(engine, "  DOS 21h/5700h get file time: handle %u -> 2000-01-01\n",
                       request.bx);
    else
      daze_trace_debug(engine, "  DOS 21h/5701h set file time: handle %u (virtual no-op)\n",
                       request.bx);
    break;
  case 0x67:
    daze_trace_debug(engine, "  DOS 21h/67h set handle count: %u\n", request.bx);
    break;
  default:
    break;
  }
  skip_interrupt_instruction(uc, run);
  return 1;
}

static int classify_shared_int21_boundary(DazeDosProcessState *dos_process,
                                          DazeDosMemory *dos_memory, DazeDosfsFileService *files,
                                          const DazeDosInt21Request *request,
                                          DazeDosInt21Result *result) {
  const DazeDosInt21Context int21_context = {
    .files = files,
    .process_state = dos_process,
    .dos_memory = dos_memory,
  };
  return daze_dos_int21_dispatch(&int21_context, request, result) == DAZE_DOS_INT21_DISPATCH_OK;
}

int daze_unicorn_int21_dispatch(uc_engine *uc, DazeUnicornEngine *engine, DazeUnicornRunState *run,
                                DazeDosRuntimeProcessState *process, DazeDosfsFileService *files) {
  const uint16_t ax = get_reg16(uc, UC_X86_REG_AX);
  const uint8_t function = (uint8_t)(ax >> 8);
  engine->metrics.dos_function_counts[function]++;
  const int shared_reply = dispatch_shared_int21_reply(uc, engine, run, &process->dos_process,
                                                       &process->dos_memory, files, function);
  if (shared_reply != 0) return shared_reply > 0;
  switch (function) {
  case 0x35: {
    const uint8_t vector = (uint8_t)ax;
    const uint16_t segment = process->dos_process.dos_vector_segment[vector];
    const uint16_t offset = process->dos_process.dos_vector_offset[vector];
    if (vector == 0x21) {
      daze_trace_debug(engine, "  DOS 21h/35h get vector 21h: %04x:%04x\n", segment, offset);
    } else if (engine->diagnostic_trace.enabled) {
      daze_trace_debug(engine, "  DOS 21h/35h get vector %02xh: %04x:%04x\n", vector, segment,
                       offset);
    }
    set_reg16(uc, UC_X86_REG_ES, segment);
    set_reg16(uc, UC_X86_REG_BX, offset);
    set_carry(uc, 0);
    skip_interrupt_instruction(uc, run);
    return 1;
  }
  case 0x06: {
    const uint8_t character = (uint8_t)get_reg16(uc, UC_X86_REG_DX);
    if (!write_dos_character(&engine->metrics, files, character)) {
      fprintf(stderr, "  DOS 21h/06h cannot write standard output\n");
      return 0;
    }
    set_reg16(uc, UC_X86_REG_AX, (uint16_t)((ax & 0xff00u) | character));
    set_zero(uc, 0);
    set_carry(uc, 0);
    skip_interrupt_instruction(uc, run);
    return 1;
  }
  case 0x02: {
    const uint8_t character = (uint8_t)get_reg16(uc, UC_X86_REG_DX);
    if (!write_dos_character(&engine->metrics, files, character)) {
      fprintf(stderr, "  DOS 21h/02h cannot write standard output\n");
      return 0;
    }
    set_reg16(uc, UC_X86_REG_AX, (uint16_t)((ax & 0xff00u) | character));
    skip_interrupt_instruction(uc, run);
    return 1;
  }
  case 0x25: {
    const uint8_t vector = (uint8_t)ax;
    const uint16_t segment = get_reg16(uc, UC_X86_REG_DS);
    const uint16_t offset = get_reg16(uc, UC_X86_REG_DX);
    process->dos_process.dos_vector_segment[vector] = segment;
    process->dos_process.dos_vector_offset[vector] = offset;
    daze_trace_debug(engine, "  DOS 21h/25h set vector %02xh: %04x:%04x\n", vector, segment,
                     offset);
    set_carry(uc, 0);
    skip_interrupt_instruction(uc, run);
    return 1;
  }
  case 0x43:
    if ((uint8_t)ax != 0x01) return 0;
    fprintf(stderr, "  DOS 21h/43h unsupported operation %u\n", (uint8_t)ax);
    set_reg16(uc, UC_X86_REG_AX, 1);
    set_carry(uc, 1);
    skip_interrupt_instruction(uc, run);
    return 1;
  case 0x4b: {
    DazeDosInt21Result classification;
    const DazeDosInt21Request request = {.ax = ax};
    if (!classify_shared_int21_boundary(&process->dos_process, &process->dos_memory, files,
                                        &request, &classification))
      return 0;
    if (classification.disposition != DAZE_DOS_INT21_EXEC) return 0;
    char diagnostic[192];
    if (!daze_setup_start_exec_child(uc, engine, run, process, files, diagnostic,
                                     sizeof(diagnostic))) {
      fprintf(stderr, "  DOS 21h/4B00h EXEC failed: %s\n", diagnostic);
      set_reg16(uc, UC_X86_REG_AX, 2); // File not found / bounded EXEC failure.
      set_carry(uc, 1);
      skip_interrupt_instruction(uc, run);
      return 1;
    }
    return 1; // daze_setup_start_exec_child supplied an explicit child entry address.
  }
  case 0x4c: {
    DazeDosInt21Result classification;
    const DazeDosInt21Request request = {.ax = ax};
    if (!classify_shared_int21_boundary(&process->dos_process, &process->dos_memory, files,
                                        &request, &classification) ||
        classification.disposition != DAZE_DOS_INT21_TERMINATED)
      return 0;
    daze_trace_debug(engine, "  DOS 21h/4Ch terminate: exit code %u\n",
                     (unsigned)classification.termination_status);
    if (process->child_process.active) {
      process->child_process.exit_code = classification.termination_status;
      process->child_process.termination_type = 0;
      process->child_process.status_available = 1;
      daze_dos_process_state_record_child_termination(&process->dos_process,
                                                      classification.termination_status, 0);
      if (uc_context_restore(uc, process->child_process.parent_context) != UC_ERR_OK ||
          !daze_flush_translation_cache(uc, &engine->metrics)) {
        fprintf(stderr, "  DOS 21h/4Ch cannot restore EXEC parent context\n");
        return 0;
      }
      uc_context_free(process->child_process.parent_context);
      process->child_process.parent_context = NULL;
      daze_dosfs_exec_handles_restore(&process->child_process.handles);
      process->dos_memory = process->child_process.parent_memory;
      process->dos_process.psp_segment = process->child_process.parent_psp_segment;
      daze_dos_process_state_set_dta(&process->dos_process,
                                     process->child_process.parent_dta_segment,
                                     process->child_process.parent_dta_offset);
      process->resident_image_end = process->child_process.parent_resident_image_end;
      process->child_process.active = 0;
      set_carry(uc, 0);
      const uint16_t parent_cs = get_reg16(uc, UC_X86_REG_CS);
      const uint16_t parent_ip = get_reg16(uc, UC_X86_REG_IP);
      run->resume_address = ((uint32_t)parent_cs << 4) + parent_ip;
      run->use_resume_address = 1;
      daze_trace_debug(engine, "  DOS 21h/4Ch return to EXEC parent at %04x:%04x\n", parent_cs,
                       parent_ip);
      return 1;
    }
    run->exit_code = classification.termination_status;
    run->terminated = 1;
    return 1;
  }
  case 0x31:
    daze_trace_debug(engine,
                     "  DOS 21h/31h terminate and stay resident: exit code %u, %u paragraphs\n",
                     (unsigned)(ax & 0xff), get_reg16(uc, UC_X86_REG_DX));
    if (process->child_process.active) {
      /* DPMILOAD installs its multiplex vector, then stays resident before
       * returning control to its EXEC parent. Keep the child's allocation
       * and its vector state live; unlike INT 21h/4Ch, there is deliberately
       * nothing to release here. */
      process->child_process.exit_code = (uint8_t)ax;
      process->child_process.termination_type = 3;
      process->child_process.status_available = 1;
      daze_dos_process_state_record_child_termination(&process->dos_process, (uint8_t)ax, 3);
      if (uc_context_restore(uc, process->child_process.parent_context) != UC_ERR_OK ||
          !daze_flush_translation_cache(uc, &engine->metrics)) {
        fprintf(stderr, "  DOS 21h/31h cannot restore EXEC parent context\n");
        return 0;
      }
      uc_context_free(process->child_process.parent_context);
      process->child_process.parent_context = NULL;
      daze_dosfs_exec_handles_restore(&process->child_process.handles);
      process->dos_process.psp_segment = process->child_process.parent_psp_segment;
      daze_dos_process_state_set_dta(&process->dos_process,
                                     process->child_process.parent_dta_segment,
                                     process->child_process.parent_dta_offset);
      process->resident_image_end = process->child_process.parent_resident_image_end;
      process->child_process.active = 0;
      set_carry(uc, 0);
      const uint16_t parent_cs = get_reg16(uc, UC_X86_REG_CS);
      const uint16_t parent_ip = get_reg16(uc, UC_X86_REG_IP);
      run->resume_address = ((uint32_t)parent_cs << 4) + parent_ip;
      run->use_resume_address = 1;
      daze_trace_debug(engine, "  DOS 21h/31h return to EXEC parent at %04x:%04x\n", parent_cs,
                       parent_ip);
      return 1;
    }
    run->exit_code = (uint8_t)ax;
    run->terminated = 1;
    return 1;
  default:
    fprintf(stderr, "  unsupported DOS 21h function %02xh (AX=%04x BX=%04x CX=%04x DX=%04x)\n",
            function, ax, get_reg16(uc, UC_X86_REG_BX), get_reg16(uc, UC_X86_REG_CX),
            get_reg16(uc, UC_X86_REG_DX));
    return 0;
  }
}
