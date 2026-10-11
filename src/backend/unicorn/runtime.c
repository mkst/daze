#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "bios_adapter.h"
#include "byte_order.h"
#include "descriptor.h"
#include "advertisement.h"
#include "exception_frame.h"
#include "file_service.h"
#include "image.h"
#include "interrupt_vector.h"
#include "mz_layout.h"
#include "monotonic_clock.h"
#include "unicorn_context.h"
#include "unicorn_services.h"
#include "selector.h"

static int daze_dispatch_interrupt_impl(uc_engine *uc, uint8_t interrupt, DazeUnicornEngine *engine,
                                        DazeUnicornRunState *run,
                                        DazeDosRuntimeProcessState *process,
                                        DazeDosfsFileService *files);
static int direct_interrupt_in_place(uint8_t interrupt);
static int protected_dos_continuation_declined(uc_engine *uc, const DazeUnicornRunState *run,
                                               uint16_t cs, uint64_t fault_linear);
static int protected_dos_continuation_serve(uc_engine *uc, DazeUnicornEngine *engine,
                                            DazeUnicornRunState *run,
                                            DazeDosRuntimeProcessState *process,
                                            DazeDosfsFileService *files);
static void daze_on_protected_dos_continuation_code(uc_engine *uc, uint64_t address, uint32_t size,
                                                    void *user_data);
int daze_dispatch_interrupt(uc_engine *uc, uint8_t interrupt, DazeUnicornEngine *engine,
                            DazeUnicornRunState *run, DazeDosRuntimeProcessState *process,
                            DazeDosfsFileService *files);

static void daze_snapshot_raw_vectors(DazeUnicornRunState *run,
                                      const DazeDosRuntimeProcessState *process) {
  memcpy(run->raw_vector_snapshot_segment, process->dos_process.dos_vector_segment,
         sizeof(run->raw_vector_snapshot_segment));
  memcpy(run->raw_vector_snapshot_offset, process->dos_process.dos_vector_offset,
         sizeof(run->raw_vector_snapshot_offset));
  run->raw_vector_snapshot_child_active = process->child_process.active;
  run->raw_vector_snapshot_allocation_segment = process->child_process.allocation_segment;
  run->raw_vector_snapshot_valid = 1;
}

static void daze_report_raw_vector_deltas(const DazeUnicornRunState *run,
                                          const DazeDosRuntimeProcessState *process,
                                          const DazeUnicornEngine *engine) {
  if (!run->raw_vector_snapshot_valid || !engine->debug) return;
  const DazeDosAllocation *owning_allocation = NULL;
  for (size_t index = 0; index < DAZE_DOS_MEMORY_MAX_ALLOCS; ++index) {
    const DazeDosAllocation *const allocation = &process->dos_memory.allocations[index];
    if (allocation->in_use && allocation->segment == run->raw_vector_snapshot_allocation_segment) {
      owning_allocation = allocation;
      break;
    }
  }
  for (unsigned vector = 0; vector < 256; ++vector) {
    const uint16_t old_segment = run->raw_vector_snapshot_segment[vector];
    const uint16_t old_offset = run->raw_vector_snapshot_offset[vector];
    const uint16_t new_segment = process->dos_process.dos_vector_segment[vector];
    const uint16_t new_offset = process->dos_process.dos_vector_offset[vector];
    if ((old_segment == new_segment && old_offset == new_offset) || new_segment == 0) continue;
    /* A child can legitimately become resident during the raw excursion. Its
     * EXEC state is then inactive, but the snapshotted allocation remains live
     * and is the only ownership evidence retained for this paired re-entry. */
    const int accepted =
      run->raw_vector_snapshot_child_active &&
      daze_raw_vector_projection_eligible(
        &process->dos_memory, run->raw_vector_snapshot_allocation_segment, new_segment, new_offset);
    daze_trace_debug(engine,
                     "  DPMI raw vector delta %02xh: %04x:%04x -> %04x:%04x child=%04x "
                     "snapshot=%d current=%d paragraphs=%04x %s\n",
                     vector, old_segment, old_offset, new_segment, new_offset,
                     run->raw_vector_snapshot_allocation_segment,
                     run->raw_vector_snapshot_child_active, process->child_process.active,
                     owning_allocation == NULL ? 0 : owning_allocation->paragraphs,
                     accepted ? "owned" : "rejected");
  }
}

static const DazeDosAllocation *daze_raw_vector_allocation(const DazeDosMemory *dos_memory,
                                                           uint16_t allocation_segment) {
  for (size_t index = 0; index < DAZE_DOS_MEMORY_MAX_ALLOCS; ++index) {
    const DazeDosAllocation *const allocation = &dos_memory->allocations[index];
    if (allocation->in_use && allocation->segment == allocation_segment) return allocation;
  }
  return NULL;
}

static int daze_raw_vector_is_referenced(const DazeDosProcessState *dos_process,
                                         uint16_t selector) {
  for (size_t vector = 0; vector < 256; ++vector) {
    if (dos_process->dos_vector_segment[vector] == selector) return 1;
  }
  return 0;
}

static int daze_raw_vector_descriptor_is_empty(uc_engine *uc, uint16_t selector) {
  uint8_t descriptor[8];
  return uc_mem_read(uc, k_dpmi_ldt_address + (uint32_t)(selector & (uint16_t)~7u), descriptor,
                     sizeof(descriptor)) == UC_ERR_OK &&
         memcmp(descriptor, (uint8_t[8]){0}, sizeof(descriptor)) == 0;
}

static int daze_materialize_raw_vector_descriptors(uc_engine *uc, DazeUnicornRunState *run,
                                                   const DazeDosRuntimeProcessState *process,
                                                   DazeMetrics *metrics) {
  uint8_t empty[8] = {0};
  int changed = 0;
  for (size_t index = 0;
       index < sizeof(run->raw_vector_projections) / sizeof(run->raw_vector_projections[0]);
       ++index) {
    DazeRawVectorProjection *const projection = &run->raw_vector_projections[index];
    if (!projection->in_use) continue;
    const DazeDosAllocation *const allocation =
      daze_raw_vector_allocation(&process->dos_memory, projection->allocation_segment);
    if (allocation != NULL && allocation->paragraphs == projection->allocation_paragraphs &&
        daze_raw_vector_is_referenced(&process->dos_process, projection->selector)) {
      continue;
    }
    if (uc_mem_write(uc, k_dpmi_ldt_address + (uint32_t)(projection->selector & (uint16_t)~7u),
                     empty, sizeof(empty)) != UC_ERR_OK) {
      return 0;
    }
    (void)daze_raw_vector_projection_forget_selector(run->raw_vector_projections,
                                                     sizeof(run->raw_vector_projections) /
                                                       sizeof(run->raw_vector_projections[0]),
                                                     projection->selector);
    changed = 1;
  }
  if (!run->raw_vector_snapshot_valid)
    return changed ? daze_flush_translation_cache(uc, metrics) : 1;
  for (size_t vector = 0; vector < 256; ++vector) {
    const uint16_t old_segment = run->raw_vector_snapshot_segment[vector];
    const uint16_t old_offset = run->raw_vector_snapshot_offset[vector];
    const uint16_t selector = process->dos_process.dos_vector_segment[vector];
    const uint16_t offset = process->dos_process.dos_vector_offset[vector];
    if ((old_segment == selector && old_offset == offset) || selector == 0 ||
        !run->raw_vector_snapshot_child_active ||
        !daze_raw_vector_projection_eligible(
          &process->dos_memory, run->raw_vector_snapshot_allocation_segment, selector, offset)) {
      continue;
    }
    int already_owned = 0;
    for (size_t index = 0;
         index < sizeof(run->raw_vector_projections) / sizeof(run->raw_vector_projections[0]);
         ++index) {
      if (run->raw_vector_projections[index].in_use &&
          run->raw_vector_projections[index].selector == selector) {
        already_owned = 1;
        break;
      }
    }
    if (already_owned || !daze_raw_vector_descriptor_is_empty(uc, selector)) continue;
    int has_projection_slot = 0;
    for (size_t index = 0;
         index < sizeof(run->raw_vector_projections) / sizeof(run->raw_vector_projections[0]);
         ++index) {
      if (!run->raw_vector_projections[index].in_use) {
        has_projection_slot = 1;
        break;
      }
    }
    if (!has_projection_slot) continue;
    const DazeDosAllocation *const allocation =
      daze_raw_vector_allocation(&process->dos_memory, run->raw_vector_snapshot_allocation_segment);
    if (allocation == NULL) continue;
    uint8_t descriptor[8] = {0};
    if (!daze_raw_vector_projection_descriptor(allocation, selector, descriptor)) continue;
    if (uc_mem_write(uc, k_dpmi_ldt_address + (uint32_t)(selector & (uint16_t)~7u), descriptor,
                     sizeof(descriptor)) != UC_ERR_OK) {
      return 0;
    }
    if (!daze_raw_vector_projection_record(
          run->raw_vector_projections,
          sizeof(run->raw_vector_projections) / sizeof(run->raw_vector_projections[0]), selector,
          allocation->segment, allocation->paragraphs, 1)) {
      return 0;
    }
    changed = 1;
  }
  return changed ? daze_flush_translation_cache(uc, metrics) : 1;
}

static int flush_translation_cache(uc_engine *uc, DazeMetrics *metrics) {
  daze_metrics_record_translation_cache_flush(metrics);
  return uc_ctl_flush_tb(uc) == UC_ERR_OK;
}

int daze_withdraw_raw_vector_projections(uc_engine *uc, DazeUnicornRunState *run,
                                         DazeMetrics *metrics, uint16_t allocation_segment) {
  uint8_t empty[8] = {0};
  int changed = 0;
  for (size_t index = 0;
       index < sizeof(run->raw_vector_projections) / sizeof(run->raw_vector_projections[0]);
       ++index) {
    DazeRawVectorProjection *const projection = &run->raw_vector_projections[index];
    if (!projection->in_use || projection->allocation_segment != allocation_segment) continue;
    if (uc_mem_write(uc, k_dpmi_ldt_address + (uint32_t)(projection->selector & (uint16_t)~7u),
                     empty, sizeof(empty)) != UC_ERR_OK) {
      return 0;
    }
    (void)daze_raw_vector_projection_forget_allocation(projection, 1, allocation_segment);
    changed = 1;
  }
  return !changed || flush_translation_cache(uc, metrics);
}

void daze_print_registers(uc_engine *uc) {
  uint16_t ax, bx, cx, dx, cs, ds, es, ss, ip, sp;
  uc_reg_read(uc, UC_X86_REG_AX, &ax);
  uc_reg_read(uc, UC_X86_REG_BX, &bx);
  uc_reg_read(uc, UC_X86_REG_CX, &cx);
  uc_reg_read(uc, UC_X86_REG_DX, &dx);
  uc_reg_read(uc, UC_X86_REG_CS, &cs);
  uc_reg_read(uc, UC_X86_REG_DS, &ds);
  uc_reg_read(uc, UC_X86_REG_ES, &es);
  uc_reg_read(uc, UC_X86_REG_SS, &ss);
  uc_reg_read(uc, UC_X86_REG_IP, &ip);
  uc_reg_read(uc, UC_X86_REG_SP, &sp);
  fprintf(stderr,
          "  AX=%04x BX=%04x CX=%04x DX=%04x  CS:IP=%04x:%04x  "
          "DS=%04x ES=%04x SS:SP=%04x:%04x\n",
          ax, bx, cx, dx, cs, ip, ds, es, ss, sp);
}

void daze_trace_debug(const DazeUnicornEngine *engine, const char *format, ...) {
  if (!engine->debug) return;
  va_list args;
  va_start(args, format);
  vfprintf(stderr, format, args);
  va_end(args);
}

int daze_flush_translation_cache(uc_engine *uc, DazeMetrics *metrics) {
  return flush_translation_cache(uc, metrics);
}

int daze_invalidate_translation_cache(uc_engine *uc, DazeMetrics *metrics, uint64_t address,
                                      uint64_t end) {
  daze_metrics_record_translation_cache_targeted_invalidation(metrics);
  return uc_ctl_remove_cache(uc, address, end) == UC_ERR_OK;
}

static int direct_interrupt_in_place(uint8_t interrupt) {
  /* These host gates can change CR0, segment caches, or the resume address,
   * so they require explicit stop/resume rather than in-place dispatch. */
  return interrupt != DAZE_INT_STATE_SAVE_GATE && interrupt != DAZE_INT_RAW_SWITCH_GATE &&
         interrupt != DAZE_INT_DOS_PROXY && interrupt != DAZE_INT_DPMI_ENTRY;
}

static void print_trace_line(uc_engine *uc, uint64_t linear_address) {
  uint16_t cs, ss, ds, es, fs, gs, ip, sp, ax, bx, cx, dx, di, bp, si;
  uint32_t cr0, eflags;
  uc_reg_read(uc, UC_X86_REG_CS, &cs);
  uc_reg_read(uc, UC_X86_REG_IP, &ip);
  uc_reg_read(uc, UC_X86_REG_SS, &ss);
  uc_reg_read(uc, UC_X86_REG_SP, &sp);
  uc_reg_read(uc, UC_X86_REG_DS, &ds);
  uc_reg_read(uc, UC_X86_REG_ES, &es);
  uc_reg_read(uc, UC_X86_REG_FS, &fs);
  uc_reg_read(uc, UC_X86_REG_GS, &gs);
  uc_reg_read(uc, UC_X86_REG_AX, &ax);
  uc_reg_read(uc, UC_X86_REG_BX, &bx);
  uc_reg_read(uc, UC_X86_REG_CX, &cx);
  uc_reg_read(uc, UC_X86_REG_DX, &dx);
  uc_reg_read(uc, UC_X86_REG_DI, &di);
  uc_reg_read(uc, UC_X86_REG_BP, &bp);
  uc_reg_read(uc, UC_X86_REG_SI, &si);
  uc_reg_read(uc, UC_X86_REG_CR0, &cr0);
  uc_reg_read(uc, UC_X86_REG_EFLAGS, &eflags);
  char bytes[3 * 8 + 1] = "?";
  {
    uint8_t raw[8];
    if (uc_mem_read(uc, linear_address, raw, sizeof(raw)) == UC_ERR_OK) {
      int offset = 0;
      for (size_t index = 0; index < sizeof(raw); ++index) {
        offset += sprintf(bytes + offset, "%02x ", raw[index]);
      }
    }
  }
  fprintf(stderr,
          "  trace CS:IP=%04x:%04x SS:SP=%04x:%04x DS=%04x ES=%04x "
          "FS=%04x GS=%04x AX=%04x BX=%04x CX=%04x DX=%04x DI=%04x SI=%04x BP=%04x "
          "CR0=%08" PRIx32 " EFLAGS=%08" PRIx32 " bytes=[%s]\n",
          cs, ip, ss, sp, ds, es, fs, gs, ax, bx, cx, dx, di, si, bp, cr0, eflags, bytes);
}

void daze_on_interrupt(uc_engine *uc, uint32_t interrupt, void *user_data) {
  DazeUnicornInterruptContext *interrupt_context = user_data;
  if (interrupt_context == NULL) return;
  DazeUnicornContext *context = interrupt_context->context;
  DazeDosfsFileService *files = interrupt_context->files;
  daze_metrics_record_interrupt(&context->engine.metrics, (uint8_t)interrupt);
  context->run.interrupt_number = (uint8_t)interrupt;
  /* Claim only protected #NP with an installed 0203h handler and a matching selector
   * fault; software INT 0Bh is not that fault. */
  if (interrupt == DAZE_INT_SEGMENT_NOT_PRESENT && !context->run.terminated) {
    DazeDpmiExceptionFault fault;
    if (daze_dpmi_exception_classify(uc, &context->process.dpmi, &fault) &&
        daze_dpmi_exception_transfer(uc, &context->engine, &context->run, &context->process.dpmi,
                                     &fault)) {
      return;
    }
    /* A transfer armed for an earlier fault must not outlive this boundary. */
    daze_dpmi_exception_transfer_disarm(uc, &context->run);
  }
  if (interrupt != DAZE_INT_GP_FAULT && direct_interrupt_in_place((uint8_t)interrupt)) {
    /* UC_HOOK_INTR is called after Unicorn advances IP beyond INT.  Service
     * ordinary calls in-place; only a dispatcher-requested re-entry needs a
     * stop so the outer loop can supply its explicit begin address. */
    context->run.interrupt_already_advanced = 1;
    const int handled = daze_dispatch_interrupt(uc, (uint8_t)interrupt, &context->engine,
                                                &context->run, &context->process, files);
    context->run.interrupt_already_advanced = 0;
    if (handled && !context->run.use_resume_address && !context->run.terminated) {
      context->run.continue_run = 0;
      return;
    }
    if (handled && (context->run.use_resume_address || context->run.terminated)) {
      context->run.stopped = 1;
      daze_metrics_record_stop(&context->engine.metrics);
      uc_emu_stop(uc);
      return;
    }
  }
  if (interrupt == DAZE_INT_GP_FAULT) {
    uint16_t cs;
    uint16_t ip;
    uint32_t cr0 = 0;
    uc_reg_read(uc, UC_X86_REG_CS, &cs);
    uc_reg_read(uc, UC_X86_REG_IP, &ip);
    uc_reg_read(uc, UC_X86_REG_CR0, &cr0);
    fprintf(stderr, "  #GP fault at %04x:%04x, CR0.PE=%u, last executed linear=%08" PRIx64 "\n", cs,
            ip, (cr0 >> 0) & 1u, context->engine.have_code ? context->engine.last_code_address : 0);
    uint8_t raw[8];
    uint64_t fault_linear = ((uint32_t)cs << 4) + ip;
    if ((cr0 & 1u) != 0) {
      uint32_t code_base = 0;
      if (daze_dpmi_selector_base(uc, cs, &code_base)) {
        fault_linear = code_base + ip;
      } else if (context->engine.full_code_hook && context->engine.have_code) {
        fault_linear = context->engine.last_code_address;
      }
    } else if (context->engine.full_code_hook && context->engine.have_code) {
      fault_linear = context->engine.last_code_address;
    }
    if (uc_mem_read(uc, fault_linear, raw, sizeof(raw)) == UC_ERR_OK) {
      fprintf(stderr, "  fault-site bytes: ");
      for (size_t index = 0; index < sizeof(raw); ++index) {
        fprintf(stderr, "%02x ", raw[index]);
      }
      fprintf(stderr, "\n");
      if (raw[0] == 0x8e && raw[1] == 0x06 && raw[2] == 0x8c && raw[3] == 0x01) {
        uint16_t selector = 0;
        if (uc_mem_read(uc, context->process.dpmi.client_data_base + 0x018c, &selector,
                        sizeof(selector)) == UC_ERR_OK) {
          fprintf(stderr, "  diagnostic: attempted ES selector from DS:018c is %04x\n", selector);
        }
      }
      if (raw[0] == 0x26 && raw[1] == 0x8e && raw[2] == 0x1e) {
        const uint16_t es = get_reg16(uc, UC_X86_REG_ES);
        const uint16_t offset = daze_read_u16(raw + 3);
        uint16_t selector = 0;
        uint32_t es_base = 0;
        uint32_t selector_base = 0;
        if (daze_dpmi_selector_base(uc, es, &es_base) &&
            uc_mem_read(uc, es_base + offset, &selector, sizeof(selector)) == UC_ERR_OK) {
          const int selector_valid = daze_dpmi_selector_base(uc, selector, &selector_base);
          fprintf(stderr,
                  "  diagnostic: MOV DS, ES:%04x reads selector %04x (%s, base=%08" PRIx32 ")\n",
                  offset, selector, selector_valid ? "resolves" : "invalid", selector_base);
        }
      }
      if (raw[0] == 0x2e && raw[1] == 0x8e && raw[2] == 0x2e && raw[3] == 0x1e && raw[4] == 0x00) {
        uint16_t selector = 0;
        if (uc_mem_read(uc, context->process.dpmi.client_code_base + 0x001e, &selector,
                        sizeof(selector)) == UC_ERR_OK) {
          fprintf(stderr, "  diagnostic: attempted GS selector from CS:001e is %04x\n", selector);
        }
      }
      if (raw[0] == 0xc4 && raw[1] == 0x3e) {
        const uint16_t ds = get_reg16(uc, UC_X86_REG_DS);
        const uint16_t offset = daze_read_u16(raw + 2);
        uint32_t base = 0;
        uint16_t pointer[2] = {0};
        if (daze_dpmi_selector_base(uc, ds, &base) &&
            uc_mem_read(uc, base + offset, pointer, sizeof(pointer)) == UC_ERR_OK) {
          fprintf(stderr, "  diagnostic: LES DS:%04x contains %04x:%04x\n", offset, pointer[1],
                  pointer[0]);
        }
      }
      if (raw[0] == 0xc5 && raw[1] == 0x16) {
        const uint16_t ds = get_reg16(uc, UC_X86_REG_DS);
        const uint16_t offset = daze_read_u16(raw + 2);
        uint32_t base = 0;
        uint16_t pointer[2] = {0};
        if (daze_dpmi_selector_base(uc, ds, &base) &&
            uc_mem_read(uc, base + offset, pointer, sizeof(pointer)) == UC_ERR_OK) {
          fprintf(stderr, "  diagnostic: LDS DS:%04x contains %04x:%04x\n", offset, pointer[1],
                  pointer[0]);
        }
      }
    }
    if (protected_dos_continuation_declined(uc, &context->run, cs, fault_linear) &&
        protected_dos_continuation_serve(uc, &context->engine, &context->run, &context->process,
                                         files)) {
      return;
    }
    if (context->engine.recent_code_count != 0) {
      fprintf(stderr, "  preceding guest instructions (oldest first):\n");
      const size_t capacity =
        sizeof(context->engine.recent_code) / sizeof(context->engine.recent_code[0]);
      const size_t start =
        (context->engine.recent_code_next + capacity - context->engine.recent_code_count) %
        capacity;
      for (size_t index = 0; index < context->engine.recent_code_count; ++index) {
        const CodeTrace *entry = &context->engine.recent_code[(start + index) % capacity];
        fprintf(stderr, "    %04x:%04x linear=%08" PRIx64 " bytes=", entry->cs, entry->ip,
                entry->linear_address);
        for (size_t byte = 0; byte < sizeof(entry->bytes); ++byte) {
          fprintf(stderr, "%02x%s", entry->bytes[byte],
                  byte + 1 == sizeof(entry->bytes) ? "\n" : " ");
        }
      }
    }
  }
  fprintf(stderr, "interrupt %02" PRIx32 "h encountered (stopping probe)\n", interrupt);
  daze_print_registers(uc);
  daze_dpmi_exception_transfer_disarm(uc, &context->run);
  context->run.stopped = 1;
  daze_metrics_record_stop(&context->engine.metrics);
  uc_emu_stop(uc);
}

void daze_on_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
  (void)size;
  DazeUnicornContext *context = user_data;
  if (context->engine.metrics.enabled) {
    context->engine.metrics.code_hook_calls++;
    if (context->engine.full_code_hook) context->engine.metrics.guest_instructions++;
  }
  /* Timing every callback distorts this hot path.  Sample one in 1,024
   * callbacks instead, then scale the representative mean in the report. */
  const int sample_hook =
    context->engine.metrics.enabled && (context->engine.metrics.code_hook_calls & 1023u) == 0;
  const uint64_t hook_started = sample_hook ? monotonic_nanoseconds() : 0;
  uint8_t opcode[2] = {0};
  uint16_t cs;
  uint16_t ip;
  uint32_t cr0;
  uc_reg_read(uc, UC_X86_REG_CS, &cs);
  uc_reg_read(uc, UC_X86_REG_IP, &ip);
  uc_reg_read(uc, UC_X86_REG_CR0, &cr0);
  const uint64_t linear_address = (cr0 & 1u) != 0 ? address : ((uint32_t)cs << 4) + ip;
  if (context->run.rm_procedure_active && (cr0 & 1u) == 0 &&
      linear_address == k_dpmi_rm_gate_linear) {
    if (!daze_setup_complete_dpmi_rm_procedure(uc, &context->engine, &context->run)) {
      fprintf(stderr, "  DPMI 31h/0301h cannot return to protected mode\n");
    }
    context->run.stopped = 1;
    daze_metrics_record_stop(&context->engine.metrics);
    uc_emu_stop(uc);
    return;
  }
  context->engine.last_code_address = linear_address;
  context->engine.have_code = 1;
  if (uc_mem_read(uc, linear_address, opcode, sizeof(opcode)) == UC_ERR_OK &&
      daze_unicorn_trace_full_hook(&context->engine.diagnostic_trace)) {
    uint8_t recent_bytes[8];
    if (uc_mem_read(uc, linear_address, recent_bytes, sizeof(recent_bytes)) == UC_ERR_OK) {
      const size_t slot = context->engine.recent_code_next;
      context->engine.recent_code[slot].linear_address = linear_address;
      context->engine.recent_code[slot].cs = cs;
      context->engine.recent_code[slot].ip = ip;
      memcpy(context->engine.recent_code[slot].bytes, recent_bytes, sizeof(recent_bytes));
      context->engine.recent_code_next =
        (slot + 1) % (sizeof(context->engine.recent_code) / sizeof(context->engine.recent_code[0]));
      if (context->engine.recent_code_count <
          sizeof(context->engine.recent_code) / sizeof(context->engine.recent_code[0])) {
        context->engine.recent_code_count++;
      }
    }
  }
  const int trace_record =
    daze_unicorn_trace_record(&context->engine.diagnostic_trace, linear_address);
  if (trace_record == 2) {
    fprintf(stderr, "  Unicorn trace truncated after %u instruction records; guest continues\n",
            DAZE_TRACE_MAX_RECORDS);
  } else if (trace_record == 1) {
    print_trace_line(uc, linear_address);
    const uint32_t dump_size = context->engine.diagnostic_trace.dump_size;
    if (dump_size != 0) {
      const uint32_t dump_address = context->engine.diagnostic_trace.dump_address;
      uint8_t bytes[64];
      if (uc_mem_read(uc, dump_address, bytes, dump_size) == UC_ERR_OK) {
        fprintf(stderr, "  trace memory %08" PRIx32 ":", dump_address);
        for (uint32_t index = 0; index < dump_size; ++index)
          fprintf(stderr, " %02x", bytes[index]);
        fputc('\n', stderr);
      } else {
        fprintf(stderr, "  trace memory %08" PRIx32 ": unavailable\n", dump_address);
      }
    }
  }

  if (opcode[0] != 0xcd) {
    goto done;
  }
  if (direct_interrupt_in_place(opcode[1])) {
    goto done;
  }
  daze_metrics_record_interrupt(&context->engine.metrics, opcode[1]);
  context->run.interrupt_number = opcode[1];
  if (opcode[1] == 0xd6) {
    fprintf(stderr, "  diagnostic: INT D6h at linear %08" PRIx64 "\n", linear_address);
    fprintf(stderr, "  preceding guest instructions (oldest first):\n");
    const size_t capacity =
      sizeof(context->engine.recent_code) / sizeof(context->engine.recent_code[0]);
    const size_t start =
      (context->engine.recent_code_next + capacity - context->engine.recent_code_count) % capacity;
    for (size_t index = 0; index < context->engine.recent_code_count; ++index) {
      const size_t slot = (start + index) % capacity;
      const CodeTrace *entry = &context->engine.recent_code[slot];
      fprintf(stderr, "    %04x:%04x linear=%08" PRIx64 " bytes=", entry->cs, entry->ip,
              entry->linear_address);
      for (size_t byte = 0; byte < sizeof(entry->bytes); ++byte) {
        fprintf(stderr, "%02x%s", entry->bytes[byte],
                byte + 1 == sizeof(entry->bytes) ? "\n" : " ");
      }
    }
  }
  context->run.stopped = 1;
  daze_metrics_record_stop(&context->engine.metrics);
  uc_emu_stop(uc);

done:
  if (sample_hook) {
    const uint64_t hook_finished = monotonic_nanoseconds();
    if (hook_finished >= hook_started) {
      daze_metrics_record_code_hook_sample(&context->engine.metrics, hook_finished - hook_started);
    }
  }
}

static int guest_segment_base(uc_engine *uc, uint16_t segment, uint32_t *base) {
  uint32_t cr0 = 0;
  if (uc == NULL || base == NULL || uc_reg_read(uc, UC_X86_REG_CR0, &cr0) != UC_ERR_OK) return 0;
  if ((cr0 & 1u) != 0) return daze_dpmi_selector_base(uc, segment, base);
  *base = (uint32_t)segment << 4;
  return 1;
}

int daze_read_guest_asciiz(uc_engine *uc, uint16_t segment, uint16_t offset, char *output,
                           size_t output_size) {
  uint32_t base = 0;
  if (output_size == 0) {
    return 0;
  }
  if (!guest_segment_base(uc, segment, &base)) {
    output[0] = '\0';
    return 0;
  }
  for (size_t index = 0; index + 1 < output_size; ++index) {
    if (base > UINT32_MAX - offset - index ||
        uc_mem_read(uc, base + offset + index, output + index, 1) != UC_ERR_OK) {
      output[0] = '\0';
      return 0;
    }
    if (output[index] == '\0') {
      return 1;
    }
  }
  output[0] = '\0';
  return 0;
}

int daze_read_guest_bytes(uc_engine *uc, uint16_t segment, uint16_t offset, void *output,
                          size_t output_size) {
  uint32_t base = 0;
  /* The end address must not wrap past 4GB: a wrapped range could land in
   * mapped low memory and succeed for the wrong bytes. */
  return guest_segment_base(uc, segment, &base) && base <= UINT32_MAX - offset &&
         output_size <= UINT32_MAX - (base + offset) &&
         uc_mem_read(uc, base + offset, output, output_size) == UC_ERR_OK;
}

int daze_write_guest_bytes(uc_engine *uc, uint16_t segment, uint16_t offset, const void *input,
                           size_t input_size) {
  uint32_t base = 0;
  /* See read path: reject a range that would wrap past 4GB. */
  return guest_segment_base(uc, segment, &base) && base <= UINT32_MAX - offset &&
         input_size <= UINT32_MAX - (base + offset) &&
         uc_mem_write(uc, base + offset, input, input_size) == UC_ERR_OK;
}

void skip_interrupt_instruction(uc_engine *uc, DazeUnicornRunState *run) {
  if (run->interrupt_already_advanced) return;
  const uint16_t ip = get_reg16(uc, UC_X86_REG_IP);
  set_reg16(uc, UC_X86_REG_IP, (uint16_t)(ip + 2));
  /* In protected mode the selector is not a real-mode segment. Resume from
   * the hooked instruction's known linear address after the two-byte INT. */
  run->continue_run = 1;
}

void daze_protected_dos_continuation_clear(DazeUnicornRunState *run) {
  if (run == NULL) return;
  if (run->dos_continuation.engine != NULL && run->dos_continuation.decline_hook != 0) {
    uc_hook_del(run->dos_continuation.engine, run->dos_continuation.decline_hook);
  }
  if (run->dos_continuation.engine != NULL && run->dos_continuation.return_hook != 0) {
    uc_hook_del(run->dos_continuation.engine, run->dos_continuation.return_hook);
  }
  if (run->dos_continuation.caller_context != NULL) {
    uc_context_free(run->dos_continuation.caller_context);
  }
  free(run->dos_continuation.continuation_context);
  run->dos_continuation = (DazeProtectedDosContinuation){0};
}

static int protected_dos_continuation_declined(uc_engine *uc, const DazeUnicornRunState *run,
                                               uint16_t cs, uint64_t fault_linear) {
  const DazeProtectedDosContinuation *continuation = &run->dos_continuation;
  if (!continuation->active || continuation->caller_context == NULL) return 0;
  if (continuation->delivered_cs == 0 || cs != continuation->delivered_cs) return 0;
  uint32_t cr0 = 0;
  uc_reg_read(uc, UC_X86_REG_CR0, &cr0);
  if ((cr0 & 1u) == 0) return 0;
  if (get_reg16(uc, UC_X86_REG_SS) != continuation->frame_ss ||
      get_reg32(uc, UC_X86_REG_ESP) != continuation->frame_esp) {
    return 0;
  }
  uint8_t bytes[5] = {0};
  if (uc_mem_read(uc, fault_linear, bytes, sizeof(bytes)) != UC_ERR_OK) return 0;
  return bytes[0] == 0xea && bytes[1] == 0x00 && bytes[2] == 0x00 && bytes[3] == 0x00 &&
         bytes[4] == 0x00;
}

static int protected_dos_continuation_serve(uc_engine *uc, DazeUnicornEngine *engine,
                                            DazeUnicornRunState *run,
                                            DazeDosRuntimeProcessState *process,
                                            DazeDosfsFileService *files) {
  if (uc_context_restore(uc, run->dos_continuation.caller_context) != UC_ERR_OK) return 0;
  const uint16_t request_ax = get_reg16(uc, UC_X86_REG_AX);
  const int previous_host_dos_gate = run->host_dos_gate;
  const int previous_already_advanced = run->interrupt_already_advanced;
  run->host_dos_gate = 1;
  run->interrupt_already_advanced = 1;
  const int handled = daze_dispatch_interrupt(uc, DAZE_INT_DOS, engine, run, process, files);
  run->host_dos_gate = previous_host_dos_gate;
  run->interrupt_already_advanced = previous_already_advanced;
  daze_protected_dos_continuation_clear(run);
  if (!handled) {
    fprintf(
      stderr,
      "  protected DOS-vector fallback: declined INT 21h/%04xh was not serviced by the host\n",
      request_ax);
    return 0;
  }
  daze_trace_debug(engine,
                   "  protected DOS-vector fallback: declined INT 21h/%04xh serviced at the host\n",
                   request_ax);
  if (!run->use_resume_address) {
    run->resume_address =
      ((uint32_t)get_reg16(uc, UC_X86_REG_CS) << 4) + get_reg16(uc, UC_X86_REG_IP);
    run->use_resume_address = 1;
  }
  run->continue_run = 0;
  run->stopped = 1;
  daze_metrics_record_stop(&engine->metrics);
  uc_emu_stop(uc);
  return 1;
}

/* Unicorn normally reports DPMILOAD's null far jump as #GP, where the
 * continuation above recognises the vector's explicit refusal.  On the locked
 * 16-bit exception stack it instead retries the instruction without delivering
 * #GP.  This one active-delivery hook recognises precisely the same refusal
 * before Unicorn executes it, so both CPU behaviours use the same host DOS
 * service and restored caller context. */
static void daze_on_protected_dos_continuation_code(uc_engine *uc, uint64_t address, uint32_t size,
                                                    void *user_data) {
  (void)size;
  DazeUnicornContinuationContext *continuation_context = user_data;
  if (continuation_context == NULL || continuation_context->run == NULL ||
      continuation_context->engine == NULL || continuation_context->process == NULL ||
      continuation_context->files == NULL)
    return;
  DazeUnicornRunState *run = continuation_context->run;
  const uint16_t cs = get_reg16(uc, UC_X86_REG_CS);
  if (protected_dos_continuation_declined(uc, run, cs, address)) {
    (void)protected_dos_continuation_serve(uc, continuation_context->engine, run,
                                           continuation_context->process,
                                           continuation_context->files);
  }
}

/* IRET consumes the decline classifier's stack witness. Retire its hook at the caller
 * return address to avoid matching unrelated execution. */
static void daze_on_protected_dos_return_code(uc_engine *uc, uint64_t address, uint32_t size,
                                              void *user_data) {
  (void)size;
  (void)address;
  DazeUnicornRunState *run = user_data;
  if (run == NULL || !run->dos_continuation.active) return;
  uint32_t cr0 = 0;
  uc_reg_read(uc, UC_X86_REG_CR0, &cr0);
  if ((cr0 & 1u) == 0) return;
  if (get_reg16(uc, UC_X86_REG_CS) != run->dos_continuation.return_cs ||
      get_reg32(uc, UC_X86_REG_EIP) != run->dos_continuation.return_eip ||
      get_reg16(uc, UC_X86_REG_SS) != run->dos_continuation.frame_ss ||
      get_reg32(uc, UC_X86_REG_ESP) !=
        run->dos_continuation.frame_esp + run->dos_continuation.frame_size) {
    return;
  }
  daze_protected_dos_continuation_clear(run);
}

/* Unicorn 2.1.4 reports #NP at the faulting opcode and retries without building
 * a frame or entering the IDT. Explicit DPMI delivery publishes the legacy
 * frame on the locked stack; a guest gateway loads SS before entering the handler. */

/* Reject null selectors and out-of-range entries; #NP requires an existing non-present
 * descriptor. */
static int daze_dpmi_selector_nonpresent(uc_engine *uc, uint16_t selector) {
  const uint16_t index = (uint16_t)(selector >> 3);
  if (selector == 0 || index >= k_dpmi_ldt_size / 8) return 0;
  const uint32_t table = (selector & 4u) != 0 ? k_dpmi_ldt_address : k_dpmi_gdt_address;
  uint8_t descriptor[8];
  return uc_mem_read(uc, table + (uint32_t)index * 8, descriptor, sizeof(descriptor)) ==
           UC_ERR_OK &&
         (descriptor[5] & 0x80u) == 0;
}

/* The post-EOF far return is admitted only when its own stack frame names a
 * 16-bit protected code selector. Unlike daze_dpmi_selector_code_width(), this
 * inspects a deliberately non-present descriptor, so the present bit must stay
 * out of the type predicate. */
static int daze_dpmi_selector_nonpresent_code16(uc_engine *uc, uint16_t selector) {
  const uint16_t index = (uint16_t)(selector >> 3);
  if (selector == 0 || index >= k_dpmi_ldt_size / 8) return 0;
  const uint32_t table = (selector & 4u) != 0 ? k_dpmi_ldt_address : k_dpmi_gdt_address;
  uint8_t descriptor[8];
  if (uc_mem_read(uc, table + (uint32_t)index * 8, descriptor, sizeof(descriptor)) != UC_ERR_OK)
    return 0;
  return (descriptor[5] & 0x98u) == 0x18u && (descriptor[6] & 0x40u) == 0;
}

int daze_dpmi_exception_classify(uc_engine *uc, const DazeDpmiProcessState *dpmi,
                                 DazeDpmiExceptionFault *fault) {
  if (uc == NULL || dpmi == NULL || fault == NULL) return 0;
  uint32_t cr0 = 0;
  uc_reg_read(uc, UC_X86_REG_CR0, &cr0);
  if ((cr0 & 1u) == 0) return 0;
  /* DPMILOAD's 0203h set-exception-vector is the only reason to reflect a
   * fault: with no installed vector there is no client handler to reach.
   * 0203h records its result in the exception-vector pair, not in the
   * interrupt-vector table 0205h uses. */
  if (dpmi->exception_vector_segment[0x0b] == 0) return 0;
  const uint16_t cs = get_reg16(uc, UC_X86_REG_CS);
  const uint16_t ip = get_reg16(uc, UC_X86_REG_IP);
  if (daze_dpmi_selector_code_width(uc, cs) != 16) return 0;
  uint32_t code_base = 0;
  if (!daze_dpmi_selector_base(uc, cs, &code_base)) return 0;
  DazeDpmiExceptionFault captured;
  memset(&captured, 0, sizeof(captured));
  if (uc_mem_read(uc, code_base + ip, captured.instruction, sizeof(captured.instruction)) !=
      UC_ERR_OK) {
    return 0;
  }
  /* Software INT 0Bh shares the vector but is not #NP. Admit only the supported
   * selector-fault encodings, not arbitrary ModRM forms. */
  uint16_t operand = 0;
  if (captured.instruction[0] == 0x9a) {
    operand = daze_read_u16(captured.instruction + 3);
    captured.instruction_size = 5;
  } else if (captured.instruction[0] == 0xff && captured.instruction[1] == 0x1e) {
    uint32_t data_base = 0;
    uint8_t pointer[4];
    if (!daze_dpmi_selector_base(uc, get_reg16(uc, UC_X86_REG_DS), &data_base) ||
        uc_mem_read(uc, data_base + daze_read_u16(captured.instruction + 2), pointer,
                    sizeof(pointer)) != UC_ERR_OK) {
      return 0;
    }
    operand = daze_read_u16(pointer + 2);
    captured.instruction_size = 4;
  } else if (captured.instruction[0] == 0x26 && captured.instruction[1] == 0xc4 &&
             captured.instruction[2] == 0x3f) {
    uint32_t es_base = 0;
    uint8_t pointer[4];
    if (!daze_dpmi_selector_base(uc, get_reg16(uc, UC_X86_REG_ES), &es_base) ||
        uc_mem_read(uc, es_base + get_reg16(uc, UC_X86_REG_BX), pointer, sizeof(pointer)) !=
          UC_ERR_OK) {
      return 0;
    }
    operand = daze_read_u16(pointer + 2);
    captured.instruction_size = 3;
  } else if (captured.instruction[0] == 0xcb || captured.instruction[0] == 0xca) {
    uint32_t stack_base = 0;
    uint8_t frame[4];
    if (!daze_dpmi_selector_base(uc, get_reg16(uc, UC_X86_REG_SS), &stack_base) ||
        uc_mem_read(uc, stack_base + get_reg16(uc, UC_X86_REG_SP), frame, sizeof(frame)) !=
          UC_ERR_OK) {
      return 0;
    }
    operand = daze_read_u16(frame + 2);
    if (!daze_dpmi_selector_nonpresent_code16(uc, operand)) return 0;
    captured.instruction_size = captured.instruction[0] == 0xcb ? 1 : 3;
  } else {
    return 0;
  }
  if (!daze_dpmi_selector_nonpresent(uc, operand)) return 0;
  if (daze_dpmi_selector_code_width(uc, dpmi->exception_vector_segment[0x0b]) != 16) return 0;
  captured.fault_linear = code_base + ip;
  captured.error_code = operand;
  captured.fault_cs = cs;
  captured.fault_ip = ip;
  captured.fault_ss = get_reg16(uc, UC_X86_REG_SS);
  captured.fault_sp = get_reg16(uc, UC_X86_REG_SP);
  captured.fault_ds = get_reg16(uc, UC_X86_REG_DS);
  captured.fault_es = get_reg16(uc, UC_X86_REG_ES);
  captured.eflags = get_reg32(uc, UC_X86_REG_EFLAGS);
  captured.gprs[0] = get_reg16(uc, UC_X86_REG_AX);
  captured.gprs[1] = get_reg16(uc, UC_X86_REG_BX);
  captured.gprs[2] = get_reg16(uc, UC_X86_REG_CX);
  captured.gprs[3] = get_reg16(uc, UC_X86_REG_DX);
  captured.gprs[4] = get_reg16(uc, UC_X86_REG_SI);
  captured.gprs[5] = get_reg16(uc, UC_X86_REG_DI);
  captured.gprs[6] = get_reg16(uc, UC_X86_REG_BP);
  *fault = captured;
  return 1;
}

DazeDpmiExceptionTransfer *daze_dpmi_exception_record(DazeUnicornRunState *run, unsigned depth) {
  return run != NULL && depth < run->exception_delivery_stack.depth
           ? &run->exception_delivery_stack.records[depth]
           : NULL;
}

DazeDpmiExceptionTransfer *daze_dpmi_exception_active(DazeUnicornRunState *run) {
  return run != NULL && run->exception_delivery_stack.depth != 0
           ? &run->exception_delivery_stack.records[run->exception_delivery_stack.depth - 1]
           : NULL;
}

int daze_dpmi_exception_transfer_dispose_active(uc_engine *uc, DazeUnicornRunState *run) {
  if (uc == NULL || run == NULL) return 0;
  DazeDpmiExceptionTransfer *const transfer = daze_dpmi_exception_active(run);
  if (transfer == NULL) return 0;
  if (transfer->armed) uc_hook_del(uc, transfer->hook);
  if (transfer->return_armed) uc_hook_del(uc, transfer->return_hook);
  if (transfer->successor_armed) uc_hook_del(uc, transfer->successor_hook);
  free(transfer->hook_context);
  memset(transfer, 0, sizeof(*transfer));
  run->exception_delivery_stack.depth--;
  return 1;
}

void daze_dpmi_exception_transfer_disarm(uc_engine *uc, DazeUnicornRunState *run) {
  if (uc == NULL || run == NULL) return;
  while (daze_dpmi_exception_transfer_dispose_active(uc, run)) {
  }
}

static void daze_on_exception_entry(uc_engine *uc, uint64_t address, uint32_t size,
                                    void *user_data) {
  (void)size;
  DazeUnicornExceptionHookContext *hook_context = user_data;
  if (hook_context == NULL || hook_context->run == NULL || hook_context->engine == NULL) return;
  DazeUnicornRunState *run = hook_context->run;
  DazeDpmiExceptionTransfer *const transfer = daze_dpmi_exception_active(run);
  if (transfer == NULL) return;
  if (!transfer->armed || address != transfer->entry_linear) return;
  transfer->entry_reached = 1;
  transfer->entry_cs = get_reg16(uc, UC_X86_REG_CS);
  transfer->entry_ip = get_reg16(uc, UC_X86_REG_IP);
  transfer->entry_ss = get_reg16(uc, UC_X86_REG_SS);
  transfer->entry_sp = get_reg16(uc, UC_X86_REG_SP);
  transfer->entry_ds = get_reg16(uc, UC_X86_REG_DS);
  transfer->entry_es = get_reg16(uc, UC_X86_REG_ES);
  transfer->entry_gprs[0] = get_reg16(uc, UC_X86_REG_AX);
  transfer->entry_gprs[1] = get_reg16(uc, UC_X86_REG_BX);
  transfer->entry_gprs[2] = get_reg16(uc, UC_X86_REG_CX);
  transfer->entry_gprs[3] = get_reg16(uc, UC_X86_REG_DX);
  transfer->entry_gprs[4] = get_reg16(uc, UC_X86_REG_SI);
  transfer->entry_gprs[5] = get_reg16(uc, UC_X86_REG_DI);
  transfer->entry_gprs[6] = get_reg16(uc, UC_X86_REG_BP);
  transfer->entry_eflags = get_reg32(uc, UC_X86_REG_EFLAGS);
  uc_mem_read(uc, transfer->frame_linear, transfer->frame, sizeof(transfer->frame));
  fprintf(stderr,
          "  DPMI exception entry: installed %04x:%04x linear=%08" PRIx64
          " SS:SP=%04x:%04x DS=%04x ES=%04x AX=%04x BX=%04x CX=%04x DX=%04x"
          " SI=%04x DI=%04x BP=%04x EFLAGS=%08" PRIx32 "\n"
          "    frame at %08" PRIx32 " =",
          transfer->entry_cs, transfer->entry_ip, address, transfer->entry_ss, transfer->entry_sp,
          transfer->entry_ds, transfer->entry_es, transfer->entry_gprs[0], transfer->entry_gprs[1],
          transfer->entry_gprs[2], transfer->entry_gprs[3], transfer->entry_gprs[4],
          transfer->entry_gprs[5], transfer->entry_gprs[6], transfer->entry_eflags,
          transfer->frame_linear);
  for (size_t index = 0; index < sizeof(transfer->frame); ++index)
    fprintf(stderr, " %02x", transfer->frame[index]);
  fprintf(stderr, "\n");
  uc_hook_del(uc, transfer->hook);
  transfer->armed = 0;
  transfer->active = 0;
  transfer->entry_linear = 0;
  daze_trace_debug(hook_context->engine, "  DPMI exception entry: continuing to client handler\n");
}

/* Unicorn may retry a later non-present far call without delivering another vector. A
 * temporary hook routes that retry through the same DPMI fault boundary. */
static void daze_on_exception_return_successor(uc_engine *uc, uint64_t address, uint32_t size,
                                               void *user_data) {
  (void)address;
  (void)size;
  DazeUnicornExceptionHookContext *hook_context = user_data;
  if (hook_context == NULL || hook_context->run == NULL || hook_context->engine == NULL ||
      hook_context->dpmi == NULL)
    return;
  DazeUnicornRunState *run = hook_context->run;
  /* Snapshot before disposing: dispose frees this bundle, so nothing may be
   * read back from hook_context afterwards. */
  DazeUnicornEngine *engine = hook_context->engine;
  DazeDpmiProcessState *dpmi = hook_context->dpmi;
  DazeDpmiExceptionTransfer *const transfer = daze_dpmi_exception_active(run);
  if (transfer == NULL) return;
  if (!transfer->successor_armed) return;
  DazeDpmiExceptionFault fault;
  if (!daze_dpmi_exception_classify(uc, dpmi, &fault)) return;
  uc_hook_del(uc, transfer->successor_hook);
  transfer->successor_armed = 0;
  /* Retire the source delivery before allocating its chained successor, or each retry
   * retains a locked-stack slot. */
  if (!daze_dpmi_exception_transfer_dispose_active(uc, run)) return;
  (void)daze_dpmi_exception_transfer(uc, engine, run, dpmi, &fault);
}

/* After the handler's LRET, restore interrupted SS:SP and low EFLAGS through
 * guest MOV SS: a host SS write can leave the locked-stack base cached and
 * cause endless far-call retries. Preserve handler-owned GPRs and data segments.
 * Resume the fault if its selector is now present, otherwise the saved successor. */
static void daze_on_exception_return(uc_engine *uc, uint64_t address, uint32_t size,
                                     void *user_data) {
  (void)size;
  DazeUnicornExceptionHookContext *hook_context = user_data;
  if (hook_context == NULL || hook_context->run == NULL || hook_context->engine == NULL) return;
  DazeUnicornRunState *run = hook_context->run;
  DazeUnicornEngine *engine = hook_context->engine;
  DazeDpmiExceptionTransfer *const transfer = daze_dpmi_exception_active(run);
  if (transfer == NULL) return;
  if (!transfer->return_armed || address != transfer->return_linear) return;
  if (get_reg16(uc, UC_X86_REG_CS) != daze_read_u16(transfer->frame + 2) ||
      get_reg16(uc, UC_X86_REG_IP) != daze_read_u16(transfer->frame)) {
    return;
  }
  const uint16_t original_ss = daze_read_u16(transfer->frame + 14);
  const uint16_t original_sp = daze_read_u16(transfer->frame + 12);
  const uint16_t original_flags = daze_read_u16(transfer->frame + 10);
  uint16_t return_ip = daze_read_u16(transfer->frame);
  const uint16_t return_cs = daze_read_u16(transfer->frame + 2);
  /* Retry the fault IP when the handler makes its selector present; otherwise resume the
   * saved successor. */
  if (!daze_dpmi_selector_nonpresent(uc, transfer->error_code)) {
    return_ip = daze_read_u16(transfer->frame + 6);
    daze_trace_debug(engine, "  DPMI exception retry-present: selector %04x at %04x:%04x\n",
                     transfer->error_code, return_cs, return_ip);
  }
  if (!daze_setup_write_raw_pm_reentry_wrapper(
        uc, run, &engine->metrics, get_reg16(uc, UC_X86_REG_DS), get_reg16(uc, UC_X86_REG_ES),
        original_ss, original_sp, get_reg16(uc, UC_X86_REG_FS), get_reg16(uc, UC_X86_REG_GS),
        get_reg16(uc, UC_X86_REG_AX), get_reg16(uc, UC_X86_REG_BX), get_reg16(uc, UC_X86_REG_CX),
        get_reg16(uc, UC_X86_REG_DX), get_reg16(uc, UC_X86_REG_SI), get_reg16(uc, UC_X86_REG_DI),
        get_reg16(uc, UC_X86_REG_BP), original_flags, return_ip, return_cs)) {
    fprintf(stderr, "  DPMI exception return: could not prepare the guest stack reload\n");
    return;
  }
  transfer->return_reached = 1;
  uc_hook_del(uc, transfer->return_hook);
  transfer->return_armed = 0;
  transfer->active = 0;
  if (transfer->frame_depth != 0) {
    /* The child return wrapper restores parent SS:SP. Its consumed frame can no longer
     * own a successor hook. */
    if (!daze_dpmi_exception_transfer_dispose_active(uc, run)) return;
  } else {
    if (uc_hook_add(uc, &transfer->successor_hook, UC_HOOK_CODE, daze_on_exception_return_successor,
                    hook_context, 1, 0) == UC_ERR_OK)
      transfer->successor_armed = 1;
  }
  set_reg16(uc, UC_X86_REG_CS, k_dpmi_exception_gateway_selector);
  set_reg16(uc, UC_X86_REG_IP,
            (uint16_t)(k_pm_reentry_wrapper - k_dpmi_exception_gateway_linear +
                       k_dpmi_exception_gateway_offset));
  run->resume_address =
    ((uint32_t)k_dpmi_exception_gateway_selector << 4) +
    (k_pm_reentry_wrapper - k_dpmi_exception_gateway_linear + k_dpmi_exception_gateway_offset);
  run->use_resume_address = 1;
  run->stopped = 1;
  daze_metrics_record_stop(&engine->metrics);
  uc_emu_stop(uc);
  daze_trace_debug(engine,
                   "  DPMI exception return: %04x:%04x -> guest stack reload SS:SP=%04x:%04x"
                   " EFLAGS=%04x\n",
                   return_cs, return_ip, original_ss, original_sp, original_flags);
}

int daze_dpmi_exception_transfer(uc_engine *uc, DazeUnicornEngine *engine, DazeUnicornRunState *run,
                                 DazeDpmiProcessState *dpmi, const DazeDpmiExceptionFault *fault) {
  if (uc == NULL || engine == NULL || run == NULL || dpmi == NULL || fault == NULL) return 0;
  if (run->exception_delivery_stack.depth == k_dpmi_exception_max_depth) return 0;
  const uint16_t handler_segment = dpmi->exception_vector_segment[0x0b];
  const uint16_t handler_offset = dpmi->exception_vector_offset[0x0b];
  uint32_t handler_base = 0;
  if (handler_segment == 0 || !daze_dpmi_selector_base(uc, handler_segment, &handler_base)) {
    return 0;
  }
  DazeDpmiExceptionTransfer *const transfer =
    &run->exception_delivery_stack.records[run->exception_delivery_stack.depth];
  /* A chained client exception handler can fault before its outer legacy frame
   * is consumed. Keep the outer 16-byte frame intact in a separate bounded
   * locked-stack slot; the gateway must load the matching SP for each delivery. */
  const unsigned frame_depth = run->exception_delivery_stack.depth;
  const uint16_t locked_stack_sp =
    (uint16_t)(k_dpmi_exception_locked_stack_sp - frame_depth * 0x20u);
  if (locked_stack_sp < DAZE_DPMI_EXCEPTION_FRAME_SIZE) return 0;
  DazeDpmiExceptionFrameInput input;
  memset(&input, 0, sizeof(input));
  input.frame.return_ip = (uint16_t)(fault->fault_ip + fault->instruction_size);
  input.frame.return_cs = fault->fault_cs;
  input.frame.error_code = fault->error_code;
  input.frame.fault_ip = fault->fault_ip;
  input.frame.fault_cs = fault->fault_cs;
  input.frame.flags = (uint16_t)fault->eflags;
  input.frame.stack_pointer = fault->fault_sp;
  input.frame.stack_segment = fault->fault_ss;
  input.locked_stack_base = k_dpmi_exception_locked_stack_base;
  input.locked_stack_sp = locked_stack_sp;
  input.guest_range_base = 0;
  input.guest_range_limit = k_memory_size - 1;
  uint32_t frame_linear = 0;
  uint8_t frame[DAZE_DPMI_EXCEPTION_FRAME_SIZE];
  if (!daze_dpmi_exception_frame_build(&input, &frame_linear, frame)) return 0;
  uint32_t gateway_linear = 0;
  if (uc_mem_write(uc, frame_linear, frame, sizeof(frame)) != UC_ERR_OK ||
      !daze_setup_write_exception_gateway(uc, &engine->metrics, handler_segment, handler_offset,
                                          locked_stack_sp, &gateway_linear)) {
    return 0;
  }
  /* Read the gateway address from its live descriptor; refuse transfer if it no longer
   * matches the reserved address. */
  if (gateway_linear != k_dpmi_exception_gateway_linear) {
    fprintf(stderr,
            "  DPMI exception gateway linear %08" PRIx32 " != published %08x, transfer refused\n",
            gateway_linear, k_dpmi_exception_gateway_linear);
    return 0;
  }
  /* The hooks outlive this frame (they fire during later uc_emu_starts),
   * so their user_data is heap-allocated per delivery and freed with the
   * record in daze_dpmi_exception_transfer_dispose_active. */
  DazeUnicornExceptionHookContext *hook_context = malloc(sizeof(*hook_context));
  if (hook_context == NULL) return 0;
  hook_context->run = run;
  hook_context->engine = engine;
  hook_context->dpmi = dpmi;
  uc_hook hook = 0;
  const uint64_t entry_linear = (uint64_t)handler_base + (uint64_t)handler_offset;
  if (uc_hook_add(uc, &hook, UC_HOOK_CODE, daze_on_exception_entry, hook_context, entry_linear,
                  entry_linear) != UC_ERR_OK) {
    free(hook_context);
    return 0;
  }
  uint32_t return_base = 0;
  const uint16_t return_cs = input.frame.return_cs;
  const uint16_t return_ip = input.frame.return_ip;
  if (!daze_dpmi_selector_base(uc, return_cs, &return_base)) {
    uc_hook_del(uc, hook);
    free(hook_context);
    return 0;
  }
  uc_hook return_hook = 0;
  const uint64_t return_linear = (uint64_t)return_base + return_ip;
  if (uc_hook_add(uc, &return_hook, UC_HOOK_CODE, daze_on_exception_return, hook_context,
                  return_linear, return_linear) != UC_ERR_OK) {
    uc_hook_del(uc, hook);
    free(hook_context);
    return 0;
  }
  memset(transfer, 0, sizeof(*transfer));
  transfer->hook_context = hook_context;
  transfer->error_code = fault->error_code;
  transfer->hook = hook;
  transfer->return_hook = return_hook;
  transfer->entry_linear = entry_linear;
  transfer->return_linear = return_linear;
  transfer->frame_linear = frame_linear;
  transfer->frame_depth = frame_depth;
  memcpy(transfer->frame, frame, sizeof(transfer->frame));
  transfer->armed = 1;
  transfer->return_armed = 1;
  transfer->active = 1;
  run->exception_delivery_stack.depth++;
  /* The gateway and handler must load SS:SP and client CS in guest code; the host sets
   * only gateway CS:IP. */
  set_reg16(uc, UC_X86_REG_CS, k_dpmi_exception_gateway_selector);
  set_reg16(uc, UC_X86_REG_IP, k_dpmi_exception_gateway_offset);
  /* Unicorn's first fetch is resume + descriptor_base - (selector << 4).
   * Pass (selector << 4) + offset; a descriptor-linear address would fetch
   * unrelated memory when the protected base differs from selector << 4. */
  run->resume_address =
    ((uint32_t)k_dpmi_exception_gateway_selector << 4) + k_dpmi_exception_gateway_offset;
  run->use_resume_address = 1;
  if (engine->debug) {
    uint8_t fault_bytes[8] = {0};
    const int have_fault_bytes =
      uc_mem_read(uc, fault->fault_linear, fault_bytes, sizeof(fault_bytes)) == UC_ERR_OK;
    daze_trace_debug(engine,
                     "  DPMI exception transfer: %04x:%04x #%04x linear=%08" PRIx32
                     " bytes=%02x %02x %02x %02x %02x%s -> gateway %04x:%04x"
                     " linear=%08" PRIx32 ", resume=%08" PRIx32 ", frame=%08" PRIx32
                     ", installed %04x:%04x\n",
                     fault->fault_cs, fault->fault_ip, fault->error_code, fault->fault_linear,
                     fault_bytes[0], fault_bytes[1], fault_bytes[2], fault_bytes[3], fault_bytes[4],
                     have_fault_bytes ? "" : " (unreadable)", k_dpmi_exception_gateway_selector,
                     k_dpmi_exception_gateway_offset, gateway_linear, (uint32_t)run->resume_address,
                     frame_linear, handler_segment, handler_offset);
  }
  run->stopped = 1;
  daze_metrics_record_stop(&engine->metrics);
  uc_emu_stop(uc);
  return 1;
}

static int deliver_protected_interrupt(uc_engine *uc, uint8_t interrupt, DazeUnicornEngine *engine,
                                       DazeUnicornRunState *run,
                                       DazeDosRuntimeProcessState *process,
                                       DazeDosfsFileService *files) {
  const uint16_t target_cs = process->dpmi.interrupt_vectors[interrupt].segment;
  const uint32_t target_eip = process->dpmi.interrupt_vectors[interrupt].offset;
  const uint16_t ss = get_reg16(uc, UC_X86_REG_SS);
  const uint16_t cs = get_reg16(uc, UC_X86_REG_CS);
  uint32_t stack_base = 0;
  uint32_t esp = get_reg32(uc, UC_X86_REG_ESP);
  uint32_t eip = get_reg32(uc, UC_X86_REG_EIP);
  uint32_t eflags = get_reg32(uc, UC_X86_REG_EFLAGS);
  const int source_code_width = daze_dpmi_selector_code_width(uc, cs);
  const int target_code_width = daze_dpmi_selector_code_width(uc, target_cs);
  const int have_stack_base = daze_dpmi_selector_base(uc, ss, &stack_base);
  if (target_cs == 0 || source_code_width == 0 || target_code_width == 0 || !have_stack_base ||
      esp < (source_code_width == 32 ? 12u : 6u) || stack_base > k_memory_size - esp) {
    return 0;
  }
  if (interrupt == DAZE_INT_DOS) {
    daze_protected_dos_continuation_clear(run);
    uc_context *caller_context = NULL;
    if (uc_context_alloc(uc, &caller_context) == UC_ERR_OK &&
        uc_context_save(uc, caller_context) == UC_ERR_OK) {
      run->dos_continuation.engine = uc;
      run->dos_continuation.caller_context = caller_context;
      run->dos_continuation.already_advanced = run->interrupt_already_advanced;
      run->dos_continuation.active = 1;
    } else if (caller_context != NULL) {
      uc_context_free(caller_context);
    }
  }
  /* The gate/frame width follows the interrupted code's operand size. The
   * client deliberately vectors from 32-bit code to a 16-bit reflector, which
   * uses prefixes to inspect its incoming 12-byte frame. */
  if (source_code_width == 32) {
    /* INT n pushes in reverse order, leaving EIP at the top for IRETD. */
    const uint32_t frame[] = {eip + (run->interrupt_already_advanced ? 0u : 2u), cs, eflags};
    esp -= sizeof(frame);
    if (uc_mem_write(uc, stack_base + esp, frame, sizeof(frame)) != UC_ERR_OK) {
      return 0;
    }
  } else {
    const uint16_t frame[] = {(uint16_t)(eip + (run->interrupt_already_advanced ? 0u : 2u)), cs,
                              (uint16_t)eflags};
    esp -= sizeof(frame);
    if (uc_mem_write(uc, stack_base + esp, frame, sizeof(frame)) != UC_ERR_OK) {
      return 0;
    }
  }
  if (interrupt == DAZE_INT_DOS && run->dos_continuation.active) {
    run->dos_continuation.delivered_cs = target_cs;
    run->dos_continuation.delivered_eip = target_eip;
    run->dos_continuation.frame_ss = ss;
    run->dos_continuation.frame_esp = esp;
    run->dos_continuation.frame_size = (uint8_t)(source_code_width == 32 ? 12u : 6u);
    /* The hook runs in later uc_emu_start calls, so its context must outlive this frame
     * and be freed with the delivery. */
    DazeUnicornContinuationContext *continuation_context = malloc(sizeof(*continuation_context));
    if (continuation_context == NULL) {
      daze_protected_dos_continuation_clear(run);
      return 0;
    }
    continuation_context->run = run;
    continuation_context->engine = engine;
    continuation_context->process = process;
    continuation_context->files = files;
    run->dos_continuation.continuation_context = continuation_context;
    if (uc_hook_add(uc, &run->dos_continuation.decline_hook, UC_HOOK_CODE,
                    daze_on_protected_dos_continuation_code, continuation_context, 1,
                    0) != UC_ERR_OK) {
      free(continuation_context);
      run->dos_continuation.continuation_context = NULL;
      daze_protected_dos_continuation_clear(run);
    } else {
      /* IRET consumes the delivery's frame; its return hook uses the caller's descriptor
       * base, or the cached real-mode base for a null selector. */
      const uint32_t pushed_eip = source_code_width == 32
                                    ? eip + (run->interrupt_already_advanced ? 0u : 2u)
                                    : (uint16_t)(eip + (run->interrupt_already_advanced ? 0u : 2u));
      run->dos_continuation.return_cs = cs;
      run->dos_continuation.return_eip = pushed_eip;
      uint32_t caller_base = 0;
      if (daze_dpmi_selector_base(uc, cs, &caller_base) || cs == 0) {
        const uint64_t return_linear = (uint64_t)caller_base + pushed_eip;
        if (uc_hook_add(uc, &run->dos_continuation.return_hook, UC_HOOK_CODE,
                        daze_on_protected_dos_return_code, run, return_linear,
                        return_linear) != UC_ERR_OK) {
          run->dos_continuation.return_hook = 0;
        }
      }
    }
  }
  eflags &= ~(1u << 8); // TF
  eflags &= ~(1u << 9); // IF
  set_reg32(uc, UC_X86_REG_ESP, esp);
  set_reg32(uc, UC_X86_REG_EFLAGS, eflags);
  set_reg16(uc, UC_X86_REG_CS, target_cs);
  if (target_code_width == 32) {
    set_reg32(uc, UC_X86_REG_EIP, target_eip);
  } else {
    set_reg16(uc, UC_X86_REG_IP, (uint16_t)target_eip);
  }
  run->resume_address = ((uint32_t)target_cs << 4) + target_eip;
  run->use_resume_address = 1;
  daze_trace_debug(engine, "  DPMI client interrupt vector %02x -> %04x:%08" PRIx32 "\n", interrupt,
                   target_cs, target_eip);
  return 1;
}

/* UC_HOOK_INTR intercepts INT before the IVT handler runs. Build its IRET frame
 * explicitly for client-installed vectors, including overlay INT 3Fh. */

static int deliver_real_mode_interrupt(uc_engine *uc, uint8_t interrupt,
                                       const DazeUnicornEngine *engine, DazeUnicornRunState *run,
                                       DazeDosProcessState *dos_process) {
  const uint16_t target_cs = dos_process->dos_vector_segment[interrupt];
  const uint16_t target_ip = dos_process->dos_vector_offset[interrupt];
  const uint16_t ss = get_reg16(uc, UC_X86_REG_SS);
  const uint16_t cs = get_reg16(uc, UC_X86_REG_CS);
  const uint16_t ip = get_reg16(uc, UC_X86_REG_IP);
  uint16_t sp = get_reg16(uc, UC_X86_REG_SP);
  uint32_t flags = get_reg32(uc, UC_X86_REG_EFLAGS);
  if (target_cs == 0 || sp < 6) return 0;
  /* The hook has already advanced IP beyond the two-byte INT. INT pushes
   * FLAGS, CS, then that return IP; IP is therefore at the low stack address
   * observed by IRET. */
  const uint16_t frame[] = {ip, cs, (uint16_t)flags};
  sp = (uint16_t)(sp - sizeof(frame));
  if (uc_mem_write(uc, ((uint32_t)ss << 4) + sp, frame, sizeof(frame)) != UC_ERR_OK) {
    return 0;
  }
  flags &= ~(1u << 8); // TF
  flags &= ~(1u << 9); // IF
  set_reg16(uc, UC_X86_REG_SP, sp);
  set_reg32(uc, UC_X86_REG_EFLAGS, flags);
  set_reg16(uc, UC_X86_REG_CS, target_cs);
  set_reg16(uc, UC_X86_REG_IP, target_ip);
  run->resume_address = ((uint32_t)target_cs << 4) + target_ip;
  run->use_resume_address = 1;
  daze_trace_debug(engine, "  real-mode client interrupt vector %02x -> %04x:%04x\n", interrupt,
                   target_cs, target_ip);
  return 1;
}

/* Hook addresses use the descriptor base, but Unicorn restart addresses use (selector <<
 * 4) + offset, including for LDT code. */

uint64_t daze_next_interrupt_address(uc_engine *uc, const DazeUnicornEngine *engine) {
  uint32_t cr0 = 0;
  uc_reg_read(uc, UC_X86_REG_CR0, &cr0);
  if ((cr0 & 1u) == 0) {
    return engine->last_code_address + 2;
  }
  const uint16_t cs = get_reg16(uc, UC_X86_REG_CS);
  uint32_t code_base = 0;
  if (daze_dpmi_selector_base(uc, cs, &code_base) && engine->last_code_address >= code_base) {
    return ((uint32_t)cs << 4) + (engine->last_code_address + 2 - code_base);
  }
  return engine->last_code_address + 2;
}

/* Protected 16-bit resumes use IP, since low-word writes can leave stale EIP high bits.
 * Real-mode resumes use the linear CS:IP address. */

uint64_t daze_restart_address(uc_engine *uc) {
  uint32_t cr0 = 0;
  uc_reg_read(uc, UC_X86_REG_CR0, &cr0);
  if ((cr0 & 1u) != 0) {
    return get_reg16(uc, UC_X86_REG_IP);
  }
  return ((uint32_t)get_reg16(uc, UC_X86_REG_CS) << 4) + get_reg16(uc, UC_X86_REG_IP);
}

/* INT FDh is reached through the protected INT 21h vector stub, whose IRET
 * consumes the frame that deliver_protected_interrupt() placed on the client
 * stack.  Unicorn's interrupt hook lets the host service update live EFLAGS,
 * but IRET would otherwise restore the stale saved flags.  Mirror the
 * guest-visible low FLAGS word into that 16-bit frame before the stub resumes.
 */
static void update_protected_interrupt_return_flags(uc_engine *uc) {
  uint32_t cr0 = 0;
  uint32_t stack_base = 0;
  uint32_t esp = 0;
  uint32_t eflags = 0;
  uint16_t ss = 0;
  uc_reg_read(uc, UC_X86_REG_CR0, &cr0);
  if ((cr0 & 1u) == 0) return;
  ss = get_reg16(uc, UC_X86_REG_SS);
  esp = get_reg32(uc, UC_X86_REG_ESP);
  if (!daze_dpmi_selector_base(uc, ss, &stack_base) || esp > k_memory_size - 6u ||
      stack_base > k_memory_size - (esp + 6u)) {
    return;
  }
  uc_reg_read(uc, UC_X86_REG_EFLAGS, &eflags);
  const uint16_t flags = (uint16_t)eflags;
  (void)uc_mem_write(uc, stack_base + esp + 4u, &flags, sizeof(flags));
}

int daze_dispatch_interrupt(uc_engine *uc, uint8_t interrupt, DazeUnicornEngine *engine,
                            DazeUnicornRunState *run, DazeDosRuntimeProcessState *process,
                            DazeDosfsFileService *files) {
  if (!engine->metrics.enabled)
    return daze_dispatch_interrupt_impl(uc, interrupt, engine, run, process, files);
  const uint64_t started = monotonic_nanoseconds();
  const int handled = daze_dispatch_interrupt_impl(uc, interrupt, engine, run, process, files);
  const uint64_t finished = monotonic_nanoseconds();
  if (finished >= started) {
    daze_metrics_record_interrupt_handler(&engine->metrics, interrupt, finished - started);
  }
  return handled;
}

static int state_procedure_widen_caller_frame(uc_engine *uc, const DazeUnicornEngine *engine,
                                              const DazeUnicornRunState *run) {
  const uint16_t cs = get_reg16(uc, UC_X86_REG_CS);
  const uint16_t ip = get_reg16(uc, UC_X86_REG_IP);
  const uint32_t return_ip = (uint32_t)ip + (run->interrupt_already_advanced ? 0u : 2u);
  uint32_t code_base = 0;
  uint8_t return_bytes[2] = {0};
  if (!daze_dpmi_selector_base(uc, cs, &code_base) ||
      uc_mem_read(uc, code_base + return_ip, return_bytes, sizeof(return_bytes)) != UC_ERR_OK) {
    return 0;
  }
  if (return_bytes[0] != 0x66 || return_bytes[1] != 0xcb) return 0;
  enum { k_frame_head_room = 4, k_widened_frame_bytes = 8 };
  const uint16_t ss = get_reg16(uc, UC_X86_REG_SS);
  const uint32_t stack_pointer = get_reg32(uc, UC_X86_REG_ESP);
  uint32_t stack_base = 0;
  uint16_t words[3] = {0};
  if (stack_pointer < k_frame_head_room || !daze_dpmi_selector_base(uc, ss, &stack_base) ||
      stack_base > k_memory_size - k_widened_frame_bytes ||
      stack_pointer > k_memory_size - stack_base - k_widened_frame_bytes ||
      uc_mem_read(uc, stack_base + stack_pointer, words, sizeof(words)) != UC_ERR_OK) {
    return 0;
  }
  if (daze_dpmi_selector_code_width(uc, words[2]) != 0) return 0;
  if (daze_dpmi_selector_code_width(uc, words[1]) == 0) return 0;
  /* The caller supplies four bytes, but operand-size RETF consumes eight. Widen at ESP-4
   * so the pending near return at ESP+4 remains on top afterward. */
  const uint16_t widened[4] = {words[0], 0, words[1], 0};
  const uint32_t widened_pointer = stack_pointer - k_frame_head_room;
  if (uc_mem_write(uc, stack_base + widened_pointer, widened, sizeof(widened)) != UC_ERR_OK) {
    return 0;
  }
  set_reg32(uc, UC_X86_REG_ESP, widened_pointer);
  daze_trace_debug(engine, "  DPMI state procedure: widened caller frame %04x:%04x\n", words[1],
                   words[0]);
  return 1;
}

static int daze_dispatch_interrupt_impl(uc_engine *uc, uint8_t interrupt, DazeUnicornEngine *engine,
                                        DazeUnicornRunState *run,
                                        DazeDosRuntimeProcessState *process,
                                        DazeDosfsFileService *files) {
  if (interrupt == DAZE_INT_DOS_PROXY) {
    const int previous_host_dos_gate = run->host_dos_gate;
    run->host_dos_gate = 1;
    const int handled = daze_dispatch_interrupt_impl(uc, DAZE_INT_DOS, engine, run, process, files);
    run->host_dos_gate = previous_host_dos_gate;
    if (handled) update_protected_interrupt_return_flags(uc);
    return handled;
  }
  if (interrupt == DAZE_INT_DOS) {
    uint32_t cr0 = 0;
    uc_reg_read(uc, UC_X86_REG_CR0, &cr0);
    if (!run->host_dos_gate && (cr0 & 1u) != 0 &&
        process->dpmi.interrupt_vectors[DAZE_INT_DOS].segment != 0 &&
        (process->dpmi.interrupt_vectors[DAZE_INT_DOS].segment != k_dos_int21_vector_segment ||
         process->dpmi.interrupt_vectors[DAZE_INT_DOS].offset != 0)) {
      return deliver_protected_interrupt(uc, interrupt, engine, run, process, files);
    }
    if (engine->metrics.enabled) engine->metrics.dos_calls++;
  }
  if (interrupt == DAZE_INT_MULTIPLEX) {
    uint32_t cr0 = 0;
    uc_reg_read(uc, UC_X86_REG_CR0, &cr0);
    /* DPMILOAD installs its protected-mode multiplex reflector before it
     * requests memory for the executable it is loading.  The initial DPMI
     * installation probe has no client vector, so it remains host-owned. */
    if ((cr0 & 1u) != 0 && process->dpmi.interrupt_vectors[DAZE_INT_MULTIPLEX].segment != 0) {
      return deliver_protected_interrupt(uc, interrupt, engine, run, process, files);
    }
  }
  if (interrupt == DAZE_INT_STATE_SAVE_GATE) {
    uint32_t cr0 = 0;
    uint32_t buffer_address = 0;
    const uint8_t operation = (uint8_t)get_reg16(uc, UC_X86_REG_AX);
    const uint16_t buffer_segment = get_reg16(uc, UC_X86_REG_ES);
    const uint32_t buffer_offset = get_reg32(uc, UC_X86_REG_EDI);
    uc_reg_read(uc, UC_X86_REG_CR0, &cr0);
    daze_trace_debug(engine, "  DPMI state procedure: %s %s buffer %04x:%08" PRIx32 "\n",
                     operation == 0 ? "save" : "restore", (cr0 & 1u) != 0 ? "protected" : "real",
                     buffer_segment, buffer_offset);
    if ((cr0 & 1u) == 0 ||
        !daze_dpmi_state_buffer_address(uc, buffer_segment, buffer_offset, &buffer_address)) {
      fprintf(stderr, "  unsupported DPMI 0305h real-mode state procedure\n");
      skip_interrupt_instruction(uc, run);
      return 1;
    }
    if (operation == 0) {
      if (!process->dpmi.real_mode_state_valid) {
        memset(&process->dpmi.real_mode_state, 0, sizeof(process->dpmi.real_mode_state));
      }
      if (uc_mem_write(uc, buffer_address, &process->dpmi.real_mode_state,
                       sizeof(process->dpmi.real_mode_state)) != UC_ERR_OK) {
        return 0;
      }
    } else if (operation == 1) {
      if (uc_mem_read(uc, buffer_address, &process->dpmi.real_mode_state,
                      sizeof(process->dpmi.real_mode_state)) != UC_ERR_OK) {
        return 0;
      }
      process->dpmi.real_mode_state_valid = 1;
    } else {
      fprintf(stderr, "  unsupported DPMI 0305h operation %u\n", operation);
    }
    state_procedure_widen_caller_frame(uc, engine, run);
    skip_interrupt_instruction(uc, run);
    return 1;
  }
  if (interrupt == DAZE_INT_RAW_SWITCH_GATE) {
    uint32_t cr0 = get_reg32(uc, UC_X86_REG_CR0);
    const int entering_protected = (cr0 & 1u) == 0;
    const uint16_t new_ds = get_reg16(uc, UC_X86_REG_AX);
    const uint16_t new_es = get_reg16(uc, UC_X86_REG_CX);
    const uint16_t new_ss = get_reg16(uc, UC_X86_REG_DX);
    const uint16_t new_sp = get_reg16(uc, UC_X86_REG_BX);
    const uint16_t new_cs = get_reg16(uc, UC_X86_REG_SI);
    const uint16_t new_ip = get_reg16(uc, UC_X86_REG_DI);
    const uint16_t saved_ax = get_reg16(uc, UC_X86_REG_AX);
    const uint16_t saved_bx = get_reg16(uc, UC_X86_REG_BX);
    const uint16_t saved_cx = get_reg16(uc, UC_X86_REG_CX);
    const uint16_t saved_dx = get_reg16(uc, UC_X86_REG_DX);
    const uint16_t saved_si = get_reg16(uc, UC_X86_REG_SI);
    const uint16_t saved_di = get_reg16(uc, UC_X86_REG_DI);
    const uint16_t saved_bp = get_reg16(uc, UC_X86_REG_BP);
    const uint16_t saved_flags = (uint16_t)get_reg32(uc, UC_X86_REG_EFLAGS);
    if (entering_protected) {
      /* A raw-mode call can have changed the parked real-mode registers
       * before the client returns through DPMI 0306h. */
      daze_dpmi_capture_state(uc, &process->dpmi.real_mode_state);
      process->dpmi.real_mode_state_valid = 1;
      if (!daze_materialize_raw_vector_descriptors(uc, run, process, &engine->metrics)) return 0;
      daze_report_raw_vector_deltas(run, process, engine);
      run->raw_vector_snapshot_valid = 0;
    }
    if (entering_protected) {
      if (!daze_setup_write_raw_pm_reentry_wrapper(
            uc, run, &engine->metrics, new_ds, new_es, new_ss, new_sp, 0, 0, saved_ax, saved_bx,
            saved_cx, saved_dx, saved_si, saved_di, saved_bp, saved_flags, new_ip, new_cs)) {
        return 0;
      }
      /* Unicorn retains the real-mode hidden CS cache after a host CR0
       * change. Continue in that cached segment long enough to enter the
       * established 32-bit host selector, then bridge into selector 0028h
       * before its wrapper reloads the client selectors. */
      static const uint8_t enter_pm[] = {
        0x2e, 0x0f, 0x01, 0x16, 0x80, 0x00, /* lgdt cs:[0x80] */
        0x0f, 0x20, 0xc0,                   /* mov eax,cr0 */
        0x66, 0x83, 0xc8, 0x01,             /* or eax,0x1 */
        0x0f, 0x22, 0xc0,                   /* mov cr0,eax */
        0xea, 0x20, 0x00, 0x20, 0x00        /* jmp far 0x20:0x20 */
      };
      static const uint8_t enter_wrapper[] = {
        0x66, 0xb8, DAZE_SEL_RAW_SWITCH,
        0x00,             /* mov ax,0x30 */
        0x0f, 0x00, 0xd0, /* lldt ax */
        0xea, 0x80, 0x01,
        0x00, 0x00, DAZE_SEL_GATE,
        0x00 /* jmp far 0x28:0x180 */
      };
      const uint32_t jump_address = ((uint32_t)k_dpmi_entry_segment << 4) + 0x0122;
      const uint32_t bridge_address = ((uint32_t)k_dpmi_entry_segment << 4) + 0x0020;
      if (uc_mem_write(uc, jump_address, enter_pm, sizeof(enter_pm)) != UC_ERR_OK ||
          uc_mem_write(uc, bridge_address, enter_wrapper, sizeof(enter_wrapper)) != UC_ERR_OK ||
          !daze_flush_translation_cache(uc, &engine->metrics)) {
        return 0;
      }
      set_reg16(uc, UC_X86_REG_IP, 0x0122);
      run->resume_address = jump_address;
      run->use_resume_address = 1;
      daze_trace_debug(engine,
                       "  DPMI raw switch: real/protected guest re-entry -> %04x:%04x, "
                       "DS:ES:SS=%04x:%04x:%04x\n",
                       new_cs, new_ip, new_ds, new_es, new_ss);
      return 1;
    }
    cr0 &= ~1u;
    daze_snapshot_raw_vectors(run, process);
    if (uc_reg_write(uc, UC_X86_REG_CR0, &cr0) != UC_ERR_OK) return 0;
    set_reg16(uc, UC_X86_REG_DS, new_ds);
    set_reg16(uc, UC_X86_REG_ES, new_es);
    set_reg16(uc, UC_X86_REG_SS, new_ss);
    set_reg16(uc, UC_X86_REG_SP, new_sp);
    set_reg16(uc, UC_X86_REG_CS, new_cs);
    set_reg16(uc, UC_X86_REG_IP, new_ip);
    set_reg16(uc, UC_X86_REG_FS, 0);
    set_reg16(uc, UC_X86_REG_GS, 0);
    run->resume_address = ((uint32_t)new_cs << 4) + new_ip;
    run->use_resume_address = 1;
    daze_trace_debug(engine, "  DPMI raw switch: %s -> %04x:%04x, DS:ES:SS=%04x:%04x:%04x\n",
                     entering_protected ? "real/protected" : "protected/real", new_cs, new_ip,
                     new_ds, new_es, new_ss);
    return 1;
  }
  {
    uint32_t cr0 = 0;
    uc_reg_read(uc, UC_X86_REG_CR0, &cr0);
    if ((cr0 & 1u) == 0 && interrupt != DAZE_INT_DOS &&
        process->dos_process.dos_vector_segment[interrupt] != 0) {
      return deliver_real_mode_interrupt(uc, interrupt, engine, run, &process->dos_process);
    }
  }
  if (interrupt == 0x08) {
    /* Unicorn may deliver a host timer IRQ while IF is set; acknowledge it without
     * introducing timer-device behavior. */
    return 1;
  }
  if (interrupt == DAZE_INT_DOS) {
    return daze_unicorn_int21_dispatch(uc, engine, run, process, files);
  }

  if (interrupt == DAZE_INT_DPMI) {
    return daze_int31_dispatch(uc, engine, run, process);
  }

  if (interrupt == DAZE_INT_MULTIPLEX && get_reg16(uc, UC_X86_REG_AX) == 0x4300) {
    /* XMS installation check.  Do not claim an XMS driver: this bounded DOS
     * host has only conventional memory, and a false positive would make the
     * client call an entry point we cannot safely provide. */
    daze_trace_debug(engine, "  XMS installation check (INT 2Fh/4300h): not present\n");
    set_reg16(uc, UC_X86_REG_AX, 0x4300);
    set_carry(uc, 0);
    skip_interrupt_instruction(uc, run);
    return 1;
  }
  if (interrupt == DAZE_INT_MULTIPLEX && get_reg16(uc, UC_X86_REG_AX) == 0xfb43 &&
      get_reg16(uc, UC_X86_REG_BX) == 0x0100) {
    /* BCC 3.1 probes this unclaimed multiplex function before it asks DOS
     * for a DPMI host. Its caller accepts the ordinary unclaimed INT 2Fh
     * behavior only when AX remains FB43h, so preserve all guest state. */
    daze_trace_debug(engine, "  BCC multiplex probe (INT 2Fh/FB43h): unclaimed\n");
    skip_interrupt_instruction(uc, run);
    return 1;
  }
  if (interrupt == DAZE_INT_MULTIPLEX && get_reg16(uc, UC_X86_REG_AX) == 0xfb42 &&
      get_reg16(uc, UC_X86_REG_BX) == 0x0014 && get_reg16(uc, UC_X86_REG_CX) == 0x0001) {
    /* BCC 3.1's BOSS stub asks whether its Borland DPMI loader is already
     * resident. Daze does not install that loader before launch, so report
     * the bounded not-installed result and let the stub EXEC DPMILOAD.EXE. */
    daze_trace_debug(engine, "  BCC DPMILOAD multiplex query (INT 2Fh/FB42h): not resident\n");
    set_reg16(uc, UC_X86_REG_BX, 1);
    skip_interrupt_instruction(uc, run);
    return 1;
  }
  if (interrupt == DAZE_INT_MULTIPLEX && get_reg16(uc, UC_X86_REG_AX) == 0x1687) {
    DazeDpmiHostAdvertisement advertisement;
    const DazeDpmiHostAdvertisementInput input = {
      .installed = 1,
      .flags = 1,
      .processor = 3,
      .major = 0,
      .minor = 0x5a,
      .private_data_paragraphs = 0,
      .entry_segment = k_dpmi_entry_segment,
      .entry_offset = 0,
    };
    if (!daze_dpmi_host_advertisement_build(&input, &advertisement)) return 0;
    daze_trace_debug(engine,
                     "  DPMI installation check (INT 2Fh/1687h): advertising 32-bit DPMI 0.9\n");
    set_reg16(uc, UC_X86_REG_AX, advertisement.ax);
    set_reg16(uc, UC_X86_REG_BX, advertisement.bx);
    set_reg16(uc, UC_X86_REG_CX, advertisement.cx);
    set_reg16(uc, UC_X86_REG_DX, advertisement.dx);
    set_reg16(uc, UC_X86_REG_ES, advertisement.es);
    set_reg16(uc, UC_X86_REG_DI, advertisement.di);
    set_reg16(uc, UC_X86_REG_SI, advertisement.si);
    set_carry(uc, advertisement.carry);
    skip_interrupt_instruction(uc, run);
    return 1;
  }
  if (interrupt == DAZE_INT_MULTIPLEX && get_reg16(uc, UC_X86_REG_AX) == 0x1600) {
    DazeDpmiHostAdvertisement advertisement;
    uint16_t reply_ax;
    int carry;
    const DazeDpmiHostAdvertisementInput input = {
      .installed = 1,
      .flags = 1,
      .processor = 3,
      .major = 0,
      .minor = 0x5a,
      .entry_segment = k_dpmi_entry_segment,
    };
    if (!daze_dpmi_host_advertisement_build(&input, &advertisement) ||
        !daze_dpmi_host_windows_reply(&advertisement, &reply_ax, &carry))
      return 0;
    daze_trace_debug(engine,
                     "  Windows enhanced-mode check (INT 2Fh/1600h): selecting DPMI path\n");
    set_reg16(uc, UC_X86_REG_AX, reply_ax);
    set_carry(uc, carry);
    skip_interrupt_instruction(uc, run);
    return 1;
  }
  if (interrupt == DAZE_INT_DPMI_ENTRY) {
    daze_trace_debug(engine, "  DPMI entry trampoline reached; protected-mode handoff is next\n");
    if (engine->debug) daze_print_registers(uc);
    const uint16_t ss = get_reg16(uc, UC_X86_REG_SS);
    const uint16_t sp = get_reg16(uc, UC_X86_REG_SP);
    uint16_t return_ip = 0;
    uint16_t return_cs = 0;
    if (uc_mem_read(uc, ((uint32_t)ss << 4) + sp, &return_ip, sizeof(return_ip)) == UC_ERR_OK &&
        uc_mem_read(uc, ((uint32_t)ss << 4) + sp + 2, &return_cs, sizeof(return_cs)) == UC_ERR_OK) {
      daze_trace_debug(engine, "  DPMI far-call return frame: %04x:%04x\n", return_cs, return_ip);
    }
    return daze_setup_prepare_dpmi_transition(uc, engine, process);
  }
  if (daze_bios_dispatch(uc, interrupt, engine, run)) return 1;
  fprintf(stderr, "  unsupported software interrupt %02xh (AX=%04x BX=%04x CX=%04x DX=%04x)\n",
          interrupt, get_reg16(uc, UC_X86_REG_AX), get_reg16(uc, UC_X86_REG_BX),
          get_reg16(uc, UC_X86_REG_CX), get_reg16(uc, UC_X86_REG_DX));
  return 0;
}
