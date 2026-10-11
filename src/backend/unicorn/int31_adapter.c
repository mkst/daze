#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>

#include "bios_adapter.h"
#include "descriptor.h"
#include "interrupt_vector.h"
#include "request.h"
#include "file_service.h"
#include "image.h"
#include "mz_layout.h"
#include "runtime.h"
#include "unicorn_context.h"
#include "unicorn_services.h"
#include "dpmi_error.h"
#include "dpmi_function.h"
#include "selector.h"

static int dpmi_ldt_slot(const DazeDpmiProcessState *dpmi, uint16_t selector, uint16_t *slot) {
  const uint16_t index = (uint16_t)(selector >> 3);
  if ((selector & 4u) == 0 || index < k_dpmi_first_ldt_index || index >= k_dpmi_ldt_size / 8 ||
      !dpmi->ldt_used[index]) {
    return 0;
  }
  *slot = index;
  return 1;
}

static int dpmi_read_ldt_descriptor(uc_engine *uc, const DazeDpmiProcessState *dpmi,
                                    uint16_t selector, uint8_t descriptor[8]) {
  uint16_t slot;
  return dpmi_ldt_slot(dpmi, selector, &slot) &&
         uc_mem_read(uc, k_dpmi_ldt_address + (uint32_t)slot * 8, descriptor, 8) == UC_ERR_OK;
}

/* CS D/B selects the width of a 0202h offset. A missing or non-code descriptor returns
 * -1. */
static int dpmi_code_default_size(uc_engine *uc, uint16_t selector) {
  const int width = daze_dpmi_selector_code_width(uc, selector);
  return width == 0 ? -1 : (width == 32 ? 1 : 0);
}

static int dpmi_write_ldt_descriptor(uc_engine *uc, const DazeDpmiProcessState *dpmi,
                                     DazeMetrics *metrics, uint16_t selector,
                                     const uint8_t descriptor[8]) {
  uint16_t slot;
  uint8_t existing[8];
  if (!dpmi_ldt_slot(dpmi, selector, &slot) ||
      uc_mem_read(uc, k_dpmi_ldt_address + (uint32_t)slot * 8, existing, sizeof(existing)) !=
        UC_ERR_OK) {
    return 0;
  }
  if (memcmp(existing, descriptor, sizeof(existing)) == 0) return 1;
  /* A non-present slot can never have been loaded into a segment register (the
   * load faults first), so no cached translation block can depend on its old
   * contents. Fresh allocations and post-free reuse skip the global flush; any
   * present-to-something change keeps it, since cached blocks may embed the
   * old base or limit. */
  int was_empty = 1;
  for (size_t byte = 0; byte < sizeof(existing); ++byte) {
    if (existing[byte] != 0) {
      was_empty = 0;
      break;
    }
  }
  if (uc_mem_write(uc, k_dpmi_ldt_address + (uint32_t)slot * 8, descriptor, 8) != UC_ERR_OK) {
    return 0;
  }
  return was_empty || daze_flush_translation_cache(uc, metrics);
}

static int dpmi_ldt_slot_is_empty(uc_engine *uc, uint16_t slot) {
  uint8_t existing[8];
  if (uc_mem_read(uc, k_dpmi_ldt_address + (uint32_t)slot * 8, existing, sizeof(existing)) !=
      UC_ERR_OK) {
    return 0;
  }
  for (size_t byte = 0; byte < sizeof(existing); ++byte) {
    if (existing[byte] != 0) return 0;
  }
  return 1;
}

static int dpmi_allocate_ldt_descriptors(uc_engine *uc, DazeDpmiProcessState *dpmi,
                                         DazeMetrics *metrics, uint16_t count, uint16_t *selector) {
  DazeDpmiRequest request = {.function = DAZE_DPMI_ALLOC_LDT, .count = count};
  DazeDpmiLdtAllocator allocator = {
    .used = dpmi->ldt_used, .capacity = k_dpmi_ldt_size / 8, .first_index = k_dpmi_first_ldt_index};
  DazeDpmiResult result;
  daze_dpmi_request_allocate_ldt_descriptors(&request, &allocator, &result);
  if (!result.success) return 0;
  const uint8_t inert_data[8] = {0, 0, 0, 0, 0, 0x92, 0, 0};
  const uint16_t first = (uint16_t)(result.ax >> 3);
  /* Fresh allocator slots hold no live descriptor (every free path zeroes its
   * bytes), so publishing them needs no global flush. Any unexpected residue
   * keeps the conservative flush. */
  int needs_flush = 0;
  for (uint16_t index = 0; index < count; ++index) {
    if (!dpmi_ldt_slot_is_empty(uc, (uint16_t)(first + index))) needs_flush = 1;
    if (uc_mem_write(uc, k_dpmi_ldt_address + (uint32_t)(first + index) * 8, inert_data,
                     sizeof(inert_data)) != UC_ERR_OK) {
      memset(dpmi->ldt_used + first, 0, count);
      return 0;
    }
  }
  if (needs_flush && !daze_flush_translation_cache(uc, metrics)) {
    memset(dpmi->ldt_used + first, 0, count);
    return 0;
  }
  *selector = result.ax;
  return 1;
}

/* DPMI 0101h releases the DOS allocation named by the LDT selector returned
 * from 0100h. Borland also uses 0101h with its private 0501h handles, so the
 * selector-shaped request is recognized only when it names a currently owned
 * LDT slot whose descriptor base matches a live DOS allocation. */
static int dpmi_release_dos_memory_selector(uc_engine *uc, DazeUnicornEngine *engine,
                                            DazeUnicornRunState *run,
                                            DazeDosRuntimeProcessState *process,
                                            uint16_t selector) {
  uint16_t slot = 0;
  uint8_t descriptor[8];
  uint8_t empty[8] = {0};
  uint32_t base = 0;
  if (!dpmi_ldt_slot(&process->dpmi, selector, &slot) ||
      !dpmi_read_ldt_descriptor(uc, &process->dpmi, selector, descriptor) ||
      !daze_dpmi_selector_base(uc, selector, &base) || (base & 0xfu) != 0) {
    return 0;
  }
  const uint16_t segment = (uint16_t)(base >> 4);
  int allocation_live = 0;
  for (size_t index = 0; index < DAZE_DOS_MEMORY_MAX_ALLOCS; ++index) {
    const DazeDosAllocation *const allocation = &process->dos_memory.allocations[index];
    if (allocation->in_use && allocation->segment == segment) {
      allocation_live = 1;
      break;
    }
  }
  if (!allocation_live ||
      !daze_withdraw_raw_vector_projections(uc, run, &engine->metrics, segment) ||
      uc_mem_write(uc, k_dpmi_ldt_address + (uint32_t)slot * 8, empty, sizeof(empty)) !=
        UC_ERR_OK ||
      !daze_flush_translation_cache(uc, &engine->metrics) ||
      !daze_dos_memory_release(&process->dos_memory, segment)) {
    if (allocation_live) {
      (void)uc_mem_write(uc, k_dpmi_ldt_address + (uint32_t)slot * 8, descriptor,
                         sizeof(descriptor));
      (void)daze_flush_translation_cache(uc, &engine->metrics);
    }
    return 0;
  }
  process->dpmi.ldt_used[slot] = 0;
  daze_trace_debug(engine, "  DPMI 31h/0101h free DOS block %04x via selector %04x\n", segment,
                   selector);
  return 1;
}

int daze_dpmi_selector_base(uc_engine *uc, uint16_t selector, uint32_t *base) {
  const uint16_t index = (uint16_t)(selector >> 3);
  uint8_t descriptor[8];
  uint32_t address;
  if (index == 0 || index >= k_dpmi_ldt_size / 8) return 0;
  address = (selector & 4u) != 0 ? k_dpmi_ldt_address : k_dpmi_gdt_address;
  if (uc_mem_read(uc, address + (uint32_t)index * 8, descriptor, sizeof(descriptor)) != UC_ERR_OK ||
      (descriptor[5] & 0x80u) == 0) {
    return 0;
  }
  *base = (uint32_t)descriptor[2] | ((uint32_t)descriptor[3] << 8) |
          ((uint32_t)descriptor[4] << 16) | ((uint32_t)descriptor[7] << 24);
  return 1;
}

void daze_dpmi_capture_state(uc_engine *uc, DpmiAlternateState *state) {
  memset(state, 0, sizeof(*state));
  uc_reg_read(uc, UC_X86_REG_EAX, &state->eax);
  uc_reg_read(uc, UC_X86_REG_EBX, &state->ebx);
  uc_reg_read(uc, UC_X86_REG_ECX, &state->ecx);
  uc_reg_read(uc, UC_X86_REG_EDX, &state->edx);
  uc_reg_read(uc, UC_X86_REG_ESI, &state->esi);
  uc_reg_read(uc, UC_X86_REG_EDI, &state->edi);
  uc_reg_read(uc, UC_X86_REG_EBP, &state->ebp);
  uc_reg_read(uc, UC_X86_REG_ESP, &state->esp);
  uc_reg_read(uc, UC_X86_REG_EIP, &state->eip);
  uc_reg_read(uc, UC_X86_REG_EFLAGS, &state->eflags);
  uc_reg_read(uc, UC_X86_REG_CS, &state->cs);
  uc_reg_read(uc, UC_X86_REG_DS, &state->ds);
  uc_reg_read(uc, UC_X86_REG_ES, &state->es);
  uc_reg_read(uc, UC_X86_REG_FS, &state->fs);
  uc_reg_read(uc, UC_X86_REG_GS, &state->gs);
  uc_reg_read(uc, UC_X86_REG_SS, &state->ss);
}

/* The DPMI 0305h buffer belongs to the client and is addressed in the mode
 * of the state procedure. The record itself represents the dormant other
 * mode, so copying it must not alter the state-procedure's registers. */

int daze_dpmi_state_buffer_address(uc_engine *uc, uint16_t segment, uint32_t offset,
                                   uint32_t *address) {
  uint32_t cr0 = 0;
  uint32_t base = 0;
  uc_reg_read(uc, UC_X86_REG_CR0, &cr0);
  if ((cr0 & 1u) != 0) {
    if (!daze_dpmi_selector_base(uc, segment, &base)) return 0;
  } else {
    base = (uint32_t)segment << 4;
  }
  if (offset > k_memory_size - sizeof(DpmiAlternateState) ||
      base > k_memory_size - sizeof(DpmiAlternateState) - offset) {
    return 0;
  }
  *address = base + offset;
  return 1;
}

int daze_dpmi_selector_code_width(uc_engine *uc, uint16_t selector) {
  const uint16_t index = (uint16_t)(selector >> 3);
  const uint32_t table = (selector & 4u) != 0 ? k_dpmi_ldt_address : k_dpmi_gdt_address;
  uint8_t descriptor[8];
  if (index == 0 || index >= k_dpmi_ldt_size / 8 ||
      uc_mem_read(uc, table + (uint32_t)index * 8, descriptor, sizeof(descriptor)) != UC_ERR_OK) {
    return 0;
  }
  if ((descriptor[5] & 0x98u) != 0x98u) return 0;
  return (descriptor[6] & 0x40u) != 0 ? 32 : 16;
}

typedef struct {
  uint32_t ecx;
  uint32_t edx;
  uint32_t edi;
  uint32_t es;
} DazeDpmiVectorInputs;

static DazeDpmiVectorInputs dpmi_vector_inputs(uc_engine *uc) {
  return (DazeDpmiVectorInputs){.ecx = get_reg32(uc, UC_X86_REG_ECX),
                                .edx = get_reg32(uc, UC_X86_REG_EDX),
                                .edi = get_reg32(uc, UC_X86_REG_EDI),
                                .es = get_reg16(uc, UC_X86_REG_ES)};
}

static int apply_vector_result_contract(uc_engine *uc, const DazeDpmiRequest *request,
                                        const DazeDpmiResult *result) {
  DazeDpmiVectorResultContract contract;
  if (!daze_dpmi_request_vector_result_contract(request, result, &contract)) return 0;
  if (contract.write_ax16) set_reg16(uc, UC_X86_REG_AX, contract.ax);
  if (contract.write_cx16) set_reg16(uc, UC_X86_REG_CX, contract.cx);
  if (contract.write_dx16) set_reg16(uc, UC_X86_REG_DX, contract.dx);
  if (contract.write_edx) set_reg32(uc, UC_X86_REG_EDX, contract.edx);
  set_carry(uc, contract.success ? 0 : 1);
  return 1;
}

static int apply_transition_result_contract(uc_engine *uc, const DazeDpmiRequest *request,
                                            const DazeDpmiResult *result) {
  DazeDpmiTransitionResultContract contract;
  if (!daze_dpmi_request_transition_result_contract(request, result, &contract)) return 0;
  if (contract.write_ax16) set_reg16(uc, UC_X86_REG_AX, contract.ax);
  if (contract.write_bx16) set_reg16(uc, UC_X86_REG_BX, contract.bx);
  if (contract.write_cx16) set_reg16(uc, UC_X86_REG_CX, contract.cx);
  if (contract.write_si16) set_reg16(uc, UC_X86_REG_SI, contract.si);
  if (contract.write_edi) set_reg32(uc, UC_X86_REG_EDI, contract.edi);
  set_carry(uc, contract.success ? 0 : 1);
  return 1;
}

static int apply_scalar_result_contract(uc_engine *uc, const DazeDpmiRequest *request,
                                        const DazeDpmiResult *result) {
  DazeDpmiScalarResultContract contract;
  if (!daze_dpmi_request_scalar_result_contract(request, result, &contract)) return 0;
  if (contract.write_ax16) set_reg16(uc, UC_X86_REG_AX, contract.ax);
  if (contract.write_al) {
    const uint16_t ax = get_reg16(uc, UC_X86_REG_AX);
    set_reg16(uc, UC_X86_REG_AX, (uint16_t)((ax & 0xff00u) | contract.al));
  }
  if (contract.write_bx16) set_reg16(uc, UC_X86_REG_BX, contract.bx);
  if (contract.write_cl) {
    const uint16_t cx = get_reg16(uc, UC_X86_REG_CX);
    set_reg16(uc, UC_X86_REG_CX, (uint16_t)((cx & 0xff00u) | contract.cl));
  }
  if (contract.write_dx16) set_reg16(uc, UC_X86_REG_DX, contract.dx);
  set_carry(uc, contract.success ? 0 : 1);
  return 1;
}

static int apply_linear_result_contract(uc_engine *uc, const DazeDpmiRequest *request,
                                        const DazeDpmiResult *result) {
  DazeDpmiLinearResultContract contract;
  if (!daze_dpmi_request_linear_result_contract(request, result, &contract)) return 0;
  if (contract.write_ax16) set_reg16(uc, UC_X86_REG_AX, contract.ax);
  if (contract.write_bx16) set_reg16(uc, UC_X86_REG_BX, contract.bx);
  if (contract.write_cx16) set_reg16(uc, UC_X86_REG_CX, contract.cx);
  if (contract.write_si16) set_reg16(uc, UC_X86_REG_SI, contract.si);
  if (contract.write_di16) set_reg16(uc, UC_X86_REG_DI, contract.di);
  set_carry(uc, contract.success ? 0 : 1);
  return 1;
}

/* Record delivered registers after skipping INT, so IP denotes the same return address
 * as the KVM gate. */
static void dpmi_vector_record(uc_engine *uc, const DazeDpmiProcessState *dpmi, uint16_t ax,
                               uint8_t bl, DazeDpmiVectorInputs in, const DazeDpmiResult *result) {
  if (!daze_dpmi_vector_record_enabled()) return;
  const int exception = ax == 0x0202 || ax == 0x0203;
  const uint16_t cs = get_reg16(uc, UC_X86_REG_CS);
  DazeDpmiVectorRecord record = {
    .backend = "unicorn",
    .function = ax,
    .cs = cs,
    .ip = get_reg32(uc, UC_X86_REG_EIP),
    .db = dpmi_code_default_size(uc, cs),
    .bl = bl,
    .off_bits = exception ? 16 : 32,
    .in_ecx = in.ecx,
    .in_edx = in.edx,
    .in_edi = in.edi,
    .in_es = in.es,
    .out_ecx = get_reg32(uc, UC_X86_REG_ECX),
    .out_edx = get_reg32(uc, UC_X86_REG_EDX),
    .out_edi = get_reg32(uc, UC_X86_REG_EDI),
    .out_es = get_reg16(uc, UC_X86_REG_ES),
    /* The Unicorn adapter writes the result straight into CPU registers, so
     * there is no conditional ES reload to report. */
    .es_reload = 1,
  };
  if (exception) {
    record.res_segment = result->vector_segment;
    record.res_offset = result->vector_offset;
    record.slot_segment = dpmi->exception_vector_segment[bl];
    record.slot_offset = dpmi->exception_vector_offset[bl];
  } else {
    record.res_segment = result->interrupt_segment;
    record.res_offset = result->interrupt_offset;
    record.slot_segment = dpmi->interrupt_vectors[bl].segment;
    record.slot_offset = dpmi->interrupt_vectors[bl].offset;
  }
  daze_dpmi_vector_record_print(&record);
}

int daze_int31_dispatch(uc_engine *uc, DazeUnicornEngine *engine, DazeUnicornRunState *run,
                        DazeDosRuntimeProcessState *process) {
  engine->metrics.dpmi_calls++;
  const uint16_t ax = get_reg16(uc, UC_X86_REG_AX);
  daze_metrics_record_dpmi_function(&engine->metrics, ax);
  if (ax == DAZE_DPMI_SIMULATE_RM) {
    return daze_setup_start_dpmi_rm_procedure(uc, engine, run);
  }
  if (ax == DAZE_DPMI_CALL_RM) {
    return daze_setup_start_dpmi_rm_interrupt(uc, engine, run, process);
  }
  if (ax == DAZE_DPMI_GET_VERSION) {
    /* DPMI 0.9 section 12. This bounded host is 80386-capable, reflects
       * interrupts through real mode, and deliberately has no virtual
       * memory. CH is unspecified by the service, so retain the caller's
       * value rather than accidentally clobbering it. */
    const DazeDpmiRequest request = {.function = ax};
    DazeDpmiResult result;
    daze_dpmi_request_get_version(&request, &result);
    daze_trace_debug(engine, "  DPMI 31h/0400h version: 0.90, 80386, real-mode reflection\n");
    /* DPMI 0.9 returns the minor version as binary decimal 90 (5Ah),
       * rather than packed BCD. */
    if (!apply_scalar_result_contract(uc, &request, &result)) return 0;
    skip_interrupt_instruction(uc, run);
    return 1;
  }
  if (ax == DAZE_DPMI_GET_RM_VECTOR) {
    const uint8_t vector = (uint8_t)get_reg16(uc, UC_X86_REG_BX);
    const DazeDpmiRequest request = {.function = ax, .interrupt = vector};
    DazeDpmiResult result;
    daze_dpmi_request_get_real_mode_vector(&request, process->dos_process.dos_vector_segment,
                                           process->dos_process.dos_vector_offset, 256, &result);
    daze_trace_debug(engine, "  DPMI 31h/0200h get real-mode vector %02x: %04x:%04x\n", vector,
                     result.vector_segment, result.vector_offset);
    if (!apply_vector_result_contract(uc, &request, &result)) return 0;
    skip_interrupt_instruction(uc, run);
    return 1;
  }
  if (ax == DAZE_DPMI_SET_RM_VECTOR) {
    const uint8_t vector = (uint8_t)get_reg16(uc, UC_X86_REG_BX);
    const DazeDpmiRequest request = {.function = ax,
                                     .interrupt = vector,
                                     .vector_segment = get_reg16(uc, UC_X86_REG_CX),
                                     .vector_offset = get_reg16(uc, UC_X86_REG_DX)};
    DazeDpmiResult result;
    daze_dpmi_request_set_real_mode_vector(&request, process->dos_process.dos_vector_segment,
                                           process->dos_process.dos_vector_offset, 256, &result);
    daze_trace_debug(engine, "  DPMI 31h/0201h set real-mode vector %02x: %04x:%04x\n", vector,
                     process->dos_process.dos_vector_segment[vector],
                     process->dos_process.dos_vector_offset[vector]);
    if (!apply_vector_result_contract(uc, &request, &result)) return 0;
    skip_interrupt_instruction(uc, run);
    return 1;
  }
  if (ax == DAZE_DPMI_GET_EXCEPTION) {
    const uint8_t exception = (uint8_t)get_reg16(uc, UC_X86_REG_BX);
    const DazeDpmiVectorInputs in = dpmi_vector_inputs(uc);
    DazeDpmiExceptionVector vectors[32];
    DazeDpmiRequest request = {.function = ax, .exception = exception};
    DazeDpmiResult result;
    for (size_t index = 0; index < sizeof(vectors) / sizeof(vectors[0]); ++index) {
      vectors[index].segment = process->dpmi.exception_vector_segment[index];
      vectors[index].offset = process->dpmi.exception_vector_offset[index];
    }
    daze_dpmi_request_get_exception_vector(&request, vectors, sizeof(vectors) / sizeof(vectors[0]),
                                           &result);
    if (!result.success) {
      fprintf(stderr, "  DPMI 31h/0202h invalid exception %u\n", exception);
    } else {
      daze_trace_debug(engine, "  DPMI 31h/0202h get exception vector %u: %04x:%04x\n", exception,
                       result.vector_segment, result.vector_offset);
      /* DPMI 0.9 10.3 (p46) returns the handler as CX:(E)DX. A 16-bit client
       * reads the selector in CX and the offset in DX, so EDX's high half is
       * not part of the result and DI/ES stay as the request left them. */
    }
    if (!apply_vector_result_contract(uc, &request, &result)) return 0;
    skip_interrupt_instruction(uc, run);
    if (result.success) dpmi_vector_record(uc, &process->dpmi, ax, exception, in, &result);
    return 1;
  }
  if (ax == DAZE_DPMI_SET_EXCEPTION) {
    const uint8_t exception = (uint8_t)get_reg16(uc, UC_X86_REG_BX);
    const DazeDpmiVectorInputs in = dpmi_vector_inputs(uc);
    DazeDpmiExceptionVector vectors[32];
    DazeDpmiRequest request = {.function = ax,
                               .exception = exception,
                               .vector_segment = get_reg16(uc, UC_X86_REG_CX),
                               .vector_offset = get_reg32(uc, UC_X86_REG_EDX)};
    DazeDpmiResult result;
    for (size_t index = 0; index < sizeof(vectors) / sizeof(vectors[0]); ++index) {
      vectors[index].segment = process->dpmi.exception_vector_segment[index];
      vectors[index].offset = process->dpmi.exception_vector_offset[index];
    }
    daze_dpmi_request_set_exception_vector(&request, vectors, sizeof(vectors) / sizeof(vectors[0]),
                                           &result);
    if (!result.success) {
      fprintf(stderr, "  DPMI 31h/0203h invalid exception %u\n", exception);
    } else {
      process->dpmi.exception_vector_segment[exception] = vectors[exception].segment;
      process->dpmi.exception_vector_offset[exception] = vectors[exception].offset;
      daze_trace_debug(engine, "  DPMI 31h/0203h set exception vector %u: %04x:%04x\n", exception,
                       process->dpmi.exception_vector_segment[exception],
                       process->dpmi.exception_vector_offset[exception]);
    }
    if (!apply_vector_result_contract(uc, &request, &result)) return 0;
    skip_interrupt_instruction(uc, run);
    if (result.success) dpmi_vector_record(uc, &process->dpmi, ax, exception, in, &result);
    return 1;
  }
  if (ax == DAZE_DPMI_GET_PM_VECTOR) {
    const uint8_t vector = (uint8_t)get_reg16(uc, UC_X86_REG_BX);
    const DazeDpmiVectorInputs in = dpmi_vector_inputs(uc);
    const DazeDpmiRequest request = {.function = ax, .interrupt = vector};
    DazeDpmiResult result;
    daze_dpmi_request_get_interrupt_vector(&request, process->dpmi.interrupt_vectors,
                                           sizeof(process->dpmi.interrupt_vectors) /
                                             sizeof(process->dpmi.interrupt_vectors[0]),
                                           &result);
    daze_trace_debug(engine, "  DPMI 31h/0204h get interrupt vector %02x: %04x:%08" PRIx32 "\n",
                     vector, result.interrupt_segment, result.interrupt_offset);
    if (!apply_vector_result_contract(uc, &request, &result)) return 0;
    skip_interrupt_instruction(uc, run);
    if (result.success) dpmi_vector_record(uc, &process->dpmi, ax, vector, in, &result);
    return 1;
  }
  if (ax == DAZE_DPMI_SET_PM_VECTOR) {
    const uint8_t vector = (uint8_t)get_reg16(uc, UC_X86_REG_BX);
    const DazeDpmiVectorInputs in = dpmi_vector_inputs(uc);
    const DazeDpmiRequest request = {.function = ax,
                                     .interrupt = vector,
                                     .interrupt_segment = get_reg16(uc, UC_X86_REG_CX),
                                     .interrupt_offset = get_reg32(uc, UC_X86_REG_EDX)};
    DazeDpmiResult result;
    daze_dpmi_request_set_interrupt_vector(&request, process->dpmi.interrupt_vectors,
                                           sizeof(process->dpmi.interrupt_vectors) /
                                             sizeof(process->dpmi.interrupt_vectors[0]),
                                           &result);
    daze_trace_debug(engine, "  DPMI 31h/0205h set interrupt vector %02x: %04x:%08" PRIx32 "\n",
                     vector, request.interrupt_segment, request.interrupt_offset);
    if (!apply_vector_result_contract(uc, &request, &result)) return 0;
    skip_interrupt_instruction(uc, run);
    if (result.success) dpmi_vector_record(uc, &process->dpmi, ax, vector, in, &result);
    return 1;
  }
  if (ax == DAZE_DPMI_GET_STATE_SAVE) {
    /* The 60-byte alternate-state record contains dormant real-mode state; saving it
     * must preserve caller registers. */
    const DazeDpmiRequest request = {.function = ax,
                                     .state_buffer_size = 60,
                                     .rm_segment = k_dpmi_entry_segment,
                                     .rm_offset = 0x0100,
                                     .pm_selector = DAZE_SEL_GATE,
                                     .pm_offset = 0x0100};
    DazeDpmiResult result;
    daze_dpmi_request_get_state_save_endpoints(&request, &result);
    daze_trace_debug(engine,
                     "  DPMI 31h/0305h state save/restore: buffer %u, rm %04x:%04x, pm %04x:%08x\n",
                     result.state_buffer_size, result.rm_segment, result.rm_offset,
                     result.pm_selector, result.pm_offset);
    if (!apply_transition_result_contract(uc, &request, &result)) return 0;
    skip_interrupt_instruction(uc, run);
    return 1;
  }
  if (ax == DAZE_DPMI_GET_RAW_SWITCH) {
    /* The two entry points share the INT FCh host gate at physical 02120h.
       * The protected endpoint uses a 16-bit selector so its far JMP contract
       * matches the client's current 16-bit extender code. */
    const DazeDpmiRequest request = {.function = ax,
                                     .rm_segment = k_dpmi_entry_segment,
                                     .rm_offset = 0x0120,
                                     .pm_selector = DAZE_SEL_GATE,
                                     .pm_offset = 0x0120};
    DazeDpmiResult result;
    daze_dpmi_request_get_raw_switch_endpoints(&request, &result);
    daze_trace_debug(engine, "  DPMI 31h/0306h raw switch gates: rm %04x:%04x, pm %04x:%08x\n",
                     result.rm_segment, result.rm_offset, result.pm_selector, result.pm_offset);
    if (!apply_transition_result_contract(uc, &request, &result)) return 0;
    skip_interrupt_instruction(uc, run);
    return 1;
  }
  if (ax == DAZE_DPMI_GET_DISABLE_VIRT_INT) {
    DazeDpmiResult result;
    daze_dpmi_request_get_and_disable_virtual_interrupts(&process->dpmi.virtual_interrupts_enabled,
                                                         &result);
    const DazeDpmiRequest request = {.function = ax};
    daze_trace_debug(engine, "  DPMI 31h/0900h get/disable virtual interrupts: AL=%u\n",
                     (unsigned)(result.previous_virtual_interrupts_enabled ? 1 : 0));
    if (!apply_scalar_result_contract(uc, &request, &result)) return 0;
    skip_interrupt_instruction(uc, run);
    return 1;
  }
  if (ax == DAZE_DPMI_GET_ENABLE_VIRT_INT) {
    DazeDpmiResult dpm_result;
    daze_dpmi_request_get_and_enable_virtual_interrupts(&process->dpmi.virtual_interrupts_enabled,
                                                        &dpm_result);
    const DazeDpmiRequest request = {.function = ax};
    daze_trace_debug(engine, "  DPMI 31h/0901h get/enable virtual interrupts: AL=%u\n",
                     (unsigned)(dpm_result.previous_virtual_interrupts_enabled ? 1 : 0));
    if (!apply_scalar_result_contract(uc, &request, &dpm_result)) return 0;
    skip_interrupt_instruction(uc, run);
    return 1;
  }
  if (ax == DAZE_DPMI_LOCK_LINEAR || ax == DAZE_DPMI_UNLOCK_LINEAR) {
    const uint32_t base =
      ((uint32_t)get_reg16(uc, UC_X86_REG_BX) << 16) | get_reg16(uc, UC_X86_REG_CX);
    const uint32_t size =
      ((uint32_t)get_reg16(uc, UC_X86_REG_SI) << 16) | get_reg16(uc, UC_X86_REG_DI);
    /* DPMI permits non-paging hosts to ignore both lock and unlock requests. */
    daze_trace_debug(engine,
                     "  DPMI 31h/%04xh %s linear region: %08" PRIx32 " + %08" PRIx32
                     " (no-paging no-op)\n",
                     ax, ax == DAZE_DPMI_LOCK_LINEAR ? "lock" : "unlock", base, size);
    const DazeDpmiRequest request = {.function = ax, .operand = base, .size = size};
    DazeDpmiResult result;
    daze_dpmi_request_lock_linear_region(&request, &result);
    set_carry(uc, !result.success);
    skip_interrupt_instruction(uc, run);
    return 1;
  }
  if (ax == DAZE_DPMI_ALLOC_LINEAR) {
    const uint32_t size =
      ((uint32_t)get_reg16(uc, UC_X86_REG_BX) << 16) | get_reg16(uc, UC_X86_REG_CX);
    const DazeDpmiRequest request = {.function = ax, .size = size};
    DazeDpmiResult result;
    daze_dpmi_request_allocate_linear_memory(&process->dpmi.linear_memory, &request, &result);
    if (!result.success) {
      fprintf(stderr, "  DPMI 31h/0501h cannot allocate %08" PRIx32 " bytes\n", size);
    } else {
      daze_trace_debug(engine,
                       "  DPMI 31h/0501h allocate: %08" PRIx32 " bytes -> %08" PRIx32
                       " (handle %08" PRIx32 ")\n",
                       size, result.base, result.handle);
    }
    if (!apply_linear_result_contract(uc, &request, &result)) return 0;
    skip_interrupt_instruction(uc, run);
    return 1;
  }
  if (ax == DAZE_DPMI_FREE_LINEAR) {
    const uint32_t handle =
      ((uint32_t)get_reg16(uc, UC_X86_REG_SI) << 16) | get_reg16(uc, UC_X86_REG_DI);
    const DazeDpmiRequest request = {.function = ax, .operand = handle};
    DazeDpmiResult result;
    daze_dpmi_request_free_linear_memory(&process->dpmi.linear_memory, &request, &result);
    if (!result.success) {
      fprintf(stderr, "  DPMI 31h/0502h invalid handle %08" PRIx32 "\n", handle);
    } else {
      daze_trace_debug(engine, "  DPMI 31h/0502h free: handle %08" PRIx32 "\n", handle);
    }
    if (!apply_linear_result_contract(uc, &request, &result)) return 0;
    skip_interrupt_instruction(uc, run);
    return 1;
  }
  if (ax == DAZE_DPMI_RESIZE_LINEAR) {
    const uint32_t size =
      ((uint32_t)get_reg16(uc, UC_X86_REG_BX) << 16) | get_reg16(uc, UC_X86_REG_CX);
    const uint32_t handle =
      ((uint32_t)get_reg16(uc, UC_X86_REG_SI) << 16) | get_reg16(uc, UC_X86_REG_DI);
    const DazeDpmiRequest request = {.function = ax, .size = size, .operand = handle};
    DazeDpmiResult result;
    daze_dpmi_request_resize_linear_memory(&process->dpmi.linear_memory, &request, &result);
    if (!result.success) {
      fprintf(stderr,
              "  DPMI 31h/0503h cannot resize handle %08" PRIx32 " to %08" PRIx32 " bytes\n",
              handle, size);
    } else {
      daze_trace_debug(engine,
                       "  DPMI 31h/0503h resize: handle %08" PRIx32 " -> %08" PRIx32 " bytes\n",
                       handle, size);
      /* DPMI returns the (possibly relocated) linear base in BX:CX. This
         * monotonic arena resizes in place, but callers must still receive
         * the recorded base rather than the size they supplied. */
    }
    if (!apply_linear_result_contract(uc, &request, &result)) return 0;
    skip_interrupt_instruction(uc, run);
    return 1;
  }
  if (ax == DAZE_DPMI_GET_FREE_MEM) {
    const uint16_t es = get_reg16(uc, UC_X86_REG_ES);
    const uint16_t di = get_reg16(uc, UC_X86_REG_DI);
    uint8_t information[48];
    memset(information, 0xff, sizeof(information));
    const uint32_t largest =
      daze_dpmi_linear_memory_largest_available(&process->dpmi.linear_memory);
    memcpy(information, &largest, sizeof(largest));
    if (!daze_write_guest_bytes(uc, es, di, information, sizeof(information))) {
      fprintf(stderr, "  DPMI 31h/0500h invalid buffer %04x:%04x\n", es, di);
      set_reg16(uc, UC_X86_REG_AX, DAZE_DPMI_ERR_INVALID_SELECTOR);
      set_carry(uc, 1);
    } else {
      daze_trace_debug(engine, "  DPMI 31h/0500h free memory: largest %08" PRIx32 " bytes\n",
                       largest);
      set_carry(uc, 0);
    }
    skip_interrupt_instruction(uc, run);
    return 1;
  }
  if (ax == DAZE_DPMI_RESIZE_DOS_MEM) {
    const uint16_t paragraphs = get_reg16(uc, UC_X86_REG_BX);
    const uint16_t token = get_reg16(uc, UC_X86_REG_DX);
    /* Borland's DPMILOAD memory-control path passes the live 0501h handle
     * in DX when resizing its protected executable image.  Keep that bridge
     * bounded to a real allocation token; ordinary invalid 0102h requests
     * continue to report the documented invalid-block error. */
    const DazeDpmiRequest request = {
      .function = ax, .operand = token, .size = (uint32_t)paragraphs << 4};
    DazeDpmiResult result;
    daze_dpmi_request_resize_loader_block(&process->dpmi.linear_memory, &request, &result);
    if (!result.success) {
      daze_trace_debug(engine, "  DPMI 31h/0102h invalid block %04x\n", token);
    } else {
      daze_trace_debug(engine,
                       "  DPMI 31h/0102h resize DPMILOAD block %04x -> %04x paragraphs"
                       " (%08" PRIx32 ")\n",
                       token, paragraphs, result.base);
    }
    if (!apply_linear_result_contract(uc, &request, &result)) return 0;
    skip_interrupt_instruction(uc, run);
    return 1;
  }
  if (ax == DAZE_DPMI_FREE_DOS_MEM) {
    const uint16_t token = get_reg16(uc, UC_X86_REG_DX);
    if (dpmi_release_dos_memory_selector(uc, engine, run, process, token)) {
      set_carry(uc, 0);
      skip_interrupt_instruction(uc, run);
      return 1;
    }
    /* See 0102h above: DPMILOAD presents its live 0501h allocation token
     * through the legacy DOS-memory release interface. */
    const DazeDpmiRequest request = {.function = ax, .operand = token};
    DazeDpmiResult result;
    daze_dpmi_request_release_loader_block(&process->dpmi.linear_memory, &request, &result);
    if (!result.success) {
      daze_trace_debug(engine, "  DPMI 31h/0101h invalid DPMILOAD block %04x\n", token);
    } else {
      daze_trace_debug(engine, "  DPMI 31h/0101h free DPMILOAD block %04x\n", token);
    }
    if (!apply_linear_result_contract(uc, &request, &result)) return 0;
    skip_interrupt_instruction(uc, run);
    return 1;
  }
  if (ax == DAZE_DPMI_ALLOC_DOS_MEM) {
    const uint16_t paragraphs = get_reg16(uc, UC_X86_REG_BX);
    DazeDpmiLdtAllocator allocator = {.used = process->dpmi.ldt_used,
                                      .capacity = k_dpmi_ldt_size / 8,
                                      .first_index = k_dpmi_first_ldt_index};
    const DazeDpmiRequest request = {.function = ax, .count = paragraphs};
    DazeDpmiResult result;
    daze_dpmi_request_allocate_dos_memory(&process->dos_memory, &allocator, &request, &result);
    if (!result.success) {
      daze_trace_debug(engine, "  DPMI 31h/0100h cannot allocate %04x paragraphs\n", paragraphs);
    } else {
      if (!dpmi_write_ldt_descriptor(uc, &process->dpmi, &engine->metrics, (uint16_t)result.handle,
                                     result.descriptor))
        return 0;
      daze_trace_debug(engine, "  DPMI 31h/0100h allocate: %04x paragraphs -> %04x, %04x\n",
                       paragraphs, result.ax, (uint16_t)result.handle);
    }
    if (!apply_scalar_result_contract(uc, &request, &result)) return 0;
    skip_interrupt_instruction(uc, run);
    return 1;
  }
  if (ax == DAZE_DPMI_FREE_LDT) {
    const uint16_t selector = get_reg16(uc, UC_X86_REG_BX);
    uint16_t slot;
    const uint8_t empty[8] = {0};
    DazeDpmiLdtAllocator allocator = {.used = process->dpmi.ldt_used,
                                      .capacity = k_dpmi_ldt_size / 8,
                                      .first_index = k_dpmi_first_ldt_index};
    DazeDpmiRequest request = {.function = ax, .selector = selector};
    DazeDpmiResult result;
    daze_dpmi_request_free_ldt_descriptor(&request, &allocator, &result);
    slot = (uint16_t)(selector >> 3);
    if (!result.success ||
        uc_mem_write(uc, k_dpmi_ldt_address + (uint32_t)slot * 8, empty, sizeof(empty)) !=
          UC_ERR_OK ||
        !daze_flush_translation_cache(uc, &engine->metrics)) {
      if (result.success) process->dpmi.ldt_used[slot] = 1;
      fprintf(stderr, "  DPMI 31h/0001h invalid LDT selector %04x\n", selector);
      set_reg16(uc, UC_X86_REG_AX, DAZE_DPMI_ERR_INVALID_SELECTOR); // Invalid selector.
      set_carry(uc, 1);
    } else {
      daze_trace_debug(engine, "  DPMI 31h/0001h free: %04x\n", selector);
      set_carry(uc, 0);
    }
    skip_interrupt_instruction(uc, run);
    return 1;
  }
  if (ax == DAZE_DPMI_SET_DESCRIPTOR) {
    const uint16_t selector = get_reg16(uc, UC_X86_REG_BX);
    const uint16_t es = get_reg16(uc, UC_X86_REG_ES);
    const uint16_t di = get_reg16(uc, UC_X86_REG_DI);
    uint8_t descriptor[8];
    DazeDpmiResult result;
    if (!dpmi_read_ldt_descriptor(uc, &process->dpmi, selector, descriptor)) {
      fprintf(stderr, "  DPMI 31h/000Ch invalid LDT selector %04x\n", selector);
      set_reg16(uc, UC_X86_REG_AX, DAZE_DPMI_ERR_INVALID_SELECTOR);
      set_carry(uc, 1);
    } else if (!daze_read_guest_bytes(uc, es, di, descriptor, sizeof(descriptor))) {
      fprintf(stderr, "  DPMI 31h/000Ch invalid descriptor buffer %04x:%04x\n", es, di);
      set_reg16(uc, UC_X86_REG_AX, DAZE_DPMI_ERR_INVALID_SELECTOR_ALIAS);
      set_carry(uc, 1);
    } else {
      /* DPMI 0.9 §9.11 replaces all eight bytes, including base and limit.
       * Reuse 0009h rights validation, not its rights-only mutation result. */
      const DazeDpmiRequest request = {
        .function = ax,
        .selector = selector,
        .rights = (uint16_t)descriptor[5] | ((uint16_t)descriptor[6] << 8),
      };
      daze_dpmi_request_set_access_rights(&request, descriptor, &result);
      if (!result.success ||
          !dpmi_write_ldt_descriptor(uc, &process->dpmi, &engine->metrics, selector, descriptor)) {
        fprintf(stderr, "  DPMI 31h/000Ch invalid descriptor for %04x\n", selector);
        set_reg16(uc, UC_X86_REG_AX, result.success ? DAZE_DPMI_ERR_INVALID_SELECTOR : result.ax);
        set_carry(uc, 1);
      } else {
        const uint32_t base = (uint32_t)descriptor[2] | ((uint32_t)descriptor[3] << 8) |
                              ((uint32_t)descriptor[4] << 16) | ((uint32_t)descriptor[7] << 24);
        const uint32_t limit = (uint32_t)descriptor[0] | ((uint32_t)descriptor[1] << 8) |
                               ((uint32_t)(descriptor[6] & 0x0fu) << 16);
        daze_trace_debug(engine,
                         "  DPMI 31h/000Ch set descriptor %04x from %04x:%04x"
                         " -> base %08" PRIx32 " limit %05" PRIx32 " access %02x flags %02x\n",
                         selector, es, di, base,
                         (descriptor[6] & 0x80u) != 0 ? (limit << 12) | 0xfffu : limit,
                         descriptor[5], descriptor[6]);
        set_carry(uc, 0);
      }
    }
    skip_interrupt_instruction(uc, run);
    return 1;
  }
  if (ax == DAZE_DPMI_GET_DESCRIPTOR) {
    const uint16_t selector = get_reg16(uc, UC_X86_REG_BX);
    const uint16_t es = get_reg16(uc, UC_X86_REG_ES);
    const uint16_t di = get_reg16(uc, UC_X86_REG_DI);
    uint8_t descriptor[8];
    if (!dpmi_read_ldt_descriptor(uc, &process->dpmi, selector, descriptor)) {
      fprintf(stderr, "  DPMI 31h/000Bh invalid LDT selector %04x\n", selector);
      set_reg16(uc, UC_X86_REG_AX, DAZE_DPMI_ERR_INVALID_SELECTOR);
      set_carry(uc, 1);
    } else if (!daze_write_guest_bytes(uc, es, di, descriptor, sizeof(descriptor))) {
      fprintf(stderr, "  DPMI 31h/000Bh invalid descriptor buffer %04x:%04x\n", es, di);
      set_reg16(uc, UC_X86_REG_AX, DAZE_DPMI_ERR_INVALID_SELECTOR_ALIAS);
      set_carry(uc, 1);
    } else {
      daze_trace_debug(engine, "  DPMI 31h/000Bh get descriptor %04x -> %04x:%04x\n", selector, es,
                       di);
      set_carry(uc, 0);
    }
    skip_interrupt_instruction(uc, run);
    return 1;
  }
  if (ax == DAZE_DPMI_GET_BASE) {
    /* This LDT uses eight-byte descriptor spacing. */
    const DazeDpmiRequest request = {.function = ax};
    DazeDpmiResult result;
    daze_dpmi_request_get_selector_increment(&request, &result);
    daze_trace_debug(engine, "  DPMI 31h/0003h selector increment: 0008\n");
    set_reg16(uc, UC_X86_REG_AX, result.ax);
    set_carry(uc, 0);
    skip_interrupt_instruction(uc, run);
    return 1;
  }
  if (ax == DAZE_DPMI_ALLOC_LDT) {
    const uint16_t count = get_reg16(uc, UC_X86_REG_CX);
    uint16_t selector = 0;
    if (!dpmi_allocate_ldt_descriptors(uc, &process->dpmi, &engine->metrics, count, &selector)) {
      fprintf(stderr, "  DPMI 31h/0000h cannot allocate %u LDT descriptors\n", count);
      set_reg16(uc, UC_X86_REG_AX, DAZE_DPMI_ERR_LDT_FULL); // Descriptor unavailable.
      set_carry(uc, 1);
    } else {
      daze_trace_debug(engine, "  DPMI 31h/0000h allocate: %u descriptors -> %04x\n", count,
                       selector);
      set_reg16(uc, UC_X86_REG_AX, selector);
      set_carry(uc, 0);
    }
    skip_interrupt_instruction(uc, run);
    return 1;
  }
  if (ax == DAZE_DPMI_SET_ACCESS) {
    const uint16_t selector = get_reg16(uc, UC_X86_REG_BX);
    const uint16_t rights = get_reg16(uc, UC_X86_REG_CX);
    uint8_t descriptor[8];
    if (!dpmi_read_ldt_descriptor(uc, &process->dpmi, selector, descriptor)) {
      fprintf(stderr, "  DPMI 31h/0009h invalid LDT selector %04x\n", selector);
      set_reg16(uc, UC_X86_REG_AX, DAZE_DPMI_ERR_INVALID_SELECTOR); // Invalid selector.
      set_carry(uc, 1);
    } else {
      const DazeDpmiRequest request = {.function = ax, .selector = selector, .rights = rights};
      DazeDpmiResult result;
      daze_dpmi_request_set_access_rights(&request, descriptor, &result);
      if (!result.success) {
        fprintf(stderr, "  DPMI 31h/0009h invalid access rights %04x\n", rights);
        set_reg16(uc, UC_X86_REG_AX, result.ax);
        set_carry(uc, 1);
      } else {
        if (!dpmi_write_ldt_descriptor(uc, &process->dpmi, &engine->metrics, selector,
                                       result.descriptor))
          return 0;
        daze_trace_debug(engine, "  DPMI 31h/0009h access: %04x <- %04x\n", selector, rights);
        set_carry(uc, 0);
      }
    }
    skip_interrupt_instruction(uc, run);
    return 1;
  }
  if (ax == DAZE_DPMI_SET_LIMIT) {
    const uint16_t selector = get_reg16(uc, UC_X86_REG_BX);
    const uint32_t base =
      ((uint32_t)get_reg16(uc, UC_X86_REG_CX) << 16) | get_reg16(uc, UC_X86_REG_DX);
    uint8_t descriptor[8];
    if (!dpmi_read_ldt_descriptor(uc, &process->dpmi, selector, descriptor)) {
      fprintf(stderr, "  DPMI 31h/0007h invalid LDT selector %04x\n", selector);
      set_reg16(uc, UC_X86_REG_AX, DAZE_DPMI_ERR_INVALID_SELECTOR); // Invalid selector.
      set_carry(uc, 1);
    } else {
      const DazeDpmiRequest request = {.function = ax, .selector = selector, .operand = base};
      DazeDpmiResult result;
      daze_dpmi_request_set_segment_base(&request, descriptor, &result);
      if (!dpmi_write_ldt_descriptor(uc, &process->dpmi, &engine->metrics, selector,
                                     result.descriptor))
        return 0;
      daze_trace_debug(engine, "  DPMI 31h/0007h base: %04x <- %08" PRIx32 "\n", selector, base);
      set_carry(uc, 0);
    }
    skip_interrupt_instruction(uc, run);
    return 1;
  }
  if (ax == DAZE_DPMI_GET_BASE_2) {
    const uint16_t selector = get_reg16(uc, UC_X86_REG_BX);
    uint32_t base = 0;
    uint8_t descriptor[8];
    /* Get Segment Base Address is an interrogation operation. An allocated
     * LDT descriptor remains interrogable while non-present; using the CPU
     * selector resolver here incorrectly rejects exactly the descriptor that
     * a #NP handler needs to inspect. GDT selectors retain the resolver's
     * stricter present-descriptor rule. */
    const int valid = (selector & 4u) != 0
                        ? dpmi_read_ldt_descriptor(uc, &process->dpmi, selector, descriptor)
                        : daze_dpmi_selector_base(uc, selector, &base);
    if (valid) {
      if ((selector & 4u) != 0) {
        base = (uint32_t)descriptor[2] | ((uint32_t)descriptor[3] << 8) |
               ((uint32_t)descriptor[4] << 16) | ((uint32_t)descriptor[7] << 24);
      }
      daze_trace_debug(engine, "  DPMI 31h/0006h base: %04x -> %08" PRIx32 "\n", selector, base);
      set_reg16(uc, UC_X86_REG_CX, (uint16_t)(base >> 16));
      set_reg16(uc, UC_X86_REG_DX, (uint16_t)base);
      set_carry(uc, 0);
    } else {
      fprintf(stderr, "  DPMI 31h/0006h invalid selector %04x\n", selector);
      set_reg16(uc, UC_X86_REG_AX, DAZE_DPMI_ERR_INVALID_SELECTOR); // Invalid selector.
      set_carry(uc, 1);
    }
    skip_interrupt_instruction(uc, run);
    return 1;
  }
  if (ax == DAZE_DPMI_SET_LIMIT_2) {
    const uint16_t selector = get_reg16(uc, UC_X86_REG_BX);
    const uint32_t limit =
      ((uint32_t)get_reg16(uc, UC_X86_REG_CX) << 16) | get_reg16(uc, UC_X86_REG_DX);
    uint8_t descriptor[8];
    if (!dpmi_read_ldt_descriptor(uc, &process->dpmi, selector, descriptor)) {
      fprintf(stderr, "  DPMI 31h/0008h cannot set %04x limit %08" PRIx32 "\n", selector, limit);
      set_reg16(uc, UC_X86_REG_AX, DAZE_DPMI_ERR_INVALID_SEGMENT); // Invalid value.
      set_carry(uc, 1);
    } else {
      const DazeDpmiRequest request = {.function = ax, .selector = selector, .operand = limit};
      DazeDpmiResult result;
      daze_dpmi_request_set_segment_limit(&request, descriptor, &result);
      if (!result.success) {
        fprintf(stderr, "  DPMI 31h/0008h cannot set %04x limit %08" PRIx32 "\n", selector, limit);
        set_reg16(uc, UC_X86_REG_AX, result.ax);
        set_carry(uc, 1);
      } else {
        if (!dpmi_write_ldt_descriptor(uc, &process->dpmi, &engine->metrics, selector,
                                       result.descriptor))
          return 0;
        daze_trace_debug(engine, "  DPMI 31h/0008h limit: %04x <- %08" PRIx32 "\n", selector,
                         limit);
        set_carry(uc, 0);
      }
    }
    skip_interrupt_instruction(uc, run);
    return 1;
  }
  if (ax == DAZE_DPMI_ALLOC_LDT_MULTI) {
    /* The writable code alias must be allocated in the LDT because clients release it
     * with 0001h. */
    const uint16_t source = get_reg16(uc, UC_X86_REG_BX);
    uint8_t descriptor[8];
    const uint16_t source_index = (uint16_t)(source >> 3);
    DazeDpmiResult result;
    DazeDpmiLdtAllocator allocator = {.used = process->dpmi.ldt_used,
                                      .capacity = k_dpmi_ldt_size / 8,
                                      .first_index = k_dpmi_first_ldt_index};
    const DazeDpmiRequest request = {.function = ax, .selector = source};
    if (source_index >= 8 || uc_mem_read(uc, k_dpmi_gdt_address + (uint32_t)source_index * 8,
                                         descriptor, sizeof(descriptor)) != UC_ERR_OK) {
      fprintf(stderr, "  DPMI 31h/000Ah cannot alias selector %04x\n", source);
      set_reg16(uc, UC_X86_REG_AX, DAZE_DPMI_ERR_INVALID_SELECTOR); // Invalid selector.
      set_carry(uc, 1);
    } else {
      daze_dpmi_request_create_data_alias(&request, descriptor, &allocator, &result);
      if (!result.success) {
        fprintf(stderr, "  DPMI 31h/000Ah cannot alias selector %04x\n", source);
        set_reg16(uc, UC_X86_REG_AX, result.ax);
        set_carry(uc, 1);
      } else if (!dpmi_write_ldt_descriptor(uc, &process->dpmi, &engine->metrics, result.ax,
                                            result.descriptor)) {
        return 0;
      } else {
        daze_trace_debug(engine, "  DPMI 31h/000Ah alias: %04x -> %04x\n", source, result.ax);
        set_reg16(uc, UC_X86_REG_AX, result.ax);
        set_carry(uc, 0);
      }
    }
    skip_interrupt_instruction(uc, run);
    return 1;
  }
  fprintf(stderr,
          "  unsupported DPMI 31h function %04xh (BX=%04x CX=%04x DX=%04x ES:DI=%04x:%04x "
          "SI:DI=%04x:%04x)\n",
          ax, get_reg16(uc, UC_X86_REG_BX), get_reg16(uc, UC_X86_REG_CX),
          get_reg16(uc, UC_X86_REG_DX), get_reg16(uc, UC_X86_REG_ES), get_reg16(uc, UC_X86_REG_DI),
          get_reg16(uc, UC_X86_REG_SI), get_reg16(uc, UC_X86_REG_DI));
  return 0;
}
