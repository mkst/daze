#include "child_context.h"

#include "byte_order.h"
#include "kvm_range.h"
#include "raw_switch.h"
#include "guest_memory_layout.h"
#include "selector.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
#include <linux/kvm.h>
#include <sys/ioctl.h>

typedef struct {
  uint64_t cr0, gdt_base, idt_base;
  uint16_t gdt_limit, idt_limit;
  uint8_t ivt_fc[4], idt_fc[8], gdt_08[8], gdt_10[8], gdt_18[8], gdt_40[8];
  uint8_t transition_code[32];
  uint8_t transition_gdtr[6];
  uint8_t transition_ds_gdtr[6];
  uint32_t ivt_fc_linear;
  uint8_t ivt_fc_target[16];
  int valid;
} DazeKvmResidentRawTrace;
#endif

enum {
  k_resident_transition_code_address = 0x2000,
  k_resident_transition_code_size = 22,
  k_resident_transition_gdtr_offset = 0x80,
  k_resident_transition_gdtr_size = 6,
};

typedef struct {
  uint8_t code[k_resident_transition_code_size];
  uint8_t gdtr[k_resident_transition_gdtr_size];
  int valid;
} DazeKvmResidentTransitionState;

static int resident_transition_capture(const DazeKvmMachine *machine,
                                       DazeKvmResidentTransitionState *state) {
  static const uint8_t code_prefix[] = {
    0xfa,                               /* cli */
    0x2e, 0x0f, 0x01, 0x16, 0x80, 0x00, /* lgdt cs:[0x80] */
    0x0f, 0x20, 0xc0,                   /* mov eax,cr0 */
    0x66, 0x83, 0xc8, 0x01,             /* or eax,0x1 */
    0x0f, 0x22, 0xc0,                   /* mov cr0,eax */
    0xea, 0x20, 0x00, 0x20, 0x00        /* jmp far 0x20:0x20 */
  };
  if (state == NULL) return 0;
  *state = (DazeKvmResidentTransitionState){0};
  if (machine == NULL || machine->guest == NULL ||
      !daze_kvm_range_fits(machine->guest_size, k_resident_transition_code_address,
                           k_resident_transition_code_size) ||
      !daze_kvm_range_fits(machine->guest_size,
                           k_resident_transition_code_address + k_resident_transition_gdtr_offset,
                           k_resident_transition_gdtr_size))
    return 0;
  const uint8_t *const guest = (const uint8_t *)machine->guest;
  if (memcmp(guest + k_resident_transition_code_address, code_prefix, sizeof(code_prefix)) != 0)
    return 0;
  memcpy(state->code, guest + k_resident_transition_code_address, sizeof(state->code));
  memcpy(state->gdtr,
         guest + k_resident_transition_code_address + k_resident_transition_gdtr_offset,
         sizeof(state->gdtr));
  state->valid = 1;
  return 1;
}

#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
static void resident_gdt_capture(const DazeKvmMachine *machine, DazeKvmResidentGdtState *state) {
  if (state == NULL) return;
  *state = (DazeKvmResidentGdtState){0};
  if (machine == NULL || machine->guest == NULL || machine->vcpu < 0) return;
  struct kvm_sregs sregs;
  if (ioctl(machine->vcpu, KVM_GET_SREGS, &sregs) < 0 || sregs.gdt.base > UINT32_MAX ||
      sregs.gdt.limit < 0x47)
    return;
  const uint32_t base = (uint32_t)sregs.gdt.base;
  if (!daze_kvm_range_fits(machine->guest_size, base, (size_t)sregs.gdt.limit + 1)) return;
  const uint8_t *const gdt = (const uint8_t *)machine->guest + base;
  state->base = base;
  state->limit = sregs.gdt.limit;
  memcpy(state->code, gdt + 0x08, sizeof(state->code));
  memcpy(state->ds, gdt + 0x10, sizeof(state->ds));
  memcpy(state->es, gdt + 0x18, sizeof(state->es));
  memcpy(state->transition, gdt + 0x28, sizeof(state->transition));
  memcpy(state->stack, gdt + 0x40, sizeof(state->stack));
  state->valid = 1;
}

static int resident_ldt_capture(const DazeKvmMachine *machine, DazeDpmiProcessState *dpmi_state,
                                DazeKvmResidentGdtState *state) {
  if (machine == NULL || machine->guest == NULL || machine->vcpu < 0 || dpmi_state == NULL ||
      state == NULL)
    return 0;
  struct kvm_sregs sregs;
  if (ioctl(machine->vcpu, KVM_GET_SREGS, &sregs) < 0 || sregs.ldt.base > UINT32_MAX) return 0;
  const uint32_t base = (uint32_t)sregs.ldt.base;
  const size_t size = (size_t)sregs.ldt.limit + 1;
  if (size == 0 || !daze_kvm_range_fits(machine->guest_size, base, size)) return 0;
  uint8_t *const bytes = malloc(size);
  if (bytes == NULL) return 0;
  memcpy(bytes, (const uint8_t *)machine->guest + base, size);
  state->ldt_base = base;
  state->ldt_limit = sregs.ldt.limit;
  state->ldt_bytes = bytes;
  state->next_ldt_index = dpmi_state->next_ldt_index;
  memcpy(state->ldt_used, dpmi_state->ldt_used, sizeof(state->ldt_used));
  state->ldt_valid = 1;
  return 1;
}

#endif

void daze_kvm_resident_gdt_state_dispose(DazeKvmResidentGdtState *state) {
  if (state == NULL) return;
  free(state->ldt_bytes);
  *state = (DazeKvmResidentGdtState){0};
}

#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
static void resident_raw_trace_capture(const DazeKvmMachine *machine,
                                       DazeKvmResidentRawTrace *trace) {
  if (trace == NULL) return;
  *trace = (DazeKvmResidentRawTrace){0};
  if (machine == NULL || machine->guest == NULL || machine->vcpu < 0) return;
  struct kvm_sregs sregs;
  if (ioctl(machine->vcpu, KVM_GET_SREGS, &sregs) < 0) return;
  trace->cr0 = sregs.cr0;
  trace->gdt_base = sregs.gdt.base;
  trace->gdt_limit = sregs.gdt.limit;
  trace->idt_base = sregs.idt.base;
  trace->idt_limit = sregs.idt.limit;
  const uint8_t *const guest = machine->guest;
  const uint64_t gdt_08 = sregs.gdt.base + 0x08u;
  const uint64_t gdt_10 = sregs.gdt.base + 0x10u;
  const uint64_t gdt_18 = sregs.gdt.base + 0x18u;
  const uint64_t gdt_40 = sregs.gdt.base + 0x40u;
  if (gdt_08 <= UINT32_MAX && gdt_08 + sizeof(trace->gdt_08) <= machine->guest_size)
    memcpy(trace->gdt_08, guest + gdt_08, sizeof(trace->gdt_08));
  if (gdt_10 <= UINT32_MAX && gdt_10 + sizeof(trace->gdt_10) <= machine->guest_size)
    memcpy(trace->gdt_10, guest + gdt_10, sizeof(trace->gdt_10));
  if (gdt_18 <= UINT32_MAX && gdt_18 + sizeof(trace->gdt_18) <= machine->guest_size)
    memcpy(trace->gdt_18, guest + gdt_18, sizeof(trace->gdt_18));
  if (gdt_40 <= UINT32_MAX && gdt_40 + sizeof(trace->gdt_40) <= machine->guest_size)
    memcpy(trace->gdt_40, guest + gdt_40, sizeof(trace->gdt_40));
  if (0xfcu * 4u + sizeof(trace->ivt_fc) <= machine->guest_size)
    memcpy(trace->ivt_fc, guest + 0xfcu * 4u, sizeof(trace->ivt_fc));
  trace->ivt_fc_linear =
    ((uint32_t)daze_read_u16(trace->ivt_fc + 2) << 4) + daze_read_u16(trace->ivt_fc);
  if (trace->ivt_fc_linear + sizeof(trace->ivt_fc_target) <= machine->guest_size)
    memcpy(trace->ivt_fc_target, guest + trace->ivt_fc_linear, sizeof(trace->ivt_fc_target));
  if (0x2000u + sizeof(trace->transition_code) <= machine->guest_size)
    memcpy(trace->transition_code, guest + 0x2000u, sizeof(trace->transition_code));
  if (0x2080u + sizeof(trace->transition_gdtr) <= machine->guest_size)
    memcpy(trace->transition_gdtr, guest + 0x2080u, sizeof(trace->transition_gdtr));
  if (0x148d0u + sizeof(trace->transition_ds_gdtr) <= machine->guest_size)
    memcpy(trace->transition_ds_gdtr, guest + 0x148d0u, sizeof(trace->transition_ds_gdtr));
  const uint64_t idt_fc = sregs.idt.base + 0xfcu * 8u;
  if (idt_fc <= UINT32_MAX && idt_fc + sizeof(trace->idt_fc) <= machine->guest_size)
    memcpy(trace->idt_fc, guest + idt_fc, sizeof(trace->idt_fc));
  trace->valid = 1;
}

static void resident_raw_trace_print(const char *label, const DazeKvmResidentRawTrace *trace) {
  if (label == NULL || trace == NULL || !trace->valid) return;
  fprintf(stderr,
          "exec: resident raw %s cr0=%08llx gdt=%08llx/%04x idt=%08llx/%04x ivtfc=%02x%02x%02x%02x "
          "target=%05x:%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x "
          "gdt8=%02x%02x%02x%02x%02x%02x%02x%02x "
          "gdt10=%02x%02x%02x%02x%02x%02x%02x%02x "
          "gdt18=%02x%02x%02x%02x%02x%02x%02x%02x "
          "gdt40=%02x%02x%02x%02x%02x%02x%02x%02x "
          "idtfc=%02x%02x%02x%02x%02x%02x%02x%02x\n",
          label, (unsigned long long)trace->cr0, (unsigned long long)trace->gdt_base,
          trace->gdt_limit, (unsigned long long)trace->idt_base, trace->idt_limit, trace->ivt_fc[0],
          trace->ivt_fc[1], trace->ivt_fc[2], trace->ivt_fc[3], trace->ivt_fc_linear,
          trace->ivt_fc_target[0], trace->ivt_fc_target[1], trace->ivt_fc_target[2],
          trace->ivt_fc_target[3], trace->ivt_fc_target[4], trace->ivt_fc_target[5],
          trace->ivt_fc_target[6], trace->ivt_fc_target[7], trace->ivt_fc_target[8],
          trace->ivt_fc_target[9], trace->ivt_fc_target[10], trace->ivt_fc_target[11],
          trace->ivt_fc_target[12], trace->ivt_fc_target[13], trace->ivt_fc_target[14],
          trace->ivt_fc_target[15], trace->gdt_08[0], trace->gdt_08[1], trace->gdt_08[2],
          trace->gdt_08[3], trace->gdt_08[4], trace->gdt_08[5], trace->gdt_08[6], trace->gdt_08[7],
          trace->gdt_10[0], trace->gdt_10[1], trace->gdt_10[2], trace->gdt_10[3], trace->gdt_10[4],
          trace->gdt_10[5], trace->gdt_10[6], trace->gdt_10[7], trace->gdt_18[0], trace->gdt_18[1],
          trace->gdt_18[2], trace->gdt_18[3], trace->gdt_18[4], trace->gdt_18[5], trace->gdt_18[6],
          trace->gdt_18[7], trace->gdt_40[0], trace->gdt_40[1], trace->gdt_40[2], trace->gdt_40[3],
          trace->gdt_40[4], trace->gdt_40[5], trace->gdt_40[6], trace->gdt_40[7], trace->idt_fc[0],
          trace->idt_fc[1], trace->idt_fc[2], trace->idt_fc[3], trace->idt_fc[4], trace->idt_fc[5],
          trace->idt_fc[6], trace->idt_fc[7]);
  fprintf(stderr,
          "exec: resident raw %s transition=%02x%02x%02x%02x%02x%02x%02x%02x"
          "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x"
          "%02x%02x%02x%02x%02x%02x%02x%02x\n",
          label, trace->transition_code[0], trace->transition_code[1], trace->transition_code[2],
          trace->transition_code[3], trace->transition_code[4], trace->transition_code[5],
          trace->transition_code[6], trace->transition_code[7], trace->transition_code[8],
          trace->transition_code[9], trace->transition_code[10], trace->transition_code[11],
          trace->transition_code[12], trace->transition_code[13], trace->transition_code[14],
          trace->transition_code[15], trace->transition_code[16], trace->transition_code[17],
          trace->transition_code[18], trace->transition_code[19], trace->transition_code[20],
          trace->transition_code[21], trace->transition_code[22], trace->transition_code[23],
          trace->transition_code[24], trace->transition_code[25], trace->transition_code[26],
          trace->transition_code[27], trace->transition_code[28], trace->transition_code[29],
          trace->transition_code[30], trace->transition_code[31]);
  fprintf(stderr, "exec: resident raw %s transition-gdtr=%02x%02x%02x%02x%02x%02x\n", label,
          trace->transition_gdtr[0], trace->transition_gdtr[1], trace->transition_gdtr[2],
          trace->transition_gdtr[3], trace->transition_gdtr[4], trace->transition_gdtr[5]);
  fprintf(stderr, "exec: resident raw %s transition-ds-gdtr=%02x%02x%02x%02x%02x%02x\n", label,
          trace->transition_ds_gdtr[0], trace->transition_ds_gdtr[1], trace->transition_ds_gdtr[2],
          trace->transition_ds_gdtr[3], trace->transition_ds_gdtr[4], trace->transition_ds_gdtr[5]);
}
#endif

void daze_kvm_child_context_dispose(DazeKvmChildContext *context) {
  if (context == NULL) return;
  if (context->active) daze_dos_process_state_dispose(&context->parent_dos);
  free(context->child_image.bytes);
  daze_kvm_machine_snapshot_dispose(&context->machine);
  free(context->parent_dpmi);
  *context = (DazeKvmChildContext){0};
}

int daze_kvm_child_context_capture(DazeKvmChildContext *context, const DazeKvmMachine *machine,
                                   const DazeKvmRunnerRequestCommon *layout,
                                   DazeDosProcessState *dos_state, DazeDosMemory *dos_memory,
                                   DazeDpmiProcessState *dpmi_state) {
  if (context == NULL || context->active || machine == NULL || layout == NULL ||
      dos_state == NULL || dos_memory == NULL || dpmi_state == NULL)
    return 0;
  DazeKvmChildContext candidate = {.parent_layout = *layout};
  candidate.parent_dpmi = malloc(sizeof(*dpmi_state));
  if (candidate.parent_dpmi == NULL ||
      daze_kvm_machine_snapshot_take(machine, &candidate.machine) != DAZE_KVM_MACHINE_OK) {
    daze_kvm_child_context_dispose(&candidate);
    return 0;
  }
  candidate.parent_dos = *dos_state;
  candidate.parent_memory = *dos_memory;
  memcpy(candidate.parent_dpmi, dpmi_state, sizeof(*dpmi_state));
  candidate.active = 1;
  *dos_state = (DazeDosProcessState){0};
  *dos_memory = (DazeDosMemory){0};
  *dpmi_state = (DazeDpmiProcessState){0};
  *context = candidate;
  return 1;
}

int daze_kvm_child_context_restore(DazeKvmChildContext *context, DazeKvmMachine *machine,
                                   DazeDosProcessState *dos_state, DazeDosMemory *dos_memory,
                                   DazeDpmiProcessState *dpmi_state) {
  if (context == NULL || !context->active || machine == NULL || dos_state == NULL ||
      dos_memory == NULL || dpmi_state == NULL ||
      daze_kvm_machine_snapshot_restore(machine, &context->machine) != DAZE_KVM_MACHINE_OK)
    return 0;
  daze_dos_process_state_dispose(dos_state);
  *dos_state = context->parent_dos;
  *dos_memory = context->parent_memory;
  memcpy(dpmi_state, context->parent_dpmi, sizeof(*dpmi_state));
  daze_kvm_machine_snapshot_dispose(&context->machine);
  free(context->parent_dpmi);
  /* The child image has already been copied into guest RAM; restoration retains no
   * references. */
  free(context->child_image.bytes);
  *context = (DazeKvmChildContext){0};
  return 1;
}

int daze_kvm_resident_vector_projections_refresh(DazeKvmMachine *machine,
                                                 DazeKvmResidentGdtState *resident,
                                                 const DazeDosMemory *memory) {
  if (machine == NULL || resident == NULL || memory == NULL) return 0;
  for (size_t index = 0; index < DAZE_RAW_VECTOR_PROJECTION_MAX; ++index) {
    DazeRawVectorProjection *projection = &resident->raw_vector_projections[index];
    if (!projection->in_use) continue;
    int live = 0;
    for (size_t allocation = 0; allocation < DAZE_DOS_MEMORY_MAX_ALLOCS; ++allocation) {
      const DazeDosAllocation *block = &memory->allocations[allocation];
      if (block->in_use && block->segment == projection->allocation_segment &&
          block->paragraphs == projection->allocation_paragraphs)
        live = 1;
    }
    if (!live) {
      uint32_t offset = projection->selector & ~7u;
      if (offset + 7 > resident->ldt_limit || resident->ldt_base > UINT32_MAX - offset ||
          !daze_kvm_range_fits(machine->guest_size, resident->ldt_base + offset, 8))
        return 0;
      memset((uint8_t *)machine->guest + resident->ldt_base + offset, 0, 8);
      *projection = (DazeRawVectorProjection){0};
    }
  }
  return 1;
}

int daze_kvm_child_context_restore_resident(DazeKvmChildContext *context, DazeKvmMachine *machine,
                                            DazeDosProcessState *dos_state,
                                            DazeDosMemory *dos_memory,
                                            DazeDpmiProcessState *dpmi_state,
                                            uint16_t resident_paragraphs,
                                            DazeKvmResidentGdtState *resident_gdt_output) {
  if (context == NULL || !context->active || machine == NULL || machine->guest == NULL ||
      dos_state == NULL || dos_memory == NULL || dpmi_state == NULL || resident_paragraphs == 0)
    return 0;
  const uint16_t resident_segment = dos_state->psp_segment;
  const size_t resident_size = (size_t)resident_paragraphs << 4;
  const uint32_t resident_address = (uint32_t)resident_segment << 4;
  if (resident_address > machine->guest_size ||
      resident_size > machine->guest_size - resident_address)
    return 0;
  int allocation_found = 0;
  for (size_t index = 0; index < DAZE_DOS_MEMORY_MAX_ALLOCS; ++index) {
    const DazeDosAllocation *allocation = &dos_memory->allocations[index];
    if (allocation->in_use && allocation->segment == resident_segment &&
        allocation->paragraphs >= resident_paragraphs) {
      allocation_found = 1;
      break;
    }
  }
  if (!allocation_found) return 0;
  DazeDosMemory retained_memory = context->parent_memory;
  DazeDosAllocation *retained = daze_dos_memory_allocate(&retained_memory, resident_paragraphs);
  if (retained == NULL || retained->segment != resident_segment) return 0;
  uint8_t *const resident_bytes = malloc(resident_size);
  if (resident_bytes == NULL) return 0;
  memcpy(resident_bytes, (const uint8_t *)machine->guest + resident_address, resident_size);
  uint8_t raw_switch_ivt[4];
  uint8_t raw_switch_handler[DAZE_KVM_RAW_SWITCH_GATE_HANDLER_SIZE];
  const uint32_t raw_switch_ivt_address = DAZE_KVM_RAW_SWITCH_GATE_VECTOR * 4u;
  if (raw_switch_ivt_address + sizeof(raw_switch_ivt) > machine->guest_size ||
      k_dpmi_rm_gate_linear + sizeof(raw_switch_handler) > machine->guest_size) {
    free(resident_bytes);
    return 0;
  }
  memcpy(raw_switch_ivt, (const uint8_t *)machine->guest + raw_switch_ivt_address,
         sizeof(raw_switch_ivt));
  memcpy(raw_switch_handler, (const uint8_t *)machine->guest + k_dpmi_rm_gate_linear,
         sizeof(raw_switch_handler));
  const DazeDpmiProcessState resident_dpmi = *dpmi_state;
  DazeKvmResidentTransitionState resident_transition;
  if (!resident_transition_capture(machine, &resident_transition)) {
    free(resident_bytes);
    return 0;
  }
#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
  DazeKvmResidentGdtState resident_gdt;
  resident_gdt_capture(machine, &resident_gdt);
  if (!resident_ldt_capture(machine, dpmi_state, &resident_gdt)) {
    free(resident_bytes);
    return 0;
  }
  resident_gdt.real_transition_address = k_resident_transition_code_address;
  resident_gdt.real_transition_gdtr_address =
    k_resident_transition_code_address + k_resident_transition_gdtr_offset;
  memcpy(resident_gdt.real_transition_code, resident_transition.code,
         sizeof(resident_gdt.real_transition_code));
  memcpy(resident_gdt.real_transition_gdtr, resident_transition.gdtr,
         sizeof(resident_gdt.real_transition_gdtr));
  resident_gdt.real_transition_valid = resident_transition.valid;
  DazeKvmResidentRawTrace child_raw;
  const int raw_trace = getenv("DAZE_EXEC_TRACE") != NULL;
  if (raw_trace) resident_raw_trace_capture(machine, &child_raw);
#endif
  uint8_t vector_changed[256] = {0};
  uint16_t vector_offset[256], vector_segment[256];
  for (size_t vector = 0; vector < 256; ++vector) {
    vector_changed[vector] =
      dos_state->dos_vector_offset[vector] != context->parent_dos.dos_vector_offset[vector] ||
      dos_state->dos_vector_segment[vector] != context->parent_dos.dos_vector_segment[vector];
    vector_offset[vector] = dos_state->dos_vector_offset[vector];
    vector_segment[vector] = dos_state->dos_vector_segment[vector];
  }
  if (getenv("DAZE_EXEC_TRACE") != NULL) {
    fprintf(stderr, "exec: resident child psp=%04x paragraphs=%04x vectors", resident_segment,
            resident_paragraphs);
    for (size_t vector = 0; vector < 256; ++vector) {
      if (vector_changed[vector])
        fprintf(stderr, " %02zx=%04x:%04x", vector, vector_segment[vector], vector_offset[vector]);
    }
    fputc('\n', stderr);
  }
  if (!daze_kvm_child_context_restore(context, machine, dos_state, dos_memory, dpmi_state)) {
#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
    daze_kvm_resident_gdt_state_dispose(&resident_gdt);
#endif
    free(resident_bytes);
    return 0;
  }
  *dos_memory = retained_memory;
  memcpy((uint8_t *)machine->guest + resident_address, resident_bytes, resident_size);
  free(resident_bytes);
  /* DPMILOAD's resident return uses INT FCh. Preserve its IVT entry and handler bytes. */
  memcpy((uint8_t *)machine->guest + raw_switch_ivt_address, raw_switch_ivt,
         sizeof(raw_switch_ivt));
  memcpy((uint8_t *)machine->guest + k_dpmi_rm_gate_linear, raw_switch_handler,
         sizeof(raw_switch_handler));
  memcpy((uint8_t *)machine->guest + k_resident_transition_code_address, resident_transition.code,
         sizeof(resident_transition.code));
  memcpy((uint8_t *)machine->guest + k_resident_transition_code_address +
           k_resident_transition_gdtr_offset,
         resident_transition.gdtr, sizeof(resident_transition.gdtr));
#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
  if (!resident_gdt.valid || !daze_kvm_range_fits(machine->guest_size, resident_gdt.base,
                                                  (size_t)resident_gdt.limit + 1)) {
    daze_kvm_resident_gdt_state_dispose(&resident_gdt);
    return 0;
  }
  uint8_t *const restored_gdt = (uint8_t *)machine->guest + resident_gdt.base;
  memcpy(restored_gdt + 0x08, resident_gdt.code, sizeof(resident_gdt.code));
  memcpy(restored_gdt + 0x10, resident_gdt.ds, sizeof(resident_gdt.ds));
  memcpy(restored_gdt + 0x18, resident_gdt.es, sizeof(resident_gdt.es));
  memcpy(restored_gdt + 0x28, resident_gdt.transition, sizeof(resident_gdt.transition));
  memcpy(restored_gdt + 0x40, resident_gdt.stack, sizeof(resident_gdt.stack));
#else
  (void)resident_gdt_output;
#endif
  for (size_t vector = 0; vector < 256; ++vector) {
    if (!vector_changed[vector]) continue;
    const uint32_t ivt = (uint32_t)vector * 4;
    if (ivt + 4 > machine->guest_size) return 0;
    daze_write_u16((uint8_t *)machine->guest + ivt, vector_offset[vector]);
    daze_write_u16((uint8_t *)machine->guest + ivt + 2, vector_segment[vector]);
    dos_state->dos_vector_offset[vector] = vector_offset[vector];
    dos_state->dos_vector_segment[vector] = vector_segment[vector];
#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
    /* Only selector-shaped vector targets inside the retained DOS allocation qualify. */
    if (resident_gdt.ldt_valid &&
        daze_raw_vector_projection_eligible(dos_memory, resident_segment, vector_segment[vector],
                                            vector_offset[vector])) {
      uint16_t selector = vector_segment[vector];
      if ((uint32_t)(selector & ~7u) + 7u > resident_gdt.ldt_limit) {
        daze_kvm_resident_gdt_state_dispose(&resident_gdt);
        return 0;
      }
      uint8_t *descriptor = resident_gdt.ldt_bytes + (selector & ~7u);
      DazeDosAllocation allocation = {
        .segment = resident_segment, .paragraphs = resident_paragraphs, .in_use = 1};
      if (memcmp(descriptor, (uint8_t[8]){0}, 8) == 0 &&
          daze_raw_vector_projection_record(resident_gdt.raw_vector_projections,
                                            DAZE_RAW_VECTOR_PROJECTION_MAX, selector,
                                            resident_segment, resident_paragraphs, 1))
        (void)daze_raw_vector_projection_descriptor(&allocation, selector, descriptor);
    }
#endif
  }
#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
  if (resident_gdt_output != NULL)
    *resident_gdt_output = resident_gdt;
  else
    daze_kvm_resident_gdt_state_dispose(&resident_gdt);
#endif
  /* DPMILOAD's real-mode multiplex entry re-enters the protected DPMI service
   * it installed before becoming resident.  This state is owned by the
   * resident loader, not by the suspended EXEC parent. */
  *dpmi_state = resident_dpmi;
#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
  if (raw_trace) {
    DazeKvmResidentRawTrace parent_raw;
    resident_raw_trace_capture(machine, &parent_raw);
    resident_raw_trace_print("child", &child_raw);
    resident_raw_trace_print("parent", &parent_raw);
  }
#endif
  return 1;
}
