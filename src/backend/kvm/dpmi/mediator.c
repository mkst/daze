#include "mediator.h"
#include "rm_entry.h"

#include "dpmi_error.h"
#include "dpmi_function.h"
#include "kvm_bytes.h"
#include "kvm_range.h"
#include "port.h"
#include "selector.h"

#include <stdio.h>
#include <string.h>

enum {
  REC_AX = 0,
  REC_BX = 4,
  REC_CX = 8,
  REC_DX = 12,
  REC_DI = 16,
  REC_ES = 20,
  REC_SI = 24,
  REC_EIP = 28,
  REC_CS = 32,
  REC_FLAGS = 36,
  MAIL_AX = 0,
  MAIL_BX = 4,
  MAIL_CX = 8,
  MAIL_SI = 12,
  MAIL_DI = 16,
  MAIL_ES = 20,
  MAIL_DX = 24,
  MAIL_FLAGS = 28,

  RM_RETURN_STACK_SEGMENT = DAZE_SEL_RETURN_STACK,
  RM_RETURN_STACK_SP = 0x0be0,
};

static int range_valid(const DazeKvmDpmiMediator *mediator, uint32_t address, size_t size) {
  return mediator != NULL && mediator->guest != NULL &&
         daze_kvm_range_fits(mediator->guest_size, address, size);
}

static int state_valid(const DazeKvmDpmiMediator *mediator) {
  return mediator != NULL && mediator->linear_memory != NULL &&
         range_valid(mediator, mediator->record_address, DAZE_KVM_DPMI_RECORD_SIZE) &&
         range_valid(mediator, mediator->mailbox_address, DAZE_KVM_DPMI_MAILBOX_SIZE) &&
         range_valid(mediator, mediator->ldt_address, mediator->ldt_size) &&
         mediator->ldt_size >= 8;
}

int daze_kvm_dpmi_mediator_descriptor_address(const DazeKvmDpmiMediator *mediator,
                                              uint16_t selector, uint32_t *address) {
  const uint16_t index = (uint16_t)(selector >> 3);
  if ((selector & 4u) == 0 || index == 0 || (size_t)index > mediator->ldt_size / 8 - 1) {
    return 0;
  }
  *address = mediator->ldt_address + (uint32_t)index * 8;
  return range_valid(mediator, *address, 8);
}

int daze_kvm_dpmi_mediator_gdt_descriptor_address(const DazeKvmDpmiMediator *mediator,
                                                  uint16_t selector, uint32_t *address) {
  const uint16_t index = (uint16_t)(selector >> 3);
  if ((selector & 4u) != 0 || index == 0 || mediator->gdt_size < 8 ||
      (size_t)index > mediator->gdt_size / 8 - 1) {
    return 0;
  }
  *address = mediator->gdt_address + (uint32_t)index * 8;
  return range_valid(mediator, *address, 8);
}

static int descriptor_base(const DazeKvmDpmiMediator *mediator, uint16_t selector, uint32_t *base) {
  uint32_t address;
  if (base == NULL ||
      ((selector & 4u)
         ? !daze_kvm_dpmi_mediator_descriptor_address(mediator, selector, &address)
         : !daze_kvm_dpmi_mediator_gdt_descriptor_address(mediator, selector, &address)))
    return 0;
  const uint8_t *descriptor = mediator->guest + address;
  *base = (uint32_t)descriptor[2] | ((uint32_t)descriptor[3] << 8) |
          ((uint32_t)descriptor[4] << 16) | ((uint32_t)descriptor[7] << 24);
  return 1;
}

static int code_segment_is_32bit(const DazeKvmDpmiMediator *mediator, uint16_t selector,
                                 int *is_32bit) {
  uint32_t address;
  if (is_32bit == NULL ||
      ((selector & 4u)
         ? !daze_kvm_dpmi_mediator_descriptor_address(mediator, selector, &address)
         : !daze_kvm_dpmi_mediator_gdt_descriptor_address(mediator, selector, &address)))
    return 0;
  *is_32bit = (mediator->guest[address + 6] >> 6) & 1;
  return 1;
}

/* The gate conditionally reloads ES using the full reply word, so diagnostics must
 * retain its high half. */
static void record_vector_request(const DazeKvmDpmiMediator *mediator, const uint8_t *record,
                                  const DazeDpmiRequest *request, const DazeDpmiResult *result) {
  if (!daze_dpmi_vector_record_enabled()) return;
  const uint16_t function = request->function;
  const int exception = function == DAZE_DPMI_GET_EXCEPTION || function == DAZE_DPMI_SET_EXCEPTION;
  const uint8_t *mailbox = mediator->guest + mediator->mailbox_address;
  int db = -1;
  (void)code_segment_is_32bit(mediator, daze_read_u16(record + REC_CS), &db);
  DazeDpmiVectorRecord observed = {
    .backend = "kvm",
    .function = function,
    .cs = daze_read_u16(record + REC_CS),
    .ip = daze_read_u32(record + REC_EIP),
    .db = db,
    .bl = exception ? request->exception : request->interrupt,
    .off_bits = exception ? 16 : 32,
    .in_ecx = daze_read_u32(record + REC_CX),
    .in_edx = daze_read_u32(record + REC_DX),
    .in_edi = daze_read_u32(record + REC_DI),
    .in_es = daze_read_u32(record + REC_ES),
    .out_ecx = daze_read_u32(mailbox + MAIL_CX),
    .out_edx = daze_read_u32(mailbox + MAIL_DX),
    .out_edi = daze_read_u32(mailbox + MAIL_DI),
    .out_es = daze_read_u32(mailbox + MAIL_ES),
    .es_reload = daze_read_u32(mailbox + MAIL_ES) != daze_read_u32(record + REC_ES),
  };
  if (exception) {
    observed.res_segment = result->vector_segment;
    observed.res_offset = result->vector_offset;
    observed.slot_segment = mediator->exception_vectors[request->exception].segment;
    observed.slot_offset = mediator->exception_vectors[request->exception].offset;
  } else {
    observed.res_segment = result->interrupt_segment;
    observed.res_offset = result->interrupt_offset;
    observed.slot_segment = mediator->interrupt_vectors[request->interrupt].segment;
    observed.slot_offset = mediator->interrupt_vectors[request->interrupt].offset;
  }
  daze_dpmi_vector_record_print(&observed);
}

/* The gate loads full mailbox words; 16-bit results must preserve their saved upper
 * halves. */
static void pack_result(uint8_t mailbox[DAZE_KVM_DPMI_MAILBOX_SIZE], const uint8_t *record,
                        const DazeDpmiRequest *request, const DazeDpmiResult *result) {
  memset(mailbox, 0, DAZE_KVM_DPMI_MAILBOX_SIZE);
  daze_write_u32(mailbox + MAIL_AX, (daze_read_u32(record + REC_AX) & 0xffff0000u) | result->ax);
  daze_write_u32(mailbox + MAIL_BX, daze_read_u32(record + REC_BX));
  daze_write_u32(mailbox + MAIL_CX, daze_read_u32(record + REC_CX));
  daze_write_u32(mailbox + MAIL_SI, daze_read_u32(record + REC_SI));
  daze_write_u32(mailbox + MAIL_DI, daze_read_u32(record + REC_DI));
  daze_write_u32(mailbox + MAIL_ES, daze_read_u32(record + REC_ES));
  daze_write_u32(mailbox + MAIL_DX, daze_read_u32(record + REC_DX));
  DazeDpmiVectorResultContract vector_contract;
  if (daze_dpmi_request_vector_result_contract(request, result, &vector_contract)) {
    if (vector_contract.write_ax16)
      daze_write_u32(mailbox + MAIL_AX,
                     (daze_read_u32(record + REC_AX) & 0xffff0000u) | vector_contract.ax);
    if (vector_contract.write_cx16)
      daze_write_u32(mailbox + MAIL_CX,
                     (daze_read_u32(record + REC_CX) & 0xffff0000u) | vector_contract.cx);
    if (vector_contract.write_dx16)
      daze_write_u32(mailbox + MAIL_DX,
                     (daze_read_u32(record + REC_DX) & 0xffff0000u) | vector_contract.dx);
    if (vector_contract.write_edx) daze_write_u32(mailbox + MAIL_DX, vector_contract.edx);
  }
  DazeDpmiTransitionResultContract transition_contract;
  if (daze_dpmi_request_transition_result_contract(request, result, &transition_contract)) {
    if (transition_contract.write_ax16)
      daze_write_u32(mailbox + MAIL_AX,
                     (daze_read_u32(record + REC_AX) & 0xffff0000u) | transition_contract.ax);
    if (transition_contract.write_bx16)
      daze_write_u32(mailbox + MAIL_BX,
                     (daze_read_u32(record + REC_BX) & 0xffff0000u) | transition_contract.bx);
    if (transition_contract.write_cx16)
      daze_write_u32(mailbox + MAIL_CX,
                     (daze_read_u32(record + REC_CX) & 0xffff0000u) | transition_contract.cx);
    if (transition_contract.write_si16)
      daze_write_u32(mailbox + MAIL_SI,
                     (daze_read_u32(record + REC_SI) & 0xffff0000u) | transition_contract.si);
    if (transition_contract.write_edi) daze_write_u32(mailbox + MAIL_DI, transition_contract.edi);
  }
  DazeDpmiScalarResultContract scalar_contract;
  if (daze_dpmi_request_scalar_result_contract(request, result, &scalar_contract)) {
    if (scalar_contract.write_ax16)
      daze_write_u32(mailbox + MAIL_AX,
                     (daze_read_u32(record + REC_AX) & 0xffff0000u) | scalar_contract.ax);
    if (scalar_contract.write_al)
      daze_write_u32(mailbox + MAIL_AX,
                     (daze_read_u32(record + REC_AX) & 0xffffff00u) | scalar_contract.al);
    if (scalar_contract.write_bx16)
      daze_write_u32(mailbox + MAIL_BX,
                     (daze_read_u32(record + REC_BX) & 0xffff0000u) | scalar_contract.bx);
    if (scalar_contract.write_cl)
      daze_write_u32(mailbox + MAIL_CX,
                     (daze_read_u32(record + REC_CX) & 0xffffff00u) | scalar_contract.cl);
    if (scalar_contract.write_dx16)
      daze_write_u32(mailbox + MAIL_DX,
                     (daze_read_u32(record + REC_DX) & 0xffff0000u) | scalar_contract.dx);
  }
  DazeDpmiLinearResultContract linear_contract;
  if (daze_dpmi_request_linear_result_contract(request, result, &linear_contract)) {
    if (linear_contract.write_ax16)
      daze_write_u32(mailbox + MAIL_AX,
                     (daze_read_u32(record + REC_AX) & 0xffff0000u) | linear_contract.ax);
    if (linear_contract.write_bx16)
      daze_write_u32(mailbox + MAIL_BX,
                     (daze_read_u32(record + REC_BX) & 0xffff0000u) | linear_contract.bx);
    if (linear_contract.write_cx16)
      daze_write_u32(mailbox + MAIL_CX,
                     (daze_read_u32(record + REC_CX) & 0xffff0000u) | linear_contract.cx);
    if (linear_contract.write_si16)
      daze_write_u32(mailbox + MAIL_SI,
                     (daze_read_u32(record + REC_SI) & 0xffff0000u) | linear_contract.si);
    if (linear_contract.write_di16)
      daze_write_u32(mailbox + MAIL_DI,
                     (daze_read_u32(record + REC_DI) & 0xffff0000u) | linear_contract.di);
  }
  if (request->function == DAZE_DPMI_GET_BASE_2 && result->success) {
    daze_write_u32(mailbox + MAIL_CX, result->base >> 16);
    daze_write_u32(mailbox + MAIL_DX, result->base);
  }
  daze_write_u32(mailbox + MAIL_FLAGS, result->success ? 2u : 3u);
}

DazeKvmDpmiMediatorStatus daze_kvm_dpmi_mediator_process(DazeKvmDpmiMediator *mediator,
                                                         uint16_t port, uint8_t marker) {
  if (!state_valid(mediator) || port != DAZE_KVM_DPMI_MEDIATOR_PORT ||
      marker != DAZE_KVM_DPMI_MEDIATOR_MARKER) {
    return DAZE_KVM_DPMI_MEDIATOR_INVALID;
  }
  mediator->rm_procedure_present = 0;
  mediator->rm_procedure_is_interrupt = 0;
  const uint8_t *record = mediator->guest + mediator->record_address;
  const uint16_t function = daze_read_u16(record + REC_AX);
  if (getenv("DAZE_GDT08_TRACE") != NULL && mediator->gdt_size >= 16) {
    static uint8_t last[8] = {0};
    static int have_last;
    const uint8_t *gdt08 = mediator->guest + mediator->gdt_address + 8u * 8u;
    if (!have_last || memcmp(last, gdt08, sizeof(last)) != 0) {
      memcpy(last, gdt08, sizeof(last));
      have_last = 1;
      fprintf(stderr,
              "gdt08-trace: fn=%04x cs=%04x gdt08=%02x%02x%02x%02x%02x%02x%02x%02x access=%02x "
              "base=%08x\n",
              function, daze_read_u16(record + REC_CS), gdt08[0], gdt08[1], gdt08[2], gdt08[3],
              gdt08[4], gdt08[5], gdt08[6], gdt08[7], gdt08[5],
              (uint32_t)gdt08[2] | ((uint32_t)gdt08[3] << 8) | ((uint32_t)gdt08[4] << 16) |
                ((uint32_t)gdt08[7] << 24));
    }
  }
  const uint16_t selector = daze_read_u16(record + REC_BX);
  const uint32_t operand =
    ((uint32_t)daze_read_u16(record + REC_CX) << 16) | daze_read_u16(record + REC_DX);
  if (daze_read_u32(record + REC_CS) == 0 || (daze_read_u32(record + REC_FLAGS) & 2u) == 0) {
    return DAZE_KVM_DPMI_MEDIATOR_INVALID;
  }
  DazeDpmiRequest request = {
    .function = function,
    .selector = selector,
    .size = ((uint32_t)daze_read_u16(record + REC_BX) << 16) | daze_read_u16(record + REC_CX),
    .operand = operand,
    .rights = daze_read_u16(record + REC_CX),
    .exception = (uint8_t)selector,
    .interrupt = (uint8_t)selector,
    .vector_segment = (function == DAZE_DPMI_SET_RM_VECTOR || function == DAZE_DPMI_SET_EXCEPTION)
                        ? daze_read_u16(record + REC_CX)
                        : daze_read_u16(record + REC_ES),
    .vector_offset = (function == DAZE_DPMI_SET_RM_VECTOR || function == DAZE_DPMI_SET_EXCEPTION)
                       ? daze_read_u16(record + REC_DX)
                       : daze_read_u16(record + REC_DI),
    .interrupt_segment = daze_read_u16(record + REC_CX),
    .interrupt_offset = daze_read_u32(record + REC_DX),
    .count = daze_read_u16(record + REC_CX)};
  DazeDpmiResult result;
  uint32_t descriptor = 0;
  switch (function) {
  case DAZE_DPMI_GET_RM_VECTOR:
    daze_dpmi_request_get_real_mode_vector(&request, mediator->real_mode_vector_segment,
                                           mediator->real_mode_vector_offset,
                                           mediator->real_mode_vector_count, &result);
    break;
  case DAZE_DPMI_SET_RM_VECTOR:
    daze_dpmi_request_set_real_mode_vector(&request, mediator->real_mode_vector_segment,
                                           mediator->real_mode_vector_offset,
                                           mediator->real_mode_vector_count, &result);
    break;
  case DAZE_DPMI_ALLOC_LDT: {
    if (mediator->ldt_used == NULL || mediator->ldt_used_count < mediator->ldt_size / 8) {
      return DAZE_KVM_DPMI_MEDIATOR_INVALID;
    }
    DazeDpmiLdtAllocator allocator = {.used = mediator->ldt_used,
                                      .capacity = mediator->ldt_used_count,
                                      .first_index = mediator->ldt_first_index};
    daze_dpmi_request_allocate_ldt_descriptors(&request, &allocator, &result);
    if (result.success) {
      const uint8_t inert_data[8] = {0, 0, 0, 0, 0, 0x92, 0, 0};
      const uint16_t first = (uint16_t)(result.ax >> 3);
      for (uint16_t offset = 0; offset < request.count; ++offset) {
        uint32_t destination;
        if (!daze_kvm_dpmi_mediator_descriptor_address(
              mediator, (uint16_t)((first + offset) << 3 | 4u), &destination)) {
          return DAZE_KVM_DPMI_MEDIATOR_INVALID;
        }
        memcpy(mediator->guest + destination, inert_data, sizeof(inert_data));
      }
    }
    break;
  }
  case DAZE_DPMI_FREE_LDT: {
    if (mediator->ldt_used == NULL || mediator->ldt_used_count < mediator->ldt_size / 8) {
      return DAZE_KVM_DPMI_MEDIATOR_INVALID;
    }
    DazeDpmiLdtAllocator allocator = {.used = mediator->ldt_used,
                                      .capacity = mediator->ldt_used_count,
                                      .first_index = mediator->ldt_first_index};
    daze_dpmi_request_free_ldt_descriptor(&request, &allocator, &result);
    if (result.success) {
      uint32_t destination;
      if (!daze_kvm_dpmi_mediator_descriptor_address(mediator, selector, &destination))
        return DAZE_KVM_DPMI_MEDIATOR_INVALID;
      memset(mediator->guest + destination, 0, 8);
    }
    break;
  }
  case DAZE_DPMI_GET_BASE:
    daze_dpmi_request_get_selector_increment(&request, &result);
    break;
  case DAZE_DPMI_ALLOC_LINEAR:
    daze_dpmi_request_allocate_linear_memory(mediator->linear_memory, &request, &result);
    break;
  case DAZE_DPMI_ALLOC_DOS_MEM: {
    if (mediator->dos_memory == NULL || mediator->ldt_used == NULL ||
        mediator->ldt_used_count < mediator->ldt_size / 8)
      return DAZE_KVM_DPMI_MEDIATOR_INVALID;
    DazeDpmiLdtAllocator allocator = {.used = mediator->ldt_used,
                                      .capacity = mediator->ldt_size / 8,
                                      .first_index = mediator->ldt_first_index};
    request.count = selector;
    daze_dpmi_request_allocate_dos_memory(mediator->dos_memory, &allocator, &request, &result);
    if (result.success) {
      uint32_t destination;
      if (!daze_kvm_dpmi_mediator_descriptor_address(mediator, (uint16_t)result.handle,
                                                     &destination))
        return DAZE_KVM_DPMI_MEDIATOR_INVALID;
      memcpy(mediator->guest + destination, result.descriptor, 8);
    }
    break;
  }
  case DAZE_DPMI_RESIZE_DOS_MEM:
    request.size = (uint32_t)selector << 4;
    request.operand = daze_read_u16(record + REC_DX);
    daze_dpmi_request_resize_loader_block(mediator->linear_memory, &request, &result);
    break;
  case DAZE_DPMI_FREE_DOS_MEM: {
    request.operand = daze_read_u16(record + REC_DX);
    const uint16_t token = (uint16_t)request.operand;
    const size_t slot = token >> 3;
    uint32_t base = 0;
    if (mediator->dos_memory != NULL && mediator->ldt_used != NULL &&
        slot >= mediator->ldt_first_index && slot < mediator->ldt_used_count &&
        mediator->ldt_used[slot] != 0 &&
        daze_kvm_dpmi_mediator_descriptor_address(mediator, token, &descriptor) &&
        descriptor_base(mediator, token, &base) && (base & 0xfu) == 0 &&
        (base >> 4) <= UINT16_MAX &&
        daze_dos_memory_release(mediator->dos_memory, (uint16_t)(base >> 4))) {
      memset(mediator->guest + descriptor, 0, 8);
      mediator->ldt_used[slot] = 0;
      result = (DazeDpmiResult){.success = 1, .ax = function};
      break;
    }
    daze_dpmi_request_release_loader_block(mediator->linear_memory, &request, &result);
    break;
  }
  case DAZE_DPMI_FREE_LINEAR: {
    DazeDpmiRequest free_request = request;
    free_request.operand =
      ((uint32_t)daze_read_u16(record + REC_SI) << 16) | daze_read_u16(record + REC_DI);
    daze_dpmi_request_free_linear_memory(mediator->linear_memory, &free_request, &result);
    break;
  }
  case DAZE_DPMI_RESIZE_LINEAR: {
    DazeDpmiRequest resize = request;
    resize.operand =
      ((uint32_t)daze_read_u16(record + REC_SI) << 16) | daze_read_u16(record + REC_DI);
    daze_dpmi_request_resize_linear_memory(mediator->linear_memory, &resize, &result);
    break;
  }
  case DAZE_DPMI_GET_VERSION:
    daze_dpmi_request_get_version(&request, &result);
    break;
  case DAZE_DPMI_LOCK_LINEAR:
  case DAZE_DPMI_UNLOCK_LINEAR:
    daze_dpmi_request_lock_linear_region(&request, &result);
    break;
  case DAZE_DPMI_GET_BASE_2: {
    uint32_t base;
    if (!descriptor_base(mediator, selector, &base)) return DAZE_KVM_DPMI_MEDIATOR_INVALID;
    daze_dpmi_request_get_segment_base(&request, base, &result);
    break;
  }
  case DAZE_DPMI_GET_FREE_MEM: {
    const uint16_t es = daze_read_u16(record + REC_ES);
    const uint16_t di = daze_read_u16(record + REC_DI);
    uint8_t information[DAZE_DPMI_FREE_MEMORY_INFORMATION_SIZE];
    uint32_t base;
    daze_dpmi_request_get_free_memory_information(mediator->linear_memory, &request, &result);
    if (!result.success || !descriptor_base(mediator, es, &base) || base > UINT32_MAX - di ||
        !range_valid(mediator, base + di, sizeof(information))) {
      return DAZE_KVM_DPMI_MEDIATOR_INVALID;
    }
    daze_dpmi_free_memory_information_encode(result.largest_available, information);
    memcpy(mediator->guest + base + di, information, sizeof(information));
    break;
  }
  case DAZE_DPMI_SET_LIMIT:
    if (!daze_kvm_dpmi_mediator_descriptor_address(mediator, selector, &descriptor))
      return DAZE_KVM_DPMI_MEDIATOR_INVALID;
    daze_dpmi_request_set_segment_base(&request, mediator->guest + descriptor, &result);
    if (result.success) memcpy(mediator->guest + descriptor, result.descriptor, 8);
    break;
  case DAZE_DPMI_SET_LIMIT_2:
    if (!daze_kvm_dpmi_mediator_descriptor_address(mediator, selector, &descriptor))
      return DAZE_KVM_DPMI_MEDIATOR_INVALID;
    daze_dpmi_request_set_segment_limit(&request, mediator->guest + descriptor, &result);
    if (result.success) memcpy(mediator->guest + descriptor, result.descriptor, 8);
    break;
  case DAZE_DPMI_SET_ACCESS:
    if (!daze_kvm_dpmi_mediator_descriptor_address(mediator, selector, &descriptor))
      return DAZE_KVM_DPMI_MEDIATOR_INVALID;
    daze_dpmi_request_set_access_rights(&request, mediator->guest + descriptor, &result);
    if (result.success) memcpy(mediator->guest + descriptor, result.descriptor, 8);
    break;
  case DAZE_DPMI_ALLOC_LDT_MULTI: {
    uint32_t source_descriptor;
    if (!daze_kvm_dpmi_mediator_gdt_descriptor_address(mediator, selector, &source_descriptor) ||
        mediator->ldt_used == NULL || mediator->ldt_used_count < mediator->ldt_size / 8) {
      return DAZE_KVM_DPMI_MEDIATOR_INVALID;
    }
    DazeDpmiLdtAllocator allocator = {.used = mediator->ldt_used,
                                      .capacity = mediator->ldt_used_count,
                                      .first_index = mediator->ldt_first_index};
    daze_dpmi_request_create_data_alias(&request, mediator->guest + source_descriptor, &allocator,
                                        &result);
    if (result.success) {
      uint32_t alias_descriptor;
      if (!daze_kvm_dpmi_mediator_descriptor_address(mediator, result.ax, &alias_descriptor)) {
        return DAZE_KVM_DPMI_MEDIATOR_INVALID;
      }
      memcpy(mediator->guest + alias_descriptor, result.descriptor, 8);
    }
    break;
  }
  case DAZE_DPMI_GET_DESCRIPTOR: {
    const uint16_t es = daze_read_u16(record + REC_ES);
    const uint16_t di = daze_read_u16(record + REC_DI);
    uint32_t destination_base;
    /* Get Descriptor accepts only LDT selectors.  An invalid source is a
     * guest-visible DPMI error, not an invalid mediator record: the client
     * must be allowed to observe AX=8022h and CF set. */
    if (!daze_kvm_dpmi_mediator_descriptor_address(mediator, selector, &descriptor)) {
      result = (DazeDpmiResult){.success = 0, .ax = DAZE_DPMI_ERR_INVALID_SELECTOR};
      break;
    }
    if (!descriptor_base(mediator, es, &destination_base) || destination_base > UINT32_MAX - di ||
        !range_valid(mediator, destination_base + di, 8)) {
      result = (DazeDpmiResult){.success = 0, .ax = DAZE_DPMI_ERR_INVALID_SELECTOR_ALIAS};
      break;
    }
    memcpy(mediator->guest + destination_base + di, mediator->guest + descriptor, 8);
    result = (DazeDpmiResult){.success = 1, .ax = function};
    break;
  }
  case DAZE_DPMI_SET_DESCRIPTOR: {
    const uint16_t es = daze_read_u16(record + REC_ES);
    const uint16_t di = daze_read_u16(record + REC_DI);
    uint32_t source_base;
    /* Set Descriptor replaces all eight bytes; 0009h validates rights but must not
     * supply the mutation result. */
    if (!daze_kvm_dpmi_mediator_descriptor_address(mediator, selector, &descriptor)) {
      result = (DazeDpmiResult){.success = 0, .ax = DAZE_DPMI_ERR_INVALID_SELECTOR};
      break;
    }
    if (!descriptor_base(mediator, es, &source_base) || source_base > UINT32_MAX - di ||
        !range_valid(mediator, source_base + di, 8)) {
      result = (DazeDpmiResult){.success = 0, .ax = DAZE_DPMI_ERR_INVALID_SELECTOR_ALIAS};
      break;
    }
    uint8_t image[8];
    memcpy(image, mediator->guest + source_base + di, sizeof(image));
    request.rights = (uint16_t)image[5] | ((uint16_t)image[6] << 8);
    daze_dpmi_request_set_access_rights(&request, image, &result);
    if (result.success) memcpy(mediator->guest + descriptor, result.descriptor, 8);
    break;
  }
  case DAZE_DPMI_GET_EXCEPTION:
    daze_dpmi_request_get_exception_vector(
      &request, mediator->exception_vectors,
      sizeof(mediator->exception_vectors) / sizeof(mediator->exception_vectors[0]), &result);
    break;
  case DAZE_DPMI_SET_EXCEPTION:
    daze_dpmi_request_set_exception_vector(
      &request, mediator->exception_vectors,
      sizeof(mediator->exception_vectors) / sizeof(mediator->exception_vectors[0]), &result);
    break;
  case DAZE_DPMI_GET_PM_VECTOR:
    daze_dpmi_request_get_interrupt_vector(
      &request, mediator->interrupt_vectors,
      sizeof(mediator->interrupt_vectors) / sizeof(mediator->interrupt_vectors[0]), &result);
    if (result.success && mediator->interrupt_vectors[request.interrupt].segment == 0 &&
        mediator->interrupt_vectors[request.interrupt].offset == 0 &&
        (mediator->default_interrupt_vectors[request.interrupt].segment != 0 ||
         mediator->default_interrupt_vectors[request.interrupt].offset != 0)) {
      result.interrupt_segment = mediator->default_interrupt_vectors[request.interrupt].segment;
      result.interrupt_offset = mediator->default_interrupt_vectors[request.interrupt].offset;
    }
    break;
  case DAZE_DPMI_SET_PM_VECTOR:
    daze_dpmi_request_set_interrupt_vector(
      &request, mediator->interrupt_vectors,
      sizeof(mediator->interrupt_vectors) / sizeof(mediator->interrupt_vectors[0]), &result);
    if (result.success) daze_kvm_rm_entry_publish_vectors(mediator);
    break;
  case DAZE_DPMI_GET_STATE_SAVE:
    request.state_buffer_size = mediator->state_save_endpoints.state_buffer_size;
    request.rm_segment = mediator->state_save_endpoints.rm_segment;
    request.rm_offset = mediator->state_save_endpoints.rm_offset;
    request.pm_selector = mediator->state_save_endpoints.pm_selector;
    request.pm_offset = mediator->state_save_endpoints.pm_offset;
    daze_dpmi_request_get_state_save_endpoints(&request, &result);
    break;
  case DAZE_DPMI_GET_RAW_SWITCH:
    request.rm_segment = mediator->raw_switch_endpoints.rm_segment;
    request.rm_offset = mediator->raw_switch_endpoints.rm_offset;
    request.pm_selector = mediator->raw_switch_endpoints.pm_selector;
    request.pm_offset = mediator->raw_switch_endpoints.pm_offset;
    daze_dpmi_request_get_raw_switch_endpoints(&request, &result);
    break;
  case DAZE_DPMI_GET_DISABLE_VIRT_INT:
    daze_dpmi_request_get_and_disable_virtual_interrupts(mediator->virtual_interrupts_enabled,
                                                         &result);
    break;
  case DAZE_DPMI_GET_ENABLE_VIRT_INT:
    daze_dpmi_request_get_and_enable_virtual_interrupts(mediator->virtual_interrupts_enabled,
                                                        &result);
    break;
  case DAZE_DPMI_SIMULATE_RM: {
    /* The mailbox preserves the caller's registers until the real-mode reflection
     * completes. */
    const uint16_t es = daze_read_u16(record + REC_ES);
    const uint16_t di = daze_read_u16(record + REC_DI);
    uint32_t es_base = 0;
    int code_is_32bit = 0;
    if (!descriptor_base(mediator, es, &es_base) || es_base > UINT32_MAX - di ||
        !range_valid(mediator, es_base + di, DAZE_DPMI_RM_FRAME_SIZE) ||
        !code_segment_is_32bit(mediator, daze_read_u16(record + REC_CS), &code_is_32bit)) {
      return DAZE_KVM_DPMI_MEDIATOR_INVALID;
    }
    uint8_t frame[DAZE_DPMI_RM_FRAME_SIZE];
    memcpy(frame, mediator->guest + es_base + di, sizeof(frame));
    if (!daze_dpmi_rm_frame_parse(frame, es_base, di, daze_read_u16(record + REC_CX),
                                  daze_read_u16(record + REC_BX), code_is_32bit,
                                  &mediator->rm_procedure)) {
      return DAZE_KVM_DPMI_MEDIATOR_INVALID;
    }
    result = (DazeDpmiResult){.success = 1, .ax = function};
    mediator->rm_procedure_present = 1;
    break;
  }
  case DAZE_DPMI_CALL_RM: {
    /* Both 16-bit and 32-bit callers use the INT FDh; IRET stub with no copied stack
     * words. */
    const uint16_t es = daze_read_u16(record + REC_ES);
    const uint32_t di = daze_read_u32(record + REC_DI);
    const uint16_t bx = daze_read_u16(record + REC_BX);
    const uint16_t cx = daze_read_u16(record + REC_CX);
    uint32_t es_base = 0;
    int code_is_32bit = 0;
    if (bx != 0x0021 || cx != 0 || !descriptor_base(mediator, es, &es_base) ||
        es_base > UINT32_MAX - di ||
        !range_valid(mediator, es_base + di, DAZE_DPMI_RM_FRAME_SIZE) ||
        !code_segment_is_32bit(mediator, daze_read_u16(record + REC_CS), &code_is_32bit)) {
      return DAZE_KVM_DPMI_MEDIATOR_INVALID;
    }
    const uint8_t *frame = mediator->guest + es_base + di;
    const uint16_t supplied_ss = daze_read_u16(frame + DAZE_DPMI_RM_SS);
    const uint16_t supplied_sp = daze_read_u16(frame + DAZE_DPMI_RM_SP);
    const uint16_t frame_ss =
      supplied_ss == 0 && supplied_sp == 0 ? RM_RETURN_STACK_SEGMENT : supplied_ss;
    const uint16_t frame_sp =
      supplied_ss == 0 && supplied_sp == 0 ? RM_RETURN_STACK_SP : supplied_sp;
    DazeDpmiRmStack stack;
    if (!daze_dpmi_rm_stack_plan(frame_ss, frame_sp, 6, 0, mediator->guest_size, &stack)) {
      return DAZE_KVM_DPMI_MEDIATOR_INVALID;
    }
    mediator->rm_procedure = (DazeDpmiRmProcedure){.target_cs = 0x0300,
                                                   .target_ip = 0,
                                                   .frame_ss = frame_ss,
                                                   .frame_sp = frame_sp,
                                                   .procedure_sp = stack.sp,
                                                   .frame_address = es_base + di,
                                                   .stack_address = stack.address};
    mediator->rm_procedure_present = 1;
    mediator->rm_procedure_is_interrupt = 1;
    result = (DazeDpmiResult){.success = 1, .ax = function};

    break;
  }
  default:
    fprintf(stderr,
            "kvm-mediator: unsupported DPMI 31h/%04xh (BX=%04x CX=%04x DX=%04x ES=%04x DI=%04x "
            "SI=%04x)\n",
            function, daze_read_u16(record + REC_BX), daze_read_u16(record + REC_CX),
            daze_read_u16(record + REC_DX), daze_read_u16(record + REC_ES),
            daze_read_u16(record + REC_DI), daze_read_u16(record + REC_SI));
    return DAZE_KVM_DPMI_MEDIATOR_UNSUPPORTED;
  }
  pack_result(mediator->guest + mediator->mailbox_address, record, &request, &result);
  if (result.success &&
      (function == DAZE_DPMI_GET_EXCEPTION || function == DAZE_DPMI_SET_EXCEPTION ||
       function == DAZE_DPMI_GET_PM_VECTOR || function == DAZE_DPMI_SET_PM_VECTOR))
    record_vector_request(mediator, record, &request, &result);
  return mediator->rm_procedure_present ? DAZE_KVM_DPMI_MEDIATOR_RM_PROCEDURE
                                        : DAZE_KVM_DPMI_MEDIATOR_OK;
}
