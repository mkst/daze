#include "request.h"

#include "descriptor.h"
#include "dpmi_error.h"
#include "dpmi_function.h"

#include <string.h>

static void result_start(const DazeDpmiRequest *request, DazeDpmiResult *result) {
  *result = (DazeDpmiResult){0};
  result->ax = request->function;
}

static void result_fail(DazeDpmiResult *result, uint16_t dpmi_error) {
  result->success = 0;
  result->dpmi_error = dpmi_error;
  result->ax = dpmi_error;
}

void daze_dpmi_request_allocate_dos_memory(DazeDosMemory *memory, DazeDpmiLdtAllocator *allocator,
                                           const DazeDpmiRequest *request, DazeDpmiResult *result) {
  if (request == NULL || result == NULL) return;
  result_start(request, result);
  result->largest_available = memory == NULL ? 0 : daze_dos_memory_largest_available(memory);
  if (memory == NULL || request->count == 0) {
    result_fail(result, 8);
    return;
  }
  DazeDosMemory candidate = *memory;
  const DazeDosAllocation *allocation = daze_dos_memory_allocate(&candidate, request->count);
  if (allocation == NULL) {
    result_fail(result, 8);
    return;
  }
  const DazeDpmiRequest ldt_request = {.function = DAZE_DPMI_ALLOC_LDT, .count = 1};
  DazeDpmiResult ldt_result = {0};
  daze_dpmi_request_allocate_ldt_descriptors(&ldt_request, allocator, &ldt_result);
  if (!ldt_result.success) {
    result_fail(result, DAZE_DPMI_ERR_LDT_FULL);
    return;
  }
  result->success = 1;
  result->ax = allocation->segment;
  result->handle = ldt_result.ax;
  result->base = (uint32_t)allocation->segment << 4;
  daze_dpmi_descriptor_encode(result->descriptor, result->base,
                              ((uint32_t)request->count << 4) - 1u, 0x92, 0);
  *memory = candidate;
}

void daze_dpmi_request_allocate_ldt_descriptors(const DazeDpmiRequest *request,
                                                DazeDpmiLdtAllocator *allocator,
                                                DazeDpmiResult *result) {
  if (result == NULL || request == NULL || allocator == NULL) return;
  result_start(request, result);
  if (request->count == 0 || allocator->used == NULL || allocator->first_index == 0 ||
      allocator->first_index >= allocator->capacity ||
      request->count > allocator->capacity - allocator->first_index) {
    result_fail(result, DAZE_DPMI_ERR_LDT_FULL);
    return;
  }
  for (size_t first = allocator->first_index; first <= allocator->capacity - request->count;
       ++first) {
    size_t offset = 0;
    while (offset < request->count && allocator->used[first + offset] == 0)
      ++offset;
    if (offset != request->count) continue;
    memset(allocator->used + first, 1, request->count);
    result->success = 1;
    result->ax = (uint16_t)((uint16_t)first << 3 | 4u);
    return;
  }
  result_fail(result, DAZE_DPMI_ERR_LDT_FULL);
}

void daze_dpmi_request_get_selector_increment(const DazeDpmiRequest *request,
                                              DazeDpmiResult *result) {
  if (result == NULL || request == NULL) return;
  result_start(request, result);
  result->success = 1;
  result->ax = DAZE_DPMI_SET_LIMIT_2;
}

void daze_dpmi_request_free_ldt_descriptor(const DazeDpmiRequest *request,
                                           DazeDpmiLdtAllocator *allocator,
                                           DazeDpmiResult *result) {
  if (result == NULL || request == NULL || allocator == NULL) return;
  result_start(request, result);
  const size_t index = request->selector >> 3;
  if ((request->selector & 4u) == 0 || index < allocator->first_index ||
      index >= allocator->capacity || allocator->used == NULL || allocator->used[index] == 0) {
    result_fail(result, DAZE_DPMI_ERR_INVALID_SELECTOR);
    return;
  }
  allocator->used[index] = 0;
  result->success = 1;
}

void daze_dpmi_request_allocate_linear_memory(DazeDpmiLinearMemory *memory,
                                              const DazeDpmiRequest *request,
                                              DazeDpmiResult *result) {
  if (result == NULL || request == NULL) return;
  result_start(request, result);
  DazeDpmiLinearAllocateResult allocation;
  daze_dpmi_linear_memory_allocate_result(memory, request->size, &allocation);
  if (!allocation.success) {
    result_fail(result, allocation.dpmi_error);
    return;
  }
  result->success = 1;
  result->base = allocation.base;
  result->handle = allocation.handle;
}

void daze_dpmi_request_resize_linear_memory(DazeDpmiLinearMemory *memory,
                                            const DazeDpmiRequest *request,
                                            DazeDpmiResult *result) {
  if (result == NULL || request == NULL) return;
  result_start(request, result);
  uint32_t base = 0;
  if (memory == NULL ||
      !daze_dpmi_linear_memory_resize(memory, request->operand, request->size, &base)) {
    result_fail(result, DAZE_DPMI_ERR_NO_MEMORY);
    return;
  }
  result->success = 1;
  result->base = base;
}

void daze_dpmi_request_free_linear_memory(DazeDpmiLinearMemory *memory,
                                          const DazeDpmiRequest *request, DazeDpmiResult *result) {
  if (result == NULL || request == NULL) return;
  result_start(request, result);
  if (memory == NULL || !daze_dpmi_linear_memory_release(memory, request->operand)) {
    result_fail(result, DAZE_DPMI_ERR_INVALID_HANDLE);
    return;
  }
  result->success = 1;
}

void daze_dpmi_request_get_free_memory_information(const DazeDpmiLinearMemory *memory,
                                                   const DazeDpmiRequest *request,
                                                   DazeDpmiResult *result) {
  if (result == NULL || request == NULL || memory == NULL) return;
  result_start(request, result);
  result->success = 1;
  result->largest_available = daze_dpmi_linear_memory_largest_available(memory);
}

void daze_dpmi_request_get_version(const DazeDpmiRequest *request, DazeDpmiResult *result) {
  if (result == NULL || request == NULL) return;
  result_start(request, result);
  result->success = 1;
  /* DPMI 0400h uses binary decimal 90 (5Ah), not packed BCD, for the minor version. */
  result->ax = 0x005a;
  result->handle = 0x00000003;
  result->base = 0x00000003;
}

void daze_dpmi_request_lock_linear_region(const DazeDpmiRequest *request, DazeDpmiResult *result) {
  if (result == NULL || request == NULL) return;
  result_start(request, result);
  result->success = 1;
}

void daze_dpmi_request_get_segment_base(const DazeDpmiRequest *request, uint32_t base,
                                        DazeDpmiResult *result) {
  if (result == NULL || request == NULL) return;
  result_start(request, result);
  result->base = base;
  result->success = 1;
}

void daze_dpmi_request_set_segment_base(const DazeDpmiRequest *request, const uint8_t descriptor[8],
                                        DazeDpmiResult *result) {
  if (result == NULL || request == NULL || descriptor == NULL) return;
  result_start(request, result);
  memcpy(result->descriptor, descriptor, 8);
  daze_dpmi_descriptor_set_base(result->descriptor, request->operand);
  result->success = 1;
}

void daze_dpmi_request_set_segment_limit(const DazeDpmiRequest *request,
                                         const uint8_t descriptor[8], DazeDpmiResult *result) {
  if (result == NULL || request == NULL || descriptor == NULL) return;
  result_start(request, result);
  memcpy(result->descriptor, descriptor, 8);
  if (!daze_dpmi_descriptor_set_limit(result->descriptor, request->operand)) {
    result_fail(result, DAZE_DPMI_ERR_INVALID_SEGMENT);
    return;
  }
  result->success = 1;
}

void daze_dpmi_request_set_access_rights(const DazeDpmiRequest *request,
                                         const uint8_t descriptor[8], DazeDpmiResult *result) {
  if (result == NULL || request == NULL || descriptor == NULL) return;
  result_start(request, result);
  memcpy(result->descriptor, descriptor, 8);
  const uint8_t access = (uint8_t)request->rights;
  const uint8_t extended = (uint8_t)(request->rights >> 8);
  if ((extended & 0x10u) != 0 || (access & 0x10u) == 0 || ((access >> 5) & 3u) != 0 ||
      ((access & 0x80u) != 0 && (access & 0x08u) != 0 && (access & 0x06u) != 0x02u)) {
    result_fail(result, DAZE_DPMI_ERR_INVALID_SEGMENT);
    return;
  }
  daze_dpmi_descriptor_set_access(result->descriptor, request->rights);
  result->success = 1;
}

void daze_dpmi_request_create_data_alias(const DazeDpmiRequest *request,
                                         const uint8_t source_descriptor[8],
                                         DazeDpmiLdtAllocator *allocator, DazeDpmiResult *result) {
  if (result == NULL || request == NULL || source_descriptor == NULL || allocator == NULL) return;
  result_start(request, result);
  const uint16_t source_index = (uint16_t)(request->selector >> 3);
  if ((request->selector & 4u) != 0 || source_index == 0 || allocator->used == NULL ||
      allocator->first_index == 0 || allocator->first_index >= allocator->capacity ||
      (source_descriptor[5] & 0x98u) != 0x98u) {
    result_fail(result, DAZE_DPMI_ERR_INVALID_SELECTOR);
    return;
  }
  size_t slot = allocator->first_index;
  while (slot < allocator->capacity && allocator->used[slot] != 0)
    ++slot;
  if (slot == allocator->capacity) {
    result_fail(result, DAZE_DPMI_ERR_INVALID_SELECTOR);
    return;
  }
  memcpy(result->descriptor, source_descriptor, sizeof(result->descriptor));
  result->descriptor[5] = (uint8_t)((result->descriptor[5] & 0x60u) | 0x92u);
  allocator->used[slot] = 1;
  result->success = 1;
  result->ax = (uint16_t)((uint16_t)slot << 3 | 4u);
}

void daze_dpmi_request_get_exception_vector(const DazeDpmiRequest *request,
                                            const DazeDpmiExceptionVector *vectors, size_t count,
                                            DazeDpmiResult *result) {
  if (result == NULL || request == NULL) return;
  result_start(request, result);
  if (vectors == NULL || request->exception >= count) {
    result_fail(result, DAZE_DPMI_ERR_INVALID_SEGMENT);
    return;
  }
  result->success = 1;
  result->vector_segment = vectors[request->exception].segment;
  result->vector_offset = vectors[request->exception].offset;
}

void daze_dpmi_request_set_exception_vector(const DazeDpmiRequest *request,
                                            DazeDpmiExceptionVector *vectors, size_t count,
                                            DazeDpmiResult *result) {
  if (result == NULL || request == NULL) return;
  result_start(request, result);
  if (vectors == NULL || request->exception >= count) {
    result_fail(result, DAZE_DPMI_ERR_INVALID_SEGMENT);
    return;
  }
  vectors[request->exception].segment = request->vector_segment;
  vectors[request->exception].offset = request->vector_offset;
  result->success = 1;
}

void daze_dpmi_request_get_real_mode_vector(const DazeDpmiRequest *request,
                                            const uint16_t *segments, const uint16_t *offsets,
                                            size_t count, DazeDpmiResult *result) {
  if (result == NULL || request == NULL) return;
  result_start(request, result);
  if (segments == NULL || offsets == NULL || request->interrupt >= count) {
    result_fail(result, DAZE_DPMI_ERR_INVALID_SEGMENT);
    return;
  }
  result->success = 1;
  result->vector_segment = segments[request->interrupt];
  result->vector_offset = offsets[request->interrupt];
}

void daze_dpmi_request_set_real_mode_vector(const DazeDpmiRequest *request, uint16_t *segments,
                                            uint16_t *offsets, size_t count,
                                            DazeDpmiResult *result) {
  if (result == NULL || request == NULL) return;
  result_start(request, result);
  if (segments == NULL || offsets == NULL || request->interrupt >= count) {
    result_fail(result, DAZE_DPMI_ERR_INVALID_SEGMENT);
    return;
  }
  segments[request->interrupt] = request->vector_segment;
  offsets[request->interrupt] = request->vector_offset;
  result->success = 1;
}

void daze_dpmi_request_get_interrupt_vector(const DazeDpmiRequest *request,
                                            const DazeDpmiInterruptVector *vectors, size_t count,
                                            DazeDpmiResult *result) {
  if (result == NULL || request == NULL) return;
  result_start(request, result);
  if (vectors == NULL || request->interrupt >= count) {
    result_fail(result, DAZE_DPMI_ERR_INVALID_SEGMENT);
    return;
  }
  result->success = 1;
  result->interrupt_segment = vectors[request->interrupt].segment;
  result->interrupt_offset = vectors[request->interrupt].offset;
}

void daze_dpmi_request_set_interrupt_vector(const DazeDpmiRequest *request,
                                            DazeDpmiInterruptVector *vectors, size_t count,
                                            DazeDpmiResult *result) {
  if (result == NULL || request == NULL) return;
  result_start(request, result);
  if (vectors == NULL || request->interrupt >= count) {
    result_fail(result, DAZE_DPMI_ERR_INVALID_SEGMENT);
    return;
  }
  vectors[request->interrupt].segment = request->interrupt_segment;
  vectors[request->interrupt].offset = request->interrupt_offset;
  result->success = 1;
}

int daze_dpmi_request_vector_result_contract(const DazeDpmiRequest *request,
                                             const DazeDpmiResult *result,
                                             DazeDpmiVectorResultContract *contract) {
  if (request == NULL || result == NULL || contract == NULL ||
      request->function < DAZE_DPMI_GET_RM_VECTOR || request->function > DAZE_DPMI_SET_PM_VECTOR) {
    return 0;
  }
  memset(contract, 0, sizeof(*contract));
  contract->success = result->success;
  if (!result->success) {
    contract->write_ax16 = 1;
    contract->ax = result->ax;
    return 1;
  }
  switch (request->function) {
  case DAZE_DPMI_GET_RM_VECTOR:
  case DAZE_DPMI_GET_EXCEPTION:
    contract->write_cx16 = 1;
    contract->cx = result->vector_segment;
    contract->write_dx16 = 1;
    contract->dx = result->vector_offset;
    break;
  case DAZE_DPMI_GET_PM_VECTOR:
    contract->write_cx16 = 1;
    contract->cx = result->interrupt_segment;
    contract->write_edx = 1;
    contract->edx = result->interrupt_offset;
    break;
  default:
    break;
  }
  return 1;
}

int daze_dpmi_request_transition_result_contract(const DazeDpmiRequest *request,
                                                 const DazeDpmiResult *result,
                                                 DazeDpmiTransitionResultContract *contract) {
  if (request == NULL || result == NULL || contract == NULL ||
      (request->function != DAZE_DPMI_GET_STATE_SAVE &&
       request->function != DAZE_DPMI_GET_RAW_SWITCH)) {
    return 0;
  }
  memset(contract, 0, sizeof(*contract));
  contract->success = result->success;
  if (!result->success) {
    contract->write_ax16 = 1;
    contract->ax = result->ax;
    return 1;
  }
  if (request->function == DAZE_DPMI_GET_STATE_SAVE) {
    contract->write_ax16 = 1;
    contract->ax = result->state_buffer_size;
  }
  contract->write_bx16 = 1;
  contract->bx = result->rm_segment;
  contract->write_cx16 = 1;
  contract->cx = result->rm_offset;
  contract->write_si16 = 1;
  contract->si = result->pm_selector;
  contract->write_edi = 1;
  contract->edi = result->pm_offset;
  return 1;
}

int daze_dpmi_request_scalar_result_contract(const DazeDpmiRequest *request,
                                             const DazeDpmiResult *result,
                                             DazeDpmiScalarResultContract *contract) {
  if (request == NULL || result == NULL || contract == NULL ||
      (request->function != DAZE_DPMI_ALLOC_DOS_MEM && request->function != DAZE_DPMI_GET_VERSION &&
       request->function != DAZE_DPMI_GET_DISABLE_VIRT_INT &&
       request->function != DAZE_DPMI_GET_ENABLE_VIRT_INT)) {
    return 0;
  }
  memset(contract, 0, sizeof(*contract));
  contract->success = result->success;
  if (!result->success) {
    contract->write_ax16 = 1;
    contract->ax = result->ax;
    if (request->function == DAZE_DPMI_ALLOC_DOS_MEM) {
      contract->write_bx16 = 1;
      contract->bx = (uint16_t)result->largest_available;
    }
    return 1;
  }
  if (request->function == DAZE_DPMI_ALLOC_DOS_MEM) {
    contract->write_ax16 = 1;
    contract->ax = result->ax;
    contract->write_dx16 = 1;
    contract->dx = (uint16_t)result->handle;
  } else if (request->function == DAZE_DPMI_GET_VERSION) {
    contract->write_ax16 = 1;
    contract->ax = result->ax;
    contract->write_bx16 = 1;
    contract->bx = (uint16_t)result->handle;
    contract->write_cl = 1;
    contract->cl = (uint8_t)result->base;
    contract->write_dx16 = 1;
    contract->dx = 0x0870;
  } else {
    contract->write_al = 1;
    contract->al = result->previous_virtual_interrupts_enabled ? 1 : 0;
  }
  return 1;
}

void daze_dpmi_request_resize_loader_block(DazeDpmiLinearMemory *memory,
                                           const DazeDpmiRequest *request, DazeDpmiResult *result) {
  if (request == NULL || result == NULL) return;
  result_start(request, result);
  if (memory == NULL || request->operand > UINT16_MAX || request->size == 0 ||
      request->size > ((uint32_t)UINT16_MAX << 4) || (request->size & 15u) != 0 ||
      !daze_dpmi_linear_memory_resize(memory, request->operand, request->size, &result->base)) {
    result_fail(result, 9);
    result->largest_available =
      memory == NULL ? 0 : daze_dpmi_linear_memory_largest_available(memory);
    return;
  }
  result->success = 1;
}

void daze_dpmi_request_release_loader_block(DazeDpmiLinearMemory *memory,
                                            const DazeDpmiRequest *request,
                                            DazeDpmiResult *result) {
  if (request == NULL || result == NULL) return;
  result_start(request, result);
  if (memory == NULL || request->operand > UINT16_MAX ||
      !daze_dpmi_linear_memory_release(memory, request->operand)) {
    result_fail(result, 9);
    return;
  }
  result->success = 1;
}

int daze_dpmi_request_linear_result_contract(const DazeDpmiRequest *request,
                                             const DazeDpmiResult *result,
                                             DazeDpmiLinearResultContract *contract) {
  if (request == NULL || result == NULL || contract == NULL ||
      ((request->function < DAZE_DPMI_ALLOC_LINEAR ||
        request->function > DAZE_DPMI_RESIZE_LINEAR) &&
       request->function != DAZE_DPMI_FREE_DOS_MEM &&
       request->function != DAZE_DPMI_RESIZE_DOS_MEM)) {
    return 0;
  }
  memset(contract, 0, sizeof(*contract));
  contract->success = result->success;
  if (!result->success) {
    contract->write_ax16 = 1;
    contract->ax = result->ax;
    if (request->function == DAZE_DPMI_RESIZE_DOS_MEM) {
      contract->write_bx16 = 1;
      contract->bx = (uint16_t)(result->largest_available >> 4);
    }
    return 1;
  }
  if (request->function == DAZE_DPMI_ALLOC_LINEAR || request->function == DAZE_DPMI_RESIZE_LINEAR) {
    contract->write_bx16 = 1;
    contract->bx = (uint16_t)(result->base >> 16);
    contract->write_cx16 = 1;
    contract->cx = (uint16_t)result->base;
  }
  if (request->function == DAZE_DPMI_ALLOC_LINEAR) {
    contract->write_si16 = 1;
    contract->si = (uint16_t)(result->handle >> 16);
    contract->write_di16 = 1;
    contract->di = (uint16_t)result->handle;
  }
  return 1;
}

void daze_dpmi_request_get_state_save_endpoints(const DazeDpmiRequest *request,
                                                DazeDpmiResult *result) {
  if (result == NULL || request == NULL) return;
  result_start(request, result);
  result->success = 1;
  result->state_buffer_size = request->state_buffer_size;
  result->rm_segment = request->rm_segment;
  result->rm_offset = request->rm_offset;
  result->pm_selector = request->pm_selector;
  result->pm_offset = request->pm_offset;
}

void daze_dpmi_request_get_raw_switch_endpoints(const DazeDpmiRequest *request,
                                                DazeDpmiResult *result) {
  if (result == NULL || request == NULL) return;
  result_start(request, result);
  result->success = 1;
  result->rm_segment = request->rm_segment;
  result->rm_offset = request->rm_offset;
  result->pm_selector = request->pm_selector;
  result->pm_offset = request->pm_offset;
}

void daze_dpmi_request_get_and_disable_virtual_interrupts(int *virtual_interrupts_enabled,
                                                          DazeDpmiResult *result) {
  if (result == NULL) return;
  *result = (DazeDpmiResult){0};
  if (virtual_interrupts_enabled == NULL) {
    result_fail(result, DAZE_DPMI_ERR_INVALID_SEGMENT);
    return;
  }
  result->ax = DAZE_DPMI_GET_DISABLE_VIRT_INT;
  result->success = 1;
  result->previous_virtual_interrupts_enabled = *virtual_interrupts_enabled ? 1 : 0;
  *virtual_interrupts_enabled = 0;
}

void daze_dpmi_request_get_and_enable_virtual_interrupts(int *virtual_interrupts_enabled,
                                                         DazeDpmiResult *result) {
  if (result == NULL) return;
  *result = (DazeDpmiResult){0};
  if (virtual_interrupts_enabled == NULL) {
    result_fail(result, DAZE_DPMI_ERR_INVALID_SEGMENT);
    return;
  }
  result->ax = DAZE_DPMI_GET_ENABLE_VIRT_INT;
  result->success = 1;
  result->previous_virtual_interrupts_enabled = *virtual_interrupts_enabled ? 1 : 0;
  *virtual_interrupts_enabled = 1;
}
