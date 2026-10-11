#include "linear_memory.h"

#include "dpmi_error.h"

#include <stddef.h>
#include <string.h>

static int align_page(uint32_t size, uint32_t *aligned) {
  const uint32_t value = (size + 0xfffu) & ~0xfffu;
  if (size == 0 || value < size) return 0;
  *aligned = value;
  return 1;
}

static DazeDpmiLinearAllocation *find_allocation(DazeDpmiLinearMemory *memory, uint32_t handle) {
  for (size_t index = 0; index < DAZE_DPMI_LINEAR_MEMORY_MAX_ALLOCS; ++index) {
    DazeDpmiLinearAllocation *allocation = &memory->allocations[index];
    if (allocation->in_use && allocation->handle == handle) return allocation;
  }
  return NULL;
}

static DazeDpmiLinearAllocation *reserve_allocation(DazeDpmiLinearMemory *memory) {
  for (size_t index = 0; index < DAZE_DPMI_LINEAR_MEMORY_MAX_ALLOCS; ++index) {
    if (!memory->allocations[index].in_use) return &memory->allocations[index];
  }
  return NULL;
}

void daze_dpmi_linear_memory_init(DazeDpmiLinearMemory *memory, uint32_t first_base,
                                  uint32_t limit) {
  memset(memory, 0, sizeof(*memory));
  memory->first_base = first_base;
  memory->limit = limit;
  memory->next_base = first_base;
  memory->next_handle = 1;
}

int daze_dpmi_linear_memory_first_base_after(uint32_t resident_image_end, uint32_t minimum_base,
                                             uint32_t limit, uint32_t *first_base) {
  uint32_t base = resident_image_end > minimum_base ? resident_image_end : minimum_base;
  if (first_base == NULL || base > UINT32_MAX - 0xfffu) return 0;
  base = (base + 0xfffu) & ~0xfffu;
  if (base >= limit) return 0;
  *first_base = base;
  return 1;
}

int daze_dpmi_linear_memory_allocate(DazeDpmiLinearMemory *memory, uint32_t size, uint32_t *base,
                                     uint32_t *handle) {
  uint32_t aligned = 0;
  DazeDpmiLinearAllocation *allocation = reserve_allocation(memory);
  if (!align_page(size, &aligned) || memory->next_base > memory->limit ||
      aligned > memory->limit - memory->next_base || memory->next_handle == 0 ||
      allocation == NULL) {
    return 0;
  }
  allocation->handle = memory->next_handle++;
  allocation->base = memory->next_base;
  allocation->allocated_size = aligned;
  allocation->in_use = 1;
  memory->next_base += aligned;
  *base = allocation->base;
  *handle = allocation->handle;
  return 1;
}

void daze_dpmi_linear_memory_allocate_result(DazeDpmiLinearMemory *memory, uint32_t size,
                                             DazeDpmiLinearAllocateResult *result) {
  if (result == NULL) return;
  *result = (DazeDpmiLinearAllocateResult){0};
  if (memory == NULL) {
    result->dpmi_error = DAZE_DPMI_ERR_NO_MEMORY; /* Linear memory unavailable. */
    return;
  }
  const DazeDpmiLinearMemory before = *memory;
  uint32_t base = 0;
  uint32_t handle = 0;
  if (!daze_dpmi_linear_memory_allocate(memory, size, &base, &handle)) {
    *memory = before;
    result->dpmi_error = DAZE_DPMI_ERR_NO_MEMORY;
    return;
  }
  result->success = 1;
  result->base = base;
  result->handle = handle;
}

int daze_dpmi_linear_memory_release(DazeDpmiLinearMemory *memory, uint32_t handle) {
  DazeDpmiLinearAllocation *allocation = find_allocation(memory, handle);
  if (allocation == NULL) return 0;
  if (allocation->base + allocation->allocated_size == memory->next_base) {
    memory->next_base = allocation->base;
  }
  allocation->in_use = 0;
  return 1;
}

int daze_dpmi_linear_memory_resize(DazeDpmiLinearMemory *memory, uint32_t handle, uint32_t size,
                                   uint32_t *base) {
  uint32_t aligned = 0;
  DazeDpmiLinearAllocation *allocation = find_allocation(memory, handle);
  if (allocation == NULL || !align_page(size, &aligned)) return 0;
  const uint32_t old_end = allocation->base + allocation->allocated_size;
  if (aligned > allocation->allocated_size &&
      (old_end != memory->next_base ||
       aligned - allocation->allocated_size > memory->limit - old_end)) {
    return 0;
  }
  if (old_end == memory->next_base) memory->next_base = allocation->base + aligned;
  allocation->allocated_size = aligned;
  *base = allocation->base;
  return 1;
}

uint32_t daze_dpmi_linear_memory_largest_available(const DazeDpmiLinearMemory *memory) {
  return memory->limit - memory->next_base;
}
