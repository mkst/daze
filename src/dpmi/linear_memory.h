#ifndef DAZE_DPMI_LINEAR_MEMORY_H
#define DAZE_DPMI_LINEAR_MEMORY_H

#include <stdint.h>

enum { DAZE_DPMI_LINEAR_MEMORY_MAX_ALLOCS = 64 };

typedef struct {
  uint32_t handle;
  uint32_t base;
  uint32_t allocated_size;
  int in_use;
} DazeDpmiLinearAllocation;

typedef struct {
  uint32_t first_base;
  uint32_t limit;
  uint32_t next_base;
  uint32_t next_handle;
  DazeDpmiLinearAllocation allocations[DAZE_DPMI_LINEAR_MEMORY_MAX_ALLOCS];
} DazeDpmiLinearMemory;

/* Linear allocation does not allocate a selector or materialize guest memory. */
typedef struct {
  int success;
  uint16_t dpmi_error;
  uint32_t base;
  uint32_t handle;
} DazeDpmiLinearAllocateResult;

void daze_dpmi_linear_memory_init(DazeDpmiLinearMemory *memory, uint32_t first_base,
                                  uint32_t limit);
int daze_dpmi_linear_memory_first_base_after(uint32_t resident_image_end, uint32_t minimum_base,
                                             uint32_t limit, uint32_t *first_base);
int daze_dpmi_linear_memory_allocate(DazeDpmiLinearMemory *memory, uint32_t size, uint32_t *base,
                                     uint32_t *handle);

/* Failure returns success=0, error 8012h, and zero base/handle without changing
 * allocator state. Success returns the allocated base/handle with error zero. */
void daze_dpmi_linear_memory_allocate_result(DazeDpmiLinearMemory *memory, uint32_t size,
                                             DazeDpmiLinearAllocateResult *result);
int daze_dpmi_linear_memory_release(DazeDpmiLinearMemory *memory, uint32_t handle);
int daze_dpmi_linear_memory_resize(DazeDpmiLinearMemory *memory, uint32_t handle, uint32_t size,
                                   uint32_t *base);
uint32_t daze_dpmi_linear_memory_largest_available(const DazeDpmiLinearMemory *memory);

#endif
