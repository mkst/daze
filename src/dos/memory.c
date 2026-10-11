#include "memory.h"

#include <stddef.h>
#include <string.h>

#include "dos_error.h"

void daze_dos_memory_init(DazeDosMemory *memory, uint16_t first_segment, uint16_t end_segment) {
  memset(memory, 0, sizeof(*memory));
  memory->first_segment = first_segment;
  memory->end_segment = end_segment;
  memory->next_segment = first_segment;
}

DazeDosAllocation *daze_dos_memory_allocate(DazeDosMemory *memory, uint16_t paragraphs) {
  const uint32_t end = (uint32_t)memory->next_segment + paragraphs;
  if (end > memory->end_segment) return NULL;
  for (size_t index = 0; index < DAZE_DOS_MEMORY_MAX_ALLOCS; ++index) {
    DazeDosAllocation *allocation = &memory->allocations[index];
    if (!allocation->in_use) {
      allocation->segment = memory->next_segment;
      allocation->paragraphs = paragraphs;
      allocation->in_use = 1;
      memory->next_segment = (uint16_t)end;
      return allocation;
    }
  }
  return NULL;
}

int daze_dos_memory_release(DazeDosMemory *memory, uint16_t segment) {
  for (size_t index = 0; index < DAZE_DOS_MEMORY_MAX_ALLOCS; ++index) {
    DazeDosAllocation *allocation = &memory->allocations[index];
    if (allocation->in_use && allocation->segment == segment) {
      allocation->in_use = 0;
      return 1;
    }
  }
  return 0;
}

uint16_t daze_dos_memory_largest_available(const DazeDosMemory *memory) {
  return (uint16_t)(memory->end_segment - memory->next_segment);
}

void daze_dos_memory_resize(DazeDosMemory *memory, uint16_t segment, uint16_t paragraphs,
                            DazeDosMemoryResizeResult *result) {
  if (memory == NULL || result == NULL) return;
  *result = (DazeDosMemoryResizeResult){.success = 0, .dos_error = DAZE_DOS_ERR_INVALID_BLOCK, .maximum_paragraphs = 0};
  if (memory->next_segment == memory->first_segment && segment < memory->first_segment) {
    const uint32_t end = (uint32_t)segment + paragraphs;
    if (end > memory->end_segment) {
      result->dos_error = DAZE_DOS_ERR_NO_MEMORY;
      result->maximum_paragraphs = (uint16_t)(memory->end_segment - segment);
      return;
    }
    memory->first_segment = (uint16_t)end;
    memory->next_segment = (uint16_t)end;
    result->success = 1;
    result->dos_error = 0;
    return;
  }
  for (size_t index = 0; index < DAZE_DOS_MEMORY_MAX_ALLOCS; ++index) {
    DazeDosAllocation *allocation = &memory->allocations[index];
    if (!allocation->in_use || allocation->segment != segment) continue;
    const uint32_t end = (uint32_t)segment + paragraphs;
    const uint32_t allocation_end = (uint32_t)allocation->segment + allocation->paragraphs;
    if (allocation_end != memory->next_segment) {
      result->dos_error = DAZE_DOS_ERR_NO_MEMORY;
      result->maximum_paragraphs = allocation->paragraphs;
      return;
    }
    if (end > memory->end_segment) {
      result->dos_error = DAZE_DOS_ERR_NO_MEMORY;
      result->maximum_paragraphs = (uint16_t)(memory->end_segment - segment);
      return;
    }
    allocation->paragraphs = paragraphs;
    memory->next_segment = (uint16_t)end;
    result->success = 1;
    result->dos_error = 0;
    return;
  }
}

void daze_dos_memory_resize_result(uint16_t requested_paragraphs,
                                   DazeDosMemoryResizeResult *result) {
  if (result == NULL) return;
  result->success = requested_paragraphs != UINT16_MAX;
  result->dos_error = result->success ? 0 : DAZE_DOS_ERR_NO_MEMORY;
  result->maximum_paragraphs = result->success ? 0 : 0x7000;
}
