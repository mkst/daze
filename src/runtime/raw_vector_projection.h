#ifndef DAZE_RAW_VECTOR_PROJECTION_H
#define DAZE_RAW_VECTOR_PROJECTION_H

#include <stddef.h>
#include <stdint.h>

#include "descriptor.h"
#include "memory.h"

enum { DAZE_RAW_VECTOR_PROJECTION_MAX = 8 };

typedef struct {
  uint16_t selector;
  uint16_t allocation_segment;
  uint16_t allocation_paragraphs;
  int in_use;
} DazeRawVectorProjection;

static inline DazeRawVectorProjection *
daze_raw_vector_projection_find(DazeRawVectorProjection *projections, size_t count,
                                uint16_t selector) {
  if (projections == NULL) return NULL;
  for (size_t index = 0; index < count; ++index) {
    if (projections[index].in_use && projections[index].selector == selector)
      return &projections[index];
  }
  return NULL;
}

/* Repeated projection of an existing selector succeeds without claiming another LDT
 * slot. */
static inline int daze_raw_vector_projection_record(DazeRawVectorProjection *projections,
                                                    size_t count, uint16_t selector,
                                                    uint16_t allocation_segment,
                                                    uint16_t allocation_paragraphs,
                                                    int descriptor_empty) {
  if (daze_raw_vector_projection_find(projections, count, selector) != NULL) return 1;
  if (projections == NULL || !descriptor_empty) return 0;
  for (size_t index = 0; index < count; ++index) {
    if (projections[index].in_use) continue;
    projections[index] = (DazeRawVectorProjection){.selector = selector,
                                                   .allocation_segment = allocation_segment,
                                                   .allocation_paragraphs = allocation_paragraphs,
                                                   .in_use = 1};
    return 1;
  }
  return 0;
}

static inline size_t
daze_raw_vector_projection_forget_allocation(DazeRawVectorProjection *projections, size_t count,
                                             uint16_t allocation_segment) {
  size_t forgotten = 0;
  if (projections == NULL) return 0;
  for (size_t index = 0; index < count; ++index) {
    if (!projections[index].in_use || projections[index].allocation_segment != allocation_segment)
      continue;
    projections[index] = (DazeRawVectorProjection){0};
    ++forgotten;
  }
  return forgotten;
}

static inline int daze_raw_vector_projection_forget_selector(DazeRawVectorProjection *projections,
                                                             size_t count, uint16_t selector) {
  DazeRawVectorProjection *const projection =
    daze_raw_vector_projection_find(projections, count, selector);
  if (projection == NULL) return 0;
  *projection = (DazeRawVectorProjection){0};
  return 1;
}

/* Project only selector-shaped targets inside the DOS allocation owning the raw
 * excursion; ordinary IVT entries are not client descriptors. */
static inline int daze_raw_vector_projection_eligible(const DazeDosMemory *memory,
                                                      uint16_t allocation_segment,
                                                      uint16_t target_segment,
                                                      uint16_t target_offset) {
  if (memory == NULL || target_segment == 0 || (target_segment & 0x4u) == 0) return 0;
  for (size_t index = 0; index < DAZE_DOS_MEMORY_MAX_ALLOCS; ++index) {
    const DazeDosAllocation *const allocation = &memory->allocations[index];
    if (!allocation->in_use || allocation->segment != allocation_segment) continue;
    const uint32_t allocation_start = (uint32_t)allocation->segment << 4;
    const uint32_t allocation_end = allocation_start + ((uint32_t)allocation->paragraphs << 4);
    const uint32_t target = ((uint32_t)target_segment << 4) + target_offset;
    return target >= allocation_start && target < allocation_end;
  }
  return 0;
}

/* Construct the exact descriptor for an owned vector target. The descriptor
 * stays byte-granular, so its encoded limit must describe the remaining
 * allocation extent without silently truncating it. */
static inline int daze_raw_vector_projection_descriptor(const DazeDosAllocation *allocation,
                                                        uint16_t selector, uint8_t descriptor[8]) {
  if (allocation == NULL || !allocation->in_use || descriptor == NULL || selector == 0 ||
      (selector & 0x4u) == 0) {
    return 0;
  }
  const uint32_t base = (uint32_t)selector << 4;
  const uint32_t end = ((uint32_t)allocation->segment + allocation->paragraphs) << 4;
  if (base < ((uint32_t)allocation->segment << 4) || base >= end) return 0;
  const uint32_t limit = end - base - 1u;
  if (limit > 0x000fffffu) return 0;
  daze_dpmi_descriptor_encode(descriptor, base, limit, 0xf2, 0x00);
  return 1;
}

#endif
