#ifndef DAZE_DOS_MEMORY_H
#define DAZE_DOS_MEMORY_H

#include <stdint.h>

enum { DAZE_DOS_MEMORY_MAX_ALLOCS = 64 };

typedef struct {
  uint16_t segment;
  uint16_t paragraphs;
  int in_use;
} DazeDosAllocation;

typedef struct {
  uint16_t first_segment;
  uint16_t end_segment;
  uint16_t next_segment;
  DazeDosAllocation allocations[DAZE_DOS_MEMORY_MAX_ALLOCS];
} DazeDosMemory;

typedef struct {
  int success;
  uint16_t dos_error;
  uint16_t maximum_paragraphs;
} DazeDosMemoryResizeResult;

void daze_dos_memory_init(DazeDosMemory *memory, uint16_t first_segment, uint16_t end_segment);
DazeDosAllocation *daze_dos_memory_allocate(DazeDosMemory *memory, uint16_t paragraphs);
int daze_dos_memory_release(DazeDosMemory *memory, uint16_t segment);
uint16_t daze_dos_memory_largest_available(const DazeDosMemory *memory);
void daze_dos_memory_resize(DazeDosMemory *memory, uint16_t segment, uint16_t paragraphs,
                            DazeDosMemoryResizeResult *result);
void daze_dos_memory_resize_result(uint16_t requested_paragraphs,
                                   DazeDosMemoryResizeResult *result);

#endif
