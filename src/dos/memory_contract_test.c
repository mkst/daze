#include "memory.h"

#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void) {
  DazeDosMemory memory;
  daze_dos_memory_init(&memory, 0x3000, 0x3010);

  DazeDosAllocation *first = daze_dos_memory_allocate(&memory, 8);
  DazeDosAllocation *second = daze_dos_memory_allocate(&memory, 8);
  DazeDosMemory before_resize = memory;
  DazeDosMemoryResizeResult maximum = {0};
  DazeDosMemoryResizeResult accepted = {0};
  daze_dos_memory_resize_result(0xffff, &maximum);
  const int maximum_unchanged = memcmp(&memory, &before_resize, sizeof(memory)) == 0;
  daze_dos_memory_resize_result(0x0d73, &accepted);
  const int accepted_unchanged = memcmp(&memory, &before_resize, sizeof(memory)) == 0;
  DazeDosMemory expanded_memory;
  daze_dos_memory_init(&expanded_memory, 0x3000, 0x3100);
  DazeDosAllocation *expanded = daze_dos_memory_allocate(&expanded_memory, 8);
  DazeDosMemoryResizeResult expanded_result = {0};
  daze_dos_memory_resize(&expanded_memory, 0x3000, 0x10, &expanded_result);
  DazeDosAllocation *after_expand = daze_dos_memory_allocate(&expanded_memory, 1);
  DazeDosMemory root_memory;
  daze_dos_memory_init(&root_memory, 0x3000, 0xa000);
  DazeDosMemoryResizeResult root_result = {0};
  daze_dos_memory_resize(&root_memory, 0x0ff0, 0x166f, &root_result);
  DazeDosAllocation *after_root_resize = daze_dos_memory_allocate(&root_memory, 1);
  const int pass = first != NULL && first->segment == 0x3000 && second != NULL &&
                   second->segment == 0x3008 && daze_dos_memory_largest_available(&memory) == 0 &&
                   daze_dos_memory_allocate(&memory, 1) == NULL &&
                   daze_dos_memory_release(&memory, first->segment) &&
                   !daze_dos_memory_release(&memory, first->segment) && !maximum.success &&
                   maximum.dos_error == 8 && maximum.maximum_paragraphs == 0x7000 &&
                   maximum_unchanged && accepted.success && accepted.dos_error == 0 &&
                   accepted.maximum_paragraphs == 0 && accepted_unchanged && expanded != NULL &&
                   expanded_result.success && expanded->paragraphs == 0x10 &&
                   after_expand != NULL && after_expand->segment == 0x3010 && root_result.success &&
                   root_memory.first_segment == 0x265f && after_root_resize != NULL &&
                   after_root_resize->segment == 0x265f;

  daze_dos_memory_init(&memory, 0x3000, 0x3010);
  assert(daze_dos_memory_allocate(&memory, 8) && daze_dos_memory_allocate(&memory, 8));
  DazeDosMemory snapshot = memory;
  DazeDosMemoryResizeResult result;
  daze_dos_memory_resize(&memory, 0x3000, 9, &result);
  assert(!result.success && result.dos_error == 8 && result.maximum_paragraphs == 8 &&
         memcmp(&memory, &snapshot, sizeof(memory)) == 0);
  daze_dos_memory_resize(&memory, 0x3008, 9, &result);
  assert(!result.success && result.dos_error == 8 && result.maximum_paragraphs == 8 &&
         memcmp(&memory, &snapshot, sizeof(memory)) == 0);
  daze_dos_memory_resize(&memory, 0x2999, 1, &result);
  assert(!result.success && result.dos_error == 9 && result.maximum_paragraphs == 0 &&
         memcmp(&memory, &snapshot, sizeof(memory)) == 0);
  daze_dos_memory_resize(&memory, 0x3008, 4, &result);
  assert(result.success && result.dos_error == 0 && second->paragraphs == 4 &&
         memory.next_segment == 0x300c && daze_dos_memory_largest_available(&memory) == 4);
  daze_dos_memory_init(&memory, 0x3000, 0x3100);
  snapshot = memory;
  daze_dos_memory_resize(&memory, 0x0ff0, 0xffff, &result);
  assert(!result.success && result.dos_error == 8 && result.maximum_paragraphs == 0x2110 &&
         memcmp(&memory, &snapshot, sizeof(memory)) == 0);
  daze_dos_memory_resize(NULL, 0, 0, &result);
  daze_dos_memory_resize(&memory, 0, 0, NULL);
  daze_dos_memory_resize_result(0, NULL);
  assert(memcmp(&memory, &snapshot, sizeof(memory)) == 0);
  daze_dos_memory_init(&memory, 0x3000, 0xa000);
  for (size_t i = 0; i < DAZE_DOS_MEMORY_MAX_ALLOCS; ++i) {
    DazeDosAllocation *allocation = daze_dos_memory_allocate(&memory, 1);
    assert(allocation && allocation->segment == 0x3000 + i && allocation->paragraphs == 1);
  }
  snapshot = memory;
  assert(daze_dos_memory_allocate(&memory, 1) == NULL &&
         memcmp(&memory, &snapshot, sizeof(memory)) == 0);
  assert(daze_dos_memory_release(&memory, 0x3000));
  DazeDosAllocation *reused = daze_dos_memory_allocate(&memory, 1);
  assert(reused == &memory.allocations[0] &&
         reused->segment == 0x3000 + DAZE_DOS_MEMORY_MAX_ALLOCS &&
         memory.next_segment == reused->segment + 1);

  fprintf(stderr, "DOS memory contract test: %s\n", pass ? "passed" : "failed");
  return pass ? 0 : 1;
}
