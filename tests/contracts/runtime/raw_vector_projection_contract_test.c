#include <stdio.h>
#include <string.h>

#include "memory.h"
#include "raw_vector_projection.h"

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>

static void boundaries(void) {
  DazeRawVectorProjection slots[2] = {0}, before[2];
  assert(daze_raw_vector_projection_find(NULL, 2, 0x1004) == NULL);
  assert(!daze_raw_vector_projection_record(NULL, 2, 0x1004, 0x1000, 2, 1));
  assert(daze_raw_vector_projection_forget_allocation(NULL, 2, 0x1000) == 0);
  assert(!daze_raw_vector_projection_forget_selector(slots, 2, 0x1004));
  assert(daze_raw_vector_projection_record(slots, 2, 0x1004, 0x1000, 2, 1));
  assert(daze_raw_vector_projection_record(slots, 2, 0x100c, 0x1000, 2, 1));
  memcpy(before, slots, sizeof(slots));
  assert(!daze_raw_vector_projection_record(slots, 2, 0x1014, 0x1010, 2, 1));
  assert(memcmp(before, slots, sizeof(slots)) == 0);
  assert(daze_raw_vector_projection_forget_allocation(slots, 2, 0x9999) == 0);
  assert(memcmp(before, slots, sizeof(slots)) == 0);
  assert(daze_raw_vector_projection_forget_allocation(slots, 2, 0x1000) == 2);
  for (size_t index = 0; index < 2; ++index) {
    assert(slots[index].selector == 0);
    assert(slots[index].allocation_segment == 0);
    assert(slots[index].allocation_paragraphs == 0);
    assert(slots[index].in_use == 0);
  }
  assert(daze_raw_vector_projection_record(slots, 2, 0x1014, 0x1010, 2, 1));
  assert(slots[0].selector == 0x1014 && slots[0].allocation_segment == 0x1010 &&
         slots[0].allocation_paragraphs == 2 && !slots[1].in_use);

  DazeDosMemory memory = {0};
  memory.allocations[0] = (DazeDosAllocation){.in_use = 1, .segment = 0x1004, .paragraphs = 8};
  assert(!daze_raw_vector_projection_eligible(NULL, 0x1004, 0x1004, 0));
  assert(!daze_raw_vector_projection_eligible(&memory, 0x1004, 0x1000, 0));
  assert(!daze_raw_vector_projection_eligible(&memory, 0x1004, 0x0ffc, 0));
  assert(daze_raw_vector_projection_eligible(&memory, 0x1004, 0x1004, 0));
  assert(daze_raw_vector_projection_eligible(&memory, 0x1004, 0x1004, 0x7f));
  assert(!daze_raw_vector_projection_eligible(&memory, 0x1004, 0x1004, 0x80));
  uint8_t descriptor[8], saved[8];
  const DazeDosAllocation allocation = memory.allocations[0];
  for (unsigned kind = 0; kind < 7; ++kind) {
    DazeDosAllocation bad = allocation;
    uint16_t selector = 0x1004;
    if (kind == 1) bad.in_use = 0;
    if (kind == 2) selector = 0;
    if (kind == 3) selector = 0x1000;
    if (kind == 4) selector = 0x0ffc;
    if (kind == 5) selector = 0x100c;
    if (kind == 6) {
      bad.segment = 4;
      bad.paragraphs = 0;
      selector = 4;
    }
    memset(descriptor, 0xa5, sizeof(descriptor));
    memcpy(saved, descriptor, sizeof(saved));
    assert(!daze_raw_vector_projection_descriptor(kind == 0 ? NULL : &bad, selector, descriptor));
    assert(memcmp(saved, descriptor, sizeof(saved)) == 0);
  }
  assert(!daze_raw_vector_projection_descriptor(&allocation, 0x1004, NULL));
  assert(daze_raw_vector_projection_descriptor(&allocation, 0x1004, descriptor));
  const uint8_t expected[] = {0x7f, 0, 0x40, 0, 1, 0xf2, 0, 0};
  assert(memcmp(expected, descriptor, sizeof(expected)) == 0);
}

int main(void) {
  boundaries();
  DazeDosMemory memory;
  daze_dos_memory_init(&memory, 0x1000, 0x2000);
  DazeDosAllocation *const child = daze_dos_memory_allocate(&memory, 0x55d);
  DazeDosAllocation *const later = daze_dos_memory_allocate(&memory, 0x10);
  const int accepts_owned =
    child != NULL && daze_raw_vector_projection_eligible(&memory, child->segment, 0x108d, 0x290f);
  const int rejects_host =
    child != NULL && !daze_raw_vector_projection_eligible(&memory, child->segment, 0x0300, 0x0010);
  const int rejects_zero =
    child != NULL && !daze_raw_vector_projection_eligible(&memory, child->segment, 0, 0);
  const int rejects_outside =
    child != NULL && !daze_raw_vector_projection_eligible(&memory, child->segment, 0x15d9, 0);
  const int rejects_other =
    child != NULL && later != NULL &&
    !daze_raw_vector_projection_eligible(&memory, later->segment, 0x108d, 0x290f);
  const int rejects_released =
    child != NULL && daze_dos_memory_release(&memory, child->segment) &&
    !daze_raw_vector_projection_eligible(&memory, child->segment, 0x108d, 0x290f);
  DazeDosMemory descriptors_memory;
  daze_dos_memory_init(&descriptors_memory, 0x1000, 0x3000);
  DazeDosAllocation *const descriptor_owner = daze_dos_memory_allocate(&descriptors_memory, 0x55d);
  uint8_t descriptor[8] = {0};
  const uint8_t expected[] = {0xff, 0x4c, 0xd0, 0x08, 0x01, 0xf2, 0x00, 0x00};
  const int descriptor_bytes =
    descriptor_owner != NULL &&
    daze_raw_vector_projection_descriptor(descriptor_owner, 0x108d, descriptor) &&
    memcmp(descriptor, expected, sizeof(descriptor)) == 0;
  DazeRawVectorProjection projections[DAZE_RAW_VECTOR_PROJECTION_MAX] = {0};
  const int records = daze_raw_vector_projection_record(projections, DAZE_RAW_VECTOR_PROJECTION_MAX,
                                                        0x108d, 0x1000, 0x55d, 1);
  const int deduplicates =
    daze_raw_vector_projection_record(projections, DAZE_RAW_VECTOR_PROJECTION_MAX, 0x108d, 0x1000,
                                      0x55d, 0) &&
    projections[1].in_use == 0;
  const int does_not_clobber =
    !daze_raw_vector_projection_record(projections, DAZE_RAW_VECTOR_PROJECTION_MAX, 0x1095, 0x1000,
                                       0x55d, 0) &&
    daze_raw_vector_projection_find(projections, DAZE_RAW_VECTOR_PROJECTION_MAX, 0x1095) == NULL;
  const int replacement_records = daze_raw_vector_projection_record(
    projections, DAZE_RAW_VECTOR_PROJECTION_MAX, 0x109d, 0x1100, 0x10, 1);
  const int replacement_withdraws =
    daze_raw_vector_projection_forget_selector(projections, DAZE_RAW_VECTOR_PROJECTION_MAX,
                                               0x108d) &&
    daze_raw_vector_projection_find(projections, DAZE_RAW_VECTOR_PROJECTION_MAX, 0x108d) == NULL &&
    daze_raw_vector_projection_find(projections, DAZE_RAW_VECTOR_PROJECTION_MAX, 0x109d) != NULL;
  const int rerecords_after_replacement = daze_raw_vector_projection_record(
    projections, DAZE_RAW_VECTOR_PROJECTION_MAX, 0x108d, 0x1000, 0x55d, 1);
  const size_t withdrawn = daze_raw_vector_projection_forget_allocation(
    projections, DAZE_RAW_VECTOR_PROJECTION_MAX, 0x1000);
  const int release_withdraws =
    withdrawn == 1 &&
    daze_raw_vector_projection_find(projections, DAZE_RAW_VECTOR_PROJECTION_MAX, 0x108d) == NULL &&
    daze_raw_vector_projection_find(projections, DAZE_RAW_VECTOR_PROJECTION_MAX, 0x109d) != NULL;
  const int pass = accepts_owned && rejects_host && rejects_zero && rejects_outside &&
                   rejects_other && rejects_released && descriptor_bytes && records &&
                   deduplicates && does_not_clobber && replacement_records &&
                   replacement_withdraws && rerecords_after_replacement && release_withdraws;
  fprintf(stderr, "raw vector projection contract test: %s\n", pass ? "passed" : "failed");
  return pass ? 0 : 1;
}
