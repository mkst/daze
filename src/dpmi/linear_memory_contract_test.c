#include "linear_memory.h"

#include <stdio.h>
#include <string.h>

static int allocation_boundaries(void) {
  DazeDpmiLinearMemory memory;
  daze_dpmi_linear_memory_init(&memory, 0xffffc000u, 0xfffff000u);
  uint32_t base = 0, handle = 0, second_base = 0, second_handle = 0;
  if (!daze_dpmi_linear_memory_allocate(&memory, 0x2000, &base, &handle) || base != 0xffffc000u ||
      handle != 1 || !daze_dpmi_linear_memory_allocate(&memory, 1, &second_base, &second_handle) ||
      second_base != 0xffffe000u || second_handle != 2 ||
      daze_dpmi_linear_memory_largest_available(&memory) != 0)
    return 0;
  const DazeDpmiLinearMemory before = memory;
  const uint32_t sizes[] = {0, 0x1001, 0xfffff001u, UINT32_MAX};
  for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); ++i) {
    uint32_t output = 0xa5a5a5a5u;
    if (daze_dpmi_linear_memory_resize(&memory, second_handle, sizes[i], &output) ||
        output != 0xa5a5a5a5u || memcmp(&memory, &before, sizeof(memory)) != 0)
      return 0;
  }
  if (!daze_dpmi_linear_memory_resize(&memory, handle, 1, &base) || base != 0xffffc000u ||
      memory.next_base != before.next_base || memory.allocations[0].allocated_size != 0x1000 ||
      !daze_dpmi_linear_memory_release(&memory, handle) || memory.next_base != before.next_base ||
      memory.allocations[0].in_use || !daze_dpmi_linear_memory_release(&memory, second_handle) ||
      memory.next_base != 0xffffe000u)
    return 0;
  uint32_t first = 0xa5a5a5a5u;
  if (daze_dpmi_linear_memory_first_base_after(0, 0, 0x1000, NULL) ||
      daze_dpmi_linear_memory_first_base_after(UINT32_MAX, 0, UINT32_MAX, &first) ||
      first != 0xa5a5a5a5u ||
      !daze_dpmi_linear_memory_first_base_after(0x50001, 0x50000, 0x52000, &first) ||
      first != 0x51000)
    return 0;
  return 1;
}

int main(void) {
  DazeDpmiLinearMemory memory;
  uint32_t first_base = 0;
  uint32_t first_handle = 0;
  uint32_t second_base = 0;
  uint32_t second_handle = 0;
  uint32_t resized_base = 0;
  uint32_t first_base_after_image = 0;
  daze_dpmi_linear_memory_init(&memory, 0x30000, 0x40000);

  int pass =
    allocation_boundaries() &&
    daze_dpmi_linear_memory_first_base_after(0x430da, 0x50000, 0x7f0000, &first_base_after_image) &&
    first_base_after_image == 0x50000 &&
    daze_dpmi_linear_memory_first_base_after(0x10000, 0x50000, 0x7f0000, &first_base_after_image) &&
    first_base_after_image == 0x50000 &&
    !daze_dpmi_linear_memory_first_base_after(0x7f0000, 0x50000, 0x7f0000,
                                              &first_base_after_image) &&
    !daze_dpmi_linear_memory_first_base_after(UINT32_MAX, 0x50000, 0x7f0000,
                                              &first_base_after_image) &&
    daze_dpmi_linear_memory_allocate(&memory, 0x1001, &first_base, &first_handle) &&
    first_base == 0x30000 && first_handle == 1 &&
    daze_dpmi_linear_memory_resize(&memory, first_handle, 0x3000, &resized_base) &&
    resized_base == first_base &&
    daze_dpmi_linear_memory_allocate(&memory, 0x1000, &second_base, &second_handle) &&
    second_base == 0x33000 && second_handle == 2 &&
    !daze_dpmi_linear_memory_resize(&memory, first_handle, 0x4000, &resized_base) &&
    daze_dpmi_linear_memory_release(&memory, second_handle) &&
    daze_dpmi_linear_memory_resize(&memory, first_handle, 0x4000, &resized_base) &&
    daze_dpmi_linear_memory_release(&memory, first_handle) &&
    !daze_dpmi_linear_memory_release(&memory, first_handle) &&
    daze_dpmi_linear_memory_largest_available(&memory) == 0x10000;

  /* Exact ASPSX 2.21 0501h result: request BX:CX=0001:5000h inside the
   * accepted [00050000h,007f0000h) arena yields base 00050000h, handle 1. */
  DazeDpmiLinearMemory chain_memory;
  DazeDpmiLinearAllocateResult chain_result;
  daze_dpmi_linear_memory_init(&chain_memory, 0x50000, 0x7f0000);
  daze_dpmi_linear_memory_allocate_result(&chain_memory, 0x15000, &chain_result);
  pass = pass && chain_result.success && chain_result.dpmi_error == 0 &&
         chain_result.base == 0x50000 && chain_result.handle == 1;

  DazeDpmiLinearAllocateResult chain_second;
  daze_dpmi_linear_memory_allocate_result(&chain_memory, 0x1000, &chain_second);
  pass = pass && chain_second.success && chain_second.dpmi_error == 0 &&
         chain_second.base == 0x65000 && chain_second.handle == 2 &&
         chain_second.base > chain_result.base && chain_second.handle != chain_result.handle;

  /* Allocation failure must preserve state and return error 8012h with zero outputs. */
  DazeDpmiLinearMemory zero_memory;
  DazeDpmiLinearAllocateResult zero_result;
  daze_dpmi_linear_memory_init(&zero_memory, 0x50000, 0x7f0000);
  const DazeDpmiLinearMemory zero_before = zero_memory;
  daze_dpmi_linear_memory_allocate_result(&zero_memory, 0, &zero_result);
  pass = pass && !zero_result.success && zero_result.dpmi_error == 0x8012 &&
         zero_result.base == 0 && zero_result.handle == 0 &&
         memcmp(&zero_memory, &zero_before, sizeof zero_memory) == 0;

  /* No space: a zero-width arena cannot satisfy even one page. */
  DazeDpmiLinearMemory full_memory;
  DazeDpmiLinearAllocateResult full_result;
  daze_dpmi_linear_memory_init(&full_memory, 0x50000, 0x50000);
  const DazeDpmiLinearMemory full_before = full_memory;
  daze_dpmi_linear_memory_allocate_result(&full_memory, 0x1000, &full_result);
  pass = pass && !full_result.success && full_result.dpmi_error == 0x8012 &&
         full_result.base == 0 && full_result.handle == 0 &&
         memcmp(&full_memory, &full_before, sizeof full_memory) == 0;

  /* Slot exhaustion must not consume arena space or alter recorded allocations. */
  DazeDpmiLinearMemory slots_memory;
  daze_dpmi_linear_memory_init(&slots_memory, 0x50000, 0xa0000);
  int slots_filled = 1;
  for (size_t index = 0; index < DAZE_DPMI_LINEAR_MEMORY_MAX_ALLOCS; ++index) {
    DazeDpmiLinearAllocateResult fill;
    daze_dpmi_linear_memory_allocate_result(&slots_memory, 0x1000, &fill);
    slots_filled = slots_filled && fill.success;
  }
  const DazeDpmiLinearMemory slots_before = slots_memory;
  DazeDpmiLinearAllocateResult slots_overflow;
  daze_dpmi_linear_memory_allocate_result(&slots_memory, 0x1000, &slots_overflow);
  pass = pass && slots_filled && !slots_overflow.success && slots_overflow.dpmi_error == 0x8012 &&
         slots_overflow.base == 0 && slots_overflow.handle == 0 &&
         memcmp(&slots_memory, &slots_before, sizeof slots_memory) == 0;

  /* A wrapped zero handle is invalid; refusal must preserve allocator state. */
  DazeDpmiLinearMemory wrap_memory;
  DazeDpmiLinearAllocateResult wrap_result;
  daze_dpmi_linear_memory_init(&wrap_memory, 0x50000, 0x7f0000);
  wrap_memory.next_handle = 0;
  const DazeDpmiLinearMemory wrap_before = wrap_memory;
  daze_dpmi_linear_memory_allocate_result(&wrap_memory, 0x1000, &wrap_result);
  pass = pass && !wrap_result.success && wrap_result.dpmi_error == 0x8012 &&
         wrap_result.base == 0 && wrap_result.handle == 0 &&
         memcmp(&wrap_memory, &wrap_before, sizeof wrap_memory) == 0;

  DazeDpmiLinearAllocateResult unavailable_result;
  daze_dpmi_linear_memory_allocate_result(NULL, 0x1000, &unavailable_result);
  pass = pass && !unavailable_result.success && unavailable_result.dpmi_error == 0x8012 &&
         unavailable_result.base == 0 && unavailable_result.handle == 0;

  DazeDpmiLinearMemory overflow_memory;
  daze_dpmi_linear_memory_init(&overflow_memory, 0x50000, 0x7f0000);
  const DazeDpmiLinearMemory overflow_before = overflow_memory;
  DazeDpmiLinearAllocateResult overflow_result;
  daze_dpmi_linear_memory_allocate_result(&overflow_memory, UINT32_MAX, &overflow_result);
  pass = pass && !overflow_result.success && overflow_result.dpmi_error == 0x8012 &&
         overflow_result.base == 0 && overflow_result.handle == 0 &&
         memcmp(&overflow_memory, &overflow_before, sizeof overflow_memory) == 0;

  DazeDpmiLinearMemory edge_memory;
  daze_dpmi_linear_memory_init(&edge_memory, 0xfffff000u, UINT32_MAX);
  const DazeDpmiLinearMemory edge_before = edge_memory;
  DazeDpmiLinearAllocateResult edge_result;
  daze_dpmi_linear_memory_allocate_result(&edge_memory, 0x1000, &edge_result);
  pass = pass && !edge_result.success && edge_result.dpmi_error == 0x8012 &&
         edge_result.base == 0 && edge_result.handle == 0 &&
         memcmp(&edge_memory, &edge_before, sizeof edge_memory) == 0;

  fprintf(stderr, "DPMI linear memory contract test: %s\n", pass ? "passed" : "failed");
  return pass ? 0 : 1;
}
