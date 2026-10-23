#include "guest_memory_layout.h"
#include "kvm_range.h"

#include <stdint.h>
#include <stdio.h>

/* Boundary-semantics equivalence between the shared layout primitives and
 * the KVM-local kvm_range.h helpers. The one deliberate difference lives one
 * layer up and is not tested here: daze_kvm_process_layout_valid rejects
 * zero-size reservations outright, while both fits helpers below allow empty
 * ranges (which can never overlap). */
static int pass = 1;

static void check(int condition, const char *message) {
  if (!condition) {
    fprintf(stderr, "range equivalence failed: %s\n", message);
    pass = 0;
  }
}

int main(void) {
  static const uint32_t guest = 0x800000;
  static const struct {
    uint32_t address;
    uint32_t size;
  } fits_cases[] = {
    {0, 0},
    {0, 1},
    {0, 0x800000},
    {0, 0x800001},
    {0x800000, 0},
    {0x800000, 1},
    {0x7fffff, 1},
    {0x7fffff, 2},
    {0x7f0000, 0x10000},
    {0x7f0000, 0x10001},
    {0xffffff00u, 0x100},
    {0xffffffffu, 0xffffffffu},
    {0xffffffffu, 0},
  };
  for (size_t index = 0; index < sizeof(fits_cases) / sizeof(fits_cases[0]); ++index) {
    const int shared =
      daze_guest_range_fits(guest, fits_cases[index].address, fits_cases[index].size);
    const int kvm =
      daze_kvm_range_fits(guest, fits_cases[index].address, fits_cases[index].size) != 0;
    check(shared == kvm, "fits differs from kvm_range fits");
  }
  /* Sizes beyond uint32_t cannot reach the shared primitive (launch code
   * narrows only after a fit check); the KVM helper alone must reject them. */
  check(!daze_kvm_range_fits(guest, 0, (size_t)UINT32_MAX + 1), "kvm rejects huge sizes");

  static const struct {
    uint32_t first_address, first_size, second_address, second_size;
  } overlap_cases[] = {
    {0x1000, 0x10, 0x100f, 0x10},
    {0xff00, 256, 0x10000, 0x1234},
    {0x1000, 0, 0x1000, 0x10},
    {0x1000, 0, 0x2000, 0},
    {0x1000, 0x100, 0x1020, 0x10},
    {0x2000, 0x100, 0x2000, 0x100},
    {0x3000, 0x100, 0x4000, 0x100},
    {0xffffff00u, 0x100, 0, 0x100},
    {0xffffff00u, 0x100, 0xffffff80u, 0x10},
    {0x7f0000, 0x10000, 0x7e0000, 0x10000},
    {0x7f0000, 0x10000, 0x800000, 0x10000},
  };
  for (size_t index = 0; index < sizeof(overlap_cases) / sizeof(overlap_cases[0]); ++index) {
    const int shared = daze_guest_ranges_overlap(
      overlap_cases[index].first_address, overlap_cases[index].first_size,
      overlap_cases[index].second_address, overlap_cases[index].second_size);
    const int kvm = daze_kvm_ranges_overlap(
                      overlap_cases[index].first_address, overlap_cases[index].first_size,
                      overlap_cases[index].second_address, overlap_cases[index].second_size) != 0;
    check(shared == kvm, "overlaps differs from kvm_range overlap");
  }
  return pass ? 0 : 1;
}
