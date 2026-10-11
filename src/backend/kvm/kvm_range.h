#ifndef DAZE_KVM_RANGE_H
#define DAZE_KVM_RANGE_H

#include <stddef.h>
#include <stdint.h>

/* Matches shared guest-range semantics with size_t lengths: empty ranges fit and never
 * overlap. */
static inline int daze_kvm_range_fits(uint32_t guest_size, uint32_t address, size_t size) {
  return address <= guest_size && size <= guest_size - address;
}

/* Non-zero if the byte range is non-empty and contained within [0,
 * guest_size). Callers that reject zero-length ranges should use this form. */
static inline int daze_kvm_range_fits_nonempty(uint32_t guest_size, uint32_t address, size_t size) {
  return size != 0 && daze_kvm_range_fits(guest_size, address, size);
}

static inline int daze_kvm_ranges_overlap(uint32_t first_address, size_t first_size,
                                          uint32_t second_address, size_t second_size) {
  return first_address < second_address + second_size &&
         second_address < first_address + first_size;
}

#endif
