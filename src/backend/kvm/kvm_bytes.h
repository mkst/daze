#ifndef DAZE_KVM_BYTES_H
#define DAZE_KVM_BYTES_H

#include <stddef.h>
#include <stdint.h>

#include "byte_order.h"

static inline uint32_t daze_kvm_fnv1a32(const uint8_t *bytes, size_t size) {
  uint32_t hash = 2166136261u;
  for (size_t index = 0; index < size; ++index) {
    hash ^= bytes[index];
    hash *= 16777619u;
  }
  return hash;
}

#endif
