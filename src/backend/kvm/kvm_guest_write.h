#ifndef DAZE_KVM_GUEST_WRITE_H
#define DAZE_KVM_GUEST_WRITE_H

#include <stddef.h>
#include <stdint.h>

/* Shared guest-write record; the caller owns bytes and supplies their content.
 * Adapters validate destination ranges before installing them. */
typedef struct {
  uint32_t address;
  const uint8_t *bytes;
  size_t size;
} DazeKvmGuestWrite;

#endif
