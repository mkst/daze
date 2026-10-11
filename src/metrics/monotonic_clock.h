#ifndef DAZE_MONOTONIC_CLOCK_H
#define DAZE_MONOTONIC_CLOCK_H

#include <stdint.h>

#if defined(__linux__) || defined(__APPLE__)
#include <time.h>

static inline uint64_t monotonic_nanoseconds(void) {
  struct timespec now;
  if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return 0;
  return (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
}
#endif
#endif
