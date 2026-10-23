#ifndef DAZE_UNICORN_DPMI_TEST_DRIVER_H
#define DAZE_UNICORN_DPMI_TEST_DRIVER_H

#include "unicorn_context.h"

typedef struct {
  uc_engine *engine;
  DazeUnicornContext context;
} DazeUnicornDpmiTestDriver;

typedef struct {
  uint32_t eax;
  uint32_t ebx;
  uint32_t ecx;
  uint32_t edx;
  uint32_t esi;
  uint32_t edi;
  uint16_t es;
  uint32_t eflags;
} DazeUnicornDpmiTestInput;

typedef struct {
  uint32_t initial_edi;
  uint16_t initial_es;
  uint32_t eax;
  uint32_t ebx;
  uint32_t ecx;
  uint32_t edx;
  uint32_t esi;
  uint32_t edi;
  uint16_t es;
  uint32_t eflags;
} DazeUnicornDpmiTestSnapshot;

/* Test-only live adapter seam.  The caller owns both the DazeUnicornContext fixture and
 * exact register input; the driver only writes that state and dispatches. */
int daze_unicorn_dpmi_test_driver_init(DazeUnicornDpmiTestDriver *driver);
void daze_unicorn_dpmi_test_driver_destroy(DazeUnicornDpmiTestDriver *driver);
int daze_unicorn_dpmi_test_driver_run(DazeUnicornDpmiTestDriver *driver,
                                      const DazeUnicornDpmiTestInput *input,
                                      DazeUnicornDpmiTestSnapshot *snapshot);

#endif
