/* LDT descriptor writes skip the global translation-cache flush exactly when
 * no cached block could depend on the old bytes: fresh (non-present) slots
 * and identical rewrites. Live mutations keep the flush. */
#include "dpmi_test_driver.h"

#include <stdio.h>
#include <string.h>

#include <unicorn/unicorn.h>

static int zero_ldt(DazeUnicornDpmiTestDriver *driver) {
  static const uint8_t zero[4096] = {0};
  for (uint32_t offset = 0; offset < (uint32_t)k_dpmi_ldt_size; offset += sizeof(zero)) {
    if (uc_mem_write(driver->engine, (uint64_t)k_dpmi_ldt_address + offset, zero, sizeof(zero)) !=
        UC_ERR_OK)
      return 0;
  }
  return 1;
}

static uint64_t flushes(const DazeUnicornDpmiTestDriver *driver) {
  return driver->context.engine.metrics.translation_cache_flushes;
}

int main(void) {
  DazeUnicornDpmiTestDriver driver;
  DazeUnicornDpmiTestSnapshot snapshot;
  if (!daze_unicorn_dpmi_test_driver_init(&driver)) return 1;
  if (uc_mem_map(driver.engine, 0, k_memory_size, UC_PROT_ALL) != UC_ERR_OK || !zero_ldt(&driver)) {
    daze_unicorn_dpmi_test_driver_destroy(&driver);
    return 1;
  }
  driver.context.engine.metrics.enabled = 1;

  int pass = 1;
  /* 0000h allocates fresh slots over zero bytes: success with no flush. */
  const DazeUnicornDpmiTestInput alloc = {.eax = 0x0000, .ecx = 1, .eflags = 0x00000202u};
  pass = pass && daze_unicorn_dpmi_test_driver_run(&driver, &alloc, &snapshot);
  const uint16_t selector = (uint16_t)snapshot.eax;
  pass = pass && (snapshot.eflags & 1u) == 0 && selector != 0 && flushes(&driver) == 0;

  /* 0009h changes rights on the live selector: the flush is required. */
  const DazeUnicornDpmiTestInput rights = {
    .eax = 0x0009, .ebx = selector, .ecx = 0x0093, .eflags = 0x00000202u};
  pass = pass && daze_unicorn_dpmi_test_driver_run(&driver, &rights, &snapshot);
  pass = pass && (snapshot.eflags & 1u) == 0 && flushes(&driver) == 1;

  /* Identical rights rewrite nothing: no further flush. */
  pass = pass && daze_unicorn_dpmi_test_driver_run(&driver, &rights, &snapshot);
  pass = pass && (snapshot.eflags & 1u) == 0 && flushes(&driver) == 1;

  /* The live descriptor really changed exactly once. */
  uint8_t descriptor[8];
  const uint16_t slot = (uint16_t)(selector >> 3);
  const uint8_t changed[8] = {0, 0, 0, 0, 0, 0x93, 0, 0};
  pass = pass &&
         uc_mem_read(driver.engine, (uint64_t)k_dpmi_ldt_address + (uint32_t)slot * 8, descriptor,
                     sizeof(descriptor)) == UC_ERR_OK &&
         memcmp(descriptor, changed, sizeof(descriptor)) == 0;

  daze_unicorn_dpmi_test_driver_destroy(&driver);
  if (!pass) {
    fprintf(stderr, "Unicorn LDT flush-scope contract: selector=%04x eflags=%08x flushes=%llu\n",
            selector, snapshot.eflags, (unsigned long long)flushes(&driver));
  }
  return pass ? 0 : 1;
}
