#include "dpmi_test_driver.h"

#include "unicorn_services.h"

#include <string.h>

int daze_unicorn_dpmi_test_driver_init(DazeUnicornDpmiTestDriver *driver) {
  memset(driver, 0, sizeof(*driver));
  return uc_open(UC_ARCH_X86, UC_MODE_32, &driver->engine) == UC_ERR_OK;
}

void daze_unicorn_dpmi_test_driver_destroy(DazeUnicornDpmiTestDriver *driver) {
  if (driver->engine != NULL) uc_close(driver->engine);
  driver->engine = NULL;
}

int daze_unicorn_dpmi_test_driver_run(DazeUnicornDpmiTestDriver *driver,
                                      const DazeUnicornDpmiTestInput *input,
                                      DazeUnicornDpmiTestSnapshot *snapshot) {
  /* The runner's register adapters deliberately tolerate Unicorn's segment
   * register status on a freshly opened engine; mirror that live seam here. */
  uc_reg_write(driver->engine, UC_X86_REG_EAX, &input->eax);
  uc_reg_write(driver->engine, UC_X86_REG_EBX, &input->ebx);
  uc_reg_write(driver->engine, UC_X86_REG_ECX, &input->ecx);
  uc_reg_write(driver->engine, UC_X86_REG_EDX, &input->edx);
  uc_reg_write(driver->engine, UC_X86_REG_ESI, &input->esi);
  uc_reg_write(driver->engine, UC_X86_REG_EDI, &input->edi);
  uc_reg_write(driver->engine, UC_X86_REG_ES, &input->es);
  uc_reg_write(driver->engine, UC_X86_REG_EFLAGS, &input->eflags);
  uc_reg_read(driver->engine, UC_X86_REG_EDI, &snapshot->initial_edi);
  uc_reg_read(driver->engine, UC_X86_REG_ES, &snapshot->initial_es);
  if (!daze_int31_dispatch(driver->engine, &driver->context.engine, &driver->context.run,
                           &driver->context.process))
    return 0;
  uc_reg_read(driver->engine, UC_X86_REG_EAX, &snapshot->eax);
  uc_reg_read(driver->engine, UC_X86_REG_EBX, &snapshot->ebx);
  uc_reg_read(driver->engine, UC_X86_REG_ECX, &snapshot->ecx);
  uc_reg_read(driver->engine, UC_X86_REG_EDX, &snapshot->edx);
  uc_reg_read(driver->engine, UC_X86_REG_ESI, &snapshot->esi);
  uc_reg_read(driver->engine, UC_X86_REG_EDI, &snapshot->edi);
  uc_reg_read(driver->engine, UC_X86_REG_ES, &snapshot->es);
  uc_reg_read(driver->engine, UC_X86_REG_EFLAGS, &snapshot->eflags);
  return 1;
}
