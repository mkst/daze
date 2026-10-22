#include "dpmi_test_driver.h"
#include "unicorn_services.h"
#include "byte_order.h"

#include <stdio.h>
#include <string.h>

#include "descriptor.h"

static int state_buffer_ranges(void) {
  DazeUnicornDpmiTestDriver driver;
  if (!daze_unicorn_dpmi_test_driver_init(&driver)) return 0;
  uint8_t descriptor[8];
  daze_dpmi_descriptor_encode(descriptor, k_memory_size - sizeof(DpmiAlternateState), 0xffff, 0x92,
                              0);
  int pass = uc_mem_map(driver.engine, 0, k_memory_size, UC_PROT_ALL) == UC_ERR_OK &&
             uc_mem_write(driver.engine, k_dpmi_gdt_address + 0x10, descriptor, 8) == UC_ERR_OK;
  set_reg32(driver.engine, UC_X86_REG_CR0, 1);
  uint32_t address = 0;
  pass = pass && daze_dpmi_state_buffer_address(driver.engine, 0x10, 0, &address) &&
         address == k_memory_size - sizeof(DpmiAlternateState);
  const struct {
    uint16_t selector;
    uint32_t offset;
  } rejected[] = {
    {0x10, 1}, {0x10, UINT32_MAX}, {0, 0}, {0x18, 0}, {0xffff, 0},
  };
  for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); ++i) {
    address = 0xa5a5a5a5;
    pass = pass &&
           !daze_dpmi_state_buffer_address(driver.engine, rejected[i].selector, rejected[i].offset,
                                           &address) &&
           address == 0xa5a5a5a5;
  }
  uint8_t after[8];
  pass = pass && uc_mem_read(driver.engine, k_dpmi_gdt_address + 0x10, after, 8) == UC_ERR_OK &&
         memcmp(after, descriptor, 8) == 0;
  set_reg32(driver.engine, UC_X86_REG_CR0, 0);
  const uint32_t end = k_memory_size - sizeof(DpmiAlternateState) - 0x12340;
  pass = pass && daze_dpmi_state_buffer_address(driver.engine, 0x1234, end, &address) &&
         address == k_memory_size - sizeof(DpmiAlternateState);
  address = 0xa5a5a5a5;
  pass = pass && !daze_dpmi_state_buffer_address(driver.engine, 0x1234, end + 1, &address) &&
         address == 0xa5a5a5a5;
  daze_unicorn_dpmi_test_driver_destroy(&driver);
  if (!pass) fprintf(stderr, "DPMI state-buffer range rejection failed\n");
  return pass;
}

static uint32_t descriptor_base(const uint8_t descriptor[8]) {
  return daze_read_u16(descriptor + 2) | (uint32_t)descriptor[4] << 16 |
         (uint32_t)descriptor[7] << 24;
}

static int client_environment_contract(uint16_t environment_segment) {
  DazeUnicornDpmiTestDriver driver;
  if (!daze_unicorn_dpmi_test_driver_init(&driver)) return 0;
  const uint16_t psp_segment = 0x2097;
  const uint16_t stack_segment = 0x2345;
  const uint32_t environment_pointer = ((uint32_t)psp_segment << 4) + 0x2c;
  uint8_t environment[2];
  const uint16_t return_frame[] = {0x0100, 0x2480};
  daze_write_u16(environment, environment_segment);
  int pass = uc_mem_map(driver.engine, 0, k_memory_size, UC_PROT_ALL) == UC_ERR_OK &&
             uc_mem_write(driver.engine, environment_pointer, environment, 2) == UC_ERR_OK &&
             uc_mem_write(driver.engine, ((uint32_t)stack_segment << 4) + 0x100, return_frame,
                          sizeof(return_frame)) == UC_ERR_OK;
  driver.context.process.dos_process.psp_segment = psp_segment;
  driver.context.process.resident_image_end = 0x30000;
  set_reg32(driver.engine, UC_X86_REG_CR0, 0);
  set_reg16(driver.engine, UC_X86_REG_AX, 1);
  set_reg16(driver.engine, UC_X86_REG_DS, stack_segment);
  set_reg16(driver.engine, UC_X86_REG_SS, stack_segment);
  set_reg16(driver.engine, UC_X86_REG_SP, 0x100);
  pass = pass && daze_setup_prepare_dpmi_transition(driver.engine, &driver.context.engine,
                                                    &driver.context.process);
  uint8_t descriptor[8];
  pass = pass &&
         uc_mem_read(driver.engine, k_dpmi_gdt_address + 0x18, descriptor, 8) == UC_ERR_OK &&
         descriptor_base(descriptor) == (uint32_t)psp_segment << 4 &&
         uc_mem_read(driver.engine, environment_pointer, environment, 2) == UC_ERR_OK;
  const uint16_t selector = daze_read_u16(environment);
  if (environment_segment == 0) {
    pass = pass && selector == 0;
  } else {
    pass = pass && selector != 0 && selector != environment_segment && (selector & 7u) == 0 &&
           uc_mem_read(driver.engine, k_dpmi_gdt_address + selector, descriptor, 8) == UC_ERR_OK &&
           descriptor_base(descriptor) == (uint32_t)environment_segment << 4 &&
           (descriptor[5] & 0x90u) == 0x90u;
  }
  daze_unicorn_dpmi_test_driver_destroy(&driver);
  if (!pass) fprintf(stderr, "Unicorn client PSP/environment contract failed\n");
  return pass;
}

int main(void) {
  DazeUnicornDpmiTestDriver driver;
  DazeUnicornDpmiTestSnapshot snapshot;
  const DazeUnicornDpmiTestInput input = {
    .eax = 0xc3c30202u,
    .ecx = 0xa5a50000u,
    .edx = 0x5a5a0000u,
    .es = 0x0010,
    .eflags = 0x00000202u,
  };
  if (!daze_unicorn_dpmi_test_driver_init(&driver)) return 1;
  driver.context.process.dpmi.exception_vector_segment[0] = 0x0010;
  driver.context.process.dpmi.exception_vector_offset[0] = 0x00003456u;
  const int ran = daze_unicorn_dpmi_test_driver_run(&driver, &input, &snapshot);
  const int pass = ran && snapshot.eax == 0xc3c30202u && snapshot.ecx == 0xa5a50010u &&
                   snapshot.edx == 0x5a5a3456u && snapshot.es == 0 && snapshot.edi == 0;
  daze_unicorn_dpmi_test_driver_destroy(&driver);
  if (!pass)
    fprintf(
      stderr,
      "Unicorn DPMI dispatch contract: failed run=%d eax=%08x ecx=%08x edx=%08x es=%04x edi=%08x\n",
      ran, snapshot.eax, snapshot.ecx, snapshot.edx, snapshot.es, snapshot.edi);
  return pass && state_buffer_ranges() && client_environment_contract(0x1623) &&
             client_environment_contract(0)
           ? 0
           : 1;
}
