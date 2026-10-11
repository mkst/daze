#include "protected.h"
#include "mediator_test_driver.h"
#include "kvm_bytes.h"
#include "dpmi_error.h"

#include <stdio.h>
#include <string.h>

static int run_case(uint8_t width, int rejected_limit) {
  DazeKvmDpmiMediatorTestFixture fixture;
  int status = daze_kvm_dpmi_mediator_test_fixture_init(
    &fixture, (DazeKvmDpmiStateSaveEndpoints){0}, (DazeKvmDpmiRawSwitchEndpoints){0});
  if (status == DAZE_KVM_MACHINE_UNAVAILABLE) return 77;
  if (status != DAZE_KVM_MACHINE_OK) return 1;
  DazeRunMetrics metrics = {.enabled = 1};
  fixture.machine.run_metrics = &metrics;
  fixture.ldt_used[16] = 1;
  const uint8_t descriptor[8] = {0xff, 0xff, 0, 0, 0, 0x92, 0, 0};
  memcpy((uint8_t *)fixture.machine.guest + fixture.layout.ldt_address + 16 * 8, descriptor,
         sizeof(descriptor));
  const DazeKvmProtectedGateLayout layout = {.idt_address = fixture.layout.idt_address,
                                             .idt_limit = 0x7ff,
                                             .handler_address = 0x300,
                                             .dos_handler_address = 0x400,
                                             .default_dos_stub_address = 0x500,
                                             .record_address = fixture.layout.record_address,
                                             .mailbox_address = fixture.layout.mailbox_address,
                                             .handler_selector = 8,
                                             .handler_data_selector = 0x10,
                                             .interrupt_gate_type = width,
                                             .exchange_limit = 2};
  DazeKvmProtectedGateArtifacts artifacts;
  int failed = !daze_kvm_protected_gate_build(&layout, &artifacts);
  if (!failed) {
    failed |= !daze_kvm_machine_write(&fixture.machine, layout.handler_address, artifacts.handler,
                                      artifacts.handler_size);
    failed |= !daze_kvm_machine_write(&fixture.machine, layout.idt_address + 0x31 * 8,
                                      artifacts.idt_entry, 8);
  }
  const DazeDpmiRequest request = {.function =
                                     rejected_limit ? DAZE_DPMI_SET_LIMIT_2 : DAZE_DPMI_GET_VERSION,
                                   .selector = 0x84,
                                   .operand = 0x12345678};
  uint16_t port = 0;
  uint8_t marker = 0;
  if (!failed) failed |= !daze_kvm_dpmi_mediator_test_begin(&fixture, &request, &port, &marker);
  DazeKvmDpmiEntryResult boundary = {0}, successor = {0};
  DazeKvmProtectedGateExchange exchange = {0};
  if (!failed) {
    failed |=
      daze_kvm_dpmi_entry_capture_state(&fixture.machine, &boundary) != DAZE_KVM_DPMI_ENTRY_OK;
    boundary.observation =
      (DazeKvmDpmiEntryObservation){.kind = DAZE_KVM_DPMI_ENTRY_EXIT_PIO,
                                    .raw_exit_reason = 2,
                                    .pio_port = port,
                                    .pio_direction = DAZE_KVM_DPMI_ENTRY_PIO_OUT,
                                    .pio_size = 1,
                                    .pio_count = 1,
                                    .pio_value_present = 1,
                                    .pio_value = marker};
    failed |= daze_kvm_protected_gate_resume_mediator_boundary(
                &fixture.machine, &fixture.mediator, &layout, &boundary, &exchange, &successor) !=
              DAZE_KVM_PROTECTED_GATE_OK;
  }
  if (!failed) {
    const uint8_t *guest = fixture.machine.guest;
    const uint8_t *capture = guest + fixture.layout.capture_address;
    failed |= successor.observation.kind != DAZE_KVM_DPMI_ENTRY_EXIT_PIO ||
              successor.observation.pio_value != 0x7e;
    failed |=
      successor.cs != 8 || successor.ds != 0x10 || successor.ss != 0x10 || successor.sp != 0x1f00;
    failed |= exchange.function != request.function || exchange.client_cs != 8 ||
              exchange.client_ip != 0x202;
    failed |= (uint16_t)daze_read_u32(capture + DAZE_KVM_DPMI_TEST_CAPTURE_AX_OFFSET) !=
              (rejected_limit ? DAZE_DPMI_ERR_INVALID_SEGMENT : 0x005a);
    failed |= (daze_read_u32(capture + DAZE_KVM_DPMI_TEST_CAPTURE_FLAGS_OFFSET) & 1u) !=
              (unsigned)rejected_limit;
    failed |= daze_read_u32(capture + DAZE_KVM_DPMI_TEST_CAPTURE_ES_OFFSET) != 0x10;
    failed |= metrics.kvm_dpmi_mediator_calls != 1 || metrics.kvm_dpmi_function_count != 1 ||
              metrics.kvm_dpmi_functions[0].function != request.function;
    if (!rejected_limit)
      failed |= daze_read_u32(capture + DAZE_KVM_DPMI_TEST_CAPTURE_AX_OFFSET) != 0xc3c3005a;
  }
  if (failed)
    fprintf(stderr,
            "protected execution width=%02x rejected=%d successor=%d/%u cs:ip=%04x:%x sp=%04x\n",
            width, rejected_limit, successor.observation.kind, successor.observation.pio_value,
            successor.cs, successor.rip, successor.sp);
  if (failed) {
    const uint8_t *capture =
      (const uint8_t *)fixture.machine.guest + fixture.layout.capture_address;
    fprintf(stderr,
            "reply ax=%08x flags=%08x es=%08x client=%04x:%04x ds=%04x ss=%04x metrics=%llu/%zu\n",
            daze_read_u32(capture), daze_read_u32(capture + 12), daze_read_u32(capture + 8),
            exchange.client_cs, exchange.client_ip, successor.ds, successor.ss,
            (unsigned long long)metrics.kvm_dpmi_mediator_calls, metrics.kvm_dpmi_function_count);
  }
  daze_kvm_dpmi_mediator_test_fixture_destroy(&fixture);
  return failed;
}

int main(void) {
  const uint8_t widths[] = {0x86, 0x8e};
  for (size_t i = 0; i < sizeof(widths); ++i)
    for (int rejected = 0; rejected < 2; ++rejected) {
      int status = run_case(widths[i], rejected);
      if (status) return status;
    }
  return 0;
}
