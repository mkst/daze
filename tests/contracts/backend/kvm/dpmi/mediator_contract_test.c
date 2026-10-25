#include "mediator.h"
#include "mediator_test_driver.h"
#include "machine.h"

#include "kvm_bytes.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
enum {
  CAP_AX = DAZE_KVM_DPMI_TEST_CAPTURE_AX_OFFSET,
  CAP_DI = DAZE_KVM_DPMI_TEST_CAPTURE_DI_OFFSET,
  CAP_ES = DAZE_KVM_DPMI_TEST_CAPTURE_ES_OFFSET,
  CAP_FLAGS = DAZE_KVM_DPMI_TEST_CAPTURE_FLAGS_OFFSET,
  CAP_BX = DAZE_KVM_DPMI_TEST_CAPTURE_BX_OFFSET,
  CAP_CX = DAZE_KVM_DPMI_TEST_CAPTURE_CX_OFFSET,
  CAP_SI = DAZE_KVM_DPMI_TEST_CAPTURE_SI_OFFSET,
  CAP_DX = DAZE_KVM_DPMI_TEST_CAPTURE_DX_OFFSET,
};

static int run_case_ax(DazeKvmDpmiMediatorTestFixture *fixture, const DazeDpmiRequest *request,
                       uint16_t expected_ax, int expected_carry) {
  DazeKvmDpmiMediatorTestSnapshot snapshot = {0};
  const DazeKvmDpmiMediatorTestLayout *layout = &fixture->layout;
  if (!daze_kvm_dpmi_mediator_test_run(fixture, request, &snapshot) ||
      (uint16_t)snapshot.eax != expected_ax ||
      ((snapshot.eflags & 1u) != 0) != (expected_carry != 0)) {
    fprintf(stderr, "mediator %04x: result ax=%04x flags=%08x\n", request->function,
            (uint16_t)snapshot.eax, snapshot.eflags);
    fprintf(stderr, "  record ax=%04x bx=%04x flags=%08x mailbox ax=%08x\n",
            daze_read_u16((const uint8_t *)fixture->machine.guest + layout->record_address),
            daze_read_u16((const uint8_t *)fixture->machine.guest + layout->record_address + 4),
            daze_read_u32((const uint8_t *)fixture->machine.guest + layout->record_address + 32),
            daze_read_u32((const uint8_t *)fixture->machine.guest + layout->mailbox_address));
    return 0;
  }
  return 1;
}

static int run_case(DazeKvmDpmiMediatorTestFixture *fixture, const DazeDpmiRequest *request) {
  const uint16_t expected_ax = request->function == 0x000a   ? 0x0084
                               : request->function == 0x0000 ? 0x008c
                               : request->function == 0x0003 ? 0x0008
                               : request->function == 0x0305 ? 60
                               : request->function == 0x0900 ? 0x0901
                                                             : request->function;
  return run_case_ax(fixture, request, expected_ax, 0);
}

static int remaining_requests(DazeKvmDpmiMediatorTestFixture *fixture) {
  DazeKvmDpmiMediator *m = &fixture->mediator;
  uint8_t *guest = m->guest;
  DazeKvmDpmiMediatorTestSnapshot reply;
  int pass = 1;
  const DazeDpmiRequest set_rm = {
    .function = 0x0201, .selector = 0x60, .vector_segment = 0x1234, .vector_offset = 0xabcd};
  pass &= run_case(fixture, &set_rm) && fixture->real_mode_vector_segment[0x60] == 0x1234 &&
          fixture->real_mode_vector_offset[0x60] == 0xabcd;
  const DazeDpmiRequest lock = {.function = 0x0600, .operand = 0x12345678};
  const DazeDpmiRequest unlock = {.function = 0x0601, .operand = 0x12345678};
  pass &= run_case(fixture, &lock) && run_case(fixture, &unlock);
  if (!pass) return fprintf(stderr, "mediator vector/lock contract failed\n"), 0;

  const uint32_t ldt = m->ldt_address + 2 * 8;
  const uint8_t descriptor[8] = {0xff, 0xff, 0x56, 0x34, 0x12, 0x92, 0x40, 0};
  memcpy(guest + ldt, descriptor, 8);
  const DazeDpmiRequest get_base = {.function = 0x0006, .selector = 0x14};
  pass &= daze_kvm_dpmi_mediator_test_run(fixture, &get_base, &reply) && reply.eax == 6 &&
          reply.ecx == 0x12 && reply.edx == 0x123456 && !(reply.eflags & 1);
  const DazeDpmiRequest rights = {.function = 0x0009, .selector = 0x14, .rights = 0x4092};
  pass &= run_case(fixture, &rights) && memcmp(guest + ldt, descriptor, 8) == 0;
  const DazeDpmiRequest invalid_rights = {.function = 0x0009, .selector = 0x14, .rights = 0};
  pass &=
    run_case_ax(fixture, &invalid_rights, 0x8021, 1) && memcmp(guest + ldt, descriptor, 8) == 0;
  if (!pass) return fprintf(stderr, "mediator base/rights contract failed\n"), 0;

  const DazeDpmiRequest free_descriptor = {.function = 0x0001, .selector = 0x8c};
  pass &= run_case(fixture, &free_descriptor) && !fixture->ldt_used[17] &&
          memcmp(guest + m->ldt_address + 17 * 8, (uint8_t[8]){0}, 8) == 0 &&
          run_case_ax(fixture, &free_descriptor, 0x8022, 1);
  if (!pass) return fprintf(stderr, "mediator descriptor release contract failed\n"), 0;

  const DazeDpmiRequest information = {
    .function = 0x0500, .vector_segment = 0x10, .vector_offset = 0x2800};
  memset(guest + 0x27ff, 0xa5, 50);
  pass &= run_case(fixture, &information) && guest[0x27ff] == 0xa5 && guest[0x2830] == 0xa5 &&
          daze_read_u32(guest + 0x2800) ==
            daze_dpmi_linear_memory_largest_available(&fixture->linear_memory);
  for (size_t i = 4; i < 48; ++i)
    pass &= guest[0x2800 + i] == 0xff;
  if (!pass) return fprintf(stderr, "mediator free information contract failed\n"), 0;

  const uint8_t buffer_descriptor[8] = {0xff, 0xff, 0, 0x20, 0, 0x92, 0x40, 0};
  memcpy(guest + ldt, buffer_descriptor, 8);
  const DazeDpmiRequest get_descriptor = {
    .function = 0x000b, .selector = 0x14, .vector_segment = 0x10, .vector_offset = 0x2900};
  pass &= run_case(fixture, &get_descriptor) && memcmp(guest + 0x2900, buffer_descriptor, 8) == 0;
  const uint8_t image[8] = {0x7f, 0, 0x56, 0x34, 0x12, 0x92, 0x40, 0};
  memcpy(guest + 0x2900, image, 8);
  const DazeDpmiRequest set_descriptor = {
    .function = 0x000c, .selector = 0x14, .vector_segment = 0x10, .vector_offset = 0x2900};
  pass &= run_case(fixture, &set_descriptor) && memcmp(guest + ldt, image, 8) == 0;
  if (!pass) return fprintf(stderr, "mediator descriptor copy contract failed\n"), 0;
  for (int function = 0xb; function <= 0xc; ++function) {
    const DazeDpmiRequest bad_source = {
      .function = function, .selector = 8, .vector_segment = 0x10, .vector_offset = 0x2900};
    pass &= run_case_ax(fixture, &bad_source, 0x8022, 1);
    const DazeDpmiRequest bad_buffer = {
      .function = function, .selector = 0x14, .vector_segment = 0x14, .vector_offset = 0x900};
    uint16_t port;
    uint8_t marker;
    pass &= daze_kvm_dpmi_mediator_test_begin(fixture, &bad_buffer, &port, &marker) &&
            daze_kvm_dpmi_mediator_process(m, port, marker) == DAZE_KVM_DPMI_MEDIATOR_OK &&
            daze_read_u32(guest + m->mailbox_address) == 0x8025 &&
            daze_read_u32(guest + m->mailbox_address + 28) == 3 &&
            memcmp(guest + ldt, image, 8) == 0;
  }
  if (!pass) return fprintf(stderr, "mediator descriptor rejection contract failed\n"), 0;

  /* Procedure preparation stops at the real mediator boundary; it must leave
   * the frame bytes intact until the separate reflection driver executes it. */
  uint8_t *frame = guest + 0x2800;
  for (int function = 0x300; function <= 0x301; ++function) {
    memset(frame, 0, DAZE_DPMI_RM_FRAME_SIZE);
    daze_write_u16(frame + DAZE_DPMI_RM_CS, 0x1234);
    daze_write_u16(frame + DAZE_DPMI_RM_IP, 0x5678);
    daze_write_u16(frame + DAZE_DPMI_RM_SS, 0x200);
    daze_write_u16(frame + DAZE_DPMI_RM_SP, 0x100);
    uint8_t before[DAZE_DPMI_RM_FRAME_SIZE];
    memcpy(before, frame, sizeof(before));
    const DazeDpmiRequest procedure = {.function = function,
                                       .selector = function == 0x300 ? 0x21 : 0,
                                       .vector_segment = 0x10,
                                       .vector_offset = 0x2800};
    uint16_t port;
    uint8_t marker;
    pass &= daze_kvm_dpmi_mediator_test_begin(fixture, &procedure, &port, &marker);
    guest[m->gdt_address + 8 + 6] &= ~0x40u;
    pass &=
      daze_kvm_dpmi_mediator_process(m, port, marker) == DAZE_KVM_DPMI_MEDIATOR_RM_PROCEDURE &&
      m->rm_procedure_present && m->rm_procedure_is_interrupt == (function == 0x300) &&
      m->rm_procedure.frame_address == 0x2800 && m->rm_procedure.frame_ss == 0x200 &&
      m->rm_procedure.frame_sp == 0x100 &&
      m->rm_procedure.stack_address == (function == 0x300 ? 0x20fa : 0x20fc) &&
      memcmp(frame, before, sizeof(before)) == 0;
    guest[m->gdt_address + 8 + 6] |= 0x40u;
    if (!pass) {
      fprintf(stderr, "procedure %04x present=%d interrupt=%d frame=%x ss:sp=%x:%x stack=%x\n",
              function, m->rm_procedure_present, m->rm_procedure_is_interrupt,
              m->rm_procedure.frame_address, m->rm_procedure.frame_ss, m->rm_procedure.frame_sp,
              m->rm_procedure.stack_address);
      fprintf(
        stderr, "record ax=%x bx=%x cx=%x di=%x es=%x cs=%x flags=%x gdt=%x/%zx\n",
        daze_read_u32(guest + m->record_address), daze_read_u32(guest + m->record_address + 4),
        daze_read_u32(guest + m->record_address + 8), daze_read_u32(guest + m->record_address + 16),
        daze_read_u32(guest + m->record_address + 20),
        daze_read_u32(guest + m->record_address + 32),
        daze_read_u32(guest + m->record_address + 36), m->gdt_address, m->gdt_size);
      return 0;
    }
  }
  if (!pass) fputs("mediator remaining request contract failed\n", stderr);
  return pass;
}

static int vector_diagnostics(DazeKvmDpmiMediatorTestFixture *fixture) {
  FILE *output = tmpfile();
  const int saved = dup(STDERR_FILENO);
  if (output == NULL || saved < 0) return 0;
  fflush(stderr);
  int pass = dup2(fileno(output), STDERR_FILENO) >= 0 &&
             setenv("DAZE_DPMI_VECTOR_RECORD", "1", 1) == 0 &&
             setenv("DAZE_GDT08_TRACE", "1", 1) == 0;
  const DazeDpmiRequest exception = {
    .function = 0x0203, .selector = 1, .vector_segment = 8, .vector_offset = 0x1234};
  const DazeDpmiRequest interrupt = {
    .function = 0x0205, .selector = 0x60, .interrupt_segment = 8, .interrupt_offset = 0x12345678};
  pass &= run_case(fixture, &exception) && run_case(fixture, &interrupt);
  fflush(stderr);
  pass &= dup2(saved, STDERR_FILENO) >= 0;
  close(saved);
  unsetenv("DAZE_DPMI_VECTOR_RECORD");
  unsetenv("DAZE_GDT08_TRACE");
  rewind(output);
  char text[8192];
  const size_t count = fread(text, 1, sizeof(text) - 1, output);
  text[count] = 0;
  fclose(output);
  pass &= count < sizeof(text) - 1 && strstr(text, "backend=kvm fn=0203 cs=0008") != NULL &&
          strstr(text, "bl=01 off_bits=16") != NULL && strstr(text, "slot=0008:00001234") != NULL &&
          strstr(text, "backend=kvm fn=0205 cs=0008") != NULL &&
          strstr(text, "bl=60 off_bits=32") != NULL && strstr(text, "slot=0008:12345678") != NULL &&
          strstr(text, "gdt08-trace: fn=0203 cs=0008") != NULL;
  if (!pass) fprintf(stderr, "mediator vector diagnostic contract: %s\n", text);
  return pass;
}

static int rejected_operations(DazeKvmDpmiMediatorTestFixture *fixture) {
  DazeKvmDpmiMediator original = fixture->mediator;
  original.rm_procedure_present = 0;
  original.rm_procedure_is_interrupt = 0;
  uint8_t *guest = original.guest;
  uint8_t before[0x4000];
  const DazeDpmiLinearMemory linear = fixture->linear_memory;
  const DazeDosMemory dos = fixture->dos_memory;
  uint8_t used[sizeof(fixture->ldt_used)];
  memcpy(used, fixture->ldt_used, sizeof(used));
  for (int kind = 0; kind < 26; ++kind) {
    fixture->mediator = original;
    uint8_t *record = guest + original.record_address;
    memset(record, 0, DAZE_KVM_DPMI_RECORD_SIZE);
    daze_write_u32(record + 32, 8);
    daze_write_u32(record + 36, 2);
    daze_write_u32(record + 20, 0x10);
    daze_write_u32(record + 16, 0x2800);
    uint16_t function = 0;
    if (kind <= 3) {
      function = kind < 2 ? 0 : 1;
      if (kind % 2 == 0)
        fixture->mediator.ldt_used = NULL;
      else
        fixture->mediator.ldt_used_count = 1;
    } else if (kind <= 6) {
      function = 0x100;
      if (kind == 4) fixture->mediator.dos_memory = NULL;
      if (kind == 5) fixture->mediator.ldt_used = NULL;
      if (kind == 6) fixture->mediator.ldt_used_count = 1;
    } else if (kind <= 10) {
      function = (uint16_t)(6 + kind - 7);
      daze_write_u16(record + 4, kind == 7 ? 0xffff : 8);
    } else if (kind <= 13) {
      function = 0xa;
      daze_write_u16(record + 4, kind == 11 ? 4 : 8);
      if (kind == 12) fixture->mediator.ldt_used = NULL;
      if (kind == 13) fixture->mediator.ldt_used_count = 1;
    } else if (kind <= 16) {
      function = 0x500;
      if (kind == 14) daze_write_u16(record + 20, 0xffff);
      if (kind == 15) daze_write_u16(record + 16, 0x3fd1);
      if (kind == 16) {
        daze_write_u16(record + 20, 0x14);
        daze_write_u16(record + 16, 0xffff);
        const uint8_t overflow[8] = {0xff, 0xff, 0xff, 0xff, 0xff, 0x92, 0x40, 0xff};
        memcpy(guest + original.ldt_address + 16, overflow, 8);
      }
    } else {
      function = 0x301;
      uint8_t *frame = guest + 0x2800;
      memset(frame, 0, DAZE_DPMI_RM_FRAME_SIZE);
      daze_write_u16(frame + DAZE_DPMI_RM_SS, 0x200);
      daze_write_u16(frame + DAZE_DPMI_RM_SP, 0x100);
      if (kind == 17) daze_write_u16(record + 20, 0xffff);
      if (kind == 18) daze_write_u16(record + 16, 0x3fff);
      if (kind == 19) daze_write_u16(record + 32, 0xffff);
      if (kind >= 20) guest[original.gdt_address + 14] &= ~0x40u;
      if (kind == 20) daze_write_u16(record + 8, 1);
      if (kind == 21) daze_write_u16(record + 4, 0x100);
      if (kind == 22) daze_write_u16(frame + DAZE_DPMI_RM_SS, 0);
      if (kind == 23) daze_write_u16(frame + DAZE_DPMI_RM_SP, 3);
      if (kind == 24) {
        daze_write_u16(record + 20, 0x14);
        daze_write_u16(record + 16, 0xffff);
      }
      if (kind == 25) guest[original.gdt_address + 14] |= 0x40u;
    }
    daze_write_u16(record, function);
    memset(guest + original.mailbox_address, 0xa5, DAZE_KVM_DPMI_MAILBOX_SIZE);
    memcpy(before, guest, sizeof(before));
    const int status = daze_kvm_dpmi_mediator_process(
      &fixture->mediator, DAZE_KVM_DPMI_MEDIATOR_PORT, DAZE_KVM_DPMI_MEDIATOR_MARKER);
    if (status != DAZE_KVM_DPMI_MEDIATOR_INVALID || memcmp(before, guest, sizeof(before)) ||
        memcmp(&linear, &fixture->linear_memory, sizeof(linear)) ||
        memcmp(&dos, &fixture->dos_memory, sizeof(dos)) ||
        memcmp(used, fixture->ldt_used, sizeof(used))) {
      fprintf(stderr, "mediator rejected operation %d function=%04x status=%d\n", kind, function,
              status);
      return 0;
    }
  }
  fixture->mediator = original;
  guest[original.gdt_address + 14] |= 0x40u;
  return 1;
}

static int procedure_admission(DazeKvmDpmiMediatorTestFixture *fixture) {
  const struct {
    uint16_t words, ss, sp;
    int accepted;
  } cases[] = {
    {0, 0x200, 0x100, 1}, {2, 0x200, 0x100, 1}, {3, 0x200, 0x100, 0},
    {0, 0, 0, 0},         {2, 0, 0, 1},         {3, 0, 0, 0},
  };
  DazeKvmDpmiMediator *m = &fixture->mediator;
  uint8_t *guest = m->guest;
  const DazeKvmDpmiMediator original = *m;
  const uint8_t code_flags = guest[m->gdt_address + 14];
  int pass = 1;
  const DazeDpmiRequest request = {
    .function = 0x0301, .vector_segment = 0x10, .vector_offset = 0x2800};
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
    *m = original;
    uint16_t port;
    uint8_t marker;
    if (!daze_kvm_dpmi_mediator_test_begin(fixture, &request, &port, &marker)) {
      fprintf(stderr, "0301h admission could not capture request for case=%zu\n", i);
      pass = 0;
      break;
    }
    guest[m->gdt_address + 14] &= ~0x40u;
    daze_write_u16(guest + m->record_address + 8, cases[i].words);
    uint8_t *frame = guest + 0x2800;
    memset(frame, 0, DAZE_DPMI_RM_FRAME_SIZE);
    daze_write_u16(frame + DAZE_DPMI_RM_CS, 0x300);
    daze_write_u16(frame + DAZE_DPMI_RM_SS, cases[i].ss);
    daze_write_u16(frame + DAZE_DPMI_RM_SP, cases[i].sp);
    uint8_t before[0x4000];
    memcpy(before, guest, sizeof(before));
    const DazeKvmDpmiMediatorStatus status = daze_kvm_dpmi_mediator_process(m, port, marker);
    const int accepted = status == DAZE_KVM_DPMI_MEDIATOR_RM_PROCEDURE;
    if (accepted != cases[i].accepted || (!accepted && status != DAZE_KVM_DPMI_MEDIATOR_INVALID) ||
        memcmp(frame, before + 0x2800, DAZE_DPMI_RM_FRAME_SIZE) != 0 ||
        (!accepted && memcmp(guest, before, sizeof(before)) != 0)) {
      fprintf(stderr, "0301h admission words=%u ss:sp=%04x:%04x status=%d\n", cases[i].words,
              cases[i].ss, cases[i].sp, status);
      pass = 0;
      break;
    }
    if (accepted && (m->rm_procedure.parameter_bytes != cases[i].words * 2u ||
                     m->rm_procedure.stack_address != (cases[i].ss == 0 ? 0xfe0u : 0x20fcu))) {
      fprintf(stderr, "0301h admission stack=%x parameters=%u\n", m->rm_procedure.stack_address,
              m->rm_procedure.parameter_bytes);
      pass = 0;
      break;
    }
    guest[m->gdt_address + 14] = code_flags;
  }
  guest[original.gdt_address + 14] = code_flags;
  *m = original;
  return pass;
}

static int rejected_records(DazeKvmDpmiMediatorTestFixture *fixture) {
  uint8_t *guest = fixture->machine.guest;
  const DazeKvmDpmiMediator original = fixture->mediator;
  const DazeDpmiLinearMemory linear = fixture->linear_memory;
  uint8_t before[0x4000];
  for (int kind = 0; kind < 13; ++kind) {
    fixture->mediator = original;
    memset(guest + original.record_address, 0, DAZE_KVM_DPMI_RECORD_SIZE);
    memset(guest + original.mailbox_address, 0xa5, DAZE_KVM_DPMI_MAILBOX_SIZE);
    daze_write_u16(guest + original.record_address, 0x0300);
    daze_write_u16(guest + original.record_address + 4, 0x21);
    daze_write_u32(guest + original.record_address + 16, 0x2800);
    daze_write_u16(guest + original.record_address + 20, 0x10);
    daze_write_u16(guest + original.record_address + 32, 8);
    memset(guest + 0x2800, 0, DAZE_DPMI_RM_FRAME_SIZE);
    daze_write_u16(guest + 0x2800 + DAZE_DPMI_RM_SS, 0x200);
    daze_write_u16(guest + 0x2800 + DAZE_DPMI_RM_SP, 0x800);
    if (kind == 0) fixture->mediator.record_address = UINT32_MAX;
    if (kind == 1) fixture->mediator.mailbox_address = fixture->machine.guest_size - 1;
    if (kind == 2) fixture->mediator.ldt_size = 7;
    if (kind == 3) fixture->mediator.linear_memory = NULL;
    if (kind == 4) daze_write_u16(guest + original.record_address + 20, 0xffff);
    if (kind == 5) daze_write_u32(guest + original.record_address + 16, UINT32_MAX);
    if (kind == 6) daze_write_u16(guest + original.record_address + 32, 0xffff);
    if (kind == 7) daze_write_u16(guest + original.record_address + 4, 0x20);
    if (kind == 8) daze_write_u16(guest + original.record_address + 8, 1);
    if (kind == 9) daze_write_u16(guest + 0x2800 + DAZE_DPMI_RM_SP, 5);
    if (kind == 10) daze_write_u16(guest + 0x2800 + DAZE_DPMI_RM_SS, 0xffff);
    memcpy(before, guest, sizeof(before));
    const DazeKvmDpmiMediator saved = fixture->mediator;
    if (daze_kvm_dpmi_mediator_process(
          &fixture->mediator, kind == 11 ? 0x21 : DAZE_KVM_DPMI_MEDIATOR_PORT,
          kind == 12 ? 0xff : DAZE_KVM_DPMI_MEDIATOR_MARKER) != DAZE_KVM_DPMI_MEDIATOR_INVALID ||
        memcmp(before, guest, sizeof(before)) ||
        memcmp(&linear, &fixture->linear_memory, sizeof(linear)) ||
        memcmp(&saved, &fixture->mediator, sizeof(saved)))
      return 0;
  }
  fixture->mediator = original;
  return 1;
}

int main(int argc, char **argv) {
  (void)argv;
  if (argc > 1) return 2;
  DazeKvmDpmiMediatorTestFixture fixture;
  const DazeKvmDpmiStateSaveEndpoints state_save_endpoints = {
    .state_buffer_size = 60,
    .rm_segment = 0x2200,
    .rm_offset = 0x0100,
    .pm_selector = 0x0028,
    .pm_offset = 0x00000100,
  };
  const DazeKvmDpmiRawSwitchEndpoints raw_switch_endpoints = {
    .rm_segment = 0x2200,
    .rm_offset = 0x0120,
    .pm_selector = 0x0028,
    .pm_offset = 0x00000120,
  };
  const int init =
    daze_kvm_dpmi_mediator_test_fixture_init(&fixture, state_save_endpoints, raw_switch_endpoints);
  if (init == DAZE_KVM_MACHINE_UNAVAILABLE) return 77;
  if (init != DAZE_KVM_MACHINE_OK) return 1;
  const DazeKvmDpmiMediatorTestLayout *layout = &fixture.layout;
  DazeKvmDpmiMediator *mediator = &fixture.mediator;
  DazeDpmiLinearMemory *linear_memory = &fixture.linear_memory;
  DazeDosMemory *dos_memory = &fixture.dos_memory;
  uint8_t *ldt_used = fixture.ldt_used;
  uint16_t *real_mode_vector_segment = fixture.real_mode_vector_segment;
  uint16_t *real_mode_vector_offset = fixture.real_mode_vector_offset;
  int *virtual_interrupts_enabled = &fixture.virtual_interrupts_enabled;
  const uint32_t LDT = layout->ldt_address;
  const uint32_t MAILBOX = layout->mailbox_address;
  const uint32_t CAPTURE = layout->capture_address;
  DazeKvmMachine *machine = &fixture.machine;
  uint8_t *guest = machine->guest;
  int pass = 1;

  DazeDpmiRequest allocate = {.function = 0x0501, .size = 0x00015000};
  const int allocate_pass =
    run_case(&fixture, &allocate) && daze_read_u16(guest + CAPTURE + CAP_BX) == 5 &&
    daze_read_u16(guest + CAPTURE + CAP_CX) == 0 && daze_read_u16(guest + CAPTURE + CAP_SI) == 0 &&
    daze_read_u16(guest + CAPTURE + CAP_DI) == 1;
  if (!allocate_pass) {
    fprintf(stderr, "mediator allocation result bx=%04x cx=%04x si=%04x di=%04x\n",
            daze_read_u16(guest + CAPTURE + CAP_BX), daze_read_u16(guest + CAPTURE + CAP_CX),
            daze_read_u16(guest + CAPTURE + CAP_SI), daze_read_u16(guest + CAPTURE + CAP_DI));
  }
  pass = pass && allocate_pass;

  DazeDpmiRequest resize = {.function = 0x0503, .size = 0x00002000u, .operand = 1};
  const int resize_pass = run_case(&fixture, &resize) &&
                          daze_read_u16(guest + CAPTURE + CAP_BX) == 5 &&
                          daze_read_u16(guest + CAPTURE + CAP_CX) == 0;
  if (!resize_pass) {
    fprintf(stderr, "mediator resize result bx=%04x cx=%04x\n",
            daze_read_u16(guest + CAPTURE + CAP_BX), daze_read_u16(guest + CAPTURE + CAP_CX));
  }
  pass = pass && resize_pass;

  /* 0502h: free the handle 1 block supplied as SI:DI (operand = 0000:0001);
   * success preserves the guest-visible registers echoed through the mailbox
   * (only CF clears) and the allocator releases the block. */
  DazeDpmiRequest free = {.function = 0x0502, .operand = 1};
  const int free_pass = run_case(&fixture, &free);
  if (!free_pass) fprintf(stderr, "mediator free result mismatch\n");
  pass = pass && free_pass;

  /* 0502h error: freeing the same handle again is an invalid-memory-handle
   * failure (AX=8023h, CF set). Untouched mailbox registers stay echoed;
   * the allocator state is unchanged by the rejected release. */
  const DazeDpmiLinearMemory linear_before_free = *linear_memory;
  DazeDpmiRequest free_again = {.function = 0x0502, .operand = 1};
  const int free_again_pass =
    run_case_ax(&fixture, &free_again, 0x8023, 1) &&
    memcmp(linear_memory, &linear_before_free, sizeof(*linear_memory)) == 0;
  if (!free_again_pass) fprintf(stderr, "mediator free again result mismatch\n");
  pass = pass && free_again_pass;

  const uint8_t base_before[8] = {0, 0, 0, 0, 0, 0x97, 0xc0, 0};
  const uint8_t base_after[8] = {0, 0, 0, 0, 5, 0x97, 0xc0, 0};
  memcpy(guest + LDT + 2 * 8, base_before, 8);
  DazeDpmiRequest base = {.function = 0x0007, .selector = 0x0014, .operand = 0x00050000};
  const int base_pass =
    run_case(&fixture, &base) && memcmp(guest + LDT + 2 * 8, base_after, 8) == 0;
  if (!base_pass) fprintf(stderr, "mediator base descriptor mismatch\n");
  pass = pass && base_pass;

  const uint8_t limit_before[8] = {0, 0, 0, 0, 0, 0x93, 0xc0, 0};
  const uint8_t limit_after[8] = {0xff, 0xff, 0, 0, 0, 0x93, 0xcf, 0};
  memcpy(guest + LDT + 2 * 8, limit_before, 8);
  DazeDpmiRequest limit = {.function = 0x0008, .selector = 0x0014, .operand = 0xffffffffu};
  const int limit_pass =
    run_case(&fixture, &limit) && memcmp(guest + LDT + 2 * 8, limit_after, 8) == 0;
  if (!limit_pass) fprintf(stderr, "mediator limit descriptor mismatch\n");
  pass = pass && limit_pass;

  /* 000Bh copies the exact LDT descriptor image to ES:DI. The source and
   * destination are deliberately distinct guest ranges, so a selector shift
   * or a descriptor mutation cannot satisfy this contract. */
  const DazeDpmiRequest get_descriptor = {
    .function = 0x000b, .selector = 0x0014, .vector_segment = 0x0010, .vector_offset = 0x1b80};
  memset(guest + get_descriptor.vector_offset, 0, 8);
  const int get_descriptor_pass =
    run_case(&fixture, &get_descriptor) &&
    memcmp(guest + get_descriptor.vector_offset, limit_after, sizeof(limit_after)) == 0;
  if (!get_descriptor_pass) fprintf(stderr, "mediator get descriptor image mismatch\n");
  pass = pass && get_descriptor_pass;

  /* 000Ch copies the complete caller descriptor image back into the selected
   * LDT entry. In particular, base and limit must change with the access
   * byte; treating this as 0009h would leave the old image behind. */
  const uint8_t set_descriptor_image[8] = {0x7f, 0x12, 0x56, 0x34, 0x9a, 0x92, 0x40, 0xbc};
  const DazeDpmiRequest set_descriptor = {
    .function = 0x000c, .selector = 0x0014, .vector_segment = 0x0010, .vector_offset = 0x1b80};
  memcpy(guest + set_descriptor.vector_offset, set_descriptor_image, sizeof(set_descriptor_image));
  const int set_descriptor_pass =
    run_case(&fixture, &set_descriptor) &&
    memcmp(guest + LDT + 2 * 8, set_descriptor_image, sizeof(set_descriptor_image)) == 0;
  if (!set_descriptor_pass) fprintf(stderr, "mediator set descriptor image mismatch\n");
  pass = pass && set_descriptor_pass;

  /* 000Bh rejects a GDT selector as a normal DPMI invalid-selector response.
   * The host must return AX=8022h/CF rather than abandon the mediator boundary,
   * and must not write the caller's descriptor buffer. */
  const uint8_t get_descriptor_guard[8] = {0xa5, 0x5a, 0x3c, 0xc3, 0x11, 0xee, 0x77, 0x88};
  const DazeDpmiRequest invalid_get_descriptor = {
    .function = 0x000b, .selector = 0x0008, .vector_segment = 0x0010, .vector_offset = 0x1b80};
  memcpy(guest + invalid_get_descriptor.vector_offset, get_descriptor_guard,
         sizeof(get_descriptor_guard));
  const int invalid_get_descriptor_pass =
    run_case_ax(&fixture, &invalid_get_descriptor, 0x8022, 1) &&
    memcmp(guest + invalid_get_descriptor.vector_offset, get_descriptor_guard,
           sizeof(get_descriptor_guard)) == 0;
  if (!invalid_get_descriptor_pass)
    fprintf(stderr, "mediator invalid get descriptor response mismatch\n");
  pass = pass && invalid_get_descriptor_pass;

  const uint8_t alias_after[8] = {0xff, 0xff, 0, 0, 0, 0x92, 0xcf, 0};
  DazeDpmiRequest alias = {.function = 0x000a, .selector = 0x0008};
  const int alias_pass = run_case(&fixture, &alias) && ldt_used[16] == 1 &&
                         memcmp(guest + LDT + 16 * 8, alias_after, 8) == 0;
  if (!alias_pass) fprintf(stderr, "mediator data alias mismatch\n");
  pass = pass && alias_pass;

  DazeDpmiRequest descriptor_allocate = {.function = 0x0000, .count = 4};
  const uint8_t inert_data[8] = {0, 0, 0, 0, 0, 0x92, 0, 0};
  const int descriptor_allocate_pass =
    run_case(&fixture, &descriptor_allocate) && ldt_used[17] == 1 && ldt_used[20] == 1 &&
    memcmp(guest + LDT + 17 * 8, inert_data, sizeof(inert_data)) == 0 &&
    memcmp(guest + LDT + 20 * 8, inert_data, sizeof(inert_data)) == 0;
  if (!descriptor_allocate_pass) fprintf(stderr, "mediator descriptor allocation mismatch\n");
  pass = pass && descriptor_allocate_pass;

  DazeDpmiRequest selector_increment = {.function = 0x0003};
  const int selector_increment_pass = run_case(&fixture, &selector_increment);
  if (!selector_increment_pass) fprintf(stderr, "mediator selector increment mismatch\n");
  pass = pass && selector_increment_pass;

  real_mode_vector_segment[0x20] = 0x0028;
  real_mode_vector_offset[0x20] = 0x1234;
  DazeDpmiRequest get_real_mode = {.function = 0x0200, .selector = 0xff20};
  const int get_real_mode_pass = run_case(&fixture, &get_real_mode) &&
                                 daze_read_u32(guest + CAPTURE + CAP_AX) == 0xc3c30200u &&
                                 daze_read_u32(guest + CAPTURE + CAP_CX) == 0xa5a50028u &&
                                 daze_read_u32(guest + CAPTURE + CAP_DX) == 0x5a5a1234u &&
                                 daze_read_u16(guest + CAPTURE + CAP_BX) == 0xff20;
  if (!get_real_mode_pass) fprintf(stderr, "mediator real-mode vector getter mismatch\n");
  pass = pass && get_real_mode_pass;

  DazeDpmiRequest get = {.function = 0x0202, .selector = 0, .vector_segment = 0x0010};
  const int empty_pass = run_case(&fixture, &get) &&
                         daze_read_u32(guest + CAPTURE + CAP_CX) == 0xa5a50000u &&
                         daze_read_u32(guest + CAPTURE + CAP_DX) == 0x5a5a0000u &&
                         daze_read_u16(guest + CAPTURE + CAP_ES) == 0x0010 &&
                         daze_read_u16(guest + CAPTURE + CAP_DI) == 0;
  if (!empty_pass) fprintf(stderr, "mediator empty exception result mismatch\n");
  pass = pass && empty_pass;
  DazeDpmiRequest set = {
    .function = 0x0203, .selector = 0, .vector_segment = 0x0010, .vector_offset = 0x3456};
  const int set_pass = run_case(&fixture, &set);
  if (!set_pass) fprintf(stderr, "mediator set exception result mismatch\n");
  pass = pass && set_pass;
  const int get_pass = run_case(&fixture, &get) &&
                       daze_read_u32(guest + CAPTURE + CAP_CX) == 0xa5a50010u &&
                       daze_read_u32(guest + CAPTURE + CAP_DX) == 0x5a5a3456u &&
                       daze_read_u16(guest + CAPTURE + CAP_ES) == 0x0010 &&
                       daze_read_u16(guest + CAPTURE + CAP_DI) == 0;
  if (!get_pass) fprintf(stderr, "mediator restored exception result mismatch\n");
  pass = pass && get_pass;

  mediator->interrupt_vectors[0x10] =
    (DazeDpmiInterruptVector){.segment = 0x0097, .offset = 0x000001adu};
  DazeDpmiRequest get_interrupt = {.function = 0x0204, .selector = 0xff10};
  const int get_interrupt_pass = run_case(&fixture, &get_interrupt) &&
                                 daze_read_u32(guest + CAPTURE + CAP_AX) == 0xc3c30204u &&
                                 daze_read_u32(guest + CAPTURE + CAP_CX) == 0xa5a50097u &&
                                 daze_read_u32(guest + CAPTURE + CAP_DX) == 0x000001adu &&
                                 daze_read_u16(guest + CAPTURE + CAP_BX) == 0xff10;
  if (!get_interrupt_pass) fprintf(stderr, "mediator interrupt getter mismatch\n");
  pass = pass && get_interrupt_pass;
  mediator->default_interrupt_vectors[0x21] =
    (DazeDpmiInterruptVector){.segment = 0x0050, .offset = 0x000001c8u};
  DazeDpmiRequest get_default_interrupt = {.function = 0x0204, .selector = 0xff21};
  const int get_default_interrupt_pass = run_case(&fixture, &get_default_interrupt) &&
                                         daze_read_u32(guest + CAPTURE + CAP_CX) == 0xa5a50050u &&
                                         daze_read_u32(guest + CAPTURE + CAP_DX) == 0x000001c8u;
  if (!get_default_interrupt_pass) fprintf(stderr, "mediator default interrupt getter mismatch\n");
  pass = pass && get_default_interrupt_pass;
  DazeDpmiRequest override_default_interrupt = {.function = 0x0205,
                                                .selector = 0xff21,
                                                .interrupt_segment = 0x0008,
                                                .interrupt_offset = 0x000039d6u};
  const int override_default_interrupt_pass =
    run_case(&fixture, &override_default_interrupt) &&
    mediator->interrupt_vectors[0x21].segment == 0x0008 &&
    mediator->interrupt_vectors[0x21].offset == 0x000039d6u &&
    run_case(&fixture, &get_default_interrupt) &&
    daze_read_u32(guest + CAPTURE + CAP_CX) == 0xa5a50008u &&
    daze_read_u32(guest + CAPTURE + CAP_DX) == 0x000039d6u;
  if (!override_default_interrupt_pass)
    fprintf(stderr, "mediator interrupt override did not replace default\n");
  pass = pass && override_default_interrupt_pass;
  DazeDpmiRequest set_interrupt = {.function = 0x0205,
                                   .selector = 0xff10,
                                   .interrupt_segment = 0x0008,
                                   .interrupt_offset = 0x12345678u};
  const int set_interrupt_pass = run_case(&fixture, &set_interrupt) &&
                                 mediator->interrupt_vectors[0x10].segment == 0x0008 &&
                                 mediator->interrupt_vectors[0x10].offset == 0x12345678u;
  if (!set_interrupt_pass) fprintf(stderr, "mediator interrupt setter mismatch\n");
  pass = pass && set_interrupt_pass;

  DazeDpmiRequest state_save = {.function = 0x0305};
  const int state_save_pass = run_case(&fixture, &state_save) &&
                              daze_read_u32(guest + CAPTURE + CAP_AX) == 0xc3c3003cu &&
                              daze_read_u32(guest + CAPTURE + CAP_BX) == 0xb1b12200u &&
                              daze_read_u32(guest + CAPTURE + CAP_CX) == 0xa5a50100u &&
                              daze_read_u32(guest + CAPTURE + CAP_SI) == 0xd4d40028u &&
                              daze_read_u32(guest + CAPTURE + CAP_DI) == 0x00000100;
  if (!state_save_pass) fprintf(stderr, "mediator state-save endpoint mismatch\n");
  pass = pass && state_save_pass;

  DazeDpmiRequest raw_switch = {.function = 0x0306};
  const int raw_switch_pass = run_case(&fixture, &raw_switch) &&
                              daze_read_u32(guest + CAPTURE + CAP_AX) == 0xc3c30306u &&
                              daze_read_u32(guest + CAPTURE + CAP_BX) == 0xb1b12200u &&
                              daze_read_u32(guest + CAPTURE + CAP_CX) == 0xa5a50120u &&
                              daze_read_u32(guest + CAPTURE + CAP_SI) == 0xd4d40028u &&
                              daze_read_u32(guest + CAPTURE + CAP_DI) == 0x00000120;
  if (!raw_switch_pass) fprintf(stderr, "mediator raw-switch endpoint mismatch\n");
  pass = pass && raw_switch_pass;

  DazeDpmiRequest version = {.function = 0x0400};
  const int version_pass = run_case_ax(&fixture, &version, 0x005a, 0) &&
                           daze_read_u32(guest + CAPTURE + CAP_AX) == 0xc3c3005au &&
                           daze_read_u32(guest + CAPTURE + CAP_BX) == 0xb1b10003u &&
                           daze_read_u32(guest + CAPTURE + CAP_CX) == 0xa5a5be03u &&
                           daze_read_u32(guest + CAPTURE + CAP_DX) == 0x5a5a0870u;
  if (!version_pass) fprintf(stderr, "mediator version result mismatch\n");
  pass = pass && version_pass;

  DazeDpmiRequest disable_virtual_interrupts = {.function = 0x0900};
  const int virtual_interrupts_pass = run_case(&fixture, &disable_virtual_interrupts) &&
                                      daze_read_u32(guest + CAPTURE + CAP_AX) == 0xc3c30901u &&
                                      *virtual_interrupts_enabled == 0;
  if (!virtual_interrupts_pass) fprintf(stderr, "mediator virtual-interrupt disable mismatch\n");
  pass = pass && virtual_interrupts_pass;

  /* 0900h -> 0901h -> 0900h from the enabled state: returned AL 1, 0, 1;
   * state enabled -> disabled -> enabled -> disabled; CF clear every step.
   * The middle return is state-dependent, so expectations are explicit. */
  *virtual_interrupts_enabled = 1;
  DazeDpmiRequest enable_virtual_interrupts = {.function = 0x0901};
  const int vi_seq_a = run_case_ax(&fixture, &disable_virtual_interrupts, 0x0901, 0) &&
                       *virtual_interrupts_enabled == 0;
  const int vi_seq_b = run_case_ax(&fixture, &enable_virtual_interrupts, 0x0900, 0) &&
                       *virtual_interrupts_enabled == 1;
  const int vi_seq_c = run_case_ax(&fixture, &disable_virtual_interrupts, 0x0901, 0) &&
                       *virtual_interrupts_enabled == 0;
  if (!vi_seq_a || !vi_seq_b || !vi_seq_c)
    fprintf(stderr, "mediator virtual-interrupt sequence 0900->0901->0900 mismatch\n");
  pass = pass && vi_seq_a && vi_seq_b && vi_seq_c;

  DazeDpmiRequest unsupported_request = {.function = 0x0902};
  const int unsupported_rejected = run_case_ax(&fixture, &unsupported_request, 0, 0) == 0;
  if (!unsupported_rejected) fprintf(stderr, "mediator neighbouring function 0902h admitted\n");
  pass = pass && unsupported_rejected;

  /* Execute the actual legacy-token request through the protected gate.
   * Success preserves BX (paragraphs) and DX (handle), rather than returning
   * the 0503h BX:CX linear address. Invalid tokens return AX=9 and largest
   * available paragraphs in BX, without changing the arena. */
  DazeDpmiRequest dos_allocate = {.function = 0x0100, .count = 6};
  DazeKvmDpmiMediatorTestSnapshot dos_snapshot;
  uint32_t dos_descriptor_address = 0;
  const uint8_t dos_descriptor[8] = {0x5f, 0, 0, 0, 3, 0x92, 0, 0};
  const int dos_pass =
    daze_kvm_dpmi_mediator_test_run(&fixture, &dos_allocate, &dos_snapshot) &&
    !(dos_snapshot.eflags & 1u) && dos_snapshot.eax == 0x3000 && dos_snapshot.ebx == 0xb1b10006u &&
    daze_kvm_dpmi_mediator_descriptor_address(mediator, (uint16_t)dos_snapshot.edx,
                                              &dos_descriptor_address) &&
    memcmp(guest + dos_descriptor_address, dos_descriptor, 8) == 0 &&
    dos_memory->next_segment == 0x3006;
  const uint16_t dos_selector = (uint16_t)dos_snapshot.edx;
  dos_allocate.count = 0x100;
  const int dos_failure_pass =
    daze_kvm_dpmi_mediator_test_run(&fixture, &dos_allocate, &dos_snapshot) &&
    (dos_snapshot.eflags & 1u) && dos_snapshot.eax == 8 && dos_snapshot.ebx == 0xb1b100fau &&
    dos_memory->next_segment == 0x3006;
  if (!dos_pass || !dos_failure_pass) fprintf(stderr, "mediator DOS allocation mismatch\n");
  pass = pass && dos_pass && dos_failure_pass;
  const DazeDpmiLinearMemory before_dos_free = *linear_memory;
  const DazeDpmiRequest dos_free = {.function = 0x0101, .operand = dos_selector};
  pass &= run_case(&fixture, &dos_free) && ldt_used[dos_selector >> 3] == 0 &&
          !dos_memory->allocations[0].in_use &&
          memcmp(guest + dos_descriptor_address, (uint8_t[8]){0}, 8) == 0 &&
          memcmp(linear_memory, &before_dos_free, sizeof(before_dos_free)) == 0 &&
          run_case_ax(&fixture, &dos_free, 9, 1);
  uint32_t loader_base, loader_handle;
  pass &= daze_dpmi_linear_memory_allocate(linear_memory, 0xffff, &loader_base, &loader_handle);
  DazeDpmiRequest loader_resize = {.function = 0x0102, .operand = loader_handle, .size = 0x2740};
  DazeKvmDpmiMediatorTestSnapshot loader_snapshot = {0};
  const DazeDpmiLinearAllocation *loader_allocation = &linear_memory->allocations[0];
  pass &= daze_kvm_dpmi_mediator_test_run(&fixture, &loader_resize, &loader_snapshot) &&
          (loader_snapshot.eflags & 1u) == 0 && loader_snapshot.eax == 0x0102 &&
          loader_snapshot.ebx == 0x0274 && loader_snapshot.edx == loader_handle &&
          loader_allocation->in_use && loader_allocation->handle == loader_handle &&
          loader_allocation->base == loader_base && loader_allocation->allocated_size == 0x3000;
  const DazeDpmiLinearMemory loader_before = *linear_memory;
  loader_resize.operand = 0x1234;
  pass &= daze_kvm_dpmi_mediator_test_run(&fixture, &loader_resize, &loader_snapshot) &&
          (loader_snapshot.eflags & 1u) != 0 && loader_snapshot.eax == 9 &&
          (uint16_t)loader_snapshot.ebx ==
            (uint16_t)(daze_dpmi_linear_memory_largest_available(linear_memory) >> 4) &&
          loader_snapshot.edx == 0x1234 &&
          memcmp(&loader_before, linear_memory, sizeof(*linear_memory)) == 0;
  DazeDpmiRequest loader_release = {.function = 0x0101, .operand = loader_handle};
  pass &= run_case(&fixture, &loader_release) && !loader_allocation->in_use &&
          run_case_ax(&fixture, &loader_release, 9, 1);

  const uint8_t before[DAZE_KVM_DPMI_MAILBOX_SIZE] = {0};
  memcpy(guest + MAILBOX, before, sizeof(before));
  const DazeDpmiLinearMemory linear_before = *linear_memory;
  DazeDpmiExceptionVector vectors_before[32];
  memcpy(vectors_before, mediator->exception_vectors, sizeof(vectors_before));
  DazeDpmiInterruptVector interrupts_before[256];
  memcpy(interrupts_before, mediator->interrupt_vectors, sizeof(interrupts_before));
  DazeDpmiRequest unsupported = {.function = 0x9999, .selector = 0x0014};
  uint16_t port;
  uint8_t marker;
  const int unsupported_pass =
    daze_kvm_dpmi_mediator_test_begin(&fixture, &unsupported, &port, &marker) &&
    daze_kvm_dpmi_mediator_process(mediator, port, marker) == DAZE_KVM_DPMI_MEDIATOR_UNSUPPORTED &&
    memcmp(guest + MAILBOX, before, sizeof(before)) == 0 &&
    memcmp(linear_memory, &linear_before, sizeof(*linear_memory)) == 0 &&
    memcmp(mediator->exception_vectors, vectors_before, sizeof(vectors_before)) == 0 &&
    memcmp(mediator->interrupt_vectors, interrupts_before, sizeof(interrupts_before)) == 0;
  if (!unsupported_pass) fprintf(stderr, "mediator unsupported state changed\n");
  pass = pass && unsupported_pass;
  pass &= procedure_admission(&fixture);
  pass &= rejected_records(&fixture);
  pass &= remaining_requests(&fixture);
  pass &= vector_diagnostics(&fixture);
  pass &= rejected_operations(&fixture);
  daze_kvm_dpmi_mediator_test_fixture_destroy(&fixture);
  fprintf(stderr, "KVM DPMI mediator contract: %s\n", pass ? "passed" : "failed");
  return pass ? 0 : 1;
}

#else

int main(void) {
  return 77;
}

#endif
