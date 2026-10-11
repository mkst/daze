#include "dpmi_test_driver.h"

#include "mediator_test_driver.h"

#include <stdio.h>

typedef struct {
  uint16_t function;
  int success;
  int carry;
  uint16_t ax;
  uint32_t ebx;
  uint32_t ecx;
  uint32_t edx;
  uint32_t esi;
  uint32_t edi;
  int edi_retained;
  int es_retained;
  int virtual_interrupts_enabled;
  uint32_t linear_next_base;
  int linear_handle_one_live;
  uint16_t slot_segment;
  uint32_t slot_offset;
} DazeDpmiSharedRecord;

static void slot_from_unicorn(const DazeUnicornDpmiTestDriver *driver,
                              const DazeDpmiRequest *request, uint16_t *segment, uint32_t *offset) {
  const uint8_t index = request->function <= 0x0201   ? request->interrupt
                        : request->function <= 0x0203 ? request->exception
                                                      : request->interrupt;
  if (request->function <= 0x0201) {
    *segment = driver->context.process.dos_process.dos_vector_segment[index];
    *offset = driver->context.process.dos_process.dos_vector_offset[index];
  } else if (request->function <= 0x0203 && request->exception < 32) {
    *segment = driver->context.process.dpmi.exception_vector_segment[index];
    *offset = driver->context.process.dpmi.exception_vector_offset[index];
  } else if (request->function >= 0x0204) {
    *segment = driver->context.process.dpmi.interrupt_vectors[index].segment;
    *offset = driver->context.process.dpmi.interrupt_vectors[index].offset;
  } else {
    *segment = 0;
    *offset = 0;
  }
}

static void slot_from_kvm(const DazeKvmDpmiMediator *mediator, const DazeDpmiRequest *request,
                          uint16_t *segment, uint32_t *offset) {
  const uint8_t index = request->function <= 0x0201   ? request->interrupt
                        : request->function <= 0x0203 ? request->exception
                                                      : request->interrupt;
  if (request->function <= 0x0201) {
    *segment = mediator->real_mode_vector_segment[index];
    *offset = mediator->real_mode_vector_offset[index];
  } else if (request->function <= 0x0203 && request->exception < 32) {
    *segment = mediator->exception_vectors[index].segment;
    *offset = mediator->exception_vectors[index].offset;
  } else if (request->function >= 0x0204) {
    *segment = mediator->interrupt_vectors[index].segment;
    *offset = mediator->interrupt_vectors[index].offset;
  } else {
    *segment = 0;
    *offset = 0;
  }
}

static DazeDpmiSharedRecord normalize_unicorn(const DazeUnicornDpmiTestDriver *driver,
                                              const DazeDpmiRequest *request,
                                              const DazeUnicornDpmiTestSnapshot *snapshot) {
  DazeDpmiSharedRecord record = {
    .function = request->function,
    .success = (snapshot->eflags & 1u) == 0,
    .carry = (snapshot->eflags & 1u) != 0,
    .ax = (uint16_t)snapshot->eax,
    .ebx = snapshot->ebx,
    .ecx = snapshot->ecx,
    .edx = snapshot->edx,
    .esi = snapshot->esi,
    .edi = snapshot->edi,
    .edi_retained = snapshot->edi == snapshot->initial_edi,
    .es_retained = snapshot->es == snapshot->initial_es,
    .virtual_interrupts_enabled = driver->context.process.dpmi.virtual_interrupts_enabled,
    .linear_next_base = driver->context.process.dpmi.linear_memory.next_base,
    .linear_handle_one_live =
      driver->context.process.dpmi.linear_memory.allocations[0].in_use &&
      driver->context.process.dpmi.linear_memory.allocations[0].handle == 1};
  slot_from_unicorn(driver, request, &record.slot_segment, &record.slot_offset);
  return record;
}

static DazeDpmiSharedRecord normalize_kvm(const DazeKvmDpmiMediator *mediator,
                                          const DazeDpmiRequest *request,
                                          const DazeKvmDpmiMediatorTestSnapshot *snapshot) {
  DazeDpmiSharedRecord record = {
    .function = request->function,
    .success = (snapshot->eflags & 1u) == 0,
    .carry = (snapshot->eflags & 1u) != 0,
    .ax = (uint16_t)snapshot->eax,
    .ebx = snapshot->ebx,
    .ecx = snapshot->ecx,
    .edx = snapshot->edx,
    .esi = snapshot->esi,
    .edi = snapshot->edi,
    .edi_retained = snapshot->edi == snapshot->initial_edi,
    .es_retained = snapshot->es == snapshot->initial_es,
    .virtual_interrupts_enabled = *mediator->virtual_interrupts_enabled,
    .linear_next_base = mediator->linear_memory->next_base,
    .linear_handle_one_live = mediator->linear_memory->allocations[0].in_use &&
                              mediator->linear_memory->allocations[0].handle == 1};
  slot_from_kvm(mediator, request, &record.slot_segment, &record.slot_offset);
  return record;
}

static int equal(const DazeDpmiSharedRecord *a, const DazeDpmiSharedRecord *b) {
  return a->function == b->function && a->success == b->success && a->carry == b->carry &&
         a->ax == b->ax && a->ebx == b->ebx && a->ecx == b->ecx && a->edx == b->edx &&
         a->esi == b->esi && a->edi == b->edi && a->edi_retained == b->edi_retained &&
         a->es_retained == b->es_retained && a->slot_segment == b->slot_segment &&
         a->slot_offset == b->slot_offset &&
         a->virtual_interrupts_enabled == b->virtual_interrupts_enabled &&
         a->linear_next_base == b->linear_next_base &&
         a->linear_handle_one_live == b->linear_handle_one_live;
}

static DazeUnicornDpmiTestInput unicorn_input(const DazeDpmiRequest *request) {
  DazeUnicornDpmiTestInput input = {.eax = request->function,
                                    .ebx = request->selector,
                                    .ecx = request->operand >> 16,
                                    .edx = request->operand,
                                    .edi = request->vector_offset,
                                    .es = request->vector_segment == 0 ? 0x0010
                                                                       : request->vector_segment,
                                    .eflags = 0x202};
  if (request->function == 0x0200 || request->function == 0x0202 || request->function == 0x0204) {
    input.eax |= 0xc3c30000u;
    input.ecx = 0xa5a50000u;
    input.edx = 0x5a5a0000u;
  } else if (request->function == 0x0201 || request->function == 0x0203) {
    input.ecx = 0xa5a50000u | request->vector_segment;
    input.edx = 0x5a5a0000u | request->vector_offset;
  } else if (request->function == 0x0205) {
    input.ecx = 0xa5a50000u | request->interrupt_segment;
    input.edx = request->interrupt_offset;
  } else if (request->function == 0x0305 || request->function == 0x0306) {
    input.eax = 0xc3c30000u | request->function;
    input.ebx = 0xb1b10000u;
    input.ecx = 0xa5a50000u;
    input.esi = 0xd4d40000u;
  } else if (request->function == 0x0400) {
    input.eax = 0xc3c30400u;
    input.ebx = 0xb1b10000u;
    input.ecx = 0xa5a5be00u;
    input.edx = 0x5a5a0000u;
  } else if (request->function == 0x0900 || request->function == 0x0901) {
    input.eax = 0xc3c30000u | request->function;
  } else if (request->function == 0x0501 || request->function == 0x0503) {
    input.ebx = request->size >> 16;
    input.ecx = (uint16_t)request->size;
  }
  if (request->function == 0x0502 || request->function == 0x0503) {
    input.esi = request->operand >> 16;
    input.edi = request->operand;
  }
  if (request->function == 0x0202 || request->function == 0x0203) input.ebx = request->exception;
  return input;
}

static int run_unicorn(const DazeDpmiRequest *requests, size_t count,
                       DazeDpmiSharedRecord *records) {
  DazeUnicornDpmiTestDriver driver;
  if (!daze_unicorn_dpmi_test_driver_init(&driver)) return 0;
  driver.context.process.dpmi.virtual_interrupts_enabled = 1;
  daze_dpmi_linear_memory_init(&driver.context.process.dpmi.linear_memory, 0x50000, 0x70000);
  for (size_t index = 0; index < count; ++index) {
    DazeUnicornDpmiTestSnapshot snapshot = {0};
    const DazeUnicornDpmiTestInput input = unicorn_input(&requests[index]);
    if (!daze_unicorn_dpmi_test_driver_run(&driver, &input, &snapshot)) {
      daze_unicorn_dpmi_test_driver_destroy(&driver);
      return 0;
    }
    records[index] = normalize_unicorn(&driver, &requests[index], &snapshot);
  }
  daze_unicorn_dpmi_test_driver_destroy(&driver);
  return 1;
}

static int run_kvm(const DazeDpmiRequest *requests, size_t count, DazeDpmiSharedRecord *records) {
  DazeKvmDpmiMediatorTestFixture fixture;
  const DazeKvmDpmiStateSaveEndpoints state_save_endpoints = {
    .state_buffer_size = 60,
    .rm_segment = 0x0200,
    .rm_offset = 0x0100,
    .pm_selector = 0x0028,
    .pm_offset = 0x00000100,
  };
  const DazeKvmDpmiRawSwitchEndpoints raw_switch_endpoints = {
    .rm_segment = 0x0200,
    .rm_offset = 0x0120,
    .pm_selector = 0x0028,
    .pm_offset = 0x00000120,
  };
  const int init =
    daze_kvm_dpmi_mediator_test_fixture_init(&fixture, state_save_endpoints, raw_switch_endpoints);
  if (init == DAZE_KVM_MACHINE_UNAVAILABLE) return 77;
  if (init != DAZE_KVM_MACHINE_OK) return 0;
  for (size_t index = 0; index < count; ++index) {
    DazeKvmDpmiMediatorTestSnapshot snapshot = {0};
    if (!daze_kvm_dpmi_mediator_test_run(&fixture, &requests[index], &snapshot)) {
      daze_kvm_dpmi_mediator_test_fixture_destroy(&fixture);
      return 0;
    }
    records[index] = normalize_kvm(&fixture.mediator, &requests[index], &snapshot);
  }
  daze_kvm_dpmi_mediator_test_fixture_destroy(&fixture);
  return 1;
}

static int run_rows(const char *name, const DazeDpmiRequest *requests, size_t count,
                    DazeDpmiSharedRecord *unicorn, DazeDpmiSharedRecord *kvm) {
  if (!run_unicorn(requests, count, unicorn)) return 0;
  const int status = run_kvm(requests, count, kvm);
  if (status == 77) return 77;
  if (status != 1) return 0;
  for (size_t index = 0; index < count; ++index) {
    if (!equal(&unicorn[index], &kvm[index])) {
      fprintf(stderr, "DPMI shared %s row %zu differs\n", name, index);
      return 0;
    }
  }
  return 1;
}

static int get16(const DazeDpmiSharedRecord *record, uint16_t function, uint16_t segment,
                 uint16_t offset) {
  return record->function == function && record->success && !record->carry &&
         record->ax == function && record->ecx == (0xa5a50000u | segment) &&
         record->edx == (0x5a5a0000u | offset) && record->edi_retained && record->es_retained &&
         record->slot_segment == segment && record->slot_offset == offset;
}

static int get32(const DazeDpmiSharedRecord *record, uint16_t segment, uint32_t offset) {
  return record->function == 0x0204 && record->success && !record->carry && record->ax == 0x0204 &&
         record->ecx == (0xa5a50000u | segment) && record->edx == offset && record->edi_retained &&
         record->es_retained && record->slot_segment == segment && record->slot_offset == offset;
}

static int set16(const DazeDpmiSharedRecord *record, uint16_t function, uint16_t segment,
                 uint16_t offset) {
  return record->function == function && record->success && !record->carry &&
         record->ax == function && record->ecx == (0xa5a50000u | segment) &&
         record->edx == (0x5a5a0000u | offset) && record->edi_retained && record->es_retained &&
         record->slot_segment == segment && record->slot_offset == offset;
}

static int set32(const DazeDpmiSharedRecord *record, uint16_t segment, uint32_t offset) {
  return record->function == 0x0205 && record->success && !record->carry && record->ax == 0x0205 &&
         record->ecx == (0xa5a50000u | segment) && record->edx == offset && record->edi_retained &&
         record->es_retained && record->slot_segment == segment && record->slot_offset == offset;
}

int main(void) {
  const DazeDpmiRequest real_rows[] = {
    {.function = 0x0200, .selector = 0x0021, .interrupt = 0x21, .vector_offset = 0x5678},
    {.function = 0x0201,
     .selector = 0x0021,
     .interrupt = 0x21,
     .vector_segment = 0x1234,
     .vector_offset = 0x5678},
    {.function = 0x0200, .selector = 0x0021, .interrupt = 0x21, .vector_offset = 0x5678},
  };
  const DazeDpmiRequest exception_rows[] = {
    {.function = 0x0202,
     .exception = 3,
     .selector = 3,
     .vector_segment = 0x0010,
     .vector_offset = 0x5678},
    {.function = 0x0203,
     .exception = 3,
     .selector = 3,
     .vector_segment = 0x2222,
     .vector_offset = 0x4567},
    {.function = 0x0202,
     .exception = 3,
     .selector = 3,
     .vector_segment = 0x0010,
     .vector_offset = 0x5678},
  };
  const DazeDpmiRequest interrupt_rows[] = {
    {.function = 0x0204,
     .selector = 0x0010,
     .interrupt = 0x10,
     .vector_segment = 0x0010,
     .vector_offset = 0x5678},
    {.function = 0x0205,
     .selector = 0x0010,
     .interrupt = 0x10,
     .interrupt_segment = 0x3333,
     .interrupt_offset = 0x89abcdefu},
    {.function = 0x0204,
     .selector = 0x0010,
     .interrupt = 0x10,
     .vector_segment = 0x0010,
     .vector_offset = 0x5678},
  };
  const DazeDpmiRequest invalid_rows[] = {
    {.function = 0x0203,
     .exception = 32,
     .selector = 32,
     .vector_segment = 0x2222,
     .vector_offset = 0x4567},
    {.function = 0x0202,
     .exception = 32,
     .selector = 32,
     .vector_segment = 0x0010,
     .vector_offset = 0x5678},
  };
  DazeDpmiSharedRecord unicorn[4] = {0};
  DazeDpmiSharedRecord kvm[4] = {0};
  int status = run_rows("real-vector", real_rows, 3, unicorn, kvm);
  if (status == 77) return 77;
  const int real_empty = get16(&unicorn[0], 0x0200, 0, 0);
  const int real_set = set16(&unicorn[1], 0x0201, 0x1234, 0x5678);
  const int real_get = get16(&unicorn[2], 0x0200, 0x1234, 0x5678);
  if (status != 1 || !real_empty || !real_set || !real_get) {
    fprintf(stderr,
            "DPMI shared real-vector expectations failed: ax=%04x/%04x/%04x ecx:edx=%08x:%08x "
            "%08x:%08x %08x:%08x retain=%d,%d state=%04x:%08x\n",
            unicorn[0].ax, unicorn[1].ax, unicorn[2].ax, unicorn[0].ecx, unicorn[0].edx,
            unicorn[1].ecx, unicorn[1].edx, unicorn[2].ecx, unicorn[2].edx, unicorn[0].edi_retained,
            unicorn[0].es_retained, unicorn[1].slot_segment, unicorn[1].slot_offset);
    fprintf(stderr, "  rows empty=%d set=%d get=%d\n", real_empty, real_set, real_get);
    return 1;
  }
  status = run_rows("exception-vector", exception_rows, 3, unicorn, kvm);
  if (status != 1 || !get16(&unicorn[0], 0x0202, 0, 0) ||
      !set16(&unicorn[1], 0x0203, 0x2222, 0x4567) || !get16(&unicorn[2], 0x0202, 0x2222, 0x4567)) {
    fprintf(stderr, "DPMI shared exception-vector expectations failed\n");
    return 1;
  }
  status = run_rows("interrupt-vector", interrupt_rows, 3, unicorn, kvm);
  if (status != 1 || !get32(&unicorn[0], 0, 0) || !set32(&unicorn[1], 0x3333, 0x89abcdefu) ||
      !get32(&unicorn[2], 0x3333, 0x89abcdefu)) {
    fprintf(stderr, "DPMI shared interrupt-vector expectations failed\n");
    return 1;
  }
  status = run_rows("invalid-exception", invalid_rows, 2, unicorn, kvm);
  if (status != 1 || unicorn[0].success || !unicorn[0].carry || unicorn[0].ax != 0x8021 ||
      unicorn[0].slot_segment != 0 || unicorn[0].slot_offset != 0 || unicorn[1].success ||
      !unicorn[1].carry || unicorn[1].ax != 0x8021 || unicorn[1].slot_segment != 0 ||
      unicorn[1].slot_offset != 0) {
    fprintf(stderr, "DPMI shared invalid-exception expectations failed\n");
    return 1;
  }
  const DazeDpmiRequest transition_rows[] = {{.function = 0x0305}, {.function = 0x0306}};
  status = run_rows("transition-endpoint", transition_rows, 2, unicorn, kvm);
  if (status != 1 || !unicorn[0].success || unicorn[0].carry || unicorn[0].ax != 60 ||
      unicorn[0].ebx != 0xb1b10200u || unicorn[0].ecx != 0xa5a50100u ||
      unicorn[0].esi != 0xd4d40028u || unicorn[0].edi != 0x00000100u || !unicorn[1].success ||
      unicorn[1].carry || unicorn[1].ax != 0x0306 || unicorn[1].ebx != 0xb1b10200u ||
      unicorn[1].ecx != 0xa5a50120u || unicorn[1].esi != 0xd4d40028u ||
      unicorn[1].edi != 0x00000120u) {
    fprintf(stderr, "DPMI shared transition-endpoint expectations failed\n");
    return 1;
  }
  const DazeDpmiRequest scalar_rows[] = {
    {.function = 0x0400}, {.function = 0x0900}, {.function = 0x0901}, {.function = 0x0900}};
  status = run_rows("scalar", scalar_rows, 4, unicorn, kvm);
  if (status != 1 || unicorn[0].ax != 0x005a || unicorn[0].ebx != 0xb1b10003u ||
      unicorn[0].ecx != 0xa5a5be03u || unicorn[0].edx != 0x5a5a0870u || !unicorn[0].success ||
      unicorn[0].carry || unicorn[1].ax != 0x0901 || !unicorn[1].success || unicorn[1].carry ||
      unicorn[1].virtual_interrupts_enabled != 0 || unicorn[2].ax != 0x0900 ||
      !unicorn[2].success || unicorn[2].carry || unicorn[2].virtual_interrupts_enabled != 1 ||
      unicorn[3].ax != 0x0901 || !unicorn[3].success || unicorn[3].carry ||
      unicorn[3].virtual_interrupts_enabled != 0) {
    fprintf(stderr, "DPMI shared scalar expectations failed\n");
    return 1;
  }
  const DazeDpmiRequest linear_rows[] = {
    {.function = 0x0501, .size = 0x00015000u},
    {.function = 0x0503, .size = 0x00002000u, .operand = 1},
    {.function = 0x0502, .operand = 1},
    {.function = 0x0502, .operand = 1},
  };
  status = run_rows("linear", linear_rows, 4, unicorn, kvm);
  if (status != 1 || !unicorn[0].success || unicorn[0].carry || unicorn[0].ax != 0x0501 ||
      unicorn[0].ebx != 5 || unicorn[0].ecx != 0 || unicorn[0].esi != 0 || unicorn[0].edi != 1 ||
      unicorn[0].linear_next_base != 0x65000u || !unicorn[0].linear_handle_one_live ||
      !unicorn[1].success || unicorn[1].carry || unicorn[1].ax != 0x0503 || unicorn[1].ebx != 5 ||
      unicorn[1].ecx != 0 || unicorn[1].esi != 0 || unicorn[1].edi != 1 ||
      unicorn[1].linear_next_base != 0x52000u || !unicorn[1].linear_handle_one_live ||
      !unicorn[2].success || unicorn[2].carry || unicorn[2].ax != 0x0502 ||
      unicorn[2].linear_next_base != 0x50000u || unicorn[2].linear_handle_one_live ||
      unicorn[3].success || !unicorn[3].carry || unicorn[3].ax != 0x8023 ||
      unicorn[3].linear_next_base != 0x50000u || unicorn[3].linear_handle_one_live) {
    fprintf(stderr,
            "DPMI shared linear expectations failed: ax=%04x/%04x/%04x/%04x bx=%08x/%08x "
            "cx=%08x/%08x next=%08x/%08x/%08x/%08x live=%d/%d/%d/%d\n",
            unicorn[0].ax, unicorn[1].ax, unicorn[2].ax, unicorn[3].ax, unicorn[0].ebx,
            unicorn[1].ebx, unicorn[0].ecx, unicorn[1].ecx, unicorn[0].linear_next_base,
            unicorn[1].linear_next_base, unicorn[2].linear_next_base, unicorn[3].linear_next_base,
            unicorn[0].linear_handle_one_live, unicorn[1].linear_handle_one_live,
            unicorn[2].linear_handle_one_live, unicorn[3].linear_handle_one_live);
    return 1;
  }
  const DazeDpmiRequest selector_increment[] = {{.function = 0x0003}};
  status = run_rows("selector-increment", selector_increment, 1, unicorn, kvm);
  if (status != 1 || !unicorn[0].success || unicorn[0].carry || unicorn[0].ax != 0x0008) {
    fprintf(stderr, "DPMI shared selector-increment expectations failed\n");
    return 1;
  }
  const DazeDpmiRequest lock_rows[] = {
    {.function = 0x0600, .selector = 5, .operand = 0x02e30000, .vector_offset = 0x12},
    {.function = 0x0601, .selector = 5, .operand = 0x02e30000, .vector_offset = 0x12}};
  status = run_rows("non-paging-lock-unlock", lock_rows, 2, unicorn, kvm);
  for (size_t index = 0; index < 2; ++index) {
    if (status != 1 || !unicorn[index].success || unicorn[index].carry ||
        unicorn[index].ax != lock_rows[index].function || unicorn[index].ebx != 5 ||
        unicorn[index].ecx != 0x02e3 || unicorn[index].edx != 0x02e30000 ||
        unicorn[index].esi != 0 || unicorn[index].edi != 0x12 || !unicorn[index].es_retained ||
        unicorn[index].linear_next_base != 0x50000 || unicorn[index].linear_handle_one_live) {
      fprintf(stderr, "DPMI shared non-paging lock/unlock expectations failed\n");
      return 1;
    }
  }
  return 0;
}
