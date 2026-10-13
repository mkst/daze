/* Exercise private exit decoding without exporting a test API or resuming a VM. */
#include "entry.c"

#include <assert.h>

#ifdef NDEBUG
#undef assert
#define assert(expression) ((expression) ? (void)0 : abort())
#endif

int main(void) {
#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
  struct {
    struct kvm_run run;
    uint8_t bytes[16];
  } storage = {0};
  DazeKvmMachine machine = {.run = &storage.run, .run_size = sizeof(storage)};
  uint8_t guest[32] = {0};
  for (int kind = 0; kind < 5; ++kind) {
    DazeKvmMachine invalid = {
      .vcpu = 0, .run = &storage.run, .guest = guest, .guest_size = sizeof(guest)};
    if (kind == 1) invalid.vcpu = -1;
    if (kind == 2) invalid.run = NULL;
    if (kind == 4) invalid.guest = NULL;
    DazeKvmDpmiEntryResult result;
    int (*const continuations[])(DazeKvmMachine *, DazeKvmDpmiEntryResult *) = {
      daze_kvm_dpmi_entry_continue_once, daze_kvm_dpmi_entry_continue_mediator_or_capture,
      daze_kvm_dpmi_entry_continue_observe, daze_kvm_dpmi_entry_observe_mediator_or_capture};
    if (kind < 4) {
      for (size_t i = 0; i < sizeof(continuations) / sizeof(continuations[0]); ++i) {
        memset(&result, 0xa5, sizeof(result));
        assert(continuations[i](kind == 0 ? NULL : &invalid, kind == 3 ? NULL : &result) ==
               DAZE_KVM_DPMI_ENTRY_INVALID);
        if (kind != 3) assert(result.observation.kind == DAZE_KVM_DPMI_ENTRY_EXIT_NONE);
      }
    }
    memset(&result, 0xa5, sizeof(result));
    assert(daze_kvm_dpmi_entry_continue_to_linear(kind == 0 ? NULL : &invalid, 0,
                                                  kind == 3 ? NULL : &result) ==
           DAZE_KVM_DPMI_ENTRY_INVALID);
    if (kind != 3) assert(result.observation.kind == DAZE_KVM_DPMI_ENTRY_EXIT_NONE);
    memset(&result, 0xa5, sizeof(result));
    assert(daze_kvm_dpmi_entry_retire_mediator_out(kind == 0 ? NULL : &invalid, 0, 0,
                                                   kind == 3 ? NULL : &result) ==
           DAZE_KVM_DPMI_ENTRY_INVALID);
    if (kind != 3) assert(result.observation.kind == DAZE_KVM_DPMI_ENTRY_EXIT_NONE);
  }
  DazeKvmDpmiEntryResult invalid_result;
  machine.guest = guest;
  machine.guest_size = sizeof(guest);
  machine.vcpu = 0;
  assert(daze_kvm_dpmi_entry_capture_state(&machine, NULL) == DAZE_KVM_DPMI_ENTRY_INVALID);
  assert(daze_kvm_dpmi_entry_run(&machine, NULL, NULL, NULL) == DAZE_KVM_DPMI_ENTRY_INVALID);
  assert(daze_kvm_dpmi_entry_run(&machine, NULL, NULL, &invalid_result) ==
         DAZE_KVM_DPMI_ENTRY_INVALID);
  assert(daze_kvm_dpmi_entry_continue_to_linear(&machine, sizeof(guest), &invalid_result) ==
         DAZE_KVM_DPMI_ENTRY_INVALID);
  assert(daze_kvm_dpmi_entry_retire_mediator_out(&machine, UINT32_MAX, 1, &invalid_result) ==
         DAZE_KVM_DPMI_ENTRY_INVALID);
  assert(daze_kvm_dpmi_entry_retire_mediator_out(&machine, 0, sizeof(guest) - 7, &invalid_result) ==
         DAZE_KVM_DPMI_ENTRY_INVALID);
  guest[0] = 0xe6;
  guest[1] = 0x80;
  assert(daze_kvm_dpmi_entry_retire_mediator_out(&machine, 0, 0, &invalid_result) ==
         DAZE_KVM_DPMI_ENTRY_INVALID);
  static const struct {
    uint32_t raw;
    DazeKvmDpmiEntryExitKind unexpected, continuation;
  } cases[] = {
    {KVM_EXIT_DEBUG, DAZE_KVM_DPMI_ENTRY_EXIT_UNEXPECTED_DEBUG, DAZE_KVM_DPMI_ENTRY_EXIT_DEBUG},
    {KVM_EXIT_HLT, DAZE_KVM_DPMI_ENTRY_EXIT_UNEXPECTED_HLT, DAZE_KVM_DPMI_ENTRY_EXIT_HLT},
    {KVM_EXIT_FAIL_ENTRY, DAZE_KVM_DPMI_ENTRY_EXIT_UNEXPECTED_FAIL_ENTRY,
     DAZE_KVM_DPMI_ENTRY_EXIT_FAIL_ENTRY},
    {KVM_EXIT_INTERNAL_ERROR, DAZE_KVM_DPMI_ENTRY_EXIT_UNEXPECTED_OTHER,
     DAZE_KVM_DPMI_ENTRY_EXIT_OTHER},
    {KVM_EXIT_SHUTDOWN, DAZE_KVM_DPMI_ENTRY_EXIT_UNEXPECTED_OTHER, DAZE_KVM_DPMI_ENTRY_EXIT_OTHER},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
    memset(&storage, 0, sizeof(storage));
    storage.run.exit_reason = cases[i].raw;
    if (cases[i].raw == KVM_EXIT_FAIL_ENTRY)
      storage.run.fail_entry.hardware_entry_failure_reason = 0x123456789abcdef0ull;
    if (cases[i].raw == KVM_EXIT_INTERNAL_ERROR) storage.run.internal.suberror = 3;
    DazeKvmDpmiEntryObservation output = {0};
    observe_exit(&machine, &storage.run, &output);
    assert(output.raw_exit_reason == cases[i].raw && output.kind == cases[i].unexpected);
    if (cases[i].raw == KVM_EXIT_FAIL_ENTRY)
      assert(output.fail_entry_reason == 0x123456789abcdef0ull);
    if (cases[i].raw == KVM_EXIT_INTERNAL_ERROR) assert(output.internal_suberror == 3);
    observe_continuation_exit(&machine, &storage.run, &output);
    assert(output.kind == cases[i].continuation && output.raw_exit_reason == cases[i].raw);
  }
  for (int kind = 0; kind < 9; ++kind) {
    memset(&storage, 0, sizeof(storage));
    storage.run.exit_reason = KVM_EXIT_IO;
    storage.run.io.direction = KVM_EXIT_IO_OUT;
    storage.run.io.port = 0xf4;
    storage.run.io.size = 1;
    storage.run.io.count = 1;
    storage.run.io.data_offset = sizeof(struct kvm_run);
    storage.bytes[0] = 0x31;
    if (kind == 1) storage.run.io.direction = KVM_EXIT_IO_IN;
    if (kind == 2) storage.run.io.count = 2;
    if (kind == 3) storage.run.io.size = 8;
    if (kind == 4) storage.run.io.data_offset = machine.run_size + 1;
    if (kind == 5) {
      storage.run.io.size = 2;
      storage.run.io.data_offset = machine.run_size - 1;
    }
    if (kind == 6) storage.run.io.port = 0x80;
    if (kind == 7) storage.bytes[0] = 0x32;
    if (kind == 8) {
      storage.run.io.size = 4;
      memcpy(storage.bytes, (uint8_t[]){0x12, 0x34, 0x56, 0x78}, 4);
    }
    DazeKvmDpmiEntryResult output = {0};
    observe_continuation_exit(&machine, &storage.run, &output.observation);
    assert(output.observation.kind == DAZE_KVM_DPMI_ENTRY_EXIT_PIO &&
           output.observation.raw_exit_reason == KVM_EXIT_IO &&
           output.observation.pio_port == storage.run.io.port &&
           output.observation.pio_size == storage.run.io.size &&
           output.observation.pio_count == storage.run.io.count);
    assert(output.observation.pio_direction ==
           (kind == 1 ? DAZE_KVM_DPMI_ENTRY_PIO_IN : DAZE_KVM_DPMI_ENTRY_PIO_OUT));
    assert(output.observation.pio_value_present == (kind == 0 || kind >= 6));
    assert(mediator_pio(&output) == (kind == 0));
    if (kind == 0) assert(output.observation.pio_value == 0x31);
    if (kind == 8) assert(output.observation.pio_value == 0x78563412);
  }
  puts("KVM entry observation contract: passed");
#endif
  return 0;
}
