#include "child_context.c"
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <unistd.h>

static void guards(void) {
  uint8_t guest[0x2100] = {0};
  DazeKvmMachine machine = {.guest = guest, .guest_size = sizeof(guest), .vcpu = -1};
  DazeKvmChildContext context = {0};
  DazeKvmRunnerRequestCommon layout = {0};
  DazeDosProcessState dos = {0};
  DazeDosMemory memory = {0};
  DazeDpmiProcessState dpmi = {0};
  for (int absent = 0; absent < 7; ++absent) {
    assert(!daze_kvm_child_context_capture(
      absent == 0 ? NULL : &context, absent == 1 ? NULL : &machine, absent == 2 ? NULL : &layout,
      absent == 3 ? NULL : &dos, absent == 4 ? NULL : &memory, absent == 5 ? NULL : &dpmi));
    assert(!context.active && context.parent_dpmi == NULL);
  }
  context.active = 1;
  for (int absent = 0; absent < 5; ++absent) {
    assert(!daze_kvm_child_context_restore(
      absent == 0 ? NULL : &context, absent == 1 ? NULL : &machine, absent == 2 ? NULL : &dos,
      absent == 3 ? NULL : &memory, absent == 4 ? NULL : &dpmi));
  }
  for (int absent = 0; absent < 7; ++absent) {
    DazeKvmMachine candidate = machine;
    if (absent == 6) candidate.guest = NULL;
    assert(!daze_kvm_child_context_restore_resident(
      absent == 0 ? NULL : &context, absent == 1 ? NULL : &candidate, absent == 2 ? NULL : &dos,
      absent == 3 ? NULL : &memory, absent == 4 ? NULL : &dpmi, absent == 5 ? 0 : 1, NULL));
    assert(context.active && context.parent_dpmi == NULL);
  }
  DazeKvmResidentGdtState resident = {0};
  assert(!daze_kvm_resident_vector_projections_refresh(NULL, &resident, &memory));
  assert(!daze_kvm_resident_vector_projections_refresh(&machine, NULL, &memory));
  assert(!daze_kvm_resident_vector_projections_refresh(&machine, &resident, NULL));
  for (int boundary = 0; boundary < 3; ++boundary) {
    resident = (DazeKvmResidentGdtState){.ldt_base = boundary == 1 ? UINT32_MAX : 0x2100,
                                         .ldt_limit = boundary == 0 ? 0 : 0xffff};
    resident.raw_vector_projections[0] = (DazeRawVectorProjection){.in_use = 1, .selector = 0x14};
    DazeKvmResidentGdtState before = resident;
    assert(!daze_kvm_resident_vector_projections_refresh(&machine, &resident, &memory));
    assert(memcmp(&before, &resident, sizeof(resident)) == 0);
  }
  daze_kvm_child_context_dispose(NULL);
  daze_kvm_resident_gdt_state_dispose(NULL);
#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
  DazeKvmResidentTransitionState transition;
  DazeKvmResidentRawTrace trace;
  assert(!resident_transition_capture(&machine, NULL));
  assert(!resident_transition_capture(NULL, &transition) && !transition.valid);
  for (int boundary = 0; boundary < 3; ++boundary) {
    DazeKvmMachine candidate = machine;
    if (boundary == 0) candidate.guest = NULL;
    if (boundary == 1) candidate.guest_size = 0x2015;
    if (boundary == 2) candidate.guest_size = 0x2085;
    assert(!resident_transition_capture(&candidate, &transition) && !transition.valid);
  }
  resident_gdt_capture(&machine, NULL);
  resident_raw_trace_capture(&machine, NULL);
  for (int absent = 0; absent < 5; ++absent) {
    DazeKvmMachine candidate = machine;
    if (absent == 1) candidate.guest = NULL;
    if (absent >= 3) candidate.vcpu = 0;
    assert(!resident_ldt_capture(absent == 0 ? NULL : &candidate, absent == 3 ? NULL : &dpmi,
                                 absent == 4 ? NULL : &resident));
    resident_gdt_capture(absent == 0 ? NULL : &candidate, &resident);
    resident_raw_trace_capture(absent == 0 ? NULL : &candidate, &trace);
    assert(!resident.valid && !trace.valid);
  }
  resident_raw_trace_print(NULL, &trace);
  resident_raw_trace_print("invalid", NULL);
  resident_raw_trace_print("invalid", &trace);
#endif
}

static int tables(void) {
#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
  DazeKvmMachine machine;
  if (daze_kvm_machine_init(&machine, 0x50000) != DAZE_KVM_MACHINE_OK) return 77;
  memset(machine.guest, 0x5a, machine.guest_size);
  struct kvm_sregs original;
  assert(ioctl(machine.vcpu, KVM_GET_SREGS, &original) == 0);
  DazeDpmiProcessState dpmi = {.next_ldt_index = 0x31};
  dpmi.ldt_used[4] = 1;
  for (int boundary = 0; boundary < 4; ++boundary) {
    struct kvm_sregs sregs = original;
    sregs.gdt.base = boundary == 0 ? (uint64_t)UINT32_MAX + 1 : 0x40000;
    sregs.gdt.limit = boundary == 1 ? 0x46 : 0xff;
    sregs.ldt.base = boundary == 0 ? (uint64_t)UINT32_MAX + 1 : 0x41000;
    sregs.ldt.limit = 0xff;
    assert(ioctl(machine.vcpu, KVM_SET_SREGS, &sregs) == 0);
    DazeKvmMachine candidate = machine;
    if (boundary == 2) candidate.guest_size = 0x40040;
    DazeKvmResidentGdtState state = {0};
    resident_gdt_capture(&candidate, &state);
    assert(state.valid == (boundary == 3));
    assert(resident_ldt_capture(&candidate, &dpmi, &state) == (boundary == 1 || boundary == 3));
    if (state.ldt_valid) {
      assert(state.next_ldt_index == 0x31 && state.ldt_used[4] == 1);
      assert(state.ldt_bytes[0] == 0x5a && state.ldt_bytes[0xff] == 0x5a);
    }
    daze_kvm_resident_gdt_state_dispose(&state);
    assert(state.ldt_bytes == NULL && !state.ldt_valid);
    DazeKvmResidentRawTrace trace;
    candidate.guest_size = boundary == 3 ? 0 : candidate.guest_size;
    resident_raw_trace_capture(&candidate, &trace);
    assert(trace.valid);
    if (boundary == 0 || boundary == 3) assert(trace.gdt_08[0] == 0);
    if (boundary == 3) assert(trace.transition_code[0] == 0 && trace.ivt_fc[0] == 0);
  }
  DazeKvmMachine invalid = machine;
  invalid.vcpu = dup(STDERR_FILENO);
  assert(invalid.vcpu >= 0);
  DazeKvmResidentGdtState state = {0};
  DazeKvmResidentRawTrace trace;
  resident_gdt_capture(&invalid, &state);
  assert(!state.valid && !resident_ldt_capture(&invalid, &dpmi, &state));
  resident_raw_trace_capture(&invalid, &trace);
  assert(!trace.valid);
  close(invalid.vcpu);
  daze_kvm_machine_destroy(&machine);
  return 0;
#else
  return 77;
#endif
}

int main(int argc, char **argv) {
  guards();
  return argc == 2 && strcmp(argv[1], "--kvm") == 0 ? tables() : 0;
}
