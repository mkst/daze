/* Substitute only the owner boundary: placement, configuration, normalization,
 * and diagnostic copying are the production implementation. */
#define daze_kvm_command_owner_begin_observe contract_owner_begin
#define daze_kvm_command_owner_continue contract_owner_continue
#define daze_kvm_command_owner_start_exec contract_owner_exec
#define daze_kvm_command_owner_handoff_destroy contract_owner_destroy
#include "backend/kvm/normal_operation.c"

#include <assert.h>
#include <string.h>
#include <unistd.h>

#ifdef NDEBUG
#undef assert
#define assert(expression) ((expression) ? (void)0 : abort())
#endif

static int begin_status, owner_status, begins, continuations, execs, destroys;
static DazeKvmRunnerGenericPreflightResult preflight_result;
static DazeKvmCommandOwnerResult owner_result;
static uint16_t handoff_ds;

int contract_owner_begin(const DazeKvmRunnerGenericPreflightRequest *request,
                         DazeKvmMachine *machine, DazeKvmCommandOwnerHandoff *handoff,
                         DazeKvmRunnerGenericPreflightResult *observation) {
  assert(request->process.psp_segment == k_psp_segment);
  assert(machine == NULL);
  ++begins;
  *observation = preflight_result;
  handoff->preflight.dpmi_handoff.entry_snapshot.ds = handoff_ds;
  handoff->preflight.dpmi_handoff.entry_snapshot.ss = 0x1010;
  handoff->preflight.dpmi_handoff.caller_return_cs = k_load_segment;
  handoff->preflight.dpmi_handoff.caller_return_ip = 0x1234;
  return begin_status;
}

int contract_owner_continue(DazeKvmCommandOwnerHandoff *handoff,
                            const DazeKvmCommandOwnerInput *input,
                            DazeKvmCommandOwnerResult *result) {
  assert(handoff->preflight.dpmi_handoff.caller_return_ip == 0x1234);
  const DazeDpmiProcessState empty = {0};
  assert(input->state != NULL && memcmp(input->state, &empty, sizeof(empty)) == 0);
  assert(input->transition_layout.resident_image_end == 0x10020);
  assert(input->transition_layout.protected_gate != NULL);
  ++continuations;
  *result = owner_result;
  return owner_status;
}

int contract_owner_exec(DazeKvmCommandOwnerHandoff *handoff,
                        const DazeKvmRunnerGenericPreflightRequest *request,
                        DazeDpmiProcessState *state, DazeKvmCommandOwnerResult *result) {
  assert(handoff != NULL && state != NULL && request->process.load_segment == k_load_segment);
  const DazeDpmiProcessState empty = {0};
  assert(memcmp(state, &empty, sizeof(empty)) == 0);
  ++execs;
  *result = owner_result;
  return owner_status;
}

void contract_owner_destroy(DazeKvmCommandOwnerHandoff *handoff) {
  assert(handoff != NULL);
  ++destroys;
}

static DazeKvmRunnerRequestCommon request(void) {
  static uint8_t bytes[64] = {'M', 'Z'};
  static DazeImage image = {bytes, sizeof(bytes)};
  static DazeMzHeader header = {.header_paragraphs = 2,
                                .module_size = sizeof(bytes),
                                .image_offset = 32,
                                .image_size = 32,
                                .initial_sp = 0xfffe,
                                .relocation_offset = 0x1c};
  static DazeDosfsMounts mounts;
  static DazeDosfsHandles handles;
  static DazeDosfsFileService files;
  daze_dosfs_mounts_init(&mounts);
  daze_dosfs_handles_init(&handles);
  return (DazeKvmRunnerRequestCommon){.image = &image,
                                      .header = &header,
                                      .command_tail = "",
                                      .guest_path = "C:\\TOOL.EXE",
                                      .mounts = &mounts,
                                      .handles = &handles,
                                      .files = &files,
                                      .psp_segment = k_psp_segment,
                                      .environment_segment = k_environment_segment,
                                      .dpmi_entry_segment = k_dpmi_entry_segment,
                                      .dos_vector_segment = k_dos_int21_vector_segment,
                                      .load_segment = k_load_segment,
                                      .guest_size = k_memory_size};
}

static void observation_contract(void) {
  owner_result = (DazeKvmCommandOwnerResult){
    .disposition = DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED,
    .guest_execution_may_have_started = 1,
    .post_successor_present = 1,
    .transition_stage = 7,
    .transition_status = 8,
    .protected_gate_status = 9,
    .post_return_request_present = 1,
    .post_return_function = 0x301,
    .post_return_selector = 0x84,
    .post_return_operand = 0x12345678,
    .post_return_gate_status = 10,
    .terminal_runner_request_present = 1,
    .terminal_runner_request =
      {.vector = 0x21, .ax = 0x1234, .bx = 2, .cx = 3, .dx = 4, .ds = 5, .es = 6, .si = 7, .di = 8},
    .post_successor = {.cs = 0x28,
                       .rip = 0x12345678,
                       .cs_base = 0x10000,
                       .ss_base = 0x20000,
                       .es_base = 0x30000,
                       .gdt_base = 0x40000,
                       .idt_base = 0x50000,
                       .ax = 11,
                       .bx = 12,
                       .cx = 13,
                       .dx = 14,
                       .ds = 15,
                       .es = 16,
                       .ss = 17,
                       .sp = 18,
                       .observation = {.kind = DAZE_KVM_DPMI_ENTRY_EXIT_PIO,
                                       .raw_exit_reason = 2,
                                       .pio_port = 0xf4,
                                       .pio_direction = 1,
                                       .pio_size = 1,
                                       .pio_value_present = 1,
                                       .pio_value = 0x31}}};
  DazeKvmNormalOperationObservation out = {0};
  observe_owner(NULL, &out);
  observe_owner(&owner_result, NULL);
  assert(!out.present);
  observe_owner(&owner_result, &out);
  assert(out.present && out.source == 2 && out.owner_disposition == (int)owner_result.disposition);
  assert(out.cs == 0x28 && out.rip == 0x12345678 && out.cs_base == 0x10000 &&
         out.ss_base == 0x20000 && out.es_base == 0x30000 && out.gdt_base == 0x40000 &&
         out.idt_base == 0x50000 && out.ax == 11 && out.bx == 12 && out.cx == 13 && out.dx == 14 &&
         out.ds == 15 && out.es == 16 && out.ss == 17 && out.sp == 18);
  assert(out.raw_exit_reason == 2 && out.pio_port == 0xf4 && out.pio_direction == 1 &&
         out.pio_size == 1 && out.pio_value_present && out.pio_value == 0x31);
  assert(out.transition_stage == 7 && out.transition_status == 8 &&
         out.protected_gate_status == 9 && out.post_return_gate_status == 10 &&
         out.post_return_request_present && out.post_return_function == 0x301 &&
         out.post_return_selector == 0x84 && out.post_return_operand == 0x12345678);
  assert(out.runner_request_present && out.runner_vector == 0x21 && out.runner_ax == 0x1234 &&
         out.runner_bx == 2 && out.runner_cx == 3 && out.runner_dx == 4 && out.runner_ds == 5 &&
         out.runner_es == 6 && out.runner_si == 7 && out.runner_di == 8);
  DazeKvmNormalOperationObservation before = out;
  owner_result.post_successor_present = 0;
  observe_owner(&owner_result, &out);
  assert(memcmp(&out, &before, sizeof(out)) == 0);
  owner_result.post_successor_present = 1;
}

static void operation_contract(void) {
  DazeKvmRunnerRequestCommon valid = request();
  assert(daze_kvm_normal_operation_request_valid(&valid));
  for (int field = 0; field < 7; ++field) {
    DazeKvmRunnerRequestCommon bad = valid;
    switch (field) {
    case 0:
      --bad.psp_segment;
      break;
    case 1:
      --bad.environment_segment;
      break;
    case 2:
      --bad.dpmi_entry_segment;
      break;
    case 3:
      --bad.dos_vector_segment;
      break;
    case 4:
      --bad.load_segment;
      break;
    case 5:
      --bad.guest_size;
      break;
    default:
      bad.image = NULL;
      break;
    }
    DazeKvmNormalOperationObservation out = {.present = 1};
    assert(daze_kvm_normal_operation_run_observe(&bad, NULL, &out).disposition ==
           DAZE_COMMAND_PRESTART_REJECTED);
    assert(!out.present && begins == 0);
  }
  for (int status = DAZE_KVM_COMMAND_OWNER_HANDOFF_PRESTART_REJECTED;
       status <= DAZE_KVM_COMMAND_OWNER_HANDOFF_TERMINATED; ++status) {
    begin_status = status;
    preflight_result = (DazeKvmRunnerGenericPreflightResult){
      .guest_execution_may_have_started =
        status != DAZE_KVM_COMMAND_OWNER_HANDOFF_PRESTART_REJECTED,
      .request_vector = 0x21,
      .request_ax = 0x4c9b,
      .request_bx = 0x1111,
      .request_cx = 0x2222,
      .request_dx = 0x3333,
      .request_ds = 0x4444,
      .terminal_observation_status = 5,
      .disposition = 6,
      .terminal_observation = {.present = 1,
                               .exit_reason = 2,
                               .cs = 0x1000,
                               .rip = 0x123456789ULL,
                               .rax = 0xaaaa1234,
                               .rbx = 0xbbbb2345,
                               .rcx = 0xcccc3456,
                               .rdx = 0xdddd4567,
                               .ss = 0x1010,
                               .rsp = 0xeeee5678}};
    DazeKvmNormalOperationObservation out;
    DazeCommandResult result = daze_kvm_normal_operation_run_observe(&valid, NULL, &out);
    assert(result.disposition == (status == DAZE_KVM_COMMAND_OWNER_HANDOFF_TERMINATED
                                    ? DAZE_COMMAND_COMPLETED
                                  : status == DAZE_KVM_COMMAND_OWNER_HANDOFF_PRESTART_REJECTED
                                    ? DAZE_COMMAND_PRESTART_REJECTED
                                    : DAZE_COMMAND_POSTSTART_FAILED));
    if (status == DAZE_KVM_COMMAND_OWNER_HANDOFF_TERMINATED) assert(result.dos_exit_code == 0x9b);
    assert(out.present && out.source == 1 && out.capture_status == 5 && out.exit_kind == 6 &&
           out.cs == 0x1000 && out.rip == 0x23456789 && out.ax == 0x1234 && out.bx == 0x2345 &&
           out.cx == 0x3456 && out.dx == 0x4567 && out.ss == 0x1010 && out.sp == 0x5678 &&
           out.request_vector == 0x21 && out.request_ax == 0x4c9b && out.request_bx == 0x1111 &&
           out.request_cx == 0x2222 && out.request_dx == 0x3333 && out.request_ds == 0x4444);
    (void)daze_kvm_normal_operation_run_observe(&valid, NULL, NULL);
  }
  owner_status = DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED;
  begin_status = DAZE_KVM_COMMAND_OWNER_HANDOFF_EXEC;
  assert(daze_kvm_normal_operation_run_observe(&valid, NULL, NULL).disposition ==
         DAZE_COMMAND_POSTSTART_FAILED);
  assert(execs == 1 && destroys == 1);
  begin_status = DAZE_KVM_COMMAND_OWNER_HANDOFF_OK;
  handoff_ds = 0;
  assert(daze_kvm_normal_operation_run_observe(&valid, NULL, NULL).disposition ==
         DAZE_COMMAND_POSTSTART_FAILED);
  assert(continuations == 0 && destroys == 2);
  handoff_ds = 0x1010;
  assert(setenv("DAZE_KVM_POST_SUCCESSOR_TRACE", "1", 1) == 0);
  assert(daze_kvm_normal_operation_run_observe(&valid, NULL, NULL).disposition ==
         DAZE_COMMAND_POSTSTART_FAILED);
  assert(unsetenv("DAZE_KVM_POST_SUCCESSOR_TRACE") == 0);
  assert(continuations == 1 && destroys == 3);
  owner_status = DAZE_KVM_COMMAND_OWNER_TERMINATED;
  owner_result.guest_exit_status_present = 1;
  owner_result.guest_exit_status = 0xd3;
  DazeKvmNormalOperationObservation out;
  DazeCommandResult result = daze_kvm_normal_operation_run_observe(&valid, NULL, &out);
  assert(result.disposition == DAZE_COMMAND_COMPLETED && result.dos_exit_code == 0xd3 &&
         out.present);
  assert(continuations == 2 && destroys == 4);
}

int main(void) {
  observation_contract();
  FILE *capture = tmpfile();
  assert(capture != NULL);
  int saved = dup(STDERR_FILENO);
  assert(saved >= 0 && dup2(fileno(capture), STDERR_FILENO) >= 0);
  operation_contract();
  owner_result.protected_gate_present = 1;
  owner_result.protected_gate.terminal.instruction_size = 2;
  owner_result.protected_gate.terminal.instruction[0] = 0xcd;
  owner_result.protected_gate.terminal.instruction[1] = 0x31;
  owner_result.terminal_vector21_idt_entry_present = 1;
  owner_result.terminal_fault_stack_present = 1;
  owner_result.protected_gate.exchange_count = 1;
  owner_result.protected_gate.exchanges[0].function = 0x501;
  trace_owner_terminal(&owner_result);
  owner_result.post_return_request_present = 0;
  trace_owner_terminal(&owner_result);
  assert(fflush(stderr) == 0 && dup2(saved, STDERR_FILENO) >= 0);
  close(saved);
  rewind(capture);
  char text[8192];
  size_t size = fread(text, 1, sizeof(text) - 1, capture);
  text[size] = 0;
  assert(strstr(text, "invalid input") != NULL && strstr(text, "bytes cd 31") != NULL &&
         strstr(text, "vector21-idt") != NULL && strstr(text, "fault-stack") != NULL &&
         strstr(text, "exchange=1 fn=0501") != NULL && strstr(text, "post-return fn=0301") != NULL);
  assert(fclose(capture) == 0);
  return 0;
}
