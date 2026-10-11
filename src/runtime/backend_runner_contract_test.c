/* The launcher callback is a boundary, not a Unicorn CPU implementation. */
#define daze_unicorn_run_prepared contract_unicorn_run
#include "backend_runner.c"

#include <assert.h>
#include <string.h>
#include <unistd.h>

#ifdef NDEBUG
#undef assert
#define assert(expression) ((expression) ? (void)0 : abort())
#endif

#if DAZE_HAS_UNICORN
static int unicorn_calls;
static DazePreparedLaunch *expected_launch;
static void *expected_context;
static const char *expected_path;

DazeCommandResult contract_unicorn_run(DazePreparedLaunch *launch,
                                       struct DazeUnicornContext *context, const char *path) {
  assert(launch == expected_launch && (void *)context == expected_context && path == expected_path);
  ++unicorn_calls;
  return (DazeCommandResult){
    .disposition = DAZE_COMMAND_COMPLETED, .guest_execution_started = 1, .dos_exit_code = 0xa7};
}
#endif

static void selection_contract(void) {
  DazePreparedLaunch launch = {0};
  DazeKvmMachine machine = {.kvm = 100, .vm = 101, .vcpu = 102};
  DazeBackendCompileAvailability compiled = {.kvm_compiled = 1,
                                             .unicorn_compiled = DAZE_HAS_UNICORN};
  assert(select_prepared_backend(&launch, DAZE_BACKEND_REQUEST_AUTO, compiled, NULL).outcome ==
         DAZE_KVM_CANDIDATE_INVALID);
  for (int kind = 0; kind < 4; ++kind) {
    DazeKvmRunnerRequestCommon request = {.guest_size = 4096};
    launch.kvm_request = kind == 3 ? NULL : &request;
    DazeBackendCompileAvailability availability = compiled;
    if (kind == 1) availability.kvm_compiled = 0;
    DazeKvmCandidateObservation candidate = select_prepared_backend(
      kind == 2 ? NULL : &launch,
      kind == 0 ? DAZE_BACKEND_REQUEST_UNICORN : DAZE_BACKEND_REQUEST_AUTO, availability, &machine);
    assert(candidate.outcome == DAZE_KVM_CANDIDATE_UNAVAILABLE && machine.kvm == -1 &&
           machine.vm == -1 && machine.vcpu == -1);
  }
  assert(backend_compile_availability().unicorn_compiled == DAZE_HAS_UNICORN);
  DazeKvmCandidateObservation candidate = {0};
  DazeKvmSelectionDiagnostic diagnostic = {0};
  DazeBackendSelection selection = {.action = DAZE_BACKEND_SELECTION_FAIL,
                                    .diagnostic = DAZE_BACKEND_DIAGNOSTIC_KVM_REJECTED};
  for (int kind = 0; kind < 3; ++kind) {
    assert(run_selected_prepared(&launch, NULL, "tool.exe", DAZE_BACKEND_REQUEST_KVM,
                                 kind == 0 ? NULL : &selection, kind == 1 ? NULL : &candidate, NULL,
                                 kind == 2 ? NULL : &diagnostic, NULL)
             .disposition == DAZE_COMMAND_POSTSTART_FAILED);
  }
  assert(run_selected_prepared(&launch, NULL, "tool.exe", DAZE_BACKEND_REQUEST_KVM, &selection,
                               &candidate, NULL, &diagnostic, NULL)
           .disposition == DAZE_COMMAND_PRESTART_REJECTED);
  assert(diagnostic.kind == DAZE_KVM_SELECTION_DIAGNOSTIC_KVM_REQUESTED_FAILURE);
  launch.kvm_request = NULL;
  selection.action = DAZE_BACKEND_SELECTION_USE_KVM_STRICT;
  assert(run_selected_prepared(&launch, NULL, "tool.exe", DAZE_BACKEND_REQUEST_KVM, &selection,
                               &candidate, NULL, &diagnostic, NULL)
           .disposition == DAZE_COMMAND_PRESTART_REJECTED);
#if DAZE_HAS_UNICORN
  expected_launch = &launch;
  expected_context = &machine;
  expected_path = "tool.exe";
  assert(run_unicorn_prepared_callback(NULL).disposition == DAZE_COMMAND_POSTSTART_FAILED);
  selection.action = DAZE_BACKEND_SELECTION_USE_UNICORN;
  DazeCommandResult result =
    run_selected_prepared(&launch, expected_context, expected_path, DAZE_BACKEND_REQUEST_UNICORN,
                          &selection, &candidate, NULL, &diagnostic, NULL);
  assert(result.disposition == DAZE_COMMAND_COMPLETED && result.dos_exit_code == 0xa7 &&
         unicorn_calls == 1 && diagnostic.kind == DAZE_KVM_SELECTION_DIAGNOSTIC_UNICORN_REQUESTED);
  selection.action = DAZE_BACKEND_SELECTION_USE_KVM;
  result =
    run_selected_prepared(&launch, expected_context, expected_path, DAZE_BACKEND_REQUEST_AUTO,
                          &selection, &candidate, NULL, &diagnostic, NULL);
  assert(result.dos_exit_code == 0xa7 && unicorn_calls == 2 &&
         diagnostic.kind == DAZE_KVM_SELECTION_DIAGNOSTIC_PRESTART_FALLBACK);
#endif
}

static void diagnostic_contract(void) {
  DazeKvmSelectionDiagnostic diagnostic = {0};
  DazeKvmNormalOperationObservation observation = {.present = 1,
                                                   .source = 2,
                                                   .cs = 0x28,
                                                   .rip = 0x12345678,
                                                   .ax = 0x4c07,
                                                   .post_return_request_present = 1,
                                                   .post_return_function = 0x301,
                                                   .post_return_selector = 0x84,
                                                   .post_return_operand = 0xabcdef01,
                                                   .runner_request_present = 1,
                                                   .runner_vector = 0x21};
  DazeRunMetrics metrics = {0};
  FILE *capture = tmpfile();
  assert(capture != NULL);
  int saved = dup(STDERR_FILENO);
  assert(saved >= 0 && dup2(fileno(capture), STDERR_FILENO) >= 0);
  report_kvm_terminal_observation(1, NULL, &observation);
  report_kvm_terminal_observation(1, &diagnostic, NULL);
  report_kvm_terminal_observation(0, &diagnostic, &observation);
  report_kvm_terminal_observation(1, &diagnostic, &observation);
  report_selection_fallback(NULL, 1);
  report_kvm_selection_diagnostic(1, NULL);
  report_kvm_selection_diagnostic(0, &diagnostic);
  report_kvm_selection_metrics(1, NULL, &diagnostic);
  report_kvm_selection_metrics(1, &metrics, NULL);
  report_kvm_selection_metrics(0, &metrics, &diagnostic);
  assert(fflush(stderr) == 0 && ftell(capture) == 0);
  diagnostic.kind = DAZE_KVM_SELECTION_DIAGNOSTIC_POSTSTART_FAILURE;
  report_kvm_terminal_observation(1, &diagnostic, &observation);
  for (int kind = DAZE_BACKEND_DIAGNOSTIC_NONE;
       kind <= DAZE_BACKEND_DIAGNOSTIC_NO_BACKEND_AVAILABLE; ++kind) {
    DazeBackendSelection selection = {.diagnostic = (DazeBackendDiagnostic)kind};
    report_selection_failure("tool.exe", &selection);
  }
  for (int kind = DAZE_KVM_SELECTION_DIAGNOSTIC_UNAVAILABLE;
       kind <= DAZE_KVM_SELECTION_DIAGNOSTIC_NO_BACKEND_AVAILABLE; ++kind) {
    diagnostic.kind = (DazeKvmSelectionDiagnosticKind)kind;
    diagnostic.kvm_prestart_rejected = 0;
    report_selection_fallback(&diagnostic, 0);
    report_selection_fallback(&diagnostic, 1);
  }
  diagnostic.kind = DAZE_KVM_SELECTION_DIAGNOSTIC_NO_BACKEND_AVAILABLE;
  diagnostic.kvm_prestart_rejected = 1;
  report_selection_fallback(&diagnostic, 0);
  diagnostic.kind = DAZE_KVM_SELECTION_DIAGNOSTIC_POSTSTART_FAILURE;
  report_kvm_selection_diagnostic(1, &diagnostic);
  report_kvm_selection_metrics(1, &metrics, &diagnostic);
  assert(fflush(stderr) == 0 && dup2(saved, STDERR_FILENO) >= 0);
  close(saved);
  rewind(capture);
  char text[8192];
  size_t size = fread(text, 1, sizeof(text) - 1, capture);
  text[size] = 0;
  assert(strstr(text, "cs:ip=0028:12345678 ax=4c07") != NULL &&
         strstr(text, "mediator=1:301/0084/abcdef01") != NULL &&
         strstr(text, "runner=1/21") != NULL &&
         strstr(text, "Unicorn fallback is not compiled in") != NULL &&
         strstr(text, "KVM unavailable; falling back to Unicorn") != NULL &&
         strstr(text, "metrics: backend=kvm selection=kvm-poststart-failure") != NULL);
  assert(fclose(capture) == 0);
}

int main(void) {
  selection_contract();
  diagnostic_contract();
  return 0;
}
