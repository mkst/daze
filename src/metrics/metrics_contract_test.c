#include "metrics.h"

#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static char output[32768];

static void capture(int is_run, const DazeMetrics *metrics, const DazeRunMetrics *run,
                    const struct timespec *started) {
  FILE *file = tmpfile();
  assert(file && fflush(stderr) == 0);
  int saved = dup(STDERR_FILENO);
  assert(saved >= 0 && dup2(fileno(file), STDERR_FILENO) >= 0);
  if (is_run)
    daze_metrics_report_run(run);
  else
    daze_metrics_report(metrics, started);
  assert(fflush(stderr) == 0 && dup2(saved, STDERR_FILENO) >= 0 && close(saved) == 0);
  rewind(file);
  memset(output, 0, sizeof(output));
  size_t size = fread(output, 1, sizeof(output) - 1, file);
  assert(size < sizeof(output) - 1 && !ferror(file) && fclose(file) == 0);
}

static void has(const char *text) {
  if (!strstr(output, text)) {
    fprintf(stderr, "missing metrics field: %s\n%s", text, output);
    assert(0);
  }
}

static void lacks(const char *text) {
  assert(!strstr(output, text));
}

static void record(DazeMetrics *metrics) {
  daze_metrics_record_interrupt(metrics, 0x21);
  daze_metrics_record_dpmi_function(metrics, 0x0501);
  daze_metrics_record_emulation_time(metrics, 2000000000);
  daze_metrics_record_interrupt_handler(metrics, 0x21, 1000000000);
  daze_metrics_record_code_hook_sample(metrics, 200);
  daze_metrics_record_translation_cache_flush(metrics);
  daze_metrics_record_translation_cache_targeted_invalidation(metrics);
  daze_metrics_record_stop(metrics);
  daze_metrics_record_resume(metrics, DAZE_RESUME_DIRECT, 1000000);
}

static void collection(void) {
  DazeMetrics metrics = {.interrupts = 7};
  DazeMetrics before = metrics;
  record(NULL);
  record(&metrics);
  assert(memcmp(&metrics, &before, sizeof(metrics)) == 0);
  metrics = (DazeMetrics){.enabled = 1};
  record(&metrics);
  daze_metrics_record_interrupt(&metrics, 0x21);
  daze_metrics_record_code_hook_sample(&metrics, 200);
  assert(metrics.interrupts == 2 && metrics.interrupt_counts[0x21] == 2 &&
         metrics.interrupt_counts[0x31] == 0 && metrics.emulation_nanoseconds == 2000000000 &&
         metrics.interrupt_handler_nanoseconds == 1000000000 &&
         metrics.interrupt_handler_counts[0x21] == 1 &&
         metrics.interrupt_handler_nanoseconds_by_interrupt[0x21] == 1000000000 &&
         metrics.code_hook_samples == 2 && metrics.code_hook_sample_nanoseconds == 400 &&
         metrics.translation_cache_flushes == 1 &&
         metrics.translation_cache_targeted_invalidations == 1 && metrics.stop_events == 1);
  for (int kind = 1; kind < DAZE_RESUME_KIND_COUNT; ++kind)
    daze_metrics_record_resume(&metrics, (DazeResumeKind)kind, (uint64_t)kind * 1000000);
  assert(metrics.resume_boundary_nanoseconds == 7000000);
  for (int kind = 0; kind < DAZE_RESUME_KIND_COUNT; ++kind)
    assert(metrics.resume_counts[kind] == 1);
  before = metrics;
  daze_metrics_record_resume(&metrics, DAZE_RESUME_KIND_COUNT, 99);
  daze_metrics_record_resume(&metrics, (DazeResumeKind)-1, 99);
  assert(memcmp(&metrics, &before, sizeof(metrics)) == 0);
  assert(metrics.dpmi_function_count == 1 && metrics.dpmi_function_counts[0].function == 0x501);
  for (uint16_t i = 1; i < 64; ++i)
    daze_metrics_record_dpmi_function(&metrics, i);
  assert(metrics.dpmi_function_count == 64);
  before = metrics;
  daze_metrics_record_dpmi_function(&metrics, 0xffff);
  assert(memcmp(&metrics, &before, sizeof(metrics)) == 0);
  daze_metrics_record_dpmi_function(&metrics, 0x501);
  assert(metrics.dpmi_function_count == 64 && metrics.dpmi_function_counts[0].calls == 2);
  for (size_t i = 1; i < 64; ++i)
    assert(metrics.dpmi_function_counts[i].function == i &&
           metrics.dpmi_function_counts[i].calls == 1);
  struct timespec started;
  assert(clock_gettime(CLOCK_MONOTONIC, &started) == 0);
  started.tv_sec += 60;
  metrics.guest_instruction_count_available = 1;
  metrics.guest_instructions = 42;
  metrics.code_hook_calls = 100;
  metrics.emulation_runs = 3;
  metrics.dos_calls = 2;
  metrics.dpmi_calls = 1;
  metrics.host_read_calls = 1;
  metrics.host_read_bytes = 4;
  metrics.host_write_calls = 2;
  metrics.host_write_bytes = 7;
  metrics.dos_function_counts[0x40] = 2;
  capture(0, &metrics, NULL, &started);
  has("guest-instructions=42 emulation-runs=3 interrupts=2 dos-calls=2 dpmi-calls=1");
  has("host-reads=1/4B host-writes=2/7B");
  has("timing unicorn=2.000s dispatch=1.000s other=0.000s");
  has("full-flushes=1 targeted-invalidations=1");
  has("calls=100 samples=2 estimate=0.020ms average=200.0ns");
  has("stop-resume stops=1 resumes=4 host-boundary=7.000ms");
  has("direct=1/1.000ms dispatch-address=1/1.000ms dispatch-next=1/2.000ms "
      "dispatch-restart=1/3.000ms");
  has("interrupts 21h=2\n");
  has("dispatch-time 21h=1/1000.000ms\n");
  has("dos-functions 40h=2\n");
  has("dpmi-functions 0501h=2 0001h=1");
  lacks("ffffh=");
}

static void reporting(void) {
  DazeMetrics metrics = {0};
  struct timespec started;
  assert(clock_gettime(CLOCK_MONOTONIC, &started) == 0);
  capture(0, &metrics, NULL, &started);
  assert(output[0] == 0);
  metrics.enabled = 1;
  capture(0, &metrics, NULL, &started);
  has("guest-instructions=not-counted");
  has("samples=0 estimate=0.000ms average=0.0ns");
  has("metrics: interrupts\nmetrics: dispatch-time\nmetrics: dos-functions\nmetrics: "
      "dpmi-functions\n");
  DazeRunMetrics run = {0};
  capture(1, NULL, NULL, NULL);
  assert(output[0] == 0);
  capture(1, NULL, &run, NULL);
  assert(output[0] == 0);
  run.enabled = 1;
  capture(1, NULL, &run, NULL);
  has("dos-file-reads=0/0B-requested/0B dos-file-writes=0/0B-requested/0B");
  lacks("metrics: kvm-");
  run.read_calls = 2;
  run.read_requested_bytes = 10;
  run.read_bytes = 7;
  run.write_calls = 1;
  run.write_requested_bytes = 6;
  run.write_bytes = 5;
  run.transfer_buffer_resizes = 2;
  run.transfer_buffer_peak = 4096;
  run.kvm_port_run_calls = 1;
  capture(1, NULL, &run, NULL);
  has("dos-file-reads=2/10B-requested/7B dos-file-writes=1/6B-requested/5B "
      "transfer-buffer=resizes:2 peak:4096B");
  lacks("metrics: kvm-");
  run.kvm_boundary_broker_calls = 2;
  run.kvm_dos_boundary_broker_calls = 1;
  run.kvm_dpmi_entry_boundary_broker_calls = 1;
  run.kvm_boundary_broker_nanoseconds = 2000000;
  run.kvm_port_run_nanoseconds = 1000000;
  run.kvm_boundary_vectors[0x21] = 1;
  run.kvm_dos_functions[0x40] = 1;
  run.kvm_dos_function_nanoseconds[0x40] = 1000000;
  capture(1, NULL, &run, NULL);
  has("kvm-port-run=1 time=1.000ms average=1000.0us");
  has("kvm-boundary-broker=2 dos=1 dpmi-entry=1 other=0 service=2.000ms average=1000.0us");
  has("kvm-broker-vectors 21h=1\n");
  has("kvm-broker-dos-functions 40h=1\n");
  has("kvm-broker-dos-service 40h=1/1.000ms/1000.0us\n");
  lacks("kvm-regs-sync");
  lacks("kvm-gate-frame");
  lacks("kvm-dpmi-host");
  DazeRunMetrics rm_only = {
    .enabled = 1, .kvm_boundary_broker_calls = 1, .kvm_rm_procedure_calls = 1};
  capture(1, NULL, &rm_only, NULL);
  has("kvm-dpmi-host state-capture=0/0.000ms/0.0us");
  has("kvm-rm-procedure total=1/0.000ms/0.0us");
  run.kvm_regs_sync_set_calls = 1;
  capture(1, NULL, &run, NULL);
  has("kvm-regs-sync get=0 set=1");
  run.kvm_gate_frame_capture_calls = 1;
  run.kvm_gate_frame_capture_nanoseconds = 1000000;
  run.kvm_dpmi_debug_update_calls = 1;
  run.kvm_dpmi_debug_update_nanoseconds = 1000000;
  capture(1, NULL, &run, NULL);
  has("kvm-gate-frame capture=1/1.000ms/1000.0us reply=0/0.000ms/0.0us");
  has("state-capture=0/0.000ms/0.0us");
  has("debug-update=1/1.000ms/1000.0us mediator=0/0.000ms/0.0us");
  lacks("kvm-rm-procedure total");
  run.kvm_gate_frame_capture_calls = 0;
  run.kvm_gate_frame_capture_nanoseconds = 0;
  run.kvm_gate_frame_reply_calls = 1;
  run.kvm_gate_frame_reply_nanoseconds = 2000000;
  run.kvm_dpmi_debug_update_calls = 0;
  run.kvm_dpmi_debug_update_nanoseconds = 0;
  run.kvm_dpmi_mediator_calls = 2;
  run.kvm_dpmi_mediator_nanoseconds = 4000000;
  capture(1, NULL, &run, NULL);
  has("capture=0/0.000ms/0.0us reply=1/2.000ms/2000.0us");
  has("debug-update=0/0.000ms/0.0us mediator=2/4.000ms/2000.0us");
  run.kvm_regs_sync_get_calls = 3;
  run.kvm_regs_sync_set_calls = 4;
  run.kvm_dpmi_state_capture_calls[DAZE_RUN_METRICS_DPMI_CAPTURE_ENTRY] = 1;
  run.kvm_dpmi_state_capture_nanoseconds[DAZE_RUN_METRICS_DPMI_CAPTURE_ENTRY] = 1000000;
  run.kvm_dpmi_mediator_capture_elisions = 2;
  run.kvm_dpmi_run_calls[DAZE_RUN_METRICS_DPMI_RUN_ENTRY] = 2;
  run.kvm_dpmi_run_nanoseconds[DAZE_RUN_METRICS_DPMI_RUN_ENTRY] = 3000000;
  run.kvm_dpmi_run_exit_calls[DAZE_RUN_METRICS_DPMI_RUN_ENTRY][DAZE_RUN_METRICS_KVM_EXIT_IO] = 2;
  run.kvm_dpmi_run_exit_nanoseconds[DAZE_RUN_METRICS_DPMI_RUN_ENTRY][DAZE_RUN_METRICS_KVM_EXIT_IO] =
    3000000;
  run.kvm_dpmi_io_marker_calls[0xa5] = 1;
  run.kvm_dpmi_io_marker_nanoseconds[0xa5] = 2000000;
  run.kvm_dpmi_function_count = 1;
  run.kvm_dpmi_functions[0] = (DazeRunMetricsDpmiFunction){0x501, 2, 3000000};
  run.kvm_virtual_interrupt_site_count = 1;
  run.kvm_virtual_interrupt_sites[0] = (DazeRunMetricsVirtualInterruptSite){0x900, 0x28, 0x1234, 3};
  capture(1, NULL, &run, NULL);
  has("kvm-regs-sync get=3 set=4");
  has("kvm-dpmi-run entry=2/3.000ms exits io=2/3.000ms");
  lacks("kvm-dpmi-run continue-once");
  has("kvm-dpmi-io-markers a5h=1/2.000ms");
  has("state-capture=1/1.000ms/1000.0us mediator-capture-elisions=2 entry=1/1.000ms");
  has("kvm-dpmi-functions 0501h=2/3.000ms\n");
  has("kvm-virtual-interrupt-sites 0900h@0028:1234=3\n");
  run.kvm_dpmi_function_overflow_calls = 4;
  run.kvm_virtual_interrupt_site_overflow_calls = 5;
  run.kvm_rm_procedure_calls = 1;
  run.kvm_rm_procedure_bridged_calls = 1;
  run.kvm_rm_procedure_nanoseconds = 10000000;
  run.kvm_rm_procedure_setup_nanoseconds = 6000000;
  run.kvm_rm_procedure_setup_parked_capture_nanoseconds = 1000000;
  run.kvm_rm_procedure_resume_nanoseconds = 3000000;
  run.kvm_rm_procedure_resume_capture_nanoseconds = 1000000;
  run.kvm_rm_procedure_reflect_nanoseconds = 4000000;
  run.kvm_rm_procedure_reflect_runner_calls = 1;
  run.kvm_rm_procedure_reflect_runner_nanoseconds = 1000000;
  run.kvm_rm_procedure_costs[DAZE_RUN_METRICS_RM_DATE] =
    (DazeRunMetricsRmProcedureCost){.calls = 2,
                                    .total_nanoseconds = 10000000,
                                    .setup_nanoseconds = 1000000,
                                    .reflect_nanoseconds = 6000000,
                                    .cleanup_nanoseconds = 1000000,
                                    .resume_nanoseconds = 2000000,
                                    .reflect_run_nanoseconds = 4000000,
                                    .resume_run_nanoseconds = 1500000,
                                    .service_nanoseconds = 500000};
  capture(1, NULL, &run, NULL);
  has("kvm-rm-procedure-cost date-2ah calls=2 total=10.000ms average=5000.0us "
      "setup=1.000ms reflect=6.000ms cleanup=1.000ms resume=2.000ms "
      "reflect-KVM_RUN=4.000ms resume-KVM_RUN=1.500ms dos-service=0.500ms");
  lacks("kvm-rm-procedure-cost time-2ch");
  lacks("kvm-guest-virtual-interrupts");
  has("kvm-rm-procedure total=1/10.000ms/10000.0us KVM_RUN=0/0.000ms/0.0us");
  has("kvm-rm-procedure-bridged=1 (reflect includes protected execution to next exit)");
  lacks("kvm-guest-writes=");
  run.kvm_guest_write_calls = 7;
  run.kvm_guest_write_bytes = 99;
  run.kvm_guest_write_drains = 2;
  run.kvm_rm_procedure_native_calls = 3;
  capture(1, NULL, &run, NULL);
  has("kvm-guest-writes=7/99B drains=2\n");
  has("kvm-rm-procedure-native=3 (host detour timings may include multiple guest callbacks)");
  has("transition=0.000ms other=5.000ms");
  lacks("debug-arm=");
  has("kvm-rm-procedure-resume KVM_RUN=0.000ms capture=1.000ms other=2.000ms");
  has("kvm-rm-procedure-reflect KVM_RUN=0.000ms runner-service=1/1.000ms other=3.000ms");
  lacks("kvm-rm-procedure-reflect-vectors");
  has("kvm-dpmi-functions 0501h=2/3.000ms overflow=4\n");
  has("kvm-virtual-interrupt-sites 0900h@0028:1234=3 overflow=5\n");
  run.kvm_rm_procedure_run_calls = 1;
  run.kvm_guest_virtual_interrupt_calls[0] = 3;
  run.kvm_guest_virtual_interrupt_calls[1] = 4;
  run.kvm_rm_procedure_run_nanoseconds = 2000000;
  run.kvm_rm_procedure_setup_nanoseconds = 500000;
  run.kvm_rm_procedure_resume_nanoseconds = 500000;
  run.kvm_rm_procedure_reflect_nanoseconds = 500000;
  run.kvm_rm_procedure_reflect_vector_count = 1;
  run.kvm_rm_procedure_reflect_vectors[0] = (DazeRunMetricsRmReflectVector){0x21, 2, 3000000};
  capture(1, NULL, &run, NULL);
  has("KVM_RUN=1/2.000ms/2000.0us");
  has("kvm-guest-virtual-interrupts 0900h=3 0901h=4");
  run.kvm_guest_virtual_interrupt_calls[0] = 0;
  capture(1, NULL, &run, NULL);
  has("kvm-guest-virtual-interrupts 0900h=0 0901h=4");
  has("transition=0.000ms other=0.000ms");
  has("kvm-rm-procedure-resume KVM_RUN=0.000ms capture=1.000ms other=0.000ms");
  has("kvm-rm-procedure-reflect KVM_RUN=2.000ms runner-service=1/1.000ms other=0.000ms");
  has("kvm-rm-procedure-reflect-vectors 21h=2/3.000ms\n");
  run.kvm_rm_procedure_reflect_vector_overflow_calls = 6;
  capture(1, NULL, &run, NULL);
  has("kvm-rm-procedure-reflect-vectors 21h=2/3.000ms overflow=6\n");
}

int main(void) {
  collection();
  reporting();
  puts("metrics collection/reporting contract: passed");
  return 0;
}
