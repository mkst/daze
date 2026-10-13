#include "metrics.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

void daze_metrics_record_interrupt(DazeMetrics *metrics, uint8_t interrupt) {
  if (metrics == NULL || !metrics->enabled) return;
  metrics->interrupts++;
  metrics->interrupt_counts[interrupt]++;
}

void daze_metrics_record_dpmi_function(DazeMetrics *metrics, uint16_t function) {
  if (metrics == NULL || !metrics->enabled) return;
  for (size_t index = 0; index < metrics->dpmi_function_count; ++index) {
    if (metrics->dpmi_function_counts[index].function == function) {
      metrics->dpmi_function_counts[index].calls++;
      return;
    }
  }
  if (metrics->dpmi_function_count <
      sizeof(metrics->dpmi_function_counts) / sizeof(metrics->dpmi_function_counts[0])) {
    DazeDpmiFunctionMetric *metric = &metrics->dpmi_function_counts[metrics->dpmi_function_count++];
    metric->function = function;
    metric->calls = 1;
  }
}

void daze_metrics_record_emulation_time(DazeMetrics *metrics, uint64_t nanoseconds) {
  if (metrics == NULL || !metrics->enabled) return;
  metrics->emulation_nanoseconds += nanoseconds;
}

void daze_metrics_record_interrupt_handler(DazeMetrics *metrics, uint8_t interrupt,
                                           uint64_t nanoseconds) {
  if (metrics == NULL || !metrics->enabled) return;
  metrics->interrupt_handler_nanoseconds += nanoseconds;
  metrics->interrupt_handler_counts[interrupt]++;
  metrics->interrupt_handler_nanoseconds_by_interrupt[interrupt] += nanoseconds;
}

void daze_metrics_record_code_hook_sample(DazeMetrics *metrics, uint64_t nanoseconds) {
  if (metrics == NULL || !metrics->enabled) return;
  metrics->code_hook_samples++;
  metrics->code_hook_sample_nanoseconds += nanoseconds;
}

void daze_metrics_record_translation_cache_flush(DazeMetrics *metrics) {
  if (metrics == NULL || !metrics->enabled) return;
  metrics->translation_cache_flushes++;
}

void daze_metrics_record_translation_cache_targeted_invalidation(DazeMetrics *metrics) {
  if (metrics == NULL || !metrics->enabled) return;
  metrics->translation_cache_targeted_invalidations++;
}

void daze_metrics_record_stop(DazeMetrics *metrics) {
  if (metrics == NULL || !metrics->enabled) return;
  metrics->stop_events++;
}

void daze_metrics_record_resume(DazeMetrics *metrics, DazeResumeKind kind, uint64_t nanoseconds) {
  if (metrics == NULL || !metrics->enabled) return;
  if (kind >= DAZE_RESUME_KIND_COUNT) return;
  metrics->resume_boundary_nanoseconds += nanoseconds;
  metrics->resume_counts[kind]++;
  metrics->resume_nanoseconds[kind] += nanoseconds;
}

void daze_metrics_report(const DazeMetrics *metrics, const struct timespec *started) {
  if (!metrics->enabled) return;
  struct timespec finished;
  if (clock_gettime(CLOCK_MONOTONIC, &finished) != 0) {
    memset(&finished, 0, sizeof(finished));
  }
  const double elapsed = (double)(finished.tv_sec - started->tv_sec) +
                         (double)(finished.tv_nsec - started->tv_nsec) / 1000000000.0;
  const double unicorn = (double)metrics->emulation_nanoseconds / 1000000000.0;
  const double handlers = (double)metrics->interrupt_handler_nanoseconds / 1000000000.0;
  const double other = elapsed - unicorn - handlers;
  fprintf(stderr, "metrics: elapsed=%.3fs", elapsed);
  if (metrics->guest_instruction_count_available) {
    fprintf(stderr, " guest-instructions=%" PRIu64, metrics->guest_instructions);
  } else {
    fprintf(stderr, " guest-instructions=not-counted");
  }
  fprintf(stderr,
          " emulation-runs=%" PRIu64 " interrupts=%" PRIu64 " dos-calls=%" PRIu64
          " dpmi-calls=%" PRIu64 " host-reads=%" PRIu64 "/%" PRIu64 "B host-writes=%" PRIu64
          "/%" PRIu64 "B\n",
          metrics->emulation_runs, metrics->interrupts, metrics->dos_calls, metrics->dpmi_calls,
          metrics->host_read_calls, metrics->host_read_bytes, metrics->host_write_calls,
          metrics->host_write_bytes);
  fprintf(stderr, "metrics: timing unicorn=%.3fs dispatch=%.3fs other=%.3fs\n", unicorn, handlers,
          other < 0.0 ? 0.0 : other);
  fprintf(stderr,
          "metrics: translation-cache full-flushes=%" PRIu64 " targeted-invalidations=%" PRIu64
          "\n",
          metrics->translation_cache_flushes, metrics->translation_cache_targeted_invalidations);
  fprintf(stderr,
          "metrics: code-hook calls=%" PRIu64 " samples=%" PRIu64
          " estimate=%.3fms average=%.1fns\n",
          metrics->code_hook_calls, metrics->code_hook_samples,
          metrics->code_hook_samples == 0
            ? 0.0
            : (double)metrics->code_hook_sample_nanoseconds / metrics->code_hook_samples *
                metrics->code_hook_calls / 1000000.0,
          metrics->code_hook_samples == 0
            ? 0.0
            : (double)metrics->code_hook_sample_nanoseconds / metrics->code_hook_samples);
  fprintf(stderr,
          "metrics: stop-resume stops=%" PRIu64 " resumes=%" PRIu64 " host-boundary=%.3fms\n",
          metrics->stop_events,
          metrics->resume_counts[DAZE_RESUME_DIRECT] +
            metrics->resume_counts[DAZE_RESUME_AFTER_DISPATCH_ADDRESS] +
            metrics->resume_counts[DAZE_RESUME_AFTER_DISPATCH_NEXT] +
            metrics->resume_counts[DAZE_RESUME_AFTER_DISPATCH_RESTART],
          (double)metrics->resume_boundary_nanoseconds / 1000000.0);
  fprintf(stderr,
          "metrics: resume-path direct=%" PRIu64 "/%.3fms"
          " dispatch-address=%" PRIu64 "/%.3fms"
          " dispatch-next=%" PRIu64 "/%.3fms"
          " dispatch-restart=%" PRIu64 "/%.3fms\n",
          metrics->resume_counts[DAZE_RESUME_DIRECT],
          (double)metrics->resume_nanoseconds[DAZE_RESUME_DIRECT] / 1000000.0,
          metrics->resume_counts[DAZE_RESUME_AFTER_DISPATCH_ADDRESS],
          (double)metrics->resume_nanoseconds[DAZE_RESUME_AFTER_DISPATCH_ADDRESS] / 1000000.0,
          metrics->resume_counts[DAZE_RESUME_AFTER_DISPATCH_NEXT],
          (double)metrics->resume_nanoseconds[DAZE_RESUME_AFTER_DISPATCH_NEXT] / 1000000.0,
          metrics->resume_counts[DAZE_RESUME_AFTER_DISPATCH_RESTART],
          (double)metrics->resume_nanoseconds[DAZE_RESUME_AFTER_DISPATCH_RESTART] / 1000000.0);
  fprintf(stderr, "metrics: interrupts");
  for (size_t interrupt = 0; interrupt < 256; ++interrupt) {
    if (metrics->interrupt_counts[interrupt] != 0) {
      fprintf(stderr, " %02zxh=%" PRIu64, interrupt, metrics->interrupt_counts[interrupt]);
    }
  }
  fprintf(stderr, "\nmetrics: dispatch-time");
  for (size_t interrupt = 0; interrupt < 256; ++interrupt) {
    if (metrics->interrupt_handler_counts[interrupt] != 0) {
      fprintf(stderr, " %02zxh=%" PRIu64 "/%.3fms", interrupt,
              metrics->interrupt_handler_counts[interrupt],
              (double)metrics->interrupt_handler_nanoseconds_by_interrupt[interrupt] / 1000000.0);
    }
  }
  fprintf(stderr, "\nmetrics: dos-functions");
  for (size_t function = 0; function < 256; ++function) {
    if (metrics->dos_function_counts[function] != 0) {
      fprintf(stderr, " %02zxh=%" PRIu64, function, metrics->dos_function_counts[function]);
    }
  }
  fprintf(stderr, "\nmetrics: dpmi-functions");
  for (size_t index = 0; index < metrics->dpmi_function_count; ++index) {
    fprintf(stderr, " %04xh=%" PRIu64, metrics->dpmi_function_counts[index].function,
            metrics->dpmi_function_counts[index].calls);
  }
  fprintf(stderr, "\n");
}

void daze_metrics_report_run(const DazeRunMetrics *metrics) {
  if (metrics == NULL || !metrics->enabled) return;
  fprintf(stderr,
          "metrics: dos-file-reads=%" PRIu64 "/%" PRIu64 "B-requested/%" PRIu64
          "B dos-file-writes=%" PRIu64 "/%" PRIu64 "B-requested/%" PRIu64
          "B transfer-buffer=resizes:%" PRIu64 " peak:%zuB\n",
          metrics->read_calls, metrics->read_requested_bytes, metrics->read_bytes,
          metrics->write_calls, metrics->write_requested_bytes, metrics->write_bytes,
          metrics->transfer_buffer_resizes, metrics->transfer_buffer_peak);
  if (metrics->kvm_boundary_broker_calls != 0) {
    if (metrics->kvm_port_run_calls != 0) {
      fprintf(stderr,
              "metrics: kvm-port-run=%" PRIu64 " time=%.3fms average=%.1fus "
              "(KVM_RUN plus guest execution to next port exit)\n",
              metrics->kvm_port_run_calls, (double)metrics->kvm_port_run_nanoseconds / 1000000.0,
              (double)metrics->kvm_port_run_nanoseconds / metrics->kvm_port_run_calls / 1000.0);
    }
    if (metrics->kvm_regs_sync_get_calls != 0 || metrics->kvm_regs_sync_set_calls != 0) {
      fprintf(stderr, "metrics: kvm-regs-sync get=%" PRIu64 " set=%" PRIu64 "\n",
              metrics->kvm_regs_sync_get_calls, metrics->kvm_regs_sync_set_calls);
    }
    if (metrics->kvm_gate_frame_capture_calls != 0 || metrics->kvm_gate_frame_reply_calls != 0) {
      fprintf(stderr,
              "metrics: kvm-gate-frame capture=%" PRIu64 "/%.3fms/%.1fus "
              "reply=%" PRIu64 "/%.3fms/%.1fus\n",
              metrics->kvm_gate_frame_capture_calls,
              (double)metrics->kvm_gate_frame_capture_nanoseconds / 1000000.0,
              metrics->kvm_gate_frame_capture_calls == 0
                ? 0.0
                : (double)metrics->kvm_gate_frame_capture_nanoseconds /
                    metrics->kvm_gate_frame_capture_calls / 1000.0,
              metrics->kvm_gate_frame_reply_calls,
              (double)metrics->kvm_gate_frame_reply_nanoseconds / 1000000.0,
              metrics->kvm_gate_frame_reply_calls == 0
                ? 0.0
                : (double)metrics->kvm_gate_frame_reply_nanoseconds /
                    metrics->kvm_gate_frame_reply_calls / 1000.0);
    }
    static const char *const run_names[DAZE_RUN_METRICS_DPMI_RUN_COUNT] = {
      "entry", "continue-once", "continue-observe", "continue-to-linear"};
    static const char *const exit_names[DAZE_RUN_METRICS_KVM_EXIT_COUNT] = {"debug", "io", "hlt",
                                                                            "other"};
    for (size_t kind = 0; kind < DAZE_RUN_METRICS_DPMI_RUN_COUNT; ++kind) {
      if (metrics->kvm_dpmi_run_calls[kind] == 0) continue;
      fprintf(stderr, "metrics: kvm-dpmi-run %s=%" PRIu64 "/%.3fms exits", run_names[kind],
              metrics->kvm_dpmi_run_calls[kind],
              (double)metrics->kvm_dpmi_run_nanoseconds[kind] / 1000000.0);
      for (size_t exit = 0; exit < DAZE_RUN_METRICS_KVM_EXIT_COUNT; ++exit) {
        if (metrics->kvm_dpmi_run_exit_calls[kind][exit] != 0) {
          fprintf(stderr, " %s=%" PRIu64 "/%.3fms", exit_names[exit],
                  metrics->kvm_dpmi_run_exit_calls[kind][exit],
                  (double)metrics->kvm_dpmi_run_exit_nanoseconds[kind][exit] / 1000000.0);
        }
      }
      fprintf(stderr, " (KVM_RUN plus guest execution)\n");
    }
    fprintf(stderr, "metrics: kvm-dpmi-io-markers");
    for (size_t marker = 0; marker < 256; ++marker) {
      if (metrics->kvm_dpmi_io_marker_calls[marker] != 0) {
        fprintf(stderr, " %02zxh=%" PRIu64 "/%.3fms", marker,
                metrics->kvm_dpmi_io_marker_calls[marker],
                (double)metrics->kvm_dpmi_io_marker_nanoseconds[marker] / 1000000.0);
      }
    }
    fprintf(stderr, "\n");
    static const char *const capture_names[DAZE_RUN_METRICS_DPMI_CAPTURE_COUNT] = {
      "entry", "continue-once", "continue-to-linear", "terminal", "diagnostic"};
    uint64_t capture_calls = 0;
    uint64_t capture_nanoseconds = 0;
    for (size_t kind = 0; kind < DAZE_RUN_METRICS_DPMI_CAPTURE_COUNT; ++kind) {
      capture_calls += metrics->kvm_dpmi_state_capture_calls[kind];
      capture_nanoseconds += metrics->kvm_dpmi_state_capture_nanoseconds[kind];
    }
    if (capture_calls != 0 || metrics->kvm_dpmi_debug_update_calls != 0 ||
        metrics->kvm_rm_procedure_calls != 0 || metrics->kvm_dpmi_mediator_calls != 0) {
      fprintf(stderr, "metrics: kvm-dpmi-host state-capture=%" PRIu64 "/%.3fms/%.1fus",
              capture_calls, (double)capture_nanoseconds / 1000000.0,
              capture_calls == 0 ? 0.0 : (double)capture_nanoseconds / capture_calls / 1000.0);
      if (metrics->kvm_dpmi_mediator_capture_elisions != 0)
        fprintf(stderr, " mediator-capture-elisions=%" PRIu64,
                metrics->kvm_dpmi_mediator_capture_elisions);
      for (size_t kind = 0; kind < DAZE_RUN_METRICS_DPMI_CAPTURE_COUNT; ++kind) {
        if (metrics->kvm_dpmi_state_capture_calls[kind] != 0) {
          fprintf(stderr, " %s=%" PRIu64 "/%.3fms", capture_names[kind],
                  metrics->kvm_dpmi_state_capture_calls[kind],
                  (double)metrics->kvm_dpmi_state_capture_nanoseconds[kind] / 1000000.0);
        }
      }
      fprintf(stderr,
              " debug-update=%" PRIu64 "/%.3fms/%.1fus "
              "mediator=%" PRIu64 "/%.3fms/%.1fus\n",
              metrics->kvm_dpmi_debug_update_calls,
              (double)metrics->kvm_dpmi_debug_update_nanoseconds / 1000000.0,
              metrics->kvm_dpmi_debug_update_calls == 0
                ? 0.0
                : (double)metrics->kvm_dpmi_debug_update_nanoseconds /
                    metrics->kvm_dpmi_debug_update_calls / 1000.0,
              metrics->kvm_dpmi_mediator_calls,
              (double)metrics->kvm_dpmi_mediator_nanoseconds / 1000000.0,
              metrics->kvm_dpmi_mediator_calls == 0
                ? 0.0
                : (double)metrics->kvm_dpmi_mediator_nanoseconds /
                    metrics->kvm_dpmi_mediator_calls / 1000.0);
      if (metrics->kvm_rm_procedure_calls != 0) {
        static const char *const cost_names[DAZE_RUN_METRICS_RM_COST_COUNT] = {"date-2ah",
                                                                               "time-2ch", "other"};
        for (size_t kind = 0; kind < DAZE_RUN_METRICS_RM_COST_COUNT; ++kind) {
          const DazeRunMetricsRmProcedureCost *cost = &metrics->kvm_rm_procedure_costs[kind];
          if (cost->calls == 0) continue;
          fprintf(stderr,
                  "metrics: kvm-rm-procedure-cost %s calls=%" PRIu64
                  " total=%.3fms average=%.1fus setup=%.3fms reflect=%.3fms cleanup=%.3fms"
                  " resume=%.3fms reflect-KVM_RUN=%.3fms resume-KVM_RUN=%.3fms"
                  " dos-service=%.3fms\n",
                  cost_names[kind], cost->calls, (double)cost->total_nanoseconds / 1000000.0,
                  (double)cost->total_nanoseconds / cost->calls / 1000.0,
                  (double)cost->setup_nanoseconds / 1000000.0,
                  (double)cost->reflect_nanoseconds / 1000000.0,
                  (double)cost->cleanup_nanoseconds / 1000000.0,
                  (double)cost->resume_nanoseconds / 1000000.0,
                  (double)cost->reflect_run_nanoseconds / 1000000.0,
                  (double)cost->resume_run_nanoseconds / 1000000.0,
                  (double)cost->service_nanoseconds / 1000000.0);
        }
        const uint64_t setup_accounted =
          metrics->kvm_rm_procedure_setup_parked_capture_nanoseconds +
          metrics->kvm_rm_procedure_setup_retire_nanoseconds +
          metrics->kvm_rm_procedure_setup_post_pio_capture_nanoseconds +
          metrics->kvm_rm_procedure_setup_transition_nanoseconds;
        const uint64_t setup_other =
          metrics->kvm_rm_procedure_setup_nanoseconds > setup_accounted
            ? metrics->kvm_rm_procedure_setup_nanoseconds - setup_accounted
            : 0;
        fprintf(stderr,
                "\nmetrics: kvm-rm-procedure total=%" PRIu64 "/%.3fms/%.1fus "
                "KVM_RUN=%" PRIu64 "/%.3fms/%.1fus\n",
                metrics->kvm_rm_procedure_calls,
                (double)metrics->kvm_rm_procedure_nanoseconds / 1000000.0,
                (double)metrics->kvm_rm_procedure_nanoseconds / metrics->kvm_rm_procedure_calls /
                  1000.0,
                metrics->kvm_rm_procedure_run_calls,
                (double)metrics->kvm_rm_procedure_run_nanoseconds / 1000000.0,
                metrics->kvm_rm_procedure_run_calls == 0
                  ? 0.0
                  : (double)metrics->kvm_rm_procedure_run_nanoseconds /
                      metrics->kvm_rm_procedure_run_calls / 1000.0);
        fprintf(stderr,
                "metrics: kvm-rm-procedure-phases setup=%.3fms reflect=%.3fms "
                "cleanup=%.3fms resume=%.3fms\n",
                (double)metrics->kvm_rm_procedure_setup_nanoseconds / 1000000.0,
                (double)metrics->kvm_rm_procedure_reflect_nanoseconds / 1000000.0,
                (double)metrics->kvm_rm_procedure_cleanup_nanoseconds / 1000000.0,
                (double)metrics->kvm_rm_procedure_resume_nanoseconds / 1000000.0);
        fprintf(stderr,
                "metrics: kvm-rm-procedure-setup parked-capture=%.3fms retire=%.3fms "
                "post-pio-capture=%.3fms transition=%.3fms other=%.3fms\n",
                (double)metrics->kvm_rm_procedure_setup_parked_capture_nanoseconds / 1000000.0,
                (double)metrics->kvm_rm_procedure_setup_retire_nanoseconds / 1000000.0,
                (double)metrics->kvm_rm_procedure_setup_post_pio_capture_nanoseconds / 1000000.0,
                (double)metrics->kvm_rm_procedure_setup_transition_nanoseconds / 1000000.0,
                (double)setup_other / 1000000.0);
        const uint64_t resume_accounted = metrics->kvm_rm_procedure_resume_run_nanoseconds +
                                          metrics->kvm_rm_procedure_resume_capture_nanoseconds;
        const uint64_t resume_other =
          metrics->kvm_rm_procedure_resume_nanoseconds > resume_accounted
            ? metrics->kvm_rm_procedure_resume_nanoseconds - resume_accounted
            : 0;
        fprintf(stderr,
                "metrics: kvm-rm-procedure-resume KVM_RUN=%.3fms capture=%.3fms "
                "other=%.3fms\n",
                (double)metrics->kvm_rm_procedure_resume_run_nanoseconds / 1000000.0,
                (double)metrics->kvm_rm_procedure_resume_capture_nanoseconds / 1000000.0,
                (double)resume_other / 1000000.0);
        const uint64_t reflect_accounted = metrics->kvm_rm_procedure_run_nanoseconds +
                                           metrics->kvm_rm_procedure_reflect_runner_nanoseconds;
        const uint64_t reflect_other =
          metrics->kvm_rm_procedure_reflect_nanoseconds > reflect_accounted
            ? metrics->kvm_rm_procedure_reflect_nanoseconds - reflect_accounted
            : 0;
        fprintf(stderr,
                "metrics: kvm-rm-procedure-reflect KVM_RUN=%.3fms runner-service=%" PRIu64
                "/%.3fms other=%.3fms\n",
                (double)metrics->kvm_rm_procedure_run_nanoseconds / 1000000.0,
                metrics->kvm_rm_procedure_reflect_runner_calls,
                (double)metrics->kvm_rm_procedure_reflect_runner_nanoseconds / 1000000.0,
                (double)reflect_other / 1000000.0);
        if (metrics->kvm_rm_procedure_reflect_vector_count != 0) {
          fprintf(stderr, "metrics: kvm-rm-procedure-reflect-vectors");
          for (size_t index = 0; index < metrics->kvm_rm_procedure_reflect_vector_count; ++index) {
            const DazeRunMetricsRmReflectVector *entry =
              &metrics->kvm_rm_procedure_reflect_vectors[index];
            fprintf(stderr, " %02xh=%" PRIu64 "/%.3fms", entry->vector, entry->calls,
                    (double)entry->nanoseconds / 1000000.0);
          }
          if (metrics->kvm_rm_procedure_reflect_vector_overflow_calls != 0)
            fprintf(stderr, " overflow=%" PRIu64,
                    metrics->kvm_rm_procedure_reflect_vector_overflow_calls);
          fprintf(stderr, "\n");
        }
      }
    }
    if (metrics->kvm_dpmi_function_count != 0) {
      fprintf(stderr, "metrics: kvm-dpmi-functions");
      for (size_t index = 0; index < metrics->kvm_dpmi_function_count; ++index) {
        const DazeRunMetricsDpmiFunction *function = &metrics->kvm_dpmi_functions[index];
        fprintf(stderr, " %04xh=%" PRIu64 "/%.3fms", function->function, function->calls,
                (double)function->mediator_nanoseconds / 1000000.0);
      }
      if (metrics->kvm_dpmi_function_overflow_calls != 0)
        fprintf(stderr, " overflow=%" PRIu64, metrics->kvm_dpmi_function_overflow_calls);
      fprintf(stderr, "\n");
    }
    if (metrics->kvm_virtual_interrupt_site_count != 0) {
      fprintf(stderr, "metrics: kvm-virtual-interrupt-sites");
      for (size_t index = 0; index < metrics->kvm_virtual_interrupt_site_count; ++index) {
        const DazeRunMetricsVirtualInterruptSite *site =
          &metrics->kvm_virtual_interrupt_sites[index];
        fprintf(stderr, " %04xh@%04x:%04x=%" PRIu64, site->function, site->cs, site->ip,
                site->calls);
      }
      if (metrics->kvm_virtual_interrupt_site_overflow_calls != 0)
        fprintf(stderr, " overflow=%" PRIu64, metrics->kvm_virtual_interrupt_site_overflow_calls);
      fprintf(stderr, "\n");
    }
    fprintf(stderr,
            "metrics: kvm-boundary-broker=%" PRIu64 " dos=%" PRIu64 " dpmi-entry=%" PRIu64
            " other=%" PRIu64 " service=%.3fms average=%.1fus\n",
            metrics->kvm_boundary_broker_calls, metrics->kvm_dos_boundary_broker_calls,
            metrics->kvm_dpmi_entry_boundary_broker_calls, metrics->kvm_other_boundary_broker_calls,
            (double)metrics->kvm_boundary_broker_nanoseconds / 1000000.0,
            metrics->kvm_boundary_broker_calls == 0
              ? 0.0
              : (double)metrics->kvm_boundary_broker_nanoseconds /
                  metrics->kvm_boundary_broker_calls / 1000.0);
    fprintf(stderr, "metrics: kvm-broker-vectors");
    for (size_t vector = 0; vector < 256; ++vector) {
      if (metrics->kvm_boundary_vectors[vector] != 0)
        fprintf(stderr, " %02zxh=%" PRIu64, vector, metrics->kvm_boundary_vectors[vector]);
    }
    fprintf(stderr, "\nmetrics: kvm-broker-dos-functions");
    for (size_t function = 0; function < 256; ++function) {
      if (metrics->kvm_dos_functions[function] != 0)
        fprintf(stderr, " %02zxh=%" PRIu64, function, metrics->kvm_dos_functions[function]);
    }
    fprintf(stderr, "\nmetrics: kvm-broker-dos-service");
    for (size_t function = 0; function < 256; ++function) {
      if (metrics->kvm_dos_functions[function] != 0)
        fprintf(stderr, " %02zxh=%" PRIu64 "/%.3fms/%.1fus", function,
                metrics->kvm_dos_functions[function],
                (double)metrics->kvm_dos_function_nanoseconds[function] / 1000000.0,
                (double)metrics->kvm_dos_function_nanoseconds[function] /
                  metrics->kvm_dos_functions[function] / 1000.0);
    }
    fprintf(stderr, "\n");
  }
}
