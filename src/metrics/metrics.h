#ifndef DAZE_METRICS_H
#define DAZE_METRICS_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#include "file_service.h"

typedef struct {
  uint16_t function;
  uint64_t calls;
} DazeDpmiFunctionMetric;

typedef enum {
  DAZE_RESUME_DIRECT = 0,
  DAZE_RESUME_AFTER_DISPATCH_ADDRESS,
  DAZE_RESUME_AFTER_DISPATCH_NEXT,
  DAZE_RESUME_AFTER_DISPATCH_RESTART,
  DAZE_RESUME_KIND_COUNT,
} DazeResumeKind;

typedef struct {
  uint64_t interrupts;
  uint64_t guest_instructions;
  uint64_t code_hook_calls;
  uint64_t emulation_runs;
  uint64_t dos_calls;
  uint64_t dpmi_calls;
  uint64_t host_read_calls;
  uint64_t host_read_bytes;
  uint64_t host_write_calls;
  uint64_t host_write_bytes;
  /* Timing is opt-in with --metrics. Unicorn time includes callbacks, so
   * interrupt-handler time can overlap emulation time. */
  uint64_t emulation_nanoseconds;
  uint64_t interrupt_handler_nanoseconds;
  uint64_t code_hook_samples;
  uint64_t code_hook_sample_nanoseconds;
  uint64_t translation_cache_flushes;
  uint64_t translation_cache_targeted_invalidations;
  uint64_t stop_events;
  uint64_t resume_boundary_nanoseconds;
  uint64_t resume_counts[DAZE_RESUME_KIND_COUNT];
  uint64_t resume_nanoseconds[DAZE_RESUME_KIND_COUNT];
  int enabled;
  int guest_instruction_count_available;
  uint64_t interrupt_counts[256];
  uint64_t interrupt_handler_counts[256];
  uint64_t interrupt_handler_nanoseconds_by_interrupt[256];
  uint64_t dos_function_counts[256];
  DazeDpmiFunctionMetric dpmi_function_counts[64];
  size_t dpmi_function_count;
} DazeMetrics;

void daze_metrics_record_interrupt(DazeMetrics *metrics, uint8_t interrupt);
void daze_metrics_record_dpmi_function(DazeMetrics *metrics, uint16_t function);
void daze_metrics_record_emulation_time(DazeMetrics *metrics, uint64_t nanoseconds);
void daze_metrics_record_interrupt_handler(DazeMetrics *metrics, uint8_t interrupt,
                                           uint64_t nanoseconds);
void daze_metrics_record_code_hook_sample(DazeMetrics *metrics, uint64_t nanoseconds);
void daze_metrics_record_translation_cache_flush(DazeMetrics *metrics);
void daze_metrics_record_translation_cache_targeted_invalidation(DazeMetrics *metrics);
void daze_metrics_record_stop(DazeMetrics *metrics);
void daze_metrics_record_resume(DazeMetrics *metrics, DazeResumeKind kind, uint64_t nanoseconds);
void daze_metrics_report(const DazeMetrics *metrics, const struct timespec *started);
void daze_metrics_report_run(const DazeRunMetrics *metrics);

#endif
