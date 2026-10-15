#ifndef DAZE_RUN_METRICS_H
#define DAZE_RUN_METRICS_H

#include <stddef.h>
#include <stdint.h>

enum {
  DAZE_RUN_METRICS_DPMI_RUN_ENTRY,
  DAZE_RUN_METRICS_DPMI_RUN_CONTINUE_ONCE,
  DAZE_RUN_METRICS_DPMI_RUN_CONTINUE_OBSERVE,
  DAZE_RUN_METRICS_DPMI_RUN_CONTINUE_TO_LINEAR,
  DAZE_RUN_METRICS_DPMI_RUN_COUNT,
};

enum { DAZE_RUN_METRICS_DPMI_FUNCTION_CAPACITY = 32 };
enum { DAZE_RUN_METRICS_VIRTUAL_INTERRUPT_SITE_CAPACITY = 16 };
enum { DAZE_RUN_METRICS_RM_REFLECT_VECTOR_CAPACITY = 16 };

enum {
  DAZE_RUN_METRICS_RM_DATE,
  DAZE_RUN_METRICS_RM_TIME,
  DAZE_RUN_METRICS_RM_OTHER,
  DAZE_RUN_METRICS_RM_COST_COUNT,
};

typedef struct {
  uint64_t calls;
  uint64_t total_nanoseconds;
  uint64_t setup_nanoseconds;
  uint64_t reflect_nanoseconds;
  uint64_t cleanup_nanoseconds;
  uint64_t resume_nanoseconds;
  uint64_t reflect_run_nanoseconds;
  uint64_t resume_run_nanoseconds;
  uint64_t service_nanoseconds;
} DazeRunMetricsRmProcedureCost;

typedef struct {
  uint16_t function;
  uint64_t calls;
  uint64_t mediator_nanoseconds;
} DazeRunMetricsDpmiFunction;

typedef struct {
  uint16_t function;
  uint16_t cs;
  uint16_t ip;
  uint64_t calls;
} DazeRunMetricsVirtualInterruptSite;

typedef struct {
  uint8_t vector;
  uint64_t calls;
  uint64_t nanoseconds;
} DazeRunMetricsRmReflectVector;

enum {
  DAZE_RUN_METRICS_KVM_EXIT_DEBUG,
  DAZE_RUN_METRICS_KVM_EXIT_IO,
  DAZE_RUN_METRICS_KVM_EXIT_HLT,
  DAZE_RUN_METRICS_KVM_EXIT_OTHER,
  DAZE_RUN_METRICS_KVM_EXIT_COUNT,
};

enum {
  DAZE_RUN_METRICS_DPMI_CAPTURE_ENTRY,
  DAZE_RUN_METRICS_DPMI_CAPTURE_CONTINUE_ONCE,
  DAZE_RUN_METRICS_DPMI_CAPTURE_CONTINUE_TO_LINEAR,
  DAZE_RUN_METRICS_DPMI_CAPTURE_TERMINAL,
  DAZE_RUN_METRICS_DPMI_CAPTURE_DIAGNOSTIC,
  DAZE_RUN_METRICS_DPMI_CAPTURE_COUNT,
};

/* Optional per-run DOS-transfer and KVM-boundary counters/timings.
 * Reporting is separate from collection. */
typedef struct {
  uint64_t read_calls;
  uint64_t read_requested_bytes;
  uint64_t read_bytes;
  uint64_t write_calls;
  uint64_t write_requested_bytes;
  uint64_t write_bytes;
  uint64_t transfer_buffer_resizes;
  size_t transfer_buffer_peak;
  uint64_t kvm_boundary_broker_calls;
  uint64_t kvm_dos_boundary_broker_calls;
  uint64_t kvm_dpmi_entry_boundary_broker_calls;
  uint64_t kvm_other_boundary_broker_calls;
  uint64_t kvm_boundary_broker_nanoseconds;
  /* The normal real-mode route runs guest code to one byte-port boundary.
   * Its duration includes both KVM_RUN and guest execution between exits. */
  uint64_t kvm_port_run_calls;
  uint64_t kvm_port_run_nanoseconds;
  /* Register traffic served from the shared kvm_run sync area instead of
   * GET/SET ioctls (see machine_access.h). Zero when unsupported. */
  uint64_t kvm_regs_sync_get_calls;
  uint64_t kvm_regs_sync_set_calls;
  uint64_t kvm_gate_frame_capture_calls;
  uint64_t kvm_gate_frame_capture_nanoseconds;
  uint64_t kvm_gate_frame_reply_calls;
  uint64_t kvm_gate_frame_reply_nanoseconds;
  uint64_t kvm_dpmi_run_calls[DAZE_RUN_METRICS_DPMI_RUN_COUNT];
  uint64_t kvm_dpmi_run_nanoseconds[DAZE_RUN_METRICS_DPMI_RUN_COUNT];
  uint64_t kvm_dpmi_run_exit_calls[DAZE_RUN_METRICS_DPMI_RUN_COUNT]
                                  [DAZE_RUN_METRICS_KVM_EXIT_COUNT];
  uint64_t kvm_dpmi_run_exit_nanoseconds[DAZE_RUN_METRICS_DPMI_RUN_COUNT]
                                        [DAZE_RUN_METRICS_KVM_EXIT_COUNT];
  uint64_t kvm_dpmi_io_marker_calls[256];
  uint64_t kvm_dpmi_io_marker_nanoseconds[256];
  uint64_t kvm_dpmi_state_capture_calls[DAZE_RUN_METRICS_DPMI_CAPTURE_COUNT];
  uint64_t kvm_dpmi_state_capture_nanoseconds[DAZE_RUN_METRICS_DPMI_CAPTURE_COUNT];
  uint64_t kvm_dpmi_mediator_capture_elisions;
  uint64_t kvm_dpmi_debug_update_calls;
  uint64_t kvm_dpmi_debug_update_nanoseconds;
  uint64_t kvm_debug_update_elisions;
  uint64_t kvm_guest_virtual_interrupt_calls[2];
  uint64_t kvm_guest_descriptor_calls[3];
  uint64_t kvm_guest_vector_queries;
  /* DPMI 0301h uses a real-mode callback detour with its own KVM_RUN. These
   * are separate from the protected-mode DPMI entry helpers above. */
  uint64_t kvm_rm_procedure_calls;
  uint64_t kvm_rm_procedure_native_calls;
  uint64_t kvm_guest_write_calls, kvm_guest_write_bytes, kvm_guest_write_drains;
  uint64_t kvm_rm_procedure_bridged_calls;
  uint64_t kvm_rm_procedure_nanoseconds;
  uint64_t kvm_rm_procedure_run_calls;
  uint64_t kvm_rm_procedure_run_nanoseconds;
  uint64_t kvm_rm_procedure_setup_nanoseconds;
  uint64_t kvm_rm_procedure_setup_parked_capture_nanoseconds;
  uint64_t kvm_rm_procedure_setup_retire_nanoseconds;
  uint64_t kvm_rm_procedure_setup_post_pio_capture_nanoseconds;
  uint64_t kvm_rm_procedure_setup_transition_nanoseconds;
  uint64_t kvm_rm_procedure_reflect_nanoseconds;
  uint64_t kvm_rm_procedure_reflect_runner_calls;
  uint64_t kvm_rm_procedure_reflect_runner_nanoseconds;
  DazeRunMetricsRmReflectVector
    kvm_rm_procedure_reflect_vectors[DAZE_RUN_METRICS_RM_REFLECT_VECTOR_CAPACITY];
  size_t kvm_rm_procedure_reflect_vector_count;
  uint64_t kvm_rm_procedure_reflect_vector_overflow_calls;
  uint64_t kvm_rm_procedure_cleanup_nanoseconds;
  uint64_t kvm_rm_procedure_resume_nanoseconds;
  uint64_t kvm_rm_procedure_resume_run_nanoseconds;
  uint64_t kvm_rm_procedure_resume_capture_nanoseconds;
  DazeRunMetricsRmProcedureCost kvm_rm_procedure_costs[DAZE_RUN_METRICS_RM_COST_COUNT];
  uint64_t kvm_dpmi_mediator_calls;
  uint64_t kvm_dpmi_mediator_nanoseconds;
  DazeRunMetricsDpmiFunction kvm_dpmi_functions[DAZE_RUN_METRICS_DPMI_FUNCTION_CAPACITY];
  size_t kvm_dpmi_function_count;
  uint64_t kvm_dpmi_function_overflow_calls;
  DazeRunMetricsVirtualInterruptSite
    kvm_virtual_interrupt_sites[DAZE_RUN_METRICS_VIRTUAL_INTERRUPT_SITE_CAPACITY];
  size_t kvm_virtual_interrupt_site_count;
  uint64_t kvm_virtual_interrupt_site_overflow_calls;
  uint64_t kvm_boundary_vectors[256];
  uint64_t kvm_dos_functions[256];
  uint64_t kvm_dos_function_nanoseconds[256];
  int enabled;
} DazeRunMetrics;

#endif
