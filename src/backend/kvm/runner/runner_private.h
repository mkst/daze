#ifndef DAZE_KVM_RUNNER_RUNNER_PRIVATE_H
#define DAZE_KVM_RUNNER_RUNNER_PRIVATE_H

#include "kvm_guest_write.h"
#include "machine.h"
#include "memory.h"
#include "process_state.h"
#include "file_service.h"
#include "guest_memory_layout.h"
#include "runner_request_common.h"
#include "image.h"
#include "mz_layout.h"
#include "process_layout.h"

struct DazeKvmRunnerDpmiHandoff;

typedef enum {
  DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED = 1,
  DAZE_KVM_PREFLIGHT_BOUNDARY_DPMI_ENTRY = 2,
  DAZE_KVM_PREFLIGHT_BOUNDARY_UNSUPPORTED = 0,
  DAZE_KVM_PREFLIGHT_BOUNDARY_FAILED = -1,
  DAZE_KVM_PREFLIGHT_BOUNDARY_TERMINATED = 3,
  DAZE_KVM_PREFLIGHT_BOUNDARY_EXEC = 4,
} DazeKvmPreflightBoundaryDisposition;

typedef struct {
  uint16_t file_handle, copied_byte_count;
  uint16_t reply_ds;
  int reply_ds_present;
  uint32_t file_position;
  uint32_t resizes_served;
} DazeKvmPreflightBoundaryResult;

DazeKvmPreflightBoundaryDisposition daze_kvm_preflight_boundary_broker(
  DazeKvmMachine *machine, DazeDosfsFileService *files, DazeDosProcessState *process_state,
  DazeDosMemory *dos_memory, uint16_t dpmi_entry_segment, const uint8_t record[24],
  uint8_t mailbox[DAZE_KVM_RUNNER_GATE_MAILBOX_SIZE], DazeKvmPreflightBoundaryResult *result);

void daze_kvm_runner_gate_reply_init(const uint8_t *record, uint8_t *mailbox);

int daze_kvm_runner_process_valid(const DazeKvmRunnerRequestCommon *process);

/* The only guest port reads the real-mode gate answers: the 8259 master and
 * slave interrupt-mask registers (0x21/0xa1), which the reference (Unicorn)
 * run reads as 0. Returns 1 with *value set when the port is owned, else 0. */
int daze_kvm_runner_gated_port_read(uint16_t port, uint8_t *value);

uint8_t *runner_mailbox(DazeKvmMachine *machine);
const uint8_t *runner_record(const DazeKvmMachine *machine);
/* Unowned projection of the layout module's named runner triple, in fixed
 * [gate arena, record, mailbox] order. Validators name entries by this order;
 * do not reorder without updating them. */
size_t runner_reserved_ranges(size_t guest_size, DazeKvmGuestRange ranges[3]);
int bootstrap_real_mode_runner(DazeKvmMachine *machine, const DazeImage *image,
                               const DazeMzHeader *header, const char *command_tail,
                               const char *guest_path, uint16_t psp_segment,
                               uint16_t environment_segment, uint16_t dpmi_entry_segment,
                               uint16_t dos_vector_segment, uint16_t load_segment,
                               const uint8_t *psp_override,
                               const DazeKvmRunnerRequestCommon *process);
int serve_gated_port_read(DazeKvmMachine *machine, const DazeKvmPortAccess *access);
int capture_real_mode_entry_snapshot(DazeKvmMachine *machine, DazeKvmRunnerDpmiHandoff *handoff);

typedef struct {
  DazeKvmRunnerRequestCommon process;
} DazeKvmRunnerGenericPreflightRequest;

typedef enum {
  DAZE_KVM_GENERIC_PREFLIGHT_DPMI_ENTRY = 0,
  DAZE_KVM_GENERIC_PREFLIGHT_UNSUPPORTED = 1,
  DAZE_KVM_GENERIC_PREFLIGHT_FAILED = 2,
  DAZE_KVM_GENERIC_PREFLIGHT_INVALID = 3,
  DAZE_KVM_GENERIC_PREFLIGHT_TERMINATED = 4,
  DAZE_KVM_GENERIC_PREFLIGHT_EXEC = 5,
  DAZE_KVM_GENERIC_PREFLIGHT_PROTECTED_BOUNDARY = 6,
  DAZE_KVM_GENERIC_PREFLIGHT_RAW_SWITCH = 7,
} DazeKvmRunnerGenericPreflightDisposition;

typedef struct {
  DazeKvmRunnerGenericPreflightDisposition disposition;
  int guest_execution_may_have_started;
  uint8_t request_vector;
  uint16_t request_ax, request_bx, request_cx, request_dx, request_ds, request_es, request_si,
    request_di;
  int mailbox_unchanged;
  DazeKvmMachineExitObservation terminal_observation;
  int terminal_observation_status;
  DazeKvmRunnerDpmiHandoff dpmi_handoff;
} DazeKvmRunnerGenericPreflightResult;

int daze_kvm_runner_preflight_to_generic_boundary(
  DazeKvmMachine *machine, const DazeKvmRunnerGenericPreflightRequest *request,
  DazeKvmRunnerGenericPreflightResult *result);

int daze_kvm_runner_bootstrap_to_generic_boundary(
  DazeKvmMachine *machine, const DazeKvmRunnerGenericPreflightRequest *request,
  DazeDosProcessState *process_state, DazeDosMemory *dos_memory,
  DazeKvmRunnerGenericPreflightResult *result);

int daze_kvm_runner_resume_to_generic_boundary(DazeKvmMachine *machine,
                                               const DazeKvmRunnerGenericPreflightRequest *request,
                                               DazeDosProcessState *process_state,
                                               DazeDosMemory *dos_memory,
                                               DazeKvmRunnerGenericPreflightResult *result);

#endif
