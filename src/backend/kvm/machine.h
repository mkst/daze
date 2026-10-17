#ifndef DAZE_KVM_MACHINE_H
#define DAZE_KVM_MACHINE_H

#include <stddef.h>
#include <stdint.h>

#include "../../metrics/run_metrics.h"

typedef struct {
  int kvm, vm, vcpu;
  void *run, *guest;
  size_t run_size, guest_size;
  DazeRunMetrics *run_metrics;
  /* Probed KVM_SYNC_REGS class mask (0 when unsupported: register access
   * stays on ioctls). Plain int: no <linux/kvm.h> needed here. */
  int sync_regs_mask;
  int immediate_exit_supported;
  uint64_t debug_breakpoint;
  int debug_breakpoint_known, debug_io_exit;
  int write_batch_installed;
  uint16_t write_batch_handle, write_batch_credit;
} DazeKvmMachine;

/* EXEC checkpoint owns a complete RAM copy and KVM general/special registers.
 * Saved bytes and CPU metadata must not be modified.
 * Construct with snapshot_take and release with snapshot_dispose; not a portable format. */
typedef struct {
  void *guest_bytes;
  void *cpu_state;
  size_t guest_size;
  int write_batch_installed;
  int valid;
} DazeKvmMachineSnapshot;

/* Copied diagnostic state after KVM_RUN; carries no machine ownership. */
typedef struct {
  int present;
  uint32_t exit_reason;
  uint16_t cs, ss;
  uint64_t rip, rsp, rax, rbx, rcx, rdx, rsi, rdi;
} DazeKvmMachineExitObservation;

enum {
  DAZE_KVM_MACHINE_OK = 0,
  DAZE_KVM_MACHINE_UNAVAILABLE = 77,
  DAZE_KVM_MACHINE_INVALID = 2,
  DAZE_KVM_MACHINE_FAILED = 1
};

/* Values match KVM_EXIT_IO_IN/OUT without requiring <linux/kvm.h>. */
enum {
  DAZE_KVM_PORT_IN = 0,
  DAZE_KVM_PORT_OUT = 1,
};

/* A single 1-byte, count-1 guest port access. For an OUT, value is the byte the
 * guest wrote. For an IN, value is the byte the caller must supply through
 * daze_kvm_machine_supply_port_in before the next run. */
typedef struct {
  int direction;
  uint16_t port;
  uint8_t value;
} DazeKvmPortAccess;

int daze_kvm_machine_init(DazeKvmMachine *machine, size_t guest_size);
void daze_kvm_machine_destroy(DazeKvmMachine *machine);
void daze_kvm_machine_set_run_metrics(DazeKvmMachine *machine, DazeRunMetrics *metrics);
/* Distinguishes a compiled KVM backend from the always-unavailable stub;
 * selection must keep build availability separate from runtime probe results. */
int daze_kvm_machine_compiled(void);
int daze_kvm_machine_write(void *context, uint32_t address, const void *bytes, size_t size);
int daze_kvm_machine_snapshot_take(const DazeKvmMachine *machine, DazeKvmMachineSnapshot *snapshot);
int daze_kvm_machine_snapshot_restore(DazeKvmMachine *machine,
                                      const DazeKvmMachineSnapshot *snapshot);
void daze_kvm_machine_snapshot_dispose(DazeKvmMachineSnapshot *snapshot);
int daze_kvm_machine_set_real_mode(DazeKvmMachine *machine, uint16_t cs, uint16_t ip, uint16_t ss,
                                   uint16_t sp, uint16_t ds, uint16_t es);
int daze_kvm_machine_set_general_registers(DazeKvmMachine *machine, uint16_t ax, uint16_t bx,
                                           uint16_t cx, uint16_t dx, uint16_t si, uint16_t di);
/* Runs until the next single-byte IN or OUT access. Multi-byte, multi-count, or
 * non-port exits fail loudly. */
int daze_kvm_machine_run_port_access(DazeKvmMachine *machine, DazeKvmPortAccess *access);
int daze_kvm_machine_supply_port_in(DazeKvmMachine *machine, uint8_t value);
int daze_kvm_machine_capture_exit(const DazeKvmMachine *machine,
                                  DazeKvmMachineExitObservation *observation);
#endif
