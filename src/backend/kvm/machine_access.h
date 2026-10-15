#ifndef DAZE_KVM_MACHINE_ACCESS_H
#define DAZE_KVM_MACHINE_ACCESS_H

#include "machine.h"

#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
#include <linux/kvm.h>

/* Debug configuration belongs to the vCPU, not an individual continuation owner.
 * Raw register installs must invalidate it before changing CPU state. */
void daze_kvm_machine_debug_invalidate(DazeKvmMachine *machine);
/* These two helpers retain ioctl's 0/-1 return convention and errno. */
int daze_kvm_machine_set_guest_debug(DazeKvmMachine *machine, const struct kvm_guest_debug *debug);
int daze_kvm_machine_run(DazeKvmMachine *machine);

/* Sync reads are valid after a completed KVM_RUN; sync writes take effect on the next
 * run. Raw ioctl installs leave the shared area stale. Refresh it or read with ioctls
 * before inspecting that state; never mix pending sync writes with raw installs. */
int daze_kvm_machine_get_regs(DazeKvmMachine *machine, struct kvm_regs *regs);
int daze_kvm_machine_get_sregs(DazeKvmMachine *machine, struct kvm_sregs *sregs);
int daze_kvm_machine_set_regs(DazeKvmMachine *machine, const struct kvm_regs *regs);
int daze_kvm_machine_set_sregs(DazeKvmMachine *machine, const struct kvm_sregs *sregs);
/* Mirror kernel state into the sync area (no-op on unsupported masks).
 * Call after raw ioctl installs ahead of sync readers. */
int daze_kvm_machine_sync_refresh(DazeKvmMachine *machine);

#endif

#endif
