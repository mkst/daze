#ifndef DAZE_KVM_MACHINE_PRIVATE_H
#define DAZE_KVM_MACHINE_PRIVATE_H

#include "machine.h"
#include <stddef.h>

enum {
  DAZE_KVM_MACHINE_STAGE_NONE = 0,
  DAZE_KVM_MACHINE_STAGE_OPEN = 3,
  DAZE_KVM_MACHINE_STAGE_API = 4,
  DAZE_KVM_MACHINE_STAGE_VM = 5,
  DAZE_KVM_MACHINE_STAGE_VCPU = 6,
  DAZE_KVM_MACHINE_STAGE_MMAP_SIZE = 7,
  DAZE_KVM_MACHINE_STAGE_RUN_MMAP = 8,
  DAZE_KVM_MACHINE_STAGE_GUEST_MMAP = 9,
  DAZE_KVM_MACHINE_STAGE_REGION = 10
};

typedef struct {
  int (*open)(const char *path, int flags);
  int (*ioctl)(int fd, unsigned long request, void *arg);
  void *(*mmap)(void *addr, size_t length, int prot, int flags, int fd, long offset);
  int (*munmap)(void *addr, size_t length);
  int (*close)(int fd);
} DazeKvmMachineSeam;

typedef struct {
  int status;
  int stage;
  int error;
} DazeKvmMachineInitResult;

DazeKvmMachineInitResult daze_kvm_machine_init_with_seam(DazeKvmMachine *machine, size_t guest_size,
                                                         const DazeKvmMachineSeam *seam);
#endif
