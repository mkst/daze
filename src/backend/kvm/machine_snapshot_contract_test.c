#include "machine.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

static int mapping_released(void *address) {
  unsigned char resident;
  errno = 0;
  const int status = mincore(address, 1, &resident);
  if (status == -1 && errno == ENOMEM) return 1;
  fprintf(stderr, "snapshot mapping retained: address=%p mincore=%d errno=%d\n", address, status,
          errno);
  return 0;
}

static int capture_failures(DazeKvmMachine *machine, DazeKvmMachineSnapshot *snapshot) {
  const DazeKvmMachineSnapshot saved = *snapshot;
  for (unsigned variant = 0; variant < 2; ++variant) {
    DazeKvmMachine view = *machine;
    if (variant == 0)
      view.guest_size = SIZE_MAX;
    else
      view.vcpu = machine->vm;
    const int status = daze_kvm_machine_snapshot_take(&view, snapshot);
    if (status != DAZE_KVM_MACHINE_FAILED || snapshot->guest_bytes != saved.guest_bytes ||
        snapshot->cpu_state != saved.cpu_state || snapshot->guest_size != saved.guest_size ||
        snapshot->write_batch_installed != saved.write_batch_installed ||
        snapshot->valid != saved.valid ||
        memcmp(machine->guest, snapshot->guest_bytes, machine->guest_size) != 0) {
      fprintf(stderr, "snapshot failure variant=%u status=%d\n", variant, status);
      return 0;
    }
  }
  return 1;
}

static int restore_variants(DazeKvmMachine *machine, const DazeKvmMachineSnapshot *snapshot) {
  uint8_t *const guest = machine->guest;
  for (unsigned variant = 0; variant < 5; ++variant) {
    if (variant == 1) {
      guest[4095] ^= 1;
      guest[4096] ^= 2;
      guest[machine->guest_size - 1] ^= 4;
    } else if (variant == 2) {
      memset(guest, 0xa5, machine->guest_size);
    } else if (variant == 3) {
      memset(guest, 0, machine->guest_size);
    } else if (variant == 4) {
      for (size_t offset = 0; offset < machine->guest_size; offset += 8192)
        guest[offset] ^= 0xff;
    }
    const int status = daze_kvm_machine_snapshot_restore(machine, snapshot);
    if (status != DAZE_KVM_MACHINE_OK ||
        memcmp(guest, snapshot->guest_bytes, machine->guest_size) != 0) {
      fprintf(stderr, "snapshot restore variant=%u status=%d\n", variant, status);
      return 0;
    }
  }
  DazeKvmMachine partial = *machine;
  DazeKvmMachineSnapshot saved = *snapshot;
  partial.guest_size = saved.guest_size = 4096 + 17;
  guest[partial.guest_size - 1] ^= 0xff;
  guest[partial.guest_size] = 0x6d;
  const int status = daze_kvm_machine_snapshot_restore(&partial, &saved);
  if (status != DAZE_KVM_MACHINE_OK || memcmp(guest, saved.guest_bytes, partial.guest_size) != 0 ||
      guest[partial.guest_size] != 0x6d) {
    fprintf(stderr, "snapshot partial restore status=%d\n", status);
    return 0;
  }
  return daze_kvm_machine_snapshot_restore(machine, snapshot) == DAZE_KVM_MACHINE_OK &&
         memcmp(guest, snapshot->guest_bytes, machine->guest_size) == 0;
}

static int capture_variants(DazeKvmMachine *machine) {
  const size_t sizes[] = {17, 4095, 4096, 4113, 0x10000, 0x22000};
  DazeKvmMachineSnapshot snapshot = {0};
  for (size_t index = 0; index < sizeof(sizes) / sizeof(sizes[0]); ++index) {
    for (unsigned variant = 0; variant < 5; ++variant) {
      uint8_t *const guest = machine->guest;
      memset(guest, variant == 1 ? 0xa5 : 0, machine->guest_size);
      DazeKvmMachine view = *machine;
      view.guest_size = sizes[index];
      if (variant == 3) {
        for (size_t offset = 0; offset < view.guest_size; offset += 4096)
          if ((offset / 4096) % 8 == 0 || (offset / 4096) % 8 == 7) guest[offset] = 0x37;
        guest[view.guest_size - 1] = 0xe1;
      }
      void *const retired = snapshot.guest_bytes;
      int status = daze_kvm_machine_snapshot_take(&view, &snapshot);
      if (status != DAZE_KVM_MACHINE_OK || !snapshot.valid ||
          snapshot.guest_size != view.guest_size ||
          memcmp(snapshot.guest_bytes, guest, view.guest_size) != 0) {
        fprintf(stderr, "capture size=%zu variant=%u status=%d\n", view.guest_size, variant,
                status);
        daze_kvm_machine_snapshot_dispose(&snapshot);
        return 0;
      }
      if (retired != NULL && !mapping_released(retired)) {
        daze_kvm_machine_snapshot_dispose(&snapshot);
        return 0;
      }
      memset(guest, 0x6d, view.guest_size);
      status = daze_kvm_machine_snapshot_restore(&view, &snapshot);
      if (status != DAZE_KVM_MACHINE_OK ||
          memcmp(snapshot.guest_bytes, guest, view.guest_size) != 0) {
        fprintf(stderr, "capture restore size=%zu variant=%u status=%d\n", view.guest_size, variant,
                status);
        daze_kvm_machine_snapshot_dispose(&snapshot);
        return 0;
      }
    }
  }
  void *const retired = snapshot.guest_bytes;
  daze_kvm_machine_snapshot_dispose(&snapshot);
  if (!mapping_released(retired)) return 0;
  memset(machine->guest, 0, machine->guest_size);
  return 1;
}

int main(void) {
  DazeKvmMachine machine;
  const int init = daze_kvm_machine_init(&machine, 0x22000);
  if (init == DAZE_KVM_MACHINE_UNAVAILABLE) return 77;
  if (init != DAZE_KVM_MACHINE_OK) return 1;
  uint8_t *guest = machine.guest;
  const uint8_t first[] = {
    0xb0, 0x11, /* mov al,0x11 */
    0xe6, 0xf4  /* out 0xf4,al */
  };
  const uint8_t second[] = {
    0xb0, 0x22, /* mov al,0x22 */
    0xe6, 0xf4  /* out 0xf4,al */
  };
  DazeKvmMachineSnapshot snapshot = {0};
  int result = 1;
  if (!capture_variants(&machine)) goto out;
  memcpy(guest, first, sizeof(first));
  memcpy(guest + 8, second, sizeof(second));
  if (daze_kvm_machine_set_real_mode(&machine, 0, 0, 0, 0xfffe, 0, 0) != DAZE_KVM_MACHINE_OK ||
      daze_kvm_machine_snapshot_take(&machine, &snapshot) != DAZE_KVM_MACHINE_OK) {
    goto out;
  }
  if (!capture_failures(&machine, &snapshot)) goto out;
  guest[0] = 0xf4;
  if (daze_kvm_machine_set_real_mode(&machine, 0, 8, 0, 0xfffe, 0, 0) != DAZE_KVM_MACHINE_OK ||
      daze_kvm_machine_snapshot_restore(&machine, &snapshot) != DAZE_KVM_MACHINE_OK) {
    goto out;
  }
  if (!restore_variants(&machine, &snapshot)) goto out;
  DazeKvmPortAccess access = {0};
  if (daze_kvm_machine_run_port_access(&machine, &access) == DAZE_KVM_MACHINE_OK &&
      access.direction == DAZE_KVM_PORT_OUT && access.port == 0xf4 && access.value == 0x11 &&
      guest[0] == first[0]) {
    result = 0;
  }
out:
  daze_kvm_machine_snapshot_dispose(&snapshot);
  daze_kvm_machine_destroy(&machine);
  return result;
}
