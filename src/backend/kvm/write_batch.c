#include "write_batch.h"
#include "machine_access.h"
#include "rm_entry.h"
#include "write_batch_code.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

int daze_kvm_write_batch_drain(DazeKvmMachine *machine, DazeDosfsFileService *files) {
  if (machine == NULL || !machine->write_batch_installed) return 1;
  if (machine->guest == NULL ||
      !daze_kvm_range_fits(machine->guest_size, k_kvm_write_batch_code, k_kvm_write_batch_size))
    return 0;
  uint8_t *const control = (uint8_t *)machine->guest + k_kvm_write_batch_control;
  const uint16_t credit = machine->write_batch_credit;
  daze_kvm_write_batch_revoke(machine);
  const uint16_t count = daze_read_u16(control + 4);
  const uint32_t calls = daze_read_u32(control + 8);
  if (count == 0 && calls == 0) return 1;
  if (files == NULL || files->handles == NULL || count == 0 || calls == 0 || calls > count ||
      count > credit || daze_read_u16(control + 2) != machine->write_batch_handle ||
      daze_read_u16(control + 6) != credit || daze_read_u32(control + 12) != count ||
      !daze_dosfs_handles_append_buffered(files->handles, machine->write_batch_handle,
                                          (const uint8_t *)machine->guest + k_kvm_write_batch_data,
                                          count)) {
    fprintf(stderr, "kvm-write-batch: invalid pending data handle=%u bytes=%u calls=%u credit=%u\n",
            machine->write_batch_handle, count, calls, credit);
    if (files != NULL && files->handles != NULL) files->handles->teardown_errno = EIO;
    return 0;
  }
  if (files->run_metrics != NULL && files->run_metrics->enabled) {
    DazeRunMetrics *const metrics = files->run_metrics;
    metrics->write_calls += calls;
    metrics->write_requested_bytes += count;
    metrics->write_bytes += count;
    metrics->kvm_guest_write_calls += calls;
    metrics->kvm_guest_write_bytes += count;
    metrics->kvm_guest_write_drains++;
  }
  daze_write_u16(control + 4, 0);
  daze_write_u32(control + 8, 0);
  daze_write_u32(control + 12, 0);
  return 1;
}

#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
#include <linux/kvm.h>

static int real_data_cache(const struct kvm_segment *segment) {
  return !segment->unusable && segment->present && segment->s && segment->type == 3 &&
         segment->dpl == 0 && !segment->db && !segment->g && !segment->l && !segment->avl &&
         segment->limit == 0xffff && segment->base == (uint32_t)segment->selector * 16;
}
#endif

void daze_kvm_write_batch_arm(DazeKvmMachine *machine, DazeDosfsFileService *files,
                              const uint8_t record[24], const uint8_t reply[16]) {
#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
  if (machine == NULL || files == NULL || record == NULL || reply == NULL ||
      machine->guest_size != k_memory_size || !daze_kvm_rm_entry_active(machine) ||
      daze_read_u16((const uint8_t *)machine->guest + 0x2a42) != 0 ||
      daze_read_u16(record + 16) != 0x21 || (daze_read_u16(record) >> 8) != 0x40 ||
      (daze_read_u16(reply + 14) & 1) || daze_read_u16(reply) != daze_read_u16(record + 4) ||
      daze_read_u16(record + 4) == 0 || daze_kvm_write_batch_pending(machine))
    return;
  const uint16_t handle = daze_read_u16(record + 2);
  const uint16_t credit = daze_dosfs_handles_write_credit(files->handles, handle);
  if (credit == 0) return;
  struct kvm_regs regs;
  struct kvm_sregs segments;
  if (daze_kvm_machine_get_regs(machine, &regs) != DAZE_KVM_MACHINE_OK ||
      daze_kvm_machine_get_sregs(machine, &segments) != DAZE_KVM_MACHINE_OK || (segments.cr0 & 1) ||
      (regs.rflags & 0x30100) || segments.cs.db || segments.cs.limit != 0xffff ||
      !real_data_cache(&segments.ds) || !real_data_cache(&segments.es) ||
      !real_data_cache(&segments.ss) || regs.rsp < 40 || regs.rsp > 0xfff9 ||
      segments.ss.base + regs.rsp < k_kvm_write_batch_data + k_kvm_write_batch_capacity + 40)
    return;
  uint8_t *const guest = machine->guest;
  if (!machine->write_batch_installed) {
    const uint8_t gate[] = {0x50, 0xb0, 0x21, 0xe6, 0xf4, 0x58, 0xcf};
    if (segments.cs.base != (uint32_t)k_dos_int21_vector_segment * 16 || regs.rip != 3 ||
        memcmp(guest + 0x3000, gate, sizeof(gate)) != 0)
      return;
    _Static_assert(sizeof(write_batch_code) <= k_kvm_write_batch_control - k_kvm_write_batch_code,
                   "write helper stays below control state");
    memcpy(guest + k_kvm_write_batch_code, write_batch_code, sizeof(write_batch_code));
    memset(guest + k_kvm_write_batch_control, 0, 0x40);
    /* KVM completes the pending OUT on re-entry; retain it and its pop/IRET successor. */
    const uint8_t jump[] = {0xea, 0, 0, 0x40, 0x07}; /* jmp far 0740h:0000h */
    memcpy(guest + 0x3007, jump, sizeof(jump));
    guest[0x3000] = 0xeb; /* jmp short +5 */
    guest[0x3001] = 5;
    machine->write_batch_installed = 1;
  }
  uint8_t *const control = guest + k_kvm_write_batch_control;
  machine->write_batch_handle = handle;
  machine->write_batch_credit = credit;
  daze_write_u16(control + 2, handle);
  daze_write_u16(control + 6, credit);
  daze_write_u16(control, 1);
#else
  (void)machine;
  (void)files;
  (void)record;
  (void)reply;
#endif
}
