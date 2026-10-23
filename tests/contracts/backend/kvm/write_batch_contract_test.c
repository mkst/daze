#define _GNU_SOURCE
#define daze_kvm_machine_get_regs batch_get_regs
#define daze_kvm_machine_get_sregs batch_get_sregs
#include "backend/kvm/write_batch.c"
#undef daze_kvm_machine_get_regs
#undef daze_kvm_machine_get_sregs

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
static struct kvm_regs registers;
static struct kvm_sregs special;
static int fail_regs, fail_sregs;
int batch_get_regs(DazeKvmMachine *machine, struct kvm_regs *regs) {
  (void)machine;
  *regs = registers;
  return fail_regs ? DAZE_KVM_MACHINE_FAILED : DAZE_KVM_MACHINE_OK;
}
int batch_get_sregs(DazeKvmMachine *machine, struct kvm_sregs *regs) {
  (void)machine;
  *regs = special;
  return fail_sregs ? DAZE_KVM_MACHINE_FAILED : DAZE_KVM_MACHINE_OK;
}

static void arm_contract(DazeKvmMachine *machine, DazeDosfsFileService *files, uint16_t handle) {
  uint8_t record[24] = {0}, reply[16] = {0};
  daze_write_u16(record, 0x4000);
  daze_write_u16(record + 2, handle);
  daze_write_u16(record + 4, 3);
  daze_write_u16(record + 16, 0x21);
  daze_write_u16(reply, 3);
  uint8_t *guest = machine->guest;
  const uint8_t gate[] = {0x50, 0xb0, 0x21, 0xe6, 0xf4, 0x58, 0xcf};
  memcpy(guest + 0x3000, gate, sizeof(gate));
  daze_write_u32(guest + 0x5868, DAZE_KVM_RM_ENTRY_SIGNATURE);
  daze_write_u32(guest + 0x5840, 1);
  registers = (struct kvm_regs){.rip = 3, .rsp = 0xff00, .rflags = 2};
  const struct kvm_segment data = {
    .selector = 0x1100, .base = 0x11000, .limit = 0xffff, .type = 3, .present = 1, .s = 1};
  special =
    (struct kvm_sregs){.cs = {.base = 0x3000, .limit = 0xffff}, .ds = data, .es = data, .ss = data};
  for (unsigned kind = 0; kind < 41; ++kind) {
    const struct kvm_sregs saved = special;
    const struct kvm_regs saved_regs = registers;
    daze_kvm_write_batch_revoke(machine);
    switch (kind) {
    case 0:
      break;
    case 1:
      machine->guest_size--;
      break;
    case 2:
      daze_write_u32(guest + 0x5840, 0);
      break;
    case 3:
      daze_write_u16(guest + 0x2a42, 1);
      break;
    case 4:
      daze_write_u16(record + 16, 0x10);
      break;
    case 5:
      daze_write_u16(record, 0x3f00);
      break;
    case 6:
      daze_write_u16(reply + 14, 1);
      break;
    case 7:
      daze_write_u16(reply, 2);
      break;
    case 8:
      daze_write_u16(record + 4, 0);
      daze_write_u16(reply, 0);
      break;
    case 9:
      files->handles->buffered_writes = 0;
      break;
    case 10:
      fail_regs = 1;
      break;
    case 11:
      fail_sregs = 1;
      break;
    case 12:
      special.cr0 = 1;
      break;
    case 13:
      registers.rflags |= 0x100;
      break;
    case 14:
      special.cs.db = 1;
      break;
    case 15:
      special.cs.limit = 1;
      break;
    case 16:
      special.ds.unusable = 1;
      break;
    case 17:
      special.ds.present = 0;
      break;
    case 18:
      special.ds.s = 0;
      break;
    case 19:
      special.ds.type = 1;
      break;
    case 20:
      special.ds.dpl = 3;
      break;
    case 21:
      special.ds.db = 1;
      break;
    case 22:
      special.ds.g = 1;
      break;
    case 23:
      special.ds.l = 1;
      break;
    case 24:
      special.ds.avl = 1;
      break;
    case 25:
      special.ds.limit = 1;
      break;
    case 26:
      special.ds.base++;
      break;
    case 27:
      special.es.db = 1;
      break;
    case 28:
      special.ss.db = 1;
      break;
    case 29:
      registers.rsp = 3;
      break;
    case 30:
      registers.rsp = 0x10000;
      break;
    case 31:
      special.ss.selector = 0;
      special.ss.base = 0;
      registers.rsp = 100;
      break;
    case 32:
      machine->write_batch_installed = 0;
      special.cs.base++;
      break;
    case 33:
      machine->write_batch_installed = 0;
      registers.rip++;
      break;
    case 34:
      machine->write_batch_installed = 0;
      guest[0x3000] = 0;
      break;
    case 35:
      daze_write_u16(guest + 0x7804, 1);
      break;
    case 36:
      daze_kvm_write_batch_arm(NULL, files, record, reply);
      continue;
    case 37:
      daze_kvm_write_batch_arm(machine, NULL, record, reply);
      continue;
    case 38:
      daze_kvm_write_batch_arm(machine, files, NULL, reply);
      continue;
    case 39:
      daze_kvm_write_batch_arm(machine, files, record, NULL);
      continue;
    case 40:
      daze_write_u16(record + 2, 256);
      break;
    }
    daze_kvm_write_batch_arm(machine, files, record, reply);
    assert((machine->write_batch_credit != 0) == (kind == 0));
    if (kind == 0) {
      assert(machine->write_batch_installed && guest[0x3000] == 0xeb && guest[0x3001] == 5);
      assert(guest[0x3003] == 0xe6 && guest[0x3004] == 0xf4 && guest[0x3005] == 0x58);
    }
    special = saved;
    registers = saved_regs;
    fail_regs = fail_sregs = 0;
    machine->guest_size = k_memory_size;
    machine->write_batch_installed = 1;
    files->handles->buffered_writes = 1;
    daze_write_u32(guest + 0x5840, 1);
    daze_write_u16(guest + 0x2a42, 0);
    daze_write_u16(record, 0x4000);
    daze_write_u16(record + 2, handle);
    daze_write_u16(record + 4, 3);
    daze_write_u16(record + 16, 0x21);
    daze_write_u16(reply, 3);
    daze_write_u16(reply + 14, 0);
    daze_write_u16(guest + 0x7804, 0);
    memcpy(guest + 0x3000, gate, sizeof(gate));
  }
}
#endif

static void pending(DazeKvmMachine *machine, uint16_t handle) {
  uint8_t *control = (uint8_t *)machine->guest + k_kvm_write_batch_control;
  machine->write_batch_installed = 1;
  machine->write_batch_credit = 16;
  machine->write_batch_handle = handle;
  daze_write_u16(control + 2, handle);
  daze_write_u16(control + 4, 4);
  daze_write_u16(control + 6, 16);
  daze_write_u32(control + 8, 2);
  daze_write_u32(control + 12, 4);
  memcpy((uint8_t *)machine->guest + k_kvm_write_batch_data, "abcd", 4);
}

int main(void) {
  assert(unsetenv("DAZE_BUFFERED_WRITES") == 0);
  char directory[] = "/tmp/daze-write-batch-XXXXXX";
  assert(mkdtemp(directory));
  int root = open(directory, O_RDONLY | O_DIRECTORY);
  assert(root >= 0);
  DazeDosfsMounts mounts;
  daze_dosfs_mounts_init(&mounts);
  assert(daze_dosfs_mounts_add_named(&mounts, 2, root, 0) == DAZE_DOSFS_OK);
  DazeDosfsHandles handles;
  daze_dosfs_handles_init(&handles);
  DazeRunMetrics metrics = {.enabled = 1};
  DazeDosfsFileService files;
  daze_dosfs_file_service_init(&files, &mounts, &handles);
  files.run_metrics = &metrics;
  DazeDosfsFileResult file;
  daze_dosfs_file_create(&files, "OUT.BIN", &file);
  assert(file.success);
  uint16_t handle = file.handle;
  DazeKvmMachine machine = {.guest = calloc(1, k_memory_size), .guest_size = k_memory_size};
  assert(machine.guest);
#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
  arm_contract(&machine, &files, handle);
#endif
  assert(daze_kvm_write_batch_drain(NULL, NULL));
  machine.write_batch_installed = 0;
  assert(daze_kvm_write_batch_drain(&machine, NULL));
  machine.write_batch_installed = 1;
  machine.guest_size = 1;
  assert(!daze_kvm_write_batch_drain(&machine, &files));
  machine.guest_size = k_memory_size;
  for (unsigned kind = 0; kind < 11; ++kind) {
    pending(&machine, handle);
    uint8_t *control = (uint8_t *)machine.guest + k_kvm_write_batch_control;
    switch (kind) {
    case 0:
      break;
    case 1:
      daze_write_u16(control + 4, 0);
      break;
    case 2:
      daze_write_u32(control + 8, 0);
      break;
    case 3:
      daze_write_u32(control + 8, 5);
      break;
    case 4:
      machine.write_batch_credit = 3;
      break;
    case 5:
      daze_write_u16(control + 2, handle + 1);
      break;
    case 6:
      daze_write_u16(control + 6, 15);
      break;
    case 7:
      daze_write_u32(control + 12, 5);
      break;
    case 8:
      handles.buffered_writes = 0;
      break;
    case 9:
      assert(!daze_kvm_write_batch_drain(&machine, NULL));
      continue;
    case 10:
      files.handles = NULL;
      break;
    }
    assert(daze_kvm_write_batch_pending(&machine));
    assert(daze_kvm_write_batch_drain(&machine, &files) == (kind == 0));
    assert(machine.write_batch_credit == 0);
    files.handles = &handles;
    handles.buffered_writes = 1;
    handles.teardown_errno = 0;
  }
  memset((uint8_t *)machine.guest + k_kvm_write_batch_control, 0, 0x40);
  assert(daze_kvm_write_batch_drain(&machine, &files));
  assert(metrics.kvm_guest_write_calls == 2 && metrics.kvm_guest_write_bytes == 4);
  assert(metrics.write_calls == 2 && metrics.write_bytes == 4);
  int fd;
  assert(daze_dosfs_handles_peek(&handles, handle, &fd) == DAZE_DOSFS_OK);
  struct stat info;
  assert(fstat(fd, &info) == 0 && info.st_size == 0);
  assert(daze_dosfs_handles_write_credit(NULL, 0) == 0);
  assert(daze_dosfs_handles_write_credit(&handles, 256) == 0);
  assert(daze_dosfs_handles_write_credit(&handles, 4) == 0);
  assert(!daze_dosfs_handles_append_buffered(&handles, handle, NULL, 1));
  assert(!daze_dosfs_handles_append_buffered(&handles, handle, (const uint8_t *)"x", 0));
  assert(!daze_dosfs_handles_append_buffered(&handles, handle, (const uint8_t *)"x", 16384));
  pending(&machine, handle);
  metrics.enabled = 0;
  assert(daze_kvm_write_batch_drain(&machine, &files));
  assert(metrics.kvm_guest_write_calls == 2);
  assert(daze_dosfs_handles_flush_and_get(&handles, handle, &fd) == DAZE_DOSFS_OK);
  char bytes[8];
  assert(pread(fd, bytes, sizeof(bytes), 0) == sizeof(bytes));
  assert(memcmp(bytes, "abcdabcd", sizeof(bytes)) == 0);
  daze_dosfs_file_open(&files, "OUT.BIN", 0, &file);
  assert(file.success && daze_dosfs_handles_write_credit(&handles, handle) == 0);
  daze_dosfs_handles_close_all(&handles);
  free(machine.guest);
  assert(unlinkat(root, "OUT.BIN", 0) == 0);
  assert(close(root) == 0 && rmdir(directory) == 0);
  return 0;
}
