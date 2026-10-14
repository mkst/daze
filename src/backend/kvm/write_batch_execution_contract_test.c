#define _GNU_SOURCE
#include "write_batch.h"
#include "runner_private.h"
#include "runner_resume.h"
#include "rm_entry.h"
#include "machine_access.h"

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
#include <sys/ioctl.h>
static DazeKvmMachine *observed;
#define CHECK(c)                                                                                   \
  do {                                                                                             \
    if (!(c)) {                                                                                    \
      DazeKvmMachineExitObservation exit = {0};                                                    \
      daze_kvm_machine_capture_exit(observed, &exit);                                              \
      fprintf(stderr,                                                                              \
              "write batch CPU failed line=%d raw=%u cs:ip=%04x:%llx ax=%llx ss:sp=%04x:%llx\n",   \
              __LINE__, exit.exit_reason, exit.cs, (unsigned long long)exit.rip,                   \
              (unsigned long long)exit.rax, exit.ss, (unsigned long long)exit.rsp);                \
      abort();                                                                                     \
    }                                                                                              \
  } while (0)

typedef struct {
  struct kvm_regs regs;
  struct kvm_sregs segments;
} State;

static int execute(DazeDosfsFileService *files, uint16_t handle, int batch, unsigned kind,
                   State *state) {
  DazeKvmMachine machine;
  int status = daze_kvm_machine_init(&machine, k_memory_size);
  if (status == DAZE_KVM_MACHINE_UNAVAILABLE) return 77;
  observed = &machine;
  CHECK(status == DAZE_KVM_MACHINE_OK);
  const uint8_t program[] = {
    0xcd, 0x21, /* int 21h */
    0xb4, 0x40, /* mov ah,40h */
    0xcd, 0x21, /* int 21h */
    0xe6, 0xef, /* out efh,al */
    0xf4,       /* hlt */
  };
  const uint8_t gate[] = {
    0x50,       /* push ax */
    0xb0, 0x21, /* mov al,21h */
    0xe6, 0xf4, /* out f4h,al */
    0x58,       /* pop ax */
    0xcf,       /* iret */
  };
  const uint8_t ivt[] = {0, 0, 0, 3};
  CHECK(daze_kvm_machine_write(&machine, 0x10000, program, sizeof(program)));
  const uint16_t source_ds = kind == 3 ? 0x800 : 0x1000;
  const uint16_t source_dx = kind == 2 ? 0xfffe : kind == 3 ? 0 : 0x100;
  CHECK(daze_kvm_machine_write(&machine, (uint32_t)source_ds * 16 + source_dx, "abc", 3));
  CHECK(daze_kvm_machine_write(&machine, 0x3000, gate, sizeof(gate)));
  CHECK(daze_kvm_machine_write(&machine, 0x21 * 4, ivt, sizeof(ivt)));
  CHECK(daze_kvm_machine_set_real_mode(&machine, 0x1000, 0, 0x1100, 0xff00, source_ds, 0x1200) ==
        DAZE_KVM_MACHINE_OK);
  struct kvm_regs regs = {.rip = 0,
                          .rsp = 0xff00,
                          .rflags = 0x447,
                          .rax = 0x12344077,
                          .rbx = 0x77770000u | handle,
                          .rcx = 0x22220003,
                          .rdx = 0x33330000u | source_dx,
                          .rsi = 0x44441111,
                          .rdi = 0x55552222,
                          .rbp = 0x66663333};
  CHECK(daze_kvm_machine_set_regs(&machine, &regs) == DAZE_KVM_MACHINE_OK);
  uint8_t *guest = machine.guest;
  daze_write_u32(guest + 0x5868, DAZE_KVM_RM_ENTRY_SIGNATURE);
  daze_write_u32(guest + 0x5840, batch);
  DazeDosProcessState process = {0};
  unsigned hosted = 0;
  for (;;) {
    DazeKvmPortAccess port;
    CHECK(daze_kvm_machine_run_port_access(&machine, &port) == DAZE_KVM_MACHINE_OK);
    if (port.port == 0xef) break;
    CHECK(port.port == 0xf4 && port.value == 0x21 && hosted < 2);
    DazeKvmRunnerGateFrame frame;
    CHECK(daze_kvm_runner_gate_frame_capture(&machine, 0x21, &frame) ==
          DAZE_KVM_RUNNER_GATE_RESUME_OK);
    uint8_t record[24] = {0}, reply[16] = {0};
    const uint16_t values[] = {frame.ax, frame.bx,        frame.cx,        frame.dx,
                               frame.ds, frame.es,        frame.si,        frame.di,
                               0x21,     frame.return_ip, frame.return_cs, frame.flags};
    for (unsigned i = 0; i < 12; ++i)
      daze_write_u16(record + 2 * i, values[i]);
    CHECK(daze_kvm_preflight_boundary_broker(&machine, files, &process, NULL, 0x200, record, reply,
                                             NULL) == DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED);
    CHECK(daze_kvm_runner_gate_frame_reply(&machine, &frame, reply) ==
          DAZE_KVM_RUNNER_GATE_RESUME_OK);
    if (batch && kind == 1 && hosted == 0) {
      machine.write_batch_credit = 1;
      daze_write_u16(guest + k_kvm_write_batch_control + 6, 1);
    }
    hosted++;
  }
  CHECK(hosted == (batch && kind == 0 ? 1 : 2));
  /* Retire the terminal OUT before capturing a checkpoint. */
  CHECK(ioctl(machine.vcpu, KVM_RUN, 0) == 0);
  CHECK(((const struct kvm_run *)machine.run)->exit_reason == KVM_EXIT_HLT);
  CHECK(daze_kvm_machine_sync_refresh(&machine) == DAZE_KVM_MACHINE_OK);
  CHECK(daze_kvm_write_batch_pending(&machine) == (batch && kind == 0));
  if (batch && kind == 0) {
    DazeKvmMachineSnapshot snapshot = {0};
    CHECK(daze_kvm_machine_snapshot_take(&machine, &snapshot) == DAZE_KVM_MACHINE_INVALID);
  }
  CHECK(daze_kvm_machine_get_regs(&machine, &state->regs) == DAZE_KVM_MACHINE_OK);
  CHECK(daze_kvm_machine_get_sregs(&machine, &state->segments) == DAZE_KVM_MACHINE_OK);
  CHECK(daze_kvm_write_batch_drain(&machine, files));
  CHECK(!daze_kvm_write_batch_pending(&machine));
  DazeKvmMachineSnapshot snapshot = {0};
  CHECK(daze_kvm_machine_snapshot_take(&machine, &snapshot) == DAZE_KVM_MACHINE_OK);
  CHECK(daze_kvm_machine_snapshot_restore(&machine, &snapshot) == DAZE_KVM_MACHINE_OK);
  CHECK(machine.write_batch_installed == batch && machine.write_batch_credit == 0);
  daze_kvm_machine_snapshot_dispose(&snapshot);
  daze_dos_process_state_dispose(&process);
  daze_kvm_machine_destroy(&machine);
  return 0;
}
#endif

int main(void) {
#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
  assert(unsetenv("DAZE_BUFFERED_WRITES") == 0);
  char directory[] = "/tmp/daze-write-batch-cpu-XXXXXX";
  assert(mkdtemp(directory));
  int root = open(directory, O_RDONLY | O_DIRECTORY);
  assert(root >= 0);
  DazeDosfsMounts mounts;
  daze_dosfs_mounts_init(&mounts);
  assert(daze_dosfs_mounts_add_named(&mounts, 2, root, 0) == DAZE_DOSFS_OK);
  DazeDosfsHandles handles;
  daze_dosfs_handles_init(&handles);
  DazeDosfsFileService files;
  daze_dosfs_file_service_init(&files, &mounts, &handles);
  int outcome = 0;
  for (unsigned kind = 0; kind < 4 && outcome != 77; ++kind) {
    State states[2] = {0};
    for (int batch = 0; batch < 2; ++batch) {
      DazeDosfsFileResult file;
      daze_dosfs_file_create(&files, "OUT.BIN", &file);
      assert(file.success);
      outcome = execute(&files, file.handle, batch, kind, &states[batch]);
      if (outcome == 77) break;
      int fd;
      assert(daze_dosfs_handles_get(&handles, file.handle, &fd) == DAZE_DOSFS_OK);
      char bytes[6];
      assert(pread(fd, bytes, sizeof(bytes), 0) == sizeof(bytes));
      assert(memcmp(bytes, "abcabc", sizeof(bytes)) == 0);
      assert(daze_dosfs_handles_close(&handles, file.handle, NULL) == DAZE_DOSFS_OK);
    }
    if (outcome != 77) {
      const struct kvm_regs *a = &states[0].regs, *b = &states[1].regs;
      assert(a->rax == b->rax && b->rax == 0x12340003 && a->rbx == b->rbx && a->rcx == b->rcx &&
             a->rdx == b->rdx && a->rsi == b->rsi && a->rdi == b->rdi && a->rbp == b->rbp &&
             a->rsp == b->rsp && a->rflags == b->rflags && !(b->rflags & 1));
      const struct kvm_sregs *x = &states[0].segments, *y = &states[1].segments;
      assert(
        memcmp(&x->ds, &y->ds, sizeof(x->ds)) == 0 && memcmp(&x->es, &y->es, sizeof(x->es)) == 0 &&
        memcmp(&x->ss, &y->ss, sizeof(x->ss)) == 0 && memcmp(&x->fs, &y->fs, sizeof(x->fs)) == 0 &&
        memcmp(&x->gs, &y->gs, sizeof(x->gs)) == 0);
    }
  }
  daze_dosfs_handles_close_all(&handles);
  assert(unlinkat(root, "OUT.BIN", 0) == 0);
  assert(close(root) == 0 && rmdir(directory) == 0);
  return outcome;
#else
  return 77;
#endif
}
