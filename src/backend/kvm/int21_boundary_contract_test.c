#include "int21_adapter.c"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

#define CHECK(c)                                                                                   \
  do {                                                                                             \
    if (!(c)) {                                                                                    \
      fprintf(stderr, "KVM DOS boundary failed at %d\n", __LINE__);                                \
      abort();                                                                                     \
    }                                                                                              \
  } while (0)

static int cpu_translation(void) {
#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
  DazeKvmMachine machine;
  int status = daze_kvm_machine_init(&machine, 0x8000);
  if (status == DAZE_KVM_MACHINE_UNAVAILABLE) return 77;
  CHECK(status == DAZE_KVM_MACHINE_OK);
  struct kvm_sregs sregs;
  CHECK(ioctl(machine.vcpu, KVM_GET_SREGS, &sregs) == 0);
  sregs.cr0 = 0x11;
  sregs.ds = (struct kvm_segment){
    .selector = 0x84, .base = 0x3000, .limit = 0xffff, .present = 1, .s = 1, .type = 3};
  sregs.es = (struct kvm_segment){
    .selector = 0x8c, .base = 0x4000, .limit = 0xffff, .present = 1, .s = 1, .type = 3};
  CHECK(ioctl(machine.vcpu, KVM_SET_SREGS, &sregs) == 0);
  uint8_t *guest = machine.guest;
  memset(guest, 0xa5, machine.guest_size);
  memcpy(guest + 0x3020, "FILE.TXT", 9);
  DazeDosfsFileService files = {0};
  uint8_t record[24] = {0}, mailbox[16];
  daze_write_u16(record, 0x2900);
  daze_write_u16(record + 8, 0x84);
  daze_write_u16(record + 10, 0x8c);
  daze_write_u16(record + 12, 0x20);
  daze_write_u16(record + 14, 0x20);
  daze_write_u16(record + 16, 0x21);
  daze_write_u16(record + 22, 0x203);
  CHECK(daze_kvm_int21_dispatch(&machine, &files, NULL, NULL, record, mailbox, NULL) ==
        DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED);
  CHECK(daze_read_u16(mailbox) == 0x2900 && daze_read_u16(mailbox + 8) == 0x28);
  CHECK(daze_read_u16(mailbox + 14) == 0x202 && guest[0x4020] == 0 &&
        memcmp(guest + 0x4021, "FILE    TXT", 11) == 0);
  CHECK(guest[0x860] == 0xa5 && guest[0x8e0] == 0xa5);
  daze_write_u16(record + 8, 0x94);
  CHECK(daze_kvm_int21_dispatch(&machine, &files, NULL, NULL, record, mailbox, NULL) ==
        DAZE_KVM_PREFLIGHT_BOUNDARY_FAILED);
  CHECK(guest[0x4020] == 0 && guest[0x4021] == 'F');
  daze_write_u16(record + 8, 0x84);
  sregs.es.base = 0x7ff0;
  CHECK(ioctl(machine.vcpu, KVM_SET_SREGS, &sregs) == 0);
  CHECK(daze_kvm_int21_dispatch(&machine, &files, NULL, NULL, record, mailbox, NULL) ==
        DAZE_KVM_PREFLIGHT_BOUNDARY_FAILED);
  CHECK(guest[0x7fff] == 0xa5);
  daze_kvm_machine_destroy(&machine);
  return 0;
#else
  return 77;
#endif
}

int main(int argc, char **argv) {
  if (argc == 2 && strcmp(argv[1], "--kvm") == 0) return cpu_translation();
  uint8_t guest[0x8000] = {0}, record[24] = {0}, mailbox[16];
  DazeKvmMachine machine = {.guest = guest, .guest_size = sizeof(guest), .vcpu = -1};
  DazeInt21KvmGuestMemory memory = {.machine = &machine};
  uint32_t address = 0xabcdef;
  CHECK(!int21_kvm_guest_address(NULL, 0, 0, 1, &address));
  CHECK(address == 0xabcdef);
  DazeInt21KvmGuestMemory invalid = {0};
  CHECK(!int21_kvm_guest_address(&invalid, 0, 0, 1, &address));
  machine.guest = NULL;
  CHECK(!int21_kvm_guest_address(&memory, 0, 0, 1, &address));
  machine.guest = guest;
  CHECK(!int21_kvm_guest_address(&memory, 0, 0, 1, NULL));
  CHECK(int21_kvm_guest_address(&memory, 0x123, 4, 2, &address) && address == 0x1234);
  CHECK(!int21_kvm_guest_address(&memory, 0x800, 0, 1, &address));
  CHECK(address == 0x1234);
#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
  memory.sregs.cr0 = 1;
  struct kvm_segment *segments[] = {&memory.sregs.ds, &memory.sregs.es, &memory.sregs.fs,
                                    &memory.sregs.gs, &memory.sregs.ss, &memory.sregs.cs};
  for (size_t i = 0; i < 6; ++i) {
    segments[i]->selector = 0x84 + i * 8;
    segments[i]->base = 0x2000 + i * 0x100;
    CHECK(int21_kvm_guest_address(&memory, segments[i]->selector, 0x20, 2, &address));
    CHECK(address == 0x2020 + i * 0x100);
  }
  CHECK(!int21_kvm_guest_address(&memory, 0x234, 0, 1, &address));
  CHECK(int21_kvm_guest_address(&memory, k_dos_int21_vector_segment, 1, 1, &address));
  CHECK(address == ((uint32_t)k_dos_int21_vector_segment << 4) + 1);
  CHECK(int21_kvm_guest_address(&memory, 0x600, 1, 1, &address) && address == 0x6001);
  memory.sregs.ds.base = UINT64_C(0x100000000);
  CHECK(!int21_kvm_guest_address(&memory, 0x84, 0, 1, &address));
  memory.sregs.ds.base = UINT32_MAX;
  CHECK(!int21_kvm_guest_address(&memory, 0x84, 1, 1, &address));
  memory.sregs.ds.base = sizeof(guest) - 2;
  const uint8_t payload[] = {0x12, 0x34};
  CHECK(int21_kvm_guest_write(&memory, 0x84, 0, payload, 2));
  uint8_t copied[2] = {0};
  CHECK(int21_kvm_guest_read(&memory, 0x84, 0, copied, 2));
  CHECK(memcmp(copied, payload, 2) == 0);
  CHECK(!int21_kvm_guest_write(&memory, 0x84, 1, payload, 2));
  CHECK(guest[sizeof(guest) - 2] == 0x12 && guest[sizeof(guest) - 1] == 0x34);
#endif

  DazeDosInt21Result reply = {.register_write_mask = DAZE_DOS_INT21_REG_AX | DAZE_DOS_INT21_REG_BX |
                                                     DAZE_DOS_INT21_REG_CX | DAZE_DOS_INT21_REG_DX |
                                                     DAZE_DOS_INT21_REG_SI | DAZE_DOS_INT21_REG_DI |
                                                     DAZE_DOS_INT21_REG_ES,
                              .ax = 0x1111,
                              .bx = 0x2222,
                              .cx = 0x3333,
                              .dx = 0x4444,
                              .si = 0x5555,
                              .di = 0x6666,
                              .es = 0x7777,
                              .flag_write_mask = 0x41,
                              .flag_values = 0x40};
  memset(mailbox, 0xa5, sizeof(mailbox));
  CHECK(apply_int21_result_to_mailbox(mailbox, &reply));
  const uint16_t expected[] = {0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0x7777, 0xa5e4};
  for (size_t i = 0; i < 8; ++i)
    CHECK(daze_read_u16(mailbox + i * 2) == expected[i]);
  uint8_t before[16];
  memcpy(before, mailbox, 16);
  reply = (DazeDosInt21Result){.register_write_mask = DAZE_DOS_INT21_REG_DS, .ds = 0x600};
  CHECK(!apply_int21_result_to_mailbox(mailbox, &reply));
  CHECK(memcmp(before, mailbox, 16) == 0);
  DazeKvmPreflightBoundaryResult accounting = {.copied_byte_count = 0xabcd};
  DazeInt21KvmTransferContext transfer = {.accounting = &accounting};
  DazeDosInt21Request request = {.ax = 0x4000};
  DazeDosfsFileResult file = {.byte_count = 0x123};
  int21_kvm_transfer_completed(NULL, &request, &file);
  DazeInt21KvmTransferContext empty = {0};
  int21_kvm_transfer_completed(&empty, &request, &file);
  int21_kvm_transfer_completed(&transfer, NULL, &file);
  int21_kvm_transfer_completed(&transfer, &request, NULL);
  CHECK(accounting.copied_byte_count == 0xabcd);
  int21_kvm_transfer_completed(&transfer, &request, &file);
  CHECK(accounting.copied_byte_count == 0x123);
  request.ax = 0x3000;
  file.byte_count = 1;
  int21_kvm_transfer_completed(&transfer, &request, &file);
  CHECK(accounting.copied_byte_count == 0x123);

  DazeDosfsHandles handles;
  daze_dosfs_handles_init(&handles);
  DazeDosfsFileService files = {.handles = &handles};
  DazeDosProcessState process;
  daze_dos_process_state_init(&process, 0x100);
  daze_write_u16(record + 16, 0x21);
  for (int kind = 0; kind < 5; ++kind) {
    memset(mailbox, 0xa5, sizeof(mailbox));
    if (kind == 4) machine.guest = NULL;
    CHECK(daze_kvm_int21_dispatch(kind == 0 ? NULL : &machine, kind == 1 ? NULL : &files, &process,
                                  NULL, kind == 2 ? NULL : record, kind == 3 ? NULL : mailbox,
                                  &accounting) == DAZE_KVM_PREFLIGHT_BOUNDARY_FAILED);
    CHECK(accounting.file_handle == 0 && !accounting.reply_ds_present && mailbox[0] == 0xa5);
    machine.guest = guest;
  }
  DazeDosfsMounts mounts;
  daze_dosfs_mounts_init(&mounts);
  files.mounts = &mounts;
  daze_write_u16(record, 0x4300);
  daze_write_u16(record + 6, 0);
  daze_write_u16(record + 8, 0x0800);
  CHECK(daze_kvm_int21_dispatch(&machine, &files, &process, NULL, record, mailbox, NULL) ==
        DAZE_KVM_PREFLIGHT_BOUNDARY_FAILED);
  daze_write_u16(record, 0x4302);
  CHECK(daze_kvm_int21_dispatch(&machine, &files, &process, NULL, record, mailbox, NULL) ==
        DAZE_KVM_PREFLIGHT_BOUNDARY_UNSUPPORTED);
  files.mounts = NULL;
  daze_write_u16(record + 16, 0x2f);
  CHECK(daze_kvm_int21_dispatch(&machine, &files, &process, NULL, record, mailbox, NULL) ==
        DAZE_KVM_PREFLIGHT_BOUNDARY_UNSUPPORTED);
  daze_write_u16(record + 16, 0x21);
  daze_write_u16(record, 0x3500);
  CHECK(daze_kvm_int21_dispatch(&machine, &files, NULL, NULL, record, mailbox, NULL) ==
        DAZE_KVM_PREFLIGHT_BOUNDARY_FAILED);
  daze_write_u16(record, 0x25ff);
  CHECK(daze_kvm_int21_dispatch(&machine, &files, NULL, NULL, record, mailbox, NULL) ==
        DAZE_KVM_PREFLIGHT_BOUNDARY_FAILED);
  machine.guest_size = 0x3ff;
  DazeDosProcessState process_before = process;
  uint8_t ivt_before[4];
  memcpy(ivt_before, guest + 0x3fc, 4);
  CHECK(daze_kvm_int21_dispatch(&machine, &files, &process, NULL, record, mailbox, NULL) ==
        DAZE_KVM_PREFLIGHT_BOUNDARY_FAILED);
  CHECK(memcmp(&process, &process_before, sizeof(process)) == 0 &&
        memcmp(ivt_before, guest + 0x3fc, 4) == 0);
  machine.guest_size = sizeof(guest);
  daze_write_u16(record, 0x4302);
  CHECK(daze_kvm_int21_dispatch(&machine, &files, &process, NULL, record, mailbox, NULL) ==
        DAZE_KVM_PREFLIGHT_BOUNDARY_UNSUPPORTED);
  daze_write_u16(record, 0x6300);
  CHECK(daze_kvm_int21_dispatch(&machine, &files, &process, NULL, record, mailbox, NULL) ==
        DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED);
  daze_write_u16(record, 0x3000);
  CHECK(dispatch_shared_int21_reply(NULL, &files, &process, NULL, record, mailbox, NULL) == -1);
  machine.vcpu = INT_MAX;
  machine.run = guest;
  memcpy(before, mailbox, 16);
  CHECK(daze_kvm_int21_dispatch(&machine, &files, &process, NULL, record, mailbox, NULL) ==
        DAZE_KVM_PREFLIGHT_BOUNDARY_FAILED);
  CHECK(memcmp(before, mailbox, 16) !=
        0); /* The adapter initializes captured caller fields before dispatch. */
  daze_dos_process_state_dispose(&process);
  puts("KVM DOS adapter boundary: passed");
  return 0;
}
