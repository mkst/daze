#include "runner_private.h"

#include "date.h"
#include "kvm_bytes.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void) {
  char mount_template[] = "/tmp/daze-broker-attrs-XXXXXX";
  if (mkdtemp(mount_template) == NULL) return 1;
  {
    char mount_file[128];
    snprintf(mount_file, sizeof(mount_file), "%s/PLAIN.TXT", mount_template);
    const int mount_plain_fd = open(mount_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (mount_plain_fd < 0) return 1;
    close(mount_plain_fd);
    snprintf(mount_file, sizeof(mount_file), "%s/SUBDIR", mount_template);
    if (mkdir(mount_file, 0755) != 0) return 1;
    snprintf(mount_file, sizeof(mount_file), "%s/SHORT.BIN", mount_template);
    const int mount_short_fd = open(mount_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (mount_short_fd < 0 || write(mount_short_fd, "abc", 3) != 3) return 1;
    close(mount_short_fd);
  }
  const int mount_fd = open(mount_template, O_RDONLY | O_DIRECTORY);
  if (mount_fd < 0) return 1;
  DazeDosfsMounts mounts;
  daze_dosfs_mounts_init(&mounts);
  int drive_index = -1;
  if (daze_dosfs_mounts_add_default(&mounts, mount_fd, 0, &drive_index) != DAZE_DOSFS_OK) return 1;

  uint8_t guest[0x4000] = {0};
  uint8_t record[24] = {0};
  uint8_t mailbox[DAZE_KVM_RUNNER_GATE_MAILBOX_SIZE] = {0};
  DazeKvmMachine machine = {.guest = guest, .guest_size = sizeof(guest)};
  DazeDosfsHandles handles;
  daze_dosfs_handles_init(&handles);
  if (daze_dosfs_handles_bind_standard(&handles, STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO,
                                       NULL) != DAZE_DOSFS_OK)
    return 1;
  DazeDosfsFileService files = {.handles = &handles, .mounts = &mounts};
  DazeDosProcessState process_state;
  daze_dos_process_state_init(&process_state, 0x0ff0);
  DazeDosMemory dos_memory;
  daze_dos_memory_init(&dos_memory, 0x3000, 0xa000);
  DazeKvmPreflightBoundaryResult result;

  memset(record, 0, sizeof(record));
  memset(mailbox, 0xff, sizeof(mailbox));
  daze_write_u16(record, 0x0b5a);
  daze_write_u16(record + 2, 0xaaaa);
  daze_write_u16(record + 4, 0xbeef);
  daze_write_u16(record + 6, 0xdddd);
  daze_write_u16(record + 8, 0xbbbb);
  daze_write_u16(record + 10, 0xcccc);
  daze_write_u16(record + 12, 0x1111);
  daze_write_u16(record + 14, 0x2222);
  daze_write_u16(record + 16, 0x0021);
  daze_write_u16(record + 22, 0x0203);
  if (daze_kvm_preflight_boundary_broker(&machine, &files, &process_state, &dos_memory, 0x2200,
                                         record, mailbox,
                                         &result) != DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED ||
      daze_read_u16(mailbox) != 0x0b00 || daze_read_u16(mailbox + 2) != 0xaaaa ||
      daze_read_u16(mailbox + 4) != 0xbeef || daze_read_u16(mailbox + 6) != 0xdddd ||
      daze_read_u16(mailbox + 8) != 0x1111 || daze_read_u16(mailbox + 10) != 0x2222 ||
      daze_read_u16(mailbox + 12) != 0xcccc || (daze_read_u16(mailbox + 14) & 1u) != 0)
    return 1;

  /* The following DPMILOAD query returns Daze's fixed two-byte SDA through
   * DS:SI, with CX and DX both naming its exact length. */
  memset(record, 0, sizeof(record));
  memset(mailbox, 0xff, sizeof(mailbox));
  guest[0x301f] = 0xff;
  guest[0x3020] = 0xff;
  daze_write_u16(record, 0x5d06);
  daze_write_u16(record + 8, 0x1234);
  daze_write_u16(record + 12, 0x4321);
  daze_write_u16(record + 14, 0x5678);
  daze_write_u16(record + 16, 0x0021);
  daze_write_u16(record + 22, 0x0203);
  if (daze_kvm_preflight_boundary_broker(&machine, &files, &process_state, &dos_memory, 0x2200,
                                         record, mailbox,
                                         &result) != DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED ||
      guest[0x301f] != 0 || guest[0x3020] != 0 || daze_read_u16(mailbox + 4) != 2 ||
      daze_read_u16(mailbox + 6) != 2 || daze_read_u16(mailbox + 8) != 0x001f ||
      daze_read_u16(mailbox + 10) != 0x5678 || !result.reply_ds_present ||
      result.reply_ds != 0x0300 || (daze_read_u16(mailbox + 14) & 1u) != 0)
    return 1;

  /* Measured BCC 3.1 protected 5D06h request, transported through the canonical
   * 24-byte record / 16-byte reply. AX must remain absent from the write mask. */
  memset(record, 0, sizeof(record));
  memset(mailbox, 0xff, sizeof(mailbox));
  guest[0x301f] = 0xff;
  guest[0x3020] = 0xff;
  daze_write_u16(record, 0x5d06);
  daze_write_u16(record + 6, 0x005a);
  daze_write_u16(record + 8, 0x0010);
  daze_write_u16(record + 10, 0x0300);
  daze_write_u16(record + 16, 0x0021);
  daze_write_u16(record + 22, 0x0006);
  if (daze_kvm_preflight_boundary_broker(&machine, &files, &process_state, &dos_memory, 0x2200,
                                         record, mailbox,
                                         &result) != DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED ||
      guest[0x301f] != 0 || guest[0x3020] != 0 || daze_read_u16(mailbox) != 0x5d06 ||
      daze_read_u16(mailbox + 2) != 0x0000 || daze_read_u16(mailbox + 4) != 0x0002 ||
      daze_read_u16(mailbox + 6) != 0x0002 || daze_read_u16(mailbox + 8) != 0x001f ||
      daze_read_u16(mailbox + 10) != 0x0000 || daze_read_u16(mailbox + 12) != 0x0300 ||
      (daze_read_u16(mailbox + 14) & 1u) != 0 || !result.reply_ds_present ||
      result.reply_ds != 0x0300)
    return 1;

  /* DPMILOAD's first protected host-DOS call is 21h/3400h. It must use the
   * same clear InDOS byte and ES:BX return pair as the Unicorn backend. */
  memset(record, 0, sizeof(record));
  memset(mailbox, 0xff, sizeof(mailbox));
  guest[0x3020] = 0xff;
  daze_write_u16(record, 0x3400);
  daze_write_u16(record + 2, 0xaaaa);
  daze_write_u16(record + 10, 0xcccc);
  daze_write_u16(record + 16, 0x0021);
  daze_write_u16(record + 22, 0x0203);
  if (daze_kvm_preflight_boundary_broker(&machine, &files, &process_state, &dos_memory, 0x2200,
                                         record, mailbox,
                                         &result) != DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED ||
      guest[0x3020] != 0 || daze_read_u16(mailbox) != 0x3400 ||
      daze_read_u16(mailbox + 2) != 0x0020 || daze_read_u16(mailbox + 12) != 0x0300 ||
      (daze_read_u16(mailbox + 14) & 1u) != 0)
    return 1;

  /* BCC 3.1's initial unclaimed INT 2Fh/FB43h probe returns every register
   * and flags word exactly as supplied. */
  memset(record, 0, sizeof(record));
  memset(mailbox, 0xff, sizeof(mailbox));
  daze_write_u16(record, 0xfb43);
  daze_write_u16(record + 2, 0x0100);
  daze_write_u16(record + 4, 0xbeef);
  daze_write_u16(record + 6, 0xdddd);
  daze_write_u16(record + 10, 0xcccc);
  daze_write_u16(record + 12, 0x1111);
  daze_write_u16(record + 14, 0x2222);
  daze_write_u16(record + 16, 0x002f);
  daze_write_u16(record + 22, 0x0203);
  if (daze_kvm_preflight_boundary_broker(&machine, &files, &process_state, &dos_memory, 0x2200,
                                         record, mailbox,
                                         &result) != DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED ||
      daze_read_u16(mailbox) != 0xfb43 || daze_read_u16(mailbox + 2) != 0x0100 ||
      daze_read_u16(mailbox + 4) != 0xbeef || daze_read_u16(mailbox + 6) != 0xdddd ||
      daze_read_u16(mailbox + 8) != 0x1111 || daze_read_u16(mailbox + 10) != 0x2222 ||
      daze_read_u16(mailbox + 12) != 0xcccc || daze_read_u16(mailbox + 14) != 0x0203)
    return 1;

  /* BCC's BOSS stub must see DPMILOAD as not resident. Its documented reply
   * changes only BX to one; every other returned mailbox word is preserved. */
  memset(record, 0, sizeof(record));
  memset(mailbox, 0xff, sizeof(mailbox));
  daze_write_u16(record, 0xfb42);
  daze_write_u16(record + 2, 0x0014);
  daze_write_u16(record + 4, 0x0001);
  daze_write_u16(record + 6, 0xdddd);
  daze_write_u16(record + 10, 0xcccc);
  daze_write_u16(record + 12, 0x1111);
  daze_write_u16(record + 14, 0x2222);
  daze_write_u16(record + 16, 0x002f);
  daze_write_u16(record + 22, 0x0203);
  if (daze_kvm_preflight_boundary_broker(&machine, &files, &process_state, &dos_memory, 0x2200,
                                         record, mailbox,
                                         &result) != DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED ||
      daze_read_u16(mailbox) != 0xfb42 || daze_read_u16(mailbox + 2) != 1 ||
      daze_read_u16(mailbox + 4) != 0x0001 || daze_read_u16(mailbox + 6) != 0xdddd ||
      daze_read_u16(mailbox + 8) != 0x1111 || daze_read_u16(mailbox + 10) != 0x2222 ||
      daze_read_u16(mailbox + 12) != 0xcccc || daze_read_u16(mailbox + 14) != 0x0203)
    return 1;

  /* A restored EXEC parent observes its child's 4Ch status once through the
   * ordinary DOS boundary broker. A second 4Dh sees no pending child. */
  daze_dos_process_state_record_child_termination(&process_state, 1, 0);
  memset(record, 0, sizeof(record));
  memset(mailbox, 0xff, sizeof(mailbox));
  daze_write_u16(record, 0x4d00);
  daze_write_u16(record + 2, 0xaaaa);
  daze_write_u16(record + 16, 0x0021);
  daze_write_u16(record + 22, 0x0203);
  if (daze_kvm_preflight_boundary_broker(&machine, &files, &process_state, &dos_memory, 0x2200,
                                         record, mailbox,
                                         &result) != DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED ||
      daze_read_u16(mailbox) != 0x0001 || daze_read_u16(mailbox + 2) != 0xaaaa ||
      (daze_read_u16(mailbox + 14) & 1u) != 0)
    return 1;
  memset(mailbox, 0xff, sizeof(mailbox));
  if (daze_kvm_preflight_boundary_broker(&machine, &files, &process_state, &dos_memory, 0x2200,
                                         record, mailbox,
                                         &result) != DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED ||
      daze_read_u16(mailbox) != 0 || (daze_read_u16(mailbox + 14) & 1u) != 0)
    return 1;

  /* Delete success must preserve the request's nonzero AL. */
  {
    char delete_file[128];
    snprintf(delete_file, sizeof(delete_file), "%s/DELETE.ME", mount_template);
    const int delete_fd = open(delete_file, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (delete_fd < 0) return 1;
    close(delete_fd);
    memcpy(guest + 0x1000, "DELETE.ME", sizeof("DELETE.ME"));
    memset(record, 0, sizeof(record));
    memset(mailbox, 0xff, sizeof(mailbox));
    daze_write_u16(record, 0x41c0);
    daze_write_u16(record + 2, 0xaaaa);
    daze_write_u16(record + 8, 0x0100);
    daze_write_u16(record + 16, 0x0021);
    daze_write_u16(record + 22, 0x0203);
    if (daze_kvm_preflight_boundary_broker(&machine, &files, &process_state, &dos_memory, 0x2200,
                                           record, mailbox,
                                           &result) != DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED ||
        daze_read_u16(mailbox) != 0x41c0 || daze_read_u16(mailbox + 2) != 0xaaaa ||
        (daze_read_u16(mailbox + 14) & 1u) != 0 || access(delete_file, F_OK) == 0)
      return 1;
  }

  /* CPP's GO32 EXEC parameter block uses this standard FCB at ES:DI. */
  {
    const uint8_t expected_fcb[16] = {3,   'G', 'O', '3', '2', ' ', ' ', ' ',
                                      ' ', 'E', 'X', 'E', ' ', ' ', ' ', ' '};
    memcpy(guest + 0x1000, "C:\\GO32.EXE", sizeof("C:\\GO32.EXE"));
    memset(record, 0, sizeof(record));
    memset(mailbox, 0xff, sizeof(mailbox));
    daze_write_u16(record, 0x2901);
    daze_write_u16(record + 2, 0xaaaa);
    daze_write_u16(record + 8, 0x0100);
    daze_write_u16(record + 10, 0x0200);
    daze_write_u16(record + 12, 0x0000);
    daze_write_u16(record + 14, 0x0020);
    daze_write_u16(record + 16, 0x0021);
    daze_write_u16(record + 22, 0x0203);
    const DazeKvmPreflightBoundaryDisposition disposition = daze_kvm_preflight_boundary_broker(
      &machine, &files, &process_state, &dos_memory, 0x2200, record, mailbox, &result);
    if (disposition != DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED || daze_read_u16(mailbox) != 0x2900 ||
        daze_read_u16(mailbox + 2) != 0xaaaa || daze_read_u16(mailbox + 8) != 0x000b ||
        memcmp(guest + 0x2020, expected_fcb, sizeof(expected_fcb)) != 0 ||
        (daze_read_u16(mailbox + 14) & 1u) != 0) {
      fprintf(stderr, "2901 disp=%d ax=%04x bx=%04x si=%04x flags=%04x\n", (int)disposition,
              daze_read_u16(mailbox), daze_read_u16(mailbox + 2), daze_read_u16(mailbox + 8),
              daze_read_u16(mailbox + 14));
      return 1;
    }
  }

  /* Find First writes the shared DOS 2+ DTA layout and preserves unrelated reply words. */
  {
    memcpy(guest + 0x1000, "PLAIN.TXT", sizeof("PLAIN.TXT"));
    daze_dos_process_state_set_dta(&process_state, 0x0200, 0);
    memset(record, 0, sizeof(record));
    memset(mailbox, 0xff, sizeof(mailbox));
    memset(guest + 0x2000, 0xff, 43);
    daze_write_u16(record, 0x4e3c);
    daze_write_u16(record + 2, 0xaaaa);
    daze_write_u16(record + 4, 0x0000);
    daze_write_u16(record + 6, 0x0000);
    daze_write_u16(record + 8, 0x0100);
    daze_write_u16(record + 10, 0xdddd);
    daze_write_u16(record + 12, 0xbbbb);
    daze_write_u16(record + 14, 0xcccc);
    daze_write_u16(record + 16, 0x0021);
    daze_write_u16(record + 22, 0x0203);
    if (daze_kvm_preflight_boundary_broker(&machine, &files, &process_state, &dos_memory, 0x2200,
                                           record, mailbox,
                                           &result) != DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED ||
        daze_read_u16(mailbox) != 0x4e3c || daze_read_u16(mailbox + 2) != 0xaaaa ||
        daze_read_u16(mailbox + 4) != 0 || daze_read_u16(mailbox + 6) != 0 ||
        daze_read_u16(mailbox + 8) != 0xbbbb || daze_read_u16(mailbox + 10) != 0xcccc ||
        daze_read_u16(mailbox + 12) != 0xdddd || (daze_read_u16(mailbox + 14) & 1u) != 0 ||
        guest[0x2015] != 0x20 || memcmp(guest + 0x201e, "PLAIN.TXT", sizeof("PLAIN.TXT")) != 0)
      return 1;

    memset(record, 0, sizeof(record));
    memset(mailbox, 0xff, sizeof(mailbox));
    daze_write_u16(record, 0x4fb7);
    daze_write_u16(record + 2, 0xaaaa);
    daze_write_u16(record + 4, 0xbeef);
    daze_write_u16(record + 6, 0xdddd);
    daze_write_u16(record + 8, 0xbbbb);
    daze_write_u16(record + 10, 0xcccc);
    daze_write_u16(record + 12, 0x1111);
    daze_write_u16(record + 14, 0x2222);
    daze_write_u16(record + 16, 0x0021);
    daze_write_u16(record + 22, 0x0202);
    if (daze_kvm_preflight_boundary_broker(&machine, &files, &process_state, &dos_memory, 0x2200,
                                           record, mailbox,
                                           &result) != DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED ||
        daze_read_u16(mailbox) != 18 || daze_read_u16(mailbox + 2) != 0xaaaa ||
        daze_read_u16(mailbox + 4) != 0xbeef || daze_read_u16(mailbox + 6) != 0xdddd ||
        daze_read_u16(mailbox + 8) != 0x1111 || daze_read_u16(mailbox + 10) != 0x2222 ||
        daze_read_u16(mailbox + 12) != 0xcccc || (daze_read_u16(mailbox + 14) & 1u) == 0)
      return 1;

    memcpy(guest + 0x1000, "MISSING.TXT", sizeof("MISSING.TXT"));
    memset(record, 0, sizeof(record));
    memset(mailbox, 0xff, sizeof(mailbox));
    daze_write_u16(record, 0x4e00);
    daze_write_u16(record + 2, 0xaaaa);
    daze_write_u16(record + 4, 0x0000);
    daze_write_u16(record + 6, 0x0000);
    daze_write_u16(record + 8, 0x0100);
    daze_write_u16(record + 16, 0x0021);
    daze_write_u16(record + 22, 0x0203);
    if (daze_kvm_preflight_boundary_broker(&machine, &files, &process_state, &dos_memory, 0x2200,
                                           record, mailbox,
                                           &result) != DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED ||
        daze_read_u16(mailbox) != 18 || daze_read_u16(mailbox + 2) != 0xaaaa ||
        (daze_read_u16(mailbox + 14) & 1u) == 0)
      return 1;
  }

  DazeDosMemory resize_memory;
  daze_dos_memory_init(&resize_memory, 0x3000, 0xa000);
  DazeDosAllocation *resize_allocation = daze_dos_memory_allocate(&resize_memory, 8);
  memset(record, 0, sizeof(record));
  memset(mailbox, 0xff, sizeof(mailbox));
  daze_write_u16(record, 0x4a00);
  daze_write_u16(record + 2, 0x0010);
  daze_write_u16(record + 10, 0x3000);
  daze_write_u16(record + 16, 0x0021);
  daze_write_u16(record + 22, 0x0203);
  if (resize_allocation == NULL ||
      daze_kvm_preflight_boundary_broker(&machine, &files, &process_state, &resize_memory, 0x2200,
                                         record, mailbox,
                                         &result) != DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED ||
      result.resizes_served != 1 || !resize_allocation->in_use ||
      resize_allocation->paragraphs != 0x10 || resize_memory.next_segment != 0x3010 ||
      (daze_read_u16(mailbox + 14) & 1u) != 0)
    return 1;

  memset(record, 0, sizeof(record));
  memset(mailbox, 0xff, sizeof(mailbox));
  daze_write_u16(record, 0x4900);
  daze_write_u16(record + 2, 0xaaaa);
  daze_write_u16(record + 4, 0xbeef);
  daze_write_u16(record + 6, 0xdddd);
  daze_write_u16(record + 8, 0xbbbb);
  daze_write_u16(record + 10, 0x0700);
  daze_write_u16(record + 12, 0x1111);
  daze_write_u16(record + 14, 0x2222);
  daze_write_u16(record + 16, 0x0021);
  daze_write_u16(record + 22, 0x0202);
  if (daze_kvm_preflight_boundary_broker(&machine, &files, &process_state, &resize_memory, 0x2200,
                                         record, mailbox,
                                         &result) != DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED ||
      daze_read_u16(mailbox) != 9 || daze_read_u16(mailbox + 2) != 0xaaaa ||
      daze_read_u16(mailbox + 4) != 0xbeef || daze_read_u16(mailbox + 6) != 0xdddd ||
      daze_read_u16(mailbox + 8) != 0x1111 || daze_read_u16(mailbox + 10) != 0x2222 ||
      daze_read_u16(mailbox + 12) != 0x0700 || (daze_read_u16(mailbox + 14) & 1u) == 0 ||
      !resize_allocation->in_use)
    return 1;

  memset(record, 0, sizeof(record));
  memset(mailbox, 0xff, sizeof(mailbox));
  daze_write_u16(record, 0x5800);
  daze_write_u16(record + 16, 0x0021);
  if (daze_kvm_preflight_boundary_broker(&machine, &files, &process_state, &dos_memory, 0x2200,
                                         record, mailbox,
                                         &result) != DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED ||
      daze_read_u16(mailbox) != 0 || (daze_read_u16(mailbox + 14) & 1u) != 0)
    return 1;

  memset(record, 0, sizeof(record));
  memset(mailbox, 0x5a, sizeof(mailbox));
  uint8_t unchanged[DAZE_KVM_RUNNER_GATE_MAILBOX_SIZE];
  memset(unchanged, 0x5a, sizeof(unchanged));
  daze_write_u16(record + 16, 0x00fe);
  if (daze_kvm_preflight_boundary_broker(&machine, &files, &process_state, &dos_memory, 0x2200,
                                         record, mailbox,
                                         &result) != DAZE_KVM_PREFLIGHT_BOUNDARY_DPMI_ENTRY ||
      memcmp(mailbox, unchanged, sizeof(mailbox)) != 0)
    return 1;

  daze_write_u16(record + 16, 0x0060);
  if (daze_kvm_preflight_boundary_broker(&machine, &files, &process_state, &dos_memory, 0x2200,
                                         record, mailbox,
                                         &result) != DAZE_KVM_PREFLIGHT_BOUNDARY_UNSUPPORTED)
    return 1;

  /* Console replies differ by backend: KVM 02h preserves AX/ZF and clears CF;
   * 06h output replaces AL and preserves ZF. Keep these observable replies pinned. */
  {
    int output_pipe[2] = {-1, -1};
    uint8_t output[2] = {0};
    if (pipe(output_pipe) != 0 ||
        daze_dosfs_handles_bind_standard(&handles, STDIN_FILENO, output_pipe[1], STDERR_FILENO,
                                         NULL) != DAZE_DOSFS_OK) {
      if (output_pipe[0] >= 0) close(output_pipe[0]);
      if (output_pipe[1] >= 0) close(output_pipe[1]);
      return 1;
    }
    close(output_pipe[1]);

    memset(record, 0, sizeof(record));
    memset(mailbox, 0xff, sizeof(mailbox));
    daze_write_u16(record, 0x02aa);
    daze_write_u16(record + 6, 0x0041);
    daze_write_u16(record + 16, 0x0021);
    daze_write_u16(record + 22, 0x0243);
    if (daze_kvm_preflight_boundary_broker(&machine, &files, &process_state, &dos_memory, 0x2200,
                                           record, mailbox,
                                           &result) != DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED ||
        daze_read_u16(mailbox) != 0x02aa || (daze_read_u16(mailbox + 14) & 1u) != 0 ||
        (daze_read_u16(mailbox + 14) & 0x40u) == 0 || read(output_pipe[0], output, 1) != 1 ||
        output[0] != 'A') {
      close(output_pipe[0]);
      return 1;
    }

    memset(record, 0, sizeof(record));
    memset(mailbox, 0xff, sizeof(mailbox));
    daze_write_u16(record, 0x06aa);
    daze_write_u16(record + 6, 0x0042);
    daze_write_u16(record + 16, 0x0021);
    daze_write_u16(record + 22, 0x0243);
    if (daze_kvm_preflight_boundary_broker(&machine, &files, &process_state, &dos_memory, 0x2200,
                                           record, mailbox,
                                           &result) != DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED ||
        daze_read_u16(mailbox) != 0x0642 || (daze_read_u16(mailbox + 14) & 1u) != 0 ||
        (daze_read_u16(mailbox + 14) & 0x40u) == 0 || read(output_pipe[0], output, 1) != 1 ||
        output[0] != 'B') {
      close(output_pipe[0]);
      return 1;
    }
    close(output_pipe[0]);

    const int unreadable_output = open("/dev/null", O_RDONLY);
    if (unreadable_output < 0 ||
        daze_dosfs_handles_bind_standard(&handles, STDIN_FILENO, unreadable_output, STDERR_FILENO,
                                         NULL) != DAZE_DOSFS_OK)
      return 1;
    close(unreadable_output);

    memset(record, 0, sizeof(record));
    memset(mailbox, 0xff, sizeof(mailbox));
    daze_write_u16(record, 0x02aa);
    daze_write_u16(record + 6, 0x0041);
    daze_write_u16(record + 16, 0x0021);
    daze_write_u16(record + 22, 0x0243);
    if (daze_kvm_preflight_boundary_broker(&machine, &files, &process_state, &dos_memory, 0x2200,
                                           record, mailbox,
                                           &result) != DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED ||
        daze_read_u16(mailbox) != 1 || (daze_read_u16(mailbox + 14) & 1u) == 0 ||
        (daze_read_u16(mailbox + 14) & 0x40u) == 0)
      return 1;

    memset(record, 0, sizeof(record));
    memset(mailbox, 0xff, sizeof(mailbox));
    daze_write_u16(record, 0x06aa);
    daze_write_u16(record + 6, 0x0042);
    daze_write_u16(record + 16, 0x0021);
    daze_write_u16(record + 22, 0x0243);
    if (daze_kvm_preflight_boundary_broker(&machine, &files, &process_state, &dos_memory, 0x2200,
                                           record, mailbox,
                                           &result) != DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED ||
        daze_read_u16(mailbox) != 1 || (daze_read_u16(mailbox + 14) & 1u) == 0 ||
        (daze_read_u16(mailbox + 14) & 0x40u) == 0)
      return 1;

    if (daze_dosfs_handles_bind_standard(&handles, STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO,
                                         NULL) != DAZE_DOSFS_OK)
      return 1;
  }

  /* File-transfer witnesses cover 32-bit seek packing and short-read behaviour. */
  {
    uint16_t handle = 0;
    memcpy(guest + 0x1000, "NEW.BIN", sizeof("NEW.BIN"));
    memset(record, 0, sizeof(record));
    memset(mailbox, 0xff, sizeof(mailbox));
    daze_write_u16(record, 0x3c00);
    daze_write_u16(record + 8, 0x0100);
    daze_write_u16(record + 16, 0x0021);
    daze_write_u16(record + 22, 0x0203);
    if (daze_kvm_preflight_boundary_broker(&machine, &files, &process_state, &dos_memory, 0x2200,
                                           record, mailbox,
                                           &result) != DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED ||
        (daze_read_u16(mailbox + 14) & 1u) != 0)
      return 1;
    handle = daze_read_u16(mailbox);

    daze_write_u16(record, 0x3e00);
    daze_write_u16(record + 2, handle);
    if (daze_kvm_preflight_boundary_broker(&machine, &files, &process_state, &dos_memory, 0x2200,
                                           record, mailbox,
                                           &result) != DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED ||
        daze_read_u16(mailbox) != 0x3e00 || (daze_read_u16(mailbox + 14) & 1u) != 0)
      return 1;
    if (daze_kvm_preflight_boundary_broker(&machine, &files, &process_state, &dos_memory, 0x2200,
                                           record, mailbox,
                                           &result) != DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED ||
        daze_read_u16(mailbox) != 6 || (daze_read_u16(mailbox + 14) & 1u) == 0)
      return 1;

    memcpy(guest + 0x1000, "MISSING.BIN", sizeof("MISSING.BIN"));
    memset(record, 0, sizeof(record));
    memset(mailbox, 0xff, sizeof(mailbox));
    daze_write_u16(record, 0x3d00);
    daze_write_u16(record + 8, 0x0100);
    daze_write_u16(record + 16, 0x0021);
    daze_write_u16(record + 22, 0x0203);
    if (daze_kvm_preflight_boundary_broker(&machine, &files, &process_state, &dos_memory, 0x2200,
                                           record, mailbox,
                                           &result) != DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED ||
        daze_read_u16(mailbox) != 2 || (daze_read_u16(mailbox + 14) & 1u) == 0)
      return 1;

    memcpy(guest + 0x1000, "SHORT.BIN", sizeof("SHORT.BIN"));
    daze_write_u16(record, 0x3d00);
    if (daze_kvm_preflight_boundary_broker(&machine, &files, &process_state, &dos_memory, 0x2200,
                                           record, mailbox,
                                           &result) != DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED ||
        (daze_read_u16(mailbox + 14) & 1u) != 0)
      return 1;
    handle = daze_read_u16(mailbox);

    memset(record, 0, sizeof(record));
    memset(mailbox, 0xff, sizeof(mailbox));
    daze_write_u16(record, 0x4200);
    daze_write_u16(record + 2, handle);
    daze_write_u16(record + 6, 1);
    daze_write_u16(record + 16, 0x0021);
    daze_write_u16(record + 22, 0x0203);
    if (daze_kvm_preflight_boundary_broker(&machine, &files, &process_state, &dos_memory, 0x2200,
                                           record, mailbox,
                                           &result) != DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED ||
        daze_read_u16(mailbox) != 1 || daze_read_u16(mailbox + 6) != 0 ||
        result.file_position != 1 || (daze_read_u16(mailbox + 14) & 1u) != 0)
      return 1;

    daze_write_u16(record + 6, 0);
    if (daze_kvm_preflight_boundary_broker(&machine, &files, &process_state, &dos_memory, 0x2200,
                                           record, mailbox,
                                           &result) != DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED ||
        daze_read_u16(mailbox) != 0 || daze_read_u16(mailbox + 6) != 0)
      return 1;

    memset(record, 0, sizeof(record));
    memset(mailbox, 0xff, sizeof(mailbox));
    daze_write_u16(record, 0x3f00);
    daze_write_u16(record + 2, handle);
    daze_write_u16(record + 4, 8);
    daze_write_u16(record + 6, 0x0100);
    daze_write_u16(record + 8, 0x0100);
    daze_write_u16(record + 16, 0x0021);
    daze_write_u16(record + 22, 0x0203);
    if (daze_kvm_preflight_boundary_broker(&machine, &files, &process_state, &dos_memory, 0x2200,
                                           record, mailbox,
                                           &result) != DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED ||
        daze_read_u16(mailbox) != 3 || result.copied_byte_count != 3 ||
        memcmp(guest + 0x1100, "abc", 3) != 0 || (daze_read_u16(mailbox + 14) & 1u) != 0)
      return 1;

    memcpy(guest + 0x1000, "WRITE.BIN", sizeof("WRITE.BIN"));
    memset(record, 0, sizeof(record));
    memset(mailbox, 0xff, sizeof(mailbox));
    daze_write_u16(record, 0x3c00);
    daze_write_u16(record + 8, 0x0100);
    daze_write_u16(record + 16, 0x0021);
    daze_write_u16(record + 22, 0x0203);
    if (daze_kvm_preflight_boundary_broker(&machine, &files, &process_state, &dos_memory, 0x2200,
                                           record, mailbox,
                                           &result) != DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED ||
        (daze_read_u16(mailbox + 14) & 1u) != 0)
      return 1;
    handle = daze_read_u16(mailbox);
    memcpy(guest + 0x1100, "write", 5);
    memset(record, 0, sizeof(record));
    memset(mailbox, 0xff, sizeof(mailbox));
    daze_write_u16(record, 0x4000);
    daze_write_u16(record + 2, handle);
    daze_write_u16(record + 4, 5);
    daze_write_u16(record + 6, 0x0100);
    daze_write_u16(record + 8, 0x0100);
    daze_write_u16(record + 16, 0x0021);
    daze_write_u16(record + 22, 0x0203);
    if (daze_kvm_preflight_boundary_broker(&machine, &files, &process_state, &dos_memory, 0x2200,
                                           record, mailbox,
                                           &result) != DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED ||
        daze_read_u16(mailbox) != 5 || result.copied_byte_count != 5 ||
        (daze_read_u16(mailbox + 14) & 1u) != 0)
      return 1;
    daze_dosfs_handles_close_all(&handles);
    if (daze_dosfs_handles_bind_standard(&handles, STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO,
                                         NULL) != DAZE_DOSFS_OK)
      return 1;
  }

  memset(record, 0, sizeof(record));
  memset(mailbox, 0xff, sizeof(mailbox));
  daze_write_u16(record, 0x3000);
  daze_write_u16(record + 2, 0x0700);
  daze_write_u16(record + 16, 0x0021);
  daze_write_u16(record + 22, 0x0203);
  if (daze_kvm_preflight_boundary_broker(&machine, &files, &process_state, &dos_memory, 0x2200,
                                         record, mailbox,
                                         &result) != DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED ||
      daze_read_u16(mailbox) != 0x0005 || daze_read_u16(mailbox + 2) != 0 ||
      daze_read_u16(mailbox + 4) != 0 || (daze_read_u16(mailbox + 14) & 1u) != 0)
    return 1;

  /* 21h/2Ch uses a deterministic midnight clock. */
  memset(record, 0, sizeof(record));
  memset(mailbox, 0xff, sizeof(mailbox));
  daze_write_u16(record, 0x2cb7);
  daze_write_u16(record + 4, 0x1234);
  daze_write_u16(record + 6, 0x5678);
  daze_write_u16(record + 16, 0x0021);
  daze_write_u16(record + 22, 0x0203);
  if (daze_kvm_preflight_boundary_broker(&machine, &files, &process_state, &dos_memory, 0x2200,
                                         record, mailbox,
                                         &result) != DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED ||
      daze_read_u16(mailbox) != 0x2cb7 || daze_read_u16(mailbox + 4) != 0 ||
      daze_read_u16(mailbox + 6) != 0 || (daze_read_u16(mailbox + 14) & 1u) != 0)
    return 1;

  /* 21h/2Ah uses the shared host-local date, including its fallback policy. */
  {
    DazeDosDate expected_date;
    daze_dos_date_get(&expected_date);
    memset(record, 0, sizeof(record));
    memset(mailbox, 0xff, sizeof(mailbox));
    daze_write_u16(record, 0x2a00);
    daze_write_u16(record + 16, 0x0021);
    daze_write_u16(record + 22, 0x0203);
    if (daze_kvm_preflight_boundary_broker(&machine, &files, &process_state, &dos_memory, 0x2200,
                                           record, mailbox,
                                           &result) != DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED ||
        daze_read_u16(mailbox) != (0x2a00u | expected_date.weekday) ||
        daze_read_u16(mailbox + 4) != expected_date.year ||
        daze_read_u16(mailbox + 6) !=
          (uint16_t)(((uint16_t)expected_date.month << 8) | expected_date.day) ||
        (daze_read_u16(mailbox + 14) & 1u) != 0)
      return 1;
  }

  /* 4300h attributes: 20h for regular files, 10h for directories. Success
   * writes CX; failure writes AX. Other registers must survive both replies. */
  {
    struct {
      const char *name;
      uint16_t expected;
    } attr_cases[] = {{"PLAIN.TXT", 0x20}, {"SUBDIR", 0x10}};
    for (size_t index = 0; index < sizeof(attr_cases) / sizeof(attr_cases[0]); ++index) {
      memcpy(guest + 0x1000, attr_cases[index].name, strlen(attr_cases[index].name) + 1);
      memset(record, 0, sizeof(record));
      memset(mailbox, 0xff, sizeof(mailbox));
      daze_write_u16(record, 0x4300);
      daze_write_u16(record + 2, 0xaaaa);
      daze_write_u16(record + 4, 0xbeef);
      daze_write_u16(record + 6, 0x0000);
      daze_write_u16(record + 8, 0x0100);
      daze_write_u16(record + 10, 0xdddd);
      daze_write_u16(record + 12, 0xbbbb);
      daze_write_u16(record + 14, 0xcccc);
      daze_write_u16(record + 16, 0x0021);
      daze_write_u16(record + 22, 0x0203);
      {
        const DazeKvmPreflightBoundaryDisposition disposition = daze_kvm_preflight_boundary_broker(
          &machine, &files, &process_state, &dos_memory, 0x2200, record, mailbox, &result);
        if (disposition != DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED) {
          fprintf(stderr, "4300 %s disp=%d\n", attr_cases[index].name, (int)disposition);
          return 1;
        }
      }
      if (daze_read_u16(mailbox) != 0x4300 || daze_read_u16(mailbox + 2) != 0xaaaa ||
          daze_read_u16(mailbox + 4) != attr_cases[index].expected ||
          daze_read_u16(mailbox + 6) != 0x0000 || daze_read_u16(mailbox + 8) != 0xbbbb ||
          daze_read_u16(mailbox + 10) != 0xcccc || daze_read_u16(mailbox + 12) != 0xdddd ||
          (daze_read_u16(mailbox + 14) & 1u) != 0) {
        fprintf(stderr,
                "4300 %s reply ax=%04x bx=%04x cx=%04x dx=%04x si=%04x di=%04x es=%04x "
                "fl=%04x\n",
                attr_cases[index].name, daze_read_u16(mailbox), daze_read_u16(mailbox + 2),
                daze_read_u16(mailbox + 4), daze_read_u16(mailbox + 6), daze_read_u16(mailbox + 8),
                daze_read_u16(mailbox + 10), daze_read_u16(mailbox + 12),
                daze_read_u16(mailbox + 14));
        return 1;
      }
    }
    memcpy(guest + 0x1000, "MISSING.TXT", sizeof("MISSING.TXT"));
    memset(record, 0, sizeof(record));
    memset(mailbox, 0xff, sizeof(mailbox));
    daze_write_u16(record, 0x4300);
    daze_write_u16(record + 2, 0xaaaa);
    daze_write_u16(record + 4, 0xbeef);
    daze_write_u16(record + 6, 0x0000);
    daze_write_u16(record + 8, 0x0100);
    daze_write_u16(record + 10, 0xdddd);
    daze_write_u16(record + 12, 0xbbbb);
    daze_write_u16(record + 14, 0xcccc);
    daze_write_u16(record + 16, 0x0021);
    daze_write_u16(record + 22, 0x0203);
    if (daze_kvm_preflight_boundary_broker(&machine, &files, &process_state, &dos_memory, 0x2200,
                                           record, mailbox,
                                           &result) != DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED ||
        daze_read_u16(mailbox) != 2 || daze_read_u16(mailbox + 2) != 0xaaaa ||
        daze_read_u16(mailbox + 4) != 0xbeef || daze_read_u16(mailbox + 6) != 0x0000 ||
        daze_read_u16(mailbox + 8) != 0xbbbb || daze_read_u16(mailbox + 10) != 0xcccc ||
        daze_read_u16(mailbox + 12) != 0xdddd || (daze_read_u16(mailbox + 14) & 1u) == 0)
      return 1;
    memset(record, 0, sizeof(record));
    memset(mailbox, 0xff, sizeof(mailbox));
    daze_write_u16(record, 0x4301);
    daze_write_u16(record + 8, 0x0100);
    daze_write_u16(record + 16, 0x0021);
    if (daze_kvm_preflight_boundary_broker(&machine, &files, &process_state, &dos_memory, 0x2200,
                                           record, mailbox,
                                           &result) != DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED ||
        daze_read_u16(mailbox) != 1 || (daze_read_u16(mailbox + 14) & 1u) == 0)
      return 1;
  }

  /* 21h/06h with DL=FFh is a non-blocking poll with no available input. */
  memset(record, 0, sizeof(record));
  memset(mailbox, 0xff, sizeof(mailbox));
  daze_write_u16(record, 0x06b7);
  daze_write_u16(record + 6, 0x00ff);
  daze_write_u16(record + 16, 0x0021);
  daze_write_u16(record + 22, 0x0203);
  if (daze_kvm_preflight_boundary_broker(&machine, &files, &process_state, &dos_memory, 0x2200,
                                         record, mailbox,
                                         &result) != DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED ||
      daze_read_u16(mailbox) != 0x0600 || (daze_read_u16(mailbox + 14) & 1u) != 0 ||
      (daze_read_u16(mailbox + 14) & 0x40u) == 0)
    return 1;

  /* 21h/44h subfunction 00h is shared; other subfunctions stay unsupported. */
  memset(record, 0, sizeof(record));
  memset(mailbox, 0xff, sizeof(mailbox));
  daze_write_u16(record, 0x4400);
  daze_write_u16(record + 2, 1);
  daze_write_u16(record + 16, 0x0021);
  daze_write_u16(record + 22, 0x0203);
  if (daze_kvm_preflight_boundary_broker(&machine, &files, &process_state, &dos_memory, 0x2200,
                                         record, mailbox,
                                         &result) != DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED ||
      daze_read_u16(mailbox + 6) != 0 || (daze_read_u16(mailbox + 14) & 1u) != 0)
    return 1;
  daze_write_u16(record + 2, 5);
  if (daze_kvm_preflight_boundary_broker(&machine, &files, &process_state, &dos_memory, 0x2200,
                                         record, mailbox,
                                         &result) != DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED ||
      daze_read_u16(mailbox) != 6 || (daze_read_u16(mailbox + 14) & 1u) == 0)
    return 1;
  daze_write_u16(record, 0x4401);
  daze_write_u16(record + 2, 1);
  if (daze_kvm_preflight_boundary_broker(&machine, &files, &process_state, &dos_memory, 0x2200,
                                         record, mailbox,
                                         &result) != DAZE_KVM_PREFLIGHT_BOUNDARY_UNSUPPORTED)
    return 1;

  /* 5700h returns deterministic 2000-01-01 midnight (CX=0000h, DX=2821h).
   * An invalid handle returns DOS error 6 without overwriting time/date. */
  memset(record, 0, sizeof(record));
  memset(mailbox, 0xff, sizeof(mailbox));
  daze_write_u16(record, 0x5700);
  daze_write_u16(record + 2, 1);
  daze_write_u16(record + 4, 0xbeef);
  daze_write_u16(record + 6, 0xdead);
  daze_write_u16(record + 8, 0x0100);
  daze_write_u16(record + 10, 0xdddd);
  daze_write_u16(record + 12, 0xbbbb);
  daze_write_u16(record + 14, 0xcccc);
  daze_write_u16(record + 16, 0x0021);
  daze_write_u16(record + 22, 0x0203);
  if (daze_kvm_preflight_boundary_broker(&machine, &files, &process_state, &dos_memory, 0x2200,
                                         record, mailbox,
                                         &result) != DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED ||
      daze_read_u16(mailbox) != 0x5700 || daze_read_u16(mailbox + 2) != 1 ||
      daze_read_u16(mailbox + 4) != 0x0000 || daze_read_u16(mailbox + 6) != 0x2821 ||
      daze_read_u16(mailbox + 8) != 0xbbbb || daze_read_u16(mailbox + 10) != 0xcccc ||
      daze_read_u16(mailbox + 12) != 0xdddd || (daze_read_u16(mailbox + 14) & 1u) != 0)
    return 1;
  daze_write_u16(record + 2, 5);
  if (daze_kvm_preflight_boundary_broker(&machine, &files, &process_state, &dos_memory, 0x2200,
                                         record, mailbox,
                                         &result) != DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED ||
      daze_read_u16(mailbox) != 6 || daze_read_u16(mailbox + 2) != 5 ||
      daze_read_u16(mailbox + 4) != 0xbeef || daze_read_u16(mailbox + 6) != 0xdead ||
      daze_read_u16(mailbox + 8) != 0xbbbb || daze_read_u16(mailbox + 10) != 0xcccc ||
      daze_read_u16(mailbox + 12) != 0xdddd || (daze_read_u16(mailbox + 14) & 1u) == 0)
    return 1;
  daze_write_u16(record, 0x5701);
  daze_write_u16(record + 2, 1);
  if (daze_kvm_preflight_boundary_broker(&machine, &files, &process_state, &dos_memory, 0x2200,
                                         record, mailbox,
                                         &result) != DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED ||
      daze_read_u16(mailbox) != 0x5701 || daze_read_u16(mailbox + 2) != 1 ||
      daze_read_u16(mailbox + 4) != 0xbeef || daze_read_u16(mailbox + 6) != 0xdead ||
      daze_read_u16(mailbox + 8) != 0xbbbb || daze_read_u16(mailbox + 10) != 0xcccc ||
      daze_read_u16(mailbox + 12) != 0xdddd || daze_read_u16(mailbox + 14) != 0x0202)
    return 1;
  daze_write_u16(record + 2, 5);
  if (daze_kvm_preflight_boundary_broker(&machine, &files, &process_state, &dos_memory, 0x2200,
                                         record, mailbox,
                                         &result) != DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED ||
      daze_read_u16(mailbox) != 6 || daze_read_u16(mailbox + 2) != 5 ||
      daze_read_u16(mailbox + 4) != 0xbeef || daze_read_u16(mailbox + 6) != 0xdead ||
      daze_read_u16(mailbox + 14) != 0x0203)
    return 1;
  daze_write_u16(record, 0x5702);
  if (daze_kvm_preflight_boundary_broker(&machine, &files, &process_state, &dos_memory, 0x2200,
                                         record, mailbox,
                                         &result) != DAZE_KVM_PREFLIGHT_BOUNDARY_UNSUPPORTED)
    return 1;
  daze_write_u16(record, 0x5700);
  daze_write_u16(record + 2, 0x0100);
  if (daze_kvm_preflight_boundary_broker(&machine, &files, &process_state, &dos_memory, 0x2200,
                                         record, mailbox,
                                         &result) != DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED ||
      daze_read_u16(mailbox) != 6 || (daze_read_u16(mailbox + 14) & 1u) == 0)
    return 1;

  memset(record, 0, sizeof(record));
  memset(mailbox, 0xff, sizeof(mailbox));
  daze_write_u16(record, 0x1a00);
  daze_write_u16(record + 6, 0x4567);
  daze_write_u16(record + 8, 0x2345);
  daze_write_u16(record + 16, 0x0021);
  daze_write_u16(record + 22, 0x0203);
  if (daze_kvm_preflight_boundary_broker(&machine, &files, &process_state, &dos_memory, 0x2200,
                                         record, mailbox,
                                         &result) != DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED ||
      process_state.dta_segment != 0x2345 || process_state.dta_offset != 0x4567 ||
      daze_read_u16(mailbox) != 0x1a00 || (daze_read_u16(mailbox + 14) & 1u) != 0)
    return 1;

  memset(record, 0, sizeof(record));
  memset(mailbox, 0, sizeof(mailbox));
  daze_write_u16(record, 0x3e00);
  daze_write_u16(record + 2, 5);
  daze_write_u16(record + 16, 0x0021);
  if (daze_kvm_preflight_boundary_broker(&machine, &files, &process_state, &dos_memory, 0x2200,
                                         record, mailbox,
                                         &result) != DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED ||
      daze_read_u16(mailbox) != 6 || (daze_read_u16(mailbox + 14) & 1u) == 0)
    return 1;

  memset(record, 0, sizeof(record));
  memset(mailbox, 0, sizeof(mailbox));
  daze_write_u16(record, 0x1687);
  daze_write_u16(record + 2, 0xbeef);
  daze_write_u16(record + 4, 0xcafe);
  daze_write_u16(record + 6, 0xdead);
  daze_write_u16(record + 10, 0x2222);
  daze_write_u16(record + 12, 0x3333);
  daze_write_u16(record + 14, 0x4444);
  daze_write_u16(record + 16, 0x002f);
  daze_write_u16(record + 22, 0x0203);
  if (daze_kvm_preflight_boundary_broker(&machine, &files, &process_state, &dos_memory, 0x2200,
                                         record, mailbox,
                                         &result) != DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED ||
      mailbox[0] != 0 || mailbox[1] != 0 || mailbox[2] != 1 || mailbox[3] != 0 || mailbox[4] != 3 ||
      mailbox[5] != 0 || mailbox[6] != 0x5a || mailbox[7] != 0 || mailbox[8] != 0 ||
      mailbox[9] != 0 || mailbox[10] != 0 || mailbox[11] != 0 || mailbox[12] != 0 ||
      mailbox[13] != 0x22 || mailbox[14] != 2 || mailbox[15] != 2)
    return 1;

  daze_write_u16(record, 0x1600);
  if (daze_kvm_preflight_boundary_broker(&machine, &files, &process_state, &dos_memory, 0x2200,
                                         record, mailbox,
                                         &result) != DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED ||
      mailbox[0] != 1 || mailbox[1] != 0 || mailbox[2] != 0xef || mailbox[3] != 0xbe ||
      mailbox[4] != 0xfe || mailbox[5] != 0xca || mailbox[6] != 0xad || mailbox[7] != 0xde ||
      mailbox[8] != 0x33 || mailbox[9] != 0x33 || mailbox[10] != 0x44 || mailbox[11] != 0x44 ||
      mailbox[12] != 0x22 || mailbox[13] != 0x22 || mailbox[14] != 2 || mailbox[15] != 2)
    return 1;

  memset(record, 0, sizeof(record));
  memset(mailbox, 0, sizeof(mailbox));
  daze_write_u16(record, 0x251b);
  daze_write_u16(record + 6, 0x6bc6);
  daze_write_u16(record + 8, 0x1000);
  daze_write_u16(record + 16, 0x0021);
  daze_write_u16(record + 22, 0x0203);
  if (daze_kvm_preflight_boundary_broker(&machine, &files, &process_state, &dos_memory, 0x2200,
                                         record, mailbox,
                                         &result) != DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED ||
      daze_read_u16(guest + 0x6c) != 0x6bc6 || daze_read_u16(guest + 0x6e) != 0x1000 ||
      daze_read_u16(mailbox) != 0x251b || (daze_read_u16(mailbox + 14) & 1u) != 0)
    return 1;

  /* 35h reads the modeled table, not the guest IVT: a vector the runner
   * gate-stubs but the guest never set reads back as 0:0, and a vector the
   * guest set with 25h reads back exactly what it stored. */
  memset(record, 0, sizeof(record));
  memset(mailbox, 0xff, sizeof(mailbox));
  daze_write_u16(record, 0x3523);
  daze_write_u16(record + 16, 0x0021);
  daze_write_u16(record + 22, 0x0203);
  if (daze_kvm_preflight_boundary_broker(&machine, &files, &process_state, &dos_memory, 0x2200,
                                         record, mailbox,
                                         &result) != DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED ||
      daze_read_u16(mailbox + 2) != 0 || daze_read_u16(mailbox + 12) != 0 ||
      (daze_read_u16(mailbox + 14) & 1u) != 0)
    return 1;

  memset(record, 0, sizeof(record));
  memset(mailbox, 0xff, sizeof(mailbox));
  daze_write_u16(record, 0x351b);
  daze_write_u16(record + 16, 0x0021);
  daze_write_u16(record + 22, 0x0203);
  if (daze_kvm_preflight_boundary_broker(&machine, &files, &process_state, &dos_memory, 0x2200,
                                         record, mailbox,
                                         &result) != DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED ||
      daze_read_u16(mailbox + 2) != 0x6bc6 || daze_read_u16(mailbox + 12) != 0x1000 ||
      (daze_read_u16(mailbox + 14) & 1u) != 0)
    return 1;

  memset(record, 0, sizeof(record));
  memset(mailbox, 0xff, sizeof(mailbox));
  daze_write_u16(record, 0x007e);
  daze_write_u16(record + 2, 0x016c);
  daze_write_u16(record + 4, 0xbeef);
  daze_write_u16(record + 6, 0xdead);
  daze_write_u16(record + 10, 0x2222);
  daze_write_u16(record + 12, 0x3333);
  daze_write_u16(record + 14, 0x4444);
  daze_write_u16(record + 16, 0x001a);
  daze_write_u16(record + 22, 0x0203);
  if (daze_kvm_preflight_boundary_broker(&machine, &files, &process_state, &dos_memory, 0x2200,
                                         record, mailbox,
                                         &result) != DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED ||
      daze_read_u16(mailbox) != 0 || daze_read_u16(mailbox + 4) != 0 ||
      daze_read_u16(mailbox + 6) != 0 || (daze_read_u16(mailbox + 14) & 1u) != 0 ||
      daze_read_u16(mailbox + 2) != 0x016c || daze_read_u16(mailbox + 8) != 0x3333 ||
      daze_read_u16(mailbox + 10) != 0x4444 || daze_read_u16(mailbox + 12) != 0x2222)
    return 1;
  daze_write_u16(record, 0x0001);
  if (daze_kvm_preflight_boundary_broker(&machine, &files, &process_state, &dos_memory, 0x2200,
                                         record, mailbox,
                                         &result) != DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED ||
      daze_read_u16(mailbox) != 0x0000 || daze_read_u16(mailbox + 4) != 0 ||
      daze_read_u16(mailbox + 6) != 0 || (daze_read_u16(mailbox + 14) & 1u) != 0 ||
      daze_read_u16(mailbox + 2) != 0x016c || daze_read_u16(mailbox + 8) != 0x3333 ||
      daze_read_u16(mailbox + 10) != 0x4444 || daze_read_u16(mailbox + 12) != 0x2222)
    return 1;
  daze_write_u16(record, 0x0100);
  {
    const DazeKvmPreflightBoundaryDisposition unsupported_disp = daze_kvm_preflight_boundary_broker(
      &machine, &files, &process_state, &dos_memory, 0x2200, record, mailbox, &result);
    if (unsupported_disp != DAZE_KVM_PREFLIGHT_BOUNDARY_UNSUPPORTED) return 1;
  }

  /* INT 21h/4Ch is a terminate, not a reply: the broker returns TERMINATED
   * and leaves the mailbox untouched. */
  memset(record, 0, sizeof(record));
  memset(mailbox, 0x5a, sizeof(mailbox));
  memset(unchanged, 0x5a, sizeof(unchanged));
  daze_write_u16(record, 0x4c07);
  daze_write_u16(record + 16, 0x0021);
  daze_write_u16(record + 22, 0x0203);
  if (daze_kvm_preflight_boundary_broker(&machine, &files, &process_state, &dos_memory, 0x2200,
                                         record, mailbox,
                                         &result) != DAZE_KVM_PREFLIGHT_BOUNDARY_TERMINATED ||
      memcmp(mailbox, unchanged, sizeof(mailbox)) != 0)
    return 1;

  /* A resident child has the same no-mailbox terminal boundary. The owner,
   * not the broker, decides how its declared paragraphs survive parent resume. */
  memset(record, 0, sizeof(record));
  memset(mailbox, 0x5a, sizeof(mailbox));
  daze_write_u16(record, 0x3102);
  daze_write_u16(record + 6, 0x059c);
  daze_write_u16(record + 16, 0x0021);
  daze_write_u16(record + 22, 0x0203);
  if (daze_kvm_preflight_boundary_broker(&machine, &files, &process_state, &dos_memory, 0x2200,
                                         record, mailbox,
                                         &result) != DAZE_KVM_PREFLIGHT_BOUNDARY_TERMINATED ||
      memcmp(mailbox, unchanged, sizeof(mailbox)) != 0)
    return 1;

  /* EXEC likewise transfers ownership to the KVM command owner; it must not
   * manufacture a reply before the child has terminated. */
  memset(record, 0, sizeof(record));
  memset(mailbox, 0x5a, sizeof(mailbox));
  daze_write_u16(record, 0x4b00);
  daze_write_u16(record + 16, 0x0021);
  if (daze_kvm_preflight_boundary_broker(&machine, &files, &process_state, &dos_memory, 0x2200,
                                         record, mailbox,
                                         &result) != DAZE_KVM_PREFLIGHT_BOUNDARY_EXEC ||
      memcmp(mailbox, unchanged, sizeof(mailbox)) != 0)
    return 1;

  /* Unsupported EXEC modes remain ordinary unsupported requests; only 4B00h
   * crosses into the command owner. */
  memset(record, 0, sizeof(record));
  daze_write_u16(record, 0x4b01);
  daze_write_u16(record + 16, 0x0021);
  if (daze_kvm_preflight_boundary_broker(&machine, &files, &process_state, &dos_memory, 0x2200,
                                         record, mailbox,
                                         &result) != DAZE_KVM_PREFLIGHT_BOUNDARY_UNSUPPORTED)
    return 1;

  memset(record, 0, sizeof(record));
  memset(mailbox, 0xff, sizeof(mailbox));
  daze_write_u16(record, 0x4300);
  daze_write_u16(record + 16, 0x002f);
  if (daze_kvm_preflight_boundary_broker(&machine, &files, &process_state, &dos_memory, 0x2200,
                                         record, mailbox,
                                         &result) != DAZE_KVM_PREFLIGHT_BOUNDARY_HANDLED ||
      daze_read_u16(mailbox) != 0x4300 || (daze_read_u16(mailbox + 14) & 1u) != 0)
    return 1;

  /* The gate owns only the two 8259 mask reads, and only they read as 0. */
  {
    uint8_t value = 0xff;
    if (!daze_kvm_runner_gated_port_read(0x21, &value) || value != 0) return 1;
    value = 0xff;
    if (!daze_kvm_runner_gated_port_read(0xa1, &value) || value != 0) return 1;
    if (daze_kvm_runner_gated_port_read(0x20, &value) ||
        daze_kvm_runner_gated_port_read(0x40, &value) ||
        daze_kvm_runner_gated_port_read(0x60, &value) ||
        daze_kvm_runner_gated_port_read(0xa0, &value))
      return 1;
  }
  puts("KVM preflight boundary broker: passed");
  /* Mirror production teardown: the find-first path can leave a host
   * directory open in the process state. */
  daze_dos_process_state_dispose(&process_state);
  return 0;
}
