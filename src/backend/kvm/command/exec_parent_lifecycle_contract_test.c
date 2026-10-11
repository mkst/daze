#include "owner.h"

#include "guest_memory_layout.h"
#include "byte_order.h"
#include "result.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static DazeKvmRunnerGenericPreflightRequest request_for(DazeImage *image,
                                                        const DazeMzHeader *header,
                                                        uint16_t psp_segment,
                                                        uint16_t load_segment) {
  static DazeDosfsMounts mounts;
  static DazeDosfsHandles handles;
  static DazeDosfsFileService files;
  return (DazeKvmRunnerGenericPreflightRequest){.process = {
                                                  .image = image,
                                                  .header = header,
                                                  .command_tail = "",
                                                  .guest_path = "C:\\TOOL.EXE",
                                                  .psp_segment = psp_segment,
                                                  .environment_segment = 0x0200,
                                                  .dpmi_entry_segment = 0x0300,
                                                  .dos_vector_segment = 0x0400,
                                                  .load_segment = load_segment,
                                                  .guest_size = 0x40000,
                                                  .mounts = &mounts,
                                                  .handles = &handles,
                                                  .files = &files,
                                                }};
}

static int owner_exec_case(int kind) {
  char root[] = "/tmp/daze-owner-exec-XXXXXX";
  if (mkdtemp(root) == NULL) return 1;
  const int root_fd = open(root, O_RDONLY | O_DIRECTORY);
  if (root_fd < 0) return 1;
  DazeDosfsMounts mounts;
  DazeDosfsHandles handles;
  DazeDosfsFileService files;
  daze_dosfs_mounts_init(&mounts);
  daze_dosfs_handles_init(&handles);
  daze_dosfs_file_service_init(&files, &mounts, &handles);
  daze_dosfs_mounts_add_named(&mounts, 2, root_fd, 0);
  uint8_t parent_bytes[0x80] = {0};
  const uint8_t parent_code[] = {
    0xbb, 0x00, 0x01,             /* mov bx,100h */
    0xba, 0x00, 0x02,             /* mov dx,200h */
    0xb8, 0x00, 0x4b,             /* mov ax,0x4b00 */
    0xcd, 0x21,                   /* int 0x21 */
    0xb4, 0x4d,                   /* mov ah,0x4d */
    0xcd, 0x21,                   /* int 0x21 */
    0xb4, 0x4c,                   /* mov ah,0x4c */
    0xcd, 0x21,                   /* int 0x21 */
    0xc6, 0x06, 0xf0, 0x02, 0x99, /* mov byte [02f0h],0x99 */
    0xf4,                         /* hlt */
  };
  memcpy(parent_bytes + 0x20, parent_code, sizeof(parent_code));
  size_t parent_code_size = sizeof(parent_code);
  if (kind == 11) {
    const uint8_t resident_parent[] = {
      0xbb, 0,    1,    /* mov bx,1 */
      0xba, 0,    2,    /* mov dx,2 */
      0xb8, 0,    0x4b, /* mov ax,0x4b00 */
      0xcd, 0x21,       /* int 0x21 */
      0xb4, 0x4d,       /* mov ah,0x4d */
      0xcd, 0x21,       /* int 0x21 */
      0xb8, 0x10, 0,    /* mov ax,0x10 */
      0xb9, 0x18, 0,    /* mov cx,0x18 */
      0xba, 0x40, 0,    /* mov dx,0x40 */
      0xbb, 0,    0xff, /* mov bx,0xff00 */
      0xbe, 8,    0,    /* mov si,8 */
      0xbf, 0x80, 0,    /* mov di,0x80 */
      0xcd, 0xfc,       /* int 0xfc */
      0xf4,             /* hlt */
    };
    memcpy(parent_bytes + 0x20, resident_parent, sizeof(resident_parent));
    parent_code_size = sizeof(resident_parent);
  }
  DazeImage image = {parent_bytes, sizeof(parent_bytes)};
  DazeMzHeader header = {.header_paragraphs = 2,
                         .initial_sp = 0xfffe,
                         .image_offset = 0x20,
                         .image_size = parent_code_size,
                         .module_size = sizeof(parent_bytes),
                         .relocation_offset = 0x1c};
  DazeKvmRunnerGenericPreflightRequest request = request_for(&image, &header, 0x100, 0x500);
  request.process.mounts = &mounts;
  request.process.handles = &handles;
  request.process.files = &files;
  request.process.guest_size = kind == 10 || kind == 11 ? k_memory_size : 0x100000;
  if (kind == 10 || kind == 11) {
    request.process.environment_segment = k_environment_segment;
    request.process.dpmi_entry_segment = k_dpmi_entry_segment;
    request.process.dos_vector_segment = k_dos_int21_vector_segment;
  }
  uint8_t child_bytes[0x100] = {'M', 'Z'};
  const uint8_t child_code[] = {
    0xbb, 5,    0,    /* mov bx,5 */
    0xb4, 0x3e,       /* mov ah,0x3e */
    0xcd, 0x21,       /* int 0x21 */
    0xba, 0x78, 0x56, /* mov dx,0x5678 */
    0xb4, 0x1a,       /* mov ah,0x1a */
    0xcd, 0x21,       /* int 0x21 */
    0xb8, 0x25, 0x4c, /* mov ax,0x4c25 */
    0xcd, 0x21,       /* int 0x21 */
  };
  memcpy(child_bytes + 0x20, child_code, sizeof(child_code));
  daze_write_u16(child_bytes + 2, sizeof(child_bytes));
  daze_write_u16(child_bytes + 4, 1);
  daze_write_u16(child_bytes + 8, 2);
  daze_write_u16(child_bytes + 0x10, 0xfffe);
  daze_write_u16(child_bytes + 0x18, 0x1c);
  if (kind == 1) child_bytes[0x20 + 15] = 0;
  if (kind == 2) child_bytes[0x20] = 0xf4;
  if (kind == 4) child_bytes[0] = 'X';
  if (kind == 5) {
    daze_write_u16(child_bytes + 6, 1);
    daze_write_u16(child_bytes + 0x1c, 0xffff);
  }
  if (kind == 9) {
    const uint8_t nested[] = {
      0xb8, 0,    0x4b, /* mov ax,0x4b00 */
      0xcd, 0x21,       /* int 0x21 */
    };
    memcpy(child_bytes + 0x20, nested, sizeof(nested));
  }
  if (kind == 10) {
    const uint8_t protected_child[] = {
      0xb8, 0x87, 0x16,       /* mov ax,0x1687 */
      0xcd, 0x2f,             /* int 0x2f */
      0x9a, 0,    0,    0, 2, /* call far 0200h:0000 */
      0xb8, 0,    4,          /* mov ax,0x400 */
      0xcd, 0x31,             /* int 0x31 */
      0xb8, 0x25, 0x4c,       /* mov ax,0x4c25 */
      0xcd, 0x21,             /* int 0x21 */
    };
    memcpy(child_bytes + 0x20, protected_child, sizeof(protected_child));
  }
  if (kind == 11) {
    const uint8_t resident_child[] = {
      0xb8, 0x87, 0x16,       /* mov ax,0x1687 */
      0xcd, 0x2f,             /* int 0x2f */
      0x9a, 0,    0,    0, 2, /* call far 0200h:0000 */
      0xba, 0x1e, 0,          /* mov dx,0x1e */
      0xb8, 0x25, 0x31,       /* mov ax,0x3125 */
      0xcd, 0x21,             /* int 0x21 */
    };
    const uint8_t returned[] = {
      0xb8, 0x25, 0x4c, /* mov ax,0x4c25 */
      0xcd, 0x21,       /* int 0x21 */
    };
    memcpy(child_bytes + 0x20, resident_child, sizeof(resident_child));
    memcpy(child_bytes + 0x20 + 0x80, returned, sizeof(returned));
  }
  const int child_fd = openat(root_fd, "CHILD.EXE", O_WRONLY | O_CREAT | O_EXCL, 0600);
  int failed = child_fd < 0;
  if (child_fd >= 0) {
    failed |= write(child_fd, child_bytes, sizeof(child_bytes)) != sizeof(child_bytes);
    close(child_fd);
  }
  DazeKvmCommandOwnerHandoff owner = {0};
  DazeKvmCommandOwnerResult result = {0};
  DazeDpmiProcessState dpmi = {.next_ldt_index = 0x2a, .virtual_interrupts_enabled = 1};
  const DazeDpmiProcessState parent_dpmi = dpmi;
  int status = daze_kvm_command_owner_begin(&request, &owner);
  int parent_fd = -1, search_fd = -1;
  if (status != DAZE_KVM_COMMAND_OWNER_HANDOFF_EXEC || !owner.active) {
    failed = 1;
    goto out;
  }
  const int vm = owner.machine.vm, vcpu = owner.machine.vcpu;
  uint8_t *guest = owner.machine.guest;
  uint8_t *parameter = guest + 0x1100;
  memset(parameter, 0, 14);
  daze_write_u16(parameter, 0x200);
  daze_write_u16(parameter + 2, 0x180);
  daze_write_u16(parameter + 4, 0x100);
  daze_write_u16(parameter + 6, 0x220);
  daze_write_u16(parameter + 8, 0x100);
  daze_write_u16(parameter + 10, 0x230);
  daze_write_u16(parameter + 12, 0x100);
  guest[0x1180] = kind == 8 ? 127 : 2;
  memcpy(guest + 0x1181, " -", 2);
  strcpy((char *)guest + 0x1200, kind == 3 ? "MISSING.EXE" : "CHILD.EXE");
  guest[0x12f0] = 0x55;
  if (kind == 7) owner.preflight.request_es = 0xffff;
  if (kind == 12) memset(guest + 0x1200, 'A', 128);
  if (kind == 13) {
    owner.preflight.request_ds = 0xffff;
    owner.preflight.request_dx = 0xffff;
  }
  if (kind >= 14 && kind <= 16) {
    const size_t slot = 2 + (size_t)(kind - 14) * 4;
    daze_write_u16(parameter + slot, 0xffff);
    daze_write_u16(parameter + slot + 2, 0xffff);
  }
  if (kind == 17) daze_dos_memory_init(&owner.dos_memory, 0x3000, 0x3001);
  if (kind == 18) owner.preflight.request_ax = 0x4b01;
  if (kind == 19) owner.preflight.request_vector = 0x2f;
  daze_dos_process_state_set_dta(&owner.process_state, 0x1234, 0x5678);
  owner.process_state.find.directory = fdopendir(dup(root_fd));
  if (owner.process_state.find.directory == NULL) {
    failed = 1;
    goto out;
  }
  search_fd = dirfd(owner.process_state.find.directory);
  parent_fd = openat(root_fd, "CHILD.EXE", O_RDONLY);
  if (parent_fd < 0) {
    failed = 1;
    goto out;
  }
  handles.host_fds[5] = parent_fd;
  if (kind == 6) close(parent_fd);
  const DazeDosMemory before_memory = owner.dos_memory;
  const DazeDosProcessState before_dos = owner.process_state;
  status = daze_kvm_command_owner_start_exec(&owner, &request, &dpmi, &result);
  failed |= status != (int)result.disposition || !result.guest_execution_may_have_started ||
            !result.handoff_present || !owner.active;
  if (kind < 2 || kind == 10 || kind == 11) {
    const uint8_t expected_exit = kind == 1 ? 0 : 0x25;
    const DazeCommandResult normalized =
      daze_kvm_command_result_normalize(&(DazeKvmCommandNormalizerInput){
        .disposition = status,
        .guest_execution_started = result.guest_execution_may_have_started,
        .exit_status_present = result.guest_exit_status_present,
        .exit_status = result.guest_exit_status});
    failed |=
      status != DAZE_KVM_COMMAND_OWNER_TERMINATED || !result.guest_exit_status_present ||
      result.guest_exit_status != expected_exit ||
      normalized.disposition != DAZE_COMMAND_COMPLETED ||
      normalized.dos_exit_code != expected_exit || owner.child.active || owner.parent_input_valid ||
      owner.child_handles.live != NULL ||
      (kind != 11 && memcmp(&owner.dos_memory, &before_memory, sizeof(before_memory)) != 0) ||
      (kind != 11 && memcmp(&dpmi, &parent_dpmi, sizeof(dpmi)) != 0) ||
      owner.process_state.dta_segment != 0x1234 || owner.process_state.dta_offset != 0x5678 ||
      owner.process_state.find.directory != before_dos.find.directory ||
      owner.process_state.child_status_available || guest[0x12f0] != 0x55 ||
      handles.host_fds[5] != parent_fd || fcntl(parent_fd, F_GETFD) < 0 ||
      fcntl(search_fd, F_GETFD) < 0;
    if (kind == 11) {
      int retained = 0;
      for (size_t i = 0; i < DAZE_DOS_MEMORY_MAX_ALLOCS; ++i)
        retained |= owner.dos_memory.allocations[i].in_use &&
                    owner.dos_memory.allocations[i].segment == 0x3000 &&
                    owner.dos_memory.allocations[i].paragraphs == 0x1e;
      failed |= !retained || !owner.resident_gdt_valid || !owner.resident_gdt.valid;
    }
  } else {
    const int captured = kind == 2 || kind == 5 || kind == 6 || kind == 9;
    failed |= status != DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED ||
              result.guest_exit_status_present || owner.child.active != captured ||
              owner.parent_input_valid != captured;
    if (!captured)
      failed |= memcmp(&owner.dos_memory, &before_memory, sizeof(before_memory)) != 0 ||
                memcmp(&owner.process_state, &before_dos, sizeof(before_dos)) != 0 ||
                memcmp(&dpmi, &parent_dpmi, sizeof(dpmi)) != 0;
    else
      failed |= owner.child.parent_dos.find.directory != before_dos.find.directory ||
                owner.child.parent_dpmi == NULL || owner.child.child_image.bytes == NULL;
  }
  daze_kvm_command_owner_handoff_destroy(&owner);
  daze_kvm_command_owner_handoff_destroy(&owner);
  failed |= fcntl(vm, F_GETFD) != -1 || errno != EBADF || fcntl(vcpu, F_GETFD) != -1 ||
            errno != EBADF || fcntl(search_fd, F_GETFD) != -1 || errno != EBADF;
out:
  daze_kvm_command_owner_handoff_destroy(&owner);
  daze_dosfs_handles_close_all(&handles);
  unlinkat(root_fd, "CHILD.EXE", 0);
  close(root_fd);
  rmdir(root);
  if (failed)
    fprintf(stderr, "owner EXEC case %d: status=%d disposition=%d started=%d exit=%d/%u\n", kind,
            status, result.disposition, result.guest_execution_may_have_started,
            result.guest_exit_status_present, result.guest_exit_status);
  return failed;
}

static int parent_snapshot_lifecycle(void) {
  /* Parent: park at EXEC, collect child status, then terminate. Child: exit 1. */
  static uint8_t parent_bytes[0x2f] = {
    'M',  'Z',  0x2f, 0, 1, 0, 0,    0, 2, 0, 0, 0, 0, 0, 0,    0, 0xfe, 0xff,
    0,    0,    0,    0, 0, 0, 0x1c, 0, 0, 0, 0, 0, 0, 0, 0xb8, 0, 0x4b, /* mov ax,0x4b00 */
    0xcd, 0x21,                                                          /* int 0x21 */
    0xb8, 0,    0x4d,                                                    /* mov ax,0x4d00 */
    0xcd, 0x21,                                                          /* int 0x21 */
    0xb8, 0,    0x4c,                                                    /* mov ax,0x4c00 */
    0xcd, 0x21,                                                          /* int 0x21 */
  };
  static uint8_t child_bytes[0x25] = {
    'M',  'Z',  0x25, 0, 1, 0, 0,    0, 2, 0, 0, 0, 0, 0, 0,    0, 0xfe, 0xff,
    0,    0,    0,    0, 0, 0, 0x1c, 0, 0, 0, 0, 0, 0, 0, 0xb8, 1, 0x4c, /* mov ax,0x4c01 */
    0xcd, 0x21,                                                          /* int 0x21 */
  };
  static DazeImage parent_image = {parent_bytes, sizeof(parent_bytes)};
  static DazeImage child_image = {child_bytes, sizeof(child_bytes)};
  static DazeMzHeader parent_header = {.header_paragraphs = 2,
                                       .initial_sp = 0xfffe,
                                       .module_size = sizeof(parent_bytes),
                                       .image_offset = 0x20,
                                       .image_size = 15,
                                       .relocation_offset = 0x1c};
  static DazeMzHeader child_header = {.header_paragraphs = 2,
                                      .initial_sp = 0xfffe,
                                      .module_size = sizeof(child_bytes),
                                      .image_offset = 0x20,
                                      .image_size = 5,
                                      .relocation_offset = 0x1c};
  const DazeKvmRunnerGenericPreflightRequest parent_request =
    request_for(&parent_image, &parent_header, 0x0100, 0x0500);
  const DazeKvmRunnerGenericPreflightRequest child_request =
    request_for(&child_image, &child_header, 0x1000, 0x1100);
  DazeKvmMachine machine;
  const int init = daze_kvm_machine_init(&machine, parent_request.process.guest_size);
  if (init == DAZE_KVM_MACHINE_UNAVAILABLE) return 77;
  if (init != DAZE_KVM_MACHINE_OK) return 1;

  int passed = 0;
  int stage = 0;
  int child_status = 0;
  int parent_status = 0;
  DazeKvmRunnerGenericPreflightResult parent_parked;
  DazeKvmRunnerGenericPreflightResult child_terminated = {0};
  DazeKvmRunnerGenericPreflightResult parent_successor = {0};
  if (daze_kvm_runner_preflight_to_generic_boundary(&machine, &parent_request, &parent_parked) !=
        DAZE_KVM_GENERIC_PREFLIGHT_EXEC ||
      parent_parked.request_vector != 0x21 || parent_parked.request_ax != 0x4b00)
    goto out;
  stage = 1;

  const uint32_t parent_tail = ((uint32_t)parent_request.process.psp_segment << 4) + 0x80;
  ((uint8_t *)machine.guest)[parent_tail] = 0x7b;
  DazeDosProcessState dos_state;
  daze_dos_process_state_init(&dos_state, parent_request.process.psp_segment);
  daze_dos_process_state_seed_vectors(&dos_state, parent_request.process.dos_vector_segment);
  daze_dos_process_state_set_dta(&dos_state, 0x1234, 0x5678);
  DazeDosMemory dos_memory;
  daze_dos_memory_init(&dos_memory, 0x3000, 0xa000);
  if (daze_dos_memory_allocate(&dos_memory, 8) == NULL) goto out_dispose;
  stage = 2;
  DazeDpmiProcessState dpmi = {.next_ldt_index = 0x2a};
  DazeKvmChildContext child = {0};
  if (!daze_kvm_child_context_capture(&child, &machine, &parent_request.process, &dos_state,
                                      &dos_memory, &dpmi))
    goto out_dispose;
  stage = 3;

  child_status =
    daze_kvm_runner_preflight_to_generic_boundary(&machine, &child_request, &child_terminated);
  const uint8_t child_exit_status = (uint8_t)child_terminated.request_ax;
  if (child_status != DAZE_KVM_GENERIC_PREFLIGHT_TERMINATED ||
      child_terminated.request_vector != 0x21 || child_terminated.request_ax != 0x4c01 ||
      !child_terminated.mailbox_unchanged || child_terminated.terminal_observation_status != 0 ||
      !daze_kvm_child_context_restore(&child, &machine, &dos_state, &dos_memory, &dpmi) ||
      daze_kvm_command_owner_reply_exec_success(&machine) != DAZE_KVM_RUNNER_GATE_RESUME_OK)
    goto out_child;
  daze_dos_process_state_record_child_termination(&dos_state, child_exit_status, 0);
  stage = 4;

  parent_status = daze_kvm_runner_resume_to_generic_boundary(&machine, &parent_request, &dos_state,
                                                             &dos_memory, &parent_successor);
  passed =
    child_exit_status == 1 && parent_status == DAZE_KVM_GENERIC_PREFLIGHT_TERMINATED &&
    parent_successor.request_vector == 0x21 && parent_successor.request_ax == 0x4c00 &&
    parent_successor.mailbox_unchanged && parent_successor.terminal_observation_status == 0 &&
    ((const uint8_t *)machine.guest)[parent_tail] == 0x7b && dos_state.dta_segment == 0x1234 &&
    dos_state.dta_offset == 0x5678 && dos_memory.allocations[0].in_use &&
    dos_memory.allocations[0].segment == 0x3000 && dos_memory.allocations[0].paragraphs == 8 &&
    dpmi.next_ldt_index == 0x2a && !dos_state.child_status_available;
  stage = 5;
out_child:
  daze_kvm_child_context_dispose(&child);
out_dispose:
  daze_dos_process_state_dispose(&dos_state);
out:
  daze_kvm_machine_destroy(&machine);
  if (!passed) {
    fprintf(
      stderr,
      "KVM EXEC parent lifecycle contract failed stage=%d parent=%d/%02x/%04x child=%d/%02x/%04x\n",
      stage, parent_status, parent_successor.request_vector, parent_successor.request_ax,
      child_status, child_terminated.request_vector, child_terminated.request_ax);
    return 1;
  }
  return 0;
}

int main(int argc, char **argv) {
  FILE *trace = NULL;
  int saved_stderr = -1;
  if (argc == 2 && strcmp(argv[1], "--trace-contract") == 0) {
    trace = tmpfile();
    saved_stderr = dup(STDERR_FILENO);
    if (trace == NULL || saved_stderr < 0 || setenv("DAZE_EXEC_TRACE", "1", 1) != 0 ||
        dup2(fileno(trace), STDERR_FILENO) < 0)
      return 1;
  }
  const int status = parent_snapshot_lifecycle();
  if (status != 0) return status;
  for (int kind = 0; kind < 20; ++kind)
    if (owner_exec_case(kind)) return 1;
  if (trace != NULL) {
    fflush(stderr);
    if (dup2(saved_stderr, STDERR_FILENO) < 0) return 1;
    close(saved_stderr);
    rewind(trace);
    char bytes[65536];
    const size_t size = fread(bytes, 1, sizeof(bytes) - 1, trace);
    bytes[size] = 0;
    fclose(trace);
    if (size == sizeof(bytes) - 1 || strstr(bytes, "exec: request ds:dx=") == NULL ||
        strstr(bytes, "path=CHILD.EXE parameter") == NULL ||
        strstr(bytes, "exec: child PSP=") == NULL ||
        strstr(bytes, "exec: child owner disposition=") == NULL ||
        strstr(bytes, "exec: child protected terminal") == NULL)
      return 1;
  }
  return 0;
}
