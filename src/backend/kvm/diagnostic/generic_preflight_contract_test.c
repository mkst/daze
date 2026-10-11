#include "runner_private.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int unsupported_dos_diagnostic(const DazeKvmRunnerGenericPreflightRequest *request) {
  DazeKvmMachine machine;
  if (daze_kvm_machine_init(&machine, request->process.guest_size) != DAZE_KVM_MACHINE_OK) return 0;
  FILE *capture = tmpfile();
  const int saved_stderr = dup(STDERR_FILENO);
  int valid = 0;
  if (capture == NULL || saved_stderr < 0) goto out;
  fflush(stderr);
  if (dup2(fileno(capture), STDERR_FILENO) < 0) goto out;
  DazeKvmRunnerGenericPreflightResult result;
  const int status = daze_kvm_runner_preflight_to_generic_boundary(&machine, request, &result);
  fflush(stderr);
  const int restored = dup2(saved_stderr, STDERR_FILENO);
  rewind(capture);
  char diagnostic[512] = {0};
  const size_t count = fread(diagnostic, 1, sizeof(diagnostic) - 1, capture);
  valid = restored >= 0 && count > 0 && status == DAZE_KVM_GENERIC_PREFLIGHT_UNSUPPORTED &&
          result.guest_execution_may_have_started && result.request_vector == 0x21 &&
          result.request_ax == 0x4501 &&
          strcmp(diagnostic, "unsupported DOS 21h function 45h (AX=4501 BX=0001 CX=0000 DX=0000) "
                             "at CS:IP=0500:0008 DS=0100\n") == 0;
out:
  if (saved_stderr >= 0) close(saved_stderr);
  if (capture != NULL) fclose(capture);
  daze_kvm_machine_destroy(&machine);
  if (!valid) fputs("unsupported DOS request did not produce its guest diagnostic\n", stderr);
  return valid;
}

int main(void) {
  static uint8_t bytes[0x2a] = {
    'M',  'Z',  0x2a, 0, 1, 0, 0,    0, 2, 0, 0, 0, 0, 0, 0,    0,    0xfe, 0xff,
    0,    0,    0,    0, 0, 0, 0x1c, 0, 0, 0, 0, 0, 0, 0, 0xb8, 0x87, 0x16, /* mov ax,0x1687 */
    0xcd, 0x2f,                                                             /* int 0x2f */
    0x9a, 0,    0,    0, 3, /* call far 0300h:0000 */};
  static DazeImage image = {bytes, sizeof(bytes)};
  static DazeMzHeader header = {.header_paragraphs = 2,
                                .initial_sp = 0xfffe,
                                .module_size = sizeof(bytes),
                                .image_offset = 0x20,
                                .image_size = 10,
                                .relocation_offset = 0x1c};
  static DazeDosfsMounts mounts;
  static DazeDosfsHandles handles;
  static DazeDosfsFileService files;
  DazeKvmMachine machine;
  const int init = daze_kvm_machine_init(&machine, 0x40000);
  if (init == DAZE_KVM_MACHINE_UNAVAILABLE) return 77;
  if (init != DAZE_KVM_MACHINE_OK) return 1;
  const DazeKvmRunnerGenericPreflightRequest request = {
    .process = {.image = &image,
                .header = &header,
                .command_tail = "",
                .guest_path = "C:\\TOOL.EXE",
                .psp_segment = 0x0100,
                .environment_segment = 0x0200,
                .dpmi_entry_segment = 0x0300,
                .dos_vector_segment = 0x0400,
                .load_segment = 0x0500,
                .guest_size = 0x40000,
                .mounts = &mounts,
                .handles = &handles,
                .files = &files},
  };
  DazeKvmRunnerGenericPreflightResult result;
  const int status = daze_kvm_runner_preflight_to_generic_boundary(&machine, &request, &result);
  const int valid = status == DAZE_KVM_GENERIC_PREFLIGHT_DPMI_ENTRY &&
                    result.guest_execution_may_have_started && result.dpmi_handoff.valid &&
                    result.dpmi_handoff.vector == 0xfe && result.dpmi_handoff.return_cs == 0x0300 &&
                    result.dpmi_handoff.return_ip == 2 &&
                    result.dpmi_handoff.caller_return_cs == 0x0500 &&
                    result.dpmi_handoff.caller_return_ip == 10 && result.mailbox_unchanged;
  daze_kvm_machine_destroy(&machine);
  if (!valid) {
    fprintf(stderr, "generic preflight status=%d vector=%02x return=%04x:%04x unchanged=%d\n",
            status, result.request_vector, result.dpmi_handoff.return_cs,
            result.dpmi_handoff.return_ip, result.mailbox_unchanged);
    return 1;
  }
  const uint8_t unsupported_guest[] = {0xb8, 0x01, 0x45, 0xbb, 0x01, 0x00, 0xcd, 0x21, 0xf4, 0x90};
  memcpy(bytes + header.image_offset, unsupported_guest, sizeof(unsupported_guest));
  if (!unsupported_dos_diagnostic(&request)) return 1;
  puts("KVM generic preflight: passed");
  return 0;
}
