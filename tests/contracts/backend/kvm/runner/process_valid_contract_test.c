#include "runner_private.h"

#include "dosfs.h"

#include <stdio.h>
#include <string.h>

static int pass = 1;

static void check(int condition, const char *message) {
  if (!condition) {
    fprintf(stderr, "runner process-valid contract failed: %s\n", message);
    pass = 0;
  }
}

static DazeKvmRunnerRequestCommon valid_request(DazeImage *image, DazeMzHeader *header,
                                                DazeDosfsMounts *mounts, DazeDosfsHandles *handles,
                                                DazeDosfsFileService *files) {
  return (DazeKvmRunnerRequestCommon){
    .image = image,
    .header = header,
    .command_tail = " -oFOO.O MIPS.S",
    .guest_path = "C:\\ASPSX.EXE",
    .psp_segment = 0x0ff0,
    .environment_segment = 0x0700,
    .dpmi_entry_segment = 0x0200,
    .dos_vector_segment = 0x0300,
    .load_segment = 0x1000,
    .guest_size = 8u * 1024u * 1024u,
    .stop_linear = 0,
    .mounts = mounts,
    .handles = handles,
    .files = files,
  };
}

int main(void) {
  static uint8_t bytes[0x40] = {'M', 'Z'};
  static DazeImage image = {bytes, sizeof(bytes)};
  static DazeMzHeader header = {.header_paragraphs = 2,
                                .initial_sp = 0xfffe,
                                .module_size = sizeof(bytes),
                                .image_offset = 0x20,
                                .image_size = 15,
                                .relocation_offset = 0x1c};
  static DazeDosfsMounts mounts;
  static DazeDosfsHandles handles;
  static DazeDosfsFileService files;
  daze_dosfs_mounts_init(&mounts);
  daze_dosfs_handles_init(&handles);

  DazeKvmRunnerRequestCommon request = valid_request(&image, &header, &mounts, &handles, &files);
  check(daze_kvm_runner_process_valid(&request), "valid request accepted");
  check(!daze_kvm_runner_process_valid(NULL), "null request rejected");
  request = valid_request(&image, &header, &mounts, &handles, &files);
  request.stop_linear = request.guest_size;
  check(!daze_kvm_runner_process_valid(&request), "stop at guest end rejected");
  request = valid_request(&image, &header, &mounts, &handles, &files);
  request.stop_linear = request.guest_size - 1;
  check(daze_kvm_runner_process_valid(&request), "stop inside guest accepted");
  /* An image spanning the runner record/mailbox is rejected pre-start. */
  static DazeMzHeader big = {.header_paragraphs = 2,
                             .initial_sp = 0xfffe,
                             .module_size = 0x90020,
                             .image_offset = 0x20,
                             .image_size = 0x90000,
                             .relocation_offset = 0x1c};
  request = valid_request(&image, &big, &mounts, &handles, &files);
  check(!daze_kvm_runner_process_valid(&request), "image over runner ranges rejected");
  return pass ? 0 : 1;
}
