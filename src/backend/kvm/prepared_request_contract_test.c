#include "prepared_request.h"

#include <string.h>

static DazeKvmPreparedRequestInput valid_input(DazeDosfsFileService *files) {
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
  daze_dosfs_mounts_init(&mounts);
  daze_dosfs_handles_init(&handles);
  return (DazeKvmPreparedRequestInput){
    .image = &image,
    .header = &header,
    .command_tail = " -oFOO.O MIPS.S",
    .guest_path = "C:\\ASPSX.EXE",
    .mounts = &mounts,
    .handles = &handles,
    .files = files,
    .layout = {.psp_segment = 0x0ff0,
               .environment_segment = 0x0700,
               .dpmi_entry_segment = 0x0200,
               .dos_vector_segment = 0x0300,
               .load_segment = 0x1000,
               .guest_size = 8 * 1024 * 1024},
  };
}

int main(void) {
  DazeDosfsFileService files = {0};
  DazeKvmPreparedRequestInput input = valid_input(&files);
  DazeKvmRunnerRequestCommon request = {.image = (void *)1};
  if (!daze_kvm_prepared_request_build(&input, &request) || request.image != input.image ||
      request.header != input.header || request.command_tail != input.command_tail ||
      request.guest_path != input.guest_path || request.mounts != input.mounts ||
      request.handles != input.handles || request.files != &files || files.mounts != input.mounts ||
      files.handles != input.handles || request.stop_linear != 0 ||
      request.dpmi_entry_segment != input.layout.dpmi_entry_segment ||
      request.dos_vector_segment != input.layout.dos_vector_segment ||
      request.guest_size != input.layout.guest_size)
    return 1;
  const DazeKvmPreparedProcessLayout original = input.layout;
  input.layout.dpmi_entry_segment = 0x0500;
  input.layout.dos_vector_segment = 0x0600;
  input.layout.guest_size = 0x40000;
  if (!daze_kvm_prepared_request_build(&input, &request) || request.dpmi_entry_segment != 0x0500 ||
      request.dos_vector_segment != 0x0600 || request.guest_size != 0x40000)
    return 1;
  input.layout.guest_size = 0;
  if (daze_kvm_prepared_request_build(&input, &request) ||
      memcmp(&request, &(DazeKvmRunnerRequestCommon){0}, sizeof(request)) != 0)
    return 1;
  input.layout = original;
  input.files = NULL;
  if (daze_kvm_prepared_request_build(&input, &request)) return 1;
  return 0;
}
