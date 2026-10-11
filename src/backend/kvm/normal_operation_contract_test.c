#include "guest_memory_layout.h"
#include "normal_operation.h"
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
               .guest_size = k_memory_size},
  };
}

int main(void) {
  DazeDosfsFileService files = {0};
  DazeKvmRunnerRequestCommon request = {0};
  DazeKvmPreparedRequestInput input = valid_input(&files);
  if (!daze_kvm_prepared_request_build(&input, &request) ||
      !daze_kvm_normal_operation_request_valid(&request))
    return 1;
  DazeKvmRunnerRequestCommon invalid = request;
  invalid.guest_size--;
  DazeKvmNormalOperationObservation observation = {.present = 1};
  DazeKvmMachine machine = {.kvm = 10, .vm = 11, .vcpu = 12};
  if (daze_kvm_normal_operation_request_valid(&invalid) ||
      daze_kvm_normal_operation_run_observe(&invalid, &machine, &observation).disposition !=
        DAZE_COMMAND_PRESTART_REJECTED ||
      observation.present || machine.kvm != 10 || machine.vm != 11 || machine.vcpu != 12 ||
      daze_kvm_normal_operation_run_observe(NULL, NULL, NULL).disposition !=
        DAZE_COMMAND_PRESTART_REJECTED)
    return 1;
  return 0;
}
