#include "normal_operation.h"
#include "guest_memory_layout.h"

#include <stdio.h>
#include <string.h>

static int run_case(int kind) {
  static const uint8_t terminate[] = {0xb8, 0x9b, 0x4c, /* mov ax,4c9bh */
                                      0xcd, 0x21};      /* int 21h */
  static const uint8_t protected_terminate[] = {
    0xb8, 0x87, 0x16,             /* mov ax,1687h */
    0xcd, 0x2f,                   /* int 2fh */
    0xb8, 0x01, 0x00,             /* mov ax,1 */
    0x9a, 0x00, 0x00, 0x00, 0x02, /* call far 0200h:0000 */
    0xb8, 0xd3, 0x4c,             /* mov ax,4cd3h */
    0xcd, 0x21,                   /* int 21h */
  };
  static const uint8_t rejected[] = {0xf4}; /* hlt */
  const uint8_t *code = kind == 0 ? terminate : kind == 1 ? protected_terminate : rejected;
  const size_t code_size = kind == 0   ? sizeof(terminate)
                           : kind == 1 ? sizeof(protected_terminate)
                                       : sizeof(rejected);
  uint8_t bytes[64] = {'M', 'Z'};
  memcpy(bytes + 32, code, code_size);
  DazeImage image = {bytes, 32 + code_size};
  DazeMzHeader header = {.header_paragraphs = 2,
                         .module_size = image.size,
                         .image_offset = 32,
                         .image_size = code_size,
                         .initial_sp = 0xfffe,
                         .relocation_offset = 0x1c};
  DazeDosfsMounts mounts;
  DazeDosfsHandles handles;
  DazeDosfsFileService files;
  daze_dosfs_mounts_init(&mounts);
  daze_dosfs_handles_init(&handles);
  daze_dosfs_file_service_init(&files, &mounts, &handles);
  DazeKvmRunnerRequestCommon request = {.image = &image,
                                        .header = &header,
                                        .command_tail = "",
                                        .guest_path = "C:\\TOOL.EXE",
                                        .mounts = &mounts,
                                        .handles = &handles,
                                        .files = &files,
                                        .psp_segment = k_psp_segment,
                                        .environment_segment = k_environment_segment,
                                        .dpmi_entry_segment = k_dpmi_entry_segment,
                                        .dos_vector_segment = k_dos_int21_vector_segment,
                                        .load_segment = k_load_segment,
                                        .guest_size = k_memory_size};
  DazeKvmMachine machine;
  int status = daze_kvm_machine_init(&machine, k_memory_size);
  if (status == DAZE_KVM_MACHINE_UNAVAILABLE) return 77;
  if (status != DAZE_KVM_MACHINE_OK) return 1;
  DazeKvmNormalOperationObservation observation;
  DazeCommandResult result =
    daze_kvm_normal_operation_run_observe(&request, &machine, &observation);
  int failed = !result.guest_execution_started;
  failed |= machine.kvm != -1 || machine.vm != -1 || machine.vcpu != -1;
  if (kind < 2)
    failed |= result.disposition != DAZE_COMMAND_COMPLETED ||
              result.dos_exit_code != (kind == 0 ? 0x9b : 0xd3) ||
              observation.source != (kind == 0 ? 1 : 2);
  else
    failed |= result.disposition != DAZE_COMMAND_POSTSTART_FAILED || observation.source != 1 ||
              !observation.present;
  if (kind == 1) failed |= !observation.present;
  if (failed)
    fprintf(stderr, "normal execution case=%d command=%d status=%u started=%d observation=%d/%d\n",
            kind, result.disposition, result.dos_exit_code, result.guest_execution_started,
            observation.present, observation.source);
  daze_kvm_machine_destroy(&machine);
  return failed;
}

int main(void) {
  for (int kind = 0; kind < 3; ++kind) {
    int status = run_case(kind);
    if (status) return status;
  }
  return 0;
}
