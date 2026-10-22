#include "owner.h"

#include <stdio.h>
#include <string.h>

int main(void) {
  uint8_t bytes[0x25] = {0};
  DazeImage image = {bytes, sizeof(bytes)};
  DazeMzHeader header = {.header_paragraphs = 2,
                         .initial_sp = 0xfffe,
                         .module_size = sizeof(bytes),
                         .image_offset = 0x20,
                         .image_size = 5,
                         .relocation_offset = 0x1c};
  DazeDosfsMounts mounts;
  DazeDosfsHandles handles;
  DazeDosfsFileService files;
  daze_dosfs_mounts_init(&mounts);
  daze_dosfs_handles_init(&handles);
  daze_dosfs_file_service_init(&files, &mounts, &handles);
  const DazeKvmRunnerGenericPreflightRequest request = {.process = {.image = &image,
                                                                    .header = &header,
                                                                    .command_tail = "",
                                                                    .guest_path = "C:\\TOOL.EXE",
                                                                    .psp_segment = 0x100,
                                                                    .environment_segment = 0x200,
                                                                    .dpmi_entry_segment = 0x300,
                                                                    .dos_vector_segment = 0x400,
                                                                    .load_segment = 0x500,
                                                                    .guest_size = 0x80000,
                                                                    .mounts = &mounts,
                                                                    .handles = &handles,
                                                                    .files = &files}};
  DazeKvmCommandOwnerHandoff owner = {0};
  DazeKvmMachine machine = {.kvm = -1, .vm = -1, .vcpu = -1};
  const DazeKvmMachine before = machine;
  DazeKvmRunnerGenericPreflightResult observation;
  int pass = 1;
  for (int kind = 0; kind < 4; ++kind) {
    DazeKvmRunnerGenericPreflightRequest invalid = request;
    if (kind == 0) invalid.process.header = NULL;
    if (kind == 1) invalid.process.guest_size = 0;
    if (kind == 2) invalid.process.image = NULL;
    memset(&observation, 0xa5, sizeof(observation));
    pass = pass &&
           daze_kvm_command_owner_begin_observe(&invalid, &machine, &owner, &observation) ==
             DAZE_KVM_COMMAND_OWNER_HANDOFF_PRESTART_REJECTED &&
           !owner.active && !observation.guest_execution_may_have_started &&
           memcmp(&machine, &before, sizeof(machine)) == 0;
  }
  pass = pass &&
         daze_kvm_command_owner_begin(NULL, &owner) ==
           DAZE_KVM_COMMAND_OWNER_HANDOFF_PRESTART_REJECTED &&
         daze_kvm_command_owner_begin(&request, NULL) ==
           DAZE_KVM_COMMAND_OWNER_HANDOFF_PRESTART_REJECTED;
  DazeDpmiProcessState state = {0};
  DazeKvmCommandOwnerResult result;
  const DazeKvmCommandOwnerInput input = {.preflight = request, .state = &state};
  pass = pass &&
         daze_kvm_command_owner_continue(&owner, &input, &result) ==
           DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED &&
         result.disposition == DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED &&
         !result.guest_exit_status_present &&
         daze_kvm_command_owner_start_exec(&owner, &request, &state, &result) ==
           DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED &&
         result.disposition == DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED && !result.handoff_present;
  owner.active = 1;
  owner.process = request.process;
  owner.preflight.guest_execution_may_have_started = 1;
  const DazeKvmCommandOwnerHandoff saved = owner;
  pass = pass &&
         daze_kvm_command_owner_begin_observe(&request, &machine, &owner, NULL) ==
           DAZE_KVM_COMMAND_OWNER_HANDOFF_PRESTART_REJECTED &&
         daze_kvm_command_owner_start_exec(&owner, &request, &state, &result) ==
           DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED &&
         result.disposition == DAZE_KVM_COMMAND_OWNER_POSTSTART_FAILED &&
         result.guest_execution_may_have_started && result.handoff_present &&
         !result.guest_exit_status_present && memcmp(&owner, &saved, sizeof(owner)) == 0;
  owner = (DazeKvmCommandOwnerHandoff){0};
  daze_kvm_command_owner_handoff_destroy(&owner);
  daze_kvm_command_owner_handoff_destroy(NULL);
  fprintf(stderr, "Owner input contract: %s\n", pass ? "passed" : "failed");
  return pass ? 0 : 1;
}
