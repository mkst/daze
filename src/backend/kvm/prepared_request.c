#include "prepared_request.h"

#include "runner_private.h"

int daze_kvm_prepared_request_build(const DazeKvmPreparedRequestInput *input,
                                    DazeKvmRunnerRequestCommon *request) {
  if (request != NULL) *request = (DazeKvmRunnerRequestCommon){0};
  if (input == NULL || request == NULL || input->image == NULL || input->header == NULL ||
      input->command_tail == NULL || input->guest_path == NULL || input->mounts == NULL ||
      input->handles == NULL || input->files == NULL)
    return 0;
  if (input->env_var_count < 0 || input->env_var_count > DAZE_PROCESS_ENV_MAX_EXTRA_VARS) return 0;
  if (input->env_var_count > 0 && input->env_vars == NULL) return 0;
  daze_dosfs_file_service_init(input->files, input->mounts, input->handles);
  *request = (DazeKvmRunnerRequestCommon){
    .image = input->image,
    .header = input->header,
    .command_tail = input->command_tail,
    .guest_path = input->guest_path,
    .psp_segment = input->layout.psp_segment,
    .environment_segment = input->layout.environment_segment,
    .dpmi_entry_segment = input->layout.dpmi_entry_segment,
    .dos_vector_segment = input->layout.dos_vector_segment,
    .load_segment = input->layout.load_segment,
    .guest_size = input->layout.guest_size,
    .stop_linear = 0,
    .mounts = input->mounts,
    .handles = input->handles,
    .files = input->files,
    .env_vars = input->env_vars,
    .env_var_count = input->env_var_count,
  };
  if (daze_kvm_runner_process_valid(request)) return 1;
  *request = (DazeKvmRunnerRequestCommon){0};
  return 0;
}
