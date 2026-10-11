#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "exec_loader.h"
#include "guest_memory_layout.h"
#include "launch.h"
#include "prepared_request.h"

static void close_mounts(DazeDosfsMounts *mounts) {
  if (mounts == NULL) {
    return;
  }
  for (int index = 0; index < DAZE_DOSFS_MAX_DRIVES; ++index) {
    if (mounts->fds[index] >= 0) {
      close(mounts->fds[index]);
      mounts->fds[index] = -1;
    }
  }
}

static void dump_launch_layout(const DazePreparedLaunch *launch,
                               const DazeGuestLaunchInput *input) {
  if (launch == NULL || input == NULL || !launch->debug) return;
  DazeGuestLayout layout;
  if (!daze_guest_layout_build_launch(&layout, input, launch->allocation_start, NULL)) return;
  if (launch->kvm_request != NULL &&
      !daze_guest_layout_add_kvm_runner(&layout, launch->kvm_request->guest_size))
    return;
  for (size_t index = 0; index < layout.count; ++index) {
    char line[64];
    if (daze_guest_layout_format_range(line, sizeof(line), layout.ranges[index]) > 0)
      fprintf(stderr, "layout: %s\n", line);
  }
}

static void report_layout_failure(const char *path, const DazeGuestLaunchInput *input,
                                  const DazeGuestLaunchFailure *failure) {
  char first_text[64], second_text[64];
  daze_guest_layout_format_range(first_text, sizeof(first_text), failure->first);
  daze_guest_layout_format_range(second_text, sizeof(second_text), failure->second);
  switch (failure->kind) {
  case DAZE_GUEST_LAUNCH_RANGE_OUT_OF_GUEST:
    fprintf(stderr,
            "%s has unsupported guest memory layout: %s does not fit the %08x-byte guest at "
            "launch\n",
            path, first_text, input->guest_size);
    break;
  case DAZE_GUEST_LAUNCH_RANGE_OVERLAP:
    fprintf(stderr, "%s has conflicting guest memory layout: %s overlaps %s at launch\n", path,
            first_text, second_text);
    break;
  case DAZE_GUEST_LAUNCH_NO_LINEAR_ARENA:
    fprintf(stderr,
            "%s has unsupported guest memory layout: no DPMI linear arena after resident image "
            "end %08x (limit %08x) at launch\n",
            path, failure->first.address, input->linear_limit);
    break;
  case DAZE_GUEST_LAUNCH_ALLOCATION_MISMATCH: {
    const uint64_t image_end = (uint64_t)input->image_address + input->image_size;
    fprintf(stderr,
            "%s has conflicting guest memory layout: conventional allocation start %04x disagrees "
            "with resident image end %" PRIx64 " at launch\n",
            path, (uint32_t)failure->first.address >> 4, image_end);
    break;
  }
  case DAZE_GUEST_LAUNCH_VALID:
  case DAZE_GUEST_LAUNCH_BAD_INPUT:
  default:
    fprintf(stderr, "%s has unsupported guest memory layout: internal validation error\n", path);
    break;
  }
}

void initialize_prepared_launch(DazePreparedLaunch *launch) {
  if (launch == NULL) return;
  *launch = (DazePreparedLaunch){0};
  daze_dosfs_mounts_init(&launch->mounts);
  daze_dosfs_handles_init(&launch->handles);
  launch->mounts_initialized = 1;
  launch->handles_initialized = 1;
}

void dispose_prepared_launch(DazePreparedLaunch *launch) {
  if (launch == NULL) return;
  free(launch->kvm_request);
  daze_dosfs_transfer_storage_dispose(&launch->transfer_storage);
  if (launch->handles_initialized) daze_dosfs_handles_close_all(&launch->handles);
  if (launch->mounts_initialized) close_mounts(&launch->mounts);
  daze_image_free(&launch->image);
  *launch = (DazePreparedLaunch){0};
}

int prepare_launch(DazePreparedLaunch *launch, const char *path, const char *host_mz_path,
                   int is_drive_qualified, const char command_tail[127],
                   const char *const *env_vars, int env_var_count) {
  if (launch == NULL || path == NULL || host_mz_path == NULL || command_tail == NULL) return 3;
  if (env_var_count < 0 || env_var_count > DAZE_PROCESS_ENV_MAX_EXTRA_VARS) return 3;
  if (env_var_count > 0 && env_vars == NULL) return 3;
  if (!launch->mounts_initialized || !launch->handles_initialized) return 3;
  launch->guest_path = path;
  memcpy(launch->command_tail, command_tail, sizeof(launch->command_tail));
  launch->env_var_count = env_var_count;
  for (int i = 0; i < env_var_count; ++i) {
    launch->env_vars[i] = env_vars[i];
  }
  if (is_drive_qualified) {
    int host_errno = 0;
    if (!daze_dos_exec_load_mounted(&launch->mounts, path, &launch->image, &host_errno)) {
      fprintf(stderr, "cannot load %s from its mounted drive: %s\n", path,
              host_errno != 0 ? strerror(host_errno) : "invalid DOS path");
      return 2;
    }
  } else if (!daze_image_load(host_mz_path, &launch->image)) {
    fprintf(stderr, "cannot load %s\n", host_mz_path);
    return 2;
  }
  if (!daze_mz_parse_header(launch->image.bytes, launch->image.size, &launch->header)) {
    if (launch->image.size < 0x1c || launch->image.bytes[0] != 'M' ||
        launch->image.bytes[1] != 'Z') {
      fprintf(stderr, "%s is not a complete DOS MZ executable\n", path);
    } else {
      fprintf(stderr, "%s has unsupported or malformed MZ layout\n", path);
    }
    return 2;
  }
  launch->image_address = (uint32_t)k_load_segment << 4;
  if (launch->image_address + launch->header.image_size > k_memory_size) {
    fprintf(stderr, "%s has unsupported or malformed MZ layout\n", path);
    return 2;
  }
  uint32_t allocation_start = (launch->image_address + launch->header.image_size + 15u) >> 4;
  if (allocation_start < k_dos_conventional_floor_segment)
    allocation_start = k_dos_conventional_floor_segment;
  launch->allocation_start = allocation_start < k_dos_conventional_end_segment
                               ? (uint16_t)allocation_start
                               : k_dos_conventional_end_segment;
  /* Reject persistent-range collisions and missing DPMI arena space before executing
   * either backend. */
  const DazeGuestLaunchInput layout_input = {
    .guest_size = k_memory_size,
    .image_address = launch->image_address,
    .image_size = launch->header.image_size,
    .environment_size = k_dos_environment_max_size,
    .linear_min_address = k_dpmi_linear_min_address,
    .linear_limit = k_dpmi_linear_arena_limit,
  };
  DazeGuestLaunchFailure layout_failure;
  if (!daze_guest_launch_layout_valid(&layout_input, launch->allocation_start, &layout_failure)) {
    report_layout_failure(path, &layout_input, &layout_failure);
    return layout_failure.kind == DAZE_GUEST_LAUNCH_BAD_INPUT ? 3 : 2;
  }
  /* Preparing a KVM request executes no guest code. Failure only rejects
   * KVM before execution; it must not prevent a Unicorn launch. */
  const DazeKvmPreparedRequestInput kvm_input = {
    .image = &launch->image,
    .header = &launch->header,
    .command_tail = launch->command_tail,
    .guest_path = launch->guest_path,
    .mounts = &launch->mounts,
    .handles = &launch->handles,
    .files = &launch->files,
    .layout =
      {
        .psp_segment = k_psp_segment,
        .environment_segment = k_environment_segment,
        .dpmi_entry_segment = k_dpmi_entry_segment,
        .dos_vector_segment = k_dos_int21_vector_segment,
        .load_segment = k_load_segment,
        .guest_size = k_memory_size,
      },
    .env_vars = env_vars,
    .env_var_count = env_var_count,
  };
  launch->kvm_request = calloc(1, sizeof(*launch->kvm_request));
  if (launch->kvm_request != NULL &&
      !daze_kvm_prepared_request_build(&kvm_input, launch->kvm_request)) {
    free(launch->kvm_request);
    launch->kvm_request = NULL;
  }
  daze_dosfs_file_service_set_transfer_storage(&launch->files, &launch->transfer_storage);
  daze_dosfs_file_service_set_run_metrics(&launch->files, &launch->run_metrics);
  dump_launch_layout(launch, &layout_input);
  return 0;
}
