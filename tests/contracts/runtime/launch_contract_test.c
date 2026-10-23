#include "byte_order.h"
#include "guest_memory_layout.h"
#include "launch.h"
#include "runner_request_common.h"

#undef NDEBUG
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void write_image(const char *path, size_t size, int malformed) {
  uint8_t *bytes = calloc(1, size);
  assert(bytes != NULL && size >= 32);
  daze_write_u16(bytes, 0x5a4d);
  daze_write_u16(bytes + 2, size % 512);
  daze_write_u16(bytes + 4, (size + 511) / 512);
  daze_write_u16(bytes + 8, malformed ? 0xffff : 2);
  daze_write_u16(bytes + 16, 0xfffe);
  daze_write_u16(bytes + 24, 0x1c);
  FILE *file = fopen(path, "wb");
  assert(file != NULL && fwrite(bytes, 1, size, file) == size);
  assert(fclose(file) == 0);
  free(bytes);
}

static void reject(const char *path, int mounted) {
  DazePreparedLaunch launch;
  initialize_prepared_launch(&launch);
  const char tail[127] = {0};
  assert(prepare_launch(&launch, path, path, mounted, tail, NULL, 0) == 2);
  assert(launch.kvm_request == NULL && launch.transfer_storage.bytes == NULL);
  dispose_prepared_launch(&launch);
  assert(launch.image.bytes == NULL && !launch.mounts_initialized);
  dispose_prepared_launch(&launch);
}

int main(void) {
  char directory[] = "/tmp/daze-launch-contract-XXXXXX";
  assert(mkdtemp(directory) != NULL);
  char path[256];
  assert(snprintf(path, sizeof(path), "%s/TEST.EXE", directory) > 0);
  const char tail[127] = " hello";
  DazePreparedLaunch launch = {0};
  initialize_prepared_launch(NULL);
  dispose_prepared_launch(NULL);
  assert(prepare_launch(NULL, path, path, 0, tail, NULL, 0) == 3);
  assert(prepare_launch(&launch, path, path, 0, tail, NULL, 0) == 3);
  initialize_prepared_launch(&launch);
  assert(prepare_launch(&launch, NULL, path, 0, tail, NULL, 0) == 3);
  assert(prepare_launch(&launch, path, NULL, 0, tail, NULL, 0) == 3);
  assert(prepare_launch(&launch, path, path, 0, NULL, NULL, 0) == 3);
  assert(prepare_launch(&launch, path, path, 0, tail, NULL, -1) == 3);
  assert(prepare_launch(&launch, path, path, 0, tail, NULL, 33) == 3);
  assert(prepare_launch(&launch, path, path, 0, tail, NULL, 1) == 3);
  launch.handles_initialized = 0;
  assert(prepare_launch(&launch, path, path, 0, tail, NULL, 0) == 3);
  dispose_prepared_launch(&launch);
  reject(path, 0);
  reject("Z:\\MISSING.EXE", 1);
  FILE *file = fopen(path, "wb");
  assert(file != NULL && fputs("MZ", file) >= 0 && fclose(file) == 0);
  reject(path, 0);
  write_image(path, 37, 1);
  reject(path, 0);
  write_image(path, 32 + k_dpmi_linear_arena_limit - (k_load_segment << 4), 0);
  reject(path, 0);
  write_image(path, 32 + k_memory_size, 0);
  reject(path, 0);
  write_image(path, 32 + 0x30001, 0);
  initialize_prepared_launch(&launch);
  assert(prepare_launch(&launch, path, path, 0, tail, NULL, 0) == 0);
  assert(launch.allocation_start == 0x4001 && launch.kvm_request != NULL);
  dispose_prepared_launch(&launch);
  /* Shared placement can be valid while the KVM runner reservations reject it. */
  write_image(path, 32 + 0x90000, 0);
  initialize_prepared_launch(&launch);
  launch.debug = 1;
  assert(prepare_launch(&launch, path, path, 0, tail, NULL, 0) == 0);
  assert(launch.allocation_start == 0xa000 && launch.kvm_request == NULL &&
         launch.files.mounts == &launch.mounts && launch.files.handles == &launch.handles);
  dispose_prepared_launch(&launch);
  write_image(path, 37, 0);
  initialize_prepared_launch(&launch);
  int mount_fd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  assert(mount_fd >= 0);
  assert(daze_dosfs_mounts_add_named(&launch.mounts, 2, mount_fd, 0) == DAZE_DOSFS_OK);
  int handle_fd = open(path, O_RDONLY | O_CLOEXEC);
  uint16_t handle;
  assert(handle_fd >= 0 &&
         daze_dosfs_handles_adopt(&launch.handles, handle_fd, &handle) == DAZE_DOSFS_OK);
  const char *env[] = {"BUILD=one", "BUILD=two"};
  launch.debug = 1;
  assert(prepare_launch(&launch, "C:\\TEST.EXE", "unused", 1, tail, env, 2) == 0);
  assert(launch.image.size == 37 && launch.header.image_size == 5);
  assert(launch.image_address == 0x10000 && launch.allocation_start == 0x3000);
  assert(strcmp(launch.command_tail, tail) == 0 && launch.env_var_count == 2);
  assert(launch.env_vars[0] == env[0] && launch.env_vars[1] == env[1]);
  assert(launch.kvm_request != NULL && launch.kvm_request->image == &launch.image &&
         launch.kvm_request->header == &launch.header &&
         launch.kvm_request->mounts == &launch.mounts &&
         launch.kvm_request->handles == &launch.handles &&
         launch.kvm_request->files == &launch.files && launch.kvm_request->env_vars == env);
  assert(launch.files.transfer_storage == &launch.transfer_storage &&
         launch.files.run_metrics == &launch.run_metrics);
  assert(daze_dosfs_file_service_transfer_buffer(&launch.files, 32) != NULL);
  dispose_prepared_launch(&launch);
  assert(launch.image.bytes == NULL && launch.kvm_request == NULL &&
         launch.transfer_storage.bytes == NULL && !launch.handles_initialized);
  assert(fcntl(mount_fd, F_GETFD) == -1 && errno == EBADF);
  assert(fcntl(handle_fd, F_GETFD) == -1 && errno == EBADF);
  dispose_prepared_launch(&launch);
  assert(unlink(path) == 0 && rmdir(directory) == 0);
  puts("launch preparation contract: passed");
  return 0;
}
