#ifndef DAZE_RUNTIME_LAUNCH_H
#define DAZE_RUNTIME_LAUNCH_H

#include "dosfs.h"
#include "file_service.h"
#include "image.h"
#include "mz_layout.h"
#include "run_metrics.h"

#include <stdint.h>

struct DazeKvmRunnerRequestCommon;

typedef struct DazePreparedLaunch {
  DazeImage image;
  DazeMzHeader header;
  char command_tail[127];
  const char *guest_path;
  uint32_t image_address;
  uint16_t allocation_start;
  DazeDosfsMounts mounts;
  DazeDosfsHandles handles;
  DazeDosfsTransferStorage transfer_storage;
  DazeRunMetrics run_metrics;
  DazeDosfsFileService files;
  struct DazeKvmRunnerRequestCommon *kvm_request;
  int mounts_initialized;
  int handles_initialized;
  const char *env_vars[DAZE_PROCESS_ENV_MAX_EXTRA_VARS];
  int env_var_count;
  int debug;
} DazePreparedLaunch;

void initialize_prepared_launch(DazePreparedLaunch *launch);
void dispose_prepared_launch(DazePreparedLaunch *launch);
int prepare_launch(DazePreparedLaunch *launch, const char *path, const char *host_mz_path,
                   int is_drive_qualified, const char command_tail[127],
                   const char *const *env_vars, int env_var_count);

#endif
