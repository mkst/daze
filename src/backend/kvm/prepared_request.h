#ifndef DAZE_KVM_PREPARED_REQUEST_H
#define DAZE_KVM_PREPARED_REQUEST_H

#include "runner_request_common.h"

typedef struct {
  uint16_t psp_segment;
  uint16_t environment_segment;
  uint16_t dpmi_entry_segment;
  uint16_t dos_vector_segment;
  uint16_t load_segment;
  uint32_t guest_size;
} DazeKvmPreparedProcessLayout;

/* References are borrowed; the file-service view does not own mounts or handles. */
typedef struct {
  const DazeImage *image;
  const DazeMzHeader *header;
  const char *command_tail;
  const char *guest_path;
  const DazeDosfsMounts *mounts;
  DazeDosfsHandles *handles;
  DazeDosfsFileService *files;
  DazeKvmPreparedProcessLayout layout;
  const char *const *env_vars;
  int env_var_count;
} DazeKvmPreparedRequestInput;

int daze_kvm_prepared_request_build(const DazeKvmPreparedRequestInput *input,
                                    DazeKvmRunnerRequestCommon *request);

#endif
