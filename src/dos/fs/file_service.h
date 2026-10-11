#ifndef DAZE_DOSFS_FILE_SERVICE_H
#define DAZE_DOSFS_FILE_SERVICE_H

#include "dosfs.h"
#include "run_metrics.h"

typedef struct {
  const DazeDosfsMounts *mounts;
  DazeDosfsHandles *handles;
  struct DazeDosfsTransferStorage *transfer_storage;
  DazeRunMetrics *run_metrics;
} DazeDosfsFileService;

/* One serial DOS process has at most one active transfer, so run-owned storage can be
 * reused. */
typedef struct DazeDosfsTransferStorage {
  uint8_t *bytes;
  size_t capacity;
} DazeDosfsTransferStorage;

typedef struct {
  int success;
  uint16_t dos_error;
  uint16_t handle;
  uint32_t position;
  /* Borrowed payload view for a completed read. `bytes` remains the only
   * result-owned allocation and is the only pointer disposal frees. */
  const uint8_t *transfer_bytes;
  uint8_t *bytes;
  uint16_t byte_count;
  int host_read_attempted;
  int host_write_attempted;
} DazeDosfsFileResult;

void daze_dosfs_file_service_init(DazeDosfsFileService *service, const DazeDosfsMounts *mounts,
                                  DazeDosfsHandles *handles);
void daze_dosfs_file_service_set_transfer_storage(DazeDosfsFileService *service,
                                                  DazeDosfsTransferStorage *storage);
void daze_dosfs_file_service_set_run_metrics(DazeDosfsFileService *service,
                                             DazeRunMetrics *metrics);
void daze_dosfs_transfer_storage_dispose(DazeDosfsTransferStorage *storage);
uint8_t *daze_dosfs_file_service_transfer_buffer(DazeDosfsFileService *service, size_t size);
void daze_dosfs_file_service_record_transfer(DazeDosfsFileService *service, int is_read,
                                             uint16_t requested_bytes,
                                             const DazeDosfsFileResult *result);
void daze_dosfs_file_result_dispose(DazeDosfsFileResult *result);

/* These services accept host-copied values only. They do not access guest CPU
 * state or guest memory; adapters copy any returned read payload themselves. */
void daze_dosfs_file_open(DazeDosfsFileService *service, const char *path, uint8_t access_mode,
                          DazeDosfsFileResult *result);
void daze_dosfs_file_create(DazeDosfsFileService *service, const char *path,
                            DazeDosfsFileResult *result);
void daze_dosfs_file_create_exclusive(DazeDosfsFileService *service, const char *path,
                                      DazeDosfsFileResult *result);
void daze_dosfs_file_seek(DazeDosfsFileService *service, uint16_t handle, uint8_t origin,
                          int32_t displacement, DazeDosfsFileResult *result);
void daze_dosfs_file_read(DazeDosfsFileService *service, uint16_t handle, uint16_t count,
                          DazeDosfsFileResult *result);
void daze_dosfs_file_read_into(DazeDosfsFileService *service, uint16_t handle, uint8_t *bytes,
                               uint16_t count, DazeDosfsFileResult *result);
void daze_dosfs_file_write(DazeDosfsFileService *service, uint16_t handle, const uint8_t *bytes,
                           uint16_t count, DazeDosfsFileResult *result);
DazeDosfsStatus daze_dosfs_file_write_character(DazeDosfsFileService *service, uint8_t character,
                                                int *host_errno);

#endif
