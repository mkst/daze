#include "file_service.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>

static void set_failure(DazeDosfsFileResult *result, uint16_t dos_error) {
  result->success = 0;
  result->dos_error = dos_error;
}

static void begin_result(DazeDosfsFileResult *result) {
  if (result != NULL) {
    *result = (DazeDosfsFileResult){0};
  }
}

static uint16_t open_error(DazeDosfsStatus status, int host_errno) {
  return status == DAZE_DOSFS_HOST_ERROR ? daze_dosfs_errno_to_dos_error(host_errno) : 3;
}

void daze_dosfs_file_service_init(DazeDosfsFileService *service, const DazeDosfsMounts *mounts,
                                  DazeDosfsHandles *handles) {
  if (service != NULL) {
    service->mounts = mounts;
    service->handles = handles;
    service->transfer_storage = NULL;
    service->run_metrics = NULL;
  }
}

void daze_dosfs_file_service_set_transfer_storage(DazeDosfsFileService *service,
                                                  DazeDosfsTransferStorage *storage) {
  if (service != NULL) service->transfer_storage = storage;
}

void daze_dosfs_file_service_set_run_metrics(DazeDosfsFileService *service,
                                             DazeRunMetrics *metrics) {
  if (service != NULL) service->run_metrics = metrics;
}

void daze_dosfs_transfer_storage_dispose(DazeDosfsTransferStorage *storage) {
  if (storage == NULL) return;
  free(storage->bytes);
  *storage = (DazeDosfsTransferStorage){0};
}

uint8_t *daze_dosfs_file_service_transfer_buffer(DazeDosfsFileService *service, size_t size) {
  if (size == 0) return NULL;
  if (service == NULL || service->transfer_storage == NULL) return NULL;
  DazeDosfsTransferStorage *storage = service->transfer_storage;
  if (storage->capacity < size) {
    uint8_t *bytes = realloc(storage->bytes, size);
    if (bytes == NULL) return NULL;
    storage->bytes = bytes;
    storage->capacity = size;
    if (service->run_metrics != NULL && service->run_metrics->enabled) {
      service->run_metrics->transfer_buffer_resizes++;
      service->run_metrics->transfer_buffer_peak = size;
    }
  }
  return storage->bytes;
}

void daze_dosfs_file_service_record_transfer(DazeDosfsFileService *service, int is_read,
                                             uint16_t requested_bytes,
                                             const DazeDosfsFileResult *result) {
  if (service == NULL || result == NULL || service->run_metrics == NULL ||
      !service->run_metrics->enabled)
    return;
  DazeRunMetrics *metrics = service->run_metrics;
  if (is_read && result->host_read_attempted) {
    metrics->read_calls++;
    metrics->read_requested_bytes += requested_bytes;
    metrics->read_bytes += result->byte_count;
  } else if (!is_read && result->host_write_attempted) {
    metrics->write_calls++;
    metrics->write_requested_bytes += requested_bytes;
    metrics->write_bytes += result->byte_count;
  }
}

void daze_dosfs_file_result_dispose(DazeDosfsFileResult *result) {
  if (result != NULL) {
    free(result->bytes);
    *result = (DazeDosfsFileResult){0};
  }
}

void daze_dosfs_file_open(DazeDosfsFileService *service, const char *path, uint8_t access_mode,
                          DazeDosfsFileResult *result) {
  begin_result(result);
  if (result == NULL || service == NULL || service->mounts == NULL || service->handles == NULL ||
      path == NULL) {
    if (result != NULL) set_failure(result, 3);
    return;
  }
  /* Sharing bits 4–6 are accepted without enforcement; they must not turn
   * a read-only open such as 40h (deny none) into DOS error 12. */
  const uint8_t access = (uint8_t)(access_mode & 0x03u);
  /* Accept no-inherit without tracking inheritance; bits 2-3 remain invalid. */
  const int open_flags = (access_mode & 0x0cu) != 0 ? -1
                         : access == 0              ? O_RDONLY
                         : access == 1              ? O_WRONLY
                         : access == 2              ? O_RDWR
                                                    : -1;
  if (open_flags < 0) {
    set_failure(result, 12);
    return;
  }
  int host_fd = -1;
  int host_errno = 0;
  DazeDosfsStatus status =
    daze_dosfs_open_c(service->mounts, path, open_flags, 0, &host_fd, &host_errno);
  uint16_t handle = 0;
  if (status == DAZE_DOSFS_OK) {
    struct stat information;
    if (fstat(host_fd, &information) != 0) {
      host_errno = errno;
      status = DAZE_DOSFS_HOST_ERROR;
    } else if (S_ISDIR(information.st_mode)) {
      /* DOS AH=3Dh opens files, while Linux also permits directory opens; reject those
       * here. */
      host_errno = EACCES;
      status = DAZE_DOSFS_HOST_ERROR;
    }
  }
  if (status == DAZE_DOSFS_OK) {
    status = daze_dosfs_handles_adopt(service->handles, host_fd, &handle);
  }
  if (status != DAZE_DOSFS_OK) {
    if (host_fd >= 0) close(host_fd);
    set_failure(result, open_error(status, host_errno));
    return;
  }
  result->success = 1;
  result->handle = handle;
}

static void file_create(DazeDosfsFileService *service, const char *path, int flags,
                        DazeDosfsFileResult *result) {
  begin_result(result);
  if (result == NULL || service == NULL || service->mounts == NULL || service->handles == NULL ||
      path == NULL) {
    if (result != NULL) set_failure(result, 3);
    return;
  }
  int host_fd = -1;
  int host_errno = 0;
  DazeDosfsStatus status =
    daze_dosfs_open_c(service->mounts, path, O_RDWR | O_CREAT | flags, 0666, &host_fd, &host_errno);
  uint16_t handle = 0;
  if (status == DAZE_DOSFS_OK)
    status = daze_dosfs_handles_adopt(service->handles, host_fd, &handle);
  if (status != DAZE_DOSFS_OK) {
    if (host_fd >= 0) close(host_fd);
    set_failure(result, open_error(status, host_errno));
    return;
  }
  result->success = 1;
  result->handle = handle;
}

void daze_dosfs_file_create(DazeDosfsFileService *service, const char *path,
                            DazeDosfsFileResult *result) {
  file_create(service, path, O_TRUNC, result);
}

void daze_dosfs_file_create_exclusive(DazeDosfsFileService *service, const char *path,
                                      DazeDosfsFileResult *result) {
  file_create(service, path, O_EXCL, result);
}

void daze_dosfs_file_seek(DazeDosfsFileService *service, uint16_t handle, uint8_t origin,
                          int32_t displacement, DazeDosfsFileResult *result) {
  begin_result(result);
  if (result == NULL || service == NULL || service->handles == NULL) {
    if (result != NULL) set_failure(result, 6);
    return;
  }
  const int whence = origin == 0 ? SEEK_SET : origin == 1 ? SEEK_CUR : origin == 2 ? SEEK_END : -1;
  int host_fd = -1;
  int host_errno = 0;
  DazeDosfsStatus status = whence < 0 ? DAZE_DOSFS_INVALID_PATH
                                      : daze_dosfs_handles_get(service->handles, handle, &host_fd);
  off_t position = -1;
  if (status == DAZE_DOSFS_OK) {
    position = lseek(host_fd, displacement, whence);
    if (position < 0) {
      host_errno = errno;
      status = DAZE_DOSFS_HOST_ERROR;
    }
  }
  if (status != DAZE_DOSFS_OK || (uint64_t)position > UINT32_MAX) {
    set_failure(result,
                status == DAZE_DOSFS_HOST_ERROR ? daze_dosfs_errno_to_dos_error(host_errno) : 6);
    return;
  }
  result->success = 1;
  result->position = (uint32_t)position;
}

void daze_dosfs_file_read(DazeDosfsFileService *service, uint16_t handle, uint16_t count,
                          DazeDosfsFileResult *result) {
  begin_result(result);
  if (result == NULL || service == NULL || service->handles == NULL) {
    if (result != NULL) set_failure(result, 6);
    return;
  }
  int host_fd = -1;
  int host_errno = 0;
  DazeDosfsStatus status = daze_dosfs_handles_get(service->handles, handle, &host_fd);
  if (status == DAZE_DOSFS_OK && count != 0) {
    result->bytes = malloc(count);
    if (result->bytes == NULL) {
      host_errno = ENOMEM;
      status = DAZE_DOSFS_HOST_ERROR;
    }
  }
  ssize_t bytes_read = 0;
  if (status == DAZE_DOSFS_OK && count != 0) {
    result->host_read_attempted = 1;
    bytes_read = read(host_fd, result->bytes, count);
    if (bytes_read < 0) {
      host_errno = errno;
      status = DAZE_DOSFS_HOST_ERROR;
    }
  }
  if (status != DAZE_DOSFS_OK) {
    free(result->bytes);
    result->bytes = NULL;
    result->byte_count = 0;
    set_failure(result,
                status == DAZE_DOSFS_HOST_ERROR ? daze_dosfs_errno_to_dos_error(host_errno) : 6);
    return;
  }
  result->success = 1;
  result->transfer_bytes = result->bytes;
  result->byte_count = (uint16_t)bytes_read;
}

void daze_dosfs_file_read_into(DazeDosfsFileService *service, uint16_t handle, uint8_t *bytes,
                               uint16_t count, DazeDosfsFileResult *result) {
  begin_result(result);
  if (result == NULL || service == NULL || service->handles == NULL ||
      (count != 0 && bytes == NULL)) {
    if (result != NULL) set_failure(result, 6);
    return;
  }
  int host_fd = -1;
  int host_errno = 0;
  DazeDosfsStatus status = daze_dosfs_handles_get(service->handles, handle, &host_fd);
  ssize_t bytes_read = 0;
  if (status == DAZE_DOSFS_OK && count != 0) {
    result->host_read_attempted = 1;
    bytes_read = read(host_fd, bytes, count);
    if (bytes_read < 0) {
      host_errno = errno;
      status = DAZE_DOSFS_HOST_ERROR;
    }
  }
  if (status != DAZE_DOSFS_OK) {
    set_failure(result,
                status == DAZE_DOSFS_HOST_ERROR ? daze_dosfs_errno_to_dos_error(host_errno) : 6);
    return;
  }
  result->success = 1;
  result->transfer_bytes = bytes;
  result->byte_count = (uint16_t)bytes_read;
}

void daze_dosfs_file_write(DazeDosfsFileService *service, uint16_t handle, const uint8_t *bytes,
                           uint16_t count, DazeDosfsFileResult *result) {
  begin_result(result);
  if (result == NULL || service == NULL || service->handles == NULL ||
      (count != 0 && bytes == NULL)) {
    if (result != NULL) set_failure(result, 6);
    return;
  }
  int host_fd = -1;
  int host_errno = 0;
  DazeDosfsStatus status = daze_dosfs_handles_get(service->handles, handle, &host_fd);
  ssize_t written = 0;
  if (status == DAZE_DOSFS_OK && count == 0) {
    struct stat information;
    const int flags = fcntl(host_fd, F_GETFL);
    if (flags < 0 || fstat(host_fd, &information) != 0) {
      host_errno = errno;
    } else if ((flags & O_ACCMODE) == O_RDONLY) {
      host_errno = EACCES;
    } else if (S_ISREG(information.st_mode)) {
      const off_t position = lseek(host_fd, 0, SEEK_CUR);
      if (position < 0 || ftruncate(host_fd, position) != 0) host_errno = errno;
    }
    if (host_errno != 0) status = DAZE_DOSFS_HOST_ERROR;
  }
  if (status == DAZE_DOSFS_OK && count != 0) {
    result->host_write_attempted = 1;
    do {
      written = write(host_fd, bytes, count);
    } while (written < 0 && errno == EINTR);
    if (written < 0) {
      host_errno = errno;
      status = DAZE_DOSFS_HOST_ERROR;
    }
  }
  if (status != DAZE_DOSFS_OK) {
    set_failure(result,
                status == DAZE_DOSFS_HOST_ERROR ? daze_dosfs_errno_to_dos_error(host_errno) : 6);
    return;
  }
  result->success = 1;
  result->byte_count = (uint16_t)written;
}

DazeDosfsStatus daze_dosfs_file_write_character(DazeDosfsFileService *service, uint8_t character,
                                                int *host_errno) {
  if (host_errno != NULL) *host_errno = 0;
  if (service == NULL || service->handles == NULL) return DAZE_DOSFS_INVALID_PATH;
  int host_fd = -1;
  DazeDosfsStatus status = daze_dosfs_handles_get(service->handles, 1, &host_fd);
  if (status != DAZE_DOSFS_OK) return status;
  for (;;) {
    const ssize_t written = write(host_fd, &character, 1);
    if (written == 1) return DAZE_DOSFS_OK;
    if (written < 0 && errno == EINTR) continue;
    if (host_errno != NULL) *host_errno = written < 0 ? errno : EIO;
    return DAZE_DOSFS_HOST_ERROR;
  }
}
