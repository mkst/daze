#ifndef DAZE_DOSFS_H
#define DAZE_DOSFS_H

#include <stddef.h>
#include <stdint.h>
#include <dirent.h>
#include <sys/types.h>

enum {
  DAZE_DOSFS_PATH_MAX = 4096,
  DAZE_DOSFS_ENV_MAX = 256,
  DAZE_DOSFS_MAX_HANDLES = 256,
  DAZE_DOSFS_MAX_DRIVES = 26, /* A:..Z: */
};

typedef enum {
  DAZE_DOSFS_OK = 0,
  DAZE_DOSFS_INVALID_PATH,
  DAZE_DOSFS_UNMOUNTED_DRIVE,
  DAZE_DOSFS_DRIVE_IN_USE,
  DAZE_DOSFS_OUTPUT_TOO_SMALL,
  DAZE_DOSFS_HOST_ERROR,
} DazeDosfsStatus;

/* Drive indexes use A:=0. Entries own root directory descriptors; -1 means unmounted.
 * Read-only drives reject guest mutations regardless of host permissions. */
typedef struct {
  int fds[DAZE_DOSFS_MAX_DRIVES];
  int readonly[DAZE_DOSFS_MAX_DRIVES];
  int default_drive; /* DOS drive index used for unqualified guest paths. */
} DazeDosfsMounts;

void daze_dosfs_mounts_init(DazeDosfsMounts *mounts);

/* Success transfers mount_fd ownership to the table; failure leaves it with the caller.
 * Stored descriptors require caller cleanup. */
DazeDosfsStatus daze_dosfs_mounts_add_default(DazeDosfsMounts *mounts, int mount_fd, int readonly,
                                              int *drive_index);

/* Adds mount_fd at an unmounted DOS drive index without changing default_drive.
 * The same success/failure ownership and caller cleanup rules apply. */
DazeDosfsStatus daze_dosfs_mounts_add_named(DazeDosfsMounts *mounts, int drive_index, int mount_fd,
                                            int readonly);

int daze_dosfs_mount_is_readonly(const DazeDosfsMounts *mounts, int drive_index);

typedef struct {
  int host_fds[DAZE_DOSFS_MAX_HANDLES];
  struct DazeDosfsWriteBuffer *write_buffers[DAZE_DOSFS_MAX_HANDLES];
  int buffered_writes;
  int teardown_errno;
} DazeDosfsHandles;

typedef struct {
  DazeDosfsHandles parent;
  DazeDosfsHandles *live;
} DazeDosfsExecHandles;

typedef struct {
  DIR *directory;
  char pattern[256];
  uint16_t attributes;
} DazeDosfsFind;

typedef struct {
  uint8_t attributes;
  uint32_t size;
  char name[13];
} DazeDosfsFindResult;

/*
 * Lexically resolves a DOS path inside the supplied C: mount. This is a
 * policy helper: filesystem calls must subsequently use descriptor-relative,
 * no-follow operations to prevent symlink escapes.
 */
DazeDosfsStatus daze_dosfs_resolve_c(const char *mount_root, const char *guest_path,
                                     char *host_path, size_t host_path_size);

/* Resolve components relative to the mounted drive with O_NOFOLLOW to prevent symlink
 * escapes. Unqualified paths use the default drive. */
DazeDosfsStatus daze_dosfs_open_c(const DazeDosfsMounts *mounts, const char *guest_path,
                                  int open_flags, int create_mode, int *guest_fd, int *host_errno);

DazeDosfsStatus daze_dosfs_unlink_c(const DazeDosfsMounts *mounts, const char *guest_path,
                                    int *host_errno);

/* Same-drive file rename; an existing destination is never replaced. */
DazeDosfsStatus daze_dosfs_rename_c(const DazeDosfsMounts *mounts, const char *source_path,
                                    const char *destination_path, int *host_errno);

/* Starts/continues a bounded DOS Find First/Find Next enumeration. The drive is
 * taken from the guest pattern; an unqualified pattern uses the default drive.
 * The caller owns the state and must close it after use. Names that cannot be
 * represented by the current 8.3-oriented DTA result are skipped. */
DazeDosfsStatus daze_dosfs_find_first_c(const DazeDosfsMounts *mounts, const char *guest_pattern,
                                        uint16_t attributes, DazeDosfsFind *find,
                                        DazeDosfsFindResult *result, int *found, int *host_errno);
DazeDosfsStatus daze_dosfs_find_next(DazeDosfsFind *find, DazeDosfsFindResult *result, int *found,
                                     int *host_errno);
void daze_dosfs_find_close(DazeDosfsFind *find);

/* Creates TMP under the default drive if absent and rejects a non-directory
 * or symlink at that path. */
DazeDosfsStatus daze_dosfs_ensure_temp_directory(const DazeDosfsMounts *mounts, int *host_errno);

DazeDosfsStatus daze_dosfs_default_environment(char *environment, size_t environment_size,
                                               size_t *environment_length);

const char *daze_dosfs_status_string(DazeDosfsStatus status);

uint16_t daze_dosfs_errno_to_dos_error(int host_errno);

/* A bounded DOS handle table. Ownership transfers to the table on adopt. */
void daze_dosfs_handles_init(DazeDosfsHandles *handles);
/* Duplicate inherited handles at the same DOS indices, sharing file positions.
 * On failure, both tables remain unchanged; child must be initially empty. */
DazeDosfsStatus daze_dosfs_handles_inherit(const DazeDosfsHandles *parent, DazeDosfsHandles *child,
                                           int *host_errno);
DazeDosfsStatus daze_dosfs_handles_bind_standard(DazeDosfsHandles *handles, int host_stdin,
                                                 int host_stdout, int host_stderr, int *host_errno);
DazeDosfsStatus daze_dosfs_handles_adopt(DazeDosfsHandles *handles, int host_fd,
                                         uint16_t *dos_handle);
DazeDosfsStatus daze_dosfs_handles_duplicate(DazeDosfsHandles *handles, uint16_t source_handle,
                                             uint16_t *dos_handle, int *host_errno);
DazeDosfsStatus daze_dosfs_handles_force_duplicate(DazeDosfsHandles *handles,
                                                   uint16_t source_handle, uint16_t target_handle,
                                                   int *host_errno);
DazeDosfsStatus daze_dosfs_handles_get(const DazeDosfsHandles *handles, uint16_t dos_handle,
                                       int *host_fd);
/* Raw descriptor access is for writes that must retain pending buffered data. */
DazeDosfsStatus daze_dosfs_handles_peek(const DazeDosfsHandles *handles, uint16_t dos_handle,
                                        int *host_fd);
DazeDosfsStatus daze_dosfs_handles_flush(const DazeDosfsHandles *handles, int *host_errno);
/* Credit is valid until the next host handle operation. Appending within credit
 * cannot flush or perform I/O; the caller must drain guest bytes before that operation. */
uint16_t daze_dosfs_handles_write_credit(const DazeDosfsHandles *handles, uint16_t handle);
int daze_dosfs_handles_append_buffered(DazeDosfsHandles *handles, uint16_t handle,
                                       const uint8_t *bytes, uint16_t count);
ssize_t daze_dosfs_handles_write(DazeDosfsHandles *handles, uint16_t dos_handle,
                                 const uint8_t *bytes, size_t count);
DazeDosfsStatus daze_dosfs_handles_close(DazeDosfsHandles *handles, uint16_t dos_handle,
                                         int *host_errno);
void daze_dosfs_handles_close_all(DazeDosfsHandles *handles);
/* Zero-initialize the scope. Restore returns parent ownership to live; disposal
 * closes only the retained parent, leaving live to its normal teardown owner. */
DazeDosfsStatus daze_dosfs_exec_handles_begin(DazeDosfsExecHandles *scope, DazeDosfsHandles *live,
                                              int *host_errno);
void daze_dosfs_exec_handles_restore(DazeDosfsExecHandles *scope);
void daze_dosfs_exec_handles_dispose(DazeDosfsExecHandles *scope);

#endif
