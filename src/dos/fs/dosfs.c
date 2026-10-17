#define _GNU_SOURCE

#include "dosfs.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>

#include "dos_error.h"

typedef struct DazeDosfsWriteBuffer {
  size_t used;
  unsigned references;
  int disabled;
  dev_t device;
  ino_t inode;
  uint8_t bytes[16384];
} DazeDosfsWriteBuffer;

static int flush_write_buffer(DazeDosfsWriteBuffer *buffer, int fd) {
  if (buffer == NULL || buffer->used == 0) return 0;
  size_t written = 0;
  while (written < buffer->used) {
    ssize_t count = write(fd, buffer->bytes + written, buffer->used - written);
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0) {
      if (count == 0) errno = EIO;
      memmove(buffer->bytes, buffer->bytes + written, buffer->used - written);
      buffer->used -= written;
      return -1;
    }
    written += (size_t)count;
  }
  buffer->used = 0;
  return 0;
}

static void release_write_buffer(DazeDosfsWriteBuffer *buffer) {
  if (buffer != NULL && --buffer->references == 0) free(buffer);
}

static int dos_wildcard_matches(const char *pattern, const char *name) {
  if (strcmp(pattern, "*.*") == 0) return 1;
  while (*pattern != '\0') {
    if (*pattern == '*') {
      do {
        ++pattern;
      } while (*pattern == '*');
      if (*pattern == '\0') return 1;
      while (*name != '\0') {
        if (dos_wildcard_matches(pattern, name)) return 1;
        ++name;
      }
      return dos_wildcard_matches(pattern, name);
    }
    if (*name == '\0' ||
        (*pattern != '?' && toupper((unsigned char)*pattern) != toupper((unsigned char)*name))) {
      return 0;
    }
    ++pattern;
    ++name;
  }
  return *name == '\0';
}

static int dos_component_equal(const char *left, const char *right) {
  while (*left != '\0' && *right != '\0') {
    if (toupper((unsigned char)*left) != toupper((unsigned char)*right)) return 0;
    ++left;
    ++right;
  }
  return *left == '\0' && *right == '\0';
}

/* Resolve one DOS path component without escaping its already-open parent.
 * Host filesystems such as ext4 are case-sensitive while DOS is not. An exact
 * host spelling wins; two differently-cased non-exact candidates are rejected
 * rather than making a guest path access depend on directory enumeration. */
static int resolve_dos_component(int directory_fd, const char *requested, char *resolved,
                                 size_t resolved_size, int *host_errno) {
  const size_t requested_length = strlen(requested);
  struct stat information;
  if (requested_length < resolved_size &&
      fstatat(directory_fd, requested, &information, AT_SYMLINK_NOFOLLOW) == 0) {
    memcpy(resolved, requested, requested_length + 1);
    return 1;
  }
  /* dup() shares the directory stream position with directory_fd; an earlier
   * case-folded lookup would then make a later one start at end-of-directory.
   * Re-open "." to obtain an independent stream while staying beneath the
   * same already-validated descriptor. */
  const int scan_fd = openat(directory_fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (scan_fd < 0) {
    if (host_errno != NULL) *host_errno = errno;
    return -1;
  }
  DIR *directory = fdopendir(scan_fd);
  if (directory == NULL) {
    if (host_errno != NULL) *host_errno = errno;
    close(scan_fd);
    return -1;
  }
  int found = 0;
  int ambiguous = 0;
  errno = 0;
  struct dirent *entry;
  while ((entry = readdir(directory)) != NULL) {
    if (!dos_component_equal(requested, entry->d_name)) continue;
    const size_t length = strlen(entry->d_name);
    if (length + 1 > resolved_size) continue;
    if (strcmp(requested, entry->d_name) == 0) {
      memcpy(resolved, entry->d_name, length + 1);
      found = 1;
      ambiguous = 0;
      break;
    }
    if (found) {
      ambiguous = 1;
      continue;
    }
    memcpy(resolved, entry->d_name, length + 1);
    found = 1;
  }
  const int saved_errno = errno;
  closedir(directory);
  if (saved_errno != 0) {
    if (host_errno != NULL) *host_errno = saved_errno;
    return -1;
  }
  if (ambiguous) {
    if (host_errno != NULL) *host_errno = EEXIST;
    return -1;
  }
  return found;
}

static DazeDosfsStatus daze_dosfs_find_next_impl(DazeDosfsFind *find, DazeDosfsFindResult *result,
                                                 int *found, int *host_errno) {
  if (find == NULL || result == NULL || found == NULL || find->directory == NULL) {
    return DAZE_DOSFS_INVALID_PATH;
  }
  *found = 0;
  errno = 0;
  struct dirent *entry;
  while ((entry = readdir(find->directory)) != NULL) {
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0 ||
        strlen(entry->d_name) >= sizeof(result->name) ||
        !dos_wildcard_matches(find->pattern, entry->d_name)) {
      continue;
    }
    struct stat information;
    if (fstatat(dirfd(find->directory), entry->d_name, &information, AT_SYMLINK_NOFOLLOW) != 0) {
      if (errno == ENOENT) continue;
      if (host_errno != NULL) *host_errno = errno;
      return DAZE_DOSFS_HOST_ERROR;
    }
    if (S_ISLNK(information.st_mode)) continue;
    const int is_directory = S_ISDIR(information.st_mode);
    if (!S_ISREG(information.st_mode) && !is_directory) continue;
    if (is_directory && (find->attributes & 0x10u) == 0) continue;
    memset(result, 0, sizeof(*result));
    result->attributes = is_directory ? 0x10u : 0x20u;
    result->size = is_directory ? 0 : (uint32_t)information.st_size;
    memcpy(result->name, entry->d_name, strlen(entry->d_name) + 1);
    *found = 1;
    return DAZE_DOSFS_OK;
  }
  if (errno != 0) {
    if (host_errno != NULL) *host_errno = errno;
    return DAZE_DOSFS_HOST_ERROR;
  }
  return DAZE_DOSFS_OK;
}

static int has_dos_forbidden_character(const char *component, size_t length) {
  for (size_t index = 0; index < length; ++index) {
    switch (component[index]) {
    case ':':
    case '*':
    case '?':
    case '"':
    case '<':
    case '>':
    case '|':
      return 1;
    default:
      break;
    }
  }
  return 0;
}

static DazeDosfsStatus append_component(char *output, size_t output_size, size_t *length,
                                        const char *component, size_t component_length) {
  const size_t separator = *length > 0 && output[*length - 1] != '/' ? 1 : 0;
  if (*length + separator + component_length + 1 > output_size) {
    return DAZE_DOSFS_OUTPUT_TOO_SMALL;
  }
  if (separator) {
    output[(*length)++] = '/';
  }
  memcpy(output + *length, component, component_length);
  *length += component_length;
  output[*length] = '\0';
  return DAZE_DOSFS_OK;
}

static DazeDosfsStatus normalize_relative_components(const char *cursor, char *relative_path,
                                                     size_t relative_path_size) {
  if (cursor == NULL || relative_path == NULL || relative_path_size == 0) {
    return DAZE_DOSFS_INVALID_PATH;
  }
  relative_path[0] = '\0';
  size_t output_length = 0;
  while (*cursor == '\\' || *cursor == '/') {
    ++cursor;
  }

  while (*cursor != '\0') {
    const char *component = cursor;
    while (*cursor != '\0' && *cursor != '\\' && *cursor != '/') {
      ++cursor;
    }
    const size_t component_length = (size_t)(cursor - component);
    while (*cursor == '\\' || *cursor == '/') {
      ++cursor;
    }
    if (component_length == 0 || (component_length == 1 && component[0] == '.')) {
      continue;
    }
    if (component_length == 2 && component[0] == '.' && component[1] == '.') {
      /* DOS treats parent traversal at a drive root as remaining at the root. */
      char *last_separator = strrchr(relative_path, '/');
      if (last_separator != NULL) {
        *last_separator = '\0';
        output_length = (size_t)(last_separator - relative_path);
      } else {
        relative_path[0] = '\0';
        output_length = 0;
      }
      continue;
    }
    if (has_dos_forbidden_character(component, component_length)) {
      return DAZE_DOSFS_INVALID_PATH;
    }
    DazeDosfsStatus status = append_component(relative_path, relative_path_size, &output_length,
                                              component, component_length);
    if (status != DAZE_DOSFS_OK) {
      return status;
    }
  }
  return DAZE_DOSFS_OK;
}

static DazeDosfsStatus normalize_drive_path(const DazeDosfsMounts *mounts, const char *guest_path,
                                            int *drive_index, char *relative_path,
                                            size_t relative_path_size) {
  if (mounts == NULL || drive_index == NULL || guest_path == NULL || relative_path == NULL ||
      relative_path_size == 0) {
    return DAZE_DOSFS_INVALID_PATH;
  }
  const char *cursor = guest_path;
  int drive = mounts->default_drive;
  if (cursor[0] != '\0' && cursor[1] == ':') {
    const int letter = toupper((unsigned char)cursor[0]) - 'A';
    if (letter < 0 || letter >= DAZE_DOSFS_MAX_DRIVES || mounts->fds[letter] < 0) {
      return DAZE_DOSFS_UNMOUNTED_DRIVE;
    }
    drive = letter;
    cursor += 2;
  } else if (strchr(cursor, ':') != NULL) {
    return DAZE_DOSFS_INVALID_PATH;
  }
  if (drive < 0 || drive >= DAZE_DOSFS_MAX_DRIVES || mounts->fds[drive] < 0) {
    return DAZE_DOSFS_UNMOUNTED_DRIVE;
  }
  *drive_index = drive;
  return normalize_relative_components(cursor, relative_path, relative_path_size);
}

void daze_dosfs_mounts_init(DazeDosfsMounts *mounts) {
  if (mounts == NULL) {
    return;
  }
  for (size_t index = 0; index < DAZE_DOSFS_MAX_DRIVES; ++index) {
    mounts->fds[index] = -1;
    mounts->readonly[index] = 0;
  }
  mounts->default_drive = 2; /* C: */
}

int daze_dosfs_mount_is_readonly(const DazeDosfsMounts *mounts, int drive_index) {
  if (mounts == NULL || drive_index < 0 || drive_index >= DAZE_DOSFS_MAX_DRIVES) {
    return 0;
  }
  return mounts->fds[drive_index] >= 0 && mounts->readonly[drive_index] != 0;
}

/* Guest write-mode opens, creates, and truncations must fail before reaching
 * the host so a readonly mount never depends on host file permissions. */
static int open_flags_want_write(int open_flags) {
  return (open_flags & O_ACCMODE) != O_RDONLY || (open_flags & (O_CREAT | O_TRUNC)) != 0;
}

DazeDosfsStatus daze_dosfs_mounts_add_default(DazeDosfsMounts *mounts, int mount_fd, int readonly,
                                              int *drive_index) {
  if (mounts == NULL || mount_fd < 0) {
    return DAZE_DOSFS_INVALID_PATH;
  }
  int drive = mounts->default_drive;
  if (drive < 0 || drive >= DAZE_DOSFS_MAX_DRIVES) {
    drive = 2;
  }
  while (drive < DAZE_DOSFS_MAX_DRIVES && mounts->fds[drive] >= 0) {
    ++drive;
  }
  if (drive >= DAZE_DOSFS_MAX_DRIVES) {
    return DAZE_DOSFS_HOST_ERROR;
  }
  mounts->fds[drive] = mount_fd;
  mounts->readonly[drive] = readonly != 0;
  if (mounts->default_drive < 0 || mounts->default_drive >= DAZE_DOSFS_MAX_DRIVES) {
    mounts->default_drive = drive;
  }
  if (drive_index != NULL) {
    *drive_index = drive;
  }
  return DAZE_DOSFS_OK;
}

DazeDosfsStatus daze_dosfs_mounts_add_named(DazeDosfsMounts *mounts, int drive_index, int mount_fd,
                                            int readonly) {
  if (mounts == NULL || mount_fd < 0) {
    return DAZE_DOSFS_INVALID_PATH;
  }
  if (drive_index < 0 || drive_index >= DAZE_DOSFS_MAX_DRIVES) {
    return DAZE_DOSFS_INVALID_PATH;
  }
  if (mounts->fds[drive_index] >= 0) {
    return DAZE_DOSFS_DRIVE_IN_USE;
  }
  mounts->fds[drive_index] = mount_fd;
  mounts->readonly[drive_index] = readonly != 0;
  return DAZE_DOSFS_OK;
}

DazeDosfsStatus daze_dosfs_resolve_c(const char *mount_root, const char *guest_path,
                                     char *host_path, size_t host_path_size) {
  if (mount_root == NULL || guest_path == NULL || host_path == NULL || mount_root[0] != '/') {
    return DAZE_DOSFS_INVALID_PATH;
  }
  char relative_path[DAZE_DOSFS_PATH_MAX];
  const char *cursor = guest_path;
  if (cursor[0] != '\0' && cursor[1] == ':') {
    if (toupper((unsigned char)cursor[0]) != 'C') {
      return DAZE_DOSFS_UNMOUNTED_DRIVE;
    }
    cursor += 2;
  } else if (strchr(cursor, ':') != NULL) {
    return DAZE_DOSFS_INVALID_PATH;
  }
  DazeDosfsStatus status =
    normalize_relative_components(cursor, relative_path, sizeof(relative_path));
  if (status != DAZE_DOSFS_OK) {
    return status;
  }
  const size_t root_length = strlen(mount_root);
  const size_t relative_length = strlen(relative_path);
  const size_t needs_separator =
    root_length > 0 && mount_root[root_length - 1] != '/' && relative_length > 0;
  if (root_length + needs_separator + relative_length + 1 > host_path_size) {
    return DAZE_DOSFS_OUTPUT_TOO_SMALL;
  }
  memcpy(host_path, mount_root, root_length);
  size_t output_length = root_length;
  if (needs_separator) {
    host_path[output_length++] = '/';
  }
  memcpy(host_path + output_length, relative_path, relative_length + 1);
  return DAZE_DOSFS_OK;
}

DazeDosfsStatus daze_dosfs_open_c(const DazeDosfsMounts *mounts, const char *guest_path,
                                  int open_flags, int create_mode, int *guest_fd, int *host_errno) {
  char relative_path[DAZE_DOSFS_PATH_MAX];
  int drive_index = -1;
  DazeDosfsStatus status =
    normalize_drive_path(mounts, guest_path, &drive_index, relative_path, sizeof(relative_path));
  if (status != DAZE_DOSFS_OK) {
    return status;
  }
  const int mount_fd = mounts->fds[drive_index];
  if (guest_fd == NULL || mount_fd < 0) {
    return DAZE_DOSFS_INVALID_PATH;
  }
  if (open_flags_want_write(open_flags) && daze_dosfs_mount_is_readonly(mounts, drive_index)) {
    if (host_errno != NULL) *host_errno = EROFS;
    return DAZE_DOSFS_HOST_ERROR;
  }
  int directory_fd = dup(mount_fd);
  if (directory_fd < 0) {
    if (host_errno != NULL) *host_errno = errno;
    return DAZE_DOSFS_HOST_ERROR;
  }
  char *component = relative_path;
  while (*component != '\0') {
    char *separator = strchr(component, '/');
    if (separator != NULL) *separator = '\0';
    char resolved[DAZE_DOSFS_PATH_MAX];
    const int resolved_component =
      resolve_dos_component(directory_fd, component, resolved, sizeof(resolved), host_errno);
    if (resolved_component < 0) {
      close(directory_fd);
      return DAZE_DOSFS_HOST_ERROR;
    }
    const char *host_component = resolved_component ? resolved : component;
    if (separator != NULL) {
      const int next_fd =
        openat(directory_fd, host_component, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
      close(directory_fd);
      if (next_fd < 0) {
        if (host_errno != NULL) *host_errno = errno;
        return DAZE_DOSFS_HOST_ERROR;
      }
      directory_fd = next_fd;
      component = separator + 1;
      continue;
    }
    const int opened_fd =
      openat(directory_fd, host_component, open_flags | O_CLOEXEC | O_NOFOLLOW, create_mode);
    const int saved_errno = errno;
    close(directory_fd);
    if (opened_fd < 0) {
      if (host_errno != NULL) *host_errno = saved_errno;
      return DAZE_DOSFS_HOST_ERROR;
    }
    *guest_fd = opened_fd;
    return DAZE_DOSFS_OK;
  }
  const int opened_fd = openat(directory_fd, ".", open_flags | O_CLOEXEC | O_NOFOLLOW, create_mode);
  const int saved_errno = errno;
  close(directory_fd);
  if (opened_fd < 0) {
    if (host_errno != NULL) *host_errno = saved_errno;
    return DAZE_DOSFS_HOST_ERROR;
  }
  *guest_fd = opened_fd;
  return DAZE_DOSFS_OK;
}

DazeDosfsStatus daze_dosfs_unlink_c(const DazeDosfsMounts *mounts, const char *guest_path,
                                    int *host_errno) {
  char relative_path[DAZE_DOSFS_PATH_MAX];
  int drive_index = -1;
  DazeDosfsStatus status =
    normalize_drive_path(mounts, guest_path, &drive_index, relative_path, sizeof(relative_path));
  if (status != DAZE_DOSFS_OK) {
    return status;
  }
  const int mount_fd = mounts->fds[drive_index];
  if (mount_fd < 0 || relative_path[0] == '\0') {
    return DAZE_DOSFS_INVALID_PATH;
  }
  if (daze_dosfs_mount_is_readonly(mounts, drive_index)) {
    if (host_errno != NULL) *host_errno = EROFS;
    return DAZE_DOSFS_HOST_ERROR;
  }
  int directory_fd = dup(mount_fd);
  if (directory_fd < 0) {
    if (host_errno != NULL) *host_errno = errno;
    return DAZE_DOSFS_HOST_ERROR;
  }
  char *component = relative_path;
  for (;;) {
    char *separator = strchr(component, '/');
    if (separator != NULL) *separator = '\0';
    char resolved[DAZE_DOSFS_PATH_MAX];
    const int resolved_component =
      resolve_dos_component(directory_fd, component, resolved, sizeof(resolved), host_errno);
    if (resolved_component < 0) {
      close(directory_fd);
      return DAZE_DOSFS_HOST_ERROR;
    }
    const char *host_component = resolved_component ? resolved : component;
    if (separator == NULL) {
      const int result = unlinkat(directory_fd, host_component, 0);
      const int saved_errno = errno;
      close(directory_fd);
      if (result != 0) {
        if (host_errno != NULL) *host_errno = saved_errno;
        return DAZE_DOSFS_HOST_ERROR;
      }
      return DAZE_DOSFS_OK;
    }
    const int next_fd =
      openat(directory_fd, host_component, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    close(directory_fd);
    if (next_fd < 0) {
      if (host_errno != NULL) *host_errno = errno;
      return DAZE_DOSFS_HOST_ERROR;
    }
    directory_fd = next_fd;
    component = separator + 1;
  }
}

static int open_rename_parent(const DazeDosfsMounts *mounts, int drive, char *relative_path,
                              char *leaf, int *host_errno) {
  char *separator = strrchr(relative_path, '/');
  if (separator != NULL) *separator = '\0';
  const char *component = separator == NULL ? relative_path : separator + 1;
  char parent[DAZE_DOSFS_PATH_MAX + 3];
  snprintf(parent, sizeof(parent), "%c:/%s", 'A' + drive, separator == NULL ? "" : relative_path);
  int directory_fd = -1;
  if (daze_dosfs_open_c(mounts, parent, O_RDONLY | O_DIRECTORY, 0, &directory_fd, host_errno) !=
      DAZE_DOSFS_OK)
    return -1;
  char resolved[DAZE_DOSFS_PATH_MAX];
  const int found =
    resolve_dos_component(directory_fd, component, resolved, sizeof(resolved), host_errno);
  if (found < 0) {
    close(directory_fd);
    return -1;
  }
  strcpy(leaf, found ? resolved : component);
  return directory_fd;
}

DazeDosfsStatus daze_dosfs_rename_c(const DazeDosfsMounts *mounts, const char *source_path,
                                    const char *destination_path, int *host_errno) {
  char source[DAZE_DOSFS_PATH_MAX], destination[DAZE_DOSFS_PATH_MAX];
  int source_drive = -1, destination_drive = -1;
  DazeDosfsStatus status =
    normalize_drive_path(mounts, source_path, &source_drive, source, sizeof(source));
  if (status != DAZE_DOSFS_OK) return status;
  status = normalize_drive_path(mounts, destination_path, &destination_drive, destination,
                                sizeof(destination));
  if (status != DAZE_DOSFS_OK) return status;
  if (source[0] == '\0' || destination[0] == '\0') return DAZE_DOSFS_INVALID_PATH;
  if (source_drive != destination_drive) {
    if (host_errno != NULL) *host_errno = EXDEV;
    return DAZE_DOSFS_HOST_ERROR;
  }
  if (daze_dosfs_mount_is_readonly(mounts, source_drive)) {
    if (host_errno != NULL) *host_errno = EROFS;
    return DAZE_DOSFS_HOST_ERROR;
  }
  char source_leaf[DAZE_DOSFS_PATH_MAX], destination_leaf[DAZE_DOSFS_PATH_MAX];
  const int source_fd = open_rename_parent(mounts, source_drive, source, source_leaf, host_errno);
  if (source_fd < 0) return DAZE_DOSFS_HOST_ERROR;
  const int destination_fd =
    open_rename_parent(mounts, destination_drive, destination, destination_leaf, host_errno);
  if (destination_fd < 0) {
    close(source_fd);
    return DAZE_DOSFS_HOST_ERROR;
  }
  struct stat information;
  int result = fstatat(source_fd, source_leaf, &information, AT_SYMLINK_NOFOLLOW);
  if (result == 0 && !S_ISREG(information.st_mode)) {
    errno = EACCES;
    result = -1;
  }
  /* macOS permits an exclusive rename onto the same file; DOS rejects any existing target. */
  if (result == 0) {
    if (fstatat(destination_fd, destination_leaf, &information, AT_SYMLINK_NOFOLLOW) == 0) {
      errno = EEXIST;
      result = -1;
    } else if (errno != ENOENT) {
      result = -1;
    }
  }
  /* DOS must not overwrite a destination created between lookup and rename. */
  if (result == 0)
#if defined(__APPLE__)
    result = renameatx_np(source_fd, source_leaf, destination_fd, destination_leaf, RENAME_EXCL);
#else
    result = renameat2(source_fd, source_leaf, destination_fd, destination_leaf, RENAME_NOREPLACE);
#endif
  const int saved_errno = errno;
  close(destination_fd);
  close(source_fd);
  if (result != 0) {
    if (host_errno != NULL) *host_errno = saved_errno;
    return DAZE_DOSFS_HOST_ERROR;
  }
  return DAZE_DOSFS_OK;
}

DazeDosfsStatus daze_dosfs_find_first_c(const DazeDosfsMounts *mounts, const char *guest_pattern,
                                        uint16_t attributes, DazeDosfsFind *find,
                                        DazeDosfsFindResult *result, int *found, int *host_errno) {
  if (guest_pattern == NULL || find == NULL || result == NULL || found == NULL) {
    return DAZE_DOSFS_INVALID_PATH;
  }
  daze_dosfs_find_close(find);
  const char *leaf = guest_pattern + strlen(guest_pattern);
  while (leaf > guest_pattern && leaf[-1] != '\\' && leaf[-1] != '/')
    --leaf;
  if (*leaf == '\0' || strlen(leaf) >= sizeof(find->pattern)) {
    return DAZE_DOSFS_INVALID_PATH;
  }
  for (const char *character = leaf; *character != '\0'; ++character) {
    if (*character != '*' && *character != '?' && has_dos_forbidden_character(character, 1)) {
      return DAZE_DOSFS_INVALID_PATH;
    }
  }
  char parent[DAZE_DOSFS_PATH_MAX];
  const size_t parent_length = (size_t)(leaf - guest_pattern);
  if (parent_length == 0) {
    memcpy(parent, ".", 2);
  } else if (parent_length >= sizeof(parent)) {
    return DAZE_DOSFS_OUTPUT_TOO_SMALL;
  } else {
    memcpy(parent, guest_pattern, parent_length);
    parent[parent_length] = '\0';
  }
  int directory_fd = -1;
  DazeDosfsStatus status =
    daze_dosfs_open_c(mounts, parent, O_RDONLY | O_DIRECTORY, 0, &directory_fd, host_errno);
  if (status != DAZE_DOSFS_OK) return status;
  find->directory = fdopendir(directory_fd);
  if (find->directory == NULL) {
    if (host_errno != NULL) *host_errno = errno;
    close(directory_fd);
    return DAZE_DOSFS_HOST_ERROR;
  }
  memcpy(find->pattern, leaf, strlen(leaf) + 1);
  find->attributes = attributes;
  return daze_dosfs_find_next_impl(find, result, found, host_errno);
}

DazeDosfsStatus daze_dosfs_find_next(DazeDosfsFind *find, DazeDosfsFindResult *result, int *found,
                                     int *host_errno) {
  return daze_dosfs_find_next_impl(find, result, found, host_errno);
}

void daze_dosfs_find_close(DazeDosfsFind *find) {
  if (find != NULL && find->directory != NULL) {
    closedir(find->directory);
    find->directory = NULL;
  }
}

DazeDosfsStatus daze_dosfs_ensure_temp_directory(const DazeDosfsMounts *mounts, int *host_errno) {
  if (mounts == NULL || mounts->default_drive < 0 ||
      mounts->default_drive >= DAZE_DOSFS_MAX_DRIVES) {
    return DAZE_DOSFS_INVALID_PATH;
  }
  const int mount_fd = mounts->fds[mounts->default_drive];
  if (mount_fd < 0) {
    return DAZE_DOSFS_INVALID_PATH;
  }
  if (daze_dosfs_mount_is_readonly(mounts, mounts->default_drive)) {
    if (host_errno != NULL) *host_errno = EROFS;
    return DAZE_DOSFS_HOST_ERROR;
  }
  if (mkdirat(mount_fd, "TMP", 0700) != 0 && errno != EEXIST) {
    if (host_errno != NULL) *host_errno = errno;
    return DAZE_DOSFS_HOST_ERROR;
  }
  const int temporary_fd = openat(mount_fd, "TMP", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  const int saved_errno = errno;
  if (temporary_fd < 0) {
    if (host_errno != NULL) *host_errno = saved_errno;
    return DAZE_DOSFS_HOST_ERROR;
  }
  close(temporary_fd);
  return DAZE_DOSFS_OK;
}

DazeDosfsStatus daze_dosfs_default_environment(char *environment, size_t environment_size,
                                               size_t *environment_length) {
  static const char values[] = "PATH=C:\\\0"
                               "TEMP=C:\\TMP\0"
                               "TMP=C:\\TMP\0"
                               "\0";
  if (environment == NULL || environment_length == NULL) {
    return DAZE_DOSFS_INVALID_PATH;
  }
  if (sizeof(values) > environment_size) {
    return DAZE_DOSFS_OUTPUT_TOO_SMALL;
  }
  memcpy(environment, values, sizeof(values));
  *environment_length = sizeof(values);
  return DAZE_DOSFS_OK;
}

const char *daze_dosfs_status_string(DazeDosfsStatus status) {
  switch (status) {
  case DAZE_DOSFS_OK:
    return "ok";
  case DAZE_DOSFS_INVALID_PATH:
    return "invalid DOS path";
  case DAZE_DOSFS_UNMOUNTED_DRIVE:
    return "DOS drive is not mounted";
  case DAZE_DOSFS_DRIVE_IN_USE:
    return "DOS drive is already mounted";
  case DAZE_DOSFS_OUTPUT_TOO_SMALL:
    return "output buffer is too small";
  case DAZE_DOSFS_HOST_ERROR:
    return "host filesystem error";
  }
  return "unknown DOS filesystem status";
}

uint16_t daze_dosfs_errno_to_dos_error(int host_errno) {
  switch (host_errno) {
  case ENOENT:
    return DAZE_DOS_ERR_FILE_NOT_FOUND;
  case ENOTDIR:
    return DAZE_DOS_ERR_PATH_NOT_FOUND;
  case EMFILE:
  case ENFILE:
    return DAZE_DOS_ERR_TOO_MANY_FILES;
  case EACCES:
  case EPERM:
  case EROFS:
    return DAZE_DOS_ERR_ACCESS_DENIED;
  case EEXIST:
    return DAZE_DOS_ERR_FILE_EXISTS;
  case ENOSPC:
    return DAZE_DOS_ERR_DISK_FULL;
  case EINVAL:
    return DAZE_DOS_ERR_INVALID_PARAM;
  default:
    return DAZE_DOS_ERR_INVALID_FUNCTION;
  }
}

void daze_dosfs_handles_init(DazeDosfsHandles *handles) {
  if (handles == NULL) {
    return;
  }
  *handles = (DazeDosfsHandles){0};
  const char *setting = getenv("DAZE_BUFFERED_WRITES");
  handles->buffered_writes = setting == NULL || strcmp(setting, "0") != 0;
  for (size_t index = 0; index < DAZE_DOSFS_MAX_HANDLES; ++index) {
    handles->host_fds[index] = -1;
  }
}

DazeDosfsStatus daze_dosfs_handles_inherit(const DazeDosfsHandles *parent, DazeDosfsHandles *child,
                                           int *host_errno) {
  if (host_errno != NULL) *host_errno = 0;
  if (parent == NULL || child == NULL || parent == child) return DAZE_DOSFS_INVALID_PATH;
  for (size_t index = 0; index < DAZE_DOSFS_MAX_HANDLES; ++index) {
    if (child->host_fds[index] >= 0) return DAZE_DOSFS_INVALID_PATH;
  }
  DazeDosfsHandles inherited;
  daze_dosfs_handles_init(&inherited);
  inherited.buffered_writes = parent->buffered_writes;
  for (size_t index = 0; index < DAZE_DOSFS_MAX_HANDLES; ++index) {
    if (parent->host_fds[index] < 0) continue;
    inherited.host_fds[index] = dup(parent->host_fds[index]);
    if (inherited.host_fds[index] < 0) {
      if (host_errno != NULL) *host_errno = errno;
      daze_dosfs_handles_close_all(&inherited);
      return DAZE_DOSFS_HOST_ERROR;
    }
    inherited.write_buffers[index] = parent->write_buffers[index];
    if (inherited.write_buffers[index] != NULL) inherited.write_buffers[index]->references++;
  }
  *child = inherited;
  return DAZE_DOSFS_OK;
}

DazeDosfsStatus daze_dosfs_exec_handles_begin(DazeDosfsExecHandles *scope, DazeDosfsHandles *live,
                                              int *host_errno) {
  if (scope == NULL || scope->live != NULL || live == NULL) return DAZE_DOSFS_INVALID_PATH;
  DazeDosfsHandles child;
  daze_dosfs_handles_init(&child);
  const DazeDosfsStatus status = daze_dosfs_handles_inherit(live, &child, host_errno);
  if (status != DAZE_DOSFS_OK) return status;
  scope->parent = *live;
  scope->live = live;
  *live = child;
  return DAZE_DOSFS_OK;
}

void daze_dosfs_exec_handles_restore(DazeDosfsExecHandles *scope) {
  if (scope == NULL || scope->live == NULL) return;
  daze_dosfs_handles_close_all(scope->live);
  if (scope->live->teardown_errno != 0) scope->parent.teardown_errno = scope->live->teardown_errno;
  *scope->live = scope->parent;
  *scope = (DazeDosfsExecHandles){0};
}

void daze_dosfs_exec_handles_dispose(DazeDosfsExecHandles *scope) {
  if (scope == NULL || scope->live == NULL) return;
  daze_dosfs_handles_close_all(&scope->parent);
  *scope = (DazeDosfsExecHandles){0};
}

DazeDosfsStatus daze_dosfs_handles_bind_standard(DazeDosfsHandles *handles, int host_stdin,
                                                 int host_stdout, int host_stderr,
                                                 int *host_errno) {
  if (handles == NULL || host_stdin < 0 || host_stdout < 0 || host_stderr < 0) {
    return DAZE_DOSFS_INVALID_PATH;
  }
  const int sources[] = {host_stdin, host_stdout, host_stderr};
  int duplicated[3] = {-1, -1, -1};
  for (size_t index = 0; index < 3; ++index) {
    duplicated[index] = dup(sources[index]);
    if (duplicated[index] < 0) {
      if (host_errno != NULL) *host_errno = errno;
      for (size_t close_index = 0; close_index < index; ++close_index) {
        close(duplicated[close_index]);
      }
      return DAZE_DOSFS_HOST_ERROR;
    }
  }
  for (size_t index = 0; index < 3; ++index) {
    if (handles->host_fds[index] >= 0) {
      (void)daze_dosfs_handles_close(handles, (uint16_t)index, NULL);
    }
    handles->host_fds[index] = duplicated[index];
  }
  return DAZE_DOSFS_OK;
}

static DazeDosfsStatus adopt_handle(DazeDosfsHandles *handles, int host_fd, uint16_t *dos_handle,
                                    int buffer_writes) {
  if (handles == NULL || dos_handle == NULL || host_fd < 0) {
    return DAZE_DOSFS_INVALID_PATH;
  }
  /* 0–2 are standard streams; 3 and 4 remain reserved for AUX and PRN. */
  for (uint16_t index = 5; index < DAZE_DOSFS_MAX_HANDLES; ++index) {
    if (handles->host_fds[index] == -1) {
      DazeDosfsWriteBuffer *buffer = NULL;
      struct stat information;
      if (buffer_writes && handles->buffered_writes && fstat(host_fd, &information) == 0 &&
          S_ISREG(information.st_mode)) {
        int alias = 0;
        /* Independently opened descriptors have independent offsets. Keep their
         * writes visible to each other by disabling buffering for that inode. */
        for (size_t slot = 0; slot < DAZE_DOSFS_MAX_HANDLES; ++slot) {
          DazeDosfsWriteBuffer *existing = handles->write_buffers[slot];
          if (existing == NULL) {
            struct stat other;
            if (handles->host_fds[slot] >= 0 && fstat(handles->host_fds[slot], &other) == 0 &&
                other.st_dev == information.st_dev && other.st_ino == information.st_ino)
              alias = 1;
            continue;
          }
          if (existing->device != information.st_dev || existing->inode != information.st_ino)
            continue;
          if (flush_write_buffer(existing, handles->host_fds[slot]) != 0)
            return DAZE_DOSFS_HOST_ERROR;
          existing->disabled = 1;
          alias = 1;
        }
        const int flags = fcntl(host_fd, F_GETFL);
        if (!alias && flags >= 0 && (flags & O_ACCMODE) != O_RDONLY) {
          buffer = calloc(1, sizeof(*buffer));
          if (buffer != NULL) {
            buffer->references = 1;
            buffer->device = information.st_dev;
            buffer->inode = information.st_ino;
          }
        }
      }
      handles->host_fds[index] = host_fd;
      handles->write_buffers[index] = buffer;
      *dos_handle = index;
      return DAZE_DOSFS_OK;
    }
  }
  return DAZE_DOSFS_HOST_ERROR;
}

DazeDosfsStatus daze_dosfs_handles_adopt(DazeDosfsHandles *handles, int host_fd,
                                         uint16_t *dos_handle) {
  return adopt_handle(handles, host_fd, dos_handle, 1);
}

DazeDosfsStatus daze_dosfs_handles_duplicate(DazeDosfsHandles *handles, uint16_t source_handle,
                                             uint16_t *dos_handle, int *host_errno) {
  if (host_errno != NULL) {
    *host_errno = 0;
  }
  int source_fd = -1;
  if (dos_handle == NULL) return DAZE_DOSFS_INVALID_PATH;
  const DazeDosfsStatus source_status =
    daze_dosfs_handles_flush_and_get(handles, source_handle, &source_fd);
  if (source_status != DAZE_DOSFS_OK) {
    if (source_status == DAZE_DOSFS_HOST_ERROR && host_errno != NULL) *host_errno = errno;
    return source_status;
  }
  const int duplicate_fd = dup(source_fd);
  if (duplicate_fd < 0) {
    if (host_errno != NULL) *host_errno = errno;
    return DAZE_DOSFS_HOST_ERROR;
  }
  const DazeDosfsStatus status = adopt_handle(handles, duplicate_fd, dos_handle, 0);
  if (status != DAZE_DOSFS_OK) {
    (void)close(duplicate_fd);
    if (host_errno != NULL) {
      *host_errno = EMFILE;
    }
  }
  if (status == DAZE_DOSFS_OK) {
    handles->write_buffers[*dos_handle] = handles->write_buffers[source_handle];
    if (handles->write_buffers[*dos_handle] != NULL)
      handles->write_buffers[*dos_handle]->references++;
  }
  return status;
}

DazeDosfsStatus daze_dosfs_handles_force_duplicate(DazeDosfsHandles *handles,
                                                   uint16_t source_handle, uint16_t target_handle,
                                                   int *host_errno) {
  if (host_errno != NULL) *host_errno = 0;
  int source_fd = -1;
  if (handles == NULL || target_handle >= DAZE_DOSFS_MAX_HANDLES) return DAZE_DOSFS_INVALID_PATH;
  const DazeDosfsStatus source_status =
    daze_dosfs_handles_flush_and_get(handles, source_handle, &source_fd);
  if (source_status != DAZE_DOSFS_OK) {
    if (source_status == DAZE_DOSFS_HOST_ERROR && host_errno != NULL) *host_errno = errno;
    return source_status;
  }
  if (source_handle == target_handle) return DAZE_DOSFS_OK;
  const int duplicate_fd = dup(source_fd);
  if (duplicate_fd < 0) {
    if (host_errno != NULL) *host_errno = errno;
    return DAZE_DOSFS_HOST_ERROR;
  }
  if (handles->host_fds[target_handle] >= 0 &&
      (flush_write_buffer(handles->write_buffers[target_handle], handles->host_fds[target_handle]) <
         0 ||
       close(handles->host_fds[target_handle]) < 0)) {
    if (host_errno != NULL) *host_errno = errno;
    (void)close(duplicate_fd);
    return DAZE_DOSFS_HOST_ERROR;
  }
  release_write_buffer(handles->write_buffers[target_handle]);
  handles->host_fds[target_handle] = duplicate_fd;
  handles->write_buffers[target_handle] = handles->write_buffers[source_handle];
  if (handles->write_buffers[target_handle] != NULL)
    handles->write_buffers[target_handle]->references++;
  return DAZE_DOSFS_OK;
}

DazeDosfsStatus daze_dosfs_handles_peek(const DazeDosfsHandles *handles, uint16_t dos_handle,
                                        int *host_fd) {
  if (handles == NULL || host_fd == NULL || dos_handle >= DAZE_DOSFS_MAX_HANDLES ||
      handles->host_fds[dos_handle] < 0) {
    return DAZE_DOSFS_INVALID_PATH;
  }
  *host_fd = handles->host_fds[dos_handle];
  return DAZE_DOSFS_OK;
}

DazeDosfsStatus daze_dosfs_handles_flush_and_get(const DazeDosfsHandles *handles,
                                                 uint16_t dos_handle, int *host_fd) {
  DazeDosfsStatus status = daze_dosfs_handles_peek(handles, dos_handle, host_fd);
  if (status == DAZE_DOSFS_OK &&
      flush_write_buffer(handles->write_buffers[dos_handle], *host_fd) != 0)
    return DAZE_DOSFS_HOST_ERROR;
  return status;
}

DazeDosfsStatus daze_dosfs_handles_flush(const DazeDosfsHandles *handles, int *host_errno) {
  if (host_errno != NULL) *host_errno = 0;
  if (handles == NULL) return DAZE_DOSFS_INVALID_PATH;
  for (size_t slot = 0; slot < DAZE_DOSFS_MAX_HANDLES; ++slot) {
    if (flush_write_buffer(handles->write_buffers[slot], handles->host_fds[slot]) != 0) {
      if (host_errno != NULL) *host_errno = errno;
      return DAZE_DOSFS_HOST_ERROR;
    }
  }
  return DAZE_DOSFS_OK;
}

uint16_t daze_dosfs_handles_write_credit(const DazeDosfsHandles *handles, uint16_t handle) {
  if (handles == NULL || !handles->buffered_writes || handle >= DAZE_DOSFS_MAX_HANDLES ||
      handles->host_fds[handle] < 0)
    return 0;
  const DazeDosfsWriteBuffer *buffer = handles->write_buffers[handle];
  return buffer != NULL && !buffer->disabled && buffer->used <= sizeof(buffer->bytes)
           ? (uint16_t)(sizeof(buffer->bytes) - buffer->used)
           : 0;
}

int daze_dosfs_handles_append_buffered(DazeDosfsHandles *handles, uint16_t handle,
                                       const uint8_t *bytes, uint16_t count) {
  if (bytes == NULL || count == 0 || count > daze_dosfs_handles_write_credit(handles, handle))
    return 0;
  DazeDosfsWriteBuffer *buffer = handles->write_buffers[handle];
  memcpy(buffer->bytes + buffer->used, bytes, count);
  buffer->used += count;
  return 1;
}

ssize_t daze_dosfs_handles_write(DazeDosfsHandles *handles, uint16_t dos_handle,
                                 const uint8_t *bytes, size_t count) {
  int fd;
  if (daze_dosfs_handles_peek(handles, dos_handle, &fd) != DAZE_DOSFS_OK) {
    errno = EBADF;
    return -1;
  }
  if (count == 0) return 0;
  if (bytes == NULL) {
    errno = EINVAL;
    return -1;
  }
  DazeDosfsWriteBuffer *buffer = handles->write_buffers[dos_handle];
  if (buffer != NULL && !buffer->disabled && count <= sizeof(buffer->bytes)) {
    if (count > sizeof(buffer->bytes) - buffer->used && flush_write_buffer(buffer, fd) != 0)
      return -1;
    memcpy(buffer->bytes + buffer->used, bytes, count);
    buffer->used += count;
    return (ssize_t)count;
  }
  if (flush_write_buffer(buffer, fd) != 0) return -1;
  ssize_t written;
  do {
    written = write(fd, bytes, count);
  } while (written < 0 && errno == EINTR);
  return written;
}

DazeDosfsStatus daze_dosfs_handles_close(DazeDosfsHandles *handles, uint16_t dos_handle,
                                         int *host_errno) {
  if (handles == NULL || dos_handle >= DAZE_DOSFS_MAX_HANDLES ||
      handles->host_fds[dos_handle] < 0) {
    return DAZE_DOSFS_INVALID_PATH;
  }
  const int host_fd = handles->host_fds[dos_handle];
  const int flushed = flush_write_buffer(handles->write_buffers[dos_handle], host_fd);
  const int flush_errno = errno;
  release_write_buffer(handles->write_buffers[dos_handle]);
  handles->write_buffers[dos_handle] = NULL;
  handles->host_fds[dos_handle] = -1;
  const int closed = close(host_fd);
  if (flushed != 0 || closed != 0) {
    if (host_errno != NULL) *host_errno = flushed != 0 ? flush_errno : errno;
    return DAZE_DOSFS_HOST_ERROR;
  }
  return DAZE_DOSFS_OK;
}

void daze_dosfs_handles_close_all(DazeDosfsHandles *handles) {
  if (handles == NULL) {
    return;
  }
  for (uint16_t index = 0; index < DAZE_DOSFS_MAX_HANDLES; ++index) {
    if (handles->host_fds[index] >= 0) {
      int host_errno = 0;
      if (daze_dosfs_handles_close(handles, (uint16_t)index, &host_errno) != DAZE_DOSFS_OK)
        handles->teardown_errno = host_errno;
    }
  }
}
