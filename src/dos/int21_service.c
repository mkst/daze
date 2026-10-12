#include "int21_service.h"

#include <stddef.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "date.h"
#include "country.h"
#include "dos_error.h"
#include "dos_function.h"

static void begin_result(DazeDosInt21Result *result) {
  *result = (DazeDosInt21Result){
    .disposition = DAZE_DOS_INT21_UNSUPPORTED,
  };
}

static void set_flag(DazeDosInt21Result *result, uint16_t flag, int set) {
  result->flag_write_mask |= flag;
  if (set)
    result->flag_values |= flag;
  else
    result->flag_values &= (uint16_t)~flag;
}

static DazeDosInt21DispatchStatus read_asciiz(const DazeDosInt21Context *context, uint16_t segment,
                                              uint16_t offset, char *output, size_t output_size) {
  if (context->guest_memory.read == NULL || output_size == 0)
    return DAZE_DOS_INT21_DISPATCH_INVALID_ARGUMENT;
  for (size_t index = 0; index + 1 < output_size; ++index) {
    if (!context->guest_memory.read(context->guest_memory.context, segment,
                                    (uint16_t)(offset + index), output + index, 1))
      return DAZE_DOS_INT21_DISPATCH_MEMORY_FAILURE;
    if (output[index] == '\0') return DAZE_DOS_INT21_DISPATCH_OK;
  }
  output[0] = '\0';
  return DAZE_DOS_INT21_DISPATCH_MEMORY_FAILURE;
}

static DazeDosInt21DispatchStatus write_find_result(const DazeDosInt21Context *context,
                                                    const DazeDosfsFindResult *find_result) {
  uint8_t bytes[DAZE_DOS_FIND_DTA_SIZE];
  if (context->guest_memory.write == NULL || context->process_state == NULL ||
      !daze_dos_find_result_encode(find_result, bytes))
    return DAZE_DOS_INT21_DISPATCH_INVALID_ARGUMENT;
  return context->guest_memory.write(context->guest_memory.context,
                                     context->process_state->dta_segment,
                                     context->process_state->dta_offset, bytes, sizeof(bytes))
           ? DAZE_DOS_INT21_DISPATCH_OK
           : DAZE_DOS_INT21_DISPATCH_MEMORY_FAILURE;
}

static DazeDosInt21DispatchStatus dispatch_find_first(const DazeDosInt21Context *context,
                                                      const DazeDosInt21Request *request,
                                                      DazeDosInt21Result *result) {
  if (context->files == NULL || context->files->mounts == NULL || context->process_state == NULL)
    return DAZE_DOS_INT21_DISPATCH_INVALID_ARGUMENT;
  char pattern[128];
  const DazeDosInt21DispatchStatus read_status =
    read_asciiz(context, request->ds, request->dx, pattern, sizeof(pattern));
  if (read_status != DAZE_DOS_INT21_DISPATCH_OK) return read_status;
  DazeDosfsFindResult find_result;
  int found = 0;
  int host_errno = 0;
  const DazeDosfsStatus status =
    daze_dosfs_find_first_c(context->files->mounts, pattern, request->cx,
                            &context->process_state->find, &find_result, &found, &host_errno);
  result->disposition = DAZE_DOS_INT21_HANDLED;
  if (status != DAZE_DOSFS_OK) {
    result->register_write_mask = DAZE_DOS_INT21_REG_AX;
    result->ax = status == DAZE_DOSFS_HOST_ERROR ? daze_dosfs_errno_to_dos_error(host_errno)
                                                 : DAZE_DOS_ERR_PATH_NOT_FOUND;
    set_flag(result, DAZE_DOS_INT21_FLAG_CF, 1);
  } else if (!found || write_find_result(context, &find_result) != DAZE_DOS_INT21_DISPATCH_OK) {
    result->register_write_mask = DAZE_DOS_INT21_REG_AX;
    result->ax = DAZE_DOS_ERR_NO_MORE_FILES;
    set_flag(result, DAZE_DOS_INT21_FLAG_CF, 1);
  } else {
    set_flag(result, DAZE_DOS_INT21_FLAG_CF, 0);
  }
  return DAZE_DOS_INT21_DISPATCH_OK;
}

static DazeDosInt21DispatchStatus dispatch_find_next(const DazeDosInt21Context *context,
                                                     DazeDosInt21Result *result) {
  if (context->process_state == NULL) return DAZE_DOS_INT21_DISPATCH_INVALID_ARGUMENT;
  DazeDosfsFindResult find_result;
  int found = 0;
  int host_errno = 0;
  const DazeDosfsStatus status =
    daze_dosfs_find_next(&context->process_state->find, &find_result, &found, &host_errno);
  result->disposition = DAZE_DOS_INT21_HANDLED;
  if (status != DAZE_DOSFS_OK) {
    result->register_write_mask = DAZE_DOS_INT21_REG_AX;
    result->ax = status == DAZE_DOSFS_HOST_ERROR ? daze_dosfs_errno_to_dos_error(host_errno)
                                                 : DAZE_DOS_ERR_NO_MORE_FILES;
    set_flag(result, DAZE_DOS_INT21_FLAG_CF, 1);
  } else if (!found || write_find_result(context, &find_result) != DAZE_DOS_INT21_DISPATCH_OK) {
    result->register_write_mask = DAZE_DOS_INT21_REG_AX;
    result->ax = DAZE_DOS_ERR_NO_MORE_FILES;
    set_flag(result, DAZE_DOS_INT21_FLAG_CF, 1);
  } else {
    set_flag(result, DAZE_DOS_INT21_FLAG_CF, 0);
  }
  return DAZE_DOS_INT21_DISPATCH_OK;
}

static DazeDosInt21DispatchStatus dispatch_fcb_parse(const DazeDosInt21Context *context,
                                                     const DazeDosInt21Request *request,
                                                     DazeDosInt21Result *result) {
  uint8_t input[128];
  size_t input_size = 0;
  for (; input_size < sizeof(input); ++input_size) {
    if (context->guest_memory.read == NULL ||
        !context->guest_memory.read(context->guest_memory.context, request->ds,
                                    (uint16_t)(request->si + input_size), input + input_size, 1))
      return DAZE_DOS_INT21_DISPATCH_MEMORY_FAILURE;
    if (input[input_size] == '\0' || input[input_size] == ' ' || input[input_size] == '\r') {
      ++input_size;
      break;
    }
  }
  uint8_t fcb[16];
  size_t consumed = 0;
  uint8_t parse_result = 0xff;
  if (!daze_dos_fcb_parse(input, input_size, (uint8_t)request->ax, fcb, &consumed, &parse_result))
    return DAZE_DOS_INT21_DISPATCH_MEMORY_FAILURE;
  if (parse_result != 0xff &&
      (context->guest_memory.write == NULL ||
       !context->guest_memory.write(context->guest_memory.context, request->es, request->di, fcb,
                                    sizeof(fcb))))
    return DAZE_DOS_INT21_DISPATCH_MEMORY_FAILURE;
  result->disposition = DAZE_DOS_INT21_HANDLED;
  result->register_write_mask = DAZE_DOS_INT21_REG_AX;
  result->ax = (uint16_t)((request->ax & 0xff00u) | parse_result);
  if (parse_result != 0xff) {
    result->register_write_mask |= DAZE_DOS_INT21_REG_SI;
    result->si = (uint16_t)(request->si + consumed);
  }
  set_flag(result, DAZE_DOS_INT21_FLAG_CF, 0);
  return DAZE_DOS_INT21_DISPATCH_OK;
}

static DazeDosInt21DispatchStatus dispatch_delete(const DazeDosInt21Context *context,
                                                  const DazeDosInt21Request *request,
                                                  DazeDosInt21Result *result) {
  if (context->files == NULL || context->files->mounts == NULL)
    return DAZE_DOS_INT21_DISPATCH_INVALID_ARGUMENT;
  char path[128];
  const DazeDosInt21DispatchStatus read_status =
    read_asciiz(context, request->ds, request->dx, path, sizeof(path));
  if (read_status != DAZE_DOS_INT21_DISPATCH_OK) return read_status;
  int host_errno = 0;
  const DazeDosfsStatus status = daze_dosfs_unlink_c(context->files->mounts, path, &host_errno);
  result->disposition = DAZE_DOS_INT21_HANDLED;
  if (status == DAZE_DOSFS_OK) {
    set_flag(result, DAZE_DOS_INT21_FLAG_CF, 0);
  } else {
    result->register_write_mask = DAZE_DOS_INT21_REG_AX;
    result->ax = status == DAZE_DOSFS_HOST_ERROR ? daze_dosfs_errno_to_dos_error(host_errno)
                                                 : DAZE_DOS_ERR_PATH_NOT_FOUND;
    set_flag(result, DAZE_DOS_INT21_FLAG_CF, 1);
  }
  return DAZE_DOS_INT21_DISPATCH_OK;
}

static DazeDosInt21DispatchStatus dispatch_rename(const DazeDosInt21Context *context,
                                                  const DazeDosInt21Request *request,
                                                  DazeDosInt21Result *result) {
  if (context->files == NULL || context->files->mounts == NULL)
    return DAZE_DOS_INT21_DISPATCH_INVALID_ARGUMENT;
  char source[128], destination[128];
  DazeDosInt21DispatchStatus read_status =
    read_asciiz(context, request->ds, request->dx, source, sizeof(source));
  if (read_status != DAZE_DOS_INT21_DISPATCH_OK) return read_status;
  read_status = read_asciiz(context, request->es, request->di, destination, sizeof(destination));
  if (read_status != DAZE_DOS_INT21_DISPATCH_OK) return read_status;
  int host_errno = 0;
  const DazeDosfsStatus status =
    daze_dosfs_rename_c(context->files->mounts, source, destination, &host_errno);
  result->disposition = DAZE_DOS_INT21_HANDLED;
  set_flag(result, DAZE_DOS_INT21_FLAG_CF, status != DAZE_DOSFS_OK);
  if (status != DAZE_DOSFS_OK) {
    result->register_write_mask = DAZE_DOS_INT21_REG_AX;
    result->ax = status != DAZE_DOSFS_HOST_ERROR ? DAZE_DOS_ERR_PATH_NOT_FOUND
                 : host_errno == EEXIST          ? DAZE_DOS_ERR_ACCESS_DENIED
                 : host_errno == EXDEV           ? DAZE_DOS_ERR_NOT_SAME_DEVICE
                                                 : daze_dosfs_errno_to_dos_error(host_errno);
  }
  return DAZE_DOS_INT21_DISPATCH_OK;
}

static DazeDosInt21DispatchStatus dispatch_file_open_create(const DazeDosInt21Context *context,
                                                            const DazeDosInt21Request *request,
                                                            DazeDosInt21Result *result,
                                                            int create) {
  if (context->files == NULL || context->files->mounts == NULL || context->files->handles == NULL)
    return DAZE_DOS_INT21_DISPATCH_INVALID_ARGUMENT;
  char path[128];
  const DazeDosInt21DispatchStatus read_status =
    read_asciiz(context, request->ds, request->dx, path, sizeof(path));
  if (read_status != DAZE_DOS_INT21_DISPATCH_OK) return read_status;
  DazeDosfsFileResult file = {0};
  if (create)
    daze_dosfs_file_create(context->files, path, &file);
  else
    daze_dosfs_file_open(context->files, path, (uint8_t)request->ax, &file);
  result->disposition = DAZE_DOS_INT21_HANDLED;
  result->register_write_mask = DAZE_DOS_INT21_REG_AX;
  if (file.success) {
    result->ax = file.handle;
    set_flag(result, DAZE_DOS_INT21_FLAG_CF, 0);
  } else {
    result->ax = file.dos_error;
    set_flag(result, DAZE_DOS_INT21_FLAG_CF, 1);
  }
  daze_dosfs_file_result_dispose(&file);
  return DAZE_DOS_INT21_DISPATCH_OK;
}

/* INT 21h/5Ah names files from a per-process counter, so repeated runs stay
 * deterministic. */
#define DAZE_DOS_TEMP_NAME_LENGTH 12

static DazeDosInt21DispatchStatus dispatch_file_create_temp(const DazeDosInt21Context *context,
                                                            const DazeDosInt21Request *request,
                                                            DazeDosInt21Result *result) {
  if (context->files == NULL || context->files->mounts == NULL || context->files->handles == NULL ||
      context->process_state == NULL || context->guest_memory.read == NULL ||
      context->guest_memory.write == NULL)
    return DAZE_DOS_INT21_DISPATCH_INVALID_ARGUMENT;
  char directory[128];
  const DazeDosInt21DispatchStatus read_status =
    read_asciiz(context, request->ds, request->dx, directory, sizeof(directory));
  if (read_status != DAZE_DOS_INT21_DISPATCH_OK) return read_status;
  const size_t prefix = strlen(directory);
  if (prefix == 0 || (directory[prefix - 1] != '\\' && directory[prefix - 1] != '/')) {
    result->disposition = DAZE_DOS_INT21_HANDLED;
    result->register_write_mask = DAZE_DOS_INT21_REG_AX;
    result->ax = DAZE_DOS_ERR_PATH_NOT_FOUND;
    set_flag(result, DAZE_DOS_INT21_FLAG_CF, 1);
    return DAZE_DOS_INT21_DISPATCH_OK;
  }
  uint32_t counter = context->process_state->temp_file_counter;
  for (int attempt = 0; attempt < 256; ++attempt) {
    char candidate[sizeof(directory) + DAZE_DOS_TEMP_NAME_LENGTH + 1];
    char name[DAZE_DOS_TEMP_NAME_LENGTH + 1];
    snprintf(name, sizeof(name), "DZ%06X.TMP", counter & 0xffffff);
    memcpy(candidate, directory, prefix);
    memcpy(candidate + prefix, name, sizeof(name));
    DazeDosfsFileResult file = {0};
    daze_dosfs_file_create_exclusive(context->files, candidate, &file);
    const int created = file.success;
    const uint16_t handle = file.handle;
    const uint16_t dos_error = file.dos_error;
    daze_dosfs_file_result_dispose(&file);
    if (!created && dos_error == DAZE_DOS_ERR_FILE_EXISTS) {
      ++counter;
      continue;
    }
    if (!created) {
      result->disposition = DAZE_DOS_INT21_HANDLED;
      result->register_write_mask = DAZE_DOS_INT21_REG_AX;
      result->ax = dos_error;
      set_flag(result, DAZE_DOS_INT21_FLAG_CF, 1);
      return DAZE_DOS_INT21_DISPATCH_OK;
    }
    if (!context->guest_memory.write(context->guest_memory.context, request->ds, request->dx,
                                     candidate, prefix + sizeof(name)))
      return DAZE_DOS_INT21_DISPATCH_MEMORY_FAILURE;
    context->process_state->temp_file_counter = counter + 1;
    result->disposition = DAZE_DOS_INT21_HANDLED;
    result->register_write_mask = DAZE_DOS_INT21_REG_AX;
    result->ax = handle;
    set_flag(result, DAZE_DOS_INT21_FLAG_CF, 0);
    return DAZE_DOS_INT21_DISPATCH_OK;
  }
  result->disposition = DAZE_DOS_INT21_HANDLED;
  result->register_write_mask = DAZE_DOS_INT21_REG_AX;
  result->ax = DAZE_DOS_ERR_ACCESS_DENIED;
  set_flag(result, DAZE_DOS_INT21_FLAG_CF, 1);
  return DAZE_DOS_INT21_DISPATCH_OK;
}

static DazeDosInt21DispatchStatus dispatch_file_close(const DazeDosInt21Context *context,
                                                      const DazeDosInt21Request *request,
                                                      DazeDosInt21Result *result) {
  if (context->files == NULL || context->files->handles == NULL)
    return DAZE_DOS_INT21_DISPATCH_INVALID_ARGUMENT;
  int host_errno = 0;
  const DazeDosfsStatus status =
    daze_dosfs_handles_close(context->files->handles, request->bx, &host_errno);
  result->disposition = DAZE_DOS_INT21_HANDLED;
  if (status == DAZE_DOSFS_OK) {
    set_flag(result, DAZE_DOS_INT21_FLAG_CF, 0);
  } else {
    result->register_write_mask = DAZE_DOS_INT21_REG_AX;
    result->ax = status == DAZE_DOSFS_HOST_ERROR ? daze_dosfs_errno_to_dos_error(host_errno)
                                                 : DAZE_DOS_ERR_INVALID_HANDLE;
    set_flag(result, DAZE_DOS_INT21_FLAG_CF, 1);
  }
  return DAZE_DOS_INT21_DISPATCH_OK;
}

static DazeDosInt21DispatchStatus dispatch_file_seek(const DazeDosInt21Context *context,
                                                     const DazeDosInt21Request *request,
                                                     DazeDosInt21Result *result) {
  if (context->files == NULL || context->files->handles == NULL)
    return DAZE_DOS_INT21_DISPATCH_INVALID_ARGUMENT;
  DazeDosfsFileResult file = {0};
  const int32_t displacement = (int32_t)((uint32_t)request->cx << 16 | request->dx);
  daze_dosfs_file_seek(context->files, request->bx, (uint8_t)request->ax, displacement, &file);
  result->disposition = DAZE_DOS_INT21_HANDLED;
  if (file.success) {
    result->register_write_mask = DAZE_DOS_INT21_REG_AX | DAZE_DOS_INT21_REG_DX;
    result->ax = (uint16_t)file.position;
    result->dx = (uint16_t)(file.position >> 16);
    set_flag(result, DAZE_DOS_INT21_FLAG_CF, 0);
  } else {
    result->register_write_mask = DAZE_DOS_INT21_REG_AX;
    result->ax = file.dos_error;
    set_flag(result, DAZE_DOS_INT21_FLAG_CF, 1);
  }
  daze_dosfs_file_result_dispose(&file);
  return DAZE_DOS_INT21_DISPATCH_OK;
}

static void observe_transfer(const DazeDosInt21Context *context, const DazeDosInt21Request *request,
                             const DazeDosfsFileResult *file, int completed) {
  const DazeDosInt21TransferHook hook =
    completed ? context->transfer_completed : context->transfer_observed;
  if (hook != NULL) hook(context->transfer_context, request, file);
}

static DazeDosInt21DispatchStatus dispatch_display_string(const DazeDosInt21Context *context,
                                                          const DazeDosInt21Request *request,
                                                          DazeDosInt21Result *result) {
  /* Validate before writing output; the bounded scan must not wrap a 16-bit offset. */
  uint8_t output[4096];
  size_t length = 0;
  result->disposition = DAZE_DOS_INT21_HANDLED;
  if (context->files == NULL || context->guest_memory.read == NULL) goto failed;
  for (; length < sizeof(output); ++length) {
    if (length > (size_t)(UINT16_MAX - request->dx) ||
        !context->guest_memory.read(context->guest_memory.context, request->ds,
                                    (uint16_t)(request->dx + length), output + length, 1))
      goto failed;
    if (output[length] == '$') break;
  }
  if (length == sizeof(output)) goto failed;
  int output_fd;
  if (daze_dosfs_handles_get(context->files->handles, 1, &output_fd) != DAZE_DOSFS_OK) goto failed;
  size_t written = 0;
  while (written < length) {
    DazeDosfsFileResult file;
    daze_dosfs_file_write(context->files, 1, output + written, (uint16_t)(length - written), &file);
    observe_transfer(context, request, &file, 0);
    if (!file.success || (written < length && file.byte_count == 0)) goto failed;
    written += file.byte_count;
    observe_transfer(context, request, &file, 1);
  }
  set_flag(result, DAZE_DOS_INT21_FLAG_CF, 0);
  return DAZE_DOS_INT21_DISPATCH_OK;
failed:
  result->register_write_mask = DAZE_DOS_INT21_REG_AX;
  result->ax = DAZE_DOS_ERR_INVALID_HANDLE;
  set_flag(result, DAZE_DOS_INT21_FLAG_CF, 1);
  return DAZE_DOS_INT21_DISPATCH_OK;
}

static DazeDosInt21DispatchStatus dispatch_file_transfer(const DazeDosInt21Context *context,
                                                         const DazeDosInt21Request *request,
                                                         DazeDosInt21Result *result) {
  if (context->files == NULL || context->files->handles == NULL)
    return DAZE_DOS_INT21_DISPATCH_INVALID_ARGUMENT;
  const uint8_t function = (uint8_t)(request->ax >> 8);
  DazeDosfsFileResult file = {0};
  uint8_t *write_bytes = NULL;
  int write_bytes_owned = 0;
  if (function == 0x3f) {
    uint8_t *read_bytes = daze_dosfs_file_service_transfer_buffer(context->files, request->cx);
    if (request->cx != 0 && read_bytes != NULL) {
      daze_dosfs_file_read_into(context->files, request->bx, read_bytes, request->cx, &file);
    } else if (request->cx != 0 && context->files->transfer_storage != NULL) {
      file.dos_error = DAZE_DOS_ERR_NO_MEMORY;
    } else {
      daze_dosfs_file_read(context->files, request->bx, request->cx, &file);
      read_bytes = file.bytes;
    }
    daze_dosfs_file_service_record_transfer(context->files, 1, request->cx, &file);
    observe_transfer(context, request, &file, 0);
    if (!file.success) goto reply;
    if (file.byte_count != 0 &&
        (context->guest_memory.write == NULL ||
         !context->guest_memory.write(context->guest_memory.context, request->ds, request->dx,
                                      read_bytes, file.byte_count))) {
      daze_dosfs_file_result_dispose(&file);
      return DAZE_DOS_INT21_DISPATCH_MEMORY_FAILURE;
    }
  } else {
    int host_fd = -1;
    if (daze_dosfs_handles_get(context->files->handles, request->bx, &host_fd) != DAZE_DOSFS_OK) {
      file.dos_error = DAZE_DOS_ERR_INVALID_HANDLE;
      goto reply;
    }
    if (request->cx != 0) {
      write_bytes = daze_dosfs_file_service_transfer_buffer(context->files, request->cx);
      if (write_bytes == NULL && context->files->transfer_storage == NULL) {
        write_bytes = malloc(request->cx);
        write_bytes_owned = 1;
      }
      if (write_bytes == NULL) {
        file.dos_error = DAZE_DOS_ERR_NO_MEMORY;
        goto reply;
      }
      if (context->guest_memory.read == NULL ||
          !context->guest_memory.read(context->guest_memory.context, request->ds, request->dx,
                                      write_bytes, request->cx)) {
        if (write_bytes_owned) free(write_bytes);
        return DAZE_DOS_INT21_DISPATCH_MEMORY_FAILURE;
      }
    }
    daze_dosfs_file_write(context->files, request->bx, write_bytes, request->cx, &file);
    if (write_bytes_owned) free(write_bytes);
    daze_dosfs_file_service_record_transfer(context->files, 0, request->cx, &file);
    observe_transfer(context, request, &file, 0);
  }

reply:
  result->disposition = DAZE_DOS_INT21_HANDLED;
  result->register_write_mask = DAZE_DOS_INT21_REG_AX;
  if (file.success) {
    result->ax = file.byte_count;
    set_flag(result, DAZE_DOS_INT21_FLAG_CF, 0);
    observe_transfer(context, request, &file, 1);
  } else {
    result->ax = file.dos_error;
    set_flag(result, DAZE_DOS_INT21_FLAG_CF, 1);
  }
  daze_dosfs_file_result_dispose(&file);
  return DAZE_DOS_INT21_DISPATCH_OK;
}

static DazeDosInt21DispatchStatus dispatch_file_attributes(const DazeDosInt21Context *context,
                                                           const DazeDosInt21Request *request,
                                                           DazeDosInt21Result *result) {
  const uint8_t operation = (uint8_t)request->ax;
  if (operation > 1) return DAZE_DOS_INT21_DISPATCH_OK;
  if (context->files == NULL || context->files->mounts == NULL)
    return DAZE_DOS_INT21_DISPATCH_INVALID_ARGUMENT;
  char path[128];
  const DazeDosInt21DispatchStatus read_status =
    read_asciiz(context, request->ds, request->dx, path, sizeof(path));
  if (read_status != DAZE_DOS_INT21_DISPATCH_OK) return read_status;
  DazeDosFileAttrs attributes;
  if (operation == 0) {
    if (!daze_dos_file_attrs_get(context->files->mounts, path, &attributes))
      return DAZE_DOS_INT21_DISPATCH_INVALID_ARGUMENT;
  } else if (!daze_dos_file_attrs_set(context->files->mounts, path, request->cx, &attributes)) {
    return DAZE_DOS_INT21_DISPATCH_INVALID_ARGUMENT;
  }
  result->disposition = DAZE_DOS_INT21_HANDLED;
  if (attributes.successful) {
    if (operation == 0) {
      result->register_write_mask = DAZE_DOS_INT21_REG_CX;
      result->cx = attributes.attributes;
    }
    set_flag(result, DAZE_DOS_INT21_FLAG_CF, 0);
  } else {
    result->register_write_mask = DAZE_DOS_INT21_REG_AX;
    result->ax = attributes.dos_error;
    set_flag(result, DAZE_DOS_INT21_FLAG_CF, 1);
  }
  return DAZE_DOS_INT21_DISPATCH_OK;
}

static DazeDosInt21DispatchStatus dispatch_current_directory(const DazeDosInt21Context *context,
                                                             const DazeDosInt21Request *request,
                                                             DazeDosInt21Result *result) {
  const uint8_t root_path[] = {'\0'};
  if (context->files == NULL || context->files->mounts == NULL)
    return DAZE_DOS_INT21_DISPATCH_INVALID_ARGUMENT;
  const DazeDosfsMounts *mounts = context->files->mounts;
  const unsigned requested_drive = (uint8_t)request->dx;
  const int drive = requested_drive == 0 ? mounts->default_drive : (int)requested_drive - 1;
  result->disposition = DAZE_DOS_INT21_HANDLED;
  if (drive < 0 || drive >= DAZE_DOSFS_MAX_DRIVES || mounts->fds[drive] < 0 ||
      context->guest_memory.write == NULL ||
      !context->guest_memory.write(context->guest_memory.context, request->ds, request->si,
                                   root_path, sizeof(root_path))) {
    result->register_write_mask = DAZE_DOS_INT21_REG_AX;
    result->ax = DAZE_DOS_ERR_INVALID_DRIVE;
    set_flag(result, DAZE_DOS_INT21_FLAG_CF, 1);
  } else {
    set_flag(result, DAZE_DOS_INT21_FLAG_CF, 0);
  }
  return DAZE_DOS_INT21_DISPATCH_OK;
}

static DazeDosInt21DispatchStatus dispatch_memory_service(const DazeDosInt21Context *context,
                                                          const DazeDosInt21Request *request,
                                                          DazeDosInt21Result *result) {
  if (context->dos_memory == NULL) return DAZE_DOS_INT21_DISPATCH_INVALID_ARGUMENT;
  result->disposition = DAZE_DOS_INT21_HANDLED;
  switch ((uint8_t)(request->ax >> 8)) {
  case 0x48: {
    DazeDosAllocation *allocation = daze_dos_memory_allocate(context->dos_memory, request->bx);
    result->register_write_mask = DAZE_DOS_INT21_REG_AX;
    if (allocation == NULL) {
      result->ax = DAZE_DOS_ERR_NO_MEMORY;
      result->register_write_mask |= DAZE_DOS_INT21_REG_BX;
      result->bx = daze_dos_memory_largest_available(context->dos_memory);
      set_flag(result, DAZE_DOS_INT21_FLAG_CF, 1);
    } else {
      result->ax = allocation->segment;
      set_flag(result, DAZE_DOS_INT21_FLAG_CF, 0);
    }
    return DAZE_DOS_INT21_DISPATCH_OK;
  }
  case 0x49:
    if (context->pre_release != NULL &&
        !context->pre_release(context->pre_release_context, request->es)) {
      result->register_write_mask = DAZE_DOS_INT21_REG_AX;
      result->ax = DAZE_DOS_ERR_NO_MEMORY;
      set_flag(result, DAZE_DOS_INT21_FLAG_CF, 1);
    } else if (!daze_dos_memory_release(context->dos_memory, request->es)) {
      result->register_write_mask = DAZE_DOS_INT21_REG_AX;
      result->ax = DAZE_DOS_ERR_INVALID_BLOCK;
      set_flag(result, DAZE_DOS_INT21_FLAG_CF, 1);
    } else {
      set_flag(result, DAZE_DOS_INT21_FLAG_CF, 0);
    }
    return DAZE_DOS_INT21_DISPATCH_OK;
  case 0x4a: {
    DazeDosMemoryResizeResult resize;
    daze_dos_memory_resize(context->dos_memory, request->es, request->bx, &resize);
    if (resize.success) {
      set_flag(result, DAZE_DOS_INT21_FLAG_CF, 0);
    } else {
      result->register_write_mask = DAZE_DOS_INT21_REG_AX | DAZE_DOS_INT21_REG_BX;
      result->ax = resize.dos_error;
      result->bx = resize.maximum_paragraphs;
      set_flag(result, DAZE_DOS_INT21_FLAG_CF, 1);
    }
    return DAZE_DOS_INT21_DISPATCH_OK;
  }
  default: {
    DazeDosAllocationStrategyReply reply;
    if (context->process_state == NULL ||
        !daze_dos_process_state_allocation_strategy(context->process_state, (uint8_t)request->ax,
                                                    request->bx, &reply))
      return DAZE_DOS_INT21_DISPATCH_INVALID_ARGUMENT;
    if ((uint8_t)request->ax == 0 || (uint8_t)request->ax == 2 || reply.carry) {
      result->register_write_mask = DAZE_DOS_INT21_REG_AX;
      result->ax =
        (uint8_t)request->ax == 2 ? (uint16_t)((request->ax & 0xff00u) | reply.ax) : reply.ax;
    }
    set_flag(result, DAZE_DOS_INT21_FLAG_CF, reply.carry);
    return DAZE_DOS_INT21_DISPATCH_OK;
  }
  }
}

static DazeDosInt21DispatchStatus dispatch_country_table(const DazeDosInt21Context *context,
                                                         const DazeDosInt21Request *request,
                                                         DazeDosInt21Result *result) {
  if (context->guest_memory.write == NULL ||
      !context->guest_memory.write(context->guest_memory.context, request->ds, request->dx,
                                   daze_dos_country_usa, DAZE_DOS_COUNTRY_TABLE_SIZE))
    return DAZE_DOS_INT21_DISPATCH_MEMORY_FAILURE;
  result->disposition = DAZE_DOS_INT21_HANDLED;
  result->register_write_mask = DAZE_DOS_INT21_REG_BX;
  result->bx = DAZE_DOS_COUNTRY_CODE_USA;
  set_flag(result, DAZE_DOS_INT21_FLAG_CF, 0);
  return DAZE_DOS_INT21_DISPATCH_OK;
}

static DazeDosInt21DispatchStatus dispatch_dbcs_table(const DazeDosInt21Context *context,
                                                      DazeDosInt21Result *result) {
  static const uint8_t table[] = {0, 0};
  if (context->guest_memory.write == NULL ||
      !context->guest_memory.write(context->guest_memory.context, context->dbcs_table_segment, 0,
                                   table, sizeof(table))) {
    return DAZE_DOS_INT21_DISPATCH_MEMORY_FAILURE;
  }
  result->disposition = DAZE_DOS_INT21_HANDLED;
  result->register_write_mask = DAZE_DOS_INT21_REG_DS | DAZE_DOS_INT21_REG_SI;
  result->ds = context->dbcs_table_segment;
  result->si = 0;
  set_flag(result, DAZE_DOS_INT21_FLAG_CF, 0);
  return DAZE_DOS_INT21_DISPATCH_OK;
}

static DazeDosInt21DispatchStatus dispatch_swappable_data_area(const DazeDosInt21Context *context,
                                                               DazeDosInt21Result *result) {
  static const uint8_t sda[] = {0, 0};
  if (context->guest_memory.write == NULL ||
      !context->guest_memory.write(context->guest_memory.context, context->sda_segment,
                                   context->sda_offset, sda, sizeof(sda)))
    return DAZE_DOS_INT21_DISPATCH_MEMORY_FAILURE;
  result->disposition = DAZE_DOS_INT21_HANDLED;
  result->register_write_mask =
    DAZE_DOS_INT21_REG_CX | DAZE_DOS_INT21_REG_DX | DAZE_DOS_INT21_REG_SI | DAZE_DOS_INT21_REG_DS;
  result->cx = sizeof(sda);
  result->dx = sizeof(sda);
  result->si = context->sda_offset;
  result->ds = context->sda_segment;
  set_flag(result, DAZE_DOS_INT21_FLAG_CF, 0);
  return DAZE_DOS_INT21_DISPATCH_OK;
}

int daze_dos_int21_is_shared_function(uint8_t ah) {
  switch (ah) {
  case DAZE_DOS_CONSOLE_IO:
  case DAZE_DOS_DISPLAY_STRING:
  case DAZE_DOS_KEYBOARD_STATUS:
  case DAZE_DOS_GET_DRIVE:
  case DAZE_DOS_SET_DTA:
  case DAZE_DOS_PARSE_FILENAME:
  case DAZE_DOS_GET_DATE:
  case DAZE_DOS_GET_TIME:
  case DAZE_DOS_GET_VERSION:
  case DAZE_DOS_GET_INDOS:
  case DAZE_DOS_GET_COUNTRY:
  case DAZE_DOS_CREATE:
  case DAZE_DOS_CREATE_TEMP:
  case DAZE_DOS_OPEN:
  case DAZE_DOS_CLOSE:
  case DAZE_DOS_READ:
  case DAZE_DOS_WRITE:
  case DAZE_DOS_DELETE:
  case DAZE_DOS_RENAME:
  case DAZE_DOS_SEEK:
  case DAZE_DOS_FILE_ATTR:
  case DAZE_DOS_IOCTL:
  case DAZE_DOS_FORCE_DUP:
  case DAZE_DOS_GET_DIR:
  case DAZE_DOS_ALLOC:
  case DAZE_DOS_FREE:
  case DAZE_DOS_RESIZE:
  case DAZE_DOS_GET_EXIT_CODE:
  case DAZE_DOS_FIND_FIRST:
  case DAZE_DOS_FIND_NEXT:
  case DAZE_DOS_FILE_TIME:
  case DAZE_DOS_ALLOC_STRATEGY:
  case DAZE_DOS_GET_SDA:
  case DAZE_DOS_GET_DBCS:
  case DAZE_DOS_SET_HANDLE_COUNT:
  case DAZE_DOS_SET_PSP:
  case DAZE_DOS_GET_PSP:
  case DAZE_DOS_GET_PSP_62:
  case DAZE_DOS_GET_DTA:
    return 1;
  default:
    return 0;
  }
}

DazeDosInt21DispatchStatus daze_dos_int21_dispatch(const DazeDosInt21Context *context,
                                                   const DazeDosInt21Request *request,
                                                   DazeDosInt21Result *result) {
  if (result == NULL) return DAZE_DOS_INT21_DISPATCH_INVALID_ARGUMENT;
  begin_result(result);
  if (context == NULL || request == NULL) return DAZE_DOS_INT21_DISPATCH_INVALID_ARGUMENT;

  switch ((uint8_t)(request->ax >> 8)) {
  case DAZE_DOS_GET_DATE: {
    DazeDosDate date;
    (void)daze_dos_date_get(&date);
    result->disposition = DAZE_DOS_INT21_HANDLED;
    result->register_write_mask =
      DAZE_DOS_INT21_REG_AX | DAZE_DOS_INT21_REG_CX | DAZE_DOS_INT21_REG_DX;
    result->ax = (uint16_t)((request->ax & 0xff00u) | date.weekday);
    result->cx = date.year;
    result->dx = (uint16_t)((date.month << 8) | date.day);
    set_flag(result, DAZE_DOS_INT21_FLAG_CF, 0);
    return DAZE_DOS_INT21_DISPATCH_OK;
  }
  case DAZE_DOS_GET_TIME:
    result->disposition = DAZE_DOS_INT21_HANDLED;
    result->register_write_mask = DAZE_DOS_INT21_REG_CX | DAZE_DOS_INT21_REG_DX;
    result->cx = 0;
    result->dx = 0;
    set_flag(result, DAZE_DOS_INT21_FLAG_CF, 0);
    return DAZE_DOS_INT21_DISPATCH_OK;
  case DAZE_DOS_DISPLAY_STRING:
    return dispatch_display_string(context, request, result);
  case DAZE_DOS_GET_VERSION:
    result->disposition = DAZE_DOS_INT21_HANDLED;
    result->register_write_mask =
      DAZE_DOS_INT21_REG_AX | DAZE_DOS_INT21_REG_BX | DAZE_DOS_INT21_REG_CX;
    result->ax = 0x0005;
    result->bx = 0;
    result->cx = 0;
    set_flag(result, DAZE_DOS_INT21_FLAG_CF, 0);
    return DAZE_DOS_INT21_DISPATCH_OK;
  case DAZE_DOS_GET_INDOS: {
    const uint8_t indos = 0;
    if (context->guest_memory.write == NULL ||
        !context->guest_memory.write(context->guest_memory.context, context->indos_segment,
                                     context->indos_offset, &indos, sizeof(indos)))
      return DAZE_DOS_INT21_DISPATCH_MEMORY_FAILURE;
    result->disposition = DAZE_DOS_INT21_HANDLED;
    result->register_write_mask = DAZE_DOS_INT21_REG_BX | DAZE_DOS_INT21_REG_ES;
    result->bx = context->indos_offset;
    result->es = context->indos_segment;
    set_flag(result, DAZE_DOS_INT21_FLAG_CF, 0);
    return DAZE_DOS_INT21_DISPATCH_OK;
  }
  case DAZE_DOS_GET_COUNTRY:
    if ((uint8_t)request->ax != 0) return DAZE_DOS_INT21_DISPATCH_OK;
    return dispatch_country_table(context, request, result);
  case DAZE_DOS_TERMINATE:
  case DAZE_DOS_TSR:
    result->disposition = DAZE_DOS_INT21_TERMINATED;
    result->termination_status = (uint8_t)request->ax;
    return DAZE_DOS_INT21_DISPATCH_OK;
  case DAZE_DOS_EXEC:
    if (request->ax == 0x4b00) result->disposition = DAZE_DOS_INT21_EXEC;
    return DAZE_DOS_INT21_DISPATCH_OK;
  case DAZE_DOS_ALLOC:
  case DAZE_DOS_FREE:
  case DAZE_DOS_RESIZE:
  case DAZE_DOS_ALLOC_STRATEGY:
    return dispatch_memory_service(context, request, result);
  case DAZE_DOS_PARSE_FILENAME:
    return dispatch_fcb_parse(context, request, result);
  case DAZE_DOS_SET_DTA:
    if (context->process_state == NULL) return DAZE_DOS_INT21_DISPATCH_INVALID_ARGUMENT;
    daze_dos_process_state_set_dta(context->process_state, request->ds, request->dx);
    result->disposition = DAZE_DOS_INT21_HANDLED;
    set_flag(result, DAZE_DOS_INT21_FLAG_CF, 0);
    return DAZE_DOS_INT21_DISPATCH_OK;
  case DAZE_DOS_GET_DTA:
    if (context->process_state == NULL) return DAZE_DOS_INT21_DISPATCH_INVALID_ARGUMENT;
    result->disposition = DAZE_DOS_INT21_HANDLED;
    result->register_write_mask = DAZE_DOS_INT21_REG_BX | DAZE_DOS_INT21_REG_ES;
    result->bx = context->process_state->dta_offset;
    result->es = context->process_state->dta_segment;
    set_flag(result, DAZE_DOS_INT21_FLAG_CF, 0);
    return DAZE_DOS_INT21_DISPATCH_OK;
  case DAZE_DOS_KEYBOARD_STATUS:
    result->disposition = DAZE_DOS_INT21_HANDLED;
    result->register_write_mask = DAZE_DOS_INT21_REG_AX;
    result->ax = (uint16_t)(request->ax & 0xff00u);
    set_flag(result, DAZE_DOS_INT21_FLAG_CF, 0);
    return DAZE_DOS_INT21_DISPATCH_OK;
  case DAZE_DOS_CONSOLE_IO:
    if ((uint8_t)request->dx != 0xff) return DAZE_DOS_INT21_DISPATCH_OK;
    result->disposition = DAZE_DOS_INT21_HANDLED;
    result->register_write_mask = DAZE_DOS_INT21_REG_AX;
    result->ax = (uint16_t)(request->ax & 0xff00u);
    set_flag(result, DAZE_DOS_INT21_FLAG_CF, 0);
    set_flag(result, DAZE_DOS_INT21_FLAG_ZF, 1);
    return DAZE_DOS_INT21_DISPATCH_OK;
  case DAZE_DOS_GET_DRIVE:
    if (context->files == NULL || context->files->mounts == NULL)
      return DAZE_DOS_INT21_DISPATCH_INVALID_ARGUMENT;
    result->disposition = DAZE_DOS_INT21_HANDLED;
    result->register_write_mask = DAZE_DOS_INT21_REG_AX;
    result->ax = (uint16_t)((request->ax & 0xff00u) | context->files->mounts->default_drive);
    set_flag(result, DAZE_DOS_INT21_FLAG_CF, 0);
    return DAZE_DOS_INT21_DISPATCH_OK;
  case DAZE_DOS_GET_EXIT_CODE: {
    if (context->process_state == NULL) return DAZE_DOS_INT21_DISPATCH_INVALID_ARGUMENT;
    DazeDosChildStatusReply reply;
    if (!daze_dos_process_state_take_child_status(context->process_state, &reply))
      return DAZE_DOS_INT21_DISPATCH_INVALID_ARGUMENT;
    result->disposition = DAZE_DOS_INT21_HANDLED;
    result->register_write_mask = DAZE_DOS_INT21_REG_AX;
    result->ax = reply.ax;
    set_flag(result, DAZE_DOS_INT21_FLAG_CF, 0);
    return DAZE_DOS_INT21_DISPATCH_OK;
  }
  case DAZE_DOS_SET_PSP:
    if (context->process_state == NULL) return DAZE_DOS_INT21_DISPATCH_INVALID_ARGUMENT;
    result->disposition = DAZE_DOS_INT21_HANDLED;
    context->process_state->psp_segment = request->bx;
    set_flag(result, DAZE_DOS_INT21_FLAG_CF, 0);
    return DAZE_DOS_INT21_DISPATCH_OK;
  case DAZE_DOS_GET_PSP:
  case DAZE_DOS_GET_PSP_62:
    if (context->process_state == NULL) return DAZE_DOS_INT21_DISPATCH_INVALID_ARGUMENT;
    result->disposition = DAZE_DOS_INT21_HANDLED;
    result->register_write_mask = DAZE_DOS_INT21_REG_BX;
    result->bx = context->process_state->psp_segment;
    set_flag(result, DAZE_DOS_INT21_FLAG_CF, 0);
    return DAZE_DOS_INT21_DISPATCH_OK;
  case DAZE_DOS_DELETE:
    return dispatch_delete(context, request, result);
  case DAZE_DOS_RENAME:
    return dispatch_rename(context, request, result);
  case DAZE_DOS_CREATE:
    return dispatch_file_open_create(context, request, result, 1);
  case DAZE_DOS_OPEN:
    return dispatch_file_open_create(context, request, result, 0);
  case DAZE_DOS_CREATE_TEMP:
    return dispatch_file_create_temp(context, request, result);
  case DAZE_DOS_CLOSE:
    return dispatch_file_close(context, request, result);
  case DAZE_DOS_SEEK:
    return dispatch_file_seek(context, request, result);
  case DAZE_DOS_READ:
  case DAZE_DOS_WRITE:
    return dispatch_file_transfer(context, request, result);
  case DAZE_DOS_FILE_ATTR:
    return dispatch_file_attributes(context, request, result);
  case DAZE_DOS_GET_DIR:
    return dispatch_current_directory(context, request, result);
  case DAZE_DOS_FIND_FIRST:
    return dispatch_find_first(context, request, result);
  case DAZE_DOS_FIND_NEXT:
    return dispatch_find_next(context, result);
  case DAZE_DOS_IOCTL: {
    if ((uint8_t)request->ax != 0) return DAZE_DOS_INT21_DISPATCH_OK;
    if (context->files == NULL || context->files->handles == NULL)
      return DAZE_DOS_INT21_DISPATCH_INVALID_ARGUMENT;
    int host_fd = -1;
    const int valid =
      daze_dosfs_handles_get(context->files->handles, request->bx, &host_fd) == DAZE_DOSFS_OK;
    result->disposition = DAZE_DOS_INT21_HANDLED;
    if (valid) {
      result->register_write_mask = DAZE_DOS_INT21_REG_DX;
      result->dx = 0;
      set_flag(result, DAZE_DOS_INT21_FLAG_CF, 0);
    } else {
      result->register_write_mask = DAZE_DOS_INT21_REG_AX;
      result->ax = DAZE_DOS_ERR_INVALID_HANDLE;
      set_flag(result, DAZE_DOS_INT21_FLAG_CF, 1);
    }
    return DAZE_DOS_INT21_DISPATCH_OK;
  }
  case DAZE_DOS_FORCE_DUP: {
    if (context->files == NULL || context->files->handles == NULL)
      return DAZE_DOS_INT21_DISPATCH_INVALID_ARGUMENT;
    int host_errno = 0;
    const DazeDosfsStatus status = daze_dosfs_handles_force_duplicate(
      context->files->handles, request->bx, request->cx, &host_errno);
    result->disposition = DAZE_DOS_INT21_HANDLED;
    result->register_write_mask = DAZE_DOS_INT21_REG_AX;
    if (status == DAZE_DOSFS_OK) {
      result->ax = request->cx;
      set_flag(result, DAZE_DOS_INT21_FLAG_CF, 0);
    } else {
      result->ax = status == DAZE_DOSFS_HOST_ERROR ? daze_dosfs_errno_to_dos_error(host_errno)
                                                   : DAZE_DOS_ERR_INVALID_HANDLE;
      set_flag(result, DAZE_DOS_INT21_FLAG_CF, 1);
    }
    return DAZE_DOS_INT21_DISPATCH_OK;
  }
  case DAZE_DOS_FILE_TIME: {
    const uint8_t operation = (uint8_t)request->ax;
    if (operation > 1) return DAZE_DOS_INT21_DISPATCH_OK;
    if (context->files == NULL || context->files->handles == NULL)
      return DAZE_DOS_INT21_DISPATCH_INVALID_ARGUMENT;
    int host_fd = -1;
    DazeDosFileTimeReply reply;
    if (!daze_dos_file_time_reply(
          daze_dosfs_handles_get(context->files->handles, request->bx, &host_fd) == DAZE_DOSFS_OK,
          &reply))
      return DAZE_DOS_INT21_DISPATCH_INVALID_ARGUMENT;
    result->disposition = DAZE_DOS_INT21_HANDLED;
    if (reply.valid && operation == 0) {
      result->register_write_mask = DAZE_DOS_INT21_REG_CX | DAZE_DOS_INT21_REG_DX;
      result->cx = reply.cx;
      result->dx = reply.dx;
    } else if (!reply.valid) {
      result->register_write_mask = DAZE_DOS_INT21_REG_AX;
      result->ax = reply.error_ax;
    }
    /* 5701h acknowledges a valid handle without storing the requested time
     * or changing host metadata. Reads retain the deterministic DOS date. */
    set_flag(result, DAZE_DOS_INT21_FLAG_CF, reply.carry);
    return DAZE_DOS_INT21_DISPATCH_OK;
  }
  case DAZE_DOS_GET_DBCS:
    if ((uint8_t)request->ax != 0) return DAZE_DOS_INT21_DISPATCH_OK;
    return dispatch_dbcs_table(context, result);
  case DAZE_DOS_GET_SDA:
    if (request->ax != 0x5d06) return DAZE_DOS_INT21_DISPATCH_OK;
    return dispatch_swappable_data_area(context, result);
  case DAZE_DOS_SET_HANDLE_COUNT:
    result->disposition = DAZE_DOS_INT21_HANDLED;
    set_flag(result, DAZE_DOS_INT21_FLAG_CF, request->bx > DAZE_DOSFS_MAX_HANDLES);
    if (request->bx > DAZE_DOSFS_MAX_HANDLES) {
      result->register_write_mask = DAZE_DOS_INT21_REG_AX;
      result->ax = DAZE_DOS_ERR_TOO_MANY_FILES;
    }
    return DAZE_DOS_INT21_DISPATCH_OK;
  default:
    return DAZE_DOS_INT21_DISPATCH_OK;
  }
}
