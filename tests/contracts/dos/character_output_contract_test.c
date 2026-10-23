#define _POSIX_C_SOURCE 200809L
#include "int21_service.h"

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

typedef struct {
  unsigned observed, completed;
} Transfers;

static void observed(void *opaque, const DazeDosInt21Request *request,
                     const DazeDosfsFileResult *file) {
  Transfers *transfers = opaque;
  assert(request->ax >> 8 == 2 || request->ax >> 8 == 6);
  assert(file->success && file->byte_count == 1 && file->host_write_attempted);
  ++transfers->observed;
}

static void completed(void *opaque, const DazeDosInt21Request *request,
                      const DazeDosfsFileResult *file) {
  Transfers *transfers = opaque;
  assert(request->ax >> 8 == 2 || request->ax >> 8 == 6);
  assert(file->success && file->byte_count == 1);
  assert(transfers->observed == transfers->completed + 1);
  ++transfers->completed;
}

static void failed(const DazeDosInt21Context *context, uint16_t ax,
                   DazeDosInt21DispatchStatus status) {
  const DazeDosInt21Request request = {.ax = ax, .dx = 'X', .flags = 0x243};
  DazeDosInt21Result result;
  assert(daze_dos_int21_dispatch(context, &request, &result) == status);
  assert(result.disposition == DAZE_DOS_INT21_UNSUPPORTED);
  assert(result.register_write_mask == 0 && result.flag_write_mask == 0);
}

int main(void) {
  FILE *output = tmpfile();
  assert(output != NULL);
  DazeDosfsHandles handles;
  daze_dosfs_handles_init(&handles);
  assert(daze_dosfs_handles_bind_standard(&handles, STDIN_FILENO, fileno(output), STDERR_FILENO,
                                          NULL) == DAZE_DOSFS_OK);
  DazeDosfsFileService files = {.handles = &handles};
  Transfers transfers = {0};
  DazeDosInt21Context context = {.files = &files,
                                 .transfer_observed = observed,
                                 .transfer_completed = completed,
                                 .transfer_context = &transfers};
  const uint8_t characters[] = {0, 'A', 0xfe};
  for (unsigned function = 2; function <= 6; function += 4) {
    assert(daze_dos_int21_is_shared_function(function));
    for (unsigned flags = 0; flags < 4; ++flags) {
      for (size_t i = 0; i < sizeof(characters); ++i) {
        const DazeDosInt21Request request = {
          .ax = (uint16_t)(function << 8 | 0xb7),
          .dx = (uint16_t)(0xab00 | characters[i]),
          .flags = (uint16_t)(0xa02 | (flags & 1) | ((flags & 2) << 5))};
        DazeDosInt21Result result;
        assert(daze_dos_int21_dispatch(&context, &request, &result) == DAZE_DOS_INT21_DISPATCH_OK);
        assert(result.disposition == DAZE_DOS_INT21_HANDLED);
        assert(result.register_write_mask == DAZE_DOS_INT21_REG_AX);
        assert(result.ax == (uint16_t)(function << 8 | characters[i]));
        assert(result.flag_write_mask == (function == 2 ? 0 : 0x41));
        assert(result.flag_values == 0);
      }
    }
  }
  assert(transfers.observed == 24 && transfers.completed == 24);
  rewind(output);
  for (unsigned i = 0; i < 24; ++i)
    assert(fgetc(output) == characters[i % 3]);
  assert(fgetc(output) == EOF);

  DazeDosInt21Request poll = {.ax = 0x06b7, .dx = 0xabff, .flags = 0xa03};
  DazeDosInt21Result result;
  assert(daze_dos_int21_dispatch(&context, &poll, &result) == DAZE_DOS_INT21_DISPATCH_OK);
  assert(result.ax == 0x0600 && result.register_write_mask == DAZE_DOS_INT21_REG_AX);
  assert(result.flag_write_mask == 0x41 && result.flag_values == 0x40);
  assert(transfers.observed == 24 && transfers.completed == 24);

  assert(daze_dosfs_handles_close(&handles, 1, NULL) == DAZE_DOSFS_OK);
  for (unsigned function = 2; function <= 6; function += 4) {
    failed(&context, function << 8, DAZE_DOS_INT21_DISPATCH_IO_FAILURE);
    DazeDosInt21Context missing = context;
    missing.files = NULL;
    failed(&missing, function << 8, DAZE_DOS_INT21_DISPATCH_INVALID_ARGUMENT);
    files.handles = NULL;
    failed(&context, function << 8, DAZE_DOS_INT21_DISPATCH_INVALID_ARGUMENT);
    files.handles = &handles;
  }
  /* Polling never needs an output handle. */
  assert(daze_dos_int21_dispatch(&context, &poll, &result) == DAZE_DOS_INT21_DISPATCH_OK);
  assert(result.ax == 0x0600 && result.flag_values == 0x40);
  int readonly = open("/dev/null", O_RDONLY);
  assert(readonly >= 0);
  daze_dosfs_handles_close_all(&handles);
  assert(daze_dosfs_handles_bind_standard(&handles, STDIN_FILENO, readonly, STDERR_FILENO, NULL) ==
         DAZE_DOSFS_OK);
  assert(close(readonly) == 0);
  failed(&context, 0x0200, DAZE_DOS_INT21_DISPATCH_IO_FAILURE);
  failed(&context, 0x0600, DAZE_DOS_INT21_DISPATCH_IO_FAILURE);
  assert(transfers.observed == 24 && transfers.completed == 24);
  daze_dosfs_handles_close_all(&handles);
  assert(fclose(output) == 0);
  return 0;
}
