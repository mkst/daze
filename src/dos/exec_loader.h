#ifndef DAZE_DOS_EXEC_LOADER_H
#define DAZE_DOS_EXEC_LOADER_H

#include "dosfs.h"
#include "image.h"

/* The caller supplies an empty image and owns the successful load. With valid
 * output pointers, failure leaves an empty image and reports the host error,
 * or EINVAL for invalid arguments and rejected DOS paths. */
int daze_dos_exec_load_mounted(const DazeDosfsMounts *mounts, const char *path, DazeImage *image,
                               int *host_errno);

#endif
