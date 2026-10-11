#ifndef DAZE_RUNTIME_IMAGE_H
#define DAZE_RUNTIME_IMAGE_H

#include <stddef.h>
#include <stdint.h>

enum { DAZE_PROCESS_ENV_MAX_EXTRA_VARS = 32 };

typedef struct {
  uint8_t *bytes;
  size_t size;
} DazeImage;

typedef int (*DazeImageMemoryWrite)(void *context, uint32_t address, const void *bytes,
                                    size_t size);

int daze_image_load(const char *path, DazeImage *image);
void daze_image_free(DazeImage *image);
/* Environment entries replace matching names, including defaults; the last value wins. */
int daze_image_write_process_with_memory(DazeImageMemoryWrite write, void *context,
                                         const char *tail, const char *path, uint16_t psp,
                                         uint16_t environment, uint16_t dpmi_entry,
                                         uint16_t dos_vector, const char *const *extra_env,
                                         int extra_env_count);
#endif
