#ifndef DAZE_DOS_EXEC_IMAGE_H
#define DAZE_DOS_EXEC_IMAGE_H

#include <stddef.h>
#include <stdint.h>

#include "image.h"
#include "mz_layout.h"

/* Copies an already-parsed MZ load module and applies its relocation entries
 * for load_segment. The caller owns *prepared_bytes and releases it with
 * free(). guest_size bounds the target physical address range. */
int daze_dos_exec_image_prepare(const DazeImage *image, const DazeMzHeader *header,
                                uint16_t load_segment, size_t guest_size, uint8_t **prepared_bytes,
                                size_t *prepared_size);

#endif
