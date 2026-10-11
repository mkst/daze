#include "exec_image.h"

#include <stdlib.h>
#include <string.h>

int daze_dos_exec_image_prepare(const DazeImage *image, const DazeMzHeader *header,
                                uint16_t load_segment, size_t guest_size, uint8_t **prepared_bytes,
                                size_t *prepared_size) {
  if (image == NULL || header == NULL || prepared_bytes == NULL || prepared_size == NULL ||
      image->bytes == NULL || header->image_offset > image->size ||
      header->image_size > image->size - header->image_offset ||
      header->relocation_offset > image->size ||
      (size_t)header->relocations > (image->size - header->relocation_offset) / 4) {
    return 0;
  }
  const size_t address = (size_t)load_segment << 4;
  if (address > guest_size || header->image_size > guest_size - address) return 0;
  uint8_t *prepared = malloc(header->image_size == 0 ? 1 : header->image_size);
  if (prepared == NULL) return 0;
  memcpy(prepared, image->bytes + header->image_offset, header->image_size);
  if (!daze_mz_relocate_image(image->bytes, image->size, header, load_segment, prepared,
                              header->image_size)) {
    free(prepared);
    return 0;
  }
  *prepared_bytes = prepared;
  *prepared_size = header->image_size;
  return 1;
}
