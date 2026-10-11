#include "mz_layout.h"

#include "byte_order.h"

int daze_mz_layout_module_size(const uint8_t *bytes, size_t file_size, size_t *module_size) {
  if (bytes == NULL || module_size == NULL || file_size < 0x1c) return 0;
  const uint16_t last_page_bytes = daze_read_u16(bytes + 2);
  const uint16_t pages = daze_read_u16(bytes + 4);
  if (pages == 0 || last_page_bytes > 512) return 0;
  const size_t size =
    last_page_bytes == 0 ? (size_t)pages * 512u : ((size_t)pages - 1u) * 512u + last_page_bytes;
  if (size > file_size) return 0;
  *module_size = size;
  return 1;
}

int daze_mz_parse_header(const uint8_t *bytes, size_t file_size, DazeMzHeader *header) {
  if (bytes == NULL || header == NULL || file_size < 0x1c) return 0;
  if (bytes[0] != 'M' || bytes[1] != 'Z') return 0;
  const uint16_t relocations = daze_read_u16(bytes + 0x06);
  const uint16_t header_paragraphs = daze_read_u16(bytes + 0x08);
  const uint16_t initial_ss = daze_read_u16(bytes + 0x0e);
  const uint16_t initial_sp = daze_read_u16(bytes + 0x10);
  const uint16_t initial_ip = daze_read_u16(bytes + 0x14);
  const uint16_t initial_cs = daze_read_u16(bytes + 0x16);
  const uint16_t relocation_offset = daze_read_u16(bytes + 0x18);
  size_t module_size = 0;
  if (!daze_mz_layout_module_size(bytes, file_size, &module_size)) return 0;
  const size_t image_offset = (size_t)header_paragraphs << 4;
  if (image_offset > module_size) return 0;
  if ((size_t)relocation_offset + (size_t)relocations * 4 > file_size) return 0;
  header->relocations = relocations;
  header->header_paragraphs = header_paragraphs;
  header->initial_ss = initial_ss;
  header->initial_sp = initial_sp;
  header->initial_ip = initial_ip;
  header->initial_cs = initial_cs;
  header->relocation_offset = relocation_offset;
  header->module_size = module_size;
  header->image_offset = image_offset;
  header->image_size = module_size - image_offset;
  return 1;
}

int daze_mz_relocate_image(const uint8_t *file_bytes, size_t file_size, const DazeMzHeader *header,
                           uint16_t load_segment, uint8_t *image_bytes, size_t image_size) {
  if (file_bytes == NULL || header == NULL || image_bytes == NULL ||
      header->image_offset > file_size || header->image_size > file_size - header->image_offset ||
      header->image_size > image_size || header->relocation_offset > file_size ||
      (size_t)header->relocations > (file_size - header->relocation_offset) / 4)
    return 0;
  for (uint16_t index = 0; index < header->relocations; ++index) {
    const uint8_t *entry = file_bytes + header->relocation_offset + (size_t)index * 4;
    const size_t offset = (size_t)daze_read_u16(entry + 2) * 16 + daze_read_u16(entry);
    if (offset > header->image_size || header->image_size - offset < sizeof(uint16_t)) return 0;
    daze_write_u16(image_bytes + offset,
                   (uint16_t)(daze_read_u16(image_bytes + offset) + load_segment));
  }
  return 1;
}
