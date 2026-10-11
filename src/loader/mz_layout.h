#ifndef DAZE_RUNTIME_MZ_LAYOUT_H
#define DAZE_RUNTIME_MZ_LAYOUT_H

#include <stddef.h>
#include <stdint.h>

/* Appended executable data is not part of the DOS-resident MZ module. */
int daze_mz_layout_module_size(const uint8_t *bytes, size_t file_size, size_t *module_size);

/* Fixed MZ executive header fields plus the load-module extent derived from
 * them. Field offsets follow the DOS MZ layout (e_crlc at 0x06 and so on). */
typedef struct {
  uint16_t relocations;       /* e_crlc    */
  uint16_t header_paragraphs; /* e_cparhdr */
  uint16_t initial_ss;        /* e_ss      */
  uint16_t initial_sp;        /* e_sp      */
  uint16_t initial_ip;        /* e_ip      */
  uint16_t initial_cs;        /* e_cs      */
  uint16_t relocation_offset; /* e_lfarlc  */
  size_t module_size;         /* e_cp/e_cblp derived extent */
  size_t image_offset;        /* header_paragraphs << 4 */
  size_t image_size;          /* module_size - image_offset */
} DazeMzHeader;

/* Invalid headers, module bounds, or relocation tables leave *header unchanged. */
int daze_mz_parse_header(const uint8_t *bytes, size_t file_size, DazeMzHeader *header);

/* Applies the relocation table from an already-parsed MZ file to its copied
 * load module. The caller retains file/image storage and all guest placement
 * policy. Returns 0 unless the image and relocation table fit their supplied
 * buffers and every relocation word lies within the load module. */
int daze_mz_relocate_image(const uint8_t *file_bytes, size_t file_size, const DazeMzHeader *header,
                           uint16_t load_segment, uint8_t *image_bytes, size_t image_size);

#endif
