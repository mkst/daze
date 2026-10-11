#include "mz_layout.h"

#include <stdio.h>
#include <string.h>

static int place_u16(uint8_t *bytes, size_t offset, uint16_t value) {
  bytes[offset] = (uint8_t)value;
  bytes[offset + 1] = (uint8_t)(value >> 8);
  return 1;
}

static int expect_module_size(const uint16_t pages, const uint16_t last_page_bytes,
                              const size_t file_size, size_t *result) {
  uint8_t header[0x1c];
  memset(header, 0, sizeof(header));
  place_u16(header, 2, last_page_bytes);
  place_u16(header, 4, pages);
  return daze_mz_layout_module_size(header, file_size, result);
}

/* Builds a complete fixed MZ header so the parser can be exercised without a
 * real image. file_size must be >= 0x1c. */
static int build_mz_header(uint8_t *header, size_t file_size, const uint16_t pages,
                           const uint16_t last_page_bytes, const uint16_t header_paragraphs,
                           const uint16_t relocations, const uint16_t relocation_offset,
                           const uint16_t ss, const uint16_t sp, const uint16_t ip,
                           const uint16_t cs) {
  if (file_size < 0x1c) return 0;
  memset(header, 0, file_size);
  header[0] = 'M';
  header[1] = 'Z';
  place_u16(header, 2, last_page_bytes);
  place_u16(header, 4, pages);
  place_u16(header, 0x06, relocations);
  place_u16(header, 0x08, header_paragraphs);
  place_u16(header, 0x0e, ss);
  place_u16(header, 0x10, sp);
  place_u16(header, 0x14, ip);
  place_u16(header, 0x16, cs);
  place_u16(header, 0x18, relocation_offset);
  return 1;
}

static int malformed_headers(void) {
  uint8_t bytes[64];
  build_mz_header(bytes, sizeof(bytes), 1, 64, 2, 0, 0x1c, 0, 0, 0, 0);
  for (size_t size = 0; size < 0x1c; ++size) {
    DazeMzHeader output;
    memset(&output, 0xa5, sizeof(output));
    const DazeMzHeader before = output;
    if (daze_mz_parse_header(bytes, size, &output) || memcmp(&output, &before, sizeof(output)) != 0)
      return 0;
  }
  const struct {
    size_t offset;
    uint16_t value;
  } cases[] = {
    {0, 0x584d}, {2, 513}, {4, 0}, {4, 2}, {8, 5}, {6, UINT16_MAX}, {0x18, UINT16_MAX},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
    build_mz_header(bytes, sizeof(bytes), 1, 64, 2, 0, 0x1c, 0, 0, 0, 0);
    place_u16(bytes, cases[i].offset, cases[i].value);
    DazeMzHeader output;
    memset(&output, 0xa5, sizeof(output));
    const DazeMzHeader before = output;
    if (daze_mz_parse_header(bytes, sizeof(bytes), &output) ||
        memcmp(&output, &before, sizeof(output)) != 0)
      return 0;
  }
  return 1;
}

static int relocation_rejections(void) {
  uint8_t file[64] = {0};
  uint8_t image[16];
  memset(image, 0xa5, sizeof(image));
  uint8_t before[sizeof(image)];
  memcpy(before, image, sizeof(image));
  const DazeMzHeader invalid[] = {
    {.image_offset = 65},
    {.image_offset = 60, .image_size = 5},
    {.image_offset = 32, .image_size = 17},
    {.relocation_offset = 65},
    {.relocation_offset = 63, .relocations = 1},
    {.relocation_offset = 28, .relocations = UINT16_MAX},
  };
  for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
    if (daze_mz_relocate_image(file, sizeof(file), &invalid[i], 0x3010, image, sizeof(image)) ||
        memcmp(image, before, sizeof(image)) != 0)
      return 0;
  }
  const DazeMzHeader header = {
    .image_offset = 32, .image_size = 16, .relocation_offset = 28, .relocations = 1};
  const uint16_t offsets[] = {15, 16, 17, UINT16_MAX};
  for (size_t i = 0; i < sizeof(offsets) / sizeof(offsets[0]); ++i) {
    place_u16(file, 28, offsets[i]);
    if (daze_mz_relocate_image(file, sizeof(file), &header, 0x3010, image, sizeof(image)) ||
        memcmp(image, before, sizeof(image)) != 0)
      return 0;
  }
  place_u16(file, 28, 0);
  place_u16(file, 30, UINT16_MAX);
  if (daze_mz_relocate_image(file, sizeof(file), &header, 0x3010, image, sizeof(image)) ||
      memcmp(image, before, sizeof(image)) != 0)
    return 0;
  if (daze_mz_relocate_image(NULL, sizeof(file), &header, 0x3010, image, sizeof(image)) ||
      daze_mz_relocate_image(file, sizeof(file), NULL, 0x3010, image, sizeof(image)) ||
      daze_mz_relocate_image(file, sizeof(file), &header, 0x3010, NULL, sizeof(image)))
    return 0;
  place_u16(file, 28, 14);
  place_u16(file, 30, 0);
  return daze_mz_relocate_image(file, sizeof(file), &header, 1, image, sizeof(image)) &&
         image[14] == 0xa6 && image[15] == 0xa5 && memcmp(image, before, 14) == 0;
}

int main(void) {
  size_t actual_size = 0;
  DazeMzHeader mh;
  uint8_t header[0x400];
  uint8_t relocation_file[64] = {0};
  uint8_t relocation_image[16] = {0};
  const DazeMzHeader relocation_header = {
    .relocations = 1, .relocation_offset = 0x1c, .image_offset = 0x20, .image_size = 16};
  place_u16(relocation_file, 0x1c, 4);
  place_u16(relocation_file, 0x1e, 0);
  place_u16(relocation_image, 4, 0x1234);

  const int pass =
    malformed_headers() && relocation_rejections() &&
    /* e_cblp == 0 describes a complete final 512-byte page. */
    expect_module_size(14, 0, 1065236, &actual_size) && actual_size == 7168 &&
    /* Appended GO32 payload must not grow the declared DOS module. */
    expect_module_size(14, 0, 7168, &actual_size) && actual_size == 7168 &&
    expect_module_size(2, 123, 635, &actual_size) && actual_size == 635 &&
    !expect_module_size(0, 0, 512, &actual_size) &&
    !expect_module_size(1, 513, 1024, &actual_size) &&
    !expect_module_size(14, 0, 7167, &actual_size) &&
    !daze_mz_layout_module_size(NULL, 0, &actual_size) &&
    !daze_mz_layout_module_size((const uint8_t[0x1b]){0}, 0x1b, &actual_size) &&
    !expect_module_size(1, 1, 512, NULL) &&

    build_mz_header(header, 660, 2, 123, 0x14, 2, 0x1c, 0x1234, 0x2000, 0x0100, 0x1f00) &&
    daze_mz_parse_header(header, 660, &mh) && mh.module_size == 635 && mh.image_offset == 0x140 &&
    mh.image_size == 315 && mh.header_paragraphs == 0x14 && mh.relocations == 2 &&
    mh.relocation_offset == 0x1c && mh.initial_ss == 0x1234 && mh.initial_sp == 0x2000 &&
    mh.initial_ip == 0x0100 && mh.initial_cs == 0x1f00 && !daze_mz_parse_header(header, 634, &mh) &&
    build_mz_header(header, 660, 2, 123, 0x30, 0, 0x1c, 0, 0, 0, 0) &&
    !daze_mz_parse_header(header, 660, &mh) &&
    build_mz_header(header, 512, 1, 0, 1, 0x100, 0x1c, 0, 0, 0, 0) &&
    !daze_mz_parse_header(header, 512, &mh) && !daze_mz_parse_header(NULL, 660, &mh) &&
    !daze_mz_parse_header((const uint8_t[0x1b]){0}, 0x1b, &mh) &&
    !daze_mz_parse_header((const uint8_t[0x1c]){'X', 'Z'}, 0x1c, &mh) &&
    !daze_mz_parse_header(header, 660, NULL) &&
    /* Relocations use image-relative segment:offset values and never escape
       the declared load-module extent. */
    daze_mz_relocate_image(relocation_file, sizeof(relocation_file), &relocation_header, 0x3010,
                           relocation_image, sizeof(relocation_image)) &&
    relocation_image[4] == 0x44 && relocation_image[5] == 0x42 &&
    !daze_mz_relocate_image(relocation_file, sizeof(relocation_file), &relocation_header, 0x3010,
                            relocation_image, sizeof(relocation_image) - 1) &&
    !daze_mz_relocate_image(relocation_file, 0x1f, &relocation_header, 0x3010, relocation_image,
                            sizeof(relocation_image));

  place_u16(relocation_file, 0x1c, 15);
  const int relocation_bounds =
    !daze_mz_relocate_image(relocation_file, sizeof(relocation_file), &relocation_header, 0x3010,
                            relocation_image, sizeof(relocation_image));

  fprintf(stderr, "MZ layout contract test: %s\n", pass && relocation_bounds ? "passed" : "failed");
  return pass && relocation_bounds ? 0 : 1;
}
