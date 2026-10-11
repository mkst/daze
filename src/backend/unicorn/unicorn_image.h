#ifndef DAZE_UNICORN_IMAGE_H
#define DAZE_UNICORN_IMAGE_H

#include "image.h"

#include <unicorn/unicorn.h>

int daze_unicorn_image_write_process(uc_engine *uc, const char *tail, const char *path,
                                     uint16_t psp, uint16_t environment, uint16_t dpmi_entry,
                                     uint16_t dos_vector, const char *const *extra_env,
                                     int extra_env_count);

#endif
