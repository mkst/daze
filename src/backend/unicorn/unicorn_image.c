#include "unicorn_image.h"

#include <unicorn/unicorn.h>

static int unicorn_memory_write(void *context, uint32_t address, const void *bytes, size_t size) {
  return uc_mem_write(context, address, bytes, size) == UC_ERR_OK;
}

int daze_unicorn_image_write_process(uc_engine *uc, const char *tail, const char *path,
                                     uint16_t psp, uint16_t environment, uint16_t dpmi_entry,
                                     uint16_t dos_vector, const char *const *extra_env,
                                     int extra_env_count) {
  if (uc == NULL) return 0;
  return daze_image_write_process_with_memory(unicorn_memory_write, uc, tail, path, psp,
                                              environment, dpmi_entry, dos_vector, extra_env,
                                              extra_env_count);
}
