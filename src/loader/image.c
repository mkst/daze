#include "image.h"
#include "interrupt_vector.h"
#include "mz_layout.h"
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int daze_image_load(const char *path, DazeImage *image) {
  FILE *f = fopen(path, "rb");
  if (!f || fseek(f, 0, SEEK_END) || (image->size = (size_t)ftell(f), fseek(f, 0, SEEK_SET))) {
    if (f) fclose(f);
    return 0;
  }
  image->bytes = malloc(image->size);
  if (!image->bytes || fread(image->bytes, 1, image->size, f) != image->size) {
    free(image->bytes);
    image->bytes = NULL;
    fclose(f);
    return 0;
  }
  fclose(f);
  return 1;
}
void daze_image_free(DazeImage *image) {
  free(image->bytes);
  image->bytes = NULL;
  image->size = 0;
}

int daze_image_write_process_with_memory(DazeImageMemoryWrite write, void *context,
                                         const char *tail, const char *path, uint16_t psp_segment,
                                         uint16_t env_segment, uint16_t dpmi_segment,
                                         uint16_t dos_segment, const char *const *extra_env,
                                         int extra_env_count) {
  uint8_t psp[256] = {0};
  uint8_t env[512];
  if (write == NULL || tail == NULL || path == NULL) return 0;
  if (extra_env_count < 0 || extra_env_count > DAZE_PROCESS_ENV_MAX_EXTRA_VARS) return 0;
  if (extra_env_count > 0 && extra_env == NULL) return 0;
  size_t n = strlen(tail);
  if (n > 126) return 0;
  psp[0] = 0xcd;
  psp[1] = DAZE_INT_TERMINATE;
  psp[2] = 0xff;
  psp[3] = 0x9f;
  for (size_t i = 0x0a; i <= 0x12; i += 4) {
    psp[i] = 0x10;
    psp[i + 2] = (uint8_t)dos_segment;
    psp[i + 3] = (uint8_t)(dos_segment >> 8);
  }
  /* The direct launcher has no COMMAND.COM parent. */
  psp[0x16] = 0;
  psp[0x17] = 0;
  memset(psp + 0x18, 0xff, 20);
  for (uint8_t i = 0; i < 5; i++)
    psp[0x18 + i] = i;
  psp[0x2c] = (uint8_t)env_segment;
  psp[0x2d] = (uint8_t)(env_segment >> 8);
  psp[0x32] = 20;
  psp[0x34] = 0x18;
  psp[0x36] = (uint8_t)psp_segment;
  psp[0x37] = (uint8_t)(psp_segment >> 8);
  memset(psp + 0x38, 0xff, 4);
  psp[0x50] = 0xcd;
  psp[0x51] = DAZE_INT_DOS;
  psp[0x52] = 0xcb;
  psp[0x80] = (uint8_t)n;
  memcpy(psp + 0x81, tail, n);
  psp[0x81 + n] = '\r';
  size_t e = 0;
  const char *variables[3 + DAZE_PROCESS_ENV_MAX_EXTRA_VARS] = {"PATH=C:\\", "TEMP=C:\\TMP",
                                                                "TMP=C:\\TMP"};
  size_t variable_count = 3;
  for (int i = 0; i < extra_env_count; ++i) {
    const char *var = extra_env[i];
    if (var == NULL) return 0;
    const char *equals = strchr(var, '=');
    if (equals == NULL || equals == var) return 0;
    const size_t name_size = (size_t)(equals - var) + 1;
    size_t index = 0;
    while (index < variable_count && strncmp(variables[index], var, name_size) != 0)
      ++index;
    variables[index] = var;
    if (index == variable_count) ++variable_count;
  }
  const char *program_name = path;
  char drive_letter = 'C';
  if (program_name[0] != '\0' && program_name[1] == ':') {
    drive_letter = (char)toupper((unsigned char)program_name[0]);
    program_name += 2;
  }
  const size_t program_length = strlen(program_name);
  if (program_length > sizeof(env) - e - 7) return 0;
  const size_t variables_end = sizeof(env) - program_length - 7;
  for (size_t i = 0; i < variable_count; ++i) {
    const char *var = variables[i];
    const size_t len = strlen(var);
    if (len == 0 || len >= variables_end - e) return 0;
    memcpy(env + e, var, len);
    e += len;
    env[e++] = 0;
  }
  env[e++] = 0;
  env[e++] = 1;
  env[e++] = 0;
  env[e++] = (uint8_t)drive_letter;
  env[e++] = ':';
  env[e++] = '\\';
  for (; *program_name; ++program_name) {
    env[e++] = *program_name == '/' ? '\\' : (uint8_t)*program_name;
  }
  env[e++] = 0;
  const uint8_t dpmi[] = {0xcd, DAZE_INT_DPMI_ENTRY, 0xf4 /* int 0xfe; hlt */},
                dos[] = {0xcd, DAZE_INT_DOS_PROXY, 0xcf /* int 0xfd; iret */},
                iret[] = {0xcf /* iret */};
  return write(context, (uint32_t)psp_segment << 4, psp, sizeof(psp)) &&
         write(context, (uint32_t)env_segment << 4, env, e) &&
         write(context, (uint32_t)dpmi_segment << 4, dpmi, sizeof(dpmi)) &&
         write(context, (uint32_t)dos_segment << 4, dos, sizeof(dos)) &&
         write(context, ((uint32_t)dos_segment << 4) + 0x10, iret, sizeof(iret));
}
