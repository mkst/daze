#include "byte_order.h"
#include "machine.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef DAZE_HAS_UNICORN
#define DAZE_HAS_UNICORN 0
#endif

static int write_mz(const char *directory, const char *name, const uint8_t *code, size_t size,
                    int bad_relocation) {
  char path[256];
  snprintf(path, sizeof(path), "%s/%s", directory, name);
  uint8_t header[32] = {0};
  const size_t total = sizeof(header) + size;
  daze_write_u16(header, 0x5a4d);
  daze_write_u16(header + 2, (uint16_t)(total % 512));
  daze_write_u16(header + 4, (uint16_t)((total + 511) / 512));
  daze_write_u16(header + 6, bad_relocation ? 1 : 0);
  daze_write_u16(header + 8, 2);
  daze_write_u16(header + 16, 0xfffe);
  daze_write_u16(header + 24, 28);
  daze_write_u16(header + 28, (uint16_t)size);
  FILE *file = fopen(path, "wb");
  if (file == NULL) return 0;
  const int pass = fwrite(header, 1, sizeof(header), file) == sizeof(header) &&
                   fwrite(code, 1, size, file) == size;
  return fclose(file) == 0 && pass;
}

static int run(const char *runner, const char *backend, const char *directory, const char *name,
               int expected) {
  const pid_t child = fork();
  if (child == 0) {
    execl(runner, runner, "--backend", backend, "--mount", directory, name, (char *)NULL);
    _exit(127);
  }
  if (child < 0) return 0;
  int status;
  pid_t waited;
  do {
    waited = waitpid(child, &status, 0);
  } while (waited < 0 && errno == EINTR);
  const int pass = waited == child && WIFEXITED(status) && WEXITSTATUS(status) == expected;
  if (!pass)
    fprintf(stderr, "%s/%s: wait status %d, expected exit %d\n", backend, name, status, expected);
  return pass;
}

static int exec_case(const char *runner, const char *directory, int failed_children) {
  uint8_t image[0x1d0] = {0};
  const uint8_t prefix[] = {
    0x0e, 0x1f, 0x0e, 0x07, /* push cs; pop ds; push cs; pop es (DS=ES=CS) */
    0x8c, 0xc8,             /* mov ax,cs */
    0xa3, 0x84, 0x01,       /* mov [0184h],ax */
    0xa3, 0x88, 0x01,       /* mov [0188h],ax */
    0xa3, 0x8c, 0x01,       /* mov [018ch],ax */
    0xbd, 0xa0, 0x00        /* mov bp,0xa0 (160 EXEC calls exceed the allocation table) */
  };
  memcpy(image, prefix, sizeof(prefix));
  size_t cursor = sizeof(prefix);
  const size_t loop = cursor;
  const uint8_t exec[] = {
    0xba, 0x00, 0x01, /* mov dx,1 */
    0xbb, 0x80, 0x01, /* mov bx,0x180 */
    0xb8, 0x00, 0x4b, /* mov ax,0x4b00 */
    0xcd, 0x21,       /* int 0x21 */
  };
  memcpy(image + cursor, exec, sizeof(exec));
  cursor += sizeof(exec);
  image[cursor++] = failed_children ? 0x73 : 0x72;
  const size_t first_failure = cursor++;
  image[cursor++] = 0x4d;
  image[cursor++] = 0x75;
  image[cursor] = (uint8_t)(loop - (cursor + 1));
  cursor++;
  memcpy(image + cursor, exec, sizeof(exec));
  image[cursor + 1] = 0x10;
  cursor += sizeof(exec);
  image[cursor++] = 0x72;
  const size_t final_failure = cursor++;
  const uint8_t success[] = {
    0xb8, 0x25, 0x4c, /* mov ax,0x4c25 */
    0xcd, 0x21,       /* int 0x21 */
  };
  memcpy(image + cursor, success, sizeof(success));
  cursor += sizeof(success);
  image[first_failure] = (uint8_t)(cursor - first_failure - 1);
  image[final_failure] = (uint8_t)(cursor - final_failure - 1);
  const uint8_t failure[] = {
    0xb8, 0x63, 0x4c, /* mov ax,0x4c63 */
    0xcd, 0x21,       /* int 0x21 */
  };
  memcpy(image + cursor, failure, sizeof(failure));
  strcpy((char *)image + 0x100, failed_children ? "BAD.EXE" : "GOOD.EXE");
  strcpy((char *)image + 0x110, "GOOD.EXE");
  daze_write_u16(image + 0x182, 0x1a0);
  daze_write_u16(image + 0x186, 0x1b0);
  daze_write_u16(image + 0x18a, 0x1c0);
  return write_mz(directory, "PARENT.EXE", image, sizeof(image), 0) &&
         run(runner, "unicorn", directory, "PARENT.EXE", 37);
}

int main(int argc, char **argv) {
  if (argc != 3) return 2;
  if (strcmp(argv[2], "kvm") == 0 || (strcmp(argv[2], "auto") == 0 && !DAZE_HAS_UNICORN)) {
    DazeKvmMachine machine;
    const int status = daze_kvm_machine_init(&machine, 0x10000);
    if (status != DAZE_KVM_MACHINE_OK) return status == DAZE_KVM_MACHINE_UNAVAILABLE ? 77 : 1;
    daze_kvm_machine_destroy(&machine);
  }
  char directory[] = "/tmp/daze-launch-regression-XXXXXX";
  if (mkdtemp(directory) == NULL) return 1;
  const uint8_t exit_code[] = {
    0xb8, 0x07, 0x4c, /* mov ax,0x4c07 */
    0xcd, 0x21,       /* int 0x21 */
  };
  uint8_t bad[0x1000] = {0};
  memcpy(bad, exit_code, sizeof(exit_code));
  const int auto_kvm_only = strcmp(argv[2], "auto") == 0 && !DAZE_HAS_UNICORN;
  int pass =
    write_mz(directory, "BAD.EXE", bad, sizeof(bad), 1) &&
    write_mz(directory, "GOOD.EXE", exit_code, sizeof(exit_code), 0) &&
    run(argv[1], argv[2], directory, auto_kvm_only ? "GOOD.EXE" : "BAD.EXE", auto_kvm_only ? 7 : 3);
  if (strcmp(argv[2], "unicorn") == 0) {
    pass &= exec_case(argv[1], directory, 0);
    pass &= exec_case(argv[1], directory, 1);
  }
  const char *names[] = {"BAD.EXE", "GOOD.EXE", "PARENT.EXE", "TMP"};
  for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
    char path[256];
    snprintf(path, sizeof(path), "%s/%s", directory, names[i]);
    if (i == 3)
      rmdir(path);
    else
      unlink(path);
  }
  rmdir(directory);
  return pass ? 0 : 1;
}
