#include "byte_order.h"
#include "machine.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/* Procedure calls yield through both entry and return continuations.
 * The real-mode RETF uses a supplied stack, as GO32 does. */
static const uint8_t procedure_guest[124] = {
  0x0e,                               /* push cs */
  0x1f,                               /* pop ds */
  0x8c, 0xc8,                         /* mov ax,cs */
  0xa3, 0x76, 0x00,                   /* mov [0076h],ax */
  0xb8, 0x45, 0x00,                   /* mov ax,0x45 */
  0xa3, 0x74, 0x00,                   /* mov [0074h],ax */
  0xc7, 0x06, 0x7a, 0x00, 0x40, 0x00, /* mov word [007ah],0x40 */
  0xc7, 0x06, 0x78, 0x00, 0xe0, 0x0b, /* mov word [0078h],0xbe0 */
  0xb8, 0x87, 0x16,                   /* mov ax,0x1687 */
  0xcd, 0x2f,                         /* int 0x2f */
  0x89, 0x3e, 0x46, 0x00,             /* mov [0046h],di */
  0x8c, 0x06, 0x48, 0x00,             /* mov [0048h],es */
  0x31, 0xc0,                         /* xor ax,ax */
  0xff, 0x1e, 0x46, 0x00,             /* call far [0046h] */
  0x1e,                               /* push ds */
  0x07,                               /* pop es */
  0xbd, 0x20, 0x4e,                   /* mov bp,0x4e20 */
  0x31, 0xdb,                         /* xor bx,bx */
  0x31, 0xc9,                         /* xor cx,cx */
  0xbf, 0x4a, 0x00,                   /* mov di,0x4a */
  0xb8, 0x01, 0x03,                   /* mov ax,0x301 */
  0xcd, 0x31,                         /* int 0x31 */
  0x4d,                               /* dec bp */
  0x75, 0xf1,                         /* jne -0x0f */
  0xb8, 0x25, 0x4c,                   /* mov ax,0x4c25 */
  0xcd, 0x21,                         /* int 0x21 */
  0xcb,                               /* lret */
};

/* This caller stays in the mediator long enough to fill the initial bounded
 * observation record before the dispatcher takes ownership. */
static const uint8_t virtual_interrupt_guest[] = {
  0x0e,                   /* push cs */
  0x1f,                   /* pop ds */
  0xb8, 0x87, 0x16,       /* mov ax,0x1687 */
  0xcd, 0x2f,             /* int 0x2f */
  0x89, 0x3e, 0x25, 0x00, /* mov [0025h],di */
  0x8c, 0x06, 0x27, 0x00, /* mov [0027h],es */
  0x31, 0xc0,             /* xor ax,ax */
  0xff, 0x1e, 0x25, 0x00, /* call far [0025h] */
  0xbd, 0x20, 0x4e,       /* mov bp,0x4e20 */
  0xb8, 0x00, 0x09,       /* mov ax,0x900 */
  0xcd, 0x31,             /* int 0x31 */
  0x4d,                   /* dec bp */
  0x75, 0xf8,             /* jne -0x08 */
  0xb8, 0x25, 0x4c,       /* mov ax,0x4c25 */
  0xcd, 0x21,             /* int 0x21 */
  0x00, 0x00, 0x00, 0x00,
};

static const uint8_t real_mode_guest[] = {
  0xbd, 0x20, 0x4e, /* mov bp,0x4e20 */
  0xb4, 0x2c,       /* mov ah,0x2c */
  0xcd, 0x21,       /* int 0x21 */
  0x4d,             /* dec bp */
  0x75, 0xf9,       /* jne -0x07 */
  0xb8, 0x25, 0x4c, /* mov ax,0x4c25 */
  0xcd, 0x21,       /* int 0x21 */
};

static int run_case(const char *runner, const char *backend, const uint8_t *code, size_t size) {
  char directory[] = "/tmp/daze-continuation-XXXXXX";
  char path[256];
  if (mkdtemp(directory) == NULL) return 1;
  snprintf(path, sizeof(path), "%s/TOOL.EXE", directory);
  uint8_t header[32] = {0};
  const uint16_t module_size = (uint16_t)(sizeof(header) + size);
  daze_write_u16(header, 0x5a4d);
  daze_write_u16(header + 2, module_size);
  daze_write_u16(header + 4, 1);
  daze_write_u16(header + 8, 2);
  daze_write_u16(header + 10, 0x1000);
  daze_write_u16(header + 12, 0xffff);
  daze_write_u16(header + 16, 0xfffe);
  daze_write_u16(header + 24, 0x1c);
  FILE *file = fopen(path, "wb");
  int failed = file == NULL;
  if (file != NULL) {
    failed = fwrite(header, 1, sizeof(header), file) != sizeof(header) ||
             fwrite(code, 1, size, file) != size;
    if (fclose(file) != 0) failed = 1;
  }
  if (!failed) {
    const pid_t child = fork();
    if (child == 0) {
      execl(runner, runner, "--backend", backend, "--mount", directory, "TOOL.EXE", (char *)NULL);
      _exit(127);
    }
    int status = 0;
    pid_t waited = -1;
    if (child > 0) {
      do {
        waited = waitpid(child, &status, 0);
      } while (waited < 0 && errno == EINTR);
    }
    /* A nonzero DOS status proves completion rather than a default success. */
    failed = waited != child || child < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 37;
    if (failed)
      fprintf(stderr, "%s continuation guest failed: wait=%ld status=%d\n", backend, (long)waited,
              status);
  }
  unlink(path);
  rmdir(directory);
  return failed;
}

int main(int argc, char **argv) {
  if (argc != 3) return 2;
  if (strcmp(argv[2], "kvm") == 0) {
    DazeKvmMachine machine;
    const int status = daze_kvm_machine_init(&machine, 0x10000);
    if (status != DAZE_KVM_MACHINE_OK) return status == DAZE_KVM_MACHINE_UNAVAILABLE ? 77 : 1;
    daze_kvm_machine_destroy(&machine);
  }
  int failed = run_case(argv[1], argv[2], procedure_guest, sizeof(procedure_guest));
  failed |= run_case(argv[1], argv[2], virtual_interrupt_guest, sizeof(virtual_interrupt_guest));
  failed |= run_case(argv[1], argv[2], real_mode_guest, sizeof(real_mode_guest));
  /* A software frame can set reserved FLAGS bits or omit the fixed bit;
   * loading that frame must still permit the real-mode procedure to run. */
  uint8_t reserved_flags_guest[sizeof(procedure_guest)];
  memcpy(reserved_flags_guest, procedure_guest, sizeof(reserved_flags_guest));
  daze_write_u16(reserved_flags_guest + 47, 1);
  daze_write_u16(reserved_flags_guest + 0x6a, 0x802c);
  failed |= run_case(argv[1], argv[2], reserved_flags_guest, sizeof(reserved_flags_guest));
  return failed;
}
