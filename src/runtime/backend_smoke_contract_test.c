#include "byte_order.h"
#include "machine.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/* Create/write/close RESULT.TXT, write the same bytes to stdout, then exit 37.
 * Every carry or short write branches to exit 99, so output cannot hide failure. */
static const uint8_t guest[0x76] = {
  0x0e,             /* push cs */
  0x1f,             /* pop ds */
  0x31, 0xc9,       /* xor cx,cx */
  0xba, 0x60, 0x00, /* mov dx,0x60 */
  0xb4, 0x3c,       /* mov ah,0x3c */
  0xcd, 0x21,       /* int 0x21 */
  0x72, 0x32,       /* jb +0x32 */
  0x89, 0xc3,       /* mov bx,ax */
  0xb9, 0x06, 0x00, /* mov cx,6 */
  0xba, 0x70, 0x00, /* mov dx,0x70 */
  0xb4, 0x40,       /* mov ah,0x40 */
  0xcd, 0x21,       /* int 0x21 */
  0x72, 0x24,       /* jb +0x24 */
  0x3d, 0x06, 0x00, /* cmp ax,6 */
  0x75, 0x1f,       /* jne +0x1f */
  0xb4, 0x3e,       /* mov ah,0x3e */
  0xcd, 0x21,       /* int 0x21 */
  0x72, 0x19,       /* jb +0x19 */
  0xbb, 0x01, 0x00, /* mov bx,1 */
  0xb9, 0x06, 0x00, /* mov cx,6 */
  0xba, 0x70, 0x00, /* mov dx,0x70 */
  0xb4, 0x40,       /* mov ah,0x40 */
  0xcd, 0x21,       /* int 0x21 */
  0x72, 0x0a,       /* jb +0x0a */
  0x3d, 0x06, 0x00, /* cmp ax,6 */
  0x75, 0x05,       /* jne +0x05 */
  0xb8, 0x25, 0x4c, /* mov ax,0x4c25 */
  0xcd, 0x21,       /* int 0x21 */
  0xb8, 0x63, 0x4c, /* mov ax,0x4c63 */
  0xcd, 0x21, [0x60] = 'R', 'E', 'S', 'U', 'L', 'T',  '.', 'T', 'X',
  'T',  0,    [0x70] = 's', 'm', 'o', 'k', 'e', '\n',
};

static int write_guest(const char *path) {
  uint8_t image[32 + sizeof(guest)] = {0};
  daze_write_u16(image, 0x5a4d);
  daze_write_u16(image + 2, sizeof(image));
  daze_write_u16(image + 4, 1);
  daze_write_u16(image + 8, 2);
  daze_write_u16(image + 12, 0xffff);
  daze_write_u16(image + 16, 0xfffe);
  daze_write_u16(image + 24, 0x1c);
  memcpy(image + 32, guest, sizeof(guest));
  FILE *file = fopen(path, "wb");
  if (file == NULL) return 0;
  const int written = fwrite(image, 1, sizeof(image), file) == sizeof(image);
  return fclose(file) == 0 && written;
}

static int output_matches(FILE *file) {
  char bytes[7] = {0};
  rewind(file);
  return fread(bytes, 1, sizeof(bytes), file) == 6 && memcmp(bytes, "smoke\n", 6) == 0 &&
         !ferror(file);
}

static int diagnostics_match(FILE *file, const char *backend, const char *selection,
                             const char *requested) {
  char expected[96];
  snprintf(expected, sizeof(expected), "metrics: backend=%s selection=%s", backend, selection);
  char line[1024];
  int selected = 0;
  int completed = 0;
  rewind(file);
  while (fgets(line, sizeof(line), file) != NULL) {
    if (strstr(line, expected) != NULL) selected = 1;
    if (strncmp(line, "kvm: ", 5) == 0 && strstr(line, "command=0") != NULL &&
        strstr(line, "started=1 exit=37") != NULL && strstr(line, requested) != NULL &&
        strstr(line, strcmp(backend, "kvm") == 0 ? "attempted=1" : "attempted=0") != NULL)
      completed = 1;
  }
  return selected && completed && !ferror(file);
}

int main(int argc, char **argv) {
  if (argc != 3) return 2;
  const int unicorn = strcmp(argv[2], "unicorn") == 0;
  const int strict = strcmp(argv[2], "kvm") == 0;
  int kvm_available = 0;
  if (!unicorn) {
    DazeKvmMachine machine;
    const int status = daze_kvm_machine_init(&machine, 0x10000);
    if (status == DAZE_KVM_MACHINE_OK) {
      kvm_available = 1;
      daze_kvm_machine_destroy(&machine);
    } else if (status != DAZE_KVM_MACHINE_UNAVAILABLE) {
      return 1;
    } else if (strict || !DAZE_HAS_UNICORN) {
      return 77;
    }
  }
  const char *backend = kvm_available ? "kvm" : "unicorn";
  const char *selection = kvm_available  ? "kvm-completed"
                          : unicorn      ? "unicorn"
                          : DAZE_HAS_KVM ? "kvm-unavailable"
                                         : "kvm-not-compiled";
  const char *requested = unicorn ? "requested=2" : strict ? "requested=1" : "requested=0";
  char directory[] = "/tmp/daze-backend-smoke-XXXXXX";
  if (mkdtemp(directory) == NULL) return 1;
  char executable[160];
  char artifact[160];
  char temporary[160];
  snprintf(executable, sizeof(executable), "%s/SMOKE.EXE", directory);
  snprintf(artifact, sizeof(artifact), "%s/RESULT.TXT", directory);
  snprintf(temporary, sizeof(temporary), "%s/TMP", directory);
  FILE *output = tmpfile();
  FILE *errors = tmpfile();
  FILE *result = NULL;
  int passed = 0;
  if (output == NULL || errors == NULL || !write_guest(executable)) goto out;
  const pid_t child = fork();
  if (child == 0) {
    if (dup2(fileno(output), STDOUT_FILENO) < 0 || dup2(fileno(errors), STDERR_FILENO) < 0)
      _exit(125);
    if (strcmp(argv[2], "omitted") == 0)
      execl(argv[1], argv[1], "--debug", "--metrics", "--mount", directory, "SMOKE.EXE",
            (char *)NULL);
    else
      execl(argv[1], argv[1], "--debug", "--metrics", "--backend", argv[2], "--mount", directory,
            "SMOKE.EXE", (char *)NULL);
    _exit(126);
  }
  if (child < 0) goto out;
  int status = 0;
  pid_t waited;
  do {
    waited = waitpid(child, &status, 0);
  } while (waited < 0 && errno == EINTR);
  result = fopen(artifact, "rb");
  passed = waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 37 && result != NULL &&
           output_matches(output) && output_matches(result) &&
           diagnostics_match(errors, backend, selection, requested);
  if (!passed) {
    fprintf(stderr, "backend smoke %s: wait status=%d, expected DOS exit=37 backend=%s\n", argv[2],
            status, backend);
    rewind(errors);
    int byte;
    while ((byte = fgetc(errors)) != EOF)
      fputc(byte, stderr);
  }
out:
  if (result != NULL) fclose(result);
  if (output != NULL) fclose(output);
  if (errors != NULL) fclose(errors);
  unlink(executable);
  unlink(artifact);
  rmdir(temporary);
  rmdir(directory);
  return passed ? 0 : 1;
}
