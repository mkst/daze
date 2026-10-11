#define _GNU_SOURCE

#include "machine.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv) {
  if (argc != 3) return 2;
  if (strcmp(argv[2], "kvm") == 0) {
    DazeKvmMachine machine;
    const int status = daze_kvm_machine_init(&machine, 0x10000);
    if (status == DAZE_KVM_MACHINE_UNAVAILABLE) return 77;
    if (status != DAZE_KVM_MACHINE_OK) return 1;
    daze_kvm_machine_destroy(&machine);
  }
  /* MZ with no relocations. Guest: push cs; pop ds; mov dx,15;
   * mov ax,0901h; int 21h; mov ax,4c00h; int 21h; db "hello!$". */
  static const unsigned char image[] = {
    'M',  'Z', 54,   0,    1,    0,    0,    0,   2,   0,    0,    0,   0xff, 0xff,
    0,    0,   0xfe, 0xff, 0,    0,    0,    0,   0,   0,    0x1c, 0,   0,    0,
    0,    0,   0,    0,    0x0e, 0x1f, 0xba, 15,  0,   0xb8, 1,    9,   0xcd, 0x21,
    0xb8, 0,   0x4c, 0xcd, 0x21, 'h',  'e',  'l', 'l', 'o',  '!',  '$',
  };
  char directory[] = "/tmp/daze-display-string-XXXXXX";
  if (mkdtemp(directory) == NULL) return 1;
  char executable[160];
  snprintf(executable, sizeof(executable), "%s/DISPLAY.EXE", directory);
  FILE *guest = fopen(executable, "wb");
  FILE *output = tmpfile();
  FILE *errors = tmpfile();
  int passed = 0;
  if (guest == NULL || output == NULL || errors == NULL) goto out;
  const size_t count = fwrite(image, 1, sizeof(image), guest);
  const int closed = fclose(guest);
  guest = NULL;
  if (count != sizeof(image) || closed != 0) goto out;
  const pid_t child = fork();
  if (child == 0) {
    if (dup2(fileno(output), STDOUT_FILENO) < 0 || dup2(fileno(errors), STDERR_FILENO) < 0)
      _exit(125);
    execl(argv[1], argv[1], "--backend", argv[2], "--mount", directory, "DISPLAY.EXE",
          (char *)NULL);
    _exit(126);
  }
  int status = 0;
  if (child < 0 || waitpid(child, &status, 0) != child) goto out;
  rewind(output);
  rewind(errors);
  char actual[16] = {0};
  char diagnostic[2048] = {0};
  const size_t bytes = fread(actual, 1, sizeof(actual) - 1, output);
  const size_t error_bytes = fread(diagnostic, 1, sizeof(diagnostic) - 1, errors);
  passed = WIFEXITED(status) && WEXITSTATUS(status) == 0 && bytes == 6 &&
           strcmp(actual, "hello!") == 0 && error_bytes == 0;
  if (!passed)
    fprintf(stderr, "display string backend=%s status=%d stdout=%s stderr=%s\n", argv[2], status,
            actual, diagnostic);
out:
  if (guest != NULL) fclose(guest);
  if (output != NULL) fclose(output);
  if (errors != NULL) fclose(errors);
  unlink(executable);
  rmdir(directory);
  return passed ? 0 : 1;
}
