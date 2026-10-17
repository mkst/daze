#include "byte_order.h"
#include "machine.h"

#undef NDEBUG
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static char runner[4096];
static char directory[] = "/tmp/daze-launch-cli-XXXXXX";
static char stderr_bytes[16384];

static void run(const char *const *arguments, int expected, const char *output,
                const char *diagnostic, const char *forbidden, int exhaust_fds) {
  FILE *out = tmpfile(), *err = tmpfile();
  assert(out && err);
  pid_t child = fork();
  assert(child >= 0);
  if (!child) {
    assert(chdir(directory) == 0);
    assert(dup2(fileno(out), STDOUT_FILENO) >= 0 && dup2(fileno(err), STDERR_FILENO) >= 0);
    assert(close(fileno(out)) == 0 && close(fileno(err)) == 0);
    if (exhaust_fds < 0) {
      /* Leave enough space for coverage counters while bounding guest output. */
      const struct rlimit limit = {0x100000, 0x100000};
      assert(setrlimit(RLIMIT_FSIZE, &limit) == 0 && signal(SIGXFSZ, SIG_IGN) != SIG_ERR);
      assert(setenv("DAZE_BUFFERED_WRITES", "1", 1) == 0);
    } else if (exhaust_fds) {
      /* Keep the descriptor budget independent of CTest's inherited streams. */
      for (int fd = 3; fd < 1024; ++fd)
        close(fd);
      const struct rlimit limit = {(rlim_t)exhaust_fds, (rlim_t)exhaust_fds};
      assert(setrlimit(RLIMIT_NOFILE, &limit) == 0);
    }
    execv(runner, (char *const *)arguments);
    _exit(127);
  }
  int status;
  assert(waitpid(child, &status, 0) == child);
  char stdout_bytes[8192] = {0};
  memset(stderr_bytes, 0, sizeof(stderr_bytes));
  rewind(out);
  rewind(err);
  size_t stdout_size = fread(stdout_bytes, 1, sizeof(stdout_bytes) - 1, out);
  size_t stderr_size = fread(stderr_bytes, 1, sizeof(stderr_bytes) - 1, err);
  if (!WIFEXITED(status) || WEXITSTATUS(status) != expected || stdout_size != strlen(output) ||
      memcmp(stdout_bytes, output, stdout_size) != 0 ||
      (diagnostic && !strstr(stderr_bytes, diagnostic)) ||
      (forbidden && strstr(stderr_bytes, forbidden))) {
    fprintf(stderr,
            "launch case failed: expected exit %d, wait status %d\nstdout: %s\nstderr: %s\n",
            expected, status, stdout_bytes, stderr_bytes);
    abort();
  }
  assert(stdout_size < sizeof(stdout_bytes) - 1 && stderr_size < sizeof(stderr_bytes) - 1 &&
         !ferror(out) && !ferror(err));
  assert(fclose(out) == 0 && fclose(err) == 0);
}

static void write_guest(const char *name, const uint8_t *code, size_t size) {
  char path[256];
  snprintf(path, sizeof(path), "%s/%s", directory, name);
  uint8_t bytes[256] = {0};
  assert(size + 32 <= sizeof(bytes));
  daze_write_u16(bytes, 0x5a4d);
  daze_write_u16(bytes + 2, size + 32);
  daze_write_u16(bytes + 4, 1);
  daze_write_u16(bytes + 8, 2);
  daze_write_u16(bytes + 16, 0xfffe);
  daze_write_u16(bytes + 24, 0x1c);
  memcpy(bytes + 32, code, size);
  FILE *file = fopen(path, "wb");
  assert(file && fwrite(bytes, 1, size + 32, file) == size + 32 && fclose(file) == 0);
}

static void setup_cases(void) {
  const int kvm_compiled = daze_kvm_machine_compiled();
  const char *kvm_failure =
    kvm_compiled ? "KVM backend is unavailable" : "KVM backend was not compiled";
#if DAZE_HAS_UNICORN
  const char *automatic_notice = kvm_compiled ? "KVM unavailable; falling back to Unicorn" : "";
  const char *automatic_selection =
    kvm_compiled ? "selection=kvm-unavailable" : "selection=kvm-not-compiled";
#endif
  const char *none[] = {runner, NULL};
  run(none, 2, "", "usage: daze", "cannot load", 0);
  const char *help[] = {runner, "--help", NULL};
  run(help, 0, "", "usage: daze", "cannot load", 0);
  const char *mount[] = {runner, "--mount", NULL};
  run(mount, 2, "", "requires a directory", "cannot load", 0);
  const char *env[] = {runner, "--env", NULL};
  run(env, 2, "", "requires NAME=VALUE", "cannot load", 0);
  const char *badenv[] = {runner, "--env", "BAD", "ZERO.EXE", NULL};
  run(badenv, 2, "", "requires NAME=VALUE format", "cannot load", 0);
  const char *many[72] = {runner};
  for (int i = 0; i < 33; ++i) {
    many[1 + i * 2] = "--env";
    many[2 + i * 2] = "A=B";
  }
  run(many, 2, "", "too many --env", "cannot load", 0);
  for (int i = 0; i < 27; ++i) {
    many[1 + i * 2] = "--mount";
    many[2 + i * 2] = directory;
  }
  many[55] = NULL;
  run(many, 2, "", "too many --mount", "cannot load", 0);
  const char *missing[] = {runner, "--mount", "/no-such-daze-mount", "ZERO.EXE", NULL};
  run(missing, 3, "", "cannot open mount", "started=1", 0);
  const char *duplicate[] = {runner, "--mount", "C:.", "--mount", "c:.", "ZERO.EXE", NULL};
  run(duplicate, 3, "", "DOS drive C: is already mounted", "started=1", 0);
  char long_path[4096];
  memset(long_path, 'x', sizeof(long_path) - 1);
  long_path[sizeof(long_path) - 1] = 0;
  const char *path[] = {runner, long_path, NULL};
  run(path, 2, "", "mounted MZ path is too long", "cannot load", 0);
  char long_tail[127];
  memset(long_tail, 'x', 126);
  long_tail[126] = 0;
  const char *tail[] = {runner, "ZERO.EXE", long_tail, NULL};
  run(tail, 2, "", "DOS command tail is longer than 126 bytes", "cannot load", 0);
  char tmp[256];
  snprintf(tmp, sizeof(tmp), "%s/TMP", directory);
  FILE *file = fopen(tmp, "wb");
  assert(file && fclose(file) == 0);
  const char *temp[] = {runner, "ZERO.EXE", NULL};
  run(temp, 3, "", "cannot initialise C: mount temp directory", "started=1", 0);
  assert(unlink(tmp) == 0);
  const char *standard[] = {runner, "--no-tmp", "ZERO.EXE", NULL};
  run(standard, 3, "", "cannot initialise standard DOS handles", "started=1", 6);
  assert(access(tmp, F_OK) == -1);
  const char *large_strict[] = {runner,    "--backend", "kvm",       "--no-tmp",
                                "--debug", "--metrics", "LARGE.EXE", NULL};
  run(large_strict, 3, "", kvm_failure, "started=1", 0);
  assert(strstr(stderr_bytes, "attempted=0 prestart=0 started=0 exit=0 requested=1"));
#if DAZE_HAS_UNICORN
  const char *large_auto[] = {runner,    "--backend", "auto",      "--no-tmp",
                              "--debug", "--metrics", "LARGE.EXE", NULL};
  run(large_auto, 37, "", automatic_notice, NULL, 0);
  assert(strstr(stderr_bytes, automatic_selection) &&
         strstr(stderr_bytes, "attempted=0 prestart=0 started=1 exit=37 requested=0"));
#endif
  const char *strict[] = {runner,    "--backend", "kvm",      "--no-tmp",
                          "--debug", "--metrics", "EXIT.EXE", NULL};
  run(strict, 3, "", kvm_failure, "falling back", 7);
  assert(strstr(stderr_bytes, "started=0 exit=0 requested=1") &&
         strstr(stderr_bytes,
                kvm_compiled ? "selection=kvm-requested-failure" : "selection=kvm-not-compiled"));
  const char *automatic[] = {runner,    "--backend", "auto",     "--no-tmp",
                             "--debug", "--metrics", "EXIT.EXE", NULL};
#if DAZE_HAS_UNICORN
  run(automatic, 37, "", automatic_notice, NULL, 7);
  assert(strstr(stderr_bytes, "started=1 exit=37 requested=0") &&
         strstr(stderr_bytes, automatic_selection));
#else
  run(automatic, 3, "", "KVM backend is unavailable", "falling back", 7);
  assert(strstr(stderr_bytes, "started=0 exit=0 requested=0"));
  const char *unicorn[] = {runner,    "--backend", "unicorn",  "--no-tmp",
                           "--debug", "--metrics", "EXIT.EXE", NULL};
  run(unicorn, 3, "", "Unicorn backend was not compiled", "started=1", 0);
#endif
}

static void execution_cases(const char *backend) {
  const char *mode = strcmp(backend, "omitted") == 0 ? "auto" : backend;
  const char *expected = strcmp(mode, "unicorn") == 0 ? "unicorn" : "kvm";
  char metrics[96];
  snprintf(metrics, sizeof(metrics), "metrics: backend=%s selection=%s", expected,
           strcmp(expected, "kvm") == 0 ? "kvm-completed" : "unicorn");
  const char *args[] = {runner,     "--backend", mode,    "--metrics", "--debug",
                        "--no-tmp", "ZERO.EXE",  "hello", "world",     NULL};
  if (strcmp(backend, "omitted") == 0) {
    args[1] = "--debug";
    args[2] = "--no-tmp";
  }
  run(args, 0, " hello world", metrics, "falling back", 0);
  assert(strstr(stderr_bytes, "started=1 exit=0"));
  char limit_tail[126];
  memset(limit_tail, 'x', 125);
  limit_tail[125] = 0;
  char output[127] = " ";
  strcat(output, limit_tail);
  const char *limit[] = {runner,      "--backend", mode,       "--no-tmp", "--debug",
                         "--metrics", "ZERO.EXE",  limit_tail, NULL};
  run(limit, 0, output, metrics, "falling back", 0);
  assert(strstr(stderr_bytes, "started=1 exit=0"));
  const char *ro[] = {runner, "--backend",    mode,    "--debug", "--metrics", "--mount-ro",
                      "C:.",  "C:\\ZERO.EXE", "hello", "world",   NULL};
  run(ro, 0, " hello world", "C: mount is readonly", "falling back", 0);
  const char *alias[] = {runner, "--backend", mode,    "--metrics", "--mount_ro",
                         ".",    "ZERO.EXE",  "hello", "world",     NULL};
  run(alias, 0, " hello world", metrics, "falling back", 0);
  const char *named[] = {runner,      "--backend",    mode,    "--debug",   "--metrics",
                         "--mount",   "X:.",          "--env", "BUILD=one", "--env",
                         "BUILD=two", "X:\\ZERO.EXE", "hello", "world",     NULL};
  run(named, 0, " hello world", "guest current drive is X:", "falling back", 0);
  char tmp[256];
  snprintf(tmp, sizeof(tmp), "%s/TMP", directory);
  assert(access(tmp, F_OK) == -1);
  const char *nonzero[] = {runner, "--backend", mode, "--debug", "--metrics", "EXIT.EXE", NULL};
  run(nonzero, 37, "", "started=1 exit=37", "falling back", 0);
  struct stat info;
  assert(stat(tmp, &info) == 0 && S_ISDIR(info.st_mode) && rmdir(tmp) == 0);
  const char *buffered[] = {runner, "--backend", mode, "--no-tmp", "BUFFER.EXE", NULL};
  char buffered_path[256];
  snprintf(buffered_path, sizeof(buffered_path), "%s/BUFFER.BIN", directory);
  int buffered_fd = open(buffered_path, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
  assert(buffered_fd >= 0 && ftruncate(buffered_fd, 0x100000) == 0);
  run(buffered, 3, "", "cannot flush DOS output", NULL, -1);
  const char *buffered_failure[] = {runner, "--backend", mode, "--no-tmp", "BUFFERFAIL.EXE", NULL};
  run(buffered_failure, 37, "", "cannot flush DOS output", NULL, -1);
  assert(fstat(buffered_fd, &info) == 0 && info.st_size == 0x100000);
  assert(unlink(buffered_path) == 0 && close(buffered_fd) == 0);
  if (strcmp(expected, "kvm") == 0) {
    const char *halt[] = {runner,    "--backend", mode,       "--no-tmp",
                          "--debug", "--metrics", "HALT.EXE", NULL};
    run(halt, 1, "", "raw=5 cs:ip=1000:00000001", "falling back", 0);
    assert(strstr(stderr_bytes, "command=2 attempted=1 prestart=0 started=1 exit=0") &&
           strstr(stderr_bytes, "metrics: backend=kvm selection=kvm-poststart-failure"));
    const char *bad[] = {runner,    "--backend", mode,      "--no-tmp",
                         "--debug", "--metrics", "BAD.EXE", NULL};
    run(bad, strcmp(mode, "kvm") == 0 || DAZE_HAS_UNICORN ? 3 : 1, "", "prestart=1 started=0",
        "started=1", 0);
    assert(strstr(stderr_bytes, strcmp(mode, "kvm") == 0 ? "selection=kvm-requested-failure"
                                : !DAZE_HAS_UNICORN      ? "selection=no-backend-available"
                                                         : "selection=kvm-prestart-rejected"));
  }
}

int main(int argc, char **argv) {
  assert(argc == 3 && realpath(argv[1], runner));
  if (strcmp(argv[2], "setup") != 0 && strcmp(argv[2], "unicorn") != 0) {
    DazeKvmMachine machine;
    int status = daze_kvm_machine_init(&machine, 0x1000);
    if (status == DAZE_KVM_MACHINE_UNAVAILABLE) return 77;
    assert(status == DAZE_KVM_MACHINE_OK);
    daze_kvm_machine_destroy(&machine);
  }
  assert(mkdtemp(directory));
  /* DS initially addresses the PSP; write its DOS command tail, then exit zero. */
  const uint8_t zero[] = {
    0x31, 0xc9,          /* xor cx,cx */
    0x8a, 0x0e, 0x80, 0, /* mov cl,[0080h] */
    0xba, 0x81, 0,       /* mov dx,0x81 */
    0xbb, 1,    0,       /* mov bx,1 */
    0xb4, 0x40,          /* mov ah,0x40 */
    0xcd, 0x21,          /* int 0x21 */
    0xb8, 0,    0x4c,    /* mov ax,0x4c00 */
    0xcd, 0x21,          /* int 0x21 */
  };
  const uint8_t exit[] = {
    0xb8, 37,   0x4c, /* mov ax,0x4c25 */
    0xcd, 0x21,       /* int 0x21 */
  };
  const uint8_t halt[] = {0xf4}; /* hlt */
  uint8_t buffered[144] = {
    0x0e, 0x1f,       /* push cs; pop ds */
    0xba, 0x40, 0,    /* mov dx,0040h */
    0xb8, 0x01, 0x3d, /* mov ax,3d01h */
    0xcd, 0x21,       /* int 21h */
    0x89, 0xc3,       /* mov bx,ax */
    0x31, 0xc9,       /* xor cx,cx */
    0x31, 0xd2,       /* xor dx,dx */
    0xb8, 0x02, 0x42, /* mov ax,4202h */
    0xcd, 0x21,       /* int 21h */
    0xba, 0x50, 0,    /* mov dx,0050h */
    0xb9, 0x40, 0,    /* mov cx,0040h */
    0xb4, 0x40,       /* mov ah,40h */
    0xcd, 0x21,       /* int 21h */
    0xb8, 0,    0x4c, /* mov ax,4c00h */
    0xcd, 0x21,       /* int 21h */
  };
  memcpy(buffered + 64, "BUFFER.BIN", sizeof("BUFFER.BIN"));
  memset(buffered + 80, 'x', 64);
  write_guest("BUFFER.EXE", buffered, sizeof(buffered));
  buffered[32] = 37;
  write_guest("BUFFERFAIL.EXE", buffered, sizeof(buffered));
  write_guest("ZERO.EXE", zero, sizeof(zero));
  write_guest("EXIT.EXE", exit, sizeof(exit));
  write_guest("HALT.EXE", halt, sizeof(halt));
  write_guest("BAD.EXE", exit, sizeof(exit));
  write_guest("LARGE.EXE", exit, sizeof(exit));
  char large_path[256];
  snprintf(large_path, sizeof(large_path), "%s/LARGE.EXE", directory);
  FILE *large = fopen(large_path, "r+b");
  assert(large);
  uint8_t extent[4];
  daze_write_u16(extent, 32);
  daze_write_u16(extent + 2, (0x90000 + 32 + 511) / 512);
  assert(fseek(large, 2, SEEK_SET) == 0 && fwrite(extent, 1, 4, large) == 4 && fflush(large) == 0 &&
         ftruncate(fileno(large), 0x90000 + 32) == 0 && fclose(large) == 0);
  char bad_path[256];
  snprintf(bad_path, sizeof(bad_path), "%s/BAD.EXE", directory);
  FILE *bad = fopen(bad_path, "r+b");
  assert(bad && fseek(bad, 6, SEEK_SET) == 0 && fputc(1, bad) == 1 &&
         fseek(bad, 28, SEEK_SET) == 0 && fputc(sizeof(exit), bad) == sizeof(exit) &&
         fclose(bad) == 0);
  if (strcmp(argv[2], "setup") == 0)
    setup_cases();
  else
    execution_cases(argv[2]);
  const char *names[] = {"ZERO.EXE",  "EXIT.EXE",   "HALT.EXE",      "BAD.EXE",
                         "LARGE.EXE", "BUFFER.EXE", "BUFFERFAIL.EXE"};
  for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
    char path[256];
    snprintf(path, sizeof(path), "%s/%s", directory, names[i]);
    assert(unlink(path) == 0);
  }
  assert(rmdir(directory) == 0);
  puts("launch CLI contract: passed");
  return 0;
}
