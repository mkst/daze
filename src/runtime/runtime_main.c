#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "backend_request.h"
#include "backend_selection.h"
#include "backend_runner.h"
#include "command_result.h"
#include "launch.h"
#if DAZE_HAS_UNICORN
#include "unicorn_services.h"
#endif

#ifndef DAZE_VERSION
#define DAZE_VERSION "unknown"
#endif

static void print_usage(void) {
  fprintf(stderr,
          "daze %s\n"
          "usage: daze [options] EXE [args ...]\n"
          "\n"
          "  --mount [X:]DIR    Writable DOS drive (repeatable: C:, D:, ...)\n"
          "  --mount-ro [X:]DIR Read-only DOS drive\n"
          "  --no-tmp           Skip creating C:\\TMP\n"
          "  --env NAME=VALUE   Guest environment variable (repeatable)\n"
          "  --backend MODE     auto (default, prefers KVM), kvm, or unicorn\n"
          "  --metrics          Execution and I/O summary to stderr\n"
          "  --debug            Runtime diagnostics to stderr\n"
          "  --version          Show version\n"
          "  --help             Show this help\n"
          "\n"
          "Default C: is the current directory. Pin a drive with --mount X:/path.\n"
          "Keep EXE on a mounted drive if it loads files through DOS.\n",
          DAZE_VERSION);
}

static void trace_debug(int enabled, const char *format, ...) {
  if (!enabled) return;
  va_list args;
  va_start(args, format);
  vfprintf(stderr, format, args);
  va_end(args);
}

int daze_runtime_main(int argc, char **argv) {
  const char *mount_paths[DAZE_DOSFS_MAX_DRIVES];
  int mount_drives[DAZE_DOSFS_MAX_DRIVES];
  int mount_readonly[DAZE_DOSFS_MAX_DRIVES];
  for (int index = 0; index < DAZE_DOSFS_MAX_DRIVES; ++index) {
    mount_drives[index] = -1;
    mount_readonly[index] = 0;
  }
  int mount_count = 0;
  const char *env_vars[DAZE_PROCESS_ENV_MAX_EXTRA_VARS];
  int env_var_count = 0;
  const char *path = NULL;
  int metrics = 0;
  int debug = 0;
  int no_tmp = 0;
  DazeBackendRequest requested = DAZE_BACKEND_REQUEST_AUTO;
  int argument = 1;
  while (argument < argc) {
    if (strcmp(argv[argument], "--no-tmp") == 0) {
      no_tmp = 1;
      ++argument;
      continue;
    }
    if (strcmp(argv[argument], "--metrics") == 0) {
      metrics = 1;
      ++argument;
      continue;
    }
    if (strcmp(argv[argument], "--debug") == 0) {
      debug = 1;
      ++argument;
      continue;
    }
    if (strcmp(argv[argument], "--backend") == 0) {
      if (argument + 1 >= argc) {
        fprintf(stderr, "--backend requires auto, kvm, or unicorn\n");
        print_usage();
        return 2;
      }
      const DazeBackendRequestParse parsed = daze_backend_request_parse(argv[argument + 1]);
      if (!parsed.valid) {
        fprintf(stderr, "invalid --backend value: %s\n", argv[argument + 1]);
        print_usage();
        return 2;
      }
      requested = parsed.request;
      argument += 2;
      continue;
    }
    if (strcmp(argv[argument], "--mount") == 0 || strcmp(argv[argument], "--mount-ro") == 0 ||
        strcmp(argv[argument], "--mount_ro") == 0) {
      const int readonly = strcmp(argv[argument], "--mount") != 0;
      if (argument + 1 >= argc) {
        fprintf(stderr, "%s requires a directory\n", argv[argument]);
        return 2;
      }
      if (mount_count >= (int)(sizeof(mount_paths) / sizeof(mount_paths[0]))) {
        fprintf(stderr, "too many --mount directories\n");
        return 2;
      }
      const char *mount_dir = argv[argument + 1];
      int mount_drive = -1;
      if (mount_dir[0] != '\0' && isalpha((unsigned char)mount_dir[0]) && mount_dir[1] == ':' &&
          mount_dir[2] != '\0') {
        mount_drive = toupper((unsigned char)mount_dir[0]) - 'A';
        mount_dir += 2;
      }
      mount_paths[mount_count] = mount_dir;
      mount_drives[mount_count] = mount_drive;
      mount_readonly[mount_count] = readonly;
      ++mount_count;
      argument += 2;
      continue;
    }
    if (strcmp(argv[argument], "--env") == 0) {
      if (argument + 1 >= argc) {
        fprintf(stderr, "--env requires NAME=VALUE\n");
        return 2;
      }
      if (env_var_count >= (int)(sizeof(env_vars) / sizeof(env_vars[0]))) {
        fprintf(stderr, "too many --env variables\n");
        return 2;
      }
      const char *env_value = argv[argument + 1];
      if (strchr(env_value, '=') == NULL) {
        fprintf(stderr, "--env requires NAME=VALUE format\n");
        return 2;
      }
      env_vars[env_var_count++] = env_value;
      argument += 2;
      continue;
    }
    if (strcmp(argv[argument], "--help") == 0) {
      print_usage();
      return 0;
    }
    if (strcmp(argv[argument], "--version") == 0) {
      printf("daze %s\n", DAZE_VERSION);
      return 0;
    }
    path = argv[argument++];
    break;
  }
  if (path == NULL) {
    print_usage();
    return 2;
  }
  if (mount_count == 0) {
    mount_paths[0] = ".";
    mount_count = 1;
  }
  char command_tail[127] = {0};
  size_t command_tail_length = 0;
  for (int index = argument; index < argc; ++index) {
    const size_t argument_length = strlen(argv[index]);
    /* PSP:81h holds the literal text after the executable name, including
     * the first separating space supplied by a normal DOS invocation. */
    const size_t separator = 1;
    if (command_tail_length > 126 - separator ||
        argument_length > 126 - command_tail_length - separator) {
      fprintf(stderr, "DOS command tail is longer than 126 bytes\n");
      return 2;
    }
    if (separator != 0) command_tail[command_tail_length++] = ' ';
    memcpy(command_tail + command_tail_length, argv[index], argument_length);
    command_tail_length += argument_length;
  }
  DazePreparedLaunch launch;
  initialize_prepared_launch(&launch);
  const int is_drive_qualified = path[0] != '\0' && path[1] == ':';
  char mounted_mz_path[DAZE_DOSFS_PATH_MAX];
  const char *host_mz_path = path;
  if (path[0] != '/' && !is_drive_qualified) {
    const int length =
      snprintf(mounted_mz_path, sizeof(mounted_mz_path), "%s/%s", mount_paths[0], path);
    if (length < 0 || (size_t)length >= sizeof(mounted_mz_path)) {
      fprintf(stderr, "mounted MZ path is too long\n");
      dispose_prepared_launch(&launch);
      return 2;
    }
    host_mz_path = mounted_mz_path;
  }
#if DAZE_HAS_UNICORN
  DazeUnicornContext context = {0};
  context.engine.metrics.enabled = metrics;
  launch.run_metrics.enabled = metrics;
  context.engine.debug = debug;
#else
  launch.run_metrics.enabled = metrics;
#endif
  void *unicorn_context = NULL;
#if DAZE_HAS_UNICORN
  unicorn_context = &context;
#endif
  launch.debug = debug;
  int mount_errno = 0;
  int first_drive = -1;
  for (int index = 0; index < mount_count; ++index) {
    const int mount_fd = open(mount_paths[index], O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (mount_fd < 0) {
      fprintf(stderr, "cannot open mount %s: %s\n", mount_paths[index], strerror(errno));
      dispose_prepared_launch(&launch);
      return 3;
    }
    int drive_index = -1;
    DazeDosfsStatus status = DAZE_DOSFS_OK;
    if (mount_drives[index] >= 0) {
      status = daze_dosfs_mounts_add_named(&launch.mounts, mount_drives[index], mount_fd,
                                           mount_readonly[index]);
      drive_index = mount_drives[index];
    } else {
      status = daze_dosfs_mounts_add_default(&launch.mounts, mount_fd, mount_readonly[index],
                                             &drive_index);
    }
    if (status != DAZE_DOSFS_OK) {
      if (status == DAZE_DOSFS_DRIVE_IN_USE) {
        fprintf(stderr, "DOS drive %c: is already mounted\n", 'A' + mount_drives[index]);
      } else {
        fprintf(stderr, "cannot assign a DOS drive for mount %s\n", mount_paths[index]);
      }
      close(mount_fd);
      dispose_prepared_launch(&launch);
      return 3;
    }
    if (first_drive < 0) first_drive = drive_index;
    trace_debug(debug, "mounted %s as %c:%s\n", mount_paths[index], 'A' + drive_index,
                mount_readonly[index] ? " (readonly)" : "");
  }
  if (launch.mounts.fds[2] < 0) {
    /* Without C:, use the first mount for unqualified paths; environment defaults remain
     * C:-based. */
    if (first_drive >= 0) {
      launch.mounts.default_drive = first_drive;
      trace_debug(debug, "no C: mount; guest current drive is %c:\n", 'A' + first_drive);
    }
    trace_debug(debug, "no C: mount; TEMP/TMP stay unavailable to the guest\n");
  } else if (daze_dosfs_mount_is_readonly(&launch.mounts, 2)) {
    /* Read-only C: must still launch tools; guest temporary writes fail with DOS access
     * denied. */
    trace_debug(debug, "C: mount is readonly; TEMP/TMP stay unavailable\n");
  } else if (no_tmp) {
    trace_debug(debug, "C:\\TMP setup skipped (--no-tmp)\n");
  } else if (daze_dosfs_ensure_temp_directory(&launch.mounts, &mount_errno) != DAZE_DOSFS_OK) {
    fprintf(stderr, "cannot initialise C: mount temp directory: %s\n", strerror(mount_errno));
    dispose_prepared_launch(&launch);
    return 3;
  }

  const int prepared_status = prepare_launch(&launch, path, host_mz_path, is_drive_qualified,
                                             command_tail, env_vars, env_var_count);
  if (prepared_status != 0) {
    dispose_prepared_launch(&launch);
    return prepared_status;
  }
  int standard_handle_errno = 0;
  if (daze_dosfs_handles_bind_standard(&launch.handles, STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO,
                                       &standard_handle_errno) != DAZE_DOSFS_OK) {
    fprintf(stderr, "cannot initialise standard DOS handles: %s\n",
            strerror(standard_handle_errno));
    dispose_prepared_launch(&launch);
    return 3;
  }
  const DazeBackendCompileAvailability compiled = backend_compile_availability();
  DazeKvmMachine kvm_machine;
  const DazeKvmCandidateObservation candidate =
    select_prepared_backend(&launch, requested, compiled, &kvm_machine);
  const DazeBackendSelection selection =
    daze_backend_selection_decide_request(requested, compiled, candidate.outcome);
  DazeKvmSelectionDiagnostic kvm_diagnostic;
  DazeKvmNormalOperationObservation kvm_observation = {0};
  const DazeCommandResult command =
    run_selected_prepared(&launch, unicorn_context, path, requested, &selection, &candidate,
                          &kvm_machine, &kvm_diagnostic, &kvm_observation);
  daze_kvm_machine_destroy(&kvm_machine);
  report_selection_fallback(&kvm_diagnostic, compiled.unicorn_compiled);
  if (selection.action == DAZE_BACKEND_SELECTION_FAIL) report_selection_failure(path, &selection);
  report_kvm_selection_diagnostic(debug, &kvm_diagnostic);
  report_kvm_terminal_observation(debug, &kvm_diagnostic, &kvm_observation);
  report_kvm_selection_metrics(metrics, &launch.run_metrics, &kvm_diagnostic);

  int write_errno = launch.handles.teardown_errno;
  int flush_errno = 0;
  if (daze_dosfs_handles_flush(&launch.handles, &flush_errno) != DAZE_DOSFS_OK)
    write_errno = flush_errno;
  if (write_errno != 0) fprintf(stderr, "cannot flush DOS output: %s\n", strerror(write_errno));
  dispose_prepared_launch(&launch);
  /* A clean emulator stop is not command success; normal completion requires top-level
   * DOS AH=4Ch. */
  const int status = daze_command_result_host_status(&command);
  return write_errno != 0 && status == 0 ? 3 : status;
}
