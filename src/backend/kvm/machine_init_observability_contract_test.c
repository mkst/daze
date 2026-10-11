#include "machine.h"
#include "machine_private.h"

#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
#include <errno.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

enum { C_OPEN, C_IOCTL, C_MMAP, C_MUNMAP, C_CLOSE, C_COUNT };
enum { SHAPE_RESET, SHAPE_DESTROYED, SHAPE_LIVE };

static const char *const CALL_NAMES[C_COUNT] = {"open", "ioctl", "mmap", "munmap", "close"};
static int call_counts[C_COUNT];
static int test_failures;

typedef struct {
  int open_fail;
  int open_errno;
  int api_mismatch;
  int fail_create_vm;
  int fail_create_vcpu;
  int mmap_size_fail;
  int mmap_size_zero;
  int run_mmap_fail;
  int guest_mmap_fail;
  int mmap_errno;
  int fail_region;
  int ioctl_errno;
  long run_mmap_size;
} ShimPlan;

static ShimPlan plan;

static int next_fd(void) {
  return open("/dev/null", O_RDWR | O_CLOEXEC);
}

static int shim_open(const char *path, int flags) {
  (void)path;
  call_counts[C_OPEN]++;
  if (plan.open_fail) {
    errno = plan.open_errno;
    return -1;
  }
  return open("/dev/null", flags);
}

static int shim_ioctl(int fd, unsigned long request, void *arg) {
  (void)fd;
  (void)arg;
  call_counts[C_IOCTL]++;
  switch (request) {
  case KVM_GET_API_VERSION:
    return plan.api_mismatch ? KVM_API_VERSION + 1 : KVM_API_VERSION;
  case KVM_CREATE_VM:
    if (plan.fail_create_vm) {
      errno = plan.ioctl_errno;
      return -1;
    }
    return next_fd();
  case KVM_CREATE_VCPU:
    if (plan.fail_create_vcpu) {
      errno = plan.ioctl_errno;
      return -1;
    }
    return next_fd();
  case KVM_GET_VCPU_MMAP_SIZE:
    if (plan.mmap_size_fail) {
      errno = plan.ioctl_errno;
      return -1;
    }
    if (plan.mmap_size_zero) return 0;
    return (int)plan.run_mmap_size;
  case KVM_SET_USER_MEMORY_REGION:
    if (plan.fail_region) {
      errno = plan.ioctl_errno;
      return -1;
    }
    return 0;
  default:
    errno = EINVAL;
    return -1;
  }
}

static void *shim_mmap(void *addr, size_t length, int prot, int flags, int fd, long offset) {
  (void)addr;
  (void)prot;
  (void)flags;
  (void)fd;
  (void)offset;
  call_counts[C_MMAP]++;
  if ((call_counts[C_MMAP] == 1 && plan.run_mmap_fail) ||
      (call_counts[C_MMAP] == 2 && plan.guest_mmap_fail)) {
    errno = plan.mmap_errno;
    return MAP_FAILED;
  }
  return mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
}

static int shim_munmap(void *addr, size_t length) {
  call_counts[C_MUNMAP]++;
  return munmap(addr, length);
}

static int shim_close(int fd) {
  call_counts[C_CLOSE]++;
  return close(fd);
}

static const DazeKvmMachineSeam seam = {
  .open = shim_open,
  .ioctl = shim_ioctl,
  .mmap = shim_mmap,
  .munmap = shim_munmap,
  .close = shim_close,
};

static void reset_plan(void) {
  memset(&plan, 0, sizeof(plan));
  plan.run_mmap_size = 0x1000;
  memset(call_counts, 0, sizeof(call_counts));
  errno = 0;
}

static int expect_calls(const int expected[C_COUNT]) {
  int ok = 1;
  for (int i = 0; i < C_COUNT; i++) {
    if (call_counts[i] != expected[i]) {
      fprintf(stderr, "  %s calls: got %d, want %d\n", CALL_NAMES[i], call_counts[i], expected[i]);
      ok = 0;
    }
  }
  return ok;
}

static int expect_result(const char *name, DazeKvmMachineInitResult result, int status, int stage,
                         int error) {
  if (result.status == status && result.stage == stage && result.error == error) return 1;
  fprintf(stderr, "%s: got status/stage/error %d/%d/%d, want %d/%d/%d\n", name, result.status,
          result.stage, result.error, status, stage, error);
  return 0;
}

static int expect_shape(const char *name, const DazeKvmMachine *m, int shape, size_t n) {
  int ok = 1;
  if (shape == SHAPE_DESTROYED) {
    if (m->kvm != -1 || m->vm != -1 || m->vcpu != -1 || m->run != NULL || m->guest != NULL ||
        m->run_size != 0 || m->guest_size != 0) {
      fprintf(stderr,
              "%s: not destroyed: kvm/vm/vcpu %d/%d/%d, run %p, guest %p, run_size %zu, "
              "guest_size %zu\n",
              name, m->kvm, m->vm, m->vcpu, m->run, m->guest, m->run_size, m->guest_size);
      ok = 0;
    }
  } else if (shape == SHAPE_RESET) {
    if (m->kvm != -1 || m->vm != -1 || m->vcpu != -1 || m->run != NULL || m->guest != NULL ||
        m->run_size != 0 || m->guest_size != n) {
      fprintf(stderr,
              "%s: not reset-only: kvm/vm/vcpu %d/%d/%d, run %p, guest %p, run_size %zu, "
              "guest_size %zu\n",
              name, m->kvm, m->vm, m->vcpu, m->run, m->guest, m->run_size, m->guest_size);
      ok = 0;
    }
  } else {
    if (m->kvm < 0 || m->vm < 0 || m->vcpu < 0 || m->run == NULL || m->guest == NULL ||
        m->run_size != (size_t)plan.run_mmap_size || m->guest_size != n) {
      fprintf(stderr,
              "%s: not live: kvm/vm/vcpu %d/%d/%d, run %p, guest %p, run_size %zu, "
              "guest_size %zu\n",
              name, m->kvm, m->vm, m->vcpu, m->run, m->guest, m->run_size, m->guest_size);
      ok = 0;
    }
  }
  return ok;
}

static void check_row(const char *name, DazeKvmMachineInitResult result, const DazeKvmMachine *m,
                      int status, int stage, int error, const int calls[C_COUNT], int shape) {
  const int ok = expect_result(name, result, status, stage, error) &&
                 expect_shape(name, m, shape, 0x1000) && expect_calls(calls);
  if (!ok) fprintf(stderr, "  (%s)\n", name);
  test_failures += !ok;
}

int main(void) {
  DazeKvmMachine m;

  reset_plan();
  plan.open_fail = 1;
  plan.open_errno = ENOENT;
  {
    const int calls[C_COUNT] = {1, 0, 0, 0, 0};
    check_row("unavailable open ENOENT", daze_kvm_machine_init_with_seam(&m, 0x1000, &seam), &m,
              DAZE_KVM_MACHINE_UNAVAILABLE, DAZE_KVM_MACHINE_STAGE_OPEN, ENOENT, calls,
              SHAPE_RESET);
  }

  reset_plan();
  plan.open_fail = 1;
  plan.open_errno = EACCES;
  {
    const int calls[C_COUNT] = {1, 0, 0, 0, 0};
    check_row("permission-denied open EACCES", daze_kvm_machine_init_with_seam(&m, 0x1000, &seam),
              &m, DAZE_KVM_MACHINE_UNAVAILABLE, DAZE_KVM_MACHINE_STAGE_OPEN, EACCES, calls,
              SHAPE_RESET);
  }

  reset_plan();
  plan.api_mismatch = 1;
  {
    const int calls[C_COUNT] = {1, 1, 0, 0, 1};
    check_row("API mismatch", daze_kvm_machine_init_with_seam(&m, 0x1000, &seam), &m,
              DAZE_KVM_MACHINE_FAILED, DAZE_KVM_MACHINE_STAGE_API, 0, calls, SHAPE_DESTROYED);
  }

  reset_plan();
  plan.fail_create_vm = 1;
  plan.ioctl_errno = EIO;
  {
    const int calls[C_COUNT] = {1, 2, 0, 0, 1};
    check_row("create-VM failure", daze_kvm_machine_init_with_seam(&m, 0x1000, &seam), &m,
              DAZE_KVM_MACHINE_FAILED, DAZE_KVM_MACHINE_STAGE_VM, EIO, calls, SHAPE_DESTROYED);
  }

  reset_plan();
  plan.fail_create_vcpu = 1;
  plan.ioctl_errno = EIO;
  {
    const int calls[C_COUNT] = {1, 3, 0, 0, 2};
    check_row("create-vCPU failure", daze_kvm_machine_init_with_seam(&m, 0x1000, &seam), &m,
              DAZE_KVM_MACHINE_FAILED, DAZE_KVM_MACHINE_STAGE_VCPU, EIO, calls, SHAPE_DESTROYED);
  }

  reset_plan();
  plan.mmap_size_zero = 1;
  {
    const int calls[C_COUNT] = {1, 4, 0, 0, 3};
    check_row("run-map size zero", daze_kvm_machine_init_with_seam(&m, 0x1000, &seam), &m,
              DAZE_KVM_MACHINE_FAILED, DAZE_KVM_MACHINE_STAGE_MMAP_SIZE, 0, calls, SHAPE_DESTROYED);
  }

  reset_plan();
  plan.mmap_size_fail = 1;
  plan.ioctl_errno = EIO;
  {
    const int calls[C_COUNT] = {1, 4, 0, 0, 3};
    check_row("run-map size raw ioctl -1", daze_kvm_machine_init_with_seam(&m, 0x1000, &seam), &m,
              DAZE_KVM_MACHINE_FAILED, DAZE_KVM_MACHINE_STAGE_MMAP_SIZE, EIO, calls,
              SHAPE_DESTROYED);
  }

  reset_plan();
  plan.run_mmap_fail = 1;
  plan.mmap_errno = ENOMEM;
  {
    const int calls[C_COUNT] = {1, 4, 2, 1, 3};
    check_row("run mmap failure", daze_kvm_machine_init_with_seam(&m, 0x1000, &seam), &m,
              DAZE_KVM_MACHINE_FAILED, DAZE_KVM_MACHINE_STAGE_RUN_MMAP, ENOMEM, calls,
              SHAPE_DESTROYED);
  }

  reset_plan();
  plan.guest_mmap_fail = 1;
  plan.mmap_errno = ENOMEM;
  {
    const int calls[C_COUNT] = {1, 4, 2, 1, 3};
    check_row("guest mmap failure", daze_kvm_machine_init_with_seam(&m, 0x1000, &seam), &m,
              DAZE_KVM_MACHINE_FAILED, DAZE_KVM_MACHINE_STAGE_GUEST_MMAP, ENOMEM, calls,
              SHAPE_DESTROYED);
  }

  reset_plan();
  plan.fail_region = 1;
  plan.ioctl_errno = EIO;
  {
    const int calls[C_COUNT] = {1, 5, 2, 2, 3};
    check_row("region failure", daze_kvm_machine_init_with_seam(&m, 0x1000, &seam), &m,
              DAZE_KVM_MACHINE_FAILED, DAZE_KVM_MACHINE_STAGE_REGION, EIO, calls, SHAPE_DESTROYED);
  }

  reset_plan();
  {
    const int calls[C_COUNT] = {1, 5, 2, 0, 0};
    DazeKvmMachineInitResult r = daze_kvm_machine_init_with_seam(&m, 0x1000, &seam);
    check_row("seam-driven success", r, &m, DAZE_KVM_MACHINE_OK, DAZE_KVM_MACHINE_STAGE_NONE, 0,
              calls, SHAPE_LIVE);
    daze_kvm_machine_destroy(&m);
    int ok = expect_shape("seam-driven success (post destroy)", &m, SHAPE_DESTROYED, 0);
    if (!ok) test_failures++;
  }

  reset_plan();
  {
    const int calls[C_COUNT] = {0, 0, 0, 0, 0};
    DazeKvmMachine noise;
    memset(&noise, 0xa5, sizeof(noise));
    DazeKvmMachine before = noise;
    DazeKvmMachineInitResult r = daze_kvm_machine_init_with_seam(&noise, 0, &seam);
    int ok = expect_result("invalid input untouched", r, DAZE_KVM_MACHINE_INVALID,
                           DAZE_KVM_MACHINE_STAGE_NONE, 0) &&
             memcmp(&noise, &before, sizeof(noise)) == 0 && expect_calls(calls);
    if (!ok) fprintf(stderr, "  (invalid input untouched)\n");
    test_failures += !ok;
  }

  reset_plan();
  {
    const int calls[C_COUNT] = {0, 0, 0, 0, 0};
    DazeKvmMachineInitResult r = daze_kvm_machine_init_with_seam(NULL, 0x1000, &seam);
    int ok = expect_result("null machine invalid", r, DAZE_KVM_MACHINE_INVALID,
                           DAZE_KVM_MACHINE_STAGE_NONE, 0) &&
             expect_calls(calls);
    if (!ok) fprintf(stderr, "  (null machine invalid)\n");
    test_failures += !ok;
  }

  fprintf(stderr, "KVM machine init observability: %s\n", test_failures ? "failed" : "passed");
  return test_failures ? 1 : 0;
}
#else
int main(void) {
  return 77;
}
#endif
