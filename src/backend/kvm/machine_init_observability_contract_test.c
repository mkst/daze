#include "machine.h"
#include "machine_private.h"

#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
#include <errno.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

enum { C_OPEN, C_IOCTL, C_MMAP, C_MUNMAP, C_CLOSE, C_MADVISE, C_COUNT };
enum { SHAPE_RESET, SHAPE_DESTROYED, SHAPE_LIVE };

static const char *const CALL_NAMES[C_COUNT] = {"open",   "ioctl", "mmap",
                                                "munmap", "close", "madvise"};
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
  int guest_address_shape;
  int all_guest_maps_fail;
  int trim_fail_call;
  int advice_fail;
} ShimPlan;

static ShimPlan plan;
static size_t map_lengths[4], unmap_lengths[8], advised_length;
static void *advised_address;
static struct kvm_userspace_memory_region region;

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
    region = *(const struct kvm_userspace_memory_region *)arg;
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
  if (call_counts[C_MMAP] <= 4) map_lengths[call_counts[C_MMAP] - 1] = length;
  if ((call_counts[C_MMAP] == 1 && plan.run_mmap_fail) ||
      (call_counts[C_MMAP] == 2 && plan.guest_mmap_fail) ||
      (call_counts[C_MMAP] >= 2 && plan.all_guest_maps_fail)) {
    errno = plan.mmap_errno;
    return MAP_FAILED;
  }
  if (call_counts[C_MMAP] >= 2 && plan.guest_address_shape) {
    const size_t alignment = 2 * 1024 * 1024;
    void *base = mmap(NULL, length + 2 * alignment, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) return base;
    uintptr_t chosen = ((uintptr_t)base + alignment - 1) & ~(uintptr_t)(alignment - 1);
    if (plan.guest_address_shape == 2) chosen += 0x1000;
    const size_t prefix = chosen - (uintptr_t)base;
    if (prefix) munmap(base, prefix);
    munmap((void *)(chosen + length), 2 * alignment - prefix);
    return (void *)chosen;
  }
  return mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
}

static int shim_munmap(void *addr, size_t length) {
  call_counts[C_MUNMAP]++;
  if (call_counts[C_MUNMAP] <= 8) unmap_lengths[call_counts[C_MUNMAP] - 1] = length;
  if (call_counts[C_MUNMAP] == plan.trim_fail_call) {
    errno = ENOMEM;
    return -1;
  }
  return munmap(addr, length);
}

static int shim_madvise(void *addr, size_t length, int advice) {
  call_counts[C_MADVISE]++;
  advised_address = addr;
  advised_length = length;
  if (advice != MADV_HUGEPAGE || plan.advice_fail) {
    errno = ENOSYS;
    return -1;
  }
  return 0;
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
  memset(map_lengths, 0, sizeof(map_lengths));
  memset(unmap_lengths, 0, sizeof(unmap_lengths));
  advised_address = NULL;
  advised_length = 0;
  region = (struct kvm_userspace_memory_region){0};
  errno = 0;
}

static int expect_result(const char *name, DazeKvmMachineInitResult result, int status, int stage,
                         int error);
static int expect_shape(const char *name, const DazeKvmMachine *m, int shape, size_t n);

static void hugepage_contract(void) {
  const size_t alignment = 2 * 1024 * 1024;
  DazeKvmMachineSeam advised = seam;
  advised.madvise = shim_madvise;
  for (unsigned kind = 0; kind < 16; ++kind) {
    reset_plan();
    unsetenv("DAZE_KVM_HUGEPAGES");
    plan.guest_address_shape = 1;
    plan.mmap_errno = ENOMEM;
    size_t size = 2 * alignment;
    int fallback = 0, failure = 0, advice = 1;
    switch (kind) {
    case 1:
      plan.guest_address_shape = 2;
      break;
    case 2:
      plan.guest_mmap_fail = 1;
      fallback = 1;
      advice = 0;
      break;
    case 3:
      plan.advice_fail = 1;
      break;
    case 4:
      plan.guest_address_shape = 2;
      plan.trim_fail_call = 1;
      fallback = 1;
      advice = 0;
      break;
    case 5:
      plan.guest_address_shape = 2;
      plan.trim_fail_call = 2;
      fallback = 1;
      advice = 0;
      break;
    case 6:
      plan.trim_fail_call = 1;
      fallback = 1;
      advice = 0;
      break;
    case 7:
      setenv("DAZE_KVM_HUGEPAGES", "0", 1);
      advice = 0;
      break;
    case 8:
      setenv("DAZE_KVM_HUGEPAGES", "1", 1);
      break;
    case 9:
      size = alignment / 2;
      advice = 0;
      break;
    case 10:
      size = alignment + 0x1000;
      advice = 0;
      break;
    case 11:
      size = (SIZE_MAX / alignment) * alignment;
      plan.guest_mmap_fail = 1;
      advice = 0;
      failure = 1;
      break;
    case 12:
      plan.all_guest_maps_fail = 1;
      fallback = 1;
      advice = 0;
      failure = 1;
      break;
    case 13:
      plan.fail_region = 1;
      plan.ioctl_errno = EIO;
      failure = 1;
      break;
    case 14:
      plan.run_mmap_fail = 1;
      plan.mmap_errno = EACCES;
      plan.advice_fail = 1;
      failure = 1;
      break;
    case 15:
      plan.run_mmap_fail = 1;
      plan.mmap_errno = EACCES;
      plan.trim_fail_call = 1;
      fallback = 1;
      advice = 0;
      failure = 1;
      break;
    }
    DazeKvmMachine machine;
    DazeKvmMachineInitResult result = daze_kvm_machine_init_with_seam(&machine, size, &advised);
    int ok = call_counts[C_MADVISE] == advice && call_counts[C_MMAP] == 2 + fallback;
    if (failure) {
      ok = ok &&
           expect_result("huge-page failure", result, DAZE_KVM_MACHINE_FAILED,
                         kind >= 14   ? DAZE_KVM_MACHINE_STAGE_RUN_MMAP
                         : kind == 13 ? DAZE_KVM_MACHINE_STAGE_REGION
                                      : DAZE_KVM_MACHINE_STAGE_GUEST_MMAP,
                         kind >= 14   ? EACCES
                         : kind == 13 ? EIO
                                      : ENOMEM) &&
           expect_shape("huge-page failure", &machine, SHAPE_DESTROYED, size);
    } else {
      ok = ok && expect_result("huge-page mapping", result, DAZE_KVM_MACHINE_OK, 0, 0) &&
           expect_shape("huge-page mapping", &machine, SHAPE_LIVE, size) &&
           region.memory_size == size && region.userspace_addr == (uintptr_t)machine.guest;
      if (advice)
        ok = ok && (uintptr_t)machine.guest % alignment == 0 && advised_address == machine.guest &&
             advised_length == size && map_lengths[1] == size + alignment;
      if (fallback) ok = ok && map_lengths[2] == size;
      if (kind == 4) ok = ok && unmap_lengths[1] == size + alignment;
      if (kind == 5) ok = ok && unmap_lengths[2] == size + 0x1000;
      uint8_t *bytes = machine.guest;
      ok = ok && bytes[0] == 0 && bytes[size - 1] == 0;
      bytes[0] = 0xa5;
      bytes[size - 1] = 0x5a;
      daze_kvm_machine_destroy(&machine);
    }
    if (!ok) fprintf(stderr, "huge-page case %u failed\n", kind);
    test_failures += !ok;
  }
  unsetenv("DAZE_KVM_HUGEPAGES");
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
  hugepage_contract();
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
