#include "machine.h"
#include "machine_access.h"
#include "machine_private.h"
#include "monotonic_clock.h"
#include <stdlib.h>
#include <string.h>

#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
#include "rm_entry.h"
#include "write_batch.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
typedef struct {
  struct kvm_regs regs;
  struct kvm_sregs sregs;
  uint8_t nonzero_chunks[];
} DazeKvmMachineCpuState;
static const uint8_t snapshot_zero_chunk[4096];
static struct kvm_segment seg(uint16_t s) {
  struct kvm_segment x;
  memset(&x, 0, sizeof(x));
  x.base = (uint64_t)s << 4;
  x.limit = 0xffff;
  x.selector = s;
  x.type = 3;
  x.present = 1;
  x.s = 1;
  return x;
}

static int sys_open(const DazeKvmMachineSeam *seam, const char *path, int flags) {
  if (seam && seam->open) return seam->open(path, flags);
  return open(path, flags);
}
static int sys_ioctl(const DazeKvmMachineSeam *seam, int fd, unsigned long request, void *arg) {
  if (seam && seam->ioctl) return seam->ioctl(fd, request, arg);
  return ioctl(fd, request, arg);
}
static void *sys_mmap(const DazeKvmMachineSeam *seam, void *addr, size_t length, int prot,
                      int flags, int fd, off_t offset) {
  if (seam && seam->mmap) return seam->mmap(addr, length, prot, flags, fd, (long)offset);
  return mmap(addr, length, prot, flags, fd, offset);
}
static int sys_munmap(const DazeKvmMachineSeam *seam, void *addr, size_t length) {
  if (seam && seam->munmap) return seam->munmap(addr, length);
  return munmap(addr, length);
}
static int sys_close(const DazeKvmMachineSeam *seam, int fd) {
  if (seam && seam->close) return seam->close(fd);
  return close(fd);
}

static void *guest_mmap(const DazeKvmMachineSeam *seam, size_t size) {
  const size_t alignment = 2 * 1024 * 1024;
  const int flags = MAP_PRIVATE | MAP_ANONYMOUS;
  const char *setting = getenv("DAZE_KVM_HUGEPAGES");
  if ((setting != NULL && strcmp(setting, "0") == 0) || (seam != NULL && seam->madvise == NULL) ||
      size < alignment || size % alignment != 0 || size > SIZE_MAX - alignment)
    return sys_mmap(seam, NULL, size, PROT_READ | PROT_WRITE, flags, -1, 0);

  const size_t reserved = size + alignment;
  const int saved_errno = errno;
  void *const raw = sys_mmap(seam, NULL, reserved, PROT_READ | PROT_WRITE, flags, -1, 0);
  if (raw != MAP_FAILED) {
    const size_t prefix = (alignment - (uintptr_t)raw % alignment) % alignment;
    const size_t suffix = alignment - prefix;
    void *const guest = (uint8_t *)raw + prefix;
    if (prefix != 0 && sys_munmap(seam, raw, prefix) != 0) {
      sys_munmap(seam, raw, reserved);
    } else if (sys_munmap(seam, (uint8_t *)guest + size, suffix) != 0) {
      sys_munmap(seam, guest, size + suffix);
    } else {
      /* Advice is optional: unavailable THPs must not reject a usable guest mapping. */
      if (seam != NULL)
        seam->madvise(guest, size, MADV_HUGEPAGE);
      else
        madvise(guest, size, MADV_HUGEPAGE);
      errno = saved_errno;
      return guest;
    }
  }
  void *const guest = sys_mmap(seam, NULL, size, PROT_READ | PROT_WRITE, flags, -1, 0);
  if (guest != MAP_FAILED) errno = saved_errno;
  return guest;
}

static void destroy_with_seam(DazeKvmMachine *m, const DazeKvmMachineSeam *seam) {
  if (!m) return;
  if (m->guest && m->guest != MAP_FAILED) sys_munmap(seam, m->guest, m->guest_size);
  if (m->run && m->run != MAP_FAILED) sys_munmap(seam, m->run, m->run_size);
  if (m->vcpu >= 0) sys_close(seam, m->vcpu);
  if (m->vm >= 0) sys_close(seam, m->vm);
  if (m->kvm >= 0) sys_close(seam, m->kvm);
  memset(m, 0, sizeof(*m));
  m->kvm = m->vm = m->vcpu = -1;
}
void daze_kvm_machine_destroy(DazeKvmMachine *m) {
  destroy_with_seam(m, NULL);
}
void daze_kvm_machine_set_run_metrics(DazeKvmMachine *m, DazeRunMetrics *metrics) {
  if (m != NULL) m->run_metrics = metrics;
}

DazeKvmMachineInitResult daze_kvm_machine_init_with_seam(DazeKvmMachine *m, size_t n,
                                                         const DazeKvmMachineSeam *seam) {
  DazeKvmMachineInitResult result = {DAZE_KVM_MACHINE_INVALID, DAZE_KVM_MACHINE_STAGE_NONE, 0};
  if (!m || n == 0) return result;
  result.status = DAZE_KVM_MACHINE_OK;
  memset(m, 0, sizeof(*m));
  m->kvm = m->vm = m->vcpu = -1;
  m->guest_size = n;
  if ((m->kvm = sys_open(seam, "/dev/kvm", O_RDWR | O_CLOEXEC)) < 0) {
    result.status = DAZE_KVM_MACHINE_UNAVAILABLE;
    result.stage = DAZE_KVM_MACHINE_STAGE_OPEN;
    result.error = errno;
    return result;
  }
  if (sys_ioctl(seam, m->kvm, KVM_GET_API_VERSION, 0) != KVM_API_VERSION) {
    result.stage = DAZE_KVM_MACHINE_STAGE_API;
    goto fail;
  }
  if ((m->vm = sys_ioctl(seam, m->kvm, KVM_CREATE_VM, 0)) < 0) {
    result.stage = DAZE_KVM_MACHINE_STAGE_VM;
    goto fail;
  }
  /* The injected ioctl seam omits the sync probe; sync is enabled only for real
   * machines. */
  if (seam == NULL) {
    const int mask = ioctl(m->kvm, KVM_CHECK_EXTENSION, KVM_CAP_SYNC_REGS);
    if (mask > 0) m->sync_regs_mask = mask & (KVM_SYNC_X86_REGS | KVM_SYNC_X86_SREGS);
  }
  {
    const int saved_errno = errno;
    m->immediate_exit_supported =
      sys_ioctl(seam, m->kvm, KVM_CHECK_EXTENSION, (void *)(uintptr_t)KVM_CAP_IMMEDIATE_EXIT) > 0;
    errno = saved_errno;
  }
  if ((m->vcpu = sys_ioctl(seam, m->vm, KVM_CREATE_VCPU, 0)) < 0) {
    result.stage = DAZE_KVM_MACHINE_STAGE_VCPU;
    goto fail;
  }
  {
    const long raw_size = sys_ioctl(seam, m->kvm, KVM_GET_VCPU_MMAP_SIZE, 0);
    if (raw_size <= 0) {
      result.stage = DAZE_KVM_MACHINE_STAGE_MMAP_SIZE;
      goto fail;
    }
    m->run_size = (size_t)raw_size;
  }
  m->run = sys_mmap(seam, 0, m->run_size, PROT_READ | PROT_WRITE, MAP_SHARED, m->vcpu, 0);
  m->guest = guest_mmap(seam, n);
  if (m->run == MAP_FAILED) {
    result.stage = DAZE_KVM_MACHINE_STAGE_RUN_MMAP;
    goto fail;
  }
  /* Arm sync-out selection once; KVM populates the shared area on every exit
   * and never clears the selection. Undersized mappings fall back to ioctls. */
  if (m->sync_regs_mask != 0 && m->run_size >= sizeof(struct kvm_run)) {
    ((struct kvm_run *)m->run)->kvm_valid_regs |= (uint64_t)m->sync_regs_mask;
  } else {
    m->sync_regs_mask = 0;
  }
  if (m->run_size < sizeof(struct kvm_run)) m->immediate_exit_supported = 0;
  if (m->guest == MAP_FAILED) {
    result.stage = DAZE_KVM_MACHINE_STAGE_GUEST_MMAP;
    goto fail;
  }
  struct kvm_userspace_memory_region region = {.memory_size = n,
                                               .userspace_addr = (uintptr_t)m->guest};
  if (sys_ioctl(seam, m->vm, KVM_SET_USER_MEMORY_REGION, &region) < 0) {
    result.stage = DAZE_KVM_MACHINE_STAGE_REGION;
    goto fail;
  }
  return result;
fail:
  result.error = errno;
  result.status = DAZE_KVM_MACHINE_FAILED;
  destroy_with_seam(m, seam);
  return result;
}

int daze_kvm_machine_init(DazeKvmMachine *m, size_t n) {
  return daze_kvm_machine_init_with_seam(m, n, NULL).status;
}
int daze_kvm_machine_compiled(void) {
  return 1;
}
void daze_kvm_machine_debug_invalidate(DazeKvmMachine *machine) {
  machine->debug_breakpoint_known = 0;
  machine->debug_io_exit = 0;
}
int daze_kvm_machine_set_guest_debug(DazeKvmMachine *machine, const struct kvm_guest_debug *debug) {
  if (machine == NULL || machine->vcpu < 0 || debug == NULL) {
    errno = EINVAL;
    return -1;
  }
  struct kvm_guest_debug breakpoint = {.control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_HW_BP};
  breakpoint.arch.debugreg[0] = debug->arch.debugreg[0];
  breakpoint.arch.debugreg[7] = 3;
  /* Single-step and exception-injection requests have effects even when repeated. */
  const int cacheable = memcmp(debug, &breakpoint, sizeof(breakpoint)) == 0;
  DazeRunMetrics *const metrics = machine->run_metrics;
  if (cacheable && machine->debug_breakpoint_known && machine->debug_io_exit &&
      machine->debug_breakpoint == breakpoint.arch.debugreg[0]) {
    if (metrics != NULL && metrics->enabled) metrics->kvm_debug_update_elisions++;
    return 0;
  }
  const uint64_t started = metrics != NULL && metrics->enabled ? monotonic_nanoseconds() : 0;
  const int status = ioctl(machine->vcpu, KVM_SET_GUEST_DEBUG, debug);
  if (metrics != NULL && metrics->enabled) {
    const uint64_t finished = monotonic_nanoseconds();
    metrics->kvm_dpmi_debug_update_calls++;
    if (finished >= started) metrics->kvm_dpmi_debug_update_nanoseconds += finished - started;
  }
  machine->debug_breakpoint_known = status == 0 && cacheable;
  if (machine->debug_breakpoint_known) machine->debug_breakpoint = breakpoint.arch.debugreg[0];
  return status;
}
int daze_kvm_machine_run(DazeKvmMachine *machine) {
  const int status = ioctl(machine->vcpu, KVM_RUN, 0);
  machine->debug_io_exit =
    status == 0 && ((const struct kvm_run *)machine->run)->exit_reason == KVM_EXIT_IO;
  if (!machine->debug_io_exit) machine->debug_breakpoint_known = 0;
  return status;
}
int daze_kvm_machine_drain_io(DazeKvmMachine *machine) {
  if (machine == NULL || machine->vcpu < 0 || machine->run == NULL ||
      machine->run_size < sizeof(struct kvm_run) || !machine->immediate_exit_supported) {
    errno = EINVAL;
    return DAZE_KVM_MACHINE_INVALID;
  }
  struct kvm_run *run = machine->run;
  if (run->immediate_exit || run->kvm_dirty_regs) {
    errno = EBUSY;
    return DAZE_KVM_MACHINE_INVALID;
  }
  DazeRunMetrics *const metrics = machine->run_metrics;
  const uint64_t started = metrics != NULL && metrics->enabled ? monotonic_nanoseconds() : 0;
  run->immediate_exit = 1;
  const int status = daze_kvm_machine_run(machine);
  const int error = errno;
  run->immediate_exit = 0;
  const int completed = status == -1 && error == EINTR;
  if (metrics != NULL && metrics->enabled) {
    metrics->kvm_io_drain_calls++;
    metrics->kvm_io_drain_nanoseconds += monotonic_nanoseconds() - started;
    metrics->kvm_io_drain_failures += !completed;
  }
  if (!completed) {
    errno = status == 0 ? EPROTO : error;
    return DAZE_KVM_MACHINE_FAILED;
  }
  return DAZE_KVM_MACHINE_OK;
}
/* Sync reads are valid only after a completed KVM_RUN; see machine_access.h. */
int daze_kvm_machine_get_regs(DazeKvmMachine *m, struct kvm_regs *regs) {
  if (m == NULL || regs == NULL || m->vcpu < 0 || m->run == NULL) return DAZE_KVM_MACHINE_INVALID;
  if ((m->sync_regs_mask & KVM_SYNC_X86_REGS) != 0) {
    *regs = ((const struct kvm_run *)m->run)->s.regs.regs;
    if (m->run_metrics != NULL && m->run_metrics->enabled)
      m->run_metrics->kvm_regs_sync_get_calls++;
    return DAZE_KVM_MACHINE_OK;
  }
  return ioctl(m->vcpu, KVM_GET_REGS, regs) == 0 ? DAZE_KVM_MACHINE_OK : DAZE_KVM_MACHINE_FAILED;
}
int daze_kvm_machine_get_sregs(DazeKvmMachine *m, struct kvm_sregs *sregs) {
  if (m == NULL || sregs == NULL || m->vcpu < 0 || m->run == NULL) return DAZE_KVM_MACHINE_INVALID;
  if ((m->sync_regs_mask & KVM_SYNC_X86_SREGS) != 0) {
    *sregs = ((const struct kvm_run *)m->run)->s.regs.sregs;
    if (m->run_metrics != NULL && m->run_metrics->enabled)
      m->run_metrics->kvm_regs_sync_get_calls++;
    return DAZE_KVM_MACHINE_OK;
  }
  return ioctl(m->vcpu, KVM_GET_SREGS, sregs) == 0 ? DAZE_KVM_MACHINE_OK : DAZE_KVM_MACHINE_FAILED;
}
int daze_kvm_machine_set_regs(DazeKvmMachine *m, const struct kvm_regs *regs) {
  if (m == NULL || regs == NULL || m->vcpu < 0 || m->run == NULL) return DAZE_KVM_MACHINE_INVALID;
  daze_kvm_machine_debug_invalidate(m);
  if ((m->sync_regs_mask & KVM_SYNC_X86_REGS) != 0) {
    struct kvm_run *run = m->run;
    run->s.regs.regs = *regs;
    run->kvm_valid_regs |= KVM_SYNC_X86_REGS;
    run->kvm_dirty_regs |= KVM_SYNC_X86_REGS;
    if (m->run_metrics != NULL && m->run_metrics->enabled)
      m->run_metrics->kvm_regs_sync_set_calls++;
    return DAZE_KVM_MACHINE_OK;
  }
  return ioctl(m->vcpu, KVM_SET_REGS, regs) == 0 ? DAZE_KVM_MACHINE_OK : DAZE_KVM_MACHINE_FAILED;
}
int daze_kvm_machine_set_sregs(DazeKvmMachine *m, const struct kvm_sregs *sregs) {
  if (m == NULL || sregs == NULL || m->vcpu < 0 || m->run == NULL) return DAZE_KVM_MACHINE_INVALID;
  daze_kvm_machine_debug_invalidate(m);
  if ((m->sync_regs_mask & KVM_SYNC_X86_SREGS) != 0) {
    struct kvm_run *run = m->run;
    run->s.regs.sregs = *sregs;
    run->kvm_valid_regs |= KVM_SYNC_X86_SREGS;
    run->kvm_dirty_regs |= KVM_SYNC_X86_SREGS;
    if (m->run_metrics != NULL && m->run_metrics->enabled)
      m->run_metrics->kvm_regs_sync_set_calls++;
    return DAZE_KVM_MACHINE_OK;
  }
  return ioctl(m->vcpu, KVM_SET_SREGS, sregs) == 0 ? DAZE_KVM_MACHINE_OK : DAZE_KVM_MACHINE_FAILED;
}
/* Raw ioctl installs do not refresh sync state. Mirror them before subsequent sync
 * readers, without marking pending writes. */
int daze_kvm_machine_sync_refresh(DazeKvmMachine *m) {
  if (m == NULL || m->vcpu < 0 || m->run == NULL) return DAZE_KVM_MACHINE_INVALID;
  struct kvm_run *run = m->run;
  if ((m->sync_regs_mask & KVM_SYNC_X86_REGS) != 0 &&
      ioctl(m->vcpu, KVM_GET_REGS, &run->s.regs.regs) != 0)
    return DAZE_KVM_MACHINE_FAILED;
  if ((m->sync_regs_mask & KVM_SYNC_X86_SREGS) != 0 &&
      ioctl(m->vcpu, KVM_GET_SREGS, &run->s.regs.sregs) != 0)
    return DAZE_KVM_MACHINE_FAILED;
  return DAZE_KVM_MACHINE_OK;
}
int daze_kvm_machine_write(void *context, uint32_t a, const void *b, size_t n) {
  DazeKvmMachine *m = context;
  if (!m || !m->guest || !b || a > m->guest_size || n > m->guest_size - a) return 0;
  memcpy((uint8_t *)m->guest + a, b, n);
  return 1;
}
void daze_kvm_machine_snapshot_dispose(DazeKvmMachineSnapshot *snapshot) {
  if (snapshot == NULL) return;
  if (snapshot->guest_bytes != NULL) munmap(snapshot->guest_bytes, snapshot->guest_size);
  free(snapshot->cpu_state);
  *snapshot = (DazeKvmMachineSnapshot){0};
}
int daze_kvm_machine_snapshot_take(const DazeKvmMachine *machine,
                                   DazeKvmMachineSnapshot *snapshot) {
  if (machine == NULL || snapshot == NULL || machine->guest == NULL || machine->vcpu < 0 ||
      machine->guest_size == 0 || daze_kvm_write_batch_pending(machine))
    return DAZE_KVM_MACHINE_INVALID;
  DazeKvmMachineSnapshot candidate = {.guest_size = machine->guest_size,
                                      .write_batch_installed = machine->write_batch_installed};
  const size_t chunks = (candidate.guest_size - 1) / sizeof(snapshot_zero_chunk) + 1;
  const size_t bitmap_bytes = (chunks - 1) / 8 + 1;
  if (bitmap_bytes > SIZE_MAX - sizeof(DazeKvmMachineCpuState)) return DAZE_KVM_MACHINE_FAILED;
  /* Keep zero backing lazy even after repeated child EXEC snapshots. */
  candidate.guest_bytes =
    mmap(NULL, candidate.guest_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (candidate.guest_bytes == MAP_FAILED) return DAZE_KVM_MACHINE_FAILED;
  candidate.cpu_state = calloc(1, sizeof(DazeKvmMachineCpuState) + bitmap_bytes);
  if (candidate.guest_bytes == NULL || candidate.cpu_state == NULL) {
    daze_kvm_machine_snapshot_dispose(&candidate);
    return DAZE_KVM_MACHINE_FAILED;
  }
  DazeKvmMachineCpuState *state = candidate.cpu_state;
  if (ioctl(machine->vcpu, KVM_GET_REGS, &state->regs) < 0 ||
      ioctl(machine->vcpu, KVM_GET_SREGS, &state->sregs) < 0) {
    daze_kvm_machine_snapshot_dispose(&candidate);
    return DAZE_KVM_MACHINE_FAILED;
  }
  for (size_t offset = 0; offset < candidate.guest_size;) {
    const size_t remaining = candidate.guest_size - offset;
    const size_t length =
      remaining < sizeof(snapshot_zero_chunk) ? remaining : sizeof(snapshot_zero_chunk);
    const uint8_t *const source = (const uint8_t *)machine->guest + offset;
    if (memcmp(source, snapshot_zero_chunk, length) != 0) {
      memcpy((uint8_t *)candidate.guest_bytes + offset, source, length);
      const size_t chunk = offset / sizeof(snapshot_zero_chunk);
      state->nonzero_chunks[chunk / 8] |= (uint8_t)(1u << (chunk % 8));
    }
    offset += length;
  }
  candidate.valid = 1;
  daze_kvm_machine_snapshot_dispose(snapshot);
  *snapshot = candidate;
  return DAZE_KVM_MACHINE_OK;
}
int daze_kvm_machine_snapshot_restore(DazeKvmMachine *machine,
                                      const DazeKvmMachineSnapshot *snapshot) {
  if (machine == NULL || snapshot == NULL || !snapshot->valid || machine->guest == NULL ||
      machine->vcpu < 0 || snapshot->guest_bytes == NULL || snapshot->cpu_state == NULL ||
      snapshot->guest_size != machine->guest_size || daze_kvm_write_batch_pending(machine))
    return DAZE_KVM_MACHINE_INVALID;
  const DazeKvmMachineCpuState *state = snapshot->cpu_state;
  daze_kvm_machine_debug_invalidate(machine);
  if (ioctl(machine->vcpu, KVM_SET_SREGS, &state->sregs) < 0 ||
      ioctl(machine->vcpu, KVM_SET_REGS, &state->regs) < 0)
    return DAZE_KVM_MACHINE_FAILED;
  daze_kvm_rm_entry_sync_metrics(machine);
  for (size_t offset = 0; offset < machine->guest_size;) {
    const size_t remaining = machine->guest_size - offset;
    const size_t length = remaining < 4096 ? remaining : 4096;
    uint8_t *const destination = (uint8_t *)machine->guest + offset;
    const size_t chunk = offset / sizeof(snapshot_zero_chunk);
    const uint8_t *const source = (state->nonzero_chunks[chunk / 8] & (1u << (chunk % 8)))
                                    ? (const uint8_t *)snapshot->guest_bytes + offset
                                    : snapshot_zero_chunk;
    if (memcmp(destination, source, length) != 0) memcpy(destination, source, length);
    offset += length;
  }
  daze_kvm_rm_entry_invalidate(machine);
  machine->write_batch_installed = snapshot->write_batch_installed;
  daze_kvm_write_batch_revoke(machine);
  return daze_kvm_machine_sync_refresh(machine);
}
int daze_kvm_machine_set_real_mode(DazeKvmMachine *m, uint16_t cs, uint16_t ip, uint16_t ss,
                                   uint16_t sp, uint16_t ds, uint16_t es) {
  if (!m || !m->guest || (uint32_t)cs * 16 + ip >= m->guest_size) return DAZE_KVM_MACHINE_INVALID;
  daze_kvm_machine_debug_invalidate(m);
  struct kvm_sregs s;
  if (ioctl(m->vcpu, KVM_GET_SREGS, &s) < 0) return DAZE_KVM_MACHINE_FAILED;
  s.cs = seg(cs);
  s.ss = seg(ss);
  s.ds = seg(ds);
  s.es = seg(es);
  s.fs = seg(0);
  s.gs = seg(0);
  s.cr0 = 0;
  s.cr4 = 0;
  s.efer = 0;
  if (ioctl(m->vcpu, KVM_SET_SREGS, &s) < 0) return DAZE_KVM_MACHINE_FAILED;
  struct kvm_regs r = {.rip = ip, .rsp = sp, .rflags = 2};
  return ioctl(m->vcpu, KVM_SET_REGS, &r) < 0 ? DAZE_KVM_MACHINE_FAILED : DAZE_KVM_MACHINE_OK;
}
int daze_kvm_machine_set_general_registers(DazeKvmMachine *m, uint16_t ax, uint16_t bx, uint16_t cx,
                                           uint16_t dx, uint16_t si, uint16_t di) {
  if (m == NULL) return DAZE_KVM_MACHINE_INVALID;
  daze_kvm_machine_debug_invalidate(m);
  struct kvm_regs regs;
  if (ioctl(m->vcpu, KVM_GET_REGS, &regs) < 0) return DAZE_KVM_MACHINE_FAILED;
  regs.rax = ax;
  regs.rbx = bx;
  regs.rcx = cx;
  regs.rdx = dx;
  regs.rsi = si;
  regs.rdi = di;
  return ioctl(m->vcpu, KVM_SET_REGS, &regs) < 0 ? DAZE_KVM_MACHINE_FAILED : DAZE_KVM_MACHINE_OK;
}
int daze_kvm_machine_run_port_access(DazeKvmMachine *m, DazeKvmPortAccess *access) {
  if (access != NULL) *access = (DazeKvmPortAccess){0};
  if (!m || !m->run || !access) return DAZE_KVM_MACHINE_INVALID;
  DazeRunMetrics *const metrics = m->run_metrics;
  const uint64_t started = metrics != NULL && metrics->enabled ? monotonic_nanoseconds() : 0;
  const int run_status = daze_kvm_machine_run(m);
  if (metrics != NULL && metrics->enabled) {
    const uint64_t finished = monotonic_nanoseconds();
    metrics->kvm_port_run_calls++;
    if (finished >= started) metrics->kvm_port_run_nanoseconds += finished - started;
  }
  if (run_status < 0) return DAZE_KVM_MACHINE_FAILED;
  struct kvm_run *run = m->run;
  if (run->exit_reason != KVM_EXIT_IO || run->io.size != 1 || run->io.count != 1 ||
      (run->io.direction != KVM_EXIT_IO_IN && run->io.direction != KVM_EXIT_IO_OUT)) {
    return DAZE_KVM_MACHINE_FAILED;
  }
  access->direction = run->io.direction;
  access->port = run->io.port;
  access->value =
    run->io.direction == KVM_EXIT_IO_OUT ? *((uint8_t *)run + run->io.data_offset) : 0;
  return DAZE_KVM_MACHINE_OK;
}
int daze_kvm_machine_supply_port_in(DazeKvmMachine *m, uint8_t value) {
  if (!m || !m->run) return DAZE_KVM_MACHINE_INVALID;
  struct kvm_run *run = m->run;
  if (run->exit_reason != KVM_EXIT_IO || run->io.direction != KVM_EXIT_IO_IN || run->io.size != 1 ||
      run->io.count != 1) {
    return DAZE_KVM_MACHINE_FAILED;
  }
  *((uint8_t *)run + run->io.data_offset) = value;
  return DAZE_KVM_MACHINE_OK;
}
int daze_kvm_machine_capture_exit(const DazeKvmMachine *m,
                                  DazeKvmMachineExitObservation *observation) {
  if (observation != NULL) *observation = (DazeKvmMachineExitObservation){0};
  if (m == NULL || m->run == NULL || m->vcpu < 0 || observation == NULL)
    return DAZE_KVM_MACHINE_INVALID;
  struct kvm_regs regs;
  struct kvm_sregs sregs;
  if (ioctl(m->vcpu, KVM_GET_REGS, &regs) < 0 || ioctl(m->vcpu, KVM_GET_SREGS, &sregs) < 0)
    return DAZE_KVM_MACHINE_FAILED;
  *observation = (DazeKvmMachineExitObservation){
    .present = 1,
    .exit_reason = ((const struct kvm_run *)m->run)->exit_reason,
    .cs = sregs.cs.selector,
    .ss = sregs.ss.selector,
    .rip = regs.rip,
    .rsp = regs.rsp,
    .rax = regs.rax,
    .rbx = regs.rbx,
    .rcx = regs.rcx,
    .rdx = regs.rdx,
    .rsi = regs.rsi,
    .rdi = regs.rdi,
  };
  return DAZE_KVM_MACHINE_OK;
}
#else
DazeKvmMachineInitResult daze_kvm_machine_init_with_seam(DazeKvmMachine *m, size_t n,
                                                         const DazeKvmMachineSeam *seam) {
  (void)seam;
  if (m != NULL) *m = (DazeKvmMachine){.kvm = -1, .vm = -1, .vcpu = -1};
  if (m == NULL || n == 0)
    return (DazeKvmMachineInitResult){DAZE_KVM_MACHINE_INVALID, DAZE_KVM_MACHINE_STAGE_NONE, 0};
  DazeKvmMachineInitResult result = {DAZE_KVM_MACHINE_UNAVAILABLE, DAZE_KVM_MACHINE_STAGE_NONE, 0};
  return result;
}
void daze_kvm_machine_destroy(DazeKvmMachine *m) {
  if (m) memset(m, 0, sizeof(*m));
}
void daze_kvm_machine_set_run_metrics(DazeKvmMachine *m, DazeRunMetrics *metrics) {
  if (m != NULL) m->run_metrics = metrics;
}
void daze_kvm_machine_snapshot_dispose(DazeKvmMachineSnapshot *snapshot) {
  if (snapshot != NULL) *snapshot = (DazeKvmMachineSnapshot){0};
}
int daze_kvm_machine_snapshot_take(const DazeKvmMachine *machine,
                                   DazeKvmMachineSnapshot *snapshot) {
  (void)machine;
  if (snapshot != NULL) *snapshot = (DazeKvmMachineSnapshot){0};
  return DAZE_KVM_MACHINE_UNAVAILABLE;
}
int daze_kvm_machine_snapshot_restore(DazeKvmMachine *machine,
                                      const DazeKvmMachineSnapshot *snapshot) {
  (void)machine;
  (void)snapshot;
  return DAZE_KVM_MACHINE_UNAVAILABLE;
}
int daze_kvm_machine_write(void *c, uint32_t a, const void *b, size_t n) {
  (void)c;
  (void)a;
  (void)b;
  (void)n;
  return 0;
}
int daze_kvm_machine_init(DazeKvmMachine *m, size_t n) {
  return daze_kvm_machine_init_with_seam(m, n, NULL).status;
}
int daze_kvm_machine_compiled(void) {
  return 0;
}
int daze_kvm_machine_set_real_mode(DazeKvmMachine *m, uint16_t a, uint16_t b, uint16_t c,
                                   uint16_t d, uint16_t e, uint16_t f) {
  (void)m;
  (void)a;
  (void)b;
  (void)c;
  (void)d;
  (void)e;
  (void)f;
  return DAZE_KVM_MACHINE_UNAVAILABLE;
}
int daze_kvm_machine_set_general_registers(DazeKvmMachine *m, uint16_t a, uint16_t b, uint16_t c,
                                           uint16_t d, uint16_t e, uint16_t f) {
  (void)m;
  (void)a;
  (void)b;
  (void)c;
  (void)d;
  (void)e;
  (void)f;
  return DAZE_KVM_MACHINE_UNAVAILABLE;
}
int daze_kvm_machine_run_port_access(DazeKvmMachine *m, DazeKvmPortAccess *access) {
  (void)m;
  if (access != NULL) *access = (DazeKvmPortAccess){0};
  return DAZE_KVM_MACHINE_UNAVAILABLE;
}
int daze_kvm_machine_supply_port_in(DazeKvmMachine *m, uint8_t value) {
  (void)m;
  (void)value;
  return DAZE_KVM_MACHINE_UNAVAILABLE;
}
int daze_kvm_machine_capture_exit(const DazeKvmMachine *m,
                                  DazeKvmMachineExitObservation *observation) {
  (void)m;
  if (observation != NULL) *observation = (DazeKvmMachineExitObservation){0};
  return DAZE_KVM_MACHINE_UNAVAILABLE;
}
#endif
