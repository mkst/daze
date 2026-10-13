#include "interrupt_vector.h"
#include "runner_resume.h"

#include "kvm_bytes.h"
#include "kvm_range.h"
#include "machine_access.h"
#include "monotonic_clock.h"
#include "port.h"

#include <string.h>

#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
#include <linux/kvm.h>
#include <sys/ioctl.h>

static void record_gate_time(DazeRunMetrics *metrics, uint64_t started, uint64_t *calls,
                             uint64_t *nanoseconds) {
  if (metrics == NULL || !metrics->enabled) return;
  const uint64_t finished = monotonic_nanoseconds();
  (*calls)++;
  if (finished >= started) *nanoseconds += finished - started;
}

static int range_valid(const DazeKvmMachine *machine, uint32_t address, size_t size) {
  return machine != NULL && machine->guest != NULL &&
         daze_kvm_range_fits(machine->guest_size, address, size);
}

static void real_data_segment(struct kvm_segment *segment, uint16_t selector) {
  *segment = (struct kvm_segment){.base = (uint32_t)selector << 4,
                                  .limit = 0xffff,
                                  .selector = selector,
                                  .type = 3,
                                  .present = 1,
                                  .dpl = 3,
                                  .s = 1};
}

static uint64_t replace_low16(uint64_t value, uint16_t low) {
  return (value & ~UINT64_C(0xffff)) | low;
}

int daze_kvm_runner_gate_frame_capture(DazeKvmMachine *machine, uint8_t vector,
                                       DazeKvmRunnerGateFrame *frame) {
  if (frame != NULL) *frame = (DazeKvmRunnerGateFrame){0};
  if (machine == NULL || machine->vcpu < 0 || machine->guest == NULL || frame == NULL) {
    return DAZE_KVM_RUNNER_GATE_RESUME_INVALID;
  }
  const uint64_t started =
    machine->run_metrics != NULL && machine->run_metrics->enabled ? monotonic_nanoseconds() : 0;
  struct kvm_regs regs;
  struct kvm_sregs sregs;
  /* Capture and reply must use compatible register channels; pending sync writes cannot
   * be mixed with raw installs. */
  if (daze_kvm_machine_get_regs(machine, &regs) != DAZE_KVM_MACHINE_OK ||
      daze_kvm_machine_get_sregs(machine, &sregs) != DAZE_KVM_MACHINE_OK ||
      regs.rsp > UINT16_MAX - 7u) {
    return DAZE_KVM_RUNNER_GATE_RESUME_FAILED;
  }
  const uint32_t stack = (uint32_t)sregs.ss.base + (uint16_t)regs.rsp;
  if (stack < sregs.ss.base || !range_valid(machine, stack, 8)) {
    return DAZE_KVM_RUNNER_GATE_RESUME_INVALID;
  }
  const uint8_t *const bytes = (const uint8_t *)machine->guest + stack;
  *frame = (DazeKvmRunnerGateFrame){.vector = vector,
                                    .ax = daze_read_u16(bytes),
                                    .bx = (uint16_t)regs.rbx,
                                    .cx = (uint16_t)regs.rcx,
                                    .dx = (uint16_t)regs.rdx,
                                    .si = (uint16_t)regs.rsi,
                                    .di = (uint16_t)regs.rdi,
                                    .ds = sregs.ds.selector,
                                    .es = sregs.es.selector,
                                    .return_ip = daze_read_u16(bytes + 2),
                                    .return_cs = daze_read_u16(bytes + 4),
                                    .flags = daze_read_u16(bytes + 6),
                                    .ss = sregs.ss.selector,
                                    .sp = (uint16_t)regs.rsp};
  if (machine->run_metrics != NULL) {
    record_gate_time(machine->run_metrics, started,
                     &machine->run_metrics->kvm_gate_frame_capture_calls,
                     &machine->run_metrics->kvm_gate_frame_capture_nanoseconds);
  }
  return DAZE_KVM_RUNNER_GATE_RESUME_OK;
}

int daze_kvm_runner_gate_frame_reply(DazeKvmMachine *machine, const DazeKvmRunnerGateFrame *frame,
                                     const uint8_t reply[DAZE_KVM_RUNNER_GATE_REPLY_SIZE]) {
  if (machine == NULL || machine->vcpu < 0 || machine->guest == NULL || frame == NULL ||
      reply == NULL) {
    return DAZE_KVM_RUNNER_GATE_RESUME_INVALID;
  }
  const uint64_t started =
    machine->run_metrics != NULL && machine->run_metrics->enabled ? monotonic_nanoseconds() : 0;
  struct kvm_regs regs;
  struct kvm_sregs sregs;
  if (daze_kvm_machine_get_regs(machine, &regs) != DAZE_KVM_MACHINE_OK ||
      daze_kvm_machine_get_sregs(machine, &sregs) != DAZE_KVM_MACHINE_OK ||
      sregs.ss.selector != frame->ss || (uint16_t)regs.rsp != frame->sp) {
    return DAZE_KVM_RUNNER_GATE_RESUME_INVALID;
  }
  const uint32_t flags_address = (uint32_t)sregs.ss.base + frame->sp + 6u;
  if (flags_address < sregs.ss.base || !range_valid(machine, flags_address, sizeof(uint16_t))) {
    return DAZE_KVM_RUNNER_GATE_RESUME_INVALID;
  }
  const struct kvm_regs before = regs;
  const uint8_t restoring_gate[] = {
    0x50,                 /* push ax */
    0xb0, frame->vector,  /* mov al,vector */
    0xe6, DAZE_PORT_GATE, /* out 0xf4,al */
    0x58,                 /* pop ax */
    0xcf                  /* iret */
  };
  const uint64_t gate_address = sregs.cs.base + regs.rip - 3u;
  const int restores_ax = regs.rip >= 3 && gate_address <= UINT32_MAX &&
                          range_valid(machine, (uint32_t)gate_address, sizeof(restoring_gate)) &&
                          memcmp((const uint8_t *)machine->guest + gate_address, restoring_gate,
                                 sizeof(restoring_gate)) == 0;
  regs.rax = restores_ax ? regs.rax : replace_low16(regs.rax, daze_read_u16(reply));
  regs.rbx = replace_low16(regs.rbx, daze_read_u16(reply + 2));
  regs.rcx = replace_low16(regs.rcx, daze_read_u16(reply + 4));
  regs.rdx = replace_low16(regs.rdx, daze_read_u16(reply + 6));
  regs.rsi = replace_low16(regs.rsi, daze_read_u16(reply + 8));
  regs.rdi = replace_low16(regs.rdi, daze_read_u16(reply + 10));
  const struct kvm_segment previous_es = sregs.es;
  real_data_segment(&sregs.es, daze_read_u16(reply + 12));
  if (!(sregs.cr0 & 1) && !(regs.rflags & (1u << 17)) && previous_es.dpl == 0) {
    /* Retain the already-running real-mode cache when only DPL normalization differs. */
    struct kvm_segment retained_es = sregs.es;
    retained_es.dpl = 0;
    if (memcmp(&previous_es, &retained_es, sizeof(previous_es)) == 0) sregs.es = previous_es;
  }
  const int es_changed = memcmp(&previous_es, &sregs.es, sizeof(previous_es)) != 0;
  daze_write_u16((uint8_t *)machine->guest + flags_address - 6u, daze_read_u16(reply));
  daze_write_u16((uint8_t *)machine->guest + flags_address, daze_read_u16(reply + 14));
  /* Use raw SETs: downstream ioctl installs bypass pending sync writes, which the next
   * KVM_RUN could otherwise overwrite. */
  if ((es_changed && ioctl(machine->vcpu, KVM_SET_SREGS, &sregs) != 0) ||
      ((!restores_ax || memcmp(&before, &regs, sizeof(regs)) != 0) &&
       ioctl(machine->vcpu, KVM_SET_REGS, &regs) != 0)) {
    return DAZE_KVM_RUNNER_GATE_RESUME_FAILED;
  }
  if (machine->run_metrics != NULL) {
    record_gate_time(machine->run_metrics, started,
                     &machine->run_metrics->kvm_gate_frame_reply_calls,
                     &machine->run_metrics->kvm_gate_frame_reply_nanoseconds);
  }
  return DAZE_KVM_RUNNER_GATE_RESUME_OK;
}

int daze_kvm_runner_gate_frame_retire_out(DazeKvmMachine *machine) {
  if (machine == NULL || machine->vcpu < 0 || machine->guest == NULL) {
    return DAZE_KVM_RUNNER_GATE_RESUME_INVALID;
  }
  struct kvm_regs regs;
  struct kvm_sregs sregs;
  if (ioctl(machine->vcpu, KVM_GET_REGS, &regs) < 0 ||
      ioctl(machine->vcpu, KVM_GET_SREGS, &sregs) < 0) {
    return DAZE_KVM_RUNNER_GATE_RESUME_FAILED;
  }
  const uint64_t linear = sregs.cs.base + regs.rip;
  if (linear > UINT32_MAX || !range_valid(machine, (uint32_t)linear, 2)) {
    return DAZE_KVM_RUNNER_GATE_RESUME_INVALID;
  }
  const uint8_t *bytes = (const uint8_t *)machine->guest + linear;
  if (bytes[0] != 0xe6 || bytes[1] != DAZE_PORT_GATE) return DAZE_KVM_RUNNER_GATE_RESUME_INVALID;
  regs.rip += 2;
  return ioctl(machine->vcpu, KVM_SET_REGS, &regs) < 0 ? DAZE_KVM_RUNNER_GATE_RESUME_FAILED
                                                       : DAZE_KVM_RUNNER_GATE_RESUME_OK;
}

int daze_kvm_runner_gate_frame_set_ds(DazeKvmMachine *machine, uint16_t ds) {
  if (machine == NULL || machine->vcpu < 0) return DAZE_KVM_RUNNER_GATE_RESUME_INVALID;
  struct kvm_sregs sregs;
  if (ioctl(machine->vcpu, KVM_GET_SREGS, &sregs) < 0) return DAZE_KVM_RUNNER_GATE_RESUME_FAILED;
  real_data_segment(&sregs.ds, ds);
  return ioctl(machine->vcpu, KVM_SET_SREGS, &sregs) < 0 ? DAZE_KVM_RUNNER_GATE_RESUME_FAILED
                                                         : DAZE_KVM_RUNNER_GATE_RESUME_OK;
}

int daze_kvm_runner_gate_resume_input_valid(const DazeKvmRunnerGateResumeInput *input) {
  return input != NULL && input->machine != NULL && input->machine->vcpu >= 0 &&
         input->machine->run != NULL && input->handoff != NULL && input->handoff->valid &&
         range_valid(input->machine, input->mailbox_address, DAZE_KVM_RUNNER_GATE_REPLY_SIZE);
}

int daze_kvm_runner_gate_reply(const DazeKvmRunnerGateResumeInput *input) {
  if (!daze_kvm_runner_gate_resume_input_valid(input)) return DAZE_KVM_RUNNER_GATE_RESUME_INVALID;
  memcpy((uint8_t *)input->machine->guest + input->mailbox_address, input->reply,
         DAZE_KVM_RUNNER_GATE_REPLY_SIZE);
  return DAZE_KVM_RUNNER_GATE_RESUME_OK;
}

int daze_kvm_runner_gate_resume_hlt(const DazeKvmRunnerGateResumeInput *input,
                                    DazeKvmRunnerGateResumeResult *result) {
  if (result != NULL) *result = (DazeKvmRunnerGateResumeResult){0};
  if (result == NULL || !daze_kvm_runner_gate_resume_input_valid(input))
    return DAZE_KVM_RUNNER_GATE_RESUME_INVALID;
  if (daze_kvm_runner_gate_reply(input) != DAZE_KVM_RUNNER_GATE_RESUME_OK)
    return DAZE_KVM_RUNNER_GATE_RESUME_INVALID;
  if (ioctl(input->machine->vcpu, KVM_RUN, 0) < 0 ||
      ((const struct kvm_run *)input->machine->run)->exit_reason != KVM_EXIT_HLT) {
    return DAZE_KVM_RUNNER_GATE_RESUME_FAILED;
  }
  struct kvm_regs regs;
  struct kvm_sregs sregs;
  if (ioctl(input->machine->vcpu, KVM_GET_REGS, &regs) < 0 ||
      ioctl(input->machine->vcpu, KVM_GET_SREGS, &sregs) < 0) {
    return DAZE_KVM_RUNNER_GATE_RESUME_FAILED;
  }
  *result = (DazeKvmRunnerGateResumeResult){
    .cr0 = (uint32_t)sregs.cr0,
    .rip = (uint32_t)regs.rip,
    .rflags = (uint32_t)regs.rflags,
    .cs = sregs.cs.selector,
    .ss = sregs.ss.selector,
    .sp = (uint16_t)regs.rsp,
    .ax = (uint16_t)regs.rax,
    .bx = (uint16_t)regs.rbx,
    .cx = (uint16_t)regs.rcx,
    .dx = (uint16_t)regs.rdx,
    .si = (uint16_t)regs.rsi,
    .di = (uint16_t)regs.rdi,
    .ds = sregs.ds.selector,
    .es = sregs.es.selector,
  };
  return DAZE_KVM_RUNNER_GATE_RESUME_OK;
}
#else
int daze_kvm_runner_gate_frame_capture(DazeKvmMachine *machine, uint8_t vector,
                                       DazeKvmRunnerGateFrame *frame) {
  (void)machine;
  (void)vector;
  if (frame != NULL) *frame = (DazeKvmRunnerGateFrame){0};
  return DAZE_KVM_RUNNER_GATE_RESUME_UNAVAILABLE;
}
int daze_kvm_runner_gate_frame_reply(DazeKvmMachine *machine, const DazeKvmRunnerGateFrame *frame,
                                     const uint8_t reply[DAZE_KVM_RUNNER_GATE_REPLY_SIZE]) {
  (void)machine;
  (void)frame;
  (void)reply;
  return DAZE_KVM_RUNNER_GATE_RESUME_UNAVAILABLE;
}
int daze_kvm_runner_gate_frame_retire_out(DazeKvmMachine *machine) {
  (void)machine;
  return DAZE_KVM_RUNNER_GATE_RESUME_UNAVAILABLE;
}
int daze_kvm_runner_gate_reply(const DazeKvmRunnerGateResumeInput *input) {
  (void)input;
  return DAZE_KVM_RUNNER_GATE_RESUME_UNAVAILABLE;
}
int daze_kvm_runner_gate_resume_hlt(const DazeKvmRunnerGateResumeInput *input,
                                    DazeKvmRunnerGateResumeResult *result) {
  (void)input;
  if (result != NULL) *result = (DazeKvmRunnerGateResumeResult){0};
  return DAZE_KVM_RUNNER_GATE_RESUME_UNAVAILABLE;
}
int daze_kvm_runner_gate_frame_set_ds(DazeKvmMachine *machine, uint16_t ds) {
  (void)machine;
  (void)ds;
  return DAZE_KVM_RUNNER_GATE_RESUME_UNAVAILABLE;
}
#endif
