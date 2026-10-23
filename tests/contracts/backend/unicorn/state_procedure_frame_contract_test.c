#include "unicorn_services.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "transition_artifacts.h"

enum {
  k_gdtr_operand = 0x0080,
  k_entry_address = 0x1000,
  k_state_code_selector = 0x0028,
  k_state_code_base = k_dpmi_entry_segment << 4,
  k_state_stub_offset = 0x0100,
  k_state_stub_linear = k_state_code_base + k_state_stub_offset,
  k_caller_selector = 0x0008,
  k_caller_base = 0x10000,
  k_narrow_stack_selector = 0x0040,
  k_wide_stack_selector = 0x0050,
  k_successor_offset = 0x0160,
  k_stack_base = 0x40000,
  k_stack_seed_sp = 0x3ef0,
  k_stack_words = 10,
  k_call_ip = 0x011a,
  k_after_call_ip = 0x011f,
  k_ret_ip = 0x0122,
  /* ESP of the modelled eight-byte EIP:CS-slot frame: the widened frame for the
   * 16-bit caller starts here, and the caller's pending near return follows it
   * at k_stack_seed_sp. */
  k_wide_frame_esp = 0x3ee8,
};

static const uint8_t k_preamble[] = {
  0xfa,                               /* cli */
  0x2e, 0x0f, 0x01, 0x16, 0x80, 0x00, /* lgdt cs:[0x80] */
  0x0f, 0x20, 0xc0,                   /* mov eax,cr0 */
  0x66, 0x83, 0xc8, 0x01,             /* or eax,0x1 */
  0x0f, 0x22, 0xc0,                   /* mov cr0,eax */
  0xea, 0x00, 0x01, 0x08, 0x00        /* jmp far 0x8:0x100 */
};

static const uint8_t k_caller_far_call[] = {
  0xb8, 0x40, 0x00,                   /* mov ax,0x40 */
  0x8e, 0xd0,                         /* mov ss,ax */
  0x66, 0xbc, 0xf0, 0x3e, 0x00, 0x00, /* mov esp,0x3ef0 */
  0xb8, 0x10, 0x00,                   /* mov ax,0x10 */
  0x8e, 0xd8,                         /* mov ds,ax */
  0x8e, 0xc0,                         /* mov es,ax */
  0x66, 0xbf, 0x00, 0x30, 0x00, 0x00, /* mov edi,0x3000 */
  0x31, 0xc0,                         /* xor ax,ax */
  0x9a, 0x00, 0x01, 0x28, 0x00,       /* call far 0x28:0x100 */
  0xb8, 0x22, 0x22,                   /* mov ax,0x2222 */
  0xc3,                               /* ret */
  0xf4,                               /* hlt */
};

static const uint8_t k_caller_far_jump[] = {
  0xb8, 0x40, 0x00,                   /* mov ax,0x40 */
  0x8e, 0xd0,                         /* mov ss,ax */
  0x66, 0xbc, 0xf0, 0x3e, 0x00, 0x00, /* mov esp,0x3ef0 */
  0xb8, 0x10, 0x00,                   /* mov ax,0x10 */
  0x8e, 0xd8,                         /* mov ds,ax */
  0x8e, 0xc0,                         /* mov es,ax */
  0x66, 0xbf, 0x00, 0x30, 0x00, 0x00, /* mov edi,0x3000 */
  0x31, 0xc0,                         /* xor ax,ax */
  0xea, 0x00, 0x01, 0x28, 0x00,       /* jmp far 0x28:0x100 */
  0xb8, 0x33, 0x33,                   /* mov ax,0x3333 */
  0xc3,                               /* ret */
  0xf4,                               /* hlt */
};

static const uint8_t k_successor[] = {
  0xb8, 0x77, 0x77, /* mov ax,0x7777 */
  0xf4              /* hlt */
};

typedef enum {
  k_case_four_byte_frame_narrow_stack,
  k_case_modeled_wide_frame_narrow_stack,
  k_case_modeled_wide_frame_wide_stack,
  k_case_ambiguous_frame,
} CaseKind;

typedef struct {
  const char *name;
  CaseKind kind;
  uint16_t stack_selector;
  int expect_stack_db;
  uint16_t near_return;
  size_t near_return_size;
  int widen_expected;
  int resume_after_decision;
  int expect_successor;
  uint32_t expect_pre_hook_esp;
  uint16_t expect_pre_hook_words[k_stack_words];
  uint32_t expect_decision_esp;
  uint16_t expect_decision_words[k_stack_words];
  uint32_t expect_post_retf_esp;
  uint32_t expect_ret_value;
} Scenario;

typedef struct {
  const Scenario *scenario;
  int failed;
  int have_far_call;
  uint32_t far_call_esp;
  uint16_t far_call_ss;
  uint16_t far_call_words[k_stack_words];
  int have_pre_hook;
  uint16_t pre_hook_cs;
  uint16_t pre_hook_ip;
  uint32_t pre_hook_esp;
  uint16_t pre_hook_ss;
  uint16_t pre_hook_words[k_stack_words];
  int have_decision;
  uint32_t decision_esp;
  uint16_t decision_words[k_stack_words];
  int have_stub;
  uint32_t stub_esp;
  uint16_t stub_words[k_stack_words];
  int have_post_retf;
  uint16_t post_retf_cs;
  uint16_t post_retf_ip;
  uint32_t post_retf_esp;
  uint16_t post_retf_ss;
  uint16_t post_retf_words[k_stack_words];
  int have_ret;
  uint32_t ret_esp;
  uint32_t ret_value;
  int have_successor;
  uint16_t successor_cs;
  uint16_t successor_ip;
  uint64_t history[24];
  size_t history_count;
  int finished;
} Observation;

static void check(Observation *observation, int condition, const char *format, ...) {
  if (condition) return;
  va_list args;
  va_start(args, format);
  fprintf(stderr, "  CHECK FAILED: ");
  vfprintf(stderr, format, args);
  fprintf(stderr, "\n");
  va_end(args);
  observation->failed = 1;
}

static int read_stack_words(uc_engine *uc, uint32_t esp, uint16_t *words, size_t count) {
  uint32_t base = 0;
  if (!daze_dpmi_selector_base(uc, get_reg16(uc, UC_X86_REG_SS), &base)) return 0;
  return uc_mem_read(uc, base + esp, words, count * sizeof(uint16_t)) == UC_ERR_OK;
}

static void print_words(const char *label, const uint16_t *words, size_t count) {
  fprintf(stderr, "  %s words[0..%zu]=", label, count - 1);
  for (size_t index = 0; index < count; ++index) {
    fprintf(stderr, "%s%04x", index == 0 ? "" : " ", words[index]);
  }
  fprintf(stderr, "\n");
}

static void print_bytes(uc_engine *uc, const char *label, uint64_t address, size_t count) {
  uint8_t bytes[16];
  if (count > sizeof(bytes)) count = sizeof(bytes);
  if (uc_mem_read(uc, address, bytes, count) != UC_ERR_OK) {
    fprintf(stderr, "  %s at %08" PRIx64 " unreadable\n", label, address);
    return;
  }
  fprintf(stderr, "  %s at %08" PRIx64 ":", label, address);
  for (size_t index = 0; index < count; ++index) {
    fprintf(stderr, "%s%02x", index == 0 ? "" : " ", bytes[index]);
  }
  fprintf(stderr, "\n");
}

static int descriptor_db_bit(uc_engine *uc, uint16_t selector) {
  uint8_t flags = 0;
  if (uc_mem_read(uc, k_dpmi_gdt_address + selector + 6, &flags, 1) != UC_ERR_OK) return -1;
  return (flags >> 4) & 1;
}

static void observe_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
  Observation *observation = user_data;
  (void)size;
  if (observation->finished) return;
  if (observation->history_count < sizeof(observation->history) / sizeof(observation->history[0])) {
    observation->history[observation->history_count++] = address;
  }
  const uint16_t cs = get_reg16(uc, UC_X86_REG_CS);
  const uint16_t ip = get_reg16(uc, UC_X86_REG_IP);
  if (cs == k_state_code_selector) {
    if (ip == k_state_stub_offset + 2 && !observation->have_stub) {
      observation->have_stub = 1;
      observation->stub_esp = get_reg32(uc, UC_X86_REG_ESP);
      if (!read_stack_words(uc, observation->stub_esp, observation->stub_words, k_stack_words)) {
        observation->failed = 1;
      }
    }
    return;
  }
  if (ip == k_call_ip && !observation->have_far_call) {
    observation->have_far_call = 1;
    observation->far_call_esp = get_reg32(uc, UC_X86_REG_ESP);
    observation->far_call_ss = get_reg16(uc, UC_X86_REG_SS);
    if (!read_stack_words(uc, observation->far_call_esp, observation->far_call_words,
                          k_stack_words)) {
      observation->failed = 1;
    }
  } else if (ip == k_after_call_ip && !observation->have_post_retf) {
    observation->have_post_retf = 1;
    observation->post_retf_cs = cs;
    observation->post_retf_ip = ip;
    observation->post_retf_esp = get_reg32(uc, UC_X86_REG_ESP);
    observation->post_retf_ss = get_reg16(uc, UC_X86_REG_SS);
    if (!read_stack_words(uc, observation->post_retf_esp, observation->post_retf_words,
                          k_stack_words)) {
      observation->failed = 1;
    }
  } else if (ip == k_ret_ip && !observation->have_ret) {
    observation->have_ret = 1;
    observation->ret_esp = get_reg32(uc, UC_X86_REG_ESP);
    observation->ret_value = 0;
    uint16_t words[1] = {0};
    if (read_stack_words(uc, observation->ret_esp, words, 1)) observation->ret_value = words[0];
  } else if (ip == k_successor_offset && observation->have_ret) {
    observation->have_successor = 1;
    observation->successor_cs = cs;
    observation->successor_ip = ip;
    observation->finished = 1;
    uc_emu_stop(uc);
  }
}

static int build_machine(uc_engine *uc, const Scenario *scenario,
                         const DazeDpmiTransitionArtifacts *artifacts) {
  uint8_t caller[sizeof(k_caller_far_jump)];
  if (scenario->kind == k_case_four_byte_frame_narrow_stack ||
      scenario->kind == k_case_ambiguous_frame) {
    memcpy(caller, k_caller_far_call, sizeof(caller));
    if (caller[26] != 0x9a || caller[27] != 0x00 || caller[28] != 0x01) return 0;
    caller[29] = (uint8_t)k_state_code_selector;
    caller[30] = (uint8_t)(k_state_code_selector >> 8);
  } else {
    memcpy(caller, k_caller_far_jump, sizeof(caller));
    if (caller[26] != 0xea || caller[27] != 0x00 || caller[28] != 0x01) return 0;
    caller[29] = (uint8_t)k_state_code_selector;
    caller[30] = (uint8_t)(k_state_code_selector >> 8);
    const uint32_t frame_esp = k_wide_frame_esp;
    memcpy(caller + 7, &frame_esp, sizeof(frame_esp));
  }
  caller[1] = (uint8_t)scenario->stack_selector;
  caller[2] = (uint8_t)(scenario->stack_selector >> 8);
  if (uc_mem_write(uc, k_gdtr_operand, artifacts->gdtr, sizeof(artifacts->gdtr)) != UC_ERR_OK ||
      uc_mem_write(uc, k_dpmi_gdt_address, artifacts->gdt, sizeof(artifacts->gdt)) != UC_ERR_OK ||
      uc_mem_write(uc, k_dpmi_ldt_address, artifacts->ldt, sizeof(artifacts->ldt)) != UC_ERR_OK ||
      uc_mem_write(uc, k_state_code_base, artifacts->trampoline, sizeof(artifacts->trampoline)) !=
        UC_ERR_OK ||
      uc_mem_write(uc, k_state_stub_linear, artifacts->state_stub, sizeof(artifacts->state_stub)) !=
        UC_ERR_OK ||
      uc_mem_write(uc, k_state_code_base + 0x0120, artifacts->raw_switch_stub,
                   sizeof(artifacts->raw_switch_stub)) != UC_ERR_OK ||
      uc_mem_write(uc, k_entry_address, k_preamble, sizeof(k_preamble)) != UC_ERR_OK ||
      uc_mem_write(uc, k_caller_base + 0x0100, caller, sizeof(caller)) != UC_ERR_OK ||
      uc_mem_write(uc, k_caller_base + k_successor_offset, k_successor, sizeof(k_successor)) !=
        UC_ERR_OK)
    return 0;
  uint8_t pattern[0x100];
  memset(pattern, 0xe1, sizeof(pattern));
  if (uc_mem_write(uc, k_stack_base + 0x3e00, pattern, sizeof(pattern)) != UC_ERR_OK ||
      uc_mem_write(uc, k_stack_base + k_stack_seed_sp, &scenario->near_return,
                   scenario->near_return_size) != UC_ERR_OK)
    return 0;
  if (scenario->kind == k_case_modeled_wide_frame_narrow_stack ||
      scenario->kind == k_case_modeled_wide_frame_wide_stack) {
    /* Modelled, not genuine: this Unicorn build faults a 32-bit far call, so
     * the rig materialises the eight-byte EIP:CS-slot frame a 32-bit caller's
     * CPU would push and enters the gate with a 16-bit far jump. */
    const uint32_t return_ip = k_after_call_ip;
    const uint16_t caller_cs = k_caller_selector;
    uint8_t frame[8] = {0};
    memcpy(frame, &return_ip, sizeof(return_ip));
    memcpy(frame + 4, &caller_cs, sizeof(caller_cs));
    if (uc_mem_write(uc, k_stack_base + k_wide_frame_esp, frame, sizeof(frame)) != UC_ERR_OK) {
      return 0;
    }
  }
  return 1;
}

static int run_scenario(const Scenario *scenario) {
  uc_engine *uc = NULL;
  if (uc_open(UC_ARCH_X86, UC_MODE_16, &uc) != UC_ERR_OK) {
    fprintf(stderr, "  uc_open failed\n");
    return 0;
  }
  int ok = 0;
  DazeUnicornContext context;
  memset(&context, 0, sizeof(context));
  DazeDosfsMounts mounts = {0};
  DazeDosfsHandles handles = {0};
  DazeDosfsFileService files;
  daze_dosfs_file_service_init(&files, &mounts, &handles);
  DazeUnicornInterruptContext interrupt_context = {.context = &context, .files = &files};
  context.engine.debug = 1;
  Observation observation;
  memset(&observation, 0, sizeof(observation));
  observation.scenario = scenario;
  DazeDpmiTransitionArtifacts artifacts;
  const DazeDpmiTransitionDescriptorAddition additions[] = {
    {DAZE_DPMI_TRANSITION_GDT, k_wide_stack_selector, k_stack_base, 0xffff, 0x92, 0x01},
  };
  const DazeDpmiTransitionArtifactInput input = {
    .client_ds = 0x2000,
    .client_ss = 0x4000,
    .return_ip = 0x0100,
    .return_cs = k_caller_base >> 4,
    .psp_segment = k_psp_segment,
    .entry_segment = k_dpmi_entry_segment,
    .gdt_address = k_dpmi_gdt_address,
    .ldt_address = k_dpmi_ldt_address,
    .additions = additions,
    .addition_count = 1,
  };
  fprintf(stderr, "  case %s (SS=%04x)\n", scenario->name, scenario->stack_selector);
  if (!daze_dpmi_transition_artifacts_build(&input, &artifacts)) {
    fprintf(stderr, "  transition artifacts build failed\n");
    uc_close(uc);
    return 0;
  }
  const uint8_t expected_stub[4] = {
    0xcd, 0xfb, /* int 0xfb */
    0x66, 0xcb  /* retfd */
  };
  if (memcmp(artifacts.state_stub, expected_stub, sizeof(expected_stub)) != 0) {
    fprintf(stderr, "  production state stub bytes are not cd fb 66 cb\n");
    uc_close(uc);
    return 0;
  }
  size_t interrupt_hook = 0;
  size_t observer_hook = 0;
  const uint64_t gate_addresses[] = {
    (uint64_t)k_dpmi_entry_segment << 4,
    ((uint64_t)k_dpmi_entry_segment << 4) + 0x0100u,
    ((uint64_t)k_dpmi_entry_segment << 4) + 0x0120u,
    (uint64_t)k_dpmi_rm_gate_linear,
    (uint64_t)k_dos_int21_vector_segment << 4,
  };
  size_t gate_hooks[sizeof(gate_addresses) / sizeof(gate_addresses[0])];
  if (uc_mem_map(uc, 0, k_memory_size, UC_PROT_ALL) != UC_ERR_OK ||
      uc_hook_add(uc, &interrupt_hook, UC_HOOK_INTR, daze_on_interrupt, &interrupt_context, 0, 0) !=
        UC_ERR_OK ||
      !build_machine(uc, scenario, &artifacts)) {
    fprintf(stderr, "  machine setup failed\n");
    uc_close(uc);
    return 0;
  }
  print_bytes(uc, "SS descriptor", k_dpmi_gdt_address + scenario->stack_selector, 8);
  check(&observation, descriptor_db_bit(uc, scenario->stack_selector) == scenario->expect_stack_db,
        "stack descriptor %04x D/B=%d, expected %d", scenario->stack_selector,
        descriptor_db_bit(uc, scenario->stack_selector), scenario->expect_stack_db);
  for (size_t index = 0; index < sizeof(gate_addresses) / sizeof(gate_addresses[0]); ++index) {
    if (uc_hook_add(uc, &gate_hooks[index], UC_HOOK_CODE, daze_on_code, &context,
                    gate_addresses[index], gate_addresses[index]) != UC_ERR_OK) {
      fprintf(stderr, "  gate hook install failed at %08" PRIx64 "\n", gate_addresses[index]);
      uc_close(uc);
      return 0;
    }
  }
  if (uc_hook_add(uc, &observer_hook, UC_HOOK_CODE, observe_code, &observation, 1, 0) !=
      UC_ERR_OK) {
    fprintf(stderr, "  observer hook install failed\n");
    uc_close(uc);
    return 0;
  }
  uint16_t cs = 0;
  uint16_t ip = (uint16_t)k_entry_address;
  uc_reg_write(uc, UC_X86_REG_CS, &cs);
  uc_reg_write(uc, UC_X86_REG_IP, &ip);
  uint32_t run_address = k_entry_address;
  for (size_t step = 0; step < 64 && !observation.finished; ++step) {
    context.run.stopped = 0;
    context.run.continue_run = 0;
    context.run.use_resume_address = 0;
    const uc_err error = uc_emu_start(uc, run_address, 0, 0, 10000);
    if (error != UC_ERR_OK) {
      fprintf(stderr, "  uc_ema_start: %s\n", uc_strerror(error));
      observation.failed = 1;
      break;
    }
    if (context.run.terminated) break;
    if (context.run.use_resume_address) {
      run_address = (uint32_t)context.run.resume_address;
      continue;
    }
    if (context.run.continue_run) {
      run_address = (uint32_t)daze_next_interrupt_address(uc, &context.engine);
      continue;
    }
    if (!context.run.stopped) break;
    observation.pre_hook_cs = get_reg16(uc, UC_X86_REG_CS);
    observation.pre_hook_ip = get_reg16(uc, UC_X86_REG_IP);
    observation.pre_hook_esp = get_reg32(uc, UC_X86_REG_ESP);
    observation.pre_hook_ss = get_reg16(uc, UC_X86_REG_SS);
    if (!read_stack_words(uc, observation.pre_hook_esp, observation.pre_hook_words,
                          k_stack_words)) {
      observation.failed = 1;
    }
    fprintf(stderr,
            "  before INT %02xh dispatch: CS:IP=%04x:%04x SS:ESP=%04x:%08" PRIx32
            " AX=%04x ES=%04x EDI=%08" PRIx32 " last-code=%08" PRIx64 "\n",
            context.run.interrupt_number, observation.pre_hook_cs, observation.pre_hook_ip,
            observation.pre_hook_ss, observation.pre_hook_esp, get_reg16(uc, UC_X86_REG_AX),
            get_reg16(uc, UC_X86_REG_ES), get_reg32(uc, UC_X86_REG_EDI),
            context.engine.have_code ? context.engine.last_code_address : 0);
    print_words("pre-dispatch", observation.pre_hook_words, k_stack_words);
    if (context.run.interrupt_number == 0xfb) {
      observation.have_pre_hook = 1;
      print_bytes(uc, "gate stub", k_state_stub_linear, 4);
    }
    if (!daze_dispatch_interrupt(uc, context.run.interrupt_number, &context.engine, &context.run,
                                 &context.process, &files)) {
      fprintf(stderr, "  dispatch of interrupt %02x failed (probe stop) esp=%08" PRIx32 "\n",
              context.run.interrupt_number, get_reg32(uc, UC_X86_REG_ESP));
      break;
    }
    if (context.run.use_resume_address) {
      run_address = (uint32_t)context.run.resume_address;
      continue;
    }
    if (context.run.continue_run) {
      observation.have_decision = 1;
      observation.decision_esp = get_reg32(uc, UC_X86_REG_ESP);
      if (!read_stack_words(uc, observation.decision_esp, observation.decision_words,
                            k_stack_words)) {
        observation.failed = 1;
      }
      fprintf(stderr,
              "  after widening decision: SS:ESP=%04x:%08" PRIx32
              " CS:IP=%04x:%04x ESP-DELTA=%+d\n",
              get_reg16(uc, UC_X86_REG_SS), observation.decision_esp, get_reg16(uc, UC_X86_REG_CS),
              get_reg16(uc, UC_X86_REG_IP),
              (int)observation.decision_esp - (int)observation.pre_hook_esp);
      print_words("post-decision", observation.decision_words, k_stack_words);
      if (!scenario->resume_after_decision) break;
      run_address = (uint32_t)daze_next_interrupt_address(uc, &context.engine);
      continue;
    }
    run_address = (uint32_t)daze_restart_address(uc);
  }
  if (observation.have_far_call) {
    fprintf(stderr, "  caller before far transfer: CS:IP=%04x:%04x SS:ESP=%04x:%08" PRIx32 "\n",
            k_caller_selector, k_call_ip, observation.far_call_ss, observation.far_call_esp);
    print_words("pre-transfer ", observation.far_call_words, k_stack_words);
  } else {
    fprintf(stderr, "  caller before far transfer: not reached\n");
  }
  if (observation.have_stub) {
    fprintf(stderr, "  at guest 66 CB: SS:ESP=%04x:%08" PRIx32 "\n", get_reg16(uc, UC_X86_REG_SS),
            observation.stub_esp);
    print_words("pre-retf    ", observation.stub_words, k_stack_words);
  } else {
    fprintf(stderr, "  at guest 66 CB: not reached\n");
  }
  if (observation.have_post_retf) {
    fprintf(stderr,
            "  after guest 66 CB: CS:EIP=%04x:%04x SS:ESP=%04x:%08" PRIx32 " ESP-ADVANCE=%+d\n",
            observation.post_retf_cs, observation.post_retf_ip, observation.post_retf_ss,
            observation.post_retf_esp, (int)observation.post_retf_esp - (int)observation.stub_esp);
    print_words("post-retf    ", observation.post_retf_words, k_stack_words);
  } else {
    fprintf(stderr, "  after guest 66 CB: not reached\n");
  }
  if (observation.have_ret) {
    fprintf(stderr, "  caller RET at %04x:%04x consumes %08" PRIx32 " from ESP=%08" PRIx32 "\n",
            k_caller_selector, k_ret_ip, observation.ret_value, observation.ret_esp);
  } else {
    fprintf(stderr, "  caller RET: not reached\n");
  }
  if (observation.have_successor) {
    fprintf(stderr, "  return continuation: CS:IP=%04x:%04x\n", observation.successor_cs,
            observation.successor_ip);
  } else {
    fprintf(stderr, "  return continuation: not reached\n");
  }
  fprintf(stderr, "  executed linear addresses:");
  for (size_t index = 0; index < observation.history_count; ++index) {
    fprintf(stderr, "%s%08" PRIx64, index == 0 ? "" : " ", observation.history[index]);
  }
  fprintf(stderr, "\n");
  check(&observation,
        observation.have_pre_hook && observation.pre_hook_cs == k_state_code_selector &&
          observation.pre_hook_ip == k_state_stub_offset,
        "INT FBh boundary not reached at %04x:%04x", observation.pre_hook_cs,
        observation.pre_hook_ip);
  if (observation.have_pre_hook) {
    check(&observation, observation.pre_hook_esp == scenario->expect_pre_hook_esp,
          "pre-hook ESP=%08" PRIx32 ", expected %08" PRIx32, observation.pre_hook_esp,
          scenario->expect_pre_hook_esp);
    check(&observation,
          memcmp(observation.pre_hook_words, scenario->expect_pre_hook_words,
                 sizeof(observation.pre_hook_words)) == 0,
          "pre-hook stack words differ from the pinned frame");
  }
  check(&observation, observation.have_decision, "widening decision record missing");
  if (observation.have_decision) {
    check(&observation, observation.decision_esp == scenario->expect_decision_esp,
          "post-decision ESP=%08" PRIx32 ", expected %08" PRIx32, observation.decision_esp,
          scenario->expect_decision_esp);
    check(&observation,
          memcmp(observation.decision_words, scenario->expect_decision_words,
                 sizeof(observation.decision_words)) == 0,
          "post-decision stack words differ from the pinned frame");
    if (scenario->widen_expected) {
      check(&observation, observation.pre_hook_esp - observation.decision_esp == 4,
            "widened frame is not eight bytes at ESP-4 (pre-hook %08" PRIx32 ", decision %08" PRIx32
            ")",
            observation.pre_hook_esp, observation.decision_esp);
    } else {
      check(&observation,
            observation.decision_esp == observation.pre_hook_esp &&
              memcmp(observation.decision_words, observation.pre_hook_words,
                     sizeof(observation.pre_hook_words)) == 0,
            "frame was mutated although the helper must decline");
    }
  }
  if (scenario->resume_after_decision) {
    check(&observation, observation.have_stub, "guest 66 CB instruction was not reached");
    check(&observation, observation.have_post_retf, "guest 66 CB did not return to the caller");
    if (observation.have_stub && observation.have_post_retf) {
      check(&observation,
            observation.post_retf_cs == k_caller_selector &&
              observation.post_retf_ip == k_after_call_ip,
            "post-RETF CS:EIP=%04x:%04x, expected %04x:%04x", observation.post_retf_cs,
            observation.post_retf_ip, k_caller_selector, k_after_call_ip);
      check(&observation, observation.post_retf_esp == scenario->expect_post_retf_esp,
            "post-RETF ESP=%08" PRIx32 ", expected %08" PRIx32, observation.post_retf_esp,
            scenario->expect_post_retf_esp);
      if (scenario->widen_expected) {
        check(&observation, observation.post_retf_esp == observation.pre_hook_esp + 4,
              "post-RETF ESP=%08" PRIx32 " is not the widened frame's old ESP+4 (%08" PRIx32 ")",
              observation.post_retf_esp, observation.pre_hook_esp + 4);
      }
      check(&observation,
            observation.have_ret && observation.ret_value == scenario->expect_ret_value,
            "caller RET consumed %08" PRIx32 ", expected %08" PRIx32, observation.ret_value,
            scenario->expect_ret_value);
      check(&observation, observation.have_successor == scenario->expect_successor,
            "return continuation reached=%d, expected %d", observation.have_successor,
            scenario->expect_successor);
    }
  }
  ok = observation.failed ? 0 : 1;
  uc_close(uc);
  return ok;
}

int main(void) {
  int passed = 0;
  int failed = 0;
  const Scenario cases[] = {
    {.name = "16bit-stack-four-byte-frame-widened",
     .kind = k_case_four_byte_frame_narrow_stack,
     .stack_selector = k_narrow_stack_selector,
     .expect_stack_db = 0,
     .near_return = k_successor_offset,
     .near_return_size = 2,
     .widen_expected = 1,
     .resume_after_decision = 1,
     .expect_successor = 1,
     .expect_pre_hook_esp = 0x3eec,
     .expect_pre_hook_words = {0x011f, 0x0008, k_successor_offset, 0xe1e1, 0xe1e1, 0xe1e1, 0xe1e1,
                               0xe1e1, 0xe1e1, 0xe1e1},
     .expect_decision_esp = k_wide_frame_esp,
     .expect_decision_words = {0x011f, 0x0000, 0x0008, 0x0000, k_successor_offset, 0xe1e1, 0xe1e1,
                               0xe1e1, 0xe1e1, 0xe1e1},
     .expect_post_retf_esp = k_stack_seed_sp,
     .expect_ret_value = k_successor_offset},
    {.name = "16bit-stack-modeled-eight-byte-frame-untouched",
     .kind = k_case_modeled_wide_frame_narrow_stack,
     .stack_selector = k_narrow_stack_selector,
     .expect_stack_db = 0,
     .near_return = k_successor_offset,
     .near_return_size = 2,
     .widen_expected = 0,
     .resume_after_decision = 1,
     .expect_successor = 1,
     .expect_pre_hook_esp = k_wide_frame_esp,
     .expect_pre_hook_words = {k_after_call_ip, 0x0000, k_caller_selector, 0x0000,
                               k_successor_offset, 0xe1e1, 0xe1e1, 0xe1e1, 0xe1e1, 0xe1e1},
     .expect_decision_esp = k_wide_frame_esp,
     .expect_decision_words = {k_after_call_ip, 0x0000, k_caller_selector, 0x0000,
                               k_successor_offset, 0xe1e1, 0xe1e1, 0xe1e1, 0xe1e1, 0xe1e1},
     .expect_post_retf_esp = k_stack_seed_sp,
     .expect_ret_value = k_successor_offset},
    {.name = "32bit-stack-modeled-eight-byte-frame-untouched",
     .kind = k_case_modeled_wide_frame_wide_stack,
     .stack_selector = k_wide_stack_selector,
     .expect_stack_db = 1,
     .near_return = k_successor_offset,
     .near_return_size = 2,
     .widen_expected = 0,
     .resume_after_decision = 1,
     .expect_successor = 1,
     .expect_pre_hook_esp = k_wide_frame_esp,
     .expect_pre_hook_words = {k_after_call_ip, 0x0000, k_caller_selector, 0x0000,
                               k_successor_offset, 0xe1e1, 0xe1e1, 0xe1e1, 0xe1e1, 0xe1e1},
     .expect_decision_esp = k_wide_frame_esp,
     .expect_decision_words = {k_after_call_ip, 0x0000, k_caller_selector, 0x0000,
                               k_successor_offset, 0xe1e1, 0xe1e1, 0xe1e1, 0xe1e1, 0xe1e1},
     .expect_post_retf_esp = k_stack_seed_sp,
     .expect_ret_value = k_successor_offset},
    {.name = "16bit-stack-ambiguous-frame-untouched",
     .kind = k_case_ambiguous_frame,
     .stack_selector = k_narrow_stack_selector,
     .expect_stack_db = 0,
     .near_return = 0x0008,
     .near_return_size = 2,
     .widen_expected = 0,
     .resume_after_decision = 0,
     .expect_successor = 0,
     .expect_pre_hook_esp = 0x3eec,
     .expect_pre_hook_words = {0x011f, 0x0008, 0x0008, 0xe1e1, 0xe1e1, 0xe1e1, 0xe1e1, 0xe1e1,
                               0xe1e1, 0xe1e1},
     .expect_decision_esp = 0x3eec,
     .expect_decision_words = {0x011f, 0x0008, 0x0008, 0xe1e1, 0xe1e1, 0xe1e1, 0xe1e1, 0xe1e1,
                               0xe1e1, 0xe1e1},
     .expect_post_retf_esp = 0,
     .expect_ret_value = 0},
  };
  for (size_t index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
    if (run_scenario(&cases[index])) {
      ++passed;
    } else {
      fprintf(stderr, "FAILED: %s\n", cases[index].name);
      ++failed;
    }
  }
  fprintf(stderr, "state-procedure-frame-contract: %d passed, %d failed\n", passed, failed);
  return failed == 0 ? 0 : 1;
}
