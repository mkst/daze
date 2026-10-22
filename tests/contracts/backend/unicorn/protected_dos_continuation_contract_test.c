/* Synthetic protected DOS-vector continuation contract. A client vector services
 * INT 21h with IRET or declines with the exact null far jump. Guest MOV Sreg
 * loads protected bases; host segment writes would invalidate the saved-frame witness. */

#include "unicorn_context.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

void daze_on_interrupt(uc_engine *uc, uint32_t interrupt, void *user_data);
void daze_on_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
int daze_dispatch_interrupt(uc_engine *uc, uint8_t interrupt, DazeUnicornEngine *engine,
                            DazeUnicornRunState *run, DazeDosRuntimeProcessState *process,
                            DazeDosfsFileService *files);
uint64_t daze_next_interrupt_address(uc_engine *uc, const DazeUnicornEngine *engine);
uint64_t daze_restart_address(uc_engine *uc);

#define TEST_FAIL(...)                                                                             \
  do {                                                                                             \
    fprintf(stderr, "protected-dos-continuation: " __VA_ARGS__);                                   \
    fprintf(stderr, "\n");                                                                         \
    return 0;                                                                                      \
  } while (0)

/* Real-mode preamble entering protected mode: cli; lgdt [1080h]; set CR0.PE;
 * far jump 0008:0100.  Six instructions; the test writes the PM segment
 * registers immediately after the far jump lands. */
static const uint8_t k_preamble[] = {
  0xfa,                         // cli
  0x0f, 0x01, 0x16, 0x80, 0x10, // lgdt [1080h]
  0x0f, 0x20, 0xc0,             // mov eax, cr0
  0x66, 0x83, 0xc8, 0x01,       // or eax, 1
  0x0f, 0x22, 0xc0,             // mov cr0, eax
  0xea, 0x00, 0x01, 0x08, 0x00, // jmp far 0008:0100
};
static const uint8_t k_gdtr_operand[] = {0x17,
                                         0x00,
                                         (uint8_t)k_dpmi_gdt_address,
                                         (uint8_t)(k_dpmi_gdt_address >> 8),
                                         (uint8_t)(k_dpmi_gdt_address >> 16),
                                         (uint8_t)(k_dpmi_gdt_address >> 24)};
/* GDT: null; 0008h 16-bit code base 10000h; 0010h 16-bit data base 20000h.
 * The data selector is RPL 0 so Daze's base lookup and the frame math agree. */
static const uint8_t k_gdt[] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // null
  0xff, 0xff, 0x00, 0x00, 0x01, 0x9a, 0x00, 0x00, // 0008h code
  0xff, 0xff, 0x00, 0x00, 0x02, 0x92, 0x00, 0x00, // 0010h data
};

/* PM caller at 0008:0100 with the observed int21 request.  Segment registers
 * are loaded by guest instructions (RPL-0 selectors): Unicorn resolves
 * instruction-loaded protected segments against the guest GDT, while a
 * uc_reg_write'd segment keeps a real-mode selector<<4 base, which would
 * desync the stack frame from the continuation classifier.  After `int 21h`
 * the caller stores AX (result) at [3420h], stores CF at [3422h], and parks
 * with `jmp $`. */
static const uint8_t k_caller_int21[] = {
  0xb8, 0x10, 0x00, // mov ax,10h
  0x8e, 0xd8,       // mov ds,ax
  0x8e, 0xc0,       // mov es,ax
  0x8e, 0xd0,       // mov ss,ax
  0xbc, 0x00, 0xfe, // mov sp,0xfe00
  0xb8, 0x00, 0x30, // mov ax,3000h (AH=30h get DOS version)
  0xcd, 0x21,       // int 21h
  0xa3, 0x20, 0x34, // mov [3420h],ax
  0x9c, 0x58,       // pushf; pop ax
  0x25, 0x01, 0x00, // and ax,1
  0xa3, 0x22, 0x34, // mov [3422h],ax
  0xeb, 0xfe,       // jmp $
};

/* Clobber AX but balance the stack before the null far jump; fallback must
 * restore the original caller request rather than the vector's temporary state. */
static const uint8_t k_stub_decline[] = {
  0x50,                         // push ax
  0x58,                         // pop ax
  0xb8, 0x34, 0x12,             // mov ax,0x1234
  0xea, 0x00, 0x00, 0x00, 0x00, // jmp far 0000:0000
};

/* Vector that declines but leaves temporary stack work: the saved post-frame
 * SS:ESP no longer matches, so the classifier must refuse to serve. */
static const uint8_t k_stub_decline_unbalanced[] = {
  0x50,                         // push ax
  0xea, 0x00, 0x00, 0x00, 0x00, // jmp far 0000:0000
};

/* Vector that services the call itself: a plain 16-bit IRET must take the
 * ordinary interrupt-frame path and never reach host DOS translation. */
static const uint8_t k_stub_iret[] = {
  0xcf, // iret
};

typedef struct {
  const uint8_t *stub;
  size_t stub_size;
  const uint8_t *caller;
  size_t caller_size;
  int expect_served;
  int expect_terminated_at_0d;
  int expect_marker_result;
  int expect_continuation_after_run;
  int expect_no_continuation_at_end;
} Scenario;

static int run_scenario(const Scenario *scenario) {
  uc_engine *uc = NULL;
  if (uc_open(UC_ARCH_X86, UC_MODE_16, &uc) != UC_ERR_OK) {
    TEST_FAIL("uc_open failed");
  }
  int ok = 0;
  DazeUnicornContext context;
  memset(&context, 0, sizeof(context));
  DazeDosfsMounts mounts = {0};
  DazeDosfsHandles handles = {0};
  DazeDosfsFileService files;
  daze_dosfs_file_service_init(&files, &mounts, &handles);
  DazeUnicornInterruptContext interrupt_context = {.context = &context, .files = &files};
  size_t hook_handle = 0;
  if (uc_mem_map(uc, 0, k_memory_size, UC_PROT_ALL) == UC_ERR_OK &&
      uc_mem_write(uc, 0x1000, k_preamble, sizeof(k_preamble)) == UC_ERR_OK &&
      uc_mem_write(uc, 0x1080, k_gdtr_operand, sizeof(k_gdtr_operand)) == UC_ERR_OK &&
      uc_mem_write(uc, k_dpmi_gdt_address, k_gdt, sizeof(k_gdt)) == UC_ERR_OK &&
      uc_mem_write(uc, 0x10000 + 0x0100, scenario->caller, scenario->caller_size) == UC_ERR_OK &&
      (scenario->stub == NULL ||
       uc_mem_write(uc, 0x10000 + 0x0200, scenario->stub, scenario->stub_size) == UC_ERR_OK) &&
      uc_hook_add(uc, &hook_handle, UC_HOOK_INTR, daze_on_interrupt, &interrupt_context, 0, 0) ==
        UC_ERR_OK) {
    context.process.dpmi.interrupt_vectors[0x21].segment = scenario->stub == NULL ? 0 : 0x0008;
    context.process.dpmi.interrupt_vectors[0x21].offset = 0x0200;
    uint16_t cs = 0;
    uint16_t ss = 0;
    uint16_t sp = 0xfe00;
    uint16_t ip = 0x1000;
    uc_reg_write(uc, UC_X86_REG_CS, &cs);
    uc_reg_write(uc, UC_X86_REG_SS, &ss);
    uc_reg_write(uc, UC_X86_REG_SP, &sp);
    uc_reg_write(uc, UC_X86_REG_IP, &ip);
    uint32_t eflags = 0;
    uc_reg_read(uc, UC_X86_REG_EFLAGS, &eflags);
    eflags |= 1u; // CF set: the host DOS handler must clear it on service.
    uc_reg_write(uc, UC_X86_REG_EFLAGS, &eflags);
    uint32_t begin = 0x1000;
    for (size_t step = 0; step < 4096; ++step) {
      context.run.stopped = 0;
      context.run.continue_run = 0;
      context.run.use_resume_address = 0;
      const uc_err error = uc_emu_start(uc, begin, 0, 0, 5000);
      if (error != UC_ERR_OK) {
        fprintf(stderr, "protected-dos-continuation: uc_emu_start: %s\n", uc_strerror(error));
        break;
      }
      if (context.run.terminated) break;
      if (context.run.use_resume_address) {
        begin = (uint32_t)context.run.resume_address;
        continue;
      }
      if (context.run.continue_run) {
        begin = (uint32_t)daze_next_interrupt_address(uc, &context.engine);
        continue;
      }
      if (context.run.stopped &&
          daze_dispatch_interrupt(uc, context.run.interrupt_number, &context.engine, &context.run,
                                  &context.process, &files)) {
        if (context.run.use_resume_address) {
          begin = (uint32_t)context.run.resume_address;
          continue;
        }
        if (context.run.continue_run) {
          begin = (uint32_t)daze_next_interrupt_address(uc, &context.engine);
          continue;
        }
        begin = (uint32_t)daze_restart_address(uc);
        continue;
      }
      break;
    }
    uint16_t result = 0;
    uint16_t carry = 0;
    uc_mem_read(uc, 0x20000 + 0x3420, &result, sizeof(result));
    uc_mem_read(uc, 0x20000 + 0x3422, &carry, sizeof(carry));
    if (scenario->expect_served) {
      if (result != 0x0005 || carry != 0) {
        fprintf(stderr,
                "protected-dos-continuation: expected DOS 21h/30h service "
                "(result=0005 carry=0), got result=%04x carry=%04x\n",
                result, carry);
        goto cleanup;
      }
      if (context.run.dos_continuation.active ||
          context.run.dos_continuation.caller_context != NULL) {
        fprintf(stderr, "protected-dos-continuation: continuation not cleared after service\n");
        goto cleanup;
      }
    } else {
      if (result != (uint16_t)scenario->expect_marker_result) {
        fprintf(stderr, "protected-dos-continuation: expected untouched marker %04x, got %04x\n",
                (uint16_t)scenario->expect_marker_result, result);
        goto cleanup;
      }
      if (scenario->expect_terminated_at_0d && !context.run.stopped) {
        fprintf(stderr, "protected-dos-continuation: null far jump was not an unhandled #GP\n");
        goto cleanup;
      }
      if (scenario->expect_no_continuation_at_end && context.run.dos_continuation.active) {
        fprintf(stderr, "protected-dos-continuation: continuation unexpectedly active\n");
        goto cleanup;
      }
    }
    if (scenario->expect_continuation_after_run) {
      if (!context.run.dos_continuation.active) {
        fprintf(stderr, "protected-dos-continuation: expected active continuation after IRET\n");
        goto cleanup;
      }
    }
    ok = 1;
  } else {
    fprintf(stderr, "protected-dos-continuation: machine setup failed\n");
  }
cleanup:
  daze_protected_dos_continuation_clear(&context.run);
  uc_close(uc);
  return ok;
}

/* Exercise the real code hook across a budget-exhausting loop. Logging must
 * stop while the guest reaches its final result, and history alone is silent. */
static int trace_runtime_contract(int enabled, int history) {
  DazeUnicornContext context = {0};
  if (daze_unicorn_trace_configure(&context.engine.diagnostic_trace, k_memory_size,
                                   enabled ? "1" : NULL, enabled ? "0x1000" : NULL,
                                   enabled ? "0x1010" : NULL, history ? "1" : NULL,
                                   enabled ? "0x2000" : NULL, enabled ? "64" : NULL))
    return 1;
  context.engine.full_code_hook = daze_unicorn_trace_full_hook(&context.engine.diagnostic_trace);
  const uint8_t code[] = {
    0xb9, 0x88, 0x13, /* mov cx,0x1388 */
    0x90,             /* nop */
    0xe2, 0xfd,       /* loop to preceding nop */
    0xb8, 0x34, 0x12, /* mov ax,0x1234 */
    0xf4              /* hlt */
  };
  uint8_t memory[64];
  memset(memory, 0x5a, sizeof(memory));
  uc_engine *uc = NULL;
  uc_hook hook;
  FILE *capture = tmpfile();
  if (capture == NULL) return 1;
  int failed = 1;
  int saved_stderr = -1;
  if (uc_open(UC_ARCH_X86, UC_MODE_16, &uc) != UC_ERR_OK ||
      uc_mem_map(uc, 0, k_memory_size, UC_PROT_ALL) != UC_ERR_OK ||
      uc_mem_write(uc, 0x1000, code, sizeof(code)) != UC_ERR_OK ||
      uc_mem_write(uc, 0x2000, memory, sizeof(memory)) != UC_ERR_OK)
    goto done;
  if (context.engine.full_code_hook &&
      uc_hook_add(uc, &hook, UC_HOOK_CODE, daze_on_code, &context, 1, 0) != UC_ERR_OK)
    goto done;
  fflush(stderr);
  saved_stderr = dup(STDERR_FILENO);
  if (saved_stderr < 0 || dup2(fileno(capture), STDERR_FILENO) < 0) goto done;
  const uc_err status = uc_emu_start(uc, 0x1000, 0, 0, 20000);
  fflush(stderr);
  if (dup2(saved_stderr, STDERR_FILENO) < 0) goto done;
  close(saved_stderr);
  saved_stderr = -1;
  if (status != UC_ERR_OK || get_reg16(uc, UC_X86_REG_AX) != 0x1234 ||
      get_reg16(uc, UC_X86_REG_CX) != 0 || context.run.stopped ||
      context.engine.recent_code_count != (context.engine.full_code_hook ? 24u : 0u))
    goto done;
  rewind(capture);
  unsigned instructions = 0, dumps = 0, notices = 0;
  char line[512];
  while (fgets(line, sizeof(line), capture) != NULL) {
    if (strncmp(line, "  trace CS:IP=", 14) == 0)
      ++instructions;
    else if (strncmp(line, "  trace memory ", 15) == 0) {
      const char *bytes = strchr(line, ':');
      if (bytes == NULL || strlen(bytes + 1) != 64 * 3 + 1) goto done;
      for (unsigned i = 0; i < 64; ++i)
        if (strncmp(bytes + 1 + i * 3, " 5a", 3) != 0) goto done;
      ++dumps;
    } else if (strstr(line, "Unicorn trace truncated") != NULL)
      ++notices;
    else
      goto done;
  }
  if (instructions != (enabled ? DAZE_TRACE_MAX_RECORDS : 0) || dumps != instructions ||
      notices != (unsigned)enabled)
    goto done;
  failed = 0;
done:
  if (saved_stderr >= 0) {
    fflush(stderr);
    dup2(saved_stderr, STDERR_FILENO);
    close(saved_stderr);
  }
  if (uc != NULL) uc_close(uc);
  fclose(capture);
  return failed;
}

int main(int argc, char **argv) {
  if (argc == 2 && strcmp(argv[1], "--trace-contract") == 0) {
    const int failed =
      trace_runtime_contract(0, 0) || trace_runtime_contract(0, 1) || trace_runtime_contract(1, 0);
    if (failed) fprintf(stderr, "Unicorn trace runtime contract failed\n");
    return failed;
  }
  if (argc != 1) return 2;
  int passed = 0;
  int failed = 0;
  const Scenario served = {.stub = k_stub_decline,
                           .stub_size = sizeof(k_stub_decline),
                           .caller = k_caller_int21,
                           .caller_size = sizeof(k_caller_int21),
                           .expect_served = 1,
                           .expect_marker_result = 0,
                           .expect_continuation_after_run = 0,
                           .expect_no_continuation_at_end = 1};
  const Scenario iret = {.stub = k_stub_iret,
                         .stub_size = sizeof(k_stub_iret),
                         .caller = k_caller_int21,
                         .caller_size = sizeof(k_caller_int21),
                         .expect_served = 0,
                         .expect_marker_result = 0x3000,
                         /* A normal IRET consumes the pushed frame, so the decline
                          * classifier can never match afterwards and the return
                          * hook retires the delivery there: nothing lingers. */
                         .expect_continuation_after_run = 0,
                         .expect_no_continuation_at_end = 1};
  const Scenario unbalanced = {.stub = k_stub_decline_unbalanced,
                               .stub_size = sizeof(k_stub_decline_unbalanced),
                               .caller = k_caller_int21,
                               .caller_size = sizeof(k_caller_int21),
                               .expect_served = 0,
                               .expect_terminated_at_0d = 1,
                               .expect_marker_result = 0,
                               .expect_continuation_after_run = 0};
  const uint8_t bare_fault[5] = {
    0xea, 0x00, 0x00, 0x00, 0x00 /* jmp far 0x0:0x0 */
  };
  const Scenario bare = {.stub = NULL,
                         .stub_size = 0,
                         .caller = bare_fault,
                         .caller_size = sizeof(bare_fault),
                         .expect_served = 0,
                         .expect_terminated_at_0d = 1,
                         .expect_marker_result = 0,
                         .expect_continuation_after_run = 0,
                         .expect_no_continuation_at_end = 1};

#define RUN(scenario)                                                                              \
  do {                                                                                             \
    if (run_scenario(&(scenario))) {                                                               \
      ++passed;                                                                                    \
    } else {                                                                                       \
      fprintf(stderr, "FAILED: %s\n", #scenario);                                                  \
      ++failed;                                                                                    \
    }                                                                                              \
  } while (0)
  RUN(served);
  RUN(iret);
  RUN(unbalanced);
  RUN(bare);
#undef RUN

  fprintf(stderr, "protected-dos-continuation-contract: %d passed, %d failed\n", passed, failed);
  return failed == 0 ? 0 : 1;
}
