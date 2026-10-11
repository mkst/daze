#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "byte_order.h"
#include "exec_image.h"
#include "interrupt_vector.h"
#include "launch.h"
#include "monotonic_clock.h"
#include "unicorn_context.h"
#include "unicorn_image.h"
#include "unicorn_run.h"
#include "unicorn_services.h"

static int initialize_unicorn_prepared(uc_engine **out, const DazePreparedLaunch *launch,
                                       DazeUnicornContext *context) {
  if (out == NULL || launch == NULL || context == NULL) return 3;
  *out = NULL;
  uint8_t *prepared_image = NULL;
  size_t prepared_size = 0;
  if (!daze_dos_exec_image_prepare(&launch->image, &launch->header, k_load_segment, k_memory_size,
                                   &prepared_image, &prepared_size)) {
    fprintf(stderr, "cannot prepare MZ image and relocations\n");
    return 3;
  }
  uc_engine *uc = NULL;
  uc_err error = uc_open(UC_ARCH_X86, UC_MODE_16, &uc);
  if (error != UC_ERR_OK) {
    free(prepared_image);
    fprintf(stderr, "uc_open failed: %s\n", uc_strerror(error));
    return 3;
  }
  error = uc_mem_map(uc, 0, k_memory_size, UC_PROT_ALL);
  if (error == UC_ERR_OK) {
    error = uc_mem_write(uc, launch->image_address, prepared_image, prepared_size);
  }
  free(prepared_image);
  if (error != UC_ERR_OK ||
      !daze_unicorn_image_write_process(uc, launch->command_tail, launch->guest_path, k_psp_segment,
                                        k_environment_segment, k_dpmi_entry_segment,
                                        k_dos_int21_vector_segment, launch->env_vars,
                                        launch->env_var_count)) {
    fprintf(stderr, "unable to initialise guest memory: %s\n", uc_strerror(error));
    uc_close(uc);
    return 3;
  }
  context->process.resident_image_end = launch->image_address + (uint32_t)launch->header.image_size;
  *out = uc;
  return 0;
}

static void dispose_unicorn_operation(uc_engine *uc, DazeUnicornContext *context) {
  daze_dosfs_exec_handles_dispose(&context->process.child_process.handles);
  daze_dosfs_find_close(&context->process.dos_process.find);
  if (context->process.child_process.parent_context != NULL) {
    uc_context_free(context->process.child_process.parent_context);
    context->process.child_process.parent_context = NULL;
  }
  daze_protected_dos_continuation_clear(&context->run);
  if (uc != NULL) uc_close(uc);
}

static DazeCommandResult run_unicorn_loop(uc_engine *uc, DazeUnicornContext *context,
                                          DazeDosfsFileService *files, uint32_t entry_address) {
  DazeCommandResult result = {.disposition = DAZE_COMMAND_POSTSTART_FAILED};
  uint32_t run_address = entry_address;
  struct timespec started;
  if (clock_gettime(CLOCK_MONOTONIC, &started) != 0) memset(&started, 0, sizeof(started));
  for (;;) {
    context->run.stopped = 0;
    context->run.continue_run = 0;
    context->run.use_resume_address = 0;
    context->engine.metrics.emulation_runs++;
    const uint64_t emulation_started =
      context->engine.metrics.enabled ? monotonic_nanoseconds() : 0;
    result.guest_execution_started = 1;
    const uc_err error = uc_emu_start(uc, run_address, 0, 0, k_instruction_limit);
    const uint64_t emulation_finished =
      context->engine.metrics.enabled ? monotonic_nanoseconds() : 0;
    if (context->engine.metrics.enabled && emulation_finished >= emulation_started)
      daze_metrics_record_emulation_time(&context->engine.metrics,
                                         emulation_finished - emulation_started);
    if (error != UC_ERR_OK) {
      fprintf(stderr, "emulation stopped with %s\n", uc_strerror(error));
      daze_print_registers(uc);
      break;
    }
    if (context->run.terminated) {
      result.disposition = DAZE_COMMAND_COMPLETED;
      result.dos_exit_code = context->run.exit_code;
      break;
    }
    const uint64_t boundary_finished =
      context->engine.metrics.enabled ? monotonic_nanoseconds() : 0;
    if (context->run.use_resume_address) {
      if (boundary_finished >= emulation_finished)
        daze_metrics_record_resume(&context->engine.metrics, DAZE_RESUME_DIRECT,
                                   boundary_finished - emulation_finished);
      run_address = context->run.resume_address;
      continue;
    }
    if (context->run.continue_run) {
      if (boundary_finished >= emulation_finished)
        daze_metrics_record_resume(&context->engine.metrics, DAZE_RESUME_DIRECT,
                                   boundary_finished - emulation_finished);
      run_address = daze_next_interrupt_address(uc, &context->engine);
      continue;
    }
    if (context->run.stopped &&
        daze_dispatch_interrupt(uc, context->run.interrupt_number, &context->engine, &context->run,
                                &context->process, files)) {
      if (context->run.use_resume_address) {
        if (boundary_finished >= emulation_finished)
          daze_metrics_record_resume(&context->engine.metrics, DAZE_RESUME_AFTER_DISPATCH_ADDRESS,
                                     boundary_finished - emulation_finished);
        run_address = context->run.resume_address;
        continue;
      }
      if (context->run.continue_run) {
        if (boundary_finished >= emulation_finished)
          daze_metrics_record_resume(&context->engine.metrics, DAZE_RESUME_AFTER_DISPATCH_NEXT,
                                     boundary_finished - emulation_finished);
        run_address = daze_next_interrupt_address(uc, &context->engine);
        continue;
      }
      if (boundary_finished >= emulation_finished)
        daze_metrics_record_resume(&context->engine.metrics, DAZE_RESUME_AFTER_DISPATCH_RESTART,
                                   boundary_finished - emulation_finished);
      run_address = daze_restart_address(uc);
      continue;
    }
    if (!context->run.stopped) {
      fprintf(stderr, "instruction limit reached without an unsupported interrupt\n");
      daze_print_registers(uc);
    }
    break;
  }
  daze_dpmi_exception_transfer_disarm(uc, &context->run);
  daze_metrics_report(&context->engine.metrics, &started);
  dispose_unicorn_operation(uc, context);
  return result;
}

DazeCommandResult daze_unicorn_run_prepared(DazePreparedLaunch *launch, DazeUnicornContext *context,
                                            const char *path) {
  DazeCommandResult result = {.disposition = DAZE_COMMAND_PRESTART_REJECTED};
  const char *trace_error = daze_unicorn_trace_configure(
    &context->engine.diagnostic_trace, k_memory_size, getenv("DAZE_TRACE"),
    getenv("DAZE_TRACE_BEGIN"), getenv("DAZE_TRACE_END"), getenv("DAZE_DIAGNOSTIC_HISTORY"),
    getenv("DAZE_TRACE_DUMP_ADDRESS"), getenv("DAZE_TRACE_DUMP_SIZE"));
  if (trace_error != NULL) {
    fprintf(stderr, "invalid Unicorn trace configuration: %s\n", trace_error);
    return result;
  }
  if (context->engine.diagnostic_trace.enabled)
    fprintf(stderr,
            "Unicorn trace enabled for linear range %08" PRIx32 "..%08" PRIx32
            " (max %u records)\n",
            context->engine.diagnostic_trace.begin, context->engine.diagnostic_trace.end,
            DAZE_TRACE_MAX_RECORDS);
  uc_engine *uc = NULL;
  uc_hook interrupt_hook;
  uc_hook code_hook;
  uc_hook gate_hooks[5];

  daze_dos_memory_init(&context->process.dos_memory, launch->allocation_start,
                       k_dos_conventional_end_segment);
  daze_trace_debug(&context->engine,
                   "MZ probe: %s\n  image=%zu bytes, load=%04x:0000, entry=%04x:%04x, "
                   "stack=%04x:%04x, relocations=%u\n",
                   path, launch->header.image_size, k_load_segment,
                   (uint16_t)(k_load_segment + launch->header.initial_cs),
                   launch->header.initial_ip,
                   (uint16_t)(k_load_segment + launch->header.initial_ss),
                   launch->header.initial_sp, launch->header.relocations);
  if (initialize_unicorn_prepared(&uc, launch, context) != 0) return result;

  const uint16_t cs = (uint16_t)(k_load_segment + launch->header.initial_cs);
  const uint16_t ss = (uint16_t)(k_load_segment + launch->header.initial_ss);
  const uint16_t ds = k_psp_segment;
  const uint16_t es = k_psp_segment;
  uint32_t flags = 0x00000202;
  uc_reg_write(uc, UC_X86_REG_CS, &cs);
  uc_reg_write(uc, UC_X86_REG_IP, &launch->header.initial_ip);
  uc_reg_write(uc, UC_X86_REG_SS, &ss);
  uc_reg_write(uc, UC_X86_REG_SP, &launch->header.initial_sp);
  uc_reg_write(uc, UC_X86_REG_DS, &ds);
  uc_reg_write(uc, UC_X86_REG_ES, &es);
  uc_reg_write(uc, UC_X86_REG_EFLAGS, &flags);
  daze_dos_process_state_init(&context->process.dos_process, k_psp_segment);
  daze_dos_process_state_seed_vectors(&context->process.dos_process, k_dos_int21_vector_segment);
  DazeDosfsFileService files;
  daze_dosfs_file_service_init(&files, &launch->mounts, &launch->handles);
  daze_dosfs_file_service_set_transfer_storage(&files, &launch->transfer_storage);
  daze_dosfs_file_service_set_run_metrics(&files, &launch->run_metrics);
  DazeUnicornInterruptContext interrupt_context = {.context = context, .files = &files};
  uc_err error =
    uc_hook_add(uc, &interrupt_hook, UC_HOOK_INTR, daze_on_interrupt, &interrupt_context, 0, 0);
  if (error != UC_ERR_OK) {
    fprintf(stderr, "cannot install interrupt trace: %s\n", uc_strerror(error));
    dispose_unicorn_operation(uc, context);
    return result;
  }
  context->engine.full_code_hook = daze_unicorn_trace_full_hook(&context->engine.diagnostic_trace);
  context->engine.metrics.guest_instruction_count_available = context->engine.full_code_hook;
  if (context->engine.full_code_hook) {
    error = uc_hook_add(uc, &code_hook, UC_HOOK_CODE, daze_on_code, context, 1, 0);
    if (error != UC_ERR_OK) {
      fprintf(stderr, "cannot install instruction trace: %s\n", uc_strerror(error));
      dispose_unicorn_operation(uc, context);
      return result;
    }
  } else {
    const uint64_t gate_addresses[] = {
      (uint64_t)k_dpmi_entry_segment << 4,
      ((uint64_t)k_dpmi_entry_segment << 4) + 0x0100,
      ((uint64_t)k_dpmi_entry_segment << 4) + 0x0120,
      k_dpmi_rm_gate_linear,
      (uint64_t)k_dos_int21_vector_segment << 4,
    };
    for (size_t index = 0; index < sizeof(gate_addresses) / sizeof(gate_addresses[0]); ++index) {
      error = uc_hook_add(uc, &gate_hooks[index], UC_HOOK_CODE, daze_on_code, context,
                          gate_addresses[index], gate_addresses[index]);
      if (error != UC_ERR_OK) {
        fprintf(stderr, "cannot install DPMI gate hook: %s\n", uc_strerror(error));
        dispose_unicorn_operation(uc, context);
        return result;
      }
    }
  }
  return run_unicorn_loop(uc, context, &files, ((uint32_t)cs << 4) + launch->header.initial_ip);
}
