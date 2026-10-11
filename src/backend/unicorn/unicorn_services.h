#ifndef DAZE_UNICORN_SERVICES_H
#define DAZE_UNICORN_SERVICES_H

#include "unicorn_context.h"

/* Service logs require --debug; errors remain unconditional. */
void daze_trace_debug(const DazeUnicornEngine *engine, const char *format, ...);

int daze_flush_translation_cache(uc_engine *uc, DazeMetrics *metrics);
int daze_invalidate_translation_cache(uc_engine *uc, DazeMetrics *metrics, uint64_t address,
                                      uint64_t end);

int daze_read_guest_asciiz(uc_engine *uc, uint16_t segment, uint16_t offset, char *output,
                           size_t output_size);
int daze_read_guest_bytes(uc_engine *uc, uint16_t segment, uint16_t offset, void *output,
                          size_t output_size);
int daze_write_guest_bytes(uc_engine *uc, uint16_t segment, uint16_t offset, const void *input,
                           size_t input_size);

int daze_dpmi_selector_base(uc_engine *uc, uint16_t selector, uint32_t *base);
int daze_dpmi_selector_code_width(uc_engine *uc, uint16_t selector);
void daze_dpmi_capture_state(uc_engine *uc, DpmiAlternateState *state);
int daze_dpmi_state_buffer_address(uc_engine *uc, uint16_t segment, uint32_t offset,
                                   uint32_t *address);

int daze_unicorn_int21_dispatch(uc_engine *uc, DazeUnicornEngine *engine, DazeUnicornRunState *run,
                                DazeDosRuntimeProcessState *process, DazeDosfsFileService *files);

int daze_int31_dispatch(uc_engine *uc, DazeUnicornEngine *engine, DazeUnicornRunState *run,
                        DazeDosRuntimeProcessState *process);

int daze_setup_start_exec_child(uc_engine *uc, DazeUnicornEngine *engine, DazeUnicornRunState *run,
                                DazeDosRuntimeProcessState *process, DazeDosfsFileService *files,
                                char *diagnostic, size_t diagnostic_size);
int daze_setup_prepare_dpmi_transition(uc_engine *uc, DazeUnicornEngine *engine,
                                       DazeDosRuntimeProcessState *process);
int daze_setup_write_raw_pm_reentry_wrapper(uc_engine *uc, DazeUnicornRunState *run,
                                            DazeMetrics *metrics, uint16_t ds, uint16_t es,
                                            uint16_t ss, uint16_t sp, uint16_t fs, uint16_t gs,
                                            uint16_t ax, uint16_t bx, uint16_t cx, uint16_t dx,
                                            uint16_t si, uint16_t di, uint16_t bp, uint16_t flags,
                                            uint16_t target_ip, uint16_t target_cs);
int daze_setup_write_raw_pm_reentry32_wrapper(uc_engine *uc, DazeUnicornRunState *run,
                                              DazeMetrics *metrics, uint16_t ds, uint16_t es,
                                              uint16_t ss, uint16_t fs, uint16_t gs, uint32_t eax,
                                              uint32_t ebx, uint32_t ecx, uint32_t edx,
                                              uint32_t esi, uint32_t edi, uint32_t ebp,
                                              uint32_t esp, uint32_t eflags, uint32_t target_eip,
                                              uint16_t target_cs);
int daze_setup_write_exception_gateway(uc_engine *uc, DazeMetrics *metrics,
                                       uint16_t handler_segment, uint16_t handler_offset,
                                       uint16_t locked_stack_sp, uint32_t *gateway_linear);
int daze_setup_start_dpmi_rm_procedure(uc_engine *uc, DazeUnicornEngine *engine,
                                       DazeUnicornRunState *run);
int daze_setup_start_dpmi_rm_interrupt(uc_engine *uc, DazeUnicornEngine *engine,
                                       DazeUnicornRunState *run,
                                       DazeDosRuntimeProcessState *process);
int daze_setup_complete_dpmi_rm_procedure(uc_engine *uc, DazeUnicornEngine *engine,
                                          DazeUnicornRunState *run);

void daze_on_interrupt(uc_engine *uc, uint32_t interrupt, void *user_data);
void daze_on_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);

/* Legacy #NP delivery requires an installed 0203h handler, 16-bit code, and a supported
 * instruction naming a non-present selector. The gateway uses a bounded locked-stack
 * frame; hooks retire it on return. */
int daze_dpmi_exception_classify(uc_engine *uc, const DazeDpmiProcessState *dpmi,
                                 DazeDpmiExceptionFault *fault);
int daze_dpmi_exception_transfer(uc_engine *uc, DazeUnicornEngine *engine, DazeUnicornRunState *run,
                                 DazeDpmiProcessState *dpmi, const DazeDpmiExceptionFault *fault);
int daze_dpmi_exception_transfer_dispose_active(uc_engine *uc, DazeUnicornRunState *run);
void daze_dpmi_exception_transfer_disarm(uc_engine *uc, DazeUnicornRunState *run);

int daze_dispatch_interrupt(uc_engine *uc, uint8_t interrupt, DazeUnicornEngine *engine,
                            DazeUnicornRunState *run, DazeDosRuntimeProcessState *process,
                            DazeDosfsFileService *files);
uint64_t daze_next_interrupt_address(uc_engine *uc, const DazeUnicornEngine *engine);
uint64_t daze_restart_address(uc_engine *uc);
void daze_print_registers(uc_engine *uc);

#endif
