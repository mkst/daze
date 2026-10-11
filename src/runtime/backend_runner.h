#ifndef DAZE_RUNTIME_BACKEND_RUNNER_H
#define DAZE_RUNTIME_BACKEND_RUNNER_H

#include "launch.h"
#include "selection.h"

DazeBackendCompileAvailability backend_compile_availability(void);
DazeKvmCandidateObservation select_prepared_backend(const DazePreparedLaunch *launch,
                                                    DazeBackendRequest requested,
                                                    DazeBackendCompileAvailability compiled,
                                                    DazeKvmMachine *machine);
DazeCommandResult run_selected_prepared(DazePreparedLaunch *launch, void *unicorn_context,
                                        const char *path, DazeBackendRequest requested,
                                        const DazeBackendSelection *selection,
                                        const DazeKvmCandidateObservation *candidate,
                                        DazeKvmMachine *machine,
                                        DazeKvmSelectionDiagnostic *diagnostic,
                                        DazeKvmNormalOperationObservation *observation);
void report_kvm_terminal_observation(int debug, const DazeKvmSelectionDiagnostic *diagnostic,
                                     const DazeKvmNormalOperationObservation *observation);
void report_selection_failure(const char *path, const DazeBackendSelection *selection);
void report_selection_fallback(const DazeKvmSelectionDiagnostic *diagnostic, int unicorn_compiled);
void report_kvm_selection_diagnostic(int debug, const DazeKvmSelectionDiagnostic *diagnostic);
void report_kvm_selection_metrics(int metrics_enabled, const DazeRunMetrics *run_metrics,
                                  const DazeKvmSelectionDiagnostic *diagnostic);

#endif
