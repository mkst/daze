#ifndef DAZE_KVM_SELECTION_METRICS_H
#define DAZE_KVM_SELECTION_METRICS_H

#include "selection.h"

typedef struct {
  const char *backend;
  const char *selection;
} DazeKvmSelectionMetrics;

DazeKvmSelectionMetrics
daze_kvm_selection_metrics_from_diagnostic(const DazeKvmSelectionDiagnostic *diagnostic);

#endif
