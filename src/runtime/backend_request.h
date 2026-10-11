#ifndef DAZE_BACKEND_REQUEST_H
#define DAZE_BACKEND_REQUEST_H

#include "backend_selection.h"

/* An unknown backend name is invalid; parsing consumes no execution state. */
typedef struct {
  int valid;
  DazeBackendRequest request;
} DazeBackendRequestParse;

DazeBackendRequestParse daze_backend_request_parse(const char *value);
#endif
