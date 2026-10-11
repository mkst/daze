#include "backend_request.h"

#include <string.h>

DazeBackendRequestParse daze_backend_request_parse(const char *value) {
  if (value == NULL) return (DazeBackendRequestParse){.valid = 0};
  if (strcmp(value, "auto") == 0)
    return (DazeBackendRequestParse){.valid = 1, .request = DAZE_BACKEND_REQUEST_AUTO};
  if (strcmp(value, "kvm") == 0)
    return (DazeBackendRequestParse){.valid = 1, .request = DAZE_BACKEND_REQUEST_KVM};
  if (strcmp(value, "unicorn") == 0)
    return (DazeBackendRequestParse){.valid = 1, .request = DAZE_BACKEND_REQUEST_UNICORN};
  return (DazeBackendRequestParse){.valid = 0};
}
