#include "backend_request.h"

#include <stddef.h>

static int expect(const char *value, int valid, DazeBackendRequest request) {
  const DazeBackendRequestParse parsed = daze_backend_request_parse(value);
  return parsed.valid == valid && (!valid || parsed.request == request);
}

int main(void) {
  return expect("auto", 1, DAZE_BACKEND_REQUEST_AUTO) &&
             expect("kvm", 1, DAZE_BACKEND_REQUEST_KVM) &&
             expect("unicorn", 1, DAZE_BACKEND_REQUEST_UNICORN) &&
             expect(NULL, 0, DAZE_BACKEND_REQUEST_AUTO) &&
             expect("", 0, DAZE_BACKEND_REQUEST_AUTO) &&
             expect("AUTO", 0, DAZE_BACKEND_REQUEST_AUTO) &&
             expect("auto ", 0, DAZE_BACKEND_REQUEST_AUTO) &&
             expect("nvme", 0, DAZE_BACKEND_REQUEST_AUTO) &&
             expect("unicorn2", 0, DAZE_BACKEND_REQUEST_AUTO)
           ? 0
           : 1;
}
