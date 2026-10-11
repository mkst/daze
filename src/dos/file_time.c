#include "file_time.h"

#include <stddef.h>

#include "dos_error.h"

int daze_dos_file_time_reply(int handle_valid, DazeDosFileTimeReply *reply) {
  if (reply == NULL) return 0;
  if (handle_valid) {
    /* DOS packed time/date for 2000-01-01 00:00:00. Keep timestamps
     * deterministic and independent of host filesystems. */
    *reply = (DazeDosFileTimeReply){
      .valid = 1,
      .cx = 0x0000,
      .dx = 0x2821,
      .error_ax = 0,
      .carry = 0,
    };
  } else {
    *reply = (DazeDosFileTimeReply){
      .valid = 0,
      .cx = 0,
      .dx = 0,
      .error_ax = DAZE_DOS_ERR_INVALID_HANDLE,
      .carry = 1,
    };
  }
  return 1;
}
