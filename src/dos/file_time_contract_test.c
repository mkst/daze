#include "file_time.h"

#include <stdio.h>

int main(void) {
  DazeDosFileTimeReply reply;
  if (!daze_dos_file_time_reply(1, &reply) || !reply.valid || reply.cx != 0x0000 ||
      reply.dx != 0x2821 || reply.error_ax != 0 || reply.carry != 0) {
    fprintf(stderr, "dos file time: valid reply cx=%04x dx=%04x error=%u carry=%d valid=%d\n",
            reply.cx, reply.dx, (unsigned)reply.error_ax, reply.carry, reply.valid);
    return 1;
  }
  if (!daze_dos_file_time_reply(0, &reply) || reply.valid || reply.cx != 0 || reply.dx != 0 ||
      reply.error_ax != 6 || reply.carry != 1) {
    fprintf(stderr, "dos file time: invalid reply cx=%04x dx=%04x error=%u carry=%d valid=%d\n",
            reply.cx, reply.dx, (unsigned)reply.error_ax, reply.carry, reply.valid);
    return 1;
  }
  if (daze_dos_file_time_reply(1, NULL)) {
    fprintf(stderr, "dos file time: NULL reply accepted\n");
    return 1;
  }
  puts("dos file time: passed");
  return 0;
}
