#include "probe_service.h"

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <stddef.h>

int main(void) {
  const struct {
    uint8_t interrupt;
    uint16_t ax, bx;
    DazeBiosProbeKind kind;
    uint16_t mask, reply_ax, reply_bx, reply_cx, reply_dx;
  } cases[] = {
    {0x11, 0, 0, DAZE_BIOS_PROBE_EQUIPMENT, 1, 0x0020, 0, 0, 0},
    {0x11, 0xffff, 0xffff, DAZE_BIOS_PROBE_EQUIPMENT, 1, 0x0020, 0, 0, 0},
    {0x10, 0x0f00, 0x1234, DAZE_BIOS_PROBE_VIDEO_MODE, 3, 0x5003, 0x34, 0, 0},
    {0x10, 0x0fff, 0xffab, DAZE_BIOS_PROBE_VIDEO_MODE, 3, 0x5003, 0xab, 0, 0},
    {0x10, 0x1200, 0x0010, DAZE_BIOS_PROBE_EGA, 6, 0, 3, 1, 0},
    {0x10, 0x1200, 0xff10, DAZE_BIOS_PROBE_EGA, 6, 0, 3, 1, 0},
    {0x1a, 0, 0, DAZE_BIOS_PROBE_TIMER, 13, 0, 0, 0, 0},
    {0x1a, 0x00ff, 0xffff, DAZE_BIOS_PROBE_TIMER, 13, 0, 0, 0, 0},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
    DazeBiosProbeReply reply = {.register_write_mask = 0xffff, .carry = 1};
    assert(daze_bios_probe_dispatch(cases[i].interrupt, cases[i].ax, cases[i].bx, &reply) ==
           cases[i].kind);
    assert(reply.register_write_mask == cases[i].mask && reply.carry == 0);
    assert(reply.ax == cases[i].reply_ax && reply.bx == cases[i].reply_bx);
    assert(reply.cx == cases[i].reply_cx && reply.dx == cases[i].reply_dx);
  }
  const uint16_t unsupported[][3] = {
    {0x10, 0x0000, 0x10}, {0x10, 0x0eff, 0},    {0x10, 0x1000, 0},      {0x10, 0x1201, 0x10},
    {0x10, 0x12ff, 0x10}, {0x10, 0x1200, 0x11}, {0x10, 0x1200, 0x0f},   {0x1a, 0x0100, 0},
    {0x67, 0xde00, 0},    {0x15, 0xc000, 0},    {0xff, 0xffff, 0xffff},
  };
  for (size_t i = 0; i < sizeof(unsupported) / sizeof(unsupported[0]); ++i) {
    DazeBiosProbeReply reply = {.register_write_mask = 0xffff, .carry = 1};
    assert(daze_bios_probe_dispatch((uint8_t)unsupported[i][0], unsupported[i][1],
                                    unsupported[i][2], &reply) == DAZE_BIOS_PROBE_UNSUPPORTED);
    assert(reply.register_write_mask == 0 && reply.carry == 0);
    assert(reply.ax == 0 && reply.bx == 0 && reply.cx == 0 && reply.dx == 0);
  }
  assert(daze_bios_probe_dispatch(0x11, 0, 0, NULL) == DAZE_BIOS_PROBE_UNSUPPORTED);
  return 0;
}
