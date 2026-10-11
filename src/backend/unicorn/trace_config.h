#ifndef DAZE_UNICORN_TRACE_CONFIG_H
#define DAZE_UNICORN_TRACE_CONFIG_H

#include <stdint.h>

enum { DAZE_TRACE_MAX_WINDOW = 65536, DAZE_TRACE_MAX_RECORDS = 4096 };

typedef struct {
  int enabled;
  int history;
  uint32_t begin, end;
  uint32_t dump_address, dump_size;
  unsigned records;
  int truncated;
} DazeUnicornTraceConfig;

const char *daze_unicorn_trace_configure(DazeUnicornTraceConfig *config, uint32_t guest_size,
                                         const char *enabled, const char *begin, const char *end,
                                         const char *history, const char *dump_address,
                                         const char *dump_size);
int daze_unicorn_trace_full_hook(const DazeUnicornTraceConfig *config);
/* 0: no output, 1: instruction record, 2: one truncation notice. */
int daze_unicorn_trace_record(DazeUnicornTraceConfig *config, uint64_t address);

#endif
