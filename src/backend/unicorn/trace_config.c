#include "trace_config.h"

#include <errno.h>
#include <stdlib.h>

static int parse_number(const char *text, uint32_t *value) {
  if (text == NULL || text[0] < '0' || text[0] > '9') return 0;
  char *end;
  errno = 0;
  const unsigned long long parsed = strtoull(text, &end, 0);
  if (errno != 0 || *end != '\0' || parsed > UINT32_MAX) return 0;
  *value = (uint32_t)parsed;
  return 1;
}

const char *daze_unicorn_trace_configure(DazeUnicornTraceConfig *config, uint32_t guest_size,
                                         const char *enabled, const char *begin, const char *end,
                                         const char *history, const char *dump_address,
                                         const char *dump_size) {
  *config = (DazeUnicornTraceConfig){0};
  DazeUnicornTraceConfig parsed = {.enabled = enabled != NULL, .history = history != NULL};
  if (!parsed.enabled) {
    if (begin != NULL || end != NULL || dump_address != NULL || dump_size != NULL)
      return "DAZE_TRACE options require DAZE_TRACE";
  } else {
    if (!parse_number(begin, &parsed.begin) || !parse_number(end, &parsed.end))
      return "DAZE_TRACE requires numeric DAZE_TRACE_BEGIN and DAZE_TRACE_END";
    if (parsed.begin > parsed.end || parsed.end >= guest_size ||
        parsed.end - parsed.begin >= DAZE_TRACE_MAX_WINDOW)
      return "DAZE_TRACE range must fit guest memory and span at most 64 KiB";
    if (dump_address != NULL) {
      parsed.dump_size = 16;
      if (!parse_number(dump_address, &parsed.dump_address) ||
          (dump_size != NULL && !parse_number(dump_size, &parsed.dump_size)) ||
          parsed.dump_size == 0 || parsed.dump_size > 64 || parsed.dump_size > guest_size ||
          parsed.dump_address > guest_size - parsed.dump_size)
        return "DAZE_TRACE dump must fit guest memory and contain 1..64 bytes";
    } else if (dump_size != NULL) {
      return "DAZE_TRACE_DUMP_SIZE requires DAZE_TRACE_DUMP_ADDRESS";
    }
  }
  *config = parsed;
  return NULL;
}

int daze_unicorn_trace_full_hook(const DazeUnicornTraceConfig *config) {
  return config->enabled || config->history;
}

int daze_unicorn_trace_record(DazeUnicornTraceConfig *config, uint64_t address) {
  if (!config->enabled || address < config->begin || address > config->end) return 0;
  if (config->records < DAZE_TRACE_MAX_RECORDS) {
    ++config->records;
    return 1;
  }
  if (config->truncated) return 0;
  config->truncated = 1;
  return 2;
}
