#include "trace_config.h"

#include <stdio.h>

int main(void) {
  DazeUnicornTraceConfig config;
  const char *bad[] = {"",   "-1", "+1", " 1",         "1 ",
                       "1x", "0x", "08", "4294967296", "18446744073709551616"};
  for (unsigned i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
    if (daze_unicorn_trace_configure(&config, 0x20000, "1", bad[i], "0x1000", NULL, NULL, NULL) ==
          NULL ||
        daze_unicorn_trace_configure(&config, 0x20000, "1", "0", bad[i], NULL, NULL, NULL) ==
          NULL ||
        daze_unicorn_trace_configure(&config, 0x20000, "1", "0", "1", NULL, bad[i], "1") == NULL ||
        daze_unicorn_trace_configure(&config, 0x20000, "1", "0", "1", NULL, "0", bad[i]) == NULL)
      return 1;
  }
  const char *invalid[][4] = {
    {NULL, "1", NULL, NULL},      {"0", NULL, NULL, NULL},      {"2", "1", NULL, NULL},
    {"0", "0x20000", NULL, NULL}, {"0", "0x10000", NULL, NULL}, {"0", "1", NULL, "1"},
    {"0", "1", "0", "0"},         {"0", "1", "0", "65"},        {"0", "1", "0x1ffff", "2"},
    {"0", "1", "0x20000", "1"},
  };
  for (unsigned i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i)
    if (daze_unicorn_trace_configure(&config, 0x20000, "1", invalid[i][0], invalid[i][1], NULL,
                                     invalid[i][2], invalid[i][3]) == NULL ||
        daze_unicorn_trace_full_hook(&config))
      return 2;
  if (daze_unicorn_trace_configure(&config, 0x20000, NULL, NULL, NULL, NULL, NULL, NULL) ||
      daze_unicorn_trace_full_hook(&config))
    return 3;
  if (daze_unicorn_trace_configure(&config, 0x20000, NULL, NULL, NULL, "1", NULL, NULL) ||
      !daze_unicorn_trace_full_hook(&config) || daze_unicorn_trace_record(&config, 0))
    return 4;
  if (!daze_unicorn_trace_configure(&config, 0x20000, NULL, "0", "1", NULL, NULL, NULL)) return 5;
  if (daze_unicorn_trace_configure(&config, 0x20000, "1", "0x10000", "0x1ffff", NULL, "0x1ffc0",
                                   "64") ||
      config.dump_size != 64)
    return 6;
  if (daze_unicorn_trace_record(&config, 0xffff) || daze_unicorn_trace_record(&config, 0x20000))
    return 7;
  for (unsigned i = 0; i < DAZE_TRACE_MAX_RECORDS; ++i)
    if (daze_unicorn_trace_record(&config, 0x10000) != 1) return 8;
  if (daze_unicorn_trace_record(&config, 0x10000) != 2) return 9;
  for (unsigned i = 0; i < 10000; ++i)
    if (daze_unicorn_trace_record(&config, 0x10000)) return 10;
  if (daze_unicorn_trace_configure(&config, 0x20000, "1", "4096", "4096", NULL, "0", NULL) ||
      config.dump_size != 16 || config.records)
    return 11;
  puts("Unicorn trace configuration and budget contract passed");
  return 0;
}
