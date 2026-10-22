#include "image.h"

#include <stdio.h>
#include <string.h>

enum { k_memory_size = 0x20000, k_max_writes = 5 };

typedef struct {
  uint8_t memory[k_memory_size];
  uint32_t addresses[k_max_writes];
  size_t sizes[k_max_writes];
  size_t writes;
  size_t fail_on_write;
} TestMemory;

static int write_memory(void *context, uint32_t address, const void *bytes, size_t size) {
  TestMemory *memory = context;
  if (memory == NULL || bytes == NULL || memory->writes == k_max_writes ||
      address > k_memory_size || size > k_memory_size - address) {
    return 0;
  }
  const size_t write = memory->writes++;
  memory->addresses[write] = address;
  memory->sizes[write] = size;
  if (memory->fail_on_write != 0 && memory->fail_on_write == write + 1) return 0;
  memcpy(memory->memory + address, bytes, size);
  return 1;
}

static int expect(int condition, const char *message) {
  if (!condition) fprintf(stderr, "%s\n", message);
  return condition;
}

static int test_success(void) {
  TestMemory memory = {0};
  uint8_t expected_psp[256] = {0};
  uint8_t expected_env[512] = {0};
  const uint8_t defaults[] = {'P', 'A', 'T', 'H', '=', 'C',  ':', '\\', 0,   'T', 'E',
                              'M', 'P', '=', 'C', ':', '\\', 'T', 'M',  'P', 0,   'T',
                              'M', 'P', '=', 'C', ':', '\\', 'T', 'M',  'P', 0,   0};
  const uint8_t dpmi[] = {
    0xcd, 0xfe, /* int 0xfe */
    0xf4        /* hlt */
  };
  const uint8_t dos[] = {
    0xcd, 0xfd, /* int 0xfd */
    0xcf        /* iret */
  };
  const uint8_t iret[] = {
    0xcf /* iret */
  };
  memcpy(expected_env, defaults, sizeof(defaults));
  size_t env_size = sizeof(defaults);
  expected_env[env_size++] = 1;
  expected_env[env_size++] = 0;
  /* The established drive-qualified path handling retains its leading slash
   * after the trailer's C:\\ prefix; preserve that exact current image. */
  memcpy(expected_env + env_size, "C:\\\\ASPSX.EXE", sizeof("C:\\\\ASPSX.EXE"));
  env_size += sizeof("C:\\\\ASPSX.EXE");

  expected_psp[0] = 0xcd;
  expected_psp[1] = 0x20;
  expected_psp[2] = 0xff;
  expected_psp[3] = 0x9f;
  for (size_t offset = 0x0a; offset <= 0x12; offset += 4) {
    expected_psp[offset] = 0x10;
    expected_psp[offset + 2] = 0x00;
    expected_psp[offset + 3] = 0x03;
  }
  expected_psp[0x16] = 0;
  expected_psp[0x17] = 0;
  memset(expected_psp + 0x18, 0xff, 20);
  for (uint8_t index = 0; index < 5; ++index)
    expected_psp[0x18 + index] = index;
  expected_psp[0x2c] = 0x00;
  expected_psp[0x2d] = 0x07;
  expected_psp[0x32] = 20;
  expected_psp[0x34] = 0x18;
  expected_psp[0x36] = 0xf0;
  expected_psp[0x37] = 0x0f;
  memset(expected_psp + 0x38, 0xff, 4);
  expected_psp[0x50] = 0xcd;
  expected_psp[0x51] = 0x21;
  expected_psp[0x52] = 0xcb;
  expected_psp[0x80] = 3;
  memcpy(expected_psp + 0x81, " -x", 3);
  expected_psp[0x84] = '\r';

  return expect(daze_image_write_process_with_memory(write_memory, &memory, " -x", "C:\\ASPSX.EXE",
                                                     0x0ff0, 0x0700, 0x0200, 0x0300, NULL, 0),
                "writer failed") &&
         expect(memory.writes == 5, "write count mismatch") &&
         expect(memory.addresses[0] == 0x0ff00 && memory.sizes[0] == sizeof(expected_psp),
                "PSP write mismatch") &&
         expect(memory.addresses[1] == 0x07000 && memory.sizes[1] == env_size,
                "environment write mismatch") &&
         expect(memory.addresses[2] == 0x02000 && memory.sizes[2] == sizeof(dpmi),
                "DPMI stub write mismatch") &&
         expect(memory.addresses[3] == 0x03000 && memory.sizes[3] == sizeof(dos),
                "DOS stub write mismatch") &&
         expect(memory.addresses[4] == 0x03010 && memory.sizes[4] == sizeof(iret),
                "IRET write mismatch") &&
         expect(memcmp(memory.memory + 0x0ff00, expected_psp, sizeof(expected_psp)) == 0,
                "PSP bytes mismatch") &&
         expect(memcmp(memory.memory + 0x07000, expected_env, env_size) == 0,
                "environment bytes mismatch") &&
         expect(memcmp(memory.memory + 0x02000, dpmi, sizeof(dpmi)) == 0,
                "DPMI stub bytes mismatch") &&
         expect(memcmp(memory.memory + 0x03000, dos, sizeof(dos)) == 0,
                "DOS stub bytes mismatch") &&
         expect(memcmp(memory.memory + 0x03010, iret, sizeof(iret)) == 0, "IRET bytes mismatch");
}

static int test_failures(void) {
  TestMemory memory = {0};
  char oversized_tail[128];
  memset(oversized_tail, 'x', sizeof(oversized_tail) - 1);
  oversized_tail[sizeof(oversized_tail) - 1] = '\0';
  if (!expect(
        !daze_image_write_process_with_memory(NULL, &memory, "", "C:\\A.EXE", 1, 2, 3, 4, NULL, 0),
        "NULL writer accepted") ||
      !expect(!daze_image_write_process_with_memory(write_memory, &memory, NULL, "C:\\A.EXE", 1, 2,
                                                    3, 4, NULL, 0),
              "NULL tail accepted") ||
      !expect(
        !daze_image_write_process_with_memory(write_memory, &memory, "", NULL, 1, 2, 3, 4, NULL, 0),
        "NULL path accepted") ||
      !expect(!daze_image_write_process_with_memory(write_memory, &memory, oversized_tail,
                                                    "C:\\A.EXE", 1, 2, 3, 4, NULL, 0),
              "oversized tail accepted") ||
      !expect(memory.writes == 0, "invalid input performed a write"))
    return 0;
  memory.fail_on_write = 3;
  return expect(!daze_image_write_process_with_memory(write_memory, &memory, "", "C:\\A.EXE", 1, 2,
                                                      3, 4, NULL, 0),
                "write failure accepted") &&
         expect(memory.writes == 3, "writer continued after callback failure");
}

static int test_environment_bounds(void) {
  const size_t lengths[] = {466, 467, 468, 478, 479, 480};
  for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); ++i) {
    TestMemory memory = {0};
    char variable[481];
    memset(variable, 'x', lengths[i]);
    variable[0] = 'X';
    variable[1] = '=';
    variable[lengths[i]] = '\0';
    const char *vars[] = {variable};
    const int success = daze_image_write_process_with_memory(
      write_memory, &memory, "", "A.EXE", 0x0ff0, 0x0700, 0x0200, 0x0300, vars, 1);
    if (!expect(success == (lengths[i] <= 467), "environment boundary mismatch") ||
        !expect(success ? memory.sizes[1] == lengths[i] + 45 : memory.writes == 0,
                "environment boundary wrote unexpected bytes"))
      return 0;
  }
  return 1;
}

static int test_environment_overrides(void) {
  TestMemory memory = {0};
  const char *variables[] = {"PATH=X:\\", "TEMP=C:\\WORK",   "TMP=",           "PATH=D:\\;C:\\",
                             "EXTRA=old", "EXTRA=new=value", "PATH_EXTRA=keep"};
  const char expected[] = "PATH=D:\\;C:\\\0TEMP=C:\\WORK\0TMP=\0EXTRA=new=value\0PATH_EXTRA=keep\0"
                          "\0\x01\0D:\\\\CPP.EXE\0";
  if (!expect(daze_image_write_process_with_memory(write_memory, &memory, "", "D:/CPP.EXE", 0x0ff0,
                                                   0x0700, 0x0200, 0x0300, variables,
                                                   sizeof(variables) / sizeof(variables[0])),
              "environment overrides rejected") ||
      !expect(memory.sizes[1] == sizeof(expected) - 1 &&
                memcmp(memory.memory + 0x07000, expected, sizeof(expected) - 1) == 0,
              "environment overrides duplicated names, lost values, or damaged trailer"))
    return 0;

  const char *names[] = {"PATH", "TEMP", "TMP"};
  const size_t maximum_lengths[] = {476, 479, 478};
  for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
    for (size_t excess = 0; excess < 2; ++excess) {
      TestMemory bounded = {0};
      char variable[481];
      const size_t length = maximum_lengths[i] + excess;
      memset(variable, 'x', length);
      memcpy(variable, names[i], strlen(names[i]));
      variable[strlen(names[i])] = '=';
      variable[length] = '\0';
      const char *values[] = {variable};
      const int success = daze_image_write_process_with_memory(
        write_memory, &bounded, "", "A.EXE", 0x0ff0, 0x0700, 0x0200, 0x0300, values, 1);
      if (!expect(success == (excess == 0), "overridden environment size boundary mismatch") ||
          !expect(success ? bounded.sizes[1] == 512 : bounded.writes == 0,
                  "overridden environment overflow performed unexpected writes"))
        return 0;
    }
  }
  const char *invalid[] = {NULL, "", "NAME", "=value"};
  for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
    TestMemory rejected = {0};
    if (!expect(!daze_image_write_process_with_memory(write_memory, &rejected, "", "A.EXE", 0x0ff0,
                                                      0x0700, 0x0200, 0x0300, &invalid[i], 1) &&
                  rejected.writes == 0,
                "malformed environment entry accepted"))
      return 0;
  }
  return 1;
}

int main(void) {
  const int pass =
    test_success() && test_failures() && test_environment_bounds() && test_environment_overrides();
  fprintf(stderr, "Image process contract test: %s\n", pass ? "passed" : "failed");
  return pass ? 0 : 1;
}
