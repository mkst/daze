#include "request.h"

#include <stdio.h>
#include <string.h>

static int descriptor_equals(const uint8_t *left, const uint8_t *right) {
  return memcmp(left, right, 8) == 0;
}

static int image(const uint8_t b0, const uint8_t b1, const uint8_t b2, const uint8_t b3,
                 const uint8_t b4, const uint8_t b5, const uint8_t b6, const uint8_t b7,
                 uint8_t descriptor[8]) {
  const uint8_t value[8] = {b0, b1, b2, b3, b4, b5, b6, b7};
  memcpy(descriptor, value, 8);
  return 1;
}

static int check_base_image(uint16_t selector, const uint8_t pre[8], const uint8_t post[8],
                            uint32_t base) {
  DazeDpmiRequest request = {.function = 0x0007, .selector = selector, .operand = base};
  DazeDpmiResult result;
  daze_dpmi_request_set_segment_base(&request, pre, &result);
  return result.success && result.dpmi_error == 0 && result.ax == 0x0007 &&
         descriptor_equals(result.descriptor, post);
}

static int failed_with(uint16_t error, const DazeDpmiResult *result) {
  return !result->success && result->dpmi_error == error && result->ax == error;
}

static int hostile_descriptors(void) {
  uint8_t used[20] = {0};
  used[16] = 1;
  used[18] = 1;
  uint8_t before[sizeof(used)];
  memcpy(before, used, sizeof(used));
  DazeDpmiLdtAllocator allocator = {.used = used, .capacity = 20, .first_index = 16};
  const uint16_t selectors[] = {0, 0x80, 0x7c, 0x8c, 0xa4, 0xffff};
  for (size_t i = 0; i < sizeof(selectors) / sizeof(selectors[0]); ++i) {
    DazeDpmiRequest request = {.function = 1, .selector = selectors[i]};
    DazeDpmiResult result;
    memset(&result, 0xa5, sizeof(result));
    daze_dpmi_request_free_ldt_descriptor(&request, &allocator, &result);
    if (!failed_with(0x8022, &result) || result.base != 0 || result.handle != 0 ||
        memcmp(used, before, sizeof(used)) != 0)
      return 0;
  }
  const uint8_t descriptor[8] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x93, 0x67, 0x88};
  const uint16_t rights[] = {0x1093, 0x0083, 0x00b3, 0x00d3, 0x00f3, 0x0098, 0x009c, 0x009e};
  for (size_t i = 0; i < sizeof(rights) / sizeof(rights[0]); ++i) {
    DazeDpmiRequest request = {.function = 9, .selector = 0x84, .rights = rights[i]};
    DazeDpmiResult result;
    daze_dpmi_request_set_access_rights(&request, descriptor, &result);
    if (!failed_with(0x8021, &result) || !descriptor_equals(result.descriptor, descriptor))
      return 0;
  }
  const uint32_t limits[] = {0x100000, 0x100ffe, 0xfffffffe};
  for (size_t i = 0; i < sizeof(limits) / sizeof(limits[0]); ++i) {
    DazeDpmiRequest request = {.function = 8, .selector = 0x84, .operand = limits[i]};
    DazeDpmiResult result;
    daze_dpmi_request_set_segment_limit(&request, descriptor, &result);
    if (!failed_with(0x8021, &result) || !descriptor_equals(result.descriptor, descriptor))
      return 0;
  }
  const DazeDpmiLdtAllocator invalid[] = {
    {.used = NULL, .capacity = 20, .first_index = 16},
    {.used = used, .capacity = 20, .first_index = 0},
    {.used = used, .capacity = 20, .first_index = 20},
    {.used = used, .capacity = 20, .first_index = 21},
  };
  for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
    DazeDpmiLdtAllocator candidate = invalid[i];
    DazeDpmiRequest request = {.function = 0, .count = 1};
    DazeDpmiResult result;
    daze_dpmi_request_allocate_ldt_descriptors(&request, &candidate, &result);
    if (!failed_with(0x8011, &result) || memcmp(used, before, sizeof(used)) != 0) return 0;
  }
  DazeDpmiRequest too_many = {.function = 0, .count = 5};
  DazeDpmiResult result;
  daze_dpmi_request_allocate_ldt_descriptors(&too_many, &allocator, &result);
  return failed_with(0x8011, &result) && memcmp(used, before, sizeof(used)) == 0;
}

static int hostile_linear_requests(void) {
  DazeDpmiLinearMemory memory;
  daze_dpmi_linear_memory_init(&memory, 0x50000, 0x54000);
  DazeDpmiRequest allocate = {.function = 0x0501, .size = 0x1000};
  DazeDpmiResult result;
  daze_dpmi_request_allocate_linear_memory(&memory, &allocate, &result);
  if (!result.success || result.base != 0x50000 || result.handle != 1) return 0;
  daze_dpmi_request_allocate_linear_memory(&memory, &allocate, &result);
  if (!result.success || result.base != 0x51000 || result.handle != 2) return 0;
  const DazeDpmiLinearMemory before = memory;
  const DazeDpmiRequest rejected[] = {
    {.function = 0x0503, .operand = 0, .size = 0x1000},
    {.function = 0x0503, .operand = UINT32_MAX, .size = 0x1000},
    {.function = 0x0503, .operand = 1, .size = 0x1001},
    {.function = 0x0503, .operand = 2, .size = 0x3001},
    {.function = 0x0503, .operand = 2, .size = 0},
    {.function = 0x0503, .operand = 2, .size = UINT32_MAX},
  };
  for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); ++i) {
    daze_dpmi_request_resize_linear_memory(&memory, &rejected[i], &result);
    if (!failed_with(0x8012, &result) || result.base != 0 || result.handle != 0 ||
        memcmp(&memory, &before, sizeof(memory)) != 0)
      return 0;
  }
  const DazeDpmiRequest release = {.function = 0x0502, .operand = UINT32_MAX};
  daze_dpmi_request_free_linear_memory(&memory, &release, &result);
  if (!failed_with(0x8023, &result) || memcmp(&memory, &before, sizeof(memory)) != 0) return 0;
  daze_dpmi_request_resize_linear_memory(NULL, &rejected[0], &result);
  if (!failed_with(0x8012, &result)) return 0;
  daze_dpmi_request_free_linear_memory(NULL, &release, &result);
  return failed_with(0x8023, &result);
}

static int free_memory_information_image(void) {
  const struct {
    uint32_t largest;
    uint8_t prefix[4];
  } cases[] = {
    {0, {0, 0, 0, 0}},
    {0x12345678, {0x78, 0x56, 0x34, 0x12}},
    {UINT32_MAX, {0xff, 0xff, 0xff, 0xff}},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
    uint8_t guarded[50];
    memset(guarded, 0xa5, sizeof(guarded));
    daze_dpmi_free_memory_information_encode(cases[i].largest, guarded + 1);
    if (guarded[0] != 0xa5 || guarded[49] != 0xa5 ||
        memcmp(guarded + 1, cases[i].prefix, sizeof(cases[i].prefix)) != 0)
      return 0;
    for (size_t byte = 5; byte < 49; ++byte)
      if (guarded[byte] != 0xff) return 0;
  }
  return 1;
}

int main(void) {
  int pass = hostile_descriptors() && hostile_linear_requests() && free_memory_information_image();

  DazeDosMemory dos_memory;
  daze_dos_memory_init(&dos_memory, 0x3000, 0x3100);
  uint8_t dos_ldt_used[32] = {0};
  DazeDpmiLdtAllocator dos_allocator = {.used = dos_ldt_used, .capacity = 32, .first_index = 16};
  DazeDpmiRequest dos_request = {.function = 0x0100, .count = 6};
  DazeDpmiResult dos_result;
  DazeDpmiScalarResultContract dos_contract;
  const uint8_t dos_descriptor[8] = {0x5f, 0, 0, 0, 3, 0x92, 0, 0};
  daze_dpmi_request_allocate_dos_memory(&dos_memory, &dos_allocator, &dos_request, &dos_result);
  pass = pass && dos_result.success && dos_result.ax == 0x3000 && dos_result.handle == 0x84 &&
         descriptor_equals(dos_result.descriptor, dos_descriptor) && dos_ldt_used[16] == 1 &&
         dos_memory.next_segment == 0x3006 && dos_memory.allocations[0].paragraphs == 6 &&
         daze_dpmi_request_scalar_result_contract(&dos_request, &dos_result, &dos_contract) &&
         dos_contract.write_ax16 && dos_contract.ax == 0x3000 && dos_contract.write_dx16 &&
         dos_contract.dx == 0x84 && !dos_contract.write_bx16 && !dos_contract.write_cl;
  memset(dos_ldt_used, 1, sizeof(dos_ldt_used));
  const DazeDosMemory dos_before = dos_memory;
  daze_dpmi_request_allocate_dos_memory(&dos_memory, &dos_allocator, &dos_request, &dos_result);
  pass = pass && !dos_result.success && dos_result.ax == 0x8011 &&
         memcmp(&dos_memory, &dos_before, sizeof(dos_memory)) == 0 &&
         daze_dpmi_request_scalar_result_contract(&dos_request, &dos_result, &dos_contract) &&
         dos_contract.write_ax16 && dos_contract.write_bx16 && dos_contract.bx == 0xfa &&
         !dos_contract.write_dx16;
  memset(dos_ldt_used, 0, sizeof(dos_ldt_used));
  dos_request.count = 0x100;
  daze_dpmi_request_allocate_dos_memory(&dos_memory, &dos_allocator, &dos_request, &dos_result);
  pass = pass && !dos_result.success && dos_result.ax == 8 && dos_ldt_used[16] == 0 &&
         memcmp(&dos_memory, &dos_before, sizeof(dos_memory)) == 0;
  dos_request.count = 0;
  daze_dpmi_request_allocate_dos_memory(&dos_memory, &dos_allocator, &dos_request, &dos_result);
  pass = pass && !dos_result.success && dos_result.ax == 8 && dos_ldt_used[16] == 0 &&
         memcmp(&dos_memory, &dos_before, sizeof(dos_memory)) == 0;

  /* Exact ASPSX 2.21 0501h evidence: request BX:CX=0001:5000h inside the
   * accepted [00050000h,007f0000h) arena yields base 00050000h, handle 1. */
  DazeDpmiLinearMemory memory;
  DazeDpmiLinearAllocateResult chain_result;
  daze_dpmi_linear_memory_init(&memory, 0x00050000u, 0x007f0000u);
  DazeDpmiRequest allocate = {.function = 0x0501, .size = 0x00015000u};
  DazeDpmiResult result;
  DazeDpmiRequest get_base = {.function = 0x0006, .selector = 0x0700};
  daze_dpmi_request_get_segment_base(&get_base, 0x00007000u, &result);
  pass = pass && result.success && result.dpmi_error == 0 && result.ax == 0x0006 &&
         result.base == 0x00007000u;

  daze_dpmi_request_allocate_linear_memory(&memory, &allocate, &result);
  pass = pass && result.success && result.dpmi_error == 0 && result.ax == 0x0501 &&
         result.base == 0x00050000u && result.handle == 1;
  chain_result.base = result.base;
  chain_result.handle = result.handle;

  DazeDpmiRequest second_allocate = {.function = 0x0501, .size = 0x00001000u};
  DazeDpmiResult second_result;
  daze_dpmi_request_allocate_linear_memory(&memory, &second_allocate, &second_result);
  pass = pass && second_result.success && second_result.dpmi_error == 0 &&
         second_result.base == 0x00065000u && second_result.handle == 2;

  /* A zero-width arena must fail atomically with error 8012h and zero outputs. */
  DazeDpmiLinearMemory full_memory;
  daze_dpmi_linear_memory_init(&full_memory, 0x00050000u, 0x00050000u);
  DazeDpmiResult full_result;
  daze_dpmi_request_allocate_linear_memory(&full_memory, &allocate, &full_result);
  pass = pass && !full_result.success && full_result.dpmi_error == 0x8012 &&
         full_result.ax == 0x8012 && full_result.base == 0 && full_result.handle == 0;

  /* 0503h names the allocation through SI:DI, not a selector. */
  DazeDpmiRequest resize = {.function = 0x0503, .operand = 2, .size = 0x00002000u};
  daze_dpmi_request_resize_linear_memory(&memory, &resize, &result);
  pass = pass && result.success && result.dpmi_error == 0 && result.ax == 0x0503 &&
         result.base == 0x00065000u;
  DazeDpmiRequest bad_resize = {.function = 0x0503, .operand = 0x99u, .size = 0x00001000u};
  daze_dpmi_request_resize_linear_memory(&memory, &bad_resize, &result);
  pass = pass && !result.success && result.dpmi_error == 0x8012 && result.ax == 0x8012;
  const DazeDpmiLinearMemory before_overflow_resize = memory;
  DazeDpmiRequest overflow_resize = {.function = 0x0503, .operand = 1, .size = UINT32_MAX};
  daze_dpmi_request_resize_linear_memory(&memory, &overflow_resize, &result);
  pass = pass && failed_with(0x8012, &result) &&
         memcmp(&memory, &before_overflow_resize, sizeof(memory)) == 0;

  DazeDpmiLinearMemory bounded_memory;
  daze_dpmi_linear_memory_init(&bounded_memory, 0x50000, 0x52000);
  const DazeDpmiLinearMemory empty_bounded_memory = bounded_memory;
  DazeDpmiRequest overflow_allocate = {.function = 0x0501, .size = UINT32_MAX};
  daze_dpmi_request_allocate_linear_memory(&bounded_memory, &overflow_allocate, &result);
  pass = pass && failed_with(0x8012, &result) && result.base == 0 && result.handle == 0 &&
         memcmp(&bounded_memory, &empty_bounded_memory, sizeof(bounded_memory)) == 0;
  DazeDpmiRequest bounded_allocate = {.function = 0x0501, .size = 0x1000};
  daze_dpmi_request_allocate_linear_memory(&bounded_memory, &bounded_allocate, &result);
  pass = pass && result.success && result.base == 0x50000 && result.handle == 1;
  const DazeDpmiLinearMemory bounded_before = bounded_memory;
  DazeDpmiRequest cross_end_resize = {.function = 0x0503, .operand = 1, .size = 0x3000};
  daze_dpmi_request_resize_linear_memory(&bounded_memory, &cross_end_resize, &result);
  pass = pass && failed_with(0x8012, &result) &&
         memcmp(&bounded_memory, &bounded_before, sizeof(bounded_memory)) == 0;

  /* Release retracts the arena; repeated/unknown releases return 8023h. */
  DazeDpmiRequest free = {.function = 0x0502, .operand = 2};
  daze_dpmi_request_free_linear_memory(&memory, &free, &result);
  pass = pass && result.success && result.dpmi_error == 0 && result.ax == 0x0502;
  daze_dpmi_request_free_linear_memory(&memory, &free, &result);
  pass = pass && !result.success && result.dpmi_error == 0x8023 && result.ax == 0x8023;
  DazeDpmiRequest bad_free = {.function = 0x0502, .operand = 0x99u};
  daze_dpmi_request_free_linear_memory(&memory, &bad_free, &result);
  pass = pass && !result.success && result.dpmi_error == 0x8023 && result.ax == 0x8023;
  DazeDpmiRequest free_one = {.function = 0x0502, .operand = 1};
  daze_dpmi_request_free_linear_memory(&memory, &free_one, &result);
  pass = pass && result.success && result.dpmi_error == 0 && result.ax == 0x0502;
  daze_dpmi_request_free_linear_memory(&memory, &free_one, &result);
  pass = pass && !result.success && result.dpmi_error == 0x8023 && result.ax == 0x8023;
  DazeDpmiResult free_information;
  DazeDpmiRequest information = {.function = 0x0500};
  daze_dpmi_request_get_free_memory_information(&memory, &information, &free_information);
  pass = pass && free_information.success && free_information.largest_available == 0x7a0000;

  /* 0000h: ASPSX first allocates four slots after 000Ah consumed slot 16,
   * so the first contiguous allocation is selector 008Ch (slots 17--20).
   * Invalid and exhausted inputs leave the caller bitmap untouched. */
  uint8_t allocation_used[24] = {0};
  allocation_used[16] = 1;
  DazeDpmiLdtAllocator descriptors = {
    .used = allocation_used, .capacity = sizeof(allocation_used), .first_index = 16};
  DazeDpmiRequest descriptor_allocate = {.function = 0x0000, .count = 4};
  daze_dpmi_request_allocate_ldt_descriptors(&descriptor_allocate, &descriptors, &result);
  pass = pass && result.success && result.ax == 0x008c && allocation_used[16] == 1 &&
         allocation_used[17] == 1 && allocation_used[20] == 1 && allocation_used[21] == 0;
  const uint8_t allocation_before[24] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                         0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0};
  descriptor_allocate.count = 0;
  daze_dpmi_request_allocate_ldt_descriptors(&descriptor_allocate, &descriptors, &result);
  pass = pass && !result.success && result.ax == 0x8011 &&
         memcmp(allocation_used, allocation_before, sizeof(allocation_used)) == 0;
  memset(allocation_used + 16, 1, sizeof(allocation_used) - 16);
  descriptor_allocate.count = 1;
  daze_dpmi_request_allocate_ldt_descriptors(&descriptor_allocate, &descriptors, &result);
  pass = pass && !result.success && result.ax == 0x8011;

  DazeDpmiRequest descriptor_free = {.function = 0x0001, .selector = 0x0084};
  daze_dpmi_request_free_ldt_descriptor(&descriptor_free, &descriptors, &result);
  pass = pass && result.success && result.ax == 0x0001 && allocation_used[16] == 0;
  daze_dpmi_request_free_ldt_descriptor(&descriptor_free, &descriptors, &result);
  pass = pass && !result.success && result.ax == 0x8022 && allocation_used[16] == 0;
  uint8_t allocation_after_release[24];
  memcpy(allocation_after_release, allocation_used, sizeof(allocation_after_release));
  descriptor_free.selector = 0x0008;
  daze_dpmi_request_free_ldt_descriptor(&descriptor_free, &descriptors, &result);
  pass = pass && failed_with(0x8022, &result) &&
         memcmp(allocation_used, allocation_after_release, sizeof(allocation_used)) == 0;
  descriptor_free.selector = 0x00fc;
  daze_dpmi_request_free_ldt_descriptor(&descriptor_free, &descriptors, &result);
  pass = pass && failed_with(0x8022, &result) &&
         memcmp(allocation_used, allocation_after_release, sizeof(allocation_used)) == 0;

  DazeDpmiRequest selector_increment = {.function = 0x0003};
  daze_dpmi_request_get_selector_increment(&selector_increment, &result);
  pass = pass && result.success && result.dpmi_error == 0 && result.ax == 0x0008;

  /* 0007h: the recorded selector/base images. The shared allocation base is
   * fed back as the CX:DX operand, proving the 0501h -> 0007h chain. */
  uint8_t pre[8];
  uint8_t post[8];
  image(0x00, 0x00, 0x00, 0x00, 0x00, 0x97, 0xC0, 0x00, pre);
  image(0x00, 0x00, 0x00, 0x00, 0x05, 0x97, 0xC0, 0x00, post);
  pass = pass && check_base_image(0x0094, pre, post, chain_result.base);
  image(0x00, 0x00, 0x00, 0x00, 0x00, 0x9B, 0xC0, 0x00, pre);
  image(0x00, 0x00, 0x00, 0x00, 0x05, 0x9B, 0xC0, 0x00, post);
  pass = pass && check_base_image(0x009C, pre, post, chain_result.base);
  image(0x7F, 0x00, 0x00, 0x00, 0x00, 0x97, 0x40, 0x00, pre);
  image(0x7F, 0x00, 0x00, 0x00, 0x05, 0x97, 0x40, 0x00, post);
  pass = pass && check_base_image(0x00A4, pre, post, chain_result.base);

  /* 0008h: the two recorded limit images. FFFFFFFFh on 008Ch is
   * page-granular (G set, low nibble F); 0000007Fh on 00A4h is a byte
   * update that clears G. */
  image(0x00, 0x00, 0x00, 0x00, 0x00, 0x93, 0xC0, 0x00, pre);
  DazeDpmiRequest limit_008c = {.function = 0x0008, .selector = 0x008C, .operand = 0xFFFFFFFFu};
  daze_dpmi_request_set_segment_limit(&limit_008c, pre, &result);
  image(0xFF, 0xFF, 0x00, 0x00, 0x00, 0x93, 0xCF, 0x00, post);
  pass = pass && result.success && result.dpmi_error == 0 && result.ax == 0x0008 &&
         descriptor_equals(result.descriptor, post);
  image(0x7F, 0x00, 0x00, 0x00, 0x05, 0x97, 0xCF, 0x00, pre);
  DazeDpmiRequest limit_00a4 = {.function = 0x0008, .selector = 0x00A4, .operand = 0x0000007Fu};
  daze_dpmi_request_set_segment_limit(&limit_00a4, pre, &result);
  image(0x7F, 0x00, 0x00, 0x00, 0x05, 0x97, 0x40, 0x00, post);
  pass = pass && result.success && result.dpmi_error == 0 && result.ax == 0x0008 &&
         descriptor_equals(result.descriptor, post);

  /* 0008h rejection: 00100000h is larger than byte granular but does not end
   * on a page boundary; the image stays byte-identical and the failure word
   * is 8021h. */
  image(0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, pre);
  DazeDpmiRequest reject_limit = {.function = 0x0008, .operand = 0x00100000u};
  daze_dpmi_request_set_segment_limit(&reject_limit, pre, &result);
  pass = pass && !result.success && result.dpmi_error == 0x8021 && result.ax == 0x8021 &&
         descriptor_equals(result.descriptor, pre);

  /* 000Ah: a present GDT code descriptor creates the first free writable
   * LDT data alias. Invalid/non-code sources and a full allocator are atomic
   * 8022h failures. */
  uint8_t used[20] = {0};
  DazeDpmiLdtAllocator aliases = {.used = used, .capacity = 20, .first_index = 16};
  image(0xff, 0xff, 0xf0, 0x07, 0x01, 0x9a, 0x00, 0x00, pre);
  DazeDpmiRequest alias = {.function = 0x000a, .selector = 0x0008};
  daze_dpmi_request_create_data_alias(&alias, pre, &aliases, &result);
  image(0xff, 0xff, 0xf0, 0x07, 0x01, 0x92, 0x00, 0x00, post);
  pass = pass && result.success && result.ax == 0x0084 && used[16] == 1 &&
         descriptor_equals(result.descriptor, post);
  const uint8_t used_before[20] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0};
  alias.selector = 0x0004;
  daze_dpmi_request_create_data_alias(&alias, pre, &aliases, &result);
  pass =
    pass && !result.success && result.ax == 0x8022 && memcmp(used, used_before, sizeof(used)) == 0;
  image(0xff, 0xff, 0, 0, 0, 0x92, 0, 0, pre);
  alias.selector = 0x0008;
  daze_dpmi_request_create_data_alias(&alias, pre, &aliases, &result);
  pass =
    pass && !result.success && result.ax == 0x8022 && memcmp(used, used_before, sizeof(used)) == 0;
  memset(used + 16, 1, 4);
  image(0xff, 0xff, 0xf0, 0x07, 0x01, 0x9a, 0x00, 0x00, pre);
  daze_dpmi_request_create_data_alias(&alias, pre, &aliases, &result);
  pass = pass && !result.success && result.ax == 0x8022;

  /* 0009h: the four recorded rights images, one per selector shape. */
  image(0x7F, 0x00, 0x00, 0x00, 0x05, 0x97, 0x40, 0x00, pre);
  DazeDpmiRequest rights_009c = {.function = 0x0009, .selector = 0x009C, .rights = 0xC09Bu};
  daze_dpmi_request_set_access_rights(&rights_009c, pre, &result);
  image(0x7F, 0x00, 0x00, 0x00, 0x05, 0x9B, 0xC0, 0x00, post);
  pass = pass && result.success && result.dpmi_error == 0 && result.ax == 0x0009 &&
         descriptor_equals(result.descriptor, post);
  image(0x00, 0x00, 0x00, 0x00, 0x00, 0x9B, 0xC0, 0x00, pre);
  DazeDpmiRequest rights_008c = {.function = 0x0009, .selector = 0x008C, .rights = 0xC093u};
  daze_dpmi_request_set_access_rights(&rights_008c, pre, &result);
  image(0x00, 0x00, 0x00, 0x00, 0x00, 0x93, 0xC0, 0x00, post);
  pass = pass && result.success && result.dpmi_error == 0 && result.ax == 0x0009 &&
         descriptor_equals(result.descriptor, post);
  image(0x7F, 0x00, 0x00, 0x00, 0x00, 0x9B, 0x40, 0x00, pre);
  DazeDpmiRequest rights_0094 = {.function = 0x0009, .selector = 0x0094, .rights = 0xC097u};
  daze_dpmi_request_set_access_rights(&rights_0094, pre, &result);
  image(0x7F, 0x00, 0x00, 0x00, 0x00, 0x97, 0xC0, 0x00, post);
  pass = pass && result.success && result.dpmi_error == 0 && result.ax == 0x0009 &&
         descriptor_equals(result.descriptor, post);
  DazeDpmiRequest rights_00a4 = {.function = 0x0009, .selector = 0x00A4, .rights = 0xC097u};
  daze_dpmi_request_set_access_rights(&rights_00a4, pre, &result);
  pass = pass && result.success && result.dpmi_error == 0 && result.ax == 0x0009 &&
         descriptor_equals(result.descriptor, post);

  /* 0009h rejection: extended-nibble bit 4 set is invalid access rights; the
   * image stays byte-identical and the failure word is 8021h. */
  DazeDpmiRequest reject_rights = {.function = 0x0009, .rights = 0xD09Bu};
  daze_dpmi_request_set_access_rights(&reject_rights, pre, &result);
  pass = pass && !result.success && result.dpmi_error == 0x8021 && result.ax == 0x8021 &&
         descriptor_equals(result.descriptor, pre);

  /* Out-of-range exception writes must fail with 8021h and preserve the table. */
  DazeDpmiExceptionVector vectors[32];
  memset(vectors, 0, sizeof(vectors));
  DazeDpmiRequest get_0 = {.function = 0x0202, .exception = 0};
  daze_dpmi_request_get_exception_vector(&get_0, vectors, 32, &result);
  pass = pass && result.success && result.dpmi_error == 0 && result.ax == 0x0202 &&
         result.vector_segment == 0 && result.vector_offset == 0;
  DazeDpmiRequest set_0 = {
    .function = 0x0203, .exception = 0, .vector_segment = 0x0008, .vector_offset = 0x0f6e};
  daze_dpmi_request_set_exception_vector(&set_0, vectors, 32, &result);
  pass = pass && result.success && result.dpmi_error == 0 && result.ax == 0x0203;
  daze_dpmi_request_get_exception_vector(&get_0, vectors, 32, &result);
  pass =
    pass && result.success && result.vector_segment == 0x0008 && result.vector_offset == 0x0f6e;
  DazeDpmiRequest get_32 = {.function = 0x0202, .exception = 32};
  daze_dpmi_request_get_exception_vector(&get_32, vectors, 32, &result);
  pass = pass && !result.success && result.dpmi_error == 0x8021 && result.ax == 0x8021 &&
         result.vector_segment == 0 && result.vector_offset == 0;
  DazeDpmiRequest set_32 = {
    .function = 0x0203, .exception = 32, .vector_segment = 0x0008, .vector_offset = 0x0f6e};
  daze_dpmi_request_set_exception_vector(&set_32, vectors, 32, &result);
  pass = pass && !result.success && result.dpmi_error == 0x8021 && result.ax == 0x8021;
  DazeDpmiRequest get_1 = {.function = 0x0202, .exception = 1};
  daze_dpmi_request_get_exception_vector(&get_1, vectors, 32, &result);
  pass = pass && result.success && result.vector_segment == 0 && result.vector_offset == 0;

  uint16_t rm_segments[2] = {0x1234, 0x5678};
  uint16_t rm_offsets[2] = {0x9abc, 0xdef0};
  const uint16_t rm_segments_before[2] = {0x1234, 0x5678};
  const uint16_t rm_offsets_before[2] = {0x9abc, 0xdef0};
  DazeDpmiRequest bad_rm_vector = {
    .function = 0x0200, .interrupt = 2, .vector_segment = 0x1111, .vector_offset = 0x2222};
  daze_dpmi_request_get_real_mode_vector(&bad_rm_vector, rm_segments, rm_offsets, 2, &result);
  pass =
    pass && failed_with(0x8021, &result) && result.vector_segment == 0 && result.vector_offset == 0;
  bad_rm_vector.function = 0x0201;
  daze_dpmi_request_set_real_mode_vector(&bad_rm_vector, rm_segments, rm_offsets, 2, &result);
  pass = pass && failed_with(0x8021, &result) &&
         memcmp(rm_segments, rm_segments_before, sizeof(rm_segments)) == 0 &&
         memcmp(rm_offsets, rm_offsets_before, sizeof(rm_offsets)) == 0;
  bad_rm_vector.interrupt = 1;
  daze_dpmi_request_get_real_mode_vector(&bad_rm_vector, NULL, rm_offsets, 2, &result);
  pass = pass && failed_with(0x8021, &result);
  daze_dpmi_request_set_real_mode_vector(&bad_rm_vector, rm_segments, NULL, 2, &result);
  pass = pass && failed_with(0x8021, &result) &&
         memcmp(rm_segments, rm_segments_before, sizeof(rm_segments)) == 0 &&
         memcmp(rm_offsets, rm_offsets_before, sizeof(rm_offsets)) == 0;

  /* Protected interrupt offsets retain full EDX width, unlike exception offsets. */
  DazeDpmiInterruptVector interrupts[256];
  memset(interrupts, 0, sizeof(interrupts));
  DazeDpmiRequest get_interrupt = {.function = 0x0204, .interrupt = 0x10};
  daze_dpmi_request_get_interrupt_vector(&get_interrupt, interrupts, 256, &result);
  pass = pass && result.success && result.ax == 0x0204 && result.interrupt_segment == 0 &&
         result.interrupt_offset == 0;
  DazeDpmiRequest set_interrupt = {.function = 0x0205,
                                   .interrupt = 0x10,
                                   .interrupt_segment = 0x0008,
                                   .interrupt_offset = 0x12345678u};
  daze_dpmi_request_set_interrupt_vector(&set_interrupt, interrupts, 256, &result);
  pass = pass && result.success && result.ax == 0x0205;
  daze_dpmi_request_get_interrupt_vector(&get_interrupt, interrupts, 256, &result);
  pass = pass && result.success && result.interrupt_segment == 0x0008 &&
         result.interrupt_offset == 0x12345678u;

  DazeDpmiInterruptVector protected_vectors[2] = {
    {.segment = 0x0008, .offset = 0x12345678u},
    {.segment = 0x0010, .offset = 0x87654321u},
  };
  const DazeDpmiInterruptVector protected_before[2] = {
    {.segment = 0x0008, .offset = 0x12345678u},
    {.segment = 0x0010, .offset = 0x87654321u},
  };
  DazeDpmiRequest bad_protected_vector = {.function = 0x0204,
                                          .interrupt = 2,
                                          .interrupt_segment = 0x0020,
                                          .interrupt_offset = 0xabcdef01u};
  daze_dpmi_request_get_interrupt_vector(&bad_protected_vector, protected_vectors, 2, &result);
  pass = pass && failed_with(0x8021, &result) && result.interrupt_segment == 0 &&
         result.interrupt_offset == 0;
  bad_protected_vector.function = 0x0205;
  daze_dpmi_request_set_interrupt_vector(&bad_protected_vector, protected_vectors, 2, &result);
  pass = pass && failed_with(0x8021, &result) &&
         memcmp(protected_vectors, protected_before, sizeof(protected_vectors)) == 0;
  bad_protected_vector.interrupt = 1;
  daze_dpmi_request_get_interrupt_vector(&bad_protected_vector, NULL, 2, &result);
  pass = pass && failed_with(0x8021, &result);
  daze_dpmi_request_set_interrupt_vector(&bad_protected_vector, NULL, 2, &result);
  pass = pass && failed_with(0x8021, &result) &&
         memcmp(protected_vectors, protected_before, sizeof(protected_vectors)) == 0;

  /* Low-word writes must retain high halves; only 0204h writes full EDX.
   * Setters preserve general registers on success; errors write AX and set carry. */
  DazeDpmiVectorResultContract vector_contract;
  DazeDpmiRequest vector_request = {.function = 0x0200};
  result = (DazeDpmiResult){.success = 1, .vector_segment = 0x0028, .vector_offset = 0x1234};
  pass = pass &&
         daze_dpmi_request_vector_result_contract(&vector_request, &result, &vector_contract) &&
         vector_contract.success && !vector_contract.write_ax16 && vector_contract.write_cx16 &&
         vector_contract.cx == 0x0028 && vector_contract.write_dx16 &&
         vector_contract.dx == 0x1234 && !vector_contract.write_edx;
  vector_request.function = 0x0204;
  result =
    (DazeDpmiResult){.success = 1, .interrupt_segment = 0x0008, .interrupt_offset = 0x12345678};
  pass =
    pass && daze_dpmi_request_vector_result_contract(&vector_request, &result, &vector_contract) &&
    vector_contract.success && vector_contract.write_cx16 && vector_contract.cx == 0x0008 &&
    !vector_contract.write_dx16 && vector_contract.write_edx && vector_contract.edx == 0x12345678u;
  vector_request.function = 0x0203;
  result = (DazeDpmiResult){.success = 0, .ax = 0x8021};
  pass = pass &&
         daze_dpmi_request_vector_result_contract(&vector_request, &result, &vector_contract) &&
         !vector_contract.success && vector_contract.write_ax16 && vector_contract.ax == 0x8021 &&
         !vector_contract.write_cx16 && !vector_contract.write_dx16 && !vector_contract.write_edx;
  vector_request.function = 0x0206;
  pass =
    pass && !daze_dpmi_request_vector_result_contract(&vector_request, &result, &vector_contract);

  DazeDpmiTransitionResultContract transition_contract;
  DazeDpmiRequest transition_request = {.function = 0x0305};
  result = (DazeDpmiResult){.success = 1,
                            .state_buffer_size = 60,
                            .rm_segment = 0x2200,
                            .rm_offset = 0x0100,
                            .pm_selector = 0x0028,
                            .pm_offset = 0x00000100};
  pass = pass &&
         daze_dpmi_request_transition_result_contract(&transition_request, &result,
                                                      &transition_contract) &&
         transition_contract.success && transition_contract.write_ax16 &&
         transition_contract.ax == 60 && transition_contract.write_bx16 &&
         transition_contract.bx == 0x2200 && transition_contract.write_cx16 &&
         transition_contract.cx == 0x0100 && transition_contract.write_si16 &&
         transition_contract.si == 0x0028 && transition_contract.write_edi &&
         transition_contract.edi == 0x00000100;
  transition_request.function = 0x0306;
  result = (DazeDpmiResult){.success = 1,
                            .rm_segment = 0x2200,
                            .rm_offset = 0x0120,
                            .pm_selector = 0x0028,
                            .pm_offset = 0x00000120};
  pass = pass &&
         daze_dpmi_request_transition_result_contract(&transition_request, &result,
                                                      &transition_contract) &&
         transition_contract.success && !transition_contract.write_ax16 &&
         transition_contract.write_bx16 && transition_contract.bx == 0x2200 &&
         transition_contract.write_cx16 && transition_contract.cx == 0x0120 &&
         transition_contract.write_si16 && transition_contract.si == 0x0028 &&
         transition_contract.write_edi && transition_contract.edi == 0x00000120;
  transition_request.function = 0x0304;
  pass = pass && !daze_dpmi_request_transition_result_contract(&transition_request, &result,
                                                               &transition_contract);
  for (uint16_t function = 0x0305; function <= 0x0306; ++function) {
    transition_request.function = function;
    result = (DazeDpmiResult){.success = 0, .ax = 0x8021};
    pass &= daze_dpmi_request_transition_result_contract(&transition_request, &result,
                                                         &transition_contract) &&
            !transition_contract.success && transition_contract.write_ax16 &&
            transition_contract.ax == 0x8021 && !transition_contract.write_bx16 &&
            !transition_contract.write_cx16 && !transition_contract.write_si16 &&
            !transition_contract.write_edi;
  }
  DazeDpmiTransitionResultContract unchanged_contract = transition_contract;
  pass &= !daze_dpmi_request_transition_result_contract(NULL, &result, &transition_contract) &&
          !daze_dpmi_request_transition_result_contract(&transition_request, NULL,
                                                        &transition_contract) &&
          !daze_dpmi_request_transition_result_contract(&transition_request, &result, NULL) &&
          memcmp(&transition_contract, &unchanged_contract, sizeof(transition_contract)) == 0;

  DazeDpmiScalarResultContract scalar_contract;
  DazeDpmiRequest scalar_request = {.function = 0x0400};
  result = (DazeDpmiResult){.success = 1, .ax = 0x005a, .handle = 3, .base = 3};
  pass = pass &&
         daze_dpmi_request_scalar_result_contract(&scalar_request, &result, &scalar_contract) &&
         scalar_contract.success && scalar_contract.write_ax16 && scalar_contract.ax == 0x005a &&
         !scalar_contract.write_al && scalar_contract.write_bx16 && scalar_contract.bx == 3 &&
         scalar_contract.write_cl && scalar_contract.cl == 3 && scalar_contract.write_dx16 &&
         scalar_contract.dx == 0x0870;
  scalar_request.function = 0x0900;
  result = (DazeDpmiResult){.success = 1, .previous_virtual_interrupts_enabled = 1};
  pass = pass &&
         daze_dpmi_request_scalar_result_contract(&scalar_request, &result, &scalar_contract) &&
         scalar_contract.success && !scalar_contract.write_ax16 && scalar_contract.write_al &&
         scalar_contract.al == 1 && !scalar_contract.write_bx16 && !scalar_contract.write_cl &&
         !scalar_contract.write_dx16;
  scalar_request.function = 0x0902;
  pass =
    pass && !daze_dpmi_request_scalar_result_contract(&scalar_request, &result, &scalar_contract);

  /* 0305h endpoints and buffer size are supplied by the backend, not invented by the service. */
  DazeDpmiRequest state_save = {.function = 0x0305,
                                .state_buffer_size = 60,
                                .rm_segment = 0x0200,
                                .rm_offset = 0x0100,
                                .pm_selector = 0x0028,
                                .pm_offset = 0x0100};
  daze_dpmi_request_get_state_save_endpoints(&state_save, &result);
  pass = pass && result.success && result.dpmi_error == 0 && result.ax == 0x0305 &&
         result.state_buffer_size == 60 && result.rm_segment == 0x0200 &&
         result.rm_offset == 0x0100 && result.pm_selector == 0x0028 && result.pm_offset == 0x0100;

  DazeDpmiRequest raw_switch = {.function = 0x0306,
                                .rm_segment = 0x0200,
                                .rm_offset = 0x0120,
                                .pm_selector = 0x0028,
                                .pm_offset = 0x0120};
  daze_dpmi_request_get_raw_switch_endpoints(&raw_switch, &result);
  pass = pass && result.success && result.dpmi_error == 0 && result.ax == 0x0306 &&
         result.rm_segment == 0x0200 && result.rm_offset == 0x0120 &&
         result.pm_selector == 0x0028 && result.pm_offset == 0x0120;

  DazeDpmiRequest raw_switch_alt = {.function = 0x0306,
                                    .rm_segment = 0x1234,
                                    .rm_offset = 0x0050,
                                    .pm_selector = 0x0038,
                                    .pm_offset = 0x0070};
  daze_dpmi_request_get_raw_switch_endpoints(&raw_switch_alt, &result);
  pass = pass && result.success && result.rm_segment == 0x1234 && result.rm_offset == 0x0050 &&
         result.pm_selector == 0x0038 && result.pm_offset == 0x0070;

  /* Each interrupt-state call reports the prior state before changing the flag. */
  int virtual_interrupts = 1;
  daze_dpmi_request_get_and_disable_virtual_interrupts(&virtual_interrupts, &result);
  pass = pass && result.success && result.dpmi_error == 0 && result.ax == 0x0900 &&
         result.previous_virtual_interrupts_enabled == 1 && virtual_interrupts == 0;
  daze_dpmi_request_get_and_disable_virtual_interrupts(&virtual_interrupts, &result);
  pass = pass && result.success && result.dpmi_error == 0 && result.ax == 0x0900 &&
         result.previous_virtual_interrupts_enabled == 0 && virtual_interrupts == 0;

  daze_dpmi_request_get_and_disable_virtual_interrupts(NULL, &result);
  pass = pass && !result.success && result.dpmi_error == 0x8021 && result.ax == 0x8021 &&
         result.previous_virtual_interrupts_enabled == 0;

  int vi_enabled = 0;
  daze_dpmi_request_get_and_enable_virtual_interrupts(&vi_enabled, &result);
  pass = pass && result.success && result.dpmi_error == 0 && result.ax == 0x0901 &&
         result.previous_virtual_interrupts_enabled == 0 && vi_enabled == 1;
  daze_dpmi_request_get_and_enable_virtual_interrupts(&vi_enabled, &result);
  pass = pass && result.success && result.dpmi_error == 0 && result.ax == 0x0901 &&
         result.previous_virtual_interrupts_enabled == 1 && vi_enabled == 1;
  daze_dpmi_request_get_and_enable_virtual_interrupts(&vi_enabled, &result);
  pass = pass && result.success && result.dpmi_error == 0 && result.ax == 0x0901 &&
         result.previous_virtual_interrupts_enabled == 1 && vi_enabled == 1;

  daze_dpmi_request_get_and_enable_virtual_interrupts(NULL, &result);
  pass = pass && !result.success && result.dpmi_error == 0x8021 && result.ax == 0x8021 &&
         result.previous_virtual_interrupts_enabled == 0;

  /* DPMILOAD's legacy resize token must name a live linear allocation. A
   * resize changes only that extent, and success writes no guest registers. */
  DazeDpmiLinearMemory loader_memory;
  daze_dpmi_linear_memory_init(&loader_memory, 0x50000, 0x800000);
  uint32_t loader_base, loader_token;
  pass &= daze_dpmi_linear_memory_allocate(&loader_memory, 0xffff, &loader_base, &loader_token);
  const DazeDpmiRequest loader_resize = {
    .function = 0x0102, .operand = loader_token, .size = 0x2740};
  daze_dpmi_request_resize_loader_block(&loader_memory, &loader_resize, &result);
  DazeDpmiLinearResultContract loader_contract;
  const DazeDpmiLinearAllocation *loader_allocation = &loader_memory.allocations[0];
  pass &= result.success && result.base == 0x50000 && loader_allocation->in_use &&
          loader_allocation->handle == loader_token && loader_allocation->base == loader_base &&
          loader_allocation->allocated_size == 0x3000 &&
          daze_dpmi_request_linear_result_contract(&loader_resize, &result, &loader_contract) &&
          !loader_contract.write_ax16 && !loader_contract.write_bx16 &&
          !loader_contract.write_cx16 && !loader_contract.write_si16 && !loader_contract.write_di16;
  const DazeDpmiLinearMemory loader_before = loader_memory;
  const DazeDpmiRequest invalid_loader_resize = {
    .function = 0x0102, .operand = 0x1234, .size = 0x2740};
  daze_dpmi_request_resize_loader_block(&loader_memory, &invalid_loader_resize, &result);
  pass &=
    !result.success && result.ax == 9 &&
    memcmp(&loader_before, &loader_memory, sizeof(loader_memory)) == 0 &&
    daze_dpmi_request_linear_result_contract(&invalid_loader_resize, &result, &loader_contract) &&
    loader_contract.write_ax16 && loader_contract.ax == 9 && loader_contract.write_bx16 &&
    loader_contract.bx == (uint16_t)((0x800000 - 0x53000) >> 4);
  const DazeDpmiRequest loader_release = {.function = 0x0101, .operand = loader_token};
  daze_dpmi_request_release_loader_block(&loader_memory, &loader_release, &result);
  pass &= result.success && !loader_allocation->in_use;
  const DazeDpmiLinearMemory released_before = loader_memory;
  daze_dpmi_request_release_loader_block(&loader_memory, &loader_release, &result);
  pass &= !result.success && result.ax == 9 &&
          memcmp(&released_before, &loader_memory, sizeof(loader_memory)) == 0;

  fprintf(stderr, "DPMI request adapter contract test: %s\n", pass ? "passed" : "failed");
  return pass ? 0 : 1;
}
