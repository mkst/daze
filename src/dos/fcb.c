#include "fcb.h"

#include <ctype.h>
#include <string.h>

int daze_dos_fcb_parse(const uint8_t *input, size_t input_size, uint8_t control, uint8_t fcb[16],
                       size_t *consumed, uint8_t *result) {
  if (input == NULL || input_size == 0 || fcb == NULL || consumed == NULL || result == NULL)
    return 0;
  size_t length = 0;
  while (length < input_size && input[length] != '\0' && input[length] != ' ' &&
         input[length] != '\r')
    ++length;
  if (length == input_size) return 0;
  size_t start_offset = 0;
  if ((control & 1u) != 0)
    while (start_offset < length && (input[start_offset] == ' ' || input[start_offset] == '\t'))
      ++start_offset;
  memset(fcb, ' ', 16);
  fcb[0] = 0;
  size_t start = start_offset;
  if (length - start_offset >= 2 && input[start_offset + 1] == ':') {
    const uint8_t drive = (uint8_t)toupper(input[start_offset]);
    if (drive < 'A' || drive > 'Z') {
      *result = 0xff;
      return 1;
    }
    fcb[0] = (uint8_t)(drive - 'A' + 1);
    start += 2;
  }
  for (size_t index = start; index < length; ++index)
    if (input[index] == '\\' || input[index] == '/') start = index + 1;
  size_t field = 1;
  size_t limit = 9;
  int wildcard = 0;
  for (size_t index = start; index < length; ++index) {
    const uint8_t character = input[index];
    if (character == '.') {
      field = 9;
      limit = 12;
      continue;
    }
    if (field >= limit) continue;
    if (character == '*') {
      memset(fcb + field, '?', limit - field);
      wildcard = 1;
      field = limit;
    } else {
      fcb[field++] = character == '?' ? '?' : (uint8_t)toupper(character);
      wildcard |= character == '?';
    }
  }
  *consumed = length;
  *result = wildcard ? 1 : 0;
  return 1;
}
