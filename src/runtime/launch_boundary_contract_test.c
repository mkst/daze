#include "launch.c"
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>

int main(void) {
  FILE *capture = tmpfile();
  assert(capture != NULL);
  int saved = dup(STDERR_FILENO);
  assert(saved >= 0 && dup2(fileno(capture), STDERR_FILENO) >= 0);
  DazePreparedLaunch launch = {.debug = 1};
  DazeGuestLaunchInput input = {0};
  close_mounts(NULL);
  dump_launch_layout(NULL, &input);
  dump_launch_layout(&launch, NULL);
  dump_launch_layout(&launch, &input);
  fflush(stderr);
  assert(ftell(capture) == 0);
  input = (DazeGuestLaunchInput){0x1000000, 0x10000, 0x1234, 512, 0x50000, 0xfd0000};
  DazeGuestLaunchFailure failure = {.first = {0x10000, 0x1234, DAZE_GUEST_OWNER_IMAGE},
                                    .second = {0xff00, 0x100, DAZE_GUEST_OWNER_PSP}};
  const char *expected[] = {
    "fixture has unsupported guest memory layout: internal validation error\n",
    "fixture has unsupported guest memory layout: internal validation error\n",
    "fixture has unsupported guest memory layout: MZ image [00010000..00011234) does not fit the "
    "01000000-byte guest at launch\n",
    "fixture has conflicting guest memory layout: MZ image [00010000..00011234) overlaps PSP "
    "[0000ff00..00010000) at launch\n",
    "fixture has unsupported guest memory layout: no DPMI linear arena after resident image end "
    "00010000 (limit 00fd0000) at launch\n",
    "fixture has conflicting guest memory layout: conventional allocation start 1000 disagrees "
    "with resident image end 11234 at launch\n",
    "fixture has unsupported guest memory layout: internal validation error\n"};
  for (int kind = 0; kind <= 6; ++kind) {
    failure.kind = (DazeGuestLaunchFailureKind)kind;
    report_layout_failure("fixture", &input, &failure);
  }
  fflush(stderr);
  assert(dup2(saved, STDERR_FILENO) >= 0);
  close(saved);
  rewind(capture);
  char line[512];
  for (size_t i = 0; i < sizeof(expected) / sizeof(expected[0]); ++i) {
    assert(fgets(line, sizeof(line), capture) != NULL);
    assert(strcmp(line, expected[i]) == 0);
  }
  assert(fgetc(capture) == EOF);
  fclose(capture);
  return 0;
}
