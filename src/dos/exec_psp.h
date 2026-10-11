#ifndef DAZE_DOS_EXEC_PSP_H
#define DAZE_DOS_EXEC_PSP_H

#include <stdint.h>

enum { DAZE_DOS_EXEC_PSP_SIZE = 256 };

int daze_dos_exec_psp_build(uint16_t psp_segment, uint16_t parent_psp_segment,
                            uint16_t environment_segment, uint16_t dos_vector_segment,
                            const uint8_t tail[127], const uint8_t fcb1[16], const uint8_t fcb2[16],
                            uint8_t output[DAZE_DOS_EXEC_PSP_SIZE]);

#endif
