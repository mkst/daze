#ifndef DAZE_DPMI_RM_FRAME_H
#define DAZE_DPMI_RM_FRAME_H

#include <stddef.h>
#include <stdint.h>

enum {
  DAZE_DPMI_RM_FRAME_SIZE = 0x32,
  DAZE_DPMI_RM_EDI = 0x00,
  DAZE_DPMI_RM_ESI = 0x04,
  DAZE_DPMI_RM_EBP = 0x08,
  DAZE_DPMI_RM_EBX = 0x10,
  DAZE_DPMI_RM_EDX = 0x14,
  DAZE_DPMI_RM_ECX = 0x18,
  DAZE_DPMI_RM_EAX = 0x1c,
  DAZE_DPMI_RM_FLAGS = 0x20,
  DAZE_DPMI_RM_ES = 0x22,
  DAZE_DPMI_RM_DS = 0x24,
  DAZE_DPMI_RM_FS = 0x26,
  DAZE_DPMI_RM_GS = 0x28,
  DAZE_DPMI_RM_IP = 0x2a,
  DAZE_DPMI_RM_CS = 0x2c,
  DAZE_DPMI_RM_SP = 0x2e,
  DAZE_DPMI_RM_SS = 0x30,
  /* Host-owned return gate: Unicorn intercepts arrival; KVM executes its HLT. */
  DAZE_DPMI_RM_GATE_LINEAR = 0x2300,
  DAZE_DPMI_RM_RETURN_IP = 0x0000,
  DAZE_DPMI_RM_RETURN_CS = 0x0230,
};

/* Resolve host-stack defaults before planning a real-mode SS:SP. Return frames
 * use four bytes for RETF or six for IRET; copied parameters follow them. */
typedef struct {
  uint16_t sp;
  uint32_t address;
} DazeDpmiRmStack;

int daze_dpmi_rm_stack_plan(uint16_t ss, uint16_t sp, uint16_t return_bytes,
                            uint32_t parameter_bytes, size_t guest_size, DazeDpmiRmStack *stack);

/* 0301h admits a 16-bit protected caller and a 50-byte frame at ES:(E)DI. The supported
 * two-word form accepts SS:SP=0:0 for the host return stack; parameters follow the
 * four-byte far return. */
typedef struct {
  uint16_t target_cs, target_ip;
  uint16_t frame_ss, frame_sp;
  uint16_t procedure_sp;
  uint32_t frame_address, stack_address;
  uint16_t parameter_bytes;
} DazeDpmiRmProcedure;

int daze_dpmi_rm_frame_parse(const uint8_t frame[DAZE_DPMI_RM_FRAME_SIZE], uint32_t es_base,
                             uint32_t offset, uint16_t cx, uint16_t bx, int code_is_32bit,
                             DazeDpmiRmProcedure *output);

int daze_dpmi_rm_far_return(uint8_t bytes[4]);

/* Final real-mode register image written back into the shared frame after the
 * procedure has run. IP/CS/SP/SS are deliberately left untouched. */
typedef struct {
  uint32_t edi, esi, ebp, ebx, edx, ecx, eax;
  uint16_t flags, es, ds, fs, gs;
} DazeDpmiRmWriteBack;

void daze_dpmi_rm_frame_write_back(uint8_t frame[DAZE_DPMI_RM_FRAME_SIZE],
                                   const DazeDpmiRmWriteBack *registers);

#endif
