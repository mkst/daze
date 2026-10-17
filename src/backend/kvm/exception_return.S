.intel_syntax noprefix
.section .text
.code32
.global exception_return
.equ DATA, 0xf100
.equ WORK, 0xfb4
.equ FRAME, 0xff0
exception_return:
  cmp sp, FRAME+4
  jne bad_frame
  push ax
  mov ax, ss
  cmp ax, 0x48
  pop ax
  jne bad_frame
  pushad
  sub sp, 32
  movzx ebp, sp
  cmp dword ptr cs:[DATA+28], 1
  jne fallback
  sgdt ss:[ebp+20]
  mov ax, ss:[ebp+20]
  cmp ax, cs:[DATA+32]
  jne fallback
  mov eax, ss:[ebp+22]
  cmp eax, cs:[DATA+34]
  jne fallback
  sldt ax
  cmp ax, cs:[DATA+38]
  jne fallback
  test word ptr ss:[ebp+70], 0x4000
  jnz fallback
  movzx edx, word ptr ss:[ebp+74]
  cmp dx, cs:[DATA+6]
  jne fallback
  test edx, 3
  jnz fallback
  mov edi, cs:[DATA+8]
  mov eax, cs:[edi]
  cmp eax, cs:[DATA+12]
  jne fallback
  mov eax, cs:[edi+4]
  and eax, 0xfffffeff
  cmp eax, cs:[DATA+16]
  jne fallback
  lar eax, edx
  jnz fallback
  and eax, 0xfe00
  cmp eax, 0x9200
  jne fallback
  lsl ecx, edx
  jnz fallback
  movzx ebx, word ptr ss:[ebp+72]
  cmp ebx, 12
  jb fallback
  cmp ebx, ecx
  ja fallback
  mov eax, cs:[DATA+20]
  add eax, ebx
  jc fallback
  cmp eax, cs:[DATA+24]
  ja fallback
  mov ss:[ebp], ebx
  mov ss:[ebp+4], dx
  movzx ecx, word ptr cs:[DATA+2]
  test ecx, 3
  jnz fallback
  lar eax, ecx
  jnz fallback
  and eax, 0x40f800
  cmp eax, 0x9800
  jne fallback
  movzx esi, word ptr cs:[DATA]
  movzx edi, word ptr cs:[DATA+4]
  lar eax, edi
  jnz fallback
  test eax, 0x1000
  jz fallback
  test eax, 0x8000
  jz skip
  movzx esi, word ptr ss:[ebp+66]
skip:
  lsl eax, ecx
  jnz fallback
  cmp esi, eax
  ja fallback
  mov ss:[ebp+8], esi
  mov ss:[ebp+12], ecx
  movzx eax, word ptr ss:[ebp+70]
  mov ss:[ebp+16], eax
  add sp, 32
  popad
  mov dword ptr ss:[FRAME], 0
  lss esp, cs:[WORK]
  push dword ptr cs:[WORK+16]
  push dword ptr cs:[WORK+12]
  push dword ptr cs:[WORK+8]
  iretd
bad_frame:
  ud2
  hlt
fallback:
  add sp, 32
  popad
  push ax
  mov al, 0x1c
fallback_out:
  out 0xf4, al
  hlt
