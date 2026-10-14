.intel_syntax noprefix
.section .text
.code16
.global write_entry
.equ CONTROL, 0x400
write_entry:
  cmp ah, 0x40
  jne fallback
  test cx, cx
  jz fallback
  cmp word ptr cs:[CONTROL], 1
  jne fallback
  cmp bx, cs:[CONTROL+2]
  jne fallback
  cmp sp, 40
  jb fallback
  cmp sp, 0xfff9
  ja fallback
  mov cs:[CONTROL+0x20], eax
  mov cs:[CONTROL+0x24], ebx
  movzx eax, sp
  sub eax, 40
  mov bx, ss
  movzx ebx, bx
  shl ebx, 4
  add eax, ebx
  cmp eax, 0xc000
  mov eax, cs:[CONTROL+0x20]
  mov ebx, cs:[CONTROL+0x24]
  jb fallback
  push ebp
  mov bp, sp
  pushad
  push ds
  push es
  test word ptr ss:[bp+8], 0x100
  jnz rejected
  smsw ax
  test ax, 1
  jnz rejected
  xor ax, ax
  mov ds, ax
  cmp dword ptr ds:[0x5840], 1
  jne rejected
  cmp word ptr ds:[0x2a42], 0
  jne rejected
  mov ax, ss:[bp-34]
  mov ds, ax
  movzx eax, word ptr cs:[CONTROL+4]
  movzx edx, cx
  add edx, eax
  cmp edx, 0x4000
  ja rejected
  cmp dx, cs:[CONTROL+6]
  ja rejected
  mov di, ax
  movzx eax, word ptr ss:[bp-12]
  movzx edx, cx
  add edx, eax
  cmp edx, 0x10000
  ja rejected
  mov si, ax
  mov dx, ds
  movzx edx, dx
  shl edx, 4
  add eax, edx
  cmp eax, 0xc000
  jae source_clear
  movzx edx, cx
  add edx, eax
  cmp edx, 0x7400
  ja rejected
source_clear:
  mov ax, 0x800
  mov es, ax
  mov ax, cx
  add cs:[CONTROL+4], ax
  inc dword ptr cs:[CONTROL+8]
  movzx eax, ax
  add cs:[CONTROL+12], eax
  mov ss:[bp-4], ax
  and word ptr ss:[bp+8], 0xfffe
  cld
  rep movsb
  pop es
  pop ds
  popad
  pop ebp
  iret
rejected:
  pop es
  pop ds
  popad
  pop ebp
fallback:
  push ax
  mov al, 0x21
  out 0xf4, al
  pop ax
  iret
