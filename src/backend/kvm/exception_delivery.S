.intel_syntax noprefix
.section .text
.code32
.global exception_delivery
.equ DATA, 0xfdd800
.equ RETURN, 0xfdf100
.equ FRAME, 0xfd0ff0
.equ REGS, 0xfd0fd0
.equ BASE, 0xfd0000

.macro descriptor
  test edx, 3
  jnz fallback
  mov edi, edx
  and edi, 0xfff8
  cmp edi, 8
  jb fallback
  test edx, 4
  jz 1f
  add edi, 0xfe0000
  jmp 2f
1:
  add edi, 0xff0000
2:
.endm

.macro descriptor_base
  mov eax, cs:[edi+2]
  and eax, 0xffffff
  mov ecx, cs:[edi+4]
  and ecx, 0xff000000
  or eax, ecx
.endm

exception_delivery:
  push ax
  cmp esp, 0x10000
  jae fallback_ax
  cmp sp, 80
  jb fallback_ax
  cmp sp, 0xfff5
  ja fallback_ax
  pushad
  sub sp, 16
  movzx ebp, sp
  cmp dword ptr cs:[DATA], 1
  jne fallback
  cmp dword ptr cs:[FRAME], 0
  jne fallback
  mov eax, cr0
  and eax, 0x80000001
  cmp eax, 1
  jne fallback
  sgdt ss:[ebp]
  cmp word ptr ss:[ebp], 0xffff
  jne fallback
  cmp dword ptr ss:[ebp+2], 0xff0000
  jne fallback
  sldt ax
  cmp ax, cs:[DATA+4]
  jne fallback
  movzx edx, ax
  descriptor
  cmp dword ptr cs:[edi], 0x0000ffff
  jne fallback
  mov eax, cs:[edi+4]
  and eax, 0xfffffdff
  cmp eax, 0x000080fe
  jne fallback
  mov ax, ss
  cmp ax, cs:[DATA+26]
  jne fallback
  movzx edx, ax
  lar eax, edx
  jnz fallback
  and eax, 0x40fe00
  cmp eax, 0x9200
  jne fallback
  lsl ecx, edx
  jnz fallback
  lea eax, [ebp+57]
  cmp eax, ecx
  ja fallback
  descriptor
  mov eax, cs:[edi]
  cmp eax, cs:[DATA+56]
  jne fallback
  mov eax, cs:[edi+4]
  and eax, 0xfffffeff
  cmp eax, cs:[DATA+60]
  jne fallback
  descriptor_base
  add eax, ebp
  jc fallback
  mov esi, eax
  add eax, 58
  jc fallback
  cmp eax, BASE
  ja fallback
  /* Compare the complete saved state through SS and its flat alias. */
  xor ebx, ebx
compare_stack:
  mov eax, ss:[ebp+ebx]
  cmp eax, cs:[esi+ebx]
  jne fallback
  add ebx, 4
  cmp ebx, 56
  jb compare_stack
  mov ax, ss:[ebp+56]
  cmp ax, cs:[esi+56]
  jne fallback
  movzx edx, word ptr ss:[ebp+54]
  lar eax, edx
  jnz fallback
  and eax, 0x40f800
  cmp eax, 0x9800
  jne fallback
  lsl ebx, edx
  jnz fallback
  descriptor
  descriptor_base
  movzx ecx, word ptr ss:[ebp+52]
  lea edx, [ecx+5]
  cmp edx, ebx
  ja fallback
  add eax, ecx
  jc fallback
  cmp eax, 0xfffffb
  ja fallback
  mov edi, eax
  mov ss:[ebp+12], eax
  cmp byte ptr cs:[edi], 0x9a
  je direct_call
  cmp word ptr cs:[edi], 0x1eff
  je indirect_call
  cmp byte ptr cs:[edi], 0xcb
  je far_return
  cmp byte ptr cs:[edi], 0xca
  je far_return
  cmp word ptr cs:[edi], 0xc426
  jne fallback
  cmp byte ptr cs:[edi+2], 0x3f
  jne fallback
  mov dx, es
  lsl ecx, edx
  jnz fallback
  movzx ebx, word ptr ss:[ebp+32]
  lea eax, [ebx+3]
  cmp eax, ecx
  ja fallback
  movzx edx, word ptr es:[ebx+2]
  mov ebx, 3
  jmp operand
direct_call:
  movzx edx, word ptr cs:[edi+3]
  mov ebx, 5
  jmp operand
indirect_call:
  mov dx, ds
  lsl ecx, edx
  jnz fallback
  movzx ebx, word ptr cs:[edi+2]
  lea eax, [ebx+3]
  cmp eax, ecx
  ja fallback
  movzx edx, word ptr ds:[ebx+2]
  mov ebx, 4
  jmp operand
far_return:
  mov dx, ss
  lsl ecx, edx
  jnz fallback
  lea eax, [ebp+61]
  cmp eax, ecx
  ja fallback
  movzx edx, word ptr ss:[ebp+60]
  mov ebx, 1
  cmp byte ptr cs:[edi], 0xcb
  je operand
  mov ebx, 3
operand:
  cmp dx, ss:[ebp+50]
  jne fallback
  mov ss:[ebp+8], ebx
  descriptor
  mov al, cs:[edi+5]
  and al, 0x90
  cmp al, 0x10
  jne fallback
  movzx edx, word ptr cs:[DATA+10]
  lar eax, edx
  jnz fallback
  and eax, 0x40fe00
  cmp eax, 0x9a00
  jne fallback
  lsl eax, edx
  jnz fallback
  movzx ecx, word ptr cs:[DATA+6]
  cmp ecx, eax
  ja fallback
  descriptor
  mov eax, cs:[edi]
  cmp eax, cs:[DATA+12]
  jne fallback
  mov eax, cs:[edi+4]
  or eax, 0x100
  cmp eax, cs:[DATA+16]
  jne fallback
  cmp dword ptr cs:[0xff0048], 0x00000fff
  jne fallback
  mov eax, cs:[0xff004c]
  and eax, 0xfffffeff
  cmp eax, 0x000092fd
  jne fallback
  cmp dword ptr cs:[0xff0058], 0x0000ffff
  jne fallback
  mov eax, cs:[0xff005c]
  and eax, 0xfffffeff
  cmp eax, 0x00cf9200
  jne fallback
  cmp dword ptr cs:[0xff00a0], 0x0000ffff
  jne fallback
  mov eax, cs:[0xff00a4]
  and eax, 0xfffffeff
  cmp eax, 0x00429afd
  jne fallback
  mov eax, ss:[ebp+8]
  cmp eax, cs:[esi+8]
  jne fallback
  mov eax, ss:[ebp+12]
  cmp eax, cs:[esi+12]
  jne fallback
  /* No data segment is reloaded; SS becomes flat only while building the frame. */
  lss esp, cs:[DATA+20]
  mov dword ptr ss:[DATA+32], 1
  mov eax, cs:[esi+12]
  add eax, cs:[esi+8]
  mov ss:[DATA+88], eax
  movzx eax, word ptr cs:[esi+52]
  add ax, cs:[esi+8]
  mov ss:[RETURN], ax
  mov ax, cs:[esi+54]
  mov ss:[RETURN+2], ax
  mov ax, cs:[esi+50]
  mov ss:[RETURN+4], ax
  movzx edx, word ptr cs:[DATA+26]
  mov ss:[RETURN+6], dx
  mov edi, edx
  and edi, 0xfff8
  test edx, 4
  jz stack_gdt
  add edi, 0xfe0000
  jmp stack_descriptor
stack_gdt:
  add edi, 0xff0000
stack_descriptor:
  mov eax, edi
  sub eax, BASE
  mov ss:[RETURN+8], eax
  mov eax, cs:[edi]
  mov ss:[RETURN+12], eax
  mov eax, cs:[edi+4]
  and eax, 0xfffffeff
  mov ss:[RETURN+16], eax
  descriptor_base
  mov ss:[RETURN+20], eax
  mov dword ptr ss:[RETURN+24], BASE
  mov dword ptr ss:[RETURN+28], 1
  mov word ptr ss:[RETURN+32], 0xffff
  mov dword ptr ss:[RETURN+34], 0xff0000
  mov ax, cs:[DATA+4]
  mov ss:[RETURN+38], ax
  mov dword ptr ss:[FRAME], 0x00a0ee00
  mov ax, cs:[esi+50]
  mov ss:[FRAME+4], ax
  mov eax, cs:[esi+52]
  mov ss:[FRAME+6], eax
  mov ax, cs:[esi+56]
  mov ss:[FRAME+10], ax
  movzx eax, ax
  and eax, 0xfffffdff
  or eax, 2
  mov ss:[DATA+44], eax
  lea eax, [ebp+58]
  mov ss:[FRAME+12], ax
  mov ax, cs:[DATA+26]
  mov ss:[FRAME+14], ax
  xor ebx, ebx
copy_registers:
  mov eax, cs:[esi+ebx+16]
  mov ss:[REGS+ebx], eax
  add ebx, 4
  cmp ebx, 32
  jb copy_registers
  inc dword ptr ss:[DATA+28]
  mov ax, 0x48
  mov ss, ax
  mov esp, 0xfd0
  popad
  push dword ptr cs:[DATA+44]
  popfd
  jmp far ptr cs:[DATA+6]
fallback:
  add sp, 16
  popad
fallback_ax:
  jmp far ptr cs:[DATA+48]

