.intel_syntax noprefix
.section .text
.code32
.global native_entry
.equ PS, 0x2a00
.equ RM, 0x2a80
.equ CTRL, 0x5800
native_entry:
  mov fs:[PS], eax
  mov fs:[PS+4], ebx
  mov fs:[PS+8], ecx
  mov fs:[PS+12], edx
  mov fs:[PS+16], esi
  mov fs:[PS+20], edi
  mov fs:[PS+24], ebp
  mov fs:[PS+28], esp
  mov eax, ss:[esp-4]
  mov fs:[PS+0x6c], eax
  pushfd
  pop dword ptr fs:[PS+32]
  mov eax, fs:[PS+0x6c]
  mov ss:[esp-4], eax
  cmp dword ptr fs:[CTRL], 1
  jne fallback
  cmp word ptr fs:[0xfdea00], 0x0301
  jne fallback
  cmp word ptr fs:[0xfdea08], 0
  jne fallback
  cmp byte ptr fs:[0xfdea05], 0
  jne fallback
  cmp word ptr fs:[0xfdea20], 8
  jne fallback
  test dword ptr fs:[PS+32], 0x30100
  jne fallback
  test dword ptr fs:[0xfdea24], 0x30100
  jne fallback
  cmp esp, 4
  jb fallback
  cmp esp, 0xffec
  ja fallback
  mov ax, ss
  cmp ax, 0x10
  jne fallback
  mov ax, ds
  cmp ax, 0x10
  jne fallback
  mov ax, es
  cmp ax, 0x10
  jne fallback
  mov ax, gs
  cmp ax, fs:[CTRL+0x34]
  jne fallback
  mov eax, cr0
  mov fs:[PS+0x24], eax
  cmp eax, fs:[CTRL+0x64]
  jne fallback
  sgdt fs:[PS+0x70]
  mov eax, fs:[PS+0x70]
  cmp eax, fs:[CTRL+0x54]
  jne fallback
  mov ax, fs:[PS+0x74]
  cmp ax, fs:[CTRL+0x58]
  jne fallback
  sldt ax
  cmp ax, fs:[CTRL+0x5a]
  jne fallback
  sidt fs:[PS+0x70]
  mov eax, fs:[PS+0x70]
  cmp eax, fs:[CTRL+0x5c]
  jne fallback
  mov ax, fs:[PS+0x74]
  cmp ax, fs:[CTRL+0x60]
  jne fallback
  mov eax, fs:[CTRL+4]
  add eax, esp
  jc fallback
  sub eax, 4
  cmp eax, 0x6000
  jb fallback
  cmp eax, 0xfdd000-24
  jae fallback
  mov fs:[PS+0x78], eax
  mov esi, 0xff0008
  mov edi, CTRL+0x10
  call descriptor_guard
  jne fallback
  mov esi, 0xff0010
  mov edi, CTRL+8
  call descriptor_guard
  jne fallback
  mov esi, 0xff0028
  mov edi, CTRL+0x18
  call descriptor_guard
  jne fallback
  mov esi, 0xff0050
  mov edi, CTRL+0x20
  call descriptor_guard
  jne fallback
  mov esi, 0xff0058
  mov edi, CTRL+0x28
  call descriptor_guard
  jne fallback
  cmp word ptr fs:[CTRL+0x34], 0
  je gs_guard_done
  mov esi, fs:[CTRL+0x38]
  mov edi, CTRL+0x48
  call descriptor_guard
  jne fallback
gs_guard_done:
  movzx edi, word ptr fs:[0xfdea10]
  cmp edi, 0xffce
  ja fallback
  add edi, fs:[CTRL+4]
  jc fallback
  cmp edi, 0xffffce
  ja fallback
  cmp edi, 0x6000
  jb fallback
  cmp edi, 0xfdd000-50
  jae fallback
  mov eax, fs:[PS+0x78]
  lea edx, [eax+24]
  cmp edi, edx
  jae frame_clear
  lea edx, [edi+50]
  cmp eax, edx
  jb fallback
frame_clear:
  mov fs:[PS+0x28], edi
  movzx edx, word ptr fs:[edi+0x2e]
  cmp edx, 4
  jb fallback
  sub edx, 4
  mov fs:[RM+0x30], edx
  movzx ebx, word ptr fs:[edi+0x30]
  test ebx, ebx
  jz fallback
  mov fs:[RM+0x34], bx
  shl ebx, 4
  lea eax, [ebx+edx]
  cmp eax, 0x6000
  jb fallback
  lea ebx, [eax+4]
  cmp edi, ebx
  jae stack_frame_clear
  lea ebx, [edi+50]
  cmp eax, ebx
  jb fallback
stack_frame_clear:
  mov ebx, fs:[PS+0x78]
  lea edx, [ebx+24]
  cmp eax, edx
  jae stack_clear
  lea edx, [eax+4]
  cmp ebx, edx
  jb fallback
stack_clear:
  mov fs:[PS+0x7c], eax
  mov eax, fs:[edi+0x2a]
  mov fs:[RM+0x20], eax
  movzx eax, word ptr fs:[edi+0x20]
  test eax, 0x100
  jnz fallback
  and eax, 0x7fd5
  or eax, 2
  mov fs:[RM+0x24], eax
  mov eax, fs:[edi+0x1c]
  mov fs:[RM], eax
  mov eax, fs:[edi+0x10]
  mov fs:[RM+4], eax
  mov eax, fs:[edi+0x18]
  mov fs:[RM+8], eax
  mov eax, fs:[edi+0x14]
  mov fs:[RM+12], eax
  mov eax, fs:[edi+4]
  mov fs:[RM+16], eax
  mov eax, fs:[edi]
  mov fs:[RM+20], eax
  mov eax, fs:[edi+8]
  mov fs:[RM+24], eax
  mov ax, fs:[edi+0x24]
  mov fs:[RM+0x36], ax
  mov ax, fs:[edi+0x22]
  mov fs:[RM+0x38], ax
  mov ax, fs:[edi+0x26]
  mov fs:[RM+0x3a], ax
  mov ax, fs:[edi+0x28]
  mov fs:[RM+0x3c], ax
  mov esi, RM+0x34
  mov edi, 0xff0070
  mov ecx, 5
descriptor_loop:
  movzx eax, word ptr fs:[esi]
  shl eax, 4
  mov word ptr fs:[edi+2], ax
  shr eax, 16
  mov byte ptr fs:[edi+4], al
  add esi, 2
  add edi, 8
  loop descriptor_loop
native_commit:
  mov eax, fs:[PS+0x7c]
  mov dword ptr fs:[eax], 0x02300000
  mov word ptr fs:[PS+0x2c], ds
  mov word ptr fs:[PS+0x2e], es
  mov word ptr fs:[PS+0x30], fs
  mov word ptr fs:[PS+0x32], gs
  mov word ptr fs:[PS+0x34], ss
  sidt fs:[PS+0x36]
  mov eax, fs:[CTRL+0x30]
  mov fs:[PS+0x3c], eax
  mov word ptr fs:[PS+0x40], 0x50
  mov word ptr fs:[PS+0x42], 0
  mov dword ptr fs:[CTRL+0x40], 1
  inc dword ptr fs:[CTRL+0x44]
  mov eax, fs:[0xfdea00]
  mov fs:[0xfdea40], eax
  mov eax, fs:[0xfdea04]
  mov fs:[0xfdea44], eax
  mov eax, fs:[0xfdea08]
  mov fs:[0xfdea48], eax
  mov eax, fs:[0xfdea18]
  mov fs:[0xfdea4c], eax
  mov eax, fs:[0xfdea10]
  mov fs:[0xfdea50], eax
  movzx eax, word ptr fs:[0xfdea28]
  shl eax, 16
  mov ax, fs:[0xfdea14]
  mov fs:[0xfdea54], eax
  mov eax, fs:[0xfdea0c]
  mov fs:[0xfdea58], eax
  mov dword ptr fs:[0xfdea5c], 2
  mov eax, fs:[PS+0x6c]
  mov ss:[esp-4], eax
  mov ax, 0x98
  mov ss, ax
  mov esp, 0xb00
  mov ax, 0x78
  mov ds, ax
  mov ax, 0x80
  mov es, ax
  mov ax, 0x90
  mov gs, ax
  mov ax, 0x88
  mov fs, ax
  ljmp 0x28, low_entry-0x2000
descriptor_guard:
  mov eax, fs:[esi]
  cmp eax, fs:[edi]
  jne descriptor_done
  mov eax, fs:[esi+4]
  cmp eax, fs:[edi+4]
descriptor_done:
  ret
fallback:
  mov eax, fs:[PS+0x6c]
  push dword ptr fs:[PS+32]
  popfd
  mov ss:[esp-4], eax
  mov ebx, fs:[PS+4]
  mov ecx, fs:[PS+8]
  mov edx, fs:[PS+12]
  mov esi, fs:[PS+16]
  mov edi, fs:[PS+20]
  mov eax, fs:[PS]
  out 0xf4, al
  jmp dword ptr fs:[CTRL+0x30]

.section .low,"ax"
.code16
.global low_entry
low_entry:
  data32 lidt cs:[real_idt-0x2000]
  mov eax, cs:[RM+0x24-0x2000]
  push eax
  popfd
  cli
  mov ebx, cs:[RM+4-0x2000]
  mov ecx, cs:[RM+8-0x2000]
  mov edx, cs:[RM+12-0x2000]
  mov esi, cs:[RM+16-0x2000]
  mov edi, cs:[RM+20-0x2000]
  mov ebp, cs:[RM+24-0x2000]
  mov eax, cs:[PS+0x24-0x2000]
  and ax, 0xfffe
  mov cr0, eax
  ljmp 0x240, real_entry-0x2400
real_entry:
  mov ax, cs:[RM+0x34-0x2400]
  mov ss, ax
  mov esp, cs:[RM+0x30-0x2400]
  mov ax, cs:[RM+0x36-0x2400]
  mov ds, ax
  mov ax, cs:[RM+0x38-0x2400]
  mov es, ax
  mov ax, cs:[RM+0x3a-0x2400]
  mov fs, ax
  mov ax, cs:[RM+0x3c-0x2400]
  mov gs, ax
  mov eax, cs:[PS+0x24-0x2400]
  and ax, 0xfffe
  jmp dword ptr cs:[RM+0x20-0x2400]
real_idt:
  .word 0x3ff
  .long 0
