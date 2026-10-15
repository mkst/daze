.intel_syntax noprefix
.section .text
.code32
.global native_entry
.equ PS, 0x2a00
.equ RM, 0x2a80
.equ CTRL, 0x5800
.equ REC, 0xfdea00
.equ MAIL, 0xfdea40
.equ VECTOR_TABLE, CTRL+0x80
.equ VECTOR_COUNT, CTRL+0x680
.equ VECTOR_VALID, CTRL+0x684
.equ VECTOR_SIGNATURE, 0x02040204
.equ SET_COUNT, CTRL+0x68c
.equ SET_GDT, CTRL+0x690
.equ SET_GDT_LAST, CTRL+0x694
.equ SET_RAM_LAST, CTRL+0x698
.equ SET_VALID, CTRL+0x69c
native_entry:
  cmp word ptr fs:[REC], 0xc
  je set_descriptor_entry
  cmp word ptr fs:[REC], 0x204
  je vector_entry
  cmp word ptr fs:[REC], 7
  jb callback_entry
  cmp word ptr fs:[REC], 9
  jbe descriptor_entry
callback_entry:
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

vector_entry:
  cmp dword ptr fs:[VECTOR_VALID], VECTOR_SIGNATURE
  jne callback_entry
  mov eax, cr0
  test eax, 0x80000000
  jnz callback_entry
  jmp descriptor_reply

descriptor_entry:
  /* The host mediator writes physical guest RAM. */
  mov eax, cr0
  test eax, 0x80000000
  jnz descriptor_fallback
  mov edi, fs:[CTRL+0x70]
  test edi, edi
  jz descriptor_fallback
  movzx edx, word ptr fs:[REC+4]
  test dl, 4
  jz descriptor_fallback
  and edx, 0xfff8
  jz descriptor_fallback
  cmp edx, edi
  ja descriptor_fallback
  add edx, fs:[CTRL+0x6c]
  movzx eax, word ptr fs:[REC]
  mov ecx, fs:[REC+8]
  cmp ax, 7
  je descriptor_base
  cmp ax, 8
  je descriptor_limit
  test ch, 0x10
  jnz descriptor_fallback
  test cl, 0x10
  jz descriptor_fallback
  test cl, 0x60
  jnz descriptor_fallback
  mov al, cl
  and al, 0x88
  cmp al, 0x88
  jne descriptor_rights_valid
  mov al, cl
  and al, 6
  cmp al, 2
  jne descriptor_fallback
descriptor_rights_valid:
  mov byte ptr fs:[edx+5], cl
  mov al, fs:[edx+6]
  and al, 0x0f
  and ch, 0xf0
  or al, ch
  mov byte ptr fs:[edx+6], al
  inc dword ptr fs:[CTRL+0x7c]
  jmp descriptor_reply
descriptor_base:
  mov eax, fs:[REC+12]
  mov word ptr fs:[edx+2], ax
  mov byte ptr fs:[edx+4], cl
  mov byte ptr fs:[edx+7], ch
  inc dword ptr fs:[CTRL+0x74]
  jmp descriptor_reply
descriptor_limit:
  shl ecx, 16
  mov cx, fs:[REC+12]
  mov al, fs:[edx+6]
  and al, 0x70
  cmp ecx, 0xfffff
  jbe descriptor_limit_valid
  mov edi, ecx
  and edi, 0xfff
  cmp edi, 0xfff
  jne descriptor_fallback
  shr ecx, 12
  or al, 0x80
descriptor_limit_valid:
  mov word ptr fs:[edx], cx
  shr ecx, 16
  or al, cl
  mov byte ptr fs:[edx+6], al
  inc dword ptr fs:[CTRL+0x78]
descriptor_reply:
  mov dword ptr fs:[CTRL], 0
  mov eax, fs:[REC]
  mov fs:[MAIL], eax
  mov eax, fs:[REC+4]
  mov fs:[MAIL+4], eax
  mov eax, fs:[REC+8]
  mov fs:[MAIL+8], eax
  mov eax, fs:[REC+24]
  mov fs:[MAIL+12], eax
  mov eax, fs:[REC+16]
  mov fs:[MAIL+16], eax
  mov eax, fs:[REC+40]
  shl eax, 16
  mov ax, fs:[REC+20]
  mov fs:[MAIL+20], eax
  mov eax, fs:[REC+12]
  mov fs:[MAIL+24], eax
  mov dword ptr fs:[MAIL+28], 0
  cmp word ptr fs:[REC], 0x204
  jne vector_reply_done
  movzx edx, byte ptr fs:[REC+4]
  lea edx, [edx+edx*2]
  shl edx, 1
  mov eax, fs:[REC+8]
  mov ax, fs:[edx+VECTOR_TABLE]
  mov fs:[MAIL+8], eax
  mov eax, fs:[edx+VECTOR_TABLE+2]
  mov fs:[MAIL+24], eax
  inc dword ptr fs:[VECTOR_COUNT]
vector_reply_done:
  jmp dword ptr fs:[CTRL+0x30]
descriptor_fallback:
  mov al, 0x31
  out 0xf4, al
  jmp dword ptr fs:[CTRL+0x30]

.section .set_descriptor,"ax"
.code32
set_descriptor_entry:
  cmp dword ptr fs:[SET_VALID], 0x000c000c
  jne descriptor_fallback
  mov eax, cr0
  test eax, 0x80000000
  jnz descriptor_fallback
  mov edi, fs:[CTRL+0x70]
  movzx edx, word ptr fs:[REC+4]
  test dl, 4
  jz descriptor_fallback
  and edx, 0xfff8
  jz descriptor_fallback
  cmp edx, edi
  ja descriptor_fallback
  add edx, fs:[CTRL+0x6c]
  movzx ecx, word ptr fs:[REC+20]
  mov esi, ecx
  and esi, 0xfff8
  jz descriptor_fallback
  test cl, 4
  jz set_descriptor_global_source
  cmp esi, edi
  ja descriptor_fallback
  add esi, fs:[CTRL+0x6c]
  jmp set_descriptor_source
set_descriptor_global_source:
  cmp esi, fs:[SET_GDT_LAST]
  ja descriptor_fallback
  add esi, fs:[SET_GDT]
set_descriptor_source:
  mov eax, fs:[esi+4]
  movzx ecx, word ptr fs:[esi+2]
  mov ebx, eax
  and ebx, 0xff000000
  or ecx, ebx
  and eax, 0xff
  shl eax, 16
  or ecx, eax
  movzx eax, word ptr fs:[REC+16]
  add ecx, eax
  jc descriptor_fallback
  cmp ecx, fs:[SET_RAM_LAST]
  ja descriptor_fallback
  /* Snapshot the source before either store: descriptor buffers can overlap. */
  mov eax, fs:[ecx]
  mov ebx, fs:[ecx+4]
  test ebx, 0x100000
  jnz descriptor_fallback
  test bh, 0x10
  jz descriptor_fallback
  test bh, 0x60
  jnz descriptor_fallback
  mov cl, bh
  and cl, 0x88
  cmp cl, 0x88
  jne set_descriptor_valid
  mov cl, bh
  and cl, 6
  cmp cl, 2
  jne descriptor_fallback
set_descriptor_valid:
  mov fs:[edx], eax
  mov fs:[edx+4], ebx
  inc dword ptr fs:[SET_COUNT]
  jmp descriptor_reply

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
