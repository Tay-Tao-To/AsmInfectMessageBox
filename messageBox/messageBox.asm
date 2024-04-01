.386
.model flat, stdcall
option casemap :none   ; Case sensitive

include \masm32\include\windows.inc
include \masm32\include\kernel32.inc
include \masm32\include\user32.inc
include \masm32\include\masm32.inc

includelib \masm32\lib\kernel32.lib
includelib \masm32\lib\user32.lib
includelib \masm32\lib\masm32.lib

.data
    fileHandle dd ?
    bytesRead dd ?
    dosHeader IMAGE_DOS_HEADER <>
    ntHeaders IMAGE_NT_HEADERS <>
    filePathBuffer db 256 dup(?)
    errMsg db "Error: Unable to open file or file is not a valid PE.", 0
    thirdArg db 256 dup(?)

.code
main proc
    LOCAL argc:DWORD
    LOCAL argv:DWORD
    
    invoke GetCommandLine
    invoke CommandLineToArgvW, eax, addr argc
    mov eax, [argc]
    cmp eax, 3
    jne displayError

    ; Get the third argument (file path)
    mov eax, [argv]
    invoke GetThirdArgument, eax, addr thirdArg
    test eax, eax
    jz displayError

    ; Open the file
    invoke OpenFile, addr thirdArg
    test eax, eax
    jz displayError

    ; File handle is in eax after successful OpenFile
    mov fileHandle, eax

    ;... (Rest of your code to process the file)

    jmp finished

displayError:
    invoke MessageBox, NULL, addr errMsg, addr errMsg, MB_ICONERROR or MB_OK

finished:
    cmp fileHandle, NULL
    je cleanup
    invoke CloseHandle, fileHandle

cleanup:
    invoke GlobalFree, argv
    invoke ExitProcess, 0
main endp

GetThirdArgument proc argv:DWORD, thirdArgBuffer:DWORD
    ; argv is the array of arguments
    ; thirdArgBuffer is the buffer where the third argument will be copied
    mov eax, [argv]
    mov ecx, [eax + 8]  ; Third command-line argument (Unicode string)
    test ecx, ecx
    jz _error
    invoke WideCharToMultiByte, CP_ACP, 0, ecx, -1, thirdArgBuffer, 256, NULL, NULL
    mov eax, 1  ; Success
    jmp _done
_error:
    mov eax, 0  ; Error
_done:
    ret
GetThirdArgument endp

OpenFile proc filePath:DWORD
    LOCAL securityAttributes:SECURITY_ATTRIBUTES
    mov securityAttributes.nLength, SIZEOF SECURITY_ATTRIBUTES
    mov securityAttributes.lpSecurityDescriptor, NULL
    mov securityAttributes.bInheritHandle, TRUE
    invoke CreateFile, filePath, GENERIC_READ, FILE_SHARE_READ, addr securityAttributes, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
    ret
OpenFile endp

;... (Rest of your code)

end main