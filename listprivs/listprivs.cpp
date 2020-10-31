// listprivs.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <Windows.h>
#include <winternl.h>
#ifndef NATIVE
#include <stdio.h>
#endif

extern "C" {
    NTSTATUS NTAPI NtTerminateProcess(_In_opt_ HANDLE ProcessHandle, _In_ NTSTATUS ExitStatus);
    NTSTATUS NTAPI NtDelayExecution(_In_ BOOLEAN Alertable, _In_opt_ PLARGE_INTEGER DelayInterval);
    NTSTATUS NTAPI NtDrawText(_In_ PUNICODE_STRING Text);
    NTSTATUS NTAPI NtQueryInformationToken(
            _In_ HANDLE TokenHandle,
            _In_ TOKEN_INFORMATION_CLASS TokenInformationClass,
            _Out_writes_bytes_to_opt_(TokenInformationLength, *ReturnLength) PVOID TokenInformation,
            _In_ ULONG TokenInformationLength,
            _Out_ PULONG ReturnLength);
    NTSTATUS NTAPI NtWriteFile(
            _In_ HANDLE FileHandle,
            _In_opt_ HANDLE Event,
            _In_opt_ PIO_APC_ROUTINE ApcRoutine,
            _In_opt_ PVOID ApcContext,
            _Out_ PIO_STATUS_BLOCK IoStatusBlock,
            _In_reads_bytes_(Length) PVOID Buffer,
            _In_ ULONG Length,
            _In_opt_ PLARGE_INTEGER ByteOffset,
            _In_opt_ PULONG Key);
    NTSTATUS NTAPI NtClose(HANDLE);
}

#ifdef NATIVE
extern "C" {
    int sprintf_s(
        char* const buffer,
        size_t sizeOfBuffer,
        const char* format, ...);
    size_t strlen(const char*);
    int swprintf_s(
        wchar_t* buffer,
        size_t numberOfElements,
        const wchar_t* format, ...);
}
#endif

#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)

extern "C" NTSTATUS NTAPI SavePrivilegesInfoToFile(PCWSTR path) {
    BYTE buffer[1 << 12];
    ULONG len;
    auto status = NtQueryInformationToken(GetCurrentProcessToken(), TokenPrivileges, buffer, sizeof(buffer), &len);
    if (!NT_SUCCESS(status))
        return status;

    auto privs = (TOKEN_PRIVILEGES*)buffer;
    WCHAR text[32];
    swprintf_s(text, _countof(text), L"Privileges: %u", privs->PrivilegeCount);
    UNICODE_STRING utext;
    RtlInitUnicodeString(&utext, text);
#ifdef NATIVE
    NtDrawText(&utext);
#else
    printf("%ws\n", text);
#endif
    HANDLE hFile;
    OBJECT_ATTRIBUTES fileAttributes;
    UNICODE_STRING filename;
    RtlInitUnicodeString(&filename, path);
    InitializeObjectAttributes(&fileAttributes, &filename, 0, nullptr, nullptr);
    IO_STATUS_BLOCK ioStatus;
    status = NtCreateFile(&hFile, FILE_GENERIC_WRITE | SYNCHRONIZE, &fileAttributes, &ioStatus, nullptr, 0, 0, FILE_SUPERSEDE, 
        FILE_SEQUENTIAL_ONLY | FILE_SYNCHRONOUS_IO_NONALERT, nullptr, 0);
    if (!NT_SUCCESS(status))
        return status;

    char textToWrite[128];
    sprintf_s(textToWrite, sizeof(textToWrite), "Privileges: %u\n", privs->PrivilegeCount);
    status = NtWriteFile(hFile, nullptr, nullptr, nullptr, &ioStatus, textToWrite, (ULONG)strlen(textToWrite), nullptr, nullptr);
    for (ULONG i = 0; i < privs->PrivilegeCount; i++) {
        auto& priv = privs->Privileges[i];
        sprintf_s(textToWrite, sizeof(textToWrite), "0x%08X (%u)\n", priv.Luid.LowPart, priv.Attributes);
        status = NtWriteFile(hFile, nullptr, nullptr, nullptr, &ioStatus, textToWrite, (ULONG)strlen(textToWrite), nullptr, nullptr);
    }
    NtClose(hFile);
    return 0;
}

#ifndef NATIVE
int main() {
    SavePrivilegesInfoToFile(L"\\??\\c:\\temp\\privs.txt");
    return 0;
}
#else
extern "C" void NTAPI NtProcessStartup(PPEB peb) {
    SavePrivilegesInfoToFile(L"\\??\\c:\\temp\\privs.txt");
    LARGE_INTEGER interval;
    interval.QuadPart = -10000 * 3000;
    NtDelayExecution(FALSE, &interval);
    NtTerminateProcess(NtCurrentProcess(), 0);
}
#endif
