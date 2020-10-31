
#include <Windows.h>
#include <winternl.h>

extern "C" {
    NTSTATUS NTAPI NtTerminateProcess(
        _In_opt_ HANDLE ProcessHandle,
        _In_ NTSTATUS ExitStatus);
    NTSTATUS NTAPI NtDelayExecution(_In_ BOOLEAN Alertable, _In_opt_ PLARGE_INTEGER DelayInterval);
    NTSTATUS NTAPI NtDrawText(_In_ PUNICODE_STRING Text);
}

#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)

extern "C" void NTAPI NtProcessStartup(PPEB peb) {
    PROCESS_BASIC_INFORMATION info;
    NtQueryInformationProcess(NtCurrentProcess(), ProcessBasicInformation, &info, sizeof(info), nullptr);
    UNICODE_STRING text;
    RtlInitUnicodeString(&text, L"Hello, Native World!");
    NtDrawText(&text);

    LARGE_INTEGER interval;
    interval.QuadPart = -10000 * 5000;
    NtDelayExecution(FALSE, &interval);
    NtTerminateProcess(NtCurrentProcess(), 0);
}
