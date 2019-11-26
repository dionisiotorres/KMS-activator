#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _MSC_VER
#define DLL_PROCESS_VERIFIER 4

using RTL_VERIFIER_DLL_LOAD_CALLBACK = VOID(NTAPI *) (PWSTR DllName, PVOID DllBase, SIZE_T DllSize, PVOID Reserved);
using RTL_VERIFIER_DLL_UNLOAD_CALLBACK = VOID(NTAPI *) (PWSTR DllName, PVOID DllBase, SIZE_T DllSize, PVOID Reserved);
using RTL_VERIFIER_NTDLLHEAPFREE_CALLBACK = VOID(NTAPI *) (PVOID AllocationBase, SIZE_T AllocationSize);

typedef struct _RTL_VERIFIER_THUNK_DESCRIPTOR {
	PCSTR ThunkName;
	PVOID ThunkOldAddress;
	PVOID ThunkNewAddress;
} RTL_VERIFIER_THUNK_DESCRIPTOR, *PRTL_VERIFIER_THUNK_DESCRIPTOR;

typedef struct _RTL_VERIFIER_DLL_DESCRIPTOR {
	PCWSTR DllName;
	DWORD DllFlags;
	PVOID DllAddress;
	PRTL_VERIFIER_THUNK_DESCRIPTOR DllThunks;
} RTL_VERIFIER_DLL_DESCRIPTOR, *PRTL_VERIFIER_DLL_DESCRIPTOR;

typedef struct _RTL_VERIFIER_PROVIDER_DESCRIPTOR {
	DWORD Length;
	PRTL_VERIFIER_DLL_DESCRIPTOR ProviderDlls;
	RTL_VERIFIER_DLL_LOAD_CALLBACK ProviderDllLoadCallback;
	RTL_VERIFIER_DLL_UNLOAD_CALLBACK ProviderDllUnloadCallback;
	PCWSTR VerifierImage;
	DWORD VerifierFlags;
	DWORD VerifierDebug;
	PVOID RtlpGetStackTraceAddress;
	PVOID RtlpDebugPageHeapCreate;
	PVOID RtlpDebugPageHeapDestroy;
	RTL_VERIFIER_NTDLLHEAPFREE_CALLBACK ProviderNtdllHeapFreeCallback;
} RTL_VERIFIER_PROVIDER_DESCRIPTOR, *PRTL_VERIFIER_PROVIDER_DESCRIPTOR;
#endif // _MSC_VER

NTSYSAPI
ULONG
DbgPrint(
	PCSTR Format,
	...
);

NTSYSAPI
ULONG
DbgPrintEx(
	ULONG ComponentId,
	ULONG Level,
	PCSTR Format,
	...
);

NTSYSAPI
NTSTATUS
NTAPI
LdrDisableThreadCalloutsForDll(
	_In_ PVOID DllImageBase
);

NTSYSAPI
NTSTATUS
NTAPI
LdrQueryImageFileKeyOption(
	_In_		HANDLE KeyHandle,
	_In_		PCWSTR ValueName,
	_In_		ULONG Type,
	_Out_		PVOID Buffer,
	_In_		ULONG BufferSize,
	_Out_opt_	PULONG ReturnedLength
);

NTSYSAPI
NTSTATUS
NTAPI
LdrOpenImageFileOptionsKey(
	_In_	PUNICODE_STRING SubKey,
	_In_	BOOLEAN Wow64,
	_Out_	PHANDLE NewKeyHandle
);

NTSYSAPI
NTSTATUS
NTAPI
LdrGetProcedureAddress(
	_In_	PVOID BaseAddress,
	_In_	PANSI_STRING Name,
	_In_	ULONG Ordinal,
	_Out_	PVOID *ProcedureAddress
);

NTSYSAPI
NTSTATUS
NTAPI
LdrGetDllHandle(
	_In_opt_	PWSTR DllPath,
	_In_opt_	PULONG DllCharacteristics,
	_In_		PUNICODE_STRING DllName,
	_Out_		PVOID *DllHandle
);

NTSYSAPI
NTSTATUS
NTAPI
LdrLoadDll(
	_In_opt_	PWSTR SearchPath,
	_In_opt_	PULONG LoadFlags,
	_In_		PUNICODE_STRING Name,
	_Out_opt_	PVOID *BaseAddress
);

NTSYSAPI
NTSTATUS
NTAPI
NtQueryPerformanceCounter(
	_Out_     PLARGE_INTEGER PerformanceCounter,
	_Out_opt_ PLARGE_INTEGER PerformanceFrequency
);

NTSYSAPI
NTSTATUS
NTAPI
NtSetEvent(
	_In_      HANDLE EventHandle,
	_Out_opt_ PLONG  PreviousState
);

NTSYSAPI
NTSTATUS
NTAPI
NtProtectVirtualMemory(
	_In_	HANDLE ProcessHandle,
	_Inout_	PVOID *BaseAddress,
	_Inout_	PSIZE_T RegionSize,
	_In_	ULONG NewProtect,
	_Out_	PULONG OldProtect
);

typedef struct TIME_FIELDS {
	SHORT Year;
	SHORT Month;
	SHORT Day;
	SHORT Hour;
	SHORT Minute;
	SHORT Second;
	SHORT Milliseconds;
	SHORT Weekday;
} TIME_FIELDS, *PTIME_FIELDS;

NTSYSAPI
VOID
NTAPI
RtlTimeToTimeFields(
	PLARGE_INTEGER Time,
	PTIME_FIELDS   TimeFields
);

NTSYSAPI
BOOLEAN
NTAPI
RtlTimeFieldsToTime(
	PTIME_FIELDS   TimeFields,
	PLARGE_INTEGER Time
);

NTSYSAPI
PVOID
NTAPI
RtlAllocateHeap(
	PVOID  HeapHandle,
	ULONG  Flags,
	SIZE_T Size
);

#ifdef _MSC_VER
NTSYSAPI
BOOLEAN
NTAPI
RtlFreeHeap(
	PVOID                 HeapHandle,
	ULONG                 Flags,
	_Frees_ptr_opt_ PVOID BaseAddress
);
#endif // _MSC_VER

NTSYSAPI
ULONG
NTAPI
RtlRandomEx(
	_Inout_ PULONG Seed
);

#define RTL_CONSTANT_STRING(s) { sizeof(s) - sizeof((s)[0]), sizeof(s), (std::add_pointer_t<std::remove_const_t<std::remove_pointer_t<std::decay_t<decltype(s)>>>>)s }

#define NtCurrentProcess() (HANDLE(LONG64(-1)))

#define NtCurrentPeb() (NtCurrentTeb()->ProcessEnvironmentBlock)

#define RtlGetProcessHeap() (NtCurrentPeb()->Reserved4[1])

#ifdef __cplusplus
}
#endif
