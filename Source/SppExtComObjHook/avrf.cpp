#include "pch.hpp"

#include "hooks.hpp"

struct hook_entry
{
	UNICODE_STRING dll_name;
	ANSI_STRING function_name;
	PVOID old_address;
	PVOID new_address;
};

#define DEFINE_HOOK(dll, name) {RTL_CONSTANT_STRING(L ## #dll), RTL_CONSTANT_STRING(#name), nullptr, (PVOID)&name ## _Hook}

static hook_entry s_hooks[] =
{
	DEFINE_HOOK(rpcrt4.dll, RpcStringBindingComposeW),
	DEFINE_HOOK(rpcrt4.dll, RpcBindingFromStringBindingW),
	DEFINE_HOOK(rpcrt4.dll, RpcStringFreeW),
	DEFINE_HOOK(rpcrt4.dll, RpcBindingFree),
	DEFINE_HOOK(rpcrt4.dll, RpcAsyncInitializeHandle),
	DEFINE_HOOK(rpcrt4.dll, RpcAsyncCompleteCall),
	DEFINE_HOOK(rpcrt4.dll, NdrAsyncClientCall),
	DEFINE_HOOK(rpcrt4.dll, NdrClientCall2),
#ifdef _WIN64
	DEFINE_HOOK(rpcrt4.dll, Ndr64AsyncClientCall),
	DEFINE_HOOK(rpcrt4.dll, NdrClientCall3),
#endif
};

static UNICODE_STRING const s_target_images[] =
{
	RTL_CONSTANT_STRING(L"osppobjs"),
	RTL_CONSTANT_STRING(L"sppobjs"),
	RTL_CONSTANT_STRING(L"SppExtComObj")
};

static VOID NTAPI DllLoadCallback(PWSTR DllName, PVOID DllBase, SIZE_T DllSize, PVOID Reserved);

static RTL_VERIFIER_DLL_DESCRIPTOR s_dll_descriptors[] = { {} };

static RTL_VERIFIER_PROVIDER_DESCRIPTOR s_provider_descriptor =
{
	sizeof(RTL_VERIFIER_PROVIDER_DESCRIPTOR),
	s_dll_descriptors,
	&DllLoadCallback
};

BOOL WINAPI DllMain(
	PVOID dll_handle,
	DWORD reason,
	PRTL_VERIFIER_PROVIDER_DESCRIPTOR* provider
)
{
	switch (reason)
	{
	case DLL_PROCESS_ATTACH:
		DebugPrint("Attached to process\n");
		LdrDisableThreadCalloutsForDll(dll_handle);
		break;
	case DLL_PROCESS_VERIFIER:
		DebugPrint("Setting verifier provider\n");

		// Sort hooks by hook ptr, so we can find originals fast using binary search
		std::sort(std::begin(s_hooks), std::end(s_hooks),
			[](const hook_entry& a, const hook_entry& b)
			{
				return a.new_address < b.new_address;
			});

		*provider = &s_provider_descriptor;
		break;
	default:
		break;
	}
	return TRUE;
}

static void apply_iat_hooks_on_dll(PVOID dll)
{
	const auto base = PUCHAR(dll);

	const auto dosh = PIMAGE_DOS_HEADER(dll);
	if (dosh->e_magic != IMAGE_DOS_SIGNATURE)
		return;

	const auto nth = PIMAGE_NT_HEADERS(base + dosh->e_lfanew);
	if (nth->Signature != IMAGE_NT_SIGNATURE)
		return;

	const auto import_dir = &nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	if (import_dir->VirtualAddress == 0 || import_dir->Size == 0)
		return;

	const auto import_begin = PIMAGE_IMPORT_DESCRIPTOR(base + import_dir->VirtualAddress);
	const auto import_end = PIMAGE_IMPORT_DESCRIPTOR(PUCHAR(import_begin) + import_dir->Size);

	for(auto desc = import_begin; desc < import_end; ++desc)
	{
		if (!desc->Name)
			break;

		const auto thunk_begin = PIMAGE_THUNK_DATA(base + desc->FirstThunk);
		const auto original_thunk_begin = PIMAGE_THUNK_DATA(base + desc->OriginalFirstThunk);

		for (auto thunk = thunk_begin, original_thunk = original_thunk_begin; thunk->u1.Function; ++thunk, ++original_thunk)
			for (auto& hook : s_hooks)
				if (hook.old_address
					? (hook.old_address == PVOID(thunk->u1.Function))
					: (!(original_thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
					&& 0 == strcmp(reinterpret_cast<const char*>(PIMAGE_IMPORT_BY_NAME(base + original_thunk->u1.AddressOfData)->Name), hook.function_name.Buffer)))
				{
					PVOID target = &thunk->u1.Function;
					SIZE_T target_size = sizeof(PVOID);
					ULONG old_protect;
					NtProtectVirtualMemory(NtCurrentProcess(), &target, &target_size, PAGE_EXECUTE_READWRITE, &old_protect);
					hook.old_address = PVOID(thunk->u1.Function);
					thunk->u1.Function = ULONG_PTR(hook.new_address);
					NtProtectVirtualMemory(NtCurrentProcess(), &target, &target_size, old_protect, &old_protect);
				}
	}
}

static VOID NTAPI DllLoadCallback(PWSTR DllName, PVOID DllBase, SIZE_T DllSize, PVOID Reserved)
{
	UNREFERENCED_PARAMETER(DllSize);
	UNREFERENCED_PARAMETER(Reserved);

	for (const auto& target : s_target_images)
	{
		if (0 == _wcsnicmp(DllName, target.Buffer, target.Length / sizeof(wchar_t)))
			apply_iat_hooks_on_dll(DllBase);
	}
}

template<typename Iter, typename T, typename Pred = std::less<T>>
Iter binary_find(Iter begin, Iter end, const T& val, Pred pred = {})
{
	const auto it = std::lower_bound(begin, end, val, pred);

	return it != end && !pred(val, *it) ? it : end;
}

void* get_original_from_hook_address(void* hook_address)
{
	const hook_entry temp_entry{ {}, {}, nullptr, hook_address };
	const auto it = binary_find(std::begin(s_hooks), std::end(s_hooks), temp_entry,
		[](const hook_entry& a, const hook_entry& b)
	{
		return a.new_address < b.new_address;
	});

	return it->old_address;
}

const wchar_t* get_process_name()
{
	return s_provider_descriptor.VerifierImage;
}

void* get_function_address(const wchar_t* dll, const char* fn)
{
	UNICODE_STRING dllu;
	RtlInitUnicodeString(&dllu, dll);

	PVOID handle;
	auto status = LdrGetDllHandle(nullptr, nullptr, &dllu, &handle);

	if (!NT_SUCCESS(status))
		status = LdrLoadDll(nullptr, nullptr, &dllu, &handle);

	if (!NT_SUCCESS(status))
		return nullptr;

	ANSI_STRING fna;
	RtlInitAnsiString(&fna, fn);

	PVOID proc;
	status = LdrGetProcedureAddress(handle, &fna, 0, &proc);

	return NT_SUCCESS(status) ? proc : nullptr;
}