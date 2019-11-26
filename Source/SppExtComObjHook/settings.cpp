#include "pch.hpp"

#include "kms.h"
#include "avrf.hpp"
#include "settings.hpp"

#define KMS_ACTIVATION_INTERVAL_KEY L"KMS_ActivationInterval"
#define KMS_ACTIVATION_INTERVAL_DEFAULT 120
#define KMS_ACTIVATION_INTERVAL_MIN 15
#define KMS_ACTIVATION_INTERVAL_MAX 43200

#define KMS_RENEWAL_INTERVAL_KEY L"KMS_RenewalInterval"
#define KMS_RENEWAL_INTERVAL_DEFAULT 10080
#define KMS_RENEWAL_INTERVAL_MIN 15
#define KMS_RENEWAL_INTERVAL_MAX 43200

#define KMS_HWID_KEY L"KMS_HWID"
#define KMS_HWID_DEFAULT 0x3A1C049600B60076
#define KMS_HWID_MIN 0x1111111111111111ULL
#define KMS_HWID_MAX 0xFFFFFFFFFFFFFFFEULL

#define KMS_ENABLED_KEY L"KMS_Emulation"
#define KMS_ENABLED_DEFAULT TRUE

#define KMS_PID_KEY_PREFIX L"KMS_PID_"

// KMS server settings
KMSServerSettings g_settings = {
	// KMS Host HWID
	KMS_HWID_DEFAULT,
	// Activation Interval
	KMS_ACTIVATION_INTERVAL_DEFAULT,
	// Renewal Interval
	KMS_RENEWAL_INTERVAL_DEFAULT,
	// KMS enabled Flag
	KMS_ENABLED_DEFAULT,
};

static NTSTATUS open_ifeo(PHANDLE key)
{
	const auto name = get_process_name();
	UNICODE_STRING ustr;
	RtlInitUnicodeString(&ustr, name);

	return LdrOpenImageFileOptionsKey(&ustr, false, key);
}

NTSTATUS settings_update()
{
	HANDLE key;

	auto status = open_ifeo(&key);
	if (!NT_SUCCESS(status))
		return status;

	// Read KMS enabled
	ULONG tmp_ulong;
	status = LdrQueryImageFileKeyOption(key, KMS_ENABLED_KEY, REG_DWORD, &tmp_ulong, sizeof(tmp_ulong), nullptr);
	if (NT_SUCCESS(status))
		g_settings.enabled = bool(tmp_ulong);

	// Read activation_interval
	status = LdrQueryImageFileKeyOption(key, KMS_ACTIVATION_INTERVAL_KEY, REG_DWORD, &tmp_ulong, sizeof(tmp_ulong), nullptr);
	if (NT_SUCCESS(status))
		g_settings.activation_interval = (USHORT)std::clamp<ULONG>(tmp_ulong, KMS_ACTIVATION_INTERVAL_MIN, KMS_ACTIVATION_INTERVAL_MAX);

	// Read renewal_interval
	status = LdrQueryImageFileKeyOption(key, KMS_RENEWAL_INTERVAL_KEY, REG_DWORD, &tmp_ulong, sizeof(tmp_ulong), nullptr);
	if (NT_SUCCESS(status))
		g_settings.renewal_interval = (USHORT)std::clamp<ULONG>(tmp_ulong, KMS_RENEWAL_INTERVAL_MIN, KMS_RENEWAL_INTERVAL_MAX);

	// Read HWID
	ULONG64 tmp_ulong64;
	status = LdrQueryImageFileKeyOption(key, KMS_HWID_KEY, REG_QWORD, &tmp_ulong64, sizeof(tmp_ulong64), nullptr);
	if (NT_SUCCESS(status))
		g_settings.hwid = std::clamp<ULONG64>(tmp_ulong64, KMS_HWID_MIN, KMS_HWID_MAX);

	NtClose(key);

	return STATUS_SUCCESS;
}

NTSTATUS settings_get_kmspid_for_kmspid(PWSTR kmspid, const GUID& kmsid)
{
	wchar_t buf[64];

	swprintf_s(buf, sizeof(buf) / sizeof(wchar_t), KMS_PID_KEY_PREFIX GUID_FORMAT, GUID_ARG(kmsid));

	HANDLE key;

	auto status = open_ifeo(&key);
	if (!NT_SUCCESS(status))
		return status;

	status = LdrQueryImageFileKeyOption(key, buf, REG_SZ, kmspid, sizeof (wchar_t) * (PID_BUFFER_LEN - 1), nullptr);

	NtClose(key);

	return status;
}