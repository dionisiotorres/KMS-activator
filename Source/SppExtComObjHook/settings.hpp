#pragma once

struct KMSServerSettings
{
	ULONG64 hwid;
	USHORT activation_interval;
	USHORT renewal_interval;
	bool enabled;
};

extern KMSServerSettings g_settings;

NTSTATUS settings_update();

NTSTATUS settings_get_kmspid_for_kmspid(PWSTR kmspid, const GUID& kmsid);