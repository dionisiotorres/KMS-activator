#include "pch.hpp"

#include "kms.h"
#include "avrf.hpp"
#include "settings.hpp"

struct host_os
{
	ULONG type;
	ULONG build;
	ULONG64 csvlk_time; // in file time
} const static k_host_os[] =
{
	{ 5426,  9200,  129911904000000000LL},    // Windows Server 2012     : 2012/09/04 RTM GA
	{ 6401,  9600,  130264416000000000LL},    // Windows Server 2012 R2  : 2013/10/17 RTM GA
	{ 3612,  14393, 131207040000000000LL},    // Windows Server 2016     : 2016/10/12 RTM GA
	{ 3612,  17763, 131829120000000000LL}     // Windows Server 2019     : 2018/10/02 RTM GA
};

enum : unsigned
{
	HOST_SERVER2012 = 0,
	HOST_SERVER2012R2,
	HOST_SERVER2016,
	HOST_SERVER2019
};

// CSVLK group id and pid range
struct pkeyconfig
{
	USHORT group_id;
	UCHAR os_min;
	UCHAR os_max;
	ULONG range_min;
	ULONG range_max;
} const static k_pkeyconfig[] =
{
	{ 206,	HOST_SERVER2012, HOST_SERVER2012,	152000000,	191999999	}, // Windows Server 2012
	{ 206,	HOST_SERVER2012, HOST_SERVER2012R2,	271000000,	310999999	}, // Windows Server 2012 R2
	{ 206,	HOST_SERVER2012, HOST_SERVER2016,	491000000,	530999999	}, // Windows Server 2016
	{ 206,	HOST_SERVER2012R2, HOST_SERVER2019,	551000000,	570999999	}, // Windows Server 2019
	{ 96,	HOST_SERVER2012, HOST_SERVER2012R2,	199000000,	217999999	}, // Office 2010
	{ 206,	HOST_SERVER2012, HOST_SERVER2016,	234000000,	255999999	}, // Office 2013
	{ 206,	HOST_SERVER2012, HOST_SERVER2019,	437000000,	458999999	}, // Office 2016
	{ 206,	HOST_SERVER2012R2, HOST_SERVER2019,	666000000,	685999999	}, // Office 2019
	{ 206,	HOST_SERVER2012R2, HOST_SERVER2019,	2835000,	2854999		}, // Windows Server 2019 VL Retail
	{ 3858,	HOST_SERVER2019, HOST_SERVER2019,	0,			14999999	}, // Windows 10 China Government
};

enum : unsigned
{
	PKEYCONFIG_SERVER2012_CSVLK = 0,
	PKEYCONFIG_SERVER2012R2_CSVLK,
	PKEYCONFIG_SERVER2016_CSVLK,
	PKEYCONFIG_SERVER2019_CSVLK,
	PKEYCONFIG_OFFICE2010_CSVLK,
	PKEYCONFIG_OFFICE2013_CSVLK,
	PKEYCONFIG_OFFICE2016_CSVLK,
	PKEYCONFIG_OFFICE2019_CSVLK,
	PKEYCONFIG_SERVER2019R_CSVLK,
	PKEYCONFIG_WIN10GOV_CSVLK,

	// Let's hope 2019 server works for unknown products
	PKEYCONFIG_DEFAULT = PKEYCONFIG_SERVER2019_CSVLK
};

// KmsCountedIdList
//static const GUID APP_ID_WINDOWS =                  {0x55C92734, 0xD682, 0x4D71, {0x98, 0x3E, 0xD6, 0xEC, 0x3F, 0x16, 0x05, 0x9F}};
//static const GUID APP_ID_OFFICE14 =                 {0x59A52881, 0xA989, 0x479D, {0xAF, 0x46, 0xF2, 0x75, 0xC6, 0x37, 0x06, 0x63}};
//static const GUID APP_ID_OFFICE15 =                 {0x0FF1CE15, 0xA989, 0x479D, {0xAF, 0x46, 0xF2, 0x75, 0xC6, 0x37, 0x06, 0x63}};
static const GUID KMS_ID_OFFICE_2010 =              {0xE85AF946, 0x2E25, 0x47B7, {0x83, 0xE1, 0xBE, 0xBC, 0xEB, 0xEA, 0xC6, 0x11}};
static const GUID KMS_ID_OFFICE_2013 =              {0xE6A6F1BF, 0x9D40, 0x40C3, {0xAA, 0x9F, 0xC7, 0x7B, 0xA2, 0x15, 0x78, 0xC0}};
static const GUID KMS_ID_OFFICE_2016 =              {0x85B5F61B, 0x320B, 0x4BE3, {0x81, 0x4A, 0xB7, 0x6B, 0x2B, 0xFA, 0xFC, 0x82}};
static const GUID KMS_ID_OFFICE_2019 =              {0x617D9EB1, 0xEF36, 0x4F82, {0x86, 0xE0, 0xA6, 0x5A, 0xE0, 0x7B, 0x96, 0xC6}};
static const GUID KMS_ID_WINDOWS_VISTA =            {0x212A64DC, 0x43B1, 0x4D3D, {0xA3, 0x0C, 0x2F, 0xC6, 0x9D, 0x20, 0x95, 0xC6}};
static const GUID KMS_ID_WINDOWS_7 =                {0x7FDE5219, 0xFBFA, 0x484A, {0x82, 0xC9, 0x34, 0xD1, 0xAD, 0x53, 0xE8, 0x56}};
static const GUID KMS_ID_WINDOWS_8_RETAIL =         {0xBBB97B3B, 0x8CA4, 0x4A28, {0x97, 0x17, 0x89, 0xFA, 0xBD, 0x42, 0xC4, 0xAC}};
static const GUID KMS_ID_WINDOWS_8_VOLUME =         {0x3C40B358, 0x5948, 0x45AF, {0x92, 0x3B, 0x53, 0xD2, 0x1F, 0xCC, 0x7E, 0x79}};
static const GUID KMS_ID_WINDOWS_81_RETAIL =        {0x6D646890, 0x3606, 0x461A, {0x86, 0xAB, 0x59, 0x8B, 0xB8, 0x4A, 0xCE, 0x82}};
static const GUID KMS_ID_WINDOWS_81_VOLUME =        {0xCB8FC780, 0x2C05, 0x495A, {0x97, 0x10, 0x85, 0xAF, 0xFF, 0xC9, 0x04, 0xD7}};
static const GUID KMS_ID_WINDOWS_10_RETAIL =        {0xE1C51358, 0xFE3E, 0x4203, {0xA4, 0xA2, 0x3B, 0x6B, 0x20, 0xC9, 0x73, 0x4E}};
static const GUID KMS_ID_WINDOWS_10_VOLUME =        {0x58E2134F, 0x8E11, 0x4D17, {0x9C, 0xB2, 0x91, 0x06, 0x9C, 0x15, 0x11, 0x48}};
static const GUID KMS_ID_WINDOWS_10_UNKNOWN =       {0xD27CD636, 0x1962, 0x44E9, {0x8B, 0x4F, 0x27, 0xB6, 0xC2, 0x3E, 0xFB, 0x85}};
static const GUID KMS_ID_WINDOWS_10_LTSB_2016 =     {0x969FE3C0, 0xA3EC, 0x491A, {0x9F, 0x25, 0x42, 0x36, 0x05, 0xDE, 0xB3, 0x65}};
static const GUID KMS_ID_WINDOWS_10_LTSC_2019 =     {0x11B15659, 0xE603, 0x4CF1, {0x9C, 0x1F, 0xF0, 0xEC, 0x01, 0xB8, 0x18, 0x88}};
static const GUID KMS_ID_WINDOWS_10_GOV =           {0x7BA0BF23, 0xD0F5, 0x4072, {0x91, 0xD9, 0xD5, 0x5A, 0xF5, 0xA4, 0x81, 0xB6}};
static const GUID KMS_ID_WINDOWS_SERVER_2008A =     {0x33E156E4, 0xB76F, 0x4A52, {0x9F, 0x91, 0xF6, 0x41, 0xDD, 0x95, 0xAC, 0x48}};
static const GUID KMS_ID_WINDOWS_SERVER_2008B =     {0x8FE53387, 0x3087, 0x4447, {0x89, 0x85, 0xF7, 0x51, 0x32, 0x21, 0x5A, 0xC9}};
static const GUID KMS_ID_WINDOWS_SERVER_2008C =     {0x8A21FDF3, 0xCBC5, 0x44EB, {0x83, 0xF3, 0xFE, 0x28, 0x4E, 0x66, 0x80, 0xA7}};
static const GUID KMS_ID_WINDOWS_SERVER_2008R2A =   {0x0FC6CCAF, 0xFF0E, 0x4FAE, {0x9D, 0x08, 0x43, 0x70, 0x78, 0x5B, 0xF7, 0xED}};
static const GUID KMS_ID_WINDOWS_SERVER_2008R2B =   {0xCA87F5B6, 0xCD46, 0x40C0, {0xB0, 0x6D, 0x8E, 0xCD, 0x57, 0xA4, 0x37, 0x3F}};
static const GUID KMS_ID_WINDOWS_SERVER_2008R2C =   {0xB2CA2689, 0xA9A8, 0x42D7, {0x93, 0x8D, 0xCF, 0x8E, 0x9F, 0x20, 0x19, 0x58}};
static const GUID KMS_ID_WINDOWS_SERVER_2012 =      {0x8665CB71, 0x468C, 0x4AA3, {0xA3, 0x37, 0xCB, 0x9B, 0xC9, 0xD5, 0xEA, 0xAC}};
static const GUID KMS_ID_WINDOWS_SERVER_2012R2 =    {0x8456EFD3, 0x0C04, 0x4089, {0x87, 0x40, 0x5B, 0x72, 0x38, 0x53, 0x5A, 0x65}};
static const GUID KMS_ID_WINDOWS_SERVER_2016 =      {0x6E9FC069, 0x257D, 0x4BC4, {0xB4, 0xA7, 0x75, 0x05, 0x14, 0xD3, 0x27, 0x43}};
static const GUID KMS_ID_WINDOWS_SERVER_2019 =      {0x8449B1FB, 0xF0EA, 0x497A, {0x99, 0xAB, 0x66, 0xCA, 0x96, 0xE9, 0xA0, 0xF5}};
/*
e85af946-2e25-47b7-83e1-bebcebeac611 - Office 2010
e6a6f1bf-9d40-40c3-aa9f-c77ba21578c0 - Office 2013
85b5f61b-320b-4be3-814a-b76b2bfafc82 - Office 2016
617d9eb1-ef36-4f82-86e0-a65ae07b96c6 - Office 2019
212a64dc-43b1-4d3d-a30c-2fc69d2095c6 - Windows Vista
7fde5219-fbfa-484a-82c9-34d1ad53e856 - Windows 7
bbb97b3b-8ca4-4a28-9717-89fabd42c4ac - Windows 8 (Retail)
3c40b358-5948-45af-923b-53d21fcc7e79 - Windows 8 (Volume)
6d646890-3606-461a-86ab-598bb84ace82 - Windows 8.1 (Retail)
cb8fc780-2c05-495a-9710-85afffc904d7 - Windows 8.1 (Volume)
e1c51358-fe3e-4203-a4a2-3b6b20c9734e - Windows 10 (Retail)
58e2134f-8e11-4d17-9cb2-91069c151148 - Windows 10 (Volume)
d27cd636-1962-44e9-8b4f-27b6c23efb85 - Windows 10 (Volume) Unknown
969fe3c0-a3ec-491a-9f25-423605deb365 - Windows 10 (Volume) 2016
11b15659-e603-4cf1-9c1f-f0ec01b81888 - Windows 10 (Volume) 2019
7ba0bf23-d0f5-4072-91d9-d55af5a481b6 - Windows 10 China Government
33e156e4-b76f-4a52-9f91-f641dd95ac48 - Windows Server 2008 A (Web and HPC)
8fe53387-3087-4447-8985-f75132215ac9 - Windows Server 2008 B (Standard and Enterprise)
8a21fdf3-cbc5-44eb-83f3-fe284e6680a7 - Windows Server 2008 C (Datacenter)
0fc6ccaf-ff0e-4fae-9d08-4370785bf7ed - Windows Server 2008 R2 A (Web and HPC)
ca87f5b6-cd46-40c0-b06d-8ecd57a4373f - Windows Server 2008 R2 B (Standard and Enterprise)
b2ca2689-a9a8-42d7-938d-cf8e9f201958 - Windows Server 2008 R2 C (Datacenter)
8665cb71-468c-4aa3-a337-cb9bc9d5eaac - Windows Server 2012
8456efd3-0c04-4089-8740-5b7238535a65 - Windows Server 2012 R2
6e9fc069-257d-4bc4-b4a7-750514d32743 - Windows Server 2016
8449b1fb-f0ea-497a-99ab-66ca96e9a0f5 - Windows Server 2019
*/

struct key_config
{
	const GUID& kmsid;
	ULONG keyconfig_min;
	ULONG keyconfig_max;
} const static k_key_config[] =
{
	{KMS_ID_OFFICE_2010,			PKEYCONFIG_OFFICE2010_CSVLK, PKEYCONFIG_OFFICE2010_CSVLK},
	{KMS_ID_OFFICE_2013,			PKEYCONFIG_OFFICE2013_CSVLK, PKEYCONFIG_OFFICE2013_CSVLK},
	{KMS_ID_OFFICE_2016,			PKEYCONFIG_OFFICE2016_CSVLK, PKEYCONFIG_OFFICE2016_CSVLK},
	{KMS_ID_OFFICE_2019,			PKEYCONFIG_OFFICE2019_CSVLK, PKEYCONFIG_OFFICE2019_CSVLK},
	{KMS_ID_WINDOWS_VISTA,			PKEYCONFIG_SERVER2012_CSVLK, PKEYCONFIG_SERVER2019_CSVLK},
	{KMS_ID_WINDOWS_SERVER_2008A,	PKEYCONFIG_SERVER2012_CSVLK, PKEYCONFIG_SERVER2019_CSVLK},
	{KMS_ID_WINDOWS_SERVER_2008B,	PKEYCONFIG_SERVER2012_CSVLK, PKEYCONFIG_SERVER2019_CSVLK},
	{KMS_ID_WINDOWS_SERVER_2008C,	PKEYCONFIG_SERVER2012_CSVLK, PKEYCONFIG_SERVER2019_CSVLK},
	{KMS_ID_WINDOWS_7,				PKEYCONFIG_SERVER2012_CSVLK, PKEYCONFIG_SERVER2019_CSVLK},
	{KMS_ID_WINDOWS_SERVER_2008R2A,	PKEYCONFIG_SERVER2012_CSVLK, PKEYCONFIG_SERVER2019_CSVLK},
	{KMS_ID_WINDOWS_SERVER_2008R2B,	PKEYCONFIG_SERVER2012_CSVLK, PKEYCONFIG_SERVER2019_CSVLK},
	{KMS_ID_WINDOWS_SERVER_2008R2C,	PKEYCONFIG_SERVER2012_CSVLK, PKEYCONFIG_SERVER2019_CSVLK},
	{KMS_ID_WINDOWS_8_VOLUME,		PKEYCONFIG_SERVER2012_CSVLK, PKEYCONFIG_SERVER2019_CSVLK},
	{KMS_ID_WINDOWS_SERVER_2012,	PKEYCONFIG_SERVER2012_CSVLK, PKEYCONFIG_SERVER2019_CSVLK},
	{KMS_ID_WINDOWS_81_VOLUME,		PKEYCONFIG_SERVER2012R2_CSVLK, PKEYCONFIG_SERVER2019_CSVLK},
	{KMS_ID_WINDOWS_SERVER_2012R2,	PKEYCONFIG_SERVER2012R2_CSVLK, PKEYCONFIG_SERVER2019_CSVLK},
	{KMS_ID_WINDOWS_10_VOLUME,		PKEYCONFIG_SERVER2016_CSVLK, PKEYCONFIG_SERVER2019_CSVLK},
	{KMS_ID_WINDOWS_10_UNKNOWN,		PKEYCONFIG_SERVER2016_CSVLK, PKEYCONFIG_SERVER2019_CSVLK},
	{KMS_ID_WINDOWS_10_LTSB_2016,	PKEYCONFIG_SERVER2016_CSVLK, PKEYCONFIG_SERVER2019_CSVLK},
	{KMS_ID_WINDOWS_SERVER_2016,	PKEYCONFIG_SERVER2016_CSVLK, PKEYCONFIG_SERVER2019_CSVLK},
	{KMS_ID_WINDOWS_10_LTSC_2019,	PKEYCONFIG_SERVER2019_CSVLK, PKEYCONFIG_SERVER2019_CSVLK},
	{KMS_ID_WINDOWS_SERVER_2019,	PKEYCONFIG_SERVER2019_CSVLK, PKEYCONFIG_SERVER2019_CSVLK},
	{KMS_ID_WINDOWS_8_RETAIL,		PKEYCONFIG_SERVER2019R_CSVLK, PKEYCONFIG_SERVER2019R_CSVLK},
	{KMS_ID_WINDOWS_81_RETAIL,		PKEYCONFIG_SERVER2019R_CSVLK, PKEYCONFIG_SERVER2019R_CSVLK},
	{KMS_ID_WINDOWS_10_RETAIL,		PKEYCONFIG_SERVER2019R_CSVLK, PKEYCONFIG_SERVER2019R_CSVLK},
	{KMS_ID_WINDOWS_10_GOV,			PKEYCONFIG_WIN10GOV_CSVLK, PKEYCONFIG_WIN10GOV_CSVLK},
};

// Generate a random KMS ePID
void generate_random_kmspid(WCHAR* kmspid, const KMSBaseRequest* request)
{
	struct random_generator
	{
		ULONG seed = 0;
		using result_type = ULONG;
		static ULONG max() { return std::numeric_limits<ULONG>::max(); }
		static ULONG min() { return std::numeric_limits<ULONG>::min(); }
		ULONG operator()() { return RtlRandomEx(&seed); }
	};

	random_generator random_gen;
	{
		LARGE_INTEGER li;
		NtQueryPerformanceCounter(&li, nullptr);
		random_gen.seed = li.u.LowPart;
	}

	const auto config_result = std::find_if(std::begin(k_key_config), std::end(k_key_config),
		[request](const key_config& a)
	{
		return a.kmsid == request->KmsID;
	});

	const auto config_index = config_result != std::end(k_key_config)
		? std::uniform_int_distribution<unsigned>(config_result->keyconfig_min, config_result->keyconfig_max)(random_gen)
		: PKEYCONFIG_DEFAULT;

	const auto config = &k_pkeyconfig[config_index];

	const auto host = &k_host_os[std::uniform_int_distribution<size_t>(config->os_min, config->os_max)(random_gen)];

	// Random KeyID
	const auto random_id = std::uniform_int_distribution<ULONG>(config->range_min, config->range_max)(random_gen);

	// Part 5: License Channel (00=Retail, 01=Retail, 02=OEM, 03=Volume (GVLK, MAK)) - always 03
	const auto license_channel = 3u;

	// Part 6: Language - use system default language
	const auto language_code = LAZY_FN("kernel32.dll", GetSystemDefaultLCID)();
	
	// Minimum value of activation date
	const auto min_date = host->csvlk_time;

	LARGE_INTEGER system_time;
	NtQuerySystemTime(&system_time);

	// Maximum possible value of activation date
	const auto max_date = system_time.QuadPart - 864000000000; // limit latest activation date to yesterday

	// Random date between min_date and max_date
	LARGE_INTEGER generated_date;
	generated_date.QuadPart = std::uniform_int_distribution<LONG64>(min_date, max_date)(random_gen);

	TIME_FIELDS tf;
	RtlTimeToTimeFields(&generated_date, &tf);
	LARGE_INTEGER generated_date_year;
	tf.Month = 1;
	tf.Day = 1;
	RtlTimeFieldsToTime(&tf, &generated_date_year);

	const auto year = (int)tf.Year;
	const auto yday = (int)(1 + (generated_date.QuadPart - generated_date_year.QuadPart) / (10ll * 1000 * 1000 * 60 * 60 * 24));
	
	swprintf_s(kmspid, PID_BUFFER_LEN, L"%05u-%05u-%03u-%06u-%02u-%u-%u.0000-%03d%04d",
		host->type, config->group_id, random_id / 1000000, random_id % 1000000, license_channel,
		language_code, host->build, yday, year
	);
}

// Get user specified PID or Generate random PID according to request and settings
void get_kmspid(PWSTR kmspid, const KMSBaseRequest* request)
{
	if(!NT_SUCCESS(settings_get_kmspid_for_kmspid(kmspid, request->KmsID)))
		generate_random_kmspid(kmspid, request);
}
