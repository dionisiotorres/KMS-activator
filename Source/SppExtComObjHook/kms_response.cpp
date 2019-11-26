#include "pch.hpp"

#include "crypto.hpp"
#include "kms.h"
#include "settings.hpp"

// Unknown 8-bytes data (seems not to affect activation)
// const BYTE Unknown8[8] = { 0x3A, 0x1C, 0x04, 0x96, 0x00, 0xB6, 0x00, 0x76 };

// Pack KMSBaseResponse into Byte Packet
static int PackBaseResponse(BYTE *response, const KMSBaseResponse *BaseResponse)
{
	auto next = response;

	auto CopySize = sizeof(BaseResponse->Version)
		+ sizeof(BaseResponse->PIDSize)
		+ BaseResponse->PIDSize;

	memcpy(next, &BaseResponse->Version, CopySize);
	next += CopySize;

	CopySize = sizeof(BaseResponse->CMID)
		+ sizeof(BaseResponse->TimeStamp)
		+ sizeof(BaseResponse->CurrentCount)
		+ sizeof(BaseResponse->VLActivationInterval)
		+ sizeof(BaseResponse->VLRenewalInterval);

	memcpy(next, &BaseResponse->CMID, CopySize);
	next += CopySize;

	return (int)(next - response);
}

// Create Base Response from Base Request
static void CreateBaseResponse(const KMSBaseRequest* BaseRequest, KMSBaseResponse* BaseResponse)
{
	// Version
	BaseResponse->Version = BaseRequest->Version;

	// Set extended PID and PID size
	get_kmspid(BaseResponse->PIDData, BaseRequest);
	BaseResponse->PIDSize = ((DWORD)wcslen(BaseResponse->PIDData) + 1) << 1;

	// CMID
	BaseResponse->CMID = BaseRequest->CMID;

	// TimeStamp
	BaseResponse->TimeStamp = BaseRequest->TimeStamp;

	// Machine Count
	BaseResponse->CurrentCount = BaseRequest->RequiredCount << 1;

	// Intervals
	BaseResponse->VLActivationInterval = g_settings.activation_interval;
	BaseResponse->VLRenewalInterval = g_settings.renewal_interval;

	TIME_FIELDS tf;
	LARGE_INTEGER filetime;
	filetime.QuadPart = ULONG64(BaseRequest->TimeStamp.dwHighDateTime) << 32 | BaseRequest->TimeStamp.dwLowDateTime;
	RtlTimeToTimeFields(&filetime, &tf);

	DebugPrint("[KMS] Protocol Version   : %i.%i\n", BaseRequest->MajorVer, BaseRequest->MinorVer);
	DebugPrint("[KMS] License Status     : %u\n", BaseRequest->LicenseStatus);
	DebugPrint("[KMS] Remaining Period   : %u minutes\n", BaseRequest->RemainingGrace);
	DebugPrint("[KMS] VM / VHD Boot      : %i\n", BaseRequest->VMInfo);
	DebugPrint("[KMS] Application ID     : {" GUID_FORMAT "}\n", GUID_ARG(BaseRequest->AppID));
	DebugPrint("[KMS] Activation ID      : {" GUID_FORMAT "}\n", GUID_ARG(BaseRequest->SkuID));
	DebugPrint("[KMS] KMS Counted ID     : {" GUID_FORMAT "}\n", GUID_ARG(BaseRequest->KmsID));
	DebugPrint("[KMS] Client Machine ID  : {" GUID_FORMAT "}\n", GUID_ARG(BaseRequest->CMID));
	DebugPrint("[KMS] Previous CMID      : {" GUID_FORMAT "}\n", GUID_ARG(BaseRequest->CMID_prev));
	DebugPrint("[KMS] Workstation Name   : %ls\n", BaseRequest->MachineName);
	DebugPrint("[KMS] TimeStamp (UTC)    : %04d/%02d/%02d %02d:%02d:%02d\n", tf.Year, tf.Month, tf.Day, tf.Hour, tf.Minute, tf.Second);
	DebugPrint("[KMS] Request N Count    : %u minimum clients\n", BaseRequest->RequiredCount);
	DebugPrint("[KMS] Response N Count   : %u activated clients\n", BaseResponse->CurrentCount);
	DebugPrint("[KMS] Activation Interval: %u minutes\n", BaseResponse->VLActivationInterval);
	DebugPrint("[KMS] Renewal Interval   : %u minutes\n", BaseResponse->VLRenewalInterval);
	DebugPrint("[KMS] KMS Host ePID      : %ls\n", BaseResponse->PIDData);
}

// Create KMS Response V4
static BYTE* CreateResponseV4(int requestSize, const BYTE* request, int *responseSize, KMSBaseRequest *gotRequest, KMSBaseResponse *sentResponse)
{
	UNREFERENCED_PARAMETER(requestSize);

	// Get KMS Base Request Object
	const auto& BaseRequest = ((const KMSV4Request*)request)->BaseRequest;

	// Prepare a Workspace Buffer
	BYTE buffer[MAX_RESPONSE_SIZE];

	// Create BaseResponse
	KMSBaseResponse BaseResponse;
	CreateBaseResponse(&BaseRequest, &BaseResponse);

	// Pack BaseResponse
	const auto size = PackBaseResponse(buffer, &BaseResponse);

	// Generate Hash Signature
	GetV4Cmac(size, buffer, buffer + size);

	// Put Response Size
	*responseSize = size + 16;

	// Put Response Data
	auto response = (BYTE*)midl_user_allocate(*responseSize);
	memcpy(response, buffer, *responseSize);

	// Return the Got Request and the Response to be sent
	memcpy(gotRequest, &BaseRequest, sizeof(KMSBaseRequest));
	memcpy(sentResponse, &BaseResponse, sizeof(KMSBaseResponse));

	// Return Created Response
	return response;
}

// Create KMS Response V5 and V6
static BYTE* CreateResponseV6(int requestSize, BYTE *request, int *responseSize, KMSBaseRequest *gotRequest, KMSBaseResponse *sentResponse)
{
	// Get KMS V5/V6 Request Object
	KMSV6Request *Request = (KMSV6Request *)request;

	// Prepare a Workspace Buffer
	BYTE buffer[MAX_RESPONSE_SIZE];
	BYTE *next = buffer;

	// Version
	*(DWORD *)next = Request->Version;
	next += sizeof(Request->Version);

	// Response IV (same as Request in V5, random in V6)
	BYTE *ResponseIV = next, ResponseIVData[16];

	if (Request->Version == KMS_VERSION_5)
	{
		// Use same IV as request
		memcpy(next, Request->IV, sizeof(Request->IV));
		next += sizeof(Request->IV);
	}
	else
	{
		// Get Random IV
		GetRandomBytes(ResponseIVData, sizeof(ResponseIVData));

		// First we put decrypted Response IV for HMAC-SHA256
		DWORD DecryptSize = sizeof(ResponseIVData);
		memcpy(next, ResponseIVData, sizeof(ResponseIVData));
		AesDecryptMessage(Request->Version, nullptr, next, &DecryptSize);
		next += sizeof(ResponseIVData);
	}

	// AES Decryption (Decrypted Salt is also needed)
	DWORD DecryptSize = requestSize - sizeof(Request->Version);
	AesDecryptMessage(Request->Version, nullptr, Request->IV, &DecryptSize);

	// Create BaseResponse
	KMSBaseResponse BaseResponse;
	CreateBaseResponse(&Request->BaseRequest, &BaseResponse);

	// Pack BaseResponse
	BYTE *encryption_start = next;
	next += PackBaseResponse(next, &BaseResponse);

	// Random Key
	GetRandomBytes(next, 16);

	// SHA-256
	GetSha256Hash(next, 16, next + 16);

	// Xor
	XorBuffer(Request->IV, next);

	next += 48; // sizeof(RandomSalt) + sizeof(SHA256)

	if (Request->Version == KMS_VERSION_6)
	{
		// Unknown8
		// memcpy(next, Unknown8, sizeof(Unknown8));
		// next += sizeof(Unknown8);
		*(ULONG64*)next = g_settings.hwid;
		next += sizeof(g_settings.hwid);
		DebugPrint("[KMS Info] KMS Host HWID      : %016I64X\n", g_settings.hwid);

		// Xor2
		memcpy(next, Request->IV, sizeof(Request->IV));
		next += sizeof(Request->IV);

		// HmacSHA256
		DWORD HmacDataLen = (DWORD)(next - ResponseIV);
		BYTE HmacKey[16], HMacSHA256[32];
		GetHmacKey((ULONG64 *)&BaseResponse.TimeStamp, HmacKey);
		GetHmacSha256(HmacKey, HmacDataLen, ResponseIV, HMacSHA256);
		memcpy(next, &HMacSHA256[16], 16);
		next += 16;

		// Put back the plaintext response IV
		memcpy(ResponseIV, ResponseIVData, sizeof(ResponseIVData));
	}

	// Encrypt Response
	DWORD encryptSize = (DWORD)(next - encryption_start);
	AesEncryptMessage(Request->Version, ResponseIV, encryption_start, &encryptSize, MAX_RESPONSE_SIZE - 20);

	// Put Created Response into RPC Buffer
	*responseSize = encryptSize + 20;
	BYTE *response = (BYTE *)midl_user_allocate(*responseSize);
	memcpy(response, buffer, *responseSize);

	// Return the Got Request and the Response to be sent
	memcpy(gotRequest, &Request->BaseRequest, sizeof(KMSBaseRequest));
	memcpy(sentResponse, &BaseResponse, sizeof(KMSBaseResponse));

	// Return Created Response
	return response;
}

// Create KMS Response from Got Request
static BYTE* CreateResponse(int requestSize, BYTE *request, int *responseSize, KMSBaseRequest *gotRequest, KMSBaseResponse *sentResponse)
{
	// KMS Protocol Version
	switch (((DWORD *)request)[0])
	{
	case KMS_VERSION_4:
		return CreateResponseV4(requestSize, request, responseSize, gotRequest, sentResponse);

	case KMS_VERSION_5:
	case KMS_VERSION_6:
		return CreateResponseV6(requestSize, request, responseSize, gotRequest, sentResponse);

	default:
		return nullptr;
	}
}

// -----------------------------------------------------------------------------------
// RPC Function to Build and Send a KMS Server Response
// -----------------------------------------------------------------------------------
RPC_STATUS make_response(INT requestSize, PBYTE request, PINT responseSize, PBYTE* response)
{
	// Verify Request Size
	if (requestSize < 92)
	{
		*responseSize = 0;
		*response = nullptr;
		return RPC_S_INVALID_ARG;
	}

	// Hold Request and Response for Logging
	KMSBaseRequest gotRequest;
	KMSBaseResponse sentResponse;

	// Send Response and Response Size
	*response = CreateResponse(requestSize, request, responseSize, &gotRequest, &sentResponse);

	return RPC_S_OK;
}