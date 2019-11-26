#include "pch.hpp"

#include "crypto.hpp"
#include "kms.h"
#include "avrf.hpp"
#include "settings.hpp"

// Fake KMS host IP address
#define LOCALHOST_IP L"127.0.0.1"
#define PROTO_SEQ_TCP L"ncacn_ip_tcp"

static struct rpc_connection
{
	BOOL bInitialized;
	WCHAR szStringBinding[128];
	PVOID hRpcBinding;
	PVOID pAsync;
	PVOID pTeb;
	PBYTE pbResponseData;
} s_rpc_connection;

RPC_STATUS RPC_ENTRY RpcStringBindingComposeW_Hook(PWSTR ObjUuid, PWSTR ProtSeq, PWSTR NetworkAddr, PWSTR EndPoint, PWSTR Options, PWSTR* StringBinding)
{
	DebugPrint("RpcStringBindingComposeW called [ProtSeq: %s, NetWorkAddr: %s, EndPoint: %s].\n", ProtSeq, NetworkAddr, EndPoint);
	
	// Check destination address and hook
	if (ProtSeq != nullptr && 0 == _wcsicmp(ProtSeq, PROTO_SEQ_TCP))
	{
		settings_update();

		if (!s_rpc_connection.bInitialized)
		{
			if (g_settings.enabled)
			{
				DebugPrint("Connection Detected... Emulating Server...\n");
				
				s_rpc_connection.bInitialized = TRUE;
				s_rpc_connection.pTeb = NtCurrentTeb();
				swprintf_s(s_rpc_connection.szStringBinding, _countof(s_rpc_connection.szStringBinding), L"%s:%s[%s]", ProtSeq, NetworkAddr, EndPoint);
				*StringBinding = s_rpc_connection.szStringBinding;

				return RPC_S_OK;
			}
			else
			{
				// Redirect rpcrt4 call to localhost
				DebugPrint("Replaced NetworkAddr from %s to %s\n", NetworkAddr, LOCALHOST_IP);

				s_rpc_connection.bInitialized = FALSE;

				NetworkAddr = const_cast<wchar_t*>(LOCALHOST_IP);
			}
		}
	}

	// Call original function
	return GET_ORIGINAL_FUNC(RpcStringBindingComposeW)(ObjUuid, ProtSeq, NetworkAddr, EndPoint, Options, StringBinding);
}

RPC_STATUS RPC_ENTRY RpcBindingFromStringBindingW_Hook(PWSTR StringBinding, RPC_BINDING_HANDLE* Binding)
{
	if (StringBinding != nullptr && Binding != nullptr)
	{
		if (s_rpc_connection.bInitialized && s_rpc_connection.pAsync == nullptr)
		{
			if (s_rpc_connection.pTeb == NtCurrentTeb() && 0 == _wcsicmp(StringBinding, s_rpc_connection.szStringBinding))
			{
				DebugPrint("Emulating Server... Return fake binding...\n");

				GetRandomBytes((BYTE*)&s_rpc_connection.hRpcBinding, sizeof(s_rpc_connection.hRpcBinding));
				*Binding = s_rpc_connection.hRpcBinding;

				DebugPrint("RpcBindingFromStringBindingW called [StringBinding: %s, Binding: 0x%p @ 0x%p].\n", StringBinding, *Binding, Binding);

				return RPC_S_OK;
			}
		}
	}

	const auto ret = GET_ORIGINAL_FUNC(RpcBindingFromStringBindingW)(StringBinding, Binding);

	DebugPrint("RpcBindingFromStringBindingW called [StringBinding: %s, Binding: 0x%p @ 0x%p].\n", StringBinding, *Binding, Binding);

	return ret;
}

RPC_STATUS RPC_ENTRY RpcStringFreeW_Hook(PWSTR* String)
{
	if (s_rpc_connection.bInitialized && String != nullptr)
	{
		if (s_rpc_connection.pTeb == NtCurrentTeb() && 0 == _wcsicmp(*String, s_rpc_connection.szStringBinding))
		{
			DebugPrint("Free StringBinding...\n");

			memset(s_rpc_connection.szStringBinding, 0, sizeof(s_rpc_connection.szStringBinding));
			*String = nullptr;

			return RPC_S_OK;
		}
	}

	return GET_ORIGINAL_FUNC(RpcStringFreeW)(String);
}

RPC_STATUS RPC_ENTRY RpcBindingFree_Hook(RPC_BINDING_HANDLE* Binding)
{
	if (s_rpc_connection.bInitialized && Binding != nullptr)
	{
		if (*Binding == s_rpc_connection.hRpcBinding && s_rpc_connection.pTeb == NtCurrentTeb())
		{
			DebugPrint("Free Connection...\n");

			s_rpc_connection.bInitialized = FALSE;
			s_rpc_connection.hRpcBinding = nullptr;
			s_rpc_connection.pAsync = nullptr;
			s_rpc_connection.pTeb = nullptr;

			return RPC_S_OK;
		}
	}

	return GET_ORIGINAL_FUNC(RpcBindingFree)(Binding);
}

RPC_STATUS RPC_ENTRY RpcAsyncInitializeHandle_Hook(PRPC_ASYNC_STATE pAsync, unsigned Size)
{
	const auto status = GET_ORIGINAL_FUNC(RpcAsyncInitializeHandle)(pAsync, Size);

	if (status != RPC_S_OK)
		return status;

	if (s_rpc_connection.bInitialized && s_rpc_connection.hRpcBinding != nullptr && s_rpc_connection.pAsync == nullptr)
	{
		if (s_rpc_connection.pTeb == NtCurrentTeb())
		{
			DebugPrint("Emulating Server... Saved Async Handle\n");
			s_rpc_connection.pAsync = pAsync;
		}
	}

	return status;
}

RPC_STATUS RPC_ENTRY RpcAsyncCompleteCall_Hook(PRPC_ASYNC_STATE pAsync, PVOID Reply)
{
	if (pAsync != nullptr && Reply != nullptr)
	{
		if (s_rpc_connection.bInitialized && s_rpc_connection.pAsync != nullptr && s_rpc_connection.hRpcBinding != nullptr)
		{
			if (s_rpc_connection.pTeb == NtCurrentTeb() && pAsync == s_rpc_connection.pAsync)
			{
				DebugPrint("Emulating Server... Return RPC_S_OK...\n");

				return RPC_S_OK;
			}
		}
	}

	return GET_ORIGINAL_FUNC(RpcAsyncCompleteCall)(pAsync, Reply);
}

CLIENT_CALL_RETURN RPC_VAR_ENTRY NdrAsyncClientCall_Hook(PMIDL_STUB_DESC pStubDescriptor, PFORMAT_STRING pFormat, ...)
{
	DebugPrint("NdrAsyncClientCall called\n");

	PRPC_ASYNC_STATE pAsync;
	RPC_BINDING_HANDLE Binding;
	INT requestSize;
	PBYTE requestData;
	PINT responseSize;
	PBYTE* responseData;

#ifdef _WIN64
	va_list ap = nullptr;
	va_start(ap, pFormat);
	pAsync = (PRPC_ASYNC_STATE)va_arg(ap, PVOID);
	Binding = (RPC_BINDING_HANDLE)va_arg(ap, PVOID);
	requestSize = (INT)va_arg(ap, int);
	requestData = (PBYTE)va_arg(ap, PVOID);
	responseSize = (PINT)va_arg(ap, PVOID);
	responseData = (PBYTE*)va_arg(ap, PVOID);
	va_end(ap);
#else
	DWORD* funcVarList = *(DWORD**)(((BYTE*)&pFormat) + sizeof(const unsigned char*));
	pAsync = (PRPC_ASYNC_STATE)(funcVarList[0]);
	Binding = (RPC_BINDING_HANDLE)(funcVarList[1]);
	requestSize = (INT)(funcVarList[2]);
	requestData = (PBYTE)(funcVarList[3]);
	responseSize = (PINT)(funcVarList[4]);
	responseData = (PBYTE*)(funcVarList[5]);
#endif

	DebugPrint("pStubDescriptor = 0x%p, pFormat = 0x%p, pAsync = 0x%p, Binding = 0x%p, requestSize = %d, resuestData = 0x%p, responseSize = 0x%p, responseData = 0x%p\n",
		pStubDescriptor, pFormat, pAsync, Binding, requestSize, requestData, responseSize, responseData);

	if (s_rpc_connection.bInitialized && pStubDescriptor != nullptr && pFormat != nullptr)
	{
		if (s_rpc_connection.hRpcBinding == Binding && s_rpc_connection.pAsync == pAsync)
		{
			if (s_rpc_connection.pTeb == NtCurrentTeb())
			{
				if (pAsync->u.APC.NotificationRoutine != nullptr && pAsync->u.APC.NotificationRoutine != INVALID_HANDLE_VALUE)
				{
					settings_update();

					DebugPrint("Emulating Server... Writing Response!\n");

					const auto succeeded = make_response(requestSize, requestData, responseSize, responseData) == RPC_S_OK;

					DebugPrint("Emulating Server... Activation %s!\n", succeeded ? "Success" : "Failure");

					NtSetEvent(HANDLE(pAsync->u.APC.NotificationRoutine), nullptr);

					return {};
				}
			}
		}
	}

	return GET_ORIGINAL_FUNC(NdrAsyncClientCall)
#ifdef _WIN64
		(pStubDescriptor, pFormat, pAsync, Binding, requestSize, requestData, responseSize, responseData);
#else
		(pStubDescriptor, pFormat, funcVarList);
#endif
}

CLIENT_CALL_RETURN RPC_VAR_ENTRY NdrClientCall2_Hook(PMIDL_STUB_DESC pStubDescriptor, PFORMAT_STRING pFormat, ...)
{
	DebugPrint("NdrClientCall2 called\n");

	INT requestSize;
	PBYTE requestData;
	PINT responseSize;
	PBYTE* responseData;
	RPC_BINDING_HANDLE Binding;

#ifdef _WIN64
	va_list ap = nullptr;
	va_start(ap, pFormat);
	Binding = (RPC_BINDING_HANDLE)va_arg(ap, PVOID);
	requestSize = (INT)va_arg(ap, int);
	requestData = (PBYTE)va_arg(ap, PVOID);
	responseSize = (PINT)va_arg(ap, PVOID);
	responseData = (PBYTE*)va_arg(ap, PVOID);
	va_end(ap);
#else
	DWORD* funcVarList = *(DWORD**)(((BYTE*)&pFormat) + sizeof(const unsigned char*));
	Binding = (RPC_BINDING_HANDLE)(funcVarList[0]);
	requestSize = (INT)(funcVarList[1]);
	requestData = (PBYTE)(funcVarList[2]);
	responseSize = (PINT)(funcVarList[3]);
	responseData = (PBYTE*)(funcVarList[4]);
#endif

	DebugPrint("pStubDescriptor = 0x%p, pFormat = 0x%p, Binding = 0x%p, requestSize = %d, resuestData = 0x%p, responseSize = 0x%p, responseData = 0x%p\n",
		pStubDescriptor, pFormat, Binding, requestSize, requestData, responseSize, responseData);

	if (s_rpc_connection.bInitialized && pStubDescriptor != nullptr && pFormat != nullptr)
	{
		if (s_rpc_connection.hRpcBinding == Binding)
		{
			if (s_rpc_connection.pTeb == NtCurrentTeb())
			{
				settings_update();

				DebugPrint("Emulating Server... Writing Response!\n");

				const auto succeeded = make_response(requestSize, requestData, responseSize, responseData) == RPC_S_OK;

				DebugPrint("Emulating Server... Activation %s!\n", succeeded ? "Success" : "Failure");

				return {};
			}
		}
	}

	return GET_ORIGINAL_FUNC(NdrClientCall2)
#ifdef _WIN64
		(pStubDescriptor, pFormat, Binding, requestSize, requestData, responseSize, responseData);
#else
		(pStubDescriptor, pFormat, funcVarList);
#endif
}

#ifdef _WIN64
CLIENT_CALL_RETURN RPC_VAR_ENTRY Ndr64AsyncClientCall_Hook(MIDL_STUBLESS_PROXY_INFO* pProxyInfo, unsigned long nProcNum, void* pReturnValue, ...)
{
	DebugPrint("Ndr64AsyncClientCall called\n");

	va_list ap = nullptr;
	va_start(ap, pReturnValue);
	const auto pAsync = (PRPC_ASYNC_STATE)va_arg(ap, PVOID);
	const auto Binding = (RPC_BINDING_HANDLE)va_arg(ap, PVOID);
	const auto requestSize = va_arg(ap, INT);
	const auto requestData = va_arg(ap, PBYTE);
	const auto responseSize = va_arg(ap, PINT);
	const auto responseData = va_arg(ap, PBYTE*);
	va_end(ap);

	DebugPrint("pProxyInfo = 0x%p, nProcNum = %u, pReturnValue = 0x%p, pAsync = 0x%p, Binding = 0x%p, requestSize = %d, resuestData = 0x%p, responseSize = 0x%p, responseData = 0x%p\n",
		pProxyInfo, nProcNum, pReturnValue, pAsync, Binding, requestSize, requestData, responseSize, responseData);

	if (s_rpc_connection.bInitialized && pProxyInfo != nullptr)
	{
		if (s_rpc_connection.hRpcBinding == Binding && s_rpc_connection.pAsync == pAsync)
		{
			if (s_rpc_connection.pTeb == NtCurrentTeb())
			{
				if (pAsync->u.APC.NotificationRoutine != nullptr && pAsync->u.APC.NotificationRoutine != INVALID_HANDLE_VALUE)
				{
					settings_update();

					DebugPrint("Emulating Server... Writing Response!\n");

					const auto succeeded = make_response(requestSize, requestData, responseSize, responseData) == RPC_S_OK;

					DebugPrint("Emulating Server... Activation %s!\n", succeeded ? "Success" : "Failure");

					NtSetEvent(HANDLE(pAsync->u.APC.NotificationRoutine), nullptr);

					return {};
				}
			}
		}
	}

	return CALL_ORIGINAL_FUNC(Ndr64AsyncClientCall, pProxyInfo, nProcNum, pReturnValue, pAsync, Binding, requestSize, requestData, responseSize, responseData);
}

CLIENT_CALL_RETURN RPC_VAR_ENTRY NdrClientCall3_Hook(MIDL_STUBLESS_PROXY_INFO* pProxyInfo, unsigned long nProcNum, void* pReturnValue, ...)
{
	DebugPrint("NdrClientCall3 called\n");

	va_list ap = nullptr;
	va_start(ap, pReturnValue);
	const auto Binding = (RPC_BINDING_HANDLE)va_arg(ap, PVOID);
	const auto requestSize = va_arg(ap, INT);
	const auto requestData = va_arg(ap, PBYTE);
	const auto responseSize = va_arg(ap, PINT);
	const auto responseData = va_arg(ap, PBYTE*);
	va_end(ap);

	DebugPrint("pProxyInfo = 0x%p, nProcNum = %u, pReturnValue = 0x%p, Binding = 0x%p, requestSize = %d, resuestData = 0x%p, responseSize = 0x%p, responseData = 0x%p\n",
		pProxyInfo, nProcNum, pReturnValue, Binding, requestSize, requestData, responseSize, responseData);

	if (s_rpc_connection.bInitialized && pProxyInfo != nullptr)
	{
		if (s_rpc_connection.hRpcBinding == Binding)
		{
			if (s_rpc_connection.pTeb == NtCurrentTeb())
			{
				settings_update();

				DebugPrint("Emulating Server... Writing Response!\n");

				const auto succeeded = make_response(requestSize, requestData, responseSize, responseData) == RPC_S_OK;

				DebugPrint("Emulating Server... Activation %s!\n", succeeded ? "Success" : "Failure");

				return {};
			}
		}
	}

	return CALL_ORIGINAL_FUNC(NdrClientCall3, pProxyInfo, nProcNum, pReturnValue, Binding, requestSize, requestData, responseSize, responseData);
}
#endif
