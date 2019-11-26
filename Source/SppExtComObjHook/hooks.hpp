#pragma once

RPC_STATUS RPC_ENTRY RpcStringBindingComposeW_Hook(PWSTR ObjUuid, PWSTR ProtSeq, PWSTR NetworkAddr, PWSTR EndPoint, PWSTR Options, PWSTR* StringBinding);
RPC_STATUS RPC_ENTRY RpcBindingFromStringBindingW_Hook(PWSTR StringBinding, RPC_BINDING_HANDLE* Binding);
RPC_STATUS RPC_ENTRY RpcStringFreeW_Hook(PWSTR* String);
RPC_STATUS RPC_ENTRY RpcBindingFree_Hook(RPC_BINDING_HANDLE* Binding);
RPC_STATUS RPC_ENTRY RpcAsyncInitializeHandle_Hook(PRPC_ASYNC_STATE pAsync, unsigned Size);
RPC_STATUS RPC_ENTRY RpcAsyncCompleteCall_Hook(PRPC_ASYNC_STATE pAsync, PVOID Reply);
CLIENT_CALL_RETURN RPC_VAR_ENTRY NdrAsyncClientCall_Hook(PMIDL_STUB_DESC pStubDescriptor, PFORMAT_STRING pFormat, ...);
CLIENT_CALL_RETURN RPC_VAR_ENTRY NdrClientCall2_Hook(PMIDL_STUB_DESC pStubDescriptor, PFORMAT_STRING pFormat, ...);
#ifdef _WIN64
CLIENT_CALL_RETURN RPC_VAR_ENTRY Ndr64AsyncClientCall_Hook(MIDL_STUBLESS_PROXY_INFO* pProxyInfo, unsigned long nProcNum, void* pReturnValue, ...);
CLIENT_CALL_RETURN RPC_VAR_ENTRY NdrClientCall3_Hook(MIDL_STUBLESS_PROXY_INFO* pProxyInfo, unsigned long nProcNum, void* pReturnValue, ...);
#endif