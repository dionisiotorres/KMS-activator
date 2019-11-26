#include "pch.hpp"

#ifdef __MINGW64_VERSION_MAJOR
#define sizet SIZE_T
#else
#define sizet size_t
#endif

// Memory allocation function for RPC.
void __RPC_FAR * __RPC_USER midl_user_allocate(sizet len)
{
	return RtlAllocateHeap(RtlGetProcessHeap(), 0, len);
}

// Memory deallocation function for RPC.
void __RPC_USER midl_user_free(void __RPC_FAR *ptr)
{
	RtlFreeHeap(RtlGetProcessHeap(), 0, ptr);
}