#ifndef __pch_h
#define __pch_h

#ifndef _NO_CRT_STDIO_INLINE
#define _NO_CRT_STDIO_INLINE 1
#endif

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <windows.h>
#ifdef __MINGW64_VERSION_MAJOR
#include "winternl.h"
#else
#include <winternl.h>
#endif
#include <winnt.h>
#include <Rpc.h>
#include <WinCrypt.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <type_traits>
#include <algorithm>
#include <random>

#include "nt_defs.hpp"

#ifdef _DEBUG
	#ifdef _MSC_VER
	#define DebugPrint(str, ...) DbgPrintEx(-1, 0, "[SppExtComObjHookAvrf] " str, __VA_ARGS__)
	#else
	#define DebugPrint(str, ...) DbgPrintEx(-1, 0, "[SppExtComObjHookAvrf] " str, ##__VA_ARGS__)
	#endif
#else
	#define DebugPrint(str, ...)
#endif

#endif // __pch_h
