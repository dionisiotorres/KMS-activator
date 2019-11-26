#pragma once

void* get_original_from_hook_address(void* hook_address);

template <typename T>
T* get_original_from_hook_address_wrapper(T* fn)
{
	return (T*)get_original_from_hook_address((void*)fn);
}

#define GET_ORIGINAL_FUNC(name) (*get_original_from_hook_address_wrapper(&name ## _Hook))
#define CALL_ORIGINAL_FUNC(name, ...) (GET_ORIGINAL_FUNC(name)(__VA_ARGS__))

const wchar_t* get_process_name();

void* get_function_address(const wchar_t* dll, const char* fn);

template <uint64_t hash>
FORCEINLINE void*& get_cached_function_pointer()
{
	static void* x;
	return x;
}

constexpr uint64_t hash_64_fnv1a_const(const char* const str, const uint64_t value = 0xcbf29ce484222325) noexcept {
	return (str[0] == '\0') ? value : hash_64_fnv1a_const(&str[1], (value ^ uint64_t(str[0])) * 0x100000001b3);
}

#define LAZY_FN(dll, fn) (*(decltype(&fn))(get_cached_function_pointer<hash_64_fnv1a_const(dll #fn)>() \
	? get_cached_function_pointer<hash_64_fnv1a_const(dll #fn)>() \
	: (get_cached_function_pointer<hash_64_fnv1a_const(dll #fn)>() = get_function_address(L##dll, #fn))))
