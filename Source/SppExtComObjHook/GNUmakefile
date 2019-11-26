CXX      ?= g++
RM       ?= rm -f
MKDIR    ?= mkdir -p
OPT       = -pipe -Os -s -Wall -Wno-unused -Wno-unused-local-typedefs
CXXFLAGS  = $(OPT) -std=c++17 -municode -mtune=core2 -mno-stack-arg-probe -fvisibility=hidden -fno-ident -fno-stack-check -fno-stack-protector -fno-asynchronous-unwind-tables -fno-exceptions -fno-align-functions -fno-align-labels -fno-align-loops -fno-align-jumps -fmerge-all-constants -fdata-sections -ffunction-sections -funsigned-char
LDFLAGS   = -nostartfiles -lntdll -lgcc -nostdlib -Wl,--gc-sections,--build-id=none,--exclude-all-symbols,--enable-stdcall-fixup,--dynamicbase,--nxcompat,--major-image-version,0,--minor-image-version,0,--major-os-version,6,--minor-os-version,00,--major-subsystem-version,6,--minor-subsystem-version,00,--subsystem,native
PCHDIR    = pch.hpp.gch
PCH32     = $(PCHDIR)/a86.gch
PCH64     = $(PCHDIR)/a64.gch
OBJECTS32 = $(patsubst %.cpp,$(PCHDIR)/%.obj,$(wildcard *.cpp))
OBJECTS64 = $(patsubst %.cpp,$(PCHDIR)/%.o,$(wildcard *.cpp))
ifneq (,$(findstring WINDOWS,$(PATH)))
RM        = rmdir /s /q
MKDIR     = mkdir
endif

.PHONY: GNUmakefile all clean directories

all: Win32/SppExtComObjHook.dll x64/SppExtComObjHook.dll

Win32/SppExtComObjHook.dll: $(OBJECTS32) | directories
	$(CXX) -m32 -shared $^ -Wl,--no-whole-archive,-e_DllMain@12 $(CXXFLAGS) $(LDFLAGS),-T,i386.ldscript,--large-address-aware -o $@

$(PCH32): pch.hpp | directories
	$(CXX) -m32 $(CXXFLAGS) -c $< -o $@

$(PCHDIR)/%.obj: %.cpp | directories $(PCH32)
	$(CXX) -m32 $(CXXFLAGS) -c $< -o $@

x64/SppExtComObjHook.dll: $(OBJECTS64) | directories
	$(CXX) -m64 -shared $^ -Wl,--no-whole-archive,-eDllMain $(CXXFLAGS) $(LDFLAGS),-T,x86_64.ldscript -o $@

$(PCH64): pch.hpp | directories
	$(CXX) -m64 $(CXXFLAGS) -c $< -o $@

$(PCHDIR)/%.o: %.cpp | directories $(PCH64)
	$(CXX) -m64 $(CXXFLAGS) -c $< -o $@

directories: $(PCHDIR) Win32 x64

$(PCHDIR):
	$(MKDIR) $@

Win32:
	$(MKDIR) $@

x64:
	$(MKDIR) $@

clean:
	$(RM) $(PCHDIR) Win32 x64
