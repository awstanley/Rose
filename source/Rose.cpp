// Copyright (c) 2016 A.W. Stanley.
// All rights reserved.
//
// See the http://github.com/awstanley/Rose LICENCE file.

// Header (defines Detour, contains includes).
#include <Rose.hpp>

// memset, etc.
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>

// Capstone (the backend/disassembler)
#include <capstone/capstone.h>

// Force alignment of memory to barrier.
// You probably *really* don't need this.
// #define ROSE_ALIGN_MEMORY 1

// My experience indicates that x86 and x86_64 CPUs don't need flushing;
// this is added so people who similarly experience it can disable it
// in the source, saving some cycles on potentially needless functions.
#define __ROSE_FLUSH__ 1

// Platform dependent code
#if defined _WIN32 || defined _WIN64
#include <Windows.h>
#define PROT_UNPROTECT PROT_READ | PROT_WRITE | PROT_EXEC
#define PROT_REPROTECT PROT_READ | PROT_EXEC
#define UNPROTECT(addr, size) (VirtualProtect((LPVOID)(addr), (SIZE_T)(size), PAGE_EXECUTE_READWRITE, &dwProt) == TRUE)
#define REPROTECT(addr, size) (VirtualProtect((LPVOID)(addr), (SIZE_T)(size), dwProt, &dwProt) == TRUE)
#include <malloc.h>
#if ROSE_ALIGN_MEMORY
#define ROSE_ALLOC(size) _aligned_malloc(size, 16)
#else
#define ROSE_ALLOC(size) malloc(size)
#endif 
#else
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#if ROSE_ALIGN_MEMORY
#define ROSE_ALLOC(size) aligned_alloc(16, alignment);
#else
#define ROSE_ALLOC(size) malloc(size)
#endif 
#define PROT_UNPROTECT PROT_READ | PROT_WRITE | PROT_EXEC
#define PROT_REPROTECT PROT_READ | PROT_EXEC
#define UNPROTECT(addr, size) SetProtection(addr, size, PROT_UNPROTECT)
#define REPROTECT(addr, size) SetProtection(addr, size, PROT_REPROTECT)
#endif

// Check if the instruction is a return type.
#define INSTRUCTION_RETURNS(i) (i == X86_INS_RET || i == X86_INS_RETF || i == X86_INS_RETFQ)

// Validates a pointer is in a range
#define IN_RANGE(start, ptr, end) (ptr >=start && ptr <= end)

namespace Rose
{
	// For now only x86/x86_64, so assume this.
	const cs_arch CapstoneArchitecture = CS_ARCH_X86;
#if ROSE_DETOURS_AMD64
	const cs_mode CapstoneMode = (cs_mode)(CS_MODE_64 + CS_MODE_LITTLE_ENDIAN);
#elif ROSE_DETOURS_X86
	const cs_mode CapstoneMode = (cs_mode)(CS_MODE_32 + CS_MODE_LITTLE_ENDIAN);
#endif

	/**
	 * @brief The number of bytes occupied by a relative jump.
	 *
	 * The breakdown is 0xE9 + 4 (rel32)
	 */
	static const size_t RelativeJumpSize = 5;

	/**
	 * @brief The number of bytes occupied by an absolute jump.
	 *
	 * The breakdown is 0xFF 0x25 + 4 (int32_t) + 4-8 (uintptr_t)
	 */
#if ROSE_DETOURS_AMD64
	static const size_t AbsoluteJumpSize = 14;
#elif ROSE_DETOURS_X86
	static const size_t AbsoluteJumpSize = 10;
#endif

	// Forwards
	bool SetProtection(void* address, size_t len, int prot);

	// Spin until some sort of return opcode is hit.  Once it's hit
	// return the information (as requested).
	//
	// This is an internal function, don't expect API stability.
	void GetDisassemblyCounts(
		size_t &instructions, size_t &bytes,
		csh &handle, uint8_t *target,
		size_t &preJumpInstructions,
		size_t &preJumpBytes)
	{
		// Reset the variables
		bytes = 0;
		instructions = 0;
		preJumpBytes = 0;
		preJumpInstructions = 0;

		cs_insn *insns;
		bool found = false;

		size_t count = 0;
		uint8_t *pos = target;

#if defined __ROSE_LOUD__
		printf("Pre-scanning function:\n");
#endif//__ROSE_LOUD__

		while (!found)
		{
			count = cs_disasm(handle, pos,
				4096, (uint64_t)pos, 0, &insns);
			for (size_t i = 0; i < count; i++)
			{
				if (bytes <= AbsoluteJumpSize)
				{
					preJumpInstructions++;
					preJumpBytes += insns[i].size;
				}

#if defined __ROSE_LOUD__
				printf("\t[% 4i] %s %s\n",
					i,
					insns[i].mnemonic,
					insns[i].op_str);
#endif//__ROSE_LOUD__

				instructions++;
				bytes += insns[i].size;
				if (INSTRUCTION_RETURNS(insns[i].id))
				{
					found = true;
					break;
				}
			}
			if (!found)
			{
				pos += 4096;
			}
			cs_free(insns, count);
		}
	}

	/** 
	 * @brief A very simple function to determine the jump type.
	 * @param src Pointer to the source of the jump.
	 * @param dst Pointer to the destination of the jump.
	 * @return true if absolute; false if relative.
	 *
	 * The check uses an int64 to determine if the jump exceeds rel32 bounds.
	 */ 
	bool ShouldJumpBeAbsolute(uint8_t *src, uint8_t *dst)
	{
	    int64_t jmp = (int64_t)src - (int64_t)dst;
	    if(jmp < INT_MIN || jmp > INT_MAX)
	    {
	    	return true;
	    }
	    return false;
	}

	/**
	 * @brief Writes an absolute jump to a point in memory.
	 * @param src Source of the jump.
	 * @param dst Destination of the jump.
	 *
	 * Can/should be extended to handle relative writes.
	 */ 
	void WriteJump(uint8_t *src, uint8_t* dst)
	{
		// This is an absolute jump type which words for both
		// 32-bit (4 byte) and 64-bit (8 byte) values.
		// It is *much* nicer for this than jmpq %rax.
		src[0] = (uint8_t)0xFF;
		src[1] = (uint8_t)0x25;
		
#if ROSE_DETOURS_X86
		*reinterpret_cast<uint32_t*>(src + 2) = reinterpret_cast<uint32_t>(src + 6);
#elif ROSE_DETOURS_AMD64
		*reinterpret_cast<uint32_t*>(src + 2) = 0;
#endif
		*reinterpret_cast<Address*>(src + 6) = reinterpret_cast<Address>(dst);

#if defined __ROSE_LOUD__
		for (int i = 0; i < AbsoluteJumpSize; i++)
		{
			printf("%02X ", src[i]);
		}
		printf("\n");
#endif
	}

#if !(defined _WIN32 || defined _WIN64)
	// This is a signfiicantly cleaner version than was in the original;
	// it's spaced out, clear, and has examples.  It should help prevent
	// people from feeling the need to "fix" it :)
	bool SetProtection(void* address, size_t len, int prot)
	{
		// Required to perform cross-page protection changes.
		static uintptr_t page = 0;
		if(page == 0)
		{
			page = sysconf(_SC_PAGESIZE);
#if defined __ROSE_LOUD__
		printf("[ROSE] Page size: 0x%016x\n", page);
#endif//defined __ROSE_LOUD__
		}

		// This just saves some space and some calculations below
		// at the cost of 4-8 bytes.
		static uintptr_t mask = page - 1;

		// Align to the first page.
		// An example to clarify this for people who might misguidedly try to
		// fix or simplify this...
		//
		//     Let ';' be comment.
		//     Let address be 0x19581.
		//     Let page be 4096 (`0x1000`)
		//     Given page, mask = 0xFFF (or 4095).
		//
		//     page1 = (address + mask)  & ~mask  ; how it's shown
		//     page1 = (0x19581 + 0xFFF) & ~0xFFF ; full equation
		//           = 107904            & ~0xFFF ; 0x1A580 & 0xFFF
		//           = 1408                       ; 0x580
		//
		//     page1 = page1 - page               ; remove the added page
		//           = 102400                     ; 0x19000
		//
		// This aligns to the start of the page through the power of masking.
		// (So please stop "fixing" it then complaining...)
		uintptr_t page1 = ((uintptr_t)(address + mask) & ~mask) - page;

#if defined __ROSE_LOUD__
		printf("[ROSE] Protection\n"
			"\tMask:    0x% 16x\n"
			"\tLen:     0x% 16x\n"
			"\tAddress: 0x% 16x\n"
			"\tPage #1: 0x% 16x\n",
			mask, len, address, page1);
#endif//defined __ROSE_LOUD__

		// We know we need a page1, so we set the protection, and we know
		// from man(2) that mprotect should return 0.
		// So apply to the address of page 1, the size
		if(mprotect((void*)page1, page, prot) != 0)
		{
#if defined __ROSE_LOUD__
		printf("[ROSE] Protection setting failed %i\n", 1);
#endif//defined __ROSE_LOUD__
			return false;
		}

		// Get the potential page 2 pointer; this differs from the first in
		// that the length is added.  If they match the values don't exceed
		// a page and mprotect isn't required again.
		uintptr_t page2 = (uintptr_t)(address + (len) + page - 1) & ~(mask);
		if(page1 == page2)
		{
#if defined __ROSE_LOUD__
		printf("[ROSE] Protection setting done; only one page was required.\n");
#endif//defined __ROSE_LOUD__
			return true;
		}

		// This problem isn't actually that simple, but given that the current
		// code won't exceed 28 bytes (let alone 4096), we're done for this.
		//
		// For anyone looking to align the pages, try taking the base, masking,
		// working out if you need more, then looping :)

		// Anyway, protect page2 if you're still here :)
		if(mprotect((void*)page2, page, prot) != 0)
		{
#if defined __ROSE_LOUD__
		printf("[ROSE] Protection setting failed %i\n", 2);
#endif//defined __ROSE_LOUD__
			return false;
		}
		return true;
	}
#endif//non-Windows code

	Detour::Detour(void *original, void* detour):
		mOriginal(reinterpret_cast<uint8_t*>(original)),
		mDetour(reinterpret_cast<uint8_t*>(detour))
	{
		Create();
	}

	Detour::~Detour()
	{
		UNPROTECT(mOriginal, mByteCount);
		memcpy(mOriginal, mBackupOriginal, mByteCount);
		REPROTECT(mOriginal, mByteCount);
#if defined _WIN32 || defined _WIN64
		FlushInstructionCache(GetCurrentProcess(),
			(const void*)mOriginal, mByteCount);
#endif
		free(mTrampoline);
		free(mBackupOriginal);
	}

	bool Detour::Activate()
	{
		if (!UNPROTECT(mOriginal, mByteCount))
		{
			throw ProtectionExceptionARose("Unable to unprotect original region.", mOriginal);
		}

		WriteJump(mOriginal, mDetour);

		if (!REPROTECT(mOriginal, mByteCount))
		{
			throw ProtectionExceptionARose("Unable to reprotect original region.", mOriginal);
		}

#if defined _WIN32 || defined _WIN64
#if defined __ROSE_FLUSH__
		if (FlushInstructionCache(GetCurrentProcess(),
			(const void*)mOriginal, mByteCount) == 0)
		{
			throw ProtectionExceptionARose("Cache failed to flush.", mOriginal);
		}
#endif//defined __ROSE_FLUSH__
#endif//defined _WIN32 || defined _WIN64
		return true;
	}

	bool Detour::Deactivate()
	{
		if (!UNPROTECT(mOriginal, mByteCount))
		{
			throw ProtectionExceptionARose("Unable to unprotect original region.", mOriginal);
		}

		WriteJump(mOriginal, mTrampoline);

		if (!REPROTECT(mOriginal, mByteCount))
		{
			throw ProtectionExceptionARose("Unable to reprotect original region.", mOriginal);
		}

#if defined _WIN32 || defined _WIN64
#if defined __ROSE_FLUSH__
		if (FlushInstructionCache(GetCurrentProcess(),
			(const void*)mOriginal, mByteCount) == 0)
		{
			throw ProtectionExceptionARose("Cache failed to flush.", mOriginal);
		}
#endif//defined __ROSE_FLUSH__
#endif
		return true;
	}

	void* Detour::GetOriginalFunction()
	{
		return mTrampoline;
	}

	void* Detour::GetDetourFunction()
	{
		return mDetour;
	}

	void Detour::Create()
	{
		// First, rule out detour collisions.
		if (reinterpret_cast<uint8_t*>(mOriginal)[0] == 0xE8)
		{
			// For now, do nothing.  This needs consideration, and a
			// hotpatch to hotpatch done badly could(/will) hurt us.
			throw ExceptionARose("Previously patched function found (0xE8 first byte)");
		}

		// Spin up capstone *once* per detour.
		csh handle;
		//cs_insn *insns;
		//size_t count;

		if (cs_open(CapstoneArchitecture, CapstoneMode, &handle) != CS_ERR_OK)
		{
			// An Exception! A Rose!
			throw BackendExceptionARose("Unable to initialise Capstone\n");
		}

		// Details aren't needed if we avoid using cs_x86;
		// this makes it harder, but that's fine,
		// it's not *too* hard...
		//
		// Note: this may need to be toggled on later for safe rebuilding!
		cs_option(handle, CS_OPT_DETAIL, CS_OPT_OFF);

		size_t instructionCount = 0;
		size_t byteCount = 0;

#if defined __ROSE_LOUD__
		printf("[ROSE] Getting disassembly information from Capstone.\n");
#endif//defined __ROSE_LOUD__

		// This will be *far* more important in the future.
		GetDisassemblyCounts(
			instructionCount, byteCount,
			handle, mOriginal,
			mInstructionCount, mByteCount
		);

#if defined __ROSE_LOUD__
		printf("[ROSE] Received disassembly information from Capstone.\n");
#endif//defined __ROSE_LOUD__

		// For now, nothing Capstoney really happens; in the future,
		// maybe a wholesale function rebuild.
		//
		// it's a lot of work (too much for now), so it's being 
		// skipped.  Note that this will be the root of so many issues

		// Close it as we're done.
		cs_close(&handle);

		// If capstone didn't find what we needed, we're doomed.
		if (byteCount < AbsoluteJumpSize)
		{
			throw BackendExceptionARose("Function too small to detour.");
		}

#if defined __ROSE_LOUD__
		printf("[ROSE] Building trampoline.\n");
#endif//defined __ROSE_LOUD__

		// The trampoline itself is a jump and any replaced operations.
		// How it works, and why it's a "trampoline" is it performs
		// the initial (clobbered) operations and then the operation is
		// bounced back.
		mTrampoline = (uint8_t*)ROSE_ALLOC(
			AbsoluteJumpSize + mByteCount
		);

#if defined __ROSE_LOUD__
		printf("[ROSE] Copying %i bytes from Original (%p) to Trampoline (%p).\n",
			mByteCount, mOriginal, mTrampoline);
#endif//defined __ROSE_LOUD__

		// Copy the original bytes into the trampoline,
		// then write a jump to return.
		memcpy(mTrampoline, mOriginal, mByteCount);
		WriteJump(mTrampoline + mByteCount,
			mOriginal + mByteCount);

#if defined __ROSE_LOUD__
		printf("[ROSE] Performing a backup of the original data.\n");
#endif//defined __ROSE_LOUD__

		// -- Optional --
		// This is just so it can be restored later; it's so future
		// versions can do crazy things (like rewrite data/update locs)
		// and then be sure it can be fixed later!
		mBackupOriginal = (uint8_t*)ROSE_ALLOC(mByteCount);
		memcpy(mBackupOriginal, mOriginal, mByteCount);

#if defined __ROSE_LOUD__
		printf("[ROSE] Making mTrampoline executable: %p\n", mTrampoline);
#endif//defined __ROSE_LOUD__

		// Set mTrampoline to be executable (and enable r/w).
		if (!UNPROTECT(mTrampoline, AbsoluteJumpSize + mByteCount))
		{
			throw ProtectionExceptionARose("Unable to unprotect trampoline.", mTrampoline);
		}

		// Installation of the detour is the responsibility of
		// the Activate function.  Similarly code *to* the
		// trampoline is the responsibility of Deactivate.
		//
		// In this case we'll do it here, so we don't need to call it,
		// and so we can 'nop' ("do nothing instruction")
		// the region first.

#if defined __ROSE_LOUD__
		printf("[ROSE] Setting RWE permissions to the original %i bytes at %p.\n",
			mByteCount, mOriginal);
#endif//defined __ROSE_LOUD__

		if (!UNPROTECT(mOriginal, mByteCount))
		{
			throw ProtectionExceptionARose("Unable to unprotect original region.", mOriginal);
		}

#if defined __ROSE_LOUD__
		printf("[ROSE] Writing jump from original region to trampoline.\n");
#endif//defined __ROSE_LOUD__

		WriteJump(mOriginal, mTrampoline);

		int trailingBytes = mByteCount - AbsoluteJumpSize;
		if(trailingBytes > 0)
		{
#if defined __ROSE_LOUD__
			printf("[ROSE] Setting %i trailing bytes to nop (0x90).\n",
				mByteCount);
#endif//defined __ROSE_LOUD__
			memset(mOriginal + AbsoluteJumpSize, 0x90, trailingBytes);
		}



#if defined __ROSE_LOUD__
		printf("[ROSE] Restoring permissions to the original %i bytes at %p.\n",
			mByteCount, mOriginal);
#endif//defined __ROSE_LOUD__

		// It's not a big deal if this fails; we have Read/Write/Execute.
		REPROTECT(mOriginal, mByteCount);

#if defined _WIN32 || defined _WIN64
#if defined __ROSE_FLUSH__
		// Flush the instruction cache for the target/source/base;
		// it needs to be flushed in keeping with the size modified.
		if (FlushInstructionCache(GetCurrentProcess(),
			(const void*)mOriginal, mByteCount) == 0)
		{
			throw ProtectionExceptionARose("Cache failed to flush.", mOriginal);
		}
#endif//defined __ROSE_FLUSH__
#endif

		// Optional spam/debug
#if defined __ROSE_LOUD__
		printf(
			"[ROSE] Original:       %p\n"
			"[ROSE] Detour:         %p\n"
			"[ROSE] Trampoline:     %p\n",
			mOriginal, mDetour, mTrampoline
		);
#endif
	}
}

#undef INSTRUCTION_RETURNS
#undef IN_RANGE
#undef UNPROTECT
#undef REPROTECT
#if !(defined _WIN32 || defined _WIN64)
#undef PROT_REPROTECT
#undef PROT_UNPROTECT
#endif
