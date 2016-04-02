// Copyright (c) 2016 A.W. Stanley.
// All rights reserved.
//
// See the http://github.com/awstanley/Rose LICENCE file.

#ifndef __ROSE_HPP
#define __ROSE_HPP

#include <stdint.h>

// Added exceptions to provide a "cleaner" (standard?) feedback system.
#include <stdexcept>

#if defined __amd64__ || defined _M_AMD64 || defined __x86_64__ || defined _M_X64
#	define ROSE_DETOURS_AMD64 1
#elif defined __i386__ || defined _M_IX86 || defined __X86__
#	define ROSE_DETOURS_X86 1
#endif

namespace Rose
{
	/**
	 * @class	ExceptionARose
	 *
	 * @brief	Base exception type for signalling errors in RoseDetours.
	 *
	 * Should be triggered in its own form, or its subtypes, whenever an
	 * error arose.
	 */
	class ExceptionARose : public std::runtime_error
	{
	public:
		typedef std::runtime_error _Mybase;
		explicit ExceptionARose(const std::string& _Message) : _Mybase(_Message.c_str()) { }
		explicit ExceptionARose(const char* _Message) : _Mybase(_Message) { }
	};

	/**
	 * @class	ProtectionExceptionARose
	 *
	 * @brief	An exception indicating a protection issue.
	 */
	class ProtectionExceptionARose : public std::runtime_error
	{
	private:
		const void* mErrorAddress;
	public:
		typedef std::runtime_error _Mybase;
		explicit ProtectionExceptionARose(const std::string& _Message, const void* errorAddress) : _Mybase(_Message.c_str()), mErrorAddress(errorAddress) { }
		explicit ProtectionExceptionARose(const char* _Message, const void* errorAddress) : _Mybase(_Message), mErrorAddress(errorAddress) { }
		const void* GetErrorAddress() { return mErrorAddress; }
	};

	/**
	 * @class	BackendExceptionARose
	 *
	 * @brief	An exception indicating an error in the disassembler/backend.
	 */
	class BackendExceptionARose : public std::runtime_error
	{
	public:
		typedef std::runtime_error _Mybase;
		explicit BackendExceptionARose(const std::string& _Message) : _Mybase(_Message.c_str()) { }
		explicit BackendExceptionARose(const char* _Message) : _Mybase(_Message) { }
	};

	/**
	 * @brief The type used to store an address on the given platform.
	 *
	 * stdint.h provides uintptr_t, which should be reliable, but could
	 * equally be larger, or do more or less whatever it wanted to do.
	 * As a result (mostly due to complaints every other time I use this)
	 * I'm using a typedef to avoid using it.
	 *
	 * Note: the standard says it will fit, not that it will not be larger;
	 * this is just to stop this breaking and forcing me to haphazardly
	 * replace all instances later.
	 */
	typedef
#if ROSE_DETOURS_X86
		uint32_t
#elif ROSE_DETOURS_AMD64
		uint64_t
#endif
		Address;

	/**
	 * @brief A Detour represents an untemplated detour call.
	 *
	 * This is the 'advanced' interface for those who aren't concerned about
	 * what things look like; you can wrap this in something with a template
	 * to make your life easier (and potentially less error prone) in code,
	 * though I recommend against it for the weight/bulk it adds over a
	 * reinterpret_cast<fnPrototype>(ptr) approach. (Granted the latter
	 * is somewhat aesthetically displeasing to some.)
	 */
	class Detour
	{
	protected:

#if defined _WIN32 || defined _WIN64
		// Windows protection
		unsigned long dwProt;

#endif//_WIN32 || _WIN64

		/// Data used for trampolining.
		// This contains some relocated data and a jump to the function.
		// This is what should be returned to run the original function,
		// at least until such times as the RelocatedOriginal is stable.
		uint8_t* mTrampoline;

		/// Unmodified code from the original function.
		// This is NOT what should be returned when someone wants to run
		// the original function.  This is a backup of the original code.
		uint8_t* mBackupOriginal;

		/// Store the relocated code here (todo/pending)
		// -- Incomplete, description is for the pending version --
		// This is what should be returned when someone wants to run
		// the original function.  It contains reconstructed code, which
		// is allocated based on the size required.
		// uint8_t* mRelocatedOriginal;

		/**
		 * @brief Number of instructions replaced in the bytes replaced.
		 *
		 * This is the number of instructions, not the number of bytes.
		 */
		size_t mInstructionCount;

		/**
		 * @brief Number of instructions replaced in the bytes replaced.
		 *
		 * Acts like a sizeof(mBackupOriginal).
		 */
		size_t mByteCount;

		/// A pointer to the original function area
		uint8_t* mOriginal;

		/// A pointer to the detouring function.
		uint8_t* mDetour;

		/// Creates the trampoline and detour but does not activate.
		void Create();

	public:

		/// Activate the detour.
		bool Activate();

		/// Activate the detour.
		bool Deactivate();

		/// Gets a pointer to the new home of the function.
		void* GetOriginalFunction();

		/// Gets a pointer to the detour.
		void* GetDetourFunction();

		/// Constructs a detour and trampoline from original to detour.
		Detour(void *original, void* detour);

		/// Destroys the trampoline and restores the original code.
		~Detour();
	};
}

#endif//__ROSE_HPP