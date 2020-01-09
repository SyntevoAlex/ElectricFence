/*
 * Electric Fence - Red-Zone memory allocator.
 * Bruce Perens, 1988, 1993
 * 
 * This is a special version of malloc() and company for debugging software
 * that is suspected of overrunning or underrunning the boundaries of a
 * malloc buffer, or touching free memory.
 *
 * It arranges for each malloc buffer to be followed (or preceded)
 * in the address space by an inaccessable virtual memory page,
 * and for free memory to be inaccessable. If software touches the
 * inaccessable page, it will get an immediate segmentation
 * fault. It is then trivial to uncover the offending code using a debugger.
 *
 * An advantage of this product over most malloc debuggers is that this one
 * detects reading out of bounds as well as writing, and this one stops on
 * the exact instruction that causes the error, rather than waiting until the
 * next boundary check.
 *
 * There is one product that debugs malloc buffer overruns
 * better than Electric Fence: "Purify" from Purify Systems, and that's only
 * a small part of what Purify does. I'm not affiliated with Purify, I just
 * respect a job well done.
 *
 * This version of malloc() should not be linked into production software,
 * since it tremendously increases the time and memory overhead of malloc().
 * Each malloc buffer will consume a minimum of two virtual memory pages,
 * this is 16 kilobytes on many systems. On some systems it will be necessary
 * to increase the amount of swap space in order to debug large programs that
 * perform lots of allocation, because of the per-buffer overhead.
 */
#include "efence.h"
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <memory.h>
#include <string.h>
#include <pthread.h>
#include <execinfo.h>

#ifdef	malloc
#undef	malloc
#endif

#ifdef	calloc
#undef	calloc
#endif

static const char	version[] = "\n"
 "==================================================\n"
 "  Electric Fence 3.0\n"
 "    Copyright (C) 1987-1998 Bruce Perens.\n"
 "    Copyright (C) 2012-2013 Alexander von Gluck IV\n"
 "==================================================\n";

static const char	enabled[] = "\n  Memory fencing has been enabled\n\n";

/*
 * MEMORY_CREATION_SIZE is the amount of memory to get from the operating
 * system at one time. We'll break that memory down into smaller pieces for
 * malloc buffers. One megabyte is probably a good value.
 */
#define			MEMORY_CREATION_SIZE	1024 * 1024

/*
 * @@@@
 */
int            EF_ENABLE_BACKTRACE = 1;
#define        BACKTRACE_SIZE 64
int            g_IsInsideBacktrace = 0;

/*
 * Struct Slot contains all of the information about a malloc buffer except
 * for the contents of its memory.
 */
struct _Slot {
	void *		userAddress;
	void *		internalAddress;
	size_t		userSize;
	size_t		internalSize;
	size_t 		magic;
	void*		backtrace[BACKTRACE_SIZE];
};
typedef struct _Slot	Slot;

 /*
 * EF_DISABLE_BANNER is a global variable used to control whether
 * Electric Fence prints its usual startup message.  If the value is
 * -1, it will be set from the environment default to 0 at run time.
 */
int            EF_DISABLE_BANNER = -1;


/*
 * EF_ALIGNMENT is a global variable used to control the default alignment
 * of buffers returned by malloc(), calloc(), and realloc(). It is all-caps
 * so that its name matches the name of the environment variable that is used
 * to set it. This gives the programmer one less name to remember.
 * If the value is -1, it will be set from the environment or sizeof(int)
 * at run time.
 */
int		EF_ALIGNMENT = -1;

/*
 * EF_PROTECT_FREE is a global variable used to control the disposition of
 * memory that is released using free(). It is all-caps so that its name
 * matches the name of the environment variable that is used to set it.
 * If its value is greater non-zero, memory released by free is made
 * inaccessable and never allocated again. Any software that touches free
 * memory will then get a segmentation fault. If its value is zero, freed
 * memory will be available for reallocation, but will still be inaccessable
 * until it is reallocated.
 * If the value is -1, it will be set from the environment or to 0 at run-time.
 */
int		EF_PROTECT_FREE = -1;

/*
 * EF_PROTECT_BELOW is used to modify the behavior of the allocator. When
 * its value is non-zero, the allocator will place an inaccessable page
 * immediately _before_ the malloc buffer in the address space, instead
 * of _after_ it. Use this to detect malloc buffer under-runs, rather than
 * over-runs. It won't detect both at the same time, so you should test your
 * software twice, once with this value clear, and once with it set.
 * If the value is -1, it will be set from the environment or to zero at
 * run-time
 */
int		EF_PROTECT_BELOW = -1;

/*
 * EF_ALLOW_MALLOC_0 is set if Electric Fence is to allow malloc(0). I
 * trap malloc(0) by default because it is a common source of bugs.
 */
int		EF_ALLOW_MALLOC_0 = -1;

/*
 * EF_FREE_WIPES is set if Electric Fence is to wipe the memory content
 * of freed blocks.  This makes it easier to check if memory is freed or
 * not
 */
int            EF_FREE_WIPES = -1;

/*
 * bytesPerPage is set at run-time to the number of bytes per virtual-memory
 * page, as returned by Page_Size().
 */
static size_t		bytesPerPage = 0;

/*
 * Performance counters for debug purposes
 */
static long long	g_Perf_AllocatedBlocks = 0;
static long long	g_Perf_AllocatedBytesUser = 0;
static long long	g_Perf_AllocatedBytesReal = 0;

 /*
 * mutex to enable multithreaded operation
 */
static pthread_mutex_t mutex ;

static void lock() {
    pthread_mutex_lock(&mutex);
}

static void unlock() {
    pthread_mutex_unlock(&mutex);
}

static void initializeMutex() {
    pthread_mutexattr_t mutexAttr;

    pthread_mutexattr_init(&mutexAttr);
    pthread_mutexattr_settype(&mutexAttr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&mutex, &mutexAttr); 
    pthread_mutexattr_destroy(&mutexAttr);
}

/*
 * internalError is called for those "shouldn't happen" errors in the
 * allocator.
 */
static void
internalError(void)
{
	EF_Abort("Internal error in allocator.");
}

/*
 * initialize sets up the memory allocation arena and the run-time
 * configuration information.
 */
static void
initialize(void)
{
	char *	string;

       initializeMutex();

       if ( EF_DISABLE_BANNER == -1 ) {
               if ( (string = getenv("EF_DISABLE_BANNER")) != 0 )
                       EF_DISABLE_BANNER = atoi(string);
               else
                       EF_DISABLE_BANNER = 0;
       }

       if ( EF_DISABLE_BANNER == 0 )
               EF_Print(version);

	/*
	 * Import the user's environment specification of the default
	 * alignment for malloc(). We want that alignment to be under
	 * user control, since smaller alignment lets us catch more bugs,
	 * however some software will break if malloc() returns a buffer
	 * that is not word-aligned.
	 *
	 * I would like
	 * alignment to be zero so that we could catch all one-byte
	 * overruns, however if malloc() is asked to allocate an odd-size
	 * buffer and returns an address that is not word-aligned, or whose
	 * size is not a multiple of the word size, software breaks.
	 * This was the case with the Sun string-handling routines,
	 * which can do word fetches up to three bytes beyond the end of a
	 * string. I handle this problem in part by providing
	 * byte-reference-only versions of the string library functions, but
	 * there are other functions that break, too. Some in X Windows, one
	 * in Sam Leffler's TIFF library, and doubtless many others.
	 */
	if ( EF_ALIGNMENT == -1 ) {
		if ( (string = getenv("EF_ALIGNMENT")) != 0 )
			EF_ALIGNMENT = (size_t)atoi(string);
		else
			EF_ALIGNMENT = sizeof(int);
	}

	/*
	 * See if the user wants to protect the address space below a buffer,
	 * rather than that above a buffer.
	 */
	if ( EF_PROTECT_BELOW == -1 ) {
		if ( (string = getenv("EF_PROTECT_BELOW")) != 0 )
			EF_PROTECT_BELOW = (atoi(string) != 0);
		else
			EF_PROTECT_BELOW = 0;
	}

	/*
	 * See if the user wants to protect memory that has been freed until
	 * the program exits, rather than until it is re-allocated.
	 */
	if ( EF_PROTECT_FREE == -1 ) {
		if ( (string = getenv("EF_PROTECT_FREE")) != 0 )
			EF_PROTECT_FREE = (atoi(string) != 0);
		else
			EF_PROTECT_FREE = 0;
	}

	/*
	 * See if the user wants to allow malloc(0).
	 */
	if ( EF_ALLOW_MALLOC_0 == -1 ) {
		if ( (string = getenv("EF_ALLOW_MALLOC_0")) != 0 )
			EF_ALLOW_MALLOC_0 = (atoi(string) != 0);
		else
			EF_ALLOW_MALLOC_0 = 0;
	}

	/*
	 * See if the user wants us to wipe out freed memory.
	 */
	if ( EF_FREE_WIPES == -1 ) {
	        if ( (string = getenv("EF_FREE_WIPES")) != 0 )
	                EF_FREE_WIPES = (atoi(string) != 0);
	        else
	                EF_FREE_WIPES = 0;
	}

	/*
	 * Get the run-time configuration of the virtual memory page size.
 	 */
	bytesPerPage = Page_Size();

	/*
	 * Account for the two slot structures that we've used.
	 */
	if ( EF_DISABLE_BANNER == 0 )
		EF_Print(enabled);
}

static size_t calculateSlotMagic(Slot* a_Slot) {
	size_t result = 0;
	result ^= (size_t)0x1B69D0D6;
	result ^= (size_t)a_Slot->userAddress;
	result ^= (size_t)a_Slot->internalAddress;
	result ^= (size_t)a_Slot->userSize;
	result ^= (size_t)a_Slot->internalSize;

	return result;
}

/*
 * This is the memory allocator. When asked to allocate a buffer, allocate
 * it in such a way that the end of the buffer is followed by an inaccessable
 * memory page. If software overruns that buffer, it will touch the bad page
 * and get an immediate segmentation fault. It's then easy to zero in on the
 * offending code with a debugger.
 *
 * There are a few complications. If the user asks for an odd-sized buffer,
 * we would have to have that buffer start on an odd address if the byte after
 * the end of the buffer was to be on the inaccessable page. Unfortunately,
 * there is lots of software that asks for odd-sized buffers and then
 * requires that the returned address be word-aligned, or the size of the
 * buffer be a multiple of the word size. An example are the string-processing
 * functions on Sun systems, which do word references to the string memory
 * and may refer to memory up to three bytes beyond the end of the string.
 * For this reason, I take the alignment requests to memalign() and valloc()
 * seriously, and 
 * 
 * Electric Fence wastes lots of memory. I do a best-fit allocator here
 * so that it won't waste even more. It's slow, but thrashing because your
 * working set is too big for a system's RAM is even slower. 
 */
extern C_LINKAGE void *
memalign(size_t alignment, size_t userSize)
{
	Slot *		fullSlot = 0;
	size_t		internalSize;
	size_t		slack;
	char *		address;

	if ( bytesPerPage == 0 )
		initialize();

	if ( userSize == 0 && !EF_ALLOW_MALLOC_0 )
		EF_Abort("Allocating 0 bytes, probably a bug.");

	lock();

	/*
	 * If EF_PROTECT_BELOW is set, all addresses returned by malloc()
	 * and company will be page-aligned.
 	 */
	if ( !EF_PROTECT_BELOW && alignment > 1 ) {
		if ( (slack = userSize % alignment) != 0 )
			userSize += alignment - slack;
	}

	/*
	 * The internal size of the buffer is rounded up to the next page-size
	 * boudary, and then we add another page's worth of memory for the
	 * dead page.
	 */
	internalSize = userSize + sizeof(Slot) + bytesPerPage;
	if ( (slack = internalSize % bytesPerPage) != 0 )
		internalSize += bytesPerPage - slack;

	/*
	 * Allocate pages to hold the requested allocation
	 * NOTE: @@@@ Doesn't support 'EF_PROTECT_BELOW'
	 */
	
	fullSlot = (Slot*)Page_Create(internalSize);
	fullSlot->internalAddress = fullSlot;
	fullSlot->internalSize    = internalSize;

	if ( !EF_PROTECT_BELOW ) {
		/*
		 * Arrange the buffer so that it is followed by an inaccessable
		 * memory page. A buffer overrun that touches that page will
		 * cause a segmentation fault.
		 */
		address = (char *)fullSlot->internalAddress;

		/* Set up the "live" page. */
		if ( internalSize - bytesPerPage > 0 )
				Page_AllowAccess(
				 fullSlot->internalAddress
				,internalSize - bytesPerPage);
			
		address += internalSize - bytesPerPage;

		/* Set up the "dead" page. */
		Page_DenyAccess(address, bytesPerPage);

		/* Figure out what address to give the user. */
		address -= userSize;
	}
	else {	/* EF_PROTECT_BELOW != 0 */
		EF_Abort("EF_PROTECT_BELOW not supported after changes to 'allocationList'");

		/*
		 * Arrange the buffer so that it is preceded by an inaccessable
		 * memory page. A buffer underrun that touches that page will
		 * cause a segmentation fault.
		 */
		address = (char *)fullSlot->internalAddress;

		/* Set up the "dead" page. */
		Page_DenyAccess(address, bytesPerPage);
			
		address += bytesPerPage;

		/* Set up the "live" page. */
		if ( internalSize - bytesPerPage > 0 )
			Page_AllowAccess(address, internalSize - bytesPerPage);
	}

	fullSlot->userAddress = address;
	fullSlot->userSize    = userSize;
	fullSlot->magic       = calculateSlotMagic(fullSlot);

	// @@@@
	memset(fullSlot->userAddress, 0xCC, fullSlot->userSize);

	g_Perf_AllocatedBlocks 	  += 1;
	g_Perf_AllocatedBytesUser += userSize;
	g_Perf_AllocatedBytesReal += internalSize;

	unlock();

	// Capture stack outside the lock to avoid deadlocking with libc
	if (EF_ENABLE_BACKTRACE && !g_IsInsideBacktrace) {
		// @@@@ Make thread-safe
		g_IsInsideBacktrace = 1;
		backtrace(fullSlot->backtrace, BACKTRACE_SIZE);
		g_IsInsideBacktrace = 0;
	}

	return address;
}

Slot* slotForUserAddressInternal(void * address) {
	return (Slot*)(((intptr_t)address - sizeof(Slot)) & ~(bytesPerPage - 1));
}

Slot* slotForUserAddress(void * address) {
	Slot *	slot;

	slot = slotForUserAddressInternal(address);

	if (slot->magic != calculateSlotMagic(slot))
		EF_Abort("Allocator's internal data was corrupted, or you're calling free() for invalid pointer");

	if (slot->userAddress != address)
		EF_Abort("free(%p) was called for block=%p", address, slot->userAddress);
	
	return slot;
}

extern C_LINKAGE void
free(void * address)
{
	Slot *	slot;

        if ( address == 0 )
                return;

        lock();

	if ( bytesPerPage == 0 )
		EF_Abort("free() called before first malloc().");

	slot = slotForUserAddress(address);

	Page_Delete(slot->internalAddress, slot->internalSize);

        unlock();
}

extern C_LINKAGE void *
realloc(void * oldBuffer, size_t newSize)
{
	void *	newBuffer = malloc(newSize);

        lock();

	if ( oldBuffer ) {
		size_t	size;
		Slot *	slot;

		slot = slotForUserAddress(oldBuffer);

		if ( newSize < (size = slot->userSize) )
			size = newSize;

		if ( size > 0 )
			memcpy(newBuffer, oldBuffer, size);

		free(oldBuffer);

		if ( size < newSize )
			memset(&(((char *)newBuffer)[size]), 0, newSize - size);
	}
	unlock();

	return newBuffer;
}

extern C_LINKAGE void *
malloc(size_t size)
{
	/* initialize() is required to load EF_ALIGNMENT */
	if ( bytesPerPage == 0 )
		initialize();

	return memalign(EF_ALIGNMENT, size); 
}

extern C_LINKAGE void *
calloc(size_t nelem, size_t elsize)
{
	size_t	size = nelem * elsize;
	void * allocation;

	allocation = malloc(size);
	memset(allocation, 0, size);

	return allocation;
}

/*
 * This will catch more bugs if you remove the page alignment, but it
 * will break some software.
 */
extern C_LINKAGE void *
valloc (size_t size)
{
	/* initialize() is required to load bytesPerPage */
	if ( bytesPerPage == 0 )
		initialize();

	return memalign(bytesPerPage, size);
}

/*
 * Debugging code, intended for use in GDB
 */
extern C_LINKAGE void *
EF_AllocInfo (void * address)
{
	Slot *	slot;
	size_t  goodMagic;

	slot = slotForUserAddressInternal(address);
	goodMagic = calculateSlotMagic(slot);

	printf("UserAddr = %p\n",   slot->userAddress);
	printf("IntAddr  = %p\n",   slot->internalAddress);
	printf("UserSize = %zd\n",  slot->userSize);
	printf("IntSize  = %zd\n",  slot->internalSize);
	printf("Magic    = %s\n",   (slot->magic == goodMagic) ? "Good" : "Wrong");
	printf("Backtrace= %p\n",   slot->backtrace);
}

