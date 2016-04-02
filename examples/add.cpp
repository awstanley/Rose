#include <Rose.hpp>

#include <stdio.h>
#include <stdarg.h>

static int count = 0;

// prototype
typedef int(*proto_add)(int a, int b);

// function you might find in a library
int add(int a, int b)
{
	int ret = a + b;
	printf("add (%i,%i) = %i\n", a, b, ret);
	return ret;
}

// same prototype, very different result.
int add2(int a, int b)
{
	int ret = a + a + b + b + 851;
	printf("add2(%i,%i) = %i\n", a, b, ret);
	return ret;
}

// wrapper to give some neat/clean output
void _add(int a, int b)
{
	// If we remove this, and use add() directly nothing happens.
	// This way we can pretend that we're running by address and not
	// a lookup table, precached data, or something similarly annoying.
	proto_add fn = &add;

	printf("[% 2i | % 16p] ", ++count, &fn);
	fn(a, b);
}

// bunch of tests
void _add_test()
{
	void* addr = (void*)add;
	{
		proto_add fn;

		// Pre detour
		_add(1, 2);

		// Trivial Add detour
		printf("Creating 'add' detour (inactive)\n");
		Rose::Detour detourAdd((void*)&add, (void*)&add2);

		// Post (pre-activate)
		_add(1, 2);

		*(void**)&fn = detourAdd.GetOriginalFunction();
		printf("[% 2i |original (by ptr)] ", count);
		fn(1, 2);

		*(void**)&fn = detourAdd.GetDetourFunction();
		printf("[% 2i |detour   (by ptr)] ", count);
		fn(1, 2);

		// scoped detour
		detourAdd.Activate();
		printf("Activating detour...\n");
		// Post (post-activate)
		_add(1, 2);

		*(void**)&fn = detourAdd.GetOriginalFunction();
		printf("[% 2i |original (by ptr)] ", count);
		fn(1, 2);

		*(void**)&fn = detourAdd.GetDetourFunction();
		printf("[% 2i |detour   (by ptr)] ", count);
		fn(1, 2);

		
		detourAdd.Deactivate();
		printf("Deactivating detour...\n");
		// Post (post-activate)
		_add(1, 2);

		*(void**)&fn = detourAdd.GetOriginalFunction();
		printf("[% 2i |original (by ptr)] ", count);
		fn(1, 2);
		
		*(void**)&fn = detourAdd.GetDetourFunction();
		printf("[% 2i |detour   (by ptr)] ", count);
		fn(1, 2);
	}
}

int main(int argc, char **argv)
{
	_add_test();
	return 0;
}