# Rose

     What's in a name? that which we call a rose
     By any other name would smell as sweet
                     -- Juliet (Romeo and Juliet)

This is a relatively simple x86/x86_64 library created for the purposes of using trampolines and/or detours on Windows and Linux.



## What? Why? How?

This library is a from-scratch implementation of detouring using the manipulation of machine language to 'hot patch' an existing executable.

It exists for the purposes of allowing me to do so without being beholden to other code.

It uses the rather execellent BSD-licensed `Capstone Engine` to disassemble and verify what's happening is safe.  (At the moment it does less of this than I would like, but it does check the lengths -- at some stage it would probably be prudent to do some more complex/relocatation work.)

As a note to those wondering: the reason I'm not using the `Hacker Disassembler Engine` (or HDE) is Capstone offers more or what I want, albeit at a performance cost.  Since the cost is in creation, and I want it done right (or to understand where it went wrong), Capstone is superior.



## Status

    This library is in very early alpha, and is being developed primarily for an active project.

Tracking of status information will be done in other files to keep this file relatively clean.

CHANGES will be tracked in `CHANGES.md`.

TODO will be tracked in `TODO.md`.



## Notes

I cannot emphasise enough that **Capstone will not work in diet mode if a relocation is required**.  This is because `cs_insn_group` is used to check the groups.

It is important to note that while this library is in alpha, it is being used.  While the testing is limited to whatever I need it for, I will respond to issues as they arise (if they arise).

It's also worth noting if you detour a function within an application (and not within a shared library, or not from a library into the application) that there is a good chance the reason your detour is not doing what you expect for any number of reasons -- see `examples/add.cpp`.



## Requirements

This library requires Capstone be compiled and available.  Another backend could be used but I'm not abstracting (at least not at this stage).

Compilation is achieved by adding the two files (header and source) to your project (in the form of including the header).

The templated class is gone (it was the old `Detour` class when the current `Detour` was slated to be `CDetour`).  It is unlikely to return, but can be simulated if you can *really* justify the overhead.


## Licence

The licence is BSD (see LICENCE.txt).  This is the same licence Capstone uses.