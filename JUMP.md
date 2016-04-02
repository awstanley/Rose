# JMP (and how it works)

The jump in question here is not the standard jump, better known to some as the `E9` jump or just `JMP` (where the latter is ambiguous).  `E9` performs a relative location jump and takes a maximum of 4 bytes (32-bits), which provide a relative location.  This relative location is taken from the beginning of the instruction (i.e. the address of the `E9`).  This jump is fairly simple to use.

The absolute jump used, and the purpose for this document, is the `FF 25` jump.  It has started to rear its head around the internet over the last few years, turning up in relation to this question, but with very little in the way of anyone pointing what it actually is.

From an x86 perspective you have no reason to use it -- it wastes space -- and you should instead calculate the relative value and use the `E9`.  However, when it comes to using the `x86_64` variant the `E9` is still restricted to 32 bits, meaning that if you have an allocation beyond the 2GB range (which on Linux is all but given with ASLR), you're out of luck or need to chain jumps.

There are two solutions: the first is a `jmp %rax` (which requires pushing into `%rax` and occupying the register), and the latter is `FF 25` (jump far).  `FF 25` is also known as `FF /4`, or `Jump Near` (p. 501 of [AMD's 24594](http://support.amd.com/TechDocs/24594.pdf)).  To break that down we need to understand the `/4` and the second byet (`25`).  This is what's known as a `Mod R/M` byte (and also `ModR/M`, and even sometimes `modrm`).  Both AMD and Intel document this in various places, but to keep things in the already linked documents it's on page 17 of [AMD's 24594](http://support.amd.com/TechDocs/24594.pdf).

Breaking down our 25 we get (using AMD's parlance):

    +--------------------- Hexidecimal
    |      +-------------- Decimal
    |      |    +--------- Binary (divided into nibbles)
    |      |    |
    0x25 = 37 = 0010 0101
                | |   |
                | |   +----[101] ModRM.r/m
                | +--------[100] ModRM.reg
                +--------- [ 00] ModRM.mod

Note how the value of the `reg` field is 4 (matching our `/4`).  For this reason this field is also frequently called the `digit` in some circles.  The `mod` and `r/m` fields are combined, in this case yielding `00101`, which is documented to specify `an absolute addressing mode` (p. 23 of [AMD's 24594](http://support.amd.com/TechDocs/24594.pdf)).  Thus we land upon 25 for our needs, giving us the ability to use absolute addressing.

On x86 this is a trivial task of pushing the displacement field in four bytes followed by the address in the next four.  This creates our relative jump.  For `x86_64` or 64-bit, this is `RIP-relative addressing` -- which is also well documented.  For our purposes it just means our displacement field is 0 and our addres follows.


    FF 25 00 00 00 00 12 34 45 67 89 AB CD EF
    |  |  |           |  
    |  |  |           |
    |  |  |           +---- Address
    |  |  +---------------- Displacement field
    |  +------------------- Mod R/M
    +---------------------- Opcode

The same principle applies for the CALL's `FF /2` (except, of course, the value is `0x25`).

Various other sources of information to introduce this in a gentler form than the AMD exist, for example [this Tufts handout](http://www.cs.tufts.edu/comp/40/handouts/amd64.pdf).

As a final note this call will do some strange looking things on legacy hardware (anything from before `32/64` when things were `16/32`).  This is because AMD replaced the legacy functionality with the 64-bit variants -- this too is documented.