CC_X64	:= ../../../tools/x86_64-w64-mingw32-cross/bin/x86_64-w64-mingw32-gcc

CFLAGS	:= $(CFLAGS) -Os -fno-asynchronous-unwind-tables -nostdlib 
CFLAGS 	:= $(CFLAGS) -fno-ident -fpack-struct=8 -falign-functions=1
CFLAGS  := $(CFLAGS) -s -ffunction-sections -falign-jumps=1 -w
CFLAGS	:= $(CFLAGS) -falign-labels=1 -fPIC -Wl,-TSectionLink.ld
LFLAGS	:= $(LFLAGS) -Wl,-s,--no-seh,--enable-stdcall-fixup

OUTX64	:= stage_1_shrukin_efi.x64.exe
BINX64	:= stage_1_shrukin_efi.x64.bin

all:
	@ nasm -f win64 asm/x64/GetIp.asm -o GetIp.x64.o
	@ $(CC_X64) *.c crt/*.c GetIp.x64.o -o $(OUTX64) $(CFLAGS) $(LFLAGS) -I.
	@ python3 ../python3/extract.py -f $(OUTX64) -o $(BINX64)
	@ rm -rf $(OUTX64)

clean:
	@ rm -rf *.o
	@ rm -rf $(OUTX64)
	@ rm -rf $(BINX64)
