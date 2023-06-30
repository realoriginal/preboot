OUTX64 := stage_1_shrukin.x64.bin

##
## Compiles each portion and merges them
##
all:
	@cd efi && make
	@nasm -f bin asm/x64/Start.asm -o $(OUTX64)
 
##
## Deletes all the artifacts
##
clean:
	@cd efi && make clean
	@rm -rf $(OUTX64)
