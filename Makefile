##
## Builds all the post-ex modules
##
SOURCE := $(wildcard source/*/)
REMOVE := $(addsuffix .,$(SOURCE))

##
## Sets up the tools directory if it doesnt
## exist. Compiles each post-ex module.
##
all: setup-tools $(SOURCE)

##
## Downloads the mingw compilers and sets up
## the tools directory
##
setup-tools:
	@echo Setting up the compilers
	@mkdir -p tools
	@cd tools && wget -q https://musl.cc/x86_64-w64-mingw32-cross.tgz
	@cd tools && tar -xzf x86_64-w64-mingw32-cross.tgz
	@cd tools && rm -rf *.tgz

##
## Compiles all the folders under source. Each
## project must have a Makefile
##
$(SOURCE):
	@cd $@ && make -f Makefile

##
## Runs the clean action in all the folders in
## source.
##
$(REMOVE): .
	@cd $@ && make -f Makefile clean

##
## Deletes all the artifacts
##
clean: $(REMOVE)
	@rm -rf tools

##
## Phony?
##
.PHONY: all $(SOURCE) clean $(REMOVE)
