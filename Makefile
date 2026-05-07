ROOT_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

.PHONY: all analyzer irdumper clean

all: analyzer

analyzer:
	./build.sh

irdumper:
	$(MAKE) -C tools/IRDumper

clean:
	rm -rf build
	$(MAKE) -C tools/IRDumper clean
