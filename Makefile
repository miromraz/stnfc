# stnfc -- userspace NFC toolkit for the Pixel 4a's ST21NFC CLF.
#
# `make`           cross-compile the static aarch64 binary `stnfc`.
# `make clean`     remove build artifacts.
# `make deploy`    scp the binary to $(PHONE) (override on the command line).
#
# The binary runs on aarch64 Linux only -- it talks directly to
# /dev/i2c-2 and /dev/gpiochip2 on the Pixel 4a.

CROSS_COMPILE ?= aarch64-linux-gnu-
CC            := $(CROSS_COMPILE)gcc
CFLAGS        := -O2 -Wall -static
SRC           := tool/stnfc.c
BIN           := stnfc

PHONE         ?= user@172.16.42.1
DEST          ?= /tmp/stnfc

.PHONY: all clean deploy
all: $(BIN)

$(BIN): $(SRC)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(BIN)

deploy: $(BIN)
	scp $(BIN) $(PHONE):$(DEST)
