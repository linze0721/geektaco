ASM      := nasm
ASMFLAGS := -f elf64 -O9
LD       := ld
LDFLAGS  := -N -s --build-id=none -z norelro

OBJS := main.o http.o db.o render.o auth.o
BIN  := geektaco
ELF  := $(BIN).elf

all: $(BIN)

$(BIN): $(ELF) mkelf.py
	python3 mkelf.py $(ELF) $@
	chmod +x $@

$(ELF): $(OBJS) link.ld
	$(LD) $(LDFLAGS) -T link.ld $(OBJS) -o $@

%.o: %.asm common.inc
	$(ASM) $(ASMFLAGS) $< -o $@

run: $(BIN)
	./$(BIN)

clean:
	rm -f $(OBJS) $(ELF) $(BIN)

.PHONY: all run clean
