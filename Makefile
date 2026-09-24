ASM      := nasm
ASMFLAGS := -f elf64 -O9
LD       := ld
LDFLAGS  := -N -s --build-id=none -z norelro

OBJS := main.o http.o db.o render.o auth.o
BIN  := geektaco
ELF  := $(BIN).elf
RAW  := $(BIN).raw

all: $(BIN)

$(BIN): $(ELF) mkpack.py unpack.asm
	python3 mkpack.py $(ELF) unpack.asm $@.tmp
	mv $@.tmp $@

$(RAW): $(ELF) mkelf.py
	python3 mkelf.py $(ELF) $@
	chmod +x $@

$(ELF): $(OBJS) link.ld
	$(LD) $(LDFLAGS) -T link.ld $(OBJS) -o $@

%.o: %.asm common.inc
	$(ASM) $(ASMFLAGS) $< -o $@

strtab.inc: strings.txt mkstr.py
	python3 mkstr.py strings.txt strtab.inc

render.o: strtab.inc

run: $(BIN)
	./$(BIN)

clean:
	rm -f $(OBJS) $(ELF) $(BIN) $(BIN).tmp $(RAW)

.PHONY: all run clean
