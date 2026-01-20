
objdir := obj


src := barcode-scanner.c

obj := $(patsubst %.c, $(objdir)/%.o, $(src))
obj_debug := $(patsubst %.c, $(objdir)/%.o.debug, $(src))

sec_flags := -fno-stack-protector
cxxflags := $(sec_flags) -I. -D_FORTIFY_SOURCE=0 -D_GNU_SOURCE -O1 -Wno-stringop-overflow

ldflags := -no-pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack


prod_req := $(obj)

prog := barcode-scanner


all: $(prog)
.PHONY: all clean

$(prog): $(prod_req)
	@echo "Linking everything together"
	gcc -o tmp $^ $(ldflags)
	@echo "Removing the debug sections"
	objcopy -w -x \
		--remove-section=.comment \
		--remove-section=.note* \
		tmp $@
	rm tmp

$(objdir):
	@mkdir -p $@

$(objdir)/%.o: %.c | $(objdir)
	@echo "Compiling $<"
	gcc -D_DEBUG=0 -DDEBUG=0 $(cxxflags) -c $< -o $@

clean:
	rm -rf $(objdir) *.o *.dep *.debug $(prog)
