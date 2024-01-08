CFLAGS=-O2 -Wall -I argon2/include -fPIC

# Source files
src=src/params.c src/argon2_mariadb.c
src-argon2=argon2/src/argon2.c argon2/src/core.c argon2/src/encoding.c argon2/src/blake2/blake2b.c
src-argon2-ref=argon2/src/ref.c
src-argon2-simd=argon2/src/opt.c
src-argon2-pthread=argon2/src/thread.c

# Object files
objects=$(src:.c=.o)
objects-argon2=$(src-argon2:.c=.o)
objects-argon2-ref=$(src-argon2-ref:.c=.o)
objects-argon2-simd=$(src-argon2-simd:.c=.o)
objects-argon2-pthread=$(src-argon2:.c=.pthread.o) $(src-argon2-pthread:.c=.pthread.o)
objects-argon2-ref-pthread=$(src-argon2-ref:.c=.pthread.o)
objects-argon2-simd-pthread=$(src-argon2-simd:.c=.pthread.o)

outdir=lib
$(shell if [ ! -d $(outdir) ]; then mkdir $(outdir); fi)

# Configure object files to be built
ifdef NO_PTHREAD
objects += $(objects-argon2)
ifdef NO_SIMD
objects += $(objects-argon2-ref)
else
objects += $(objects-argon2-simd)
endif
else
objects += $(objects-argon2-pthread)
ifdef NO_SIMD
objects += $(objects-argon2-ref-pthread)
else
objects += $(objects-argon2-simd-pthread) 
endif
endif

# Output targets
lib=$(outdir)/argon2_mariadb.so

$(lib): $(objects)
	$(CC) -o $@ $^ $(CFLAGS)
.PHONY: $(lib)

src/%.o: src/%.c
	$(CC) -c -o $@ $< $(CFLAGS)

argon2/src/%.o: argon2/src/%.c
	$(CC) -c -o $@ $< $(CFLAGS) -DARGON2_NO_THREADS

argon2/src/%.pthread.o: argon2/src/%.c
	$(CC) -c -o $@ $< $(CFLAGS) -pthread

$(objects-argon2-simd): $(src-argon2-simd)
	$(CC) -c -o $@ $< $(CFLAGS) -mavx2 -msse2

$(objects-argon2-simd-pthread): $(src-argon2-simd)
	$(CC) -c -o $@ $< $(CFLAGS) -pthread -mavx2 -msse2

clean:
	rm -f $(objects) $(objects-argon2) $(objects-argon2-ref) $(objects-argon2-simd) $(objects-argon2-simd) $(objects-argon2-pthread) $(objects-argon2-ref-pthread) $(objects-argon2-simd-pthread) $(lib)
	rm -rf $(outdir)
.PHONY: clean
