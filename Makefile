CFLAGS=-O2 -Wall -I argon2/include -I b64/include -fPIC

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

outdir=build
# Static library dir
slibdir=slib
$(shell if [ ! -d $(outdir) ]; then mkdir $(outdir); fi)
$(shell if [ ! -d $(slibdir) ]; then mkdir $(slibdir); fi)

# Static library files
slib-argon2=$(slibdir)/argon2.a
slib-argon2-simd=$(slibdir)/argon2-simd.a
slib-argon2-pthread=$(slibdir)/argon2-pthread.a
slib-argon2-simd-pthread=$(slibdir)/argon2-simd-pthread.a

# Configure argon2 features by setting static lib target
ifdef NO_PTHREAD
CFLAGS += -DARGON2_NO_THREADS
ifdef NO_SIMD
slib-argon2-target=$(slib-argon2)
else
slib-argon2-target=$(slib-argon2-simd)
endif
else
ifdef NO_SIMD
slib-argon2-target=$(slib-argon2-pthread)
else
slib-argon2-target=$(slib-argon2-simd-pthread)
endif
endif

# Output targets
lib=$(outdir)/argon2_mariadb.so

$(lib): $(objects) $(slib-argon2-target)
	$(CC) -shared -o $@ $^ $(CFLAGS)

# Static lib targets
$(slib-argon2): $(objects-argon2) $(objects-argon2-ref)
	$(AR) rcs $@ $^
$(slib-argon2-simd): $(objects-argon2) $(objects-argon2-simd)
	$(AR) rcs $@ $^
$(slib-argon2-pthread): $(objects-argon2-pthread) $(objects-argon2-ref-pthread)
	$(AR) rcs $@ $^
$(slib-argon2-simd-pthread): $(objects-argon2-pthread) $(objects-argon2-simd-pthread)
	$(AR) rcs $@ $^

src/%.o: src/%.c
	$(CC) -c -o $@ $< $(CFLAGS)

argon2/src/%.o: argon2/src/%.c
	$(CC) -c -o $@ $< $(CFLAGS)

argon2/src/%.pthread.o: argon2/src/%.c
	$(CC) -c -o $@ $< $(CFLAGS) -pthread

$(objects-argon2-simd): $(src-argon2-simd)
	$(CC) -c -o $@ $< $(CFLAGS) -mavx2 -msse2

$(objects-argon2-simd-pthread): $(src-argon2-simd)
	$(CC) -c -o $@ $< $(CFLAGS) -pthread -mavx2 -msse2

clean:
	rm -f $(objects) $(objects-argon2) $(objects-argon2-ref) $(objects-argon2-simd) $(objects-argon2-simd) $(objects-argon2-pthread) $(objects-argon2-ref-pthread) $(objects-argon2-simd-pthread) $(lib)
	rm -rf $(outdir) $(slibdir)
.PHONY: clean