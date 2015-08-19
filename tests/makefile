
# get the top level makefile
include ../makefile

ADDSOURCES=src/tests.c
WRAPS=

TESTSOURCES=$(ADDSOURCES) $(foreach src, $(SOURCES), ../$(src))
TESTOBJECTS=$(TESTSOURCES:.c=.o)
TESTEXECUTABLE=$(EXECUTABLE).test
TESTWRAPS=main $(WRAPS)
LDWRAP=$(foreach funct, $(TESTWRAPS), -Wl,--wrap=$(funct))
.DEFAULT_GOAL=test

test: $(TESTEXECUTABLE)

$(TESTEXECUTABLE): $(TESTOBJECTS)
	$(CC) $(LDFLAGS) $(LDWRAP) $(TESTOBJECTS) -o $@ $(LIBS)

debug:
	gdb --tui $(TESTEXECUTABLE)

valgrind:
	valgrind --check-type=full $(TESTEXECUTABLE)

clean:
	rm $(TESTOBJECTS) $(TESTEXECUTABLE)
