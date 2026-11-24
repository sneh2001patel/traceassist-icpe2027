# Builds every symptom bench program. `make scenarios.json` lists every program's faults.
CC ?= gcc
CFLAGS ?= -O2 -g -Wall -Wextra -pthread
PROGRAMS = batch_server ticker crunch filestore pipeline kvstore cachesvc jobrunner reporter

all: $(PROGRAMS)

%: %.c bench.h
	$(CC) $(CFLAGS) -o $@ $< -lm

scenarios.json: $(PROGRAMS)
	@{ echo '['; first=1; for p in $(PROGRAMS); do \
	     [ $$first = 1 ] || echo ','; first=0; ./$$p --list-faults; done; echo ']'; } > $@
	@echo "wrote $@"

clean:
	rm -f $(PROGRAMS) scenarios.json

.PHONY: all clean
