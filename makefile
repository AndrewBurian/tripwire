EXECUTABLE=tripwire
CFLAGS=-c -g -O0 -Wall
CC=gcc
LDFLAGS=
LIBS=
OBJECTS=$(SOURCES:.c=.o)

SOURCES=src/main.c src/log.c src/portwatch.c src/synwatch.c src/confread.c \
	src/ratelimit.c src/logfile.c src/logformat.c src/logsyslog.c src/logremote.c

all: $(SOURCES) $(EXECUTABLE)

install-initv: $(EXECUTABLE)
	install -D $(EXECUTABLE) $(DSTDIR)/usr/bin/$(EXECUTABLE)
	install -d $(DSTDIR)/var/log/$(EXECUTABLE)
	install -d $(DSTDIR)/etc/$(EXECUTABLE)/
	install $(EXECUTABLE).conf $(DSTDIR)/etc/$(EXECUTABLE)/
	install init/initv.script $(DSTDIR)/etc/init.d/$(EXECUTABLE)

install-systemd: $(EXECUTABLE)
	install -D $(EXECUTABLE) $(DSTDIR)/usr/bin/$(EXECUTABLE)
	install -d $(DSTDIR)/var/log/$(EXECUTABLE)
	install -d $(DSTDIR)/etc/$(EXECUTABLE)/
	install $(EXECUTABLE).conf $(DSTDIR)/etc/$(EXECUTABLE)/
	install init/systemd.service $(DSTDIR)/lib/systemd/system/$(EXECUTABLE).service
	systemctl daemon-reload

uninstall:
	rm -f $(DSTDIR)/usr/bin/$(EXECUTABLE)
	rm -rf $(DSTDIR)/etc/$(EXECUTABLE)
	rm -f $(DSTDIR)/etc/init.d/$(EXECUTABLE)
	rm -f $(DSTDIR)/usr/lib/systemd/system/$(EXECUTABLE).service

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@ $(LIBS)

.c.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm $(OBJECTS) $(EXECUTABLE)
