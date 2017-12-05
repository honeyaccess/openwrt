#CFLAGS += -std=c99  # should also still work with -std=c89
#CFLAGS += -D_POSIX_C_SOURCE=199309 -D_BSD_SOURCE
CFLAGS += -W -Wall  # -W is spelled -Wextra these days, but -W is stilli
                    # valid and works with older compilers.
CFLAGS += -O2
# CFLAGS += -DPRECISION_SIOCGSTAMP
# CFLAGS += -DENABLE_DEBUG
# CFLAGS += -DUSE_OBSOLETE_GETTIMEOFDAY

LOADLIBES += -lpcap

all: cts_rts_util sniffer

cts_rts_util:
	$(CC) $(CFLAGS) src/hotspot_beacon.c -lpcap -o cts_rts_util

sniffer:
	$(CC) $(CFLAGS) src/sniffer.c -lpcap -o sniffer

clean:
	rm -f cts_rts_util sniffer *.o
