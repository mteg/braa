
###################################################################
########################### UNCOMMENT THE CORRECT SETTING FOR YOUR SYSTEM
###################################################################

# Linux, FreeBSD, OpenBSD
CFLAGS = 
LDFLAGS = 

# Solaris / SPARC
# CFLAGS = -DSOLARIS_SPARC
# LDFLAGS = -lnsl -lsocket

###################################################################
########################### AVOID TOUCHING ANYTHING BELOW THIS LINE
###################################################################

SOURCES= braaasn.c braaoids.c braaprotocol.c queries.c braa.c
OBJECTS = ${SOURCES:.c=.o}


OUT= braa

LIBS = 

all: ${OBJECTS}
	cc $(OBJECTS) -o $(OUT) $(LDFLAGS) $(LIBS)
	strip $(OUT)

clean:
	rm -rf $(OBJECTS) $(OUT)
	