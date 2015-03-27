
#ifdef SOLARIS_SPARC
typedef uint32_t u_int32_t;
typedef uint16_t u_int16_t;
typedef uint8_t u_int8_t;
typedef uint64_t u_int64_t;
#endif

// #define DEBUG
// #undef DEBUG

#ifdef DEBUG
#include <stdio.h>
#define debug(format, arg...) fprintf(stderr, format, ## arg)
#else
#define debug(format, arg...) {}
#endif


#define BRAAASN_INTEGER 0x02
#define BRAAASN_BITSTRING 0x03
#define BRAAASN_OCTETSTRING 0x04
#define BRAAASN_NULL 0x05
#define BRAAASN_OID 0x06

#define BRAAASN_SEQUENCE 0x30

#define BRAAASN_PDU_GETREQUEST 0xa0
#define BRAAASN_PDU_GETRESPONSE 0xa2
#define BRAAASN_PDU_GETNEXTREQUEST 0xa1
#define BRAAASN_PDU_SETREQUEST 0xa3
#define BRAAASN_PDU_UNKNOWN 0

#define BRAAASN_IPADDR 0x40
#define BRAAASN_COUNTER 0x41
#define BRAAASN_GAUGE 0x42
#define BRAAASN_TIMETICKS 0x43
#define BRAAASN_OPAQUE 0x44
#define BRAAASN_COUNTER64 0x46


#define BRAAASN_NSAPADDR 0x45
/* ^^Not supported */

struct braa_asnobject
{
	u_int8_t type;
	
	int32_t ldata;
	void * pdata;
};

typedef struct braa_asnobject asnobject;

static inline struct braa_asnobject * braa_ASNObject_Create(u_int8_t type, u_int32_t ldata, void * pdata)
{
	struct braa_asnobject * ret;
	assert(ret = (struct braa_asnobject*) malloc(sizeof(struct braa_asnobject)));
	ret->type = type;
	ret->ldata = ldata;
	ret->pdata = pdata;
	return(ret);
}

int braa_ASNObject_EncodeBER(struct braa_asnobject * data, u_int8_t * buffer, u_int32_t size);
struct braa_asnobject * braa_ASNObject_DecodeBER(u_int8_t * data, u_int32_t size);
void braa_ASNObject_Dispose(struct braa_asnobject * obj);
void braa_ASNObject_Dump(struct braa_asnobject * obj);
void braa_ASNObject_ToString(struct braa_asnobject * obj, unsigned char * buffer, int size, int hexdump);
asnobject * braa_ASNObject_CreateFromString(char * str);

#define BRAA_ERROR_UNKNOWN 0
#define BRAA_ERROR_TOOBIG 1
#define BRAA_ERROR_NOSUCHNAME 2
#define BRAA_ERROR_BADVALUE 3
#define BRAA_ERROR_READONLY 4
#define BRAA_ERROR_GENERIC 5

#define BRAA_VERSION_SNMP1 0
#define BRAA_VERSION_SNMP2C 1

#define gmalloc(x) malloc(x)
#define grealloc(x, y) realloc(x, y)
