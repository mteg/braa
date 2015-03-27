
struct braa_oid
{
	int len;
	u_int32_t *oid;
};

typedef struct braa_oid oid;

oid * braa_OID_Duplicate(oid * o);
void braa_OID_Dispose(oid *o);
void braa_OID_ToString(oid * o, unsigned char * buffer, int buffer_len);
oid * braa_OID_CreateFromString(unsigned char* str);
oid * braa_OID_CreateFromArray(u_int32_t *arr, int len);
int braa_OID_Compare(oid *a, oid *b);
int braa_OID_CompareN(oid *a, oid *b);
