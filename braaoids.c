#include <sys/types.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include "braaasn.h"
#include "braaoids.h"

oid * braa_OID_Duplicate(oid * o)
{
	oid * n = (oid*) gmalloc(o->len * sizeof(uint32_t) + sizeof(oid));
	
	n->oid = (uint32_t*) (n + 1);
	n->len = o->len;

	memcpy(n->oid, o->oid, sizeof(uint32_t) * o->len);
	return(n);
}

void braa_OID_Dispose(oid *o)
{
	free(o);
}

void braa_OID_ToString(oid * o, unsigned char * buffer, int buffer_len)
{
	int l = 0, i;
	
	buffer[0] = 0;
	for(i = 0; i<o->len; i++)
	{
		unsigned char ib[14];
		int n;
		
		n = snprintf(ib, 12, ".%d", o->oid[i]);
		if((l + n + 1) < buffer_len)
			sprintf(buffer, "%s%s", buffer, ib);
		else
			break;
	}
}

#define MEMSTEP 16

oid * braa_OID_CreateFromString(unsigned char* str)
{
	oid * n;
	uint16_t s = 0;

	assert(n = (oid*) gmalloc(sizeof(oid)));
	n->oid = NULL;
	n->len = 0;
	n->oid = (uint32_t*) (n + 1);
	
	while(*str)
	{
		uint32_t digit = 0;
		int valid = 0;
		
		if(*str == '.')
		{
			char * end;
			
			str++;
			digit = strtoul(str, &end, 10);
			if(((unsigned char *) end) != str)
			{
				str = end;
				valid = 1;
				if((((s + 1) / MEMSTEP) != (s / MEMSTEP)) || s == 0)
				{
					n = (oid*) realloc(n, (((s + 2) / MEMSTEP) + 1) * MEMSTEP * sizeof(uint32_t) + sizeof(oid));
					n->oid = (uint32_t*) (n + 1);
				}
//				debug("Assigning...\n");
				n->oid[s++] = digit;
				debug("DIGIT: %d\n", digit);
//				debug("Digit decomposed\n");
			}
		}
		
		if(!valid)
		{
			free(n);
			return(NULL);
		}
	}
	n->len = s;
#ifdef DEBUG
	{
		int b;
		for(b = 0; b < s; b++)
			printf("OID DIGIT: %d (of %d)\n", n->oid[b], b);
	}
#endif
	
	return(n);
}

oid * braa_OID_CreateFromArray(uint32_t *arr, int len)
{
	oid * n;
	assert(n = (oid*) gmalloc(sizeof(oid) + sizeof(uint32_t) * len));

	n->oid = (uint32_t*) (n + 1);
	n->len = len;
	memcpy(n->oid, arr, sizeof(uint32_t) * len);
	return(n);
}

int braa_OID_Compare(oid *a, oid *b)
{
	if(a->len != b->len) return(0);
	if(!memcmp(a->oid, b->oid, a->len * sizeof(uint32_t))) return(1);
	return(0);
}

int braa_OID_CompareN(oid *shorter, oid *b)
{
	if(shorter->len > b->len) return(0);
	if(!memcmp(shorter->oid, b->oid, shorter->len * sizeof(uint32_t))) return(1);
	return(0);
}
