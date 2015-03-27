#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "assert.h"
#include "braaoids.h"
#include "braaasn.h"

#define BRAAASN_BER_MAXDEPTH 10

static u_int32_t braa_EncodeShortBitstring(u_int8_t * buffer, u_int32_t v)
{
	int i, len = 0;
	
	for(i = 0; i < 4; i++)
	{
		u_int32_t c;
		debug("  Bitstring: enc: %x AND %x\n", v, v & 0xff800000);
		if((v & 0xff800000) || len != 0 || i == 3)
		{
			c = v >> 24;
			buffer[len++] = c;
		}
		v <<= 8;
				
	}
	return(len);
}

static u_int32_t braa_EncodeShortBitstringOid(u_int8_t * buffer, u_int32_t v)
{
/*	0 - 6
	0 - 13
	0 - 20
	0 - 27*/
	
	if(! (v & 0xffffff80))
	{
		buffer[0] = v & 0x7f;
		return(1);
	}
	else if(! (v & 0xffffc000))
	{
		buffer[0] = ((v >> 7) & 0x7f) | 0x80;
		buffer[1] = v & 0x7f;
		return(2);
	}
	else if(! (v & 0xffe00000))
	{
		buffer[0] = ((v >> 14) & 0x7f) | 0x80;
		buffer[1] = ((v >> 7) & 0x7f) | 0x80;
		buffer[2] = (v & 0x7f);
		return(3);
	}
	else
	{
		buffer[0] = ((v >> 21) & 0x7f) | 0x80;
		buffer[1] = ((v >> 14) & 0x7f) | 0x80;
		buffer[2] = ((v >> 7) & 0x7f) | 0x80;
		buffer[3] = (v & 0x7f);
		return(4);
	}
}


static u_int32_t braa_FetchShortBitstring(u_int8_t * data, int max, u_int8_t * status)
{
	u_int32_t ret = 0;
	int i;
	
	for(i = 0; i < 4 && i < max; i++)
	{
		ret <<= 7;
		ret |= data[i] & 0x7f;
		if(!(data[i] & 0x80))
		{
			*status = i + 1;
			return(ret);
		}
		
	}
	*status = 0;
	return(0);
}



struct braa_asnobject * braa_InternalDecodeBER(u_int8_t * data, u_int32_t size, int level, int *bytesused)
{
	u_int8_t tag;
	u_int8_t type, structured;
	u_int32_t len;
	int bu = 0;

	if(level > BRAAASN_BER_MAXDEPTH) 
	{
		debug("!!! MAXDEPTH REACHED\n");
		return(NULL); /* maximal recursion depth limit */
	}
	if(size < 2)
	{
		debug("!!! MESSAGE TOO SHORT (size=%d, type=%x)\n", size, *data);
		return(NULL); /* too short message */
	}
	debug("BEGIN decoding (@%x, %d)\n", data, size);
	
	tag = *data;
	debug("  TYPE: %x\n", tag);
	type = tag & 0xdf;
	structured = tag & 0x20;

	if((type & 0x1f) == 0x1f)
	{
		debug("!!! Type not supported!\n");
		return(NULL); /* not supported */
	}
	
	data++;
	size--; bu++;
	
	len = *data;
	if(len == 0x80)
	{
		unsigned int i;
		len = 0; /* indefinite length */
		data += 1;
		size -= 1; bu += 1;
		for(i = 0; i< (size - 1); i++)
		{
			if(data[i] == 0 && data[i + 1] == 0)
			{
				len = i;
				break;
			} 
		}
	}
	else
	{
		if(len & 0x80)
		{
		    int noct = len & 0x7f;
		    int j;
		    len = 0;
		    for(j = 0; j < noct; j++)
		    {
			len <<= 8;
			len |= data[j + 1];
		    }
		    data += noct + 1;
		    size -= noct + 1;
		    bu += noct + 1;
		}
		else
		{
		    data += 1;
		    size -= 1;
		    bu += 1;
		}
		
		if(len > size)
		{
			debug("!!! Message too long!\n");
			return(NULL);
		}
	}
	if(type == BRAAASN_NULL && size == 0)
	{
		*bytesused = bu;
		return(braa_ASNObject_Create(BRAAASN_NULL, 0, NULL));
	}
#ifdef DEBUG
	if(type == BRAAASN_NULL)
		debug("!!! Null of size %d\n", size);
#endif
	
	if(size <= 0)
	{
		debug("!!! Invalid size (short packet).\n");
		return(NULL); /* short packet */
	}
	switch(tag)
	{
		case BRAAASN_INTEGER:
		case BRAAASN_COUNTER:
		case BRAAASN_GAUGE:
		case BRAAASN_TIMETICKS:
		{
			int32_t v = 0;
			unsigned int i;
			
			debug(" => Decoding integer, %d bytes of data\n", len);
			
			for(i = 0; i < len; i++)
			{
				v <<= 8;
				v |= data[i];
			}
			
			if(data[0] & 0x80) /* negative */
			{
				int32_t compl;
				switch(len)
				{
					case 1: compl = 256; break;
					case 2: compl = 256 * 256; break;
					case 3: compl = 256 * 256 * 256; break;
					case 4: compl = 0; break;
				}
				v = v - compl;
			}
			
			bu += len;
			*bytesused = bu;
			debug(" => END decoding integer\n");
			return(braa_ASNObject_Create(tag, v, NULL));
		}
		case BRAAASN_COUNTER64:
		{
			u_int64_t v = 0;
			unsigned int i;
			u_int64_t *vptr;
			
			debug(" => Decoding 64-bit integer, %d bytes of data\n", len);
			
			for(i = 0; i < len; i++)
			{
				v <<= 8;
				v |= data[i];
			}
			
			bu += len;
			*bytesused = bu;
			
			vptr = (u_int64_t*) malloc(sizeof(u_int64_t));
			if(!vptr) return(NULL);
			*vptr = v;
			
			debug(" => END decoding 64-bit integer\n");
			return(braa_ASNObject_Create(tag, 0, vptr));
			
		}
		case BRAAASN_OCTETSTRING:
		{
			struct braa_asnobject * ret;
			u_int8_t * ostr = (u_int8_t *) malloc(len + 1);
			if(!ostr) return(NULL); /* No memory */
			memcpy(ostr, data, len);
			ostr[len] = 0;
			bu += len;
			*bytesused = bu;
			ret = braa_ASNObject_Create(tag, len, ostr);
			if(!ret) free(ostr);	/* ... paranoid */
			debug(" => END decoding octet string\n");
			return(ret);
		}
		case BRAAASN_IPADDR:
		{
			int32_t i;
			if(len != 4)
			{
				debug(" => decoding IP address: invalid size, %d instead of 4\n", len);
				return(NULL);
			}
			memcpy(&i, data, 4);
			bu += 4;
			*bytesused = bu;
			return(braa_ASNObject_Create(tag, i, NULL));
		}
		case BRAAASN_OID:
		{
			struct braa_asnobject * ret;
			int pos = 0;
			u_int32_t * ostr = (u_int32_t *) malloc((len * 4) + 4);
			u_int32_t id;
			u_int8_t status;
			
			if(!ostr) return(NULL); /* Out of mem. */
			id = braa_FetchShortBitstring(data, len, &status);
			if(!status) { free(ostr); return(NULL); }
			data += status;
			len -= status; bu += status;
			
			if(id <= 39)
			{
				ostr[0] = 0;
				ostr[1] = id;
			}
			else if(id <= 79)
			{
				ostr[0] = 1;
				ostr[1] = id - 40;
			}
			else
			{
				ostr[0] = 2;
				ostr[1] = id - 80;
			}
			pos = 2;
			
			while(len > 0)
			{
				id = braa_FetchShortBitstring(data, len, &status);
				if(!status) { free(ostr); return(NULL); }
				data += status;
				len -= status; bu += status;
				ostr[pos++] = id;
			}
			ret = braa_ASNObject_Create(tag, 0, braa_OID_CreateFromArray(ostr, pos));
			free(ostr);
			*bytesused = bu;
			debug(" => END decoding OID\n");
			return(ret);
		}
		case BRAAASN_SEQUENCE:
		case BRAAASN_PDU_GETREQUEST:
		case BRAAASN_PDU_GETNEXTREQUEST:
		case BRAAASN_PDU_SETREQUEST:
		case BRAAASN_PDU_GETRESPONSE:
		{
			struct braa_asnobject * ret;
			int childbytes;
			struct braa_asnobject ** children = NULL;
			struct braa_asnobject ** paranoidchildren = NULL;
			int n = 0;
			
			while(len > 0)
			{
				struct braa_asnobject * child;
				child = braa_InternalDecodeBER(data, len, level + 1, &childbytes);
				
				if(!child)
				{
					int i;
					for(i = 0; i < n; i++) braa_ASNObject_Dispose(children[i]);
					free(children);
					return(NULL);
				}
				
				data += childbytes; 
				len -= childbytes; bu += childbytes;
				
				paranoidchildren = (struct braa_asnobject**) realloc(children, (n + 1) * sizeof(struct braa_asnobject*));
				if(!paranoidchildren)
				{
					int i;
					for(i = 0; i < n; i++) braa_ASNObject_Dispose(children[i]);
					free(children);
					return(NULL);
				}
				children = paranoidchildren;
				debug("ADDING TO SEQUENCE: bytes: %d, new len %d\n", childbytes, len);
				children[n++] = child;
			}
			ret = braa_ASNObject_Create(tag, n, children);
			if(!ret)
			{
				int i;
				for(i = 0; i < n; i++) braa_ASNObject_Dispose(children[i]);
				free(children);
				return(NULL);
			}
			debug(" => END decoding sequence\n");
			*bytesused = bu;
			return(ret);
		}
		default:
			debug("Object type %x not supported.", type);
			return(NULL);
			
		
	}
	
}

int braa_ASNObject_EncodeBER(struct braa_asnobject * data, u_int8_t * buffer, u_int32_t size)
{
	int len = 0;
	if(size < 3) 
	{
		return(-1);
		debug("@%x: No space left\n", buffer);
	}
	buffer[0] = data->type;
	
	debug("@%x: Encoding: %d\n", buffer, data->type);
	
	switch(data->type)
	{
		case BRAAASN_INTEGER:
		case BRAAASN_COUNTER:
		case BRAAASN_GAUGE:
		case BRAAASN_TIMETICKS:
		{
			u_int32_t v = data->ldata;
			
			if(size < 7)
			{
				debug("@%x: No space left for integer\n", buffer);
				return(-1);
			}

			
			len = braa_EncodeShortBitstring(buffer + 2, v);
			break;
		}
		case BRAAASN_OCTETSTRING:
		{
			unsigned char * str = data->pdata;
			
			if(((len = strlen(str)) + 2) > size)
			{
				debug("@%x: No space left for octetstring\n", buffer);
				return(-1);
			}

			if(len > 255) return(-2);
			memcpy(buffer + 2, str, len);
			break;
		}
		case BRAAASN_IPADDR:
		{
			if(6 > size)
			{
				debug("@%x: No space left for ipaddr\n", buffer);
				return(-1);
			}
			len = 4;
			memcpy(buffer + 2, &data->ldata, 4);
			break;
		}
		case BRAAASN_OID:
		{
			u_int32_t * ostr = ((oid*) data->pdata)->oid;
			int n = ((oid*) data->pdata)->len;
			int pos;
			
			if(size < 3) return(-3);
			buffer[2 + (len++)] = ostr[0] * 40 + ostr[1];
			
			for(pos = 2; pos < n; pos++)
			{
				if((len + 8) > size)
				{
					debug("@%x: No space left for OID\n", buffer);
					return(-1);
				}

				len += braa_EncodeShortBitstringOid(buffer + len + 2, ostr[pos]);
			}
			break;
		}
		case BRAAASN_SEQUENCE:
		case BRAAASN_PDU_GETREQUEST:
		case BRAAASN_PDU_GETNEXTREQUEST:
		case BRAAASN_PDU_SETREQUEST:
		case BRAAASN_PDU_GETRESPONSE:
		{
			struct braa_asnobject ** children = data->pdata;
			int n = data->ldata;
			int i;
			for(i = 0; i<n; i++)
			{
				int cl;
				cl = braa_ASNObject_EncodeBER(children[i], buffer + 2 + len, size - 2 - len);
				if(cl < 0)
				{
					debug("@%x: Child complains about free space (%d)\n", buffer, cl);
					return(-1);
				}

				len += cl;
			}
			break;			
		}
		case BRAAASN_NULL:
			break;
		
	}

	debug("@%x: Done encoding: %d length %d\n", buffer, data->type, len);
	
	if(len > 127)
	{
	    if(len > 255)
	    {
	        if((len + 2) >= size) return(-1);
		memmove(buffer + 4, buffer + 2, len);
		buffer[1] = 0x82;
		buffer[2] = (len & 0xff00) >> 8;
	        buffer[3] = len & 0xff;
		return(4 + len);
	    }
	    else
	    {
	        if((len + 1) >= size) return(-1);
		memmove(buffer + 3, buffer + 2, len);
		buffer[1] = 0x81;
	        buffer[2] = len & 0xff;
		return(3 + len);
	    }
	}
	else
	{
	    buffer[1] = len;
	}
	return(2 + len);
	
}

struct braa_asnobject * braa_ASNObject_DecodeBER(u_int8_t * data, u_int32_t size)
{
	int bu;
	struct braa_asnobject * bi;
	debug("Decoding STARTED\n");
	bi = braa_InternalDecodeBER(data, size, 0, &bu);
	debug("Decoding FINISHED\n");
	return(bi);
}

void braa_ASNObject_Dispose(struct braa_asnobject * obj)
{
	int i, n;
	switch(obj->type)
	{
		case BRAAASN_OID:
			debug("=> Disposing OID...\n");
			braa_OID_Dispose(obj->pdata);
			break;
		case BRAAASN_OCTETSTRING:
			debug("=> Disposing string...\n");
			free(obj->pdata);
			debug("OK\n");
			break;
		case BRAAASN_COUNTER64:
			debug("=> Disposing Counter64...\n");
			free(obj->pdata);
			debug("OK\n");
			break;
		case BRAAASN_SEQUENCE:
		case BRAAASN_PDU_GETREQUEST:
		case BRAAASN_PDU_GETRESPONSE:
		case BRAAASN_PDU_SETREQUEST:
		case BRAAASN_PDU_GETNEXTREQUEST:
			debug("=> Disposing SEQUENCE...\n");
			for(i = 0, n = obj->ldata; i < n; i++)
				braa_ASNObject_Dispose(((struct braa_asnobject **) obj->pdata)[i]);
			free(obj->pdata);
			break;
		default:
			break;
	}
	free(obj);
}

static void braa_InternalDumpASNObject(struct braa_asnobject * obj, int lvl)
{
	unsigned char indent[50];
	int i;
	for(i = 0; i < 49 && i < (lvl * 2); i++)
		indent[i] = ' ';
	indent[i] = 0;
	
	switch(obj->type)
	{
		case BRAAASN_NULL:
			fprintf(stderr, "%s=> Null object\n", indent);
			break;
		case BRAAASN_INTEGER:
			fprintf(stderr, "%s=> Integer: %d\n", indent, obj->ldata);
			break;
		case BRAAASN_COUNTER:
			fprintf(stderr, "%s=> Counter: %d\n", indent, obj->ldata);
			break;
		case BRAAASN_GAUGE:
			fprintf(stderr, "%s=> Gauge: %d\n", indent, obj->ldata);
			break;
		case BRAAASN_TIMETICKS:
			fprintf(stderr, "%s=> Timeticks: %d\n", indent, obj->ldata);
			break;
		case BRAAASN_OCTETSTRING:
			fprintf(stderr, "%s=> String: '%s'\n", indent, (char*) obj->pdata);
			break;
		case BRAAASN_COUNTER64:
			fprintf(stderr, "%s=> Counter64: '%Ld'\n", indent, *((u_int64_t*) obj->pdata));
			break;
		case BRAAASN_IPADDR:
			{
				struct in_addr in;
				in.s_addr = obj->ldata;
				fprintf(stderr, "%s=> IPAddress: '%s'", indent, inet_ntoa(in));
			}
			break;
		case BRAAASN_OID:
			{
				u_int32_t * o = ((oid*) obj->pdata)->oid;
				unsigned long len = ((oid*) obj->pdata)->len;
				int i;
				
				fprintf(stderr, "%s=> OID: ", indent);
				for(i = 0; i<len; i++) fprintf(stderr, ".%d", o[i]);
				fprintf(stderr, "\n");
				break;
			}
		case BRAAASN_SEQUENCE:
		case BRAAASN_PDU_GETNEXTREQUEST:
		case BRAAASN_PDU_GETREQUEST:
		case BRAAASN_PDU_SETREQUEST:
		case BRAAASN_PDU_GETRESPONSE:
			{
				struct braa_asnobject ** children = obj->pdata;
				unsigned long len = obj->ldata;
				int i;
				
				fprintf(stderr, "%s=> Sequence/PDU:\n", indent);
				for(i = 0; i<len; i++)
					braa_InternalDumpASNObject(children[i], lvl + 1);
				break;
			}
		default:
			fprintf(stderr, "%s=> (Unknown object)\n", indent);
			break;
			
		
	}
	
}

void braa_ASNObject_Dump(struct braa_asnobject * obj)
{
//	fprintf(stderr, "Dumping message...\n");
	braa_InternalDumpASNObject(obj, 0);
}

void braa_ASNObject_ToString(struct braa_asnobject * obj, unsigned char * buffer, int size, int hexdump)
{
	switch(obj->type)
	{
		case BRAAASN_NULL:
			snprintf(buffer, size, "(null object)");
			break;
		case BRAAASN_COUNTER64:
			snprintf(buffer, size, "%Ld", *((u_int64_t*) obj->pdata));
			break;
		case BRAAASN_INTEGER:
		case BRAAASN_GAUGE:
			snprintf(buffer, size, "%d", obj->ldata);
			break;
		case BRAAASN_COUNTER:
		case BRAAASN_TIMETICKS:
			snprintf(buffer, size, "%u", obj->ldata);
			break;
		case BRAAASN_OCTETSTRING:
			if(hexdump)
			{
				int remains = size;
				char * ptr = buffer;
				unsigned char * data = (unsigned char*) obj->pdata;
				int len = obj->ldata;
				int i;
				
				for(i = 0; i<len; i++)
				{
					int c;
					snprintf(ptr, 3, "%02x", data[i]);
					ptr += 2; remains -= 2;
					if(remains < 5) break;
				}
				*ptr = 0;
			}
			else
			{
				snprintf(buffer, size, "%s", (char*) obj->pdata);
			}
			break;
		case BRAAASN_IPADDR:
			{
				struct in_addr in;
				in.s_addr = obj->ldata;
				snprintf(buffer, size, "%s", inet_ntoa(in));
			}
			break;
		case BRAAASN_OID:
			braa_OID_ToString((oid*) obj->pdata, buffer, size);
			break;
		case BRAAASN_SEQUENCE:
		case BRAAASN_PDU_GETREQUEST:
		case BRAAASN_PDU_GETNEXTREQUEST:
		case BRAAASN_PDU_GETRESPONSE:
		case BRAAASN_PDU_SETREQUEST:
			snprintf(buffer, size, "(Complex object type (tree))");
			break;
		default:
			snprintf(buffer, size, "(Unknown object type)");
			break;
			
		
	}
}

asnobject * braa_ASNObject_CreateFromString(char * str)
{
	int type = 0;
	
	if(*str == 'i')
	{
		str++;
		type = BRAAASN_INTEGER;
	}
	else if(*str == 's')
	{
		str++;
		type = BRAAASN_OCTETSTRING;
	}
	else if(*str == 'o')
	{
		str++;
		type = BRAAASN_OID;
	}
	else if(*str == 'a')
	{
		str++;
		type = BRAAASN_IPADDR;
	}
	else
	{
		if(*str == '.')
			type = BRAAASN_OID;
		else if(isdigit(*str))
			type = BRAAASN_INTEGER;
		else
			type = BRAAASN_OCTETSTRING;
	}
	
	switch(type)
	{
		case BRAAASN_OID:
		{
			oid * o = braa_OID_CreateFromString(str);
			if(!o) return(NULL);
			return(braa_ASNObject_Create(type, 0, o));
		}
		case BRAAASN_IPADDR:
		{
			int32_t ipa;
			struct in_addr ina;

			if(!inet_aton(str, &ina))
				return(NULL);

			ipa = ina.s_addr;
			return(braa_ASNObject_Create(type, ipa, NULL));
		}
		case BRAAASN_INTEGER:
		{
			char *ep;
			unsigned long n;
			n = strtol(str, &ep, 0);
			if(*ep) return(NULL);
			return(braa_ASNObject_Create(type, n, NULL));
		}
		case BRAAASN_OCTETSTRING:
			assert(str = strdup(str));
			return(braa_ASNObject_Create(type, strlen(str), str));
		default:
			return(NULL);
	}
}
