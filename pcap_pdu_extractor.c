#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

/*
This code extracts the payload of the UDP-packets from a "special" Wireshark-capture and saves them as raw binary in a folder called "dumps" (that you must create) for further processing/analysis.


By "special" capture i mean it's not a regular pcap*ng* file but a file in the older pcap format that contains "exported PDU".

Just do you regular capture in Wireshark, then click ->file ->export PDU into file. The filter you need (for 373A V4) is "udp && udp.dstport eq 7777" and you must select OSI Layer 4. Make sure you select the old pcap format and not the standard pcap*ng* when saving!

Why use this PDU-stuff? Because its convenient. Wireshark will assemble all fragmented IP-stuff that the 373A seems to spit out, remove all Ethernet/IP/UDP-header-stuff we don't need, remove all other network traffic (except if you have something talking to UDP-port 7777, but in this case you could also filter by IP address or so) and save everything into a file that is easy to parse.


A pcap-file that contains exported PDU contains a global header, then each packet preceeded by a packet header and some metadata.

For details you can check https://www.tcpdump.org/linktypes.html and https://code.wireshark.org/review/gitweb?p=wireshark.git;a=blob;f=epan/exported_pdu.h;hb=refs/heads/master

The last metadata-entry has length 0.


To use this code adjust NAME_PCAP_FILE, compile (gcc, no special flags or libs needed) and execute. If you have really a lot of data you may want to increase the number of digits for the outputfile names. If you have BIG packets you might need to increase PACKET_PAYLOAD_MAX_SIZE.


This code is based on some old experiments of mine, it might not be pretty but it works. I avoided UNIX-stuff so you can compile this under Windows too.


(c) 2021 by kitten_nb_five

freenode #lkv373a

THIS CODE IS RELEASED UNDER AGPLv3+ AND PROVIDED WITHOUT ANY WARRANTY!
*/

#define NAME_PCAP_FILE "tx_reset_pdu.pcap"

#define PACKET_PAYLOAD_MAX_SIZE (100*1024)


// --- dont change the following definitions and defines! ---

//global header
typedef struct __attribute__ ((packed)) pcap_hdr_s {
        uint32_t magic_number;   /* magic number */
        uint16_t version_major;  /* major version number */
        uint16_t version_minor;  /* minor version number */
        int32_t  thiszone;       /* GMT to local correction */
        uint32_t sigfigs;        /* accuracy of timestamps */
        uint32_t snaplen;        /* max length of captured packets, in octets */
        uint32_t network;        /* data link type */
} pcap_hdr_t;

//packet header
typedef struct __attribute__ ((packed)) pcaprec_hdr_s {
        uint32_t ts_sec;         /* timestamp seconds */
        uint32_t ts_usec;        /* timestamp microseconds */
        uint32_t incl_len;       /* number of octets of packet saved in file */
        uint32_t orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

#define PCAP_MAGIC 0xa1b2c3d4
#define PCAP_SWAPPED_MAGIC 0xd4c3b2a1

void swap2(uint16_t * const val)
{
	*val=(*val>>8)|((*val&0xFF)<<8);
}

void myerr(char const * const msg)
{
	printf("ERROR: %s\n", msg);
	exit(1);
}

uint8_t get_packet_payload(FILE * f, pcaprec_hdr_t * const header, uint8_t * const data, int * const size)
{
	if(fread(header, sizeof(pcaprec_hdr_t), 1, f)!=1) //TODO check for EOF or error
		return 0;
	
	//we need to go through the PDU-metadata as it's variable length and there is no other way to know where the actual packet payload starts
	uint16_t opt_code;
	uint16_t opt_length;
	int total_length_pdu=0;
		
	do
	{
		if(fread(&opt_code, 2, 1, f)!=1)
			myerr("fread opt_code");
		if(fread(&opt_length, 2, 1, f)!=1)
			myerr("fread opt_length");
		swap2(&opt_code);
		swap2(&opt_length);
		
		//add some printf here if you are interested...
		
		//just skip the content, we don't need it
		fseek(f, opt_length, SEEK_CUR);
		
		total_length_pdu+=opt_length+2+2;
		
	} while(opt_length!=0);
	
	int payload_length=header->incl_len-total_length_pdu; //defined as int in the header so use plain int and not *_t for the variable
	
	if(payload_length>PACKET_PAYLOAD_MAX_SIZE)
		myerr("buffer for payload/data is too small, increase PACKET_MAX_SIZE");
	
	if(fread(data, payload_length, 1, f)!=1)
		myerr("fread packet payload failed");
	
	*size=payload_length;
	
	return 1;
}

void dump_to_file(uint8_t const * const data, const int size, const uint32_t dump_nr)
{
	char name[30];
	sprintf(name, "dumps/dump-%05d.bin", dump_nr);
	FILE *f=fopen(name, "wb");
	if(!f)
		myerr("fopen of dumpfile failed - does the folder \"dumps\" exist?");
	fwrite(data, size, 1, f);
	fclose(f);
}

int main(void)
{
	FILE *file=fopen(NAME_PCAP_FILE, "rb");
	if(file==NULL)
		myerr("fopen of NAME_PCAP_FILE failed");
	
	pcap_hdr_t global_header;
	
	if(fread(&global_header, sizeof(pcap_hdr_t), 1, file)!=1)
		myerr("fread global header failed");
	
	if(global_header.magic_number==PCAP_SWAPPED_MAGIC)
		myerr("global_header.magic_number: swap needed but not supported");
	else if(global_header.magic_number!=PCAP_MAGIC)
		myerr("invalid global_header.magic_number");
	
	if(global_header.network!=252) //i don't really remember what this means, check with the documentation or the Wireshark code and adjust if you want to use this source code for other stuff...
		myerr("global_header.network!=252");
	
	pcaprec_hdr_t packet_header;
	uint8_t * packet_payload=malloc(PACKET_PAYLOAD_MAX_SIZE);
	if(!packet_payload)
		myerr("malloc packet_payload failed");
	
	int payload_size;

	uint32_t counter=0;
	
	while(get_packet_payload(file, &packet_header, packet_payload, &payload_size))
		dump_to_file(packet_payload, payload_size, counter++); 

	fclose(file);
	
	printf("%u packets saved to disk. exiting.\n", counter);
	
	return 0;
}
