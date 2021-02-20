#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <endian.h>
#include <err.h>

#include "aes_decrypt.h"

/*
This code reads the files made by pcap_pdu_extractor.c and stored in folder dumps/ and extracts the audio stream.

Steps to use:
1) read the comment in pcap_pdu_extractor.c, compile and execute
2) adjust NB_OF_PACKETS to number spit out by the extractor-tool
3) !! INSERT REAL KEY INTO aes_decrypt.c !! Otherwise you will get complete garbage!
4) run ./make_audio to compile (Yes i still don't know makefiles...)
5) execute
6) final result is "output.mp2", can be played with VLC

If you get a segfault make sure SZ_MALLOC_OUTPUT_DATA is big enough.

(c) 2021 by kitten_nb_five

freenode #lkv373a

THIS CODE IS RELEASED UNDER AGPLv3+ AND PROVIDED WITHOUT ANY WARRANTY!
*/

//adjust this!
#define NB_OF_PACKETS 4100

//increase this if needed!
#define SZ_MALLOC_OUTPUT_DATA 5*1024*1024

int main(void)
{
	uint16_t packet_nr;
	
	uint8_t data_from_file[576];
	
	uint8_t data_decrypted[576];
	
	uint8_t *accumulated_data=malloc(SZ_MALLOC_OUTPUT_DATA); 
	if(!accumulated_data)
		err(1, "malloc");
	
	uint32_t sz_accumulated=0;

	for(packet_nr=0; packet_nr<NB_OF_PACKETS; packet_nr++)
	{
		char name[40];
		sprintf(name, "dumps/dump-%05d.bin", packet_nr);
		printf("reading file %s: ", name);		
		
		FILE *inp=fopen(name, "rb");
		if(!inp)
			err(1, "fopen %s", name);
		fseek(inp, 0, SEEK_END);
		uint32_t filesz=ftell(inp);
		fseek(inp, 0, SEEK_SET);
		
		if(filesz!=576+12)
		{
			printf("wrong size for audio, ignoring\n");
			fclose(inp);
			continue;
		}
	
		uint8_t magic[4];
		const uint8_t magic_audio[4]={0x74, 0x47, 0x74, 0x81};
				
		if(fread(magic, 4, 1, inp)!=1)
			err(1, "fread magic");
		
		printf("magic: %02X %02X %02X %02X ", magic[0], magic[1], magic[2], magic[3]);
		
		if(memcmp(magic, magic_audio, 4))
		{
			printf("wrong magic for audio, ignoring\n");
			fclose(inp);
			continue;
		}
		
		printf("audio, processing...\n");
		
		uint8_t tmp_data[8];
		
		if(fread(tmp_data, 8, 1, inp)!=1)
			err(1, "fread tmp_data==size+counter");
		
		uint32_t length=be32toh(*(uint32_t*)(tmp_data));
		uint32_t counter=be32toh(*(uint32_t*)(tmp_data+4));
		(void)counter; //ignore this, we dont need it (yet?)
		
		if(length!=576+4)
			errx(1, "wrong length, this should not happen at this point");
		
		if(fread(data_from_file, 576, 1, inp)!=1)
			err(1, "fread data_from_file");
		
		fclose(inp);
		
		if(decrypt(data_from_file, 576, data_decrypted)!=576)
			errx(1, "decrypt returned wrong size");
		
		memcpy(accumulated_data+sz_accumulated, data_decrypted, 576);
		sz_accumulated+=576;
	}
				
	FILE *outp=fopen("output.mp2", "wb");
	if(!outp)
		err(1, "fopen output.mp2");
	if(fwrite(accumulated_data, sz_accumulated, 1, outp)!=1)
		err(1, "fwrite output.mp2");
	fclose(outp);

	free(accumulated_data);
	
	printf("\n");
	printf("%u bytes written to output.mp2. exiting.\n", sz_accumulated);
	return 0;
}
