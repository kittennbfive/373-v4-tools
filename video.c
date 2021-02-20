#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <endian.h>
#include <err.h>

#include "aes_decrypt.h"

/*
This code reads the files made by pcap_pdu_extractor.c and stored in folder dumps/ and extracts the video stream.

Steps to use:
1) read the comment in pcap_pdu_extractor.c, compile and execute
2) adjust NB_OF_PACKETS to number spit out by the extractor-tool
3) !! INSERT REAL KEY INTO aes_decrypt.c !! Otherwise you will get complete garbage!
4) run ./make_video to compile (Yes i still don't know makefiles...)
5) execute
6) final result is "output.bin"

Notice: The output is a h.264 bitstream without any encapsulation(?) like mp4. VLC will NOT accept it, ffmpeg (or ffplay) however will do. You can use latter to make a valid mp4-file.

If you get a segfault make sure SZ_MALLOC_OUTPUT_DATA is big enough.

THIS IS HIGHLY EXPERIMENTAL STUFF! IT MAY NOT WORK!

(c) 2021 by kitten_nb_five

freenode #lkv373a

THIS CODE IS RELEASED UNDER AGPLv3+ AND PROVIDED WITHOUT ANY WARRANTY!
*/

//adjust this!
#define NB_OF_PACKETS 3245

//increase this if needed!
#define SZ_MALLOC_OUTPUT_DATA 20*1024*1024

int main(void)
{
	uint16_t packet_nr;
	
	uint8_t *packet_data=malloc(1*1024*1024);
	if(!packet_data)
		err(1, "malloc packet_data");
	
	uint8_t *data_decrypted=malloc(1*1024*1024);
	if(!data_decrypted)
		err(1, "malloc data_decrypted");
	
	uint8_t *output_data=malloc(SZ_MALLOC_OUTPUT_DATA);
	if(!output_data)
		err(1, "malloc output_data");
	uint32_t sz_output_data=0;
	
	bool flag_fragmented=false;
	
	for(packet_nr=0; packet_nr<NB_OF_PACKETS; packet_nr++)
	{
		char name[40];
		sprintf(name, "dumps/dump-%05d.bin", packet_nr);
		printf("file %s: ", name);
		
		FILE *inp=fopen(name, "rb");
		if(!inp)
			err(1, "fopen %s", name);
		fseek(inp, 0, SEEK_END);
		uint32_t filesz=ftell(inp);
		fseek(inp, 0, SEEK_SET);
		if(fread(packet_data, filesz, 1, inp)!=1)
			err(1, "fread %s", name);
		fclose(inp);
		
		uint8_t magic[4];
		memcpy(magic, packet_data, 4);
		
		const uint8_t magic_video_80[4]={0x74, 0x47, 0x74, 0x80};
		const uint8_t magic_audio[4]={0x74, 0x47, 0x74, 0x81};
		const uint8_t magic_82[4]={0x74, 0x47, 0x74, 0x82};
		const uint8_t magic_video_00[4]={0x74, 0x47, 0x74, 0x00};
		
		printf("filesize: %u magic: %02X %02X %02X %02X ", filesz, magic[0], magic[1], magic[2], magic[3]);
		
		if(!memcmp(magic, magic_video_80, 4))
		{
			uint32_t length=be32toh(*(uint32_t*)(packet_data+4));
			uint32_t counter=be32toh(*(uint32_t*)(packet_data+8));
			
			if(length-4>filesz)
				flag_fragmented=true;
			
			printf("video 80 l=%u c=%u %s", length, counter, flag_fragmented?"FRAGMENTED ":"");
			
			uint32_t crypted_size=(length-4)-(length-4)%16;
			
			if(crypted_size>1024)
			{
				printf("limiting crypted_size ");
				crypted_size=1024;
			}
			
			printf("%u bytes are crypted, processing...\n", crypted_size);

			//decrypt and copy crypted
			if(decrypt(packet_data+12, crypted_size, data_decrypted)!=crypted_size)
				errx(1, "decrypt returned wrong size");
		
			memcpy(output_data+sz_output_data, data_decrypted, crypted_size);
			sz_output_data+=crypted_size;
			
			//copy remaining
			memcpy(output_data+sz_output_data, packet_data+12+crypted_size, length-crypted_size-4);
			sz_output_data+=length-crypted_size-4;

		}
		else if(!memcmp(magic, magic_video_00, 4))
		{
			
			uint32_t length=be32toh(*(uint32_t*)(packet_data+4));
			uint32_t counter=be32toh(*(uint32_t*)(packet_data+8));
			
			printf("video 00 l=%u c=%u, processing...\n", length, counter);
			
			memcpy(output_data+sz_output_data, packet_data+12, length-4);
			sz_output_data+=length;
		}
		else if(!memcmp(magic, magic_audio, 4))
		{
			printf("audio, skip\n");
		}
		else if(!memcmp(magic, magic_82, 4))
		{
			printf("ignoring magic_82\n");
		}
		else if(flag_fragmented)
		{
			flag_fragmented=false;
			printf("copy remaining of fragmented\n");
			memcpy(output_data+sz_output_data, packet_data, filesz);
			sz_output_data+=filesz;
		}
		else
		{
			printf("UNKNOWN MAGIC / PACKET!\n");
		}
	}
	
	FILE *outp=fopen("output.bin", "wb");
	fwrite(output_data, sz_output_data, 1, outp);
	fclose(outp);
	
	free(packet_data);
	free(data_decrypted);
	free(output_data);
	
	printf("\n");
	printf("%u bytes written to output.bin. exiting.\n", sz_output_data);
	return 0;
}
