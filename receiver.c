#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <err.h>
#include <endian.h>
#include <time.h>

#include "aes_decrypt.h"

/*
This is a HIGHLY EXPERIMENTAL receiver for audio and video from the 373A V4 and V4 only. It will output a Transport Stream on stdout that can be redirected to disk or piped into VLC. As usual it comes WITHOUT ANY WARRANTY! USE AT YOUR OWN RISK!

This tool is for Linux only, tested on Debian 10.

How to use:
1) !! INSERT REAL KEY INTO aes_decrypt.c !! Otherwise you will get complete garbage!
2) run ./make_receiver to compile (Yes i still don't know makefiles...)
3) execute sudo setcap cap_net_raw+ep receiver to set the CAP_NET_RAW capability for the executable. You could also run the entire tool as root, at your own risk, but in this case piping into VLC will not work as VLC refuses to run as root.
4) execute ./receiver $network_interface > $file.ts OR ./receiver $network_interface | VLC - [notice the - ] OR similar

Please notice: This code should be considered a hack and is unfinished. I spent way to much time on this and i am loosing interest (and/because i don't have and don't need a 373A V4). TS (and the underlying PES and H.264 even more) are quite difficult stuff, so there are probably a lot of things to be checked and possibly improved:
-The PAT and PMT are hardcoded for know. Beware there is a CRC for both, so don't change any single bit!
-The audio and video might not be in sync. To fix this you will need to read about the PCR and PTS-stuff. 
-If there is no other network traffic recv() will wait forever and the program not terminate on Ctrl+C. A possible solution might be some sort of timeout of recv(), but i am not familiar with this / i have no idea if this is even possible. (On a real network this shouldn't be a problem as there will always be something like ARP or other stuff, but with a virtual network card - see below - this is annoying.)
-With some captures from other people (Thank you!) (see below) there are no decoder-errors, with others there are A LOT and you can see it on the output. It might be that some V4 do encrypt more data than others or something else, i don't want to dig into this. H.264 as you would need to decode everything from the start to figure out the meaning of a particular bit.

If you really want to dig inside TS search for ITU-T recommendation H.222.0. The pdf is available for free, but its over a hundred pages long. They also have a standard/recommendation for H.264 but it's 800 pages and absolutely horrible...

If you want to test this tool without using a real 373A you can use a virtual network card:
sudo ip tuntap add mode tap user $user group $group tap0
sudo ip link set tap0 up
./receiver tap0 [>file.ts]
in another terminal:
tcpreplay -i tap0 file.pcapng

As i said i don't own a 373A V4 myself so this tool was only tested using the virtual network card way as described above. This means i only tested on 2 or 3 captures.


If you want to debug/improve this code the tool "dvbsnoop" might come handy as it decodes quite some stuff, especially using the "tssubdecode" option. Read the manpage.


(c) 2021 by kitten_nb_five

freenode #lkv373a

THIS CODE IS RELEASED UNDER AGPLv3+ AND PROVIDED WITHOUT ANY WARRANTY!
*/

//uncomment this for quite some output - beware that it might slow down the capture / produce weird errors
//#define SHOW_PACKET_DETAILS

//these should be fine
#define SZ_MALLOC_RX_BUFFER (100*1024)
#define SZ_MALLOC_DATA_BUFFER (100*1024)
#define SZ_MALLOC_OUTPUT_VIDEO (1024*1024)
#define SZ_MALLOC_OUTPUT_AUDIO (1*1024)

volatile int run=1;

static void sigint(int sig)
{
	(void)sig;
	run=0;
}

static void usage(void)
{
	fprintf(stderr, "usage: ./receiver $interface > $file OR ./receiver $interface | $other_tool\n");
	exit(0);
}

typedef struct __attribute__((__packed__)) //network order is BIG ENDIAN!
{
	uint8_t IHL:4; //header_length=IHL*4
	uint8_t version:4; //must be 4
	uint8_t TOS; //ignore
	uint16_t total_length; //of packet
	uint16_t ident; //for fragmented
	uint16_t frag_offset_and_flags;
	uint8_t TTL;
	uint8_t proto;
	uint16_t header_checksum;
	uint32_t src_addr;
	uint32_t dst_addr;
} ip_header_t;

typedef struct __attribute__((__packed__)) //BIG ENDIAN!
{
	uint16_t src_port;
	uint16_t dst_port;
	uint16_t length;
	uint16_t checksum;
} udp_header_t;


//just make these global for now...
static uint8_t *output_video=NULL;
static uint32_t sz_output_video=0;

static uint8_t *output_audio=NULL;
static uint32_t sz_output_audio=0;

//we need somewhere to store informations about the TS-packet that will eventually be sent out
typedef struct
{
	bool is_video;
	bool payload_unit_start_indicator; //->add PES data
	bool has_adaptation_field; //->adaptation_field_control=0b11, else 0b01
	bool af_has_pcr;
	bool af_has_stuffing;
	uint8_t nb_stuffing;
	bool af_random_access_indicator;
	time_t timestamp;
	int64_t timestamp_ns;
} ts_packet_info_t;

//wait for H.264 SPS to start output
static bool flag_output_start=false;

//ffmpeg told me to set payload_start_indicator if there is a SPS or a coded slice following. 1) seems good, for 2) i am not so sure but i seems to work. 

static bool payload_is_sps(uint8_t const * const data, const uint32_t nb_bytes)
{
	if(nb_bytes<5)
		errx(1, "payload_is_sps: not enough data");
	
	if(data[0]!=0x00 || data[1]!=0x00 || data[2]!=0x00 || data[3]!=0x01)
		errx(1, "payload_is_sps: this is not a valid start indicator");
	
	if((data[4]&0x1f)==7) //sequence parameter set
	{
		flag_output_start=true;
		return true;
	}
	else
		return false;
}

static bool payload_is_coded_slice(uint8_t const * const data, const uint32_t nb_bytes)
{
	if(nb_bytes<5)
		errx(1, "payload_is_coded_slice: not enough data");
	
	if(data[0]!=0x00 || data[1]!=0x00 || data[2]!=0x00 || data[3]!=0x01)
		errx(1, "payload_is_coded_slice: this is not a valid start indicator");
	
	if((data[4]&0x1f)==1) //coded slice
		return true;
	else
		return false;
}

//base with DTS set to zero, markerbits set as in specification
#define SIZE_PES 14
static const uint8_t PES_base_video[SIZE_PES]={0x00, 0x00, 0x01, 0xE0, 0x00, 0x00, 0x80, 0x80, 0x05, 0x21, 0x00, 0x01, 0x00, 0x01};
static const uint8_t PES_base_audio[SIZE_PES]={0x00, 0x00, 0x01, 0xC0, 0x00, 0x00, 0x80, 0x80, 0x05, 0x21, 0x00, 0x01, 0x00, 0x01};

static uint8_t ts_get_free_space(ts_packet_info_t  * const ts)
{
	uint8_t space=188-4;
	
	if(ts->payload_unit_start_indicator)
		space-=SIZE_PES;
	
	if(ts->has_adaptation_field)
	{
		space-=1;
		if(ts->af_has_pcr||ts->af_random_access_indicator)
			space-=1;
		if(ts->af_has_pcr)
			space-=6;
	}
	
	return space;
}

//the PCR/PTS-stuff is based on a 27MHz clock. Thats what is simulated here.
static uint64_t get_clock_cycles(ts_packet_info_t * const ts)
{
	static bool startpoint_set=false;
	static struct timespec start;
	
	if(!startpoint_set)
	{
		fprintf(stderr, "setting startpoint for clock\n");
		start.tv_sec=ts->timestamp;
		start.tv_nsec=ts->timestamp_ns;
		startpoint_set=true;
	}
	
	time_t diff=ts->timestamp-start.tv_sec;
	uint64_t diff_ns;
	
	if(start.tv_nsec<=ts->timestamp_ns)
		diff_ns=ts->timestamp_ns-start.tv_nsec;
	else
	{
		diff_ns=1E9+ts->timestamp_ns-start.tv_nsec;
		if(diff)
			diff--;
		else
			errx(1, "get_clock_cycles: underflow\n");
	}
	
	uint64_t tdiff_ns=1E9*diff+diff_ns;
	uint64_t clocks=(27*tdiff_ns)/1000;
	
	return clocks;
}

static void ts_make_pcr(uint8_t * * const packet_ptr_ptr, ts_packet_info_t * const ts)
{
	if(!ts->af_has_pcr)
		errx(1, "unneeded call to ts_make_pcr");
	
	uint64_t clocks=get_clock_cycles(ts);
	
	uint64_t pcr_base=(clocks/300)%((uint64_t)1<<33);
	uint16_t pcr_ext=clocks%300;
	
	(*packet_ptr_ptr)[0]=(pcr_base>>25)&0xff;
	(*packet_ptr_ptr)[1]=(pcr_base>>17)&0xff;
	(*packet_ptr_ptr)[2]=(pcr_base>>9)&0xff;
	(*packet_ptr_ptr)[3]=(pcr_base>>1)&0xff;
	(*packet_ptr_ptr)[4]=(pcr_ext>>15)&0xff;
	(*packet_ptr_ptr)[5]=pcr_ext&0xff;
	
	(*packet_ptr_ptr)+=6;
}

static void ts_make_adaptation_field(uint8_t * * const packet_ptr, ts_packet_info_t * const ts)
{
	if(!ts->has_adaptation_field)
		errx(1, "unneeded call to ts_make_adaptation_field");
	
	uint8_t af_field_length=0;
	
	if(ts->af_random_access_indicator||ts->af_has_pcr)
		af_field_length++;
	
	if(ts->af_has_stuffing)
	{
		if(ts->nb_stuffing>=2)
			ts->nb_stuffing-=2;
		else
			ts->nb_stuffing=0;
		af_field_length+=ts->nb_stuffing+1;
	}

	if(ts->af_has_pcr)
		af_field_length+=6;

	**packet_ptr=af_field_length;
	(*packet_ptr)++;
	
	if(af_field_length || ts->af_has_stuffing)
	{
		**packet_ptr=((ts->af_random_access_indicator)<<6)|((ts->af_has_pcr)<<4);
		(*packet_ptr)++;
	}

	if(ts->af_has_pcr)
		ts_make_pcr(packet_ptr, ts);

	if(ts->af_has_stuffing)
	{
		while(ts->nb_stuffing--)
		{
			**packet_ptr=0xff;
			(*packet_ptr)++;
		}
	}
}

static void make_pes(uint8_t * * const packet_ptr_ptr, ts_packet_info_t * const ts)
{
	if(ts->is_video)
		memcpy(*packet_ptr_ptr, PES_base_video, SIZE_PES);
	else
		memcpy(*packet_ptr_ptr, PES_base_audio, SIZE_PES);
	
	//make PTS - 90kHz
	uint64_t clocks_27M=get_clock_cycles(ts);
	
	uint64_t clocks=clocks_27M/300;
	clocks=clocks%((uint64_t)1<<33);
	
	(*packet_ptr_ptr)[9]|=(clocks&0x1C0000000)>>29;
	(*packet_ptr_ptr)[10]|=(clocks&0x3FC00000)>>22;
	(*packet_ptr_ptr)[11]|=(clocks&0x3F8000)>>14;
	(*packet_ptr_ptr)[12]|=(clocks&0x7F80)>>7;
	(*packet_ptr_ptr)[13]|=(clocks&0x7f)<<1;
	
	(*packet_ptr_ptr)+=SIZE_PES;
}

static void ts_make_packet(uint8_t * packet, const uint16_t PID, ts_packet_info_t * const ts, uint8_t const * * const data, uint32_t * const nb_bytes)
{
	static uint8_t continuity_counter[2]={0,0};
	
	uint32_t bytes_to_copy=*nb_bytes;
	uint8_t free_space=ts_get_free_space(ts);
	if(bytes_to_copy>free_space)
		bytes_to_copy=free_space;
	else if(bytes_to_copy<free_space)
	{
		uint8_t nb_bytes_to_fill=free_space-*nb_bytes;
		ts->has_adaptation_field=true;
		ts->af_has_stuffing=true;
		ts->nb_stuffing=nb_bytes_to_fill;
	}
	
	packet[0]=0x47;
	packet[1]=(0<<7)|(ts->payload_unit_start_indicator<<6)|(0<<5)|((PID&0x1fff)>>8);
	packet[2]=PID&0xff;
	packet[3]=continuity_counter[ts->is_video]++;
	
	if(ts->has_adaptation_field)
		packet[3]|=(3<<4);
	else
		packet[3]|=(1<<4);
	
	uint8_t * packet_ptr=&packet[4];
	
	if(ts->has_adaptation_field)
		ts_make_adaptation_field(&packet_ptr, ts);
	
	if(ts->payload_unit_start_indicator)
		make_pes(&packet_ptr, ts);
	
	memcpy(packet_ptr, *data, bytes_to_copy);
	
	(*nb_bytes)-=bytes_to_copy;
	(*data)+=bytes_to_copy;
	
	if(continuity_counter[ts->is_video]>0x0f)
		continuity_counter[ts->is_video]=0;
}

static void write_ts_packets_video(uint8_t const * data, const uint32_t size_data, struct timespec t)
{	
	uint32_t nb_bytes=size_data;

	ts_packet_info_t ts_packet_info;
	memset(&ts_packet_info, 0, sizeof(ts_packet_info_t));
	
	bool is_sps=payload_is_sps(data, nb_bytes);
	bool is_coded_slice=payload_is_coded_slice(data, nb_bytes);

	ts_packet_info.is_video=true;

	if(!flag_output_start)
		return;
	
	ts_packet_info.payload_unit_start_indicator=is_sps||is_coded_slice;
	if(is_sps)
	{
		ts_packet_info.has_adaptation_field=true;
		ts_packet_info.af_random_access_indicator=true;
		ts_packet_info.af_has_pcr=true;
	}
	
	ts_packet_info.timestamp=t.tv_sec;
	ts_packet_info.timestamp_ns=t.tv_nsec;
	
	while(nb_bytes)
	{
		uint8_t ts_packet[188];
		
		ts_make_packet(ts_packet, 256, &ts_packet_info, &data, &nb_bytes);
		fwrite(ts_packet, 188, 1, stdout);
		
		memset(&ts_packet_info, 0, sizeof(ts_packet_info_t));
		ts_packet_info.is_video=true;
	}
}

static void write_ts_packets_audio(uint8_t const * data, const uint32_t size_data, struct timespec t)
{
	uint32_t nb_bytes=size_data;

	if(size_data!=576)
		errx(1, "audio packet size differs from standard size (%u instead of 576 bytes)", size_data);
	
	ts_packet_info_t ts_packet_info;
	memset(&ts_packet_info, 0, sizeof(ts_packet_info_t));
	
	if(!flag_output_start)
		return;
	
	ts_packet_info.payload_unit_start_indicator=true;
	ts_packet_info.has_adaptation_field=true;
	ts_packet_info.af_random_access_indicator=true;
	ts_packet_info.af_has_pcr=true;
	
	ts_packet_info.timestamp=t.tv_sec;
	ts_packet_info.timestamp_ns=t.tv_nsec;
	
	while(nb_bytes)
	{
		uint8_t ts_packet[188];
		
		ts_make_packet(ts_packet, 257, &ts_packet_info, &data, &nb_bytes);
		fwrite(ts_packet, 188, 1, stdout);
		
		memset(&ts_packet_info, 0, sizeof(ts_packet_info_t));
	}
}

static void parse_373_packet(uint8_t const * const buffer, const uint32_t size_data, struct timespec t)
{
	static bool flag_fragmented=false;
	static uint32_t frag_total_size=0;
	
	uint8_t magic[4];
	memcpy(magic, buffer, 4);

#ifdef SHOW_PACKET_DETAILS	
	fprintf(stderr, "magic %02x %02x %02x %02x: ", magic[0], magic[1], magic[2], magic[3]);
#endif

	const uint8_t magic_video_80[4]={0x74, 0x47, 0x74, 0x80};
	const uint8_t magic_audio[4]={0x74, 0x47, 0x74, 0x81};
	const uint8_t magic_status[4]={0x74, 0x47, 0x74, 0x82};
	const uint8_t magic_video_00[4]={0x74, 0x47, 0x74, 0x00};

	if(!memcmp(magic, magic_video_80, 4))
	{
		uint32_t length=be32toh(*(uint32_t*)(buffer+4));
		uint32_t counter=be32toh(*(uint32_t*)(buffer+8)); //what is this exactly / what is this for? some sync-stuff?
		(void)counter;

#ifdef SHOW_PACKET_DETAILS
		fprintf(stderr, "video (80)\n");
#endif
		
		uint8_t *data_decrypted=malloc(SZ_MALLOC_DATA_BUFFER);
		if(!data_decrypted)
			err(1, "malloc data_decrypted failed");
		
		if(length-4>size_data)
		{
			flag_fragmented=true;
			frag_total_size=length-4;
		}
		
		uint32_t crypted_size=(length-4)-(length-4)%16;
		
		if(crypted_size>1024)
			crypted_size=1024;
		
		//decrypt and copy crypted
		if(decrypt(buffer+12, crypted_size, data_decrypted)!=crypted_size)
			errx(1, "decrypt returned wrong size");
	
		memcpy(output_video+sz_output_video, data_decrypted, crypted_size);
		sz_output_video+=crypted_size;
		
		//copy remaining
		memcpy(output_video+sz_output_video, buffer+12+crypted_size, length-crypted_size-4);
		sz_output_video+=length-crypted_size-4;
		
		free(data_decrypted);

	}
	else if(!memcmp(magic, magic_video_00, 4))
	{
		uint32_t length=be32toh(*(uint32_t*)(buffer+4));
		uint32_t counter=be32toh(*(uint32_t*)(buffer+8));
		(void)counter;

#ifdef SHOW_PACKET_DETAILS
		fprintf(stderr, "video (00)\n");
#endif
		
		memcpy(output_video+sz_output_video, buffer+12, length-4);
		sz_output_video+=length-4;
	}
	else if(!memcmp(magic, magic_audio, 4))
	{
		uint32_t length=be32toh(*(uint32_t*)(buffer+4));
		uint32_t counter=be32toh(*(uint32_t*)(buffer+8));
		(void)counter;
		
#ifdef SHOW_PACKET_DETAILS
		fprintf(stderr, "audio\n");
#endif
		uint8_t data_decrypted[576];
		
		if(length!=576+4)
			errx(1, "audio: wrong length, this should not happen at this point");
		
		if(decrypt(buffer+12, 576, data_decrypted)!=576)
			errx(1, "decrypt returned wrong size");
		
		memcpy(output_audio+sz_output_audio, data_decrypted, 576);
		sz_output_audio+=576;
	}
	else if(!memcmp(magic, magic_status, 4))
	{
#ifdef SHOW_PACKET_DETAILS
		fprintf(stderr, "status (ignored)\n");
#endif
	}
	else if(flag_fragmented)
	{
#ifdef SHOW_PACKET_DETAILS
		fprintf(stderr, "part of fragmented transfer, reassembling...");
#endif
		memcpy(output_video+sz_output_video, buffer, size_data);
		sz_output_video+=size_data;
		
		if(sz_output_video>=frag_total_size)
			flag_fragmented=false;
	}
	else
	{
		fprintf(stderr, "parse_373_packet: received unknown packet (no matching magic)!\n");
	}
	
	if(sz_output_video && !flag_fragmented)
	{
		write_ts_packets_video(output_video, sz_output_video, t);
		sz_output_video=0;
	}
	if(sz_output_audio)
	{
		write_ts_packets_audio(output_audio, sz_output_audio, t);
		sz_output_audio=0;
	}
}

static void write_pat_pmt(void)
{
	//hardcoded for now - PID 256 + 257 - don't change or if you do update the CRC!
	const uint8_t data1[188]={0x47, 0x40, 0x00, 0x10, 0x00, 0x00, 0xB0, 0x0D, 0x00, 0x01, 0xC1, 0x00, 0x00, 0x00, 0x01, 0xF0, 0x00, 0x2A, 0xB1, 0x04, 0xB2, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
		
	const uint8_t data2[188]={0x47, 0x50, 0x00, 0x10, 0x00, 0x02, 0xb0, 0x17, 0x00, 0x01, 0xc1, 0x00, 0x00, 0xe1, 0x00, 0xf0, 0x00, 0x1b, 0xe1, 0x00, 0xf0, 0x00, 0x03, 0xe1, 0x01, 0xf0, 0x00, 0x4e, 0x59, 0x3d, 0x1e, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	
	fwrite(data1, 188, 1, stdout);
	fwrite(data2, 188, 1, stdout);
}

int main(int argc, char *argv[])
{
	if(argc!=2)
		usage();
	
	int sock;
	uint8_t *buf=malloc(SZ_MALLOC_RX_BUFFER);
	if(!buf)
		err(1, "malloc buf for rx failed");
	
	unsigned int size_rx;
	
	uint8_t *data_buffer=malloc(SZ_MALLOC_DATA_BUFFER);
	if(!data_buffer)
		err(1, "malloc data_buffer failed");
	
	output_video=malloc(SZ_MALLOC_OUTPUT_VIDEO);
	if(!output_video)
		err(1, "malloc output_video failed");
	
	output_audio=malloc(SZ_MALLOC_OUTPUT_AUDIO);
	if(!output_audio)
		err(1, "malloc output_audio failed");
	
	sock=socket(AF_PACKET, SOCK_DGRAM, htons(0x0800)); //receive only IPv4
	if(sock<0)
		err(1, "could not open socket - did you set CAP_NET_RAW?");

	if(setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, argv[1], IFNAMSIZ)<0)
		err(1, "could not bind to device - did you set CAP_NET_RAW?");
	
	fprintf(stderr, "listening on %s\n", argv[1]);

	signal(SIGINT, &sigint);
	
	write_pat_pmt(); //VLC needs these
	
	ip_header_t ip_header;
	const uint32_t addr_373=0xd201a8c0;
	udp_header_t udp_header;
	
	uint32_t size_data=0;
	
	struct timespec timespec;
	
	while(run)
	{
		size_rx=recv(sock, buf, SZ_MALLOC_RX_BUFFER, 0);
		clock_gettime(CLOCK_REALTIME, &timespec);
		
		if(size_rx<sizeof(ip_header_t))
			continue;
		
		memcpy(&ip_header, buf, sizeof(ip_header_t));
		size_rx-=sizeof(ip_header_t);

		if(ip_header.proto!=17) //not UDP?
			continue;
		
		if(ip_header.src_addr!=addr_373) //not from our device?
			continue;
		
		//we assume all fragments have arrived before a new transmission (fragmented or not) starts
		//we also assume that there is only one fragmented UDP-packet at every point in time (ip_header.ident not checked)
		//for unfragmented packets frag_off is 0
		
		//decode this manually as using bitfields did not work
		uint16_t tmp=be16toh(ip_header.frag_offset_and_flags);
		uint16_t frag_offset=(tmp&0x1fff)*8;
		bool flag_reserved=!!(tmp&(1<<15));
		bool flag_dont_fragment=!!(tmp&(1<<14));
		(void)flag_dont_fragment; //we don't actually need this one, only declared for completeness
		bool flag_more_fragments=!!(tmp&(1<<13));
		
		if(flag_reserved)
			errx(1, "flag_reserved is set in IP-header");

		memcpy(data_buffer+frag_offset, buf+sizeof(ip_header_t), size_rx);
		size_data+=size_rx;

		if(flag_more_fragments)
			continue;
		
		if(size_data<sizeof(udp_header_t))
		{
			fprintf(stderr, "WARNING: incomplete packet, no complete UDP-header, skipping\n");
			size_data=0;
			continue;
		}
		
		memcpy(&udp_header, data_buffer, sizeof(udp_header_t));
		size_data-=sizeof(udp_header_t);
				
		if(udp_header.dst_port!=htobe16(7777)) //wrong port?
		{
			size_data=0;
			continue;
		}
		
#ifdef SHOW_PACKET_DETAILS
		fprintf(stderr, "got UDP packet from 373 to port 7777 length %u timestamp %lu.%lu\n", size_data, timespec.tv_sec, timespec.tv_nsec);
#endif
		parse_373_packet(data_buffer+sizeof(udp_header_t), size_data, timespec);

		size_data=0;
	}
	
	close(sock);
	
	free(buf);
	free(data_buffer);
	free(output_video);
	free(output_audio);
	
	fprintf(stderr, "\nCleaned up, exiting.\n");
	
	return 0;
}
