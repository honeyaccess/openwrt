

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdint.h>
#include <time.h>

static const uint32_t crc32_ccitt_table[256] = {
        0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419,
        0x706af48f, 0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4,
        0xe0d5e91e, 0x97d2d988, 0x09b64c2b, 0x7eb17cbd, 0xe7b82d07,
        0x90bf1d91, 0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de,
        0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7, 0x136c9856,
        0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
        0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4,
        0xa2677172, 0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
        0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940, 0x32d86ce3,
        0x45df5c75, 0xdcd60dcf, 0xabd13d59, 0x26d930ac, 0x51de003a,
        0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423, 0xcfba9599,
        0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
        0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190,
        0x01db7106, 0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f,
        0x9fbfe4a5, 0xe8b8d433, 0x7807c9a2, 0x0f00f934, 0x9609a88e,
        0xe10e9818, 0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
        0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e, 0x6c0695ed,
        0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
        0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3,
        0xfbd44c65, 0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2,
        0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a,
        0x346ed9fc, 0xad678846, 0xda60b8d0, 0x44042d73, 0x33031de5,
        0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa, 0xbe0b1010,
        0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
        0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17,
        0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6,
        0x03b6e20c, 0x74b1d29a, 0xead54739, 0x9dd277af, 0x04db2615,
        0x73dc1683, 0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8,
        0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1, 0xf00f9344,
        0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
        0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a,
        0x67dd4acc, 0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
        0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252, 0xd1bb67f1,
        0xa6bc5767, 0x3fb506dd, 0x48b2364b, 0xd80d2bda, 0xaf0a1b4c,
        0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55, 0x316e8eef,
        0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
        0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe,
        0xb2bd0b28, 0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31,
        0x2cd99e8b, 0x5bdeae1d, 0x9b64c2b0, 0xec63f226, 0x756aa39c,
        0x026d930a, 0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
        0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38, 0x92d28e9b,
        0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
        0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1,
        0x18b74777, 0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c,
        0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45, 0xa00ae278,
        0xd70dd2ee, 0x4e048354, 0x3903b3c2, 0xa7672661, 0xd06016f7,
        0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc, 0x40df0b66,
        0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
        0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605,
        0xcdd70693, 0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8,
        0x5d681b02, 0x2a6f2b94, 0xb40bbe37, 0xc30c8ea1, 0x5a05df1b,
        0x2d02ef8d
};
#define CRC32_CCITT_SEED 0xFFFFFFFF
uint32_t
crc32_ccitt_seed(const uint8_t *buf, uint32_t len, uint32_t seed)
{
	uint32_t i;
	uint32_t crc32 = seed;

	for (i = 0; i < len; i++)
		crc32 = crc32_ccitt_table[(crc32 ^ buf[i]) & 0xff] ^ (crc32 >> 8);

	return ( ~crc32 );
}

uint32_t crc(const uint8_t *buf, uint32_t len)
{
	return ( crc32_ccitt_seed(buf, len, CRC32_CCITT_SEED) );
}

static const unsigned char u8aRadiotapHeader[] = { 
  0x00, 0x00, // <-- radiotap version
  0x19, 0x00, // <- radiotap header length
  0x6f, 0x08, 0x00, 0x00, // <-- bitmap
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // <-- timestamp
  0x10, // <-- flags (contains FCS is set)
  0x30, // <-- rate (24 * 2)
  0x71, 0x09, 0xc0, 0x00, // <-- channel
  0xde, // <-- antsignal
  0x00, // <-- antnoise
  0x01, // <-- antenna
};

static const unsigned char ieeeHeader[] = {
	0xB4, 0x00, 0x01, 0x02
//	0xbe, 0xc6, 0x74, 0x89, 0x60, 0xe9,
//	0x14, 0x22, 0x33, 0x44, 0x55, 0x66
};

static const unsigned char beaconPrefix[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Timestamp (don't know when its filled, but it is received on wireshark)
   	0x64, 0x00,
	0x11, 0x14,
	0x00,
};

static const unsigned char beaconSuffix[] = {
	0x01, 0x08,
	0x82, 0x84, 0x8b, 0x96,
	0x24, 0x30, 0x48, 0x6c,
};

static const unsigned char additionalTags[] = {
	0x03, 0x01, 0x06,  // current channel 6
	0x05, 0x04, 0x00, 0x01, 0x00, 0x00,  // traffic indication map
	0x2a, 0x01, 0x00,  // ERP
	0x2f, 0x01, 0x00,  // ERP
	0x32, 0x04, 0x0c, 0x12, 0x18, 0x60,  // Extended rates
	0x7f, 0x08, 0x04, 0x00, 0x00, 0x80, 0x03, 0x00, 0x00, 0x40,  // additional capabilities
};

static const unsigned char hotspotTwoInterworkingElement[] = {
	0x6b,  // 107
	0x09,  // length
	0x33,  // free public network with internet and 
	0x0b,  // outdoor  (from http://www.cisco.com/c/en/us/td/docs/wireless/controller/7-2/configuration/guide/cg/cg_hotspot_msap.html#wp1064286)
	0x00,  // unspecified 
	0x13, 0x22, 0x33, 0x44, 0x55, 0x66,
};


static const unsigned char hotspotTwoRoamingConsortiumElement[] = {
	0x6f,  // 111
	0x0a,  // length
	0x01,  // number of ANQP OI-s 
	0x53,  // OI-s lengths (5 and 3)
	0x00, 0x10, 0x5E,
	0x00, 0x1b, 0xc5, 0x04, 0xbd,
};

static const unsigned char hotspotTwoAdvertisementProtocolElement[] = {
	0xdd,  // 108
	0x19,  // length
	0xa9,  // ? copied from sample
	0x97,
};

static const unsigned char hotspotTwoElement[] = {
	0xe7,  // 221 as defined in IEEE 802.11-2012 Part 11
	0x05,  // length between 5-7
	0x50, 0x6F, 0x9A,  // OI field from 8.4.2.71.5 of IEEE 802.11-2012
	0x10,  // Type?
};

void usage(char* bin_name, const char* error) {
  printf("Error: %s\nUssage: %s INTERFACE_NAME DEST_MAC INTERVAL [SOURCE_MAC=00:11:22:33:44:55]\n\tExample: %s wlan0 00:11:22:33:44:55 1000 22:33:44:55:66:77\n", error, bin_name, bin_name);
  exit(1);
}

int main(int argc, char *argv[] ){   
  srand(time(NULL));
  int i=0; 
  pcap_t *pcap = NULL;
  char errbuf[PCAP_ERRBUF_SIZE], *device=NULL; 
  memset(errbuf,0,PCAP_ERRBUF_SIZE); 

  unsigned char frame[512];
  int frame_size;
  int sequence_control = 1;

  if (argc < 4) {
    usage(argv[0], "Invalid number of arguments");
  } 
  
  device = argv[1];

  unsigned char mac[6];
  unsigned char mac2[6];
  int tmp_mac[6];
  if (6 != sscanf(argv[2], "%x:%x:%x:%x:%x:%x", tmp_mac, tmp_mac+1, tmp_mac+2, tmp_mac+3, tmp_mac+4, tmp_mac+5)) usage(argv[0], "Invalid MAC format");
  for (i=0;i<6;++i) {
    if (tmp_mac[i] >= 256) usage(argv[0], "Invalid MAC format");
    mac[i] = (unsigned char)tmp_mac[i]; 
  }
  if (argc == 5) {
    if (6 != sscanf(argv[4], "%x:%x:%x:%x:%x:%x", tmp_mac, tmp_mac+1, tmp_mac+2, tmp_mac+3, tmp_mac+4, tmp_mac+5)) usage(argv[0], "Invalid MAC format");
    for (i=0;i<6;++i) {
      if (tmp_mac[i] >= 256) usage(argv[0], "Invalid MAC format");
      mac2[i] = (unsigned char)tmp_mac[i];
    }
  } else {
    *(uint32_t*)mac2 = 0x33221100;
    mac2[4] = 0x44;
    mac2[5] = 0x55;
  }

  int interval;
  if (1 != sscanf(argv[3], "%d", &interval)) usage(argv[0], "Invalid interval");
  int sleep_seconds = (int)((uint64_t)interval * 1024ULL / 1000000ULL);
  int sleep_useconds = (int)((uint64_t)interval * 1024ULL % 1000000ULL);

  memset(frame, 0, sizeof(frame)); 

  /*  Radio Tap Header  */ 
  memcpy(frame, u8aRadiotapHeader, sizeof (u8aRadiotapHeader));
  frame_size = sizeof(u8aRadiotapHeader);

  /*  IEEE 802.11 Header  */
  memcpy(&frame[frame_size], ieeeHeader, sizeof (ieeeHeader));
  frame_size += sizeof(ieeeHeader);
  memcpy(&frame[frame_size], mac, 6);
frame_size += 6;
  memcpy(mac2, mac, 6);
  mac2[5] = mac[5]+1;
  memcpy(&frame[frame_size], mac2, 6);
frame_size += 6;
  // Sequence control is set up on send
 

  uint32_t crc32 = crc(frame+sizeof(u8aRadiotapHeader), frame_size - sizeof(u8aRadiotapHeader));
  memcpy(&frame[frame_size], &crc32, sizeof(uint32_t));
  frame_size += 4;

  if ( (pcap = pcap_open_live(device, frame_size + 4, 1, 20, errbuf)) == NULL){
    fprintf(stderr, "ERROR: %s\n", errbuf);
    exit(1);
  }
  printf("sleep %d %d\n", sleep_seconds, sleep_useconds);
  for (;;) {
#    frame[frame_size-5] = rand()%0xFF;
    crc32 = crc(frame+sizeof(u8aRadiotapHeader), frame_size - 4 - sizeof(u8aRadiotapHeader));
  memcpy(&frame[frame_size-4], &crc32, sizeof(uint32_t));
    if (pcap_inject(pcap,frame,frame_size)==-1) {
      pcap_perror(pcap,0);
      break;
    }
    printf("sleep\n");
    if (sleep_seconds > 0) { if (sleep(sleep_seconds) != 0) break; }
    if (sleep_useconds > 0) { if (usleep(sleep_useconds) != 0) break; }
  }

  printf("Cleaning up\n"); 
  pcap_close(pcap);
  return 0;
}

