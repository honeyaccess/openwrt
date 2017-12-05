/* Simple Raw Sniffer                                                    */ 
/* Author: Luis Martin Garcia. luis.martingarcia [.at.] gmail [d0t] com  */
/* To compile: gcc simplesniffer.c -o simplesniffer -lpcap               */ 
/* Run as root!                                                          */ 
/*                                                                       */
/* This code is distributed under the GPL License. For more info check:  */
/* http://www.gnu.org/copyleft/gpl.html                                  */

#include <pcap.h> 
#include <string.h> 
#include <stdlib.h> 

#define MAXBYTES2CAPTURE 2048 


/* processPacket(): Callback function called by pcap_loop() everytime a packet */
/* arrives to the network card. This function prints the captured raw data in  */
/* hexadecimal.                                                                */
unsigned char prev_mac[6];
unsigned char prev_mac_t[6];

unsigned char filter[6];
int has_filter;

void processPacket(u_char *arg, const struct pcap_pkthdr* pkthdr, const u_char * packet){ 

 int i=0, *counter = (int *)arg; 

 if (pkthdr->len < 3)
    return;

 if (packet[0] != 0 || packet[1] != 0)
   return;

 int len = packet[2]|(packet[3]<<8);

 if (packet[len] != 0xc4 && packet[len] != 0xb4)
    return;

 int flags = packet[len+1];
 int duration = packet[len+2] | (packet[len+3]<<8);

 unsigned char mac[6];
 for (i = 0; i < 6; ++i)
   mac[i] = packet[len+i+4];

 unsigned char mac_transmitter[6];
 if (packet[len] == 0xb4)
 {
   for (i = 0; i < 6; ++i)
      mac_transmitter[i] = packet[len+i+4+6];
 }

// if (packet[len] == 0xc4 && memcmp(mac, prev_mac, 6)==0)
 //   return;

// if (packet[len] == 0xb4 && memcmp(mac, prev_mac_t, 6)==0)
//    return;

if (has_filter && ((packet[len] == 0xc4 && memcmp(mac, filter, 5) != 0) ||
                   (packet[len] == 0xb4 && memcmp(mac_transmitter, filter, 5) != 0)))
   return;

 if (packet[len]==0xb4)
      prev_mac[0] = 0;

 if (packet[len] == 0xc4)
     printf(" -> %02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
 else
     printf(" %02x:%02x:%02x:%02x:%02x:%02x <-- %02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], mac_transmitter[0], mac_transmitter[1], mac_transmitter[2], mac_transmitter[3], mac_transmitter[4], mac_transmitter[5]);

 fflush(stdout);

 for (i = 0; i < 6; ++i)
 {
    if (packet[len]==0xc4)
       prev_mac[i] = mac[i];
    else
       prev_mac_t[i] = mac[i];
 }
 return;
 printf("Packet Count: %d\n", ++(*counter)); 
 printf("Received Packet Size: %d\n", pkthdr->len); 
 printf("Payload:\n"); 
 for (i=0; i<pkthdr->len; i++){ 

    if ( isprint(packet[i]) ) /* If it is a printable character, print it */
        printf("%c ", packet[i]); 
    else 
        printf(". "); 
    
     if( (i%16 == 0 && i!=0) || i==pkthdr->len-1 ) 
        printf("\n"); 
  } 
 return; 
} 



/* main(): Main function. Opens network interface and calls pcap_loop() */
int main(int argc, char *argv[] ){ 
    
 int i=0, count=0; 
 pcap_t *descr = NULL; 
 char errbuf[PCAP_ERRBUF_SIZE], *device=NULL; 
 memset(errbuf,0,PCAP_ERRBUF_SIZE); 

 if( argc > 1){  /* If user supplied interface name, use it. */
    device = argv[1];


  if (argc > 2)
  {
    has_filter = 1;
    int temp[6];
    sscanf(argv[2], "%x:%x:%x:%x:%x:%x", temp, temp+1, temp+2, temp+3, temp+4, temp+5);
   for (i = 0; i < 6; ++i)
   {
     filter[i] = temp[i];
   }
  i = 0;
  }
 }
 else{  /* Get the name of the first device suitable for capture */ 

    if ( (device = pcap_lookupdev(errbuf)) == NULL){
        fprintf(stderr, "ERROR: %s\n", errbuf);
        exit(1);
    }
 }

 printf("Opening device %s\n", device); 
 
 /* Open device in promiscuous mode */ 
 if ( (descr = pcap_open_live(device, MAXBYTES2CAPTURE, 1,  512, errbuf)) == NULL){
    fprintf(stderr, "ERROR: %s\n", errbuf);
    exit(1);
 }

 /* Loop forever & call processPacket() for every received packet*/ 
 if ( pcap_loop(descr, -1, processPacket, (u_char *)&count) == -1){
    fprintf(stderr, "ERROR: %s\n", pcap_geterr(descr) );
    exit(1);
 }

return 0; 

} 

/* EOF*/
