#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>
#include <iostream>
#include <netdb.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <openssl/aes.h>
#include <sys/socket.h>
#include <cerrno>
#include <pcap/pcap.h>


#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#define __FAVOR_BSD          // important for tcphdr structure
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <err.h>

#ifdef __linux__            // for Linux
#include <netinet/ether.h>
#include <time.h>
#include <pcap/pcap.h>
#endif

#ifndef PCAP_ERRBUF_SIZE
#define PCAP_ERRBUF_SIZE (256)
#endif

#define SIZE_ETHERNET (14)       // offset of Ethernet header to L3 protocol

int n = 0;
struct keys {
    char key1;
    char key2;
    char key3;
    char name[48];
};

struct filenameStruct
{
    char *filename;
};


void error_handler(std::string str, int errNum)
{
    /// This function prints an Error message and exits the program
    fflush(stderr);
    fflush(stdout);
    fprintf(stderr,"%s",str.c_str());
    exit(errNum);
}

int argument_parser(int argc, char** argv, std::string *ipaddress, std::string *rfile)
{
    int opt;
    bool isserver = false;
    bool isrFile = false;
    bool isIpaddress = false;

    /// checks for arguments
    while ((opt = getopt(argc, argv, "-r:-s:-I")) != -1)
    {
        switch (opt)
        {
            /*
            case 'h':
             call help;
             break;
             * */
            /// assignes values of -r delimiter
            case 'r':
                //strcpy(rfile, optarg);
                //rfile->assign(optarg,sizeof(optarg));
                rfile->append(optarg);
                isrFile = true;
                break;
            /// assignes value of -i delimiter
            case 's':
                //strcpy(ipaddress, optarg);
                //ipaddress->assign(optarg,sizeof(optarg));
                ipaddress->append(optarg);
                isIpaddress = true;
                break;
            /// checks for server or client delimiter
            case 'I':
                isserver = true;
                break;
            default:
                error_handler("Wrong arguments",2);
                break;
        }
    }
    if (isserver)
        return 1;
    if (isrFile && isIpaddress)
        return 0;
    return -1;
}

void is_file (std::string& name) {
    if (FILE *file = fopen(name.c_str(), "r"))
        fclose(file);
     else
        error_handler("File does not exist", -1);
}
/*
char* get_file_name(std::string& rfile)
{
    int i = rfile.rfind('/',rfile.length());
    if(i != string::'\\'){
        return(rfile.substr(i+1,rfile.length()) - i);
    }
    return('\0');

}*/

// https://www.techiedelight.com/implement-substr-function-c/
// Following function extracts characters present in `src`
// between `m` and `n` (excluding `n`)
char* substr(const char *src, int m, int n)
{
    // get the length of the destination string
    int len = n - m;

    // allocate (len + 1) chars for destination (+1 for extra null character)
    char *dest = (char*)malloc(sizeof(char) * (len + 1));

    // extracts characters between m'th and n'th index from source string
    // and copy them into the destination string
    for (int i = m; i < n && (*(src + i) != '\0'); i++)
    {
        *dest = *(src + i);
        dest++;
    }

    // null-terminate the destination string
    *dest = '\0';

    // return the destination string
    return dest - len;
}

void mypcap_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ip *my_ip;               // pointer to the beginning of IP header
    struct ether_header *eptr;      // pointer to the beginning of Ethernet header
    const struct tcphdr *my_tcp;    // pointer to the beginning of TCP header
    const struct udphdr *my_udp;    // pointer to the beginning of UDP header
    u_int size_ip;
    n++;
    AES_KEY key_d;
    AES_set_decrypt_key((const unsigned char *)"xlogin00", 128, &key_d);

    // Only my icmp packet filter
    if(!(packet[34] == 'E' && packet[35] == 'E' && packet[36] == 'E'))
        return;

    /*
     * printf("FILENAME encrypted: ");
    for (int i = 37; i < 92; ++i)
    {
        printf("%X ",packet[i]);
    }
    printf("\n");
    for (int i = 37; i < 37+16; ++i)
    {
        printf("%X ",packet[i]);
    }
    printf("\n");
    for (int i = 37+16; i < 37+16+16; ++i)
    {
        printf("%X ",packet[i]);
    }
    printf("\n");
    for (int i = 37+16+16; i < 37+16+16+16; ++i)
    {
        printf("%X ",packet[i]);
    }
    printf("\n");
     */



    unsigned char *filecopyname = (unsigned char *) calloc(16,1);
    unsigned char *filetocopyname = (unsigned char *) calloc(16,1);
    unsigned char*rfile = (unsigned char*) calloc(48,1);

    memcpy(filecopyname, packet + 37, 16);

    for (int i = 0; i < AES_BLOCK_SIZE; ++i)
    {
        printf("%X ",filecopyname[i]);
    }
    printf("\n");

    AES_decrypt((const unsigned char*)filecopyname, filetocopyname, &key_d);
    printf("%s\n", filetocopyname);
    memcpy(rfile,filetocopyname,16);

    if((int)packet[37+16] != 0)
    {
        memcpy(filecopyname, packet + 37 + 16, 16);
        AES_decrypt((const unsigned char *) filecopyname, filetocopyname, &key_d);
        printf("%s\n", filetocopyname);
        memcpy(rfile+16,filetocopyname,16);
    }
    if((int)packet[37+16+16] != 0)
    {
        memcpy(filecopyname, packet + 37+16+16, 16);
        AES_decrypt((const unsigned char*)filecopyname,filetocopyname, &key_d);
        printf("%s\n", filetocopyname);
        memcpy(rfile+32,filetocopyname,16);
    }

    printf("filename: %s\n",rfile);
    free(filecopyname);
    free(filetocopyname);





   unsigned char* data = (unsigned char *)calloc(header->len - 93, 1);
   unsigned char* datatocopy = (unsigned char *) calloc(16,1);


    memcpy(data, packet + 93, header->len - 93);
    int i = 0;

    FILE *file = fopen((const char*)rfile,"a");
    while(i < header->len - 93)
    {
        memcpy(datatocopy,data + i, 16);
        AES_decrypt(datatocopy, datatocopy, &key_d);
        //write into file by 16 chars...
        fputs((const char*)datatocopy,file);
        printf("decrypted data: %s\n",datatocopy);
        i += 16;
        for (int i = 0; i < AES_BLOCK_SIZE; ++i)
        {
            printf("%X ",datatocopy[i]);
        }
    }
    fclose(file);



    fflush(stdout);
    printf("%d\n",header->len);

    free(data);
    free(rfile);
    free(datatocopy);
    // write_into_file(rfile,decryptedData);

    /*
    printf("\n");
    // print the packet header data
    printf("\tPacket no. %d:\n",n);
    printf("\tLength %d, received at %s",header->len,ctime((const time_t*)&header->ts.tv_sec));
    //    printf("Ethernet address length is %d\n",ETHER_HDR_LEN);

    // read the Ethernet header
    eptr = (struct ether_header *) packet;
    printf("\tSource MAC: %s\n",ether_ntoa((const struct ether_addr *)&eptr->ether_shost)) ;
    printf("\tDestination MAC: %s\n",ether_ntoa((const struct ether_addr *)&eptr->ether_dhost)) ;

    switch (ntohs(eptr->ether_type)){               // see /usr/include/net/ethernet.h for types
        case ETHERTYPE_IP: // IPv4 packet
            printf("\tEthernet type is  0x%x, i.e. IP packet \n", ntohs(eptr->ether_type));
            my_ip = (struct ip*) (packet+SIZE_ETHERNET);        // skip Ethernet header
            size_ip = my_ip->ip_hl*4;                           // length of IP header

            printf("\tIP: id 0x%x, hlen %d bytes, version %d, total length %d bytes, TTL %d\n",ntohs(my_ip->ip_id),size_ip,my_ip->ip_v,ntohs(my_ip->ip_len),my_ip->ip_ttl);
            printf("\tIP src = %s, ",inet_ntoa(my_ip->ip_src));
            printf("IP dst = %s",inet_ntoa(my_ip->ip_dst));

            switch (my_ip->ip_p){
                case 2: // IGMP protocol
                    printf(", protocol IGMP (%d)\n",my_ip->ip_p);
                    break;
                case 6: // TCP protocol
                    printf(", protocol TCP (%d)\n",my_ip->ip_p);
                    my_tcp = (struct tcphdr *) (packet+SIZE_ETHERNET+size_ip); // pointer to the TCP header
                    printf("\tSrc port = %d, dst port = %d, seq = %u",ntohs(my_tcp->th_sport), ntohs(my_tcp->th_dport), ntohl(my_tcp->th_seq));
                    if (my_tcp->th_flags & TH_SYN)
                        printf(", SYN");
                    if (my_tcp->th_flags & TH_FIN)
                        printf(", FIN");
                    if (my_tcp->th_flags & TH_RST)
                        printf(", RST");
                    if (my_tcp->th_flags & TH_PUSH)
                        printf(", PUSH");
                    if (my_tcp->th_flags & TH_ACK)
                        printf(", ACK");
                    printf("\n");
                    break;
                case 17: // UDP protocol
                    printf(", protocol UDP (%d)\n",my_ip->ip_p);
                    my_udp = (struct udphdr *) (packet+SIZE_ETHERNET+size_ip); // pointer to the UDP header
                    printf("\tSrc port = %d, dst port = %d, length %d\n",ntohs(my_udp->uh_sport), ntohs(my_udp->uh_dport), ntohs(my_udp->uh_ulen));
                    break;
                default:
                    printf(", protocol %d\n",my_ip->ip_p);
            }
            break;

        case ETHERTYPE_IPV6:  // IPv6
            printf("\tEthernet type is 0x%x, i.e., IPv6 packet\n",ntohs(eptr->ether_type));
            break;
        case ETHERTYPE_ARP:  // ARP
            printf("\tEthernet type is 0x%x, i.e., ARP packet\n",ntohs(eptr->ether_type));
            break;
        default:
            printf("\tEthernet type 0x%x, not IPv4\n", ntohs(eptr->ether_type));
    }*/
}

void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET)
    {
        return &(((struct sockaddr_in *)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}

int client_branch(std::string ipaddress, std::string rfile)
{
    AES_KEY key_encr;
    AES_set_encrypt_key((const unsigned char *)"xlogin00", 128, &key_encr);

    struct addrinfo hints, *serverinfo;
    memset(&hints, 0, sizeof(hints));

    //char *host = (char*)("google.sk");
    //char *host = (char*)("147.229.192.125");
    char *host = (char*)ipaddress.c_str();
    int result;

    hints.ai_family = AF_UNSPEC;
    //hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_RAW;

    if ((result = getaddrinfo(host, NULL, &hints, &serverinfo)) != 0)
    {
        fprintf(stderr, "%s\n", gai_strerror(result));
        return 1;
    }

    char ip[100];
    inet_ntop(serverinfo->ai_family, get_in_addr(serverinfo->ai_addr), ip, 100);
    printf("ip: %s\n", ip);
    printf("ip:family: %d\n",serverinfo->ai_family);
    printf("socktype: %d\n", serverinfo->ai_socktype);

    int protocol = serverinfo->ai_family == AF_INET ? IPPROTO_ICMP : IPPROTO_ICMPV6;
    printf("protocol: %d\n",protocol);

    int sock = socket(serverinfo->ai_family, serverinfo->ai_socktype, protocol);
    //int sock = socket (AF_INET, SOCK_RAW, 2);
    if (sock == -1)
    {
        printf("errno: %s\n",strerror(errno));
        fprintf(stderr, "sock err :)\n");
        return 1;
    }







    // DATA ENCRYPTION
    FILE *file = fopen(rfile.c_str(), "r");
    unsigned char dataIn[1000]; // max memAlocSize will be [1008]

    while(fread(dataIn,1,1000,file))
    {

    char packet[1500];
	memset(&packet, 0, 1500);

	struct icmphdr *icmp_header = (struct icmphdr *)packet;
	icmp_header->code = ICMP_ECHO;
	icmp_header->checksum = 0;
	//vypočitaj si checksum ak chceš :)


    // FILENAME ENCRYPTION
    printf("%s\n", basename(rfile.c_str()));
    printf("filenamesize %ld\n", strlen(basename(rfile.c_str())));
    unsigned char *dataFile = (unsigned char *)calloc(48 + (AES_BLOCK_SIZE % 48), 1);
    if(strlen(basename(rfile.c_str())) <= 16)
    {
        AES_encrypt((const unsigned char*)basename(rfile.c_str()), dataFile, &key_encr);
    }
    else
    {
        if(strlen(basename(rfile.c_str())) <= 32)
        {
            unsigned char *fname = (unsigned char *) calloc(16,1);
            unsigned char *fcopyname = (unsigned char *) calloc(32,1);

            AES_encrypt((const unsigned char*) substr(basename(rfile.c_str()),0,16),(unsigned char*)fname,&key_encr);
            memcpy(fcopyname ,fname,16);
            AES_encrypt((const unsigned char*) substr(basename(rfile.c_str()),16, strlen(basename(rfile.c_str()))),(unsigned char*)fname,&key_encr);
            memcpy(fcopyname + 16,fname,16);
            memcpy(dataFile,fcopyname,32);

            free(fname);
            free(fcopyname);
        }
        else
        {
            if(strlen(basename(rfile.c_str())) <= 48)
            {
                unsigned char *fname = (unsigned char *) calloc(16,1);
                unsigned char *fcopyname = (unsigned char *) calloc(32,1);

                AES_encrypt((const unsigned char*) substr(basename(rfile.c_str()),0,16),(unsigned char*)fname,&key_encr);
                memcpy(fcopyname ,fname,16);
                AES_encrypt((const unsigned char*) substr(basename(rfile.c_str()),16, 32),(unsigned char*)fname,&key_encr);
                memcpy(fcopyname + 16,fname,16);
                AES_encrypt((const unsigned char*) substr(basename(rfile.c_str()),32, strlen(basename(rfile.c_str()))),(unsigned char*)fname,&key_encr);
                memcpy(fcopyname + 32,fname,16);
                memcpy(dataFile,fcopyname,48);

                free(fname);
                free(fcopyname);
            }
            else
                error_handler("Name of file is too long",-1);
        }
    }



    printf("Read Encrypted File: ");
    for (int i = 0; i < AES_BLOCK_SIZE*3; ++i)
    {
        printf("%X ", dataFile[i]);
    }
    printf("\n");
    //GET NAME OF THE FILE
    struct keys *dah = (struct keys *) packet;
    dah->key1 = 69;
    dah->key2 = 69;
    dah->key3 = 69;
    memcpy(dah->name, dataFile,48);






        int memAlocSize = 0;
        int datalen = strlen((char *) dataIn);
        // GETTING memory size for excryption process
        while (datalen > memAlocSize)
            memAlocSize += 16;


        unsigned char *data = (unsigned char *) calloc(memAlocSize, 1);
        //unsigned char datatocopy = (unsigned char *) calloc(16,1);
        int i = 0;
        while(i < memAlocSize)
        {
            unsigned char *encrypteddata = (unsigned char*) calloc(16,1);
            if(i == (memAlocSize - 16))
            {
                unsigned char *datatocopy = (unsigned char *) substr((const char *) dataIn, i, datalen);
                AES_encrypt(datatocopy, encrypteddata, &key_encr);
                memcpy(data + i, encrypteddata, 16);
                i += 16;
            }
            else
            {
                unsigned char *datatocopy = (unsigned char *) substr((const char *) dataIn, i, i + 16);
                AES_encrypt(datatocopy, encrypteddata, &key_encr);
                memcpy(data + i, encrypteddata, 16);
                i += 16;
            }
            AES_KEY key_d;
            AES_set_decrypt_key((const unsigned char *) "xlogin00", 128, &key_d);
            AES_decrypt(encrypteddata, encrypteddata, &key_d);
            printf("decrypted: %s\n", encrypteddata);
            free(encrypteddata);
        }


        printf("Read Encrypted Data: ");
        for (int i = 0; i < memAlocSize; ++i)
        {
            printf("%X ", data[i]);
        }
        printf("\n");


        // HEADER AND DATA TO PACKET
        memcpy(packet + sizeof(struct icmphdr) + sizeof(struct keys), data, memAlocSize);


        // PACKET SENDING
	    if (sendto(sock, packet, sizeof(struct icmphdr) + sizeof(struct keys) + memAlocSize, 0, (struct sockaddr *)(serverinfo->ai_addr), serverinfo->ai_addrlen) < 0)
        {
            printf("errno: %s\n", strerror(errno));
            fprintf(stderr, "sendto err :)\n");
            return 1;
        }




        free(data);
    }

	// //šifrovanie
/*
	const unsigned char cyphertext[] = "XKVASN14";
	int cyphertextlen = 10;

	AES_KEY key_e;
	AES_KEY key_d;
	AES_set_encrypt_key((const unsigned char *)"xlogin00", 128, &key_e);
	AES_set_decrypt_key((const unsigned char *)"xlogin00", 128, &key_d);

	unsigned char *output = (unsigned char *)calloc(cyphertextlen + (AES_BLOCK_SIZE % cyphertextlen), 1);

	AES_encrypt(cyphertext, output, &key_e);

	printf("encrypted: ");
	for (int i = 0; i < AES_BLOCK_SIZE; ++i)
	{
		printf("%X ", output[i]);
	}
	printf("\n");

	AES_decrypt(output, output, &key_d);

	printf("decrypted: %s\n", output);

    AES_KEY key_d;
    AES_set_decrypt_key((const unsigned char *)"xlogin00", 128, &key_d);
    AES_decrypt(data, data, &key_d);
    printf("decrypted: %s\n", data);
    //free(data);
*/
    return 0;
}

int server_branch(int argc, char* argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];  // constant defined in pcap.h
    pcap_t *handle;                 // packet capture handle
    pcap_if_t *alldev, *dev ;       // a list of all input devices
    char *devname;                  // a name of the device
    struct in_addr a,b;
    bpf_u_int32 netaddr;            // network address configured at the input device
    bpf_u_int32 mask;               // network mask of the input device
    struct bpf_program fp;          // the compiled filter

    if (argc != 2)
        errx(1,"Usage: %s <pcap filter>", argv[0]);

    // open the input devices (interfaces) to sniff data
    if (pcap_findalldevs(&alldev, errbuf))
        err(1,"Can't open input device(s)");

    // list the available input devices
    printf("Available input devices are: ");
    for (dev = alldev; dev != NULL; dev = dev->next){
        printf("%s ",dev->name);
    }
    printf("\n");

    devname = alldev->name;  // select the name of first interface (default) for sniffing

    // get IP address and mask of the sniffing interface
    if (pcap_lookupnet(devname,&netaddr,&mask,errbuf) == -1)
        err(1,"pcap_lookupnet() failed");

    a.s_addr=netaddr;
    printf("Opening interface \"%s\" with net address %s,",devname,inet_ntoa(a));
    b.s_addr=mask;
    printf("mask %s for listening...\n",inet_ntoa(b));

    // open the interface for live sniffing
    if ((handle = pcap_open_live(devname,BUFSIZ,1,1000,errbuf)) == NULL)
        err(1,"pcap_open_live() failed");

    // compile the filter
    //if (pcap_compile(handle,&fp,argv[1],0,netaddr) == -1)
    //    err(1,"pcap_compile() failed");
    if (pcap_compile(handle,&fp,"icmp or icmp6",0,netaddr) == -1)
        err(1,"pcap_compile() failed");


    // set the filter to the packet capture handle
    if (pcap_setfilter(handle,&fp) == -1)
        err(1,"pcap_setfilter() failed");

    // read packets from the interface in the infinite loop (count == -1)
    // incoming packets are processed by function mypcap_handler()
    if (pcap_loop(handle,-1,mypcap_handler,NULL) == -1)
        err(1,"pcap_loop() failed");

    // close the capture device and deallocate resources
    pcap_close(handle);
    pcap_freealldevs(alldev);
    return 0;
}

int main (int argc, char *argv[])
{
    std::string rfile;
    std::string ipaddress;

    int isserver = argument_parser(argc,argv,&ipaddress,&rfile);

    if(isserver == -1)
    {
        error_handler("Missing Arguments\n",3);
    }
    if(isserver == 1)
    {
        // CALL SERVER BRANCH
        server_branch(argc, argv);
    }
    else
    {
        // CALL CLIENT BRANCH
        is_file(rfile);
        client_branch(ipaddress,rfile);
    }
    return 0;
}
