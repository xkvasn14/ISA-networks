#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>
#include <iostream>
#include <filesystem>
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
    while ((opt = getopt(argc, argv, "-r:-i:-I")) != -1)
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
                rfile->assign(optarg,sizeof(optarg));
                isrFile = true;
                break;
            /// assignes value of -i delimiter
            case 'i':
                //strcpy(ipaddress, optarg);
                ipaddress->assign(optarg,sizeof (optarg));
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

void write_to_file()
{

}

void mypcap_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ip *my_ip;               // pointer to the beginning of IP header
    struct ether_header *eptr;      // pointer to the beginning of Ethernet header
    const struct tcphdr *my_tcp;    // pointer to the beginning of TCP header
    const struct udphdr *my_udp;    // pointer to the beginning of UDP header
    u_int size_ip;

    n++;

    /// Only my icmp packet filter
    if(!(packet[34] == 'E' && packet[35] == 'E' && packet[36] == 'E'))
        return;


    int count = 0;
    unsigned char data[10];
    printf("Read Encrypted Data: ");
    for (int i = 0; i < header->len; ++i)
    {
        printf("%X ", packet[i]);
    }
    printf("\nRead Data: ");
    for (int i = 45; i < header->len; ++i)
	{
		printf("%c ", packet[i]);
        data[count] = packet[i];
        count++;
	}
    printf("\nData: %s\n",data);
    printf("Showed encrypted data to decrypt: ");
    for (int i = 0; i < count; ++i)
    {
        printf("%X ", data[i]);
    }
    printf("\n");
    AES_KEY key_d;
    AES_set_decrypt_key((const unsigned char *)"xlogin00", 128, &key_d);
    AES_decrypt(data, data, &key_d);
    printf("decrypted: %s\n", data);





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
    }
}

void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET)
    {
        return &(((struct sockaddr_in *)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}

int client_branch()
{
    struct addrinfo hints, *serverinfo;
    memset(&hints, 0, sizeof(hints));

    //char *host = (char*)("google.sk");
    char *host = (char*)("147.229.192.125");
    int result;

    //hints.ai_family = AF_UNSPEC;
    hints.ai_family = AF_INET;
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


	char packet[1500];
	const unsigned char dataIn[] = "XKVASN14";
	int datalen = 10;

    // data = read_file();

    AES_KEY key_encr;
    AES_set_encrypt_key((const unsigned char *)"xlogin00", 128, &key_encr);
    unsigned char *data = (unsigned char *)calloc(datalen + (AES_BLOCK_SIZE % datalen), 1);
    AES_encrypt(dataIn, data, &key_encr);
    printf("Read Encrypted Data: ");
    for (int i = 0; i < datalen; ++i)
    {
        printf("%X ", data[i]);
    }
    printf("\n");



	memset(&packet, 0, 1500);

	struct icmphdr *icmp_header = (struct icmphdr *)packet;
	icmp_header->code = ICMP_ECHO;
	icmp_header->checksum = 0;
	//vypočitaj si checksum ak chceš :)


    struct mystruct {
        char key1;
        char key2;
        char key3;
    };

    struct mystruct *dah = (struct mystruct *) packet;
    dah->key1 = 69;
    dah->key2 = 69;
    dah->key3 = 69;

    memcpy(packet + sizeof(struct icmphdr) + sizeof(struct mystruct), data, datalen);


	//memcpy(packet + sizeof(struct icmphdr), data, datalen);

	// MAXDATALEN = MTU(1500B) - zvyšna velkost čo si spotreboval :)

	if (sendto(sock, packet, sizeof(struct icmphdr) + sizeof (struct mystruct)+ datalen, 0, (struct sockaddr *)(serverinfo->ai_addr), serverinfo->ai_addrlen) < 0)
	{
        printf("errno: %s\n",strerror(errno));
		fprintf(stderr, "sendto err :)\n");
		return 1;
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

    // Is_file(rfile);

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
        client_branch();
    }
    return 0;
}
