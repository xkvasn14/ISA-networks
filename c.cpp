#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <iostream>
#include <netdb.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <openssl/aes.h>
#include <sys/socket.h>
#include <pcap/pcap.h>
#include <errno.h>
#define __FAVOR_BSD          // important for tcphdr structure
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <err.h>


#ifndef PCAP_ERRBUF_SIZE
#define PCAP_ERRBUF_SIZE (256)
#endif

#define SIZE_ETHERNET (14)       // offset of Ethernet header to L3 protocol

/// packet couters
int n = 0;
int packetCounterR = 1;

/// packet keys
struct keys {
    char key1;
    char key2;
    char key3;
    char name[48];
};

/// filename struct
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
    /// variable initialization
    int opt;
    bool isserver = false;
    bool isrFile = false;
    bool isIpaddress = false;

    /// checks for arguments
    while ((opt = getopt(argc, argv, "-r:-s:-I")) != -1)
    {
        switch (opt)
        {
            /// assignes values of -r delimiter
            case 'r':
                rfile->append(optarg);
                isrFile = true;
                break;
            /// assignes value of -i delimiter
            case 's':
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

    /// 1 for server, 0 for client, -1 error
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

/// https://www.techiedelight.com/implement-substr-function-c/
/// Following function extracts characters present in `src`
/// between `m` and `n` (excluding `n`)
char* substr(const char *src, int m, int n)
{
    /// get the length of the destination string
    int len = n - m;

    /// allocate (len + 1) chars for destination (+1 for extra null character)
    char *dest = (char*)malloc(sizeof(char) * (len + 1));

    /// extracts characters between m'th and n'th index from source string
    /// and copy them into the destination string
    for (int i = m; i < n && (*(src + i) != '\0'); i++)
    {
        *dest = *(src + i);
        dest++;
    }

    /// null-terminate the destination string
    *dest = '\0';

    /// return the destination string
    return dest - len;
}

void mypcap_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

    struct ip *my_ip;               /// pointer to the beginning of IP header
    struct ether_header *eptr;      /// pointer to the beginning of Ethernet header
    const struct tcphdr *my_tcp;    /// pointer to the beginning of TCP header
    const struct udphdr *my_udp;    /// pointer to the beginning of UDP header
    u_int size_ip;
    n++;

    /// Creating decrytion key
    AES_KEY key_d;
    AES_set_decrypt_key((const unsigned char *)"xkvasn14", 128, &key_d);

    /// Only my icmp packet filter
    if(!(packet[34] == 'E' && packet[35] == 'E' && packet[36] == 'E'))
        return;

    /// preparing memory
    unsigned char *filecopyname = (unsigned char *) calloc(16,1);
    unsigned char *filetocopyname = (unsigned char *) calloc(16,1);
    unsigned char*rfile = (unsigned char*) calloc(48,1);

    /// getting filename and path if 16B long
    memcpy(filecopyname, packet + 37, 16);
    AES_decrypt((const unsigned char*)filecopyname, filetocopyname, &key_d);
    memcpy(rfile,filetocopyname,16);
    /// getting filename and path if 32B long
    if((int)packet[37+16] != 0)
    {
        memcpy(filecopyname, packet + 37 + 16, 16);
        AES_decrypt((const unsigned char *) filecopyname, filetocopyname, &key_d);
        memcpy(rfile+16,filetocopyname,16);
    }
    /// getting filename and path if 32B longer
    if((int)packet[37+16+16] != 0)
    {
        memcpy(filecopyname, packet + 37+16+16, 16);
        AES_decrypt((const unsigned char*)filecopyname,filetocopyname, &key_d);
        memcpy(rfile+32,filetocopyname,16);
    }

    /// free tmp memory
    free(filecopyname);
    free(filetocopyname);


    /// initializing memory for data
    unsigned char* data = (unsigned char *)calloc(header->len - 93, 1);
    unsigned char* datatocopy = (unsigned char *) calloc(16,1);

    /// copying data to memory
    memcpy(data, packet + 93, header->len - 93);

    /// opening file
    int i = 0;
    FILE *file = fopen((const char*)rfile,"a");

    /// message for user
    fflush(stdout);
    printf("Packet %d recieved!\n",packetCounterR++);

    /// data decrypting and writing into file
    while(i < header->len - 93)
    {
        memcpy(datatocopy,data + i, 16);
        AES_decrypt(datatocopy, datatocopy, &key_d);
        /// write into file by 16 chars...
        fputs((const char*)datatocopy,file);
        i+=16;
    }

    /// close file, free memory
    fclose(file);
    free(data);
    free(rfile);
    free(datatocopy);
}

void *get_addr(struct sockaddr *sck)
{
    /// ipv4 or ipv6 determination
    if (sck->sa_family == AF_INET)
    {
        return &(((struct sockaddr_in *)sck)->sin_addr);
    }
    return &(((struct sockaddr_in6 *)sck)->sin6_addr);
}

int client_branch(std::string ipaddress, std::string rfile)
{
    /// initialization of memory, encryt key, socket, ipv4/6 protocol
    int packetcounter = 0;
    int result;
    AES_KEY key_encr;
    AES_set_encrypt_key((const unsigned char *)"xkvasn14", 128, &key_encr);
    struct addrinfo hints, *serverinfo;
    memset(&hints, 0, sizeof(hints));
    char *host = (char*)ipaddress.c_str();
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_RAW;

    /// realizing host address
    if ((result = getaddrinfo(host, NULL, &hints, &serverinfo)) != 0)
        error_handler(gai_strerror(result),-1);

    char ip[100];
    /// getting host address
    inet_ntop(serverinfo->ai_family, get_addr(serverinfo->ai_addr), ip, 100);

    /// choosing protocol
    int protocol = serverinfo->ai_family == AF_INET ? IPPROTO_ICMP : IPPROTO_ICMPV6;

    /// getting socket
    int sock = socket(serverinfo->ai_family, serverinfo->ai_socktype, protocol);
    if (sock == -1)
        error_handler("socket error",-1);

    /// message for user
    printf("ip: %s\n", ip);
    printf("ip:family: %d\n",serverinfo->ai_family);
    printf("socktype: %d\n", serverinfo->ai_socktype);
    printf("protocol: %d\n",protocol);

    /// DATA ENCRYPTION
    FILE *file = fopen(rfile.c_str(), "r");
    unsigned char dataIn[998];

    /// file parser and sender
    while(fread(dataIn,1,998,file))
    {
        /// timer for sending packets
        sleep(1);

        /// packet initialization
        char packet[1500];
        memset(&packet, 0, 1500);

        /// construcing ICMP header
        struct icmphdr *icmp_header = (struct icmphdr *) packet;
        icmp_header->code = ICMP_ECHO;
        icmp_header->checksum = 0;

        /// FILENAME ENCRYPTION
        unsigned char *dataFile = (unsigned char *) calloc(48 + (AES_BLOCK_SIZE % 48), 1);
        /// encryption of file name if smaller then 16
        if (strlen(basename(rfile.c_str())) <= 16)
        {
            AES_encrypt((const unsigned char *) basename(rfile.c_str()), dataFile, &key_encr);
        }
        else
        {
            /// encryption of file name if smaller then 32
            if (strlen(basename(rfile.c_str())) <= 32)
            {
                /// memory preparation
                unsigned char *fname = (unsigned char *) calloc(16, 1);
                unsigned char *fcopyname = (unsigned char *) calloc(32, 1);

                /// filename encryption and data copy
                AES_encrypt((const unsigned char *) substr(basename(rfile.c_str()), 0, 16), (unsigned char *) fname,
                            &key_encr);
                memcpy(fcopyname, fname, 16);
                AES_encrypt(
                        (const unsigned char *) substr(basename(rfile.c_str()), 16, strlen(basename(rfile.c_str()))),
                        (unsigned char *) fname, &key_encr);
                memcpy(fcopyname + 16, fname, 16);
                memcpy(dataFile, fcopyname, 32);

                /// free tmp memory
                free(fname);
                free(fcopyname);
            }
            else
            {
                /// encryption of file name if smaller then 48
                if (strlen(basename(rfile.c_str())) <= 48)
                {
                    /// memory preparation
                    unsigned char *fname = (unsigned char *) calloc(16, 1);
                    unsigned char *fcopyname = (unsigned char *) calloc(32, 1);

                    /// filename encryption and data copy
                    AES_encrypt((const unsigned char *) substr(basename(rfile.c_str()), 0, 16), (unsigned char *) fname,
                                &key_encr);
                    memcpy(fcopyname, fname, 16);
                    AES_encrypt((const unsigned char *) substr(basename(rfile.c_str()), 16, 32),
                                (unsigned char *) fname, &key_encr);
                    memcpy(fcopyname + 16, fname, 16);
                    AES_encrypt((const unsigned char *) substr(basename(rfile.c_str()), 32,
                                                               strlen(basename(rfile.c_str()))),
                                (unsigned char *) fname, &key_encr);
                    memcpy(fcopyname + 32, fname, 16);
                    memcpy(dataFile, fcopyname, 48);

                    /// free tmp memory
                    free(fname);
                    free(fcopyname);
                }
                else
                    /// name of file is too big to send
                    error_handler("Name of file is too long", -1);
            }
        }

        /// GET NAME OF THE FILE
        /// preparing our keys for our packets
        struct keys *dah = (struct keys *) packet;
        dah->key1 = 69;
        dah->key2 = 69;
        dah->key3 = 69;

        /// filename copy into packet
        memcpy(dah->name, dataFile, 48);

        /// getting right memory for data
        int memAlocSize = 0;
        int datalen = strlen((char *) dataIn);
        /// GETTING memory size for excryption process
        while (datalen > memAlocSize)
            memAlocSize += 16;

        /// data encryption
        unsigned char *data = (unsigned char *) calloc(memAlocSize, 1);
        int i = 0;
        while (i < memAlocSize)
        {
            /// tmp memory initialization
            unsigned char *encrypteddata = (unsigned char *) calloc(16, 1);

            /// data encryption if smaller then 16B
            if (i == (memAlocSize - 16))
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

            /// decryption key to show decrypted data - forgot to remove
            AES_KEY key_d;
            AES_set_decrypt_key((const unsigned char *) "xkvasn14", 128, &key_d);
            AES_decrypt(encrypteddata, encrypteddata, &key_d);

            /// free tmp data
            free(encrypteddata);
        }


        /// HEADER AND DATA TO PACKET
        memcpy(packet + sizeof(struct icmphdr) + sizeof(struct keys), data, memAlocSize);


        /// PACKET SENDING
        if (sendto(sock, packet, sizeof(struct icmphdr) + sizeof(struct keys) + memAlocSize, 0,
                   (struct sockaddr *) (serverinfo->ai_addr), serverinfo->ai_addrlen) < 0)
        {
            printf("errno: %s\n", strerror(errno));
            fprintf(stderr, "sendto err :)\n");
            return 1;
        }

        /// message for user
        packetcounter++;
        printf("Packet n.%d has been sent!\n", packetcounter);

        /// free data
        free(data);

        /// reinitializing data
        memset(&dataIn, '\0', 998);
    }

    /// message for user
    printf("The end\n");
    return 0;
}

int server_branch(int argc, char* argv[])
{
    /// VUT ISA examples
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

    /// open the input devices (interfaces) to sniff data
    if (pcap_findalldevs(&alldev, errbuf))
        err(1,"Can't open input device(s)");

    /// list the available input devices
    printf("Available input devices are: ");
    for (dev = alldev; dev != NULL; dev = dev->next){
        printf("%s ",dev->name);
    }
    printf("\n");

    devname = alldev->name;  // select the name of first interface (default) for sniffing

    /// get IP address and mask of the sniffing interface
    if (pcap_lookupnet(devname,&netaddr,&mask,errbuf) == -1)
        err(1,"pcap_lookupnet() failed");

    a.s_addr=netaddr;
    printf("Opening interface \"%s\" with net address %s,",devname,inet_ntoa(a));
    b.s_addr=mask;
    printf("mask %s for listening...\n",inet_ntoa(b));

    /// open the interface for live sniffing
    if ((handle = pcap_open_live(devname,BUFSIZ,1,1000,errbuf)) == NULL)
        err(1,"pcap_open_live() failed");

    /// compile the filter
    ///if (pcap_compile(handle,&fp,argv[1],0,netaddr) == -1)
    ///    err(1,"pcap_compile() failed");
    if (pcap_compile(handle,&fp,"icmp or icmp6",0,netaddr) == -1)
        err(1,"pcap_compile() failed");


    /// set the filter to the packet capture handle
    if (pcap_setfilter(handle,&fp) == -1)
        err(1,"pcap_setfilter() failed");

    /// read packets from the interface in the infinite loop (count == -1)
    /// incoming packets are processed by function mypcap_handler()
    if (pcap_loop(handle,-1,mypcap_handler,NULL) == -1)
        err(1,"pcap_loop() failed");

    /// close the capture device and deallocate resources
    pcap_close(handle);
    pcap_freealldevs(alldev);
    return 0;
}

int main (int argc, char *argv[])
{
    /// variables initialization
    std::string rfile;
    std::string ipaddress;

    /// reading arguments
    int isserver = argument_parser(argc,argv,&ipaddress,&rfile);

    /// arguments handling
    if(isserver == -1)
    {
        error_handler("Missing Arguments\n",3);
    }
    if(isserver == 1)
    {
        /// CALL SERVER BRANCH
        server_branch(argc, argv);
    }
    else
    {
        /// CALL CLIENT BRANCH
        is_file(rfile);
        client_branch(ipaddress,rfile);
    }
    return 0;
}
