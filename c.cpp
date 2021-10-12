#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>
#include <iostream>
#include <string.h>
#include <filesystem>


int argument_parser(int argc, char** argv, char *ipaddress, char *rfile)
{
    int opt;
    bool isserver = false;
    bool isrFile = false;
    bool isIpaddress = false;

    while((opt = getopt(argc,argv,"-r:-i:-I")) != -1)
    {
        switch (opt)
        {
            /*
            case 'h':
             call help;
             break;
             * */
            case 'r':
                strcpy(rfile, optarg);
                isrFile = true;
                break;
            case 'i':
                strcpy(ipaddress, optarg);
                isIpaddress = true;
                break;
            case 'I':
                isserver = true;
                break;
            default:
                printf("Wrong arguments");
                exit(1);
                break;
        }
        printf("Isserver: %d\n",isserver);
    }
    printf("Isserver: %d\n",isserver);
    if (isserver)
        return 1;
    if(isrFile && isIpaddress)
        return 0;
    return -1;
}


int main (int argc, char *argv[])
{
    char *ipaddress = (char*)malloc(50*sizeof(char));
    char *rfile = (char*)malloc(50*sizeof(char));

    int isserver = argument_parser(argc,argv,ipaddress,rfile);
    if(isserver == -1)
    {
        printf("Some arguments are missing\n");
        free(ipaddress);
        free(rfile);
    }
    if(isserver == 1)
    {
        // CALL SERVER BRANCH
    }
    else
    {
        // CALL CLIENT BRANCH
    }
    return 0;
}