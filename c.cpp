#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>
#include <iostream>
#include <string.h>
#include <filesystem>

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


int main (int argc, char *argv[])
{
    std::string rfile;
    std::string ipaddress;

    int isserver = argument_parser(argc,argv,&ipaddress,&rfile);
    if(isserver == -1)
    {
        error_handler("Missing Arguments",3);
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