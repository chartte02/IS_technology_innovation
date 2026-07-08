#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

unsigned int controlled_protocol = 0;
unsigned short controlled_srcport = 0;
unsigned short controlled_dstport = 0;
unsigned int controlled_saddr = 0;
unsigned int controlled_daddr = 0; 

void display_usage(char *commandname)
{
	printf("Usage 1: %s \n", commandname); //Don't filter
	printf("Usage 2: %s -p protocol -x saddr -y daddr -m srcport -n dstport \n", commandname);
}

int getpara(int argc, char *argv[]){
	int optret;
	unsigned short tmpport;
	optret = getopt(argc,argv,"pxymnh");
	while( optret != -1 ) {
		//printf(" first in getpara: %s\n",argv[optind]);
        	switch( optret ) {
        		case 'p':
        			if (strncmp(argv[optind], "ping",4) == 0 )
					controlled_protocol = 1;
				else if ( strncmp(argv[optind], "tcp",3) == 0  )
					controlled_protocol = 6;
					else if ( strncmp(argv[optind], "udp",3) == 0 )
						controlled_protocol = 17;
					else {
						printf("Unkonwn protocol! please check and try again! \n");
						exit(1);
					}
        			break;
         		case 'x':   //get source ipaddr 
				if ( inet_aton(argv[optind], (struct in_addr* )&controlled_saddr) == 0){
					printf("Invalid source ip address! please check and try again! \n ");
					exit(1);
				}
         			break;
         		case 'y':   //get destination ipaddr
				if ( inet_aton(argv[optind], (struct in_addr* )&controlled_daddr) == 0){
					printf("Invalid destination ip address! please check and try again! \n ");
					exit(1);
				}
         			break;
         		case 'm':   //get destination ipaddr
				tmpport = atoi(argv[optind]);
				if (tmpport == 0){
					printf("Invalid source port! please check and try again! \n ");
					exit(1);
				}
				controlled_srcport = htons(tmpport);
         			break;
        		case 'n':   //get destination ipaddr
				tmpport = atoi(argv[optind]);
				if (tmpport == 0){
					printf("Invalid source port! please check and try again! \n ");
					exit(1);
				}
				controlled_dstport = htons(tmpport);
         			break;
         		case 'h':   /* fall-through is intentional */
         		case '?':
         			display_usage(argv[0]);
         			exit(1);;
                
         		default:
				printf("Invalid parameters! \n ");
         			display_usage(argv[0]);
         			exit(1);;
        	}
		optret = getopt(argc,argv,"pxymnh");
	}
}

int main(int argc, char *argv[]){
	char controlinfo[32];
	int controlinfo_len = 0;
	int fd;
	struct stat buf;
	
	if (argc == 1) 
		controlinfo_len = 0; //cancel the filter
	else if (argc > 1){
		getpara(argc, argv);
		*(int *)controlinfo = controlled_protocol;
		*(int *)(controlinfo + 4) = controlled_saddr;
		*(int *)(controlinfo + 8) = controlled_daddr;
		*(int *)(controlinfo + 12) = controlled_srcport;
		*(int *)(controlinfo + 16) = controlled_dstport;
		controlinfo_len = 20;
	}
	
	//printf("input info: p = %d, x = %d y = %d m = %d n = %d \n", controlled_protocol,controlled_saddr,controlled_daddr,controlled_srcport,controlled_dstport);

	if (stat("/dev/controlinfo",&buf) != 0){
		if (system("mknod /dev/controlinfo c 124 0") == -1){
			printf("Cann't create the devive file ! \n");
			printf("Please check and try again! \n");
			exit(1);
		}
	}
	fd =open("/dev/controlinfo",O_RDWR,S_IRUSR|S_IWUSR);
	if (fd > 0)
	{
		write(fd,controlinfo,controlinfo_len);
	}
	else {
		perror("can't open /dev/controlinfo \n");
	 	exit(1);
	}
	close(fd);
}
