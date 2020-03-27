#include <sys/socket.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/ioctl.h>

#ifndef SIOCGIFCONF
#include <sys/sockio.h>
#endif

#define WORD unsigned short
#define BYTE unsigned char
#define DWORD unsigned long

void getServ(DWORD *servers, WORD *ports, const BYTE max_servers)
{
	struct ifconf Ifc;
	struct ifreq IfcBuf[max_servers];
	struct ifreq *pIfr;
	int num_ifreq;
	int i;
	int fd;

	Ifc.ifc_len = sizeof(IfcBuf);
	Ifc.ifc_buf = (char *) IfcBuf;

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) >= 0)
	{
		if ( ioctl(fd, SIOCGIFCONF, &Ifc) >= 0)
		{
			num_ifreq = Ifc.ifc_len / sizeof(struct ifreq);

			for ( pIfr = Ifc.ifc_req, i = 0 ; i < num_ifreq; pIfr++, i++ )
			{
				DWORD ip = ((sockaddr_in*)(&pIfr->ifr_ifru.ifru_addr))->sin_addr.s_addr;

				for (BYTE j = 0; j < max_servers; j++)
				{
					if (servers[j] == ip)
						break;
					else if (!servers[j])
					{
						servers[j] = ip;
						ports[j] = 69;
						break;
					}
				}
			}
		}
	}
}

