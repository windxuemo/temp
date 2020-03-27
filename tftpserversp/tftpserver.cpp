/**************************************************************************
*   Copyright (C) 2005 by Achal Dhir                                      *
*   achaldhir@gmail.com                                                   *
*                                                                         *
*   This program is free software; you can redistribute it and/or modify  *
*   it under the terms of the GNU General Public License as published by  *
*   the Free Software Foundation; either version 2 of the License, or     *
*   (at your option) any later version.                                   *
*                                                                         *
*   This program is distributed in the hope that it will be useful,       *
*   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
*   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
*   GNU General Public License for more details.                          *
*                                                                         *
*   You should have received a copy of the GNU General Public License     *
*   along with this program; if not, write to the                         *
*   Free Software Foundation, Inc.,                                       *
*   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
***************************************************************************/

// tftpserver.cpp

#include <sys/types.h>
#include <limits.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/time.h>
#include <time.h>
#include <stdlib.h>
#include <limits.h>
#include <memory.h>
#include <sys/stat.h>
#include <stdio.h>
#include <syslog.h>
#include <string>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <map>
using namespace std;
#include "tftpserver.h"

//Functions
void runProg();
int processNew(request*);
int processSend(request*);
int processRecv(request*);
char *cleanstr(char*, bool);
void init();
void closeConn();
void catch_int(int sig_num);
bool getSection(char*, char*, int, char*);
char *myLower(char*);
char *myUpper(char*);
char* IP2String(char*, DWORD);
void clean(request*);
extern void getServ(DWORD*, WORD*, const BYTE);
bool isIP(char*);
void logMess(request*, BYTE);
void logMess(char*, BYTE);
DWORD my_inet_addr(char*);

//types
typedef map<string, request*> myMap;
typedef multimap<long, request*> myMultiMap;

//Global Variables
bool kRunning = true;
myMap tftpCache;
myMultiMap tftpAge;
bool verbatim = false;
char iniFile[256]="";
char logFile[256]="";
WORD blksize = 65464;
WORD interval = 3;
data2 cfig;
char tempbuff[256];
char logBuff[512];
packet* datain;
tftperror serverError;

int main(int argc, char **argv)
{
	signal(SIGINT, catch_int);
	signal(SIGABRT, catch_int);
	signal(SIGTERM, catch_int);
	signal(SIGQUIT, catch_int);
	signal(SIGTSTP, catch_int);
	//signal(SIGHUP, catch_int);

	for (int i = 1; i < argc; i++)
	{
		if (!strcmp(argv[i], "-v"))
			verbatim = true;
		else if (!strcmp(argv[i], "-i") && argc > i+1 && argv[i+1][0] != '-' )
		{
			strcpy(iniFile, argv[i+1]);
			i++;
		}
		else if (!strcmp(argv[i], "-l") && argc > i+1 && argv[i+1][0] != '-' )
		{
			strcpy(logFile, argv[i+1]);
			i++;
		}
		else if (!strncmp(argv[i], "-i", 2))
			strcpy(iniFile, argv[i] + 2);
		else if (!strncmp(argv[i], "-l", 2))
			strcpy(iniFile, argv[i] + 2);
		else
		{
			sprintf(logBuff, "Invalid argument %s", argv[i]);
			logMess(logBuff, 0);
			exit(1);
		}
	}

	if (!iniFile[0])
		strcpy(iniFile,"/etc/tftpserver.ini");

	if (verbatim)
	{
		init();
		timeval tv;
		fd_set readfds;
		request req;
		datain = (packet*)calloc(1, blksize + 4);
		int fdsReady = 0;

		if (!datain)
		{
			sprintf(logBuff,"Memory Error");
			logMess(logBuff, 0);
			exit(1);
		}

		if (cfig.tftpConn[0].server)
		{
			printf("\nAccepting requests..\n");

			do
			{
				FD_ZERO(&readfds);
				tv.tv_sec = 1;
				tv.tv_usec = 0;

				for (int i = 0; i < MAX_SERVERS && cfig.tftpConn[i].server; i++)
					FD_SET(cfig.tftpConn[i].sock, &readfds);

				fdsReady = select(cfig.maxFD, &readfds, NULL, NULL, &tv);

				//if (errno)
				//	printf("%s\n", strerror(errno));

				for (int i = 0; fdsReady > 0 && i < MAX_SERVERS && cfig.tftpConn[i].server; i++)
				{
					if (FD_ISSET(cfig.tftpConn[i].sock, &readfds))
					{
						fdsReady--;
						memset(&req, 0, sizeof(request));
						memset(datain, 0, blksize + 4);
						req.clientsize = sizeof(req.client);
						req.sockInd = i;
						errno = 0;
						req.bytesRecd = recvfrom(cfig.tftpConn[req.sockInd].sock, (char*)datain, blksize + 4, 0, (sockaddr*)&req.client, &req.clientsize);
						sprintf(req.mapname, "%s:%u", inet_ntoa(req.client.sin_addr), ntohs(req.client.sin_port));
						request *req1 = tftpCache[req.mapname];

						if (!req1)
							tftpCache.erase(req.mapname);


						if (req1)
						{
							req1->bytesRecd = req.bytesRecd;

							if (req1->bytesRecd < 4 || errno)
							{
								sprintf(serverError.errormessage, "Communication Error");
								logMess(req1, 1);
								req1->attempt = UCHAR_MAX;
							}
							else if (ntohs(datain->opcode) == 1 || ntohs(datain->opcode) == 2)
							{
								if (req1->file || req1->attempt <= 3)
									continue;
							}
							else if (ntohs(datain->opcode) == 3 && (req1->bytesRecd - 4) > req1->blksize)
							{
								if (req1->attempt <= 3)
									continue;
							}
							else if (ntohs(datain->opcode) == 3 && req1->opcode == 2)
							{
								req1->tblock = req1->block + 1;
								if (ntohs(datain->block) == req1->tblock)
								{
									req1->block = req1->tblock;
									req1->fblock++;
									req1->attempt = 0;
									req1->acout.opcode = htons(4);
									req1->acout.block = ntohs(req1->block);
									processRecv(req1);
								}
							}
							else if (ntohs(datain->opcode) == 4 && req1->opcode == 1)
							{
								if (ntohs(datain->block) == req1->block)
								{
									req1->block++;
									req1->fblock++;
									req1->attempt = 0;
									req1->bytesRecd = req.bytesRecd;
									processSend(req1);
								}
							}
							else if (ntohs(datain->opcode) == 5)
							{
								sprintf(serverError.errormessage, "Error %i at Client, %s", ntohs(datain->block), &datain->buffer);
								logMess(req1, 1);
								req1->attempt = UCHAR_MAX;
								if (req1->file)
								{
									fclose(req1->file);
									req1->file = 0;
								}
							}
							else
							{
								serverError.opcode = htons(5);
								serverError.errorcode = htons(0);
								sprintf(serverError.errormessage, "Unexpected Option Code %u", ntohs(datain->opcode));
								req1->bytesSent = sendto(cfig.tftpConn[req1->sockInd].sock, (const char*)&serverError, strlen(serverError.errormessage) + 5, 0, (sockaddr*)&req1->client, req1->clientsize);
								logMess(req1, 1);
								req1->attempt = UCHAR_MAX;
								if (req1->file)
								{
									fclose(req1->file);
									req1->file = 0;
								}
							}
						}
						else if (req.bytesRecd < 4 || errno)
						{
							sprintf(serverError.errormessage, "Communication Error");
							logMess(&req, 1);
							continue;
						}
						else
						{
							if (cfig.hostRanges[0].rangeStart)
							{
								DWORD iip = ntohl(req.client.sin_addr.s_addr);
								BYTE allowed = 0;

								for (int j = 0; j <= sizeof(cfig.hostRanges) && cfig.hostRanges[j].rangeStart; j++)
								{
									if (iip >= cfig.hostRanges[j].rangeStart && iip <= cfig.hostRanges[j].rangeEnd)
									{
										allowed = 1;
										break;
									}
								}

								if (!allowed)
								{
									serverError.opcode = htons(5);
									serverError.errorcode = htons(2);
									strcpy(serverError.errormessage, "Access Denied");
									logMess(&req, 1);
									req.bytesSent = sendto(cfig.tftpConn[i].sock, (const char*) &serverError, strlen(serverError.errormessage) + 5, 0, (sockaddr*)&req.client, req.clientsize);
									continue;
								}
							}

							if (ntohs(datain->opcode) == 1 || ntohs(datain->opcode) == 2)
							{
								if (!processNew(&req))
								{
									request *req1 = (request*)calloc(1, sizeof(request));

									if (!req1)
									{
										sprintf(logBuff,"Memory Error");
										logMess(logBuff, 1);
										continue;
									}

									memcpy(req1, &req, sizeof(request));
									tftpCache[req1->mapname] = req1;
									tftpAge.insert(pair<long, request*>(req1->expiry, req1));
								}
							}
							else if (ntohs(datain->opcode) == 5)
							{
								sprintf(serverError.errormessage, "Error %i at Client, %s", ntohs(datain->block), &datain->buffer);
								logMess(&req, 1);
								continue;
							}
							else
							{
								serverError.opcode = htons(5);
								serverError.errorcode = htons(5);
								sprintf(serverError.errormessage, "Unknown transfer ID");
								req.bytesSent = sendto(cfig.tftpConn[i].sock, (const char*) &serverError, strlen(serverError.errormessage) + 5, 0, (sockaddr*)&req.client, req.clientsize);
								logMess(&req, 1);
							}
						}
					}
				}

				myMultiMap::iterator p = tftpAge.begin();
				myMultiMap::iterator q;
				time_t currentTime = time(NULL);

				while (p != tftpAge.end())
				{
					if (!tftpAge.size())
						break;

					request *req = (*p).second;

					if (p->first > currentTime)
					{
						break;
					}
					else if (p->first < req->expiry && req->expiry > currentTime)
					{
						q = p;
						p++;
						tftpAge.erase(q);
						tftpAge.insert(pair<long, request*>(req->expiry, req));
					}
					else if (req->expiry <= currentTime && req->attempt >= 3)
					{
						if (req->attempt < UCHAR_MAX)
						{
							serverError.opcode = htons(5);
							serverError.errorcode = htons(0);

							if (req->fblock && !req->block)
								strcpy(serverError.errormessage, "File too large for client");
							else
								strcpy(serverError.errormessage, "Timeout");

							req->bytesSent = sendto(cfig.tftpConn[req->sockInd].sock, (const char*) &serverError, strlen(serverError.errormessage) + 5, 0, (sockaddr*)&req->client, req->clientsize);
							logMess(req, 1);
						}

						q = p;
						p++;
						tftpAge.erase(q);
						tftpCache.erase(req->mapname);
						clean(req);
					}
					else if (req->expiry <= currentTime)
					{
						if (ntohs(req->acout.opcode) == 3)
						{
							if (processSend(req))
								req->attempt = 255;
							else
							{
								req->attempt++;
								req->expiry = currentTime + req->interval;
							}
						}
						else
						{
							errno = 0;
							req->bytesSent = sendto(cfig.tftpConn[req->sockInd].sock, (const char*)&req->acout, req->bytesSent, 0, (sockaddr*)&req->client, req->clientsize);

							if (errno)
								req->attempt = 255;
							else
							{
								req->attempt++;
								req->expiry = currentTime + req->interval;
							}
						}
						p++;
					}
					else
						p++;
				}
			}
			while (kRunning);

			for (int i = 0; i < MAX_SERVERS && cfig.tftpConn[i].server; i++)
				close(cfig.tftpConn[i].sock);
		}
	}
	else
	{
		/* Our process ID and Session ID */
		pid_t pid, sid;

		/* Fork off the parent process */
		pid = fork();
		if (pid < 0)
		{
			exit(EXIT_FAILURE);
		}
		/* If we got a good PID, then
		we can exit the parent process. */
		if (pid > 0)
		{
			exit(EXIT_SUCCESS);
		}

		/* Change the file mode mask */
		umask(0);

		/* Open any logs here */

		/* Create a new SID for the child process */
		sid = setsid();
		if (sid < 0)
		{
			/* Log the failure */
			exit(EXIT_FAILURE);
		}

		/* Close out the standard file descriptors */
		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		close(STDERR_FILENO);

		/* Daemon-specific initialization goes here */
		//Initialize
		verbatim = false;
		init();

		timeval tv;
		fd_set readfds;
		request req;
		datain = (packet*)calloc(1, blksize + 4);
		int fdsReady = 0;

		if (!datain)
		{
			sprintf(logBuff,"Memory Error");
			logMess(logBuff, 0);
			exit(1);
		}

		if (cfig.tftpConn[0].server)
		{
			do
			{
				FD_ZERO(&readfds);
				tv.tv_sec = 1;
				tv.tv_usec = 0;

				for (int i = 0; i < MAX_SERVERS && cfig.tftpConn[i].server; i++)
					FD_SET(cfig.tftpConn[i].sock, &readfds);

				fdsReady = select(cfig.maxFD, &readfds, NULL, NULL, &tv);

				//if (errno)
				//	printf("%s\n", strerror(errno));

				for (int i = 0; fdsReady > 0 && i < MAX_SERVERS && cfig.tftpConn[i].server; i++)
				{
					if (FD_ISSET(cfig.tftpConn[i].sock, &readfds))
					{
						fdsReady--;
						memset(&req, 0, sizeof(request));
						memset(datain, 0, blksize + 4);
						req.clientsize = sizeof(req.client);
						req.sockInd = i;
						errno = 0;
						req.bytesRecd = recvfrom(cfig.tftpConn[req.sockInd].sock, (char*)datain, blksize + 4, 0, (sockaddr*)&req.client, &req.clientsize);
						sprintf(req.mapname, "%s:%u", inet_ntoa(req.client.sin_addr), ntohs(req.client.sin_port));
						request *req1 = tftpCache[req.mapname];

						if (!req1)
							tftpCache.erase(req.mapname);

						//printf("%u\n",req1);

						if (req1)
						{
							req1->bytesRecd = req.bytesRecd;

							if (req1->bytesRecd < 4 || errno)
							{
								sprintf(serverError.errormessage, "Communication Error");
								logMess(req1, 1);
								req1->attempt = UCHAR_MAX;
							}
							else if (ntohs(datain->opcode) == 1 || ntohs(datain->opcode) == 2)
							{
								if (req1->file || req1->attempt <= 3)
									continue;
							}
							else if (ntohs(datain->opcode) == 3 && (req1->bytesRecd - 4) > req1->blksize)
							{
								if (req1->attempt <= 3)
									continue;
							}
							else if (ntohs(datain->opcode) == 3 && req1->opcode == 2)
							{
								req1->tblock = req1->block + 1;
								if (ntohs(datain->block) == req1->tblock)
								{
									req1->block = req1->tblock;
									req1->fblock++;
									req1->attempt = 0;
									req1->acout.opcode = htons(4);
									req1->acout.block = ntohs(req1->block);
									processRecv(req1);
								}
							}
							else if (ntohs(datain->opcode) == 4 && req1->opcode == 1)
							{
								if (ntohs(datain->block) == req1->block)
								{
									req1->block++;
									req1->fblock++;
									req1->attempt = 0;
									req1->bytesRecd = req.bytesRecd;
									processSend(req1);
								}
							}
							else if (ntohs(datain->opcode) == 5)
							{
								sprintf(serverError.errormessage, "Error %i at Client, %s", ntohs(datain->block), &datain->buffer);
								logMess(req1, 1);
								req1->attempt = UCHAR_MAX;
								if (req1->file)
								{
									fclose(req1->file);
									req1->file = 0;
								}
							}
							else
							{
								serverError.opcode = htons(5);
								serverError.errorcode = htons(0);
								sprintf(serverError.errormessage, "Unexpected Option Code %u", ntohs(datain->opcode));
								req1->bytesSent = sendto(cfig.tftpConn[req1->sockInd].sock, (const char*)&serverError, strlen(serverError.errormessage) + 5, 0, (sockaddr*)&req1->client, req1->clientsize);
								logMess(req1, 1);
								req1->attempt = UCHAR_MAX;
								if (req1->file)
								{
									fclose(req1->file);
									req1->file = 0;
								}
							}
						}
						else if (req.bytesRecd < 4 || errno)
						{
							sprintf(serverError.errormessage, "Communication Error");
							logMess(&req, 1);
							continue;
						}
						else
						{
							if (cfig.hostRanges[0].rangeStart)
							{
								DWORD iip = ntohl(req.client.sin_addr.s_addr);
								BYTE allowed = 0;

								for (int j = 0; j <= sizeof(cfig.hostRanges) && cfig.hostRanges[j].rangeStart; j++)
								{
									if (iip >= cfig.hostRanges[j].rangeStart && iip <= cfig.hostRanges[j].rangeEnd)
									{
										allowed = 1;
										break;
									}
								}

								if (!allowed)
								{
									serverError.opcode = htons(5);
									serverError.errorcode = htons(2);
									strcpy(serverError.errormessage, "Access Denied");
									logMess(&req, 1);
									req.bytesSent = sendto(cfig.tftpConn[i].sock, (const char*) &serverError, strlen(serverError.errormessage) + 5, 0, (sockaddr*)&req.client, req.clientsize);
									continue;
								}
							}

							if (ntohs(datain->opcode) == 1 || ntohs(datain->opcode) == 2)
							{
								if (!processNew(&req))
								{
									request *req1 = (request*)calloc(1, sizeof(request));

									if (!req1)
									{
										sprintf(logBuff,"Memory Error");
										logMess(logBuff, 1);
										continue;
									}

									memcpy(req1, &req, sizeof(request));
									tftpCache[req1->mapname] = req1;
									tftpAge.insert(pair<long, request*>(req1->expiry, req1));
								}
							}
							else if (ntohs(datain->opcode) == 5)
							{
								sprintf(serverError.errormessage, "Error %i at Client, %s", ntohs(datain->block), &datain->buffer);
								logMess(&req, 1);
								continue;
							}
							else
							{
								serverError.opcode = htons(5);
								serverError.errorcode = htons(5);
								sprintf(serverError.errormessage, "Unknown transfer ID");
								req.bytesSent = sendto(cfig.tftpConn[i].sock, (const char*) &serverError, strlen(serverError.errormessage) + 5, 0, (sockaddr*)&req.client, req.clientsize);
								logMess(&req, 1);
							}
						}
					}
				}

				myMultiMap::iterator p = tftpAge.begin();
				myMultiMap::iterator q;
				time_t currentTime = time(NULL);

				while (p != tftpAge.end())
				{
					if (!tftpAge.size())
						break;

					request *req = (*p).second;

					if (p->first > currentTime)
					{
						break;
					}
					else if (p->first < req->expiry && req->expiry > currentTime)
					{
						q = p;
						p++;
						tftpAge.erase(q);
						tftpAge.insert(pair<long, request*>(req->expiry, req));
					}
					else if (req->expiry <= currentTime && req->attempt >= 3)
					{
						if (req->attempt < UCHAR_MAX)
						{
							serverError.opcode = htons(5);
							serverError.errorcode = htons(0);

							if (req->fblock && !req->block)
								strcpy(serverError.errormessage, "File too large for client");
							else
								strcpy(serverError.errormessage, "Timeout");

							req->bytesSent = sendto(cfig.tftpConn[req->sockInd].sock, (const char*) &serverError, strlen(serverError.errormessage) + 5, 0, (sockaddr*)&req->client, req->clientsize);
							logMess(req, 1);
						}

						q = p;
						p++;
						tftpAge.erase(q);
						tftpCache.erase(req->mapname);
						clean(req);
					}
					else if (req->expiry <= currentTime)
					{
						if (ntohs(req->acout.opcode) == 3)
						{
							if (processSend(req))
								req->attempt = 255;
							else
							{
								req->attempt++;
								req->expiry = currentTime + req->interval;
							}
						}
						else
						{
							errno = 0;
							req->bytesSent = sendto(cfig.tftpConn[req->sockInd].sock, (const char*)&req->acout, req->bytesSent, 0, (sockaddr*)&req->client, req->clientsize);

							if (errno)
								req->attempt = 255;
							else
							{
								req->attempt++;
								req->expiry = currentTime + req->interval;
							}
						}
						p++;
					}
					else
						p++;
				}
			}
			while (kRunning);

			for (int i = 0; i < MAX_SERVERS && cfig.tftpConn[i].server; i++)
				close(cfig.tftpConn[i].sock);
		}
	}
}

void closeConn()
{
	kRunning = false;
	sprintf(logBuff, "Closing Network Connections...");
	logMess(logBuff, 1);

	for (int i = 0; i < MAX_SERVERS && cfig.tftpConn[i].server; i++)
		shutdown(cfig.tftpConn[i].sock, 2);

	for (int i = 0; i < MAX_SERVERS && cfig.tftpConn[i].server; i++)
		close(cfig.tftpConn[i].sock);

	sprintf(logBuff, "TFTP Server Stopped !");
	logMess(logBuff, 1);

	exit(EXIT_SUCCESS);
}

void catch_int(int sig_num)
{
	closeConn();
}

int processNew(request *req)
{
    req->block = 0;
    req->bytesSent = 0;
    req->blksize = 512;
    req->interval = interval - (interval / 2);
    req->expiry = time(NULL) + req->interval;
    req->opcode = ntohs(datain->opcode);
    char *temp = (char*)datain;
    temp += 2;
    req->filename = temp;
    temp += strlen(temp) + 1;
    req->mode = temp;
    temp += strlen(temp) + 1;
    req->alias = req->filename;

    for (int i = 0; i < strlen(req->alias); i++)
        if (req->alias[i] == '\\')
{
            printf("New branch\n");
            req->alias[i] = '/';
}

    if (strstr(req->alias, "../"))
    {
        serverError.opcode = htons(5);
        serverError.errorcode = htons(2);
        strcpy(serverError.errormessage, "Access violation");
        req->bytesSent = sendto(cfig.tftpConn[req->sockInd].sock, (const char*)&serverError, strlen(serverError.errormessage) + 5, 0, (sockaddr*)&req->client, req->clientsize);
        logMess(req, 1);
        req->attempt = UCHAR_MAX;
        return 1;
    }

    if (req->alias[0] == '/')
        req->alias++;

    if (!cfig.homes[0].alias[0])
    {
        strcpy(req->path, cfig.homes[0].target);
        strcat(req->path, req->alias);
    }
    else
    {
        char *ptr = strchr(req->alias, '/');

        if (ptr)
        {
            *ptr = 0;
            ptr++;
        }
        else
        {
            serverError.opcode = htons(5);
            serverError.errorcode = htons(2);
            sprintf(serverError.errormessage, "Missing directory/alias");
            req->bytesSent = sendto(cfig.tftpConn[req->sockInd].sock, (const char*)&serverError, strlen(serverError.errormessage) + 5, 0, (sockaddr*)&req->client, req->clientsize);
            logMess(req, 1);
            req->attempt = UCHAR_MAX;
            return 1;
        }

        for (int i = 0; i < 8; i++)
        {
            if (cfig.homes[i].alias[0] && !strcasecmp(req->alias, cfig.homes[i].alias))
            {
                strcpy(req->path, cfig.homes[i].target);
                strcat(req->path, ptr);
                break;
            }
            else if (i == 7 || !cfig.homes[i].alias[0])
            {
                serverError.opcode = htons(5);
                serverError.errorcode = htons(2);
                sprintf(serverError.errormessage, "No such directory/alias");
                req->bytesSent = sendto(cfig.tftpConn[req->sockInd].sock, (const char*)&serverError, strlen(serverError.errormessage) + 5, 0, (sockaddr*)&req->client, req->clientsize);
                logMess(req, 1);
                req->attempt = UCHAR_MAX;
                return 1;
            }
        }
    }

    if (ntohs(datain->opcode) == 1)
    {
        errno = 0;

        if (strcasecmp(req->mode, "netascii"))
            req->file = fopen(req->path, "rb");
        else
            req->file = fopen(req->path, "rt");

        if (errno || !req->file)
        {
            serverError.opcode = htons(5);
            serverError.errorcode = htons(1);
            strcpy(serverError.errormessage, "File Not Found");
            req->bytesSent = sendto(cfig.tftpConn[req->sockInd].sock, (const char*)&serverError, strlen(serverError.errormessage) + 5, 0, (sockaddr*)&req->client, req->clientsize);
            logMess(req, 1);
            req->attempt = UCHAR_MAX;
            return 1;
        }
    }
    else
    {
        if (!cfig.overwrite)
        {
            req->file = fopen(req->path, "rb");
            if (req->file)
            {
                fclose(req->file);
                req->file = 0;
                serverError.opcode = htons(5);
                serverError.errorcode = htons(6);
                strcpy(serverError.errormessage, "File already exists");
                req->bytesSent = sendto(cfig.tftpConn[req->sockInd].sock, (const char*)&serverError, strlen(serverError.errormessage) + 5, 0, (sockaddr*)&req->client, req->clientsize);
                logMess(req, 1);
                req->attempt = UCHAR_MAX;
                return 1;
            }
        }

        errno = 0;

        if (strcasecmp(req->mode, "netascii"))
            req->file = fopen(req->path, "wb");
        else
            req->file = fopen(req->path, "wt");

        if (errno || !req->file)
        {
            serverError.opcode = htons(5);
            serverError.errorcode = htons(1);
            strcpy(serverError.errormessage, "Invalid Path");
            req->bytesSent = sendto(cfig.tftpConn[req->sockInd].sock, (const char*)&serverError, strlen(serverError.errormessage) + 5, 0, (sockaddr*)&req->client, req->clientsize);
            logMess(req, 1);
            req->attempt = UCHAR_MAX;
            return 1;
        }
    }

    if (*temp)
    {
        char *pointer = req->acout.buffer;
        req->acout.opcode = htons(6);
        DWORD val;
        while (*temp)
        {
            //printf("%s", temp);
            if (!strcasecmp(temp, "blksize"))
            {
                strcpy(pointer, temp);
                pointer += strlen(pointer) + 1;
                temp += strlen(temp) + 1;
                val = atol(temp);

                if (val < 512)
                    val = 512;
                else if (val > blksize)
                    val = blksize;

                req->blksize = val;
                sprintf(pointer, "%u", val);
                pointer += strlen(pointer) + 1;
            }
            else if (!strcasecmp(temp, "tsize"))
            {
                strcpy(pointer, temp);
                pointer += strlen(pointer) + 1;
                temp += strlen(temp) + 1;
                fseek(req->file, 0, SEEK_END);
                req->tsize = ftell(req->file);
                sprintf(pointer, "%u", req->tsize);
                pointer += strlen(pointer) + 1;
            }
            else if (!strcasecmp(temp, "interval"))
            {
                strcpy(pointer, temp);
                pointer += strlen(pointer) + 1;
                temp += strlen(temp) + 1;
                val = atoi(temp);

                if (val < 1)
                    val = 1;
                else if (val > 120)
                    val = 120;

                req->interval = val - (val / 2);
                sprintf(pointer, "%u", val);
                pointer += strlen(pointer) + 1;
            }

            temp += strlen(temp) + 1;

            //printf("=%u\n", val);
        }

        errno = 0;
        req->bytesSent = sendto(cfig.tftpConn[req->sockInd].sock, (const char*)&req->acout, (DWORD)pointer - (DWORD)&req->acout, 0, (sockaddr*)&req->client, req->clientsize);
    }
    else if (htons(datain->opcode) == 2)
    {
        req->acout.opcode = htons(4);
        req->acout.block = htons(0);
        errno = 0;
        req->bytesSent = sendto(cfig.tftpConn[req->sockInd].sock, (const char*)&req->acout, 4, 0, (sockaddr*)&req->client, req->clientsize);
    }

    if (errno)
    {
        sprintf(serverError.errormessage, "Communication Error");
        logMess(req, 1);
        req->attempt = UCHAR_MAX;

        if (req->file)
        {
            fclose(req->file);
            req->file = 0;
        }
        return errno;
    }

    if (ntohs(datain->opcode) == 1)
    {
        errno = 0;
        req->pkt[0] = (packet*)calloc(1, req->blksize + 4);
        req->pkt[1] = (packet*)calloc(1, req->blksize + 4);

        if (errno || !req->pkt[0] || !req->pkt[1])
        {
			sprintf(logBuff,"Memory Error");
			logMess(logBuff, 1);
            req->attempt = UCHAR_MAX;
            clean(req);
            return 1;
        }

        if (ftell(req->file))
            fseek(req->file, 0, SEEK_SET);

        req->pkt[0]->opcode = htons(3);
        req->pkt[0]->block = htons(1);
        req->bytesRead[0] = fread(&req->pkt[0]->buffer, 1, req->blksize, req->file);

        if (errno)
        {
            serverError.errorcode = htons(0);
            sprintf(serverError.errormessage, strerror(errno));
            logMess(req, 1);
            req->bytesSent = sendto(cfig.tftpConn[req->sockInd].sock, (const char*)&serverError, strlen(serverError.errormessage) + 5, 0, (sockaddr*)&req->client, req->clientsize);
            req->attempt = UCHAR_MAX;

            if (req->file)
            {
                fclose(req->file);
                req->file = 0;
            }
            return errno;
        }

        if (req->bytesRead[0] == req->blksize)
        {
            req->pkt[1]->opcode = htons(3);
            req->pkt[1]->block = htons(2);
            req->bytesRead[1] = fread(&req->pkt[1]->buffer, 1, req->blksize, req->file);

            if (errno)
            {
                serverError.errorcode = htons(5);
                sprintf(serverError.errormessage, strerror(errno));
                logMess(req, 1);
                req->bytesSent = sendto(cfig.tftpConn[req->sockInd].sock, (const char*)&serverError, strlen(serverError.errormessage) + 5, 0, (sockaddr*)&req->client, req->clientsize);
                req->attempt = UCHAR_MAX;

                if (req->file)
                {
                    fclose(req->file);
                    req->file = 0;
                }
                return errno;
            }

            if (req->bytesRead[1] < req->blksize)
            {
                fclose(req->file);
                req->file = 0;
            }
        }
        else
        {
            fclose(req->file);
            req->file = 0;
        }

        if (!req->bytesSent)
        {
            req->block = 1;
            return processSend(req);
        }
    }
    return 0;
}

int processSend(request *req)
{
    errno = 0;
    req->expiry = time(NULL) + req->interval;

    if (ntohs(req->pkt[0]->block) == req->block)
    {
        errno = 0;
        req->bytesSent = sendto(cfig.tftpConn[req->sockInd].sock, (const char*)req->pkt[0], req->bytesRead[0] + 4, 0, (sockaddr*)&req->client, req->clientsize);
        memcpy(&req->acout, req->pkt[0], 4);

        if (errno)
        {
            sprintf(serverError.errormessage, "Communication Error");
            logMess(req, 1);
            req->attempt = UCHAR_MAX;

            if (req->file)
            {
                fclose(req->file);
                req->file = 0;
            }
            return errno;
        }

        if (req->file)
        {
            req->tblock = ntohs(req->pkt[1]->block) + 1;
            if (req->tblock == req->block)
            {
                req->pkt[1]->block = htons(++req->tblock);
                req->bytesRead[1] = fread(&req->pkt[1]->buffer, 1, req->blksize, req->file);

                if (errno)
                {
                    serverError.errorcode = htons(1);
                    sprintf(serverError.errormessage, strerror(errno));
                    req->bytesSent = sendto(cfig.tftpConn[req->sockInd].sock, (const char*)&serverError, strlen(serverError.errormessage) + 5, 0, (sockaddr*)&req->client, req->clientsize);
                    logMess(req, 1);
                    req->attempt = UCHAR_MAX;

                    if (req->file)
                    {
                        fclose(req->file);
                        req->file = 0;
                    }
                    return errno;
                }
                else if (req->bytesRead[1] < req->blksize)
                {
                    fclose(req->file);
                    req->file = 0;
                }
            }
        }
    }
    else if (ntohs(req->pkt[1]->block) == req->block)
    {
        errno = 0;
        req->bytesSent = sendto(cfig.tftpConn[req->sockInd].sock, (const char*)req->pkt[1], req->bytesRead[1] + 4, 0, (sockaddr*)&req->client, req->clientsize);
        memcpy(&req->acout, req->pkt[1], 4);

        if (errno)
        {
            sprintf(serverError.errormessage, "Communication Error");
            logMess(req, 1);
            req->attempt = UCHAR_MAX;

            if (req->file)
            {
                fclose(req->file);
                req->file = 0;
            }
            return errno;
        }

        if (req->file)
        {
            req->tblock = ntohs(req->pkt[0]->block) + 1;
            if (req->tblock == req->block)
            {
                req->pkt[0]->block = htons(++req->tblock);
                req->bytesRead[0] = fread(&req->pkt[0]->buffer, 1, req->blksize, req->file);

                if (errno)
                {
                    serverError.errorcode = htons(1);
                    sprintf(serverError.errormessage, strerror(errno));
                    req->bytesSent = sendto(cfig.tftpConn[req->sockInd].sock, (const char*)&serverError, strlen(serverError.errormessage) + 5, 0, (sockaddr*)&req->client, req->clientsize);
                    logMess(req, 1);
                    req->attempt = UCHAR_MAX;

                    if (req->file)
                    {
                        fclose(req->file);
                        req->file = 0;
                    }
                    return errno;
                }
                else if (req->bytesRead[0] < req->blksize)
                {
                    fclose(req->file);
                    req->file = 0;
                }
            }
        }
    }
    else //if (ntohs(req->pkt[0]->block) < req->block && ntohs(req->pkt[1]->block) < req->block)
    {
        req->attempt = UCHAR_MAX;
        sprintf(logBuff, "Client %s %s, %i Blocks Served", req->mapname, req->path, req->fblock - 1 );
        logMess(logBuff, 2);
    }

    return 0;
}

int processRecv(request *req)
{
    req->expiry = time(NULL) + req->interval;
    errno = 0;
    req->bytesSent = sendto(cfig.tftpConn[req->sockInd].sock, (const char*)&req->acout, 4, 0, (sockaddr*)&req->client, req->clientsize);

    if (errno)
    {
        sprintf(serverError.errormessage, "Communication Error");
        logMess(req, 1);
        req->attempt = UCHAR_MAX;

        if (req->file)
        {
            fclose(req->file);
            req->file = 0;
        }

        return errno;
    }

    if (req->bytesRecd > 4 && !fwrite(&datain->buffer, req->bytesRecd - 4, 1, req->file))
    {
        serverError.opcode = htons(5);
        serverError.errorcode = htons(3);
        strcpy(serverError.errormessage, "Disk full or allocation exceeded");
        req->bytesSent = sendto(cfig.tftpConn[req->sockInd].sock, (const char*)&serverError, strlen(serverError.errormessage) + 5, 0, (sockaddr*)&req->client, req->clientsize);
        logMess(req, 1);
        req->attempt = UCHAR_MAX;

        if (req->file)
        {
            fclose(req->file);
            req->file = 0;
        }
        return 1;
    }

    //printf("%u\n", req->bytesRecd);

    if (req->bytesRecd - 4 < req->blksize)
    {
        sprintf(logBuff, "Client %s %s, %u Blocks Received", req->mapname, req->path, req->fblock);
        logMess(logBuff, 2);
        req->attempt = UCHAR_MAX;
        fclose(req->file);
        req->file = 0;
        return 0;
    }

    return 0;
}

char *cleanstr(char* buff, bool next)
{
	if (buff[0] && next)
		buff += strlen(buff) + 1;

	while (strlen(buff))
		if (*buff >= '0' && *buff <= '9' || *buff >= 'A' && *buff <= 'Z' || *buff >= 'a' && *buff <= 'z' || *buff == '/' || *buff == '.')
			break;
		else
			buff += strlen(buff) + 1;

	return buff;
}

bool getSection(char *sectionName, char *buffer, int sizeofbuffer, char *fileName)
{
	char section[128];
	sprintf(section, "[%s]", sectionName);
	myUpper(section);
	FILE *f = fopen(fileName, "r");
	char buff[512];
	char *ptr = buffer;
	*ptr = 0;
	bool found = false;
	while (f && fgets(buff, 255, f))
	{
		myUpper(buff);
		if (strstr(buff, section) == buff)
		{
			found = true;
			while (fgets(buff, 255, f))
			{
				if (strstr(buff, "[") == buff)
					break;
				sprintf(ptr, "%s", buff);
				ptr += strlen(buff);
				while (*ptr <= 32)
					ptr--;
				ptr++;
				*ptr = 0;
				ptr++;
			}
			*ptr = 0;
		}
	}
	if (f)
		fclose(f);
	return found;
}

char *IP2String(char *target, DWORD ip)
{
	data15 inaddr;
	inaddr.ip = ip;
	sprintf(target, "%u.%u.%u.%u", inaddr.octate[0],inaddr.octate[1],inaddr.octate[2],inaddr.octate[3]);
	return target;
}

char *myUpper(char *string)
{
	char diff = 'a' - 'A';
	WORD len = strlen(string);
	for (int i = 0; i < len; i++)
		if (string[i] >= 'a' && string[i] <= 'z')
			string[i] -= diff;
	return string;
}

char *myLower(char *string)
{
	char diff = 'a' - 'A';
	WORD len = strlen(string);
	for (int i = 0; i < len; i++)
		if (string[i] >= 'A' && string[i] <= 'Z')
			string[i] += diff;
	return string;
}

bool isIP(char *string)
{
	int j = 0;

	for (; *string; string++)
	{
		if (*string == '.')
			j++;
		else if (*string < '0' || *string > '9')
			return 0;
	}

	if (j == 3)
		return 1;
	else
		return 0;
}

DWORD my_inet_addr(char *str)
{
	if (str == NULL)
		return INADDR_ANY;

	DWORD x = inet_addr(str);

	if (x == INADDR_NONE)
		return INADDR_ANY;
	else
		return x;
}

void clean(request* req)
{
	if (req)
	{
		if (req->file)
			fclose(req->file);

		if (req->pkt[0])
			free(req->pkt[0]);

		if (req->pkt[1])
			free(req->pkt[1]);

		free(req);
	}
}

void init()
{
	memset(&cfig, 0, sizeof(cfig));
	char iniStr[4096];

	if (verbatim)
		cfig.logLevel = 2;
	else if (getSection("LOGGING", iniStr, sizeof(iniStr), iniFile))
	{
		char *iniStrPtr = cleanstr(iniStr, false);

		if (!iniStrPtr[0] || !strcasecmp(iniStrPtr, "None"))
			cfig.logLevel = 0;
		else if (!strcasecmp(iniStrPtr, "Errors"))
			cfig.logLevel = 1;
		else if (!strcasecmp(iniStrPtr, "All"))
			cfig.logLevel = 2;
		else
		{
			sprintf(logBuff, "Section [LOGGING], Invalid Logging Level: %s ignored", iniStrPtr);
			logMess(logBuff, 0);
		}
	}

	if (!verbatim && cfig.logLevel && logFile[0])
	{
		FILE *f = fopen(logFile, "wt");

		if (f)
			fclose(f);
		else
		{
			sprintf(iniStr, "faled to open log file %s", logFile);
			syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_CRIT), iniStr);
			logFile[0] = 0;
		}
	}

	if (getSection("LISTEN-ON", iniStr, sizeof(iniStr), iniFile))
	{
		char *iniStrPtr = cleanstr(iniStr, false);
		for (int i = 0; i < MAX_SERVERS && iniStrPtr[0]; iniStrPtr = cleanstr(iniStrPtr, true))
		{
			char name[256];
			strncpy(name, iniStrPtr, 255);
			WORD port = 69;
			char *dp = strchr(name,':');
			if (dp)
			{
				*dp = 0;
				dp++;
				port = atoi(dp);
			}

			DWORD ip = my_inet_addr(name);

			if (isIP(name) && ip)
			{
				for (BYTE j = 0; j < MAX_SERVERS; j++)
				{
					if (cfig.servers[j] == ip)
						break;
					else if (!cfig.servers[j])
					{
						cfig.servers[j] = ip;
						cfig.ports[j] = port;
						i++;
						break;
					}
				}
			}
			else
			{
				sprintf(logBuff, "Warning: Section [LISTEN-ON], Invalid IP Address %s, ignored", iniStrPtr);
				logMess(logBuff, 1);
			}
		}
	}

	if (getSection("HOME", iniStr, sizeof(iniStr), iniFile))
	{
		char *iniStrPtr = cleanstr(iniStr, false);
		for (; iniStrPtr[0]; iniStrPtr = cleanstr(iniStrPtr, true))
		{
			char name[256];
			strncpy(name, iniStrPtr, 255);
			char *value = strchr(name, '=');
			if (value)
			{
				*value = 0;
				value++;
				if (!cfig.homes[0].alias[0] && cfig.homes[0].target[0])
				{
					sprintf(logBuff, "Section [HOME], alias and bare path mixup, entry %s ignored", iniStrPtr);
					logMess(logBuff, 1);
				}
				else if (strchr(name, '\\') || strchr(name, '/') || strchr(name, '>') || strchr(name, '<') || strchr(name, '.'))
				{
					sprintf(logBuff, "Section [HOME], invalid chars in alias %s, entry ignored", name);
					logMess(logBuff, 1);
				}
				else if (name[0] && strlen(name) < 64 && value[0])
				{
					for (int i = 0; i < 8; i++)
					{
						if (cfig.homes[i].alias[0] && !strcasecmp(name, cfig.homes[i].alias))
						{
							sprintf(logBuff, "Section [HOME], Duplicate Entry: %s ignored", iniStrPtr);
							logMess(logBuff, 1);
							break;
						}
						else if (!cfig.homes[i].alias[0])
						{
							strcpy(cfig.homes[i].alias, name);
							strcpy(cfig.homes[i].target, value);

							if (cfig.homes[i].target[strlen(cfig.homes[i].target) - 1] != '/')
								strcat(cfig.homes[i].target, "/");

							break;
						}
					}
				}
				else
				{
					sprintf(logBuff, "Section [HOME], alias name too large", name);
					logMess(logBuff, 1);
				}
			}
			else if (!cfig.homes[0].alias[0] && !cfig.homes[0].target[0])
			{
				strcpy(cfig.homes[0].target, name);

				if (cfig.homes[0].target[strlen(cfig.homes[0].target) - 1] != '/')
					strcat(cfig.homes[0].target, "/");
			}
			else if (cfig.homes[0].alias[0])
			{
				sprintf(logBuff, "Section [HOME], alias and bare path mixup, entry %s ignored", iniStrPtr);
				logMess(logBuff, 1);
			}
			else if (cfig.homes[0].target[0])
			{
				sprintf(logBuff, "Section [HOME], Duplicate Path: %s ignored", iniStrPtr);
				logMess(logBuff, 1);
			}
			else
			{
				printf(logBuff, "Section [HOME], missing = sign, Invalid Entry: %s ignored", iniStrPtr);
				logMess(logBuff, 1);
			}
		}
	}

	if (!cfig.homes[0].target[0])
	{
		strcpy(cfig.homes[0].target, "/home/");
	}

	if (getSection("TFTP-OPTIONS", iniStr, sizeof(iniStr), iniFile))
	{
		char *iniStrPtr = cleanstr(iniStr, false);
		for (;strlen(iniStrPtr);iniStrPtr = cleanstr(iniStrPtr, true))
		{
			char name[256];
			strncpy(name, iniStrPtr, 255);
			char *value = strchr(name, '=');
			if (value != NULL)
			{
				*value = 0;
				value++;
				myLower(name);

				if (!strcmp(name, "blksize"))
				{
					DWORD tblksize = atol(value);

					if (tblksize < 512)
						blksize = 512;
					else if (tblksize > USHRT_MAX - 32)
						blksize = USHRT_MAX - 32;
					else
						blksize = tblksize;
				}
				else if (!strcmp(name, "interval"))
				{
					interval = atol(value);
					if (interval < 1)
						interval = 3;
					else if (interval > 120)
						interval = 120;
				}
				else if (!strcmp(name, "overwrite"))
				{
					if (!strcasecmp(value, "Y"))
						cfig.overwrite = true;
					else
						cfig.overwrite = false;
				}
				else
				{
					sprintf(logBuff, "unknown option %s\n", name);
					logMess(logBuff, 1);
				}
			}
		}
	}

	if (getSection("ALLOWED-CLIENTS", iniStr, sizeof(iniStr), iniFile))
	{
		char *iniStrPtr = cleanstr(iniStr, false);
		for (int i = 0; i < 32 && iniStrPtr[0]; iniStrPtr = cleanstr(iniStrPtr, true))
		{
			char name[256];
			strncpy(name, iniStrPtr, 255);
			DWORD rs = 0;
			DWORD re = 0;
			char *ptr = strchr(name, '-');
			if (ptr)
			{
				*ptr = 0;
				ptr++;
				rs = htonl(my_inet_addr(name));
				re = htonl(my_inet_addr(ptr));
			}
			else
			{
				rs = htonl(my_inet_addr(name));
				re = rs;
			}
			if (rs && rs != INADDR_NONE && re && re != INADDR_NONE && rs <= re)
			{
				cfig.hostRanges[i].rangeStart = rs;
				cfig.hostRanges[i].rangeEnd = re;
				i++;
			}
			else
			{
				sprintf(logBuff, "Section [ALLOWED-CLIENTS] Invalid entry %s in ini file, ignored", iniStrPtr);
				logMess(logBuff, 1);
			}
		}
	}

	if (!cfig.servers[0])
		getServ(cfig.servers, cfig.ports, MAX_SERVERS);

	int i = 0;

	for (int j = 0; j < MAX_SERVERS && cfig.servers[j]; j++)
	{
		cfig.tftpConn[i].sock = socket(PF_INET,
		                              SOCK_DGRAM,
		                              IPPROTO_UDP);

		if (cfig.tftpConn[i].sock == -1 )
		{
			sprintf(logBuff, "Failed to Create Socket");
			logMess(logBuff, 1);
			continue;
		}

		cfig.tftpConn[i].addr.sin_family = AF_INET;
		cfig.tftpConn[i].addr.sin_addr.s_addr = cfig.servers[j];
		cfig.tftpConn[i].addr.sin_port = htons(cfig.ports[j]);

		socklen_t nRet = bind(cfig.tftpConn[i].sock,
		                      (sockaddr*)&cfig.tftpConn[i].addr,
		                      sizeof(struct sockaddr_in)
		                     );

		if (nRet == -1)
		{
			close(cfig.tftpConn[i].sock);
			sprintf(logBuff, "%s Port %u, bind failed, %s", IP2String(tempbuff, cfig.servers[j]), cfig.ports[j], strerror(errno));
			logMess(logBuff, 1);
			continue;
		}

		if (cfig.maxFD < cfig.tftpConn[i].sock)
			cfig.maxFD = cfig.tftpConn[i].sock;

		cfig.tftpConn[i].server = cfig.servers[j];
		cfig.tftpConn[i].port = cfig.ports[j];
		i++;
	}

	cfig.maxFD++;

	if (!cfig.tftpConn[0].server)
	{
		sprintf(logBuff, "no listening Interfaces available, stopping...");
		logMess(logBuff, 1);
		exit(-1);
	}
	else if (verbatim)
	{
		printf("\nstarting TFTP...\n");
	}
	else
	{
		sprintf(logBuff, "starting TFTP Service");
		logMess(logBuff, 1);
	}

	if (cfig.tftpConn[0].server)
	{
		for (int i = 0; i < 8; i++)
			if (cfig.homes[i].target[0])
			{
				sprintf(logBuff, "alias /%s is mapped to %s", cfig.homes[i].alias, cfig.homes[i].target);
				logMess(logBuff, 1);
			}

		for (int i = 0; i < MAX_SERVERS && cfig.tftpConn[i].server; i++)
		{
			sprintf(logBuff, "listening On: %s:%i", IP2String(tempbuff, cfig.tftpConn[i].server),cfig.tftpConn[i].port);
			logMess(logBuff, 1);
		}

		if (cfig.hostRanges[0].rangeStart)
		{
			char temp[128];

			for (int i = 0; i <= 32 && cfig.hostRanges[i].rangeStart; i++)
			{
				sprintf(logBuff, "%s", "permitted clients: ");
				sprintf(temp, "%s-", IP2String(tempbuff, htonl(cfig.hostRanges[i].rangeStart)));
				strcat(logBuff, temp);
				sprintf(temp, "%s", IP2String(tempbuff, htonl(cfig.hostRanges[i].rangeEnd)));
				strcat(logBuff, temp);
				logMess(logBuff, 1);
			}
		}
		else
		{
			sprintf(logBuff, "%s", "permitted clients: all");
			logMess(logBuff, 1);
		}

		sprintf(logBuff, "max blksize: %u", blksize);
		logMess(logBuff, 1);
		sprintf(logBuff, "defult blksize: %u", 512);
		logMess(logBuff, 1);
		sprintf(logBuff, "default interval: %u", interval);
		logMess(logBuff, 1);
		sprintf(logBuff, "overwrite existing files: %s", cfig.overwrite ? "Yes" : "No");
		logMess(logBuff, 1);

		if (!verbatim)
		{
			sprintf(logBuff, "logging: %s", cfig.logLevel > 1 ? "all" : "errors");
			logMess(logBuff, 1);
		}
	}
}

void logMess(char *logBuff, BYTE logLevel)
{
	if (verbatim)
		printf("%s\n", logBuff);
	else if (logFile[0] && logLevel <= cfig.logLevel)
	{
		char currentTime[32];
		time_t t = time(NULL);
		tm *ttm = localtime(&t);
		strftime(currentTime, sizeof(currentTime), "%d-%b-%y %X", ttm);
		FILE *f = fopen(logFile, "at");
		if (f)
		{
			fprintf(f, "[%s] %s\n", currentTime, logBuff);
			fclose(f);
		}
		else
		{
			syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_CRIT), logBuff);
		}
	}
	else if (logLevel <= cfig.logLevel)
		syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_CRIT), logBuff);
}

void logMess(request *req, BYTE logLevel)
{
	if (verbatim)
	{
		if (!serverError.errormessage[0])
			printf(serverError.errormessage, strerror(errno));

		if (req->path[0])
			printf("Client %s:%u %s, %s\n", inet_ntoa(req->client.sin_addr), ntohs(req->client.sin_port), req->path, serverError.errormessage);
		else
			printf("Client %s:%u, %s\n", inet_ntoa(req->client.sin_addr), ntohs(req->client.sin_port), serverError.errormessage);

	}
	else if (logFile[0] && logLevel <= cfig.logLevel)
	{
		char currentTime[32];
		time_t t = time(NULL);
		tm *ttm = localtime(&t);
		strftime(currentTime, sizeof(currentTime), "%d-%b-%y %X", ttm);
		FILE *f = fopen(logFile, "at");
		if (f)
		{
			if (req->path[0])
				fprintf(f,"[%s] Client %s:%u %s, %s\n", currentTime, inet_ntoa(req->client.sin_addr), ntohs(req->client.sin_port), req->path, serverError.errormessage);
			else
				fprintf(f,"[%s] Client %s:%u, %s\n", currentTime, inet_ntoa(req->client.sin_addr), ntohs(req->client.sin_port), serverError.errormessage);

			fclose(f);
		}
	}
	else if (logLevel <= cfig.logLevel)
	{
		char logBuff[256];

		if (!serverError.errormessage[0])
			sprintf(serverError.errormessage, strerror(errno));

		if (req->path[0])
			sprintf(logBuff,"Client %s:%u %s, %s\n", inet_ntoa(req->client.sin_addr), ntohs(req->client.sin_port), req->path, serverError.errormessage);
		else
			sprintf(logBuff,"Client %s:%u, %s\n", inet_ntoa(req->client.sin_addr), ntohs(req->client.sin_port), serverError.errormessage);

		syslog(LOG_MAKEPRI(LOG_LOCAL1, LOG_CRIT), logBuff);
	}
}


