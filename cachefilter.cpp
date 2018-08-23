/*
This file is part of cachefilter.

cachefilter is free software : you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.If not, see < https://www.gnu.org/licenses/>.
*/

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#include "windivert.h"

#define MAXBUF  0xFFFF

static DWORD passthru(LPVOID arg);

// input packet
// ipv4
// http port 80
const char* const filter_rule = "inbound and ip and tcp.SrcPort == 80";

// http response 302 http 222.29.259.*
const char* const matching_str = "HTTP/1.1 302 Found\r\nConnection: close\r\nLocation: http://222.29.159.";
const int matching_len = 67;

// assume ip header's and tcp header's lengthes are both 20;
const int matching_offset = 40;

const int url_offset = 49 + matching_offset;

// threads to process package
const int num_threads = 2;

// priority
const int priority = 0;

int __cdecl main(int argc, char **argv)
{
	int i;
	HANDLE handle, thread;

	// Divert traffic matching the filter:
	handle = WinDivertOpen(filter_rule, WINDIVERT_LAYER_NETWORK, (INT16)priority,
		0);
	if (handle == INVALID_HANDLE_VALUE)
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER)
		{
			fprintf(stderr, "error: filter syntax error\n");
			getc(stdin);
			exit(EXIT_FAILURE);
		}
		fprintf(stderr, "error: failed to open the WinDivert device (%d)\n",
			GetLastError());
		getc(stdin);
		exit(EXIT_FAILURE);
	}

	// Start the threads
	for (i = 1; i < num_threads; i++)
	{
		thread = CreateThread(NULL, 1, (LPTHREAD_START_ROUTINE)passthru,
			(LPVOID)handle, 0, NULL);
		if (thread == NULL)
		{
			fprintf(stderr, "error: failed to start passthru thread (%u)\n",
				GetLastError());
			getc(stdin);
			exit(EXIT_FAILURE);
		}
	}

	// Main thread:
	passthru((LPVOID)handle);

	return 0;
}

static DWORD passthru(LPVOID arg)
{
	unsigned char packet[MAXBUF];
	UINT packet_len;
	WINDIVERT_ADDRESS addr;
	HANDLE handle = (HANDLE)arg;

	fprintf(stderr, "thread started.\n");

	// Main loop:
	while (TRUE)
	{
		// Read a matching packet.
		if (!WinDivertRecv(handle, packet, sizeof(packet), &addr, &packet_len))
		{
			fprintf(stderr, "warning: failed to read packet (%d)\n",
				GetLastError());
			continue;
		}

		bool match = true;

		for (int i = 0; i < matching_len; ++i)
		{
			if (packet[i + matching_offset] != matching_str[i])
			{
				match = false;
				break;
			}
		}

		if (match)
		{
			char *locationurl = (char *)(packet + url_offset);
			for (int i = 0; i < MAXBUF - url_offset; ++i)
			{
				if (locationurl[i] == '\r' || locationurl[i] == 0)
				{
					locationurl[i] = 0;
					break;
				}
			}
			locationurl[MAXBUF - url_offset - 1] = 0;
			fprintf(stderr, "dropped packet: %s\n", locationurl);
		}
		else
		{
			// Re-inject the packet.
			if (!WinDivertSend(handle, packet, packet_len, &addr, NULL))
			{
				fprintf(stderr, "warning: failed to reinject packet (%d)\n",
					GetLastError());
			}
		}
	}
}
