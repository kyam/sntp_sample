// SNTP‚ÌƒTƒ“ƒvƒ‹ŽÀ‘•
//
// 
//
//

#include "stdafx.h"
#include <Windows.h>

#include "sntp.h"

// sample
// sntp.exe ntp.xxx.org
//
int main(int argc, const char* argv[])
{
  if (SntpOpen(argv[1])) {

    printf("Server                   Local                    DIFF         DELAY\n");
    while (1) {
      SYSTEMTIME server, local;
      int diff;
      int delayed;

      GetLocalTime(&local);
      if (Sntp(&server, &diff, &delayed)) {
        printf("%4d-%02d-%02d %02d:%02d:%02d.%03d |",
               server.wYear, server.wMonth, server.wDay, 
               server.wHour, server.wMinute, server.wSecond, server.wMilliseconds);
        printf("%4d-%02d-%02d %02d:%02d:%02d.%03d |%.3f(ms) |%.3f(ms)\n",
               local.wYear, local.wMonth, local.wDay,
               local.wHour, local.wMinute, local.wSecond, local.wMilliseconds,
               (double)diff/1000,(double)delayed/1000);
      
        Sleep(10 * 1000);
      }
    }

    SntpClose();
  }

	return 0;
}

