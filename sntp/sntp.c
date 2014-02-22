/*
* SNTP�ʐM�p����
*
* �I���W�i���͈ȉ��̃R�[�h���Q�l�ɂ��Ă����B
* http://www.ccad.sist.chukyo-u.ac.jp/~mito/ss/program/C/API/NTP/
*
* �{�R�[�h��NTP v4�x�[�X�ɍ쐬����
* http://tools.ietf.org/html/rfc4330
* (RFC�ԍ��͈Ⴄ���ȉ����{���)
* http://www.geocities.co.jp/SiliconValley/6876/rfc2030j.htm
* http://www.geocities.jp/heartland_cosmos_2211/rfc2030.html
*/

#include "stdafx.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#include <windows.h>
#include <assert.h>

#include "sntp.h"

// �ʐM�ݒ�
static const int kMajorVersion = 2;   // Winsock Major version
static const int kMinorVersion = 2;   // Winsock Minor version
static const int kSntpPort = 123;     // SNTP�ʐM�p�|�[�g�ԍ� UDP/123
static const int kSntpTimeout = 3;    // SNTP�ʐM�^�C���A�E�g 3�b

// NTP���b�Z�[�W
static const int kNTPWarning = 3;     // LI=3 NTP�T�[�o�Ɠ������Ƃ�Ă��Ȃ�
static const int kNTPVersion = 4;     // NTP version 4
static const int kNTPClientMode = 3;  // Client���[�h
static const int kNTPServerMode = 4;  // Server���[�h
static const int kNTPMaxInterval = 9; // 2^9=512�b�ȓ��Ɏ��̒ʐM���s���B

static SOCKET sntp_socket;  // SNTP�p�\�P�b�g
static IN_ADDR srvaddr;     // SNTP�T�[�o

static BOOL WinsockOpen(void)
{
  WORD reqver;
  WSADATA wsadata;

  /* Use the MAKEWORD(lowbyte, highbyte) macro declared in Windef.h */
  reqver = MAKEWORD(kMajorVersion, kMinorVersion);
  if (WSAStartup(reqver, &wsadata) != 0) {
    return FALSE;
  }

  if ((LOBYTE(wsadata.wVersion) != kMajorVersion) ||
      (HIBYTE(wsadata.wVersion) != kMinorVersion)) {
    return FALSE;
  }

  return TRUE;
}

static void WinsockClose(void)
{
  WSACleanup();
}

static BOOL GetIpv4Address(const char *srvip, IN_ADDR *addr)
{
  unsigned long ipaddr;

  ipaddr = inet_addr(srvip);
  if ((ipaddr == INADDR_NONE) || (ipaddr == INADDR_ANY)) {
    // ����������IP�A�h���X�ł͂Ȃ��z�X�g���œ����Ă���H
    struct addrinfo *result = NULL;
    struct addrinfo *ptr = NULL;
    int ret;

    ret = getaddrinfo(srvip, NULL, NULL, &result);
    if (ret != 0) {
      return FALSE;
    }

    for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {
      if (ptr->ai_family == AF_INET) {
        struct sockaddr_in *sin;
        sin = (struct sockaddr_in *)ptr->ai_addr;
        *addr = sin->sin_addr;
        break;
      }
    }
    if (ptr == NULL) {
      return FALSE;
    }
  } else {
    addr->s_addr = ipaddr;
  }

  return TRUE;
}

BOOL CreateSntpSocket(const char *srvip)
{
  struct sockaddr_in sin;

  sntp_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (sntp_socket == INVALID_SOCKET) {
    return FALSE;
  }

  ZeroMemory(&sin, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = INADDR_ANY;
  sin.sin_port = htons(kSntpPort);

  if (bind(sntp_socket, (struct sockaddr *)&sin, sizeof(sin)) != 0) {
    return FALSE;
  }

  return TRUE;
}

void CloseSntpSocket()
{
  closesocket(sntp_socket);
}

BOOL SntpOpen(const char *srvip)
{
  if (WinsockOpen()) {
    if (GetIpv4Address(srvip, &srvaddr)) {
      return CreateSntpSocket(srvip);
    }
  }

  return FALSE;
}

void SntpClose(void)
{
  CloseSntpSocket();
  WinsockClose();
}

struct NTPPacket {
  __int32 control;
  __int32 root_delay;
  __int32 root_dispersion;
  __int32 reference_identifier;
  unsigned __int64 reference_timestamp;
  unsigned __int64 originate_timestamp;
  unsigned __int64 receive_timestamp;
  unsigned __int64 transmit_timestamp;
};

// �ȉ�Control���[�h�ɐݒ肷�鐧��f�[�^
static const int kLIPos = 30;
static const int kLIMask = 0x00000003;
static const int kVNPos = 27;
static const int kVNMask = 0x00000007;
static const int kModePos = 24;
static const int kModeMask = 0x00000007;
static const int kStratumPos = 16;
static const int kStratumMask = 0x000000FF;
static const int kPollPos = 8;
static const int kPollMask = 0x000000FF;
static const int kPrecisionPos = 8;
static const int kPrecisionMask = 0x000000FF;

// NTP�^�C���X�^���v�̊�l
// 1900�N1��1��0��(���j��) 2036�N1��1��(�Ηj��)
static const SYSTEMTIME k1900BaseTime = { 1900, 1, 1, 1, 0, 0, 0, 0 };
static const SYSTEMTIME k2036BaseTime = { 2036, 1, 1, 2, 0, 0, 0, 0 };

static __int32 SetStatus(__int32 src, int data, int pos)
{
  return (src | (data << pos));
}
static int GetStatus(__int32 src, int pos, int mask)
{
  return ((src >> pos) & mask);
}

// Windows��SYSTEMTIME�̐��x��msec�̂��߁A
// NTP�t�H�[�}�b�g�̃^�C���X�^���v�̐��x��msec�ɂ���B
static unsigned __int64 GetSystemTimeAsNTPFormat(const SYSTEMTIME *now)
{
  FILETIME totime;
  FILETIME fromtime;
  unsigned __int64 t;
  unsigned __int64 sec;
  unsigned __int64 frac;

  if (now->wYear >= 2036) {
    assert(SystemTimeToFileTime(&k2036BaseTime, &fromtime) != 0);
  } else {
    assert(SystemTimeToFileTime(&k1900BaseTime, &fromtime) != 0);
  }
  assert(SystemTimeToFileTime(now, &totime) != 0);

  if (totime.dwLowDateTime > fromtime.dwLowDateTime) {
    t = (unsigned __int64)(totime.dwHighDateTime - fromtime.dwHighDateTime) << 32;
    t += totime.dwLowDateTime - fromtime.dwLowDateTime;
  } else {
    t = (unsigned __int64)(totime.dwHighDateTime - fromtime.dwHighDateTime) << 32;
    t += fromtime.dwLowDateTime - totime.dwLowDateTime;
  }

  // FILETIME�̒P�ʂ�100nsec
  sec = t / 10000000;
  frac = (t % 10000000) * 0x100000000UL / 10000000;

  return ((sec << 32) | frac);
}

static FILETIME AddFILETIME(FILETIME a, FILETIME b)
{
  FILETIME c;
  unsigned __int64 l;
  unsigned __int64 h;

  h = a.dwHighDateTime;
  h += b.dwHighDateTime;

  l = a.dwLowDateTime;
  l += b.dwLowDateTime;

  if (l > 0x100000000UL) {
    h++;
  }

  c.dwHighDateTime = (DWORD)h;
  c.dwLowDateTime = (DWORD)l;

  return c;
}

static SYSTEMTIME ConvertNTPTimestampToSystemTime(unsigned __int64 timestamp)
{
  SYSTEMTIME system_time;
  FILETIME base_time;
  FILETIME utc_time, local_time;
  unsigned __int64 t;
  unsigned __int64 sec;
  unsigned __int64 frac;

  if (timestamp & 0x8000000000000000) {
    SystemTimeToFileTime(&k1900BaseTime, &base_time);
  } else {
    // 2036�N�ȍ~��NTP�̃^�C���X�^���v�̓I�[�o�[�t���[����
    SystemTimeToFileTime(&k2036BaseTime, &base_time);
  }

  // ��UFILETIME�`��(100ns)�ɕϊ����Ă���SYSTEMTIME�ɕϊ�����
  sec = timestamp >> 32;
  frac = (((timestamp & 0xffffffff) * 10000000) >> 32);

  t = sec * 10000000 + frac;
  utc_time.dwHighDateTime = t >> 32;
  utc_time.dwLowDateTime = t & 0xFFFFFFFF;

  utc_time = AddFILETIME(utc_time, base_time);

  assert(FileTimeToLocalFileTime(&utc_time, &local_time) != 0);
  assert(FileTimeToSystemTime(&local_time, &system_time) != 0);

  return system_time;
}

static int GetMillisecondFromNTPFormat(__int64 timestamp)
{
  __int64 sec;
  __int64 frac;

  // NTP�^�C���X�^���v��
  sec = timestamp >> 32;
  frac = (((timestamp & 0xffffffff) * 1000) >> 32);

  return (int)(sec * 1000 + frac);
}

static void BuildNTPMessage(struct NTPPacket *pkt)
{
  SYSTEMTIME transmit_time;
  __int32 control;
  __int64 transmit_timestamp;

  control = 0;
  control = SetStatus(control, kNTPVersion, kVNPos);        // NTP version 4
  control = SetStatus(control, kNTPClientMode, kModePos);   // Client���[�h
  control = SetStatus(control, kNTPMaxInterval, kPollPos);  // 2^9=512�b�ȓ���SNTP�ɂ��₢���킹���s���B

  GetSystemTime(&transmit_time);
  transmit_timestamp = GetSystemTimeAsNTPFormat(&transmit_time);

  ZeroMemory(pkt, sizeof(struct NTPPacket));
  pkt->control = htonl(control);
  pkt->transmit_timestamp = htonll(transmit_timestamp);
}

static __int64 GetDelayedTime(const struct NTPPacket *pkt, unsigned __int64 received_timestamp)
{
  unsigned __int64 t1;
  unsigned __int64 t2;
  unsigned __int64 t3;
  unsigned __int64 t4;

  t1 = ntohll(pkt->originate_timestamp);
  t2 = ntohll(pkt->receive_timestamp);
  t3 = ntohll(pkt->transmit_timestamp);
  t4 = received_timestamp;

  return ((__int64)(t4 - t1) - (__int64)(t2 - t3));
}

static __int64 GetDiffTime(const struct NTPPacket *pkt, unsigned __int64 received_timestamp)
{
  unsigned __int64 t1;
  unsigned __int64 t2;
  unsigned __int64 t3;
  unsigned __int64 t4;

  t1 = ntohll(pkt->originate_timestamp);
  t2 = ntohll(pkt->receive_timestamp);
  t3 = ntohll(pkt->transmit_timestamp);
  t4 = received_timestamp;

  return ((__int64)(t2 - t1) + (__int64)(t3 - t4)) / 2;
}

static BOOL GetServerTime(const struct NTPPacket *pkt, 
                          SYSTEMTIME *revised_time, int *diff_time, int *delayed_time)
{
  int li, vn, mode;
  SYSTEMTIME received_time;
  unsigned __int64 received_timestamp;
  __int64 delayed;
  __int64 diff;

  li = GetStatus(ntohl(pkt->control), kLIPos, kLIMask);
  vn = GetStatus(ntohl(pkt->control), kVNPos, kVNMask);
  mode = GetStatus(ntohl(pkt->control), kModePos, kModeMask);

  // NTP���b�Z�[�W�̊m�F
  if ((li == kNTPWarning) || (vn != kNTPVersion) || (mode != kNTPServerMode)) {
    return FALSE;
  }

  GetSystemTime(&received_time);
  received_timestamp = GetSystemTimeAsNTPFormat(&received_time);

  // �␳��̎������v�Z����B
  delayed = GetDelayedTime(pkt, received_timestamp);
  diff = GetDiffTime(pkt, received_timestamp);
  *revised_time = ConvertNTPTimestampToSystemTime(received_timestamp + diff);

  *diff_time = GetMillisecondFromNTPFormat(diff);
  *delayed_time = GetMillisecondFromNTPFormat(delayed);

  return TRUE;
}

enum {
  SNTP_OK       = 1,
  SNTP_TIMEOUT  = 0,
  SNTP_ERROR    = -1,
};

static int SntpCommunicate(const char *send_pkt, char *recv_pkt, 
                           const struct sockaddr *server, int timeout)
{
  int result;
  struct timeval waittime;
  fd_set rfds;

  result = sendto(sntp_socket, send_pkt, sizeof(struct NTPPacket), 0,
                  server, sizeof(struct sockaddr_in));
  if (result == SOCKET_ERROR) {
    return SNTP_ERROR;
  }

  waittime.tv_sec = timeout;
  waittime.tv_usec = 0;
  FD_ZERO(&rfds);
  FD_SET(sntp_socket, &rfds);

  result = select(sntp_socket + 1, &rfds, NULL, NULL, &waittime);
  if (result == -1) {
    return SNTP_ERROR;
  } else if (result == 0) { // timeout
    return SNTP_TIMEOUT;
  } else if (FD_ISSET(sntp_socket, &rfds) == 0) {
    return SNTP_ERROR;  // �Ӑ}���Ȃ��f�B�X�N���v�^�Ɏ�M�������ꍇ
  } else {
    struct sockaddr_in sender;
    int sender_len = sizeof(sender);

    result = recvfrom(sntp_socket, recv_pkt, sizeof(struct NTPPacket), 0, 
                      (struct sockaddr *)&sender, &sender_len);
    if (result == SOCKET_ERROR) {
      return SNTP_ERROR;
    }
  }
  return SNTP_OK;
}

BOOL Sntp(SYSTEMTIME *revised_time, int *diff_time, int *delayed_time)
{
  BOOL result;
  struct sockaddr_in sin;

  struct NTPPacket send_pkt;
  struct NTPPacket recv_pkt;

  ZeroMemory(&sin, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_addr = srvaddr;
  sin.sin_port = htons(kSntpPort);

  BuildNTPMessage(&send_pkt);

  if (SntpCommunicate((const char *)&send_pkt, (char *)&recv_pkt, 
                      (struct sockaddr *)&sin, kSntpTimeout) != SNTP_OK) {
    // error
    return FALSE;
  }

//  LocalTimeTest(&recv_pkt);
  result = GetServerTime(&recv_pkt, revised_time, diff_time, delayed_time);

  return result;
}
