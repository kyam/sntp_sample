/*
 * SNTP通信用処理
 *
 *
 */

#ifndef SNTP_H_
#define SNTP_H_

#include <Windows.h>

// SNTP通信初期処理
// 通信するSNTPサーバをIPアドレスないしFQDNで指定する。
extern BOOL SntpOpen(const char *srvip);
// SNTP通信終了処理
extern void SntpClose(void);

// SNTP通信
// 512秒以内の間隔でSNTPサーバにポーリングを行う。
// SNTPのバージョンは４を想定している。
// 
// 通信に成功した場合はTRUE、失敗時はFALSEを返す。
// revised_time ... 補正後のシステム時間
// diff_time    ... SNTPサーバとのずれ(ms)
// delayed_time ... SNTPサーバとの往復通信遅延時間(ms)
extern BOOL Sntp(SYSTEMTIME *revised_time, int *diff_time, int *delayed_time);

#endif