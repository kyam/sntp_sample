/*
 * SNTP�ʐM�p����
 *
 *
 */

#ifndef SNTP_H_
#define SNTP_H_

#include <Windows.h>

// SNTP�ʐM��������
// �ʐM����SNTP�T�[�o��IP�A�h���X�Ȃ���FQDN�Ŏw�肷��B
extern BOOL SntpOpen(const char *srvip);
// SNTP�ʐM�I������
extern void SntpClose(void);

// SNTP�ʐM
// 512�b�ȓ��̊Ԋu��SNTP�T�[�o�Ƀ|�[�����O���s���B
// SNTP�̃o�[�W�����͂S��z�肵�Ă���B
// 
// �ʐM�ɐ��������ꍇ��TRUE�A���s����FALSE��Ԃ��B
// revised_time ... �␳��̃V�X�e������
// diff_time    ... SNTP�T�[�o�Ƃ̂���(ms)
// delayed_time ... SNTP�T�[�o�Ƃ̉����ʐM�x������(ms)
extern BOOL Sntp(SYSTEMTIME *revised_time, int *diff_time, int *delayed_time);

#endif