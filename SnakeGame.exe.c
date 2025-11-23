#include "SnakeGame.exe.h"


int DAT_140007050;
undefined4 DAT_14002300c;
undefined4 DAT_140023138;
undefined4 DAT_140023134;
undefined FUN_140004820;
undefined4 DAT_140023130;
int DAT_140023150;
undefined4 DAT_140023180;
undefined4 DAT_140023140;
undefined DAT_140023004;
undefined4 DAT_140023120;
undefined4 DAT_140007030;
undefined8 DAT_140023018;
undefined8 DAT_140023020;
undefined4 DAT_140023028;
undefined FUN_140001000;
int DAT_140023008;
IMAGE_DOS_HEADER *DAT_140023248;
int DAT_140023028;
undefined8 *DAT_140023020;
int DAT_14002300c;
uint DAT_140023010;
uint DAT_140007000;
char *DAT_140023240;
undefined FUN_140004f70;
uint DAT_140023150;
longlong DAT_140023258;
int DAT_140023250;
LPTOP_LEVEL_EXCEPTION_FILTER DAT_140023190;
undefined *PTR___initenv_140024d18;
IMAGE_DOS_HEADER IMAGE_DOS_HEADER_140000000;
undefined4 DAT_140023150;
undefined FUN_140001520;
undefined *PTR_setSource_1400249f0;
undefined *PTR_setVolume_1400249c8;
undefined DAT_140023050;
undefined DAT_140023060;
undefined DAT_140023070;
undefined DAT_140023080;
undefined DAT_140023090;
int *DAT_140023030;
undefined *PTR_fromUtf8_1400248c8;
undefined *PTR_setPen_140024980;
undefined *PTR_setBrush_1400249a0;
undefined *PTR_setBrush_140024910;
undefined FUN_140002d00;
undefined *PTR_timeout_140024858;
undefined *PTR_staticMetaObject_140024840;
undefined FUN_140006340;
undefined *PTR_FUN_14001f1d0;
undefined *PTR_FUN_14001f380;
int *DAT_1400230a0;
undefined FUN_140003c30;
undefined FUN_140003d00;
undefined FUN_1400063c0;
undefined DAT_14001e540;
undefined *PTR_FUN_14001efc0;
undefined FUN_140003e70;
undefined *PTR_FUN_14001f178;
undefined FUN_140003ea0;
undefined DAT_1400230c0;
undefined DAT_1400230d0;
undefined DAT_1400230e0;
undefined DAT_1400230f0;
undefined DAT_140023100;
undefined *PTR_LAB_14001f3d0;
undefined *PTR_FUN_14001f580;
undefined DAT_14001e700;
undefined *PTR_DAT_140007010;
undefined8 DAT_140006d60;
undefined UNK_140006d58;
undefined FUN_140004680;
int DAT_140023110;
int DAT_140007040;
int DAT_140023164;
undefined1 *DAT_140023168;
int DAT_140023160;
undefined UNK_14001f89f;
undefined DAT_14001f8a0;
undefined *DAT_140023170;
undefined4 DAT_14001f84c;
undefined8 DAT_140023170;
undefined *DAT_140023190;
DWORD *DAT_1400231a0;
undefined DAT_1400231c0;
int DAT_1400231a8;
undefined4 *DAT_1400231a0;
int *DAT_1400231a0;
void *DAT_1400231a0;
undefined *PTR_FUN_140007090;
undefined *PTR___argc_140024d00;
undefined *PTR__fmode_140024d58;
undefined *PTR__commode_140024d50;
undefined *PTR__acmdln_140024d38;
undefined *PTR___argv_140024d08;
undefined8 DAT_140023230;
undefined *PTR_staticMetaObject_140024a40;
undefined *PTR_staticMetaObject_140024b60;
undefined *PTR__empty_1400248a0;
undefined FUN_140001820;
undefined FUN_140001830;
undefined FUN_140001840;
undefined FUN_140001850;
undefined8 DAT_140023030;
undefined FUN_140001860;
undefined FUN_140001870;
undefined FUN_1400030c0;
undefined8 DAT_1400230a0;
undefined FUN_140003af0;
undefined FUN_140003b00;
undefined FUN_140003b10;
undefined FUN_140003b20;
undefined FUN_140003ae0;
undefined FUN_140003dc0;
undefined4 DAT_140007000;
undefined8 DAT_140023240;
undefined8 DAT_140023248;

void FUN_140001000(void)

{
  return;
}



// WARNING: Removing unreachable block (ram,0x000140001104)
// WARNING: Removing unreachable block (ram,0x00014000110e)

undefined8 FUN_140001010(void)

{
  undefined4 *puVar1;
  
  DAT_140023138 = 1;
  DAT_140023134 = 1;
  DAT_140023130 = 1;
  DAT_14002300c = 0;
  if (DAT_140023150 == 0) {
    __set_app_type(1);
  }
  else {
    __set_app_type(2);
  }
  puVar1 = (undefined4 *)FUN_140005a10();
  *puVar1 = DAT_140023180;
  puVar1 = (undefined4 *)FUN_140005a20();
  *puVar1 = DAT_140023140;
  FUN_140004750();
  if (DAT_140007050 != 1) {
    return 0;
  }
  FUN_140004f60(FUN_140004820);
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_140001130(void)

{
  _DAT_140023004 = DAT_140023120;
  __getmainargs(&DAT_140023028,&DAT_140023020,&DAT_140023018,DAT_140007030,&DAT_140023004);
  return;
}



ulonglong FUN_140001180(undefined8 param_1,undefined8 param_2,undefined8 param_3)

{
  int iVar1;
  char cVar2;
  int iVar3;
  longlong lVar4;
  longlong lVar5;
  undefined8 *puVar6;
  char *pcVar7;
  undefined8 *puVar8;
  size_t sVar9;
  void *_Dst;
  ulonglong uVar10;
  longlong lVar11;
  undefined8 uVar12;
  undefined8 uVar13;
  LPSTARTUPINFOA p_Var14;
  PDWORD pDVar15;
  longlong unaff_GS_OFFSET;
  bool bVar16;
  _STARTUPINFOA local_a8;
  
  p_Var14 = &local_a8;
  for (lVar11 = 0xd; lVar11 != 0; lVar11 = lVar11 + -1) {
    *(undefined8 *)p_Var14 = 0;
    p_Var14 = (LPSTARTUPINFOA)&p_Var14->lpReserved;
  }
  pDVar15 = (PDWORD)(ulonglong)DAT_140023150;
  if (DAT_140023150 != 0) {
    GetStartupInfoA(&local_a8);
  }
  lVar11 = *(longlong *)(*(longlong *)(unaff_GS_OFFSET + 0x30) + 8);
  while( true ) {
    LOCK();
    lVar5 = 0;
    lVar4 = lVar11;
    if (DAT_140023258 != 0) {
      lVar5 = DAT_140023258;
      lVar4 = DAT_140023258;
    }
    DAT_140023258 = lVar4;
    UNLOCK();
    if (lVar5 == 0) {
      bVar16 = false;
      goto joined_r0x0001400011ff;
    }
    if (lVar11 == lVar5) break;
    Sleep(1000);
  }
  bVar16 = true;
joined_r0x0001400011ff:
  if (DAT_140023250 == 1) {
    _amsg_exit(0x1f);
  }
  else if (DAT_140023250 == 0) {
    DAT_140023250 = 1;
    _initterm();
  }
  else {
    DAT_140023008 = 1;
  }
  if (DAT_140023250 == 1) {
    _initterm();
    DAT_140023250 = 2;
  }
  if (!bVar16) {
    LOCK();
    DAT_140023258 = 0;
    UNLOCK();
  }
  uVar13 = 2;
  uVar12 = 0;
  tls_callback_0(0,2);
  FUN_140004ba0(uVar12,uVar13,param_3,pDVar15);
  DAT_140023190 = SetUnhandledExceptionFilter(FUN_140004f70);
  FUN_140005a60(FUN_140001000);
  FUN_140004920();
  DAT_140023248 = &IMAGE_DOS_HEADER_140000000;
  puVar6 = (undefined8 *)FUN_140005a30();
  iVar3 = DAT_140023028;
  bVar16 = false;
  pcVar7 = (char *)*puVar6;
  if (pcVar7 != (char *)0x0) {
    do {
      cVar2 = *pcVar7;
      if (cVar2 < '!') {
        if ((cVar2 == '\0') || (!bVar16)) goto LAB_1400012c0;
        bVar16 = true;
      }
      else if (cVar2 == '\"') {
        bVar16 = (bool)(bVar16 ^ 1);
      }
      pcVar7 = pcVar7 + 1;
    } while( true );
  }
  goto LAB_1400012e7;
LAB_1400012c0:
  DAT_140023240 = pcVar7;
  if (cVar2 != '\0') {
    do {
      pcVar7 = pcVar7 + 1;
      DAT_140023240 = pcVar7;
      if (*pcVar7 == '\0') break;
    } while (*pcVar7 < '!');
  }
LAB_1400012e7:
  if ((DAT_140023150 != 0) && (DAT_140007000 = 10, ((byte)local_a8.dwFlags & 1) != 0)) {
    DAT_140007000 = (uint)local_a8.wShowWindow;
  }
  iVar1 = DAT_140023028 + 1;
  puVar8 = (undefined8 *)malloc((longlong)iVar1 * 8);
  lVar11 = (longlong)DAT_140023020;
  puVar6 = puVar8;
  if (0 < iVar3) {
    uVar10 = 0;
    do {
      sVar9 = strlen(*(char **)(lVar11 + uVar10 * 8));
      _Dst = malloc(sVar9 + 1);
      puVar8[uVar10] = _Dst;
      memcpy(_Dst,*(void **)(lVar11 + uVar10 * 8),sVar9 + 1);
      bVar16 = iVar3 - 1 != uVar10;
      uVar10 = uVar10 + 1;
    } while (bVar16);
    puVar6 = puVar8 + (longlong)iVar1 + -1;
  }
  *puVar6 = 0;
  DAT_140023020 = puVar8;
  FUN_140004730();
  *(undefined8 *)__initenv_exref = DAT_140023018;
  uVar10 = FUN_140006d10();
  DAT_140023010 = (uint)uVar10;
  if (DAT_14002300c != 0) {
    if (DAT_140023008 != 0) {
      return uVar10;
    }
    _cexit();
    return (ulonglong)DAT_140023010;
  }
                    // WARNING: Subroutine does not return
  exit(DAT_140023010);
}



void entry(undefined8 param_1,undefined8 param_2,undefined8 param_3)

{
  DAT_140023150 = 1;
  FUN_140001180(param_1,param_2,param_3);
  return;
}



void FUN_1400014d0(undefined8 param_1,undefined8 param_2,undefined8 param_3)

{
  DAT_140023150 = 0;
  FUN_140001180(param_1,param_2,param_3);
  return;
}



int FUN_1400014f0(_onexit_t param_1)

{
  _onexit_t p_Var1;
  
  p_Var1 = _onexit(param_1);
  return -(uint)(p_Var1 == (_onexit_t)0x0);
}



void FUN_140001510(void)

{
  FUN_1400014f0(FUN_140001520);
  return;
}



void FUN_140001520(void)

{
  return;
}



void FUN_140001530(undefined8 *param_1)

{
  QMediaPlayer *this;
  QAudioOutput *this_00;
  
  this = (QMediaPlayer *)operator_new(0x10);
  QMediaPlayer::QMediaPlayer(this,(QObject *)0x0);
  *param_1 = this;
  this_00 = (QAudioOutput *)operator_new(0x18);
  QAudioOutput::QAudioOutput(this_00,(QObject *)0x0);
  param_1[1] = this_00;
  return;
}



void FUN_1400015b0(void)

{
  QMediaPlayer::stop();
                    // WARNING: Could not recover jumptable at 0x0001400015d0. Too many branches
                    // WARNING: Treating indirect jump as call
  QMediaPlayer::play();
  return;
}



void FUN_1400015e0(void)

{
  QMediaPlayer::stop();
                    // WARNING: Could not recover jumptable at 0x000140001600. Too many branches
                    // WARNING: Treating indirect jump as call
  QMediaPlayer::play();
  return;
}



undefined8 FUN_140001610(undefined8 *param_1)

{
  return *param_1;
}



undefined8 FUN_140001620(longlong param_1)

{
  return *(undefined8 *)(param_1 + 8);
}



void FUN_140001630(undefined8 *param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4)

{
  QUrl *pQVar1;
  undefined8 *puVar2;
  float fVar3;
  float extraout_XMM0_Da;
  float extraout_XMM0_Da_00;
  undefined8 local_88;
  char *local_80;
  QUrl local_70 [8];
  int *local_68 [5];
  
  puVar2 = (undefined8 *)operator_new(0x10);
  FUN_140001530(puVar2);
  *param_1 = puVar2;
  puVar2 = (undefined8 *)operator_new(0x10);
  FUN_140001530(puVar2);
  param_1[1] = puVar2;
  QMediaPlayer::setAudioOutput(*(QAudioOutput **)*param_1);
  pQVar1 = *(QUrl **)*param_1;
  local_88 = 0x1f;
  local_80 = "qrc:/sounds/Sounds/eatSound.wav";
  QString::fromUtf8(local_68,&local_88);
  QUrl::QUrl(local_70,local_68,0);
  QMediaPlayer::setSource(pQVar1);
  fVar3 = (float)QUrl::~QUrl(local_70);
  if (local_68[0] != (int *)0x0) {
    LOCK();
    *local_68[0] = *local_68[0] + -1;
    UNLOCK();
    if (*local_68[0] == 0) {
      free(local_68[0]);
      fVar3 = extraout_XMM0_Da_00;
    }
  }
  QAudioOutput::setVolume(fVar3);
  QMediaPlayer::setAudioOutput(*(QAudioOutput **)param_1[1]);
  pQVar1 = *(QUrl **)param_1[1];
  local_88 = 0x20;
  local_80 = "qrc:/sounds/Sounds/deadSound.wav";
  QString::fromUtf8(local_68,&local_88);
  QUrl::QUrl(local_70,local_68,0);
  QMediaPlayer::setSource(pQVar1);
  fVar3 = (float)QUrl::~QUrl(local_70);
  if (local_68[0] != (int *)0x0) {
    LOCK();
    *local_68[0] = *local_68[0] + -1;
    UNLOCK();
    if (*local_68[0] == 0) {
      free(local_68[0]);
      fVar3 = extraout_XMM0_Da;
    }
  }
                    // WARNING: Could not recover jumptable at 0x0001400017a8. Too many branches
                    // WARNING: Treating indirect jump as call
  QAudioOutput::setVolume(fVar3);
  return;
}



void FUN_140001820(void)

{
                    // WARNING: Could not recover jumptable at 0x000140001827. Too many branches
                    // WARNING: Treating indirect jump as call
  QFont::~QFont((QFont *)&DAT_140023050);
  return;
}



void FUN_140001830(void)

{
                    // WARNING: Could not recover jumptable at 0x000140001837. Too many branches
                    // WARNING: Treating indirect jump as call
  QFont::~QFont((QFont *)&DAT_140023060);
  return;
}



void FUN_140001840(void)

{
                    // WARNING: Could not recover jumptable at 0x000140001847. Too many branches
                    // WARNING: Treating indirect jump as call
  QFont::~QFont((QFont *)&DAT_140023070);
  return;
}



void FUN_140001850(void)

{
                    // WARNING: Could not recover jumptable at 0x000140001857. Too many branches
                    // WARNING: Treating indirect jump as call
  QFont::~QFont((QFont *)&DAT_140023080);
  return;
}



void FUN_140001860(void)

{
                    // WARNING: Could not recover jumptable at 0x000140001867. Too many branches
                    // WARNING: Treating indirect jump as call
  QFont::~QFont((QFont *)&DAT_140023090);
  return;
}



void FUN_140001870(void)

{
  int *piVar1;
  
  piVar1 = DAT_140023030;
  if (DAT_140023030 != (int *)0x0) {
    LOCK();
    *DAT_140023030 = *DAT_140023030 + -1;
    UNLOCK();
    if (*piVar1 == 0) {
      free(DAT_140023030);
      return;
    }
  }
  return;
}



undefined8 FUN_1400018a0(undefined8 param_1,undefined4 *param_2,undefined4 *param_3)

{
  int iVar1;
  int iVar2;
  undefined4 extraout_var;
  
  iVar1 = FUN_140003660(param_2);
  iVar2 = FUN_140003660(param_3);
  if (iVar1 != iVar2) {
    return 0;
  }
  iVar1 = FUN_140003670((longlong)param_2);
  iVar2 = FUN_140003670((longlong)param_3);
  return CONCAT71((int7)(CONCAT44(extraout_var,iVar2) >> 8),iVar1 == iVar2);
}



void FUN_140001900(QObject *param_1)

{
  QObject *pQVar1;
  char *local_68;
  undefined8 local_60;
  int *local_58;
  undefined8 local_50;
  undefined8 local_48;
  int *local_38;
  undefined8 local_30;
  undefined8 local_28;
  
  pQVar1 = param_1 + 0x3c;
  *pQVar1 = (QObject)((byte)*pQVar1 ^ 1);
  local_58 = (int *)0x0;
  local_50 = 0;
  local_48 = 0;
  if (*pQVar1 == (QObject)0x0) {
    local_60 = 5;
    local_68 = "Pause";
    QString::assign(&local_58,&local_68);
    QTimer::start((int)*(undefined8 *)(param_1 + 0x50));
  }
  else {
    QTimer::stop();
    local_60 = 8;
    local_68 = "Continue";
    QString::assign(&local_58,&local_68);
  }
  local_30 = local_50;
  local_38 = local_58;
  local_28 = local_48;
  if (local_58 != (int *)0x0) {
    LOCK();
    *local_58 = *local_58 + 1;
    UNLOCK();
  }
  FUN_140003e70(param_1,&local_38);
  if (local_38 != (int *)0x0) {
    LOCK();
    *local_38 = *local_38 + -1;
    UNLOCK();
    if (*local_38 == 0) {
      free(local_38);
    }
  }
  if (local_58 != (int *)0x0) {
    LOCK();
    *local_58 = *local_58 + -1;
    UNLOCK();
    if (*local_58 == 0) {
      free(local_58);
      return;
    }
  }
  return;
}



void FUN_140001a60(longlong param_1)

{
  QTextStream QVar1;
  undefined8 *puVar2;
  int *piVar3;
  QTextStream *this;
  undefined8 local_88;
  char *local_80;
  QTextStream *local_70;
  int *local_68 [4];
  undefined8 local_48;
  undefined8 local_40;
  undefined8 local_38;
  char *local_30;
  
  if (*(char *)(param_1 + 0x3f) != '\0') {
    return;
  }
  puVar2 = *(undefined8 **)(param_1 + 0x40);
  if (puVar2 != (undefined8 *)0x0) {
    piVar3 = (int *)*puVar2;
    if (piVar3 != (int *)0x0) {
      LOCK();
      *piVar3 = *piVar3 + -1;
      UNLOCK();
      if (*piVar3 == 0) {
        free((void *)*puVar2);
      }
    }
    operator_delete(puVar2,0x20);
  }
  if (*(longlong **)(param_1 + 0x50) != (longlong *)0x0) {
    (**(code **)(**(longlong **)(param_1 + 0x50) + 0x20))();
  }
  if (*(void **)(param_1 + 0x48) != (void *)0x0) {
    operator_delete(*(void **)(param_1 + 0x48),8);
  }
  if (*(void **)(param_1 + 0x58) != (void *)0x0) {
    operator_delete(*(void **)(param_1 + 0x58),0x9d0);
  }
  *(undefined1 *)(param_1 + 0x3f) = 1;
  local_30 = "default";
  local_48 = 2;
  local_40 = 0;
  local_38 = 0;
  QMessageLogger::debug();
  this = local_70;
  local_88 = 0xf;
  local_80 = "Objects deleted";
  QString::fromUtf8((QString *)local_68,&local_88);
  QTextStream::operator<<(this,(QString *)local_68);
  if (local_68[0] != (int *)0x0) {
    LOCK();
    *local_68[0] = *local_68[0] + -1;
    UNLOCK();
    if (*local_68[0] == 0) {
      free(local_68[0]);
      QVar1 = local_70[0x30];
      goto joined_r0x000140001b6e;
    }
  }
  QVar1 = local_70[0x30];
joined_r0x000140001b6e:
  if (QVar1 != (QTextStream)0x0) {
    QTextStream::operator<<(local_70,' ');
  }
  QDebug::~QDebug((QDebug *)&local_70);
  return;
}



void FUN_140001be0(longlong param_1)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  longlong *plVar6;
  longlong lVar7;
  
  do {
    iVar4 = *(int *)(param_1 + 0x30);
    puVar1 = *(undefined4 **)(param_1 + 0x48);
    uVar3 = QRandomGenerator::_fillRange(*(void **)(param_1 + 0x58),0);
    FUN_140003680(puVar1,(int)((ulonglong)uVar3 * (ulonglong)(iVar4 - 1) >> 0x20));
    iVar4 = *(int *)(param_1 + 0x30);
    lVar7 = *(longlong *)(param_1 + 0x48);
    uVar3 = QRandomGenerator::_fillRange(*(void **)(param_1 + 0x58),0);
    FUN_140003690(lVar7,(int)((ulonglong)uVar3 * (ulonglong)(iVar4 - 1) >> 0x20));
    plVar6 = *(longlong **)(param_1 + 0x40);
    if (plVar6[2] < 1) {
      return;
    }
    lVar7 = 0;
    while( true ) {
      while( true ) {
        if (((int *)*plVar6 == (int *)0x0) || (1 < *(int *)*plVar6)) {
          FUN_140005c60(plVar6,0,0,(undefined8 *)0x0);
        }
        puVar1 = *(undefined4 **)(param_1 + 0x48);
        puVar2 = *(undefined4 **)(plVar6[1] + lVar7 * 8);
        iVar4 = FUN_140003660(puVar1);
        iVar5 = FUN_140003660(puVar2);
        if (iVar4 == iVar5) break;
        plVar6 = *(longlong **)(param_1 + 0x40);
        lVar7 = lVar7 + 1;
        if (plVar6[2] <= lVar7) {
          return;
        }
      }
      iVar4 = FUN_140003670((longlong)puVar1);
      iVar5 = FUN_140003670((longlong)puVar2);
      if (iVar4 == iVar5) break;
      plVar6 = *(longlong **)(param_1 + 0x40);
      lVar7 = lVar7 + 1;
      if (plVar6[2] <= lVar7) {
        return;
      }
    }
  } while( true );
}



void FUN_140001cf0(longlong param_1)

{
  int iVar1;
  int *piVar2;
  int iVar3;
  longlong *plVar4;
  code *pcVar5;
  int iVar6;
  longlong lVar7;
  undefined8 local_e8;
  char *local_e0;
  QPainter local_d0 [8];
  QBrush local_c8 [8];
  QBrush local_c0 [8];
  QBrush local_b8 [8];
  QBrush local_b0 [8];
  QPen local_a8 [8];
  QPen local_a0 [8];
  undefined8 local_98;
  int local_90;
  int local_8c;
  int local_88;
  int iStack_84;
  int local_80;
  int local_7c;
  int local_68;
  int iStack_64;
  int local_60;
  int local_5c;
  
  QPainter::QPainter(local_d0);
  QColor::QColor((QColor *)&local_68,0xff272f1e);
  QBrush::QBrush(local_c8,(QColor *)&local_68,1);
  QColor::QColor((QColor *)&local_68,0xffcf2828);
  QBrush::QBrush(local_c0,(QColor *)&local_68,1);
  QColor::QColor((QColor *)&local_68,0xff90b63d);
  QBrush::QBrush(local_b8,(QColor *)&local_68,1);
  QColor::QColor((QColor *)&local_68,0xffa0c54e);
  QBrush::QBrush(local_b0,(QColor *)&local_68,1);
  QPainter::begin((QPaintDevice *)local_d0);
  QPen::QPen(local_a8);
  QPen::QPen(local_a0);
  QPen::setStyle(local_a8,2);
  QPen::setStyle(local_a0,1);
  pcVar5 = setPen_exref;
  if (0 < *(int *)(param_1 + 0x30)) {
    iVar6 = 0;
    do {
      pcVar5 = setPen_exref;
      iVar3 = 0;
      do {
        iVar1 = *(int *)(param_1 + 0x2c);
        iStack_64 = iVar1 * iVar6;
        local_68 = iVar1 * iVar3;
        local_60 = iVar1 + -1 + local_68;
        local_5c = iVar1 + -1 + iStack_64;
        if ((iVar3 + iVar6 & 1U) == 0) {
          QPainter::setBrush((QBrush *)local_d0);
          QPen::setBrush((QBrush *)local_a0);
        }
        else {
          QPainter::setBrush((QBrush *)local_d0);
          QPen::setBrush((QBrush *)local_a0);
        }
        QPainter::setPen((QPen *)local_d0);
        QPainter::drawRects((QRect *)local_d0,(int)(QColor *)&local_68);
        iVar1 = *(int *)(param_1 + 0x30);
        iVar3 = iVar3 + 1;
      } while (iVar3 < iVar1);
      iVar6 = iVar6 + 1;
    } while ((iVar6 < iVar1) && (0 < iVar1));
  }
  local_98 = 0;
  lVar7 = *(longlong *)(param_1 + 0x20);
  local_8c = (*(int *)(lVar7 + 0x20) - *(int *)(lVar7 + 0x18)) + -1;
  local_90 = (*(int *)(lVar7 + 0x1c) - *(int *)(lVar7 + 0x14)) + -1;
  (*pcVar5)(local_d0,local_a8);
  QPainter::setBrush(local_d0,0);
  iVar6 = (int)&local_98;
  QPainter::drawRects((QRect *)local_d0,iVar6);
  (*pcVar5)(local_d0,local_a8);
  QPainter::setBrush((QBrush *)local_d0);
  if (*(char *)(param_1 + 0x3e) == '\0') {
    (*pcVar5)(local_d0,local_a0);
    QPainter::setBrush((QBrush *)local_d0);
    plVar4 = *(longlong **)(param_1 + 0x40);
    lVar7 = 0;
    if (0 < plVar4[2]) {
      do {
        iVar6 = *(int *)(param_1 + 0x2c);
        if (((int *)*plVar4 == (int *)0x0) || (1 < *(int *)*plVar4)) {
          FUN_140005c60(plVar4,0,0,(undefined8 *)0x0);
        }
        iVar3 = FUN_140003670(*(longlong *)(plVar4[1] + lVar7 * 8));
        plVar4 = *(longlong **)(param_1 + 0x40);
        iVar3 = iVar3 * *(int *)(param_1 + 0x2c);
        if (((int *)*plVar4 == (int *)0x0) || (1 < *(int *)*plVar4)) {
          FUN_140005c60(plVar4,0,0,(undefined8 *)0x0);
        }
        local_88 = FUN_140003660(*(undefined4 **)(plVar4[1] + lVar7 * 8));
        local_88 = local_88 * *(int *)(param_1 + 0x2c);
        local_80 = iVar6 + -1 + local_88;
        local_7c = iVar6 + -1 + iVar3;
        iStack_84 = iVar3;
        QPainter::drawEllipse((QRect *)local_d0);
        plVar4 = *(longlong **)(param_1 + 0x40);
        lVar7 = lVar7 + 1;
      } while (lVar7 < plVar4[2]);
    }
    QPainter::setBrush((QBrush *)local_d0);
    iVar6 = *(int *)(param_1 + 0x2c);
    iVar3 = FUN_140003670(*(longlong *)(param_1 + 0x48));
    iVar3 = iVar3 * *(int *)(param_1 + 0x2c);
    local_68 = FUN_140003660(*(undefined4 **)(param_1 + 0x48));
    local_68 = local_68 * *(int *)(param_1 + 0x2c);
    local_60 = iVar6 + -1 + local_68;
    local_5c = iVar6 + -1 + iVar3;
    iStack_64 = iVar3;
    QPainter::drawEllipse((QRect *)local_d0);
    QPainter::end();
    *(undefined1 *)(param_1 + 0x3d) = 0;
  }
  else {
    QPainter::setFont((QFont *)local_d0);
    local_e8 = 0xb;
    local_e0 = "Game Over\n\n";
    QString::fromUtf8((QColor *)&local_68,&local_e8);
    QPainter::drawText((QRect *)local_d0,iVar6,(QString *)0x84,(QRect *)&local_68);
    piVar2 = (int *)CONCAT44(iStack_64,local_68);
    if (piVar2 != (int *)0x0) {
      LOCK();
      *piVar2 = *piVar2 + -1;
      UNLOCK();
      if (*piVar2 == 0) {
        free((void *)CONCAT44(iStack_64,local_68));
      }
    }
    QPainter::setFont((QFont *)local_d0);
    QString::number((int)&local_88,*(int *)(param_1 + 0x38));
    local_e8 = 0xc;
    local_e0 = "Best score: ";
    QString::fromUtf8((QColor *)&local_68,&local_e8);
    QString::append((QString *)&local_68);
    QPainter::drawText((QRect *)local_d0,iVar6,(QString *)0x84,(QRect *)&local_68);
    piVar2 = (int *)CONCAT44(iStack_64,local_68);
    if (piVar2 != (int *)0x0) {
      LOCK();
      *piVar2 = *piVar2 + -1;
      UNLOCK();
      if (*piVar2 == 0) {
        free((void *)CONCAT44(iStack_64,local_68));
      }
    }
    piVar2 = (int *)CONCAT44(iStack_84,local_88);
    if (piVar2 != (int *)0x0) {
      LOCK();
      *piVar2 = *piVar2 + -1;
      UNLOCK();
      if (*piVar2 == 0) {
        free((void *)CONCAT44(iStack_84,local_88));
      }
    }
    FUN_140001a60(param_1);
  }
  QPen::~QPen(local_a0);
  QPen::~QPen(local_a8);
  QBrush::~QBrush(local_b0);
  QBrush::~QBrush(local_b8);
  QBrush::~QBrush(local_c0);
  QBrush::~QBrush(local_c8);
  QPainter::~QPainter(local_d0);
  return;
}



void FUN_140002350(longlong param_1)

{
  char cVar1;
  undefined8 local_58;
  char *local_50;
  QFile local_48 [16];
  int *local_38 [4];
  
  local_50 = "BestScore.txt";
  local_58 = 0xd;
  QString::fromUtf8((QDataStream *)local_38,&local_58);
  QFile::QFile(local_48,(QString *)local_38);
  if (local_38[0] != (int *)0x0) {
    LOCK();
    *local_38[0] = *local_38[0] + -1;
    UNLOCK();
    if (*local_38[0] == 0) {
      free(local_38[0]);
    }
  }
  cVar1 = QFile::open(local_48,1);
  if (cVar1 != '\0') {
    QDataStream::QDataStream((QDataStream *)local_38,(QIODevice *)local_48);
    QDataStream::operator>>((QDataStream *)local_38,(int *)(param_1 + 0x38));
    QFileDevice::close();
    QDataStream::~QDataStream((QDataStream *)local_38);
    QFile::~QFile(local_48);
    return;
  }
  *(undefined4 *)(param_1 + 0x38) = 0;
  QFile::~QFile(local_48);
  return;
}



void FUN_140002470(QObject *param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4)

{
  QTextStream QVar1;
  undefined8 uVar2;
  code *pcVar3;
  QTextStream *this;
  QTimer *this_00;
  longlong *plVar4;
  undefined4 *puVar5;
  QRandomGenerator *this_01;
  undefined8 *puVar6;
  uint *puVar7;
  uint *puVar8;
  undefined8 local_98;
  char *local_90;
  QTextStream *local_80;
  code *local_78;
  undefined8 uStack_70;
  undefined8 local_58;
  undefined8 local_50;
  undefined8 local_48;
  char *local_40;
  
  *(undefined4 *)(param_1 + 0x3c) = 0;
  this_00 = (QTimer *)operator_new(0x10);
  QTimer::QTimer(this_00,(QObject *)0x0);
  *(QTimer **)(param_1 + 0x50) = this_00;
  plVar4 = (longlong *)operator_new(0x20);
  FUN_1400036a0(plVar4);
  *(longlong **)(param_1 + 0x40) = plVar4;
  puVar5 = (undefined4 *)operator_new(8);
  FUN_140003620(puVar5,*(int *)(param_1 + 0x30) / 2,*(int *)(param_1 + 0x30) / 2);
  *(undefined4 **)(param_1 + 0x48) = puVar5;
  this_01 = (QRandomGenerator *)operator_new(0x9d0);
  local_58 = (code *)CONCAT44(local_58._4_4_,1);
  puVar8 = (uint *)((longlong)&local_58 + 4);
  puVar7 = (uint *)&local_58;
  QRandomGenerator::QRandomGenerator(this_01,(uint *)&local_58,puVar8);
  *(QRandomGenerator **)(param_1 + 0x58) = this_01;
  puVar6 = (undefined8 *)operator_new(0x10);
  FUN_140001630(puVar6,puVar7,puVar8,param_4);
  *(undefined8 **)(param_1 + 0x60) = puVar6;
  local_58 = timeout_exref;
  uVar2 = *(undefined8 *)(param_1 + 0x50);
  local_78 = FUN_140002d00;
  *(undefined4 *)(param_1 + 0x34) = 0;
  uStack_70 = 0;
  local_50 = 0;
  puVar5 = (undefined4 *)operator_new(0x20);
  *puVar5 = 1;
  *(code **)(puVar5 + 2) = FUN_140006340;
  pcVar3 = staticMetaObject_exref;
  *(code **)(puVar5 + 4) = local_78;
  *(undefined8 *)(puVar5 + 6) = uStack_70;
  QObject::connectImpl
            ((Connection *)&local_80,uVar2,&local_58,param_1,(QString *)&local_78,puVar5,0,0,pcVar3)
  ;
  QMetaObject::Connection::~Connection((Connection *)&local_80);
  QTimer::start((int)*(undefined8 *)(param_1 + 0x50));
  local_40 = "default";
  local_58 = (code *)0x2;
  local_50 = 0;
  local_48 = 0;
  QMessageLogger::debug();
  this = local_80;
  local_98 = 0x13;
  local_90 = "gameTimerStarted...";
  QString::fromUtf8((QString *)&local_78,&local_98);
  QTextStream::operator<<(this,(QString *)&local_78);
  if (local_78 != (code *)0x0) {
    LOCK();
    *(int *)local_78 = *(int *)local_78 + -1;
    UNLOCK();
    if (*(int *)local_78 == 0) {
      free(local_78);
      QVar1 = local_80[0x30];
      goto joined_r0x000140002773;
    }
  }
  QVar1 = local_80[0x30];
joined_r0x000140002773:
  if (QVar1 != (QTextStream)0x0) {
    QTextStream::operator<<(local_80,' ');
  }
  QDebug::~QDebug((QDebug *)&local_80);
  FUN_140002350((longlong)param_1);
  local_98 = 5;
  local_90 = "Pause";
  QString::fromUtf8(&local_58,&local_98);
  FUN_140003e70(param_1,&local_58);
  if (local_58 != (code *)0x0) {
    LOCK();
    *(int *)local_58 = *(int *)local_58 + -1;
    UNLOCK();
    if (*(int *)local_58 == 0) {
      free(local_58);
    }
  }
  local_98 = 1;
  local_90 = "0";
  QString::fromUtf8(&local_58,&local_98);
  FUN_140003ea0(param_1,&local_58);
  if (local_58 != (code *)0x0) {
    LOCK();
    *(int *)local_58 = *(int *)local_58 + -1;
    UNLOCK();
    if (*(int *)local_58 == 0) {
      free(local_58);
    }
  }
  return;
}



void FUN_140002840(QObject *param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4)

{
  int iVar1;
  undefined8 uVar2;
  
  QWidget::QWidget((QWidget *)param_1,0,0);
  uVar2 = 300;
  *(undefined ***)(param_1 + 0x10) = &PTR_FUN_14001f380;
  *(undefined ***)param_1 = &PTR_FUN_14001f1d0;
  *(undefined8 *)(param_1 + 0x28) = 0xa00000064;
  QWidget::setFixedSize((int)param_1,300);
  QWidget::setFocusPolicy(param_1,0xb);
  iVar1 = (*(int *)(*(longlong *)(param_1 + 0x20) + 0x1c) -
          *(int *)(*(longlong *)(param_1 + 0x20) + 0x14)) + 1;
  *(int *)(param_1 + 0x30) = iVar1 / *(int *)(param_1 + 0x2c);
  FUN_140002470(param_1,(longlong)iVar1 % (longlong)*(int *)(param_1 + 0x2c) & 0xffffffff,uVar2,
                param_4);
  return;
}



void FUN_1400028f0(QObject *param_1,longlong param_2,undefined8 param_3,undefined8 param_4)

{
  int iVar1;
  
  if (*(int *)(param_2 + 0x40) == 0x20) {
    if (param_1[0x3e] != (QObject)0x0) {
      FUN_140002470(param_1,param_2,param_3,param_4);
      return;
    }
    FUN_140001900(param_1);
  }
  if (param_1[0x3d] != (QObject)0x0) {
    return;
  }
  iVar1 = *(int *)(param_2 + 0x40);
  if (iVar1 == 0x1000014) {
    iVar1 = FUN_140003640(*(longlong *)(param_1 + 0x40));
    if (iVar1 != 1) {
      FUN_140003650(*(longlong *)(param_1 + 0x40),2);
      goto LAB_14000292e;
    }
    iVar1 = *(int *)(param_2 + 0x40);
  }
  if (iVar1 == 0x1000012) {
    iVar1 = FUN_140003640(*(longlong *)(param_1 + 0x40));
    if (iVar1 != 2) {
      FUN_140003650(*(longlong *)(param_1 + 0x40),1);
      goto LAB_14000292e;
    }
    iVar1 = *(int *)(param_2 + 0x40);
  }
  if (iVar1 == 0x1000013) {
    iVar1 = FUN_140003640(*(longlong *)(param_1 + 0x40));
    if (iVar1 != 3) {
      FUN_140003650(*(longlong *)(param_1 + 0x40),0);
      goto LAB_14000292e;
    }
    iVar1 = *(int *)(param_2 + 0x40);
  }
  if ((iVar1 == 0x1000015) && (iVar1 = FUN_140003640(*(longlong *)(param_1 + 0x40)), iVar1 != 0)) {
    FUN_140003650(*(longlong *)(param_1 + 0x40),3);
  }
LAB_14000292e:
  param_1[0x3d] = (QObject)0x1;
  return;
}



void FUN_140002a30(longlong param_1)

{
  char cVar1;
  undefined8 local_58;
  char *local_50;
  QFile local_48 [16];
  int *local_38 [4];
  
  local_50 = "BestScore.txt";
  local_58 = 0xd;
  QString::fromUtf8((QDataStream *)local_38,&local_58);
  QFile::QFile(local_48,(QString *)local_38);
  if (local_38[0] != (int *)0x0) {
    LOCK();
    *local_38[0] = *local_38[0] + -1;
    UNLOCK();
    if (*local_38[0] == 0) {
      free(local_38[0]);
    }
  }
  cVar1 = QFile::open(local_48,2);
  if (cVar1 != '\0') {
    QDataStream::QDataStream((QDataStream *)local_38,(QIODevice *)local_48);
    QDataStream::operator<<((QDataStream *)local_38,*(int *)(param_1 + 0x38));
    QFileDevice::close();
    QDataStream::~QDataStream((QDataStream *)local_38);
    QFile::~QFile(local_48);
    return;
  }
  *(undefined4 *)(param_1 + 0x38) = 0;
  QFile::~QFile(local_48);
  return;
}



void FUN_140002b40(QObject *param_1)

{
  QTextStream QVar1;
  QTextStream *this;
  undefined8 local_98;
  char *local_90;
  QTextStream *local_80;
  int *local_78 [4];
  int *local_58;
  undefined8 local_50;
  undefined8 local_48;
  char *local_40;
  
  param_1[0x3e] = (QObject)0x1;
  if (*(int *)(param_1 + 0x38) < *(int *)(param_1 + 0x34)) {
    *(int *)(param_1 + 0x38) = *(int *)(param_1 + 0x34);
    FUN_140002a30((longlong)param_1);
  }
  FUN_1400015e0();
  local_90 = "New game";
  local_98 = 8;
  QString::fromUtf8(&local_58,&local_98);
  FUN_140003e70(param_1,&local_58);
  if (local_58 != (int *)0x0) {
    LOCK();
    *local_58 = *local_58 + -1;
    UNLOCK();
    if (*local_58 == 0) {
      free(local_58);
    }
  }
  QTimer::stop();
  local_40 = "default";
  local_58 = (int *)0x2;
  local_50 = 0;
  local_48 = 0;
  QMessageLogger::debug();
  this = local_80;
  local_98 = 0x10;
  local_90 = "gameTimerStoped!";
  QString::fromUtf8((QString *)local_78,&local_98);
  QTextStream::operator<<(this,(QString *)local_78);
  if (local_78[0] != (int *)0x0) {
    LOCK();
    *local_78[0] = *local_78[0] + -1;
    UNLOCK();
    if (*local_78[0] == 0) {
      free(local_78[0]);
      QVar1 = local_80[0x30];
      goto joined_r0x000140002c83;
    }
  }
  QVar1 = local_80[0x30];
joined_r0x000140002c83:
  if (QVar1 != (QTextStream)0x0) {
    QTextStream::operator<<(local_80,' ');
  }
  QDebug::~QDebug((QDebug *)&local_80);
  return;
}



void FUN_140002d00(QObject *param_1)

{
  undefined4 *puVar1;
  longlong *plVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int *piVar6;
  longlong *plVar7;
  longlong lVar8;
  int *local_58 [5];
  
  plVar7 = *(longlong **)(param_1 + 0x40);
  if (((int *)*plVar7 == (int *)0x0) || (1 < *(int *)*plVar7)) {
    FUN_140005c60(plVar7,0,0,(undefined8 *)0x0);
  }
  iVar3 = FUN_140003660(*(undefined4 **)plVar7[1]);
  plVar7 = *(longlong **)(param_1 + 0x40);
  if (((int *)*plVar7 == (int *)0x0) || (1 < *(int *)*plVar7)) {
    FUN_140005c60(plVar7,0,0,(undefined8 *)0x0);
  }
  iVar4 = FUN_140003670(*(longlong *)plVar7[1]);
  iVar5 = FUN_140003640(*(longlong *)(param_1 + 0x40));
  if (iVar5 == 2) {
    piVar6 = (int *)operator_new(8);
    FUN_140003620(piVar6,iVar3 + 1,iVar4);
LAB_140002dc9:
    iVar3 = FUN_140003660(piVar6);
    if (*(int *)(param_1 + 0x30) <= iVar3) goto LAB_140002ddc;
LAB_140002f4f:
    iVar3 = FUN_140003660(piVar6);
    if (iVar3 < 0) {
      FUN_140003680(piVar6,*(int *)(param_1 + 0x30) + -1);
    }
    else {
      iVar3 = FUN_140003670((longlong)piVar6);
      if (iVar3 < 0) {
        FUN_140003690((longlong)piVar6,*(int *)(param_1 + 0x30) + -1);
      }
      else {
        iVar3 = FUN_140003670((longlong)piVar6);
        if (*(int *)(param_1 + 0x30) <= iVar3) {
          FUN_140003690((longlong)piVar6,0);
        }
      }
    }
  }
  else {
    iVar5 = FUN_140003640(*(longlong *)(param_1 + 0x40));
    if (iVar5 != 1) {
      iVar5 = FUN_140003640(*(longlong *)(param_1 + 0x40));
      if (iVar5 == 0) {
        piVar6 = (int *)operator_new(8);
        FUN_140003620(piVar6,iVar3,iVar4 + -1);
      }
      else {
        piVar6 = (int *)operator_new(8);
        FUN_140003620(piVar6,iVar3,iVar4 + 1);
      }
      goto LAB_140002dc9;
    }
    piVar6 = (int *)operator_new(8);
    FUN_140003620(piVar6,iVar3 + -1,iVar4);
    iVar3 = FUN_140003660(piVar6);
    if (iVar3 < *(int *)(param_1 + 0x30)) goto LAB_140002f4f;
LAB_140002ddc:
    FUN_140003680(piVar6,0);
  }
  plVar7 = *(longlong **)(param_1 + 0x40);
  lVar8 = 0;
  if (0 < plVar7[2]) {
    do {
      while( true ) {
        if (((int *)*plVar7 == (int *)0x0) || (1 < *(int *)*plVar7)) {
          FUN_140005c60(plVar7,0,0,(undefined8 *)0x0);
        }
        puVar1 = *(undefined4 **)(plVar7[1] + lVar8 * 8);
        iVar3 = FUN_140003660(piVar6);
        iVar4 = FUN_140003660(puVar1);
        if (iVar3 == iVar4) break;
LAB_140002e00:
        plVar7 = *(longlong **)(param_1 + 0x40);
        lVar8 = lVar8 + 1;
        if (plVar7[2] <= lVar8) goto LAB_140002e79;
      }
      iVar3 = FUN_140003670((longlong)piVar6);
      iVar4 = FUN_140003670((longlong)puVar1);
      if (iVar3 != iVar4) goto LAB_140002e00;
      lVar8 = lVar8 + 1;
      FUN_140002b40(param_1);
      plVar7 = *(longlong **)(param_1 + 0x40);
    } while (lVar8 < plVar7[2]);
  }
LAB_140002e79:
  puVar1 = *(undefined4 **)(param_1 + 0x48);
  iVar3 = FUN_140003660(piVar6);
  iVar4 = FUN_140003660(puVar1);
  if (iVar3 == iVar4) {
    iVar3 = FUN_140003670((longlong)piVar6);
    iVar4 = FUN_140003670((longlong)puVar1);
    if (iVar3 == iVar4) {
      *(int *)(param_1 + 0x34) = *(int *)(param_1 + 0x34) + 1;
      FUN_140001be0((longlong)param_1);
      FUN_1400015b0();
      QString::number((int)local_58,*(int *)(param_1 + 0x34));
      FUN_140003ea0(param_1,local_58);
      if (local_58[0] != (int *)0x0) {
        LOCK();
        *local_58[0] = *local_58[0] + -1;
        UNLOCK();
        if (*local_58[0] == 0) {
          free(local_58[0]);
          plVar7 = *(longlong **)(param_1 + 0x40);
          goto LAB_140002ece;
        }
      }
      plVar7 = *(longlong **)(param_1 + 0x40);
      goto LAB_140002ece;
    }
  }
  plVar2 = *(longlong **)(param_1 + 0x40);
  if (((int *)*plVar2 == (int *)0x0) || (plVar7 = plVar2, 1 < *(int *)*plVar2)) {
    FUN_140005c60(plVar2,0,0,(undefined8 *)0x0);
    plVar7 = *(longlong **)(param_1 + 0x40);
  }
  plVar2[2] = plVar2[2] + -1;
LAB_140002ece:
  local_58[0] = piVar6;
  FUN_140006080(plVar7,0,local_58);
  if (((int *)*plVar7 == (int *)0x0) || (1 < *(int *)*plVar7)) {
    FUN_140005c60(plVar7,0,0,(undefined8 *)0x0);
  }
                    // WARNING: Could not recover jumptable at 0x000140002f10. Too many branches
                    // WARNING: Treating indirect jump as call
  QWidget::repaint();
  return;
}



void FUN_1400030c0(void)

{
  int *piVar1;
  
  piVar1 = DAT_1400230a0;
  if (DAT_1400230a0 != (int *)0x0) {
    LOCK();
    *DAT_1400230a0 = *DAT_1400230a0 + -1;
    UNLOCK();
    if (*piVar1 == 0) {
      free(DAT_1400230a0);
      return;
    }
  }
  return;
}



void FUN_1400030f0(QString *param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4)

{
  undefined8 uVar1;
  QObject *pQVar2;
  QWidget *pQVar3;
  QGridLayout *this;
  undefined4 *puVar4;
  undefined **ppuVar5;
  undefined8 uVar6;
  QIcon *this_00;
  ulonglong uVar7;
  undefined8 local_98;
  char *local_90;
  Connection local_88 [8];
  Connection local_80 [8];
  code *local_78;
  undefined8 uStack_70;
  code *local_68;
  undefined8 uStack_60;
  
  uVar6 = 0;
  QMainWindow::QMainWindow();
  ppuVar5 = &PTR_FUN_14001efc0;
  *(undefined ***)param_1 = &PTR_FUN_14001efc0;
  *(undefined ***)(param_1 + 0x10) = &PTR_FUN_14001f178;
  pQVar2 = (QObject *)operator_new(0x68);
  FUN_140002840(pQVar2,ppuVar5,uVar6,param_4);
  *(QObject **)(param_1 + 0x28) = pQVar2;
  pQVar3 = (QWidget *)operator_new(0x58);
  FUN_140003b30(pQVar3);
  *(QWidget **)(param_1 + 0x30) = pQVar3;
  this = (QGridLayout *)operator_new(0x20);
  QGridLayout::QGridLayout(this,(QWidget *)0x0);
  *(QGridLayout **)(param_1 + 0x38) = this;
  pQVar3 = (QWidget *)operator_new(0x28);
  QWidget::QWidget(pQVar3,0,0);
  *(QWidget **)(param_1 + 0x40) = pQVar3;
  QWidget::setFixedSize((int)param_1,0x140);
  local_98 = 10;
  local_90 = "Snake Game";
  QString::fromUtf8((QString *)&local_68,&local_98);
  QWidget::setWindowTitle(param_1);
  if (local_68 != (code *)0x0) {
    LOCK();
    *(int *)local_68 = *(int *)local_68 + -1;
    UNLOCK();
    if (*(int *)local_68 == 0) {
      free(local_68);
    }
  }
  local_98 = 0x20;
  local_90 = "qrc:/icons/images/windowIcon.png";
  QString::fromUtf8((QString *)&local_68,&local_98);
  this_00 = (QIcon *)&local_78;
  QIcon::QIcon(this_00,(QString *)&local_68);
  QWidget::setWindowIcon((QIcon *)param_1);
  QIcon::~QIcon(this_00);
  if (local_68 != (code *)0x0) {
    LOCK();
    *(int *)local_68 = *(int *)local_68 + -1;
    UNLOCK();
    if (*(int *)local_68 == 0) {
      free(local_68);
    }
  }
  uStack_60 = 0;
  uVar6 = *(undefined8 *)(param_1 + 0x30);
  uStack_70 = 0;
  local_68 = FUN_140003c30;
  uVar1 = *(undefined8 *)(param_1 + 0x28);
  local_78 = FUN_140003e70;
  puVar4 = (undefined4 *)operator_new(0x20);
  *puVar4 = 1;
  *(code **)(puVar4 + 2) = FUN_1400063c0;
  *(code **)(puVar4 + 4) = local_68;
  *(undefined8 *)(puVar4 + 6) = uStack_60;
  QObject::connectImpl(local_88,uVar1,this_00,uVar6,(QString *)&local_68,puVar4,0,0,&DAT_14001e540);
  QMetaObject::Connection::~Connection(local_88);
  uStack_70 = 0;
  uVar6 = *(undefined8 *)(param_1 + 0x28);
  uStack_60 = 0;
  local_78 = FUN_140003d00;
  uVar1 = *(undefined8 *)(param_1 + 0x30);
  local_68 = FUN_140003ea0;
  puVar4 = (undefined4 *)operator_new(0x20);
  *(code **)(puVar4 + 2) = FUN_1400063c0;
  *puVar4 = 1;
  *(code **)(puVar4 + 4) = local_78;
  *(undefined8 *)(puVar4 + 6) = uStack_70;
  QObject::connectImpl(local_80,uVar6,(QString *)&local_68,uVar1,this_00,puVar4,0,0,&DAT_14001e540);
  QMetaObject::Connection::~Connection(local_80);
  uVar7 = (ulonglong)this_00 & 0xffffffff00000000;
  QGridLayout::addWidget(*(undefined8 *)(param_1 + 0x38),*(undefined8 *)(param_1 + 0x30),0,0,uVar7);
  QGridLayout::addWidget
            (*(undefined8 *)(param_1 + 0x38),*(undefined8 *)(param_1 + 0x28),1,0,
             uVar7 & 0xffffffff00000000);
  QWidget::setLayout(*(QLayout **)(param_1 + 0x40));
  QMainWindow::setCentralWidget((QWidget *)param_1);
  local_98 = 0xc;
  local_90 = "background: ";
  QString::fromUtf8((QString *)&local_68,&local_98);
  QString::append((QString *)&local_68);
  QWidget::setStyleSheet(param_1);
  if (local_68 != (code *)0x0) {
    LOCK();
    *(int *)local_68 = *(int *)local_68 + -1;
    UNLOCK();
    if (*(int *)local_68 == 0) {
      free(local_68);
    }
  }
  return;
}



undefined4 FUN_140003550(int param_1,char **param_2)

{
  undefined4 uVar1;
  undefined8 uVar2;
  int local_res8 [8];
  QApplication local_78 [16];
  undefined **local_68 [2];
  undefined **local_58;
  
  uVar2 = 0x60702;
  local_res8[0] = param_1;
  QApplication::QApplication(local_78,local_res8,param_2,0x60702);
  FUN_1400030f0((QString *)local_68,0,param_2,uVar2);
  QWidget::show();
  uVar1 = QApplication::exec();
  local_68[0] = &PTR_FUN_14001efc0;
  local_58 = &PTR_FUN_14001f178;
  QMainWindow::~QMainWindow((QMainWindow *)local_68);
  QApplication::~QApplication(local_78);
  return uVar1;
}



void FUN_140003620(undefined4 *param_1,undefined4 param_2,undefined4 param_3)

{
  *param_1 = param_2;
  param_1[1] = param_3;
  return;
}



undefined4 FUN_140003630(longlong param_1)

{
  return *(undefined4 *)(param_1 + 0x18);
}



undefined4 FUN_140003640(longlong param_1)

{
  return *(undefined4 *)(param_1 + 0x1c);
}



void FUN_140003650(longlong param_1,undefined4 param_2)

{
  *(undefined4 *)(param_1 + 0x1c) = param_2;
  return;
}



undefined4 FUN_140003660(undefined4 *param_1)

{
  return *param_1;
}



undefined4 FUN_140003670(longlong param_1)

{
  return *(undefined4 *)(param_1 + 4);
}



void FUN_140003680(undefined4 *param_1,undefined4 param_2)

{
  *param_1 = param_2;
  return;
}



void FUN_140003690(longlong param_1,undefined4 param_2)

{
  *(undefined4 *)(param_1 + 4) = param_2;
  return;
}



void FUN_1400036a0(longlong *param_1)

{
  int *piVar1;
  longlong lVar2;
  undefined8 *puVar3;
  longlong lVar4;
  int *piVar5;
  longlong lVar6;
  int iVar7;
  int iVar8;
  longlong lVar9;
  undefined8 *puVar10;
  
  iVar7 = 0;
  *param_1 = 0;
  param_1[1] = 0;
  param_1[2] = 0;
  *(undefined4 *)(param_1 + 3) = 4;
  do {
    piVar1 = (int *)operator_new(8);
    *piVar1 = iVar7;
    piVar1[1] = 0;
    piVar5 = (int *)*param_1;
    if (piVar5 == (int *)0x0) {
      if (param_1[2] != 0) {
LAB_14000371b:
        FUN_140005c60(param_1,1,1,(undefined8 *)0x0);
        puVar3 = (undefined8 *)param_1[1];
        lVar9 = param_1[2];
        piVar5 = (int *)*param_1;
        goto LAB_14000373f;
      }
LAB_1400037e4:
      FUN_140005c60(param_1,0,1,(undefined8 *)0x0);
      puVar3 = (undefined8 *)param_1[1];
      lVar9 = param_1[2];
LAB_140003801:
      if (0 < lVar9) {
        memmove(puVar3 + 1,puVar3,lVar9 << 3);
        lVar9 = param_1[2];
      }
      piVar5 = (int *)*param_1;
LAB_140003748:
      *puVar3 = piVar1;
      param_1[2] = lVar9 + 1;
      if (piVar5 != (int *)0x0) goto LAB_1400037c9;
LAB_14000375a:
      FUN_140005c60(param_1,0,0,(undefined8 *)0x0);
    }
    else {
      if (1 < *piVar5) {
        if (param_1[2] == 0) {
LAB_14000383d:
          if (1 < *piVar5) goto LAB_1400037e4;
          lVar2 = *param_1;
          if (lVar2 == 0) {
LAB_1400039a0:
            iVar8 = 0;
          }
          else {
            puVar10 = (undefined8 *)param_1[1];
            lVar6 = *(longlong *)(lVar2 + 8);
            lVar9 = param_1[2];
            lVar4 = (longlong)puVar10 - (lVar2 + 0x1fU & 0xfffffffffffffff0);
            lVar2 = lVar4 >> 3;
            puVar3 = puVar10;
            if (lVar9 < lVar6 - lVar2) goto LAB_140003801;
            if (lVar4 < 1) goto LAB_1400039a0;
            iVar8 = 0;
            if (SBORROW8(lVar9 * 3,lVar6 * 2) != lVar9 * 3 + lVar6 * -2 < 0) {
              lVar6 = 0;
              goto LAB_14000393c;
            }
          }
LAB_14000389a:
          FUN_140005c60(param_1,iVar8,1,(undefined8 *)0x0);
          puVar3 = (undefined8 *)param_1[1];
          lVar9 = param_1[2];
        }
        else {
LAB_140003710:
          if (1 < *piVar5) goto LAB_14000371b;
          piVar5 = (int *)*param_1;
          if (piVar5 == (int *)0x0) {
LAB_1400039d0:
            iVar8 = 1;
            goto LAB_14000389a;
          }
          puVar3 = (undefined8 *)param_1[1];
          lVar2 = (longlong)puVar3 - ((longlong)piVar5 + 0x1fU & 0xfffffffffffffff0);
          lVar9 = param_1[2];
          if (0 < lVar2) goto LAB_14000373f;
          lVar6 = *(longlong *)(piVar5 + 2);
          lVar2 = lVar2 >> 3;
          if (lVar6 - lVar2 <= lVar9) goto LAB_1400039d0;
          if (lVar6 <= lVar9 * 3) goto LAB_14000371b;
          iVar8 = 1;
          lVar6 = ((lVar6 - lVar9) + -1) / 2;
          if (lVar6 < 0) {
            lVar6 = 0;
          }
          lVar6 = lVar6 + 1;
          puVar10 = puVar3;
LAB_14000393c:
          puVar3 = puVar10 + (lVar6 - lVar2);
          if ((((lVar9 != 0) && (puVar3 != puVar10)) && (puVar10 != (undefined8 *)0x0)) &&
             (puVar3 != (undefined8 *)0x0)) {
            puVar3 = (undefined8 *)memmove(puVar3,puVar10,lVar9 << 3);
            lVar9 = param_1[2];
          }
          param_1[1] = (longlong)puVar3;
        }
        if (iVar8 == 0) goto LAB_140003801;
        piVar5 = (int *)*param_1;
LAB_14000373f:
        puVar3 = puVar3 + -1;
        param_1[1] = (longlong)puVar3;
        goto LAB_140003748;
      }
      lVar9 = param_1[2];
      puVar3 = (undefined8 *)param_1[1];
      if (lVar9 == 0) {
        puVar10 = (undefined8 *)((longlong)piVar5 + 0x1fU & 0xfffffffffffffff0);
        if (*(longlong *)(piVar5 + 2) == (longlong)puVar3 - (longlong)puVar10 >> 3) {
          if (puVar3 == puVar10) goto LAB_14000383d;
          goto LAB_1400037b3;
        }
        *puVar3 = piVar1;
        lVar9 = 1;
      }
      else {
        if (puVar3 == (undefined8 *)((longlong)piVar5 + 0x1fU & 0xfffffffffffffff0))
        goto LAB_140003710;
LAB_1400037b3:
        puVar3[-1] = piVar1;
        lVar9 = lVar9 + 1;
        param_1[1] = (longlong)(puVar3 + -1);
      }
      param_1[2] = lVar9;
LAB_1400037c9:
      if (1 < *piVar5) goto LAB_14000375a;
    }
    iVar7 = iVar7 + 1;
    if ((int)param_1[3] <= iVar7) {
      *(undefined4 *)((longlong)param_1 + 0x1c) = 3;
      return;
    }
  } while( true );
}



void FUN_140003a00(longlong param_1)

{
  longlong lVar1;
  QPainter local_40 [8];
  undefined8 local_38;
  int local_30;
  int local_2c;
  
  QPainter::QPainter(local_40);
  QPainter::begin((QPaintDevice *)local_40);
  local_38 = 0;
  lVar1 = *(longlong *)(param_1 + 0x20);
  local_2c = (*(int *)(lVar1 + 0x20) - *(int *)(lVar1 + 0x18)) + -1;
  local_30 = (*(int *)(lVar1 + 0x1c) - *(int *)(lVar1 + 0x14)) + -1;
  QPainter::setFont((QFont *)local_40);
  QPainter::drawText((QRect *)local_40,(int)&local_38,(QString *)0x81,(QRect *)(param_1 + 0x28));
  QPainter::drawText((QRect *)local_40,(int)&local_38,(QString *)0x82,(QRect *)(param_1 + 0x40));
  QPainter::end();
  QPainter::~QPainter(local_40);
  return;
}



void FUN_140003ae0(void)

{
                    // WARNING: Could not recover jumptable at 0x000140003ae7. Too many branches
                    // WARNING: Treating indirect jump as call
  QFont::~QFont((QFont *)&DAT_1400230c0);
  return;
}



void FUN_140003af0(void)

{
                    // WARNING: Could not recover jumptable at 0x000140003af7. Too many branches
                    // WARNING: Treating indirect jump as call
  QFont::~QFont((QFont *)&DAT_1400230d0);
  return;
}



void FUN_140003b00(void)

{
                    // WARNING: Could not recover jumptable at 0x000140003b07. Too many branches
                    // WARNING: Treating indirect jump as call
  QFont::~QFont((QFont *)&DAT_1400230e0);
  return;
}



void FUN_140003b10(void)

{
                    // WARNING: Could not recover jumptable at 0x000140003b17. Too many branches
                    // WARNING: Treating indirect jump as call
  QFont::~QFont((QFont *)&DAT_1400230f0);
  return;
}



void FUN_140003b20(void)

{
                    // WARNING: Could not recover jumptable at 0x000140003b27. Too many branches
                    // WARNING: Treating indirect jump as call
  QFont::~QFont((QFont *)&DAT_140023100);
  return;
}



void FUN_140003b30(QWidget *param_1)

{
  char *local_38;
  undefined8 local_30;
  
  QWidget::QWidget(param_1,0,0);
  *(undefined8 *)(param_1 + 0x28) = 0;
  *(undefined ***)param_1 = &PTR_LAB_14001f3d0;
  *(undefined ***)(param_1 + 0x10) = &PTR_FUN_14001f580;
  *(undefined8 *)(param_1 + 0x30) = 0;
  *(undefined8 *)(param_1 + 0x38) = 0;
  *(undefined8 *)(param_1 + 0x40) = 0;
  *(undefined8 *)(param_1 + 0x48) = 0;
  *(undefined8 *)(param_1 + 0x50) = 0;
  QWidget::setFixedSize((int)param_1,300);
  local_30 = 8;
  local_38 = "Score: 0";
  QString::assign(param_1 + 0x28,&local_38);
  local_30 = 0xd;
  local_38 = "Pause - SPACE";
  QString::assign(param_1 + 0x40,&local_38);
  return;
}



void FUN_140003c30(longlong param_1,undefined8 *param_2)

{
  int *_Memory;
  undefined8 uVar1;
  undefined8 uVar2;
  char *local_48;
  undefined8 local_40;
  int *local_38;
  undefined8 local_30;
  undefined8 local_28;
  
  local_38 = (int *)*param_2;
  local_30 = param_2[1];
  local_28 = param_2[2];
  if (local_38 != (int *)0x0) {
    LOCK();
    *local_38 = *local_38 + 1;
    UNLOCK();
  }
  local_40 = 8;
  local_48 = " - SPACE";
  QString::append(&local_38,&local_48);
  _Memory = *(int **)(param_1 + 0x40);
  *(int **)(param_1 + 0x40) = local_38;
  uVar1 = *(undefined8 *)(param_1 + 0x48);
  *(undefined8 *)(param_1 + 0x48) = local_30;
  uVar2 = *(undefined8 *)(param_1 + 0x50);
  *(undefined8 *)(param_1 + 0x50) = local_28;
  local_38 = _Memory;
  local_30 = uVar1;
  local_28 = uVar2;
  if (_Memory != (int *)0x0) {
    LOCK();
    *_Memory = *_Memory + -1;
    UNLOCK();
    if (*_Memory == 0) {
      free(_Memory);
    }
  }
                    // WARNING: Could not recover jumptable at 0x000140003cd8. Too many branches
                    // WARNING: Treating indirect jump as call
  QWidget::repaint();
  return;
}



void FUN_140003d00(longlong param_1)

{
  int *_Memory;
  undefined8 uVar1;
  undefined8 uVar2;
  undefined8 local_48;
  char *local_40;
  int *local_38;
  undefined8 local_30;
  undefined8 local_28;
  
  local_40 = "Score: ";
  local_48 = 7;
  QString::fromUtf8((QString *)&local_38,&local_48);
  QString::append((QString *)&local_38);
  _Memory = *(int **)(param_1 + 0x28);
  *(int **)(param_1 + 0x28) = local_38;
  uVar1 = *(undefined8 *)(param_1 + 0x30);
  *(undefined8 *)(param_1 + 0x30) = local_30;
  uVar2 = *(undefined8 *)(param_1 + 0x38);
  *(undefined8 *)(param_1 + 0x38) = local_28;
  local_38 = _Memory;
  local_30 = uVar1;
  local_28 = uVar2;
  if (_Memory != (int *)0x0) {
    LOCK();
    *_Memory = *_Memory + -1;
    UNLOCK();
    if (*_Memory == 0) {
      free(_Memory);
    }
  }
                    // WARNING: Could not recover jumptable at 0x000140003d98. Too many branches
                    // WARNING: Treating indirect jump as call
  QWidget::repaint();
  return;
}



void FUN_140003dc0(void)

{
  qUnregisterResourceData(3,"","","");
  return;
}



undefined8 FUN_140003df0(void)

{
  qRegisterResourceData(3,"","","");
  return 1;
}



undefined8 FUN_140003e20(void)

{
  qUnregisterResourceData(3,"","","");
  return 1;
}



undefined * FUN_140003e50(longlong param_1)

{
  undefined *puVar1;
  
  if (*(longlong *)(*(longlong *)(param_1 + 8) + 0x38) != 0) {
                    // WARNING: Could not recover jumptable at 0x000140003e5b. Too many branches
                    // WARNING: Treating indirect jump as call
    puVar1 = (undefined *)QObjectData::dynamicMetaObject();
    return puVar1;
  }
  return &DAT_14001e540;
}



void FUN_140003e70(QObject *param_1,undefined8 param_2)

{
  void *local_18;
  undefined8 local_10;
  
  local_18 = (void *)0x0;
  local_10 = param_2;
  QMetaObject::activate(param_1,(QMetaObject *)&DAT_14001e540,0,&local_18);
  return;
}



void FUN_140003ea0(QObject *param_1,undefined8 param_2)

{
  void *local_18;
  undefined8 local_10;
  
  local_18 = (void *)0x0;
  local_10 = param_2;
  QMetaObject::activate(param_1,(QMetaObject *)&DAT_14001e540,1,&local_18);
  return;
}



void FUN_140003ed0(QObject *param_1,int param_2,int param_3,undefined8 *param_4)

{
  longlong *plVar1;
  undefined8 *puVar2;
  void *local_48;
  int **local_40;
  int *local_38;
  undefined8 local_30;
  undefined8 local_28;
  
  if (param_2 == 0) {
    if (param_3 == 1) {
      puVar2 = (undefined8 *)param_4[1];
      local_38 = (int *)*puVar2;
      local_30 = puVar2[1];
      local_28 = puVar2[2];
      if (local_38 != (int *)0x0) {
        LOCK();
        *local_38 = *local_38 + 1;
        UNLOCK();
      }
      local_40 = &local_38;
      local_48 = (void *)0x0;
      QMetaObject::activate(param_1,(QMetaObject *)&DAT_14001e540,1,&local_48);
    }
    else {
      if (param_3 == 2) {
        FUN_140002d00(param_1);
        return;
      }
      if (param_3 != 0) {
        return;
      }
      puVar2 = (undefined8 *)param_4[1];
      local_38 = (int *)*puVar2;
      local_30 = puVar2[1];
      local_28 = puVar2[2];
      if (local_38 != (int *)0x0) {
        LOCK();
        *local_38 = *local_38 + 1;
        UNLOCK();
      }
      local_40 = &local_38;
      local_48 = (void *)0x0;
      QMetaObject::activate(param_1,(QMetaObject *)&DAT_14001e540,0,&local_48);
    }
    if (local_38 != (int *)0x0) {
      LOCK();
      *local_38 = *local_38 + -1;
      UNLOCK();
      if (*local_38 == 0) {
        free(local_38);
      }
    }
  }
  else if (param_2 == 5) {
    plVar1 = (longlong *)param_4[1];
    if ((code *)*plVar1 == FUN_140003e70) {
      if (plVar1[1] == 0) {
        *(undefined4 *)*param_4 = 0;
      }
    }
    else if (((code *)*plVar1 == FUN_140003ea0) && (plVar1[1] == 0)) {
      *(undefined4 *)*param_4 = 1;
    }
  }
  return;
}



char * FUN_140004060(char *param_1,char *param_2)

{
  int iVar1;
  char *pcVar2;
  
  if (param_2 == (char *)0x0) {
    param_1 = (char *)0x0;
  }
  else {
    iVar1 = strcmp(param_2,"GameField");
    if (iVar1 != 0) {
                    // WARNING: Could not recover jumptable at 0x0001400040a6. Too many branches
                    // WARNING: Treating indirect jump as call
      pcVar2 = (char *)QWidget::qt_metacast(param_1);
      return pcVar2;
    }
  }
  return param_1;
}



ulonglong FUN_1400040c0(QObject *param_1,int param_2,undefined8 param_3,undefined8 *param_4)

{
  int iVar1;
  ulonglong uVar2;
  
  uVar2 = QWidget::qt_metacall();
  iVar1 = (int)uVar2;
  if (-1 < iVar1) {
    if (param_2 == 0) {
      if (iVar1 < 3) {
        FUN_140003ed0(param_1,0,iVar1,param_4);
        uVar2 = uVar2 & 0xffffffff;
      }
    }
    else {
      if (param_2 != 7) {
        return uVar2;
      }
      if (iVar1 < 3) {
        *(undefined8 *)*param_4 = 0;
      }
    }
    uVar2 = (ulonglong)((int)uVar2 - 3);
  }
  return uVar2;
}



void FUN_140004130(void)

{
  return;
}



undefined * FUN_140004140(longlong param_1)

{
  undefined *puVar1;
  
  if (*(longlong *)(*(longlong *)(param_1 + 8) + 0x38) != 0) {
                    // WARNING: Could not recover jumptable at 0x00014000414b. Too many branches
                    // WARNING: Treating indirect jump as call
    puVar1 = (undefined *)QObjectData::dynamicMetaObject();
    return puVar1;
  }
  return &DAT_14001e700;
}



char * FUN_140004160(char *param_1,char *param_2)

{
  int iVar1;
  char *pcVar2;
  
  if (param_2 == (char *)0x0) {
    param_1 = (char *)0x0;
  }
  else {
    iVar1 = strcmp(param_2,"GameWindow");
    if (iVar1 != 0) {
                    // WARNING: Could not recover jumptable at 0x0001400041a6. Too many branches
                    // WARNING: Treating indirect jump as call
      pcVar2 = (char *)QMainWindow::qt_metacast(param_1);
      return pcVar2;
    }
  }
  return param_1;
}



void QMainWindow::qt_metacall(void)

{
                    // WARNING: Could not recover jumptable at 0x0001400041c0. Too many branches
                    // WARNING: Treating indirect jump as call
  qt_metacall();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void qUnregisterResourceData(int param_1,uchar *param_2,uchar *param_3,uchar *param_4)

{
                    // WARNING: Could not recover jumptable at 0x000140004668. Too many branches
                    // WARNING: Treating indirect jump as call
  qUnregisterResourceData(param_1,param_2,param_3,param_4);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void qRegisterResourceData(int param_1,uchar *param_2,uchar *param_3,uchar *param_4)

{
                    // WARNING: Could not recover jumptable at 0x000140004670. Too many branches
                    // WARNING: Treating indirect jump as call
  qRegisterResourceData(param_1,param_2,param_3,param_4);
  return;
}



void FUN_140004680(void)

{
  code *pcVar1;
  
  pcVar1 = *(code **)PTR_DAT_140007010;
  while (pcVar1 != (code *)0x0) {
    (*pcVar1)();
    pcVar1 = *(code **)(PTR_DAT_140007010 + 8);
    PTR_DAT_140007010 = PTR_DAT_140007010 + 8;
  }
  return;
}



void FUN_1400046c0(void)

{
  ulonglong uVar1;
  int iVar2;
  undefined8 *puVar4;
  ulonglong uVar3;
  
  uVar1 = 0;
  do {
    uVar3 = uVar1;
    iVar2 = (int)uVar3;
    uVar1 = (ulonglong)(iVar2 + 1);
  } while ((&DAT_140006d60)[iVar2 + 1] != 0);
  if (iVar2 != 0) {
    puVar4 = &DAT_140006d60 + uVar3;
    do {
      (*(code *)*puVar4)();
      puVar4 = puVar4 + -1;
    } while (puVar4 != (undefined8 *)(&UNK_140006d58 + (uVar3 - (iVar2 - 1)) * 8));
  }
  FUN_1400014f0(FUN_140004680);
  return;
}



void FUN_140004730(void)

{
  if (DAT_140023110 != 0) {
    return;
  }
  DAT_140023110 = 1;
  FUN_1400046c0();
  return;
}



undefined8 FUN_140004750(void)

{
  return 0;
}



undefined8 tls_callback_1(undefined8 param_1,int param_2)

{
  if ((param_2 != 3) && (param_2 != 0)) {
    return 1;
  }
  FUN_1400052e0(param_1,param_2);
  return 1;
}



// WARNING: Removing unreachable block (ram,0x0001400047d3)
// WARNING: Removing unreachable block (ram,0x0001400047db)
// WARNING: Removing unreachable block (ram,0x0001400047dd)
// WARNING: Removing unreachable block (ram,0x0001400047e6)

undefined8 tls_callback_0(undefined8 param_1,int param_2)

{
  if (DAT_140007040 != 2) {
    DAT_140007040 = 2;
  }
  if ((param_2 != 2) && (param_2 == 1)) {
    FUN_1400052e0(param_1,1);
    return 1;
  }
  return 1;
}



undefined8 FUN_140004810(void)

{
  return 0;
}



undefined8 FUN_140004820(undefined4 *param_1)

{
  undefined8 uVar1;
  undefined8 uVar2;
  undefined8 uVar3;
  undefined8 uVar4;
  FILE *_File;
  char *pcVar5;
  
  switch(*param_1) {
  default:
    pcVar5 = "Unknown error";
    break;
  case 1:
    pcVar5 = "Argument domain error (DOMAIN)";
    break;
  case 2:
    pcVar5 = "Argument singularity (SIGN)";
    break;
  case 3:
    pcVar5 = "Overflow range error (OVERFLOW)";
    break;
  case 4:
    pcVar5 = "The result is too small to be represented (UNDERFLOW)";
    break;
  case 5:
    pcVar5 = "Total loss of significance (TLOSS)";
    break;
  case 6:
    pcVar5 = "Partial loss of significance (PLOSS)";
  }
  uVar4 = *(undefined8 *)(param_1 + 2);
  uVar1 = *(undefined8 *)(param_1 + 8);
  uVar2 = *(undefined8 *)(param_1 + 6);
  uVar3 = *(undefined8 *)(param_1 + 4);
  _File = FUN_140005a70(2);
  fprintf(_File,"_matherr(): %s in %s(%g, %g)  (retval=%g)\n",pcVar5,uVar4,uVar3,uVar2,uVar1);
  return 0;
}



void FUN_140004920(void)

{
  return;
}



void FUN_140004930(char *param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4)

{
  FILE *pFVar1;
  undefined8 local_res10;
  undefined8 local_res18;
  undefined8 local_res20;
  
  local_res10 = param_2;
  local_res18 = param_3;
  local_res20 = param_4;
  pFVar1 = FUN_140005a70(2);
  fwrite("Mingw-w64 runtime failure:\n",1,0x1b,pFVar1);
  pFVar1 = FUN_140005a70(2);
  vfprintf(pFVar1,param_1,(va_list)&local_res10);
                    // WARNING: Subroutine does not return
  abort();
}



// WARNING: Removing unreachable block (ram,0x000140004c38)
// WARNING: Removing unreachable block (ram,0x000140004c40)
// WARNING: Removing unreachable block (ram,0x000140004c6b)
// WARNING: Removing unreachable block (ram,0x000140004e82)
// WARNING: Removing unreachable block (ram,0x000140004e8b)
// WARNING: Removing unreachable block (ram,0x000140004eb0)
// WARNING: Removing unreachable block (ram,0x000140004ed5)

void FUN_1400049a0(byte *param_1,byte *param_2,undefined8 param_3,PDWORD param_4)

{
  undefined8 uVar1;
  byte bVar2;
  ushort uVar3;
  LPVOID lpAddress;
  uint uVar4;
  BOOL BVar5;
  DWORD DVar6;
  ulonglong *puVar7;
  longlong lVar8;
  undefined4 *puVar9;
  IMAGE_DOS_HEADER *pIVar10;
  SIZE_T SVar11;
  DWORD *pDVar12;
  ulonglong uVar13;
  int iVar14;
  undefined4 uVar15;
  char *pcVar16;
  uint uVar17;
  uint uVar18;
  uint *puVar19;
  longlong lVar20;
  ulonglong in_R8;
  ulonglong uVar21;
  char *pcVar22;
  PDWORD pDVar23;
  undefined8 in_XMM3_Qa;
  undefined8 auStack_160 [5];
  undefined4 auStack_138 [2];
  ulonglong auStack_130 [10];
  longlong alStack_e0 [2];
  undefined1 auStack_d0 [8];
  longlong alStack_c8 [3];
  longlong lStack_b0;
  byte *pbStack_a8;
  longlong lStack_a0;
  _MEMORY_BASIC_INFORMATION local_58;
  
  lVar20 = (longlong)DAT_140023164;
  uVar21 = in_R8;
  if (DAT_140023164 < 1) goto LAB_140004b30;
  iVar14 = 0;
  puVar7 = (ulonglong *)(DAT_140023168 + 0x18);
  do {
    if (((byte *)*puVar7 <= param_1) &&
       (uVar21 = (ulonglong)*(uint *)(puVar7[1] + 8), param_1 < (byte *)*puVar7 + uVar21))
    goto LAB_140004a75;
    iVar14 = iVar14 + 1;
    puVar7 = puVar7 + 5;
  } while (iVar14 != DAT_140023164);
  while (lVar8 = FUN_140005500((longlong)param_1), lVar8 != 0) {
    lVar20 = lVar20 * 0x28;
    puVar9 = (undefined4 *)(DAT_140023168 + lVar20);
    *(longlong *)(puVar9 + 8) = lVar8;
    *puVar9 = 0;
    pIVar10 = FUN_140005640();
    uVar18 = *(uint *)(lVar8 + 0xc);
    *(char **)(DAT_140023168 + lVar20 + 0x18) = pIVar10->e_magic + uVar18;
    SVar11 = VirtualQuery(pIVar10->e_magic + uVar18,&local_58,0x30);
    if (SVar11 == 0) {
      uVar21 = *(ulonglong *)(DAT_140023168 + lVar20 + 0x18);
      FUN_140004930("  VirtualQuery failed for %d bytes at address %p",
                    (ulonglong)*(uint *)(lVar8 + 8),uVar21,param_4);
      break;
    }
    if (((local_58.Protect - 0x40 & 0xffffffbf) == 0) || ((local_58.Protect - 4 & 0xfffffffb) == 0))
    {
LAB_140004a6e:
      DAT_140023164 = DAT_140023164 + 1;
LAB_140004a75:
      uVar18 = (uint)in_R8;
      if (uVar18 < 8) {
        if ((in_R8 & 4) == 0) {
          if ((uVar18 != 0) && (*param_1 = *param_2, (in_R8 & 2) != 0)) {
            *(undefined2 *)(param_1 + ((in_R8 & 0xffffffff) - 2)) =
                 *(undefined2 *)(param_2 + ((in_R8 & 0xffffffff) - 2));
          }
        }
        else {
          *(undefined4 *)param_1 = *(undefined4 *)param_2;
          *(undefined4 *)(param_1 + ((in_R8 & 0xffffffff) - 4)) =
               *(undefined4 *)(param_2 + ((in_R8 & 0xffffffff) - 4));
        }
      }
      else {
        *(undefined8 *)(param_1 + ((in_R8 & 0xffffffff) - 8)) =
             *(undefined8 *)(param_2 + ((in_R8 & 0xffffffff) - 8));
        if (7 < uVar18 - 1) {
          uVar17 = 0;
          do {
            uVar4 = uVar17 + 8;
            *(undefined8 *)(param_1 + uVar17) = *(undefined8 *)(param_2 + uVar17);
            uVar17 = uVar4;
          } while (uVar4 < (uVar18 - 1 & 0xfffffff8));
          return;
        }
      }
      return;
    }
    uVar21 = 4;
    if (local_58.Protect != 2) {
      uVar21 = 0x40;
    }
    param_4 = (PDWORD)(DAT_140023168 + lVar20);
    *(PVOID *)(param_4 + 2) = local_58.BaseAddress;
    *(SIZE_T *)(param_4 + 4) = local_58.RegionSize;
    BVar5 = VirtualProtect(local_58.BaseAddress,local_58.RegionSize,(DWORD)uVar21,param_4);
    if (BVar5 != 0) goto LAB_140004a6e;
    DVar6 = GetLastError();
    FUN_140004930("  VirtualProtect failed with code 0x%x",(ulonglong)DVar6,uVar21,param_4);
LAB_140004b30:
    lVar20 = 0;
  }
  FUN_140004930("Address %p has no image-section",param_1,uVar21,param_4);
  if (DAT_140023160 == 0) {
    DAT_140023160 = 1;
    auStack_130[5] = 0x140004be2;
    lStack_b0 = lVar20;
    pbStack_a8 = param_1;
    lStack_a0 = lVar8;
    FUN_140005580();
    auStack_130[5] = 0x140004bf9;
    uVar21 = FUN_1400059d0();
    DAT_140023164 = 0;
    lVar20 = -uVar21;
    DAT_140023168 = auStack_d0 + lVar20;
    puVar19 = &DAT_14001f84c;
LAB_140004cbb:
    do {
      uVar18 = puVar19[2];
      uVar21 = (ulonglong)uVar18 & 0xff;
      pcVar22 = IMAGE_DOS_HEADER_140000000.e_magic + puVar19[1];
      pcVar16 = IMAGE_DOS_HEADER_140000000.e_magic + *puVar19;
      uVar17 = (uint)uVar21;
      pDVar23 = *(PDWORD *)pcVar16;
      if (uVar17 == 0x10) {
        uVar3 = *(ushort *)pcVar22;
        uVar13 = (ulonglong)uVar3;
        if ((short)uVar3 < 0) {
          uVar13 = (ulonglong)uVar3 | 0xffffffffffff0000;
        }
        alStack_c8[0] = (uVar13 - (longlong)pcVar16) + (longlong)pDVar23;
        if ((uVar18 & 0xc0) == 0) goto LAB_140004de0;
LAB_140004e6c:
        *(undefined8 *)((longlong)auStack_130 + lVar20 + 0x28) = 0x140004e7d;
        FUN_1400049a0((byte *)pcVar22,(byte *)alStack_c8,param_3,pDVar23);
        goto LAB_140004cb2;
      }
      if (uVar17 < 0x11) {
        if (uVar17 == 8) {
          bVar2 = *pcVar22;
          uVar13 = (ulonglong)bVar2;
          if ((char)bVar2 < '\0') {
            uVar13 = (ulonglong)bVar2 | 0xffffffffffffff00;
          }
          alStack_c8[0] = (uVar13 - (longlong)pcVar16) + (longlong)pDVar23;
          if ((uVar18 & 0xc0) == 0) goto LAB_140004de0;
LAB_140004dc5:
          *(undefined8 *)((longlong)auStack_130 + lVar20 + 0x28) = 0x140004dd6;
          FUN_1400049a0((byte *)pcVar22,(byte *)alStack_c8,param_3,pDVar23);
          goto LAB_140004cb2;
        }
LAB_140004eda:
        alStack_c8[0] = 0;
        *(undefined8 *)((longlong)auStack_130 + lVar20 + 0x28) = 0x140004eee;
        lVar8 = FUN_140004930("  Unknown pseudo relocation bit size %d.\n",uVar21,(ulonglong)uVar18,
                              pDVar23);
LAB_140004eee:
        *(longlong *)((longlong)alStack_e0 + lVar20) = lVar8;
        *(undefined8 *)((longlong)auStack_130 + lVar20 + 0x28) = 0x140004f02;
        FUN_140004930("%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p.\n"
                      ,uVar21,pcVar22,pDVar23);
        uVar15 = 0x4001e9e0;
        *(undefined8 *)((longlong)auStack_130 + lVar20 + 0x28) = 0x140004f0e;
        FUN_140004930("  Unknown pseudo relocation protocol version %d.\n",uVar21,pcVar22,pDVar23);
        if (DAT_140023170 != (code *)0x0) {
          uVar1 = *(undefined8 *)((longlong)alStack_e0 + lVar20 + 8);
          *(undefined4 *)((longlong)auStack_138 + lVar20) = uVar15;
          *(ulonglong *)((longlong)auStack_130 + lVar20) = uVar21;
          *(undefined8 *)((longlong)auStack_130 + lVar20 + 8) = param_3;
          *(undefined8 *)((longlong)auStack_130 + lVar20 + 0x10) = in_XMM3_Qa;
          *(undefined8 *)((longlong)auStack_130 + lVar20 + 0x18) = uVar1;
          *(undefined8 *)((longlong)auStack_160 + lVar20) = 0x140004f4b;
          (*DAT_140023170)((longlong)auStack_138 + lVar20);
        }
        return;
      }
      if (uVar17 == 0x20) {
        uVar4 = *(uint *)pcVar22;
        uVar13 = (ulonglong)uVar4 | 0xffffffff00000000;
        if (-1 < (int)uVar4) {
          uVar13 = (ulonglong)uVar4;
        }
        alStack_c8[0] = (uVar13 - (longlong)pcVar16) + (longlong)pDVar23;
        if ((uVar18 & 0xc0) == 0) {
LAB_140004de0:
          lVar8 = alStack_c8[0];
          if ((alStack_c8[0] < -1L << ((byte)uVar18 - 1 & 0x3f)) ||
             (1L << ((byte)uVar18 & 0x3f) <= alStack_c8[0])) goto LAB_140004eee;
          if (uVar17 == 0x10) goto LAB_140004e6c;
          if (uVar17 < 0x11) {
            if (uVar17 == 8) goto LAB_140004dc5;
          }
          else {
            if (uVar17 == 0x20) goto LAB_140004ca1;
            if (uVar17 == 0x40) goto LAB_140004d09;
          }
        }
        else {
LAB_140004ca1:
          *(undefined8 *)((longlong)auStack_130 + lVar20 + 0x28) = 0x140004cb2;
          FUN_1400049a0((byte *)pcVar22,(byte *)alStack_c8,param_3,pDVar23);
        }
LAB_140004cb2:
        puVar19 = puVar19 + 3;
        if (&DAT_14001f8a0 <= puVar19) break;
        goto LAB_140004cbb;
      }
      if (uVar17 != 0x40) goto LAB_140004eda;
      alStack_c8[0] = (*(longlong *)pcVar22 - (longlong)pcVar16) + (longlong)pDVar23;
      if ((uVar18 & 0xc0) == 0) goto LAB_140004de0;
LAB_140004d09:
      *(undefined8 *)((longlong)auStack_130 + lVar20 + 0x28) = 0x140004d1a;
      FUN_1400049a0((byte *)pcVar22,(byte *)alStack_c8,param_3,pDVar23);
      puVar19 = puVar19 + 3;
    } while (puVar19 <= &UNK_14001f89f);
    if (0 < DAT_140023164) {
      lVar8 = 0;
      iVar14 = 0;
      do {
        pDVar12 = (DWORD *)(DAT_140023168 + lVar8);
        DVar6 = *pDVar12;
        if (DVar6 != 0) {
          SVar11 = *(SIZE_T *)(pDVar12 + 4);
          lpAddress = *(LPVOID *)(pDVar12 + 2);
          *(undefined8 *)((longlong)auStack_130 + lVar20 + 0x28) = 0x140004d5f;
          VirtualProtect(lpAddress,SVar11,DVar6,(PDWORD)alStack_c8);
        }
        iVar14 = iVar14 + 1;
        lVar8 = lVar8 + 0x28;
      } while (iVar14 < DAT_140023164);
    }
  }
  return;
}



// WARNING: Removing unreachable block (ram,0x000140004c38)
// WARNING: Removing unreachable block (ram,0x000140004c40)
// WARNING: Removing unreachable block (ram,0x000140004c6b)
// WARNING: Removing unreachable block (ram,0x000140004e82)
// WARNING: Removing unreachable block (ram,0x000140004e8b)
// WARNING: Removing unreachable block (ram,0x000140004eb0)
// WARNING: Removing unreachable block (ram,0x000140004ed5)

void FUN_140004ba0(undefined8 param_1,undefined8 param_2,undefined8 param_3,PDWORD param_4)

{
  undefined8 uVar1;
  byte bVar2;
  ushort uVar3;
  uint uVar4;
  uint uVar5;
  DWORD flNewProtect;
  SIZE_T dwSize;
  LPVOID lpAddress;
  longlong lVar6;
  ulonglong uVar7;
  DWORD *pDVar8;
  ulonglong uVar9;
  undefined4 uVar10;
  char *pcVar11;
  uint uVar12;
  uint *puVar13;
  longlong lVar14;
  int iVar15;
  char *pcVar16;
  PDWORD pDVar17;
  undefined8 in_XMM3_Qa;
  undefined8 auStack_e8 [5];
  undefined4 auStack_c0 [2];
  ulonglong auStack_b8 [10];
  longlong alStack_68 [2];
  undefined1 auStack_58 [8];
  longlong local_50 [2];
  
  if (DAT_140023160 == 0) {
    DAT_140023160 = 1;
    auStack_b8[5] = 0x140004be2;
    FUN_140005580();
    auStack_b8[5] = 0x140004bf9;
    uVar7 = FUN_1400059d0();
    DAT_140023164 = 0;
    lVar6 = -uVar7;
    DAT_140023168 = auStack_58 + lVar6;
    puVar13 = &DAT_14001f84c;
LAB_140004cbb:
    do {
      uVar5 = puVar13[2];
      uVar7 = (ulonglong)uVar5 & 0xff;
      pcVar16 = IMAGE_DOS_HEADER_140000000.e_magic + puVar13[1];
      pcVar11 = IMAGE_DOS_HEADER_140000000.e_magic + *puVar13;
      uVar12 = (uint)uVar7;
      pDVar17 = *(PDWORD *)pcVar11;
      if (uVar12 == 0x10) {
        uVar3 = *(ushort *)pcVar16;
        uVar9 = (ulonglong)uVar3;
        if ((short)uVar3 < 0) {
          uVar9 = (ulonglong)uVar3 | 0xffffffffffff0000;
        }
        local_50[0] = (uVar9 - (longlong)pcVar11) + (longlong)pDVar17;
        if ((uVar5 & 0xc0) == 0) goto LAB_140004de0;
LAB_140004e6c:
        *(undefined8 *)((longlong)auStack_b8 + lVar6 + 0x28) = 0x140004e7d;
        FUN_1400049a0((byte *)pcVar16,(byte *)local_50,param_3,pDVar17);
        goto LAB_140004cb2;
      }
      if (uVar12 < 0x11) {
        if (uVar12 == 8) {
          bVar2 = *pcVar16;
          uVar9 = (ulonglong)bVar2;
          if ((char)bVar2 < '\0') {
            uVar9 = (ulonglong)bVar2 | 0xffffffffffffff00;
          }
          local_50[0] = (uVar9 - (longlong)pcVar11) + (longlong)pDVar17;
          if ((uVar5 & 0xc0) == 0) goto LAB_140004de0;
LAB_140004dc5:
          *(undefined8 *)((longlong)auStack_b8 + lVar6 + 0x28) = 0x140004dd6;
          FUN_1400049a0((byte *)pcVar16,(byte *)local_50,param_3,pDVar17);
          goto LAB_140004cb2;
        }
LAB_140004eda:
        local_50[0] = 0;
        *(undefined8 *)((longlong)auStack_b8 + lVar6 + 0x28) = 0x140004eee;
        lVar14 = FUN_140004930("  Unknown pseudo relocation bit size %d.\n",uVar7,(ulonglong)uVar5,
                               pDVar17);
LAB_140004eee:
        *(longlong *)((longlong)alStack_68 + lVar6) = lVar14;
        *(undefined8 *)((longlong)auStack_b8 + lVar6 + 0x28) = 0x140004f02;
        FUN_140004930("%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p.\n"
                      ,uVar7,pcVar16,pDVar17);
        uVar10 = 0x4001e9e0;
        *(undefined8 *)((longlong)auStack_b8 + lVar6 + 0x28) = 0x140004f0e;
        FUN_140004930("  Unknown pseudo relocation protocol version %d.\n",uVar7,pcVar16,pDVar17);
        if (DAT_140023170 != (code *)0x0) {
          uVar1 = *(undefined8 *)((longlong)alStack_68 + lVar6 + 8);
          *(undefined4 *)((longlong)auStack_c0 + lVar6) = uVar10;
          *(ulonglong *)((longlong)auStack_b8 + lVar6) = uVar7;
          *(undefined8 *)((longlong)auStack_b8 + lVar6 + 8) = param_3;
          *(undefined8 *)((longlong)auStack_b8 + lVar6 + 0x10) = in_XMM3_Qa;
          *(undefined8 *)((longlong)auStack_b8 + lVar6 + 0x18) = uVar1;
          *(undefined8 *)((longlong)auStack_e8 + lVar6) = 0x140004f4b;
          (*DAT_140023170)((longlong)auStack_c0 + lVar6);
        }
        return;
      }
      if (uVar12 == 0x20) {
        uVar4 = *(uint *)pcVar16;
        uVar9 = (ulonglong)uVar4 | 0xffffffff00000000;
        if (-1 < (int)uVar4) {
          uVar9 = (ulonglong)uVar4;
        }
        local_50[0] = (uVar9 - (longlong)pcVar11) + (longlong)pDVar17;
        if ((uVar5 & 0xc0) == 0) {
LAB_140004de0:
          lVar14 = local_50[0];
          if ((local_50[0] < -1L << ((byte)uVar5 - 1 & 0x3f)) ||
             (1L << ((byte)uVar5 & 0x3f) <= local_50[0])) goto LAB_140004eee;
          if (uVar12 == 0x10) goto LAB_140004e6c;
          if (uVar12 < 0x11) {
            if (uVar12 == 8) goto LAB_140004dc5;
          }
          else {
            if (uVar12 == 0x20) goto LAB_140004ca1;
            if (uVar12 == 0x40) goto LAB_140004d09;
          }
        }
        else {
LAB_140004ca1:
          *(undefined8 *)((longlong)auStack_b8 + lVar6 + 0x28) = 0x140004cb2;
          FUN_1400049a0((byte *)pcVar16,(byte *)local_50,param_3,pDVar17);
        }
LAB_140004cb2:
        puVar13 = puVar13 + 3;
        if (&DAT_14001f8a0 <= puVar13) break;
        goto LAB_140004cbb;
      }
      if (uVar12 != 0x40) goto LAB_140004eda;
      local_50[0] = (*(longlong *)pcVar16 - (longlong)pcVar11) + (longlong)pDVar17;
      if ((uVar5 & 0xc0) == 0) goto LAB_140004de0;
LAB_140004d09:
      *(undefined8 *)((longlong)auStack_b8 + lVar6 + 0x28) = 0x140004d1a;
      FUN_1400049a0((byte *)pcVar16,(byte *)local_50,param_3,pDVar17);
      puVar13 = puVar13 + 3;
    } while (puVar13 <= &UNK_14001f89f);
    if (0 < DAT_140023164) {
      lVar14 = 0;
      iVar15 = 0;
      do {
        pDVar8 = (DWORD *)(DAT_140023168 + lVar14);
        flNewProtect = *pDVar8;
        if (flNewProtect != 0) {
          dwSize = *(SIZE_T *)(pDVar8 + 4);
          lpAddress = *(LPVOID *)(pDVar8 + 2);
          *(undefined8 *)((longlong)auStack_b8 + lVar6 + 0x28) = 0x140004d5f;
          VirtualProtect(lpAddress,dwSize,flNewProtect,(PDWORD)local_50);
        }
        iVar15 = iVar15 + 1;
        lVar14 = lVar14 + 0x28;
      } while (iVar15 < DAT_140023164);
    }
  }
  return;
}



void FUN_140004f10(undefined4 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                  undefined8 param_5)

{
  undefined4 local_38 [2];
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  undefined8 local_18;
  
  if (DAT_140023170 != (code *)0x0) {
    local_18 = param_5;
    local_38[0] = param_1;
    local_30 = param_2;
    local_28 = param_3;
    local_20 = param_4;
    (*DAT_140023170)(local_38);
  }
  return;
}



void FUN_140004f60(undefined8 param_1)

{
  DAT_140023170 = param_1;
  __setusermatherr();
  return;
}



undefined8 FUN_140004f70(undefined8 *param_1)

{
  uint uVar1;
  code *extraout_RAX;
  code *extraout_RAX_00;
  code *extraout_RAX_01;
  undefined8 uVar2;
  code *extraout_RAX_02;
  code *pcVar3;
  
  uVar1 = *(uint *)*param_1;
  if (((uVar1 & 0x20ffffff) == 0x20474343) && ((((uint *)*param_1)[1] & 1) == 0)) {
    return 0xffffffff;
  }
  if (uVar1 < 0xc0000092) {
    if (0xc000008c < uVar1) {
LAB_140005012:
      signal(8);
      pcVar3 = extraout_RAX_00;
      if (extraout_RAX_00 == (code *)0x1) {
        signal(8);
        FUN_140004920();
        return 0xffffffff;
      }
LAB_1400050c7:
      if (pcVar3 != (code *)0x0) {
        (*pcVar3)(8);
        return 0xffffffff;
      }
      goto LAB_14000509e;
    }
    if (uVar1 == 0xc0000008) {
      return 0xffffffff;
    }
    if (uVar1 < 0xc0000009) {
      if (uVar1 == 0x80000002) {
        return 0xffffffff;
      }
      if (uVar1 == 0xc0000005) {
        signal(0xb);
        if (extraout_RAX == (code *)0x1) {
          signal(0xb);
          return 0xffffffff;
        }
        if (extraout_RAX != (code *)0x0) {
          (*extraout_RAX)(0xb);
          return 0xffffffff;
        }
      }
      goto LAB_14000509e;
    }
    if (uVar1 != 0xc000001d) {
      if (uVar1 == 0xc000008c) {
        return 0xffffffff;
      }
      goto LAB_14000509e;
    }
  }
  else {
    if (uVar1 == 0xc0000094) {
      signal(8);
      pcVar3 = extraout_RAX_02;
      if (extraout_RAX_02 == (code *)0x1) {
        signal(8);
        return 0xffffffff;
      }
      goto LAB_1400050c7;
    }
    if (uVar1 < 0xc0000095) {
      if (uVar1 == 0xc0000092) {
        return 0xffffffff;
      }
      if (uVar1 != 0xc0000093) goto LAB_14000509e;
      goto LAB_140005012;
    }
    if (uVar1 == 0xc0000095) {
      return 0xffffffff;
    }
    if (uVar1 != 0xc0000096) goto LAB_14000509e;
  }
  signal(4);
  if (extraout_RAX_01 == (code *)0x1) {
    signal(4);
  }
  else {
    if (extraout_RAX_01 == (code *)0x0) {
LAB_14000509e:
      if (DAT_140023190 != (code *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0001400050b2. Too many branches
                    // WARNING: Treating indirect jump as call
        uVar2 = (*DAT_140023190)(param_1);
        return uVar2;
      }
      return 0;
    }
    (*extraout_RAX_01)(4);
  }
  return 0xffffffff;
}



void FUN_140005150(void)

{
  DWORD *pDVar1;
  DWORD DVar2;
  LPVOID pvVar3;
  
  EnterCriticalSection((LPCRITICAL_SECTION)&DAT_1400231c0);
  for (pDVar1 = DAT_1400231a0; pDVar1 != (DWORD *)0x0; pDVar1 = *(DWORD **)(pDVar1 + 4)) {
    pvVar3 = TlsGetValue(*pDVar1);
    DVar2 = GetLastError();
    if ((DVar2 == 0) && (pvVar3 != (LPVOID)0x0)) {
      (**(code **)(pDVar1 + 2))(pvVar3);
    }
  }
                    // WARNING: Could not recover jumptable at 0x0001400051b3. Too many branches
                    // WARNING: Treating indirect jump as call
  LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_1400231c0);
  return;
}



undefined8 FUN_1400051c0(undefined4 param_1,undefined8 param_2)

{
  undefined4 *puVar1;
  undefined8 uVar2;
  
  uVar2 = 0;
  if (DAT_1400231a8 != 0) {
    puVar1 = (undefined4 *)calloc(1,0x18);
    if (puVar1 != (undefined4 *)0x0) {
      *puVar1 = param_1;
      *(undefined8 *)(puVar1 + 2) = param_2;
      EnterCriticalSection((LPCRITICAL_SECTION)&DAT_1400231c0);
      *(undefined4 **)(puVar1 + 4) = DAT_1400231a0;
      DAT_1400231a0 = puVar1;
      LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_1400231c0);
      return 0;
    }
    uVar2 = 0xffffffff;
  }
  return uVar2;
}



undefined8 FUN_140005240(int param_1)

{
  int *piVar1;
  int *_Memory;
  
  if (DAT_1400231a8 == 0) {
    return 0;
  }
  EnterCriticalSection((LPCRITICAL_SECTION)&DAT_1400231c0);
  if (DAT_1400231a0 == (int *)0x0) {
LAB_140005293:
    LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_1400231c0);
  }
  else {
    _Memory = DAT_1400231a0;
    if (param_1 == *DAT_1400231a0) {
      DAT_1400231a0 = *(int **)(DAT_1400231a0 + 4);
    }
    else {
      do {
        piVar1 = _Memory;
        _Memory = *(int **)(piVar1 + 4);
        if (_Memory == (int *)0x0) goto LAB_140005293;
      } while (*_Memory != param_1);
      *(undefined8 *)(piVar1 + 4) = *(undefined8 *)(_Memory + 4);
    }
    free(_Memory);
    LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_1400231c0);
  }
  return 0;
}



undefined8 FUN_1400052e0(undefined8 param_1,int param_2)

{
  void *pvVar1;
  void *_Memory;
  
  if (param_2 == 1) {
    if (DAT_1400231a8 == 0) {
      InitializeCriticalSection((LPCRITICAL_SECTION)&DAT_1400231c0);
    }
    DAT_1400231a8 = 1;
    return 1;
  }
  if (param_2 == 0) {
    if (DAT_1400231a8 != 0) {
      FUN_140005150();
    }
    if (DAT_1400231a8 == 1) {
      DAT_1400231a8 = 1;
      _Memory = DAT_1400231a0;
      while (_Memory != (void *)0x0) {
        pvVar1 = *(void **)((longlong)_Memory + 0x10);
        free(_Memory);
        _Memory = pvVar1;
      }
      DAT_1400231a0 = (void *)0x0;
      DAT_1400231a8 = 0;
      DeleteCriticalSection((LPCRITICAL_SECTION)&DAT_1400231c0);
    }
  }
  else {
    if (param_2 == 2) {
      FUN_140004920();
      return 1;
    }
    if ((param_2 == 3) && (DAT_1400231a8 != 0)) {
      FUN_140005150();
    }
  }
  return 1;
}



bool FUN_1400053d0(longlong param_1)

{
  int *piVar1;
  bool bVar2;
  
  piVar1 = (int *)(param_1 + *(int *)(param_1 + 0x3c));
  bVar2 = false;
  if (*piVar1 == 0x4550) {
    bVar2 = (short)piVar1[6] == 0x20b;
  }
  return bVar2;
}



bool FUN_1400053f0(short *param_1)

{
  bool bVar1;
  
  if (*param_1 == 0x5a4d) {
    bVar1 = FUN_1400053d0((longlong)param_1);
    return bVar1;
  }
  return false;
}



longlong FUN_140005410(longlong param_1,ulonglong param_2)

{
  longlong lVar1;
  longlong lVar2;
  longlong lVar3;
  
  lVar3 = param_1 + *(int *)(param_1 + 0x3c);
  lVar2 = lVar3 + 0x18 + (ulonglong)*(ushort *)(lVar3 + 0x14);
  if (*(ushort *)(lVar3 + 6) != 0) {
    lVar1 = lVar2 + 0x28;
    do {
      if ((*(uint *)(lVar2 + 0xc) <= param_2) &&
         (param_2 < *(uint *)(lVar2 + 0xc) + *(int *)(lVar2 + 8))) {
        return lVar2;
      }
      lVar2 = lVar2 + 0x28;
    } while (lVar2 != lVar1 + (ulonglong)(*(ushort *)(lVar3 + 6) - 1) * 0x28);
  }
  return 0;
}



char * FUN_140005460(char *param_1)

{
  char *pcVar1;
  dword dVar2;
  bool bVar3;
  int iVar4;
  size_t sVar5;
  undefined7 extraout_var;
  IMAGE_DOS_HEADER *pIVar6;
  char *_Str1;
  
  sVar5 = strlen(param_1);
  if (sVar5 < 9) {
    pIVar6 = &IMAGE_DOS_HEADER_140000000;
    bVar3 = FUN_1400053d0((longlong)&IMAGE_DOS_HEADER_140000000);
    if ((int)CONCAT71(extraout_var,bVar3) == 0) {
      return (char *)0x0;
    }
    dVar2 = pIVar6->e_lfanew;
    _Str1 = (char *)((longlong)pIVar6->e_res_4_ +
                    (ulonglong)*(ushort *)((longlong)pIVar6->e_res_4_ + (longlong)(int)dVar2 + -8) +
                    (longlong)(int)dVar2 + -4);
    if (*(ushort *)(pIVar6->e_magic + (longlong)(int)dVar2 + 6) != 0) {
      pcVar1 = _Str1 + (ulonglong)(*(ushort *)(pIVar6->e_magic + (longlong)(int)dVar2 + 6) - 1) *
                       0x28 + 0x28;
      do {
        iVar4 = strncmp(_Str1,param_1,8);
        if (iVar4 == 0) {
          return _Str1;
        }
        _Str1 = _Str1 + 0x28;
      } while (_Str1 != pcVar1);
    }
  }
  return (char *)0x0;
}



longlong FUN_140005500(longlong param_1)

{
  longlong lVar1;
  dword dVar2;
  bool bVar3;
  undefined7 extraout_var;
  longlong lVar4;
  IMAGE_DOS_HEADER *pIVar5;
  
  pIVar5 = &IMAGE_DOS_HEADER_140000000;
  lVar4 = 0;
  bVar3 = FUN_1400053d0((longlong)&IMAGE_DOS_HEADER_140000000);
  if ((int)CONCAT71(extraout_var,bVar3) != 0) {
    dVar2 = pIVar5->e_lfanew;
    lVar4 = (longlong)pIVar5->e_res_4_ +
            (ulonglong)*(ushort *)((longlong)pIVar5->e_res_4_ + (longlong)(int)dVar2 + -8) +
            (longlong)(int)dVar2 + -4;
    if (*(ushort *)(pIVar5->e_magic + (longlong)(int)dVar2 + 6) != 0) {
      lVar1 = lVar4 + (ulonglong)(*(ushort *)(pIVar5->e_magic + (longlong)(int)dVar2 + 6) - 1) *
                      0x28 + 0x28;
      do {
        if (((ulonglong)*(uint *)(lVar4 + 0xc) <= (ulonglong)(param_1 - (longlong)pIVar5)) &&
           ((ulonglong)(param_1 - (longlong)pIVar5) <
            (ulonglong)(*(uint *)(lVar4 + 0xc) + *(int *)(lVar4 + 8)))) {
          return lVar4;
        }
        lVar4 = lVar4 + 0x28;
      } while (lVar4 != lVar1);
    }
    lVar4 = 0;
  }
  return lVar4;
}



ulonglong FUN_140005580(void)

{
  bool bVar1;
  undefined7 extraout_var;
  IMAGE_DOS_HEADER *pIVar2;
  ulonglong uVar3;
  
  pIVar2 = &IMAGE_DOS_HEADER_140000000;
  uVar3 = 0;
  bVar1 = FUN_1400053d0((longlong)&IMAGE_DOS_HEADER_140000000);
  if ((int)CONCAT71(extraout_var,bVar1) != 0) {
    uVar3 = (ulonglong)*(ushort *)(pIVar2->e_magic + (longlong)(int)pIVar2->e_lfanew + 6);
  }
  return uVar3 & 0xffffffff;
}



longlong FUN_1400055c0(longlong param_1)

{
  longlong lVar1;
  dword dVar2;
  bool bVar3;
  undefined7 extraout_var;
  longlong lVar4;
  IMAGE_DOS_HEADER *pIVar5;
  
  pIVar5 = &IMAGE_DOS_HEADER_140000000;
  lVar4 = 0;
  bVar3 = FUN_1400053d0((longlong)&IMAGE_DOS_HEADER_140000000);
  if ((int)CONCAT71(extraout_var,bVar3) != 0) {
    dVar2 = pIVar5->e_lfanew;
    lVar4 = (longlong)pIVar5->e_res_4_ +
            (ulonglong)*(ushort *)((longlong)pIVar5->e_res_4_ + (longlong)(int)dVar2 + -8) +
            (longlong)(int)dVar2 + -4;
    if (*(ushort *)(pIVar5->e_magic + (longlong)(int)dVar2 + 6) != 0) {
      lVar1 = lVar4 + (ulonglong)(*(ushort *)(pIVar5->e_magic + (longlong)(int)dVar2 + 6) - 1) *
                      0x28 + 0x28;
      do {
        if ((*(byte *)(lVar4 + 0x27) & 0x20) != 0) {
          if (param_1 == 0) {
            return lVar4;
          }
          param_1 = param_1 + -1;
        }
        lVar4 = lVar4 + 0x28;
      } while (lVar4 != lVar1);
    }
    lVar4 = 0;
  }
  return lVar4;
}



IMAGE_DOS_HEADER * FUN_140005640(void)

{
  bool bVar1;
  undefined7 extraout_var;
  IMAGE_DOS_HEADER *pIVar2;
  IMAGE_DOS_HEADER *pIVar3;
  
  pIVar3 = &IMAGE_DOS_HEADER_140000000;
  pIVar2 = (IMAGE_DOS_HEADER *)0x0;
  bVar1 = FUN_1400053d0((longlong)&IMAGE_DOS_HEADER_140000000);
  if ((int)CONCAT71(extraout_var,bVar1) != 0) {
    pIVar2 = pIVar3;
  }
  return pIVar2;
}



ulonglong FUN_140005670(longlong param_1)

{
  longlong lVar1;
  dword dVar2;
  bool bVar3;
  undefined7 extraout_var;
  longlong lVar5;
  IMAGE_DOS_HEADER *pIVar6;
  ulonglong uVar4;
  
  pIVar6 = &IMAGE_DOS_HEADER_140000000;
  bVar3 = FUN_1400053d0((longlong)&IMAGE_DOS_HEADER_140000000);
  uVar4 = CONCAT71(extraout_var,bVar3);
  if ((int)uVar4 != 0) {
    dVar2 = pIVar6->e_lfanew;
    lVar5 = (longlong)pIVar6->e_res_4_ +
            (ulonglong)*(ushort *)((longlong)pIVar6->e_res_4_ + (longlong)(int)dVar2 + -8) +
            (longlong)(int)dVar2 + -4;
    if (*(ushort *)(pIVar6->e_magic + (longlong)(int)dVar2 + 6) != 0) {
      lVar1 = lVar5 + (ulonglong)(*(ushort *)(pIVar6->e_magic + (longlong)(int)dVar2 + 6) - 1) *
                      0x28 + 0x28;
      do {
        if (((ulonglong)*(uint *)(lVar5 + 0xc) <= (ulonglong)(param_1 - (longlong)pIVar6)) &&
           ((ulonglong)(param_1 - (longlong)pIVar6) <
            (ulonglong)(*(uint *)(lVar5 + 0xc) + *(int *)(lVar5 + 8)))) {
          return (ulonglong)(~*(uint *)(lVar5 + 0x24) >> 0x1f);
        }
        lVar5 = lVar5 + 0x28;
      } while (lVar5 != lVar1);
    }
    uVar4 = 0;
  }
  return uVar4;
}



char * FUN_140005700(uint param_1)

{
  longlong lVar1;
  dword dVar2;
  uint uVar3;
  bool bVar4;
  undefined7 extraout_var;
  ulonglong uVar5;
  word *pwVar6;
  longlong lVar7;
  ulonglong uVar8;
  char *pcVar9;
  IMAGE_DOS_HEADER *pIVar10;
  
  pIVar10 = &IMAGE_DOS_HEADER_140000000;
  pcVar9 = (char *)0x0;
  uVar8 = (ulonglong)param_1;
  bVar4 = FUN_1400053d0((longlong)&IMAGE_DOS_HEADER_140000000);
  if ((int)CONCAT71(extraout_var,bVar4) != 0) {
    dVar2 = pIVar10->e_lfanew;
    uVar3 = *(uint *)((longlong)pIVar10[1].e_res_4_ + (longlong)(int)dVar2 + -0xc);
    uVar5 = (ulonglong)uVar3;
    if (uVar3 != 0) {
      lVar7 = (longlong)pIVar10->e_res_4_ +
              (ulonglong)*(ushort *)((longlong)pIVar10->e_res_4_ + (longlong)(int)dVar2 + -8) +
              (longlong)(int)dVar2 + -4;
      if (*(ushort *)(pIVar10->e_magic + (longlong)(int)dVar2 + 6) != 0) {
        lVar1 = lVar7 + (ulonglong)(*(ushort *)(pIVar10->e_magic + (longlong)(int)dVar2 + 6) - 1) *
                        0x28 + 0x28;
        do {
          if ((*(uint *)(lVar7 + 0xc) <= uVar5) &&
             (uVar5 < *(uint *)(lVar7 + 0xc) + *(int *)(lVar7 + 8))) {
            pwVar6 = (word *)(pIVar10->e_magic + uVar5);
            if (pwVar6 != (word *)0x0) {
              for (; (*(int *)(pwVar6 + 2) != 0 || (*(int *)(pwVar6 + 6) != 0));
                  pwVar6 = pwVar6 + 10) {
                if ((int)uVar8 < 1) {
                  return pIVar10->e_magic + *(uint *)(pwVar6 + 6);
                }
                uVar8 = (ulonglong)((int)uVar8 - 1);
              }
            }
            break;
          }
          lVar7 = lVar7 + 0x28;
        } while (lVar7 != lVar1);
        pcVar9 = (char *)0x0;
      }
    }
  }
  return pcVar9;
}



undefined4 FUN_1400057c0(void)

{
  LPCWSTR lpWideCharStr;
  undefined4 uVar1;
  int iVar2;
  undefined8 *puVar3;
  LPWSTR lpCmdLine;
  char **ppcVar4;
  char *pcVar5;
  undefined8 unaff_RBX;
  longlong lVar6;
  undefined8 unaff_RBP;
  uint uVar7;
  ulonglong unaff_RSI;
  undefined8 unaff_RDI;
  undefined8 unaff_R12;
  LPWSTR *unaff_R13;
  undefined8 unaff_R14;
  
  while( true ) {
    *(undefined8 *)((longlong)register0x00000020 + -8) = unaff_R14;
    *(LPWSTR **)((longlong)register0x00000020 + -0x10) = unaff_R13;
    *(undefined8 *)((longlong)register0x00000020 + -0x18) = unaff_R12;
    *(undefined8 *)((longlong)register0x00000020 + -0x20) = unaff_RBP;
    *(undefined8 *)((longlong)register0x00000020 + -0x28) = unaff_RDI;
    *(ulonglong *)((longlong)register0x00000020 + -0x30) = unaff_RSI;
    *(undefined8 *)((longlong)register0x00000020 + -0x38) = unaff_RBX;
    *(undefined4 *)((longlong)register0x00000020 + -0x3c) = *(undefined4 *)__argc_exref;
    *(undefined8 *)((longlong)register0x00000020 + -0x90) = 0x1400057e4;
    puVar3 = (undefined8 *)(*(code *)PTR_FUN_140007090)();
    ppcVar4 = (char **)*puVar3;
    if (ppcVar4 != (char **)0x0) {
      *(undefined8 *)((longlong)register0x00000020 + -0x90) = 0x1400057f5;
      uVar1 = FUN_140003550(*(int *)((longlong)register0x00000020 + -0x3c),ppcVar4);
      return uVar1;
    }
    *(undefined8 *)((longlong)register0x00000020 + -0x90) = 0x140005816;
    lpCmdLine = GetCommandLineW();
    *(undefined8 *)((longlong)register0x00000020 + -0x90) = 0x140005824;
    unaff_R13 = CommandLineToArgvW(lpCmdLine,(int *)((longlong)register0x00000020 + -0x3c));
    if (unaff_R13 == (LPWSTR *)0x0) {
      return 0xffffffff;
    }
    uVar7 = *(uint *)((longlong)register0x00000020 + -0x3c);
    unaff_RSI = (ulonglong)uVar7;
    if ((ulonglong)(longlong)(int)(uVar7 + 1) < 0x1000000000000000) break;
    *(undefined8 *)((longlong)register0x00000020 + -0x90) = 0x140005955;
    __cxa_throw_bad_array_new_length();
    register0x00000020 = (BADSPACEBASE *)((longlong)register0x00000020 + -0x88);
  }
  lVar6 = 0;
  *(undefined8 *)((longlong)register0x00000020 + -0x90) = 0x140005858;
  ppcVar4 = (char **)operator_new__((longlong)(int)(uVar7 + 1) << 3);
  if (uVar7 != 0) {
    do {
      lpWideCharStr = unaff_R13[lVar6];
      *(undefined8 *)((longlong)register0x00000020 + -0x50) = 0;
      *(undefined8 *)((longlong)register0x00000020 + -0x58) = 0;
      *(undefined4 *)((longlong)register0x00000020 + -0x60) = 0;
      *(undefined8 *)((longlong)register0x00000020 + -0x68) = 0;
      *(undefined8 *)((longlong)register0x00000020 + -0x90) = 0x1400058a7;
      iVar2 = WideCharToMultiByte(0,0,lpWideCharStr,-1,
                                  *(LPSTR *)((longlong)register0x00000020 + -0x68),
                                  *(int *)((longlong)register0x00000020 + -0x60),
                                  *(LPCSTR *)((longlong)register0x00000020 + -0x58),
                                  *(LPBOOL *)((longlong)register0x00000020 + -0x50));
      *(undefined8 *)((longlong)register0x00000020 + -0x90) = 0x1400058b2;
      pcVar5 = (char *)operator_new__((longlong)iVar2);
      *(int *)((longlong)register0x00000020 + -0x60) = iVar2;
      *(char **)((longlong)register0x00000020 + -0x68) = pcVar5;
      *(undefined8 *)((longlong)register0x00000020 + -0x50) = 0;
      *(undefined8 *)((longlong)register0x00000020 + -0x58) = 0;
      *(undefined8 *)((longlong)register0x00000020 + -0x90) = 0x1400058df;
      WideCharToMultiByte(0,0,lpWideCharStr,-1,*(LPSTR *)((longlong)register0x00000020 + -0x68),
                          *(int *)((longlong)register0x00000020 + -0x60),
                          *(LPCSTR *)((longlong)register0x00000020 + -0x58),
                          *(LPBOOL *)((longlong)register0x00000020 + -0x50));
      ppcVar4[lVar6] = pcVar5;
      uVar7 = (int)lVar6 + 1;
      lVar6 = lVar6 + 1;
    } while (*(int *)((longlong)register0x00000020 + -0x3c) != (int)lVar6);
  }
  lVar6 = 0;
  ppcVar4[(int)uVar7] = (char *)0x0;
  *(undefined8 *)((longlong)register0x00000020 + -0x90) = 0x140005906;
  LocalFree(unaff_R13);
  *(undefined8 *)((longlong)register0x00000020 + -0x90) = 0x140005912;
  uVar1 = FUN_140003550(*(int *)((longlong)register0x00000020 + -0x3c),ppcVar4);
  if (*(int *)((longlong)register0x00000020 + -0x3c) != 0) {
    do {
      pcVar5 = ppcVar4[lVar6];
      if (pcVar5 == (char *)0x0) break;
      *(undefined8 *)((longlong)register0x00000020 + -0x90) = 0x140005925;
      operator_delete__(pcVar5);
      lVar6 = lVar6 + 1;
    } while (*(int *)((longlong)register0x00000020 + -0x3c) != (int)lVar6);
  }
  *(undefined8 *)((longlong)register0x00000020 + -0x90) = 0x140005940;
  operator_delete__(ppcVar4);
  return uVar1;
}



undefined4 thunk_FUN_1400057c0(void)

{
  LPCWSTR lpWideCharStr;
  undefined4 uVar1;
  int iVar2;
  undefined8 *puVar3;
  LPWSTR lpCmdLine;
  char **ppcVar4;
  char *pcVar5;
  longlong lVar6;
  undefined8 unaff_RBX;
  undefined8 unaff_RBP;
  uint uVar7;
  ulonglong unaff_RSI;
  undefined8 unaff_RDI;
  undefined8 unaff_R12;
  LPWSTR *unaff_R13;
  undefined8 unaff_R14;
  
  while( true ) {
    *(undefined8 *)((longlong)register0x00000020 + -8) = unaff_R14;
    *(LPWSTR **)((longlong)register0x00000020 + -0x10) = unaff_R13;
    *(undefined8 *)((longlong)register0x00000020 + -0x18) = unaff_R12;
    *(undefined8 *)((longlong)register0x00000020 + -0x20) = unaff_RBP;
    *(undefined8 *)((longlong)register0x00000020 + -0x28) = unaff_RDI;
    *(ulonglong *)((longlong)register0x00000020 + -0x30) = unaff_RSI;
    *(undefined8 *)((longlong)register0x00000020 + -0x38) = unaff_RBX;
    *(undefined4 *)((longlong)register0x00000020 + -0x3c) = *(undefined4 *)__argc_exref;
    *(undefined8 *)((longlong)register0x00000020 + -0x90) = 0x1400057e4;
    puVar3 = (undefined8 *)(*(code *)PTR_FUN_140007090)();
    ppcVar4 = (char **)*puVar3;
    if (ppcVar4 != (char **)0x0) {
      *(undefined8 *)((longlong)register0x00000020 + -0x90) = 0x1400057f5;
      uVar1 = FUN_140003550(*(int *)((longlong)register0x00000020 + -0x3c),ppcVar4);
      return uVar1;
    }
    *(undefined8 *)((longlong)register0x00000020 + -0x90) = 0x140005816;
    lpCmdLine = GetCommandLineW();
    *(undefined8 *)((longlong)register0x00000020 + -0x90) = 0x140005824;
    unaff_R13 = CommandLineToArgvW(lpCmdLine,(int *)((longlong)register0x00000020 + -0x3c));
    if (unaff_R13 == (LPWSTR *)0x0) {
      return 0xffffffff;
    }
    uVar7 = *(uint *)((longlong)register0x00000020 + -0x3c);
    unaff_RSI = (ulonglong)uVar7;
    if ((ulonglong)(longlong)(int)(uVar7 + 1) < 0x1000000000000000) break;
    *(undefined8 *)((longlong)register0x00000020 + -0x90) = 0x140005955;
    __cxa_throw_bad_array_new_length();
    register0x00000020 = (BADSPACEBASE *)((longlong)register0x00000020 + -0x88);
  }
  lVar6 = 0;
  *(undefined8 *)((longlong)register0x00000020 + -0x90) = 0x140005858;
  ppcVar4 = (char **)operator_new__((longlong)(int)(uVar7 + 1) << 3);
  if (uVar7 != 0) {
    do {
      lpWideCharStr = unaff_R13[lVar6];
      *(undefined8 *)((longlong)register0x00000020 + -0x50) = 0;
      *(undefined8 *)((longlong)register0x00000020 + -0x58) = 0;
      *(undefined4 *)((longlong)register0x00000020 + -0x60) = 0;
      *(undefined8 *)((longlong)register0x00000020 + -0x68) = 0;
      *(undefined8 *)((longlong)register0x00000020 + -0x90) = 0x1400058a7;
      iVar2 = WideCharToMultiByte(0,0,lpWideCharStr,-1,
                                  *(LPSTR *)((longlong)register0x00000020 + -0x68),
                                  *(int *)((longlong)register0x00000020 + -0x60),
                                  *(LPCSTR *)((longlong)register0x00000020 + -0x58),
                                  *(LPBOOL *)((longlong)register0x00000020 + -0x50));
      *(undefined8 *)((longlong)register0x00000020 + -0x90) = 0x1400058b2;
      pcVar5 = (char *)operator_new__((longlong)iVar2);
      *(int *)((longlong)register0x00000020 + -0x60) = iVar2;
      *(char **)((longlong)register0x00000020 + -0x68) = pcVar5;
      *(undefined8 *)((longlong)register0x00000020 + -0x50) = 0;
      *(undefined8 *)((longlong)register0x00000020 + -0x58) = 0;
      *(undefined8 *)((longlong)register0x00000020 + -0x90) = 0x1400058df;
      WideCharToMultiByte(0,0,lpWideCharStr,-1,*(LPSTR *)((longlong)register0x00000020 + -0x68),
                          *(int *)((longlong)register0x00000020 + -0x60),
                          *(LPCSTR *)((longlong)register0x00000020 + -0x58),
                          *(LPBOOL *)((longlong)register0x00000020 + -0x50));
      ppcVar4[lVar6] = pcVar5;
      uVar7 = (int)lVar6 + 1;
      lVar6 = lVar6 + 1;
    } while (*(int *)((longlong)register0x00000020 + -0x3c) != (int)lVar6);
  }
  lVar6 = 0;
  ppcVar4[(int)uVar7] = (char *)0x0;
  *(undefined8 *)((longlong)register0x00000020 + -0x90) = 0x140005906;
  LocalFree(unaff_R13);
  *(undefined8 *)((longlong)register0x00000020 + -0x90) = 0x140005912;
  uVar1 = FUN_140003550(*(int *)((longlong)register0x00000020 + -0x3c),ppcVar4);
  if (*(int *)((longlong)register0x00000020 + -0x3c) != 0) {
    do {
      pcVar5 = ppcVar4[lVar6];
      if (pcVar5 == (char *)0x0) break;
      *(undefined8 *)((longlong)register0x00000020 + -0x90) = 0x140005925;
      operator_delete__(pcVar5);
      lVar6 = lVar6 + 1;
    } while (*(int *)((longlong)register0x00000020 + -0x3c) != (int)lVar6);
  }
  *(undefined8 *)((longlong)register0x00000020 + -0x90) = 0x140005940;
  operator_delete__(ppcVar4);
  return uVar1;
}



undefined4 thunk_FUN_1400057c0(void)

{
  LPCWSTR lpWideCharStr;
  undefined4 uVar1;
  int iVar2;
  undefined8 *puVar3;
  LPWSTR lpCmdLine;
  char **ppcVar4;
  char *pcVar5;
  longlong lVar6;
  undefined8 unaff_RBX;
  undefined1 *puVar7;
  undefined8 unaff_RBP;
  uint uVar8;
  ulonglong unaff_RSI;
  undefined8 unaff_RDI;
  undefined8 unaff_R12;
  LPWSTR *unaff_R13;
  undefined8 unaff_R14;
  
  puVar7 = (undefined1 *)register0x00000020;
  while( true ) {
    *(undefined8 *)(puVar7 + -8) = unaff_R14;
    *(LPWSTR **)(puVar7 + -0x10) = unaff_R13;
    *(undefined8 *)(puVar7 + -0x18) = unaff_R12;
    *(undefined8 *)(puVar7 + -0x20) = unaff_RBP;
    *(undefined8 *)(puVar7 + -0x28) = unaff_RDI;
    *(ulonglong *)(puVar7 + -0x30) = unaff_RSI;
    *(undefined8 *)(puVar7 + -0x38) = unaff_RBX;
    *(undefined4 *)(puVar7 + -0x3c) = *(undefined4 *)__argc_exref;
    *(undefined8 *)(puVar7 + -0x90) = 0x1400057e4;
    puVar3 = (undefined8 *)(*(code *)PTR_FUN_140007090)();
    ppcVar4 = (char **)*puVar3;
    if (ppcVar4 != (char **)0x0) {
      *(undefined8 *)(puVar7 + -0x90) = 0x1400057f5;
      uVar1 = FUN_140003550(*(int *)(puVar7 + -0x3c),ppcVar4);
      return uVar1;
    }
    *(undefined8 *)(puVar7 + -0x90) = 0x140005816;
    lpCmdLine = GetCommandLineW();
    *(undefined8 *)(puVar7 + -0x90) = 0x140005824;
    unaff_R13 = CommandLineToArgvW(lpCmdLine,(int *)(puVar7 + -0x3c));
    if (unaff_R13 == (LPWSTR *)0x0) {
      return 0xffffffff;
    }
    uVar8 = *(uint *)(puVar7 + -0x3c);
    unaff_RSI = (ulonglong)uVar8;
    if ((ulonglong)(longlong)(int)(uVar8 + 1) < 0x1000000000000000) break;
    *(undefined8 *)(puVar7 + -0x90) = 0x140005955;
    __cxa_throw_bad_array_new_length();
    puVar7 = puVar7 + -0x88;
  }
  lVar6 = 0;
  *(undefined8 *)(puVar7 + -0x90) = 0x140005858;
  ppcVar4 = (char **)operator_new__((longlong)(int)(uVar8 + 1) << 3);
  if (uVar8 != 0) {
    do {
      lpWideCharStr = unaff_R13[lVar6];
      *(undefined8 *)(puVar7 + -0x50) = 0;
      *(undefined8 *)(puVar7 + -0x58) = 0;
      *(undefined4 *)(puVar7 + -0x60) = 0;
      *(undefined8 *)(puVar7 + -0x68) = 0;
      *(undefined8 *)(puVar7 + -0x90) = 0x1400058a7;
      iVar2 = WideCharToMultiByte(0,0,lpWideCharStr,-1,*(LPSTR *)(puVar7 + -0x68),
                                  *(int *)(puVar7 + -0x60),*(LPCSTR *)(puVar7 + -0x58),
                                  *(LPBOOL *)(puVar7 + -0x50));
      *(undefined8 *)(puVar7 + -0x90) = 0x1400058b2;
      pcVar5 = (char *)operator_new__((longlong)iVar2);
      *(int *)(puVar7 + -0x60) = iVar2;
      *(char **)(puVar7 + -0x68) = pcVar5;
      *(undefined8 *)(puVar7 + -0x50) = 0;
      *(undefined8 *)(puVar7 + -0x58) = 0;
      *(undefined8 *)(puVar7 + -0x90) = 0x1400058df;
      WideCharToMultiByte(0,0,lpWideCharStr,-1,*(LPSTR *)(puVar7 + -0x68),*(int *)(puVar7 + -0x60),
                          *(LPCSTR *)(puVar7 + -0x58),*(LPBOOL *)(puVar7 + -0x50));
      ppcVar4[lVar6] = pcVar5;
      uVar8 = (int)lVar6 + 1;
      lVar6 = lVar6 + 1;
    } while (*(int *)(puVar7 + -0x3c) != (int)lVar6);
  }
  lVar6 = 0;
  ppcVar4[(int)uVar8] = (char *)0x0;
  *(undefined8 *)(puVar7 + -0x90) = 0x140005906;
  LocalFree(unaff_R13);
  *(undefined8 *)(puVar7 + -0x90) = 0x140005912;
  uVar1 = FUN_140003550(*(int *)(puVar7 + -0x3c),ppcVar4);
  if (*(int *)(puVar7 + -0x3c) != 0) {
    do {
      pcVar5 = ppcVar4[lVar6];
      if (pcVar5 == (char *)0x0) break;
      *(undefined8 *)(puVar7 + -0x90) = 0x140005925;
      operator_delete__(pcVar5);
      lVar6 = lVar6 + 1;
    } while (*(int *)(puVar7 + -0x3c) != (int)lVar6);
  }
  *(undefined8 *)(puVar7 + -0x90) = 0x140005940;
  operator_delete__(ppcVar4);
  return uVar1;
}



void __cxa_throw_bad_array_new_length(void)

{
                    // WARNING: Could not recover jumptable at 0x000140005998. Too many branches
                    // WARNING: Treating indirect jump as call
  __cxa_throw_bad_array_new_length();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void * operator_new(ulonglong param_1)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x0001400059a0. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = operator_new(param_1);
  return pvVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void * operator_new__(ulonglong param_1)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x0001400059a8. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = operator_new__(param_1);
  return pvVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void operator_delete(void *param_1,ulonglong param_2)

{
                    // WARNING: Could not recover jumptable at 0x0001400059b0. Too many branches
                    // WARNING: Treating indirect jump as call
  operator_delete(param_1,param_2);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void operator_delete__(void *param_1)

{
                    // WARNING: Could not recover jumptable at 0x0001400059b8. Too many branches
                    // WARNING: Treating indirect jump as call
  operator_delete__(param_1);
  return;
}



void _Unwind_Resume(void)

{
                    // WARNING: Could not recover jumptable at 0x0001400059c0. Too many branches
                    // WARNING: Treating indirect jump as call
  _Unwind_Resume();
  return;
}



ulonglong FUN_1400059d0(void)

{
  ulonglong in_RAX;
  ulonglong uVar1;
  undefined8 *puVar2;
  undefined8 local_res8 [4];
  
  puVar2 = local_res8;
  uVar1 = in_RAX;
  if (0xfff < in_RAX) {
    do {
      puVar2 = puVar2 + -0x200;
      *puVar2 = *puVar2;
      uVar1 = uVar1 - 0x1000;
    } while (0x1000 < uVar1);
  }
  *(undefined8 *)((longlong)puVar2 - uVar1) = *(undefined8 *)((longlong)puVar2 - uVar1);
  return in_RAX;
}



undefined * FUN_140005a10(void)

{
  return _fmode_exref;
}



undefined * FUN_140005a20(void)

{
  return _commode_exref;
}



undefined * FUN_140005a30(void)

{
  return _acmdln_exref;
}



undefined * FUN_140005a40(void)

{
  return __argv_exref;
}



undefined8 FUN_140005a50(void)

{
  return DAT_140023230;
}



undefined8 FUN_140005a60(undefined8 param_1)

{
  undefined8 uVar1;
  
  uVar1 = DAT_140023230;
  LOCK();
  DAT_140023230 = param_1;
  UNLOCK();
  return uVar1;
}



FILE * FUN_140005a70(uint param_1)

{
  FILE *pFVar1;
  
  pFVar1 = __iob_func();
  return pFVar1 + param_1;
}



void __getmainargs(void)

{
                    // WARNING: Could not recover jumptable at 0x000140005a98. Too many branches
                    // WARNING: Treating indirect jump as call
  __getmainargs();
  return;
}



FILE * __cdecl __iob_func(void)

{
  FILE *pFVar1;
  
                    // WARNING: Could not recover jumptable at 0x000140005aa0. Too many branches
                    // WARNING: Treating indirect jump as call
  pFVar1 = __iob_func();
  return pFVar1;
}



void __cdecl __set_app_type(int param_1)

{
                    // WARNING: Could not recover jumptable at 0x000140005aa8. Too many branches
                    // WARNING: Treating indirect jump as call
  __set_app_type(param_1);
  return;
}



void __setusermatherr(void)

{
                    // WARNING: Could not recover jumptable at 0x000140005ab0. Too many branches
                    // WARNING: Treating indirect jump as call
  __setusermatherr();
  return;
}



void __cdecl _amsg_exit(int param_1)

{
                    // WARNING: Could not recover jumptable at 0x000140005ab8. Too many branches
                    // WARNING: Treating indirect jump as call
  _amsg_exit(param_1);
  return;
}



void __cdecl _cexit(void)

{
                    // WARNING: Could not recover jumptable at 0x000140005ac0. Too many branches
                    // WARNING: Treating indirect jump as call
  _cexit();
  return;
}



void _initterm(void)

{
                    // WARNING: Could not recover jumptable at 0x000140005ac8. Too many branches
                    // WARNING: Treating indirect jump as call
  _initterm();
  return;
}



_onexit_t __cdecl _onexit(_onexit_t _Func)

{
  _onexit_t p_Var1;
  
                    // WARNING: Could not recover jumptable at 0x000140005ad0. Too many branches
                    // WARNING: Treating indirect jump as call
  p_Var1 = _onexit(_Func);
  return p_Var1;
}



void __cdecl abort(void)

{
                    // WARNING: Could not recover jumptable at 0x000140005ad8. Too many branches
                    // WARNING: Subroutine does not return
                    // WARNING: Treating indirect jump as call
  abort();
  return;
}



void * __cdecl calloc(size_t _Count,size_t _Size)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x000140005ae0. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = calloc(_Count,_Size);
  return pvVar1;
}



void __cdecl exit(int _Code)

{
                    // WARNING: Could not recover jumptable at 0x000140005ae8. Too many branches
                    // WARNING: Subroutine does not return
                    // WARNING: Treating indirect jump as call
  exit(_Code);
  return;
}



int __cdecl fprintf(FILE *_File,char *_Format,...)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x000140005af0. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = fprintf(_File,_Format);
  return iVar1;
}



void __cdecl free(void *_Memory)

{
                    // WARNING: Could not recover jumptable at 0x000140005af8. Too many branches
                    // WARNING: Treating indirect jump as call
  free(_Memory);
  return;
}



size_t __cdecl fwrite(void *_Str,size_t _Size,size_t _Count,FILE *_File)

{
  size_t sVar1;
  
                    // WARNING: Could not recover jumptable at 0x000140005b00. Too many branches
                    // WARNING: Treating indirect jump as call
  sVar1 = fwrite(_Str,_Size,_Count,_File);
  return sVar1;
}



void * __cdecl malloc(size_t _Size)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x000140005b08. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = malloc(_Size);
  return pvVar1;
}



void * __cdecl memcpy(void *_Dst,void *_Src,size_t _Size)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x000140005b10. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = memcpy(_Dst,_Src,_Size);
  return pvVar1;
}



void * __cdecl memmove(void *_Dst,void *_Src,size_t _Size)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x000140005b18. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = memmove(_Dst,_Src,_Size);
  return pvVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void signal(int param_1)

{
                    // WARNING: Could not recover jumptable at 0x000140005b20. Too many branches
                    // WARNING: Treating indirect jump as call
  signal(param_1);
  return;
}



int __cdecl strcmp(char *_Str1,char *_Str2)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x000140005b28. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = strcmp(_Str1,_Str2);
  return iVar1;
}



size_t __cdecl strlen(char *_Str)

{
  size_t sVar1;
  
                    // WARNING: Could not recover jumptable at 0x000140005b30. Too many branches
                    // WARNING: Treating indirect jump as call
  sVar1 = strlen(_Str);
  return sVar1;
}



int __cdecl strncmp(char *_Str1,char *_Str2,size_t _MaxCount)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x000140005b38. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = strncmp(_Str1,_Str2,_MaxCount);
  return iVar1;
}



int __cdecl vfprintf(FILE *_File,char *_Format,va_list _ArgList)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x000140005b40. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = vfprintf(_File,_Format,_ArgList);
  return iVar1;
}



void FUN_140005bc0(QMainWindow *param_1)

{
  *(undefined ***)param_1 = &PTR_FUN_14001efc0;
  *(undefined ***)(param_1 + 0x10) = &PTR_FUN_14001f178;
  QMainWindow::~QMainWindow(param_1);
  operator_delete(param_1,0x48);
  return;
}



void FUN_140005c00(QMainWindow *param_1)

{
  *(undefined ***)param_1 = &PTR_FUN_14001efc0;
  *(undefined ***)(param_1 + 0x10) = &PTR_FUN_14001f178;
                    // WARNING: Could not recover jumptable at 0x000140005c14. Too many branches
                    // WARNING: Treating indirect jump as call
  QMainWindow::~QMainWindow(param_1);
  return;
}



undefined * FUN_140005c20(void)

{
  return staticMetaObject_exref;
}



undefined * FUN_140005c30(void)

{
  return staticMetaObject_exref;
}



void FUN_140005c40(undefined8 *param_1)

{
  int *piVar1;
  
  piVar1 = (int *)*param_1;
  if (piVar1 != (int *)0x0) {
    LOCK();
    *piVar1 = *piVar1 + -1;
    UNLOCK();
    if (*piVar1 == 0) {
      free((void *)*param_1);
      return;
    }
  }
  return;
}



void FUN_140005c60(longlong *param_1,int param_2,longlong param_3,undefined8 *param_4)

{
  size_t _Size;
  int *piVar1;
  undefined4 uVar2;
  void *_Dst;
  longlong lVar3;
  undefined8 uVar4;
  longlong lVar5;
  longlong lVar6;
  void *_Src;
  int *piVar7;
  longlong lVar8;
  int *unaff_R12;
  longlong local_58;
  longlong local_50;
  longlong local_40 [2];
  
  piVar7 = (int *)*param_1;
  if ((param_2 == 0) && (param_4 == (undefined8 *)0x0)) {
    if (piVar7 == (int *)0x0) {
      lVar6 = param_1[2];
    }
    else {
      if ((*piVar7 < 2) && (0 < param_3)) {
        QArrayData::reallocateUnaligned
                  (&local_58,piVar7,param_1[1],8,
                   param_3 + ((longlong)
                              (param_1[1] - ((longlong)piVar7 + 0x1fU & 0xfffffffffffffff0)) >> 3) +
                             param_1[2],0);
        if (local_50 != 0) {
          *param_1 = local_58;
          param_1[1] = local_50;
          return;
        }
        uVar4 = qBadAlloc();
        if (unaff_R12 != (int *)0x0) goto LAB_140005fa1;
        do {
          _Unwind_Resume(uVar4);
LAB_140005fa1:
          LOCK();
          *unaff_R12 = *unaff_R12 + -1;
          UNLOCK();
          if (*unaff_R12 == 0) {
            free(unaff_R12);
          }
        } while( true );
      }
      lVar3 = *param_1;
      lVar6 = param_1[2];
      if (lVar3 != 0) {
        lVar5 = *(longlong *)(lVar3 + 8);
        lVar8 = lVar5;
        if (lVar5 <= lVar6) {
          lVar8 = lVar6;
        }
        lVar8 = lVar8 + param_3;
LAB_140005cbd:
        lVar6 = (lVar5 - ((longlong)(param_1[1] - (lVar3 + 0x1fU & 0xfffffffffffffff0)) >> 3)) -
                lVar6;
        goto LAB_140005d18;
      }
    }
LAB_140005e34:
    lVar8 = 0;
    if (-1 < lVar6) {
      lVar8 = lVar6;
    }
    lVar5 = 0;
    lVar8 = lVar8 + param_3;
  }
  else {
    lVar3 = *param_1;
    lVar6 = param_1[2];
    if (lVar3 == 0) goto LAB_140005e34;
    lVar5 = *(longlong *)(lVar3 + 8);
    lVar8 = lVar6;
    if (lVar6 <= lVar5) {
      lVar8 = lVar5;
    }
    lVar8 = lVar8 + param_3;
    if (param_2 == 0) goto LAB_140005cbd;
    lVar6 = (longlong)(param_1[1] - (lVar3 + 0x1fU & 0xfffffffffffffff0)) >> 3;
LAB_140005d18:
    lVar8 = lVar8 - lVar6;
    if (((*(byte *)(lVar3 + 4) & 1) != 0) && (lVar8 < *(longlong *)(lVar3 + 8))) {
      lVar8 = *(longlong *)(lVar3 + 8);
    }
  }
  _Dst = (void *)QArrayData::allocate(local_40,8,0x10,lVar8,lVar8 <= lVar5);
  if ((local_40[0] == 0) || (_Dst == (void *)0x0)) {
    if (0 < param_3) {
      if (_Dst != (void *)0x0) goto LAB_140005da0;
      qBadAlloc();
    }
LAB_140005e68:
    lVar3 = param_1[2];
    if (lVar3 != 0) {
      lVar3 = lVar3 + param_3;
      goto LAB_140005dad;
    }
LAB_140005e71:
    _Src = (void *)param_1[1];
    lVar6 = 0;
  }
  else {
    lVar3 = *param_1;
    if (param_2 == 1) {
      lVar6 = ((*(longlong *)(local_40[0] + 8) - param_1[2]) - param_3) / 2;
      if (lVar6 < 0) {
        lVar6 = 0;
      }
      _Dst = (void *)((longlong)_Dst + (lVar6 + param_3) * 8);
      if (lVar3 == 0) goto LAB_140005f73;
LAB_140005d8f:
      uVar2 = *(undefined4 *)(lVar3 + 4);
    }
    else {
      if (lVar3 != 0) {
        _Dst = (void *)((longlong)_Dst + (param_1[1] - (lVar3 + 0x1fU & 0xfffffffffffffff0)));
        goto LAB_140005d8f;
      }
LAB_140005f73:
      uVar2 = 0;
    }
    *(undefined4 *)(local_40[0] + 4) = uVar2;
    if (param_3 < 1) goto LAB_140005e68;
LAB_140005da0:
    lVar3 = param_1[2];
    if (lVar3 == 0) goto LAB_140005e71;
LAB_140005dad:
    _Size = lVar3 * 8;
    lVar3 = (longlong)_Size >> 3;
    if ((((int *)*param_1 != (int *)0x0) && (*(int *)*param_1 < 2)) &&
       (param_4 == (undefined8 *)0x0)) {
      lVar6 = 0;
      if (_Size != 0) {
        _Dst = memcpy(_Dst,(void *)param_1[1],_Size);
        lVar6 = lVar3;
      }
      piVar7 = (int *)*param_1;
      param_1[1] = (longlong)_Dst;
      *param_1 = local_40[0];
      param_1[2] = lVar6;
      goto LAB_140005e17;
    }
    _Src = (void *)param_1[1];
    if (_Size == 0) {
      lVar6 = param_1[2];
      lVar3 = 0;
    }
    else {
      _Dst = memcpy(_Dst,_Src,_Size);
      lVar6 = param_1[2];
    }
  }
  piVar1 = (int *)*param_1;
  *param_1 = local_40[0];
  param_1[1] = (longlong)_Dst;
  param_1[2] = lVar3;
  piVar7 = piVar1;
  if (param_4 != (undefined8 *)0x0) {
    piVar7 = (int *)*param_4;
    param_4[1] = _Src;
    *param_4 = piVar1;
    param_4[2] = lVar6;
  }
LAB_140005e17:
  if (piVar7 != (int *)0x0) {
    LOCK();
    *piVar7 = *piVar7 + -1;
    UNLOCK();
    if (*piVar7 == 0) {
      free(piVar7);
      return;
    }
  }
  return;
}



void FUN_140005fc0(undefined8 *param_1)

{
  int *piVar1;
  
  piVar1 = (int *)*param_1;
  if (piVar1 != (int *)0x0) {
    LOCK();
    *piVar1 = *piVar1 + -1;
    UNLOCK();
    if (*piVar1 == 0) {
      free((void *)*param_1);
      return;
    }
  }
  return;
}



void FUN_140005fe0(undefined8 param_1,char *param_2)

{
  size_t local_28;
  char *local_20;
  
  local_28 = 0;
  if (param_2 != (char *)0x0) {
    local_28 = strlen(param_2);
  }
  local_20 = param_2;
  QString::fromUtf8(param_1,&local_28);
  return;
}



void FUN_140006020(QWidget *param_1)

{
  *(undefined ***)param_1 = &PTR_FUN_14001f1d0;
  *(undefined ***)(param_1 + 0x10) = &PTR_FUN_14001f380;
  QWidget::~QWidget(param_1);
  operator_delete(param_1,0x68);
  return;
}



void FUN_140006060(QWidget *param_1)

{
  *(undefined ***)param_1 = &PTR_FUN_14001f1d0;
  *(undefined ***)(param_1 + 0x10) = &PTR_FUN_14001f380;
                    // WARNING: Could not recover jumptable at 0x000140006074. Too many branches
                    // WARNING: Treating indirect jump as call
  QWidget::~QWidget(param_1);
  return;
}



void FUN_140006080(longlong *param_1,longlong param_2,undefined8 *param_3)

{
  int *piVar1;
  bool bVar2;
  longlong lVar3;
  undefined8 *_Dst;
  longlong lVar4;
  ulonglong uVar5;
  undefined8 *puVar6;
  uint uVar7;
  longlong lVar8;
  ulonglong uVar9;
  longlong lVar10;
  undefined8 uVar11;
  
  piVar1 = (int *)*param_1;
  if (piVar1 == (int *)0x0) {
    uVar11 = *param_3;
    uVar7 = (uint)(param_2 == 0);
    if (param_1[2] == 0) {
      uVar7 = 0;
    }
    goto LAB_14000625e;
  }
  if (*piVar1 < 2) {
    lVar3 = param_1[2];
    uVar11 = *param_3;
    if (lVar3 == param_2) {
      uVar5 = param_1[1];
      uVar9 = (longlong)piVar1 + 0x1fU & 0xfffffffffffffff0;
      if (lVar3 != *(longlong *)(piVar1 + 2) - ((longlong)(uVar5 - uVar9) >> 3)) {
        *(undefined8 *)(uVar5 + lVar3 * 8) = uVar11;
        param_1[2] = lVar3 + 1;
        return;
      }
      if ((lVar3 == 0) && (uVar5 != uVar9)) {
LAB_1400062e8:
        *(undefined8 *)(uVar5 - 8) = uVar11;
        param_1[1] = uVar5 - 8;
        param_1[2] = lVar3 + 1;
        return;
      }
    }
    else {
      if (param_2 != 0) goto LAB_1400060c0;
      uVar5 = param_1[1];
      if (uVar5 != ((longlong)piVar1 + 0x1fU & 0xfffffffffffffff0)) goto LAB_1400062e8;
      if (lVar3 != 0) goto LAB_1400061c7;
    }
LAB_1400060c9:
    uVar7 = 0;
    bVar2 = false;
    if ((1 < *piVar1) || (lVar3 = *param_1, lVar3 == 0)) goto LAB_14000625e;
    puVar6 = (undefined8 *)param_1[1];
    lVar4 = *(longlong *)(lVar3 + 8);
    lVar8 = param_1[2];
    lVar10 = (longlong)puVar6 - (lVar3 + 0x1fU & 0xfffffffffffffff0);
    lVar3 = lVar10 >> 3;
    if (lVar4 - lVar3 <= lVar8) {
      if ((0 < lVar10) && (uVar7 = 0, SBORROW8(lVar8 * 3,lVar4 * 2) != lVar8 * 3 + lVar4 * -2 < 0))
      {
        lVar4 = 0;
        goto LAB_14000612d;
      }
      goto LAB_14000625e;
    }
    puVar6 = puVar6 + param_2;
joined_r0x000140006307:
    if (param_2 < lVar8) {
      memmove(puVar6 + 1,puVar6,(lVar8 - param_2) * 8);
      lVar8 = param_1[2];
    }
  }
  else {
    uVar11 = *param_3;
    if ((param_1[2] == 0) || (param_2 != 0)) {
LAB_1400060c0:
      if (piVar1 != (int *)0x0) goto LAB_1400060c9;
      uVar7 = 0;
LAB_14000625e:
      FUN_140005c60(param_1,uVar7,1,(undefined8 *)0x0);
      _Dst = (undefined8 *)param_1[1];
      lVar8 = param_1[2];
      puVar6 = _Dst + param_2;
      if (uVar7 == 0) goto joined_r0x000140006307;
    }
    else {
LAB_1400061c7:
      uVar7 = 1;
      bVar2 = true;
      if ((1 < *piVar1) || (lVar4 = *param_1, lVar4 == 0)) goto LAB_14000625e;
      _Dst = (undefined8 *)param_1[1];
      lVar3 = (longlong)_Dst - (lVar4 + 0x1fU & 0xfffffffffffffff0);
      lVar8 = param_1[2];
      puVar6 = _Dst;
      if (lVar3 < 1) {
        lVar4 = *(longlong *)(lVar4 + 8);
        lVar3 = lVar3 >> 3;
        if ((lVar4 - lVar3 <= lVar8) || (lVar4 <= lVar8 * 3)) goto LAB_14000625e;
        lVar4 = ((lVar4 - lVar8) + -1) / 2;
        if (lVar4 < 0) {
          lVar4 = 0;
        }
        lVar4 = lVar4 + 1;
LAB_14000612d:
        _Dst = puVar6 + (lVar4 - lVar3);
        if ((((lVar8 != 0) && (puVar6 != _Dst)) && (puVar6 != (undefined8 *)0x0)) &&
           (_Dst != (undefined8 *)0x0)) {
          _Dst = (undefined8 *)memmove(_Dst,puVar6,lVar8 << 3);
          lVar8 = param_1[2];
        }
        param_1[1] = (longlong)_Dst;
        puVar6 = _Dst + param_2;
        if (!bVar2) goto joined_r0x000140006307;
      }
    }
    puVar6 = puVar6 + -1;
    param_1[1] = (longlong)(_Dst + -1);
  }
  param_1[2] = lVar8 + 1;
  *puVar6 = uVar11;
  return;
}



void FUN_140006340(int param_1,void *param_2,longlong param_3,longlong *param_4,undefined1 *param_5)

{
  code *UNRECOVERED_JUMPTABLE;
  longlong *plVar1;
  
  if (param_1 == 1) {
    UNRECOVERED_JUMPTABLE = *(code **)((longlong)param_2 + 0x10);
    plVar1 = (longlong *)(param_3 + *(longlong *)((longlong)param_2 + 0x18));
    if (((ulonglong)UNRECOVERED_JUMPTABLE & 1) != 0) {
      UNRECOVERED_JUMPTABLE = *(code **)(UNRECOVERED_JUMPTABLE + *plVar1 + -1);
    }
                    // WARNING: Could not recover jumptable at 0x00014000639f. Too many branches
                    // WARNING: Treating indirect jump as call
    (*UNRECOVERED_JUMPTABLE)(plVar1);
    return;
  }
  if (param_1 != 2) {
    if ((param_1 == 0) && (param_2 != (void *)0x0)) {
      operator_delete(param_2,0x20);
      return;
    }
    return;
  }
  if (*param_4 == *(longlong *)((longlong)param_2 + 0x10)) {
    *param_5 = param_4[1] == *(longlong *)((longlong)param_2 + 0x18) || *param_4 == 0;
  }
  else {
    *param_5 = 0;
  }
  return;
}



void FUN_1400063c0(int param_1,void *param_2,longlong param_3,longlong *param_4,undefined1 *param_5)

{
  undefined8 *puVar1;
  longlong *plVar2;
  code *pcVar3;
  int *local_38;
  undefined8 local_30;
  undefined8 local_28;
  
  if (param_1 == 1) {
    pcVar3 = *(code **)((longlong)param_2 + 0x10);
    plVar2 = (longlong *)(param_3 + *(longlong *)((longlong)param_2 + 0x18));
    if (((ulonglong)pcVar3 & 1) != 0) {
      pcVar3 = *(code **)(pcVar3 + *plVar2 + -1);
    }
    puVar1 = (undefined8 *)param_4[1];
    local_38 = (int *)*puVar1;
    local_30 = puVar1[1];
    local_28 = puVar1[2];
    if (local_38 != (int *)0x0) {
      LOCK();
      *local_38 = *local_38 + 1;
      UNLOCK();
    }
    (*pcVar3)(plVar2,&local_38);
    if (local_38 != (int *)0x0) {
      LOCK();
      *local_38 = *local_38 + -1;
      UNLOCK();
      if (*local_38 == 0) {
        free(local_38);
      }
    }
  }
  else {
    if (param_1 == 2) {
      if (*param_4 == *(longlong *)((longlong)param_2 + 0x10)) {
        *param_5 = param_4[1] == *(longlong *)((longlong)param_2 + 0x18) || *param_4 == 0;
      }
      else {
        *param_5 = 0;
      }
      return;
    }
    if ((param_1 == 0) && (param_2 != (void *)0x0)) {
      operator_delete(param_2,0x20);
      return;
    }
  }
  return;
}



undefined * FUN_1400064d0(void)

{
  return &DAT_14001e700;
}



undefined * FUN_1400064e0(void)

{
  return &DAT_14001e540;
}



undefined8 FUN_1400064f0(undefined8 param_1,longlong param_2,longlong param_3)

{
  undefined8 uVar1;
  longlong local_28;
  undefined8 local_20;
  longlong local_18;
  undefined8 local_10;
  
  uVar1 = 0;
  local_28 = *(longlong *)(param_2 + 0x10);
  if (local_28 == *(longlong *)(param_3 + 0x10)) {
    local_10 = *(undefined8 *)(param_2 + 8);
    local_20 = *(undefined8 *)(param_3 + 8);
    local_18 = local_28;
    uVar1 = QtPrivate::equalStrings(&local_18,&local_28);
  }
  return uVar1;
}



uint FUN_140006540(undefined8 param_1,longlong param_2,longlong param_3)

{
  uint uVar1;
  undefined8 local_28;
  undefined8 local_20;
  undefined8 local_18;
  undefined8 local_10;
  
  local_28 = *(undefined8 *)(param_3 + 0x10);
  local_20 = *(undefined8 *)(param_3 + 8);
  local_18 = *(undefined8 *)(param_2 + 0x10);
  local_10 = *(undefined8 *)(param_2 + 8);
  uVar1 = QtPrivate::compareStrings(&local_18,&local_28,1);
  return uVar1 >> 0x1f;
}



void FUN_140006590(undefined8 param_1,QDataStream *param_2,QString *param_3)

{
                    // WARNING: Could not recover jumptable at 0x000140006596. Too many branches
                    // WARNING: Treating indirect jump as call
  operator>>(param_2,param_3);
  return;
}



void FUN_1400065a0(undefined8 param_1,QDataStream *param_2,QString *param_3)

{
                    // WARNING: Could not recover jumptable at 0x0001400065a6. Too many branches
                    // WARNING: Treating indirect jump as call
  operator<<(param_2,param_3);
  return;
}



void FUN_1400065b0(undefined8 param_1,QChar *param_2,longlong param_3)

{
  code *pcVar1;
  
  pcVar1 = *(code **)(param_3 + 8);
  if (*(code **)(param_3 + 8) == (code *)0x0) {
    pcVar1 = _empty_exref;
  }
  QDebug::putString(param_2,(ulonglong)pcVar1);
  if ((*(QTextStream **)param_2)[0x30] == (QTextStream)0x0) {
    return;
  }
                    // WARNING: Could not recover jumptable at 0x0001400065f2. Too many branches
                    // WARNING: Treating indirect jump as call
  QTextStream::operator<<(*(QTextStream **)param_2,' ');
  return;
}



void FUN_140006600(QWidget *param_1)

{
  int *piVar1;
  
  *(undefined ***)param_1 = &PTR_LAB_14001f3d0;
  *(undefined ***)(param_1 + 0x10) = &PTR_FUN_14001f580;
  piVar1 = *(int **)(param_1 + 0x40);
  if (piVar1 != (int *)0x0) {
    LOCK();
    *piVar1 = *piVar1 + -1;
    UNLOCK();
    if (*piVar1 == 0) {
      free(*(void **)(param_1 + 0x40));
    }
  }
  piVar1 = *(int **)(param_1 + 0x28);
  if (piVar1 != (int *)0x0) {
    LOCK();
    *piVar1 = *piVar1 + -1;
    UNLOCK();
    if (*piVar1 == 0) {
      free(*(void **)(param_1 + 0x28));
    }
  }
  QWidget::~QWidget(param_1);
  operator_delete(param_1,0x58);
  return;
}



void FUN_140006680(QWidget *param_1)

{
  int *piVar1;
  
  *(undefined ***)param_1 = &PTR_LAB_14001f3d0;
  *(undefined ***)(param_1 + 0x10) = &PTR_FUN_14001f580;
  piVar1 = *(int **)(param_1 + 0x40);
  if (piVar1 != (int *)0x0) {
    LOCK();
    *piVar1 = *piVar1 + -1;
    UNLOCK();
    if (*piVar1 == 0) {
      free(*(void **)(param_1 + 0x40));
    }
  }
  piVar1 = *(int **)(param_1 + 0x28);
  if (piVar1 != (int *)0x0) {
    LOCK();
    *piVar1 = *piVar1 + -1;
    UNLOCK();
    if (*piVar1 == 0) {
      free(*(void **)(param_1 + 0x28));
                    // WARNING: Could not recover jumptable at 0x0001400066e3. Too many branches
                    // WARNING: Treating indirect jump as call
      QWidget::~QWidget(param_1);
      return;
    }
  }
                    // WARNING: Could not recover jumptable at 0x0001400066c5. Too many branches
                    // WARNING: Treating indirect jump as call
  QWidget::~QWidget(param_1);
  return;
}



void FUN_140006700(undefined8 *param_1)

{
  param_1[-2] = &PTR_FUN_14001efc0;
  *param_1 = &PTR_FUN_14001f178;
  QMainWindow::~QMainWindow((QMainWindow *)(param_1 + -2));
  operator_delete((QMainWindow *)(param_1 + -2),0x48);
  return;
}



void FUN_140006740(undefined8 *param_1)

{
  param_1[-2] = &PTR_FUN_14001efc0;
  *param_1 = &PTR_FUN_14001f178;
                    // WARNING: Could not recover jumptable at 0x000140006759. Too many branches
                    // WARNING: Treating indirect jump as call
  QMainWindow::~QMainWindow((QMainWindow *)(param_1 + -2));
  return;
}



void FUN_140006760(undefined8 *param_1)

{
  param_1[-2] = &PTR_FUN_14001f1d0;
  *param_1 = &PTR_FUN_14001f380;
  QWidget::~QWidget((QWidget *)(param_1 + -2));
  operator_delete((QWidget *)(param_1 + -2),0x68);
  return;
}



void FUN_1400067a0(undefined8 *param_1)

{
  param_1[-2] = &PTR_FUN_14001f1d0;
  *param_1 = &PTR_FUN_14001f380;
                    // WARNING: Could not recover jumptable at 0x0001400067b9. Too many branches
                    // WARNING: Treating indirect jump as call
  QWidget::~QWidget((QWidget *)(param_1 + -2));
  return;
}



void FUN_1400067c0(undefined8 *param_1)

{
  int *piVar1;
  
  param_1[-2] = &PTR_LAB_14001f3d0;
  *param_1 = &PTR_FUN_14001f580;
  piVar1 = (int *)param_1[6];
  if (piVar1 != (int *)0x0) {
    LOCK();
    *piVar1 = *piVar1 + -1;
    UNLOCK();
    if (*piVar1 == 0) {
      free((void *)param_1[6]);
    }
  }
  piVar1 = (int *)param_1[3];
  if (piVar1 != (int *)0x0) {
    LOCK();
    *piVar1 = *piVar1 + -1;
    UNLOCK();
    if (*piVar1 == 0) {
      free((void *)param_1[3]);
    }
  }
  QWidget::~QWidget((QWidget *)(param_1 + -2));
  operator_delete((QWidget *)(param_1 + -2),0x58);
  return;
}



void FUN_140006840(undefined8 *param_1)

{
  int *piVar1;
  
  param_1[-2] = &PTR_LAB_14001f3d0;
  *param_1 = &PTR_FUN_14001f580;
  piVar1 = (int *)param_1[6];
  if (piVar1 != (int *)0x0) {
    LOCK();
    *piVar1 = *piVar1 + -1;
    UNLOCK();
    if (*piVar1 == 0) {
      free((void *)param_1[6]);
    }
  }
  piVar1 = (int *)param_1[3];
  if (piVar1 != (int *)0x0) {
    LOCK();
    *piVar1 = *piVar1 + -1;
    UNLOCK();
    if (*piVar1 == 0) {
      free((void *)param_1[3]);
                    // WARNING: Could not recover jumptable at 0x0001400068a2. Too many branches
                    // WARNING: Treating indirect jump as call
      QWidget::~QWidget((QWidget *)(param_1 + -2));
      return;
    }
  }
                    // WARNING: Could not recover jumptable at 0x000140006883. Too many branches
                    // WARNING: Treating indirect jump as call
  QWidget::~QWidget((QWidget *)(param_1 + -2));
  return;
}



void FUN_1400068c0(undefined8 param_1,QString *param_2,undefined8 param_3,undefined8 param_4)

{
  FUN_1400030f0(param_2,0,param_3,param_4);
  return;
}



void FUN_1400068d0(undefined8 param_1,longlong *param_2)

{
                    // WARNING: Could not recover jumptable at 0x0001400068d6. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_2 + 0x18))(param_2);
  return;
}



void FUN_1400068e0(undefined8 param_1,undefined8 *param_2,undefined8 *param_3)

{
  int *piVar1;
  undefined8 uVar2;
  
  piVar1 = (int *)*param_3;
  param_2[1] = param_3[1];
  uVar2 = param_3[2];
  *param_2 = piVar1;
  param_2[2] = uVar2;
  if (piVar1 != (int *)0x0) {
    LOCK();
    *piVar1 = *piVar1 + 1;
    UNLOCK();
  }
  return;
}



void FUN_140006900(undefined8 param_1,undefined8 *param_2,undefined8 *param_3)

{
  undefined8 uVar1;
  
  *param_2 = *param_3;
  uVar1 = param_3[1];
  *param_3 = 0;
  param_3[1] = 0;
  param_2[1] = uVar1;
  uVar1 = param_3[2];
  param_3[2] = 0;
  param_2[2] = uVar1;
  return;
}



void FUN_140006930(undefined8 param_1,undefined8 *param_2)

{
  *param_2 = 0;
  param_2[1] = 0;
  param_2[2] = 0;
  return;
}



void FUN_140006950(undefined8 param_1,undefined8 *param_2)

{
  int *piVar1;
  
  piVar1 = (int *)*param_2;
  if (piVar1 != (int *)0x0) {
    LOCK();
    *piVar1 = *piVar1 + -1;
    UNLOCK();
    if (*piVar1 == 0) {
      free((void *)*param_2);
      return;
    }
  }
  return;
}



void FUN_140006970(undefined8 param_1,QObject *param_2,undefined8 param_3,undefined8 param_4)

{
  FUN_140002840(param_2,param_2,param_3,param_4);
  return;
}



void FUN_140006980(undefined8 param_1,longlong *param_2)

{
                    // WARNING: Could not recover jumptable at 0x000140006986. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_2 + 0x18))(param_2);
  return;
}



void FUN_140006990(void)

{
  QString local_38 [32];
  
  FUN_140005fe0(local_38,"XSSNAKE");
  QFont::QFont((QFont *)&DAT_140023090,local_38,0xc,-1,false);
  FUN_140005c40((undefined8 *)local_38);
  FUN_1400014f0(FUN_140001860);
  FUN_140005fe0(local_38,"XSSNAKE");
  QFont::QFont((QFont *)&DAT_140023080,local_38,0x24,-1,false);
  FUN_140005c40((undefined8 *)local_38);
  FUN_1400014f0(FUN_140001850);
  FUN_140005fe0(local_38,"XSSNAKE");
  QFont::QFont((QFont *)&DAT_140023070,local_38,0x14,-1,false);
  FUN_140005c40((undefined8 *)local_38);
  FUN_1400014f0(FUN_140001840);
  FUN_140005fe0(local_38,"XSSNAKE");
  QFont::QFont((QFont *)&DAT_140023060,local_38,0x24,-1,false);
  FUN_140005c40((undefined8 *)local_38);
  FUN_1400014f0(FUN_140001830);
  FUN_140005fe0(local_38,"XSSNAKE");
  QFont::QFont((QFont *)&DAT_140023050,local_38,0xf,-1,false);
  FUN_140005c40((undefined8 *)local_38);
  FUN_1400014f0(FUN_140001820);
  FUN_140005fe0(&DAT_140023030,"#a0c54e");
  FUN_1400014f0(FUN_140001870);
  return;
}



void FUN_140006b30(void)

{
  undefined8 local_18;
  char *local_10;
  
  local_18 = 7;
  local_10 = "#a0c54e";
  QString::fromUtf8(&DAT_1400230a0,&local_18);
  FUN_1400014f0(FUN_1400030c0);
  return;
}



void FUN_140006b70(void)

{
  QString local_38 [32];
  
  FUN_140005fe0(local_38,"XSSNAKE");
  QFont::QFont((QFont *)&DAT_140023100,local_38,0xc,-1,false);
  FUN_140005c40((undefined8 *)local_38);
  FUN_1400014f0(FUN_140003b20);
  FUN_140005fe0(local_38,"XSSNAKE");
  QFont::QFont((QFont *)&DAT_1400230f0,local_38,0x24,-1,false);
  FUN_140005c40((undefined8 *)local_38);
  FUN_1400014f0(FUN_140003b10);
  FUN_140005fe0(local_38,"XSSNAKE");
  QFont::QFont((QFont *)&DAT_1400230e0,local_38,0x14,-1,false);
  FUN_140005c40((undefined8 *)local_38);
  FUN_1400014f0(FUN_140003b00);
  FUN_140005fe0(local_38,"XSSNAKE");
  QFont::QFont((QFont *)&DAT_1400230d0,local_38,0x24,-1,false);
  FUN_140005c40((undefined8 *)local_38);
  FUN_1400014f0(FUN_140003af0);
  FUN_140005fe0(local_38,"XSSNAKE");
  QFont::QFont((QFont *)&DAT_1400230c0,local_38,0xf,-1,false);
  FUN_140005c40((undefined8 *)local_38);
  FUN_1400014f0(FUN_140003ae0);
  return;
}



void FUN_140006cf0(void)

{
  FUN_140003df0();
  FUN_1400014f0(FUN_140003dc0);
  return;
}



void FUN_140006d10(void)

{
  FUN_140004730();
  thunk_FUN_1400057c0();
  return;
}



void thunk_FUN_140001510(void)

{
  FUN_1400014f0(FUN_140001520);
  return;
}


