typedef unsigned char   undefined;

typedef unsigned char    bool;
typedef unsigned char    byte;
typedef unsigned int    dword;
typedef pointer32 ImageBaseOffset32;

typedef long long    longlong;
typedef unsigned long long    qword;
typedef unsigned char    uchar;
typedef unsigned int    uint;
typedef unsigned long    ulong;
typedef unsigned long long    ulonglong;
typedef unsigned char    undefined1;
typedef unsigned short    undefined2;
typedef unsigned int    undefined4;
typedef unsigned long long    undefined8;
typedef unsigned short    ushort;
typedef short    wchar_t;
typedef unsigned short    word;
#define unkbyte9   unsigned long long
#define unkbyte10   unsigned long long
#define unkbyte11   unsigned long long
#define unkbyte12   unsigned long long
#define unkbyte13   unsigned long long
#define unkbyte14   unsigned long long
#define unkbyte15   unsigned long long
#define unkbyte16   unsigned long long

#define unkuint9   unsigned long long
#define unkuint10   unsigned long long
#define unkuint11   unsigned long long
#define unkuint12   unsigned long long
#define unkuint13   unsigned long long
#define unkuint14   unsigned long long
#define unkuint15   unsigned long long
#define unkuint16   unsigned long long

#define unkint9   long long
#define unkint10   long long
#define unkint11   long long
#define unkint12   long long
#define unkint13   long long
#define unkint14   long long
#define unkint15   long long
#define unkint16   long long

#define unkfloat1   float
#define unkfloat2   float
#define unkfloat3   float
#define unkfloat5   double
#define unkfloat6   double
#define unkfloat7   double
#define unkfloat9   long double
#define unkfloat11   long double
#define unkfloat12   long double
#define unkfloat13   long double
#define unkfloat14   long double
#define unkfloat15   long double
#define unkfloat16   long double

#define BADSPACEBASE   void
#define code   void

typedef unsigned short    wchar16;
typedef struct _IMAGE_RUNTIME_FUNCTION_ENTRY _IMAGE_RUNTIME_FUNCTION_ENTRY, *P_IMAGE_RUNTIME_FUNCTION_ENTRY;

struct _IMAGE_RUNTIME_FUNCTION_ENTRY {
    ImageBaseOffset32 BeginAddress;
    dword EndAddress; // Apply ImageBaseOffset32 to see reference
    ImageBaseOffset32 UnwindInfoAddressOrData;
};

typedef struct _STARTUPINFOA _STARTUPINFOA, *P_STARTUPINFOA;

typedef ulong DWORD;

typedef char CHAR;

typedef CHAR *LPSTR;

typedef ushort WORD;

typedef uchar BYTE;

typedef BYTE *LPBYTE;

typedef void *HANDLE;

struct _STARTUPINFOA {
    DWORD cb;
    LPSTR lpReserved;
    LPSTR lpDesktop;
    LPSTR lpTitle;
    DWORD dwX;
    DWORD dwY;
    DWORD dwXSize;
    DWORD dwYSize;
    DWORD dwXCountChars;
    DWORD dwYCountChars;
    DWORD dwFillAttribute;
    DWORD dwFlags;
    WORD wShowWindow;
    WORD cbReserved2;
    LPBYTE lpReserved2;
    HANDLE hStdInput;
    HANDLE hStdOutput;
    HANDLE hStdError;
};

typedef struct _STARTUPINFOA *LPSTARTUPINFOA;

typedef struct _RTL_CRITICAL_SECTION _RTL_CRITICAL_SECTION, *P_RTL_CRITICAL_SECTION;

typedef struct _RTL_CRITICAL_SECTION *PRTL_CRITICAL_SECTION;

typedef PRTL_CRITICAL_SECTION LPCRITICAL_SECTION;

typedef struct _RTL_CRITICAL_SECTION_DEBUG _RTL_CRITICAL_SECTION_DEBUG, *P_RTL_CRITICAL_SECTION_DEBUG;

typedef struct _RTL_CRITICAL_SECTION_DEBUG *PRTL_CRITICAL_SECTION_DEBUG;

typedef long LONG;

typedef ulonglong ULONG_PTR;

typedef struct _LIST_ENTRY _LIST_ENTRY, *P_LIST_ENTRY;

typedef struct _LIST_ENTRY LIST_ENTRY;

struct _RTL_CRITICAL_SECTION {
    PRTL_CRITICAL_SECTION_DEBUG DebugInfo;
    LONG LockCount;
    LONG RecursionCount;
    HANDLE OwningThread;
    HANDLE LockSemaphore;
    ULONG_PTR SpinCount;
};

struct _LIST_ENTRY {
    struct _LIST_ENTRY *Flink;
    struct _LIST_ENTRY *Blink;
};

struct _RTL_CRITICAL_SECTION_DEBUG {
    WORD Type;
    WORD CreatorBackTraceIndex;
    struct _RTL_CRITICAL_SECTION *CriticalSection;
    LIST_ENTRY ProcessLocksList;
    DWORD EntryCount;
    DWORD ContentionCount;
    DWORD Flags;
    WORD CreatorBackTraceIndexHigh;
    WORD SpareWORD;
};

typedef struct _EXCEPTION_POINTERS _EXCEPTION_POINTERS, *P_EXCEPTION_POINTERS;

typedef LONG (*PTOP_LEVEL_EXCEPTION_FILTER)(struct _EXCEPTION_POINTERS *);

typedef struct _EXCEPTION_RECORD _EXCEPTION_RECORD, *P_EXCEPTION_RECORD;

typedef struct _EXCEPTION_RECORD EXCEPTION_RECORD;

typedef EXCEPTION_RECORD *PEXCEPTION_RECORD;

typedef struct _CONTEXT _CONTEXT, *P_CONTEXT;

typedef struct _CONTEXT *PCONTEXT;

typedef void *PVOID;

typedef ulonglong DWORD64;

typedef union _union_54 _union_54, *P_union_54;

typedef struct _M128A _M128A, *P_M128A;

typedef struct _M128A M128A;

typedef struct _XSAVE_FORMAT _XSAVE_FORMAT, *P_XSAVE_FORMAT;

typedef struct _XSAVE_FORMAT XSAVE_FORMAT;

typedef XSAVE_FORMAT XMM_SAVE_AREA32;

typedef struct _struct_55 _struct_55, *P_struct_55;

typedef ulonglong ULONGLONG;

typedef longlong LONGLONG;

struct _M128A {
    ULONGLONG Low;
    LONGLONG High;
};

struct _XSAVE_FORMAT {
    WORD ControlWord;
    WORD StatusWord;
    BYTE TagWord;
    BYTE Reserved1;
    WORD ErrorOpcode;
    DWORD ErrorOffset;
    WORD ErrorSelector;
    WORD Reserved2;
    DWORD DataOffset;
    WORD DataSelector;
    WORD Reserved3;
    DWORD MxCsr;
    DWORD MxCsr_Mask;
    M128A FloatRegisters[8];
    M128A XmmRegisters[16];
    BYTE Reserved4[96];
};

struct _struct_55 {
    M128A Header[2];
    M128A Legacy[8];
    M128A Xmm0;
    M128A Xmm1;
    M128A Xmm2;
    M128A Xmm3;
    M128A Xmm4;
    M128A Xmm5;
    M128A Xmm6;
    M128A Xmm7;
    M128A Xmm8;
    M128A Xmm9;
    M128A Xmm10;
    M128A Xmm11;
    M128A Xmm12;
    M128A Xmm13;
    M128A Xmm14;
    M128A Xmm15;
};

union _union_54 {
    XMM_SAVE_AREA32 FltSave;
    struct _struct_55 s;
};

struct _CONTEXT {
    DWORD64 P1Home;
    DWORD64 P2Home;
    DWORD64 P3Home;
    DWORD64 P4Home;
    DWORD64 P5Home;
    DWORD64 P6Home;
    DWORD ContextFlags;
    DWORD MxCsr;
    WORD SegCs;
    WORD SegDs;
    WORD SegEs;
    WORD SegFs;
    WORD SegGs;
    WORD SegSs;
    DWORD EFlags;
    DWORD64 Dr0;
    DWORD64 Dr1;
    DWORD64 Dr2;
    DWORD64 Dr3;
    DWORD64 Dr6;
    DWORD64 Dr7;
    DWORD64 Rax;
    DWORD64 Rcx;
    DWORD64 Rdx;
    DWORD64 Rbx;
    DWORD64 Rsp;
    DWORD64 Rbp;
    DWORD64 Rsi;
    DWORD64 Rdi;
    DWORD64 R8;
    DWORD64 R9;
    DWORD64 R10;
    DWORD64 R11;
    DWORD64 R12;
    DWORD64 R13;
    DWORD64 R14;
    DWORD64 R15;
    DWORD64 Rip;
    union _union_54 u;
    M128A VectorRegister[26];
    DWORD64 VectorControl;
    DWORD64 DebugControl;
    DWORD64 LastBranchToRip;
    DWORD64 LastBranchFromRip;
    DWORD64 LastExceptionToRip;
    DWORD64 LastExceptionFromRip;
};

struct _EXCEPTION_RECORD {
    DWORD ExceptionCode;
    DWORD ExceptionFlags;
    struct _EXCEPTION_RECORD *ExceptionRecord;
    PVOID ExceptionAddress;
    DWORD NumberParameters;
    ULONG_PTR ExceptionInformation[15];
};

struct _EXCEPTION_POINTERS {
    PEXCEPTION_RECORD ExceptionRecord;
    PCONTEXT ContextRecord;
};

typedef PTOP_LEVEL_EXCEPTION_FILTER LPTOP_LEVEL_EXCEPTION_FILTER;

typedef struct _iobuf _iobuf, *P_iobuf;

struct _iobuf {
    char *_ptr;
    int _cnt;
    char *_base;
    int _flag;
    int _file;
    int _charbuf;
    int _bufsiz;
    char *_tmpfname;
};

typedef struct _iobuf FILE;

typedef char *va_list;

typedef ulonglong size_t;

typedef struct _MEMORY_BASIC_INFORMATION _MEMORY_BASIC_INFORMATION, *P_MEMORY_BASIC_INFORMATION;

typedef ULONG_PTR SIZE_T;

struct _MEMORY_BASIC_INFORMATION {
    PVOID BaseAddress;
    PVOID AllocationBase;
    DWORD AllocationProtect;
    SIZE_T RegionSize;
    DWORD State;
    DWORD Protect;
    DWORD Type;
};

typedef wchar_t WCHAR;

typedef WCHAR *LPWSTR;

typedef WCHAR *LPCWSTR;

typedef CHAR *LPCSTR;

typedef struct _MEMORY_BASIC_INFORMATION *PMEMORY_BASIC_INFORMATION;

typedef struct IMAGE_DOS_HEADER IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

struct IMAGE_DOS_HEADER {
    char e_magic[2]; // Magic number
    word e_cblp; // Bytes of last page
    word e_cp; // Pages in file
    word e_crlc; // Relocations
    word e_cparhdr; // Size of header in paragraphs
    word e_minalloc; // Minimum extra paragraphs needed
    word e_maxalloc; // Maximum extra paragraphs needed
    word e_ss; // Initial (relative) SS value
    word e_sp; // Initial SP value
    word e_csum; // Checksum
    word e_ip; // Initial IP value
    word e_cs; // Initial (relative) CS value
    word e_lfarlc; // File address of relocation table
    word e_ovno; // Overlay number
    word e_res[4][4]; // Reserved words
    word e_oemid; // OEM identifier (for e_oeminfo)
    word e_oeminfo; // OEM information; e_oemid specific
    word e_res2[10][10]; // Reserved words
    dword e_lfanew; // File address of new exe header
    byte e_program[64]; // Actual DOS program
};

typedef DWORD *PDWORD;

typedef int BOOL;

typedef BOOL *LPBOOL;

typedef void *LPCVOID;

typedef void *LPVOID;

typedef HANDLE HLOCAL;

typedef uint UINT;

typedef struct IMAGE_OPTIONAL_HEADER64 IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef struct IMAGE_DATA_DIRECTORY IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

struct IMAGE_DATA_DIRECTORY {
    ImageBaseOffset32 VirtualAddress;
    dword Size;
};

struct IMAGE_OPTIONAL_HEADER64 {
    word Magic;
    byte MajorLinkerVersion;
    byte MinorLinkerVersion;
    dword SizeOfCode;
    dword SizeOfInitializedData;
    dword SizeOfUninitializedData;
    ImageBaseOffset32 AddressOfEntryPoint;
    ImageBaseOffset32 BaseOfCode;
    pointer64 ImageBase;
    dword SectionAlignment;
    dword FileAlignment;
    word MajorOperatingSystemVersion;
    word MinorOperatingSystemVersion;
    word MajorImageVersion;
    word MinorImageVersion;
    word MajorSubsystemVersion;
    word MinorSubsystemVersion;
    dword Win32VersionValue;
    dword SizeOfImage;
    dword SizeOfHeaders;
    dword CheckSum;
    word Subsystem;
    word DllCharacteristics;
    qword SizeOfStackReserve;
    qword SizeOfStackCommit;
    qword SizeOfHeapReserve;
    qword SizeOfHeapCommit;
    dword LoaderFlags;
    dword NumberOfRvaAndSizes;
    struct IMAGE_DATA_DIRECTORY DataDirectory[16];
};

typedef struct IMAGE_SECTION_HEADER IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef union Misc Misc, *PMisc;

typedef enum SectionFlags {
    IMAGE_SCN_TYPE_NO_PAD=8,
    IMAGE_SCN_RESERVED_0001=16,
    IMAGE_SCN_CNT_CODE=32,
    IMAGE_SCN_CNT_INITIALIZED_DATA=64,
    IMAGE_SCN_CNT_UNINITIALIZED_DATA=128,
    IMAGE_SCN_LNK_OTHER=256,
    IMAGE_SCN_LNK_INFO=512,
    IMAGE_SCN_RESERVED_0040=1024,
    IMAGE_SCN_LNK_REMOVE=2048,
    IMAGE_SCN_LNK_COMDAT=4096,
    IMAGE_SCN_GPREL=32768,
    IMAGE_SCN_MEM_16BIT=131072,
    IMAGE_SCN_MEM_PURGEABLE=131072,
    IMAGE_SCN_MEM_LOCKED=262144,
    IMAGE_SCN_MEM_PRELOAD=524288,
    IMAGE_SCN_ALIGN_1BYTES=1048576,
    IMAGE_SCN_ALIGN_2BYTES=2097152,
    IMAGE_SCN_ALIGN_4BYTES=3145728,
    IMAGE_SCN_ALIGN_8BYTES=4194304,
    IMAGE_SCN_ALIGN_16BYTES=5242880,
    IMAGE_SCN_ALIGN_32BYTES=6291456,
    IMAGE_SCN_ALIGN_64BYTES=7340032,
    IMAGE_SCN_ALIGN_128BYTES=8388608,
    IMAGE_SCN_ALIGN_256BYTES=9437184,
    IMAGE_SCN_ALIGN_512BYTES=10485760,
    IMAGE_SCN_ALIGN_1024BYTES=11534336,
    IMAGE_SCN_ALIGN_2048BYTES=12582912,
    IMAGE_SCN_ALIGN_4096BYTES=13631488,
    IMAGE_SCN_ALIGN_8192BYTES=14680064,
    IMAGE_SCN_LNK_NRELOC_OVFL=16777216,
    IMAGE_SCN_MEM_DISCARDABLE=33554432,
    IMAGE_SCN_MEM_NOT_CACHED=67108864,
    IMAGE_SCN_MEM_NOT_PAGED=134217728,
    IMAGE_SCN_MEM_SHARED=268435456,
    IMAGE_SCN_MEM_EXECUTE=536870912,
    IMAGE_SCN_MEM_READ=1073741824,
    IMAGE_SCN_MEM_WRITE=2147483648
} SectionFlags;

union Misc {
    dword PhysicalAddress;
    dword VirtualSize;
};

struct IMAGE_SECTION_HEADER {
    char Name[8];
    union Misc Misc;
    ImageBaseOffset32 VirtualAddress;
    dword SizeOfRawData;
    dword PointerToRawData;
    dword PointerToRelocations;
    dword PointerToLinenumbers;
    word NumberOfRelocations;
    word NumberOfLinenumbers;
    enum SectionFlags Characteristics;
};

typedef struct IMAGE_NT_HEADERS64 IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

typedef struct IMAGE_FILE_HEADER IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

struct IMAGE_FILE_HEADER {
    word Machine; // 34404
    word NumberOfSections;
    dword TimeDateStamp;
    dword PointerToSymbolTable;
    dword NumberOfSymbols;
    word SizeOfOptionalHeader;
    word Characteristics;
};

struct IMAGE_NT_HEADERS64 {
    char Signature[4];
    struct IMAGE_FILE_HEADER FileHeader;
    struct IMAGE_OPTIONAL_HEADER64 OptionalHeader;
};

typedef struct IMAGE_THUNK_DATA64 IMAGE_THUNK_DATA64, *PIMAGE_THUNK_DATA64;

struct IMAGE_THUNK_DATA64 {
    qword StartAddressOfRawData;
    qword EndAddressOfRawData;
    qword AddressOfIndex;
    qword AddressOfCallBacks;
    dword SizeOfZeroFill;
    dword Characteristics;
};

typedef struct QMetaMethod QMetaMethod, *PQMetaMethod;

struct QMetaMethod { // PlaceHolder Structure
};

typedef struct QHideEvent QHideEvent, *PQHideEvent;

struct QHideEvent { // PlaceHolder Structure
};

typedef struct QRect QRect, *PQRect;

struct QRect { // PlaceHolder Structure
};

typedef struct QObject QObject, *PQObject;

struct QObject { // PlaceHolder Structure
};

typedef undefined QBasicUtf8StringView;

typedef struct QPainter QPainter, *PQPainter;

struct QPainter { // PlaceHolder Structure
};

typedef struct QByteArray QByteArray, *PQByteArray;

struct QByteArray { // PlaceHolder Structure
};

typedef struct QPaintDevice QPaintDevice, *PQPaintDevice;

struct QPaintDevice { // PlaceHolder Structure
};

typedef struct QMediaPlayer QMediaPlayer, *PQMediaPlayer;

struct QMediaPlayer { // PlaceHolder Structure
};

typedef struct QAudioOutput QAudioOutput, *PQAudioOutput;

struct QAudioOutput { // PlaceHolder Structure
};

typedef struct QInputMethodEvent QInputMethodEvent, *PQInputMethodEvent;

struct QInputMethodEvent { // PlaceHolder Structure
};

typedef struct QCloseEvent QCloseEvent, *PQCloseEvent;

struct QCloseEvent { // PlaceHolder Structure
};

typedef struct QMoveEvent QMoveEvent, *PQMoveEvent;

struct QMoveEvent { // PlaceHolder Structure
};

typedef struct QFocusEvent QFocusEvent, *PQFocusEvent;

struct QFocusEvent { // PlaceHolder Structure
};

typedef struct QDragLeaveEvent QDragLeaveEvent, *PQDragLeaveEvent;

struct QDragLeaveEvent { // PlaceHolder Structure
};

typedef struct QTimer QTimer, *PQTimer;

struct QTimer { // PlaceHolder Structure
};

typedef struct QChar QChar, *PQChar;

struct QChar { // PlaceHolder Structure
};

typedef struct QChildEvent QChildEvent, *PQChildEvent;

struct QChildEvent { // PlaceHolder Structure
};

typedef struct QPaintEvent QPaintEvent, *PQPaintEvent;

struct QPaintEvent { // PlaceHolder Structure
};

typedef struct QKeyEvent QKeyEvent, *PQKeyEvent;

struct QKeyEvent { // PlaceHolder Structure
};

typedef struct QDebug QDebug, *PQDebug;

struct QDebug { // PlaceHolder Structure
};

typedef struct QWidget QWidget, *PQWidget;

struct QWidget { // PlaceHolder Structure
};

typedef struct QResizeEvent QResizeEvent, *PQResizeEvent;

struct QResizeEvent { // PlaceHolder Structure
};

typedef undefined QByteArrayView;

typedef struct QLayout QLayout, *PQLayout;

struct QLayout { // PlaceHolder Structure
};

typedef struct QMainWindow QMainWindow, *PQMainWindow;

struct QMainWindow { // PlaceHolder Structure
};

typedef struct QString QString, *PQString;

struct QString { // PlaceHolder Structure
};

typedef struct QFont QFont, *PQFont;

struct QFont { // PlaceHolder Structure
};

typedef struct QTabletEvent QTabletEvent, *PQTabletEvent;

struct QTabletEvent { // PlaceHolder Structure
};

typedef struct QWheelEvent QWheelEvent, *PQWheelEvent;

struct QWheelEvent { // PlaceHolder Structure
};

typedef struct QShowEvent QShowEvent, *PQShowEvent;

struct QShowEvent { // PlaceHolder Structure
};

typedef struct QIcon QIcon, *PQIcon;

struct QIcon { // PlaceHolder Structure
};

typedef undefined QStringView;

typedef struct QMouseEvent QMouseEvent, *PQMouseEvent;

struct QMouseEvent { // PlaceHolder Structure
};

typedef undefined QFlags;

typedef struct QArrayData QArrayData, *PQArrayData;

struct QArrayData { // PlaceHolder Structure
};

typedef struct QUrl QUrl, *PQUrl;

struct QUrl { // PlaceHolder Structure
};

typedef struct QEvent QEvent, *PQEvent;

struct QEvent { // PlaceHolder Structure
};

typedef struct QGridLayout QGridLayout, *PQGridLayout;

struct QGridLayout { // PlaceHolder Structure
};

typedef struct QColor QColor, *PQColor;

struct QColor { // PlaceHolder Structure
};

typedef struct QMetaObject QMetaObject, *PQMetaObject;

struct QMetaObject { // PlaceHolder Structure
};

typedef struct QDropEvent QDropEvent, *PQDropEvent;

struct QDropEvent { // PlaceHolder Structure
};

typedef struct QDragEnterEvent QDragEnterEvent, *PQDragEnterEvent;

struct QDragEnterEvent { // PlaceHolder Structure
};

typedef struct QEnterEvent QEnterEvent, *PQEnterEvent;

struct QEnterEvent { // PlaceHolder Structure
};

typedef struct QDragMoveEvent QDragMoveEvent, *PQDragMoveEvent;

struct QDragMoveEvent { // PlaceHolder Structure
};

typedef struct QPen QPen, *PQPen;

struct QPen { // PlaceHolder Structure
};

typedef struct QActionEvent QActionEvent, *PQActionEvent;

struct QActionEvent { // PlaceHolder Structure
};

typedef struct QContextMenuEvent QContextMenuEvent, *PQContextMenuEvent;

struct QContextMenuEvent { // PlaceHolder Structure
};

typedef struct QTimerEvent QTimerEvent, *PQTimerEvent;

struct QTimerEvent { // PlaceHolder Structure
};

typedef struct QIODevice QIODevice, *PQIODevice;

struct QIODevice { // PlaceHolder Structure
};

typedef struct QDataStream QDataStream, *PQDataStream;

struct QDataStream { // PlaceHolder Structure
};

typedef struct QPoint QPoint, *PQPoint;

struct QPoint { // PlaceHolder Structure
};

typedef struct QBrush QBrush, *PQBrush;

struct QBrush { // PlaceHolder Structure
};

typedef struct QApplication QApplication, *PQApplication;

struct QApplication { // PlaceHolder Structure
};

typedef undefined QAnyStringView;

typedef struct QRandomGenerator QRandomGenerator, *PQRandomGenerator;

struct QRandomGenerator { // PlaceHolder Structure
};

typedef struct QTextStream QTextStream, *PQTextStream;

struct QTextStream { // PlaceHolder Structure
};

typedef struct QFile QFile, *PQFile;

struct QFile { // PlaceHolder Structure
};

typedef undefined ConnectionType;

typedef undefined PenStyle;

typedef undefined BrushStyle;

typedef undefined FocusPolicy;

typedef undefined InputMethodQuery;

typedef undefined CaseSensitivity;

typedef struct Connection Connection, *PConnection;

struct Connection { // PlaceHolder Structure
};

typedef undefined Call;

typedef struct QSlotObjectBase QSlotObjectBase, *PQSlotObjectBase;

struct QSlotObjectBase { // PlaceHolder Structure
};

typedef undefined AllocationOption;

typedef undefined PaintDeviceMetric;

typedef undefined ParsingMode;

typedef undefined QPrivateSignal;

typedef int (*_onexit_t)(void);




void FUN_140001000(void);
undefined8 FUN_140001010(void);
void FUN_140001130(void);
ulonglong FUN_140001180(undefined8 param_1,undefined8 param_2,undefined8 param_3);
void entry(undefined8 param_1,undefined8 param_2,undefined8 param_3);
void FUN_1400014d0(undefined8 param_1,undefined8 param_2,undefined8 param_3);
int FUN_1400014f0(_onexit_t param_1);
void FUN_140001510(void);
void FUN_140001520(void);
void FUN_140001530(undefined8 *param_1);
void FUN_1400015b0(void);
void FUN_1400015e0(void);
undefined8 FUN_140001610(undefined8 *param_1);
undefined8 FUN_140001620(longlong param_1);
void FUN_140001630(undefined8 *param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4);
void FUN_140001820(void);
void FUN_140001830(void);
void FUN_140001840(void);
void FUN_140001850(void);
void FUN_140001860(void);
void FUN_140001870(void);
undefined8 FUN_1400018a0(undefined8 param_1,undefined4 *param_2,undefined4 *param_3);
void FUN_140001900(QObject *param_1);
void FUN_140001a60(longlong param_1);
void FUN_140001be0(longlong param_1);
void FUN_140001cf0(longlong param_1);
void FUN_140002350(longlong param_1);
void FUN_140002470(QObject *param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4);
void FUN_140002840(QObject *param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4);
void FUN_1400028f0(QObject *param_1,longlong param_2,undefined8 param_3,undefined8 param_4);
void FUN_140002a30(longlong param_1);
void FUN_140002b40(QObject *param_1);
void FUN_140002d00(QObject *param_1);
void FUN_1400030c0(void);
void FUN_1400030f0(QString *param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4);
undefined4 FUN_140003550(int param_1,char **param_2);
void FUN_140003620(undefined4 *param_1,undefined4 param_2,undefined4 param_3);
undefined4 FUN_140003630(longlong param_1);
undefined4 FUN_140003640(longlong param_1);
void FUN_140003650(longlong param_1,undefined4 param_2);
undefined4 FUN_140003660(undefined4 *param_1);
undefined4 FUN_140003670(longlong param_1);
void FUN_140003680(undefined4 *param_1,undefined4 param_2);
void FUN_140003690(longlong param_1,undefined4 param_2);
void FUN_1400036a0(longlong *param_1);
void FUN_140003a00(longlong param_1);
void FUN_140003ae0(void);
void FUN_140003af0(void);
void FUN_140003b00(void);
void FUN_140003b10(void);
void FUN_140003b20(void);
void FUN_140003b30(QWidget *param_1);
void FUN_140003c30(longlong param_1,undefined8 *param_2);
void FUN_140003d00(longlong param_1);
void FUN_140003dc0(void);
undefined8 FUN_140003df0(void);
undefined8 FUN_140003e20(void);
undefined * FUN_140003e50(longlong param_1);
void FUN_140003e70(QObject *param_1,undefined8 param_2);
void FUN_140003ea0(QObject *param_1,undefined8 param_2);
void FUN_140003ed0(QObject *param_1,int param_2,int param_3,undefined8 *param_4);
char * FUN_140004060(char *param_1,char *param_2);
ulonglong FUN_1400040c0(QObject *param_1,int param_2,undefined8 param_3,undefined8 *param_4);
void FUN_140004130(void);
undefined * FUN_140004140(longlong param_1);
char * FUN_140004160(char *param_1,char *param_2);
void QMainWindow::qt_metacall(void);
void qUnregisterResourceData(int param_1,uchar *param_2,uchar *param_3,uchar *param_4);
void qRegisterResourceData(int param_1,uchar *param_2,uchar *param_3,uchar *param_4);
void FUN_140004680(void);
void FUN_1400046c0(void);
void FUN_140004730(void);
undefined8 FUN_140004750(void);
undefined8 tls_callback_1(undefined8 param_1,int param_2);
undefined8 tls_callback_0(undefined8 param_1,int param_2);
undefined8 FUN_140004810(void);
undefined8 FUN_140004820(undefined4 *param_1);
void FUN_140004920(void);
void FUN_140004930(char *param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4);
void FUN_1400049a0(byte *param_1,byte *param_2,undefined8 param_3,PDWORD param_4);
void FUN_140004ba0(undefined8 param_1,undefined8 param_2,undefined8 param_3,PDWORD param_4);
void FUN_140004f10(undefined4 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,undefined8 param_5);
void FUN_140004f60(undefined8 param_1);
undefined8 FUN_140004f70(undefined8 *param_1);
void FUN_140005150(void);
undefined8 FUN_1400051c0(undefined4 param_1,undefined8 param_2);
undefined8 FUN_140005240(int param_1);
undefined8 FUN_1400052e0(undefined8 param_1,int param_2);
bool FUN_1400053d0(longlong param_1);
bool FUN_1400053f0(short *param_1);
longlong FUN_140005410(longlong param_1,ulonglong param_2);
char * FUN_140005460(char *param_1);
longlong FUN_140005500(longlong param_1);
ulonglong FUN_140005580(void);
longlong FUN_1400055c0(longlong param_1);
IMAGE_DOS_HEADER * FUN_140005640(void);
ulonglong FUN_140005670(longlong param_1);
char * FUN_140005700(uint param_1);
undefined4 FUN_1400057c0(void);
undefined4 thunk_FUN_1400057c0(void);
undefined4 thunk_FUN_1400057c0(void);
void __cxa_throw_bad_array_new_length(void);
void * operator.new(ulonglong param_1);
void * operator.new[](ulonglong param_1);
void operator.delete(void *param_1,ulonglong param_2);
void operator.delete[](void *param_1);
void _Unwind_Resume(void);
ulonglong FUN_1400059d0(void);
undefined * FUN_140005a10(void);
undefined * FUN_140005a20(void);
undefined * FUN_140005a30(void);
undefined * FUN_140005a40(void);
undefined8 FUN_140005a50(void);
undefined8 FUN_140005a60(undefined8 param_1);
FILE * FUN_140005a70(uint param_1);
void __getmainargs(void);
FILE * __cdecl __iob_func(void);
void __cdecl __set_app_type(int param_1);
void __setusermatherr(void);
void __cdecl _amsg_exit(int param_1);
void __cdecl _cexit(void);
void _initterm(void);
_onexit_t __cdecl _onexit(_onexit_t _Func);
void __cdecl abort(void);
void * __cdecl calloc(size_t _Count,size_t _Size);
void __cdecl exit(int _Code);
int __cdecl fprintf(FILE *_File,char *_Format,...);
void __cdecl free(void *_Memory);
size_t __cdecl fwrite(void *_Str,size_t _Size,size_t _Count,FILE *_File);
void * __cdecl malloc(size_t _Size);
void * __cdecl memcpy(void *_Dst,void *_Src,size_t _Size);
void * __cdecl memmove(void *_Dst,void *_Src,size_t _Size);
void signal(int param_1);
int __cdecl strcmp(char *_Str1,char *_Str2);
size_t __cdecl strlen(char *_Str);
int __cdecl strncmp(char *_Str1,char *_Str2,size_t _MaxCount);
int __cdecl vfprintf(FILE *_File,char *_Format,va_list _ArgList);
void FUN_140005bc0(QMainWindow *param_1);
void FUN_140005c00(QMainWindow *param_1);
undefined * FUN_140005c20(void);
undefined * FUN_140005c30(void);
void FUN_140005c40(undefined8 *param_1);
void FUN_140005c60(longlong *param_1,int param_2,longlong param_3,undefined8 *param_4);
void FUN_140005fc0(undefined8 *param_1);
void FUN_140005fe0(undefined8 param_1,char *param_2);
void FUN_140006020(QWidget *param_1);
void FUN_140006060(QWidget *param_1);
void FUN_140006080(longlong *param_1,longlong param_2,undefined8 *param_3);
void FUN_140006340(int param_1,void *param_2,longlong param_3,longlong *param_4,undefined1 *param_5);
void FUN_1400063c0(int param_1,void *param_2,longlong param_3,longlong *param_4,undefined1 *param_5);
undefined * FUN_1400064d0(void);
undefined * FUN_1400064e0(void);
undefined8 FUN_1400064f0(undefined8 param_1,longlong param_2,longlong param_3);
uint FUN_140006540(undefined8 param_1,longlong param_2,longlong param_3);
void FUN_140006590(undefined8 param_1,QDataStream *param_2,QString *param_3);
void FUN_1400065a0(undefined8 param_1,QDataStream *param_2,QString *param_3);
void FUN_1400065b0(undefined8 param_1,QChar *param_2,longlong param_3);
void FUN_140006600(QWidget *param_1);
void FUN_140006680(QWidget *param_1);
void FUN_140006700(undefined8 *param_1);
void FUN_140006740(undefined8 *param_1);
void FUN_140006760(undefined8 *param_1);
void FUN_1400067a0(undefined8 *param_1);
void FUN_1400067c0(undefined8 *param_1);
void FUN_140006840(undefined8 *param_1);
void FUN_1400068c0(undefined8 param_1,QString *param_2,undefined8 param_3,undefined8 param_4);
void FUN_1400068d0(undefined8 param_1,longlong *param_2);
void FUN_1400068e0(undefined8 param_1,undefined8 *param_2,undefined8 *param_3);
void FUN_140006900(undefined8 param_1,undefined8 *param_2,undefined8 *param_3);
void FUN_140006930(undefined8 param_1,undefined8 *param_2);
void FUN_140006950(undefined8 param_1,undefined8 *param_2);
void FUN_140006970(undefined8 param_1,QObject *param_2,undefined8 param_3,undefined8 param_4);
void FUN_140006980(undefined8 param_1,longlong *param_2);
void FUN_140006990(void);
void FUN_140006b30(void);
void FUN_140006b70(void);
void FUN_140006cf0(void);
void FUN_140006d10(void);
void thunk_FUN_140001510(void);

