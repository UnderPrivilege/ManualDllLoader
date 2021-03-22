#define word_change_endian(x) (x = (x >> 8 | x << 8))
#define MAX_FUNCTION_NAME 63

typedef BOOL(WINAPI* DllMain)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved);
typedef DWORD(WINAPI* DllEntry)(LPVOID lParam);

struct DLL_START_INFOS {
	DWORD_PTR ImageBase;
	DWORD_PTR EntryPointVA;
};

enum Errors {
    OPEN_FAILED = 0x1,
    INVALID_SIZE = 0x2,
    FAILED_ALLOC = 0x3,
    FAILED_READ = 0x4,
    INVALID_PE = 0x5,
    INVALID_PE_ARCH = 0x6,
    INVALID_DLL = 0x7,
    IMAGE_NO_RELOCATIONS = 0x8,
    IMAGE_NOT_ENOUGH_MEMORY = 0x9,
    FAILED_MAP = 0xA,
    FAILED_RELOC = 0xB,
    FAILED_RESOLVE_IMPORTS = 0xC,
    FAILED_ALLOC_HEAP = 0xD,
    FAILED_VIRTUAL_PROTECT = 0xE,
    FAILED_CALLING_EP = 0xF,
    REMOTE_THREAD_ERROR = 0x10,
    MANUAL_SUCCESS = 0x0
};

Errors LoadRemoteDll(LPCWSTR, DWORD);
