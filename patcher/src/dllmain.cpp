#include <Windows.h>
#include <stdint.h>
#include <Psapi.h>
#include <stdio.h>
#include <inttypes.h>
#include <io.h>
#include <fcntl.h>
#include <thread>
#include <chrono>

#include <map>

#include "MinHook.h"

#ifdef _WIN64

extern "C" void do_thing();
extern "C" void hook_decrypt_func_on_keyload();
extern "C" void hook_decrypt_func_under_xor();
extern "C" void write_new_ret_addr(long long new_addr);
extern "C" void write_new_file_pointer(FILE* new_file);

#pragma section("_SHARED", read, write, shared)
__declspec(dllexport) __declspec(allocate("_SHARED")) long long return_jump_addr;




FILE* ofp = NULL;

uint64_t decrypt_RVA = 0x61B140;
uint64_t decrypt_key_RVA = 0x61B20A;
uint64_t decrypt_under_xor_RVA = 0x61B2E1;
uint64_t end_of_beeg_RVA = 0x1EE0C0;
uint64_t beeg_RVA = 0x1D45E0;
uint64_t above_beeg_RVA = 0x3CE3B0;
uint64_t after_beeg_call_RVA = 0x3CE3D6;
uint64_t chosen_RVA = decrypt_under_xor_RVA;


uint64_t decrypt_overWriteLen = 6;
uint64_t decrypt_key_overWriteLen = 10;
uint64_t decrypt_under_xor_overWriteLen = 6;
uint64_t curr_overWriteLen = decrypt_under_xor_overWriteLen;

void* AllocatePageNearAddress(void* targetAddr)
{
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    const uint64_t PAGE_SIZE = sysInfo.dwPageSize;

    uint64_t startAddr = (uint64_t(targetAddr) & ~(PAGE_SIZE - 1)); //round down to nearest page boundary
    uint64_t minAddr = min(startAddr - 0x7FFFFF00, (uint64_t)sysInfo.lpMinimumApplicationAddress);
    uint64_t maxAddr = max(startAddr + 0x7FFFFF00, (uint64_t)sysInfo.lpMaximumApplicationAddress);

    uint64_t startPage = (startAddr - (startAddr % PAGE_SIZE));

    uint64_t pageOffset = 1;
    while (1)
    {
        uint64_t byteOffset = pageOffset * PAGE_SIZE;
        uint64_t highAddr = startPage + byteOffset;
        uint64_t lowAddr = (startPage > byteOffset) ? startPage - byteOffset : 0;

        bool needsExit = highAddr > maxAddr && lowAddr < minAddr;

        if (highAddr < maxAddr)
        {
            void* outAddr = VirtualAlloc((void*)highAddr, PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (outAddr)
                return outAddr;
        }

        if (lowAddr > minAddr)
        {
            void* outAddr = VirtualAlloc((void*)lowAddr, PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (outAddr != nullptr)
                return outAddr;
        }

        pageOffset++;

        if (needsExit)
        {
            break;
        }
    }

    return nullptr;
}
uint64_t GetBaseModuleForProcess()
{
    HANDLE process = GetCurrentProcess();
    HMODULE processModules[1024];
    DWORD numBytesWrittenInModuleArray = 0;
    EnumProcessModules(process, processModules, sizeof(HMODULE) * 1024, &numBytesWrittenInModuleArray);

    DWORD numRemoteModules = numBytesWrittenInModuleArray / sizeof(HMODULE);
    CHAR processName[256];
    GetModuleFileNameEx(process, NULL, processName, 256); //a null module handle gets the process name
    _strlwr_s(processName, 256);

    HMODULE module = 0; //An HMODULE is the DLL's base address 

    for (DWORD i = 0; i < numRemoteModules; ++i)
    {
        CHAR moduleName[256];
        CHAR absoluteModuleName[256];
        GetModuleFileNameEx(process, processModules[i], moduleName, 256);

        _fullpath(absoluteModuleName, moduleName, 256);
        _strlwr_s(absoluteModuleName, 256);

        if (strcmp(processName, absoluteModuleName) == 0)
        {
            module = processModules[i];
            break;
        }
    }

    return (uint64_t)module;
}

void WriteAbsoluteJump64(void* absJumpMemory, void* addrToJumpTo)
{
    uint8_t absJumpInstructions[] = { 0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x41, 0xFF, 0xE2 };

    uint64_t addrToJumpTo64 = (uint64_t)addrToJumpTo;
    memcpy(&absJumpInstructions[2], &addrToJumpTo64, sizeof(addrToJumpTo64));
    memcpy(absJumpMemory, absJumpInstructions, sizeof(absJumpInstructions));
}

void InstallHook(void* targetFunction, void* payloadFunction, uint64_t* returnAddr)
{
    uint64_t functionRVA = chosen_RVA;
    uint64_t func2HookAddr = GetBaseModuleForProcess() + functionRVA;
    void* func2hook = (void*)func2HookAddr;

    void* relayFuncMemory = AllocatePageNearAddress(func2hook);
    WriteAbsoluteJump64(relayFuncMemory, payloadFunction); //write relay func instructions

    write_new_ret_addr(((long long)func2hook) + curr_overWriteLen);

    fprintf(ofp, "first few bytes: ");
    for (int i = 0; i < 64; i++) {
        int ye = ((uint8_t*)func2hook)[i];
        fprintf(ofp, "0x%02x ", ye);
    }

    //now that the relay function is built, we need to install the E9 jump into the target func,
    //this will jump to the relay function
    DWORD oldProtect;
    VirtualProtect(func2hook, 1024, PAGE_EXECUTE_READWRITE, &oldProtect);

    uint8_t jmpInstruction[5] = { 0xE9, 0x0, 0x0, 0x0, 0x0 };

    const uint64_t relAddr = (uint64_t)relayFuncMemory - ((uint64_t)func2hook + sizeof(jmpInstruction));
    memcpy(jmpInstruction + 1, &relAddr, 4);

    //install the hook
    memcpy(func2hook, jmpInstruction, sizeof(jmpInstruction));
    fprintf(ofp, "hook installed!\n");
}

void* GetFunc2HookAddr()
{
    uint64_t functionRVA = chosen_RVA;
    uint64_t func2HookAddr = GetBaseModuleForProcess() + functionRVA;
    fprintf(ofp, "base module: %" PRIu64 ", func2HookAddr: %" PRIu64 "\n", GetBaseModuleForProcess(), func2HookAddr);
    return (void*)func2HookAddr;
}

typedef HANDLE(WINAPI* fCreateFileW)(
    LPCWSTR               lpFileName,
    DWORD                 dwDesiredAccess,
    DWORD                 dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD                 dwCreationDisposition,
    DWORD                 dwFlagsAndAttributes,
    HANDLE                hTemplateFile
);
fCreateFileW fpCreateFileW = NULL;
HANDLE WINAPI DetourCreateFileW(
    LPCWSTR               lpFileName,
    DWORD                 dwDesiredAccess,
    DWORD                 dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD                 dwCreationDisposition,
    DWORD                 dwFlagsAndAttributes,
    HANDLE                hTemplateFile) {

    HANDLE ret = fpCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);

    char pathBuf[1024];
    wcstombs(pathBuf, (const wchar_t*)lpFileName, 1024);
    printf("[fCreateW] handle: %d, name: %s\n", ret, pathBuf);
    fprintf(ofp, "[fCreateW] handle: %d, name: %s\n", ret, pathBuf);

    return ret;
}

typedef HFILE (WINAPI* fOpenFile)(
    LPCSTR     lpFileName,
    LPOFSTRUCT lpReOpenBuff,
    UINT       uStyle
);
fOpenFile fpOpenFile = NULL;
HFILE WINAPI DetourOpenFile(
    LPCSTR     lpFileName,
    LPOFSTRUCT lpReOpenBuff,
    UINT       uStyle) {

    HFILE ret = fpOpenFile(lpFileName, lpReOpenBuff, uStyle);

    char pathBuf[1024];
    wcstombs(pathBuf, (const wchar_t*)lpFileName, 1024);
    printf("[fOpen] handle: %d, name: %s\n", ret, pathBuf);
    fprintf(ofp, "[fOpen] handle: %d, name: %s\n", ret, pathBuf);
    fflush(stdout);
    fflush(ofp);

    return ret;
}

typedef BOOL (WINAPI* fReadFile)(
    HANDLE       hFile,
    LPVOID       lpBuffer,
    DWORD        nNumberOfBytesToRead,
    LPDWORD      lpNumberOfBytesRead,
    LPOVERLAPPED lpOverlapped
);
fReadFile fpReadFile = NULL;
bool WINAPI DetourReadFile(
    HANDLE       hFile,
    LPVOID       lpBuffer,
    DWORD        nNumberOfBytesToRead,
    LPDWORD      lpNumberOfBytesRead,
    LPOVERLAPPED lpOverlapped) {

    //getting current offset
    LARGE_INTEGER pos;
    pos.QuadPart = 0;
    LARGE_INTEGER zero;
    zero.QuadPart = 0;
    SetFilePointerEx(hFile, zero, &pos, FILE_CURRENT);

    const auto lpBufOld = lpBuffer;

    const auto ret = fpReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);

    printf("[fRead]: handle: %d, size: %d, offset: %lld, bytes: %016llx\n", hFile, nNumberOfBytesToRead, pos.QuadPart, *reinterpret_cast<uint64_t*>(lpBufOld));
    fprintf(ofp, "[fRead]: handle: %d, size: %d, offset: %lld, bytes: %016llx\n", hFile, nNumberOfBytesToRead, pos.QuadPart, *reinterpret_cast<uint64_t*>(lpBufOld));
    fflush(stdout);
    fflush(ofp);

    return ret;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD ul_reason_for_call, LPVOID lpvReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        int curr = 0;
        char buf[1024];
        while (true) {
            sprintf(buf, "hooking_log_%03d.txt", curr);
            if (_access(buf, 0/*check for existence*/) == -1) { //if this file doesn't exist
                break;
            }
            curr++;
        }
        ofp = fopen(buf, "wb");
        write_new_file_pointer(ofp);
        InstallHook(GetFunc2HookAddr(), hook_decrypt_func_under_xor, (uint64_t*)&return_jump_addr);
        

        AllocConsole();
        freopen("CONOUT$", "w", stdout);
        freopen("CONOUT$", "w", stderr);
        printf("ok dayo\n");

        if (MH_Initialize() != MH_OK) {
            printf("minhook init failed!\n");
            return false;
        }

        if (MH_CreateHook(&ReadFile, &DetourReadFile, reinterpret_cast<LPVOID*>(&fpReadFile)) != MH_OK) {
            printf("creating hook on fileread failed\n");
            return false;
        }
        if (MH_CreateHook(&OpenFile, &DetourOpenFile , reinterpret_cast<LPVOID*>(&fpOpenFile)) != MH_OK) {
            printf("creating hook on openfile failed\n");
            return false;
        }
        if (MH_CreateHook(&CreateFileW, &DetourCreateFileW, reinterpret_cast<LPVOID*>(&fpCreateFileW)) != MH_OK) {
            printf("creating hook on createfileW failed\n");
            return false;
        }

        if (MH_EnableHook(&ReadFile) != MH_OK) {
            printf("enabling hook on readfile failed\n");
            return false;
        }
        if (MH_EnableHook(&OpenFile) != MH_OK) {
            printf("enabling hook on openfile failed\n");
            return false;
        }
        if (MH_EnableHook(&CreateFileW) != MH_OK) {
            printf("enabling hook on createFileW failed\n");
            return false;
        }
    }
    return true;
}

#endif
