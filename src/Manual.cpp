#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <tlhelp32.h>

#include "Manual.h"

static LPVOID remoteDLLAddress = NULL;

Errors ParseError(HANDLE hProc, LPVOID RemoteLoadBase, Errors givenError)
{
  if(RemoteLoadBase)
    VirtualFreeEx(hProc, RemoteLoadBase, 0, MEM_RELEASE);
  return givenError;
}

DWORD GetFirstThreadID(DWORD pid) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);//second param is ignored if TH32CS_SNAPTHREAD is specified
    if (hSnap == INVALID_HANDLE_VALUE)
        return NULL;
    
    THREADENTRY32 te32 = { sizeof(te32) };

    if (!Thread32First(hSnap, &te32))
        return NULL;

    //only check for threads belonging to our target process
    do
    {
        if (te32.th32OwnerProcessID == pid)
        {
            printf("Trying to hijack thread %u -> priority: %u\n", te32.th32ThreadID, te32.tpBasePri);    
            break;
        }
    } while (Thread32Next(hSnap, &te32));
    CloseHandle(hSnap);
    return te32.th32ThreadID;
}

DWORD_PTR FindImportsHeader(DWORD_PTR ImportDirectoryRVA, DWORD_PTR SectionHeaderStart) {
    for (; *(DWORD*)SectionHeaderStart != 0; SectionHeaderStart++) {
        if(reinterpret_cast<IMAGE_SECTION_HEADER*>(SectionHeaderStart)->VirtualAddress > ImportDirectoryRVA)
            return SectionHeaderStart-sizeof(IMAGE_SECTION_HEADER);
    }
    return -1;
}

Errors LoadRemoteDll(LPCWSTR dllPath, DWORD pid) {

  HANDLE remoteProcess = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_VM_READ , FALSE, pid);
  if(!remoteProcess)
    return ParseError(remoteProcess,NULL, OPEN_FAILED);
  //PS: does not check if DLL already loaded
  //Does not affect the linked list PEB::Ldr

  /*
  Step 1: Open file and check headers
  */
  HANDLE hFile = CreateFileW(dllPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if(hFile == INVALID_HANDLE_VALUE) return ParseError(remoteProcess, NULL, OPEN_FAILED);

  //Get File Size
  DWORD fSize = GetFileSize(hFile, NULL);

  if(fSize == INVALID_FILE_SIZE) return ParseError(remoteProcess, NULL, INVALID_SIZE);

  //Let the OS determine the address
  LPVOID lpBuffer = VirtualAlloc(NULL, fSize, MEM_COMMIT, PAGE_READWRITE);
  if(!lpBuffer) return ParseError(remoteProcess, NULL, FAILED_ALLOC);

  DWORD bytesRead;
  if(!ReadFile(hFile, lpBuffer, fSize, &bytesRead, NULL) || bytesRead != fSize) return ParseError(remoteProcess,NULL, FAILED_READ);

  IMAGE_DOS_HEADER* dos;
  IMAGE_NT_HEADERS64* nt;

  dos = reinterpret_cast<IMAGE_DOS_HEADER*>(lpBuffer);
  nt = reinterpret_cast<IMAGE_NT_HEADERS64*>((DWORD_PTR)lpBuffer+dos->e_lfanew);

  if(dos->e_magic != IMAGE_DOS_SIGNATURE || nt->Signature != IMAGE_NT_SIGNATURE)
    return ParseError(remoteProcess, NULL, INVALID_PE);

  if(nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return ParseError(remoteProcess, NULL, INVALID_PE_ARCH);

  if(!(nt->FileHeader.Characteristics & IMAGE_FILE_DLL)) return ParseError(remoteProcess, NULL, INVALID_DLL);

  //dos+e_lfanew+SizeOfFileHeader
  ULONGLONG SectionListOffset = (ULONGLONG)IMAGE_FIRST_SECTION(nt);

  /*
  Step 2: Allocate memory in remote process for dll sections
  */

  DWORD_PTR    firstSectionOffset =  (DWORD_PTR)lpBuffer+reinterpret_cast<IMAGE_SECTION_HEADER*>(SectionListOffset)->PointerToRawData;

  //We first get the RVA of the first PE section to mark the start of the actual contents of the DLL
  ULONGLONG firstAddress = reinterpret_cast<IMAGE_SECTION_HEADER*>(SectionListOffset)->VirtualAddress;
 //get Virtual Address, note that ImageBase is preferred
  IMAGE_SECTION_HEADER* lastSection = reinterpret_cast<IMAGE_SECTION_HEADER*>(SectionListOffset+sizeof(IMAGE_SECTION_HEADER)*(nt->FileHeader.NumberOfSections-1));
  //get to the end of the PE not a the beginning of the last section
  ULONGLONG lastAddress = (ULONGLONG)lastSection->VirtualAddress+(ULONGLONG)lastSection->Misc.VirtualSize;

  SIZE_T SizeOfContents = (SIZE_T)(lastAddress-firstAddress);

  DWORD_PTR preferredLoadAddress = (DWORD_PTR)firstAddress+nt->OptionalHeader.ImageBase;

  printf("[+] Trying to allocate DLL at remote address 0x%llx\n", preferredLoadAddress);

  //Allocate a page on remote process
  LPVOID RemoteLoadBase = VirtualAllocEx(remoteProcess, (LPVOID)preferredLoadAddress, SizeOfContents , MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if(!RemoteLoadBase) {
    //If the remote buffer is invalid then we need to do relocations since the addresses delta is wrong!
   //re alloc buffer since the first failed
    RemoteLoadBase = VirtualAllocEx(remoteProcess, NULL, SizeOfContents, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  }

  if(!RemoteLoadBase)
    return ParseError(remoteProcess,RemoteLoadBase, IMAGE_NOT_ENOUGH_MEMORY);

  //we subtract firstAddress since the allocated remote buffer corresponds to the mapped firstAddress value(code VA) not the ACTUAL image base!
  DWORD_PTR RemoteImageBase = (DWORD_PTR)RemoteLoadBase-firstAddress;

  /*
  Step 3: Map DLL Sections in remote memory: LdrpMapDll
  */

  IMAGE_SECTION_HEADER* s =  reinterpret_cast<IMAGE_SECTION_HEADER*>(SectionListOffset);

  for (int i = 0; i < nt->FileHeader.NumberOfSections; ++s,++i) {
      DWORD sec_size = min(s->Misc.VirtualSize, s->SizeOfRawData);
      DWORD_PTR sec_address = ((DWORD_PTR)RemoteLoadBase - firstAddress) + s->VirtualAddress;

      if (!WriteProcessMemory(remoteProcess, (LPVOID)sec_address, (LPVOID)((DWORD_PTR)lpBuffer + s->PointerToRawData), sec_size, NULL))
          return ParseError(remoteProcess,RemoteLoadBase, FAILED_MAP);
  }

  /*
  Step 4: Do relocations: RtlImageDirectoryEntryToData and LdrRelocateImageWithBias
  */

  //Do we need relocations?
  if((DWORD_PTR)RemoteLoadBase != preferredLoadAddress) {
      printf("[+] Allocated memory at 0x%llx instead\n", (DWORD_PTR)RemoteLoadBase);

      if(nt->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED || !nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress)
        goto imports;
        //return ParseError(remoteProcess,RemoteLoadBase, IMAGE_NO_RELOCATIONS;

        //calculate delta -> prefered Image Base - Actual Load Address
        DWORD delta = (DWORD)(nt->OptionalHeader.ImageBase - (DWORD_PTR)RemoteImageBase);

        printf("[+] Applying Delta: %x\n", delta);

        //Rename to BaseRelocHeader
        DWORD_PTR firstBaseReloc = (DWORD_PTR)RemoteImageBase + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;

        DWORD RelocSize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
        DWORD_PTR EndReloc = firstBaseReloc + RelocSize;

        do
        {
            DWORD SizeOfBlock;
            if (!ReadProcessMemory(remoteProcess, (LPVOID)(firstBaseReloc + offsetof(IMAGE_BASE_RELOCATION, SizeOfBlock)), (LPVOID)&SizeOfBlock, sizeof(DWORD), NULL))
                return ParseError(remoteProcess,RemoteLoadBase, FAILED_RELOC);

            DWORD BlockRVA;
            if (!ReadProcessMemory(remoteProcess, (LPVOID)(firstBaseReloc + offsetof(IMAGE_BASE_RELOCATION, VirtualAddress)), (LPVOID)&BlockRVA, sizeof(DWORD), NULL))
                return ParseError(remoteProcess,RemoteLoadBase, FAILED_RELOC);

            //SizeOfBlock is size in BYTES
            for (WORD i = 0; i < SizeOfBlock / 2; i++) {
                WORD relocEntry;
                ReadProcessMemory(remoteProcess, (LPVOID)((DWORD_PTR)firstBaseReloc + sizeof(IMAGE_BASE_RELOCATION) + i), (LPVOID)&relocEntry, sizeof(WORD), NULL);

                if (relocEntry & IMAGE_REL_BASED_HIGHLOW) {
                    DWORD_PTR fixupAddress = (DWORD_PTR)RemoteImageBase + BlockRVA;//get page va for fixup

                    relocEntry &= 0xFF0F; // get offset -> little endian, reverse order!

                    //change endian to big endian
                    word_change_endian(relocEntry);

                    fixupAddress += relocEntry;
                    //Avoid re-allocating rdata things since we resolve imports later on.
                    IMAGE_SECTION_HEADER* IMPORT_SECTION = reinterpret_cast<IMAGE_SECTION_HEADER*>(FindImportsHeader(nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, SectionListOffset));

                    if ((fixupAddress - RemoteImageBase) >= IMPORT_SECTION->VirtualAddress && (fixupAddress - RemoteImageBase) <= IMPORT_SECTION->VirtualAddress + IMPORT_SECTION->Misc.VirtualSize)
                        continue;

                    DWORD_PTR AddressAtFixup;
                    if (!ReadProcessMemory(remoteProcess, (LPVOID)fixupAddress, (LPVOID)&AddressAtFixup, sizeof(DWORD_PTR), NULL))
                        return ParseError(remoteProcess,RemoteLoadBase, FAILED_RELOC);

                    AddressAtFixup += delta;

                    if (!WriteProcessMemory(remoteProcess, (LPVOID)fixupAddress, (LPVOID)&AddressAtFixup, sizeof(DWORD_PTR), NULL))
                        return ParseError(remoteProcess,RemoteLoadBase, FAILED_RELOC);
                }
             }
            //The size of the block including the Page RVA and Block Size fields!
            firstBaseReloc += SizeOfBlock;
        } while (firstBaseReloc < EndReloc);
  }

  /*
  Step 5:Check imports and Resolve their addresses
  */
imports:
  DWORD_PTR ImportDescriptorAddress = RemoteImageBase+nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
  DWORD ImportDescriptorsSize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
  DWORD_PTR EndImportDecriptor = (ImportDescriptorAddress + ImportDescriptorsSize) - sizeof(IMAGE_IMPORT_DESCRIPTOR); //since we have one null import descriptor at the end

  //we ignore delay loaded dll's for now
  while (ImportDescriptorAddress < EndImportDecriptor) {
      LPVOID dll_name = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY , FILENAME_MAX);
      if (!dll_name)
          return ParseError(remoteProcess,RemoteLoadBase, FAILED_ALLOC_HEAP);

      DWORD NameRva;

      if (!ReadProcessMemory(remoteProcess, (LPVOID)(ImportDescriptorAddress + offsetof(IMAGE_IMPORT_DESCRIPTOR, Name)), &NameRva, sizeof(DWORD), NULL))
          return ParseError(remoteProcess,RemoteLoadBase, FAILED_RESOLVE_IMPORTS);

      if (!ReadProcessMemory(remoteProcess, (LPVOID)(RemoteImageBase + NameRva), dll_name, FILENAME_MAX, NULL))
          return ParseError(remoteProcess,RemoteLoadBase, FAILED_RESOLVE_IMPORTS);

      HMODULE hModule = LoadLibraryA((LPCSTR)dll_name);

      printf("[?] Resolved %s imports\n", (const char*)dll_name);

      HeapFree(GetProcessHeap(), NULL, dll_name);

      if (hModule == INVALID_HANDLE_VALUE)
          return ParseError(remoteProcess,RemoteLoadBase, FAILED_RESOLVE_IMPORTS);

      DWORD FirstThunkRVA;
      //Get the address of the not yet loader bound IAT
      if (!ReadProcessMemory(remoteProcess, (LPVOID)(ImportDescriptorAddress + offsetof(IMAGE_IMPORT_DESCRIPTOR, FirstThunk)), (LPVOID)&FirstThunkRVA, sizeof(DWORD), NULL))
          return ParseError(remoteProcess,RemoteLoadBase, FAILED_RESOLVE_IMPORTS);

      DWORD_PTR FirstThunkAddress = RemoteImageBase + FirstThunkRVA;
      DWORD_PTR ThunkData;
      DWORD_PTR ImportAddress;
      do {
          if (!ReadProcessMemory(remoteProcess, (LPVOID)FirstThunkAddress, (LPVOID)&ThunkData, sizeof(DWORD_PTR), NULL))
              return ParseError(remoteProcess,RemoteLoadBase, FAILED_RESOLVE_IMPORTS);

          //Imported by ordinal
          if (ThunkData & IMAGE_ORDINAL_FLAG64) {
              DWORD_PTR ordinalNumber = (DWORD)(ThunkData & IMAGE_ORDINAL_FLAG64);//remove ordinal flag

              //If this parameter is an ordinal value, it must be in the low-order word; the high-order word must be zero.
              //just truncate the DWORD to a word and re-convert it to a DWORD_PTR
              ImportAddress = (DWORD_PTR)GetProcAddress(hModule, MAKEINTRESOURCEA(ordinalNumber));
          } else {
              //Imported by name
              LPVOID name_buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_FUNCTION_NAME);
              if (!name_buffer)
                  return ParseError(remoteProcess,RemoteLoadBase, FAILED_ALLOC_HEAP);

              DWORD_PTR hintNameTable = (RemoteImageBase + ThunkData) + sizeof(WORD);//skip the HINT field

              if (!ThunkData) continue;

              if (!ReadProcessMemory(remoteProcess, (LPVOID)hintNameTable, name_buffer, MAX_FUNCTION_NAME, NULL))
                  return ParseError(remoteProcess,RemoteLoadBase, FAILED_RESOLVE_IMPORTS);

              //printf("\t\t%s\n", (const char*)name_buffer);

              ImportAddress = (DWORD_PTR)GetProcAddress(hModule, (LPCSTR)name_buffer);

              HeapFree(GetProcessHeap(), NULL, name_buffer);
          }

          if (!WriteProcessMemory(remoteProcess, (LPVOID)FirstThunkAddress, (LPVOID)&ImportAddress, sizeof(DWORD_PTR), NULL))
            return ParseError(remoteProcess,RemoteLoadBase, FAILED_RESOLVE_IMPORTS);

          FirstThunkAddress += sizeof(IMAGE_THUNK_DATA64);
      } while (ThunkData != NULL);

      ImportDescriptorAddress += sizeof(IMAGE_IMPORT_DESCRIPTOR);
  }

  /*
  Step 6: Restore original page protection for sections: LdrpSetProtection
  */

  int i;
  IMAGE_SECTION_HEADER* sec;
  for (i = 0, sec = reinterpret_cast<IMAGE_SECTION_HEADER*>(SectionListOffset); i < (nt->FileHeader.NumberOfSections)-1; ++sec, ++i) //-1 since we start at index 0
  {
      DWORD_PTR sectionVA = RemoteImageBase + sec->VirtualAddress;
      DWORD Characteristics = sec->Characteristics;
      DWORD protection;

      if (Characteristics & IMAGE_SCN_CNT_CODE) {
          protection = PAGE_EXECUTE_READ;
      }
      else if (Characteristics & IMAGE_SCN_MEM_WRITE && Characteristics & IMAGE_SCN_MEM_READ) {
          protection = PAGE_READWRITE;
      }
      else if (Characteristics & IMAGE_SCN_MEM_EXECUTE) {
          protection = PAGE_EXECUTE;
      }
      else if (Characteristics & IMAGE_SCN_MEM_READ) {
          protection = PAGE_READONLY;
      }
      else if (Characteristics & IMAGE_SCN_MEM_WRITE) {
          protection = PAGE_WRITECOPY;
      }
      //_Param(5) CANNOT be NULL or function fails;
      DWORD oldProtect;
      if (!VirtualProtectEx(remoteProcess, (LPVOID)sectionVA, sec->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtect))
          return ParseError(remoteProcess, RemoteLoadBase, FAILED_VIRTUAL_PROTECT);
  }

  /*
  Step 7: Call DLL entry point: LdrpCallInitRoutine
  */
  DWORD_PTR EntryPoint = (DWORD_PTR)RemoteImageBase + nt->OptionalHeader.AddressOfEntryPoint;

  printf("[+] Relocated DLL entry point: 0x%p\n", EntryPoint);

  DllEntry dllentry = (DllEntry)EntryPoint;
  HANDLE hThread;

  goto thread_hijack;
manual_create_thread:
  hThread = CreateRemoteThread(remoteProcess, NULL, 0, (LPTHREAD_START_ROUTINE)dllentry, (LPVOID)RemoteLoadBase, 0, NULL);

  printf("[!] LastError(for debug purposes, may not be linked directly with the DLL loading): 0x%x\n", GetLastError());

  if (!hThread)
      return ParseError(remoteProcess,RemoteLoadBase, REMOTE_THREAD_ERROR);

  CloseHandle(hThread);
  printf("[+] Successfully loaded DLL into target process!\n");

thread_hijack:
  /*
   push rax
push r9
push r8
push rdx
push rcx



push 0x00000000
push 0x00000000
mov  r9,  0x1234567812345678
mov  r8,  0x1234567812345678
mov  rdx, 0
mov  rcx, 0

mov  rax, 0x1234567812345678
call rax

add  rsp, 8*2

pop rcx
pop rdx
pop r8
pop r9
pop rax

mov r15, 0x1234567812345678
push r15
ret

  */

  DWORD tid = GetFirstThreadID(pid);
  if(!tid)
      return ParseError(remoteProcess, RemoteLoadBase, REMOTE_THREAD_ERROR);

  BYTE shellcode[] =
  { 0x50, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51, 0x41, 0x53, 0x9C, 0x6A, 0x00, 0x6A, 0x00, 0x49, 0xB9, 0x78, 0x56, 0x34, 0x12, 0x78, 0x56, 0x34, 0x12, 0x49, 0xB8, 0x78, 0x56, 0x34, 0x12, 0x78, 0x56, 0x34, 0x12, 0x48, 0xC7, 0xC2, 0x00, 0x00, 0x00, 0x00, 0x48, 0xC7, 0xC1, 0x00, 0x00, 0x00, 0x00, 0x48, 0xB8, 0x78, 0x56, 0x34, 0x12, 0x78, 0x56, 0x34, 0x12, 0xFF, 0xD0, 0x48, 0x83, 0xC4, 0x10, 0x9D, 0x41, 0x5B, 0x59, 0x5A, 0x41, 0x58, 0x41, 0x59, 0x58, 0x49, 0xBF, 0x78, 0x56, 0x34, 0x12, 0x78, 0x56, 0x34, 0x12, 0x41, 0xFF, 0xE7 };

  *(DWORD_PTR*)(shellcode + 0x10) = (DWORD_PTR)RemoteLoadBase;//lParam
  *(DWORD_PTR*)(shellcode + 0x1A) = EntryPoint;//ThreadProc

  *(DWORD_PTR*)(shellcode + 0x32) = (DWORD_PTR)CreateThread;//remember kernel32 functions are loaded in absolute system space!

  hThread = OpenThread(THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT, FALSE, tid);
  if (hThread == INVALID_HANDLE_VALUE)
      return ParseError(remoteProcess, RemoteLoadBase, REMOTE_THREAD_ERROR);

  if(SuspendThread(hThread) == -1)
      return ParseError(remoteProcess, RemoteLoadBase, REMOTE_THREAD_ERROR);

  CONTEXT context;
  //Get All context registers
  context.ContextFlags = CONTEXT_FULL;
  if (!GetThreadContext(hThread, &context))
  {
      ResumeThread(hThread);
      return ParseError(remoteProcess, RemoteLoadBase, REMOTE_THREAD_ERROR);
  }

  *(DWORD_PTR*)(shellcode + 0x4C) = context.Rip;
  
  //Write the shellcode in target process
  LPVOID shell_buffer = VirtualAllocEx(remoteProcess, NULL, 1 << 12, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  if (!shell_buffer)
  {
      ResumeThread(hThread);
      return ParseError(remoteProcess, RemoteLoadBase, REMOTE_THREAD_ERROR);
  }

  printf("[+] Allocated shellcode at 0x%p\n", (DWORD_PTR)shell_buffer);

  if (!WriteProcessMemory(remoteProcess, shell_buffer, shellcode, sizeof(shellcode), NULL))
  {
      ResumeThread(hThread);
      return ParseError(remoteProcess, RemoteLoadBase, REMOTE_THREAD_ERROR);
  }

  context.Rip = (DWORD64)shell_buffer;//hijack thread execution

  if(!SetThreadContext(hThread, &context))
  {
      ResumeThread(hThread);
      return ParseError(remoteProcess, RemoteLoadBase, REMOTE_THREAD_ERROR);
  }

  ResumeThread(hThread);

  //PostThreadMessage(tid, WM_NULL, 0, 0);//Wake up thread

  VirtualFreeEx(remoteProcess, shell_buffer, 0, MEM_RELEASE);//free shellcode page

  /*
  Step n: Clean up
  */
  VirtualFree(lpBuffer, NULL, MEM_RELEASE);
  CloseHandle(hFile);

  return (Errors)NULL;
}
