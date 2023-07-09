#include <iostream>
#include "Memory.h"

#include <TlHelp32.h>
//Discord: writeline
DWORD GetDiscordProcessId()
{
    
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
    {
        std::cerr << "Failed to create process snapshot." << std::endl;
        return 0;
    }

    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32);

  
    if (Process32First(snapshot, &processEntry))
    {
        do
        {
         
            if (_wcsicmp(processEntry.szExeFile, L"Discord.exe") == 0)
            {
                // Close the snapshot handle and return the process ID
                CloseHandle(snapshot);
                return processEntry.th32ProcessID;
            }
        } while (Process32Next(snapshot, &processEntry));
    }

 
    CloseHandle(snapshot);

    std::cerr << "Discord process not found." << std::endl;
    return 0;
}

int main() {
    
    DWORD discordProcessId = GetDiscordProcessId();
    if (discordProcessId == 0)
    {
        return 1;
    }

    HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, discordProcessId);
    BYTE searchPattern[] = { 0x41, 0x75, 0x74, 0x68, 0x6F, 0x72, 0x69, 0x7A, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x00, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00 };
    std::vector<DWORD_PTR> addresses;
    FindPattren(processHandle, searchPattern, sizeof(searchPattern), 0x0, 0xFFFFFFFF, false, 0, addresses);
    for (const auto& address : addresses) {
        char buffer[100];
        size_t length = ReadStringA(processHandle, reinterpret_cast<void*>(address + 24), buffer, sizeof(buffer));
        if (length > 0) {
            std::cout << "String at address " << std::hex << address << ": " << buffer << std::endl;
        }
    }
    CloseHandle(processHandle);

    return 0;

}