#include <iostream>
#include <fstream>
#include <string>
#include <memory>
#include <windows.h>
#include <tlhelp32.h>

DWORD get_process_id(std::wstring procname);
bool dump(char* process_name, std::uintptr_t offset, uint64_t size);

int main(int argc, char** argv)
{
	char* process_name = argv[1];
	std::uintptr_t offset = std::atoll(argv[2]);
	uint64_t size = std::atoll(argv[3]);
    if (dump(process_name, offset, size))
    {
        std::cout << "[+] Successfully dumped content!" << std::endl;
    }
    else
    {
        std::cout << "[X] Could not dump the content :(" << std::endl;
    }
    return 0;

}

bool dump(char* process_name, std::uintptr_t offset, uint64_t size)
{
    size_t process_size = strlen(process_name);
    std::unique_ptr<wchar_t> w_process(new wchar_t[process_size + 1]);
    mbstowcs_s(NULL, w_process.get(), strlen(process_name) + 1, process_name, strlen(process_name));
    DWORD proc_id = get_process_id(w_process.get());

    HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, false, proc_id);
    if (!handle)
    {
        std::cout << "[!] Could not open the process :(" << std::endl;
        return false;
    }

    std::unique_ptr<char> buffer(new char[size]);
    if (ReadProcessMemory(handle,  reinterpret_cast<LPCVOID>(offset), reinterpret_cast<LPVOID>(buffer.get()), size, NULL))
    {
        std::ofstream dump("0x" + std::to_string(offset) + ".bin");
        dump.write(buffer.get(), size);
        dump.close();
        return true;

    }
    else
    {
        return false;
    }

}

DWORD get_process_id(std::wstring procname)
{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (snapshot && snapshot != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 process_entry{};
        process_entry.dwSize = sizeof(process_entry);

        if (Process32First(snapshot, &process_entry))
        {
            do
            {
                if (std::wstring(process_entry.szExeFile).find(procname) != std::wstring::npos)
                {
                    return process_entry.th32ProcessID;
                }
            } while (Process32Next(snapshot, &process_entry));
        }
        return -1;
    }
    return -1;
}