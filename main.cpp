// SX Payload Packer for WIN32

// Based on TX SX Pro Custom Payload Packer by CTCaer
// https://gist.github.com/CTCaer/13c02c05daec9e674ba00ce5ac35f5be)

#include <windows.h>
#include <commctrl.h>

#include <string>
#include <fstream>
#include <vector>

#include "hash_sha256.h"

HWND hStatusBar = nullptr;

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);

void repackPayload(std::wstring fullFilename);

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow)
{
    const wchar_t CLASS_NAME[]  = L"SX";

    WNDCLASS wc = { };

    wc.lpfnWndProc   = WindowProc;
    wc.hInstance     = hInstance;
    wc.lpszClassName = CLASS_NAME;

    RegisterClass(&wc);

    HWND hwnd = CreateWindowEx(0, CLASS_NAME, L"SXPayloadPacker", WS_CAPTION | WS_SYSMENU, CW_USEDEFAULT, CW_USEDEFAULT,
                               300, 70, nullptr, nullptr, hInstance, nullptr);
    if (!hwnd) { return 0; }

    HWND hLabel = CreateWindowEx(0, L"STATIC", L"Drop payload here", WS_CHILD | WS_VISIBLE | SS_CENTER,
                                 0, 0, 300, 20, hwnd, nullptr, hInstance, nullptr);
    if (!hLabel) { return 0; }

    hStatusBar = CreateWindowEx(0, STATUSCLASSNAME, nullptr, WS_CHILD | WS_VISIBLE,
                                     0, 30, 200, 20, hwnd, nullptr, hInstance, nullptr);
    if (!hStatusBar) { return 0; }

    int statuses[] = {SB_SIMPLE};
    SendMessage(hStatusBar, SB_SETPARTS, 1, (LPARAM)statuses);
    SendMessage(hStatusBar, SB_SETTEXT, 0, (LPARAM)L"");

    DragAcceptFiles(hwnd, TRUE);
    ShowWindow(hwnd, nCmdShow);

    MSG msg {};
    while (GetMessage(&msg, nullptr, 0, 0) > 0)
    {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return 0;
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg)
    {
        case WM_DROPFILES:
        {
            auto hDrop = (HDROP)wParam;
            UINT cFiles = DragQueryFile(hDrop, 0xFFFFFFFF, nullptr, 0);

            if (cFiles > 1)
            {
                SendMessage(hStatusBar, SB_SETTEXT, 0, (LPARAM)L"ERROR: Please drop just one file");
                return 0;
            }

            TCHAR szFile[MAX_PATH];
            DragQueryFile(hDrop, 0, szFile, MAX_PATH);
            repackPayload(szFile);
            DragFinish(hDrop);
            return 0;
        }
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;

        case WM_PAINT:
        {
            PAINTSTRUCT ps;
            BeginPaint(hwnd, &ps);
            EndPaint(hwnd, &ps);
        }
            return 0;

        default:
            break;

    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

void repackPayload(std::wstring fullFilename)
{
    const std::string inFilename = std::string(fullFilename.begin(), fullFilename.end());
    std::ifstream file(inFilename, std::ios::binary);

    if (!file.is_open())
    {
        const std::string msg = "File not found: " + inFilename;
        SendMessage(hStatusBar, SB_SETTEXT, 0, (LPARAM)L"ERROR: File not found");
        return;
    }

    file.seekg(0, std::ios::end);
    std::vector<char> payload(file.tellg());

    file.seekg(0, std::ios::beg);
    file.read(payload.data(), static_cast<std::streamsize>(payload.size()));

    file.close();

    const std::string filePath = inFilename.substr(0, inFilename.find_last_of('\\'));
    const std::string outputOriginalFilename = filePath + "\\boot.dat";
    std::string outputFilename = outputOriginalFilename;

    unsigned i = 0;
    while (std::ifstream(outputFilename).good())
    {
        outputFilename = outputOriginalFilename + "_" + std::to_string(i++);
    }

    std::ofstream outfile(outputFilename, std::ios::binary);

    if (!outfile.is_open())
    {
        MessageBoxA(nullptr, "Error opening the target file", "ERROR", MB_OK);
        return;
    }

    std::vector<char> header;

    header.assign({0x43, 0x54, 0x43, 0x61, 0x65, 0x72, 0x20, 0x42, 0x4F, 0x4F, 0x54, 0x00,
                   0x56, 0x32, 0x2E, 0x35 });

    hash_sha256 sha;
    sha.sha256_init();
    sha.sha256_update(reinterpret_cast<const uint8_t*>(payload.data()), payload.size());
    const sha256_type shaOResult = sha.sha256_final();

    header.insert(header.end(), shaOResult.begin(), shaOResult.end());

    auto payloadDestination = std::string({ 0x00, 0x00, 0x01, 0x40 });
    header.insert(header.end(), payloadDestination.begin(), payloadDestination.end());

    header.resize(header.size() + sizeof(unsigned));
    *reinterpret_cast<unsigned*>(&header[header.size() - sizeof(unsigned)]) = static_cast<unsigned>(payload.size());

    header.resize(header.size() + sizeof(unsigned));
    *reinterpret_cast<unsigned*>(&header[header.size() - sizeof(unsigned)]) = 0;

    header.resize(header.size() + 0xA4, '\x00');

    sha.sha256_init();
    sha.sha256_update(reinterpret_cast<const uint8_t*>(header.data()), header.size());
    const sha256_type shaHResult = sha.sha256_final();
    header.insert(header.end(), shaHResult.begin(), shaHResult.end());

    outfile.write(header.data(),  static_cast<std::streamsize>(header.size()));
    outfile.write(payload.data(), static_cast<std::streamsize>(payload.size()));
    outfile.close();

    std::wstring msg = std::wstring(L"Saved to: ");
    msg.append(outputFilename.begin(), outputFilename.end());
    SendMessage(hStatusBar, SB_SETTEXT, 0, (LPARAM)msg.c_str());
}