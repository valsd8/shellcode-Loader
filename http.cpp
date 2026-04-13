#include "http.hpp"
#pragma comment(lib, "winhttp.lib")

std::vector<unsigned char> DownloadBinary(const std::wstring& host, const std::wstring& path)
{
    std::vector<unsigned char> buffer;

    HINTERNET hSession = WinHttpOpen(
        L"MyUserAgent/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );

    if (!hSession) return buffer;

    HINTERNET hConnect = WinHttpConnect(
        hSession,
        host.c_str(),
        INTERNET_DEFAULT_HTTP_PORT,
        0
    );

    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return buffer;
    }

    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect,
        L"GET",
        path.c_str(),
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        0
    );

    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return buffer;
    }

    BOOL ok = WinHttpSendRequest(
        hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS,
        0,
        WINHTTP_NO_REQUEST_DATA,
        0,
        0,
        0
    );

    if (ok) ok = WinHttpReceiveResponse(hRequest, NULL);

    if (ok)
    {
        DWORD size = 0;

        do {
            DWORD downloaded = 0;

            if (!WinHttpQueryDataAvailable(hRequest, &size) || size == 0)
                break;

            size_t oldSize = buffer.size();
            buffer.resize(oldSize + size);

            if (WinHttpReadData(hRequest,
                buffer.data() + oldSize,
                size,
                &downloaded))
            {
                buffer.resize(oldSize + downloaded);
            }
            else {
                buffer.resize(oldSize);
                break;
            }

        } while (size > 0);
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return buffer;
}
