#include "http.hpp"
#pragma comment(lib, "winhttp.lib")
std::vector<unsigned char> DownloadBinary(const std::wstring& host, const std::wstring& path, bool https)
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

    INTERNET_PORT port = https ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT;

    HINTERNET hConnect = WinHttpConnect(
        hSession,
        host.c_str(),
        port,
        0
    );
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return buffer;
    }

    DWORD flags = https ? WINHTTP_FLAG_SECURE : 0;

    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect,
        L"GET",
        path.c_str(),
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        flags
    );

    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return buffer;
    }

    // (optional but often needed depending on target)
    if (https) {
        DWORD securityFlags =
            SECURITY_FLAG_IGNORE_UNKNOWN_CA |
            SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
            SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
            SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;

        WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &securityFlags, sizeof(securityFlags));
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

            if (WinHttpReadData(
                hRequest,
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