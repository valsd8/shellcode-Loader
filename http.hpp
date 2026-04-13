#pragma once


#include "def.h"
#include <winhttp.h>
#include <vector>
#include <iostream>

std::vector<unsigned char> DownloadBinary(const std::wstring& host, const std::wstring& path);