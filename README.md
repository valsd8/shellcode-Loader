# C++ PE & Shellcode Loader

A custom C++ loader supporting in-memory execution of shellcode and PE files, including .NET assemblies. This project explores advanced Windows internals, process manipulation, memory execution techniques and security mechanism research.

> **Disclaimer**
>
> This project is intended strictly for educational purposes, security research and authorized testing in controlled environments.
>
> Do not use this software for malicious purposes or against systems without explicit authorization. The author assumes no responsibility for misuse or damage resulting from the use of this project.

## Features

- **Shellcode execution:** Supports module stomping and APC queue injection as execution methods.
- **PE loading:** Supports in-memory loading of native PE files and .NET assemblies.
- **Indirect syscalls:** Implements indirect syscall techniques, including Tartarus' Gate.
- **Module stomping:** Uses existing modules as execution targets to avoid relying solely on unbacked memory allocations.
- **AMSI / ETW research:** Experiments with Hardware Breakpoints (HWBP) to intercept relevant Windows API execution paths without directly modifying the original `ntdll` or AMSI function bytes.
- **Dynamic API interception:** Explores hooks on `LdrLoadDll`, `GetProcAddress` and `NtCreateThreadEx`.

### .NET Assembly Loading

The .NET loading component uses an existing DLL allocation as a memory backing region, replacing its contents with the target .NET PE data.

### AMSI & ETW Research

The loader explores alternative approaches to AMSI and ETW instrumentation through hardware breakpoints and API interception.

For AMSI, it intercepts DLL loading and API resolution to redirect execution towards a manually mapped AMSI module.

For ETW, it explores interception of thread creation and hardware-breakpoint-based instrumentation of `EtwEventWrite`.

These implementations are experimental and may behave differently depending on the Windows version and execution environment.

## Demo

A short demonstration showing `certify.exe` being retrieved from a SharpCollection release URL and executed directly from memory through the loader, without first saving the executable to disk.

[▶ Watch demo.mp4](./demo.mp4)

## Usage

The loader provides a command-line interface with several execution options.

![Usage](https://github.com/user-attachments/assets/5bbeeb45-bc5c-43a7-a28b-b17dad01611a)

**Note:** The PowerShell script execution option currently displayed in the help menu is still under development and is not functional.

## Development Status

**Work in progress — stability and reliability are not guaranteed.**

This project is actively being developed. Some features are experimental, and unexpected behavior or crashes may occur.

## Roadmap

- [ ] AES-based payload encryption and key support
- [ ] Codebase refactoring and improved code quality
- [ ] Stack spoofing research
- [ ] Support for additional remote resource retrieval protocols beyond HTTP/HTTPS
- [ ] Improve stability and reliability

## Disclaimer

This repository is provided as-is, without warranties or guarantees of any kind. It is intended for legitimate security research, educational use and authorized security assessments only.
