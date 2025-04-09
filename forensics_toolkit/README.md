# Memory Forensics Toolkit

A comprehensive PowerShell-based memory forensics analysis toolkit using Volatility 3.

## Overview

This toolkit provides a modular, organized framework for analyzing memory dumps with Volatility 3. It automates common forensic tasks, identifies suspicious activities, and generates readable reports in multiple formats.

## Prerequisites

- PowerShell 5.1 or higher
- Volatility 3 (installed and available in PATH)
- A memory dump file from a Windows system

## Features

The toolkit includes analysis modules for:

1. **System Information**
   - Basic system details from memory dump

2. **Process Analysis**
   - Process listing and relationships
   - Command line arguments
   - Console history
   - Suspicious process detection

3. **DLLs and Modules Analysis**
   - Loaded DLLs per process
   - Kernel modules
   - Driver objects
   - Suspicious module detection

4. **Memory Analysis**
   - Malware detection (malfind)
   - Memory injections
   - API hooks

5. **Network Analysis**
   - Active/recent connections
   - Suspicious connection detection

6. **File Analysis**
   - Files in memory
   - Suspicious file detection

7. **Registry Analysis**
   - Autorun keys
   - Persistence mechanisms
   - User activity artifacts

8. **Handle Analysis**
   - Process handles to files, registry, etc.
   - Suspicious handle detection

9. **User Activity Analysis**
   - Clipboard contents
   - Console command history
   - Program execution timeline

## Usage

Run the main script and provide the path to the memory dump file:

```powershell
.\main.ps1 C:\path\to\memory.raw
```

You can also provide the memory dump path when prompted.

## Output

The toolkit generates multiple types of outputs:

- Text reports for each analysis module
- CSV files for easier data analysis
- HTML reports with formatted results
- Comprehensive timeline of suspicious activity

All outputs are saved in the `output` directory, organized by timestamp and analysis category.

## Customization

The toolkit is built with modularity in mind. You can easily:

- Add new Volatility plugins
- Customize suspicious pattern detection
- Modify report formats
- Add new analysis modules

## Known Limitations

- The toolkit is designed for Windows memory dumps
- Performance may vary based on the size of the memory dump
- Some pattern detections may require adjustment based on your specific Volatility 3 output formats

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- The Volatility Framework team for their exceptional memory forensics tool
- The digital forensics community for continuous research and knowledge sharing 