# WinRM Shell

Custom WinRM client with raw WSMan/SOAP implementation for authorized penetration testing. No pywinrm dependency.

## Features

- Raw WSMan/SOAP protocol implementation
- NTLM and Kerberos authentication
- Interactive shell with command history
- No external WinRM library dependency

## Usage

```bash
pip install requests requests-ntlm
python winrm_shell.py -t <target> -u <user> -p <password>
```

## Disclaimer

**This tool is provided for authorized security testing and educational purposes only.**

This software is intended to be used by security professionals during authorized penetration testing engagements, red team operations, and security research. Unauthorized use of this tool against systems you do not own or have explicit written permission to test is illegal and unethical.

The author assumes no liability for misuse of this software. By using this tool, you agree that you are solely responsible for your actions and that you will comply with all applicable local, state, national, and international laws.

## License

For educational and authorized security testing use only.
