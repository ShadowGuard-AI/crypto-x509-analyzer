![Banner](banner.png)

# crypto-x509-analyzer
A tool to parse and analyze X.509 certificates, highlighting potential vulnerabilities such as weak signature algorithms, expired dates, or missing critical extensions. - Focused on Basic cryptographic operations

What the signature line means: the tool checks the certificate signature against the certificate's own public key. That is a self-signed consistency check, and it is a real signature verdict only for a self-signed certificate. A CA issued certificate was signed with the issuer's key, so this check fails on sound CA issued certificates; a real signature verdict for one needs the issuer certificate's public key, and this tool does not take an issuer certificate argument. Findings are reported in the log only: no finding, including an expired certificate or a weak signature algorithm, changes the exit code. The run exits 1 only when the certificate file cannot be read or parsed.

## Install
`git clone https://github.com/ShadowGuard-AI/crypto-x509-analyzer`
Then install the one dependency from the cloned directory: `pip install -r requirements.txt`

## Usage
`python3 main.py [-h] [-v] certificate_path`, run from the cloned directory. There is no executable or package by the repo name. Input must be a PEM encoded certificate; DER input is not accepted and fails with an error asking for PEM format.

## Parameters
- `certificate_path`: Path to the X.509 certificate file (PEM format). Required.
- `-h`: Show help message and exit
- `-v`: Enable verbose logging (DEBUG level).

## License
Copyright (c) ShadowStrikeHQ
