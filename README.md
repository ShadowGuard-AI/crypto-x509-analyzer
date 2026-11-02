![Introduction banner: the grove after rain before any name is spoken](intro-banner.png)

# crypto-x509-analyzer

Title block: the name above is set in Bona Nova SC in leaf green on a light sky plate, with a leaf green rule beneath it and one small sliced stalk ring at the left of the first heading only, in the manner of a herbarium specimen label.

![Logo](logo.png)

![Banner](banner.png)

![Animated scene](scene.svg)

![Major separator](sep-heavy.svg)

# crypto-x509-analyzer
A tool to parse and analyze X.509 certificates, highlighting potential vulnerabilities such as weak signature algorithms, expired dates, or missing critical extensions. - Focused on Basic cryptographic operations

What the signature line means: the tool checks the certificate signature against the certificate's own public key. That is a self-signed consistency check, and it is a real signature verdict only for a self-signed certificate. A CA issued certificate was signed with the issuer's key, so this check fails on sound CA issued certificates; a real signature verdict for one needs the issuer certificate's public key, and this tool does not take an issuer certificate argument. Findings are reported in the log only: no finding, including an expired certificate or a weak signature algorithm, changes the exit code. The run exits 1 only when the certificate file cannot be read or parsed.

![Major separator](sep-heavy.svg)

> Grove memorandum: the signature test is self signed only. It tries the signature against the certificate's own public key, so it gives a real verdict only for a self-signed certificate.

## Install
`git clone https://github.com/ShadowGuard-AI/crypto-x509-analyzer`
Then install the one dependency from the cloned directory: `pip install -r requirements.txt`

![Minor separator](sep-light.svg)

> Grove memorandum: PEM only. Input must be a PEM encoded certificate; DER input is turned away with an error asking for PEM format.

## Usage
`python3 main.py [-h] [-v] certificate_path`, run from the cloned directory. There is no executable or package by the repo name. Input must be a PEM encoded certificate; DER input is not accepted and fails with an error asking for PEM format.

![Minor separator](sep-light.svg)

> Grove memorandum: findings never change the exit code. Everything the tool finds lives in the log; the run exits 1 only when the certificate file cannot be read or parsed.

## Parameters
- `certificate_path`: Path to the X.509 certificate file (PEM format). Required.
- `-h`: Show help message and exit
- `-v`: Enable verbose logging (DEBUG level).

![Minor separator](sep-light.svg)

> Grove memorandum: the suspect algorithm roster names three identifiers and no others: RSA with MD5, RSA with SHA1, and DSA with SHA1. No warning means none of those three appeared, not that no weak algorithm appeared.

## License
Copyright (c) ShadowStrikeHQ

![Major separator](sep-heavy.svg)

## Grove notes, gathered on the walk

The controls of this re-skin read Read the Certificate, Show the Full Log, and Show the Grove Notes. Its headings read One Certificate at a Time, PEM Only, Three Weak OIDs Named, The Signature Test Is Self Signed Only, and Findings Never Change the Exit. The licence line above stands as printed in the live README and is flagged, not corrected: it names ShadowStrikeHQ, which does not match the organisation in the install line. Beside it sits a separate fact. The repository LICENSE file carries the MIT License. Its holder line gives a pen name together with a single initial for the remaining name. That fact is recorded. The initial is not expanded.
