# CSR (Certificate Signing Request) and CRT fuzzer

## Overview

This project aims to generate malicious CSR files (and then generate CRT from those requests).
 - Firstly, some CSR with random values will be generated (in the *fuzzed_csrs/* folder) ;
 - Then, other CSR with malicious payloads (in the *fuzzed_csrs/malicious_csrs* folder).
	
The OpenSSL library will then trying to generate CRT file by validating the CSR files thanks to an AC (Authority Certification).

It is either possible to user your own AC, or generate a new one.  

## Requirement

 - Having python3.8
 - Optional : Having an AC (*<AC>.pem* and *<AC>.key*) if you want to generate the files with your AC

## Installation

```sh
$ pip3 install asn1==2.2.0 --user
```

## Usage

```sh
$ python3 src/csr_fuzz.py --help
usage: csr_fuzz.py [-h] [-o output] [-n number] [-pem CA pem] [-key CA key]

CSR fuzzer v1.0: generation of malicious/fuzzed Certificate Signing Requests and their associated CRT files.

optional arguments:
  -h, --help   show this help message and exit
  -o output    Generation path (defaults to ./fuzzed_csrs).
  -n number    Number of mutations for <randomize value> and <randomize OID> (defaults to 1)
  -pem CA pem  Path to CA certificate (.pem)
  -key CA key  Path to CA private key (.key)
```

## Contributors

Jean-Henri GRANAROLO
	
[Mikael Benhaiem](https://github.com/MikaelBenhaiem)
