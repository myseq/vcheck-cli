# vcehck-cli

A cmdline tool for [VulnCheck KEV](https://vulncheck.com/browse/kev).

## VulnCheck KEV

It is a community resource that enables security teams to manage vulnerabilities and risk with additional context and evidence-based
validation.

For more information, see https://vulncheck.com/kev

## Installation

```bash
$ git clone git@github.com:myseq/vcheck-cli.git
$ cd vcheck-cli
$ python3 -m venv .venv
$ source .venv/bin/activate
$
$ pip install -r requirements.txt
```

```bash
$ ./main.py -ve cve-2024-1709
```

## History

 - [ 2024.03.11 ] : Create the token.
 - [ 2024.03.16 ] : Download zip file successfully.
 - [ 2024.03.17 ] : Extract JSON and load into a list (vcdata). Search by CVE.

