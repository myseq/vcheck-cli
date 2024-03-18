# vcehck-cli

A cmdline tool for [VulnCheck KEV](https://vulncheck.com/browse/kev).

## VulnCheck KEV

It is a community resource that enables security teams to manage vulnerabilities and risk with additional context and evidence-based
validation.

For more information, see https://vulncheck.com/kev

## Installation/Setup

Install and activate the virtual environment:
```bash
$ git clone git@github.com:myseq/vcheck-cli.git
$ cd vcheck-cli
$ python3 -m venv .venvhttps://myseq.github.io/posts/python_with_try_finally/
$ source .venv/bin/activate
$
$ pip install -r requirements.txt
```

The VulnCheck platform uses a token system to allow access.
You must obtain a VulnCheck API token in order to use the VulnCheck KEV service.

Just following the instruction at VulnCheck to [Register for Access](https://docs.vulncheck.com/getting-started/register).

Then save the token at a safe place. And follow by setup your VulnCheck token for the tool:
```bash
$ export VC_TOKEN="<insert your VulnCheck token here"
```

## Usage

To show the simple help screen:
```bash
$ ./main.py -h
usage: main.py [-h] [-e <cve> [<cve> ...]] [-v]

A cmdline tool for VulnCheck KEV. (https://vulncheck.com/browse/kev)

options:
  -h, --help            show this help message and exit
  -e <cve> [<cve> ...]  Specifying CVEs
  -v                    verbose output

        VulnCheck KEV

        It is a community resource that enables security teams  to manage
        vulnerabilities and risk with additional context and evidence-based
        validation.

        For more information, see https://vulncheck.com/kev

```

To search a CVE: 
```bash
$ ./main.py -ve cve-2024-1709
```

To exit the virtual environment:
```bash
$ deactivate
```

## History

 - [ 2024.03.11 ] : Create the token.
 - [ 2024.03.16 ] : Download zip file successfully.
 - [ 2024.03.17 ] : Extract JSON and load into a list (vcdata). Search by CVE.

## Links 

 - MySeq [blog post](https://myseq.github.io/posts/vulncheck_kev_community/)


