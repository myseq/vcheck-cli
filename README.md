# vcehck-cli

A cmdline tool for [VulnCheck KEV](https://vulncheck.com/browse/kev).

## VulnCheck KEV

It is a community resource that enables security teams to manage vulnerabilities and risk with additional context and evidence-based
validation.

For more information, see https://vulncheck.com/kev

## Installation

Install and activate the virtual environment:
```bash
$ git clone git@github.com:myseq/vcheck-cli.git
$ cd vcheck-cli
$ python3 -m venv .venvhttps://myseq.github.io/posts/python_with_try_finally/
$ source .venv/bin/activate
$
$ pip install -r requirements.txt
```

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


