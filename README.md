# Low Hanging Fruit Collector

A simple tool to collate testssl.sh output, especially useful when conducting SSL/TLS scans on multiple hosts.

## Usage

Best and most effective usage of the tool:

Run testssl.sh in a dedicated directory where you wish to save your output  
`testssl.sh --openssl=<insert your path here> --json --quiet --color 0 --file <file with your targets>`

Run LHFC  
`var=$(pwd); lhfc.py --path $var`

You'll get a CSV file with the output

## Prerequisites

1. testssl.sh - https://github.com/drwetter/testssl.sh
2. OpenSSl - https://www.openssl.org/source/ 
3. Pandas - https://pandas.pydata.org/

