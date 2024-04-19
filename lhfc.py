#!/usr/bin/env python3

import json
from pathlib import PurePath
import os
from os.path import isfile, join
from os import listdir
import csv
import argparse
import pandas as pd

#GLOBAL
alreadyReported = []
df = pd.DataFrame({})
#df.index.name = "Host"
#df.at[0,0] = "padding"
def isVulnerable(entry):
    risk = ["HIGH", "MEDIUM", "LOW"]
    if entry["severity"] in risk:
        return True
    else:
        return False

def isExcluded(entry):
    # this excludes entries that we don't want to print - filtered by entry["id"]
    excluded = ["overall_grade", "cipherlist_AVERAGE", "DNS_CAArecord", "BREACH", "OCSP_stapling"]
    if entry["id"] in excluded:
        return False
    else:
        return True

def isCipher(entry):
    if entry["id"].startswith("cipher-"): #this makes sure ciphers are not printed - improves readability
        return False
    else:
        return True

def isReported(entry):
    if entry["id"] in alreadyReported:
        return False
    else:
        alreadyReported.append(entry['id'])
        return True


def displayVulns(json_file):
    alreadyReported.clear()
    global df
    with open (json_file) as f:
        rawdata = json.load(f)
    host = rawdata[0]["ip"]
    host = host.replace("/", "")
    print("\nHost -> " + host)
    for entry in rawdata:
        if isVulnerable(entry) and isExcluded(entry) and isReported(entry) and isCipher(entry):
            if host not in df.index.names:
                df.index.name = host
            if entry["id"] not in df.columns:
                df[entry["id"]] = df.get([entry["id"], host])
                #df[entry["id"]] = host
                #print(host)
                #print(df)
            df.at[host,entry["id"]] = "X"
            #df = df.append({entry["id"]:host}, ignore_index=True)
            #df[entry["id"]] = host 
            print(entry["id"] + " - " + entry["finding"])


def displayVulnsFind(json_file, find):
    alreadyReported.clear()
    with open (json_file) as f:
        rawdata = json.load(f)
    host = rawdata[0]["ip"]
    host = host.replace("/", "")
    for entry in rawdata:
        if isVulnerable(entry) and isReported(entry) and entry["id"].startswith(find):
                #print(host + " - " + entry["finding"])
                print(host)


def displayVulnsCiphers(json_file):
    with open (json_file) as f:
        rawdata = json.load(f)
    host = rawdata[0]["ip"]
    host = host.replace("/", "")
    print("\nHost: " + host)
    for entry in rawdata:
        if isVulnerable(entry) and entry["id"].startswith("cipher-"):
            print(entry["finding"])


def createCSV(json_file, verbose):
    with open (json_file) as f:
        rawdata = json.load(f)

    host = rawdata[0]["ip"]
    host = host.replace("/", "")
    if verbose:
        filename = "verbose_output_" + host + ".csv"
    else:
        filename = "output_" + host + ".csv"
    print("-> Start writing to CSV")
    with open(filename, mode='w') as output_file:
        writer = csv.writer(output_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
        writer.writerow(["", host])
        for entry in rawdata:
            if isVulnerable(entry):
                writer.writerow([entry["id"], entry["finding"]])
            elif verbose:
                writer.writerow([entry["id"], ""])
    print("-> Stop writing to CSV")
    output_file.close()




def json_path(string):
    if os.path.isfile(string) & string.endswith(".json"):
        return string
    else:
        raise argparse.ArgumentTypeError(f"{string} is not a valid json file")

def isJson(string):
    if string.endswith(".json"):
        return True
    else:
        return False



def cmdParser():
    parser = argparse.ArgumentParser(description='SSL/TLS Automator by Alexander Wilczek')
    #parser.add_argument('--file', type = json_path, help="JSON output files to process")
    parser.add_argument('--path', required=True, help="Provide path to directory containing one or multiple json files or json file directly")
    parser.add_argument('--find', help="Find specific vuln")
    parser.add_argument('--csv', action=argparse.BooleanOptionalAction, help="Create CSV output")
    parser.add_argument('--ciphers', action=argparse.BooleanOptionalAction, help="Dispaly ciphers only")
    parser.add_argument('-v', '--verbose', action=argparse.BooleanOptionalAction, help="Add non vulnerable rows to CVS output - requires --csv flag")

    args = parser.parse_args()
    return args




def main():
    args = cmdParser()

    files = [os.path.join(args.path,f) for f in listdir(args.path) if isfile(join(args.path, f))]
    for f in files:
        if isJson(f):
            if args.csv:
                createCSV(args.file, args.verbose)

            elif args.ciphers:
                displayVulnsCiphers(f)

            elif args.find:
                displayVulnsFind(f, args.find)

            else:
                displayVulns(f)

    df1 = df.fillna('')
    print(df1)
    df1.to_csv(os.path.join(args.path,"results.csv"))

if __name__ == "__main__":
    main()
