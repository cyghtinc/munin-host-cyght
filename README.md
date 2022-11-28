# munin-host-cyght
## What is munin-host-cyght?

munin-host-cyght is a online IP checker utility that retrieves valuable information from MISP

## Usage

    usage: misp-ip-search.py [-h] [-f path] [-i IP address]

    MISP Online IP Checker (Limit Of 15 IP Addresses Per 15 Minutes)

    optional arguments:
      -h, --help     show this help message and exit
      -f path        File to process (IP adress line by line
      -i IP address  Single IP adress

## Getting started

1. Download / clone the repo
3. Install required packages: `pip install -r requirements.txt` (on macOS add `--user`)
4. Set the API key for misp in `misp-ip-search.ini`

## Requirements

- Python 3.8 and higher 
- Internet Connection

## Typical Command Lines

Process the IP addresses given in the file, the results will appear in the results.csv file.

```bash
python misp-ip-search.py -f c:\users\user1\ips.txt
```

Processing only one IP addressת the result will appear in the console promt.

```bash
python misp-ip-search.py -i 0.0.0.0
```

## Get the API Keys
### MISP 

1. Log into your MISP 
2. Go to your profile "My Profile"
3. The value of `Authkey` is used as API key

## Warning
1. You can only make 15 requests in 15 minutes, after reaching the request limit the program will enter sleep mode and wait another 15 minutes so as not to be blocked, please do not exit the program, it will continue to scan the addresses after it sleeps.
2. Please do not delete or edit the file limit.txt if it appears, the file helps to track the number of requests made.
