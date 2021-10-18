# Copyright (c) 2021, D. Scholefield
# All rights reserved.

# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

# Check SSL Certs for expiry dates in the near future
# Log output to Graylog to STDIO
# Version 1

# use: ssl_expiry_check.py <domain_list_file> 

import ssl
import time
import json
import re
import sys
from html import escape as html_escape
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta

# these versions will be used in the logging messages
__this_script_version = "1.0"
__GELF_version = "1.1"

# minimum number of days that needs to be remaining
# before the domain's SSL cert expires, otherwise warn!
__threshold = 75

# define the standard syslog alert levels
# because we'd prefer to use the name not numbers
syslog_alerts = {
    "emergency": 0,
    "alert": 1,
    "critcal": 2,
    "error": 3,
    "warning": 4,
    "notice": 5,
    "informational": 6,
    "debug": 7
}

# define a helper regex to detect blank lines
# in the domain file: we only need this def once
# so do it globally here
blank_line = re.compile(r'^\s*$')

# define a helper regex to ensure that the 'domains'
# that we read from the domain file are actually domains
# or at least not injection strings
safe_domain = re.compile(r'(https://)?([A-Za-z_0-9.-]+).*')

# getSSLCert will attempt to fetch the SSL cert from a
# domain and then return the x509 object containing the cert fields
# it can throw a whole zoo of exceptions which we will catch later
def getSSLCert(hostname:str, port:int) -> x509:
    conn = ssl.create_connection((hostname, port))
    # try with TLS first, then fall back to SSL2 or SSL3
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    except Exception as failed_protocol:
        writeGELFLog("SSL TLS context failure", 
            "could not create context for TLS (%s)" % failed_protocol, 
            "informational")
        context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)

    sock = context.wrap_socket(conn, server_hostname=hostname)
    certificate = ssl.DER_cert_to_PEM_cert(sock.getpeercert(True))
    pem = bytes(certificate, 'utf-8')
    cert = x509.load_pem_x509_certificate(pem, default_backend())
    return cert 

# checkCertandLog will retrieve the SSL cert with getSSLCert
# and then check the expiry date against the global threshold value
def checkCertandLog(hostname:str, port:int) -> None:
    try:
        myCert = getSSLCert(hostname, port) 
    except Exception as read_failure:    
        # log failure to STDOUT with exception details
        writeGELFLog("SSL cert read failure", 
            "could not read SSL cert (%s): %s" % (hostname,read_failure), 
            "emergency")
    else:
        days_to_expire = (myCert.not_valid_after - datetime.now()).days
        if days_to_expire < __threshold:
            writeGELFLog("SSL cert not timely for %s" % hostname, 
            "Expiry in %s days: which is within %s days (%s)" % (days_to_expire, __threshold, myCert.not_valid_after), 
            "alert")
        else:
            writeGELFLog("SSL cert not about to expire for %s" % hostname, 
            "Expiry in %s days: which is after %s days (%s)" % (days_to_expire, __threshold, myCert.not_valid_after), 
            "informational")

# GELF logs can inject JSON objects with specific fields
# defined at https://docs.graylog.org/en/3.3/pages/gelf.html
# note that syslog levels are passed as words and translated
# in the global dict syslog_alerts
# JSON is created by populating dict and dumping that as JSON
def writeGELFLog(short_message: str, full_message: str, level: str):
    # create dict for JSON contents
    log = {}

    # preset the standard values
    log['version'] = __GELF_version
    log['host'] = "SSL expiry check"
    log['timestamp'] = int(time.time())

    # add variable fields, check for HTML injection because long message
    # may contain value taken from command line or read from domains file
    log['short_message'] = html_escape(short_message)
    log['full_message'] = html_escape("[check_ssl_expire: v" + __this_script_version + "] (" + level + ") " + full_message)
    log['level'] = syslog_alerts[level]

    print(json.dumps(log))

# helper function to check that domain file line
# isn't blank
def notBlankLine(domain: str) -> bool:
    if blank_line.match(domain):
        return False
    else:
        return True
        
# start the checking script by sending heatbeat log entry
# this can be checked to ensure that the script is running
writeGELFLog("script starting up", 
            "heartbeat", 
            "informational")

# read the domains from the input file and process them
# one by one, ignoring blank lines
try:
    domains = [line.rstrip('\n') for line in open(sys.argv[1])]
except Exception as read_domain:
    writeGELFLog("domain file read failure", 
            "could not open domain file: %s" % read_domain, 
            "emergency")
else:
    # check each domain in turn, note default SSL port
    # may need to add this to domain file later if other ports used
    domain_file_line_count = 0
    for domain in domains:
        domain_file_line_count += 1
        if notBlankLine(domain):
            # and check for injections in the domains file, if it
            # doesn't match the safe domain regex then log an alert
            # and continue to the next line
            if safe_domain.match(domain):
                checkCertandLog(domain, 443)
            else:
                writeGELFLog("domain file possible injection", 
                    "found domain that may not be safe at line: %s" % domain_file_line_count, 
                    "emergency")










