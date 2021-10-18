# ssl_expiry_check
Check for imminent expiration of SSL domain certs and log results in GELF format to STDIO

Simple script to read a file called domains.txt which has a single domain on each line.
The variable '__threshold' is set to the number of days, such that if a the cert is due
to expire before that date, an alert log message will be output. Otherwise an informational
log message will be output.

use: ssl_expiry_check.py <domain_list_file>

