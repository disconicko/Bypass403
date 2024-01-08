# Bypass403
A multi-threaded program for bypassing 403 and 401 responses.

## Usage
python3 Bypass403.py -f [HOST FILE|OPTIONAL] -u [URL|OPTIONAL] -p [PATH|REQUIRED] -t [THREADS|DEFAULT 10] -H [HEADERS|OPTIONAL]
python3 Bypass403.py -f hosts.txt -p admin -t 20 -H "Authorization: bearer tokenValue"
python3 Bypass403.py -u http://example.text.com -p admin/dashboard -t 10 -H "Cookie: cookieValue"
