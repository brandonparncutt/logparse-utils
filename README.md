# logparse-utils
A collection of python script(s) which parse various web server (Apache, Nginx,
Varnish, etc.) access logs and return data. Logs must be in 'combined' format.

## logsummary.py
Reads access logs specified on command line and returns a table of of stats:

* IP
* Total bytes transferred
* Total number of requests

This data can then be sorted by request count or bytes count.

###Execute on CLI:
```
Usage: logsummary.py [options]

Options:
  -h, --help            show this help message and exit
  -c, --consolidate     consolidate log files
  -s SORT, --sort=SORT  sort by "bytes" or "hit"
  -w OUTPUT_FILE, --write-to=OUTPUT_FILE
                        write output to file name
```
