#!/usr/bin/env python3
# Brandon Parncutt
# brandon.parncutt@gmail.com
# logsummary.py


"""
logsummary.py:  Python script which takes web server logs files in combined
format and returns a table of IPs and total number of bytes transferred as well
as the total number of requests. This table can then be sorted by bytes or the
number of requests.
"""


from optparse import OptionParser
from collections import defaultdict


def dictify_logline(line):
    '''
    Return a dictionary of the pertinent pieces of a combined format log
    file. Currently, the only fields of interest are "remote_host", "status",
    and "bytes_sent"
    '''

    split_line = line.split()
    return {'remote_host': split_line[0],
            'status': split_line[8],
            'bytes_sent': split_line[9],
            }


def generate_log_report(logfile):
    '''
    Return a dictionary of format remote_host=>[list of bytes_sent]
    This function takes a file object, iterates through all of the lines in the
    file, and generates a report of the number of bytes transferred to each
    remote host.
    '''

    bytes_dict = {}
    count_dict = {}
    for line in logfile:
        if len(line.strip()) == 0:
            continue
        line_dict = dictify_logline(line)
        host = line_dict['remote_host']
        try:
            bytes_sent = int(line_dict['bytes_sent'])
        except ValueError:
            continue
        bytes_dict[host] = bytes_dict.setdefault(host, 0) + bytes_sent
        if host in line_dict['remote_host']:
            count_dict[host] = count_dict.setdefault(host, 0) + 1
    report_dict = defaultdict(list)
    for host in (bytes_dict, count_dict):
        for key, value in host.items():
            report_dict[key].append(value)
    return report_dict


def open_files(files):
    for f in files:
        yield(f, open(f))


def combine_lines(files):
    for f, f_obj in files:
        for line in f_obj:
            yield line


if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option("-c", "--consolidate", dest="consolidate", default=False,
                      action="store_true", help="consolidate log files")
    parser.add_option("-s", "--sort", action="store", type="choice",
                      dest="sort", choices=["hit", "bytes", "none"],
                      default="none", help='sort by "bytes" or "hit"')
    parser.add_option("-w", "--write-to", dest="output_file", action="store",
                      help="write output to file name")

    (options, args) = parser.parse_args()
    logfiles = args

    opened_files = open_files(logfiles)

    if not args:
        import sys
        parser.print_help()
        sys.exit(1)

    if options.consolidate:
        opened_files = (('CONSOLIDATED', combine_lines(opened_files)),)

    for filename, file_obj in opened_files:
        if options.output_file:
            outputfile = open(options.output_file, 'w')
            print("*" * 60, file=outputfile)
            print(filename, file=outputfile)
            print("-" * 60, file=outputfile)
            print("%-20s%s\t%s" % ("IPADDRESS", "BYTES TRANSFERRED",
                                   "HIT COUNT"), file=outputfile)
            print("-" * 60, file=outputfile)
            report_dict = generate_log_report(file_obj)
            if options.sort == "hit":
                for ipaddr, values in sorted(report_dict.items(),
                                             key=lambda k: k[1][1],
                                             reverse=True):
                    print("%-20s%-20s\t%s" % (ipaddr, values[0],
                                              values[1]),
                          file=outputfile)
            if options.sort == "bytes":
                for ipaddr, values in sorted(report_dict.items(),
                                             key=lambda k: k[1][0],
                                             reverse=True):
                    print("%-20s%-20s\t%s" % (ipaddr, values[0],
                                              values[1]),
                          file=outputfile)
            if options.sort == "none":
                for ipaddr, values in report_dict.items():
                    print("%-20s%-20s\t%s" % (ipaddr, values[0],
                                              values[1]),
                          file=outputfile)
            print("=" * 60, file=outputfile)
        else:
            print("*" * 60)
            print(filename)
            print("-" * 60)
            print("%-20s%s\t%s" % ("IPADDRESS", "BYTES TRANSFERRED",
                                   "HIT COUNT"))
            print("-" * 60)
            report_dict = generate_log_report(file_obj)
            if options.sort == "hit":
                for ipaddr, values in sorted(report_dict.items(),
                                             key=lambda k: k[1][1],
                                             reverse=True):
                    print("%-20s%-20s\t%s" % (ipaddr, values[0], values[1]))
            if options.sort == "bytes":
                for ipaddr, values in sorted(report_dict.items(),
                                             key=lambda k: k[1][0],
                                             reverse=True):
                    print("%-20s%-20s\t%s" % (ipaddr, values[0], values[1]))
            if options.sort == "none":
                for ipaddr, values in report_dict.items():
                    print("%-20s%-20s\t%s" % (ipaddr, values[0], values[1]))
            print("=" * 60)
