#!/usr/bin/env python


"""profiler.py - A script to extract, parse and average rule profiling
 statistics for Snort."""

from __future__ import print_function

__author__  = 'Damian Torres'
__email__   = 'datorr2@gmail.com'
__version__ = '1.0'

import sys
import os
import argparse
import re


# Constants
SCRIPT_NAME     = os.path.basename(__file__)
USAGE_HELP      = """Usage: {} [-hV] [file]

Extract, parse and average rule profiling statistics for Snort.

Optional arguments:
  file                      input filename (default: stdin)

Other options
  -h, --help                display this help and exit
  -V, --version             output version information and exit
""".format(SCRIPT_NAME)
SCAN_HEADER     = "Rule Profile Statistics \(all rules\)"
SCAN_BOUNDARY   = "=" * 58
OUTPUT_HEADER   = "Average Rule Profile Statistics (across {} processes)" \
                + " (all rules)"
OUTPUT_HEADINGS = [ "Num", "SID", "GID", "Rev", "Checks", "Matches",
                    "Alerts", "Microsecs", "Avg/Check", "Avg/Match",
                    "Avg/Nonmatch", "dis" ]
OUTPUT_FORMAT   = " {:>6} {:>8} {:>3} {:>3} {:>11} {:>11}" \
                + " {:>9} {:>19} {:>9} {:>9} {:>12} {:>9}"


# Error print function
def eprint(*args, **kwargs):
    print (*args, file=sys.stderr, **kwargs)


# Print usage
def usage():
    print(USAGE_HELP)
    return


# Handle command-line options and arguments
def optionsHandler():
    parser = argparse.ArgumentParser(add_help=True,
      description="Extract, parse and average rule profiling statistics" \
      " for Snort.")
    parser.add_argument("-V", "--version", action="version",
      help="output version information and exit")
    parser.add_argument('filename', metavar='file', type=str, nargs="?",
      help="input filename (default: stdin)")

    args = parser.parse_args()
    
    return args.filename


# Read file and separate messages by process
def parseMessages(fn):
    # Open specified file or if none, use stdin
    if (fn):
        try:
            fh = open(fn, 'r')
        except:
            eprint("Error opening {}".format(fn))
    else:
        fh = sys.stdin

    # Separate message streams by pid
    logStreamList = []
    logStreams = {}
    scanHeader = re.compile(SCAN_HEADER)
    scanPid = re.compile(".*\[(\d+)\]:.*")
    scanStatLine = re.compile(".*\[\d+\]:[ ]+(\d+)[ ]+(\d+)[ ]+(\d+)[ ]+" \
      + "(\d+)[ ]+(\d+)[ ]+(\d+)[ ]+(\d+)[ ]+(\d+)[ ]+(\d+\.\d+)[ ]+" \
      + "(\d+\.\d+)[ ]+(\d+\.\d+)[ ]+(\d+)")

    for line in fh:
        m = scanPid.match(line)
        if (m):
            pid = m.group(1)
            # Only capture streams that contain the SCAN_HEADER
            if scanHeader.search(line):
                logStreamList.append(pid)
            if pid in logStreamList:
                if pid not in logStreams:
                    logStreams[pid] = []
                logStreams[pid].append(line.rstrip())

    # Parse out the separate tables individually
    statsTable = {}

    for k in logStreams:
        for line in logStreams[k]:
            m = scanStatLine.match(line)
            if (m and len(m.groups()) == 12):
                rank, sid, gid, rev, checks, matches, \
                  alerts, ms, ac, am, an, dis = m.groups()
                sig = "{}:{}:{}".format(gid, sid, rev)
                if sig not in statsTable:
                    statsTable[sig] = {
                      "rank":[],
                      "checks":[],
                      "matches":[],
                      "alerts":[],
                      "ms":[],
                      "ac":[],
                      "am":[],
                      "an":[],
                      "dis":[] }
                statsTable[sig]["rank"].append(float(rank))
                statsTable[sig]["checks"].append(float(checks))
                statsTable[sig]["matches"].append(float(matches))
                statsTable[sig]["alerts"].append(float(alerts))
                statsTable[sig]["ms"].append(float(ms))
                statsTable[sig]["ac"].append(float(ac))
                statsTable[sig]["am"].append(float(am))
                statsTable[sig]["an"].append(float(an))
                statsTable[sig]["dis"].append(float(dis))

    # Calculate all averages
    avgStatsTable = {}

    for k in statsTable:
        sT = statsTable[k]
        if k not in avgStatsTable:
            avgStatsTable[k] = {}
        aST = avgStatsTable[k]
        aST.update({"rank": round(sum(sT["rank"])/len(sT["rank"]), 1) })
        aST.update({"checks": round(sum(sT["checks"])/len(sT["checks"]), 1) })
        aST.update({"matches": round(sum(sT["matches"])/len(sT["matches"]), 1) })
        aST.update({"alerts": round(sum(sT["alerts"])/len(sT["alerts"]), 1) })
        aST.update({"ms": round(sum(sT["ms"])/len(sT["ms"]), 1) })
        aST.update({"ac": round(sum(sT["ac"])/len(sT["ac"]), 1) })
        aST.update({"am": round(sum(sT["am"])/len(sT["am"]), 1) })
        aST.update({"an": round(sum(sT["an"])/len(sT["an"]), 1) })
        aST.update({"dis": round(sum(sT["dis"])/len(sT["dis"]), 1) })

    # Print sorted averages
    sorted_keys = sorted(avgStatsTable,
      key=lambda name: avgStatsTable[name]["rank"])
    outHdr = OUTPUT_HEADER.format(len(logStreams))
    print("", outHdr)
    print("", ("=" * len(outHdr)))
    print(OUTPUT_FORMAT.format(*OUTPUT_HEADINGS))
    # Build the lines that go under the headers
    underLines = []
    for hdr in OUTPUT_HEADINGS:
        underLines.append("=" * len(hdr))
    print(OUTPUT_FORMAT.format(*underLines))

    for k in sorted_keys:
        gid, sid, rev = k.split(":")
        vals = avgStatsTable[k]
        print(OUTPUT_FORMAT.format(vals["rank"], sid, gid, rev,
          vals["checks"], vals["matches"], vals["alerts"], vals["ms"],
          vals["ac"], vals["am"], vals["an"], vals["dis"]))

    return


# Main function
def main():
    fn = optionsHandler()
    parseMessages(fn)
    return


if __name__ == "__main__":
    main()

