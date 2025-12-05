#! /bin/bash

# SI-3 Malicious Code Protection

# CONTROL: The organization:
# a. Employs malicious code protection mechanisms at information system entry and exit points
#    to detect and eradicate malicious code;
# b. Updates malicious code protection mechanisms whenever new releases are available in accordance
#    with organizational configuration management policy and procedures;
# c. Configures malicious code protection mechanisms to:
#    1. Perform periodic scans of the information system [Assignment: organization-defined frequency]
#       and real-time scans of files from external sources at [Selection (one or more); endpoint;
#       network entry/exit points] as the files are downloaded, opened, or executed in accordance
#       with organizational security policy; and
#    2. [Selection (one or more): block malicious code; quarantine malicious code; send alert to
#       administrator; [Assignment: organization-defined action]] in response to malicious code
#       detection; and
# d. Addresses the receipt of false positives during malicious code detection and eradication and
#    the resulting potential impact on the availability of the information system.

# Check if the script is being run as root
if [ "$EUID" -ne 0 ]
then
   echo "Please run with sudo or as root"
   exit
fi

# Color declarations
RED=`echo    "\e[31;1m"`        # bold red
GRN=`echo    "\e[32;1m"`        # bold green
BLD=`echo    "\e[0;1m"`         # bold black
CYN=`echo    "\e[33;1;35m"`     # bold cyan
YLO=`echo    "\e[33;1m"`        # bold yellow
BAR=`echo    "\e[32;1;46m"`     # aqua separator bar
NORMAL=`echo "\e[0m"`           # normal

stig="Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Version 3, Release: 10 Benchmark Date: 26 Jan 2023"

hostname="$(uname -n)"

if [[ -f /etc/redhat-release ]]
then
   os="$(cat /etc/redhat-release)"
else
   os="OS not defined"
fi

prog="$(basename $0)"

controlid="SI-3 Malicious Code Protection"

title1a="The Red Hat Enterprise Linux operating system must use a virus scan program."
title1b="Checking with: (using clamav as an example)
           a. yum list installed clamav
           b. crontab -l | grep clam
           c. grep -ir clam /etc/cron.daily
           d. grep -w clamscan /var/log/cron
           e. tail var/log/clamav/clamscan.log (check scan.log config)"
title1c="Expecting:${YLO}
           a. clamav.x86_64         0.103.8-3.el7              @epel
           b. 15,4,*,*,0 /bin/clamscan -r /home --move=/tmp/quar --log=/var/log/clamav/clamscan.log --infected & --quiet
           c. Get the name of the script and the command that cron.daily runs
           d. /etc/cron.daily/50-clamscan.sh:clamscan -r /home --move=/tmp/quar --log=/var/log/clamav/clamscan.log --infected & --quiet (for example)
           e. Evidence that the daily scan is logging
           Note: If there is no anti-virus solution installed on the system, this is a finding."${BLD}
cci1="CCI-000366"
stigid1="RHEL-07-032000"
severity1="CAT I"
ruleid1="SV-214801r603261_rule"
vulnid1="V-214801"

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid1${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid1${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid1${NORMAL}"
echo -e "${NORMAL}CCI:       $cci1${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 1:    ${BLD}$title1a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title1b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title1c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity1${NORMAL}"

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${CYN}VERIFY, (See CM-6 Configuration Settings: V-214801)${NORMAL}"
    
exit
