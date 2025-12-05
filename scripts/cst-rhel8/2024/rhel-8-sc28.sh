#! /bin/bash

# SC-28 Protection of Information At Rest
#
# CONTROL: Protect the [Selection (one or more): confidentiality; integrity] of the following
# information at rest: [Assignment: organization-defined information at rest].

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

stig="Red Hat Enterprise Linux 8 Security Technical Implementation Guide :: Version 1, Release: 4 Benchmark Date: 27 Oct 2021"

hostname="$(uname -n)"

if [[ -f /etc/redhat-release ]]
then
   os="$(cat /etc/redhat-release)"
else
   os="OS not defined"
fi

prog="$(basename $0)"

controlid="SC-28 Protection of Information At Rest"

title1a="All RHEL 8 local disk partitions must implement cryptographic mechanisms to prevent unauthorized disclosure or modification of all information that requires at rest protection."
title1b="Checking with 'blkid'."
title1c="Expecting: ${YLO}/dev/mapper/rhel-root: UUID=\"67b7d7fe-de60-6fd0-befb-e6748cf97743\" TYPE=\"crypto_LUKS\"${BLD}
           NOTE: ${YLO}If there is a documented and approved reason for not having data-at-rest encryption, this requirement is Not Applicable.${BLD}
           NOTE: ${YLO}Every persistent disk partition present must be of type \"crypto_LUKS\". If any partitions other than pseudo file systems (such as /proc or /sys) are not type \"crypto_LUKS\", ask the administrator to indicate how the partitions are encrypted. If there is no evidence that all local disk partitions are encrypted, this is a finding."${BLD}
cci1="CCI-001199"
stigid1="RHEL-08-010030"
severity1="CAT II"
ruleid1="SV-230224r917864_rule"
vulnid1="V-230224"

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid1${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid1${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid1${NORMAL}"
echo -e "${NORMAL}CCI:       $cci1${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 1:    ${BLD}$title1a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title1b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title1c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity1${NORMAL}"

IFS='
'

fail=0

clblks="$( blkid )"

datetime="$(date +%FT%H:%M:%S)"

for line in ${clblks[@]}
do
  if [[ $line =~ 'crypto_LUKS' ]]
  then
    echo -e "${NORMAL}RESULT:    ${GRN}$line${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
    fail==1
  fi
done

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, The operating system prevents unauthorized disclosure or modification of all information requiring at-rest protection by using disk encryption.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, The operating system does not prevent unauthorized disclosure or modification of all information requiring at-rest protection by using disk encryption.${NORMAL}"
fi

exit
