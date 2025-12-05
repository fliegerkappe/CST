#! /bin/bash

# AU-8 Time Stamps

# CONTROL: The information system:
# a. Uses internal system clocks to generate time stamps for audit records; and
# b. Records time stamps for audit records that can be mapped to Coordinated Universal Time (UTC)
#    or Greenwich Mean Time (GMT) and meets [Assignment: organization-defined granularity of time
#    measurement].

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

stig="Red Hat Enterprise Linux 8 Security Technical Implementation Guide :: Version 1, Release: 13 Benchmark Date: 24 Jan 2024"

hostname="$(uname -n)"

if [[ -f /etc/redhat-release ]]
then
   os="$(cat /etc/redhat-release)"
else
   os="OS not defined"
fi

prog="$(basename $0)"

controlid="AU-8 Time Stamps"

title1a="RHEL 8 must securely compare internal information system clocks at least every 24 hours with a server synchronized to an authoritative time source, such as the United States Naval Observatory (USNO) time servers, or a time server designated for the appropriate DoD network (NIPRNet/SIPRNet), and/or the Global Positioning System (GPS)."
title1b="Checking with:
	   a. grep maxpoll /etc/chrony.conf
	   b. grep -i server /etc/chrony.conf"
title1c="Expecting: ${YLO}
           a. server 0.us.pool.ntp.mil iburst maxpoll 16
	   b. server 0.us.pool.ntp.mil
	   NOTE: If the \"maxpoll\" option is set to a number greater than 16 or the line is commented out, this is a finding.
	   NOTE: If the parameter \"server\" is not set or is not set to an authoritative DoD time source, this is a finding."${BLD}
cci1="CCI-001891"
stigid1="RHEL-08-030740"
severity1="CAT II"
ruleid1="SV-230484r627750_rule"
vulnid1="V-230484"

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

IFS='
'

file1="/etc/chrony.conf"
found=0
fail1=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file1 ]]
then
  maxpoll="$(grep maxpoll /etc/chrony.conf)"
  for line in ${maxpoll[@]}
  do
    IFS=' '
    string="$(echo $line)"
    for element in ${string[@]}
    do
      if [[ $found == 1 ]]
      then
	maxpollval=$element
	found=0
	if (( $maxpollval <= 16 ))
        then
          echo -e "${NORMAL}RESULT:    ${BLD}a. $line${NORMAL}"
	else
	  echo -e "${NORMAL}RESULT:    ${RED}a. $line${NORMAL}"
	fi
      elif [[ $element == "maxpoll" ]]
      then
	found=1
      fi
    done
    IFS=$'\n'
  done
  server="$(grep -E 'pool|server' $file1 | grep -v "^#")"
  if [[ $server ]]
  then
    for line in ${server[@]}
    do
      echo -e "${NORMAL}RESULT:    ${BLD}b. $line${NORMAL}"
    done
  else
    echo -e "${NORMAL}RESULT:    ${RED}b. an authoritative time source is not listed in $file1.${NORMAL}"
  fi
fi

echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${CYN}VERIFY, RHEL 8 must securely compare internal information system clocks at least every 24 hours with a server synchronized to an authoritative time source, such as the United States Naval Observatory (USNO) time servers, or a time server designated for the appropriate DoD network (NIPRNet/SIPRNet), and/or the Global Positioning System (GPS).${NORMAL}"

exit

