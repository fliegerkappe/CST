#! /bin/bash

# AC-10 Concurrent Session Control

# CONTROL: The information system limits the number of concurrent sessions for each
# [Assignment: organization-defined account and/or account type] to
# [Assignment: organization-defined number].

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

controlid="AC-10 Concurrent Session Control"

title1a="RHEL 8 must limit the number of concurrent sessions to ten for all accounts and/or account types."
title1b="Checking with 'grep -r -s '^[^#].*maxlogins' /etc/security/limits.conf /etc/security/limits.d/*.conf'."
title1c="Expecting: ${YLO}* hard maxlogins 10
           NOTE: If the \"maxlogins\" item is missing, commented out, or the value is set greater than \"10\" and is not documented with the Information System Security Officer (ISSO) as an operational requirement for all domains that have the \"maxlogins\" item assigned, this is a finding."${BLD}
cci1="CCI-000054"
stigid1="RHEL-08-020024"
severity1="CAT III"
ruleid1="SV-230346r877399_rule"
vulnid1="V-230346"

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

file1="/etc/security/limits.conf"
filearr1=("/etc/security/limits.conf" "/etc/security/limits.d/*.conf")
fail=1

datetime="$(date +%FT%H:%M:%S)"

for file in ${filearr1[@]}
do
  maxlogins="$(grep -r -s '^[^#].*maxlogins' $file)"
  if [[ $maxlogins ]]
  then
    for line in ${maxlogins[@]}
    do
      if [[ $line =~ '*' && $line =~ 'hard' ]]
      then
        maxloginsval="$(echo $line | awk '{print $4}')"
	if  (( $maxloginsval <= 10 )) 
        then
          echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
          fail=0
        else
          echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
        fi
      else
        echo -e "${NORMAL}RESULT:    $line${NORMAL}"
      fi
    done
  else
    echo -e "${NORMAL}RESULT:    maxlogins is not defined in $file${NORMAL}"
  fi
done

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, The operating system limits the number of concurrent sessions to 10 for all accounts and/or account types.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, The operating system does not limit the number of concurrent sessions to 10 for all accounts and/or account types.${NORMAL}"
fi

exit
