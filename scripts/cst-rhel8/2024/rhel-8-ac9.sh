#! /bin/bash

# AC-9 Protection of Audit Information
#
# CONTROL:
# a. Protect audit information and audit logging tools from unauthorized access, modification,
#    and deletion; and
# b. Alert [Assignment: organization-definedpersonnel or roles] upon detection of unauthorized
#    access, modification, or deletion of audit information.

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

controlid="AC-9 Protection of Audit Information"

title1a="RHEL 8 must display the date and time of the last successful account logon upon logon."
title1b="Checking with:'grep pam_lastlog /etc/pam.d/postlogin'."
title1c="Expecting: ${YLO} session required pam_lastlog.so showfailed
           NOTE: If \"pam_lastlog\" is missing from \"/etc/pam.d/postlogin\" file, or the silent option is present, this is a finding."${BLD}
cci1="CCI-000052"
stigid1="RHEL-08-020340"
severity1="CAT III"
ruleid1="SV-230381r858726_rule"
vulnid1="V-230381"

title2a="RHEL 8 must display the date and time of the last successful account logon upon an SSH logon."
title2b="Checking with: 'grep -ir printlastlog /etc/ssh/sshd_config'."
title2c="Expecting: ${YLO}PrintLastLog yes
           NOTE: If the "PrintLastLog" keyword is set to "no", is missing, or is commented out, this is a finding.
	   NOTE: If conflicting results are returned, this is a finding."${BLD}
cci2="CCI-000052"
stigid2="RHEL-08-020350"
severity2="CAT II"
ruleid2="SV-230382r858717_rule"
vulnid2="V-230382"

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

file1="/etc/pam.d/postlogin"

fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file1 ]]
then
  lastlog="$(grep pam_lastlog $file1)"
  if [[ $lastlog ]]
  then
    for line in ${lastlog[@]}
    do
      if [[ $line =~ 'showfailed' ]]
      then
        if [[ $line =~ 'required' ]]
        then
	  echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
	  fail=0
        else
	  echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
	  fail=2
	fi
      else
        echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
      fi
    done
  else
    echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file1 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, RHEL 8 displays the date and time of the last failed logon attempts upon logon.${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, RHEL 8 displays the date and time of the last failed logon attempts upon logon, but the \"required\" option is missing.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, RHEL 8 does not display the date and time of the last successful account logon upon logon.${NORMAL}"
fi



echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid2${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid2${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid2${NORMAL}"
echo -e "${NORMAL}CCI:       $cci2${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 2:    ${BLD}$title2a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title2b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title2c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity2${NORMAL}"

IFS='
'

file2="/etc/ssh/sshd_config"

fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file2 ]]
then
  printlast="$(grep -ir printlastlog $file2 2>/dev/null)"
  if [[ $printlast ]]
  then
    for line in ${printlast[@]}
    do
      printlastval="$(echo $printlast | awk -F "PrintLastLog" '{print $2}' | sed 's/ //g')"
      if [[ ${printlast:0:1} != "#" && $printlastval == "yes" ]]
      then
	echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
	fail=0
      else
	echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
      fi
    done
  else
    echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file2 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, RHEL 8 displays the date and time of the last successful account logon upon an SSH logon.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, RHEL 8 does not display the date and time of the last successful account logon upon an SSH logon.${NORMAL}"
fi

exit
