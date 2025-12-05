#! /bin/bash

# CM-3 Configuration Change Control
#
# CONTROL: The organization:
# a. Determines the types of changes to the information system that are configuration-controlled;
# b. Reviews proposed configuration-controlled changes to the information system and approves or
#    disapproves such changes with explicit consideration for security impact analyses;
# c. Documents configuration change decisions associated with the information system;
# d. Implements approved configuration-controlled changes to the information system;
# e. Retains records of configuration-controlled changes to the information system for [Assignment:
#    organization-defined time period];
# f. Audits and reviews activities associated with configuration-controlled changes to the information
#    system; and
# g. Coordinates and provides oversight for configuration change control activities through [Assignment:
#    organization-defined configuration change control element (e.g., committee, board] that convenes
#    [Selection (one or more): [Assignment: organization-defined frequency]; [Assignment: organization-defined configuration change conditions]].

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
YLO=`echo    "\e[93;1m"`        # bold yellow
BAR=`echo    "\e[11;1;44m"`     # blue separator bar
NORMAL=`echo "\e[0m"`           # normal

stig="Red Hat Enterprise Linux 9 Version: 2 Release: 5 Benchmark Date: 02 Jul 2025"

hostname="$(uname -n)"

if [[ -f /etc/redhat-release ]]
then
   os="$(cat /etc/redhat-release)"
else
   os="OS not defined"
fi

prog="$(basename $0)"

controlid="CM-3 Configuration Change Control"

title1a="RHEL 9 must have the s-nail package installed."
title1b="Checking with: dnf list --installed s-nail"
title1c="Expecting: ${YLO}s-nail.x86_64          14.9.22-6.el9)
           NOTE: If the \"s-nail\" package is not installed, this is a finding."${BLD}
cci1="CCI-001744"
stigid1="RHEL-09-215095"
severity1="CAT II"
ruleid1="SV-257842r1044916"
vulnid1="V-257842"

title2a="RHEL 9 must have the AIDE package installed."
title2b="checking with: find / -name aide.conf"
title2c="Expecting: ${YLO}/etc/aide.conf
           NOTE: If the \"acl\" rule is not being used on all selection lines in the \"/etc/aide.conf\" file, is commented out, or ACLs are not being checked by another file integrity tool, this is a finding."${BLD}
cci2="CCI-001744 CCI-002696"
stigid2="RHEL-09-651010"
severity2="CAT II"
ruleid2="SV-258134r1101983"
vulnid2="V-258134"

title3a="RHEL 9 must routinely check the baseline configuration for unauthorized changes and notify the system administrator when anomalies in the operation of any security functions are discovered."
title3b="Checking with: 
           a. ls -al /etc/cron.* | grep aide
           b. grep aide /etc/crontab /var/spool/cron/root
           c. more /etc/cron.daily/aide"
title3c="Expecting: ${YLO}
           a. -rwxr-xr-x 1 root root 29 Nov 22 2015 aide
           b. /etc/crontab: 30 04 * * * root usr/sbin/aide
           b. /var/spool/cron/root: 30 04 * * * root usr/sbin/aide
           c. #!/bin/bash
           c. /usr/sbin/aide --check | /bin/mail -s \"\$HOSTNAME - Daily aide integrity check run\" root@sysname.mil
           NOTE: If the file integrity application does not exist, a script file controlling the execution of the file integrity application does not exist, or the file integrity application does not notify designated personnel of changes, this is a finding."
cci3="CCI-001744 CCI-002699 CCI-002702"
stigid3="RHEL-09-651015"
severity3="CAT II"
ruleid3="SV-258135r1045267"
vulnid3="V-258135"

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

fail=0

datetime="$(date +%FT%H:%M:%S)"

isinstalled="$(dnf list --installed 2>&1 s-nail | grep -Ev 'Updating|Installed')"

if [[ $isinstalled ]]
then
  echo -e "${NORMAL}RESULT:    ${BLD}$isinstalled${NORMAL}"
else
  echo -e "${NORMAL}RESULT:    ${RED}$isinstalled${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]] 
then
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, RHEL 9 has the s-nail package installed.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, RHEL 9 does not have the s-nail package installed.${NORMAL}"
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
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 2:    ${BLD}$title2a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title2b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title2c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity2${NORMAL}"

IFS='
'

fail=0

datetime="$(date +%FT%H:%M:%S)"

search="acl"

isinstalled="$(dnf list --installed 2>/dev/null aide | grep -Ev 'Updating|Installed')"

if [[ $isinstalled ]]
then

  location="$(find / 2>/dev/null -name aide.conf)"
  
  if [[ $location ]]
  then
  
    # In a restricted environment, "more /etc/aide.conf" will not work. You
    # have to use "cat /etc/aide.conf" instead
  
    echo -e "${NORMAL}RESULT:    ${BLD}\"aide.conf\" is in $location${NORMAL}"
    aideconfig="$(cat $location | grep -v "^!"| grep -v "=" | grep -v "^#" | grep -v "@@" | grep -v "verbose" | grep -v "dbout" | grep -v "report_url" | grep -v "^:::" | grep -v "^/etc/aide.conf$")"
  
    categories="$(cat $location | grep -v "^!" | grep "=" | grep -v "^#" | grep -v "@@" | grep -v "verbose" | grep -v "dbout" | grep -v "report_url")"
  
    badcat=( )
    goodcat=( )
  
    for line in ${categories[@]}
    do
      if ! [[ $line =~ $search ]]
      then
        badcat+=("$line")
      else
        goodcat+=("$line")
      fi
    done
  
    echo -e "${YLO}ACL Categories -----------------------------------${NORMAL}"
    for line in ${goodcat[@]}
    do
      echo -e "${NORMAL}RESULT:    $line${NORMAL}"
    done
  
    echo #blank line
  
    echo -e "${YLO}ACL Selections -----------------------------------${NORMAL}"
    for line in ${aideconfig[@]}
    do
      found=0
      for category in ${goodcat[@]}
      do
        cat="$(echo $category | awk '{print $1}')"
        compare="$(echo $line | awk '{print $2}')"
        if [[ $compare == $cat || $line =~ $search ]]
        then
          echo -e "${NORMAL}RESULT:    $line${NORMAL}"
          found=1
          break
        fi
      done
      if [[ $found == 0 ]]
      then
        if (( ${#badcat[@]} > 0 ))
        then
          for category in ${badcat[@]}
          do
            cat="$(echo $category | awk '{print $1}')"
            compare="$(echo $line | awk '{print $2}')"
            if [[ $compare == $cat || $line =~ $search ]]
            then
              echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
              fail=1
              break
            fi
          done
        fi
      fi
    done
  else
    echo -e "${NORMAL}RESULT:    ${RED}\"aide.conf\" not found${NORMAL}"
    fail=1
  fi
else
  fail=1
  echo -e "${NORMAL}RESULT:    ${RED}The \"aide\" package is not installed${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, RHEL 9 is configured so that the file integrity tool verifies Access Control Lists (ACLs).${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, RHEL 9 is not configured so that the file integrity tool verifies Access Control Lists (ACLs).${NORMAL}"
fi


echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid3${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid3${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid3${NORMAL}"
echo -e "${NORMAL}CCI:       $cci3${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 3:    ${BLD}$title3a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title3b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title3c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity3${NORMAL}"

IFS='
'

fail=0

datetime="$(date +%FT%H:%M:%S)"

cron="$(ls -al 2>/dev/null /etc/cron.* | grep aide)"
if [[ $cron ]]
then
  echo -e "${NORMAL}RESULT:    ${BLD}a. $cron${NORMAL}"
else
  fail=1
  echo -e "${NORMAL}RESULT:    ${RED}a. Nothing returned${NORMAL}"
fi

crontab="$(grep aide 2>/dev/null /etc/crontab /var/spool/cron/root)"
if [[ $crontab ]]
then
  for line in ${crontab[@]}
  do
    file="$(echo $line | awk -F: '{print $1}')"
    task="$(echo $line | awk -F: '{print $2}')"
    echo -e "${NORMAL}RESULT:    ${BLD}b. ${CYN}$file:${BLD}$task${NORMAL}"
  done
else
  fail=1
  echo -e "${NORMAL}RESULT:    ${RED}b. Nothing returned${NORMAL}"
fi

if [[ -e /etc/cron.daily/aide ]]
then
  daily="$(more /etc/cron.daily/aide)"
  for line in ${daily[@]}
  do
    echo -e "${NORMAL}RESULT:    ${BLD}c. $line${NORMAL}"
  done
else
  fail=1
  echo -e "${NORMAL}RESULT:    ${RED}c. Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${GRN}PASSED, RHEL 9 routinely checks the baseline configuration for unauthorized changes and notify the system administrator when anomalies in the operation of any security functions are discovered.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${RED}FAILED, RHEL 9 does not routinely check the baseline configuration for unauthorized changes and notify the system administrator when anomalies in the operation of any security functions are discovered.${NORMAL}"
fi

exit
