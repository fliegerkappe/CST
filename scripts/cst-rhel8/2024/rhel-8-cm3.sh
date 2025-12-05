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

controlid="CM-3 Configuration Change Control"

title1a="The RHEL 8 file integrity tool must notify the system administrator when changes to the baseline configuration or anomalies in the operation of any security functions are discovered within an organizationally defined frequency."
title1b="Checking with:
           a. yum list installed aide | grep aide
	   b. ls -al /etc/cron.* | grep aide 
	   c. find [path/to/mailapp]
	   d. grep aide /etc/crontab /var/spool/cron/root
	   e. sudo more /etc/cron.daily/aide"
title1c="Expecting:${YLO}
           a. aide.x86_64    0.16-14.el8_5.1     @AppStream
	   b. -rwxr-xr-x 1 root root 29 Nov 22 2015 /etc/cron.daily/aide
	   c. /usr/sbin/mail
	   d. /etc/crontab:30 04 * * * root /usr/sbin/aide /var/spool/cron/root: 30 04 * * * root usr/sbin/aide
	   e. #!/bin/bash
	   e. /usr/sbin/aide --check | /bin/mail -s \"$HOSTNAME - Daily aide integrity check run\" root@sysname.mil
	   NOTE: If AIDE is not installed, ask the System Administrator how file integrity checks are performed on the system.
	   NOTE: If the file integrity application does not exist, or a script file controlling the execution of the file integrity application does not exist, or the file integrity application does not notify designated personnel of changes, this is a finding."${BLD}
cci1="CCI-001744"
stigid1="RHEL-08-010360"
severity1="CAT II"
ruleid1="SV-230263r627750_rule"
vulnid1="V-230263"

title2a="RHEL 8 must be configured to allow sending email notifications of unauthorized configuration changes to designated personnel."
title2b="Checking with: 'yum list installed mailx'."
title2c="Expecting: ${YLO}mailx.x86_64     12.5-29.el8     @rhel-8-for-x86_64-baseos-rpm
           NOTE: If "mailx" package is not installed, this is a finding.${BLD}"
cci2="CCI-001744"
stigid2="RHEL-08-010358"
severity2="CAT II"
ruleid2="SV-256974r902755_rule"
vulnid2="V-256974"

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

file1a="/etc/cron"
file1b="/etc/crontab"
file1c="/var/spool/cron/root"

dir1="/etc/cron"

installed=0
dailyjob=0

fail=0

isinstalled="$(yum list installed | grep aide)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $isinstalled ]]
then
  for pkg in ${isinstalled[@]}
  do
     echo -e "${NORMAL}RESULT:    ${BLD}a. $pkg${NORMAL}"
     installed=1
  done
  if [[ -d $dir1.daily ]]
  then
    aidejob="$(ls -al 2>/dev/null $dir1.* | grep aide)" 
    if [[ $aidejob ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}b. $aidejob${NORMAL}"
      jobname="$(echo $aidejob | awk '{print $9}')"
      aidefile="$(find $dir1.* -name $jobname)"
      aidedir="$(dirname $aidefile)"
      jobcmd="$(grep $jobname 2>/dev/null $file1b $file1c 2>/dev/null)"
      if [[ $jobcmd ]]
      then
        for line in ${jobcmd[@]}
        do
          echo -e "${NORMAL}RESULT:    ${BLD}c. $line${NORMAL}"
          if [[ $line =~ "mail" ]]
          then
            IFS=' ' read -a fieldvals <<< "${line[@]}"
            for element in ${fieldvals[@]}
            do
              if [[ $element =~ "mail" ]]
              then
       	 mailapp=$element
       	 if [[ -f $mailapp ]]
                then
       	   echo -e "${NORMAL}RESULT:    ${BLD}d. $mailapp exists{NORMAL}"
       	 else
       	   echo -e "${NORMAL}RESULT:    ${RED}d. $mailapp does not exist${NORMAL}"
       	   fail=1
       	 fi
              fi
            done
          fi
        done
      fi
      dailyjob=1
      aidecmd="$(cat $aidefile)"
      for line in ${aidecmd[@]}
      do
        echo -e "${NORMAL}RESULT:    ${BLD}e. $line${NORMAL}"
      done
      aidecmd="$(cat $dir1.*/aide)"
    else
      echo -e "${NORMAL}RESULT:    ${RED}b. No cronjobs for aide found in $dir1.${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    /etc/cron.daily not found${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}The AIDE package is not installed${NORMAL}"
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, File Integrity Checking (AIDE): The AIDE package is not installed.${NORMAL}"
fi

if [[ $fail == 0 ]] 
then
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, File Integrity Checking (AIDE): A file integrity tool verifies the baseline operating system configuration at least weekly.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, File Integrity Checking (AIDE): A file integrity tool does not verify the baseline operating system configuration at least weekly.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

isinstalled="$(yum list installed mailx 2>/dev/null)"
if [[ $isinstalled =~ "mailx" ]]
then
  echo -e "${NORMAL}RESULT:    ${GRN}The MAILX package is installed${NORMAL}"
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, The operating system is configured to allow sending email notifications..${NORMAL}"
else
  echo -e "${NORMAL}RESULT:    ${RED}The MAILX package is not installed${NORMAL}"
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, The operating system is not configured to allow sending email notifications..${NORMAL}"
fi

exit
