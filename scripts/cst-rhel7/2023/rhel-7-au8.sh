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
NORMAL=`echo "\e[0m"`           # NORMAL

stig="Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Version 3, Release: 10 Benchmark Date: 26 Jan 2023"

hostname="$(uname -n)"

if [[ -f /etc/redhat-release ]]
then
   os="$(cat /etc/redhat-release)"
else
   os="OS not defined"
fi

prog="$(basename $0)"

controlid="AU-8 Time Stamps"

title1a="The Red Hat Enterprise Linux operating system must, for networked systems, synchronize clocks with a server that is synchronized to one of the redundant United States Naval Observatory (USNO) time servers, a time server designated for the appropriate DoD network (NIPRNet/SIPRNet), and/or the Global Positioning System (GPS)."
title1b="Checking with
           a. 'ps -ef | grep ^ntp'                      (or chronyd)
           b. 'grep maxpoll /etc/ntp.conf'              (or chrony.conf)
           c. 'grep -ir \"ntpd -q\" /etc/cron.daily/*     (or 'chronyc sources')
           d. 'ls -al /etc/cron.* | grep ntp'           (or 'makestep' ?)"
title1c="Expecting:${YLO}
           (for ntpd)
           a. ntp       68795      1  0 11:31 ?        00:00:00 /usr/sbin/ntpd -u ntp:ntp -g
           b. maxpoll 10
           c. -rwx------.   1 root root  219 Oct 30 13:12 ntpdate
           d. (needs info)
           Note: If the \"maxpoll\" option is set to a number greater than 16 or the line is commented out, this is a finding.
           Note: If a crontab file does not exist in the \"/etc/cron.daily\" that executes the \"ntpd -q\" (or chronyd equivalent) command, this is a finding.
           Note: If the \"maxpoll\" option is not set or the line is commented out, this is a finding.${BLD}"
cci1="CCI-001891"
stigid1="RHEL-07-040500"
severity1="CAT II"
ruleid1="SV-204603r809230_rule"
vulnid1="V-72269"

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

datetime="$(date +%FT%H:%M:%S)"

file1a="/etc/ntp.conf"
file1b="/etc/chrony.conf"
fail=0

ntp="$(ps -ef | grep ^ntp 2>/dev/null | grep -v 'grep')"
chrony="$(ps -ef | grep ^chrony 2>/dev/null | grep -v 'grep')"

if [[ $ntp ]]
then
   timesvrs="$(ntpd -q)"
   if [[ $timesvrs ]]
   then
      for line in ${timesvrs[@]}
      do
         if [[ $line =~ '*' && ! $line =~ "LOCAL" ]]
         then
            echo -e "${NORMAL}RESULT:    ${GRN}$line${NORMAL}"
         else
            echo -e "${NORMAL}RESULT:    $line${NORMAL}"
         fi
      done
   fi
elif [[ $chrony ]]
then
   ntpservers="$(chronyc sources)"
   echo -e "${NORMAL}RESULT:    ${BLD}The \"chronyd.service\" is running${NORMAL}"
   if [[ $ntpservers ]]
   then
      for line in ${ntpservers[@]}
      do
         if [[ $line =~ "^*" ]]
         then
            IFS=' ' read -a servers <<< $line
            if [[ ! ${servers[1]} =~ ${hostname} &&
                  ! ${servers[1]} =~ 'localhost' &&
                  ! ${servers[1]} =~ '^127.'
               ]]
            then
               echo -e "${NORMAL}RESULT:    ${GRN}$line${NORMAL}"
            else
               echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
               fail=1
            fi
         else
            echo -e "${NORMAL}RESULT:    $line${NORMAL}"
         fi
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}No NTP sources found${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}The \"chronyd\" service is not running.${NORMAL}"
fi

echo "           -------------------------------------------------------------------------------"

if [[ $ntp ]]
then
   maxpoll=""
   if [[ -f $file1a ]]
   then
      ntpmaxpoll="$(grep 'maxpoll' $file1a)"
      if [[ $ntpmaxpoll ]]
      then
         for line in ${ntpmaxpoll[@]}
         do
            IFS=' ' read -a rule <<< $line
            for val in ${rule[@]}
            do
               if [[ $maxpoll == 'found'  ]]
               then
                  if (( $val <= 16 && $val > 0 ))
                  then
                     echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}" 
                  else
                     echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
                     fail=1
                  fi
                  maxpoll=""
                  break
               fi
               if [[ $val == 'maxpoll' ]]
               then
                  maxpoll='found'
               fi
            done
         done
      else
         echo -e "${NORMAL}RESULT:    ${RED}\"maxpoll\" is not defined in $file1a${NORMAL}"
         fail=1
      fi
   else
      echo -e "${NORMAL}RESULT:    ${RED}$file1a not found${NORMAL}"
      fail=1
   fi
elif [[ $chrony ]]
then
   if [[ -f $file1b ]]
   then
      chronyservers="$(grep '^server' $file1b)"
      if [[ $chronyservers ]]
      then
         for line in ${chronyservers[@ ]}
         do
            chronymaxval="$(echo $line | awk -F'maxpoll ' '{print $2}')"
            if [[ $chronymaxval ]]
            then
               if (( $chronymaxval <= 16 && $chronymaxval > 0 ))
               then
                  echo -e "${NORMAL}RESULT:    ${BLD}$file1b:$line${NORMAL}" 
               else
                  echo -e "${NORMAL}RESULT:    ${RED}$file1b:$line${NORMAL}"
                  fail=1
               fi
            else
               echo -e "${NORMAL}RESULT:    ${RED}$file1b:$line${NORMAL}"
               fail=1
            fi
         done
      else
         echo -e "${NORMAL}RESULT:    ${RED}\"maxpoll\" is not defined in $file1b${NORMAL}"
         fail=1
      fi
   else
      echo -e "${NORMAL}RESULT:    ${RED}$file1b not found${NORMAL}"
      fail=1
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}A network time service is not running${NORMAL}"
   fail=1
fi

if [[ -d '/etc/cron.daily' ]]
then
   ctab="$(grep -ir 'ntpd -q' /etc/cron.*)"
   if [[ $ctab ]]
   then
      for line in ${ctab[@]}
      do
         filename="$(echo $line | awk -F: '{print $1}')"
         cronjob="$(echo $line | awk -F: '{print $2}')"
         echo -e "${NORMAL}RESULT:    ${CYN}$filename:${BLD}$cronjob${NORMAL}"
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}No cronjob found for 'ntpd -q'${NORMAL}"
      fail=1
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}'/etc/cron.*' not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, Network Time Protocol: NTP is syncronized to one of the redundant United States Naval Observatory (USNO) time servers a time server designated for the appropriate DoD network (NIPRNet/SIPRNet) and/or the Global Positioning System (GPS) and \"maxpoll\" is set to a value of \"16\" or less.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, Network Time Protocol: Either NTP is not syncronized to one of the redundant United States Naval Observatory (USNO) time servers a time server designated for the appropriate DoD network (NIPRNet/SIPRNet) and/or the Global Positioning System (GPS) - \"maxpoll\" is not properly set - or a crontab file that executes the \"ntpd -q\" command was not found.${NORMAL}"
fi

exit

