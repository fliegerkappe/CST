#! /bin/bash

# AC-9 Previous Logon (Access) Notification
#
# CONTROL: The information system notifies the user, upon successful logon (access) to the
# system, of the date and time of the last logon (access).
# 
# Supplemental Guidance: This control is applicable to logons to information systems via
# human user interfaces and logons to systems that occur in other types of architectures
# (e.g., service-oriented architectures). Related controls: AC-7, PL-4.

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

controlid="AC-9 Previous Logon (Access) Notification"

title1a="The Red Hat Enterprise Linux operating system must display the date and time of the last successful account logon upon an SSH logon."
title1b="Checking with: 'grep -i printlastlog /etc/ssh/sshd_config'"
title1c="Expecting:${YLO}
           PrintLastLog yes
           Note: If the \"PrintLastLog\" keyword is set to \"no\", is missing, or is commented out, this is a finding."${BLD}
cci1="CCI-000052"
stigid1="RHEL-07-040360"
severity1="CAT II"
ruleid1="SV-204591r603261_rule"
vulnid1="V-204591"

title2a="The Red Hat Enterprise Linux operating system must display the date and time of the last successful account logon upon logon."
title2b="Checking with: 'grep pam_lastlog /etc/pam.d/postlogin'"
title2c="Expecting:${YLO}
           session required pam_lastlog.so showfailed
           Note: If \"pam_lastlog\" is missing from \"/etc/pam.d/postlogin\" file, or the silent option is present, this is a finding."${BLD}
cci2="CCI-000052"
stigid2="RHEL-07-040530"
severity2="CAT III"
ruleid2="SV-204605r603261_rule"
vulnid2="V-204605"

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

file1="/etc/ssh/sshd_config"
fail=1

prtll="$(grep -i printlastlog $file1)"
if [[ $prtll ]]
then
   for line in ${prtll[@]}
   do
      prtllval="$(echo $line | awk '{print $2}')"
      if [[ $prtllval == 'yes' &&
            ${line:0:1} != '#' 
         ]]
      then
         echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
         fail=0
      else
         echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
      fi
   done
else
   echo -e "${NORMAL}RESULT:    ${RED}\"printlastlog\" not found in $file1${NORMAL}"
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, The system displays the date and time of the last successful account logon upon an SSH logon..${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, The system does not display the date and time of the last successful account logon upon an SSH logon..${NORMAL}"
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

datetime="$(date +%FT%H:%M:%S)"

file2="/etc/pam.d/postlogin"
fail=1

pamll="$(grep pam_lastlog $file2)"
if [[ $pamll ]]
then
   for line in ${pamll[@]}
   do
      if [[ ${line:0:1} != '#' && $line =~ 'showfailed' ]]
      then
         if [[ $line =~ 'silent' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
         else
            echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
            fail=0
         fi
      else
         echo -e "${NORMAL}RESULT:    $line${NORMAL}"
      fi
   done
else
   echo -e "${NORMAL}RESULT:    ${RED}\"pam_lastlog\" not found in $file2${NORMAL}"
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, The system displays the date and time of the last successful account logon upon logon..${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, The system does not display the date and time of the last successful account logon upon logon.${NORMAL}"
fi

exit
