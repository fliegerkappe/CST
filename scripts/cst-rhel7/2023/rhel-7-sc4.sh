#! /bin/bash

# SC-4 Information in Shared Resources
#
# CONTROL: The information system prevents unauthorized and unintended information 
# transfer via shared system resources.

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

controlid="SC-5 Denial of Service (DoS) Protection"

title1a="The operating system is configured to restrict access to the kernel message buffer."
title1b="Checking with:
           a. 'sysctl kernel.dmesg_restrict'.
	   b. 'grep -r kernel.dmesg_restrict /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/null'"
title1c="Expecting:${YLO}
           a. kernel.dmesg_restrict = 1
	   b. /etc/sysctl.conf:kernel.dmesg_restrict = 1
              /etc/sysctl.d/99-sysctl.conf:kernel.dmesg_restrict = 1
	   Note: If \"kernel.dmesg_restrict\" is not set to \"1\", is missing or commented out, this is a finding.
	   Note: If conflicting results are returned, this is a finding."${BLD}
cci1="CCI-002385"
stigid1="RHEL-07-040510"
severity1="CAT II"
ruleid1="SV-255927r880791_rule"
vulnid1="V-72271"

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

file1arr=('/run/sysctl.d/*' '/etc/sysctl.d/*' '/usr/local/lib/sysctl.d/*' '/usr/lib/sysctl.d/*' '/lib/sysctl.d/*' '/etc/sysctl.conf')

restrict=null
val=null

check1=""
check2=""

restrict="$(sysctl -a 2>/dev/null | grep kernel.dmesg_restrict)"

if [[ $restrict ]]
then
   for line in ${restrict[@]}
   do
      val="$(echo $line | awk -F'= ' '{print $2}')"
      if [[ $val == 1 ]]
      then
         echo -e "${NORMAL}RESULT:    ${BLD}a. $line${NORMAL}"
         check1="pass"
      else
         echo -e "${NORMAL}RESULT:    ${RED}a. $line${NORMAL}"
         check1="fail"
      fi
   done
else
   echo -e "${NORMAL}RESULT:    ${RED}a. Nothing returned${NORMAL}"
fi

for xfile in ${file1arr[@]}
do
   kdr="$(grep -r kernel.dmesg_restrict $xfile 2>/dev/null)"
   if [[ $kdr ]]
   then
      for yfile in ${kdr[@]}
      do
         filename="$(echo $xfile | awk -F: '{print $1}')"
         restrictval="$(echo $yfile | awk -F'= ' '{print $2}')"
         if [[ ${yfile:0:1} == '#' ]]
         then
            echo -e "${NORMAL}RESULT:    ${CYN}b. $filename:${NORMAL}$yfile${NORMAL}"
         elif [[ $restrictval == 1 ]]
         then
            echo -e "${NORMAL}RESULT:    ${CYN}b. $filename:${BLD}$yfile${NORMAL}"
            check2="pass"
         else
            echo -e "${NORMAL}RESULT:    ${CYN}b. $filename:${RED}$yfile${NORMAL}"
            check2="fail"
         fi
      done
   fi
done

if [[ $check1 == "pass" && $check2 == "pass" ]]
then
   fail=0
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, The operating system is configured to restrict access to the kernel message buffer${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, The operating system is not configured to restrict access to the kernel message buffer${NORMAL}"
fi

exit

