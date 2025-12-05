#! /bin/bash

# SI-2 Flaw Remediation

# CONTROL: The organization:
# a. Identifies, reports, and corrects information system flaws;
# b. Tests software and firmware updates related to flaw remediation for effectiveness and
#    potential side effects before installation;
# c. Installs security-relevant software and firmware updates within [Assignment: 
#    organization-defined time period] of the release of the updates; and
# d. Incorporates flaw remediation into the organizational configuration management process.

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

controlid="SI-2 Flaw Remediation"

title1a="The Red Hat Enterprise Linux operating system must remove all software components after updated versions have been installed."
title1b="Checking with 'grep -i clean_requirements_on_remove /etc/yum.conf'."
title1c="Expecting:${YLO}
           clean_requirements_on_remove=1
           Note: If \"clean_requirements_on_remove\" is not set to \"1\", \"True\", or \"yes\", or is not set in \"/etc/yum.conf\", this is a finding."${BLD}
cci1="CCI-002617"
stigid1="RHEL-07-020200"
severity1="CAT III"
ruleid1="SV-204452r603261_rule"
vulnid1="V-204452"

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

file1='/etc/yum.conf'
fail=1

if [[ -f $file1 ]]
then
   cleanchk="$(grep clean_requirements_on_remove $file1)"
   if [[ $cleanchk ]]
   then
      for line in ${cleanchk[@]}
      do
         if ! [[ ${line:0:1} == '#' ]]
         then
            val="$(echo $line | awk -F= '{print $2}')"
            if ( (( $val == 1 )) || [[ $val == 'yes' || $val == 'True' ]] )
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
      echo -e "${NORMAL}RESULT:    ${RED}'clean_requirements_on_remove' is not defined in $file1${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}$file1 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, The operating system removes all software components after updated versions have been installed.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, The operating system does not remove all software components after updated versions have been installed.${NORMAL}"
fi

exit
