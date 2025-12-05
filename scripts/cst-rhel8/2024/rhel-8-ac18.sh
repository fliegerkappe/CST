#! /bin/bash

# AC-18 Wireless Access
#
# CONTROL: The organization:
# a. Establishes usage restrictions, configuration/connection requirements, and implementation
#    guidance for wireless access; and
# b. Authorizes wireless access to the information system prior to allowing such connections.

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

controlid="AC-18 Wireless Access"

title1a="RHEL 8 wireless network adapters must be disabled."
title1b="Checking with 'nmcli device | egrep -i '(radio|wifi)''."
title1c="Expecting: ${YLO}
           nothing returned or wlp3s0 wifi disconnected
           NOTE: This is N/A for systems that do not have physical wireless network adapters.
           NOTE: If a wireless interface is configured and its use on the system is not documented with the Information System Security Officer (ISSO), this is a finding."${BLD}
cci1="CCI-001444"
stigid1="RHEL-08-040110"
severity1="CAT II"
ruleid1="SV-230506r627750_rule"
vulnid1="V-230506"

title2a="RHEL 8 Bluetooth must be disabled."
title2b="Checking with: 'grep bluetooth /etc/modprobe.d/*'."
title2c="Expecting: ${YLO}/etc/modprobe.d/bluetooth.conf:install bluetooth /bin/true
           NOTE: If the device or operating system does not have a Bluetooth adapter installed, this requirement is not applicable.
           NOTE: This requirement is not applicable to mobile devices (smartphones and tablets), where the use of Bluetooth is a local AO decision.
           NOTE: If the Bluetooth driver blacklist entry is missing, a Bluetooth driver is determined to be in use, and the collaborative computing device has not been authorized for use, this is a finding."${BLD}
cci2="CCI-001443"
severity2="CAT II"
stigid2="RHEL-08-040111"
ruleid2="SV-230507r627750_rule"
vulnid2="V-230507"

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

nmcli="$(nmcli device | egrep -i '(radio|wifi)')"
fail=0

datetime="$(date +%FT%H:%M:%S)"

if [[ $nmcli ]]
then
   for line in ${nmcli[@]}
   do
      if [[ ! $line =~ 'disconnected' ]]
      then
         echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
         echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, Wireless Access: Wireless network adapters are not disabled${NORMAL}"
      else
          echo -e "${NORMAL}RESULT:    $line${NORMAL}"
          echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, Wireless Access: Wireless network adapters are disabled${NORMAL}"
      fi
   done
else
   echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}N/A, No wireless adapters were found${NORMAL}"

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

dir2="/etc/modprobe.d"

bluetooth="$(grep bluetooth $dir2/*)"
fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ $bluetooth ]]
then
  if [[ $bluetooth =~ "install bluetooth /bin/true" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$bluetooth${NORMAL}"
    fail=0
  else
    echo -e "${NORMAL}RESULT:    ${RED}$bluetooth${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}\"bluetooth\" is not defined in $dir2.${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, RHEL 8 Bluetooth is disabled.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}PASSED, RHEL 8 Bluetooth is not disabled.${NORMAL}"
fi

exit
