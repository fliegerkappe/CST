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

controlid="AC-18 Wireless Access"

title1a="RHEL 9 wireless network adapters must be disabled."
title1b="Checking with: nmcli device status."
title1c="Expecting: ${YLO}(example)
           DEVICE               TYPE            STATE               CONNECTION
           virbr0               bridge          connected           virbr0
           wlp7s0               wifi            connected           wifiSSID
           enp6s0               ethernet        disconnected        --
           ${GRN}p2p-dev-wlp7s0       wifi-p2p        disconnected        --${YLO}
           lo                   loopback        unmanaged           --
           virbr0-nic           tun             unmanaged           --
           NOTE: This requirement is Not Applicable for systems that do not have physical wireless network radios.
           NOTE: If a wireless interface is configured and has not been documented and approved by the information system security officer (ISSO), this is a finding."${BLD}
cci1="CCI-001443 CCI-001444 CCI-002418 CCI-002421"
stigid1="RHEL-09-291040"
severity1="CAT II"
ruleid1="SV-258040r991568"
vulnid1="V-258040"

title2a="RHEL 9 Bluetooth must be disabled."
title2b="Checking with: grep -r bluetooth /etc/modprobe.conf /etc/modprobe.d/*"
title2c="Expecting: ${YLO}
           install bluetooth /bin/false
           blacklist bluetooth
           NOTE: If the command does not return any output, or the lines are commented out, and use of Bluetooth is not documented with the information system security officer (ISSO) as an operational requirement, this is a finding."${BLD}
cci2="CCI-000381 CCI-001443"
severity2="CAT II"
stigid2="RHEL-09-291035"
ruleid2="SV-258039r1045131"
vulnid2="V-258039"

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

fail=1
found=0

datetime="$(date +%FT%H:%M:%S)"

nmcli="$(nmcli device status)"

if [[ $nmcli ]]
then
  for line in ${nmcli[@]}
  do
    if [[ $line =~ "wifi" ]]
    then
      found=1
      if [[ $line =~ 'disconnected' ]]
      then
	fail=0
        echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
      else
	echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
      fi
    else
      echo -e "${NORMAL}RESULT:    $line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, Wireless network adapters are disabled${NORMAL}"
elif [[ $found == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}N/A, No wireless network adapters found.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, Wireless network adapters are not disabled${NORMAL}"
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
install=0
blacklist=0

datetime="$(date +%FT%H:%M:%S)"

bluetooth="$(grep -r bluetooth 2>/dev/null /etc/modprobe.conf /etc/modprobe.d/*)"

if [[ $bluetooth ]]
then
  for line in ${bluetooth[@]}
  do
    if [[ $line =~ "install" && $line =~ "/bin/false" ]]
    then
      install=1
      echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
    elif [[ $line =~ "blacklist" ]]
    then
      blacklist=1
      echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}\"bluetooth\" is not defined${NORMAL}"
fi

if [[ $install == 1 && $blacklist == 1 ]]
then
  fail=0
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, RHEL 9 Bluetooth is disabled.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, RHEL 9 Bluetooth is not disabled.${NORMAL}"
fi

exit
