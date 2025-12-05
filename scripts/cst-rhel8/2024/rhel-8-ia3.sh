#! /bin/bash

# IA-3 Device Identification and Authentication

# CONTROL: The information system uniquely identifies and authenticates [Assignment: organization-defined specific and/or types of devices] before establishing a [Selection (one or more): local; remote; network] connection."

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

stig="Red Hat Enterprise Linux 8 Security Technical Implementation Guide :: Version 1, Release: 6 Benchmark Date: 27 Apr 2022"

hostname="$(uname -n)"

if [[ -f /etc/redhat-release ]]
then
   os="$(cat /etc/redhat-release)"
else
   os="OS not defined"
fi

prog="$(basename $0)"

controlid="IA-3 Device Identification and Authentication"

title1a="The RHEL 8 file system automounter must be disabled unless required."
title1b="Checking with: systemctl status autofs"
title1c="Expecting: ${YLO}
           autofs.service - Automounts filesystems on demand
	   Loaded: loaded (/usr/lib/systemd/system/autofs.service; disabled)
	   Active: inactive (dead)
           NOTE: If the \"autofs\" status is set to \"active\" and is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding."${BLD}
cci1="CCI-000778"
stigid1="RHEL-08-040070"
severity1="CAT II"
ruleid1="SV-230502r627750_rule"
vulnid1="V-230502"

title2a="RHEL 8 must be configured to disable USB mass storage."
title2b="Checking with: 
           a. \'grep -r usb-storage /etc/modprobe.d/* | grep -i \"/bin/true\"\'.
	   b. \'grep usb-storage /etc/modprobe.d/* | grep -i \"blacklist\""
title2c="Expecting:
           ${YLO}a. install usb-storage /bin/true
	   b. blacklist usb-storage
           NOTE: a. If the command does not return any output, or the line is commented out, and use of USB Storage is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.
	   NOTE: b. If the command does not return any output or the output is not \"blacklist usb-storage\" and use of USB storage devices is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding."${BLD}
cci2="CCI-000778"
stigid2="RHEL-08-040080"
severity2="CAT II"
ruleid2="SV-230503r809319_rule"
vulnid2="V-230503"

title3a="RHEL 8 must block unauthorized peripherals before establishing a connection."
title3b="Checking with: 'sudo usbguard list-rules'."
title3c="Expecting: ${YLO}Rules that define specific users, groups, 
           NOTE: If the command does not return results or an error is returned, ask the SA to indicate how unauthorized peripherals are being blocked.
	   NOTE: If there is no evidence that unauthorized peripherals are being blocked before establishing a connection, this is a finding."${BLD}
cci3="CCI-001958"
stigid3="RHEL-08-040140"
severity3="CAT II"
ruleid3="SV-230524r744026_rule"
vulnid3="V-230524"

title4a="RHEL 8 must have the USBGuard installed."
title4b="Checking with: 'yum list installed usbguard'."
title4c="Expecting: ${YLO}usbguard.x86_64                   0.7.8-7.el8             @ol8_appstream
           NOTE: If the USBGuard package is not installed, ask the SA to indicate how unauthorized peripherals are being blocked.
	   NOTE: If there is no evidence that unauthorized peripherals are being blocked before establishing a connection, this is a finding."${BLD}
cci4="CCI-001958"
stigid4="RHEL-08-040139"
severity4="CAT II"
ruleid4="SV-244547r743890_rule"
vulnid4="V-244547"

title5a="RHEL 8 must enable the USBGuard."
title5b="Checking with: systemctl status usbguard.service."
title5c="Expecting: ${YLO}
           usbguard.service - USBGuard daemon
	   Loaded: loaded (/usr/lib/systemd/system/usbguard.service; enabled; vendor preset: disabled)
	   Active: active (running)
	   NOTE: If the usbguard.service is not enabled and active, ask the SA to indicate how unauthorized peripherals are being blocked.
	   NOTE: If there is no evidence that unauthorized peripherals are being blocked before establishing a connection, this is a finding."${BLD}
cci5="CCI-001958"
stigid5="RHEL-08-040141"
severity5="CAT II"
ruleid5="SV-244548r743893_rule"
vulnid5="V-244548"

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

autofsstat="$(systemctl status autofs 2>/dev/null | grep autofs.service)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $autofsstat ]]
then
  for line in ${autofsstat[@]}
  do
    if [[ $line =~ 'Loaded: loaded' && $line =~ 'enabled' ||
          $line =~ 'Active: active'
       ]]
    then
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
      fail=1
    else
      echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}The \"autofs.service\" is not installed${NORMAL}"
  fail=2
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, The RHEL 8 file system automounter is disabled unless required.${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}N/A, The autofs service is not installed.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, The RHEL 8 file system automounter is not disabled unless required.${NORMAL}"
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
echo -e "${NORMAL}SEVERITY:  ${BLD}$sever2ty1${NORMAL}"

IFS='
'

dir2="/etc/modprobe.d"

kernelmod=0
useusbdisabled=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -d $dir2 ]]
then
  usbdisabled="$(grep -r usb-storage $dir2/* | grep -i "bin/true")"
  usbdisabledval="$(echo $usbdisabled | awk -F: '{print $2}')"
  usbblacklisted="$(grep usb-storage $dir2/* | grep -i "blacklist")"
  usbblacklistedval="$(echo $usbblacklisted | awk -F: '{print $2}')"
  if [[ $usbdisabled ]]
  then
    if [[ $usbdisabledval == "install usb-storage /bin/true" ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}a. $usbdisabled${NORMAL}"
      kernelmod=1
    else
      echo -e "${NORMAL}RESULT:    ${RED}a. $usbdisabled${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}a. \"nstall usb-storage\" is not defined in $dir2/*.${NORMAL}"
  fi
  if [[ $usbblacklisted ]]
  then
    if [[ $usbblacklistedval == "blacklist usb-storage" ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}b. $usbblacklisted${NORMAL}"
      useusbdisabled=1
    else
      echo -e "${NORMAL}RESULT:    ${RED}b. $usbblacklisted${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}b. \"blacklist usb-storage\" is not defined in $dir2/*.${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$dir2 not found.${NORMAL}"
fi

if [[ $kernelmod == 1 && $useusbdisabled == 1 ]]
then
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, RHEL 8 is configured to disable USB mass storage.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, RHEL 8 is not configured to disable USB mass storage.${NORMAL}"
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

usbpolicy="$(usbguard list-rules)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $usbpolicy ]]
then
  for line in ${usbpolicy[@]}
  do
    echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}A USBGuard policy was not found.${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${CYN}VERIFY, Verify USBGuard rules to ensure RHEL 8 blocks unauthorized peripherals before establishing a connection.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${RED}FAILED, RHEL 8 does not block unauthorized peripherals before establishing a connection.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid4${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid4${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid4${NORMAL}"
echo -e "${NORMAL}CCI:       $cci4${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 4:    ${BLD}$title4a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title4b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title4c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity4${NORMAL}"

IFS='
'

fail=1

isinstalled="$(yum list instaled usbguard | grep usbguard)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $isinstalled ]]
then
  for file in ${isinstalled[@]}
  do
    echo -e "${NORMAL}RESULT:    ${BLD}$file${NORMAL}"
    fail=0
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}The \"usbguard\" package is not installed.${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${GRN}PASSED, USBGuard is installed${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${RED}FAILED, USBGuard is not installed${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid5${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid5${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid5${NORMAL}"
echo -e "${NORMAL}CCI:       $cci5${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 5:    ${BLD}$title5a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title5b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title5c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity5${NORMAL}"

IFS='
'

fail=1

isenabled="$(systemctl status usbguard.service)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $isenabled =~ "Loaded: loaded" &&
      $isenabled =~ "Active: active (running)" ]]
then
  for line in ${isenabled[@]} 
  do
    echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
  done
  fail=0
else
  for line in ${isenabled[@]}
  do
    echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
  done
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${GRN}PASSED, USBGuard is enabled.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${RED}FAILED, USBGuard is not enabled.${NORMAL}"
fi

exit
