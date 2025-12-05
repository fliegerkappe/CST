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

controlid="IA-3 Device Identification and Authentication"

title1a="RHEL 9 file system automount function must be disabled unless required."
title1b="Checking with: systemctl is-enabled  autofs"
title1c="Expecting: ${YLO}masked
           NOTE: If the returned value is not \"masked\", \"disabled\", or \"Failed to get unit file state for autofs.service for autofs\" and is not documented as an operational requirement with the information system security officer (ISSO), this is a finding."${BLD}
cci1="CCI-000778 CCI-001958"
stigid1="RHEL-09-231040"
severity1="CAT II"
ruleid1="SV-257849r1044928"
vulned1="V-257849"

title2a="RHEL 9 must disable the graphical user interface automount function unless required."
title2b="Checking with: gsettings get org.gnome.desktop.media-handling automount-open"
title2c="Expecting: ${YLO}false
           NOTE: This requirement assumes the use of the RHEL 9 default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is Not Applicable.
           NOTE: If \"automount-open\" is set to \"true\", and is not documented with the information system security officer (ISSO) as an operational requirement, this is a finding."${BLD}
cci2="CCI-000778 CCI-001958"
stigid2="RHEL-09-271020"
severity2="CAT II"
ruleid2="SV-258014r1045084"
vulned2="V-258014"

title3a="RHEL 9 must prevent a user from overriding the disabling of the graphical user interface automount function."
title3b="Checking with: grep system-db /etc/dconf/profile/user"
title3c="Expecting: ${YLO}system-db:local
           NOTE: The example above is using the database \"local\" for the system, so the path is \"/etc/dconf/db/local.d\". This path must be modified if a database other than \"local\" is being used.
	   NOTE: If the command does not return at least the example result, this is a finding."${BLD}
cci3="CCI-000778 CCI-001958"
stigid3="RHEL-09-271025"
severity3="CAT II"
ruleid3="SV-258015r1045086"
vulned3="V-258015"

title4a="RHEL 9 must prevent a user from overriding the disabling of the graphical user interface autorun function."
title4b="Checking with: gsettings writable org.gnome.desktop.media-handling autorun-never"
title4c="Expecting: ${YLO}false
           NOTE: If \"autorun-never\" is writable, the result is \"true\". If this is not documented with the information system security officer (ISSO) as an operational requirement, this is a finding."${BLD}
cci4="CCI-000778 CCI-001958"
stigid4="RHEL-09-271035"
severity4="CAT II"
ruleid4="SV-258017r1045088"
vulned4="V-258017"

title5a="RHEL 9 must be configured to disable USB mass storage."
title5b="Checking with: grep -r usb-storage /etc/modprobe.conf /etc/modprobe.d/*"
title5c="Expecting: ${YLO}
           install usb-storage /bin/false
           blacklist usb-storage
           NOTE: If the command does not return any output, or either line is commented out, and use of USB Storage is not documented with the information system security officer (ISSO) as an operational requirement, this is a finding."${BLD}
cci5="CCI-000778 CCI-001958 CCI-003959"
stigid5="RHEL-09-291010"
severity5="CAT II"
ruleid5="SV-258034r1051267"
vulned5="V-258034"

title6a="RHEL 9 must have the USBGuard package installed."
title6b="Checking with: dnf list installed usbguard"
title6c="Expecting: ${YLO}
           usbguard.x86_64          1.0.0-10.el9_1.2          @rhel-9-for-x86_64-appstream-rpms
	   NOTE: If the USBGuard package is not installed, ask the SA to indicate how unauthorized peripherals are being blocked.
	   NOTE: If there is no evidence that unauthorized peripherals are being blocked before establishing a connection, this is a finding."${BLD}
cci6="CCI-001958 CCI-003959"
stigid6="RHEL-09-291015"
severity6="CAT II"
ruleid6="SV-258035r1045125"
vulned6="V-258035"

title7a="RHEL 9 must have the USBGuard package enabled."
title7b="Checking with: systemctl is-active usbguard"
title7c="Expecting: ${YLO}active
           NOTE: If usbguard is not active, ask the SA to indicate how unauthorized peripherals are being blocked.
	   NOTE: If there is no evidence that unauthorized peripherals are being blocked before establishing a connection, this is a finding."${BLD}
cci7="CCI-001958 CCI-003959"
stigid7="RHEL-09-291020"
severity7="CAT II"
ruleid7="SV-258036r1014861"
vulned7="V-258036"

title8a="RHEL 9 must block unauthorized peripherals before establishing a connection."
title8b="Checking with: usbguard list-rules"
title8c="Expecting: ${YLO}allow id 1d6b:0001 serial
           NOTE: If the command does not return results or an error is returned, ask the SA to indicate how unauthorized peripherals are being blocked.
	   NOTE: If there is no evidence that unauthorized peripherals are being blocked before establishing a connection, this is a finding."${BLD}
cci8="CCI-001958"
stigid8="RHEL-09-291030"
severity8="CAT II"
ruleid8="SV-258038r1045128"
vulned8="V-258038"

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

datetime="$(date +%FT%H:%M:%S)"

isenabled="$(systemctl 2>/dev/null is-enabled  autofs)"

if [[ $isenabled ]]
then
  if [[ $isenabled == "masked" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$isenabled${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$isenabled${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, RHEL 9 file system automount function is disabled unless required.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, RHEL 9 file system automount function is not disabled unless required.${NORMAL}"
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

automount="$(gsettings get 2>/dev/null org.gnome.desktop.media-handling automount-open)"

if [[ $automount ]]
then
  if [[ $automount == "false" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$automount${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$automount${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, RHEL 9 disables the graphical user interface automount function unless required.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, RHEL 9 does not disable the graphical user interface automount function.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

profile="$(grep system-db /etc/dconf/profile/user)"

if [[ $profile ]]
then
  for line in ${profile[@]}
  do
    value="$(echo $line | awk -F: '{print $2}' | sed 's/ //')"
    if [[ $value == "local" ]]
    then
      fail=0
      echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    $line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${GRN}PASSED, RHEL 9 prevents a user from overriding the disabling of the graphical user interface automount function.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${RED}FAILED, RHEL 9 does not prevent a user from overriding the disabling of the graphical user interface automount function.${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

autorun="$(gsettings writable 2>/dev/null org.gnome.desktop.media-handling autorun-never)"

if [[ $autorun ]]
then
  if [[ $autorun == "false" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$autorun${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$autorun${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${GRN}PASSED, RHEL 9 preventd a user from overriding the disabling of the graphical user interface autorun function.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${RED}FAILED, RHEL 9 does not prevent a user from overriding the disabling of the graphical user interface autorun function.${NORMAL}"
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

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${CYN}VERIFY, (See CM-7 Least Functionality: V-258034)${NORMAL}"

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid6${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid6${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid6${NORMAL}"
echo -e "${NORMAL}CCI:       $cci6${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 6:    ${BLD}$title6a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title6b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title6c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity6${NORMAL}"

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${CYN}VERIFY, (See CM-7 Least Functionality: V-258035)${NORMAL}"

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid7${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid7${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid7${NORMAL}"
echo -e "${NORMAL}CCI:       $cci7${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 7:    ${BLD}$title7a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title7b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title7c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity7${NORMAL}"

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${CYN}VERIFY, (See CM-7 Least Functionality: V-258036)${NORMAL}"

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid8${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid8${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid8${NORMAL}"
echo -e "${NORMAL}CCI:       $cci8${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 8:    ${BLD}$title8a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title8b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title8c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity8${NORMAL}"

IFS='
'

fail=0

datetime="$(date +%FT%H:%M:%S)"

policy="$(usbguard 2>&1 list-rules)"

if [[ $policy ]]
then
  for line in ${policy[@]}
  do
    if [[ $line =~ "hash" ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
    else
      fail=1
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cci8, $datetime, ${GRN}PASSED, RHEL 9 blocks unauthorized peripherals before establishing a connection.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cci8, $datetime, ${RED}FAILED, RHEL 9 does not block unauthorized peripherals before establishing a connection.${NORMAL}"
fi

exit
