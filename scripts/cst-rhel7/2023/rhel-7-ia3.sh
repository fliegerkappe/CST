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

stig="Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Version 3, Release: 10 Benchmark Date: 26 Jan 2023"

hostname="$(uname -n)"

if [[ -f /etc/redhat-release ]]
then
   os="$(cat /etc/redhat-release)"
else
   os="OS not defined"
fi

prog="$(basename $0)"

controlid="IA-3 Device Identification and Authentication"

title1a="The Red Hat Enterprise Linux operating system must be configured to disable USB mass storage."
title1b="Checking with:
           a. grep -r usb-storage /etc/modprobe.d/* | grep -i \"/bin/true\" | grep -v \"^#\"
	   b. grep usb-storage /etc/modprobe.d/* | grep -i \"blacklist\" | grep -v \"^#\""
title1c="Expecting:${YLO}
           a. install usb-storage /bin/true
	   b. blacklist usb-storage
           Note: If the command does not return any output or the output is not \"blacklist usb-storage\", and use of USB storage devices is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding."${BLD}
cci1="CCI-000366"
stigid1="RHEL-07-020100"
severity1="CAT II"
ruleid1="SV-204449r603261_rule"
vulnid1="V-204449"

title2a="The Red Hat Enterprise Linux operating system must be configured so that the Datagram Congestion Control Protocol (DCCP) kernel module is disabled unless required."
title2b="Checking with 'grep -R dccp /etc/modprobe.d'."
title2c="Expecting: install dccp /bin/true
           Note: If the command does not return any output, or the line is commented out, and use of DCCP is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding."
cci2="CCI-001958"
stigid2="RHEL-07-020101"
severity2="CAT II"
ruleid2="SV-204450r603261_rule"
vulnid2="V-204450"

title3a="The Red Hat Enterprise Linux operating system must disable the file system automounter unless required."
title3b="Checking with 'systemctl status autofs'"
title3c="Expecting:${YLO}
           Active: inactive (dead)
           Note: If the \"autofs\" status is set to \"active\" and is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding."${BLD}
cci3="CCI-001958"
stigid3="RHEL-07-020110"
severity3="CAT II"
ruleid3="SV-204451r603261_rule"
vulnid3="V-204451"

title4a="The Red Hat Enterprise Linux operating system must disable the graphical user interface automounter unless required."
title4b="Checking with:
           a. 'cat /etc/dconf/db/local.d/00-No-Automount'
	   b. 'cat /etc/dconf/db/local.d/locks/00-No-Automount'"
title4c="Expecting:${YLO}
           a. automount=false
              automount-open=false
              autorun-never=true
	   b. /org/gnome/desktop/media-handling/automount
              /org/gnome/desktop/media-handling/automount-open
              /org/gnome/desktop/media-handling/autorun-never
	   Note:If the output does not match the example above, this is a finding."${BLD}
cci4="CCI-000366"
stigid4="RHEL-07-020111"
severity4="CAT II"
ruleid4="SV-219059r603261_rule"
vulnid4="V-219059"

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

datetime="$(date +%FT%H?%M:%S)"

echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${CYN}VERIFY, (See CM-6 Configuration Settings: V-71983)${NORMAL}"

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

datetime="$(date +%FT%H?%M:%S)"

dir2="/etc/modprobe.d"
fail=1

if [[ -d $dir2 ]]
then
   dccp="$(grep -r dccp $dir2/* | egrep -i '(/bin/true|blacklist)' | grep -v '^#')"
   if [[ $dccp ]]
   then
      for line in ${dccp[@]}
      do
         if [[ $line =~ 'install' && $line =~ 'dccp' && $line =~ '/bin/true' ]]
	 then
	    echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
	    install=1
	 elif [[ $line =~ 'blacklist' && $line =~ 'dccp' ]]
         then
            echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
            blacklist=1
         else
            echo -e "${NORMAL}RESULT:    $line${NORMAL}"
         fi
      done
   else
      echo  -e "${NORMAL}RESULT:   ${RED}A DCCP configuration was not found in $dir2${NORMAL}"
   fi
   if [[ $install == 1 && $blacklist == 1 ]]
   then
      fail=0
   fi
else
   echo -e "${NORMAL}RESULT:    $dir2 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, The DCCP kernel module is disabled.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, The DCCP kernel module is not disabled.${NORMAL}"
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

echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${CYN}VERIFY, (See CM-6 Configuration Settings: V-204451)${NORMAL}"

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

echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${CYN}VERIFY, (See CM-6 Configuration Settings: V-219059)${NORMAL}"

exit
