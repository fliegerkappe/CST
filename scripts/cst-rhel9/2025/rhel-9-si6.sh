#! /bin/bash

# SI-6 Security Function Verification

# CONTROL: The information system:
# a. Verified the correct operation of [Assignment: organization-defined security functions];
# b. Performs this verification [Selection (one or more): [Assigment: organization-defined
#    system transitional states]; upon command by user with apropriate privilege; [Assignment:
#    organization-defined frequency]];
# c. Notifies [Assignment: organization-defined personnel or roles] of failed security verification
#    tests; and
# d. [Selection (one or more); shuts the information system down; restarts theinformation
#    system; [Assmignment: organization-defined alternative action(s)]] when anomalies are
#    discovered.

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

controlid="SI-6 Security Function Verification"

title1a="RHEL 9 must use a Linux Security Module configured to enforce limits on system services."
title1b="Checking with: getenforce"
title1c="Expecting: ${YLO}Enforcing
           NOTE: If SELINUX is not set to \"Enforcing\", this is a finding."${BLD}
cci1="CCI-001084 CCI-002696"
stigid1="RHEL-09-431010"
severity1="CAT I"
ruleid1="SV-258078r958944"
vulnid1="V-258078"

title2a="RHEL 9 must enable the SELinux targeted policy."
title2b="Checking with:
           a. sestatus
	   b. grep -i \"selinuxtype\" /etc/selinux/config | grep -v '^#'"
title2c="Expecting: ${YLO}
           a. ${BLD}SELinux status: enabled${YLO}
              SELinuxfs mount: /sys/fs/selinux
              SELinux root directory: /etc/selinux
              ${BLD}Loaded policy name: targeted${YLO}
              Current mode: enforcing
              Mode from config file: enforcing
              Policy MLS status: enabled
              Policy deny_unknown status: allowed
              Memory protection checking: actual (secure)
              Max kernel policy version: 31
	   b. ${BLD}SELINUXTYPE = targeted${YLO}
  	   NOTE: a. If the \"Loaded policy name\" is not set to \"targeted\", this is a finding.
	   NOTE: b. If no results are returned or \"SELINUXTYPE\" is not set to \"targeted\", this is a finding."${BLD}
cci2="CCI-002696"
stigid2="RHEL-09-431015"
severity2="CAT II"
ruleid2="SV-258079r1045159"
vulnid2="V-258079"

title3a="RHEL 9 must have the AIDE package installed."
title3b="Checking with:
           a. dnf list --installed aide
	   b. find / -name aide.conf
	   c. cat /etc/aide.conf | more"
title3c="Expecting: ${YLO}
           a. aide.x86_64            0.16-105.el9            @rhel-9-for-x86_64-appstream-rpms
	   b. /etc/aide.conf
	   c. The \"acl\" rule is being used on all selection lines
	   NOTE: If the \"acl\" rule is not being used on all selection lines in the \"/etc/aide.conf\" file, is commented out, or ACLs are not being checked by another file integrity tool, this is a finding."${BLD}
cci3="CCI-001744 CCI-002696"
stigid3="RHEL-09-651010"
severity3="CAT II"
ruleid3="SV-258134r1101983"
vulnid3="V-258134"

title4a="RHEL 9 must routinely check the baseline configuration for unauthorized changes and notify the system administrator when anomalies in the operation of any security functions are discovered."
title4b="Checking with: 
           a. ls -al /etc/cron.* | grep aide
	   b. grep aide /etc/crontab /var/spool/cron/root
	   c. more /etc/cron.daily/aide"
title4c="Expecting: ${YLO}
           a. -rwxr-xr-x 1 root root 29 Nov 22 2015 aide
	   b. /etc/crontab: 30 04 * * * root usr/sbin/aide
           b. /var/spool/cron/root: 30 04 * * * root usr/sbin/aide
	   c. #!/bin/bash
           c. /usr/sbin/aide --check | /bin/mail -s \"\$HOSTNAME - Daily aide integrity check run\" root@sysname.mil
	   NOTE: If the file integrity application does not exist, a script file controlling the execution of the file integrity application does not exist, or the file integrity application does not notify designated personnel of changes, this is a finding."${BLD}
cci4="CCI-001744 CCI-002699 CCI-002702"
stigid4="RHEL-09-651015"
severity4="CAT II"
ruleid4="SV-258135r1045267"
vulnid4="V-258135"

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

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${CYN}VERIFY, (SC-3 Security Functioon Isolation: V-258078)${NORMAL}"

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

file2="/etc/selinux/config"

fail=1
test1=0
test2=0

sestatus1="$(sestatus)"
sestatus2="$(grep -i "selinuxtype" $file2 | grep -v '^#')"

datetime="$(date +%FT%H:%M:%S)"

if [[ $sestatus1 ]]
then
  for line in ${sestatus1[@]}
  do
    if [[ $line =~ "Loaded policy name:" && $line =~ "targeted" ]] ||
       [[ $line =~ "SELinux status" && $line =~ "enabled" ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}a. $line${NORMAL}"
      test1=1
    else
      echo -e "${NORMAL}RESULT:    a. $line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}a. Nothing returned${NORMAL}"
fi

if [[ $sestatus2 ]]
then
  if [[ $sestatus2 =~ "SELINUXTYPE" && $sestatus2 =~ "targeted" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}b. $sestatus2${NORMAL}"
    test2=1
  else
    echo -e "${NORMAL}RESULT:    ${RED}b. $sestatus2${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}b. Nothing returned${NORMAL}"
fi

if [[ $test1 == 1 && $test2 == 1 ]]
then
  fail=0
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, The information system verifies correct operation of organization-defined security functions.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, The information system does not verify correct operation of organization-defined security functions.${NORMAL}"
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

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${CYN}VERIFY, (See CM-3 Configuration Change Control: V-258134)${NORMAL}"

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

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${CYN}VERIFY, (See CM-3 Configuration Change Control: V-258135)${NORMAL}"

exit
