#! /bin/bash

# SI-11 Error Handling

# CONTROL: The information system:
# a. Generates error messages that provide  informationnecessaryfor corrective actions without
#    revealinginformation that could be exploited by adversaries; and
# b. Reveals error messages only to [Assignment: organization-defined personnel or  roles].

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

controlid="SI-11 Error Handling"

title1a="RHEL 9 audit logs must be group-owned by root or by a restricted logging group to prevent unauthorized read access."
title1b="Checking with: 
           a. grep log_group /etc/audit/auditd.conf
	   b. grep -iw log_file /etc/audit/auditd.conf
	   c. stat -c \"%G %n\" /var/log/audit/audit.log"
title1c="Expecting: ${YLO}
           a. log_group = root
	   b. log_file = /var/log/audit/audit.log
	   c. root /var/log/audit/audit.log
	   NOTE: If the audit log is not group-owned by \"root\" or the configured alternative logging group, this is a finding."${BLD}
cci1="CCI-000162 CCI-000163 CCI-000164 CCI-001314"
stigid1="RHEL-09-653080"
severity1="CAT II"
ruleid1="SV-258165r958434"
vulnid1="V-258165"

title2a="RHEL 9 /var/log directory must have mode 0755 or less permissive."
title2b="Checking with: stat -c '%a %n' /var/log"
title2c="Expecting: 755 /var/log
           NOTE: If \"/var/log\" does not have a mode of "0755" or less permissive, this is a finding."${BLD}
cci2="CCI-001314"
stigid2="RHEL-09-232025"
severity2="CAT II"
ruleid2="SV-257885r1044953"
vulnid2="V-257885"

title3a="RHEL 9 /var/log/messages file must have mode 0640 or less permissive."
title3b="Checking with: stat -c '%a %n' /var/log/messages"
title3c="Expecting: ${YLO}600 /var/log/messages
           NOTE: If \"/var/log/messages\" does not have a mode of \"0640\" or less permissive, this is a finding."${BLD}
cci3="CCI-001314"
stigid3="RHEL-09-232030"
severity3="CAT II"
ruleid3="SV-257886r1044955"
vulnid3="V-257886"

title4a="RHEL 9 /var/log directory must be owned by root."
title4b="Checking with: stat -c \"%U %n\" /var/log"
title4c="Expecting: ${YLO}root /var/log
           NOTE: If \"/var/log\" does not have an owner of \"root\", this is a finding."${BLD}
cci4="CCI-001314"
stigid4="RHEL-09-232170"
severity4="CAT II"
ruleid4="SV-257914r1044969"
vulnid4="V-257914"

title5a="RHEL 9 /var/log directory must be group-owned by root."
title5b="Checking with: stat -c \"%G %n\" /var/log"
title5c="Expecting: ${YLO}root /var/log
           NOTE: If \"/var/log\" does not have a group owner of \"root\", this is a finding."${BLD}
cci5="CCI-001314"
stigid5="RHEL-09-232175"
severity5="CAT II"
ruleid5="SV-257915r1044971"
vulnid5="V-257915"

title6a="RHEL 9 /var/log/messages file must be owned by root."
title6b="Checking with: stat -c \"%U %n\" /var/log/messages"
title6c="Expecting: ${YLO}root /var/log/messages
           NOTE: If \"/var/log/messages\" does not have an owner of \"root\", this is a finding."${BLD}
cci6="CCI-001314"
stigid6="RHEL-09-232180"
severity6="CAT II"
ruleid6="SV-257916r1101916"
vulnid6="V-257916"

title7a="RHEL 9 /var/log/messages file must be group-owned by root."
title7b="Checking with: stat -c \"%G %n\" /var/log/messages"
title7c="Expecting: ${YLO}root /var/log/messages
           NOTE: If \"/var/log/messages\" does not have a group owner of \"root\", this is a finding."${BLD}
cci7="CCI-001314"
stigid7="RHEL-09-232185"
severity7="CAT II"
ruleid7="SV-257917r1101914"
vulnid7="V-257917"

title8a="RHEL 9 audit log directory must be owned by root to prevent unauthorized read access."
title8b="Checking with: 
           a. grep -iw log_file /etc/audit/auditd.conf
	   b. stat -c '%U %n' /var/log/audit"
title8c="Expecting: ${YLO}
           a. log_file = /var/log/audit/audit.log
	   b. root /var/log/audit
	   NOTE: If the audit log directory is not owned by \"root\", this is a finding."${BLD}
cci8="CCI-000162 CCI-000163 CCI-000164 CCI-001314"
stigid8="RHEL-09-653085"
severity8="CAT II"
ruleid8="SV-258166r1045303"
vulnid8="V-258166"

title9a="RHEL 9 audit logs file must have mode 0600 or less permissive to prevent unauthorized access to the audit log."
title9b="Checking with: 
           a. find /var/log/audit/ -type f -exec stat -c '%a %n' {} \;
	   b. find /var/log/audit/ -type f -exec stat -c '%a %n' {} \;"
title9c="Expecting: ${YLO}
           a. 600 /var/log/audit/audit.log
	   b. rw-------. 2 root root 237923 Jun 11 11:56 /var/log/audit/audit.log
	   NOTE: If the audit logs have a mode more permissive than \"0600\", this is a finding."${BLD}
cci9="CCI-000162 CCI-000163 CCI-000164 CCI-001314"
stigid9="RHEL-09-653090"
severity9="CAT II"
ruleid9="SV-258167r1101918"
vulnid9="V-258167"

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

echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${CYN}VERIFY, (See AU-9 Protection of Audit Information: V-258165)${NORMAL}"

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

logmode="$(stat -c '%a %n' /var/log)"

if [[ $logmode ]]
then
  mode="$(echo $logmode | awk '{print $1}')"
  if (( ${mode:1:1} <= 5 && ${mode:2:1} <= 5 ))
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$logmode${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$logmode${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, The RHEL 9 /var/log directory is mode 0755 or less permissive.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, The RHEL 9 /var/log directory is not mode 0755 or less permissive.${NORMAL}"
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

messagesmode="$(stat -c '%a %n' /var/log/messages)"

if [[ $messagesmode ]]
then
  mode="$(echo $messagesmode | awk '{print $1}')"
  if (( ${mode:0:1} <= 6 && ${mode:1:1} <= 4 )) && [[ ${mode:2:1} == 0 ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$messagesmode${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$messagesmode${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${GRN}PASSED, The RHEL 9 /var/log/messages file is mode 0640 or less permissive.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${RED}FAILED, The RHEL 9 /var/log/messages file is not mode 0640 or less permissive.${NORMAL}"
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

datetime="$(date +%FT%H:%M:%S)"

logowner="$(stat -c "%U %n" /var/log)"

if [[ $logowner ]]
then
  owner="$(echo $logowner | awk '{print $1}')"
  if [[ $owner == "root" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$logowner${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$logowner${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${GRN}PASSED, The RHEL 9 /var/log directory is owned by root.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${RED}FAILED, The RHEL 9 /var/log directory is not owned by root.${NORMAL}"
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

datetime="$(date +%FT%H:%M:%S)"

grpown="$(stat -c "%U %n" /var/log)"

if [[ $grpown ]]
then
  owner="$(echo $grpown | awk '{print $1}')"
  if [[ $owner == "root" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$grpown${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$grpown${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${GRN}PASSED, The RHEL 9 /var/log directory is group-owned by root.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${RED}FAILED, The RHEL 9 /var/log directory is not group-owned by root.${NORMAL}"
fi

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

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

msgowner="$(stat -c "%U %n" /var/log/messages)"

if [[ $msgowner ]]
then
  owner="$(echo $msgowner | awk '{print $1}')"
  if [[ $owner == "root" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$msgowner${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$msgowner${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi


if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${GRN}PASSED, The RHEL 9 /var/log/messages file is owned by root.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${RED}FAILED, The RHEL 9 /var/log/messages file is owned by root.${NORMAL}"
fi

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

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

grpown="$(stat -c "%U %n" /var/log/messages)"

if [[ $grpown ]]
then
  owner="$(echo $grpown | awk '{print $1}')"
  if [[ $owner == "root" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$grpown${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$grpown${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${GRN}PASSED, The RHEL 9 /var/log/messages file is group-owned by root.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid1, $cci7, $datetime, ${RED}FAILED, The RHEL 9 /var/log/messages file is not group-owned by root.${NORMAL}"
fi

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

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cci8, $datetime, ${CYN}VERIFY, (See AU-9 Protection of Audit Information: V-258166)${NORMAL}"

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid9${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid9${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid9${NORMAL}"
echo -e "${NORMAL}CCI:       $cci9${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 9:    ${BLD}$title9a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title9b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title9c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity9${NORMAL}"

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity9, $controlid, $stigid9, $ruleid9, $cci9, $datetime, ${CYN}VERIFY, (See AU-9 Protection of Audit Information: V-258167)${NORMAL}"

exit
