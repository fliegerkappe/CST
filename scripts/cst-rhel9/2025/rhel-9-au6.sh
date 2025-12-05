#! /bin/bash

# AU-6 Audit Record Review, Analysis, and Reporting

# CONTROL: 
# a. Review and analyze system audit records [Assignment: organization-defined frequency]
#    for indications of [Assignment: organization-defined inappropriate or unusual activity]
#    and the potential impact of the inappropriate or unusual activity;
# b. Report findings to [Assignment: organization-defined personnel or roles]; and
# c. Adjust the level of audit record review, analysis, and reporting within the system    
#    when there is a change in risk based on law enforcement information, intelligenct
#    information, or other credible sources of information.
#

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

controlid="AU-6 Audit Record Review Analysis and Reporting"

title1a="RHEL 9 must periodically flush audit records to disk to prevent the loss of audit records."
title1b="Checking with: grep freq /etc/audit/auditd.conf"
title1c="Expecting: ${YLO}freq = 100
           NOTE: If \"freq\" isn't set to a value between \"1\" and \"100\", the value is missing, or the line is commented out, this is a finding."${BLD}
cci1="CCI-000154"
stigid1="RHEL-09-653095"
severity1="CAT II"
ruleid1="SV-258168r958428"
vulnid1="V-258168"

title2a="RHEL 9 must have the rsyslog package installed."
title2b="Checking with: dnf list --installed rsyslog"
title2c="Expecting: ${YLO}rsyslog.x86_64          8.2102.0-101.el9_0.1
           NOTE: If the \"rsyslog\" package is not installed, this is a finding."${BLD}
cci2="CCI-000154 CCI-001851"
stigid2="RHEL-09-652010"
severity2="CAT II"
ruleid2="SV-258140r1106460"
vulnid2="V-258140"

title3a="RHEL 9 audit package must be installed."
title3b="Checking with: dnf list --installed audit"
title3c="Expecting: ${YLO}audit-3.0.7-101.el9_0.2.x86_64
           NOTE: If the \"audit\" package is not installed, this is a finding."${BLD}
cci3="CCI-000130 CCI-000131 CCI-000132 CCI-000133 CCI-000134 CCI-000135 CCI-000154 CCI-000158 CCI-000159 CCI-000169 CCI-000172 CCI-001464 CCI-001487 CCI-003938 CCI-001875 CCI-001876 CCI-001877 CCI-001878 CCI-001879 CCI-001880 CCI-001881 CCI-001882 CCI-001889 CCI-001914 CCI-002884 CCI-001814"
stigid3="RHEL-09-653010"
severity3="CAT II"
ruleid3="SV-258151r1045298"
vulnid3="V-258151"

title4a="RHEL 9 audit service must be enabled."
title4b="Checking with: systemctl status auditd.service"
title4c="Expecting: ${YLO}
           auditd.service - Security Auditing Service
           Loaded:loaded (/usr/lib/systemd/system/auditd.service; enabled; vendor preset: enabled)
           Active: active (running) since Tues 2022-05-24 12:56:56 EST; 4 weeks 0 days ago
           NOTE: If the audit service is not \"active\" and \"running\", this is a finding."${BLD}
cci4="CCI-000130 CCI-000131 CCI-000132 CCI-000133 CCI-000134 CCI-000135 CCI-000154 CCI-000158 CCI-000169 CCI-000172 CCI-001464 CCI-001487 CCI-003938 CCI-001876 CCI-001877 CCI-001878 CCI-001879 CCI-001880 CCI-001881 CCI-001882 CCI-001889 CCI-001914 CCI-002884 CCI-001814"
stigid4="RHEL-09-653015"
severity4="CAT II"
ruleid4="SV-258152r1015127"
vulnid4="V-258152"

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

freq="$(grep freq /etc/audit/auditd.conf)"

if [[ $freq ]]
then
  value="$(echo $freq | awk -F= '{print $2}' | sed 's/ //')"
  if (( $value <= 100 && $value > 0 )) && [[ ${freq:0:1} != "#" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$freq${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$freq${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, RHEL 9 periodically flushes audit records to disk to prevent the loss of audit records.${NORMAL}" 
else
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, RHEL 9 doesn't periodically flush audit records to disk to prevent the loss of audit records, or the setting is incorrect.${NORMAL}"
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

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${CYN}VERIFY, (See AU-4 Audit Storage Capacity V-258140)${NORMAL}" 

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

echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation V-258151)${NORMAL}"

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

echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation V-258152)${NORMAL}"

exit
