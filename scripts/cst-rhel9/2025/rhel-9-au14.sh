#! /bin/bash

# AU-14 Session Audit

# CONTROL: 
# a. Provide and implement the capability for [Assignment: organization-defined users or roles] to
#    [Selection (one or more): record; view; hear; log] the content of a user session under 
#    [Assignment: organization-defined circumstances]; and
# b. Develop, integrate, and use session auditing activities in consultation with legal counsel
#    and in accordance with applicable laws, executive orders, directives, regulations, policies, 
#    standards, and guidelines.

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

controlid="AU-14 Session Audit"

title1a="RHEL 9 must enable auditing of processes that start prior to the audit daemon."
title1b="Checking with:
           a. grubby --info=ALL | grep args | grep -v 'audit=1'
	   b. grep audit /etc/default/grub"
title1c="Expecting: ${YLO}
           a. Nothing returned
	   b. GRUB_CMDLINE_LINUX=\"audit=1\"
	   NOTE: a. If any output is returned, this is a finding.
	   NOTE: b. If \"audit\" is not set to \"1\", is missing, or is commented out, this is a finding."${BLD}
cci1="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-001464 CCI-002884"
stigid1="RHEL-09-212055"
severity1="CAT III"
ruleid1="SV-257796r1044847"
vulnid1="V-257796"

title2a="RHEL 9 audit package must be installed."
title2b="Checking with: dnf list --installed audit"
title2c="Expecting: ${YLO}audit-3.0.7-101.el9_0.2.x86_64
           NOTE: If the \"audit\" package is not installed, this is a finding."${BLD}
cci2="CCI-000130 CCI-000131 CCI-000132 CCI-000133 CCI-000134 CCI-000135 CCI-000154 CCI-000158 CCI-000159 CCI-000169 CCI-000172 CCI-001464 CCI-001487 CCI-003938 CCI-001876 CCI-001877 CCI-001878 CCI-001879 CCI-001880 CCI-001881 CCI-001882 CCI-001889 CCI-001914 CCI-002884 CCI-001814"
stigid2="RHEL-09-653010"
severity2="CAT II"
ruleid2="SV-258151r1045298"
vulnid2="V-258151"

title3a="RHEL 9 audit service must be enabled."
title3b="Checking with: systemctl status auditd.service"
title3c="Expecting: ${YLO}
auditd.service - Security Auditing Service
Loaded:loaded (/usr/lib/systemd/system/auditd.service; enabled; vendor preset: enabled)
Active: active (running) since Tues 2022-05-24 12:56:56 EST; 4 weeks 0 days ago
NOTE: If the audit service is not \"active\" and \"running\", this is a finding."${BLD}
cci3="CCI-000130 CCI-000131 CCI-000132 CCI-000133 CCI-000134 CCI-000135 CCI-000154 CCI-000158 CCI-000159 CCI-000169 CCI-000172 CCI-001464 CCI-001487 CCI-003938 CCI-001876 CCI-001877 CCI-001878 CCI-001879 CCI-001880 CCI-001881 CCI-001882 CCI-001889 CCI-001914 CCI-002884 CCI-001814"
stigid3="RHEL-09-653015"
severity3="CAT II"
ruleid3="SV-258152r1015127"
vulnid3="V-258152"

title4a="RHEL 9 must allocate an audit_backlog_limit of sufficient size to capture processes that start prior to the audit daemon."
title4b="Checking with: grubby --info=ALL | grep args | grep 'audit_backlog_limit'"
title4c="Expecting: ${YLO}Nothing returned (or) audit_backlog_limit is not less than \"8192\"
           NOTE: If the command returns any outputs, and audit_backlog_limit is less than \"8192\", this is a finding."${BLD}
cci4="CCI-001464 CCI-001849"
stigid4="RHEL-09-653120"
severity4="CAT III"
ruleid4="SV-258173r1101933"
vulnid4="V-258173"

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

echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation V-257796)${NORMAL}"

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

echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation V-258151)${NORMAL}"

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

echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation V-258152)${NORMAL}"

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

echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${CYN}VERIFY, (See AU-4 Audit Storage Capacity: V-258173)${NORMAL}"

exit
