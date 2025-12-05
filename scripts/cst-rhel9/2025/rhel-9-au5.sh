#! /bin/bash

# AU-5 Response to Audit Processing Failures

# CONTROL: The information system:
# a. Alerts [Assignment: organization-defined personnel or roles] in the event of an
#    audit processing failure; and
# b. Takes the following additional actions: [Assignment: organization-defined actions
#    to be taken (e.g. shut down information system overwrite oldest audit records
#    stop generating audit records)].

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

controlid="AU-5 Response to Audit Processing Failures"

title1a="RHEL 9 must forward mail from postmaster to the root account using a postfix alias."
title1b="Checking with: grep \"postmaster:\s*root$\" /etc/aliases"
title1c="Expecting: ${YLO}postmaster: root (or the SA or ISSO)
           NOTE: If the command does not return a line, or the line is commented out, ask the system administrator to indicate how they and the information systems security officer (ISSO) are notified of an audit process failure. If there is no evidence of the proper personnel being notified of an audit processing failure, this is a finding."${BLD}
cci1="CCI-000139"
stigid1="RHEL-09-252060"
severity1="CAT II"
ruleid1="SV-257953r958424"
vulnid1="V-257953"

title2a="RHEL 9 must notify the system administrator (SA) and information system security officer (ISSO) (at a minimum) when allocated audit record storage volume 75 percent utilization."
title2b="Checking with: grep -w space_left_action /etc/audit/auditd.conf"
title2c="Expecting: ${YLO}space_left_action = email
           NOTE: If the value of the \"space_left_action\" is not set to \"email\", or if the line is commented out, ask the SA to indicate how the system is providing real-time alerts to the SA and ISSO.
	   NOTE: If there is no evidence that real-time alerts are configured on the system, this is a finding."${BLD}
cci2="CCI-001855"
stigid2="RHEL-09-653040"
severity2="CAT II"
ruleid2="SV-258157r971542"
vulnid2="V-258157"

title3a="RHEL 9 must take action when allocated audit record storage volume reaches 95 percent of the audit record storage capacity."
title3b="Checking with: grep -w admin_space_left /etc/audit/auditd.conf"
title3c="Expecting: ${YLO}admin_space_left = 5%
           NOTE: If the value of the \"admin_space_left\" keyword is not set to 5 percent of the storage volume allocated to audit logs, or if the line is commented out, ask the system administrator (SA) to indicate how the system is taking action if the allocated storage is about to reach capacity. If the \"space_left\" value is not configured to the correct value, this is a finding."${BLD}
cci3="CCI-001855"
stigid3="RHEL-09-653045"
severity3="CAT II"
ruleid3="SV-258158r971542"
vulnid3="V-258158"

title4a="RHEL 9 must take action when allocated audit record storage volume reaches 95 percent of the repository maximum audit record storage capacity."
title4b="Checking with: grep admin_space_left_action /etc/audit/auditd.conf"
title4c="Expecting: ${YLO}admin_space_left_action = single
           NOTE: If the value of the \"admin_space_left_action\" is not set to \"single\", or if the line is commented out, ask the system administrator (SA) to indicate how the system is providing real-time alerts to the SA and information system security officer (ISSO).
	   NOTE: If there is no evidence that real-time alerts are configured on the system, this is a finding."${BLD}
cci4="CCI-001855"
stigid4="RHEL-09-653050"
severity4="CAT II"
ruleid4="SV-258159r971542"
vulnid4="V-258159"

title5a="RHEL 9 System Administrator (SA) and/or information system security officer (ISSO) (at a minimum) must be alerted of an audit processing failure event."
title5b="Checking with: grep action_mail_acct /etc/audit/auditd.conf"
title5c="Expecting: ${YLO}action_mail_acct = root
           NOTE: If the value of the \"action_mail_acct\" keyword is not set to \"root\" and/or other accounts for security personnel, the \"action_mail_acct\" keyword is missing, or the retuned line is commented out, ask the SA to indicate how they and the ISSO are notified of an audit process failure. If there is no evidence of the proper personnel being notified of an audit processing failure, this is a finding."${BLD}
cci5="CCI-000139"
stigid5="RHEL-09-653070"
severity5="CAT II"
ruleid5="SV-258163r958424"
vulnid5="V-258163"

title6a="RHEL 9 must have mail aliases to notify the information system security officer (ISSO) and system administrator (SA) (at a minimum) in the event of an audit processing failure."
title6b="Checking with: 
           a. postconf alias_maps
           b. postmap -q root hash:/etc/aliases"
title6c="Expecting: ${YLO}
           a. alias_maps = hash:/etc/aliases
	   b. isso
	   NOTE: If an alias is not set, this is a finding."${BLD}
cci6="CCI-000139"
stigid6="RHEL-09-653125"
severity6="CAT II"
ruleid6="SV-258174r958424"
vulnid6="V-258174"

title7a="RHEL 9 audit system must take appropriate action when an error writing to the audit storage volume occurs."
title7b="Checking with: sudo grep disk_error_action /etc/audit/auditd.conf"
title7c="Expecting: ${YLO}disk_error_action = HALT
           NOTE: If the value of the \"disk_error_action\" option is not \"SYSLOG\", \"SINGLE\", or \"HALT\", or the line is commented out, ask the system administrator (SA) to indicate how the system takes appropriate action when an audit process failure occurs. If there is no evidence of appropriate action, this is a finding."${BLD}
cci7="CCI-000140"
stigid7="RHEL-09-653020"
severity7="CAT II"
ruleid7="SV-258153r1038966"
vulnid7="V-258153"

title8a="RHEL 9 audit system must take appropriate action when the audit storage volume is full."
title8b="Checking with: grep disk_full_action /etc/audit/auditd.conf"
title8c="Expecting: ${YLO}disk_full_action = HALT
           NOTE: If the value of the \"disk_full_action\" option is not \"SYSLOG\", \"SINGLE\", or \"HALT\", or the line is commented out, ask the system administrator (SA) to indicate how the system takes appropriate action when an audit storage volume is full. If there is no evidence of appropriate action, this is a finding."${BLD}
cci8="CCI-000140"
stigid8="RHEL-09-653025"
severity8="CAT II"
ruleid8="SV-258154r1038966"
vulnid8="V-258154"

title9a="RHEL 9 must take action when allocated audit record storage volume reaches 75 percent of the repository maximum audit record storage capacity."
title9b="Checking with: grep -w space_left /etc/audit/auditd.conf"
title9c="Expecting: ${YLO}space_left = 25%
           NOTE: If the value of the \"space_left\" keyword is not set to 25 percent or greater of the storage volume allocated to audit logs, or if the line is commented out, ask the system administrator (SA) to indicate how the system is providing real-time alerts to the SA and ISSO. If the \"space_left\" value is not configured to the value 25 percent or more, this is a finding."${BLD}
cci9="CCI-001855"
stigid9="RHEL-09-653035"
severity9="CAT II"
ruleid9="SV-258156r1106364"
vulnid9="V-258156"

title10a="RHEL 9 audit system must take appropriate action when the audit files have reached maximum size."
title10b="Checking with: ${YLO}grep max_log_file_action /etc/audit/auditd.conf"
title10c="Expecting: ${YLO}max_log_file_action = ROTATE
           NOTE: If the value of the \"max_log_file_action\" option is not \"ROTATE\", \"SINGLE\", or the line is commented out, ask the system administrator (SA)to indicate how the system takes appropriate action when an audit storage volume is full. If there is no evidence of appropriate action, this is a finding."${BLD}
cci10="CCI-000140"
stigid10="RHEL-09-653055"
severity10="CAT II"
ruleid10="SV-258160r1038966"
vulnid10="V-258160"

title11a="RHEL 9 must take appropriate action when a critical audit processing failure occurs."
title11b="Checking with: grep \"-f\" /etc/audit/audit.rules"
title11c="Expecting: ${YLO}-f 2
           NOTE: If the value for \"-f\" is not \"2\", and availability is not documented as an overriding concern, this is a finding."${BLD}
cci11="CCI-000139"
stigid11="RHEL-09-654265"
severity11="CAT II"
ruleid11="SV-258227r1014992"
vulnid11="V-258227"

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

alias="$(grep "postmaster:\s*root$" /etc/aliases)"

if [[ $alias && ${alias:0:1} != "#" ]]
then
  fail=0
  echo -e "${NORMAL}RESULT:    ${BLD}$alias${NORMAL}"
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, RHEL 9 forwards mail from postmaster to the root account using a postfix alias.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, RHEL 9 does not forward mail from postmaster to the root account using a postfix alias.${NORMAL}"
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

alert="$(grep -w space_left_action /etc/audit/auditd.conf)"

if [[ $alert ]]
then
  value="$(echo $alert | awk -F= '{print $2}' | sed 's/ //')"
  if [[ $value == "email" && ${alert:0:1} != "#" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$alert${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$alert${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, RHEL 9 notifies the system administrator (SA) and information system security officer (ISSO) (at a minimum) when allocated audit record storage volume 75 percent utilization."${NORMAL}
else
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, RHEL 9 does not notify the system administrator (SA) and information system security officer (ISSO) (at a minimum) when allocated audit record storage volume 75 percent utilization."${NORMAL}
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

space="$(grep -w admin_space_left /etc/audit/auditd.conf)"

if [[ $space ]]
then
  value="$(echo $space | awk -F= '{print $2}' | sed 's/ //' | sed 's/%//')"
  if [[ $value == "5" && ${space:0:1} != "#" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$space${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${BLD}$space${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${GRN}PASSED, RHEL 9 takes action when allocated audit record storage volume reaches 95 percent of the audit record storage capacity.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${RED}FAILED, RHEL 9 does not take action when allocated audit record storage volume reaches 95 percent of the audit record storage capacity.${NORMAL}"
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

admspace="$(grep admin_space_left_action /etc/audit/auditd.conf)"

if [[ $admspace ]]
then
  value="$(echo $admspace | awk -F= '{print tolower($2)}' | sed 's/ //')"
  if [[ $value == "single" && ${value:0:1} != "#" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$admspace${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$admspace${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${GRN}PASSED, RHEL 9 takes action when allocated audit record storage volume reaches 95 percent of the repository maximum storage capacity.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${RED}FAILED, RHEL 9 does not take action when allocated audit record storage volume reaches 95 percent of the repository maximum storage capacity.${NORMAL}"
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

acct="$(grep action_mail_acct /etc/audit/auditd.conf)"

if [[ $acct ]]
then
  usr="$(echo $acct | awk -F= '{print $2}' | sed 's/ //')"
  if [[ $usr == "root" && ${acct:0:1} != "#" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$acct${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${BLD}$acct${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${GRN}PASSED, RHEL 9 System Administrator (SA) and/or information system security officer (ISSO) (at a minimum) are alerted of an audit processing failure event.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${RED}FAILED, RHEL 9 System Administrator (SA) and/or information system security officer (ISSO) (at a minimum) are not alerted of an audit processing failure event.${NORMAL}"
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

isinstalled="$(dnf list --installed 2>&1 postfix | grep -Ev '(Updating|Installed)')"

if [[ $isinstalled ]]
then

  alias="$(postconf 2>/dev/null alias_maps)"

  if [[ $alias ]]
  then
    maps="$(postmap -q root 2>/dev/null hash:/etc/aliases)"
    if [[ $maps == "isso" ]] 
    then
      fail=0
      echo -e "${NORMAL}RESULT:    ${BLD}$acct${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${CYN}$acct${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}A mail alias is not configured${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}The \"postfix\" mail service package is not installed.${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${CYN}VERIFY, Have the system administrator (SA) or ISSO verify that the alias is valid.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${CYN}VERIFY, RHEL 9 does not have mail aliases to notify the information system security officer (ISSO) and system administrator (SA) (at a minimum) in the event of an audit processing failure.${NORMAL}"
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

isinstalled="$(dnf list --installed 2>&1 postfix | grep -Ev '(Updating|Installed)')"

if [[ $isinstalled ]]
then

  erraction="$(grep disk_error_action /etc/audit/auditd.conf)"

  if [[ $erraction ]]
  then
    action="$(echo $erraction | awk -F= '{print tolower($2)}' | sed 's/ //')"
    if [[ $action == "syslog" || $action == "single" || $action == "halt" ]]
    then
      fail=0
      echo -e "${NORMAL}RESULT:    ${BLD}$erraction${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$erraction${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}A disk full error action is not configured${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}The \"postfix\" mail service package is not installed.${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${GRN}PASSED, RHEL 9 audit system takes appropriate action when an error writing to the audit storage volume occurs.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${RED}FAILED, RHEL 9 audit system does not take appropriate action when an error writing to the audit storage volume occurs.${NORMAL}"
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

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ $isinstalled ]]
then

  fullaction="$(grep disk_full_action /etc/audit/auditd.conf)"

  if [[ $fullaction ]]
  then
    action="$(echo $fullaction | awk -F= '{print tolower($2)}' | sed 's/ //')"
    if [[ $action == "syslog" || $action == "single" || $action == "halt" ]]
    then
      fail=0
      echo -e "${NORMAL}RESULT:    ${BLD}$fullaction${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$fullaction${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}A storage volume full error action is not configured${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}The \"postfix\" mail service package is not installed.${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cci8, $datetime, ${GRN}PASSED, RHEL 9 audit system takes appropriate action when the audit storage volume is full.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cci8, $datetime, ${RED}FAILED, RHEL 9 audit system does not take appropriate action when the audit storage volume is full.${NORMAL}"
fi

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

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

space="$(grep -w space_left /etc/audit/auditd.conf)"

if [[ $space ]]
then
  size="$(echo $space | awk -F= '{print $2}' | sed 's/ *%//')"
  if  (( $size >= 25 ))
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$space${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$space${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity9, $controlid, $stigid9, $ruleid9, $cci9, $datetime, ${GRN}PASSED, RHEL 9 takes action when allocated audit record storage volume reaches 75 percent of the repository maximum audit record storage capacity.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity9, $controlid, $stigid9, $ruleid9, $cci9, $datetime, ${RED}FAILED, RHEL 9 does not take action when allocated audit record storage volume reaches 75 percent of the repository maximum audit record storage capacity.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid10${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid10${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid10${NORMAL}"
echo -e "${NORMAL}CCI:       $cci10${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 10:   ${BLD}$title10a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title10b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title10c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity10${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

maxaction="$(grep max_log_file_action /etc/audit/auditd.conf)"

if [[ $maxaction ]]
then
  action="$(echo $maxaction | awk -F= '{print tolower($2)}' | sed 's/ //')"
  if [[ $action == "rotate" || $action == "single" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$maxaction${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$maxaction${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity10, $controlid, $stigid10, $ruleid10, $cci10, $datetime, ${GRN}PASSED, RHEL 9 takes appropriate action when the audit files have reached maximum size.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity10, $controlid, $stigid10, $ruleid10, $cci10, $datetime, ${RED}FAILED, RHEL 9 does not take appropriate action when the audit files have reached maximum size.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid11${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid11${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid11${NORMAL}"
echo -e "${NORMAL}CCI:       $cci11${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 11:   ${BLD}$title11a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title11b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title11c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity11${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

panic="$(grep "\-f" /etc/audit/audit.rules)"

if [[ $panic ]]
then
  action="$(echo $panic | awk '{print $2}')"
  if [[ $action == 2 ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$panic${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$panic${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity11, $controlid, $stigid11, $ruleid11, $cci11, $datetime, ${GRN}PASSED, RHEL 9 takes appropriate action when a critical audit processing failure occurs.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity11, $controlid, $stigid11, $ruleid11, $cci11, $datetime, ${RED}FAILED, RHEL 9 does not take appropriate action when a critical audit processing failure occurs.${NORMAL}"
fi

exit
