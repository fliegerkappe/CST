#! /bin/bash

# AU-4 Audit Storage Capacity
#
# CONTROL: The organization allocates audit record storage capacity in accordance with
# [Assignment: organization-defined audit record storage requirements].

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

controlid="AU-4 Audit Storage Capacity"

title1a="RHEL 9 must label all off-loaded audit logs before sending them to the central log server."
title1b="Checking with 'grep \"name_format\" /etc/audit/auditd.conf."
title1c="Expecting: ${YLO}name_format = hostname
           Note: If the \"name_format\" option is not \"hostname\", \"fqd\", or \"numeric\", or the line is commented out, this is a finding."${BLD}
cci1="CCI-000132 CCI-001851"
stigid1="RHEL-09-653060"
severity1="CAT II"
ruleid1="SV-258161r958416"
vulnid1="V-258161"

title2a="RHEL 9 must take appropriate action when the internal event queue is full."
title2b="Checking with 'grep -i overflow_action /etc/audit/auditd.conf'."
title2c="Expecting: ${YLO}overflow_action = syslog
           NOTE: If the value of the \"overflow_action\" option is not set to \"syslog\", \"single\", \"halt\", or the line is commented out, ask the System Administrator to indicate how the audit logs are off-loaded to a different system or media.
           NOTE: If there is no evidence that the transfer of the audit logs being off-loaded to another system or media takes appropriate action if the internal event queue becomes full, this is a finding."${BLD}
cci2="CCI-001851"
stigid2="RHEL-09-653065"
severity2="CAT II"
ruleid2="SV-258162r958754"
vulnid2="V-258162"

title3a="RHEL 9 must use a separate file system for the system audit data path."
title3b="Checking with: mount | grep /var/log/audit"
title3c="Expecting: ${YLO}/dev/mapper/rootvg-varlogaudit on /var/log/audit type xfs (rw,relatime,seclabel,attr2,inode64,logbufs=8,logbsize=32k,noquota)
           NOTE: Options displayed for mount may differ. /var/log/audit is used in this test.
	   NOTE: If no line is returned, this is a finding."${BLD}
cci3="CCI-001849"
stigid3="RHEL-09-231030"
severity3="CAT III"
ruleid3="SV-257847r1044924"
vulned3="V-257847"

title4a="RHEL 9 must have the rsyslog package installed."
title4b="Checking with: dnf list --installed rsyslog"
title4c="Expecting: ${YLO}(example) rsyslog.x86_64          8.2102.0-101.el9_0.1
           NOTE: If the \"rsyslog\" package is not installed, this is a finding."${BLD}
cci4="CCI-000154 CCI-001851"
stigid4="RHEL-09-652010"
severity4="CAT II"
ruleid4="SV-258140r1106460"
vulned4="V-258140"

title5a="RHEL 9 must authenticate the remote logging server for offloading audit logs via rsyslog."
title5b="Checking with: grep -i 'StreamDriver[\.]*AuthMode' /etc/rsyslog.conf /etc/rsyslog.d/*.conf."
title5c="Expecting: ${YLO}/etc/rsyslog.conf:\$ActionSendStreamDriverAuthMode x509/name
           NOTE: If the variable name \"StreamDriverAuthMode\" is present in an omfwd statement block, this is not a finding. However, if the \"StreamDriverAuthMode\" variable is in a module block, this is a finding.
	   NOTE: If the value of the \"\$ActionSendStreamDriverAuthMode\" or \"StreamDriver.AuthMode\" option is not set to \"x509/name\" or the line is commented out, ask the system administrator (SA) to indicate how the audit logs are offloaded to a different system or media.
           NOTE: If there is no evidence that the transfer of the audit logs being off-loaded to another system or media is encrypted, this is a finding."${BLD}
cci5="CCI-001851"
stigid5="RHEL-09-652040"
severity5="CAT II"
ruleid5="SV-258146r1045288"
vulnid5="V-258146"

title6a="RHEL 9 must encrypt the transfer of audit records off-loaded onto a different system or media from the system being audited."
title6b="Checking with: grep -i 'StreamDriver[\.]*Mode' /etc/rsyslog.conf /etc/rsyslog.d/*.conf"
title6c="Expecting: ${YLO}/etc/rsyslog.conf:\$ActionSendStreamDriverMode 1
           NOTE: If the value of the \"\$ActionSendStreamDriverMode\" or \"StreamDriver.Mode\" option is not set to \"1\" or the line is commented out, this is a finding."${BLD}
cci6="CCI-001851"
stigid6="RHEL-09-652045"
severity6="CAT II"
ruleid6="SV-258147r1045290"
vulnid6="V-258147"

title7a="RHEL 9 must encrypt via the gtls driver the transfer of audit records offloaded onto a different system or media from the system being audited via rsyslog."
title7b="Checking with: grep -Ei 'DefaultNetStreamDriver\b|StreamDriver.Name' /etc/rsyslog.conf /etc/rsyslog.d/*.conf"
title7c="Expecting: ${YLO}/etc/rsyslog.conf:\$DefaultNetstreamDriver gtls
           NOTE: If the value of the \"$DefaultNetstreamDriver\" or \"StreamDriver\" option is not set to \"gtls\" or the line is commented out, this is a finding."${BLD}
cci7="CCI-001851"
stigid7="RHEL-09-652050"
severity7="CAT II"
ruleid7="SV-258148r1045292"
vulnid7="V-258148"

title8a="RHEL 9 must be configured to forward audit records via TCP to a different system or media from the system being audited via rsyslog."
title8b="Checking with: grep -iR '@@' /etc/rsyslog.conf /etc/rsyslog.d/"
title8c="Expecting: ${YLO}/etc/rsyslog.d/remoteLogging.conf:*.* @@[remoteloggingserver]:[port]
           NOTE: If a remote server is not configured, or the line is commented out, ask the system administrator (SA) to indicate how the audit logs are off-loaded to a different system or media. 
           NOTE: If there is no evidence that the audit logs are being off-loaded to another system or media, this is a finding."${BLD}
cci8="CCI-001851"
stigid8="RHEL-09-652055"
severity8="CAT II"
ruleid8="SV-258149r1106462"
vulnid8="V-258149"

title9a="RHEL 9 must allocate audit record storage capacity to store at least one week's worth of audit records."
title9b="Checking with:
           a. grep -w log_file /etc/audit/auditd.conf
           b. df -h /var/log/audit/"
title9c="Expecting: ${YLO}
           a. log_file = /var/log/audit/audit.log
           b. /dev/sda2 24G 10.4G 13.6G 43% /var/log/audit
           NOTE: If the audit record partition is not allocated for sufficient storage capacity, this is a finding."${BLD}
cci9="CCI-001849 CCI-001851"
stigid9="RHEL-09-653030"
severity9="CAT II"
ruleid9="SV-258155r1045300"
vulnid9="V-258155"

title10a="RHEL 9 must allocate an audit_backlog_limit of sufficient size to capture processes that start prior to the audit daemon."
title10b="Checking with: grubby --info=ALL | grep args | grep 'audit_backlog_limit'"
title10c="Expecting: ${YLO}Nothing returned
           NOTE: If the command returns any outputs, and audit_backlog_limit is less than "8192", this is a finding."${BLD}
cci10="CCI-001464 CCI-001849"
stigid10="RHEL-09-653120"
severity10="CAT III"
ruleid10="SV-258173r1101933"
vulnid10="V-258173"

title11a="RHEL 9 audispd-plugins package must be installed."
title11b="Checking with: dnf list --installed audispd-plugins"
title11c="Expecting: ${YLO}(example) audispd-plugins.x86_64          3.0.7-101.el9_0.2
           NOTE: If the \"audispd-plugins\" package is not installed, this is a finding."${BLD}
cci11="CCI-001851"
stigid11="RHEL-09-653130"
severity11="CAT II"
ruleid11="SV-258175r1045310"
vulnid11="V-258175"

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

echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${CYN}VERIFY, (See AU-3 Content of Audit Records V-258161).${NORMAL}"

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

action="$(grep -i overflow_action /etc/audit/auditd.conf)"

if [[ $action ]]
then
  value="$(echo $action | awk -F= '{print tolower($2)}' | sed 's/ //')"
  if [[ $value == "syslog" || $value == "halt" && ${action:0:1} != "#" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$action${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$action${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, RHEL 9 takes appropriate action when the internal event queue is full.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, RHEL 9 does not take appropriate action when the internal event queue is full.${NORMAL}"
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

fs="$(mount | grep /var/log/audit)"

if [[ $fs ]]
then
  fail=0
  echo -e "${NORMAL}RESULT:    ${BLD}$fs${NORMAL}"
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${GRN}PASSED, RHEL 9 uses a separate file system for the system audit data path.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${RED}FAILED, RHEL 9 does not use a separate file system for the system audit data path.${NORMAL}"
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

isinstalled="$(dnf list --installed 2>&1 rsyslog | grep -Ev 'Updating|Installed')"

if [[ $isinstalled ]]
then
  for line in ${isinstalled[@]}
  do
    if [[ $line =~ 'rsyslog' ]]
    then
      fail=0
      echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${GRN}PASSED, RHEL 9 has the rsyslog package installed.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${RED}FAILED, RHEL 9 has the rsyslog package installed.${NORMAL}"
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

authmode="$(grep -i 'StreamDriver[\.]*AuthMode' /etc/rsyslog.conf /etc/rsyslog.d/*.conf)"

if [[ $authmode ]]
then
  file="$(echo $authmode | awk -F: '{print $1}')"
  setting="$(echo $authmode | awk -F: '{print $2}')"
  value="$(echo $setting | awk '{print $2}')"
  if [[ $setting =~ "ActionSendStreamDriverAuthMode" && $value == "x509/name" && ${setting:0:1} != "#" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${CYN}$file:${BLD}$setting${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${CYN}$file:${RED}$setting${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${GRN}PASSED, RHEL 9 authenticates the remote logging server for offloading audit logs via rsyslog.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${RED}FAILED, RHEL 9 authenticates the remote logging server for offloading audit logs via rsyslog.${NORMAL}"
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

encrypt="$(grep -i 'StreamDriver[\.]*Mode' /etc/rsyslog.conf /etc/rsyslog.d/*.conf)"

if [[ $encrypt ]]
then
  file="$(echo $encrypt | awk -F: '{print $1}')"
  setting="$(echo $encrypt | awk -F: '{print $2}')"
  value="$(echo $setting | awk '{print $2}')"
  if [[ $setting =~ "ActionSendStreamDriverMode" && $value == "1" && ${setting:0:1} != "#" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${CYN}$file:${BLD}$setting${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${CYN}$file:${RED}$setting${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${GRN}PASSED, RHEL 9 encrypts the transfer of audit records offloaded onto a different system or media from the system being audited via rsyslog.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${RED}FAILED, RHEL 9 does not encrypt the transfer of audit records offloaded onto a different system or media from the system being audited via rsyslog.${NORMAL}"
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

encrypt="$(grep -Ei 'DefaultNetStreamDriver\b|StreamDriver.Name' /etc/rsyslog.conf /etc/rsyslog.d/*.conf)"

if [[ $encrypt ]]
then
  file="$(echo $encrypt | awk -F: '{print $1}')"
  setting="$(echo $encrypt | awk -F: '{print $2}')"
  value="$(echo $setting | awk '{print $2}')"
  if [[ $setting =~ "DefaultNetstreamDriver" && $value == "gtls" && ${setting:0:1} != "#" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${CYN}$file:${BLD}$setting${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${CYN}$file:${RED}$setting${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${GRN}PASSED, RHEL 9 encrypts via the gtls driver the transfer of audit records offloaded onto a different system or media from the system being audited via rsyslog.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${RED}FAILED, RHEL 9 does not encrypt via the gtls driver the transfer of audit records offloaded onto a different system or media from the system being audited via rsyslog.${NORMAL}"
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

forward="$(grep -iR '@@' /etc/rsyslog.conf /etc/rsyslog.d/)"

if [[ $forward ]]
then
  for line in ${forward[@]}
  do
    file="$(echo $line| awk -F: '{print $1}')"
    setting="$(echo $line | awk -F: '{$1=""; sub(/^ /, ""); print}')"
    if [[ $setting =~ "*.* @@" && ${setting:0:1} != "#" ]]
    then
      fail=0
      echo -e "${NORMAL}RESULT:    ${CYN}$file:${BLD}$setting${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${CYN}$file:${RED}$setting${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cci8, $datetime, ${CYN}VERIFY, Have the system administrator verify that the server and tcp port shown are valid for log forwarding.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cci8, $datetime, ${RED}FAILED, RHEL 9 is not configured to forward audit records via TCP to a different system or media from the system being audited via rsyslog.${NORMAL}"
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

logfile="$(grep -w log_file /etc/audit/auditd.conf)"

if [[ $logfile ]]
then
  file="$(echo $logfile | awk -F= '{print $2}' | sed 's/ //')"
  dir="$(dirname $file)"
  size="$(df -h $dir)"

  echo -e "${NORMAL}RESULT:    a. Log Directory: $dir${NORMAL}"
  for line in ${size[@]}
  do
    if [[ $line =~ $dir ]]
    then
      used="$(echo $line | awk '{print $5}' | sed 's/%//')"
      echo -e "${NORMAL}RESULT:    b. $line${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    b. $line${NORMAL}"
    fi
  done

  echo "----------------------------------------------------------"

  files="$(ls $dir | grep -v "^total")"
  first="$(echo $files | awk '{print $1}')"
  last="$(echo $files | awk '{print $NF}')"

  dt1="$(stat -c "%y" $dir/$first | awk -F. '{print $1}')"
  dt2="$(stat -c "%y" $dir/$last  | awk -F. '{print $1}')"
  sz1="$(stat -c "%s" $dir/$first)"
  sz2="$(stat -c "%s" $dir/$last)"

  date1="$(echo $dt1 | awk '{print $1}')"
  date2="$(echo $dt2 | awk '{print $1}')"

  TS1="$(date -d "$date1" +%s)"
  TS2="$(date -d "$date2" +%s)"

  diff="$(( TS1 - TS2 ))"
  days="$(( diff / (60*60*24) ))"

  if ! (( $used > 95 && $days < 7 ))
  then
    fail=0
    echo -e "${NORMAL}RESULT:    First file: $dt1 $sz1 $first${NORMAL}"
    echo -e "${NORMAL}RESULT:    Last file:  $dt2 $sz2 $last${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}First file: $dt1 $sz1 $first${NORMAL}"
    echo -e "${NORMAL}RESULT:    ${RED}Last file:  $dt2 $sz2 $last${NORMAL}"
    echo -e "${NORMAL}RESULT:    ${RED}Not enough storage to hold logs${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    Nothing returned${NORMAL}"	
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity9, $controlid, $stigid9, $ruleid9, $cci9, $datetime, ${GRN}PASSED, RHEL 9 allocates audit record storage capacity to store at least one week's worth of audit records.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity9, $controlid, $stigid9, $ruleid9, $cci9, $datetime, ${RED}FAILED, RHEL 9 does not allocate audit record storage capacity to store at least one week's worth of audit records.${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

backlog="$(grubby --update-kernel=ALL --args=audit_backlog_limit)"

if [[ $backlog ]]
then
  for line in ${backlog[@]}
  do
    limit="$(echo $backlog | awk '{print $NF}')"
    if (( $limit >= 8192 ))
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$limit${NORMAL}"
    else
      fail=1
      echo -e "${NORMAL}RESULT:    ${RED}$limit${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity10, $controlid, $stigid10, $ruleid10, $cci10, $datetime, ${GRN}PASSED, RHEL 9 allocates an audit_backlog_limit of sufficient size to capture processes that start prior to the audit daemon.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity10, $controlid, $stigid10, $ruleid10, $cci10, $datetime, ${RED}FAILED, RHEL 9 does not allocate an audit_backlog_limit of sufficient size to capture processes that start prior to the audit daemon.${NORMAL}"
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

isinstalled="$(dnf list --installed 2>&1 audispd-plugins | grep -Ev '(Updating|Installed)')"

if [[ $isinstalled ]]
then
  for line in ${isinstalled[@]}
  do
    if [[ $line =~ "audispd-plugins" ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$isinstalled${NORMAL}"
      fail=0
    else
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity11, $controlid, $stigid11, $ruleid11, $cci11, $datetime, ${GRN}PASSED, RHEL 9 audispd-plugins package is installed.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity11, $controlid, $stigid11, $ruleid11, $cci11, $datetime, ${RED}FAILED, RHEL 9 audispd-plugins package is not installed.${NORMAL}"
fi

exit
