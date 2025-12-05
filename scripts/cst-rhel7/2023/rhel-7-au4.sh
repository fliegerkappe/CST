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

controlid="AU-4 Audit Storage Capacity"

title1a="The Red Hat Enterprise Linux operating system must be configured to off-load audit logs onto a different system or storage media from the system being audited."
title1b="Checking with 'cat /etc/audisp/plugins.d/au-remote.conf | grep -v \"^#\"'"
title1c="Expecting:${YLO}
active = yes
direction = out
path = /sbin/audisp-remote
type = always
format = string
           Note: If \"active\" is not set to \"yes\", \"direction\" is not set to \"out\", \"path\" is not set to \"/sbin/audisp-remote\", \"type\" is not set to \"always\", or any of the lines are commented out, ask the System Administrator to indicate how the audit logs are off-loaded to a different system or storage media.
           Note: If there is no evidence that the audit logs are being off-loaded to another system or media, this is a finding."${BLD}
cci1="CCI-001851"
stigid1="RHEL-07-030300"
severity1="CAT II"
ruleid1="SV-204506r603261_rule"
vulnid1="V-204506"

title2a="The Red Hat Enterprise Linux operating system must take appropriate action when the remote logging buffer is full."
title2b="Checking with 'grep \"overflow_action\" /etc/audisp/audispd.conf."
title2c="Expecting:${YLO}
           overflow_action = syslog
           Note: If the \"overflow_action\" option is not \"syslog\", \"single\", or \"halt\", or the line is commented out, ask the System Administrator to indicate how the audit logs are off-loaded to a different system or storage media, and to indicate what action that system takes when the internal queue is full..
           Note: If there is no evidence the system is configured to off-load audit logs to a different system or storage media or, if the configuration does not take appropriate action when the internal queue is full, this is a finding.${BLD}"
cci2="CCI-001851"
stigid2="RHEL-07-030210"
severity2="CAT II"
ruleid2="SV-204507r603261_rule"
vulnid2="V-204507"

title3a="The Red Hat Enterprise Linux operating system must label all off-loaded audit logs before sending them to the central log server."
title3b="Checking with 'grep \"name_format\" /etc/audisp/audispd.conf."
title3c="Expecting:${YLO}
           name_format = hostname
           Note: If the "name_format" option is not \"hostname\", \"fqd\", or \"numeric\", or the line is commented out, ask the System Administrator to indicate how the audit logs are off-loaded to a different system or storage media, and to indicate if the logs are labeled appropriately. 
           Note: If there is no evidence that the audit logs are being off-loaded to another system or media, or if the configuration does not appropriately label logs before they are off-loaded, this is a finding.${BLD}"
cci3="CCI-001851"
stigid3="RHEL-07-030211"
severity3="CAT II"
ruleid3="SV-204508r603261_rule"
vulnid3="V-204508"

title4a="The Red Hat Enterprise Linux operating system must off-load audit records onto a different system or media from the system being audited."
title4b="Checking with 'grep -i remote_server /etc/audisp/audisp-remote.conf'."
title4c="Expecting:${YLO}
           remote_server = 10.0.21.1
           Note: If a remote server is not configured, or the line is commented out, ask the System Administrator to indicate how the audit logs are off-loaded to a different system or media.
           Note: If there is no evidence that the audit logs are being off-loaded to another system or media, this is a finding.${BLD}"
cci4="CCI-001851"
stigid4="RHEL-07-030300"
severity4="CAT II"
ruleid4="SV-204509r603261_rule"
vulnid4="V-204509"

title5a="The Red Hat Enterprise Linux operating system must encrypt the transfer of audit records off-loaded onto a different system or media from the system being audited."
title5b="Checking with 'grep -i 'enable_krb5' /etc/audisp/audisp-remote.conf'."
title5c="Expecting:${YLO}
           enable_krb5 = yes.
           Note: If the value of the \"enable_krb5\" option is not set to \"yes\" or the line is commented out, ask the System Administrator to indicate how the audit logs are off-loaded to a different system or media.
           Note: If there is no evidence that the transfer of the audit logs being off-loaded to another system or media is encrypted, this is a finding."${BLD}
cci5="CCI-001851"
stigid5="RHEL-07-030310"
severity5="CAT II"
ruleid5="SV-204510r603261_rule"
vulnid5="V-204510"

title6a="The Red Hat Enterprise Linux operating system must be configured so that the audit system takes appropriate action when the audit storage volume is full."
title6b="Checking with 'grep -i disk_full_action /etc/audisp/audisp-remote.conf'."
title6c="Expecting:${YLO}
           disk_full_action = single
           Note: If the value of the \"disk_full_action\" option is not \"syslog\", \"single\", or \"halt\", or the line is commented out, ask the System Administrator to indicate how the audit logs are off-loaded to a different system or storage media, and to indicate the action taken when the disk is full on the remote server.
           Note: If there is no evidence that the system is configured to off-load audit logs to a different system or storage media, or if the configuration does not take appropriate action when the disk is full on the remote server, this is a finding."${BLD}
cci6="CCI-001851"
stigid6="RHEL-07-030320"
severity6="CAT II"
ruleid6="SV-204511r603261_rule"
vulnid6="V-204511"

title7a="The Red Hat Enterprise Linux operating system must be configured so that the audit system takes appropriate action when there is an error sending audit records to a remote system."
title7b="Checking with 'grep -i network_failure_action /etc/audisp/audisp-remote.conf'."
title7c="Expecting:${YLO}
           network_failure_action = syslog
           Note: If the value of the \"network_failure_action\" option is not \"syslog\", \"single\", or \"halt\", or the line is commented out, ask the System Administrator to indicate how the audit logs are off-loaded to a different system or storage media, and to indicate the action taken if there is an error sending audit records to the remote system.
           Note: If there is no evidence that the system is configured to off-load audit logs to a different system or storage media, or if the configuration does not take appropriate action if there is an error sending audit records to the remote system, this is a finding."${BLD}
cci7="CCI-001851"
stigid7="RHEL-07-030321"
severity7="CAT II"
ruleid7="SV-204512r603261_rule"
vulnid7="V-204512"

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

file1="/etc/audisp/plugins.d/au-remote.conf"
fail=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file1 ]]
then
   rmtsvr="$(cat $file1 | grep -v '^#')"
   if [[ $rmtsvr ]]
   then
      for line in ${rmtsvr[@]}
      do
         case element in
         'active')
             active="$(echo $element | awk -F"= " '{print $2}')"
             if [[ $active == "yes" ]]
             then
                echo -e "${NORMAL}RESULT:    ${BLD}$element${NORMAL}"
             else
                echo -e "${NORMAL}RESULT:    ${RED}$element${NORMAL}"
                fail=1
             fi
             ;;
         'direction')
             direction="$(echo $element | awk -F"= " '{print $2}')"
             if [[ $direction == "out" ]]
             then
                echo -e "${NORMAL}RESULT:    ${BLD}$element${NORMAL}"
             else
                echo -e "${NORMAL}RESULT:    ${RED}$element${NORMAL}"
                fail=1
             fi
             ;;
         'path')
             path="$(echo $element | awk -F"= " '{print $2}')"
             if [[ $path == "/sbin/audisp-remote" ]]
             then
                echo -e "${NORMAL}RESULT:    ${BLD}$element${NORMAL}"
             else
                echo -e "${NORMAL}RESULT:    ${RED}$element${NORMAL}"
                fail=1
             fi
             ;;
         'type')
             type="$(echo $element | awk -F"= " '{print $2}')"
             if [[ $type == "always" ]]
             then
                echo -e "${NORMAL}RESULT:    ${BLD}$element${NORMAL}"
             else
                echo -e "${NORMAL}RESULT:    ${RED}$element${NORMAL}"
                fail=1
             fi
             ;;
         'format')
             format="$(echo $element | awk -F"= " '{print $2}')"
             if [[ $format == "string" ]]
             then
                echo -e "${NORMAL}RESULT:    ${BLD}$element${NORMAL}"
             else
                echo -e "${NORMAL}RESULT:    ${RED}$element${NORMAL}"
                fail=1
             fi
             ;;
         esac
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}A remote log file server is not configured${NORMAL}"
   fi

   if [[ $fail == 0 ]]
   then
      echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, Audit log off-loading: The operating system off-loads audit records onto a different system or media from the system being audited.${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, Audit log off-loading: The operating system does not off-load audit records onto a different system or media from the system being audited.${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}$file1 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, Audit Log Off-Loading: The operating system does not off-load audit records onto a different system or media from the system being audited.${NORMAL}"
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

file2="/etc/audisp/audispd.conf"

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file2 ]]
then
   overflow="$(grep 'overflow_action' $file2 | grep -v '^#' )"
   if [[ $overflow ]]
   then
      action="$(echo $overflow | awk -F= '{print tolower($2)}' | sed -e 's/^[[:space:]]*//')"
      if [[ $action == 'syslog' || $action == 'single' || $action == 'halt' ]]
      then
         echo -e "${NORMAL}RESULT:    ${BLD}$overflow${NORMAL}"
         echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, AUDISP-REMOTE Buffer: The operating system takes appropriate action when the audisp-remote buffer is full.${NORMAL}"
      else
         echo -e "${NORMAL}RESULT:    ${RED}$overflow${NORMAL}"
         echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, AUDISP-REMOTE Buffer: The operating system does not take appropriate action when the audisp-remote buffer is full.${NORMAL}"
      fi
   else
      echo -e "${NORMAL}RESULT:    ${RED}'overflow_action' is not defined in $file2${NORMAL}"
       echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, AUDISP-REMOTE Buffer: The operating system does not take appropriate action when the audisp-remote buffer is full.${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}$file2 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, AU-REMOTE Overflow_action: The operating system does not take appropriate action when the audisp-remote buffer is full.${NORMAL}"

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

file3="/etc/audisp/audispd.conf"

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file3 ]]
then
   nformat="$(grep name_format $file3)"
   if [[ $nformat ]]
   then
      format="$(echo $nformat | awk -F= '{print tolower($2)}' | sed -e 's/^[[:space:]]*//')"
      if [[ $format == 'hostname' || $format == 'fqd' || $format == 'numeric' ]]
      then
         echo -e "${NORMAL}RESULT:    ${BLD}$nformat${NORMAL}"
         echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${GRN}PASSED, The audisp daemon is configured to label all off-loaded audit logs${NORMAL}"
      else
         echo -e "${NORMAL}RESULT:    ${RED}$nformat${NORMAL}"
         echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${RED}FAILED, The audisp daemon is not configured to label all off-loaded audit logs:${NORMAL}"
      fi
   else
      echo -e "${NORMAL}RESULT:    ${RED}'name_format' is not defined in $file3${NORMAL}"
       echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${RED}FAILED, The audisp daemon is not configured to label all off-loaded audit logs:${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}$file3 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${RED}FAILED, AUDISPD NAME_FORMAT: The operating system does not label all off-loaded audit logs before sending them to the central log server.${NORMAL}"

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

file4="/etc/audisp/audisp-remote.conf"
fail=1

if [[ -f $file4 ]]
then
   remote="$(grep -i remote_server $file4 2>/dev/null)"
   if [[ $remote ]]
   then
      remotesvr="$(echo $remote | awk -F"= " '{print $2}')"
      if [[ $remotesvr ]]
      then
         echo -e "${NORMAL}RESULT:    ${BLD}$remote${NORMAL}"
         fail=0
      else
         echo -e "${NORMAL}RESULT:    ${RED}$remote${NORMAL}"
      fi
    else
       echo -e "${NORMAL}RESULT:    ${RED}A remote server is not defined in $file4${NORMAL}"
    fi
else
   echo -e "${NORMAL}RESULT:    ${RED}$file4 not found${NORMAL}"
fi

datetime="$(date +%FT%H:%M:%S)"

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${CYN}VERIFY, Verify that the operating system off-loads audit records onto a different system or media from the system being audited.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${RED}FAILED, The operating system does not off-load audit records onto a different system or media from the system being audited.${NORMAL}"
fi

cho
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

file5="/etc/audisp/audisp-remote.conf"
fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file5 ]]
then
   krb5enabled="$(grep -i 'enable_krb5' $file5)"
   if [[ $krb5enabled ]]
   then
      if [[ ! ${krb5enabled:0:1} == '#' ]]
      then
         echo -e "${NORMAL}RESULT:    ${BLD}$krb5enabled${NORMAL}"
         fail=0
      else
         echo -e "${NORMAL}RESULT:    ${RED}$krb5enabled${NORMAL}"
      fi
   else
      echo -e "${NORMAL}RESULT:    ${RED}Remote log file transfer encryption is not enabled${NORMAL}"
   fi

   if [[ $fail == 0 ]]
   then
      echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid2, $cci5, $datetime, ${GRN}PASSED, Audit log off-loading: File transfer encryption is enabled${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid2, $cci5, $datetime, ${RED}FAILED, Audit log off-loading: File transfer encryption is not enabled${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}$file5 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${RED}FAILED, Audit Log Off-Loading: File transfer encryption is not enabled${NORMAL}"
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

file6="/etc/audisp/audisp-remote.conf"
fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file6 ]]
then
   fullaction="$(grep -i 'disk_full_action' $file6)"
   if [[ $fullaction ]]
   then
      if [[ ! ${fullaction:0:1} == '#' ]]
      then
         action="$(echo $fullaction | awk -F= '{print tolower($2)}')"
         if [[ $action == 'syslog' || $action == 'single' || $action == 'halt' ]]
         then
            echo -e "${NORMAL}RESULT:    ${BLD}$fullaction${NORMAL}"
            fail=0
         else
            echo -e "${NORMAL}RESULT:    ${RED}$fullaction${NORMAL}"
         fi
      else
         echo -e "${NORMAL}RESULT:    ${RED}$fullaction${NORMAL}"
      fi
   else
      echo -e "${NORMAL}RESULT:    ${RED}\"disk_full action\" is not defined in $file6${NORMAL}"
   fi

   if [[ $fail == 0 ]]
   then
      echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid3, $cci6, $datetime, ${GRN}PASSED, The operating system is configured to take appropriate action when the audit storage volume is full.${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${RED}FAILED, The operating system is not configured to take appropriate action when the audit storage volume is full.${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}$file6 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${RED}FAILED, Audit Volume Full Action: $file6 not found. \"disk_full_action\" is not enabled${NORMAL}"
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

file7="/etc/audisp/audisp-remote.conf"
fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file7 ]]
then
   netfailaction="$(grep -i 'network_failure_action' $file7)"
   if [[ $netfailaction ]]
   then
      if [[ ! ${netfailaction:0:1} == '#' ]]
      then
         action="$(echo $netfailaction | awk -F= '{print tolower($2)}')"
         if [[ $action == 'syslog' || $action == 'single' || $action == 'halt' ]]
         then
            echo -e "${NORMAL}RESULT:    ${BLD}$netfailaction${NORMAL}"
            fail=0
         else
            echo -e "${NORMAL}RESULT:    ${RED}$netfailaction${NORMAL}"
         fi
      else
         echo -e "${NORMAL}RESULT:    ${RED}$netfailaction${NORMAL}"
      fi
   else
      echo -e "${NORMAL}RESULT:    ${RED}Network_failure action is not defined in $file7${NORMAL}"
   fi

   if [[ $fail == 0 ]]
   then
      echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${GRN}PASSED, Audit Log Off-loading: network_failure_action is enabled${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid4, $cci7, $datetime, ${RED}FAILED, Audit Log Off-loading: network_failure_action is not enabled${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}$file7 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${RED}FAILED, Audit Log Off-loading: network_failure_action is not enabled${NORMAL}"
fi

exit
