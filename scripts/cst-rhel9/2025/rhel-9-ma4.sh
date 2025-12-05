#! /bin/bash

# MA-4 Nonlocal Maintenance

# CONTROL: 
# a. Approve and monitor nonlocal maintenance and diagnostic activities;
# b. Allow the use of nonlocal maintenance and diagnostic tools only as consistent
#    with organizational policy and documented in the security plan for the system;
# c. Employ strong authentication in the establishment of nonlocal maintenance and
#    diagnostic sessions;
# d. Maintain records for nonlocal maintenance and diagnostic activities; and
# e. Terminate session and network connections when nonlocal maintenance is completed.

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

controlid="MA-4 Nonlocal Maintenance"

title1a="RHEL 9 must generate audit records for all account creations, modifications, disabling, and termination events that affect /var/log/tallylog."
title1b="Checking with: auditctl -l | grep /var/log/tallylog"
title1c="Expecting: ${YLO}-w /var/log/tallylog -p wa -k logins
           NOTE: If the command does not return a line, or the line is commented out, is a finding."${BL}
cci1="CCI-000172 CCI-002884"
stigid1="RHEL-09-654260"
severity1="CAT II"
ruleid1="SV-258226r958846"
vulnid1="V-258226"

title2a="RHEL 9 must enable FIPS mode."
title2b="Checking with: fips-mode-setup --check"
title2c="Expecting: ${YLO}FIPS mode is enabled.
           NOTE: If FIPS mode is not enabled, this is a finding."
cci2="CCI-000068 CCI-000877 CCI-002418 CCI-002450"
stigid2="RHEL-09-671010"
severity2="CAT I"
ruleid2="SV-258230r958408"
vulnid2="V-258230"

title3a="RHEL 9 must enable auditing of processes that start prior to the audit daemon."
title3b="Checking with: 
           a. grubby --info=ALL | grep args | grep -v 'audit=1'
	   b. grep audit /etc/default/grub"
title3c="Expecting: ${YLO}
           a. Nothing returned
	   b. GRUB_CMDLINE_LINUX=\"audit=1\"
	   NOTE: a. If any output is returned, this is a finding.
	   NOTE: b. If \"audit\" is not set to \"1\", is missing, or is commented out, this is a finding."${BLD}
cci3="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-001464 CCI-002884"
stigid3="RHEL-09-212055"
severity3="CAT III"
ruleid3="SV-257796r1044847"
vulnid3="V-257796"

title4a="RHEL 9 must enable the Pluggable Authentication Module (PAM) interface for SSHD."
title4b="Checking with: /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print \$4}' | tr -d '\\\\r' | tr '\\\\n' ' ' | sudo grep -iH '^\s*usepam'"
title4c="Expecting: ${YLO}UsePAM yes
           NOTE: If the \"UsePAM\" keyword is set to \"no\", is missing, or is commented out, this is a finding."${BLD}
cci4="CCI-000877"
stigid4="RHEL-09-255050"
severity4="CAT I"
ruleid4="SV-257986r1045030"
vulnid4="V-257986"

title5a="RHEL 9 must be configured so that all network connections associated with SSH traffic are terminated after 10 minutes of becoming unresponsive."
title5b="Checking with: /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print \$4}' | tr -d '\\\\r' | tr '\\\\n' ' ' | xargs grep -iH '^\s*clientaliveinterval'"
title5c="Expecting: ${YLO}ClientAliveInterval 600
           NOTE: If \"ClientAliveInterval\" does not exist, does not have a value of \"600\" or less in \"/etc/ssh/sshd_config\", or is commented out, this is a finding."${BLD}
cci5="CCI-001133 CCI-002361 CCI-002891"
stigid5="RHEL-09-255100"
severity5="CAT II"
ruleid5="SV-257996r1045055"
vulnid5="V-257996"

title6a="RHEL 9 audit package must be installed."
title6b="Checking with: dnf list --installed audit"
title6c="Expecting: ${YLO}audit-3.0.7-101.el9_0.2.x86_64
           NOTE: If the \"audit\" package is not installed, this is a finding."${BLD}
cci6="CCI-000130 CCI-000131 CCI-000132 CCI-000133 CCI-000134 CCI-000135 CCI-000154 CCI-000158 CCI-000159 CCI-000169 CCI-000172 CCI-001464 CCI-001487 CCI-003938 CCI-001875 CCI-001876 CCI-001877 CCI-001878 CCI-001879 CCI-001880 CCI-001881 CCI-001882 CCI-001889 CCI-001914 CCI-002884 CCI-001814"
stigid6="RHEL-09-653010"
severity6="CAT II"
ruleid6="SV-258151r1045298"
vulnid6="V-258151"

title7a=""
title7b=""
title7c=""
cci7=""
stigid7=""
severity7=""
ruleid7=""
vulnid7=""

title8a=""
title8b=""
title8c=""
cci8=""
stigid8=""
severity8=""
ruleid8=""
vulnid8=""

title9a=""
title9b=""
title9c=""
cci9=""
stigid9=""
severity9=""
ruleid9=""
vulnid9=""

title10a=""
title10b=""
title10c=""
cci10=""
stigid10=""
severity10=""
ruleid10=""
vulnid10=""

title11a=""
title11b=""
title11c=""
cci11=""
stigid11=""
severity11=""
ruleid11=""
vulnid11=""

title12a=""
title12b=""
title12c=""
cci12=""
stigid12=""
severity12=""
ruleid12=""
vulnid12=""

title13a=""
title13b=""
title13c=""
cci13=""
stigid13=""
severity13=""
ruleid13=""
vulnid13=""

title14a=""
title14b=""
title14c=""
cci14=""
stigid14=""
severity14=""
ruleid14=""
vulnid14=""

title15a=""
title15b=""
title15c=""
cci15=""
stigid15=""
severity15=""
ruleid15=""
vulnid15=""

title16a=""
title16b=""
title16c=""
cci16=""
stigid16=""
severity16=""
ruleid16=""
vulnid16=""

title17a=""
title17b=""
title17c=""
cci17=""
stigid17=""
severity17=""
ruleid17=""
vulnid17=""

title18a=""
title18b=""
title18c=""
cci18=""
stigid18=""
severity18=""
ruleid18=""
vulnid18=""

title19a=""
title19b=""
title19c=""
cci19=""
stigid19=""
severity19=""
ruleid19=""
vulnid19=""

title20a=""
title20b=""
title20c=""
cci20=""
stigid20=""
severity20=""
ruleid20=""
vulnid20=""

title21a=""
title21b=""
title21c=""
cci21=""
stigid21=""
severity21=""
ruleid21=""
vulnid21=""

title22a=""
title22b=""
title22c=""
cci22=""
stigid22=""
severity22=""
ruleid22=""
vulnid22=""

title23a=""
title23b=""
title230c=""
cci23=""
stigid23=""
severity23=""
ruleid23=""
vulnid23=""

title24a=""
title24b=""
title24c=""
cci24=""
stigid24=""
severity24=""
ruleid24=""
vulnid24=""

title25a=""
title25b=""
title25c=""
cci25=""
stigid25=""
severity25=""
ruleid25=""
vulnid25=""

title26a=""
title26b=""
title26c=""
cci26=""
stigid26=""
severity26=""
ruleid26=""
vulnid26=""

title27a=""
title27b=""
title27c=""
cci27=""
stigid27=""
severity27=""
ruleid27=""
vulnid27=""

title28a=""
title28b=""
title28c=""
cci28=""
stigid28=""
severity28=""
ruleid28=""
vulnid28=""

title29a=""
title29b=""
title29c=""
cci29=""
stigid29=""
severity29=""
ruleid29=""
vulnid29=""

title30a=""
title30b=""
title30c=""
cci30=""
stigid30=""
severity30=""
ruleid30=""
vulnid30=""

title31a=""
title31b=""
title31c=""
cci31=""
stigid31=""
severity31=""
ruleid31=""
vulnid31=""

title32a=""
title32b=""
title32c=""
cci32=""
stigid32=""
severity32=""
ruleid32=""
vulnid32=""

title33a=""
title33b=""
title33c=""
cci33=""
stigid33=""
severity33=""
ruleid33=""
vulnid33=""

title34a=""
title34b=""
title34c=""
cci34=""
stigid34=""
severity34=""
ruleid34=""
vulnid34=""

title35a=""
title35b=""
title35c=""
cci35=""
stigid35=""
severity35=""
ruleid35=""
vulnid35=""

title36a=""
title36b=""
title36c=""
cci36=""
stigid36=""
severity36=""
ruleid36=""
vulnid36=""

title37a=""
title37b=""
title37c=""
cci37=""
stigid37=""
severity37=""
ruleid37=""
vulnid37=""

title38a=""
title38b=""
title38c=""
cci38=""
stigid38=""
severity38=""
ruleid38=""
vulnid38=""

title39a=""
title39b=""
title39c=""
cci39=""
stigid39=""
severity39=""
ruleid39=""
vulnid39=""

title40a=""
title40b=""
title40c=""
cci40=""
stigid40=""
severity40=""
ruleid40=""
vulnid40=""

title41a=""
title41b=""
title41c=""
cci41=""
stigid41=""
severity41=""
ruleid41=""
vulnid41=""

title42a=""
title42b=""
title42c=""
cci42=""
stigid42=""
severity42=""
ruleid42=""
vulnid42=""

title43a=""
title43b=""
title43c=""
cci43=""
stigid43=""
severity43=""
ruleid43=""
vulnid43=""

title44a=""
title44b=""
title44c=""
cci44=""
stigid44=""
severity44=""
ruleid44=""
vulnid44=""

title45a=""
title45b=""
title45c=""
cci45=""
stigid45=""
severity45=""
ruleid45=""
vulnid45=""

title46a=""
title46b=""
title46c=""
cci46=""
stigid46=""
severity46=""
ruleid46=""
vulnid46=""

title47a=""
title47b=""
title47c=""
cci47=""
stigid47=""
severity47=""
ruleid47=""
vulnid47=""

title48a=""
title48b=""
title48c=""
cci48=""
stigid48=""
severity48=""
ruleid48=""
vulnid48=""

title49a=""
title49b=""
title49c=""
cci49=""
stigid49=""
severity49=""
ruleid49=""
vulnid49=""

title50a=""
title50b=""
title50c=""
cci50=""
stigid50=""
severity50=""
ruleid50=""
vulnid50=""

title51a=""
title51b=""
title51c=""
cci51=""
stigid51=""
severity51=""
ruleid51=""
vulnid51=""

title52a=""
title52b=""
title52c=""
cci52=""
stigid52=""
severity52=""
ruleid52=""
vulnid52=""

title53a=""
title53b=""
title53c=""
cci53=""
stigid53=""
severity53=""
ruleid53=""
vulnid53=""

title54a=""
title54b=""
title54c=""
cci54=""
stigid54=""
severity54=""
ruleid54=""
vulnid54=""

title55a=""
title55b=""
title55c=""
cci55=""
stigid55=""
severity55=""
ruleid55=""
vulnid55=""

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

echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation: V-258226)${NORMAL}"

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

echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${CYN}VERIFY, (See AC-17 Remote Access: V-258230)${NORMAL}"

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

echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation: V-257796)${NORMAL}"

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

usepam="$(/usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs grep -iH '^\s*usepam')"

if [[ $usepam ]]
then
  file="$(echo $usepam | awk -F: '{print $1}')"
  setting="$(echo $usepam | awk -F: '{print $2}')"
  value="$(echo $setting | awk '{print $2}' | sed 's/ //')"
  if [[ $value == "yes" && ${setting:0:1} != "#" ]]
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
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${GRN}PASSED, RHEL 9 enables the Pluggable Authentication Module (PAM) interface for SSHD.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${RED}FAILED, RHEL 9 does not enable the Pluggable Authentication Module (PAM) interface for SSHD.${NORMAL}"
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

echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${CYN}VERIFY, (See AC-12 Session Termination: V-257996)${NORMAL}"

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

echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation: V-258151)${NORMAL}"

#echo
#echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
#echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
#echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
#echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
#echo -e "${NORMAL}STIG ID:   $stigid7${NORMAL}"
#echo -e "${NORMAL}RULE ID:   $ruleid7${NORMAL}"
#echo -e "${NORMAL}VULN ID:   $vulnid7${NORMAL}"
#echo -e "${NORMAL}CCI:       $cci7${NORMAL}"
#echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
#echo -e "${NORMAL}TEST 7:    ${BLD}$title7a${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title7b${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title7c${NORMAL}"
#echo -e "${NORMAL}SEVERITY:  ${BLD}$severity7${NORMAL}"
#
#datetime="$(date +%FT%H:%M:%S)"
#
#
#echo
#echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
#echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
#echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
#echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
#echo -e "${NORMAL}STIG ID:   $stigid8${NORMAL}"
#echo -e "${NORMAL}RULE ID:   $ruleid8${NORMAL}"
#echo -e "${NORMAL}VULN ID:   $vulnid8${NORMAL}"
#echo -e "${NORMAL}CCI:       $cci8${NORMAL}"
#echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
#echo -e "${NORMAL}TEST 8:    ${BLD}$title8a${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title8b${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title8c${NORMAL}"
#echo -e "${NORMAL}SEVERITY:  ${BLD}$severity8${NORMAL}"
#
#datetime="$(date +%FT%H:%M:%S)"
#
#
#echo
#echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
#echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
#echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
#echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
#echo -e "${NORMAL}STIG ID:   $stigid9${NORMAL}"
#echo -e "${NORMAL}RULE ID:   $ruleid9${NORMAL}"
#echo -e "${NORMAL}VULN ID:   $vulnid9${NORMAL}"
#echo -e "${NORMAL}CCI:       $cci9${NORMAL}"
#echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
#echo -e "${NORMAL}TEST 9:    ${BLD}$title9a${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title9b${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title9c${NORMAL}"
#echo -e "${NORMAL}SEVERITY:  ${BLD}$severity9${NORMAL}"
#
#datetime="$(date +%FT%H:%M:%S)"
#
#
#echo
#echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
#echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
#echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
#echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
#echo -e "${NORMAL}STIG ID:   $stigid10${NORMAL}"
#echo -e "${NORMAL}RULE ID:   $ruleid10${NORMAL}"
#echo -e "${NORMAL}VULN ID:   $vulnid10${NORMAL}"
#echo -e "${NORMAL}CCI:       $cci10${NORMAL}"
#echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
#echo -e "${NORMAL}TEST 10:   ${BLD}$title10a${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title10b${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title10c${NORMAL}"
#echo -e "${NORMAL}SEVERITY:  ${BLD}$severity10${NORMAL}"
#
#datetime="$(date +%FT%H:%M:%S)"
#
#
#echo
#echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
#echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
#echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
#echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
#echo -e "${NORMAL}STIG ID:   $stigid11${NORMAL}"
#echo -e "${NORMAL}RULE ID:   $ruleid11${NORMAL}"
#echo -e "${NORMAL}VULN ID:   $vulnid11${NORMAL}"
#echo -e "${NORMAL}CCI:       $cci11${NORMAL}"
#echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
#echo -e "${NORMAL}TEST 11:   ${BLD}$title11a${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title11b${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title11c${NORMAL}"
#echo -e "${NORMAL}SEVERITY:  ${BLD}$severity11${NORMAL}"
#
#datetime="$(date +%FT%H:%M:%S)"
#
#
#echo
#echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
#echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
#echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
#echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
#echo -e "${NORMAL}STIG ID:   $stigid12${NORMAL}"
#echo -e "${NORMAL}RULE ID:   $ruleid12${NORMAL}"
#echo -e "${NORMAL}VULN ID:   $vulnid12${NORMAL}"
#echo -e "${NORMAL}CCI:       $cci12${NORMAL}"
#echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
#echo -e "${NORMAL}TEST 12:   ${BLD}$title12a${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title12b${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title12c${NORMAL}"
#echo -e "${NORMAL}SEVERITY:  ${BLD}$severity12${NORMAL}"
#
#datetime="$(date +%FT%H:%M:%S)"
#
#
#echo
#echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
#echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
#echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
#echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
#echo -e "${NORMAL}STIG ID:   $stigid13${NORMAL}"
#echo -e "${NORMAL}RULE ID:   $ruleid13${NORMAL}"
#echo -e "${NORMAL}VULN ID:   $vulnid13${NORMAL}"
#echo -e "${NORMAL}CCI:       $cci13${NORMAL}"
#echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
#echo -e "${NORMAL}TEST 13:   ${BLD}$title13a${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title13b${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title13c${NORMAL}"
#echo -e "${NORMAL}SEVERITY:  ${BLD}$severity13${NORMAL}"
#
#datetime="$(date +%FT%H:%M:%S)"
#
#
#echo
#echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
#echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
#echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
#echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
#echo -e "${NORMAL}STIG ID:   $stigid14${NORMAL}"
#echo -e "${NORMAL}RULE ID:   $ruleid14${NORMAL}"
#echo -e "${NORMAL}VULN ID:   $vulnid14${NORMAL}"
#echo -e "${NORMAL}CCI:       $cci14${NORMAL}"
#echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
#echo -e "${NORMAL}TEST 14:   ${BLD}$title14a${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title14b${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title14c${NORMAL}"
#echo -e "${NORMAL}SEVERITY:  ${BLD}$severity14${NORMAL}"
#
#datetime="$(date +%FT%H:%M:%S)"
#
#
#echo
#echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
#echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
#echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
#echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
#echo -e "${NORMAL}STIG ID:   $stigid15${NORMAL}"
#echo -e "${NORMAL}RULE ID:   $ruleid15${NORMAL}"
#echo -e "${NORMAL}VULN ID:   $vulnid15${NORMAL}"
#echo -e "${NORMAL}CCI:       $cci15${NORMAL}"
#echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
#echo -e "${NORMAL}TEST 15:   ${BLD}$title15a${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title15b${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title15c${NORMAL}"
#echo -e "${NORMAL}SEVERITY:  ${BLD}$severity15${NORMAL}"
#
#datetime="$(date +%FT%H:%M:%S)"
#
#
#echo
#echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
#echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
#echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
#echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
#echo -e "${NORMAL}STIG ID:   $stigid16${NORMAL}"
#echo -e "${NORMAL}RULE ID:   $ruleid16${NORMAL}"
#echo -e "${NORMAL}VULN ID:   $vulnid16${NORMAL}"
#echo -e "${NORMAL}CCI:       $cci16${NORMAL}"
#echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
#echo -e "${NORMAL}TEST 16:   ${BLD}$title16a${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title16b${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title16c${NORMAL}"
#echo -e "${NORMAL}SEVERITY:  ${BLD}$severity16${NORMAL}"
#
#datetime="$(date +%FT%H:%M:%S)"
#
#
#echo
#echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
#echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
#echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
#echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
#echo -e "${NORMAL}STIG ID:   $stigid17${NORMAL}"
#echo -e "${NORMAL}RULE ID:   $ruleid17${NORMAL}"
#echo -e "${NORMAL}VULN ID:   $vulnid17${NORMAL}"
#echo -e "${NORMAL}CCI:       $cci17${NORMAL}"
#echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
#echo -e "${NORMAL}TEST 17:   ${BLD}$title17a${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title17b${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title17c${NORMAL}"
#echo -e "${NORMAL}SEVERITY:  ${BLD}$severity17${NORMAL}"
#
#datetime="$(date +%FT%H:%M:%S)"
#
#
#echo
#echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
#echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
#echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
#echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
#echo -e "${NORMAL}STIG ID:   $stigid18${NORMAL}"
#echo -e "${NORMAL}RULE ID:   $ruleid18${NORMAL}"
#echo -e "${NORMAL}VULN ID:   $vulnid18${NORMAL}"
#echo -e "${NORMAL}CCI:       $cci18${NORMAL}"
#echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
#echo -e "${NORMAL}TEST 18:   ${BLD}$title18a${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title18b${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title18c${NORMAL}"
#echo -e "${NORMAL}SEVERITY:  ${BLD}$severity18${NORMAL}"
#
#datetime="$(date +%FT%H:%M:%S)"
#
#
#echo
#echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
#echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
#echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
#echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
#echo -e "${NORMAL}STIG ID:   $stigid19${NORMAL}"
#echo -e "${NORMAL}RULE ID:   $ruleid19${NORMAL}"
#echo -e "${NORMAL}VULN ID:   $vulnid19${NORMAL}"
#echo -e "${NORMAL}CCI:       $cci19${NORMAL}"
#echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
#echo -e "${NORMAL}TEST 19:   ${BLD}$title19a${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title19b${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title19c${NORMAL}"
#echo -e "${NORMAL}SEVERITY:  ${BLD}$severity19${NORMAL}"
#
#datetime="$(date +%FT%H:%M:%S)"
#
#
#echo
#echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
#echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
#echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
#echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
#echo -e "${NORMAL}STIG ID:   $stigid20${NORMAL}"
#echo -e "${NORMAL}RULE ID:   $ruleid20${NORMAL}"
#echo -e "${NORMAL}VULN ID:   $vulnid20${NORMAL}"
#echo -e "${NORMAL}CCI:       $cci20${NORMAL}"
#echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
#echo -e "${NORMAL}TEST 20:   ${BLD}$title20a${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title20b${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title20c${NORMAL}"
#echo -e "${NORMAL}SEVERITY:  ${BLD}$severity20${NORMAL}"
#
#datetime="$(date +%FT%H:%M:%S)"
#
#
#echo
#echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
#echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
#echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
#echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
#echo -e "${NORMAL}STIG ID:   $stigid21${NORMAL}"
#echo -e "${NORMAL}RULE ID:   $ruleid21${NORMAL}"
#echo -e "${NORMAL}VULN ID:   $vulnid21${NORMAL}"
#echo -e "${NORMAL}CCI:       $cci21${NORMAL}"
#echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
#echo -e "${NORMAL}TEST 21:   ${BLD}$title21a${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title21b${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title21c${NORMAL}"
#echo -e "${NORMAL}SEVERITY:  ${BLD}$severity21${NORMAL}"
#
#datetime="$(date +%FT%H:%M:%S)"
#
#
#echo
#echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
#echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
#echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
#echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
#echo -e "${NORMAL}STIG ID:   $stigid22${NORMAL}"
#echo -e "${NORMAL}RULE ID:   $ruleid22${NORMAL}"
#echo -e "${NORMAL}VULN ID:   $vulnid22${NORMAL}"
#echo -e "${NORMAL}CCI:       $cci22${NORMAL}"
#echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
#echo -e "${NORMAL}TEST 22:   ${BLD}$title22a${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title22b${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title22c${NORMAL}"
#echo -e "${NORMAL}SEVERITY:  ${BLD}$severity22${NORMAL}"
#
#datetime="$(date +%FT%H:%M:%S)"
#
#
#echo
#echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
#echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
#echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
#echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
#echo -e "${NORMAL}STIG ID:   $stigid23${NORMAL}"
#echo -e "${NORMAL}RULE ID:   $ruleid23${NORMAL}"
#echo -e "${NORMAL}VULN ID:   $vulnid23${NORMAL}"
#echo -e "${NORMAL}CCI:       $cci23${NORMAL}"
#echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
#echo -e "${NORMAL}TEST 23:   ${BLD}$title23a${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title23b${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title23c${NORMAL}"
#echo -e "${NORMAL}SEVERITY:  ${BLD}$severity23${NORMAL}"
#
#datetime="$(date +%FT%H:%M:%S)"
#
#
#echo
#echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
#echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
#echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
#echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
#echo -e "${NORMAL}STIG ID:   $stigid24${NORMAL}"
#echo -e "${NORMAL}RULE ID:   $ruleid24${NORMAL}"
#echo -e "${NORMAL}VULN ID:   $vulnid24${NORMAL}"
#echo -e "${NORMAL}CCI:       $cci24${NORMAL}"
#echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
#echo -e "${NORMAL}TEST 24:   ${BLD}$title24a${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title24b${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title24c${NORMAL}"
#echo -e "${NORMAL}SEVERITY:  ${BLD}$severity24${NORMAL}"
#
#datetime="$(date +%FT%H:%M:%S)"
#
#
#echo
#echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
#echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
#echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
#echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
#echo -e "${NORMAL}STIG ID:   $stigid25${NORMAL}"
#echo -e "${NORMAL}RULE ID:   $ruleid25${NORMAL}"
#echo -e "${NORMAL}VULN ID:   $vulnid25${NORMAL}"
#echo -e "${NORMAL}CCI:       $cci25${NORMAL}"
#echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
#echo -e "${NORMAL}TEST 25:   ${BLD}$title25a${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title25b${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title25c${NORMAL}"
#echo -e "${NORMAL}SEVERITY:  ${BLD}$severity25${NORMAL}"
#
#datetime="$(date +%FT%H:%M:%S)"
#
#
#echo
#echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
#echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
#echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
#echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
#echo -e "${NORMAL}STIG ID:   $stigid26${NORMAL}"
#echo -e "${NORMAL}RULE ID:   $ruleid26${NORMAL}"
#echo -e "${NORMAL}VULN ID:   $vulnid26${NORMAL}"
#echo -e "${NORMAL}CCI:       $cci26${NORMAL}"
#echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
#echo -e "${NORMAL}TEST 26:   ${BLD}$title26a${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title26b${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title26c${NORMAL}"
#echo -e "${NORMAL}SEVERITY:  ${BLD}$severity26${NORMAL}"
#
#datetime="$(date +%FT%H:%M:%S)"
#
#
#echo
#echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
#echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
#echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
#echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
#echo -e "${NORMAL}STIG ID:   $stigid27${NORMAL}"
#echo -e "${NORMAL}RULE ID:   $ruleid27${NORMAL}"
#echo -e "${NORMAL}VULN ID:   $vulnid27${NORMAL}"
#echo -e "${NORMAL}CCI:       $cci27${NORMAL}"
#echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
#echo -e "${NORMAL}TEST 27:   ${BLD}$title27a${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title27b${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title27c${NORMAL}"
#echo -e "${NORMAL}SEVERITY:  ${BLD}$severity27${NORMAL}"
#
#datetime="$(date +%FT%H:%M:%S)"
#
#
#echo
#echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
#echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
#echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
#echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
#echo -e "${NORMAL}STIG ID:   $stigid28${NORMAL}"
#echo -e "${NORMAL}RULE ID:   $ruleid28${NORMAL}"
#echo -e "${NORMAL}VULN ID:   $vulnid28${NORMAL}"
#echo -e "${NORMAL}CCI:       $cci28${NORMAL}"
#echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
#echo -e "${NORMAL}TEST 28:   ${BLD}$title28a${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title28b${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title28c${NORMAL}"
#echo -e "${NORMAL}SEVERITY:  ${BLD}$severity28${NORMAL}"
#
#datetime="$(date +%FT%H:%M:%S)"
#
#
#echo
#echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
#echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
#echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
#echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
#echo -e "${NORMAL}STIG ID:   $stigid29${NORMAL}"
#echo -e "${NORMAL}RULE ID:   $ruleid29${NORMAL}"
#echo -e "${NORMAL}VULN ID:   $vulnid29${NORMAL}"
#echo -e "${NORMAL}CCI:       $cci29${NORMAL}"
#echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
#echo -e "${NORMAL}TEST 29:   ${BLD}$title29a${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title29b${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title29c${NORMAL}"
#echo -e "${NORMAL}SEVERITY:  ${BLD}$severity29${NORMAL}"
#
#datetime="$(date +%FT%H:%M:%S)"
#
#
#echo
#echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
#echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
#echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
#echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
#echo -e "${NORMAL}STIG ID:   $stigid30${NORMAL}"
#echo -e "${NORMAL}RULE ID:   $ruleid30${NORMAL}"
#echo -e "${NORMAL}VULN ID:   $vulnid30${NORMAL}"
#echo -e "${NORMAL}CCI:       $cci30${NORMAL}"
#echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
#echo -e "${NORMAL}TEST 30:   ${BLD}$title30a${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title30b${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title30c${NORMAL}"
#echo -e "${NORMAL}SEVERITY:  ${BLD}$severity30${NORMAL}"
#
#datetime="$(date +%FT%H:%M:%S)"
#
#
#echo
#echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
#echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
#echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
#echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
#echo -e "${NORMAL}STIG ID:   $stigid31${NORMAL}"
#echo -e "${NORMAL}RULE ID:   $ruleid31${NORMAL}"
#echo -e "${NORMAL}VULN ID:   $vulnid31${NORMAL}"
#echo -e "${NORMAL}CCI:       $cci31${NORMAL}"
#echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
#echo -e "${NORMAL}TEST 31:   ${BLD}$title31a${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title31b${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title31c${NORMAL}"
#echo -e "${NORMAL}SEVERITY:  ${BLD}$severity31${NORMAL}"
#
#datetime="$(date +%FT%H:%M:%S)"
#
#
#echo
#echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
#echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
#echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
#echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
#echo -e "${NORMAL}STIG ID:   $stigid32${NORMAL}"
#echo -e "${NORMAL}RULE ID:   $ruleid32${NORMAL}"
#echo -e "${NORMAL}VULN ID:   $vulnid32${NORMAL}"
#echo -e "${NORMAL}CCI:       $cci32${NORMAL}"
#echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
#echo -e "${NORMAL}TEST 32:   ${BLD}$title32a${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title32b${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title32c${NORMAL}"
#echo -e "${NORMAL}SEVERITY:  ${BLD}$severity32${NORMAL}"
#
#datetime="$(date +%FT%H:%M:%S)"
#
#
#echo
#echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
#echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
#echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
#echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
#echo -e "${NORMAL}STIG ID:   $stigid33${NORMAL}"
#echo -e "${NORMAL}RULE ID:   $ruleid33${NORMAL}"
#echo -e "${NORMAL}VULN ID:   $vulnid33${NORMAL}"
#echo -e "${NORMAL}CCI:       $cci33${NORMAL}"
#echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
#echo -e "${NORMAL}TEST 33:   ${BLD}$title33a${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title33b${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title33c${NORMAL}"
#echo -e "${NORMAL}SEVERITY:  ${BLD}$severity33${NORMAL}"
#
#datetime="$(date +%FT%H:%M:%S)"
#
#
#echo
#echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
#echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
#echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
#echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
#echo -e "${NORMAL}STIG ID:   $stigid34${NORMAL}"
#echo -e "${NORMAL}RULE ID:   $ruleid34${NORMAL}"
#echo -e "${NORMAL}VULN ID:   $vulnid34${NORMAL}"
#echo -e "${NORMAL}CCI:       $cci34${NORMAL}"
#echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
#echo -e "${NORMAL}TEST 34:   ${BLD}$title34a${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title34b${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title34c${NORMAL}"
#echo -e "${NORMAL}SEVERITY:  ${BLD}$severity34${NORMAL}"
#
#datetime="$(date +%FT%H:%M:%S)"
#
#
#echo
#echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
#echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
#echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
#echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
#echo -e "${NORMAL}STIG ID:   $stigid35${NORMAL}"
#echo -e "${NORMAL}RULE ID:   $ruleid35${NORMAL}"
#echo -e "${NORMAL}VULN ID:   $vulnid35${NORMAL}"
#echo -e "${NORMAL}CCI:       $cci35${NORMAL}"
#echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
#echo -e "${NORMAL}TEST 35:   ${BLD}$title35a${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title35b${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title35c${NORMAL}"
#echo -e "${NORMAL}SEVERITY:  ${BLD}$severity35${NORMAL}"
#
#datetime="$(date +%FT%H:%M:%S)"
#
#
#echo
#echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
#echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
#echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
#echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
#echo -e "${NORMAL}STIG ID:   $stigid36${NORMAL}"
#echo -e "${NORMAL}RULE ID:   $ruleid36${NORMAL}"
#echo -e "${NORMAL}VULN ID:   $vulnid36${NORMAL}"
#echo -e "${NORMAL}CCI:       $cci36${NORMAL}"
#echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
#echo -e "${NORMAL}TEST 36:   ${BLD}$title36a${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title36b${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title36c${NORMAL}"
#echo -e "${NORMAL}SEVERITY:  ${BLD}$severity36${NORMAL}"
#
#datetime="$(date +%FT%H:%M:%S)"
#
#
#echo
#echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
#echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
#echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
#echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
#echo -e "${NORMAL}STIG ID:   $stigid37${NORMAL}"
#echo -e "${NORMAL}RULE ID:   $ruleid37${NORMAL}"
#echo -e "${NORMAL}VULN ID:   $vulnid37${NORMAL}"
#echo -e "${NORMAL}CCI:       $cci37${NORMAL}"
#echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
#echo -e "${NORMAL}TEST 37:   ${BLD}$title37a${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title37b${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title37c${NORMAL}"
#echo -e "${NORMAL}SEVERITY:  ${BLD}$severity37${NORMAL}"
#
#datetime="$(date +%FT%H:%M:%S)"
#
#
#echo
#echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
#echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
#echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
#echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
#echo -e "${NORMAL}STIG ID:   $stigid38${NORMAL}"
#echo -e "${NORMAL}RULE ID:   $ruleid38${NORMAL}"
#echo -e "${NORMAL}VULN ID:   $vulnid38${NORMAL}"
#echo -e "${NORMAL}CCI:       $cci38${NORMAL}"
#echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
#echo -e "${NORMAL}TEST 38:   ${BLD}$title38a${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title38b${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title38c${NORMAL}"
#echo -e "${NORMAL}SEVERITY:  ${BLD}$severity38${NORMAL}"
#
#datetime="$(date +%FT%H:%M:%S)"
#
#
#echo
#echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
#echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
#echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
#echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
#echo -e "${NORMAL}STIG ID:   $stigid39${NORMAL}"
#echo -e "${NORMAL}RULE ID:   $ruleid39${NORMAL}"
#echo -e "${NORMAL}VULN ID:   $vulnid39${NORMAL}"
#echo -e "${NORMAL}CCI:       $cci39${NORMAL}"
#echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
#echo -e "${NORMAL}TEST 39:   ${BLD}$title39a${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title39b${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title39c${NORMAL}"
#echo -e "${NORMAL}SEVERITY:  ${BLD}$severity39${NORMAL}"
#
#datetime="$(date +%FT%H:%M:%S)"
#
#
#echo
#echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
#echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
#echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
#echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
#echo -e "${NORMAL}STIG ID:   $stigid40${NORMAL}"
#echo -e "${NORMAL}RULE ID:   $ruleid40${NORMAL}"
#echo -e "${NORMAL}VULN ID:   $vulnid40${NORMAL}"
#echo -e "${NORMAL}CCI:       $cci40${NORMAL}"
#echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
#echo -e "${NORMAL}TEST 40:   ${BLD}$title40a${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title40b${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title40c${NORMAL}"
#echo -e "${NORMAL}SEVERITY:  ${BLD}$severity40${NORMAL}"
#
#datetime="$(date +%FT%H:%M:%S)"
#
#
#echo
#echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
#echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
#echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
#echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
#echo -e "${NORMAL}STIG ID:   $stigid41${NORMAL}"
#echo -e "${NORMAL}RULE ID:   $ruleid41${NORMAL}"
#echo -e "${NORMAL}VULN ID:   $vulnid41${NORMAL}"
#echo -e "${NORMAL}CCI:       $cci41${NORMAL}"
#echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
#echo -e "${NORMAL}TEST 41:   ${BLD}$title41a${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title41b${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title41c${NORMAL}"
#echo -e "${NORMAL}SEVERITY:  ${BLD}$severity41${NORMAL}"
#
#datetime="$(date +%FT%H:%M:%S)"
#
#
#echo
#echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
#echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
#echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
#echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
#echo -e "${NORMAL}STIG ID:   $stigid42${NORMAL}"
#echo -e "${NORMAL}RULE ID:   $ruleid42${NORMAL}"
#echo -e "${NORMAL}VULN ID:   $vulnid42${NORMAL}"
#echo -e "${NORMAL}CCI:       $cci42${NORMAL}"
#echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
#echo -e "${NORMAL}TEST 42:   ${BLD}$title42a${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title42b${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title42c${NORMAL}"
#echo -e "${NORMAL}SEVERITY:  ${BLD}$severity42${NORMAL}"
#
#datetime="$(date +%FT%H:%M:%S)"
#
#
#echo
#echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
#echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
#echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
#echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
#echo -e "${NORMAL}STIG ID:   $stigid43${NORMAL}"
#echo -e "${NORMAL}RULE ID:   $ruleid43${NORMAL}"
#echo -e "${NORMAL}VULN ID:   $vulnid43${NORMAL}"
#echo -e "${NORMAL}CCI:       $cci43${NORMAL}"
#echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
#echo -e "${NORMAL}TEST 43:   ${BLD}$title43a${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title43b${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title43c${NORMAL}"
#echo -e "${NORMAL}SEVERITY:  ${BLD}$severity43${NORMAL}"
#
#datetime="$(date +%FT%H:%M:%S)"
#
#
#echo
#echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
#echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
#echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
#echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
#echo -e "${NORMAL}STIG ID:   $stigid44${NORMAL}"
#echo -e "${NORMAL}RULE ID:   $ruleid44${NORMAL}"
#echo -e "${NORMAL}VULN ID:   $vulnid44${NORMAL}"
#echo -e "${NORMAL}CCI:       $cci44${NORMAL}"
#echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
#echo -e "${NORMAL}TEST 44:   ${BLD}$title44a${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title44b${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title44c${NORMAL}"
#echo -e "${NORMAL}SEVERITY:  ${BLD}$severity44${NORMAL}"
#
#datetime="$(date +%FT%H:%M:%S)"
#
#
#echo
#echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
#echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
#echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
#echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
#echo -e "${NORMAL}STIG ID:   $stigid45${NORMAL}"
#echo -e "${NORMAL}RULE ID:   $ruleid45${NORMAL}"
#echo -e "${NORMAL}VULN ID:   $vulnid45${NORMAL}"
#echo -e "${NORMAL}CCI:       $cci45${NORMAL}"
#echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
#echo -e "${NORMAL}TEST 45:   ${BLD}$title45a${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title45b${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title45c${NORMAL}"
#echo -e "${NORMAL}SEVERITY:  ${BLD}$severity45${NORMAL}"
#
#datetime="$(date +%FT%H:%M:%S)"
#
#
#echo
#echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
#echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
#echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
#echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
#echo -e "${NORMAL}STIG ID:   $stigid46${NORMAL}"
#echo -e "${NORMAL}RULE ID:   $ruleid46${NORMAL}"
#echo -e "${NORMAL}VULN ID:   $vulnid46${NORMAL}"
#echo -e "${NORMAL}CCI:       $cci46${NORMAL}"
#echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
#echo -e "${NORMAL}TEST 46:   ${BLD}$title46a${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title46b${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title46c${NORMAL}"
#echo -e "${NORMAL}SEVERITY:  ${BLD}$severity46${NORMAL}"
#
#datetime="$(date +%FT%H:%M:%S)"
#
#
#echo
#echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
#echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
#echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
#echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
#echo -e "${NORMAL}STIG ID:   $stigid47${NORMAL}"
#echo -e "${NORMAL}RULE ID:   $ruleid47${NORMAL}"
#echo -e "${NORMAL}VULN ID:   $vulnid47${NORMAL}"
#echo -e "${NORMAL}CCI:       $cci47${NORMAL}"
#echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
#echo -e "${NORMAL}TEST 47:   ${BLD}$title47a${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title47b${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title47c${NORMAL}"
#echo -e "${NORMAL}SEVERITY:  ${BLD}$severity47${NORMAL}"
#
#datetime="$(date +%FT%H:%M:%S)"
#
#
#echo
#echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
#echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
#echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
#echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
#echo -e "${NORMAL}STIG ID:   $stigid48${NORMAL}"
#echo -e "${NORMAL}RULE ID:   $ruleid48${NORMAL}"
#echo -e "${NORMAL}VULN ID:   $vulnid48${NORMAL}"
#echo -e "${NORMAL}CCI:       $cci48${NORMAL}"
#echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
#echo -e "${NORMAL}TEST 48:   ${BLD}$title48a${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title48b${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title48c${NORMAL}"
#echo -e "${NORMAL}SEVERITY:  ${BLD}$severity48${NORMAL}"
#
#datetime="$(date +%FT%H:%M:%S)"
#
#
#echo
#echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
#echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
#echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
#echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
#echo -e "${NORMAL}STIG ID:   $stigid49${NORMAL}"
#echo -e "${NORMAL}RULE ID:   $ruleid49${NORMAL}"
#echo -e "${NORMAL}VULN ID:   $vulnid49${NORMAL}"
#echo -e "${NORMAL}CCI:       $cci49${NORMAL}"
#echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
#echo -e "${NORMAL}TEST 49:   ${BLD}$title49a${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title49b${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title49c${NORMAL}"
#echo -e "${NORMAL}SEVERITY:  ${BLD}$severity49${NORMAL}"
#
#datetime="$(date +%FT%H:%M:%S)"
#
#
#echo
#echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
#echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
#echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
#echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
#echo -e "${NORMAL}STIG ID:   $stigid50${NORMAL}"
#echo -e "${NORMAL}RULE ID:   $ruleid50${NORMAL}"
#echo -e "${NORMAL}VULN ID:   $vulnid50${NORMAL}"
#echo -e "${NORMAL}CCI:       $cci50${NORMAL}"
#echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
#echo -e "${NORMAL}TEST 50:   ${BLD}$title50a${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title50b${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title50c${NORMAL}"
#echo -e "${NORMAL}SEVERITY:  ${BLD}$severity50${NORMAL}"
#
#datetime="$(date +%FT%H:%M:%S)"
#
#
#echo
#echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
#echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
#echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
#echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
#echo -e "${NORMAL}STIG ID:   $stigid51${NORMAL}"
#echo -e "${NORMAL}RULE ID:   $ruleid51${NORMAL}"
#echo -e "${NORMAL}VULN ID:   $vulnid51${NORMAL}"
#echo -e "${NORMAL}CCI:       $cci51${NORMAL}"
#echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
#echo -e "${NORMAL}TEST 51:   ${BLD}$title51a${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title51b${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title51c${NORMAL}"
#echo -e "${NORMAL}SEVERITY:  ${BLD}$severity51${NORMAL}"
#
#datetime="$(date +%FT%H:%M:%S)"
#
#
#echo
#echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
#echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
#echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
#echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
#echo -e "${NORMAL}STIG ID:   $stigid52${NORMAL}"
#echo -e "${NORMAL}RULE ID:   $ruleid52${NORMAL}"
#echo -e "${NORMAL}VULN ID:   $vulnid52${NORMAL}"
#echo -e "${NORMAL}CCI:       $cci52${NORMAL}"
#echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
#echo -e "${NORMAL}TEST 52:   ${BLD}$title52a${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title52b${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title52c${NORMAL}"
#echo -e "${NORMAL}SEVERITY:  ${BLD}$severity52${NORMAL}"
#
#datetime="$(date +%FT%H:%M:%S)"
#
#
#echo
#echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
#echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
#echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
#echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
#echo -e "${NORMAL}STIG ID:   $stigid53${NORMAL}"
#echo -e "${NORMAL}RULE ID:   $ruleid53${NORMAL}"
#echo -e "${NORMAL}VULN ID:   $vulnid53${NORMAL}"
#echo -e "${NORMAL}CCI:       $cci53${NORMAL}"
#echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
#echo -e "${NORMAL}TEST 53:   ${BLD}$title53a${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title53b${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title53c${NORMAL}"
#echo -e "${NORMAL}SEVERITY:  ${BLD}$severity53${NORMAL}"
#
#datetime="$(date +%FT%H:%M:%S)"
#
#
#echo
#echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
#echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
#echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
#echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
#echo -e "${NORMAL}STIG ID:   $stigid54${NORMAL}"
#echo -e "${NORMAL}RULE ID:   $ruleid54${NORMAL}"
#echo -e "${NORMAL}VULN ID:   $vulnid54${NORMAL}"
#echo -e "${NORMAL}CCI:       $cci54${NORMAL}"
#echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
#echo -e "${NORMAL}TEST 54:   ${BLD}$title54a${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title54b${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title54c${NORMAL}"
#echo -e "${NORMAL}SEVERITY:  ${BLD}$severity54${NORMAL}"
#
#datetime="$(date +%FT%H:%M:%S)"
#
#
#echo
#echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
#echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
#echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
#echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
#echo -e "${NORMAL}STIG ID:   $stigid55${NORMAL}"
#echo -e "${NORMAL}RULE ID:   $ruleid55${NORMAL}"
#echo -e "${NORMAL}VULN ID:   $vulnid55${NORMAL}"
#echo -e "${NORMAL}CCI:       $cci55${NORMAL}"
#echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
#echo -e "${NORMAL}TEST 55:   ${BLD}$title55a${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title55b${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title55c${NORMAL}"
#echo -e "${NORMAL}SEVERITY:  ${BLD}$severity55${NORMAL}"
#
#datetime="$(date +%FT%H:%M:%S)"





exit
