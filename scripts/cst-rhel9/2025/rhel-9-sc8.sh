#! /bin/bash
RHEL-08-040160
# SC-8 Transmission Confidentiality and Integrity
#
# CONTRHEL-9-v2-r5-SC8.txtROL: The information system protects the [Selection (one or more): confidentiality; integrity]
# of transmitted information.

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

controlid="SC-8 Transmission Confidentiality and Integrity"

title1a="All RHEL 9 networked systems must have and implement SSH to protect the confidentiality and integrity of transmitted and received information, as well as information during preparation for transmission."
title1b="Checking with 'systemctl is-active sshd."
title1c="Expecting: ${YLO}active
           NOTE: If the \"sshd\" service is not \"active\", this is a finding."${BLD}
cci1="CCI-002418 CCI-002420 CCI-002421 CCI-002422"
stigid1="RHEL-09-255015"
severity1="CAT II"
ruleid1="SV-257979r958908"
vulnid1="V-257979"

title2a="RHEL 9 wireless network adapters must be disabled."
title2b="Checking with: nmcli device status"
title2c="Expecting: ${YLO}Nothing returned
           NOTE: If a wireless interface is configured and has not been documented and approved by the information system security officer (ISSO), this is a finding."${BLD}
cci2="CCI-001443 CCI-001444 CCI-002418 CCI-002421"
stigid2="RHEL-09-291040"
severity2="CAT II"
ruleid2="SV-258040r991568"
vulnid2="V-258040"

title3a="RHEL 9 must enable FIPS mode."
title3b="Checking with: fips-mode-setup --check"
title3c="Expecting: ${YLO}FIPS mode is enabled
           NOTE: If FIPS mode is not enabled, this is a finding."${BLD}
cci3="CCI-000068 CCI-000877 CCI-002418 CCI-002450"
stigid3="RHEL-09-671010"
severity3="CAT I"
ruleid3="SV-258230r958408"
vulnid3="V-258230"

title4a="RHEL 9 must implement DOD-approved encryption in the bind package."
title4b="Checking with: grep include /etc/named.conf"
title4c="Expecting: ${YLO}include \"/etc/crypto-policies/back-ends/bind.config\";'
           NOTE: Note: If the \"bind\" package is not installed, this requirement is Not Applicable.
           NOTE: If BIND is installed and the BIND config file doesn't contain the  include \"/etc/crypto-policies/back-ends/bind.config\" directive, or the line is commented out, this is a finding."${BLD}
cci4="CCI-002418 CCI-002422"
stigid4="RHEL-09-672050"
severity4="CAT II"
ruleid4="SV-258242r958908"
vulnid4="V-258242"

title5a="All RHEL 9 networked systems must have SSH installed."
title5b="Checking with 'yum list installed openssh-server"
title5c="Expecting:${YLO}openssh-server.x86_64                 8.0p1-5.el8          @anaconda
           NOTE: If the \"SSH server\" package is not installed, this is a finding."${BLD}
cci5="CCI-002418 CCI-002420 CCI-002421 CCI-002422"
stigid5="RHEL-09-255010"
severity5="CAT II"
ruleid5="SV-257978r1045013"
vulnid5="V-257978"

title6a="RHEL 9 must force a frequent session key renegotiation for SSH connections to the server."
title6b="Checking with: /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print \$4}' | tr -d '\\\\r' | tr '\\\\n' ' ' | xargs grep -iH '^\s*rekeylimit'"
title6c="Expecting: ${YLO}RekeyLimit 1G 1h
           NOTE: If \"RekeyLimit\" does not have a maximum data amount and maximum time defined, is missing, or is commented out, this is a finding."${BLD}
cci6="CCI-000068 CCI-002418 CCI-002421"
stigid6="RHEL-09-255090"
severity6="CAT II"
ruleid6="SV-257994r1045051"
vulnid6="V-257994"

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

fail=0

datetime="$(date +%FT%H:%M:%S)"

sshdstat="$(systemctl is-active sshd)"
if [[ $sshdstat ]]
then
  if [[ $sshdstat = 'active' ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$sshdstat${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$sshdstat${NORMAL}"
  fi
fi
if (( $fail == 0 ))
then
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, The RHEL 9 sshd service is active.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, The RHEL 9 sshd service is not active.${NORMAL}"
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

echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${CYN}VERIFY, (See AC-18 Wireless Access: V-258040)${NORMAL}"

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

echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${CYN}VERIFY, (See AC-17 Remote Access: V-258230)${NORMAL}"

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

file4a="/etc/named.conf"
file4b="/etc/crypto-policies/back-ends/bind.config"

isinstalled="$(dnf list --installed 2>/dev/null bind | grep -Ev 'Updating|Installed')"

if [[ $isinstalled ]]
then
  if [[ -f $file4a ]]
  then
    include="$(grep include /etc/named.conf)"
    if [[ $include ]]
    then
      if [[ -f $file4 ]]
      then
        fail=0
        echo -e "${NORMAL}RESULT:    ${BLD}$include${NORMAL}"
      else
        echo -e "${NORMAL}RESULT:    ${RED}$file4b not found${NORMAL}"
      fi
    else
      echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}$file4a not found${NORMAL}"
  fi
else
  fail=2
  echo -e "${NORMAL}RESULT:    ${BLD}The \"bind\" package is not installed${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${GRN}PASSED, RHEL 9 implements DOD-approved encryption in the bind package.${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${GRN}N/A, The RHEL 9 \"bind\" package is not installed. This requirement is Not Applicable.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${RED}FAILED, RHEL 9 does not implement DOD-approved encryption in the bind package.${NORMAL}"
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

isinstalled="$(yum list installed openssh-server | grep openssh-server)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $isinstalled ]]
then
  echo -e "${NORMAL}RESULT:    ${BLD}$isinstalled${NORMAL}"
  fail=0
else
  echo -e "${NORMAL}RESULT:    ${RED}The \"openssh-server\" package is not installed${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${GRN}PASSED, SSH is installed${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${RED}FAILED, SSH is not installed.${NORMAL}"
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

limit="$(/usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs grep -iH '^\s*rekeylimit')"

if [[ $limit ]]
then
  file="$(echo $limit | awk -F: '{print $1}')"
  setting="$(echo $limit | awk -F: '{print $2}')"
  maxdata="$(echo $limit | awk '{print $2}')"
  maxtime="$(echo $limit | awk '{print $3}')"
  if [[ $maxdata && $maxtime ]]
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
  echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${GRN}PASSED, RHEL 9 forces a frequent session key renegotiation for SSH connections to the server.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${RED}FAILED, RHEL 9 does not force a frequent session key renegotiation for SSH connections to the server.${NORMAL}"
fi


exit
