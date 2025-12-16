#! /bin/bash

# IA-2 Identification and Authentication (Organizational Users)

# CONTROL: The information system uniquely identifies and authenticates organizational users
# (or processes acting on behalf of organizational users).

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

controlid="IA-2 Identification and Authentication (Organizational Users)"

title1a="RHEL 9 duplicate User IDs (UIDs) must not exist for interactive users."
title1b="Checking with: awk -F \":\" 'list[\$3]++{print \$1, \$3}' /etc/passwd"
title1c="Expecting: ${YLO}Nothing returned
           NOTE: If output is produced and the accounts listed are interactive user accounts, this is a finding."${BLD}
cci1="CCI-000135 CCI-000764 CCI-000804"
stigid1="RHEL-09-411030"
severity1="CAT II"
ruleid1="SV-258045r958482"
vulnid1="V-258045"

title2a="RHEL 9 groups must have unique Group ID (GID)."
title2b="Checking with: cut -d : -f 3 /etc/group | uniq -d"
title2c="Expecting: ${YLO}Nothing returned
           NOTE: If the system has duplicate GIDs, this is a finding."${BLD}
cci2="CCI-000764"
stigid2="RHEL-09-411110"
severity2="CAT II"
ruleid2="SV-258061r958482"
vulnid2="V-258061"

title3a="RHEL 9 must have the openssl-pkcs11 package installed."
title3b="Checking with: dnf list --installed openssl-pkcs11"
title3c="Expecting: ${YLO}
           openssl-pkcs.i686          0.4.11-7.el9
           openssl-pkcs.x86_64          0.4.11-7.el9
           NOTE: If the \"openssl-pkcs11\" package is not installed, this is a finding."${BLD}
cci3="CCI-000765 CCI-004046 CCI-001953 CCI-001954 CCI-001948"
stigid3="RHEL-09-215075"
severity3="CAT II"
ruleid3="SV-257838r1044912"
vulnid3="V-257838"

title4a="RHEL 9 SSHD must accept public key authentication."
title4b="Checking with: /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print \$4}' | tr -d '\\\\r' | tr '\\\\n' ' ' | xargs grep -iH '^\s*pubkeyauthentication'"
title4c="Expecting: ${YLO}PubkeyAuthentication yes
           NOTE: If \"PubkeyAuthentication\" is set to no, the line is commented out, or the line is missing, this is a finding."${BLD}
cci4="CCI-000765 CCI-000766 CCI-000767 CCI-000768"
stigid4="RHEL-09-255035"
severity4="CAT II"
ruleid4="SV-257983r1045024"
vulnid4="V-257983"

title5a="RHEL 9 SSHD must not allow blank passwords."
title5b="Checking with: /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print \$4}' | tr -d '\\\\r' | tr '\\\\n' ' ' | xargs grep -iH '^\s*permitemptypasswords'"
title5c="Expecting: ${YLO}PermitEmptyPasswords no
           NOTE: If the \PermitEmptyPasswords\ keyword is set to \yes\, is missing, or is commented out, this is a finding."${BLD}
cci5="CCI-000766"
stigid5="RHEL-09-255040"
severity5="CAT I"
ruleid5="SV-257984r1045026"
vulnid5="V-257984"

title6a="RHEL 9 must not permit direct logons to the root account using remote access via SSH."
title6b="Checking with: /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print \$4}' | tr -d '\\\\r' | tr '\\\\n' ' ' | xargs grep -iH '^\s*permitrootlogin'"
title6c="Expecting: ${YLO}PermitRootLogin no
           NOTE: If the \"PermitRootLogin\" keyword is set to any value other than \"no\", is missing, or is commented out, this is a finding."${BLD}
cci6="CCI-004045 CCI-000770"
stigid6="RHEL-09-255045"
severity6="CAT II"
ruleid6="SV-257985r1069364"
vulnid6="V-257985"

title7a="All RHEL 9 interactive users must have a primary group that exists."
title7b="Checking with: pwck -r"
title7c="Expecting: ${YLO}Nothing returned
           NOTE: If pwck reports \"no group\" for any interactive user, this is a finding."${BLD}
cci7="CCI-000764"
stigid7="RHEL-09-411045"
severity7="CAT II"
ruleid7="SV-258048r1069380"
vulnid7="V-258048"

title8a="RHEL 9 must use the common access card (CAC) smart card driver."
title8b="Checking with: opensc-tool --get-conf-entry app:default:card_drivers cac"
title8c="Expecting: ${YLO}cac
           NOTE: If \"cac\" is not listed as a card driver, or no line is returned for \"card_drivers\", this is a finding."${BLD}
cci8="CCI-000764 CCI-000766 CCI-000765 CCI-004045 CCI-001941 CCI-000767 CCI-000768 CCI-000770 CCI-001942"
stigid8="RHEL-09-611160"
severity8="CAT II"
ruleid8="SV-258121r1102086"
vulnid8="V-258121"

title9a="RHEL 9 must enable certificate based smart card authentication."
title9b="Checking with: grep -ir pam_cert_auth /etc/sssd/sssd.conf /etc/sssd/conf.d/"
title9c="Expecting: ${YLO}pam_cert_auth = True
           NOTE: If \"pam_cert_auth\" is not set to \"True\", the line is commented out, or the line is missing, this is a finding."${BLD}
cci9="CCI-000765 CCI-004046 CCI-004047 CCI-001948"
stigid9="RHEL-09-611165"
severity9="CAT II"
ruleid9="SV-258122r1045246"
vulnid9="V-258122"

title10a="RHEL 9 must implement certificate status checking for multifactor authentication."
title10b="Checking with: grep -ir certificate_verification /etc/sssd/sssd.conf /etc/sssd/conf.d/ | grep -v \"^#\""
title10c="Expecting: ${YLO}certificate_verification = ocsp_dgst=sha512
           NOTE: If the certificate_verification line is missing from the [sssd] section, or is missing \"ocsp_dgst=sha512\", ask the administrator to indicate what type of multifactor authentication is being used and how the system implements certificate status checking.
	   NOTE: If there is no evidence of certificate status checking being used, this is a finding."${BLD}
cci10="CCI-004046 CCI-001954 CCI-001948"
stigid10="RHEL-09-611170"
severity10="CAT II"
ruleid10="SV-258123r1045248"
vulnid10="V-258123"

title11a="RHEL 9 must have the pcsc-lite package installed."
title11b="Checking with: dnf list --installed pcsc-lite"
title11c="Expecting: ${YLO}pcsc-lite.x86_64          1.9.4-1.el9
           NOTE: If the \"pcsc-lite\" package is not installed, this is a finding."${BLD}
cci11="CCI-004046 CCI-001948"
stigid11="RHEL-09-611175"
severity11="CAT II"
ruleid11="SV-258124r1045250"
vulnid11="V-258124"

title12a="The pcscd service on RHEL 9 must be active."
title12b="Checking with: systemctl is-active pcscd.socket"
title12c="Expecting: ${YLO}active
           NOTE: If the pcscd socket is not active, this is a finding."
cci12="CCI-004046 CCI-001948"
stigid12="RHEL-09-611180"
severity12="CAT II"
ruleid12="SV-258125r1045253"
vulnid12="V-258125"

title13a="RHEL 9 must have the opensc package installed."
title13b="Checking with: dnf list --installed opensc"
title13c="Expecting: ${YLO}opensc.x86_64          0.22.0-2.el9
           NOTE: If the \"opensc\" package is not installed, this is a finding."${BLD}
cci13="CCI-004046 CCI-001953 CCI-001948"
stigid13="RHEL-09-611185"
severity13="CAT II"
ruleid13="SV-258126r1045255"
vulnid13="V-258126"

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

dupeid="$(awk -F ":" 'list[$3]++{print $1, $3}' /etc/passwd)"

if [[ $dupeid ]]
then
  fail=1
  for line in ${dupeid[@]}
  do
    echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
  done
else
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, RHEL 9 duplicate User IDs (UIDs) do not exist for interactive users.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, RHEL 9 duplicate User IDs (UIDs) exist for interactive users..${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

dupgid="$(cut -d : -f 3 /etc/group | uniq -d)"

if [[ $dupgid ]]
then
  fail=1
  for line in ${dupgid[@]}
  do
    echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
  done
else
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, RHEL 9 contains no duplicate Group IDs (GIDs).${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, RHEL 9 contains duplicate Group IDs (GIDs).${NORMAL}"
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

isinstalled="$(dnf list --installed 2>/dev/null openssl-pkcs11 | grep -Ev 'Updating|Installed')"

if [[ $isinstalled ]]
then
  fail=0
  for line in ${isinstalled[@]}
  do
    echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${GRN}PASSED, RHEL 9 has the openssl-pkcs11 package installed.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${RED}FAILED, RHEL 9 does not have the openssl-pkcs11 package installed.${NORMAL}"
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

pubkey="$(/usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs grep -iH '^\s*pubkeyauthentication')"

if [[ $pubkey ]]
then
  for line in ${pubkey[@]}
  do
    file="$(echo $line | awk -F: '{print $1}')"
    setting="$(echo $line | awk -F: '{print $2}')"
    value="$(echo $setting | awk '{print $2}' | sed 's/ //')"
    if [[ $value == "yes" ]]
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
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${GRN}PASSED, RHEL 9 SSHD accepts public key authentication.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${RED}FAILED, RHEL 9 does not accept public key authentication.${NORMAL}"
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

blankpw="$(/usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs grep -iH '^\s*permitemptypasswords')"

if [[ $blankpw ]]
then
  for line in ${blankpw[@]}
  do
    file="$(echo $line | awk -F: '{print $1}')"
    setting="$(echo $line | awk -F: '{print $2}')"
    value="$(echo $setting | awk '{print $2}' | sed 's/ //')"
    if [[ $value == "no" ]]
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
  echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${GRN}PASSED, RHEL 9 SSHD does not allow blank passwords.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${RED}FAILED, RHEL 9 SSHD allows blank passwords.${NORMAL}"
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

direct="$(/usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs grep -iH '^\s*permitrootlogin')"

if [[ $direct ]]
then
  for line in ${direct[@]}
  do
    file="$(echo $line | awk -F: '{print $1}')"
    setting="$(echo $line | awk -F: '{print $2}')"
    value="$(echo $setting | awk '{print $2}' | sed 's/ //')"
    if [[ $value == "no" ]]
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
  echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${GRN}PASSED, RHEL 9 does not permit direct logons to the root account using remote access via SSH.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${RED}FAILED, RHEL 9 permits direct logons to the root account using remote access via SSH.${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

gidinvalid="$(pwck -r)"

if [[ $gidinvalid ]]
then
  fail=1
  for line in ${gidinvalid[@]}
  do
    if [[ ${line:0:1} != "#" ]]
    then
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    $line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${GRN}PASSED, All RHEL 9 interactive users have a primary group that exists.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${RED}FAILED, All RHEL 9 interactive users do not have a primary group that exists.${NORMAL}"
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

cmd="$(if command -v opensc-tool &> /dev/null; then echo "exists";else echo "missing"; fi)"
if [[ $cmd == "exists" ]]
then
  usecac="$(opensc-tool --get-conf-entry 2>&1 app:default:card_drivers cac)"
  if [[ $usecac == "cac" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$usecac${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$usecac${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}The \"opensc-tool\" command is $usecac.${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cci8, $datetime, ${GRN}PASSED, RHEL 9 uses the common access card (CAC) smart card driver.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cci8, $datetime, ${RED}FAILED, RHEL 9 does not use the common access card (CAC) smart card driver.${NORMAL}"
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

certauth="$(grep -ir pam_cert_auth /etc/sssd/sssd.conf /etc/sssd/conf.d/)"

if [[ $certauth ]]
then
  for line in ${certauth[@]}
  do
    file="$(echo $line | awk -F: '{print $1}')"
    setting="$(echo $line | awk -F: '{print $2}')"
    value="$(echo $setting | awk -F= '{print tolower($2)}' | sed 's/ //')"
    if [[ $value == "true" ]]
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
  echo -e "${NORMAL}$hostname, $severity9, $controlid, $stigid9, $ruleid9, $cci9, $datetime, ${GRN}PASSED, RHEL 9 does not permit direct logons to the root account using remote access via SSH.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity9, $controlid, $stigid9, $ruleid9, $cci9, $datetime, ${RED}FAILED, RHEL 9 permits direct logons to the root account using remote access via SSH.${NORMAL}"
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

certstat="$(grep -ir certificate_verification /etc/sssd/sssd.conf /etc/sssd/conf.d/ | grep -v "^#")"

if [[ $certstat ]]
then
  for line in ${certstat[@]}
  do
    file="$(echo $line | awk -F: '{print $1}')"
    setting="$(echo $line | awk -F: '{print $2}')"
    value="$(echo $setting | awk -F 'certificate_verification=' '{print $2}' | sed 's/ //')"
    if [[ $value == "ocsp_dgst=sha512" ]]
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
  echo -e "${NORMAL}$hostname, $severity10, $controlid, $stigid10, $ruleid10, $cci10, $datetime, ${GRN}PASSED, RHEL 9 implements certificate status checking for multifactor authentication.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity10, $controlid, $stigid10, $ruleid10, $cci10, $datetime, ${RED}FAILED, RHEL 9 does not implement certificate status checking for multifactor authentication.${NORMAL}"
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
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity1${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

isinstalled="$(dnf list --installed 2>&1 pcsc-lite | grep -Ev 'Updating|Installed')"

if [[ $isinstalled ]]
then
  fail=0
  echo -e "${NORMAL}RESULT:    ${BLD}$isinstalled${NORMAL}"
else
  echo -e "${NORMAL}RESULT:    ${BLD}$isinstalled${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity11, $controlid, $stigid11, $ruleid11, $cci11, $datetime, ${GRN}PASSED, RHEL 9 has the pcsc-lite package installed.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity11, $controlid, $stigid11, $ruleid11, $cci11, $datetime, ${RED}FAILED, RHEL 9 does not have the pcsc-lite package installed.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid12${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid12${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid12${NORMAL}"
echo -e "${NORMAL}CCI:       $cci12${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 12:   ${BLD}$title12a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title12b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title12c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity12${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

isactive="$(systemctl is-active pcscd.socket)"

if [[ $isactive ]]
then
  if [[ $isactive == "active" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$isactive${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$isactive${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity12, $controlid, $stigid12, $ruleid12, $cci12, $datetime, ${GRN}PASSED, The pcscd service on RHEL 9 is active.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity12, $controlid, $stigid12, $ruleid12, $cci12, $datetime, ${RED}FAILED, The pcscd service on RHEL 9 is not active.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid13${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid13${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid13${NORMAL}"
echo -e "${NORMAL}CCI:       $cci13${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 13:   ${BLD}$title13a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title13b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title13c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity3${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

isinstalled="$(dnf list --installed 2>&1 opensc | grep -Ev 'Updating|Installed')"

if [[ $isinstalled ]]
then
  fail=0
  echo -e "${NORMAL}RESULT:    ${BLD}$isinstalled${NORMAL}"
else
  echo -e "${NORMAL}RESULT:    ${BLD}$isinstalled${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity13, $controlid, $stigid13, $ruleid13, $cci13, $datetime, ${GRN}PASSED, RHEL 9 has the opensc package installed.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity13, $controlid, $stigid13, $ruleid13, $cci13, $datetime, ${RED}FAILED, RHEL 9 does not have the opensc package installed.${NORMAL}"
fi

exit

