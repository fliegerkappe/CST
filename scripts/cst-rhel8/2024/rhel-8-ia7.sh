#! /bin/bash

# IA-7 Cryptographic Module Authentication
#
# CONTROL: The organization manages information system identifiers by:
# Implement mechanisms for authentication to a cryptographic module that meet
# the requirements of applicable laws, executive orders, directives, policies,
# regulations, standards, and guidelines for such authentication.

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

stig="Red Hat Enterprise Linux 8 Security Technical Implementation Guide :: Version 1, Release: 13 Benchmark Date: 24 Jan 2024"

hostname="$(uname -n)"

if [[ -f /etc/redhat-release ]]
then
   os="$(cat /etc/redhat-release)"
else
   os="OS not defined"
fi

prog="$(basename $0)"

controlid="IA-7 Cryptographic Module Authentication"

title1a="The RHEL 8 pam_unix.so module must be configured in the password-auth file to use a FIPS 140-2 approved cryptographic hashing algorithm for system authentication."
title1b="Checking with 'grep password /etc/pam.d/password-auth | grep pam_unix'."
title1c="Expecting: ${YLO}password sufficient pam_unix.so sha512
           NOTE: If \"sha512\" is missing, or is commented out, this is a finding."${BLD}
cci1="CCI-000803"
stigid1="RHEL-08-010160"
severity1="CAT II"
ruleid1="SV-230237r809276_rule"
vulnid1="V-230237"

title2a="RHEL 8 must prevent system daemons from using Kerberos for authentication."
title2b="Checking with 'ls -al /etc/*.keytab'."
title2c="Expecting: ${YLO}Nothing returned
           NOTE: If this command produces any file(s), this is a finding."${BLD}
cci2="CCI-000803"
stigid2="RHEL-08-010161"
severity2="CAT II"
ruleid2="SV-230238r646862_rule"
vulnid2="V-230238"

title3a="The krb5-workstation package must not be installed on RHEL 8."
title3b="Checking with 'yum list installed krb5-workstation'."
title3c="Expecting: ${YLO}Nothing returned
           NOTE: If the krb5-workstation package is installed and is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding."${BLD}
cci3="CCI-000803"
stigid3="RHEL-08-010162"
severity3="CAT II"
ruleid3="SV-230239r646864_rule"
vulnid3="V-230239"

title4a="The krb5-server package must not be installed on RHEL 8."
title4b="Checking with 'yum list installed krb5-server'."
title4c="Expecting: ${YLO}Nothing returned
           NOTE: If the krb5-server package is installed and is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding."${BLD}
cci4="CCI-000803"
stigid4="RHEL-08-010163"
severity4="CAT II"
ruleid4="SV-237640r646890_rule"
vulnid4="V-237640"

title5a="The RHEL 8 pam_unix.so module must be configured in the system-auth file to use a FIPS 140-2 approved cryptographic hashing algorithm for system authentication."
title5b="Checking with 'grep password /etc/pam.d/system-auth | grep pam_unix'."
title5c="Expecting: ${YLO}password sufficient pam_unix.so sha512
           NOTE: If \"sha512\" is missing, or is commented out, this is a finding.."
cci5="CCI-000803"
stigid5="RHEL-08-010159"
severity5="CAT II"
ruleid5="SV-244524r809331_rule"
vulnid5="V-244524"

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

file1="/etc/pam.d/password-auth"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file1 ]]
then
  pwcrypt="$(grep password $file1 | grep pam_unix)"
  if [[ $pwcrypt ]]
  then
    if [[ $pwcrypt =~ 'sufficient' && $pwcrypt =~ 'sha512' ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$pwcrypt${NORMAL}"
      fail=0
    else
      echo -e "${NORMAL}RESULT:    ${RED}$pwcrypt${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}\"password\" was not defined in $file1${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file1 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, The RHEL 8 pam_unix.so module is configured in the password-auth file to use a FIPS 140-2 approved cryptographic hashing algorithm for system authentication.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, The RHEL 8 pam_unix.so module is not configured in the password-auth file to use a FIPS 140-2 approved cryptographic hashing algorithm for system authentication.${NORMAL}"
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

file2="$(ls -latr /etc | grep *.keytab)"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file2 ]]
then
  for line in ${file2[@]}
  do
    echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
  done
else
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
  fail=0
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, RHEL 8 prevents system daemons from using Kerberos for authentication.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, RHEL 8 does not prevent system daemons from using Kerberos for authentication.${NORMAL}"
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

krbwkstn="$(yum list installed krb5-workstation 2>/dev/null | grep krb5-workstation)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $krbwkstn ]]
then
  echo -e "${NORMAL}RESULT:    ${RED}$krbwkstn${NORMAL}"
else
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
  fail=0
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${GRN}PASSED, The krb5-workstation package is not installed on RHEL 8.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${RED}FAILED, The krb5-workstation package is installed on RHEL 8.${NORMAL}"
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

krbsrv="$(yum list installed krb5-server 2>/dev/null | grep krb5-server)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $krbsrv ]]
then
  echo -e "${NORMAL}RESULT:    ${RED}$krbsrv${NORMAL}"
else
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
  fail=0
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${GRN}PASSED, The krb5-server package is not installed on RHEL 8.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${RED}FAILED, The krb5-server package is installed on RHEL 8.${NORMAL}"
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

file5="/etc/pam.d/system-auth"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file5 ]]
then
  pwcrypt="$(grep password $file5 | grep pam_unix)"
  if [[ $pwcrypt ]]
  then
    if [[ $pwcrypt =~ 'sufficient' && $pwcrypt =~ 'sha512' ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$pwcrypt${NORMAL}"
      fail=0
    else
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}\"password\" was not defined in $file5${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file5 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${GRN}PASSED, The RHEL 8 pam_unix.so module is configured in the system-auth file to use a FIPS 140-2 approved cryptographic hashing algorithm for system authentication.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${RED}FAILED, The RHEL 8 pam_unix.so module is not configured in the system-auth file to use a FIPS 140-2 approved cryptographic hashing algorithm for system authentication.${NORMAL}"
fi

exit

