#! /bin/bash

# SC-13 Cryptographic Protection
#
# CONTROL: 
# a. Determine the [Assignment: organization-defined cryptographic uses]; and
# b. Implement the following types of cryptography required for each specified cryptographic use:
#    [Assignment: organization-defined types of cryptography for each specified cryptographic use].

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

controlid="SC-13 Cryptographic Protection"

title1a="RHEL 9 must enable FIPS mode."
title1b="Checking with: fips-mode-setup --check"
title1c="Expecting: ${YLO}FIPS mode is enabled.
           NOTE: If FIPS mode is not enabled, this is a finding."${BLD}
cci1="CCI-000068 CCI-000877 CCI-002418 CCI-002450"
stigid1="RHEL-09-671010"
severity1="CAT I"
ruleid1="SV-258230r958408"
vulnid1="V-258230"

title2a="RHEL 9 must have the crypto-policies package installed."
title2b="Checking with: dnf list --installed crypto-policie"
title2c="Expecting: ${YLO}crypto-policies.noarch          20240828-2.git626aa59.el9_5
           NOTE: If the crypto-policies package is not installed, this is a finding."${BLD}
cci2="CCI-002450 CCI-002890 CCI-003123"
stigid2="RHEL-09-215100"
severity2="CAT II"
ruleid2="SV-258234r1051250"
vulnid2="V-258234"

title3a="RHEL 9 cryptographic policy must not be overridden."
title3b="Checking with:
           a. update-crypto-policies --check
	   b. ls -l /etc/crypto-policies/back-ends/"
title3c="Expecting: ${YLO}
           a. The configured policy matches the generated policy
	   b. lrwxrwxrwx. 1 root root  40 Nov 13 16:29 bind.config -> /usr/share/crypto-policies/FIPS/bind.txt
           ...
           ...
           ...
           b. lrwxrwxrwx. 1 root root  48 Nov 13 16:29 openssl_fips.config -> /usr/share/crypto-policies/FIPS/openssl_fips.txt
	   NOTE: a. If the returned message does not match the above, but instead matches the following, this is a finding.
	   NOTE: b. If the paths do not point to the respective files under /usr/share/crypto-policies/FIPS path, this is a finding.
	   NOTE: nss.config should not be symlinked."${BLD}
cci3="CCI-002450 CCI-002890 CCI-003123"
stigid3="RHEL-09-672020"
severity3="CAT I"
ruleid3="SV-258236r1101920"
vulnid3="V-258236"

title4a="RHEL 9 must implement a FIPS 140-3-compliant systemwide cryptographic policy."
title4b="Checking with: update-crypto-policies --show"
title4c="Expecting: ${YLO}FIPS
           NOTE: If the systemwide crypto policy is not set to \"FIPS\", this is a finding."${BLD}
cci4="CCI-002450 CCI-002890 CCI-003123"
stigid4="RHEL-09-215105"
severity4="CAT II"
ruleid4="SV-258241r1106302"
vulnid4="V-258241"

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

echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${CYN}VERIFY, (See AC-17 Remote Access: V-258230)${NORMAL}"

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

policies="$(dnf list --installed 2>/dev/null crypto-policies | grep -Ev 'Updating|Installed')"

if [[ $policies ]]
then
  fail=0
  echo -e "${NORMAL}RESULT:    ${BLD}$policies${NORMAL}"
else
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, RHEL 9 has the crypto-policies package installed.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, RHEL 9 does not have the crypto-policies package installed.${NORMAL}"
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

check="$(update-crypto-policies --check)"

if [[ $check ]]
then
  if [[ $check =~ "matches" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}a. $check\n           b. (skipping)${NORMAL}"
  else
    backends="$(ls -l /etc/crypto-policies/back-ends/)"
    if [[ $backends ]]
    then
      for line in ${backends[@]}
      do
	config="$(echo $line | awk -F "->" '{print $1}')"
        txt="$(echo $line | awk =F "->" '{print $2}')"
	if ! [[ $txt =~ "/usr/share/crypto-policies/FIPS/" ]]
	then
	  fail=1
	  echo -e "${NORMAL}RESULT:    ${CYN}b. $config -> ${RED}$txt${NORMAL}"
	else
	  echo -e "${NORMAL}RESULT:    ${CYN}b. $config -> ${BLD}$txt${NORMAL}"
	fi
      done
    else
      echo -e "${NORMAL}RESULT:    ${RED}b. Nothing returned${NORMAL}"
    fi
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}a. Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${GRN}PASSED, RHEL 9 cryptographic policies are not overridden.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${GRN}PASSED, RHEL 9 cryptographic policies are overridden.${NORMAL}"
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

policy="$(update-crypto-policies --show)"

if [[ $policy ]]
then
  if [[ $policy == "FIPS" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$policy${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$policy${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${GRN}PASSED, RHEL 9 implements a FIPS 140-3-compliant systemwide cryptographic policy.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${GRN}PASSED, RHEL 9 does not implement a FIPS 140-3-compliant systemwide cryptographic policy.${NORMAL}"
fi

exit
