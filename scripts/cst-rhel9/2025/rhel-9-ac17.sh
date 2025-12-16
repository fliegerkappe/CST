#! /bin/bash

# AC-17 Remote Access
#
# CONTROL: The organization:
# a. Establishes and documents usage restrictions, configuration/connection requirements,
#    and implementation guidance for each type of remote access allowed; and
# b. Authorizes remote access to the information system prior to allowing such connections.

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

controlid="AC-17 Remote Access"

title1a="RHEL 9 must enable FIPS mode."
title1b="Checking with: 'fips-mode-setup --check'."
title1c="Expecting: ${YLO}FIPS mode is enabled
           NOTE: If FIPS mode is not enabled, this is a finding."${BLD}
cci1="CCI-000068 CCI-000877 CCI-002418"
stigid1="RHEL-09-671010"
severity1="CAT I"
ruleid1="SV-258230r958408"
vulnid1="V-258230"

title2a="RHEL 9 must have the firewalld package installed."
title2b="Checking with: 'dnf list --installed firewall'."
title2c="Expecting: ${YLO}(example) firewalld.noarch          1.0.0-4.el9
           NOTE: If the \"firewall\" package is not installed, this is a finding."${BLD}
cci2="CCI-000382 CCI-002314 CCI-002322"
stigid2="RHEL-09-251010"
severity2="CAT II"
ruleid2="SV-257935r1044994"
vulnid2="V-257935"

title3a="The firewalld service on RHEL 9 must be active."
title3b="Checking with: 'systemctl is-active firewalld'."
title3c="Expecting: ${YLO}active
           If the firewalld service is not active, this is a finding."${BLD}
cci3="CCI-000382 CCI-002314"
stigid3="RHEL-09-251015"
severity3="CAT II"
ruleid3="SV-257936r1044995"
vulnid3="V-257936"

title4a="RHEL 9 must log SSH connection attempts and failures to the server."
title4b="Checking with: /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print \$4}' | tr -d '\\\\r' | tr '\\\\n' ' ' | grep -iH '^\s*loglevel'."
title4c="Expecting: ${YLO}LogLevel VERBOSE
           NOTE: If a value of \"VERBOSE\" is not returned or the line is commented out or missing, this is a finding."${BLD}
cci4="CCI-000067"
stigid4="RHEL-09-255030"
severity4="CAT II"
ruleid4="SV-257982r1045021"
vulnid4="V-257982"

title5a="The RHEL 9 SSH server must be configured to use only DOD-approved encryption ciphers employing FIPS 140-3 validated cryptographic hash algorithms to protect the confidentiality of SSH server connections."
title5b="Checking with: 'grep -i Ciphers /etc/crypto-policies/back-ends/opensshserver.config'."
title5c="Expecting: ${YLO}Ciphers aes256-gcm@openssh.com,aes256-ctr,aes128-gcm@openssh.com,aes128-ctr
           NOTE: If the cipher entries in the \"opensshserver.config\" file have any ciphers other than \"aes256-gcm@openssh.com,aes256-ctr,aes128-gcm@openssh.com,aes128-ctr\", or they are missing or commented out, this is a finding."${BLD}
cci5="CCI-001453"
stigid5="RHEL-09-255065"
severity5="CAT II"
ruleid5="SV-257989r1051240"
vulnid5="V-257989"

title6a="The RHEL 9 SSH server must be configured to use only Message Authentication Codes (MACs) employing FIPS 140-3 validated cryptographic hash algorithms to protect the confidentiality of SSH server connections."
title6b="Checking with: 'grep -i MACs /etc/crypto-policies/back-ends/opensshserver.config'."
title6c="Expecting: ${YLO}MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512
           NOTE: If the MACs entries in the \"opensshserver.config\" file have any hashes other than \"hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512\", or they are missing or commented out, this is a finding."${BLD}
cci6="CCI-001453"
stigid6="RHEL-09-255075"
severity6="CAT II"
ruleid6="SV-257991r1051246"
vulnid6="V-257991"

title7a="RHEL 9 must force a frequent session key renegotiation for SSH connections to the server."
title7b="Checking with: '/usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print \$4}' | tr -d '\\\\r' | tr '\\\\n' ' ' | grep -iH '^\s*rekeylimit'"
title7c="Expecting: ${YLO}RekeyLimit 1G 1h
           NOTE: If \"RekeyLimit\" does not have a maximum data amount and maximum time defined, is missing, or is commented out, this is a finding."${BLD}
cci7="CCI-000068 CCI-002418 CCI-002421"
stigid7="RHEL-09-255090"
severity7="CAT II"
ruleid7="SV-257994r1045051"
vulnid7="V-257994"

title8a="All RHEL 9 remote access methods must be monitored."
title8b="Checking with: 'grep -rE '(auth.\*|authpriv.\*|daemon.\*)' /etc/rsyslog.conf /etc/rsyslog.d/'."
title8c="Expecting: ${YLO}/etc/rsyslog.conf:authpriv.*
           NOTE: If \"auth.*\", \"authpriv.*\" or \"daemon.*\" are not configured to be logged, this is a finding."${BLD}
cci8="CCI-000067"
stigid8="RHEL-09-652030"
severity8="CAT II"
ruleid8="SV-258144r1045286"
vulnid8="V-258144"

title9a="RHEL 9 IP tunnels must use FIPS 140-3 approved cryptographic algorithms."
title9b="Checking with: 'grep include /etc/ipsec.conf /etc/ipsec.d/*.conf'."
title9c="Expecting: ${YLO}/etc/ipsec.conf:include /etc/crypto-policies/back-ends/libreswan.config
           NOTE: If the ipsec configuration file does not contain \"include /etc/crypto-policies/back-ends/libreswan.config\", this is a finding."${BLD}
cci9="CCI-000068"
stigid9="RHEL-09-671020"
severity9="CAT II"
ruleid9="SV-258232r1045440"
vulnid9="V-258232"

title10a="The RHEL 9 SSH client must be configured to use only DOD-approved encryption ciphers employing FIPS 140-3 validated cryptographic hash algorithms to protect the confidentiality of SSH client connections."
title10b="Checking with: grep -i Ciphers /etc/crypto-policies/back-ends/openssh.config"
title10c="Expecting: ${YLO}Ciphers aes256-gcm@openssh.com,aes256-ctr,aes128-gcm@openssh.com,aes128-ctr
           Note: If the cipher entries in the \"openssh.config\" file have any ciphers other than \"aes256-gcm@openssh.com,aes256-ctr,aes128-gcm@openssh.com,aes128-ctr\", or they are missing or commented out, this is a finding."${BLD}
cci10="CCI-001453"
stigid10="RHEL-09-255064"
severity10="CAT II"
ruleid10="SV-270177r1051237"
vulnid10="V-270177"

title11a="The RHEL 9 SSH client must be configured to use only DOD-approved Message Authentication Codes (MACs) employing FIPS 140-3 validated cryptographic hash algorithms to protect the confidentiality of SSH client connections."
title11b="Checking with: grep -i MACs /etc/crypto-policies/back-ends/openssh.config"
title11c="Expecting: ${YLO}MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512
           NOTE: If the MACs entries in the \"openssh.config\" file have any hashes other than \"hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512\", or they are missing or commented out, this is a finding."${BLD}
cci11="CCI-001453"
stigid11="RHEL-09-255070"
severity11="CAT II"
ruleid11="SV-270178r1051243"
vulnid11="V-270178"

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

fips="$(fips-mode-setup --check)"

if [[ $fips ]]
then
  if [[ $fips =~ "is enabled" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$fips${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$fips${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, RHEL 9 FIPS mode is enabled.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, RHEL 9 FIPS mode is not enabled.${NORMAL}"
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

echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${CYN}VERIFY, (See CM-7 Least Functionality: V-257935)${NORMAL}"

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

echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${CYN}VERIFY, (See CM-7 Least Functionality: V-257936)${NORMAL}"

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

#loglevel="$(/usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs grep -iH '^\s*loglevel')"
loglevel="$(/usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs grep -iH '^\s*loglevel')"

if [[ $loglevel ]]
then
  if [[ $loglevel =~ "#" || ! $loglevel =~ "VERBOSE" ]]
  then
    echo -e "${NORMAL}RESULT:    ${RED}$loglevel${NORMAL}"
  elif [[ $loglevel =~ "VERBOSE" ]]
  then
    fail=0
    file="$(echo $loglevel | awk -F: '{print $1}')"
    setting="$(echo $loglevel | awk -F: '{print $2}')"
    echo -e "${NORMAL}RESULT:    ${CYN}$file:${BLD}$setting${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${CYN}$file:${RED}$setting${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${GRN}PASSED, RHEL 9 logs SSH connection attempts and failures to the server.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${RED}FAILED, RHEL 9 logs SSH connection attempts and failures to the server.${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

file5="/etc/crypto-policies/back-ends/opensshserver.config"

if [[ -f $file5 ]]
then
  cipherstr1="$(grep -i Ciphers $file5)"
  if [[ $cipherstr1 == "Ciphers aes256-gcm@openssh.com,aes256-ctr,aes128-gcm@openssh.com,aes128-ctr" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$cipherstr1${NORMAL}"
  else
    ciphersarr1=("aes256-gcm@openssh.com" "aes256-ctr" "aes128-gcm@openssh.com" "aes128-ctr")
    arr1size=${#ciphersarr1[@]}
    cipherstr2="$(echo $cipherstr1 | awk '{print $2}')"
    IFS=','
    read -ra ciphersarr2 <<< $cipherstr2
    arr2size=${#ciphersarr2[@]}
    #echo "$arr1size :: $arr2size"
    for x in ${ciphersarr2[@]}
    do
      found=0
      for y in ${ciphersarr1[@]}
      do
	if [[ $x == $y ]]
	then
	  found=1
	  break
	fi
      done
      if [[ $found == 0 ]]
      then
	fail=1
	echo -e "${NORMAL}RESULT:    ${RED}$x doesn't match${NORMAL}"
      fi
    done
    IFS='\n'
    if [[ $fail == 0 ]]
    then
      if (( $arr1size > $arr2size ))
      then
	fail=1
        echo -e "${NORMAL}RESULT:    ${RED}Some algorithms are missing${NORMAL}"
      else
        echo -e "${NORMAL}RESULT:    ${BLD}$cipherstr1${NORMAL}"
      fi
    else
      echo -e "${NORMAL}RESULT:    ${RED}$cipherstr1${NORMAL}"
    fi
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file5 not found${NORMAL}"
  fail=1
fi
    
if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${GRN}PASSED, RHEL 9 is configured to use only DOD-approved encryption ciphers employing FIPS 140-3 validated cryptographic hash algorithms to protect the confidentiality of SSH server connections.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${RED}FAILED, RHEL 9 is not configured to use only DOD-approved encryption ciphers employing FIPS 140-3 validated cryptographic hash algorithms to protect the confidentiality of SSH server connections.${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

file6="/etc/crypto-policies/back-ends/opensshserver.config"

if [[ -f $file6 ]]
then
  macstr1="$(grep -i MACs $file6)"
  if [[ macstr1 == "MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$macstr1${NORMAL}"
  else
    macarr1=("hmac-sha2-256-etm@openssh.com" "hmac-sha2-512-etm@openssh.com" "hmac-sha2-256" "hmac-sha2-512")
    arr1size=${#macarr1[@]}
    macstr2="$(echo $macstr1 | awk '{print $2}')"
    IFS=','
    read -ra macarr2 <<< $macstr2
    arr2size=${#macarr2[@]}
    for x in ${macarr2[@]}
    do
      found=0
      for y in ${macarr1[@]}
      do
        if [[ $x == $y ]]
        then
          found=1
	  break
        fi
      done
      if [[ $found == 0 ]]
      then
        fail=1
        echo -e "${NORMAL}RESULT:    ${RED}$x doesn't match${NORMAL}"
      fi
    done
    IFS='\n'
    if [[ $fail == 0 ]]
    then
      if (( $arr1size > $arr2size ))
      then
        fail=1
        echo -e "${NORMAL}RESULT:    ${RED}Some algorithms are missing${NORMAL}"
      else
        echo -e "${NORMAL}RESULT:    ${BLD}$macstr1${NORMAL}"
      fi
    else
      echo -e "${NORMAL}RESULT:    ${RED}$macstr1${NORMAL}"
    fi
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file6 not found${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${GRN}PASSED, RHEL 9 is configured to use only Message Authentication Codes (MACs) employing FIPS 140-3 validated cryptographic hash algorithms to protect the confidentiality of SSH server connections.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${RED}FAILED, RHEL 9 is not configured to use only Message Authentication Codes (MACs) employing FIPS 140-3 validated cryptographic hash algorithms to protect the confidentiality of SSH server connections.${NORMAL}"
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

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${CYN}VERIFY, (See SC-8 Transmission Confidentiality and Integrity: V-257994)${NORMAL}"

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

accessmon="$(grep -rE '(auth.\*|authpriv.\*|daemon.\*)' /etc/rsyslog.conf /etc/rsyslog.d/)"

if [[ $accessmon ]]
then
  for line in ${accessmon[@]}
  do
    if [[ $line =~ "/var/log/secure" || $line =~ "/var/log/messages" ]]
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
  echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cci8, $datetime, ${GRN}PASSED, All RHEL 9 remote access methods are monitored.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cci8, $datetime, ${RED}FAILED, All RHEL 9 remote access methods are not monitored.${NORMAL}"
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

include="$(grep include 2>/dev/null /etc/ipsec.conf /etc/ipsec.d/*.conf | grep -v "#")"

if [[ $include ]]
then
  for line in ${include[@]}
  do
    if [[ $line =~ "libreswan.config" ]]
    then
      fail=0
      echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    $line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity9, $controlid, $stigid9, $ruleid9, $cci9, $datetime, ${GRN}PASSED, RHEL 9 IP tunnels use FIPS 140-3 approved cryptographic algorithms.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity9, $controlid, $stigid9, $ruleid9, $cci9, $datetime, ${RED}FAILED, RHEL 9 IP tunnels do not use FIPS 140-3 approved cryptographic algorithms.${NORMAL}"
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

file10="/etc/crypto-policies/back-ends/openssh.config"

if [[ -f $file10 ]]
then
  cipherstr1="$(grep -i Ciphers $file10)"
  if [[ $cipherstr1 == "Ciphers aes256-gcm@openssh.com,aes256-ctr,aes128-gcm@openssh.com,aes128-ctr" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$cipherstr1${NORMAL}"
  else
    ciphersarr1=("aes256-gcm@openssh.com" "aes256-ctr" "aes128-gcm@openssh.com" "aes128-ctr")
    arr1size=${#ciphersarr1[@]}
    cipherstr2="$(echo $cipherstr1 | awk '{print $2}')"
    IFS=','
    read -ra ciphersarr2 <<< $cipherstr2
    arr2size=${#ciphersarr2[@]}
    #echo "$arr1size :: $arr2size"
    for x in ${ciphersarr2[@]}
    do
      found=0
      for y in ${ciphersarr1[@]}
      do
        if [[ $x == $y ]]
        then
          found=1
          break
        fi
      done
      if [[ $found == 0 ]]
      then
        fail=1
        echo -e "${NORMAL}RESULT:    ${RED}$x doesn't match${NORMAL}"
      fi
    done
    IFS='\n'
    if [[ $fail == 0 ]]
    then
      if (( $arr1size > $arr2size ))
      then
        fail=1
        echo -e "${NORMAL}RESULT:    ${RED}Some algorithms are missing${NORMAL}"
      else
        echo -e "${NORMAL}RESULT:    ${BLD}$cipherstr1${NORMAL}"
      fi
    else
      echo -e "${NORMAL}RESULT:    ${RED}$cipherstr1${NORMAL}"
    fi
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file10 not found${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity10, $controlid, $stigid10, $ruleid10, $cci10, $datetime, ${GRN}PASSED, RHEL 9 is configured to use only DOD-approved encryption ciphers employing FIPS 140-3 validated cryptographic hash algorithms to protect the confidentiality of SSH client connections.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity10, $controlid, $stigid10, $ruleid10, $cci10, $datetime, ${RED}FAILED, RHEL 9 is not configured to use only DOD-approved encryption ciphers employing FIPS 140-3 validated cryptographic hash algorithms to protect the confidentiality of SSH client connections.${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

file11="/etc/crypto-policies/back-ends/openssh.config"

if [[ -f $file11 ]]
then
  macstr1="$(grep -i MACs $file11)"
  if [[ macstr1 == "MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$macstr1${NORMAL}"
  else
    macarr1=("hmac-sha2-256-etm@openssh.com" "hmac-sha2-512-etm@openssh.com" "hmac-sha2-256" "hmac-sha2-512")
    arr1size=${#macarr1[@]}
    macstr2="$(echo $macstr1 | awk '{print $2}')"
    IFS=','
    read -ra macarr2 <<< $macstr2
    arr2size=${#macarr2[@]}
    #echo "$arr1size :: $arr2size"
    for x in ${macarr2[@]}
    do
      found=0
      for y in ${macarr1[@]}
      do
        if [[ $x == $y ]]
        then
          found=1
          break
        fi
      done
      if [[ $found == 0 ]]
      then
        fail=1
        echo -e "${NORMAL}RESULT:    ${RED}$x doesn't match${NORMAL}"
      fi
    done
    IFS='\n'
    if [[ $fail == 0 ]]
    then
      if (( $arr1size > $arr2size ))
      then
        fail=1
        echo -e "${NORMAL}RESULT:    ${RED}Some algorithms are missing${NORMAL}"
      else
        echo -e "${NORMAL}RESULT:    ${BLD}$macstr1${NORMAL}"
      fi
    else
      echo -e "${NORMAL}RESULT:    ${RED}$macstr1${NORMAL}"
    fi
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file11 not found${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity11, $controlid, $stigid11, $ruleid11, $cci11, $datetime, ${GRN}PASSED, RHEL 9 is configured to use only Message Authentication Codes (MACs) employing FIPS 140-3 validated cryptographic hash algorithms to protect the confidentiality of SSH client connections.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity11, $controlid, $stigid11, $ruleid11, $cci11, $datetime, ${RED}FAILED, RHEL 9 is not configured to use only Message Authentication Codes (MACs) employing FIPS 140-3 validated cryptographic hash algorithms to protect the confidentiality of SSH client connections.${NORMAL}"
fi

exit
