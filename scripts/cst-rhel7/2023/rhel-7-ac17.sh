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

controlid="AC-17 Remote Access"

title1a="The Red Hat Enterprise Linux operating system must implement NIST FIPS-validated cryptography for the following: to provision digital signatures, to generate cryptographic hashes, and to protect data requiring data-at-rest protections in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards."
title1b="Checking with:
           a. 'yum list installed dracut-fips'
	   b. 'grep fips /boot/grub2/grub.cfg'
	   c. 'cat /proc/sys/crypto/fips_enabled'
	   d. 'ls -l /etc/system-fips'"
title1c="Expecting:
           a. dracut-fips-033-360.el7_2.x86_64.rpm (or later)
	   b. /vmlinuz-3.8.0-0.40.el7.x86_64 root=/dev/mapper/rhel-root ro rd.md=0 rd.dm=0 rd.lvm.lv=rhel/swap crashkernel=auto rd.luks=0 vconsole.keymap=us rd.lvm.lv=rhel/root rhgb ${GRN}fips=1${BLD} quiet
	   c. 1
	   d. -rw-r--r--. 1 root root 36 Jun  9  2022 /etc/system-fips${YLO}
	   Note: GRUB 2 reads its configuration from the \"/boot/grub2/grub.cfg\" file on traditional BIOS-based machines and from the \"/boot/efi/EFI/redhat/grub.cfg\" file on UEFI machines.
	   Note: If a \"dracut-fips\" package is not installed, the kernel command line does not have a fips entry, or the system has a value of \"0\" for \"fips_enabled\" in \"/proc/sys/crypto\", this is a finding.
	   Note: If the \"/etc/system-fips\" file does not exist, this is a finding.${BLD}"
cci1="CCI-000068"
stigid1="RHEL-07-021350"
severity1="CAT I"
ruleid1="SV-204497r603261_rule"
vulnid1="V-204497"

title2a="The Red Hat Enterprise Linux operating system must be configured to prohibit or restrict the use of functions, ports, protocols, and/or services, as defined in the Ports, Protocols, and Services Management Component Local Service Assessment (PPSM CLSA) and vulnerability assessments."
title2b="Checking with 'firewall-cmd --list-all'."
title2c="Expecting:${YLO}
           public (default, active) 
           interfaces: enp0s3 
           sources: 
           rhel-7-ac10.sh             services: dhcpv6-client dns http https ldaps rpc-bind ssh 
           ports: 
           masquerade: no 
           forward-ports: 
           icmp-blocks: 
           rich rules:
           Note: If there are additional ports, protocols, or services that are not in the PPSM CLSA, or there are ports, protocols, or services that are prohibited by the PPSM Category Assurance List (CAL), this is a finding.${BLD}"
cci2="CCI-000382"
stigid2="RHEL-07-040100"
severity2="CAT II"
ruleid2="SV-204577r603261_rule"
vulnid2="V-204577"

title3a="The Red Hat Enterprise Linux 7 operating system must implement DoD-approved encryption to protect the confidentiality of SSH connections."
title3b="Checking with 'grep -i ciphers /etc/ssh/sshd_config'."
title3c="Expecting: ${YLO}Ciphers aes128-ctr,aes192-ctr,aes256-ctr
           Note: If any ciphers other than \"aes256-ctr\", \"aes192-ctr\", or \"aes128-ctr\" are listed, the order differs from the example above, the \"Ciphers\" keyword is missing, or the returned line is commented out, this is a finding.${BLD}"
cci3="CCI-000068"
stigid3="RHEL-07-040110"
severity3="CAT II"
ruleid3="SV-204578r744166_rule"
vulnid3="V-204578"

title4a="The Red Hat Enterprise Linux operating system must implement cryptography to protect the integrity of Lightweight Directory Access Protocol (LDAP) authentication communications."
title4b="Checking wih
           a. systemctl status sssd.service
           b. grep -i \"id_provider\" /etc/sssd/sssd.conf
           c. grep -i \"start_tls\" /etc/sssd/sssd.conf'."
title4c="Expecting:${YLO}
           a. sssd.service - System Security Services Daemon
              Loaded: loaded (/usr/lib/systemd/system/sssd.service; enabled; vendor preset: disabled)
              Active: active (running) since Wed 2018-06-27 10:58:11 EST; 1h 50min ago
           b. id_provider = ad
           c. ldap_id_use_start_tls = true
           Note: If LDAP is not being utilized, this requirement is Not Applicable.
           Note: If \"id_provider\" is set to \"ad\", this is Not Applicable.
           Note: If the \"ldap_id_use_start_tls\" option is not \"true\", this is a finding.${BLD}"
cci4="CCI-001453"
stigid4="RHEL-07-040180"
severity4="CAT II"
ruleid4="SV-204581r603261_rule"
vulnid4="V-204581"

title5a="The Red Hat Enterprise Linux operating system must implement cryptography to protect the integrity of Lightweight Directory Access Protocol (LDAP) communications."
title5b="Checking with 
           a. systemctl status sssd.service
           b. grep -i \"id_provider\" /etc/sssd/sssd.conf
           c. grep -i tls_reqcert /etc/sssd/sssd.conf"
title5c="Expecting: ${YLO}
           a. sssd.service - System Security Services Daemon
              Loaded: loaded (/usr/lib/systemd/system/sssd.service; enabled; vendor preset: disabled)
              Active: active (running) since Wed 2018-06-27 10:58:11 EST; 1h 50min ago
           b. id_provider = ad
           c. ldap_tls_reqcert = demand
           Note: If \"id_provider\" is set to \"ad\", this requirement is Not Applicable.
           Note: If the \"ldap_tls_reqcert\" setting is missing, commented out, or does not exist, this is a finding.
           Note: If the \"ldap_tls_reqcert\" setting is not set to \"demand\" or \"hard\", this is a finding.${BLD}"
cci5="CCI-001453"
stigid5="RHEL-07-040190"
severity5="CAT II"
ruleid5="SV-204582r877394_rule"
vulnid5="V-204582"

title6a="The Red Hat Enterprise Linux operating system must implement cryptography to protect the integrity of Lightweight Directory Access Protocol (LDAP) communications."
title6b="Checking with:
           a. 'systemctl status sssd.service'
           b. 'grep -i \"id_provider\" /etc/sssd/sssd.conf'
           c. 'grep -i tls_cacert /etc/sssd/sssd.conf'"
title6c="Expecting: ${YLO}
           a. sssd.service - System Security Services Daemon
              Loaded: loaded (/usr/lib/systemd/system/sssd.service; enabled; vendor preset: disabled)
              Active: active (running) since Wed 2018-06-27 10:58:11 EST; 1h 50min ago
           b. id_provider = ad
           c. ldap_tls_cacert = /etc/pki/tls/certs/ca-bundle.crt
           Note: If LDAP is not being utilized, this requirement is Not Applicable.
           Note: If this file does not exist, or the option is commented out or missing, this is a finding."${BLD}
cci6="CCI-001453"
stigid6="RHEL-07-040200"
severity6="CAT II"
ruleid6="SV-204583r877394_rule"
vulnid6="V-204583"

title7a="The Red Hat Enterprise Linux operating system must be configured so that the SSH daemon is configured to only use Message Authentication Codes (MACs) employing FIPS 140-2 approved cryptographic hash algorithms."
title7b="Checking with 'grep -i macs /etc/ssh/sshd_config'."
title7c="Expecting: ${YLO}MACs hmac-sha2-512,hmac-sha2-256
           Note: If any hashes other than \"hmac-sha2-512\" or \"hmac-sha2-256\" are listed, the order differs from the example above, they are missing, or the returned line is commented out, this is a finding."${BLD}
cci7="CCI-001453"
stigid7="RHEL-07-040400"
severity7="CAT II"
ruleid7="SV-204595r877394_rule"
vulnid7="V-204595"

title8a="The Red Hat Enterprise Linux operating ystem SSH server must be configured to use onlly FIPS-validated key exchange algorithms."
title8b="Checking with: 'grep -i kexalgorithms /etc/ssh/sshd_config'."
title8c="Expecting: ${YLO}'KexAlgorithms ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256'
           Note: If \"KexAlgorithms\" is not configured, is commented out, or does not contain only the algorithms \"ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256\" in exact order, this is a finding.${NORMAL}"
cci8="CCI-001453"
stigid8="RHEL-07-040712"
severity8="CAT II"
ruleid8="SV-255925r880749_rule"
vulnid8="V-255925"

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

datetime="$(date +%FT%H:%M:%S)"

fail=0

fipsrpmfail=0
kernelfipsfail=0
fipsenabledfail=0
systemfipsfilefail=0

file1a="/boot/grub2/grub.cfg"
file1b="/boot/efi/EFI/redhat/grub.cfg"
file1c="/proc/sys/crypto/fips_enabled"
file1d="/etc/system-fips"

fipsrpm="$(rpm -qa | grep dracut-fips 2>/dev/null)"

if [[ $fipsrpm ]]
then
  for rpm in ${fipsrpm[@]}
  do
    echo -e "${NORMAL}RESULT:    ${BLD}a. $rpm${NORMAL}"
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}a. The \"dracut-fips\" package is not installed.${NORMAL}"
  fipsrpmfail=1
fi

if [[ -f $file1a ]]
then
  bootoptions="$(grep fips $file1a | sed -e 's/^[[:space:]]*//')"
elif [[ -f $file1b ]]
then
  bootoptions="$(grep fips $file1b | sed -e 's/^[[:space:]]*//')"
fi
if [[ $bootoptions ]]
then
  for line in ${bootoptions[@]}
  do
    IFS=' ' read -a fieldvals <<< "${line}"
    for field in ${fieldvals[@]}
    do
      if [[ $field == 'fips='* ]]
      then
        fipsval="$(echo $field | awk -F= '{print $2}')"
        if (( $fipsval == 1 ))
        then
          echo -e "${NORMAL}RESULT:    ${BLD}b. $line${NORMAL}"
        else
          echo -e "${NORMAL}RESULT:    ${RED}b. $line${NORMAL}"
          kernelfipsfail=1
        fi
      fi
    done
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}b. $line${NORMAL}"
  kernelfipsfail=1
fi
  
if [[ -f $file1c ]]
then
  fipsenabled="$(cat $file1c)"
  if [[ $fipsenabled == 1 ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}c. $fipsenabled${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}c. $fipsenabled${NORMAL}"
    fipsenabledfail=1
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}c. $file1c does not exist.${NORMAL}"
  fipsenablefail=1
fi

if [[ -f $file1d ]]
then
  systemfipsfile="$(ls -l $file1d)"
  echo -e "${NORMAL}RESULT:    ${BLD}d. $systemfipsfile${NORMAL}"
else
  echo -e "${NORMAL}RESULT:    ${RED}d. \"$file1d\" does not exist.${NORMAL}"
  systemfipsfilefail=1
fi

if [[ $fipsrpmfail == 1 || $kernelfipsfail == 1 || $fipsenabledfail == 1 || $systemfipsfilefail == 1 ]]
then
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, The operating system implements DoD-approved encryption to protect the confidentiality of remote access sessions.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, The operating system does not implement DoD-approved encryption to protect the confidentiality of remote access sessions.${NORMAL}"
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

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${CYN}VERIFY, (See CM-7 Least Functionality: V-204577)${NORMAL}"

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

echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${CYN}VERIFY, (See CM-6 Configuration Settings: V-204578)${NORMAL}"

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

file4="/etc/sssd/sssd.conf"

loaded=0
running=0
starttls=0
fail=1

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file4 ]]
then
  sssdsvc="$(systemctl status sssd.service 2>/dev/null)"
  if [[ $sssdsvc ]]
  then
    for line in ${sssdsvc[@]}
    do
      if [[ $line =~ "Loaded: loaded" ]]
      then
         echo -e "${NORMAL}RESULT:    ${BLD}a. $line${NORMAL}"
         loaded=1
      elif [[ $line =~ "Active: active (running)" ]]
      then
         echo -e "${NORMAL}RESULT:    ${BLD}a. $line${NORMAL}"
         running=1
      else
         echo -e "${NORMAL}RESULT:    a. $line${NORMAL}"
      fi
    done
  else
    echo -e "${NORMAL}RESULT:    a. The system is not using LDAP authentication${NORMAL}"
    fail=2
  fi

  provider="$(grep -i 'id_provider' $file4)"
  if [[ $provider ]]
  then
    for line in ${provider[@]}
    do
      idprovider="$(echo $provider | awk -F'= ' '{print $3}')"
      if [[ $idprovider == "ad" ]]
      then
        echo -e "${NORMAL}RESULT:    ${BLD}b. $line${NORMAL}"
        fail=2
      else
        echo -e "${NORMAL}RESULT:    b. $line${NORMAL}"
      fi
    done
  else
    echo -e "${NORMAL}RESULT:    ${}b. $idprovider${NORMAL}"
  fi

  starttls="$(grep -i 'start_tls' $file4)"
  if [[ $starttls ]]
  then
    starttlsval="$(echo $starttls | awk -F'= ' '{print $2}')"
    if [[ $starttlsval == "true" ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}c. $starttls${NORMAL}"
      starttls=1
    else
      echo -e "${NORMAL}RESULT:    ${RED}c. $starttls${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${BLD}c. \"ldap_id_use_start_tls\" not defined in $file4${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    $file4 does not exist${NORMAL}"
  fail=2
fi

if [[ $loaded == 1 && $running == 1 && $starttls == 1 ]]
then
  fail=0
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${GRN}PASSED, Cryptography: The operating system implements cryptography to protect the integrity of Lightweight Directory Access Protocol (LDAP) authentication communications.${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${GRN}N/A, Cryptography: Not Applicable: The operating system is not utilizing LDAP for authentication.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${RED}FAILED, Cryptography: The operating system does not implement cryptography to protect the integrity of Lightweight Directory Access Protocol (LDAP) authentication communications.${NORMAL}"
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

file5="/etc/sssd/sssd.conf"
loaded=0
running=0
reqcert=0

fail=1

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file5 ]]
then
  sssdsvc="$(systemctl status sssd.service 2>/dev/null)"
  if [[ $sssdsvc ]]
  then
    for line in ${sssdsvc[@]}
    do
      if [[ $line =~ "Loaded: loaded" ]]
      then
         echo -e "${NORMAL}RESULT:    ${BLD}a. $line${NORMAL}"
         loaded=1
      elif [[ $line =~ "Active: active (running)" ]]
      then
         echo -e "${NORMAL}RESULT:    ${BLD}a. $line${NORMAL}"
         running=1
      else
         echo -e "${NORMAL}RESULT:    a. $line${NORMAL}"
      fi
    done
  else
    echo -e "${NORMAL}RESULT:    a. The system is not using LDAP authentication${NORMAL}"
    fail=2
  fi

  provider="$(grep -i 'id_provider' $file4)"
  if [[ $provider ]]
  then
    for line in ${provider[@]}
    do
      idprovider="$(echo $provider | awk -F'= ' '{print $3}')"
      if [[ $idprovider == "ad" ]]
      then
        echo -e "${NORMAL}RESULT:    ${BLD}b. $line${NORMAL}"
        fail=2
      else
        echo -e "${NORMAL}RESULT:    b. $line${NORMAL}"
      fi
    done
  else
    echo -e "${NORMAL}RESULT:    ${}b. $idprovider${NORMAL}"
  fi

  tlsreqcert="$(grep -i 'tls_reqcert' $file5)"
  if [[ $tlsreqcert ]]
  then
    tlsreqcertval="$(echo $tlsreqcert | awk -F'= ' '{print $2}')"
    if [[ $tlsreqcertval == "demand" || $tlsreqcertval == "hard" ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}c. $tlsreqcert${NORMAL}"
      reqcert=1
    else
      echo -e "${NORMAL}RESULT:    ${RED}c. $tlsreqcert${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${BLD}c. \"ldap_id_use_start_tls\" not defined in $file5${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    $file5 does not exist${NORMAL}"
  fail=2
fi

if [[ $loaded == 1 && $running == 1 && $reqcert == 1 ]]
then
  fail=0
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${GRN}PASSED, LDAP Cryptography: The operating system implements cryptography to protect the integrity of Lightweight Directory Access Protocol (LDAP) communications.${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${GRN}N/A, LDAP Cryptography: LDAP is not used. This is Not Applicable.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${RED}FAILED, LDAP Cryptography: The operating system does not implement cryptography to protect the integrity of Lightweight Directory Access Protocol (LDAP) communications.${NORMAL}"
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

file6="/etc/sssd/sssd.conf"
enabled=0
running=0
certval=0

fail=1

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file6 ]]
then
  status="$(systemctl status sssd.service)"
  if [[ $status ]]
  then
    for line in ${status[@]}
    do
      if [[ $line =~ "Loaded: loaded" ]]
      then
         echo -e "${NORMAL}RESULT:    ${BLD}a. $line${NORMAL}"
         loaded=1
      elif [[ $line =~ "Active: active (running)" ]]
      then
         echo -e "${NORMAL}RESULT:    ${BLD}a. $line${NORMAL}"
         running=1
      else
         echo -e "${NORMAL}RESULT:    a. $line${NORMAL}"
      fi
    done
  else
    echo -e "${NORMAL}RESULT:    Nothing returned${NORMAL}"
  fi

  provider="$(grep -i 'id_provider' $file4)"
  if [[ $provider ]]
  then
    for line in ${provider[@]}
    do
      idprovider="$(echo $provider | awk -F'= ' '{print $3}')"
      if [[ $idprovider == "ad" ]]
      then
        echo -e "${NORMAL}RESULT:    ${BLD}b. $line${NORMAL}"
        fail=2
      else
        echo -e "${NORMAL}RESULT:    b. $line${NORMAL}"
      fi
    done
  else
    echo -e "${NORMAL}RESULT:    ${}b. $idprovider${NORMAL}"
  fi

  cacert="$(grep -i tls_cacert $file6 | grep -v '^#' )"
  if [[ $cacert ]]
  then
    cacertval="$(echo $cacert | awk -F'= ' '{print $2}')"
    if [[ $cacertval =~ '/etc/pki' ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}c. $cacert${NORMAL}"
      certval=1
    else
      echo -e "${NORMAL}RESULT:    c. $cacert${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}'ldap_tls_cacert' is not defined in $file6${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    LDAP is not used.${NORMAL}"
  fail=2
fi
    
if [[ $loaded == 1 && $running == 1 && $certval == 1 ]]
then
  fail=0
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${GRN}PASSED, LDAP X-509 Certificate: The operating system implements cryptography to protect the integrity of Lightweight Directory Access Protocol (LDAP) communications.${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${GRN}N/A, LDAP is not used.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${RED}FAILED, LDAP X-509 Certificate: The operating system does not implement cryptography to protect the integrity of Lightweight Directory Access Protocol (LDAP) communications.${NORMAL}"
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

file7="/etc/ssh/sshd_config"

machash=("hmac-sha2-256" "hmac-sha2-512")
c256cnt=0
c512cnt=0
fail=1

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file7 ]]
then
   hmacs="$(grep -i ^macs $file7)"
   if [[ $hmacs ]]
   then
      for line in ${hmacs[@]}
      do
         echo -e "${NORMAL}RESULT:    $line${NORMAL}"
         ciphers="$(echo $line | sed -e 's/^MACs //g')"
         IFS=',' read -a cipher <<< $ciphers IFS='\n'
         for algorithm in ${cipher[@]}
         do
            case $algorithm in
            "hmac-sha2-512")
               if (( $c256cnt > $c512cnt ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}$algorithm out of order${NORMAL}"
                  fail=1
               fi
               (( c512cnt++ ))
               ;;
            "hmac-sha2-256")
               (( c256cnt++ ))
               ;;
            esac
            if [[ $algorithm != 'hmac-sha2-512' &&
                  $algorithm != 'hmac-sha2-256'
               ]]
            then
               echo -e "${NORMAL}RESULT:    ${RED}$algorithm not approved${NORMAL}"
               fail=1
            fi
         done
      done
   else
       echo -e "${NORMAL}RESULT:    ${BLD}'MACs' is not defined in $file7${NORMAL}"
   fi

   if [[ $fail == 0 ]]
   then
      
      echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${GRN}PASSED, Cryptography: The SSH daemon is configured to only use Message Authentication Codes (MACs) employing FIPS 140-2 approved cryptographic hash algorithms.${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${RED}FAILED, Cryptography: The SSH daemon is not configured to only use Message Authentication Codes (MACs) employing FIPS 140-2 approved cryptographic hash algorithms.${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file7 was not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${RED}FAILED, Cryptography: $file7 was not found${NORMAL}"
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

file8="/etc/ssh/sshd_config"

fail=0

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file8 ]]
then
  kexalgo="$(grep -i kexalgorithms $file8 | awk '{print $2}')"
  if [[ $kexalgo ]]
  then
    
    for line in ${kexalgo[@]}
    do
      echo -e "${NORMAL}RESULT:    $line${NORMAL}"
      if [[ ! $line =~ 'ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256' ]]
      then
         echo -e "${NORMAL}RESULT:    ${RED}Algorithms missing or out of order${NORMAL}"
         fail=1
      fi
      IFS=',' read -a fieldvals <<< $line IFS='\n'
      for field in ${fieldvals[@]}
      do
        if [[ $field != "ecdh-sha2-nistp256" && 
              $field != "ecdh-sha2-nistp384" && 
              $field != "ecdh-sha2-nistp521" && 
              $field != "diffie-hellman-group-exchange-sha256"
           ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}$field not allowed${NORMAL}"
          fail=1
        fi
      done
    done
  else
    echo -e "${NORMAL}RESULT:    ${RED}\"Kexalgorithms\" not defined in $file8.${NORMAL}"
    fail=1
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file8 not found.${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cci8, $datetime, ${GRN}PASSED, SSH Algorithms: The SSH server is configured to use only FIPS-validated key exchange algorithms.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cci8, $datetime, ${RED}FAILED, SSH Algorithms: The SSH server is not configured to use only FIPS-validated key exchange algorithms.${NORMAL}"
fi

exit
