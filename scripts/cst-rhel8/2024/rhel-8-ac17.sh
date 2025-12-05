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

stig="Red Hat Enterprise Linux 8 Security Technical Implementation Guide :: Version 1, Release: 13 Benchmark Date: 24 Jan 2024"

hostname="$(uname -n)"

if [[ -f /etc/redhat-release ]]
then
   os="$(cat /etc/redhat-release)"
else
   os="OS not defined"
fi

prog="$(basename $0)"

controlid="AC-17 Remote Access"

title1a="RHEL 8 must implement NIST FIPS-validated cryptography for the following: to provision digital signatures, to generate cryptographic hashes, and to protect data requiring data-at-rest protections in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards."
title1b="Checking with:
           a. 'fips-mode-setup --check'
	   NOTE: If FIPS mode is \"enabled\", check to see if the kernel boot parameter is configured for FIPS mode with the following command.
           b. 'sudo grub2-editenv list | grep fips'
	   NOTE: If the kernel boot parameter is configured to use FIPS mode, check to see if the system is in FIPS mode with the following command.
           c. 'sudo cat /proc/sys/crypto/fips_enabled'."
title1c="Expecting:${YLO}
           a.'FIPSmode is enabled'
           b.'kernelopts=root=/dev/mapper/rhel-root ro crashkernel=auto resume=/dev/mapper/rhel-swap rd.lvm.lv=rhel/root rd.lvm.lv=rhel/swap rhgb quiet ${GRN}fips=1${YLO} boot=UUID=8d171156-cd61-421c-ba41-1c021ac29e82'
           c.'1'.
           : If FIPS mode is not \"on\", the kernel boot parameter is not configured for FIPS mode, or the system does not have a value of \"1\" for \"fips_enabled\" in \"/proc/sys/crypto\", this is a finding."${BLD}
cci1="CCI-000068"
stigid1="RHEL-08-010020"
severity1="CAT I"
ruleid1="SV-230223r928585_rule"
vulnid1="V-230223"

title2a="All RHEL 8 remote access methods must be monitored."
title2b="Checking with:
           sudo grep -E '(auth.*|authpriv.*|daemon.*)' /etc/rsyslog.conf"
title2c="Expecting: ${YLO}
           authpriv.*	/var/log/secure
	   daemon.*	/var/log/secure
	   auth.*	/var/log/secure"${BLD}
cci2="CCI-000067"
stigid2="RHEL-08-010070"
severity2="CAT II"
ruleid2="SV-230228r627750_rule"
vulnid2="V-230228"

title3a="The RHEL 8 SSH server must be configured to use only Message Authentication Codes (MACs) employing FIPS 140-2 validated cryptographic hash algorithms."
title3b="Checking with 'grep -i macs /etc/crypto-policies/back-ends/opensshserver.config'."
title3c="Expecting: ${YLO}hmac-sha2-512,hmac-sha2-256,hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
           NOTE: If the MACs entries in the \"opensshserver.config\" file have any hashes other than shown here, the order differs from the example above, or they are missing or commented out, this is a finding."${BLD}
cci3="CCI-001453"
stigid3="RHEL-08-010290"
severity3="CAT II"
ruleid3="SV-230251r917870_rule"
vulnid3="V-230251"

title4a="The RHEL 8 operating system must implement DoD-approved encryption to protect the confidentiality of SSH server connections."
title4b="Checking with 'grep -i ciphers /etc/crypto-policies/back-ends/opensshserver.config."
title4c="Expecting: ${YLO}Ciphers=aes256-ctr,aes192-ctr,aes128-ctr,aes256-gcm@openssh.com,aes128-gcm@openssh.com'
           NOTE: If the cipher entries in the \"opensshserver.config\" file have any ciphers other than shown here, the order differs from the example above, or they are missing or commented out, this is a finding."${BLD}
cci4="CCI-000068"
stigid4="RHEL-08-010291"
severity4="CAT II"
ruleid4="SV-230252r917873_rule"
vulnid4="V-230252"

title5a="The RHEL 8 operating system must implement DoD-approved encryption in the OpenSSL package."
title5b="Checking with: 
           a. 'grep -i opensslcnf.config /etc/pki/tls/openssl.cnf' 
	   b. 'update-crypto-policies --show'"
title5c="Expecting: 
           ${YLO}a. .include /etc/crypto-policies/back-ends/opensslcnf.config
	   b. FIPS
           NOTE: If the \"opensslcnf.config\" is not defined in the \"/etc/pki/tls/openssl.cnf\" file, this is a finding.
	   NOTE: If the system-wide crypto policy is set to anything other than \"FIPS\", this is a finding."${BLD}
cci5="CCI-001453"
stigid5="RHEL-08-010293"
severity5="CAT II"
ruleid5="SV-230254r877394_rule"
vulnid5="V-230254"

title6a="The RHEL 8 operating system must implement DoD-approved TLS encryption in the OpenSSL package."
title6b="Checking with: 
           'grep -i MinProtocol /etc/crypto-policies/back-ends/opensslcnf.config'."
title6c="Expecting:${YLO}
           MinProtocol = TLSv1.2
           NOTE: If the \"MinProtocol\" is set to anything older than \"TLSv1.2\", this is a finding.
	   NOTE: For version crypto-policies-20210617-1.gitc776d3e.el8.noarch and newer:
               TLS.MinProtocol = TLSv1.2
               DTLS.MinProtocol = DTLSv1.2
           NOTE: If the \"TLS.MinProtocol\" is set to anything older than \"TLSv1.2\" or the \"DTLS.MinProtocol\" is set to anything older than DTLSv1.2, this is a finding."${BLD}
cci6="CCI-001453"
stigid6="RHEL-08-010294"
severity6="CAT II"
ruleid6="SV-230255r877394_rule"
vulnid6="V-230255"

title7a="The RHEL 8 operating system must implement DoD-approved TLS encryption in the GnuTLS package."
title7b="Checking with: 'grep -io +vers.*  /etc/crypto-policies/back-ends/gnutls.config'."
title7c="Expecting:${YLO}
           +VERS-ALL
           -VERS-DTLS0.9
           -VERS-SSL3.0
           -VERS-TLS1.0
           -VERS-TLS1.1
           -VERS-DTLS1.0
           +COMP-NULL
           %PROFILE_MEDIUM
           NOTE: If the \"gnutls.config\" does not list \"-VERS-DTLS0.9:-VERS-SSL3.0:-VERS-TLS1.0:-VERS-TLS1.1:-VERS-DTLS1.0\" to disable unapproved SSL/TLS versions, this is a finding."${BLD}
cci7="CCI-001453"
stigid7="RHEL-08-010295"
severity7="CAT II"
ruleid7="SV-230256r877304_rule"
vulnid7="V-230256"

title8a="A RHEL 8 firewall must employ a deny-all, allow-by-exception policy for allowing connections to other systems."
title8b="Checking with:
           a. firewall-cmd --state
	   b. firewall-cmd --get-active-zones
	   c. firewall-cmd --info-zone=[custom] | grep target"
title8c="Expecting: ${YLO}
           a. running
	   b. [custom]
	        interfaces: ens33
	   c. target: DROP
           NOTE: If no zones are active on the RHEL 8 interfaces or if the target is set to a different option other than \"DROP\", this is a finding."${BLD}
cci8="CCI-002314"
stigid8="RHEL-08-040090"
severity8="CAT II"
ruleid8="SV-230504r942942_rule"
vulnid8="V-230504"

title9a="A firewall must be installed on RHEL 8."
title9b="Checking with: 'yum list installed firewalld'."
title9c="Expecting: ${YLO}firewalld.noarch     0.7.0-5.el8
           NOTE: If the \"firewalld\" package is not installed, ask the System Administrator if another firewall is installed. If no firewall is installed this is a finding."${BLD}
cci9="CCI-002314"
stigid9="RHEL-08-040100"
severity9="CAT II"
ruleid9="SV-230505r854048_rule"
vulnid9="V-230505"

title10a="RHEL 8 must force a frequent session key renegotiation for SSH connections to the server."
title10b="Checking with: 'grep -i RekeyLimit /etc/ssh/sshd_config'."
title10c="Expecting: ${YLO}RekeyLimit 1G 1h
           NOTE: If \"RekeyLimit\" does not have a maximum data amount and maximum time defined, is missing or commented out, this is a finding.${BLD}"
cci10="CCI-000068"
stigid10="RHEL-08-040161"
severity10="CAT II"
ruleid10="SV-230527r877398_rule"
vulnid10="V-230527"

title11a="The RHEL 8 SSH daemon must be configured to use system-wide crypto policies."
title11b="Checking with: 'grep CRYPTO_POLICY /etc/sysconfig/sshd'."
title11c="Expecting: ${YLO}# CRYPTO_POLICY=
           NOTE: If the \"CRYPTO_POLICY\" is uncommented, this is a finding."${BLD}
cci11="CCI-001453"
stigid11="RHEL-08-010287"
severity11="CAT II"
ruleid11="SV-244526r877394_rule"
vulnid11="V-244526"

title12a="A firewall must be active on RHEL 8."
title12b="Checking with: 'systemctl is-active firewalld'."
title12c="Expecting: ${YLO}active
           NOTE: If the \"firewalld\" package is not \"active\", ask the System Administrator if another firewall is installed. If no firewall is installed and active this is a finding."${BLD}
cci12="CCI-002314"
stigid12="RHEL-08-040101"
severity12="CAT II"
ruleid12="SV-244544r854073_rule"
vulnid12="V-244544"

title13a="RHEL 8 SSH server must be configured to use only FIPS-validated key exchange algorithms."
title13b="Checking with: 'grep -i kexalgorithms /etc/crypto-policies/back-ends/opensshserver.config'."
title13c="Expecting: ${YLO}
           CRYPTO_POLICY='-oKexAlgorithms=ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
	   NOTE: If the entries following \"KexAlgorithms\" have any algorithms defined other than \"ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512\", appear in different order than shown, or are missing or commented out, this is a finding."${BLD}
cci13="CCI-001453"
stigid13="RHEL-08-040342"
severity13="CAT II"
ruleid13="SV-255924r917888_rule"
vulnid13="V-255924"

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

file1="/proc/sys/crypto/fips_enabled"

fipsmode="$(fips-mode-setup --check)"
fipsenabled="$(fips-mode-setup --check | awk '{print $4}' | sed 's/.$//g')"

if [[ $fipsenabled == 'on' || $fipsenabled == 'enabled' ]]
then
  echo -e "${NORMAL}RESULT:    ${BLD}a. $fipsmode${NORMAL}"
  kbparam="$(grub2-editenv list | grep fips)"
  if [[ $kbparam =~ 'fips=1' ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}b. $kbparam${NORMAL}"
    sysfips="$(cat $file1)"
    if [[ $sysfips == 1 ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}c. $sysfips${NORMAL}"
    else
      fail=1
      echo -e "${NORMAL}RESULT:    ${RED}c. $sysfips${NORMAL}"
    fi
  else
    fail=1
    echo -e "${NORMAL}RESULT:    ${RED}b. $kparams${NORMAL}"
  fi
else
  fail=1
  echo -e "${NORMAL}RESULT:    ${RED}a. $fipsmode${NORMAL}"
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

fail=1

file2="/etc/rsyslog.conf"

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file2 ]]
then
  authmode="$(grep ^auth[.*] $file2 | sed 's/ \+/\t/g')"
  authprivmode="$(grep ^authpriv[.*] $file2 | sed 's/ \+/\t/g')"
  daemonmode="$(grep ^daemon[.*] $file2 | sed 's/ \+/\t/g')"
  if [[ $authprivmode ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$authprivmode${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}\"authpriv.*\" not found${NORMAL}"
  fi
  if [[ $daemonmode ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$daemonmode${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}\"daemon.*\" not found${NORMAL}"
  fi
  if [[ $authmode ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$authmode${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}\"auth.*\" not found${NORMAL}"
  fi
  if [[ $authmode && $authprivmode && $daemonmode ]]
  then
    fail=0
    echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, All RHEL 8 remote access methods are monitored${NORMAL}"
  else
    echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, All RHEL 8 remote access methods are not monitored${NORMAL}"
  fi
else
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, $file2 not found${NORMAL}"
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

file3="/etc/crypto-policies/back-ends/opensshserver.config"

i=0

declare -A macalgos
macalgos+=( [hmac-sha2-512]=$(( i++ ))
            [hmac-sha2-256]=$(( i++ ))
	    [hmac-sha2-512-etm@openssh.com]=$(( i++ ))
	    [hmac-sha2-256-etm@openssh.com]=$(( i++ ))
	  )

fail=0
found=0
y=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file3 ]]
then
  IFS=" "
  algorithms="$(cat $file3)"
  if [[ $algorithms ]]
  then
    for line in ${algorithms[@]}
    do
      if [[ $line =~ "MACs" ]]
      then
	found=1
	algorithms="$(echo $line | awk -F= '{print $2}')"
	IFS=','
	for element in ${algorithms[@]}
        do
	  (( y++ ))
	  if [[ ${macalgos[$element]} ]]
	  then
	    x=${macalgos[$element]}
	    if [[ $x < $y ]]
	    then
	      echo -e "${NORMAL}RESULT:    ${BLD}$element${NORMAL}"
	    else
	      echo -e "${NORMAL}RESULT:    ${BLD}$element${RED}-----out of order${NORMAL}"
	      fail=1
	    fi
	  else
	    echo -e "${NORMAL}RESULT:    ${RED}$element${NORMAL}"
	    fail=1
	  fi
	done
      fi
    done
    if [[ $found == 0 ]]
    then
      echo -e "${NORMAL}RESULT:    ${RED}\"MACs\" not defined in $file3${NORMAL}"
      fail=1
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}$file3 is empty${NORMAL}"
    fail=1
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file3 not found${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${GRN}PASSED, The RHEL 8 SSH server is configured to use only Message Authentication Codes (MACs) employing FIPS 140-2 validated cryptographic hash algorithms.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${RED}FAILED, The RHEL 8 SSH server is either not configured to use only Message Authentication Codes (MACs) employing FIPS 140-2 validated cryptographic hash algorithms or the order they are shown in is incorrect.${NORMAL}"
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

file4="/etc/crypto-policies/back-ends/opensshserver.config"

i=0

declare -A cipheralgos
cipheralgos+=( [aes256-ctr]=$(( i++ ))
               [aes192-ctr]=$(( i++ ))
	       [aes128-ctr]=$(( i++ ))
	       [aes256-gcm@openssh.com]=$(( i++ ))
	       [aes128-gcm@openssh.com]=$(( i++ ))
	     )

fail=0
found=0
y=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file4 ]]
then
  IFS=" "
  algorithms="$(cat $file4)"
  if [[ $algorithms ]]
  then
    for line in ${algorithms[@]}
    do
      if [[ $line =~ "Ciphers" ]]
      then
        found=1
        algorithms="$(echo $line | awk -F= '{print $3}')"
        IFS=','
        for element in ${algorithms[@]}
        do
          (( y++ ))
          if [[ ${cipheralgos[$element]} ]]
          then
            x=${cipheralgos[$element]}
            if [[ $x < $y ]]
            then
              echo -e "${NORMAL}RESULT:    ${BLD}$element${NORMAL}"
            else
              echo -e "${NORMAL}RESULT:    ${BLD}$element${RED}-----out of order${NORMAL}"
	      fail=1
            fi
          else
            echo -e "${NORMAL}RESULT:    ${RED}$element${NORMAL}"
            fail=1
          fi
        done
      fi
    done
    if [[ $found == 0 ]]
    then
      echo -e "${NORMAL}RESULT:    ${RED}\"Ciphers\" not defined in $file4${NORMAL}"
      fail=1
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}$file4 is empty${NORMAL}"
    fail=1
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file4 not found${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${GRN}PASSED, The RHEL 8 operating system implements DoD-approved encryption to protect the confidentiality of SSH server connections.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${RED}FAILED, The RHEL 8 operating system either does not implement DoD-approved encryption to protect the confidentiality of SSH server connections or the order that the ciphers are listed is incorrect.${NORMAL}"
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

file5="/etc/pki/tls/openssl.cnf"

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file5 ]]
then
  opensslcnf="$(grep -i opensslcnf.config $file5)"
  if [[ $opensslcnf ]]
  then
    if [[ $opensslcnf =~ '.include' &&
	  $opensslcnf =~ '/etc/crypto-policies/back-ends/opensslcnf.config' ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}a. $opensslcnf${NORMAL}"
      cryptopolicy="$(update-crypto-policies --show)"
      if [[ $cryptopolicy == "FIPS" ]]
      then
	fail=0
	echo -e "${NORMAL}RESULT:    ${BLD}b. $cryptopolicy${NORMAL}"
      else
	echo -e "${NORMAL}RESULT:    ${RED}b. $cryptopolicy${NORMAL}"
      fi
    else
      echo -e "${NORMAL}RESULT:    ${RED}$opensslcnf${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}\"opensslcnf.conf\" is not defined in$file5${NORMAL}"
  fi
else
  echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, ${RED}FAILED, $file5 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${GRN}PASSED, The RHEL 8 operating system implements DoD-approved encryption in the OpenSSL package.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${RED}FAILED, The RHEL 8 operating system implements DoD-approved encryption in the OpenSSL package.${NORMAL}"
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

file6="/etc/crypto-policies/back-ends/opensslcnf.config"
cryptopolicyversion="$(rpm -qa crypto-policies)"

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file6 ]]
then
  minprotocol="$(grep -i minprotocol $file6)"
  if [[ $cryptopolicyversion ]]
  then
    versiondate="$(echo $cryptopolicyversion | awk -F- '{print $3}')"
    echo -e "${NORMAL}RESULT:    ${BLD}The crypto-policies rpm version date is: $versiondate${NORMAL}"
    if (( $versiondate >= 20210617 ))
    then
      if [[ $minprotocol ]]
      then
        for line in ${minprotocol[@]}
        do
          tlsprotoval="$(echo $line | awk -F= '{print $2}' | sed 's/ \+//')"
          if [[ $tlsprotoval == 'TLSv1.2' ]]
          then
            echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
            tlsfound=1
          elif [[ $tlsprotoval == 'DTLSv1.2' ]]
          then
            echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
            dtlsfound=1
          fi
        done
        if [[ $tlsfound == 1 && $dtlsfound == 1 ]]
        then
          fail=0
        fi
      else
        echo -e "${NORMAL}RESULT:    ${RED}'MinProtocol' is not defined in $file11${NORMAL}"
      fi
    else
      if [[ $minprotocol ]]
      then
        for line in ${minprotocol[@]}
        do
          tlsprotoval="$(echo $line | awk -F= '{print $2}')"
          if [[ $tlsprotoval == 'TLSv1.2' ]]
          then
            echo -e "${NORMAL}RESULT:    ${BLD}line${NORMAL}"
            fail=0
          fi
        done
      else
        echo -e "${NORMAL}RESULT:    ${RED}'MinProtocol' is not defined in $file6${NORMAL}"
      fi
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}The crypto-policies package is not installed${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file6 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${GRN}PASSED, The RHEL 8 operating system implements DoD-approved TLS encryption in the OpenSSL package.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${RED}FAILED, The RHEL 8 operating system does not implement DoD-approved TLS encryption in the OpenSSL package.${NORMAL}"
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

file7="/etc/crypto-policies/back-ends/gnutls.config"

declare -A gnuvers
gnuvers+=( [+VERS-ALL]=$(( i++ ))
           [-VERS-DTLS0.9]=$(( i++ ))
           [-VERS-SSL3.0]=$(( i++ ))
           [-VERS-TLS1.0]=$(( i++ ))
           [-VERS-TLS1.1]=$(( i++ ))
           [-VERS-DTLS1.0]=$(( i++ ))
           [+COMP-NULL]=$(( i++ ))
           [%PROFILE_MEDIUM]=$(( i++ ))
         )

fail=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file7 ]]
then
  IFS=":"
  algorithms="$(grep -io +vers.* $file7)"
  if [[ $algorithms ]]
  then
    for element in ${algorithms[@]}
    do
      if [[ ${gnuvers[$element]} ]]
      then
        echo -e "${NORMAL}RESULT:    ${BLD}$element${NORMAL}"
      else
        echo -e "${NORMAL}RESULT:    ${RED}$element${NORMAL}"
        fail=1
      fi
    done
  else
    echo -e "${NORMAL}RESULT:    ${RED}$file7 is empty${NORMAL}"
    fail=1
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file7 not found${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${GRN}PASSED, The RHEL 8 operating system implements DoD-approved TLS encryption in the OpenSSL package.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${RED}FAILED, The "gnutls.config" does not disable all unapproved SSL/TLS versions,${NORMAL}"
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

fwstate="$(firewall-cmd --state)"
fwzonecfg="$(firewall-cmd --get-active-zones)"
fwzone="$(echo $fwzonecfg | awk '{print $1}' | grep -v "^interfaces")"
fwtarget="$(firewall-cmd --info-zone=$fwzone | grep target)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $fwstate == "running" ]]
then
  echo -e "${NORMAL}RESULT:    ${BLD}a. $fwstate${NORMAL}"
  if [[ $fwzonecfg ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}b. $fwzonecfg${NORMAL}"
    if [[ $fwtarget =~ "DROP" ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}c. $fwtarget${NORMAL}"
      fail=0
    else
      echo -e "${NORMAL}RESULT:    ${RED}c. $fwtarget${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}b A firewall zone is not defined${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}a. $fwstate${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cci8, $datetime, ${GRN}PASSED, A RHEL 8 firewall is employs a deny-all allow-by-exception policy for allowing connections to other systems.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cci8, $datetime, ${RED}FAILED, A RHEL 8 firewall does not employ a deny-all allow-by-exception policy for allowing connections to other systems.${NORMAL}"
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

fwinstalled="$(yum list installed firewalld | grep '^firewalld' )"

datetime="$(date +%FT%H:%M:%S)"

if [[ $fwinstalled ]]
then
  echo -e "${NORMAL}RESULT:    ${BLD}$fwinstalled${NORMAL}"
  fail=0
else
  echo -e "${NORMAL}RESULT:    ${BLD}The 'firewalld' package is not installed.${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity9, $controlid, $stigid9, $ruleid9, $cci9, $datetime, ${GRN}PASSED, The firewalld package is installed on RHEL 8.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity9, $controlid, $stigid9, $ruleid9, $cci9, $datetime, ${RED}FAILED, The firewalld package is not installed on RHEL 8.${NORMAL}"
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

file10='/etc/ssh/sshd_config'

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file10 ]]
then
  rekeylimit="$(grep -i ^rekeylimit $file10)"
  if [[ $rekeylimit ]]
  then
    maxdata="$(echo $rekeylimit | awk '{print $2}')"
    if [[ $maxdata ]]
    then
      maxtime="$(echo $rekeylimit | awk '{print $3}')"
      if [[ $maxtime ]]
      then
	echo -e "${NORMAL}RESULT:    ${BLD}$rekeylimit${NORMAL}"
        fail=0
      else
	echo -e "${NORMAL}RESULT:    ${RED}$rekeylimit${NORMAL}"
      fi
    else
      echo -e "${NORMAL}RESULT:    ${RED}$rekeylimit${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}SSH key renegotiation is not configured in $file10.${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file10 not found.${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity10, $controlid, $stigid10, $ruleid10, $cci10, $datetime, ${GRN}PASSED, RHEL 8 forces a frequent session key renegotiation for SSH connections to the server."${NORMAL}
else
  echo -e "${NORMAL}$hostname, $severity10, $controlid, $stigid10, $ruleid10, $cci10, $datetime, ${RED}FAILED, RHEL 8 does not force a frequent session key renegotiation for SSH connections to the server."${NORMAL}
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

file11='/etc/sysconfig/sshd'

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file11 ]]
then
  cryptopolicy="$(grep CRYPTO_POLICY $file11)"
  if [[ ${cryptopolicy} ]]
  then
    for line in ${cryptopolicy[@]}
    do
      if [[ ${line::1} == "#" ]]
      then
	echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
	fail=0
      else
	echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
      fi
    done
  else
    echo -e "${NORMAL}RESULT:    ${RED}\"CRYPTO_POLICY\" is not defined in $file11.${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file11 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity11, $controlid, $stigid11, $ruleid11, $cci11, $datetime, ${GRN}PASSED, The RHEL 8 SSH daemon is configured to use system-wide crypto policies."${NORMAL}
else
  echo -e "${NORMAL}$hostname, $severity11, $controlid, $stigid11, $ruleid11, $cci11, $datetime, ${GRN}FAILED, The RHEL 8 SSH daemon is not configured to use system-wide crypto policies."${NORMAL}
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

fwisactive="$(systemctl is-active firewalld)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $fwisactive == 'active' ]]
then
  echo -e "${NORMAL}RESULT:    ${BLD}$fwisactive${NORMAL}"
  fail=0
else
  echo -e "${NORMAL}RESULT:    ${RED}$fwisactive${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity12, $controlid, $stigid12, $ruleid12, $cci12, $datetime, ${GRN}PASSED, A firewall is active on RHEL 8."${NORMAL}
else
  echo -e "${NORMAL}$hostname, $severity12, $controlid, $stigid12, $ruleid12, $cci12, $datetime, ${GRN}FAILED, A filewall is not active on RHEL 8."${NORMAL}
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
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity13${NORMAL}"

IFS='
'

file13="/etc/crypto-policies/back-ends/opensshserver.config"
i=0

declare -A kexalgos
kexalgos+=( [ecdh-sha2-nistp256]=$(( i++ ))
            [ecdh-sha2-nistp384]=$(( i++ ))
            [ecdh-sha2-nistp521]=$(( i++ ))
            [diffie-hellman-group-exchange-sha256]=$(( i++ ))
            [diffie-hellman-group14-sha256]=$(( i++ ))
            [diffie-hellman-group16-sha512]=$(( i++ ))
            [diffie-hellman-group18-sha512]=$(( i++ ))
	  )

fail=0
found=0
y=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file13 ]]
then
  IFS=" "
  algorithms="$(cat $file13)"
  if [[ $algorithms ]]
  then
    for line in ${algorithms[@]}
    do
      if [[ $line =~ "KexAlgorithms" ]]
      then
	found=1
	algorithms="$(echo $line | awk -F= '{print $2}')"
	IFS=','
	for element in ${algorithms[@]}
	do
	  (( y++ ))
	  if [[ ${kexalgos[$element]} ]]
          then
	    x=${kexalgos[$element]}
            if [[ $x < $y ]]
	    then 
	      echo -e "${NORMAL}RESULT:    ${BLD}$element${NORMAL}"
	    else
	      echo -e "${NORMAL}RESULT:    ${BLD}$element${RED}-----out of order${NORMAL}"
	    fi
	  else
            echo -e "${NORMAL}RESULT:    ${RED}$element${NORMAL}"
	    fail=1
	  fi
	done
      fi
    done
    if [[ $found == 0 ]]
    then
      echo -e "${NORMAL}RESULT:    ${RED}\"KexAlgorithms\" not defined in $file13${NORMAL}"
      fail=1
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}$file13 is empty${NORMAL}"
    fail=1
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file13 not found${NORMAL}"
fi	

if [[ $fail == 1 ]]
then
  echo -e "${NORMAL}$hostname, $severity13, $controlid, $stigid13, $ruleid13, $cci13, $datetime, ${RED}FAILED, The SSH server is not configured to use only FIPS-validated key exchange algorithms - all FIPS-validated algorithms are not shown and/or the algorithms are not listed in the proper order."${NORMAL}
else
  echo -e "${NORMAL}$hostname, $severity13, $controlid, $stigid13, $ruleid13, $cci13, $datetime, ${GRN}PASSED, The SSH server is configured to use only FIPS-validated key exchange algorithms and the algorithms are listed in the proper order."${NORMAL}
fi

exit
