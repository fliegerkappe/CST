#! /bin/bash

# IA-5 Password Management
#
# CONTROL: The organization manages information system authenticators by:
# a. Verifying, as part of the initial authenticator distribution, the identity
#    of the individual, group, role, or device receiving the authenticator;
# b. Establishing initial authenticator content for authenticators defined by
#    the organization;
# c. Ensuring that authenticators have sufficient strength of mechanism for their
#    intended use;
# d. Establishing and implementing administrative procedures for initial authenticator
#    distribution, for lost/compromised or damaged authenticators, and for revoking
#    authenticators;
# e. Changing default content of authenticators prior to information system installation;
# f. Establishing minimum and maximum lifetime restrictions and reuse conditions for
#    authenticators;
# g. Changing/refreshing authenticators [Assignment: organization-defined time
#    period by authenticator type];
# h. Protecting authenticator content from unauthorized disclosure and modification;
# i. Requiring individuals to take, and having devices implement, specific security
#    safeguards to protect authenticators; and
# j. Changing authenticators for group/role accounts when membership to those accounts
#    changes.

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

controlid="IA-5 Password Management"

title1a="RHEL 8, for PKI-based authentication, must validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor."
title1b="Checking with: 'openssl x509 -text -in /etc/sssd/pki/sssd_auth_ca_db.pem'."
title1c="Expecting: ${YLO}
           Certificate:
              Data:
                 Version: 3 (0x2)
                 Serial Number: 1 (0x1)
                 Signature Algorithm: sha256WithRSAEncryption
                 Issuer: C = US, O = U.S. Government, OU = DoD, OU = PKI, CN = DoD Root CA 3
                 Validity
                    Not Before: Mar 20 18:46:41 2012 GMT
                    Not After   : Dec 30 18:46:41 2029 GMT
                 Subject: C = US, O = U.S. Government, OU = DoD, OU = PKI, CN = DoD Root CA 3
                 Subject Public Key Info:
                    Public Key Algorithm: rsaEncryption
           NOTE: If the root ca file is not a DoD-issued certificate with a valid date and installed in the /etc/sssd/pki/sssd_auth_ca_db.pem location, this is a finding."${BLD}
cci1="CCI-000185"
stigid1="RHEL-08-010090"
severity1="CAT II"
ruleid1="SV-230229r858739_rule"
vulnid1="V-230229"

title2a="RHEL 8, for certificate-based authentication, must enforce authorized access to the corresponding private key."
title2b="Checking with: 'ssh-keygen -y -f /path/to/file'."
title2c="Expecting: ${YLO}A prompt to enter a passcode
           NOTE: If the contents of the key are displayed, this is a finding.
	   NOTE: This test will use the default location for the host key, '/etc/ssh/ssh_host_rsa_key'. If any other key is used, check it manually."${BLD}
cci2="CCI-000186"
stigid2="RHEL-08-010100"
severity2="CAT II"
ruleid2="SV-230230r627750_rule"
vulnid2="V-230230"

title3a="RHEL 8 must encrypt all stored passwords with a FIPS 140-2 approved cryptographic hashing algorithm."
title3b="Checking with: 'grep -i crypt /etc/login.defs'."
title3c="Expecting: ${YLO}ENCRYPT_METHOD SHA512
           NOTE: If \"ENCRYPT_METHOD\" does not equal SHA512 or greater, this is a finding."${BLD}
cci3="CCI-000196"
stigid3="RHEL-08-010110"
severity3="CAT II"
ruleid3="SV-230231r877397_rule"
vulnid3="V-230231"

title4a="RHEL 8 must employ FIPS 140-2 approved cryptographic hashing algorithms for all stored passwords."
title4b="Checking with: 'cut -d: -f2 /etc/shadow'."
title4c="Expecting: ${YLO}\$6\$kcOnRq/5\$NUEYPuyL.wghQwWssXRcLRFiiru7f5JPV6GaJhNC2aK5F3PZpE/BCCtwrxRc/AInKMNX3CdMw11m9STiql12f/
           NOTE: Password hashes \"!\" or \"*\" indicate inactive accounts not available for logon and are not evaluated. If any interactive user password hash does not begin with \"\$6\$\", this is a finding."${BLD}
cci4="CCI-000196"
stigid4="RHEL-08-010120"
severity4="CAT II"
ruleid4="SV-230232r877397_rule"
vulnid4="V-230232"

title5a="The RHEL 8 shadow password suite must be configured to use a sufficient number of hashing rounds."
title5b="Checking with: 'egrep \"^SHA_CRYPT_\" /etc/login.defs'."
title5c="Expecting: ${YLO}SHA_CRYPT_MIN_ROUNDS 5000
           NOTE: If only one of \"SHA_CRYPT_MIN_ROUNDS\" or \"SHA_CRYPT_MAX_ROUNDS\" is set, and this value is below \"5000\", this is a finding.
	   NOTE: If both \"SHA_CRYPT_MIN_ROUNDS\" and \"SHA_CRYPT_MAX_ROUNDS\" are set, and the highest value for either is below \"5000\", this is a finding."${BLD}
cci5="CCI-000196"
stigid5="RHEL-08-010130"
severity5="CAT II"
ruleid5="SV-230233r880705_rule"
vulnid5="V-230233"

title6a="RHEL 8 must map the authenticated identity to the user or group account for PKI-based authentication."
title6b="Checking with: 'cat /etc/sssd/sssd.conf'."
title6c="Expecting: ${YLO}
           [sssd]
           config_file_version = 2
           services = pam, sudo, ssh
           domains = testing.test
           
           [pam]
           pam_cert_auth = True
           
           [domain/testing.test]
           id_provider = ldap
           
           [certmap/testing.test/rule_name]
           matchrule =<SAN>.*EDIPI@mil
           maprule = (userCertificate;binary={cert!bin})
           domains = testing.test
           NOTE: If the certmap section does not exist, ask the System Administrator to indicate how certificates are mapped to accounts.  If there is no evidence of certificate mapping, this is a finding."${BLD}
cci6="CCI-000187"
stigid6="RHEL-08-020090"
severity6="CAT II"
ruleid6="SV-230355r858743_rule"
vulnid6="V-230355"

title7a="RHEL 8 must enforce password complexity by requiring that at least one uppercase character be used."
title7b="Checking with 'grep ^ucredit /etc/security/pwquality.conf'."
title7c="Expecting: ${YLO}ucredit = -1
           NOTE: If the value of \"ucredit\" is a positive number or is commented out, this is a finding."${BLD}
cci7="CCI-000192"
stigid7="RHEL-08-020110"
severity7="CAT II"
ruleid7="SV-230357r858771_rule"
vulnid7="V-230357"

title8a="RHEL 8 must enforce password complexity by requiring that at least one lower-case character be used."
title8b="Checking with 'grep ^lcredit /etc/security/pwquality.conf'."
title8c="Expecting: ${YLO}lcredit = -1
           NOTE: If the value of \"lcredit\" is a positive number or is commented out, this is a finding."${BLD}
cci8="CCI-000193"
stigid8="RHEL-08-020120"
severity8="CAT II"
ruleid8="SV-230358r858773_rule"
vulnid8="V-230358"

title9a="RHEL 8 must enforce password complexity by requiring that at least one numeric character be used."
title9b="Checking with 'grep ^dcredit /etc/security/pwquality.conf."
title9c="Expecting: ${YLO}dcredit = -1
           NOTE: If the value of \"dcredit\" is a positive number or is commented out, this is a finding."${BLD}
cci9="CCI-000194"
stigid9="RHEL-08-020130"
severity9="CAT II"
ruleid9="SV-230359r858775_rule"
vulnid9="V-230359"

title10a="RHEL 8 must require the maximum number of repeating characters of the same character class be limited to four when passwords are changed."
title10b="Checking with 'grep maxclassrepeat /etc/security/pwquality.conf'."
title10c="Expecting: ${YLO}maxclassrepeat = 4
           NOTE: If the value of \"maxclassrepeat\" is set to \"0\", more than \"4\", or is commented out, this is a finding."${BLD}
cci10="CCI-000195"
stigid10="RHEL-08-020140"
severity10="CAT II"
ruleid10="SV-230360r858777_rule"
vulnid10="V-230360"

title11a="RHEL 8 must require the maximum number of repeating characters be limited to three when passwords are changed."
title11b="Checking with 'grep maxrepeat /etc/security/pwquality.conf'."
title11c="Expecting: ${YLO}maxrepeat = 3
           NOTE: If the value of \"maxrepeat\" is set to more than \"3\", or is commented out, this is a finding."${BLD}
cci11="CCI-000195"
stigid11="RHEL-08-020150"
severity11="CAT II"
ruleid11="SV-230361r858779_rule"
vulnid11="V-230361"

title12a="RHEL 8 must require the change of at least four character classes when passwords are changed."
title12b="Checking with 'grep minclass /etc/security/pwquality.conf'."
title12c="Expecting: ${YLO}minclass = 4
           NOTE: If the value of \"minclass\" is set to less than \"4\", or is commented out, this is a finding."${BLD}
cci12="CCI-000195"
stigid12="RHEL-08-020160"
severity12="CAT II"
ruleid12="SV-230362r858781_rule"
vulnid12="V-230362"

title13a="RHEL 8 must require the change of at least 8 characters when passwords are changed."
title13b="Checking with 'grep difok /etc/security/pwquality.conf'."
title13c="Expecting: ${YLO}difok = 8 (NOTE: Should be set to half of the required password length)
           NOTE: If the value of \"difok\" is set to less than \"8\", or is commented out, this is a finding."${BLD}
cci13="CCI-000195"
stigid13="RHEL-08-020170"
severity13="CAT II"
ruleid13="SV-230363r858783_rule"
vulnid13="V-230363"

title14a="RHEL 8 passwords must have a 24 hours/1 day minimum password lifetime restriction in /etc/shadow."
title14b="Checking with 'awk -F: '$4 < 1 {print $1 " " $4}' /etc/shadow'."
title14c="Expecting: ${YLO}No results returned. (Note: root is an exception)
           NOTE: If any results are returned that are not associated with a system account, this is a finding."${BLD}
cci14="CCI-000198"
stigid14="RHEL-08-020180"
severity14="CAT II"
ruleid14="SV-230364r627750_rule"
vulnid14="V-230364"

title15a="RHEL 8 passwords for new users or password changes must have a 24 hours/1 day minimum password lifetime restriction in /etc/logins.def."
title15b="Checking with 'grep -i pass_min_days /etc/login.defs'."
title15c="Expecting: ${YLO}PASS_MIN_DAYS 1
           NOTE: If the \"PASS_MIN_DAYS\" parameter value is not \"1\" or greater, or is commented out, this is a finding."${BLD}
cci15="CCI-000198"
stigid15="RHEL-08-020190"
severity15="CAT II"
ruleid15="SV-230365r858727_rule"
vulnid15="V-230365"

title16a="RHEL 8 user account passwords must have a 60-day maximum password lifetime restriction."
title16b="Checking with 'grep PASS_MAX_DAYS /etc/login.defs'."
title16c="Expecting: ${YLO}PASS_MAX_DAYS 60
           NOTE: If the \"PASS_MAX_DAYS\" parameter value is greater than \"60\", or commented out, this is a finding."${BLD}
cci16="CCI-000199"
stigid16="RHEL-08-020200"
severity16="CAT II"
ruleid16="SV-230366r646878_rule"
vulnid16="V-230366"

title17a="RHEL 8 user account passwords must be configured so that existing passwords are restricted to a 60-day maximum lifetime."
title17b="Checking with 'awk -F: '\$5 > 60 {print \$1 " " \$5}' /etc/shadow'"
title17c="Expecting: ${YLO}No results returned.
           NOTE: If any results are returned that are not associated with a system account, this is a finding."${BLD}
cci17="CCI-000199"
stigid17="RHEL-08-020210"
severity17="CAT II"
ruleid17="SV-230367r627750_rule"
vulnid17="V-230367"

title18a="RHEL 8 must be configured in the password-auth file to prohibit password reuse for a minimum of five generations."
title18b="Checking with 'grep -i remember /etc/pam.d/password-auth'."
title18c="Expecting: i${YLO}password required pam_pwhistory.so use_authtok remember=5 retry=3
           NOTE: If the line containing the \"pam_pwhistory.so\" line does not have the \"remember\" module argument set, is commented out, or the value of the \"remember\" module argument is set to less than \"5\", this is a finding."
cci18="CCI-000200"
stigid18="RHEL-08-020220"
severity18="CAT II"
ruleid18="SV-230368r902759_rule"
vulnid18="V-230368"

title19a="RHEL 8 passwords must have a minimum of 15 characters."
title19b="Checking with 'grep minlen /etc/security/pwquality.conf'."
title19c="Expecting: ${YLO}minlen = 15
           NOTE: If the command does not return a \"minlen\" value of 15 or greater, this is a finding."
cci19="CCI-000205"
stigid19="RHEL-08-020230"
severity19="CAT II"
ruleid19="SV-230369r858785_rule"
vulnid19="V-230369"

title20a="RHEL 8 passwords for new users must have a minimum of 15 characters."
title20b="Checking with 'grep -i pass_min_len /etc/login.defs'."
title20c="Expecting: ${YLO}PASS_MIN_LEN 15
           NOTE: If the \"PASS_MIN_LEN\" parameter value is less than \"15\", or commented out, this is a finding."${BLD}
cci20="CCI-000205"
stigid20="RHEL-08-020231"
severity20="CAT II"
ruleid20="SV-230370r627750_rule"
vulnid20="V-230370"

title21a="All RHEL 8 passwords must contain at least one special character."
title21b="Checking with 'grep ocredit /etc/security/pwquality.conf'."
title21c="Expecting: ${YLO}ocredit = -1
           NOTE: If the value of \"ocredit\" is a positive number or is commented out, this is a finding."${BLD}
cci21="CCI-001619"
stigid21="RHEL-08-020280"
severity21="CAT II"
ruleid21="SV-230375r858787_rule"
vulnid21="V-230375"

title22a="RHEL 8 must prohibit the use of cached authentications after one day."
title22b="Checking with: 'grep cache_credentials /etc/sssd/sssd.conf'."
title22c="Expecting: ${YLO}
           a. cache_credentials = true
	   b. grep offline_credentials_expiration  /etc/sssd/sssd.conf
	   NOTE: a. If \"cache_credentials\" is set to \"false\" or missing from the configuration file, this is not a finding and no further checks are required.
	   NOTE: b. If \"cache_credentials\" is set to \"true\", check that SSSD prohibits the use of cached authentications after one day."${BLD}
cci22="CCI-002007"
stigid22="RHEL-08-020290"
severity22="CAT II"
ruleid22="SV-230376r942948_rule"
vulnid22="V-230376"

title23a="RHEL 8 must be configured in the system-auth file to prohibit password reuse for a minimum of five generations."
title23b="Checking with: 'grep -i remember /etc/pam.d/system-auth'."
title23c="Expecting: ${YLO}
           password requisite pam_pwhistory.so use_authtok remember=5 retry=3
	   NOTE: If the line containing \"pam_pwhistory.so\" does not have the \"remember\" module argument set, is commented out, or the value of the \"remember\" module argument is set to less than \"5\", this is a finding."${BLD}
cci23="CCI-000200"
stigid23="RHEL-08-020221"
severity23="CAT II"
ruleid23="SV-251717r902749_rule"
vulnid23="V-251717"

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

file1="/etc/sssd/pki/sssd_auth_ca_db.pem"
fail=1

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file1 ]]
then
  sssdca="$(openssl x509 -text -in $file1 | grep -v "BEGIN" | grep -v "END")"
  if [[ $sssdca ]]
  then
    for line in ${sssdca[@]}
    do
      if [[ $line =~ 'Issuer:' || $line =~ 'Subject:' || 
	    $line =~ 'Public Key' || $line =~ 'Certificate:' ||
	    $line =~ 'Data:' || $line =~ 'Algorithm:' ||
	    $line =~ 'Validity' || $line =~ 'Not Before' ||
	    $line =~ 'Not After' || $line =~ 'Version:' ||
	    $line =~ 'Serial Number:' ]]
      then
	if [[ $line =~ 'Issuer' && $line =~ 'C = US, O = U.S. Government, OU = DoD, OU = PKI, CN = DoD Root CA 3' ]]
	then
	  issuer=1
	  echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
	elif [[ $line =~ 'Subject:' && $line =~ 'C = US, O = U.S. Government, OU = DoD, OU = PKI, CN = DoD Root CA 3' ]]
        then
          subject=1
          echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
	elif [[ $line =~ 'Signature Algorithm' && $line =~ 'sha256WithRSAEncryption' ]]
        then
          sigalgorithm=1
          echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
	elif [[ $line =~ 'Public Key Algorithm' && $line =~ 'rsaEncryption' ]]
        then
          pubkeyalgorithm=1
          echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
	elif [[ $line =~ 'Not Before' && $line =~ 'Mar 20 18:46:41 2012 GMT' ]]
	then
	  notbefore=1
	  echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
	elif [[ $line =~ 'Not After' && $line =~ 'Dec 30 18:46:41 2029 GMT' ]]
	then
	  notafter=1
	  echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
	elif [[ $line =~ 'Serial Number:' || $line =~ 'Version:' || $line =~ 'Certificate' || $line =~ 'Data:' || $line =~ 'Validity' || $line =~ 'Subject Public Key Info:' ]]
	then
	  echo -e "${NORMAL}RESULT:    $line${NORMAL}"
	else
	  echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
	fi
      fi
    done
  else
    echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file1 not found${NORMAL}"
fi

if [[ $issuer == 1 && $subject == 1 && $sigalgorithm == 1 && $pubkeyalgorithm == 1 && $notbefore == 1 && $notafter == 1 ]]
then
  fail=0
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, RHEL 8 for PKI-based authentication validates certificates by constructing a certification path (which includes status information) to an accepted trust anchor.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, RHEL 8 for PKI-based authentication does not validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor.${NORMAL}"
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

echo -e "${NORMAL}RESULT:    1. Have the System Administrator identify the path to all private keys used on the system. ${NORMAL}"
echo -e "${NORMAL}RESULT:    2. Run the command ${YLO}sudo ssh-keygen -y -f </path/to/file>. ${NORMAL}"

echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${CYN}VERIFY, RHEL 8 for certificate-based authentication must enforce authorized access to the corresponding private key.${NORMAL}"

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

file3="/etc/login.defs"

fail=1

encrypt="$(grep -i encrypt_method $file3 | grep -v "^#")"

datetime="$(date +%FT%H:%M:%S)"

if [[ $encrypt ]]
then
  if [[ $encrypt =~ "SHA512" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$encrypt${NORMAL}"
    fail=0
  else
    echo -e "${NORMAL}RESULT:    ${RED}$encrypt${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}\"ENCRYPT_METHOD\" is not defined in $file3${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${GRN}PASSED, RHEL 8 encrypts all stored passwords with a FIPS 140-2 approved cryptographic hashing algorithm.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${RED}FAILED, RHEL 8 does not encrypt all stored passwords with a FIPS 140-2 approved cryptographic hashing algorithm.${NORMAL}"
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

file4="/etc/shadow"

fail=0

users="$(cut -d: -f1,2 $file4)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $users ]]
then
  for line in ${users[@]}
  do
    user="$(echo $line | awk -F: '{print $1}')"
    interactive="$(echo $line | awk -F: '{print $2}')"
    if [[ $interactive != "*" && $interactive != "!!" ]]
    then
      issha512="$(echo ${interactive:0:3})"
      interactive=""
      if [[ $issha512 == "\$6\$" ]]
      then
        echo -e "${NORMAL}RESULT:    ${BLD}$user:$issha512...(password hash omitted)...${NORMAL}"
      else
        echo -e "${NORMAL}RESULT:    ${RED}$user:$issha512...(password hash omitted)...${NORMAL}"
        fail=1
      fi
    fi
  done
  users=""
else
  echo -e "${NORMAL}RESULT:    ${BLD}No interactive user accounts found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${GRN}PASSED, RHEL 8 employs FIPS 140-2 approved cryptographic hashing algorithms for all stored passwords.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${RED}FAILED, RHEL 8 does not employ FIPS 140-2 approved cryptographic hashing algorithms for all stored passwords.${NORMAL}"
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
echo -e "${NORMAL}TEST  5:   ${BLD}$title5a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title5b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title5c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity5${NORMAL}"

IFS='
'

file5="/etc/login.defs"

fail=0

cryptrounds="$(egrep "^SHA_CRYPT_" $file5)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $cryptrounds ]]
then
  if [[ $cryptrounds =~ "SHA_CRYPT_MIN_ROUNDS" || $criptrounds =~ "SHA_CRYPT_MAX_ROUNDS" ]]
  then
    rounds="$(echo $cryptrounds | awk '{print $2}')"
    if (( $rounds >= 5000 ))
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$cryptrounds${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$cryptrounds${NORMAL}"
      fail=1
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}$cryptrounds"${NORMAL}
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}\"SHA_CRYPT_[MIN|MAX]_ROUNDS\" is not defined in $file5."${NORMAL}
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${GRN}PASSED, The RHEL 8 shadow password suite is configured to use a sufficient number of hashing rounds.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${RED}FAILED, The RHEL 8 shadow password suite is not configured to use a sufficient number of hashing rounds.${NORMAL}"
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

file6="/etc/sssd/sssd.conf"

fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file6 ]]
then
  authmap="$(cat $file6)"
  if [[ $authmap ]]
  then
    for line in ${authmap[@]}
    do
      echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
    done
  else
    echo -e "${NORMAL}RESULT:    ${RED}$file6 is empty${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file6 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${GRN}PASSED, RHEL 8 maps the authenticated identity to the user or group account for PKI-based authentication.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${RED}FAILED, RHEL 8 does not map the authenticated identity to the user or group account for PKI-based authentication.${NORMAL}"
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

file7="/etc/security/pwquality.conf"
found=null
fail=1

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file7 ]]
then
   ucredit="$(egrep -i '(^ucredit|^# ucredit)' $file7)"
   if [[ $ucredit ]]
   then
      for line in ${ucredit[@]}
      do
         ucreditval="$(echo $line | awk -F= '{print $2}')"
         if [[ $ucreditval =~ '-' ]] && [[ $line =~ ^ucredit ]]
         then
            echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
            fail=0
         else
            echo -e "${NORMAL}RESULT:    ${NORMAL}$line${NORMAL}"
         fi
      done
      found=$line
   else
      echo -e "${NORMAL}RESULT:    ${BLD}ucredit is not defined in $file7${NORMAL}"
   fi
   if (( $fail == 0 ))
   then
      echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${GRN}PASSED, Password complexity ($found): When passwords are changed or new passwords are assigned the new password must contain at least one upper-case character.${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${RED}FAILED, Password complexity ($found): When passwords are changed or new passwords are assigned the new password does not have to contain at least one upper-case character.${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}$file7 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${RED}FAILED, Password complexity (ucredit): $file7 not found${NORMAL}"
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

file8="/etc/security/pwquality.conf"
found=null
fail=1

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file8 ]]
then
   lcredit="$(egrep -i '(^lcredit|^# lcredit)' $file8)"
   if [[ $lcredit ]]
   then
      for line in ${lcredit[@]}
      do
         lcreditval="$(echo $line | awk -F= '{print $2}')"
         if [[ $lcreditval =~ '-' ]] && [[ $line =~ ^lcredit ]]
         then
            echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
            fail=0
         else
            echo -e "${NORMAL}RESULT:    ${NORMAL}$line${NORMAL}"
         fi
      done
      found=$line
   else
      echo -e "${NORMAL}RESULT:    ${BLD}lcredit is not defined in $file8${NORMAL}"
   fi
   if (( $fail == 0 ))
   then
      echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cci8, $datetime, ${GRN}PASSED, Password complexity ($found): When passwords are changed or new passwords are assigned the new password must contain at least one lower-case character.${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cci8, $datetime, ${RED}FAILED, Password complexity ($found): When passwords are changed or new passwords are assigned the new password does not have to contain at least one lower-case character.${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}$file8 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cci8, $datetime, ${RED}FAILED, Password complexity (lcredit): $file2 not found${NORMAL}"
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

file9="/etc/security/pwquality.conf"
found=null
fail=1

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file9 ]]
then
   dcredit="$(egrep -i '(^dcredit|^# dcredit)' $file9)"
   if [[ $dcredit ]]
   then
      for line in ${dcredit[@]}
      do
         dcreditval="$(echo $line | awk -F= '{print $2}')"
         if [[ $dcreditval =~ '-' ]] && [[ $line =~ ^dcredit ]]
         then
            echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
            fail=0
         else
            echo -e "${NORMAL}RESULT:    ${NORMAL}$line${NORMAL}"
         fi
      done
      found=$line
   else
      echo -e "${NORMAL}RESULT:    ${BLD}dcredit is not defined in $file9${NORMAL}"
   fi
   if (( $fail == 0 ))
   then
      echo -e "${NORMAL}$hostname, $severity9, $controlid, $stigid9, $ruleid9, $cci9, $datetime, ${GRN}PASSED, Password complexity ($found): When passwords are changed or new passwords are assigned the new password must contain at least one numeric character.${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity9, $controlid, $stigid9, $ruleid9, $cci9, $datetime, ${RED}FAILED, Password complexity ($found): When passwords are changed or new passwords are assigned the new password does not have to contain at least one numeric character.${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}$file9 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity9, $controlid, $stigid9, $ruleid9, $cci9, $datetime, ${RED}FAILED, Password complexity (dcredit): $file9 not found${NORMAL}"
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
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity1${NORMAL}"

file10="/etc/security/pwquality.conf"
found=null
fail=1

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file10 ]]
then
   maxclassrepeat="$(egrep -i '(^maxclassrepeat|^# maxclassrepeat)' $file10)"
   if [[ $maxclassrepeat ]]
   then
      for line in ${maxclassrepeat[@]}
      do
         maxval="$(echo $line | awk -F= '{print $2}')"
         if (( $maxval <= 4 )) && [[ $line =~ ^maxclassrepeat ]]
         then
            echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
            fail=0
         else
            echo -e "${NORMAL}RESULT:    ${NORMAL}$line${NORMAL}"
         fi
      done
      found=$line
   else
      echo -e "${NORMAL}RESULT:    ${BLD}maxclassrepeat is not defined in $file10${NORMAL}"
   fi
   if (( $fail == 0 ))
   then
      echo -e "${NORMAL}$hostname, $severity10, $controlid, $stigid10, $ruleid10, $cci10, $datetime, ${GRN}PASSED, Password complexity ($found): When passwords are changed the number of repeating characters of the same character class must not be more than four characters.${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity10, $controlid, $stigid10, $ruleid10, $cci10, $datetime, ${RED}FAILED, Password complexity ($found): When passwords are changed the number of repeating characters of the same character class can be more than four characters.${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}$file10 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity10, $controlid, $stigid10, $ruleid10, $cci10, $datetime, ${RED}FAILED, Password complexity (maxclassrepeat): $file10 not found${NORMAL}"
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

file11="/etc/security/pwquality.conf"
found=null
fail=1

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file11 ]]
then
   maxrepeat="$(egrep -i '(^maxrepeat|^# maxrepeat)' $file11)"
   if [[ $maxrepeat ]]
   then
      for line in ${maxrepeat[@]}
      do
         maxrepeatval="$(echo $line | awk -F= '{print $2}')"
         if (( $maxrepeatval <= 3 )) && [[ $line =~ ^maxrepeat ]]
         then
            echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
            fail=0
         else
            echo -e "${NORMAL}RESULT:    ${NORMAL}$line${NORMAL}"
         fi
      done
      found=$line
   else
      echo -e "${NORMAL}RESULT:    ${BLD}maxrepeat is not defined in $file11${NORMAL}"
   fi
   if (( $fail == 0 ))
   then
      echo -e "${NORMAL}$hostname, $severity11, $controlid, $stigid11, $ruleid11, $cci11, $datetime, ${GRN}PASSED, Password complexity ($found): When passwords are changed the number of repeating consecutive characters must not be more than three characters.${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity11, $controlid, $stigid11, $ruleid11, $cci11, $datetime, ${RED}FAILED, Password complexity ($found): When passwords are changed the number of repeating consecutive characters can be more than three characters.${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}$file11 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity11, $controlid, $stigid11, $ruleid11, $cci11, $datetime, ${RED}FAILED, Password complexity (maxrepeat): $file11 not found${NORMAL}"
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

file12="/etc/security/pwquality.conf"
found=null
fail=1

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file12 ]]
then
   minclass="$(egrep -i '(^minclass|^# minclass)' $file12)"
   if [[ $minclass ]]
   then
      for line in ${minclass[@]}
      do
         minclassval="$(echo $line | awk -F= '{print $2}')"
         if (( $minclassval <= 4 )) && [[ $line =~ ^minclass ]]
         then
            echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
            fail=0
         else
            echo -e "${NORMAL}RESULT:    ${NORMAL}$line${NORMAL}"
         fi
      done
      found=$line
   else
      echo -e "${NORMAL}RESULT:    ${BLD}minclass is not defined in $file12${NORMAL}"
   fi
   if (( $fail == 0 ))
   then
      echo -e "${NORMAL}$hostname, $severity12, $controlid, $stigid12, $ruleid12, $cci12, $datetime, ${GRN}PASSED, Password complexity ($found): When passwords are changed a minimum of four character classes must be changed.${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity12, $controlid, $stigid12, $ruleid12, $cci12, $datetime, ${RED}FAILED, Password complexity ($found): When passwords are changed a minimum of four character class changes is not enforced.${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}$file12 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity12, $controlid, $stigid12, $ruleid12, $cci12, $datetime, ${RED}FAILED, Password complexity (minclass): $file12 not found${NORMAL}"
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


file13="/etc/security/pwquality.conf"
found=null
fail=1

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file13 ]]
then
   difok="$(egrep -i '(^difok|^# difok)' $file13)"
   if [[ $difok ]]
   then
      for line in ${difok[@]}
      do
         difokval="$(echo $line | awk -F= '{print $2}')"
         if (( $difokval >= 8 )) && [[ $line =~ ^difok ]]
         then
            echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
            fail=0
         else
            echo -e "${NORMAL}RESULT:    ${NORMAL}$line${NORMAL}"
         fi
      done
      found=$line
   else
      echo -e "${NORMAL}RESULT:    ${BLD}difok is not defined in $file13${NORMAL}"
   fi
   if (( $fail == 0 ))
   then
      echo -e "${NORMAL}$hostname, $severity13, $controlid, $stigid13, $ruleid13, $cci13, $datetime, ${GRN}PASSED, Password complexity ($found): When passwords are changed a minimum of eight of the total number of characters must be changed.${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity13, $controlid, $stigid13, $ruleid13, $cci13, $datetime, ${RED}FAILED, Password complexity ($found): When passwords are changed a minimum of eight of the total number of characters being changed is not enforced.${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}$file13 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity13, $controlid, $stigid13, $ruleid13, $cci13, $datetime, ${RED}FAILED, Password complexity (difok): $file13 not found${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid14${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid14${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid14${NORMAL}"
echo -e "${NORMAL}CCI:       $cci14${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 14:   ${BLD}$title14a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title14b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title14c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity14${NORMAL}"

file14="/etc/shadow"
fail=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file14 ]]
then
   usrs="$(awk -F: '($2 != "*" && $2 != "!!" && $2 != ".") {print}' $file14)"
   for usr in ${usrs[@]}
   do
      username="$(echo $usr | awk -F: '{print $1}')"
      usrchage="$(echo $usr | awk -F: '{print $4}')"
      if [[ $usrchage ]]
      then
         if (( $usrchage >= 1 ))
         then
            echo -e "${NORMAL}RESULT:    ${BLD}$username's password minimum lifetime is $usrchage${NORMAL}"
         else
            echo -e "${NORMAL}RESULT:    ${RED}$username's password minimum lifetime is $usrchage${NORMAL}"
            fail=1
         fi
      else
         echo -e "${NORMAL}RESULT:    ${RED}$username's password minimum lifetime is $usrchage${NORMAL}"
         fail=1
      fi
   done
   if (( $fail == 0 ))
   then
      echo -e "${NORMAL}$hostname, $severity14, $controlid, $stigid14, $ruleid14, $cci14, $datetime, ${GRN}PASSED, Password lifetime: Passwords are restricted to a 24 hours/1 day minimum lifetime.${NORMAL}"
   else
       echo -e "${NORMAL}$hostname, $severity14, $controlid, $stigid14, $ruleid14, $cci14, $datetime, ${RED}FAILED, Password lifetime: Passwords are not restricted to a 24 hours/1 day minimum lifetime.${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}$file14 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity14, $controlid, $stigid14, $ruleid14, $cci14, $datetime, ${RED}FAILED, Password lifetime: $file14 not found${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid15${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid15${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid15${NORMAL}"
echo -e "${NORMAL}CCI:       $cci15${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 15:   ${BLD}$title15a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title15b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title15c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity15${NORMAL}"

file15="/etc/login.defs"

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file15 ]]
then
   mindays="$(grep ^PASS_MIN_DAYS $file15)"
   if [[ $mindays ]]
   then
      echo -e "${NORMAL}RESULT:    ${BLD}$mindays${NORMAL}"
      mindaysval="$(echo $mindays | awk '{print $2}')"
      if (( $mindaysval >= 1 ))
      then
         echo -e "${NORMAL}$hostname, $severity15, $controlid, $stigid15, $ruleid15, $cci15, $datetime, ${GRN}PASSED, Password lifetime: PASS_MIN_DAYS - Passwords for new users are restricted to a 24 hours/1 day minimum lifetime.${NORMAL}"
      else
         echo -e "${NORMAL}$hostname, $severity15, $controlid, $stigid15, $ruleid15, $cci15, $datetime, ${RED}FAILED, Password lifetime: PASS_MIN_DAYS - Passwords for new users are not restricted to a 24 hours/1 day minimum lifetime.${NORMAL}"
      fi
   else
      echo -e "${NORMAL}RESULT:    ${NORMAL}PASS_MIN_DAYS is not defined in $file15${NORMAL}"
      echo -e "${NORMAL}$hostname, $severity15, $controlid, $stigid15, $ruleid15, $cci15, $datetime, ${RED}FAILED, Password lifetime: PASS_MIN_DAYS is not defined in $file15${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}$file15 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity15, $controlid, $stigid15, $ruleid15, $cci15, $datetime, ${RED}FAILED, Password lifetime: $file15 not found${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid16${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid16${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid16${NORMAL}"
echo -e "${NORMAL}CCI:       $cci16${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 16:   ${BLD}$title16a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title16b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title16c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity16${NORMAL}"

file16="/etc/login.defs"

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file16 ]]
then
   maxdays="$(grep ^PASS_MAX_DAYS $file16)"
   if [[ $maxdays ]]
   then
      echo -e "${NORMAL}RESULT:    ${BLD}$maxdays${NORMAL}"
      maxdaysval="$(echo $maxdays | awk '{print $2}')"
      if (( $maxdaysval <= 60 ))
      then
         echo -e "${NORMAL}$hostname, $severity16, $controlid, $stigid16, $ruleid16, $cci16, $datetime, ${GRN}PASSED, Password lifetime: PASS_MAX_DAYS - Passwords for new users are restricted to a 60-day maximum lifetime.${NORMAL}"
      else
         echo -e "${NORMAL}$hostname, $severity16, $controlid, $stigid16, $ruleid16, $cci16, $datetime, ${RED}FAILED, Password lifetime: PASS_MAX_DAYS - Passwords for new users are not restricted to a 60-day maximum lifetime.${NORMAL}"
      fi
   else
      echo -e "${NORMAL}RESULT:    ${NORMAL}PASS_MAX_DAYS is not defined in $file16${NORMAL}"
      echo -e "${NORMAL}$hostname, $severity16, $controlid, $stigid16, $ruleid16, $cci16, $datetime, ${RED}FAILED, Password lifetime: PASS_MAX_DAYS is not defined in $file16${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}$file16 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity16, $controlid, $stigid16, $ruleid16, $cci16, $datetime, ${RED}FAILED, Password lifetime: $file16 not found${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid17${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid17${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid17${NORMAL}"
echo -e "${NORMAL}CCI:       $cci17${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 17:   ${BLD}$title17a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title17b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title17c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity17${NORMAL}"

file17="/etc/shadow"
fail=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file17 ]]
then
   usrs="$(awk -F: '($2 != "*" && $2 != "!!" && $2 != "." && $5 > 60) {print}' $file17)"
   if [[ ${usrs[@]} > 0 ]]
   then
     for usr in ${usrs[@]}
     do
        username="$(echo $usr | awk -F: '{print $1}')"
        maxpwage="$(echo $usr | awk -F: '{print $5}')"
        if [[ $username != 'root' ]]
        then
           echo -e "${NORMAL}RESULT:    ${RED}$username: Maximum password lifetime = $maxpwage${NORMAL}"
           fail=1
        else
           echo -e "${NORMAL}RESULT:    ${BLD}$username: Maximum password lifetime = $maxpwage${NORMAL}"
        fi
     done
   else
     echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
   fi
   if (( $fail == 0 ))
   then
      echo -e "${NORMAL}$hostname, $severity17, $controlid, $stigid17, $ruleid17, $cci17, $datetime, ${GRN}PASSED, Password lifetime: Existing passwords are restricted to a 60-day maximum lifetime.${NORMAL}"
   else
       echo -e "${NORMAL}$hostname, $severity17, $controlid, $stigid17, $ruleid17, $cci17, $datetime, ${RED}FAILED, Password lifetime: Existing passwords are not restricted to a 60-day maximum lifetime.${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}$file17 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity17, $controlid, $stigid17, $ruleid17, $cci17, $datetime, ${RED}FAILED, Password lifetime: $file17 not found${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid18${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid18${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid18${NORMAL}"
echo -e "${NORMAL}CCI:       $cci18${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 18:   ${BLD}$title18a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title18b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title18c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity18${NORMAL}"

file18="/etc/pam.d/password-auth"
fail=1

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file18 ]]
then
  pwhistory="$(grep -i remember $file18)"
  if [[ $pwhistory ]]
  then
    for line in ${pwhistory[@]}
    do
      if [[ $line =~ 'required' && $line =~ 'pam_pwhistory.so' && $line =~ 'remember' ]]
      then
        IFS=' '
        hist="$(echo $line)"
        for histval in ${hist[@]}
        do
          if [[ $histval =~ 'remember' ]]
          then
            pwhistoryval="$(echo $histval | awk -F= '{print $2}')"
            if (( $pwhistoryval >= 5 ))
            then
              echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
              fail=0
            else
              echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
            fi
          fi
        done
      else
        echo -e "${NORMAL}RESULT:    ${NORMAL}$line${NORMAL}"
      fi
    done
  else
    echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
  fi

  if [[ $fail == 0 ]]
  then
    echo -e "${NORMAL}$hostname, $severity18, $controlid, $stigid18, $ruleid18, $cci18, $datetime, ${GRN}PASSED, Password history: Passwords are prohibited from reuse for a minimum of five generations.${NORMAL}"
  else
    echo -e "${NORMAL}$hostname, $severity18, $controlid, $stigid18, $ruleid18, $cci18, $datetime, ${RED}FAILED, Password history: Passwords are not prohibited from reuse for a minimum of five generations.${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file18 not found${NORMAL}"
  echo -e "${NORMAL}$hostname, $severity18, $controlid, $stigid18, $ruleid18, $cci18, $datetime, ${RED}FAILED, Password history: $file17 not found${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid19${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid19${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid19${NORMAL}"
echo -e "${NORMAL}CCI:       $cci19${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 19:   ${BLD}$title19a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title19b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title19c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity19${NORMAL}"

file19="/etc/security/pwquality.conf"
found=null
fail=1

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file19 ]]
then
   minlen="$(egrep -i '(^minlen|^# minlen)' $file19)"
   if [[ $minlen ]]
   then
      for line in ${minlen[@]}
      do
         minlenval="$(echo $line | awk -F= '{print $2}')"
         if (( $minlenval >= 15 )) && [[ ${line:0:1} != '#' ]]
         then
            echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
            fail=0
         else
            echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
         fi
      done
      found=$line
   else
      echo -e "${NORMAL}RESULT:    ${BLD}minlen is not defined in $file19${NORMAL}"
   fi
   if (( $fail == 0 ))
   then
      echo -e "${NORMAL}$hostname, $severity19, $controlid, $stigid19, $ruleid19, $cci19, $datetime, ${GRN}PASSED, Password complexity ($found): Passwords must be a minimum of 15 characters in length.${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity19, $controlid, $stigid19, $ruleid19, $cci19, $datetime, ${RED}FAILED, Password complexity ($found): Passwords are not restricted to a minimum of 15 characters in length.${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}$file19 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity19, $controlid, $stigid19, $ruleid19, $cci19, $datetime, ${RED}FAILED, Password complexity (minlen): $file19 not found${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid20${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid20${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid20${NORMAL}"
echo -e "${NORMAL}CCI:       $cci20${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 20:   ${BLD}$title20a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title20b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title20c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity20${NORMAL}"

file20="/etc/login.defs"
found=null
fail=1

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file20 ]]
then
   minlen="$(egrep -i pass_min_len $file20)"
   if [[ $minlen ]]
   then
      for line in ${minlen[@]}
      do
         minlenval="$(echo $line | awk '{print $2}')"
         if (( $minlenval >= 15 )) && [[ ${line:0:1} != '#' ]]
         then
            echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
            fail=0
         else
            echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
         fi
      done
      found=$line
   else
      echo -e "${NORMAL}RESULT:    ${BLD}\"PASS_MIN_LEN\" is not defined in $file20${NORMAL}"
   fi
   if (( $fail == 0 ))
   then
      echo -e "${NORMAL}$hostname, $severity20, $controlid, $stigid20, $ruleid20, $cci20, $datetime, ${GRN}PASSED, Password complexity ($found): Passwords must be a minimum of 15 characters in length.${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity20, $controlid, $stigid20, $ruleid20, $cci20, $datetime, ${RED}FAILED, Password complexity ($found): Passwords are not restricted to a minimum of 15 characters in length.${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}$file20 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity20, $controlid, $stigid20, $ruleid20, $cci20, $datetime, ${RED}FAILED, Password complexity (PASS_MIN_LEN): $file20 not found${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid21${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid21${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid21${NORMAL}"
echo -e "${NORMAL}CCI:       $cci21${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 21:   ${BLD}$title21a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title21b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title21c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity21${NORMAL}"

file21="/etc/security/pwquality.conf"
found=null
fail=1

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file21 ]]
then
   ocredit="$(egrep -i '(^ocredit|^# ocredit)' $file21)"
   if [[ $ocredit ]]
   then
      for line in ${ocredit[@]}
      do
         ocreditval="$(echo $line | awk -F= '{print $2}')"
         if [[ $ocreditval =~ '-' ]] && [[ $line =~ ^ocredit ]]
         then
            echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
            fail=0
         else
            echo -e "${NORMAL}RESULT:    ${NORMAL}$line${NORMAL}"
         fi
      done
      found=$line
   else
      echo -e "${NORMAL}RESULT:    ${BLD}ocredit is not defined in $file21${NORMAL}"
   fi
   if (( $fail == 0 ))
   then
      echo -e "${NORMAL}$hostname, $severity21, $controlid, $stigid21, $ruleid21, $cci21, $datetime, ${GRN}PASSED, Password complexity ($found): When passwords are changed or new passwords are assigned the new password must contain at least one special character.${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity21, $controlid, $stigid21, $ruleid21, $cci21, $datetime, ${RED}FAILED, Password complexity ($found): When passwords are changed or new passwords are assigned the new password does not have to contain at least one special character.${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}$file21 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity21, $controlid, $stigid21, $ruleid21, $cci21, $datetime, ${RED}FAILED, Password complexity (ocredit): $file21 not found${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid22${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid22${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid22${NORMAL}"
echo -e "${NORMAL}CCI:       $cci22${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 22:   ${BLD}$title22a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title22b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title22c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity22${NORMAL}"

file22="/etc/sssd/sssd.conf"
fail=1

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file22 ]]
then
  cache="$(grep cache_credentials $file22)"
  if [[ $cache ]]
  then
    cacheval="$(echo $line | awk -F= '{print $2}')"
    if [[ $cacheval == "true" ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}a. $line${NORMAL}"
      offline="$(grep offline_credentials_expiration $file22)"
      if [[ $offline ]]
      then
	offlineval="$(echo $offline | awk -F= '{print $2}')"
	if (( $offlineval == 1 ))
        then
	  echo -e "${NORMAL}RESULT:    ${BLD}b. $offline${NORMAL}"
          fail=0
	else
	  echo -e "${NORMAL}RESULT:    ${RED}b. $offline${NORMAL}"
	fi
      else
	echo -e "${NORMAL}RESULT:    ${RED}$b. \"offline_credentials_expiration\" not defined in $file22${NORMAL}"
      fi
    else
      echo -e "${NORMAL}RESULT:    ${RED}a. $line${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}$b. \"cache_credentials\" not defined in $file22${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file22 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity22, $controlid, $stigid22, $ruleid22, $cci22, $datetime, ${GRN}PASSED, RHEL 8 prohibits the use of cached authentications after one day.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity22, $controlid, $stigid22, $ruleid22, $cci22, $datetime, ${RED}FAILED, RHEL 8 does not prohibit the use of cached authentications after one day.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid23${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid23${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid23${NORMAL}"
echo -e "${NORMAL}CCI:       $cci23${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 23:   ${BLD}$title23a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title23b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title23c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity23${NORMAL}"

file23="/etc/pam.d/system-auth"
fail=1

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file23 ]]
then
  pwhistory="$(grep -i remember $file23)"
  if [[ $pwhistory ]]
  then
    for line in ${pwhistory[@]}
    do
      if [[ $line =~ 'requisite' && $line =~ 'pam_pwhistory.so' && $line =~ 'remember' ]]
      then
        IFS=' '
        hist="$(echo $line)"
        for histval in ${hist[@]}
        do
          if [[ $histval =~ 'remember' ]]
          then
            pwhistoryval="$(echo $histval | awk -F= '{print $2}')"
            if (( $pwhistoryval >= 5 ))
            then
              echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
              fail=0
            else
              echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
            fi
          fi
        done
      else
        echo -e "${NORMAL}RESULT:    ${NORMAL}$line${NORMAL}"
      fi
    done
  else
    echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
  fi

  if [[ $fail == 0 ]]
  then
    echo -e "${NORMAL}$hostname, $severity23, $controlid, $stigid23, $ruleid23, $cci23, $datetime, ${GRN}PASSED, Password history: Passwords are prohibited from reuse for a minimum of five generations.${NORMAL}"
  else
    echo -e "${NORMAL}$hostname, $severity23, $controlid, $stigid23, $ruleid23, $cci23, $datetime, ${RED}FAILED, Password history: Passwords are not prohibited from reuse for a minimum of five generations.${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file23 not found${NORMAL}"
  echo -e "${NORMAL}$hostname, $severity23, $controlid, $stigid23, $ruleid23, $cci23, $datetime, ${RED}FAILED, Password history: $file23 not found${NORMAL}"
fi

exit

