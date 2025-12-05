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

stig="Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Version 3, Release: 10 Benchmark Date: 26 Jan 2023"

hostname="$(uname -n)"

if [[ -f /etc/redhat-release ]]
then
   os="$(cat /etc/redhat-release)"
else
   os="OS not defined"
fi

prog="$(basename $0)"

controlid="IA-5 Password Management"

title1a="The Red Hat Enterprise Linux operating system must be configured so that /etc/pam.d/passwd implements /etc/pam.d/system-auth when changing passwords."
title1b="Checking with: 'cat /etc/pam.d/passwd | grep -i substack | grep -i system-auth'."
title1c="Expecting:${YLO}
           password substack system-auth
           Note: If no results are returned, the line is commented out, this is a finding."${BLD}
cci1="CCI-000192"
stigid1="RHEL-07-010118"
severity1="CAT II"
ruleid1="SV-204405r603261_rule"
vulnid1="V-204405"

title2a="The Red Hat Enterprise Linux operating system must be configured so that when passwords are changed or new passwords are established, pwquality must be used."
title2b="Checking with:
           'cat /etc/pam.d/system-auth | grep pam_pwquality'."
title2c="Expecting:${YLO}
           password required pam_pwquality.so retry=3
           Note: If the command does not return an uncommented line containing the value \"pam_pwquality.so\", this is a finding.
           Note: If the value of \"retry\" is set to \"0\" or greater than \"3\", this is a finding."${BLD}
cci2="CCI-000192"
stigid2="RHEL-07-010119"
severity2="CAT II"
ruleid2="SV-204406r603261_rule"
vulnid2="V-204406"

title3a="The Red Hat Enterprise Linux operating system must be configured so that when passwords are changed or new passwords are established, the new password must contain at least one upper-case character."
title3b="Checking with:
           'grep ucredit /etc/security/pwquality.conf'."
title3c="Expecting:${YLO}
           ucredit = -1
           Note: If the value of \"ucredit\" is not set to a negative value, this is a finding."${BLD}
cci3="CCI-000192"
stigid3="RHEL-07-010120"
severity3="CAT II"
ruleid3="SV-204407r603261_rule"
vulnid3="V-204407"

title4a="The Red Hat Enterprise Linux operating system must be configured so that when passwords are changed or new passwords are established, the new password must contain at least one lower-case character."
title4b="Checking with:
           'grep lcredit /etc/security/pwquality.conf'."
title4c="Expecting:${YLO}
           lcredit = -1
           Note: If the value of \"lcredit\" is not set to a negative value, this is a finding."${BLD}
cci4="CCI-000192"
stigid4="RHEL-07-010130"
severity4="CAT II"
ruleid4="SV-204408r603261_rule"
vulnid4="V-204408"

title5a="The Red Hat Enterprise Linux operating system must be configured so that when passwords are changed or new passwords are assigned, the new password must contain at least one numeric character."
title5b="Checking with:
           'grep ^dcredit /etc/security/pwquality.conf."
title5c="Expecting:${YLO}
           dcredit = -1
           Note: If the value of \"dcredit\" is not set to a negative value, this is a finding."${BLD}
cci5="CCI-000194"
stigid5="RHEL-07-010140"
severity5="CAT II"
ruleid5="SV-204409r603261_rule"
vulnid5="V-204409"

title6a="The Red Hat Enterprise Linux operating system must be configured so that when passwords are changed or new passwords are established, the new password must contain at least one special character."
title6b="Checking with:
           'grep ocredit /etc/security/pwquality.conf'."
title6c="Expecting:${YLO}
           ocredit = -1
           Note: If the value of \"ocredit\" is not set to a negative value, this is a finding."${BLD}
cci6="CCI-000619"
stigid6="RHEL-07-010150"
severity6="CAT II"
ruleid6="SV-204410r603261_rule"
vulnid6="V-204410"

title7a="The Red Hat Enterprise Linux operating system must be configured so that when passwords are changed a minimum of eight of the total number of characters must be changed."
title7b="Checking with:
           'grep difok /etc/security/pwquality.conf'"
title7c="Expecting:${YLO}
           difok = 8 (NOTE: Should be set to half of the required password length)
           Note: If the value of \"difok\" is set to less than \"8\", this is a finding."${BLD}
cci7="CCI-000192"
stigid7="RHEL-07-010160"
severity7="CAT II"
ruleid7="SV-204411r603261_rule"
vulnid7="V-204411"

title8a="The Red Hat Enterprise Linux operating system must be configured so that when passwords are changed a minimum of four character classes must be changed."
title8b="Checking with:
           'grep minclass /etc/security/pwquality.conf'"
title8c="Expecting:${YLO}
           minclass = 4
           Note: If the value of \"minclass\" is set to less than \"4\", this is a finding."${BLD}
cci8="CCI-000195"
stigid8="RHEL-07-010170"
severity8="CAT II"
ruleid8="SV-204412r603261_rule"
vulnid8="V-204412"

title9a="The Red Hat Enterprise Linux operating system must be configured so that when passwords are changed the number of repeating consecutive characters must not be more than three characters."
title9b="Checking with:
           'grep maxrepeat /etc/security/pwquality.conf'"
title9c="Expecting:${YLO}
           maxrepeat = 3
           Note: If the value of \"maxrepeat\" is set to more than \"3\", this is a finding."${BLD}
cci9="CCI-000195"
stigid9="RHEL-07-010180"
severity9="CAT II"
ruleid9="SV-204413r603261_rule"
vulnid9="V-204413"

title10a="The Red Hat Enterprise Linux operating system must be configured so that when passwords are changed the number of repeating characters of the same character class must not be more than four characters."
title10b="Checking with:
           'grep maxclassrepeat /etc/security/pwquality.conf'."
title10c="Expecting:${YLO}
           maxclassrepeat = 4
           Note: If the value of \"maxclassrepeat\" is set to more than \"4\", this is a finding."${BLD}
cci10="CCI-000195"
stigid10="RHEL-07-010190"
severity10="CAT II"
ruleid10="SV-204414r809186_rule"
vulnid10="V-204414"

title11a="The Red Hat Enterprise Linux operating system must be configured so that the PAM system service is configured to store only encrypted representations of passwords."
title11b="Checking with:
           'grep password /etc/pam.d/system-auth /etc/pam.d/password-auth'."
title11c="Expecting:${YLO}
          /etc/pam.d/system-auth-ac:password    sufficient    pam_unix.so sha512 shadow try_first_pass use_authtok
          /etc/pam.d/password-auth:password     sufficient    pam_unix.so sha512 shadow try_first_pass use_authtok

           Note: If the \"/etc/pam.d/system-auth\" and \"/etc/pam.d/password-auth\" configuration files allow for password hashes other than SHA512 to be used, this is a finding."
cci11="CCI-000195"
stigid11="RHEL-07-010200"
severity11="CAT II"
ruleid11="SV-204415r603261_rule"
vulnid11="V-204415"

title12a="The Red Hat Enterprise Linux operating system must be configured to use the shadow file to store only encrypted representations of passwords."
title12b="Checking with:
           'grep -i encrypt_method' /etc/login.defs'"
title12c="Expecting:${YLO}
           ENCRYPT_METHOD SHA512
           Note: If the \"/etc/login.defs\" configuration file does not exist or allows for password hashes other than SHA512 to be used, this is a finding."${BLD}
cci12="CCI-000196"
stigid12="RHEL-07-010210"
severity12="CAT II"
ruleid12="SV-204416r603261_rule"
vulnid12="V-204416"

title13a="The Red Hat Enterprise Linux operating system must be configured so that user and group account administration utilities are configured to store only encrypted representations of passwords."
title13b="Checking with:
           'grep -i sha512 /etc/libuser.conf '."
title13c="Expecting:${YLO}
           crypt_style = sha512
           Note: If the \"crypt_style\" variable is not set to \"sha512\", is not in the defaults section, is commented out, or does not exist, this is a finding."${BLD}
cci13="CCI-000196"
stigid13="RHEL-07-010220"
severity13="CAT II"
ruleid13="SV-204417r603261_rule"
vulnid13="V-204417"

title14a="The Red Hat Enterprise Linux operating system must be configured so that passwords for new users are restricted to a 24 hours/1 day minimum lifetime."
title14b="Checking with:
           'grep -i pass_min_days /etc/login.defs'."
title14c="Expecting:${YLO}
           PASS_MIN_DAYS 1
           Note: If the \"PASS_MIN_DAYS\" parameter value is not \"1\" or greater, or is commented out, this is a finding."${BLD}
cci14="CCI-000198"
stigid14="RHEL-07-010230"
severity14="CAT II"
ruleid14="SV-204418r603261_rule"
vulnid14="V-204418"

title15a="The Red Hat Enterprise Linux operating system must be configured so that passwords are restricted to a 24 hours/1 day minimum lifetime."
title15b="Checking with:
           'awk -F: \'\$4 < 1 {print \$1 \" \" \$4}\' /etc/shadow'."
title15c="Expecting:${YLO}
           No results returned.
	   Note: If any results are returned that are not associated with a system account, this is a finding."${BLD}
cci15="CCI-000198"
stigid15="RHEL-07-010240"
severity15="CAT II"
ruleid15="SV-204419r603261_rule"
vulnid15="V-204419"

title16a="The Red Hat Enterprise Linux operating system must be configured so that passwords for new users are restricted to a 60-day maximum lifetime."
title16b="Checking with:
           'grep -i pass_max_days /etc/login.defs'."
title16c="Expecting:${YLO}
           PASS_MAX_DAYS 60
           Note: If the \"PASS_MAX_DAYS\" parameter value is not \"60\" or less, or is commented out, this is a finding."${BLD}
cci16="CCI-000199"
stigid16="RHEL-07-010250"
severity16="CAT II"
ruleid16="SV-204420r603261_rule"
vulnid16="V-204420"

title17a="The Red Hat Enterprise Linux operating system must be configured so that existing passwords are restricted to a 60-day maximum lifetime."
title17b="Checking with:
           'awk -F: \'\$5 > 60 {print \$1 " " \$5}\' /etc/shadow'"
title17c="Expecting:${YLO}
           No results returned.
           Note: If any results are returned that are not associated with a system account, this is a finding."${BLD}
cci17="CCI-000199"
stigid17="RHEL-07-010260"
severity17="CAT II"
ruleid17="SV-204421r603261_rule"
vulnid17="V-204421"

title18a="The Red Hat Enterprise Linux operating system must be configured so that passwords are prohibited from reuse for a minimum of five generations."
title18b="Checking with:
           'grep -i remember /etc/pam.d/system-auth /etc/pam.d/password-auth'."
title18c="Expecting:${YLO}
           password     requisite     pam_pwhistory.so use_authtok remember=5 retry=3
           Note: If the line containing the \"pam_pwhistory.so\" line does not have the \"remember\" module argument set, is commented out, or the value of the \"remember\" module argument is set to less than \"5\", this is a finding."${BLD}
cci18="CCI-000200"
stigid18="RHEL-07-010270"
severity18="CAT II"
ruleid18="SV-204422r603261_rule"
vulnid18="V-204422"

title19a="The Red Hat Enterprise Linux operating system must be configured so that passwords are a minimum of 15 characters in length."
title19b="Checking with:
           'grep minlen /etc/security/pwquality.conf'."
title19c="Expecting:${YLO}
           minlen = 15
           Note: If the command does not return a \"minlen\" value of 15 or greater, this is a finding."${BLD}
cci19="CCI-000205"
stigid19="RHEL-07-010280"
severity19="CAT II"
ruleid19="SV-204423r603261_rule"
vulnid19="V-204423"

title20a="The Red Hat Enterprise Linux operating system must be configured so that the SSH daemon is configured to only use the SSHv2 protocol."
title20b="Checking with:
           'grep -i protocol /etc/ssh/sshd_config'."
title20c="Expecting:${YLO}
           Protocol 2
           Note: If the release is 7.4 or newer this requirement is Not Applicable.
           Note: If any protocol line other than \"Protocol 2\" is uncommented, this is a finding."${BLD}
cci20="CCI-000197"
stigid20="RHEL-07-040390"
severity20="CAT II"
ruleid20="SV-204594r603261_rule"
vulnid20="V-204594"

title21a="The Red Hat Enterprise Linux operating system must be configured to prevent overwriting of custom authentication configuration settings by the authconfig utility."
title21b="Checking with:
           'ls -l /etc/pam.d/{password,system}-auth'"
title21c="Expecting:${YLO}
           lrwxrwxrwx. 1 root root 30 Apr 1 11:59 /etc/pam.d/password-auth -> /etc/pam.d/password-auth-local
           lrwxrwxrwx. 1 root root 28 Apr 1 11:59 /etc/pam.d/system-auth -> /etc/pam.d/system-auth-local
	   Note: If system-auth and password-auth files are not symbolic links, this is a finding.
           Note: If system-auth and password-auth are symbolic links but do not point to \"system-auth-local\" and \"password-auth-local\", this is a finding."${BLD}
cci21="CCI-000196"
stigid21="RHEL-07-010199"
severity21="CAT II"
ruleid21="SV-255928r880830_rule"
vulnid21="V-255928"

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

file1="/etc/pam.d/passwd"
fail=1

IFS='
'

datetime="$(date +%FT%H?%M:%S)"

if [[ -f $file1 ]]
then
   passwd="$(cat $file1 | grep -i substack | grep -i system-auth)"
   if [[ $passwd ]]
   then
      for line in ${passwd[@]}
      do
         if [[ $line =~ 'password' && $line =~ 'substack' && $line =~ 'system-auth' ]]
         then
            echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
            fail=0
         else
            echo -e "${NORMAL}RESULT:    $line${NORMAL}"
         fi
      done
   fi
   if [[ $fail == 0 ]]
   then
      echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, The operating system is configured so that /etc/pam.d/passwd implements /etc/pam.d/system-auth when changing passwords${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, The operating system is not configured so that /etc/pam.d/passwd implements /etc/pam.d/system-auth when changing passwords${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}$file1 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, Password SYSTEM-AUTH: $file1 not found${NORMAL}"
fi

echoecho -e "${NORMAL}RESULT:    ${RED}$file15 not found${NORMAL}"
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

file2="/etc/pam.d/system-auth"
fail=1

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file2 ]]
then
   pwquality="$(cat $file2 | grep pam_pwquality.so)"
   if [[ $pwquality ]]
   then
      for line in ${pwquality[@]}
      do
         if [[ ($line =~ 'requisite' || $line =~ 'required') && $line =~ 'retry=3' ]]
         then
            echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
            fail=0
         else
            echo -e "${NORMAL}RESULT:    $line${NORMAL}"
         fi
      done
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}$file2 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, When passwords are changed or new passwords are established pwquality is used.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, When passwords are changed or new passwords are established pwquality is not used.${NORMAL}"
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

datetime="$(date +%FT%H?%M:%S)"

file3="/etc/security/pwquality.conf"
fail=1

if [[ -f $file3 ]]
then
   ucredit="$(grep ucredit $file3)"
   if [[ $ucredit ]]
   then
      for line in ${ucredit[@]}
      do
         val="$(echo $line | awk -F'= ' '{print $2}')"
         if [[ ${line:0:1} != '#' && ${val:0:1} == '-' ]]
         then
            echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
            fail=0
         else
            echo -e "${NORMAL}RESULT:    $line${NORMAL}"
         fi
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}\"ucredit\" is not defined in $file3${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}$file3 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${GRN}PASSED, When passwords are changed or new passwords are assigned the new password must contain at least one upper-case character.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${RED}FAILED, When passwords are changed or new passwords are assigned the new password does not have to contain at least one upper-case character.${NORMAL}"
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

datetime="$(date +%FT%H?%M:%S)"

file4="/etc/security/pwquality.conf"
fail=1

if [[ -f $file4 ]]
then
   lcredit="$(grep lcredit $file4)"
   if [[ $lcredit ]]
   then
      for line in ${lcredit[@]}
      do
         val="$(echo $line | awk -F'= ' '{print $2}')"
         if [[ ${line:0:1} != '#' && ${val:0:1} == '-' ]]
         then
            echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
            fail=0
         else
            echo -e "${NORMAL}RESULT:    $line${NORMAL}"
         fi
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}lcredit is not defined in $file4${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}$file4 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${GRN}PASSED, When passwords are changed or new passwords are assigned the new password must contain at least one lower-case character.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${RED}FAILED, When passwords are changed or new passwords are assigned the new password does not have to contain at least one lower-case character.${NORMAL}"
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

datetime="$(date +%FT%H?%M:%S)"

file5="/etc/security/pwquality.conf"
fail=1

if [[ -f $file5 ]]
then
   dcredit="$(grep dcredit $file5)"
   if [[ $dcredit ]]
   then
      for line in ${dcredit[@]}
      do
         val="$(echo $line | awk -F'= ' '{print $2}')"
         if [[ ${line:0:1} != '#' && ${val:0:1} == '-' ]]
         then
            echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
            fail=0
         else
            echo -e "${NORMAL}RESULT:    $line${NORMAL}"
         fi
      done
      found=$line
   else
      echo -e "${NORMAL}RESULT:    ${RED}dcredit is not defined in $file5${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}$file5 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${GRN}PASSED, When passwords are changed or new passwords are assigned the new password must contain at least one numeric character.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${RED}FAILED, When passwords are changed or new passwords are assigned the new password does not have to contain at least one numeric character.${NORMAL}"
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

datetime="$(date +%FT%H?%M:%S)"

file6="/etc/security/pwquality.conf"
fail=1

if [[ -f $file6 ]]
then
   ocredit="$(grep ocredit $file6)"
   if [[ $ocredit ]]
   then
      for line in ${ocredit[@]}
      do
         val="$(echo $line | awk -F'= ' '{print $2}')"
         if [[ ${line:0:1} != '#' && ${val:0:1} == '-' ]]
         then
            echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
            fail=0
         else
            echo -e "${NORMAL}RESULT:    $line${NORMAL}"
         fi
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}ocredit is not defined in $file6${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}$file6 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${GRN}PASSED, When passwords are changed or new passwords are assigned the new password must contain at least one special character.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${RED}FAILED, When passwords are changed or new passwords are assigned the new password does not have to contain at least one special character.${NORMAL}"
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

datetime="$(date +%FT%H?%M:%S)"

file7="/etc/security/pwquality.conf"
fail=1

if [[ -f $file7 ]]
then
   difok="$(grep difok $file7)"
   if [[ $difok ]]
   then
      for line in ${difok[@]}
      do
         val="$(echo $line | awk -F'= ' '{print $2}')"
	 if [[ ${line:0:1} != '#' ]] && (( $val >= 8 ))
         then
            echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
            fail=0
         else
            echo -e "${NORMAL}RESULT:    $line${NORMAL}"
         fi
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}difok is not defined in $file7${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}$file7 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${GRN}PASSED, When passwords are changed a minimum of eight of the total number of characters must be changed.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${RED}FAILED, When passwords are changed a minimum of eight of the total number of characters being changed is not enforced.${NORMAL}"
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

datetime="$(date +%FT%H?%M:%S)"

file8="/etc/security/pwquality.conf"
fail=1

if [[ -f $file8 ]]
then
   minclass="$(grep minclass $file8)"
   if [[ $minclass ]]
   then
      for line in ${minclass[@]}
      do
         val="$(echo $line | awk -F'= ' '{print $2}')"
         if [[ ${line:0:1} != '#' ]] && (( $val <= 4 ))
         then
            echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
            fail=0
         else
            echo -e "${NORMAL}RESULT:    $line${NORMAL}"
         fi
      done
      found=$line
   else
      echo -e "${NORMAL}RESULT:    ${RED}minclass is not defined in $file8${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}$file6 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cci8, $datetime, ${GRN}PASSED, When passwords are changed a minimum of four character classes must be changed.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cci8, $datetime, ${RED}FAILED, When passwords are changed a minimum of four character class changes is not enforced.${NORMAL}"
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

datetime="$(date +%FT%H?%M:%S)"

file9="/etc/security/pwquality.conf"

if [[ -f $file9 ]]
then
   maxrepeat="$(grep maxrepeat $file9)"
   if [[ $maxrepeat ]]
   then
      for line in ${maxrepeat[@]}
      do
         val="$(echo $line | awk -F'= ' '{print $2}')"
         if [[ ${line:0:1} != '#' ]] && (( $val <= 3 ))
         then
            echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
            fail=0
         else
            echo -e "${NORMAL}RESULT:    $line${NORMAL}"
         fi
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}maxrepeat is not defined in $file9${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}$file9 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity9, $controlid, $stigid9, $ruleid9, $cci9, $datetime, ${GRN}PASSED, When passwords are changed the number of repeating consecutive characters must not be more than three characters.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity9, $controlid, $stigid9, $ruleid9, $cci9, $datetime, ${RED}FAILED, When passwords are changed the number of repeating consecutive characters can be more than three characters.${NORMAL}"
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

datetime="$(date +%FT%H?%M:%S)"

file10="/etc/security/pwquality.conf"
fail=1

if [[ -f $file10 ]]
then
   maxclassrepeat="$(grep maxclassrepeat $file10)"
   if [[ $maxclassrepeat ]]
   then
      for line in ${maxclassrepeat[@]}
      do
         val="$(echo $line | awk -F'= ' '{print $2}')"
         if [[ ${line:0:1} != '#' ]] && (( $val <= 4 ))
         then
            echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
            fail=0
         else
            echo -e "${NORMAL}RESULT:    $line${NORMAL}"
         fi
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}maxclassrepeat is not defined in $file10${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}$file10 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity10, $controlid, $stigid10, $ruleid10, $cci10, $datetime, ${GRN}PASSED, When passwords are changed the number of repeating characters of the same character class must not be more than four characters.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity10, $controlid, $stigid10, $ruleid10, $cci10, $datetime, ${RED}FAILED, When passwords are changed the number of repeating characters of the same character class can be more than four characters.${NORMAL}"
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

datetime="$(date +%FT%H?%M:%S)"

file11arr=('/etc/pam.d/system-auth' '/etc/pam.d/password-auth')
fail=1

for file in ${file11arr[@]}
do
   if [[ -f $file ]]
   then
      echo "$file---------------------------------------------------------------------------"
      pwencrypt="$(grep password $file)"
      if [[ $pwencrypt ]]
      then
         for line in ${pwencrypt[@]}
         do
            if [[ $line =~ 'sufficient' && $line =~ 'sha512' ]]
            then
               echo -e "${NORMAL}RESULT:    ${GRN}$line${NORMAL}"
               fail=0
            else
               echo -e "${NORMAL}RESULT:    $line${NORMAL}"
            fi
         done
      else
	 echo -e "${NORMAL}RESULT:    ${RED}missing \"sufficient\" with \"sha512\"${NORMAL}"
      fi
   else
      echo -e "${NORMAL}RESULT:    ${RED}$file not found${NORMAL}"
   fi
done

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity11, $controlid, $stigid11, $ruleid11, $cci11, $datetime, ${GRN}PASSED, The PAM system service is configured to store only encrypted representations of passwords.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity11, $controlid, $stigid11, $ruleid11, $cci11, $datetime, ${RED}FAILED, The PAM system service is not configured to store only encrypted representations of passwords.${NORMAL}"
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

datetime="$(date +%FT%H?%M:%S)"

file12="/etc/login.defs"
fail=1

if [[ -f $file12 ]]
then
   emethod="$(grep -i encrypt $file12)"
   if [[ $emethod ]]
   then
      for line in ${emethod[@]}
      do
         val="$(echo $line | awk '{print $2}')"
         if [[ $val ]]
         then
            if [[ $val == 'SHA512' ]]
            then
	       echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
	       fail=0
	    else
	       echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
	    fi
	 else
            echo -e "${NORMAL}RESULT:    ${NORMAL}ENCRYPT_METHOD is blank $file12${NORMAL}"
	 fi
      done
   else
      echo -e "${NORMAL}RESULT:    ${NORMAL}ENCRYPT_METHOD is not defined in $file12${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}$file12 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity12, $controlid, $stigid12, $ruleid12, $cci12, $datetime, ${GRN}PASSED, The shadow file is configured to store only encrypted representations of passwords.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity12, $controlid, $stigid12, $ruleid12, $cci12, $datetime, ${RED}FAILED, The shadow file is not configured to store only encrypted representations of passwords.${NORMAL}"
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

datetime="$(date +%FT%H?%M:%S)"

file13="/etc/libuser.conf"
fail=1

if [[ -f $file13 ]]
then
   cstyle="$(grep crypt_style $file13)"
   if [[ $cstyle ]]
   then
      val="$(echo $cstyle | awk -F'= ' '{print $2}')"
      if [[ $val =~ 'sha512' ]]
      then
         echo -e "${NORMAL}RESULT:    ${BLD}$cstyle${NORMAL}"
	 fail=0
      else
	 echo -e "${NORMAL}RESULT:    ${RED}$cstyle${NORMAL}"
      fi
   else
      echo -e "${NORMAL}RESULT:    ${NORMAL}crypt_style is not defined in $file13${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}$file13 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity13, $controlid, $stigid13, $ruleid13, $cci13, $datetime, ${GRN}PASSED, User and group account administration utilities are configured to store only encrypted representations of passwords.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity13, $controlid, $stigid13, $ruleid13, $cci13, $datetime,${RED}FAILED, User and group account administration utilities are not configured to store only encrypted representations of passwords.${NORMAL}"
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

IFS='
'

datetime="$(date +%FT%H?%M:%S)"

file14="/etc/login.defs"
fail=1

if [[ -f $file14 ]]
then
   mindays="$(grep -i pass_min_days $file14 | tr -s ' ')"
   if [[ $mindays ]]
   then
      for line in ${mindays[@]}
      do
	 val="$(echo $mindays | awk '{print $2}')"
         if [[ ${line:0:1} != '#' ]] && (( $val >= 1 ))
         then
   	    echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
   	    fail=0
         else
   	    echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
         fi
      done
   else
      echo -e "${NORMAL}RESULT:    ${NORMAL}PASS_MIN_DAYS is not defined in $file14${NORMAL}"
   fi
else
   echo -e         name="$(echo $usr | awk '{print $1}')"
         minlife="$(echo $user | awk '{print $2}')"
 "${NORMAL}RESULT:    ${RED}$file12 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity14, $controlid, $stigid14, $ruleid14, $cci14, $datetime, ${GRN}PASSED, Password lifetime: PASS_MIN_DAYS - Passwords for new users are restricted to a 24 hours/1 day minimum lifetime.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity14, $controlid, $stigid14, $ruleid14, $cci14, $datetime, ${RED}FAILED, Password lifetime: PASS_MIN_DAYS - Passwords for new users are not restricted to a 24 hours/1 day minimum lifetime.${NORMAL}"
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

IFS='
'

datetime="$(date +%FT%H?%M:%S)"

file15="/etc/shadow"
fail=0

if [[ -f $file15 ]]
then
   usrs="$(awk -F: '$4 < 1 && ($2 != "*" && $2 != "!!" && $2 != ".") {print $1, $4}' $file15)"
   if [[ $usrs ]]
   then
      for usr in ${usrs[@]}
      do
	 name="$(echo $usr | awk '{print $1}')"
	 minlife="$(echo $usr | awk '{print $2}')"
         echo -e "${NORMAL}RESULT:    ${RED}$name's password minimum lifetime is \"$minlife\"${NORMAL}"
	 fail=1
      done
   else
      echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}$file15 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity15, $controlid, $stigid15, $ruleid15, $cci15, $datetime, ${GRN}PASSED, Passwords are restricted to a 24 hours/1 day minimum lifetime.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity15, $controlid, $stigid15, $ruleid15, $cci15, $datetime, ${RED}FAILED, Passwords are not restricted to a 24 hours/1 day minimum lifetime.${NORMAL}"
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

IFS='
'

datetime="$(date +%FT%H?%M:%S)"

file16="/etc/login.defs"
fail=0

if [[ -f $file16 ]]
then
   maxdays="$(grep -i pass_max_days $file16 | tr -s ' ')"
   if [[ $mindays ]]
   then
      for line in ${maxdays[@]}
      do
         val="$(echo $line | awk '{print $2}')"
         if [[ ${line:0:1} != '#' ]] && 
            (( $val >= 1 && $val <= 60 ))
         then
            echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
            fail=0
         else
            echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
         fi
      done
   else
      echo -e "${NORMAL}RESULT:    ${NORMAL}Nothing returned${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}$file16 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity16, $controlid, $stigid16, $ruleid16, $cci16, $datetime, ${GRN}PASSED, Passwords for new users are restricted to a 60-day maximum lifetime.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity16, $controlid, $stigid16, $ruleid16, $cci16, $datetime, ${RED}FAILED, Passwords for new users are not restricted to a 60-day maximum lifetime.${NORMAL}"
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

IFS='
'

datetime="$(date +%FT%H?%M:%S)"

file17="/etc/shadow"
fail=0

if [[ -f $file17 ]]
then
   usrs="$(awk -F: '$5 > 60 && ($2 != "*" && $2 != "!!" && $2 != ".") {print $1, $5}' $file17)"
   if [[ $usrs ]]
   then
      for usr in ${usrs[@]}
      do
         name="$(echo $usr | awk '{print $1}')"
         maxpwage="$(echo $usr | awk '{print $2}')"
         echo -e "${NORMAL}RESULT:    ${RED}$name's maximum password lifetime = $maxpwage${NORMAL}"
         fail=1
      done
   else
      echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}$file17 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity17, $controlid, $stigid17, $ruleid17, $cci17, $datetime, ${GRN}PASSED, Existing passwords are restricted to a 60-day maximum lifetime.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity17, $controlid, $stigid17, $ruleid17, $cci17, $datetime, ${RED}FAILED, Existing passwords are not restricted to a 60-day maximum lifetime.${NORMAL}"
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

IFS='
'

datetime="$(date +%FT%H?%M:%S)"

file18arr=('/etc/pam.d/system-auth' '/etc/pam.d/password-auth')
fail=1

for file in ${file18arr[@]}
do
   if [[ -f $file ]]
   then
      echo "$file---------------------------------------------------------------------------"
      pwremember="$(grep remember $file)"
      if [[ $pwremember ]]
      then
         for line in ${pwremember[@]}
         do
	    IFS=' ' read -a element <<< $line
	    for el in ${element[@]}
	    do
	       if [[ $el =~ 'remember' ]]
	       then
		  val="$(echo $el | awk -F= '{print $2}')"
                  if [[ ${line:0:1} != '#' && $line =~ 'pam_pwhistory.so' ]] && (( $val >= 5 ))
	          then
                     echo -e "${NORMAL}RESULT:    ${GRN}$line${NORMAL}"
                     fail=0
                  else
                     echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
                  fi
	       else
		  echo -e "${NORMAL}RESULT:    $line${NORMAL}"
	       fi
	    done
         done
      else
         echo -e "${NORMAL}RESULT:    ${RED}missing \"password\" with \"remember\"${NORMAL}"
      fi
   else
      echo -e "${NORMAL}RESULT:    ${RED}$file not found${NORMAL}"
   fi
done

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity18, $controlid, $stigid18, $ruleid18, $cci18, $datetime, ${GRN}PASSED, Passwords are prohibited from reuse for a minimum of five generations.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity18, $controlid, $stigid18, $ruleid18, $cci18, $datetime, ${RED}FAILED, Passwords are not prohibited from reuse for a minimum of five generations.${NORMAL}"
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

IFS='
'

datetime="$(date +%FT%H?%M:%S)"

file19="/etc/security/pwquality.conf"
fail=1

if [[ -f $file19 ]]
then
   minlen="$(grep minlen $file19)"
   if [[ $minlen ]]
   then
      for line in ${minlen[@]}
      do
         val="$(echo $line | awk -F'= ' '{print $2}')"
         if [[ ${line:0:1} != '#' ]] && (( $val >= 15 ))
         then
            echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
            fail=0
         else
            echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
         fi
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}minlen is not defined in $file19${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}$file19 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity19, $controlid, $stigid19, $ruleid19, $cci19, $datetime, ${GRN}PASSED, Passwords must be a minimum of 15 characters in length.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity19, $controlid, $stigid19, $ruleid19, $cci19, $datetime, ${RED}FAILED, Passwords are not restricted to a minimum of 15 characters in length.${NORMAL}"
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

IFS='
'

datetime="$(date +%FT%H?%M:%S)"

echo -e "${NORMAL}$hostname, $severity20, $controlid, $stigid20, $ruleid20, $cci20, $datetime, ${CYN}VERIFY, (See CM-6 Configuration Settings: V-204594)${NORMAL}"

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

IFS='
'

datetime="$(date +%FT%H?%M:%S)"

authpath="$(ls -l /etc/pam.d/{password,system}-auth)"
fail=1

if [[ $authpath ]]
then
   for line in ${authpath[@]}
   do
      if [[ ${line:0:1} == 'l' && $line =~ 'password-auth' ]]
      then
         echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
	 pwauth=1
      elif [[ ${line:0:1} == 'l' && $line =~ 'system-auth' ]]
      then
	 echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
	 sysauth=1
      else
	 echo -e "${NORMAL}RESULT:    $line${NORMAL}"
      fi
   done
else
   echo -e "${NORMAL}RESULT:    ${RED}Symbolic links to \"password-auth\" and \"system-auth\" not found.${NORMAL}"
fi

if [[ $pwauth == 1 && $sysauth == 1 ]]
then
   fail=0
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity21, $controlid, $stigid21, $ruleid21, $cci21, $datetime, ${GRN}PASSED, The Red Hat Enterprise Linux operating system is configured to prevent overwriting of custom authentication configuration settings${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity21, $controlid, $stigid21, $ruleid21, $cci21, $datetime, ${RED}FAILED, The Red Hat Enterprise Linux operating system is not configured to prevent overwriting of custom authentication configuration settings${NORMAL}"
fi

exit

