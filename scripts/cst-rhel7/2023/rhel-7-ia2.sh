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

controlid="IA-2 Identification and Authentication (Organizational Users)"

title1a="The Red Hat Enterprise Linux operating system must uniquely identify and must authenticate users using multifactor authentication via a graphical user logon."
title1b="Checking with
           a. 'grep -ir system-db /etc/dconf*/*'
           b. 'grep -ir enable-smartcard-authentication /etc/dconf*/*'"
title1c="Expecting:${YLO}
           a. system-db:local
           b. enable-smartcard-authentication=true
           Note: If the system does not have GNOME installed, this requirement is Not Applicable.
           Note: If \"enable-smartcard-authentication\" is set to \"false\" or the keyword is missing, this is a finding."
cci1="CCI-001948"
stigid1="RHEL-07-010061"
severity1="CAT II"
ruleid1="SV-204397r603261_rule"
vulnid1="V-204397"

title2a="The Red Hat Enterprise Linux operating system must be configured so that the SSH daemon does not allow authentication using an empty password."
title2b="Checking with 'grep -i permitemptypasswords /etc/ssh/sshd_config'."
title2c="Expecting:${YLO}
          PermitEmptyPasswords no
          Note: If no line, a commented line, or a line indicating the value "no" is returned, the required value is set.
          Note: If the required value is not set, this is a finding."${YLO}
cci2="CCI-000766"
stigid2="RHEL-07-010300"
severity2="CAT I"
ruleid2="SV-204425r603261_rule"
vulnid2="V-204425"

title3a="The Red Hat Enterprise Linux operating system must uniquely identify and must authenticate organizational users (or processes acting on behalf of organizational users) using multifactor authentication."
title3b="Checking with
           'authconfig --test | egrep -i '(pkcs11|smartcard)'."
title3c="Expecting:${YLO}
           pam_pkcs11 is enabled
           SSSD: smartcard support is disabled
             use only smartcard for login is enabled
             smartcard module = \"coolkey\"
             smartcard removal action = \"Ignore\"
           Note: If no 'pkcs11' results are returned, this is a finding.
           Note: If \"smartcard removal action\" is blank, this is a finding.
           Note: If \"smartcard module\" is blank, this is a finding."
cci3="CCI-000766"
stigid3="RHEL-07-010500"
severity3="CAT II"
ruleid3="SV-204441r818813_rule"
vulnid3="V-204441"

title4a="The Red Hat Enterprise Linux operating system must be configured so that all Group Identifiers (GIDs) referenced in the /etc/passwd file are defined in the /etc/group file."
title4b="Checking with:
          'pwck -r'"
title4c="Expecting:${YLO}
           All groups from /etc/passwd are listed in /etc/group
           Note: If GIDs referenced in \"/etc/passwd\" file are returned as not defined in \"/etc/group\" file, this is a finding."${BLD}
cci4="CCI-000766"
stigid4="RHEL-07-020300"
severity4="CAT III"
ruleid4="SV-204461r603261_rule"
vulnid4="V-204461"

title5a="The Red Hat Enterprise Linux operating system must have the required packages for multifactor authentication installed."
title5b="Checking with:
           'yum list installed pam_pkcs11'"
title5c="Expecting:${YLO}
           pam_pkcs11-0.6.2-14.el7.noarch.rpm
           Note: If the \"pam_pkcs11\" package is not installed, this is a finding."${BLD}
cci5="CCI-001948"
stigid5="RHEL-07-041001"
severity5="CAT II"
ruleid5="SV-204631r603261_rule"
vulnid5="V-204631"

title6a="The Red Hat Enterprise Linux operating system must implement multifactor authentication for access to privileged accounts via pluggable authentication modules (PAM)."
title6b="Checking with:
         'grep services /etc/sssd/sssd.conf /etc/sssd/conf.d/*.conf'."
title6c="Expecting:${YLO}
           services = nss, pam
           Note: If the \"pam\" service is not present on all \"services\" lines, this is a finding."${BLD}
cci6="CCI-001948"
stigid6="RHEL-07-041002"
severity6="CAT II"
ruleid6="SV-204632r603261_rule"
vulnid6="V-204632"

title7a="The Red Hat Enterprise Linux operating system must implement certificate status checking for PKI authentication."
title7b="Checking with:
           'grep cert_policy /etc/pam_pkcs11/pam_pkcs11.conf | grep -v "^#"'."
title7c="Expecting:${YLO}
           cert_policy = ca, ocsp_on, signature;
           cert_policy = ca, ocsp_on, signature;
           cert_policy = ca, ocsp_on, signature;
           Note: If \"ocsp_on\" is not present in all uncommented \"cert_policy\" lines in \"/etc/pam_pkcs11/pam_pkcs11.conf\", this is a finding."${BLD}
cci7="CCI-001948"
stigid7="RHEL-07-041003"
severity7="CAT II"
ruleid7="SV-204633r603261_rule"
vulnid7="V-204633"

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

echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}N/A, Multifactor authentication is not required on this system.${NORMAL}"

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

file2="/etc/ssh/sshd_config"
fail=1

if [[ -f $file2 ]]
then
   emptypw="$(grep -i permitemptypasswords $file2)"
   if [[ $emptypw ]]
   then
      for line in ${emptypw[@]}
      do
         emptypwval="$(echo $emptypw | awk '{print $2}')"
         if [[ $emptypwval == 'no' && ${line:0:1} != '#' ]]
         then
            echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
            fail=0
         else
            echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
         fi
      done
   else
      echo -e "${NORMAL}RESULT:    ${BLD}\"PermitEmptyPasswords\" is not defined in $file2${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file2 was not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, The SSH daemon does not allow authentication using an empty password.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, The SSH daemon allows authentication using an empty password${NORMAL}"
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
echo -e "${NORMAL}TEST 3:    ${BLD}$title32a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title3b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title3c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity3${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"
fail=1

mfa="$(authconfig --test | egrep -i '(pkcs11|smartcard)')"
if [[ $mfa ]]
then
   for line in ${mfa[@]}
   do
      if [[ $line =~ 'pam_pkcs11 is enabled' ]]
      then
         echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
         pkcs11enabled=1
      elif [[ $line =~ 'use only smartcard for login is enabled' ]]
      then
         echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
         useonly=1
      elif [[ $line =~ "smartcard module" ]]
      then
         val="$(echo $line | awk -F'= ' '{print $2}')"
         if [[ $val =~ "coolkey" ]]
         then
            echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
            coolkey=1
         else
            echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
         fi
      elif [[ $line =~ 'smartcard removal action' ]]
      then
         val="$(echo $line | awk -F'= ' '{print $2}')"
         if [[ $val =~ "Ignore" ]]
         then
            echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
            ignore=1
         else
            echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
         fi
      else
         echo -e "${NORMAL}RESULT:    $line${NORMAL}"
      fi
   done
else
   echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $pkcs11enabled == 1 && $useonly == 1 && $coolkey == 1 && $ignore == 1 ]]
then
   fail=0
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${GRN}PASSED, The Red Hat Enterprise Linux operating system uniquely identifies and must authenticates organizational users (or processes acting on behalf of organizational users) using multifactor authentication.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${RED}FAILED, The Red Hat Enterprise Linux operating system does not uniquely identify and authenticates organizational users (or processes acting on behalf of organizational users) using multifactor authentication.${NORMAL}"
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

datetime="$(date +%FT%H:%M:%S)"

cmd="$(command -v pwck)"
fail=0

if [[ $cmd ]]
then
   nogrouplist="$($cmd -r | grep -v 'pwck' | grep 'no group')"
   if [[ $nogrouplist ]]
   then
      for group in ${nogrouplist[@]}
      do
         echo -e "${NORMAL}RESULT:    ${RED}$group${NORMAL}"
         fail=1
      done
   else
      echo -e "${NORMAL}RESULT:    Nothing returned${NORMAL}"
   fi
   if [[ $fail == 0 ]]
   then
      echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${GRN}PASSED, Valid Group Identifiers - All group identifiers (GIDs) referenced in the /etc/passwd file are defined in the /etc/group file.${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${RED}FAILED, Valid Group Identifiers - All group identifiers (GIDs) referenced in the /etc/passwd file are not defined in the /etc/group file.${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}The 'pwck' command was not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${RED}FAILED, Valid Group Identifiers: The 'pwck' command was not found${NORMAL}"
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

datetime="$(date +%FT%H:%M:%S)"

isinstalled="$(yum list installed pam_pkcs11 2>/dev/null | grep pam_pkcs11)"
fail=1

if [[ $isinstalled ]]
then
   echo -e "${NORMAL}RESULT:    ${BLD}$isinstalled${NORMAL}"
   fail=0
else
   echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${GRN}PASSED, The system is capable of enforcing multifactor authentication${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${GRN}N/A, The program does not require multifactor authentication on this system.${NORMAL}"
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

datetime="$(date +%FT%H:%M:%S)"

file6arr=('/etc/sssd/sssd.conf' '/etc/sssd/conf.d/*.conf')
fail=0

for file in ${file6arr[@]}
do
   if [[ -f $file ]]
   then
      pamsvc="$(grep services $file)"
      if [[ $pamsvc ]]
      then
	 for line in ${pamsvd[@]}
         do
            if [[ ! $line =~ 'pam' ]]
	    then
               echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
	       fail=1
	    else
	       echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
	    fi
	 done
      else
	 echo -e "${NORMAL}RESULT:    ${BLD}\"services\" is not defined in $file${NORMAL}"
	 fail=1
      fi
   else
      echo -e "${NORMAL}RESULT:    ${RED}$file not found${NORMAL}"
      fail=1
   fi
done

if [[ $fail == 0 ]]
then
	echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${GRN}PASSED, The system is capable of requiring multifactor authentication via pluggable authentication modules (PAM).${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${GRN}N/A, The program does not require multifactor authentication on this system.${NORMAL}"
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

datetime="$(date +%FT%H:%M:%S)"

file7="/etc/pam_pkcs11/pam_pkcs11.conf"
fail=0

if [[ -f $file7 ]]
then
   certpol="$(grep cert_policy $file7 2>/dev/null | grep cert_policy)"
   if [[ $certpol ]]
   then
      for line in ${certpol[@]}
      do
	 if [[ ! $line =~ 'ocsp_on' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
	    fail=1
	 else
            echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
	 fi
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}\"cert_policy\" is not defined in $file7${NORMAL}"
      fail=1
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}$file7 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${GRN}N/A, The system implements certificate status checking for PKI authentication.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${GRN}N/A, The program does not require multifactor authentication on this system.${NORMAL}"
fi

exit

