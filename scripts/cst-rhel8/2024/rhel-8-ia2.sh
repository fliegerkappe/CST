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

stig="Red Hat Enterprise Linux 8 Security Technical Implementation Guide :: Version 1, Release: 13 Benchmark Date: 24 Jan 2024"

hostname="$(uname -n)"

if [[ -f /etc/redhat-release ]]
then
   os="$(cat /etc/redhat-release)"
else
   os="OS not defined"
fi

prog="$(basename $0)"

controlid="IA-2 Identification and Authentication (Organizational Users)"

title1a="RHEL 8 must have the packages required for multifactor authentication installed."
title1b="Checking with 'yum list installed openssl-pkcs11'."
title1c="Expecting: ${YLO}openssl-pkcs11.x86_64          0.4.8-2.el8          @anaconda
          NOTE: If the \openssl-pkcs11\ package is not installed, ask the administrator to indicate what type of multifactor authentication is being utilized and what packages are installed to support it.  If there is no evidence of multifactor authentication being used, this is a finding."${BLD}
cci1="CCI-001948"
stigid1="RHEL-08-010390"
severity1="CAT II"
ruleid1="SV-230273r854028_rule"
vulnid1="V-230273"

title2a="RHEL 8 must implement certificate status checking for multifactor authentication."
title2b="Checking with: grep certificate_verification /etc/sssd/sssd.conf /etc/sssd/conf.d/*.conf | grep -v \"^#\"."
title2c="Expecting: ${YLO}certificate_verification = ocsp_dgst=sha1 
           NOTE: If the certificate_verification line is missing from the [sssd] section, or is missing \"ocsp_dgst=sha1\", ask the administrator to indicate what type of multifactor authentication is being utilized and how the system implements certificate status checking.  If there is no evidence of certificate status checking being used, this is a finding."${BLD}
cci2="CCI-001948"
stigid2="RHEL-08-010400"
severity2="CAT II"
ruleid2="SV-230274r854741_rule"
vulnid2="V-230274"

title3a="RHEL 8 must accept Personal Identity Verification (PIV) credentials."
title3b="Checking with: 
           a. 'yum list installed opensc'
	   b. 'opensc-tool --list-drivers | grep -i piv"
title3c="Expecting: ${YLO}
           a. opensc.x86_64     0.19.0-5.el8     @anaconda
	   b. PIV-II     Personal Identity Verification Card
           NOTE: If the "opensc" package is not installed and the \"opensc-tool\" driver list does not include \"PIV-II\", this is a finding."${BLD}
cci3="CCI-001953"
stigid3="RHEL-08-010410"
severity3="CAT II"
ruleid3="SV-230275r854030_rule"
vulnid3="V-230275"

title4a="RHEL 8 must not permit direct logons to the root account using remote access via SSH."
title4b="Checking with: grep -i PermitRootLogin /etc/ssh/sshd_config"
title4c="Expecting: ${YLO}PermitRootLogin no
           NOTE: If the \"PermitRootLogin\" keyword is set to \"yes\", is missing, or is commented out, this is a finding."${BLD}
cci4="CCI-000770"
stigid4="RHEL-08-010550"
severity4="CAT II"
ruleid4="SV-230296r858711_rule"
vulnid4="V-230296"

title5a="RHEL 8 duplicate User IDs (UIDs) must not exist for interactive users."
title5b="Checking with: awk -F \":\" 'list[\$3]++{print \$1, \$3}' /etc/passwd."
title5c="Expecting: ${YLO}Nothing returned
           NOTE: If output is produced, and the accounts listed are interactive user accounts, this is a finding."${BLD}
cci5="CCI-000764"
stigid5="RHEL-08-020240"
severity5="CAT II"
ruleid5="SV-230371r627750_rule"
vulnid5="V-230371"

title6a=" RHEL 8 must implement smart card logon for multifactor authentication for access to interactive accounts."
title6b="Checking with: grep cert_auth /etc/sssd/sssd.conf /etc/pam.d/"
title6c="Expecting: ${YLO}
           /etc/sssd/sssd.conf:pam_cert_auth = True
           /etc/pam.d/smartcard-auth:auth   sufficient   pam_sss.so try_cert_auth
           /etc/pam.d/system-auth:auth   [success=done authinfo_unavail=ignore ignore=ignore default=die]   pam_sss.so try_cert_auth
	   NOTE: If the System Administrator demonstrates the use of an approved alternate multifactor authentication method, this requirement is not applicable.
	   NOTE: Check that the \"pam_cert_auth\" setting is set to \"true\" in the \"/etc/sssd/sssd.conf\" file.
	   NOTE: Check that the \"try_cert_auth\" or \"require_cert_auth\" options are configured in both \"/etc/pam.d/system-auth\" and \"/etc/pam.d/smartcard-auth\" files
	   NOTE: If \"pam_cert_auth\" is not set to \"true\" in \"/etc/sssd/sssd.conf\", this is a finding.
	   NOTE: If \"pam_sss.so\" is not set to \"try_cert_auth\" or \"require_cert_auth\" in both the \"/etc/pam.d/smartcard-auth\" and \"/etc/pam.d/system-auth\" files, this is a finding."${BLD}
cci6="CCI-000765"
stigid6="RHEL-08-020250"
severity6="CAT II"
ruleid6="SV-230372r942945_rule"
vulnid6="V-230372"

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

osslinstalled="$(yum list installed openssl-pkcs11 | grep openssl-pkcs11)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $osslinstalled ]]
then
  if [[ $osslinstalled =~ 'openssl-pkcs11.x86_64' ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$osslinstalled${NORMAL}"
    fail=0
  else
    echo -e "${NORMAL}RESULT:    ${RED}$osslinstalled${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}The \"openssl-pkcs11\" package is not installed${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, RHEL 8 has the packages required for multifactor authentication installed.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, RHEL 8 does not have the packages required for multifactor authentication installed.${NORMAL}"
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

#file2a="/etc/sssd/sssd.conf"
#file2b="/etc/sssd/conf.d/*.conf"

file2arr=("/etc/sssd/sssd.conf" "/etc/sssd/conf.d/*.conf")

datetime="$(date +%FT%H:%M:%S)"

for file in ${file2arr[@]}
do
  if [[ -f $file ]]
  then
    certverification="$(grep -ir certificate_verification $file 2>/dev/null | grep certificate_verification | grep -v \"^#\")"
    if [[ $certverification ]]
    then
      if [[ $certverification =~ 'ocsp_dgst' && $certverification =~ 'sha1' ]]
      then
        echo -e "${NORMAL}RESULT:    ${BLD}$file:$certverification${NORMAL}"
        fail=0
      else
        echo -e "${NORMAL}RESULT:    ${RED}$file:$certverification${NORMAL}"
      fi
    else
      echo -e "${NORMAL}RESULT:    ${RED}\"certificate_verification\" not defined in $file${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}$file not found${NORMAL}"
  fi
done

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, RHEL 8 implements certificate status checking for multifactor authentication.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, RHEL 8 does not implement certificate status checking for multifactor authentication.${NORMAL}"
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

openscinstalled="$(yum list installed opensc | grep opensc)"

datetime="$(date +%FT%H:%M:%S)"

if [[ openscinstalled ]]
then
  echo -e "${NORMAL}RESULT:    ${BLD}a. $openscinstalled${NORMAL}"
  pivaccepted="$(opensc-tool --list-drivers | grep -i piv | sed 's/ \+//')"
  if [[ $pivaccepted ]]
  then
    if [[ $pivaccepted =~ 'PIV-II' ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}b. $pivaccepted${NORMAL}"
      fail=0
    else
      echo -e "${NORMAL}RESULT:    ${RED}b. $pivaccepted${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}b. A PIV driver is not defined.${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${BLD}a. The \"opensc\" package is not installed.${NORMAL}"
fi

if (( $fail == 0 ))
then
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${GRN}PASSED, RHEL 8 accepts Personal Identity Verification (PIV) credentials.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${RED}FAILED, RHEL 8 does not accept Personal Identity Verification (PIV) credentials.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echoecho -e "${NORMAL}RESULT:    ${BLD}$pivaccepted${NORMAL}" -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
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

file4="/etc/ssh/sshd_config"

fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file4 ]]
then
  permitrootlogin="$(grep -ir permitrootlogin $file4 | grep -v "^#")"
  if [[ $permitrootlogin ]]
  then
    rootloginallowed="$(echo $permitrootlogin | awk '{print $2}')"
    if [[ $rootloginallowed == "no" ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$permitrootlogin${NORMAL}"
      fail=0
    else
      echo -e "${NORMAL}RESULT:    ${RED}$permitrootlogin${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}\"PermitRootLogin\" not defined in $file4${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file4 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${GRN}PASSED, RHEL 8 does not permit direct logons to the root account using remote access via SSH.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${RED}FAILED, RHEL 8 permits direct logons to the root account using remote access via SSH.${NORMAL}"
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

file5="/etc/passwd"

fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ $file5 ]]
then
  dupuid="$(awk -F":" 'list[$3]++{print $1, $3}' $file5)"
  if ! [[ $dupuid ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
    fail=0
  else
    for uid in ${dupuid[@]}
    do
      echo -e "${NORMAL}RESULT:    ${CYN}VERIFY: $uid${NORMAL}"
    done
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file5 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${GRN}PASSED, RHEL 8 duplicate User IDs (UIDs) do not exist for interactive users.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${CYN}VERIFY, RHEL 8 duplicate User IDs (UIDs) exist for interactive users.${NORMAL}"
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

file6a="/etc/sssd/sssd.conf"
file6b="/etc/pam.d/*"

fail=1
istrue=0
authtype=("try_cert_auth" "require_cert_auth")

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file6a ]]
then
  pamcertauth="$(grep pam_cert_auth $file6a)"
  if [[ $pamcertauth ]]
  then
    pamcertauthval="$(echo $pamcertauth | awk '{print $2}')"
    if [[ $pamcertauthval == "[Tt]rue" ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$file6a:$pamcertauth${NORMAL}"
      istrue=1
      certauth="$(grep -ir cert_auth $file6b | grep pam_sss.so)"
      if [[ $certauth ]]
      then
        trysysauth=0
        reqsysauth=0
	trysmartauth=0
	reqsmartauth=0
        for line in ${certauth[@]}
        do
          for type in ${authtype[@]}
          do
	    sourcefile="$(echo $line | awk -F: '{print $1}' | awk -F"/" '{print $(NF)}')"
            case $sourcefile in
            'smartcart-auth')
               case $type in
                 'try_cert_auth')
                    echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
                    trysmartauth=1
                    ;;
                 'require_cert_auth')
                    echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
                    reqsmartauth=1
                    ;;
               esac
	       ;;
	    'system-auth')
               case $type in
                 'try_cert_auth')
                    echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
                    tryssysauth=1
                    ;;
                 'require_cert_auth')
                    echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
                    reqsysauth=1
                    ;;
               esac
	       ;;
            esac
          done
        done
      else
        echo -e "${NORMAL}RESULT:    ${RED}Nothing returned{NORMAL}"
      fi
    else
      echo -e "${NORMAL}RESULT:    ${RED}$pamcertauthval${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}\"pam_cert_auth\" not defined in $file6a${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file6a not found${NORMAL}"
fi

if [[ ( $trysysauth == 1 && $reqsysauth == 1 ) ||
      ( $trysmartauth == 1 && $reqsmartauth == 1 ) ]] 
then
  fail=0
else
  echo -e "${NORMAL}RESULT:    ${RED}\"pam_sss.so\" is not set to either \"try_cert_auth\" or \"require_cert_auth\" in $file6b${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${GRN}PASSED, RHEL 8 implements smart card logon for multifactor authentication for access to interactive accounts.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${RED}FAILED, RHEL 8 does not implement smart card logon for multifactor authentication for access to interactive accounts.${NORMAL}"
fi

exit

