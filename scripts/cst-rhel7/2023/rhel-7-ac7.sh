#! /bin/bash

# AC-7 Unsuccessful Logon Attempts
#
# CONTROL: The information system:
# a. Enforces a limit of [Assignment: organization-defined number] consecutive invalid logon
#    attempts by a user during a [Assignment: organization-defined time period]; and
# b. Automatically [Selection: locks the account/node for an [Assignment: organization-defined
#    time period]; locks the account/node until released by an administrator; delays next logon
#    prompt according to [Assignment: organization-defined delay algorithm]] when the maximum
#     number of unsuccessful attempts is exceeded.

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

controlid="AC-7 Unsuccessful Logon Attempts"

title1a="The Red Hat Enterprise Linux operating system must be configured to lock accounts for a minimum of 15 minutes after three unsuccessful logon attempts within a 15-minute timeframe."
title1b="Checking with 'grep pam_faillock.so /etc/pam.d/password-auth'"
title1c="Expecting: ${YLO}
           auth required pam_faillock.so preauth silent audit deny=3 even_deny_root unlock_time=604800
           auth [default=die] pam_faillock.so authfail audit deny=3 even_deny_root unlock_time=604800
           account required pam_faillock.so${BLD}
           Note: ${YLO}If the \"deny\" parameter is set to \"0\" or a value greater than \"3\" on both \"auth\" lines with the \"pam_faillock.so\" module, or is missing from these lines, this is a finding.${BLD}
           Note: ${YLO}If the \"even_deny_root\" parameter is not set on both \"auth\" lines with the \"pam_faillock.so\" module, or is missing from these lines, this is a finding.${BLD}
           Note: ${YLO}If the \"fail_interval\" parameter is set to \"0\" or is set to a value less than \"900\" on both \"auth\" lines with the \"pam_faillock.so\" module, or is missing from these lines, this is a finding.${BLD}
           Note: ${YLO}If the \"unlock_time\" parameter is set to \"0\", \"never\" or is set to a value less than \"900\" on both \"auth\" lines with the \"pam_faillock.so\" module, or is missing from these lines, this is a finding.${BLD}
           Note: ${YLO}The maximum configurable value for \"unlock_time\" is \"604800\".${BLD}
           Note: ${YLO}If any line referencing the \"pam_faillock.so\" module is commented out, this is a finding.${BLD}"
cci1="CCI-002238"
stigid1="RHEL-07-010320"
severity1="CAT II"
ruleid1="SV-204427r603824_rule"
vulnid1="V-204427"

title2a="The Red Hat Enterprise Linux operating system must lock the associated account after three unsuccessful root logon attempts are made within a 15-minute period."
title2b="Checking with 'grep pam_faillock.so /etc/pam.d/password-auth /etc/pam.d/system-auth'."
title2c="Expecting: ${YLO}
           auth required pam_faillock.so preauth silent audit deny=3 even_deny_root unlock_time=604800 fail_interval=900
           auth [default=die] pam_faillock.so authfail audit deny=3 even_deny_root unlock_time=604800 fail_interval=900
           account required pam_faillock.so${BLD}
           Note: ${YLO}If the \"even_deny_root\" setting is not defined on both lines with the \"pam_faillock.so\" module, is commented out, or is missing from a line, this is a finding."${BLD}
cci2="CCI-002238"
stigid2="RHEL-07-010330"
severity2="CAT II"
ruleid2="SV-204428r792821_rule"
vulnid2="V-204428"

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

filearr1=('/etc/pam.d/password-auth' '/etc/pam.d/system-auth')

if [[ $filearr1 ]]
then

   for file in ${filearr1[@]}
   do
      echo
      echo $file
      echo "----------------------------------------------------------------"

      unlock="$(egrep -i '(auth|account)' $file | grep 'unlock_time' | grep -v '^#')"
      if ! [[ $unlock ]]
      then
         fail=1
      fi
      denyroot="$(egrep -i '(auth|account)' $file | grep 'even_deny_root' | grep -v '^#')"
      if ! [[ $denyroot ]]
      then
         fail=1
      fi

      pwauth="$(egrep -i '(auth|account)' $file | grep -v '^#')"
      if [[ $pwauth ]]
      then
         for line in ${pwauth[@]}
         do
            if [[ ($line =~ 'auth' && $line =~ 'required' && $line =~ 'pam_faillock.so') ||
                  ($line =~ 'auth' && $line =~ '[default=die]' && $line =~ 'pam_faillock.so')
               ]]
            then
               IFS=' ' read -a rule <<< $line IFS='\n'
               for element in ${rule[@]}
               do
                  if [[ $element =~ 'deny=' ]]
                  then
                     denyval="$(echo $element | awk -F= '{print $2}')"
                     if [[ $denyval == 0 || $denyval > 3 ]]
                     then
                        rulefail=1
                     fi
                  elif [[ $element =~ 'fail_interval' ]]
                  then
                     fival="$(echo $element | awk -F= '{print $2}')"
                     if [[ $fival == 0 || ($fival < 900 && $fival != 0) ]]
                     then
                        rulefail=1
                     fi
                  elif [[ $element =~ 'unlock_time' && ! $element =~ 'root_unlock_time' ]]
                  then
                     utval="$(echo $element | awk -F= '{print $2}')"
                     if [[ $utval == 0 || $utval == 'never' || $utval < 900 ]]
                     then
                        rulefail=1
                     fi
                  fi
               done

               if [[ $rulefail == 0 ]]
               then
                  echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
               else
                  echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
                  fail=1
               fi

            elif [[ $line =~ 'account' && $line =~ 'required' && $line =~ 'pam_faillock.so' ]]
            then
               echo -e "${NORMAL}RESULT:    ${GRN}$line${NORMAL}"
               found=1
            else
               echo -e "${NORMAL}RESULT:    $line${NORMAL}"
            fi
         done

         if [[ $found == 0 ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}The 'acount required' line is missing or incorrect${NORMAL}"
            fail=1
         fi
      fi
   done

   if [[ $fail == 0 ]]
   then
      echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, Account Lockout: Accounts subject to three unsuccessful logon attempts within 15 minutes are locked for the maximum configurable period.${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, Account Lockout: Accounts subject to three unsuccessful logon attempts within 15 minutes are not locked for the maximum configurable period.${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file1a or $file1b not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, Account Lockout: /etc/pam.d files not found${NORMAL}"
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

fail=0

filearr2=('/etc/pam.d/password-auth' '/etc/pam.d/system-auth')

if [[ $filearr2 ]]
then
   for file in ${filearr2[@]}
   do
      echo
      echo $file
      echo "----------------------------------------------------------------"
      
      pwauth="$(egrep -i '(auth|account)' $file | grep -v '^#')"
      if [[ $pwauth ]]
      then
         for line in ${pwauth[@]}
         do
            if [[ $line =~ 'auth' && 
                ( $line =~ 'required' || $line =~ 'default=die') &&
                  $line =~ 'pam_faillock.so' 
               ]]
            then
               if ! [[  $line =~ 'even_deny_root' ]]
               then
                  echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
                  fail=1
               else
                  echo -e "${NORMAL}RESULT:    ${GRN}$line${NORMAL}"
               fi
            else
               echo -e "${NORMAL}RESULT:    $line${NORMAL}"
            fi
         done
      fi
   done
else
   echo -e "${NORMAL}RESULT:    ${RED}Missing \"/etc/pam.d/password-auth\" or \"/etc/pam.d/system-auth\"${NORMAL}"
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, Root Account Lockout: The operating system locks the associated account after three unsuccessful root logon attempts are made within a 15-minute period.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, Root Account Lockout: The operating system does not lock the associated account after three unsuccessful root logon attempts are made within a 15-minute period.${NORMAL}"
fi

exit
