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

stig="Red Hat Enterprise Linux 8 Security Technical Implementation Guide :: Version 1, Release: 13 Benchmark Date: 24 Jan 2024"

hostname="$(uname -n)"

if [[ -f /etc/redhat-release ]]
then
   os="$(cat /etc/redhat-release)"
else
   os="OS not defined"
fi

prog="$(basename $0)"

controlid="AC-7 Unsuccessful Logon Attempts"

title1a="RHEL 8 must automatically lock an account when three unsuccessful logon attempts occu"
title1b="Checking with:
           a. egrep -i pam_faillock.so /etc/pam.d/password-auth
	   b. egrep -i pam_faillock.so /etc/pam.d/system-auth"
title1c="Expecting: ${YLO}
           auth required pam_faillock.so preauth dir=/var/log/faillock silent audit ${GRN}deny=3${YLO} even_deny_root fail_interval=900 unlock_time=0
           auth required pam_faillock.so authfail dir=/var/log/faillock unlock_time=0
           account required pam_faillock.so
	   NOTE: This check applies to RHEL versions 8.0 and 8.1, if the system is RHEL version 8.2 or newer, this check is not applicable.
           NOTE: If the \"deny\" option is not set to \"3\" or less (but not \"0\") on the \"preauth\" line with the \"pam_faillock.so\" module, or is missing from this line, this is a finding. 
           NOTE: If any line referencing the \"pam_faillock.so\" module is commented out, this is a finding."${BLD}
cci1="CCI-000044"
stigid1="RHEL-08-020010	"
severity1="CAT II"
ruleid1="SV-230332r627750_rule"
vulnid1="V-230332"

title2a="RHEL 8 must automatically lock an account when three unsuccessful logon attempts occur."
title2b="Checking with: grep 'deny =' /etc/security/faillock.conf."
title2c="Expecting: ${YLO}deny = 3
           NOTE: This check applies to RHEL versions 8.2 or newer, if the system is RHEL version 8.0 or 8.1, this check is not applicable.
           NOTE: If the \"deny\" option is not set to \"3\" or less (but not \"0\"), is missing or commented out, this is a finding."${BLD}
cci2="CCI-000044"
stigid2="RHEL-08-020011"
severity2="CAT II"
ruleid2="SV-230333r743966_rule"
vulnid2="V-230333"

title3a="RHEL 8 must automatically lock an account when three unsuccessful logon attempts occur during a 15-minute time period."
title3b="Checking with:
           a. grep pam_faillock.so /etc/pam.d/password-auth
	   b. grep pam_faillock.so /etc/pam.d/system-auth"
title3c="Expecting: ${YLO}
           auth required pam_faillock.so preauth dir=/var/log/faillock silent audit deny=3 even_deny_root ${GRN}fail_interval=900${YLO}
           auth required pam_faillock.so authfail dir=/var/log/faillock unlock_time=0
           account required pam_faillock.so
           NOTE: Note: If the System Administrator demonstrates the use of an approved centralized account management method that locks an account after three unsuccessful logon attempts within a period of 15 minutes, this requirement is not applicable. 
           NOTE: This check applies to RHEL versions 8.0 and 8.1, if the system is RHEL version 8.2 or newer, this check is not applicable.
           NOTE: If the \"fail_interval\" option is not set to \"900\" or less (but not \"0\") on the \"preauth\" lines with the \"pam_faillock.so\" module, or is missing from this line, this is a finding."${BLD}
cci3="CCI-000044"
stigid3="RHEL-08-020012"
severity3="CAT II"
ruleid3="SV-230334r627750_rule"
vulnid3="V-230334"

title4a="RHEL 8 must automatically lock an account when three unsuccessful logon attempts occur during a 15-minute time period."
title4b="Checking with: grep 'fail_interval =' /etc/security/faillock.conf."
title4c="Expecting: ${YLO}fail_interval = 900
           NOTE: This check applies to RHEL versions 8.2 or newer, if the system is RHEL version 8.0 or 8.1, this check is not applicable.
           NOTE: If the \"fail_interval\" option is not set to \"900\" or more, is missing or commented out, this is a finding."${BLD}
cci4="CCI-000044"
stigid4="RHEL-08-020013"
severity4="CAT II"
ruleid4="SV-230335r743969_rule"
vulnid4="V-230335"

title5a="RHEL 8 must automatically lock an account until the locked account is released by an administrator when three unsuccessful logon attempts occur during a 15-minute time period."
title5b="Checking with: 
           a. grep pam_faillock.so /etc/pam.d/password-auth
	   b. grep pam_faillock.so /etc/pam.d/system-auth"
title5c="Expecting: ${YLO}
           auth required pam_faillock.so preauth dir=/var/log/faillock silent audit deny=3 even_deny_root fail_interval=900 ${GRN}unlock_time=0${YLO}
           auth required pam_faillock.so authfail dir=/var/log/faillock ${GRN}unlock_time=0${YLO}
           account required pam_faillock.so
	   NOTE: This check applies to RHEL versions 8.0 and 8.1, if the system is RHEL version 8.2 or newer, this check is not applicable.
	   NOTE: If the \"unlock_time\" option is not set to \"0\" on the \"preauth\" and \"authfail\" lines with the \"pam_faillock.so\" module, or is missing from these lines, this is a finding."${BLD}
cci5="CCI-000044"
stigid5="RHEL-08-020014"
severity5="CAT II"
ruleid5="SV-230336r627750_rule"
vulnid5="V-230336"

title6a="RHEL 8 must automatically lock an account until the locked account is released by an administrator when three unsuccessful logon attempts occur during a 15-minute time period."
title6b="Checking with: grep 'unlock_time =' /etc/security/faillock.conf'."
title6c="Expecting: ${YLO}unlock_time = 0
           NOTE: This check applies to RHEL versions 8.2 or newer, if the system is RHEL version 8.0 or 8.1, this check is not applicable.
	   NOTE: If the \"unlock_time\" option is not set to \"0\", is missing or commented out, this is a finding."${BLD}
cci6="CCI-000044"
stigid6="RHEL-08-020015"
severity6="CAT II"
ruleid6="SV-230337r743972_rule"
vulnid6="V-230337"

title7a="RHEL 8 must ensure account lockouts persist."
title7b="Checking with:
           a. grep pam_faillock.so /etc/pam.d/password-auth
	   b. grep pam_faillock.so /etc/pam.d/system-auth"
title7c="Expecting: ${YLO} 
           auth required pam_faillock.so preauth ${GRN}dir=/var/log/faillock${YLO} silent audit deny=3 even_deny_root fail_interval=900 unlock_time=0
           auth required pam_faillock.so authfail ${GRN}dir=/var/log/faillock${YLO} unlock_time=0
           account required pam_faillock.so
           NOTE: This check applies to RHEL versions 8.0 and 8.1, if the system is RHEL version 8.2 or newer, this check is not applicable.
	   NOTE: If the \"dir\" option is not set to a non-default documented tally log directory on the \"preauth\" and \"authfail\" lines with the \"pam_faillock.so\" module, or is missing from these lines, this is a finding."${BLD}
cci7="CCI-000044"
stigid7="RHEL-08-020016"
severity7="CAT II"
ruleid7="SV-230338r627750_rule"
vulnid7="V-230338"

title8a="RHEL 8 must ensure account lockouts persist."
title8b="Checking with: grep 'dir =' /etc/security/faillock.conf"
title8c="Expecting: ${YLO}dir = /var/log/faillock
           NOTE: This check applies to RHEL versions 8.2 or newer. If the system is RHEL version 8.0 or 8.1, this check is not applicable.
	   NOTE: If the \"dir\" option is not set to a non-default documented tally log directory, is missing or commented out, this is a finding."${BLD}
cci8="CCI-000044"
stigid8="RHEL-08-020017"
severity8="CAT II"
ruleid8="SV-230339r743975_rule"
vulnid8="V-230339"

title9a="RHEL 8 must prevent system messages from being presented when three unsuccessful logon attempts occur."
title9b="Checking with:
           a. grep pam_faillock.so /etc/pam.d/password-auth
	   b. grep pam_faillock.so /etc/pam.d/system-auth"
title9c="Expecting: ${YLO}
           auth required pam_faillock.so preauth dir=/var/log/faillock ${GRN}silent${YLO} audit deny=3 even_deny_root fail_interval=900 unlock_time=0
           auth required pam_faillock.so authfail dir=/var/log/faillock unlock_time=0
           account required pam_faillock.so
           NOTE: This check applies to RHEL versions 8.0 and 8.1, if the system is RHEL version 8.2 or newer, this check is not applicable.
	   NOTE: If the \"silent\" option is missing from the \"preauth\" line with the \"pam_faillock.so\" module, this is a finding."${BLD}
cci9="CCI-000044"
stigid9="RHEL-08-020018"
severity9="CAT II"
ruleid9="SV-230340r627750_rule"
vulnid9="V-230340"

title10a="RHEL 8 must prevent system messages from being presented when three unsuccessful logon attempts occur."
title10b="Checking with: 'grep silent /etc/security/faillock.conf'."
title10c="Expecting: ${YLO}silent
           NOTE: This check applies to RHEL versions 8.2 or newer, if the system is RHEL version 8.0 or 8.1, this check is not applicable.
           NOTE: If the \"silent\" option is not set, is missing or commented out, this is a finding."${BLD}
cci10="CCI-000044"
stigid10="RHEL-08-020019"
severity10="CAT II"
ruleid10="SV-230341r743978_rule"
vulnid10="V-230341"

title11a="RHEL 8 must log user name information when unsuccessful logon attempts occur."
title11b="Checking with:
           a. grep pam_faillock.so /etc/pam.d/password-auth
	   b. grep pam_faillock.so /etc/pam.d/system-auth"
title11c="Expecting: ${YLO}
           auth required pam_faillock.so preauth dir=/var/log/faillock silent ${GRN}audit${YLO} deny=3 even_deny_root fail_interval=900 unlock_time=0
           auth required pam_faillock.so authfail dir=/var/log/faillock unlock_time=0
           account required pam_faillock.so
	   NOTE: If the system is RHEL version 8.2 or newer, this check is not applicable.
           NOTE: If the \"audit\" option is missing from the \"preauth\" line with the \"pam_faillock.so\" module, this is a finding."${BLD}
cci11="CCI-000044"
stigid11="RHEL-08-020020"
severity11="CAT II"
ruleid11="SV-230342r646872_rule"
vulnid11="V-230342"

title12a="RHEL 8 must log user name information when unsuccessful logon attempts occur."
title12b="Checking with: 'sudo grep audit /etc/security/faillock.conf'."
title12c="Expecting: ${YLO}audit
           NOTE: This check applies to RHEL versions 8.2 or newer, if the system is RHEL version 8.0 or 8.1, this check is not applicable.
	   NOTE: If the \"audit\" option is not set, is missing or commented out, this is a finding."${BLD}
cci12="CCI-000044"
stigid12="RHEL-08-020021"
severity12="CAT II"
ruleid12="SV-230343r743981_rule"
vulnid12="V-230343"

title13a="RHEL 8 must include root when automatically locking an account until the locked account is released by an administrator when three unsuccessful logon attempts occur during a 15-minute time period."
title13b="Checking with: 
           a. grep pam_faillock.so /etc/pam.d/password-auth
	   b. grep pam_faillock.so /etc/pam.d/system-auth"
title13c="Expecting: ${YLO}
           auth required pam_faillock.so preauth dir=/var/log/faillock silent audit deny=3 ${GRN}even_deny_root${YLO} fail_interval=900 unlock_time=0
           auth required pam_faillock.so authfail dir=/var/log/faillock unlock_time=0
           account required pam_faillock.so
           NOTE: If the system is RHEL version 8.2 or newer, this check is not applicable.
	   NOTE: If the \"even_deny_root\" option is missing from the \"preauth\" line with the \"pam_faillock.so\" module, this is a finding."${BLD}
cci13="CCI-000044"
stigid13="RHEL-08-020022"
severity13="CAT II"
ruleid13="SV-230344r646874_rule"
vulnid13="V-230344"

title14a="RHEL 8 must include root when automatically locking an account until the locked account is released by an administrator when three unsuccessful logon attempts occur during a 15-minute time period."
title14b="Checking with: 'grep even_deny_root /etc/security/faillock.conf'."
title14c="Expecting: ${YLO}even_deny_root
           NOTE: This check applies to RHEL versions 8.2 or newer, if the system is RHEL version 8.0 or 8.1, this check is not applicable.
	   NOTE: If the \"even_deny_root\" option is not set, is missing or commented out, this is a finding."${BLD}
cci14="CCI-000044"
stigid14="RHEL-08-020023"
severity14="CAT II"
ruleid14="SV-230345r743984_rule"
vulnid14="V-230345"

title15a="RHEL 8 must configure the use of the pam_faillock.so module in the /etc/pam.d/system-auth file."
title15b="Checking with: 'grep pam_faillock.so /etc/pam.d/system-auth'."
title15c="Expecting: ${YLO}
           auth               required                               pam_faillock.so preauth
           auth               required                               pam_faillock.so authfail
           account            required                               pam_faillock.so
           NOTE: This check applies to RHEL versions 8.2 or newer, if the system is RHEL version 8.0 or 8.1, this check is not applicable.
	   NOTE: If the pam_faillock.so module is not present in the \"/etc/pam.d/system-auth\" file with the \"preauth\" line listed before pam_unix.so, this is a finding."${BLD}
cci15="CCI-000044"
stigid15="RHEL-08-020025"
severity15="CAT II"
ruleid15="SV-244533r743848_rule"
vulnid15="V-244533"

title16a="RHEL 8 must configure the use of the pam_faillock.so module in the /etc/pam.d/password-auth file."
title16b="Checking with: 'grep pam_faillock.so /etc/pam.d/password-auth'."
title16c="Expecting: ${YLO}
           auth               required                               pam_faillock.so preauth
           auth               required                               pam_faillock.so authfail
           account            required                               pam_faillock.so
           NOTE: This check applies to RHEL versions 8.2 or newer, if the system is RHEL version 8.0 or 8.1, this check is not applicable.
	   NOTE: If the pam_faillock.so module is not present in the \"/etc/pam.d/password-auth\" file with the \"preauth\" line listed before pam_unix.so, this is a finding."${BLD}
cci16="CCI-000044"
stigid16="RHEL-08-020026"
severity16="CAT II"
ruleid16="SV-244534r743851_rule"
vulnid16="V-244534"

title17a="RHEL 8 systems, versions 8.2 and above, must configure SELinux context type to allow the use of a non-default faillock tally directory."
title17b="Checking with: 
           a. grep -w dir /etc/security/faillock.conf
	   b. ls -Zd /var/log/faillock"
title17c="Expecting: ${YLO}
           a. dir = /var/log/faillock
	   b. unconfined_u:object_r:faillog_t:s0 /var/log/faillock
           NOTE: This check applies to RHEL versions 8.2 or newer. If the system is RHEL version 8.0 or 8.1, this check is not applicable.
	   NOTE: If the security context type of the non-default tally directory is not "faillog_t", this is a finding."${BLD}
cci17="CCI-000044"
stigid17="RHEL-08-020027"
severity17="CAT II"
ruleid17="SV-250315r793009_rule"
vulnid17="V-250315"

title18a="RHEL 8 systems below version 8.2 must configure SELinux context type to allow the use of a non-default faillock tally directory."
title18b="Checking with: 
           a. grep -w dir /etc/pam.d/password-auth
	   b. ls -Zd /var/log/faillock"
title18c="Expecting: ${YLO}
           auth   required   pam_faillock.so preauth dir=/var/log/faillock
           auth   required   pam_faillock.so authfail dir=/var/log/faillock
	   NOTE: This check applies to RHEL versions 8.0 and 8.1. If the system is RHEL version 8.2 or newer, this check is not applicable.
	   NOTE: If the security context type of the non-default tally directory is not "faillog_t", this is a finding."${BLD}
cci18="CCI-000044"
stigid18="RHEL-08-020028"
severity18="CAT II"
ruleid18="SV-250316r793010_rule"
vulnid18="V-250316"

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

osmajor="$(echo $os | awk '{print $6}' | awk -F. '{print $1}')"
osminor="$(echo $os | awk '{print $6}' | awk -F. '{print $2}')"

datetime="$(date +%FT%H:%M:%S)"

if (( $osmajor == 8 && $osminor <2 ))
then

  file1arr=("/etc/pam.d/password-auth" "/etc/pam.d/system-auth")
  
  for file in ${file1arr[@]}
  do
    echo "$file----------------------------------------------"
    pwauth="$(egrep -i pam_faillock.so $file)"
    if [[ $pwauth ]]
    then
      for line in ${pwauth[@]}
      do
        if [[ ${line:0:1} != "#" ]]
        then
          if [[ ($line =~ 'auth' || $line =~ 'account') && $line =~ 'required' ]]
          then
            if [[ $line =~ 'preauth' ]]
            then
              IFS=' ' elements="$(echo $line)"
              for segment in ${elements[@]}
              do
                if [[ $segment =~ 'deny' ]]
                then
                  denyval="$(echo $segment | awk -F= '{print $2}')"
                  if (( $denyval > 0 && $denyval <= 3 ))
                  then
                    fail=0
                    echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
                  else
                    echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
                  fi
                fi
              done
  	    IFS=$'\n'
  	    if [[ $fail == 1 ]]
              then
                echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
  	    fi
  	  else
              echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
            fi
          fi
        else
          echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
        fi
      done
    else
      echo -e "${NORMAL}RESULT:    ${RED}\"pam_faillock\" not defined in $file{NORMAL}"
    fi
  done
  echo "----------------------------------------------------------------------"
  
  if [[ $fail == 0 ]]
  then
    echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, {GRN}PASSED, RHEL 8 automatically locks an account when three unsuccessful logon attempts occur.${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}missing \"deny=3\"${NORMAL}"
    echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci11, $datetime, ${RED}FAILED, RHEL 8 does not automatically lock an account when three unsuccessful logon attempts occur.${NORMAL}"
  fi

else
  echo -e "${NORMAL}RESULT:    ${GRN}The system is running $os${NORMAL}"
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}N/A, Does not apply to this version of the OS.${NORMAL}"
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

osmajor="$(echo $os | awk '{print $6}' | awk -F. '{print $1}')"
osminor="$(echo $os | awk '{print $6}' | awk -F. '{print $2}')"

datetime="$(date +%FT%H:%M:%S)"

if (( $osmajor == 8 && $osminor >=2 ))
then
	
  file2="/etc/security/faillock.conf"
  
  if [[ -f $file2 ]]
  then
    pwlock="$(grep deny $file2 | grep -v "^#" | grep -v "root")"
    if [[ $pwlock ]]
    then
      lockval="$(echo $pwlock | awk -F= '{print $2}')"
      if (( $lockval > 0 && $lockval <= 3 ))
      then
        echo -e "${NORMAL}RESULT:    ${BLD}$pwlock${NORMAL}"
        fail=0
      else
        echo -e "${NORMAL}RESULT:    ${RED}$pwlock${NORMAL}"
      fi
    else
       echo -e "${NORMAL}RESULT:    ${RED}\"deny =\" not defined in $file2.${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}$file2 not found.${NORMAL}"
  fi
  
  if [[ $fail == 0 ]]
  then
    echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, RHEL 8 automatically locks an account when three unsuccessful logon attempts occur.${NORMAL}"
  else
    echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, RHEL 8 does not automatically lock an account when three unsuccessful logon attempts occur.${NORMAL}"
  fi
  
else
  echo -e "${NORMAL}RESULT:    ${GRN}The system is running $os${NORMAL}"
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}N/A, Does not apply to this version of the OS.${NORMAL}"
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

osmajor="$(echo $os | awk '{print $6}' | awk -F. '{print $1}')"
osminor="$(echo $os | awk '{print $6}' | awk -F. '{print $2}')"

datetime="$(date +%FT%H:%M:%S)"

if (( $osmajor == 8 && $osminor <2 ))
then

  file3arr=("/etc/pam.d/password-auth" "/etc/pam.d/system-auth")
  
  for file in ${file3arr[@]}
  do
    echo "$file----------------------------------------------"
    pwauth="$(egrep -i pam_faillock.so $file)"
    if [[ $pwauth ]]
    then
      for line in ${pwauth[@]}
      do
        if [[ ${line:0:1} != "#" ]]
        then
          if [[ ($line =~ 'auth' || $line =~ 'account') && $line =~ 'required' ]]
          then
            if [[ $line =~ 'preauth' ]]
            then
              IFS=' ' elements="$(echo $line)"
              for segment in ${elements[@]}
              do
                if [[ $segment =~ 'fail_interval' ]]
                then
                  failintval="$(echo $segment | awk -F= '{print $2}')"
                  if (( $failintval >= 0 && $failintval <= 900 ))
                  then
                    fail=0
                    echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
                  else
                    echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
                  fi
                fi
              done
  	    IFS=$'\n'
  	    if [[ $fail == 1 ]]
              then
                echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
  	    fi
  	  else
              echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
            fi
          fi
        else
          echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
        fi
      done
    else
      echo -e "${NORMAL}RESULT:    ${RED}\"pam_faillock\" not defined in $file{NORMAL}"
    fi
  done
  echo "----------------------------------------------------------------------"

  if [[ $fail == 0 ]]
  then
    echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${GRN}PASSED, RHEL 8 automatically locks an account when three unsuccessful logon attempts occur during a 15-minute time period.${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}missing \"fail_interval=900\"${NORMAL}"
    echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${RED}FAILED, RHEL 8 does not automatically locks an account when three unsuccessful logon attempts occur during a 15-minute time period.${NORMAL}"
  fi

else
  echo -e "${NORMAL}RESULT:    ${GRN}The system is running $os${NORMAL}"
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${GRN}N/A, Does not apply to this version of the OS.${NORMAL}"
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

osmajor="$(echo $os | awk '{print $6}' | awk -F. '{print $1}')"
osminor="$(echo $os | awk '{print $6}' | awk -F. '{print $2}')"

datetime="$(date +%FT%H:%M:%S)"

if (( $osmajor == 8 && $osminor >=2 ))
then

  file4="/etc/security/faillock.conf"
  
  if [[ -f $file4 ]]
  then
    pwlock="$(grep fail_interval $file4 | grep -v "^#")"
    if [[ $pwlock ]]
    then
      lockval="$(echo $pwlock | awk -F= '{print $2}')"
      if (( $lockval > 0 && $lockval <= 900 ))
      then
        echo -e "${NORMAL}RESULT:    ${BLD}$pwlock${NORMAL}"
        fail=0
      else
        echo -e "${NORMAL}RESULT:    ${RED}$pwlock${NORMAL}"
      fi
    else
       echo -e "${NORMAL}RESULT:    ${RED}\"fail_interval =\" not defined in $file4.${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}$file4 not found.${NORMAL}"
  fi
  
  if [[ $fail == 0 ]]
  then
    echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${GRN}PASSED, RHEL 8 automatically locks an account when three unsuccessful logon attempts occur during a 15-minute time period.${NORMAL}"
  else
    echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${RED}FAILED, RHEL 8 does not automatically lock an account when three unsuccessful logon attempts occur during a 15-minute time period.${NORMAL}"
  fi
  
else
  echo -e "${NORMAL}RESULT:    ${GRN}The system is running $os${NORMAL}"
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${GRN}N/A, Does not apply to this version of the OS.${NORMAL}"
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

osmajor="$(echo $os | awk '{print $6}' | awk -F. '{print $1}')"
osminor="$(echo $os | awk '{print $6}' | awk -F. '{print $2}')"

datetime="$(date +%FT%H:%M:%S)"

if (( $osmajor == 8 && $osminor <2 ))
then

  file5arr=("/etc/pam.d/password-auth" "/etc/pam.d/system-auth")
  
  for file in ${file5arr[@]}
  do
    echo "$file----------------------------------------------"
    pwauth="$(egrep -i pam_faillock.so $file)"
    if [[ $pwauth ]]
    then
      for line in ${pwauth[@]}
      do
        if [[ ${line:0:1} != "#" ]]
        then
          if [[ ($line =~ 'auth' || $line =~ 'account') && $line =~ 'required' ]]
          then
            if [[ $line =~ 'preauth' || $line =~ 'authfail' ]]
            then
              IFS=' ' elements="$(echo $line)"
              for segment in ${elements[@]}
              do
                if [[ $segment =~ 'unlock_time' ]]
                then
                  unlockval="$(echo $segment | awk -F= '{print $2}')"
                  if (( $unlockval == 0 ))
                  then
                    fail=0
                    echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
                  else
                    echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
                  fi
                fi
              done
  	    IFS=$'\n'
  	    if [[ $fail == 1 ]]
              then
                echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
  	    fi
  	  else
              echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
            fi
          fi
        else
          echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
        fi
      done
    else
      echo -e "${NORMAL}RESULT:    ${RED}\"pam_faillock\" not defined in $file{NORMAL}"
    fi
  done
  echo "----------------------------------------------------------------------"
  
  if [[ $fail == 0 ]]
  then
    echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${GRN}PASSED, RHEL 8 automatically locks an account until the locked account is released by an administrator when three unsuccessful logon attempts occur during a 15-minute time period.${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}missing \"unlock_time=0\"${NORMAL}"
    echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${RED}FAILED, RHEL 8 does not automatically locks an account until the locked account is released by an administrator when three unsuccessful logon attempts occur during a 15-minute time period.${NORMAL}"
  fi

else
  echo -e "${NORMAL}RESULT:    ${GRN}The system is running $os${NORMAL}"
  echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${GRN}N/A, Does not apply to this version of the OS.${NORMAL}"
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

osmajor="$(echo $os | awk '{print $6}' | awk -F. '{print $1}')"
osminor="$(echo $os | awk '{print $6}' | awk -F. '{print $2}')"

datetime="$(date +%FT%H:%M:%S)"

if (( $osmajor == 8 && $osminor >=2 ))
then

  file6="/etc/security/faillock.conf"
  
  if [[ -f $file6 ]]
  then
    unlock="$(grep unlock_time $file6 | grep -v "^#")"
    if [[ $unlock ]]
    then
      lockval="$(echo $unlock | awk -F= '{print $2}')"
      if (( $lockval == 0 ))
      then
        echo -e "${NORMAL}RESULT:    ${BLD}$unlock${NORMAL}"
        fail=0
      else
        echo -e "${NORMAL}RESULT:    ${RED}$unlock${NORMAL}"
      fi
    else
       echo -e "${NORMAL}RESULT:    ${RED}\"unlock_time =\" not defined in $file6.${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}$file6 not found.${NORMAL}"
  fi
  
  if [[ $fail == 0 ]]
  then
    echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${GRN}PASSED, RHEL 8 automatically locks an account until the locked account is released by an administrator when three unsuccessful logon attempts occur during a 15-minute time period.${NORMAL}"
  else
    echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${RED}FAILED, RHEL 8 does not automatically lock an account until the locked account is released by an administrator when three unsuccessful logon attempts occur during a 15-minute time period.${NORMAL}"
  fi

else
  echo -e "${NORMAL}RESULT:    ${GRN}The system is running $os${NORMAL}"
  echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${GRN}N/A, Does not  apply to this version of the OS. ${NORMAL}"
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

fail=1

osmajor="$(echo $os | awk '{print $6}' | awk -F. '{print $1}')"
osminor="$(echo $os | awk '{print $6}' | awk -F. '{print $2}')"

datetime="$(date +%FT%H:%M:%S)"

if (( $osmajor == 8 && $osminor <2 ))
then

  file7arr=("/etc/pam.d/password-auth" "/etc/pam.d/system-auth")
  
  for file in ${file7arr[@]}
  do
    echo "$file----------------------------------------------"
    pwauth="$(grep pam_faillock.so $file)"
    if [[ $pwauth ]]
    then
      for line in ${pwauth[@]}
      do
        if [[ ${line:0:1} != "#" ]]
        then
          if [[ ($line =~ 'auth' || $line =~ 'account') && $line =~ 'required' ]]
          then
            if [[ $line =~ 'preauth' || $line =~ 'authfail' ]]
            then
              IFS=' ' elements="$(echo $line)"
              for segment in ${elements[@]}
              do
                if [[ $segment =~ 'dir' ]]
                then
                  dirval="$(echo $segment | awk -F= '{print $2}')"
                  if [[ $dirval == '/var/log/faillock' ]]
                  then
                    fail=0
                    echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
                  else
                    echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
                  fi
                fi
              done
  	    IFS=$'\n'
  	    if [[ $fail == 1 ]]
              then
                echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
  	    fi
  	  else
              echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
            fi
          fi
        else
          echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
        fi
      done
    else
      echo -e "${NORMAL}RESULT:    ${RED}\"pam_faillock\" not defined in $file{NORMAL}"
    fi
  done
  echo "----------------------------------------------------------------------"

  if [[ $fail == 0 ]]
  then
    echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${GRN}PASSED, RHEL 8 ensures account lockouts persist.${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}missing \"dir=/var/log/faillock\"${NORMAL}"
    echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${RED}FAILED, RHEL 8 does not ensure account lockouts persist${NORMAL}"
  fi

else
  echo -e "${NORMAL}RESULT:    ${GRN}The system is running $os${NORMAL}"
  echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${GRN}N/A, Does not apply to this version of the OS.${NORMAL}"
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

osmajor="$(echo $os | awk '{print $6}' | awk -F. '{print $1}')"
osminor="$(echo $os | awk '{print $6}' | awk -F. '{print $2}')"

datetime="$(date +%FT%H:%M:%S)"

if (( $osmajor == 8 && $osminor >=2 ))
then
	
  file8="/etc/security/faillock.conf"
  
  if [[ -f $file8 ]]
  then
    lockdir="$(grep 'dir =' $file8 | grep -v "^#")"
    if [[ $lockdir ]]
    then
      dirval="$(echo $lockdir | awk -F= '{print $2}')"
      if (( $dirval == 'var/log/faillock' ))
      then
        echo -e "${NORMAL}RESULT:    ${BLD}$lockdir${NORMAL}"
        fail=0
      else
        echo -e "${NORMAL}RESULT:    ${RED}$lockdir${NORMAL}"
      fi
    else
       echo -e "${NORMAL}RESULT:    ${RED}\"dir =\" not defined in $file8.${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}$file8 not found.${NORMAL}"
  fi
  
  if [[ $fail == 0 ]]
  then
    echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cci8, $datetime, ${GRN}PASSED, RHEL 8 ensures account lockouts persist.${NORMAL}"
  else
    echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cci8, $datetime, ${RED}FAILED, RHEL 8 does not ensure account lockouts persist.${NORMAL}"
  fi
  
else
  echo -e "${NORMAL}RESULT:    ${GRN}The system is running $os${NORMAL}"
  echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cci8, $datetime, ${GRN}N/A, Does not apply to this version of the OS.${NORMAL}"
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

osmajor="$(echo $os | awk '{print $6}' | awk -F. '{print $1}')"
osminor="$(echo $os | awk '{print $6}' | awk -F. '{print $2}')"

datetime="$(date +%FT%H:%M:%S)"

if (( $osmajor == 8 && $osminor <2 ))
then
	
  file9arr=("/etc/pam.d/password-auth" "/etc/pam.d/system-auth")
  
  for file in ${file7arr[@]}
  do
    echo "$file----------------------------------------------"
    pwauth="$(grep pam_faillock.so $file)"
    if [[ $pwauth ]]
    then
      for line in ${pwauth[@]}
      do
        if [[ ${line:0:1} != "#" ]]
        then
          if [[ ($line =~ 'auth' || $line =~ 'account') && $line =~ 'required' ]]
          then
            if [[ $line =~ 'preauth' ]]
            then
              IFS=' ' elements="$(echo $line)"
              for segment in ${elements[@]}
              do
                if [[ $segment =~ 'silent' ]]
                then
                  fail=0
                  echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
                else
                  echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
                fi
              done
  	      IFS=$'\n'
  	      if [[ $fail == 1 ]]
              then
                echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
  	      fi
  	    else
              echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
            fi
          fi
        else
          echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
        fi
      done
    else
      echo -e "${NORMAL}RESULT:    ${RED}\"pam_faillock\" not defined in $file{NORMAL}"
    fi
  done

  if [[ $fail == 0 ]]
  then
    echo -e "${NORMAL}$hostname, $severity9, $controlid, $stigid9, $ruleid9, $cci9, $datetime, ${GRN}PASSED, RHEL 8 ensures account lockouts persist.${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}missing \"dir=/var/log/faillock\"${NORMAL}"
    echo -e "${NORMAL}$hostname, $severity9, $controlid, $stigid9, $ruleid9, $cci9, $datetime, ${RED}FAILED, RHEL 8 does not ensure account lockouts persist${NORMAL}"
  fi

else
  echo -e "${NORMAL}RESULT:    ${GRN}The system is running $os${NORMAL}"
  echo -e "${NORMAL}$hostname, $severity9, $controlid, $stigid9, $ruleid9, $cci9, $datetime, ${GRN}N/A, Does not apply to this version of the OS.${NORMAL}"
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


osmajor="$(echo $os | awk '{print $6}' | awk -F. '{print $1}')"
osminor="$(echo $os | awk '{print $6}' | awk -F. '{print $2}')"

datetime="$(date +%FT%H:%M:%S)"

if (( $osmajor == 8 && $osminor >=2 ))
then
	
  file10="/etc/security/faillock.conf"
  
  if [[ -f $file10 ]]
  then
    silent="$(grep 'silent' $file10 | grep -v "^#")"
    if [[ $silent ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$silent{NORMAL}"
      fail=0
    else
      echo -e "${NORMAL}RESULT:    ${RED}\"silent\" not defined in $file10.${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}$file10 not found.${NORMAL}"
  fi
  
  if [[ $fail == 0 ]]
  then
    echo -e "${NORMAL}$hostname, $severity10, $controlid, $stigid10, $ruleid10, $cci10, $datetime, ${GRN}PASSED, RHEL 8 prevents system messages from being presented when three unsuccessful logon attempts occur.${NORMAL}"
  else
    echo -e "${NORMAL}$hostname, $severity10, $controlid, $stigid10, $ruleid10, $cci10, $datetime, ${RED}FAILED, RHEL 8 does not prevent system messages from being presented when three unsuccessful logon attempts occur.${NORMAL}"
  fi
  
else
  echo -e "${NORMAL}RESULT:    ${GRN}The system is running $os${NORMAL}"
  echo -e "${NORMAL}$hostname, $severity10, $controlid, $stigid10, $ruleid10, $cci10, $datetime, ${GRN}N/A, Does not apply to this version of the OS.${NORMAL}"
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

osmajor="$(echo $os | awk '{print $6}' | awk -F. '{print $1}')"
osminor="$(echo $os | awk '{print $6}' | awk -F. '{print $2}')"

datetime="$(date +%FT%H:%M:%S)"

if (( $osmajor == 8 && $osminor <2 ))
then
	
  file11arr=("/etc/pam.d/password-auth" "/etc/pam.d/system-auth")
  
  for file in ${file11arr[@]}
  do
    echo "$file----------------------------------------------"
    pwauth="$(grep pam_faillock.so $file)"
    if [[ $pwauth ]]
    then
      for line in ${pwauth[@]}
      do
        if [[ ${line:0:1} != "#" ]]
        then
          if [[ ($line =~ 'auth' || $line =~ 'account') && $line =~ 'required' ]]
          then
            if [[ $line =~ 'preauth' ]]
            then
              IFS=' ' elements="$(echo $line)"
              for segment in ${elements[@]}
              do
                if [[ $segment =~ 'audit' ]]
                then
                  fail=0
                  echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
                fi
              done
  	      IFS=$'\n'
  	      if [[ $fail == 1 ]]
              then
                echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
  	      fi
  	    else
              echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
            fi
          fi
        else
          echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
        fi
      done
    else
      echo -e "${NORMAL}RESULT:    ${RED}\"pam_faillock\" not defined in $file{NORMAL}"
    fi
  done

  if [[ $fail == 0 ]]
  then
    echo -e "${NORMAL}$hostname, $severity11, $controlid, $stigid11, $ruleid11, $cci11, $datetime, ${GRN}PASSED, RHEL 8 logs user name information when unsuccessful logon attempts occur.${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}missing \"audit\"${NORMAL}"
    echo -e "${NORMAL}$hostname, $severity11, $controlid, $stigid11, $ruleid11, $cci11, $datetime, ${RED}FAILED, RHEL 8 does not log user name information when unsuccessful logon attempts occur.${NORMAL}"
  fi

else
  echo -e "${NORMAL}RESULT:    ${GRN}The system is running $os${NORMAL}"
  echo -e "${NORMAL}$hostname, $severity11, $controlid, $stigid11, $ruleid11, $cci11, $datetime, ${GRN}N/A, Does not apply to this version of the OS.${NORMAL}"
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

osmajor="$(echo $os | awk '{print $6}' | awk -F. '{print $1}')"
osminor="$(echo $os | awk '{print $6}' | awk -F. '{print $2}')"

datetime="$(date +%FT%H:%M:%S)"

if (( $osmajor == 8 && $osminor >=2 ))
then
	
  file12="/etc/security/faillock.conf"
  
  if [[ -f $file12 ]]
  then
    audit="$(grep 'audit' $file12 | grep -v "^#")"
    if [[ $audit ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$audit{NORMAL}"
      fail=0
    else
      echo -e "${NORMAL}RESULT:    ${RED}\"audit\" not defined in $file12.${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}$file12 not found.${NORMAL}"
  fi
  
  if [[ $fail == 0 ]]
  then
    echo -e "${NORMAL}$hostname, $severity12, $controlid, $stigid12, $ruleid12, $cci12, $datetime, ${GRN}PASSED, RHEL 8 logs user name information when unsuccessful logon attempts occur.${NORMAL}"
  else
    echo -e "${NORMAL}$hostname, $severity12, $controlid, $stigid12, $ruleid12, $cci12, $datetime, ${RED}FAILED, RHEL 8 does not log user name information when unsuccessful logon attempts occur.${NORMAL}"
  fi
  
else
  echo -e "${NORMAL}RESULT:    ${GRN}The system is running $os${NORMAL}"
  echo -e "${NORMAL}$hostname, $severity12, $controlid, $stigid12, $ruleid12, $cci12, $datetime, ${GRN}N/A, Does not apply to this version of the OS.${NORMAL}"
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

fail=1

osmajor="$(echo $os | awk '{print $6}' | awk -F. '{print $1}')"
osminor="$(echo $os | awk '{print $6}' | awk -F. '{print $2}')"

datetime="$(date +%FT%H:%M:%S)"

if (( $osmajor == 8 && $osminor <2 ))
then
	
  file13arr=("/etc/pam.d/password-auth" "/etc/pam.d/system-auth")
  
  for file in ${file13arr[@]}
  do
    echo "$file----------------------------------------------"
    pwauth="$(grep pam_faillock.so $file)"
    if [[ $pwauth ]]
    then
      for line in ${pwauth[@]}
      do
        if [[ ${line:0:1} != "#" ]]
        then
          if [[ ($line =~ 'auth' || $line =~ 'account') && $line =~ 'required' ]]
          then
            if [[ $line =~ 'preauth' ]]
            then
              IFS=' ' elements="$(echo $line)"
              for segment in ${elements[@]}
              do
                if [[ $segment =~ 'even_deny_root' ]]
                then
                  fail=0
                  echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
                fi
              done
  	      IFS=$'\n'
  	      if [[ $fail == 1 ]]
              then
                echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
  	      fi
  	    else
              echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
            fi
          fi
        else
          echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
        fi
      done
    else
      echo -e "${NORMAL}RESULT:    ${RED}\"pam_faillock\" not defined in $file{NORMAL}"
    fi
  done

  if [[ $fail == 0 ]]
  then
    echo -e "${NORMAL}$hostname, $severity13, $controlid, $stigid13, $ruleid13, $cci13, $datetime, ${GRN}PASSED, RHEL 8 includes root when automatically locking an account until the locked account is released by an administrator when three unsuccessful logon attempts occur during a 15-minute time period.${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}missing \"even_deny_root\"${NORMAL}"
    echo -e "${NORMAL}$hostname, $severity13, $controlid, $stigid13, $ruleid13, $cci13, $datetime, ${RED}FAILED, RHEL 8 does not include root when automatically locking an account until the locked account is released by an administrator when three unsuccessful logon attempts occur during a 15-minute time period.${NORMAL}"
  fi

else
  echo -e "${NORMAL}RESULT:    ${GRN}The system is running $os${NORMAL}"
  echo -e "${NORMAL}$hostname, $severity13, $controlid, $stigid13, $ruleid13, $cci13, $datetime, ${GRN}N/A, Does not apply to this version of the OS.${NORMAL}"
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

fail=1

osmajor="$(echo $os | awk '{print $6}' | awk -F. '{print $1}')"
osminor="$(echo $os | awk '{print $6}' | awk -F. '{print $2}')"

datetime="$(date +%FT%H:%M:%S)"

if (( $osmajor == 8 && $osminor >=2 ))
then
	
  file14="/etc/security/faillock.conf"
  
  if [[ -f $file14 ]]
  then
    evenroot="$(grep 'even_deny_root' $file14 | grep -v "^#")"
    if [[ $evenroot ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$evenroot${NORMAL}"
      fail=0
    else
      echo -e "${NORMAL}RESULT:    ${RED}\"even_deny_root\" not defined in $file14.${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}$file14 not found.${NORMAL}"
  fi
  
  if [[ $fail == 0 ]]
  then
    echo -e "${NORMAL}$hostname, $severity14, $controlid, $stigid14, $ruleid14, $cci14, $datetime, ${GRN}PASSED, RHEL 8 includes root when automatically locking an account until the locked account is released by an administrator when three unsuccessful logon attempts occur during a 15-minute time period.${NORMAL}"
  else
    echo -e "${NORMAL}$hostname, $severity14, $controlid, $stigid14, $ruleid14, $cci14, $datetime, ${RED}FAILED, RHEL 8 does not include root when automatically locking an account until the locked account is released by an administrator when three unsuccessful logon attempts occur during a 15-minute time period.${NORMAL}"
  fi
  
else
  echo -e "${NORMAL}RESULT:    ${GRN}The system is running $os${NORMAL}"
  echo -e "${NORMAL}$hostname, $severity14, $controlid, $stigid14, $ruleid14, $cci14, $datetime, ${GRN}N/A, Does not apply to this version of the OS.${NORMAL}"
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

fail=1

osmajor="$(echo $os | awk '{print $6}' | awk -F. '{print $1}')"
osminor="$(echo $os | awk '{print $6}' | awk -F. '{print $2}')"

datetime="$(date +%FT%H:%M:%S)"

if (( $osmajor == 8 && $osminor >=2 ))
then
	
  file15arr=("/etc/pam.d/system-auth")
  count=0
  preauthcount=0
  pamunixcount=0
  
  for file in ${file15arr[@]}
  do
    echo "$file----------------------------------------------"
    pwauth="$(grep -E 'pam_faillock.so|pam_unix.so' $file)"
    if [[ $pwauth ]]
    then
      for line in ${pwauth[@]}
      do
        (( count++))
        if [[ ${line:0:1} != "#" ]]
        then
          if [[ ($line =~ 'auth' || $line =~ 'account') && $line =~ 'required' ]]
          then
            if [[ $line =~ 'preauth' ]]
            then
	      preauthcount=$count 
	      if (( $pamunixcount == 0 || $preauthcount < $pamunixcount ))
	      then
		echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
		fail=0
	      else
		echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
              fi
            else
	      echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
	    fi
	  elif [[ $line =~ 'pam_unix.so' ]]
	  then
            pamunixcount=$count
	    if (( $preauthcount < $pamunixcount ))
            then
	      echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
	    else
	      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
	    fi
          fi
        else
          echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
        fi
      done
    else
      echo -e "${NORMAL}RESULT:    ${RED}\"pam_faillock\" not defined in $file{NORMAL}"
    fi
  done

  if [[ $fail == 0 ]]
  then
    echo -e "${NORMAL}$hostname, $severity15, $controlid, $stigid15, $ruleid15, $cci15, $datetime, ${GRN}PASSED, RHEL 8 configures the use of the pam_faillock.so module in the /etc/pam.d/system-auth file.${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}missing \"pam_faillock.so\"${NORMAL}"
    echo -e "${NORMAL}$hostname, $severity15, $controlid, $stigid15, $ruleid15, $cci15, $datetime, ${RED}FAILED, RHEL 8 does not configure the use of the pam_faillock.so module (at least properly) in the /etc/pam.d/system-auth file.${NORMAL}"
  fi

else
  echo -e "${NORMAL}RESULT:    ${GRN}The system is running $os${NORMAL}"
  echo -e "${NORMAL}$hostname, $severity15, $controlid, $stigid15, $ruleid15, $cci15, $datetime, ${GRN}N/A, Does not apply to this version of the OS.${NORMAL}"
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

fail=1

osmajor="$(echo $os | awk '{print $6}' | awk -F. '{print $1}')"
osminor="$(echo $os | awk '{print $6}' | awk -F. '{print $2}')"

datetime="$(date +%FT%H:%M:%S)"

if (( $osmajor == 8 && $osminor >=2 ))
then
	
  file16arr=("/etc/pam.d/password-auth")
  count=0
  preauthcount=0
  pamunixcount=0
  
  for file in ${file16arr[@]}
  do
    echo "$file----------------------------------------------"
    pwauth="$(grep -E 'pam_faillock.so|pam_unix.so' $file)"
    if [[ $pwauth ]]
    then
      for line in ${pwauth[@]}
      do
        (( count++))
        if [[ ${line:0:1} != "#" ]]
        then
          if [[ ($line =~ 'auth' || $line =~ 'account') && $line =~ 'required' ]]
          then
            if [[ $line =~ 'preauth' ]]
            then
              preauthcount=$count
              if (( $pamunixcount == 0 || $preauthcount < $pamunixcount ))
              then
                echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
                fail=0
              else
                echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
              fi
            else
              echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
            fi
          elif [[ $line =~ 'pam_unix.so' ]]
          then
            pamunixcount=$count
            if (( $preauthcount < $pamunixcount ))
            then
              echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
            else
              echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
            fi
          fi
        else
          echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
        fi
      done
    else
      echo -e "${NORMAL}RESULT:    ${RED}\"pam_faillock\" not defined in $file{NORMAL}"
    fi
  done

  if [[ $fail == 0 ]]
  then
    echo -e "${NORMAL}$hostname, $severity16, $controlid, $stigid16, $ruleid16, $cci16, $datetime, ${GRN}PASSED, RHEL 8 configures the use of the pam_faillock.so module in the /etc/pam.d/password-auth file.${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}missing \"pam_faillock.so\"${NORMAL}"
    echo -e "${NORMAL}$hostname, $severity16, $controlid, $stigid16, $ruleid16, $cci16, $datetime, ${RED}FAILED, RHEL 8 does not configure the use of the pam_faillock.so module (at least properly) in the /etc/pam.d/password-auth file.${NORMAL}"
  fi

else
  echo -e "${NORMAL}RESULT:    ${GRN}The system is running $os${NORMAL}"
  echo -e "${NORMAL}$hostname, $severity16, $controlid, $stigid16, $ruleid16, $cci16, $datetime, ${GRN}N/A, Does not apply to this version of the OS.${NORMAL}"
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

fail=1

osmajor="$(echo $os | awk '{print $6}' | awk -F. '{print $1}')"
osminor="$(echo $os | awk '{print $6}' | awk -F. '{print $2}')"

datetime="$(date +%FT%H:%M:%S)"

if (( $osmajor == 8 && $osminor >=2 ))
then
  file17="/etc/security/faillock.conf"
  if [[ -f $file17 ]]
  then
    dir="$(grep -w dir $file17 | grep -v "^#")"
    if [[ $dir ]]
    then
      dirpath="$(echo $dir | awk -F= '{print $2}' | sed 's/ //g')"
      if [[ $dirpath == "/var/log/faillock" || ! $dirpath =~ "/var/run/" ]]
      then
	echo -e "${NORMAL}RESULT:    ${BLD}a. $dir${NORMAL}"
        context="$(ls -Zd $dirpath)"
        contextval="$(echo $context | awk -F: '{print $3}')"
        if [[ $contextval == "faillog_t" ]]
        then
	  echo -e "${NORMAL}RESULT:    ${BLD}b. $context${NORMAL}"
	  fail=0
        else
	  echo -e "${NORMAL}RESULT:    ${RED}b. $context${NORMAL}"
        fi
      else
	echo -e "${NORMAL}RESULT:    ${RED}a. $dirpath is a default location${NORMAL}"
      fi
    else
      echo -e "${NORMAL}RESULT:    ${RED}a. \"dir\" is not defined in $file17.${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}$file17 not found${NORMAL}"
  fi

  if [[ $fail == 0 ]]
  then
    echo -e "${NORMAL}$hostname, $severity17, $controlid, $stigid17, $ruleid17, $cci17, $datetime, ${GRN}PASSED, RHEL 8 configures SELinux context type to allow the use of a non-default faillock tally directory.${NORMAL}"
  else
    echo -e "${NORMAL}$hostname, $severity17, $controlid, $stigid17, $ruleid17, $cci17, $datetime, ${RED}FAILED, RHEL 8 does not configure SELinux context type to allow the use of a non-default faillock tally directory.${NORMAL}"
  fi

else
  echo -e "${NORMAL}RESULT:    ${GRN}The system is running $os${NORMAL}"
  echo -e "${NORMAL}$hostname, $severity17, $controlid, $stigid17, $ruleid17, $cci17, $datetime, ${GRN}N/A, Does not apply to this version of the OS.${NORMAL}"
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

fail=1

osmajor="$(echo $os | awk '{print $6}' | awk -F. '{print $1}')"
osminor="$(echo $os | awk '{print $6}' | awk -F. '{print $2}')"

datetime="$(date +%FT%H:%M:%S)"

if (( $osmajor == 8 && $osminor <2 ))
then
  file18="/etc/pam.d/password-auth"
  if [[ -f $file18 ]]
  then
    dir="$(grep -w dir $file18 | grep -v "^#")"
    if [[ $dir ]]
    then
      for line in ${dir[@]}
      do
        IFS=' ' elements="$(echo $line)"
	for segment in ${elements[@]}
	do
	  if [[ $segment =~ 'dir=' ]]
	  then
	    dirpath="$(echo $segment | awk -F= '{print $2}' | sed 's/ //g')"
            if [[ $dirpath == "/var/log/faillock" || ! $dirpath =~ "/var/run/" ]]
            then
      	      echo -e "${NORMAL}RESULT:    ${BLD}a. $dir${NORMAL}"
              context="$(ls -Zd $dirpath)"
              context="$(echo $context | awk -F: '{print $3}')"
              if [[ $contextval == "faillog_t" ]]
              then
      	        echo -e "${NORMAL}RESULT:    ${BLD}b. $context${NORMAL}"
      	        fail=0
              else
      	        echo -e "${NORMAL}RESULT:    ${RED}b. $context${NORMAL}"
              fi
            else
      	      echo -e "${NORMAL}RESULT:    ${RED}a. $dirpath is a default location${NORMAL}"
            fi
	  fi
	done
      done
    else
      echo -e "${NORMAL}RESULT:    ${RED}a. \"dir\" is not defined in $file18.${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}$file18 not found${NORMAL}"
  fi

  if [[ $fail == 0 ]]
  then
    echo -e "${NORMAL}$hostname, $severity18, $controlid, $stigid18, $ruleid17, $cci18, $datetime, ${GRN}PASSED, RHEL 8 configures SELinux context type to allow the use of a non-default faillock tally directory.${NORMAL}"
  else
    echo -e "${NORMAL}$hostname, $severity18, $controlid, $stigid18, $ruleid18, $cci18, $datetime, ${RED}FAILED, RHEL 8 does not configure SELinux context type to allow the use of a non-default faillock tally directory.${NORMAL}"
  fi

else
  echo -e "${NORMAL}RESULT:    ${GRN}The system is running $os${NORMAL}"
  echo -e "${NORMAL}$hostname, $severity18, $controlid, $stigid18, $ruleid18, $cci18, $datetime, ${GRN}N/A, Does not apply to this version of the OS.${NORMAL}"
fi 

exit
