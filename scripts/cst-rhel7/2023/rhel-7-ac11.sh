#! /bin/bash

# AC-11 Session Lock
# CONTROL: The information system:
# a. Prevents further access to the system by initiating a session lock after 
#    [Assignment: organization-defined time period] of inactivity or upon 
#    receiving a request from a user; and
# b. Retains the session lock until the user reestablishes access using established
#    identification and authentication procedures.

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

controlid="AC-11 Session Lock"

title1a="The Red Hat Enterprise Linux operating system must enable a user session lock until that user re-establishes access using established identification and authentication procedures."
title1b="Checking with grep -ir lock-enabled /etc/dconf* | grep '='."
title1c="Expecting: ${YLO}lock-enabled=true
           Note: If the system does not have GNOME installed, this requirement is Not Applicable.
           Note: If the \"lock-enabled\" setting is missing or is not set to \"true\", this is a finding.${BLD}"
cci1="CCI-000056"
stigid1="RHEL-07-010060"
severity1="CAT II"
ruleid1="SV-204396r603261_rule"
vulnid1="V-204396"

title2a="The Red Hat Enterprise Linux operating system must initiate a screensaver after a 15-minute period of inactivity for graphical user interfaces."
title2b="Checking with 'grep -ir idle-delay /etc/dconf*'."
title2c="Expecting: ${YLO}idle-delay=uint32 900
           Note: If the system does not have GNOME installed, this requirement is Not Applicable.
           Note: If the \"idle-delay\" setting is missing or is not set to \"900\" or less, this is a finding.${BLD}"
cci2="CCI-000057"
stigid2="RHEL-07-010070"
severity2="CAT II"
ruleid2="SV-204398r603261_rule"
vulnid2="V-204398"

title3a="The Red Hat Enterprise Linux operating system must have the screen package installed."
title3b="Checking with:
           a. 'yum list installed screen'.
	   b. 'yum list installed tmux'"
title3c="Expecting:${YLO}
           a. screen.x86_64
	   b. tmux-1.8-4.el7.x86_64.rpm
           Note: If either the screen package or the tmux package is not installed, this is a finding.${BLD}"
cci3="CCI-000057"
stigid3="RHEL-07-010090"
severity3="CAT II"
ruleid3="SV-255926r880779_rule"
vulnid3="V-255926"

title4a="The Red Hat Enterprise Linux operating system must initiate a session lock for the screensaver after a period of inactivity for graphical user interfaces."
title4b="Checking with 'grep -ir idle-activation-enabled' /etc/dconf*"
title4c="Expecting: ${YLO}idle-activation-enabled=true
           Note: If it is installed, GNOME must be configured to enforce a session lock after a 15-minute delay.
           Note: If \"idle-activation-enabled\" is not set to \"true\", this is a finding.${BLD}"
cci4="CCI-000057"
stigid4="RHEL-07-010100"
severity4="CAT II"
ruleid4="SV-204402r603261_rule"
vulnid4="V-204402"

title5a="The Red Hat Enterprise Linux operating system must initiate a session lock for graphical user interfaces when the screensaver is activated."
title5b="Checking with 'grep -ir lock-delay /etc/dconf*"
title5c="Expecting: ${YLO}lock-delay=uint32 5
           Note: If the system does not have GNOME installed, this requirement is Not Applicable.
           Note: The screen program must be installed to lock sessions on the console.${BLD}"
cci5="CCI-000057"
stigid5="RHEL-07-010110"
severity5="CAT II"
ruleid5="SV-204404r603261_rule"
vulnid5="V-204404"

title6a="The Red Hat Enterprise Linux operating system must prevent a user from overriding the screensaver lock-delay setting for the graphical user interface."
title6b="Checking with 'grep system-db /etc/dconf/profile/user'."
title6c="Expecting: ${YLO}system-db:local
           Note: If the system does not have GNOME installed, this requirement is Not Applicable.
           Note: If the command does not return a result, this is a finding.${BLD}"
cci6="CCI-000057"
stigid6="RHEL-07-010081"
severity6="CAT II"
ruleid6="SV-204399r603261_rule"
vulnid6="V-204399"

title7a="The Red Hat Enterprise Linux operating system must prevent a user from overriding the session idle-delay setting for the graphical user interface."
title7b="Checking with
           a. 'grep system-db /etc/dconf/profile/user'
           b. 'grep -i idle-delay /etc/dconf/db/local.d/locks/*'."
title7c="Expecting: ${YLO}
           a. system-db:local
           b. /org/gnome/desktop/session/idle-delay
           Note: If the system does not have GNOME installed, this requirement is Not Applicable. 
           Note: The screen program must be installed to lock sessions on the console.
           Note: If the command does not return a result, this is a finding.${BLD}"
cci7="CCI-000057"
stigid7="RHEL-07-010082"
severity7="CAT II"
ruleid7="SV-204400r603261_rule"
vulnid7="V-204400"

title9a="The Red Hat Enterprise Linux operating system must prevent a user from overriding the screensaver idle-activation-enabled setting for the graphical user interface."
title9b="Checking with
           a. 'grep system-db /etc/dconf/profile/user'
           b. 'grep -i idle-activation-enabled /etc/dconf/db/local.d/locks/*'."
title9c="Expecting: ${YLO}
           a. system-db:local
           b. /org/gnome/desktop/screensaver/idle-activation-enabled.
           Note: If the system does not have GNOME installed, this requirement is Not Applicable.
           Note: The screen program must be installed to lock sessions on the console.
           Note: If the command does not return a result, this is a finding.${BLD}"
cci9="CCI-000057"
stigid9="RHEL-07-010101"
severity9="CAT II"
ruleid9="SV-204403r603261_rule"
vulnid9="V-204403"

title10a="The Red Hat Enterprise Linux operating system must prevent a user from overriding the screensaver lock-enabled setting for the graphical user interface."
title10b="Checking with:
           a. 'grep system-db /etc/dconf/profile/user', then
	   b. 'grep -i lock-enabled /etc/dconf/db/local.d/locks/*'"
title10c="Expecting:${YLO}
           a. system-db:local
	   b. /org/gnome/desktop/screensaver/lock-enabled
	   Note: If the system does not have GNOME installed, this requirement is Not Applicable.
	   Note: The example below is using the database \"local\" for the system, so the path is \"/etc/dconf/db/local.d\". This path must be modified if a database other than \"local\" is being used.${BLD}"
cci10="CCI-000057"
stigid10="RHEL-07-010062"
severity10="CAT II"
ruleid10="SV-214937r603261_rule"
vulnid10="V-214937"

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

dir1="/etc/dconf"
fail=1

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

gnomeinstalled="$(rpm -qa | grep gnome | egrep '(desktop|session)')"

if [[ $gnomeinstalled ]]
then

   if [[ -d $dir1 ]]
   then
      dconf="$(grep -ir 'lock-enabled' $dir1* | grep '=')"
      if [[ $dconf ]]
      then
         dbfile="$(echo $dconf | awk -F: '{print $1}')"
         lckenabled="$(echo $dconf | awk -F: '{print $3}')"
         isenabled="$(echo $lckenabled | awk -F'= ' '{print $2}')"

         echo -e "${NORMAL}RESULT:    ${BLD}file: $dbfile${NORMAL}"

         if [[ $dconf =~ 'lock-enabled=true' ||
	       $dconf =~ 'lock-enabled = true'
	    ]]
         #if [[ $isenabled =~ 'true' ]]
         then         
            #echo -e "${NORMAL}RESULT:    ${BLD}$lckenabled${NORMAL}"
            echo -e "${NORMAL}RESULT:    ${BLD}$dconf${NORMAL}"
            fail=0
         else
            echo -e "${NORMAL}RESULT:    ${RED}$lckenabled${NORMAL}"
         fi
      else
         echo -e "${NORMAL}RESULT:    lock-enabled is not configured in $dir1${NORMAL}"
      fi

      if [[ $fail == 0 ]]
      then
         echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, Session Lock: The operating system initiates a session lock for graphical user interfaces when the screensaver is activated.${NORMAL}"
      else
         echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, Session Lock: The operating system does not initiate a session lock for graphical user interfaces when the screensaver is activated.${NORMAL}"
      fi
   else
      echo -e "${NORMAL}RESULT:    $dir1 not found${NORMAL}"
      echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, Session Lock: $dir1 not found${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}GNOME server and client RPMs not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}N/A, Session Lock: GNOME is not installed${NORMAL}"
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

dir2="/etc/dconf"
fail=1

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

gnomeinstalled="$(rpm -qa | grep gnome | egrep '(desktop|session)')"

if [[ $gnomeinstalled ]]
then

   if [[ -d $dir2 ]]
   then
      dconf="$(grep -ir 'idle-delay' $dir2* | grep '=')"
      if [[ $dconf ]]
      then
         dbfile="$(echo $dconf | awk -F: '{print $1}')"
         idledelay="$(echo $dconf | awk -F: '{print $3}')"
         delaytime="$(echo $idledelay | awk -F'= ' '{print $2}' | awk '{print $2}')"

         echo -e "${NORMAL}RESULT:    ${BLD}file: $dbfile${NORMAL}"

         if (( $delaytime <= 900 && $delaytime != 0 ))
         then
            echo -e "${NORMAL}RESULT:    ${BLD}$idledelay${NORMAL}"
            fail=0
         else
            echo -e "${NORMAL}RESULT:    ${RED}$idledelay${NORMAL}"
         fi
      else
         echo -e "${NORMAL}RESULT:    idle-delay is not configured in $dir2${NORMAL}"
      fi

      if [[ $fail == 0 ]]
      then
         echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, Screensaver Timeout: The operating system initiates a screensaver after a $seconds second period of inactivity for graphical user interfaces${NORMAL}"
      else
         echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetimem, ${RED}FAILED, Screensaver Timeout: The operating system initiates a screensaver after a $seconds second period of inactivity for graphical user interfaces${NORMAL}"
      fi
   else
      echo -e "${NORMAL}RESULT:    $dir2 not found${NORMAL}"
      echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, Screensaver Timeout: $dir2 not found${NORMAL}"
   fi

else
   echo -e "${NORMAL}RESULT:    ${BLD}GNOME server and client RPMs not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}N/A, Screensaver Timeout: GNOME is not installed${NORMAL}"
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

datetime="$(date +%FT%H:%M:%S)"

fail=0

pkgarr=("screen" "tmux")

for package in ${pkgarr[@]}
do
  rpmarr="$(rpm -qa | grep ^$package 2>/dev/null)"
  if [[ $rpmarr ]]
  then
    for rpm in ${rpmarr[@]}
    do
      echo -e "${NORMAL}RESULT:    ${BLD}$rpm${NORMAL}"
    done
  else
    echo -e "${NORMAL}RESULT:    ${RED}The \"$package\" package is not installed.${NORMAL}"
    fail=1
  fi
done

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${GRN}PASSED, Both the \"screen\" and \"tmux\" package are installed${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${RED}FAILED, The \"screen\" and/or \"tmux\" package is not installed${NORMAL}"
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

dir4="/etc/dconf"
fail=1

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

gnomeinstalled="$(rpm -qa | grep gnome | egrep '(desktop|session)')"

if [[ $gnomeinstalled ]]
then

   if [[ -d $dir4 ]]
   then
      dconf="$(grep -ir 'idle-activation' $dir4* | grep '=')"
      if [[ $dconf ]]
      then
         dbfile="$(echo $dconf | awk -F: '{print $1}')"
         idleactivation="$(echo $dconf | awk -F: '{print $3}')"
         isenabled="$(echo $lckenabled | awk -F'= ' '{print $2}')"

         echo -e "${NORMAL}RESULT:    ${BLD}file: $dbfile${NORMAL}"

         if [[ $isenabled =~ 'true' ]]
         then
            echo -e "${NORMAL}RESULT:    ${BLD}$idleactivation${NORMAL}"
            fail=0
         else
            echo -e "${NORMAL}RESULT:    ${RED}$idleactivation${NORMAL}"
         fi
      else
         echo -e "${NORMAL}RESULT:    idle-activation is not configured in $dir4${NORMAL}"
      fi

      if [[ $fail == 0 ]]
      then
         echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${GRN}PASSED, Session Lock: The operating system initiates a session lock for the screensaver after a period of inactivity for graphical user interfaces${NORMAL}"
      else
         echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${RED}FAILED, Session Lock: The operating system does not initiate a session lock for the screensaver after a period of inactivity for graphical user interfaces${NORMAL}"
      fi
   else
      echo -e "${NORMAL}RESULT:    $dir4 not found${NORMAL}"
      echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${RED}FAILED, Session Lock: $dir4 not found${NORMAL}"
   fi

else
   echo -e "${NORMAL}RESULT:    ${BLD}GNOME server and client RPMs not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${GRN}N/A, Session Lock: GNOME is not installed${NORMAL}"
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

dir5="/etc/dconf"
fail=1

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

gnomeinstalled="$(rpm -qa | grep gnome | egrep '(desktop|session)')"

if [[ $gnomeinstalled ]]
then

   if [[ -d $dir5 ]]
   then
      dconf="$(grep -ir lock-delay $dir5* | grep '=')"
      if [[ $dconf ]]
      then
         dbfile="$(echo $dconf | awk -F: '{print $1}')"
         lockdelay="$(echo $dconf | awk -F: '{print $3}')"
         delaytime="$(echo $lockdelay | awk -F'= ' '{print $2}')"

         echo -e "${NORMAL}RESULT:    ${BLD}file: $dbfile${NORMAL}"

         if (( $delaytime <= 5 && $delaytime != 0 ))
         then
            echo -e "${NORMAL}RESULT:    ${BLD}$lockdelay${NORMAL}"
            fail=0
         else
            echo -e "${NORMAL}RESULT:    ${RED}$lockdelay${NORMAL}"
         fi
      else
         echo -e "${NORMAL}RESULT:    lock-delay is not configured in $dir5${NORMAL}"
      fi

      if [[ $fail == 0 ]]
      then
         echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${GRN}PASSED, Session Lock: The operating system initiates a session lock for graphical user interfaces 5 seconds or less after the screensaver is activated.${NORMAL}"
      else
         echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${RED}FAILED, Session Lock: The operating system does not initiate a session lock for graphical user interfaces 5 seconds or less after the screensaver is activated.${NORMAL}"
      fi
   else
      echo -e "${NORMAL}RESULT:    $dir5 not found${NORMAL}"
      echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${RED}FAILED, Session Lock: $dir5 not found${NORMAL}"
   fi

else
   echo -e "${NORMAL}RESULT:    ${BLD}GNOME server and client RPMs not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${GRN}N/A, Session Lock: GNOME is not installed${NORMAL}"
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

dir6="/etc/dconf/db"
fail=0

gnomeinstalled="$(rpm -qa | grep gnome | egrep '(desktop|session)')"

if [[ $gnomeinstalled ]]
then

   if [[ -d $dir6 ]]
   then
      dconf="$(grep -ir 'lock-delay' $dir6/* | grep -v '=' | grep -v 'Binary')"
      if [[ $dconf ]]
      then
         echo -e "${NORMAL}RESULT:    ${BLD}$dconf${NORMAL}"
      else
         echo -e "${NORMAL}RESULT:    lock-delay is not configured in $dir6${NORMAL}"
         fail=1
      fi

      if [[ $fail == 0 ]]
      then
         echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${GRN}PASSED, Screensaver Lock Delay: The operating system prevents a user from overriding the screensaver lock-delay setting for the graphical user interface.${NORMAL}"
      else
         echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${RED}FAILED, Screensaver Lock Delay: The operating system does not prevent a user from overriding the screensaver lock-delay setting for the graphical user interface.${NORMAL}"
      fi
   else
      echo -e "${NORMAL}RESULT:    $dir6 not found${NORMAL}"
      echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${RED}FAILED, Screensaver Lock Delay: $dir6 not found${NORMAL}"
   fi

else
   echo -e "${NORMAL}RESULT:    ${BLD}GNOME server and client RPMs not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${GRN}N/A, Screensaver Lock Delay: GNOME is not installed${NORMAL}"
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

dir7="/etc/dconf"
fail=0

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

gnomeinstalled="$(rpm -qa | grep gnome | egrep '(desktop|session)')"

if [[ $gnomeinstalled ]]
then

   if [[ -d $dir7 ]]
   then
      dconf="$(grep -ir 'idle-delay' $dir7*)"
      if [[ $dconf ]]
      then
         dbfile="$(echo $dconf | awk -F: '{print $1}')"
         idledelay="$(echo $dconf | awk -F: '{print $3}')"

         echo -e "${NORMAL}RESULT:    ${BLD}file: $dbfile${NORMAL}"
         echo -e "${NORMAL}RESULT:    ${BLD}$idledelay${NORMAL}"
      else
         echo -e "${NORMAL}RESULT:    idle-delay is not configured in $dir7${NORMAL}"
         fail=1
      fi

      if [[ $fail == 0 ]]
      then
         echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${GRN}PASSED, Session Idle-Delay Override: The operating system prevents a user from overriding the session idle-delay setting for the graphical user interface.${NORMAL}"
      else
         echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${RED}FAILED, Session Idle-Delay Override: The operating system does not prevent a user from overriding the session idle-delay setting for the graphical user interface.${NORMAL}"
      fi
   else
      echo -e "${NORMAL}RESULT:    $dir7 not found${NORMAL}"
      echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${RED}FAILED, Session Idle-Delay Override: $dir7 not found${NORMAL}"
   fi

else
   echo -e "${NORMAL}RESULT:    ${BLD}GNOME server and client RPMs not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${GRN}N/A, Session Idle-Delay Override: GNOME is not installed${NORMAL}"
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

dir9="/etc/dconf"
fail=0

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

gnomeinstalled="$(rpm -qa | grep gnome | egrep '(desktop|session)')"

if [[ $gnomeinstalled ]]
then

   if [[ -d $dir9 ]]
   then
      db="$(grep -R 'system-db'  $dir9)"
      if [[ $db ]]
      then
         for line in ${db[@]}
         do
            echo -e "${NORMAL}RESULT:    a. $line${NORMAL}"
         done
      else
         echo -e ${NORMAL}RESULT:    ${RED}a. Nothing found${NORMAL}
         fail=1
      fi
      dconf="$(grep -R 'idle-activation-enabled' $dir9)"
      if [[ $dconf ]]
      then
         for line in ${dconf[@]}
         do
            echo -e "${NORMAL}RESULT:    ${BLD}b. $line${NORMAL}"
         done
      else
         echo -e "${NORMAL}RESULT:    ${RED}b. idle-activation-enabled is not configured in $dir9${NORMAL}"
         fail=1
      fi

      if [[ $fail == 0 ]]
      then
         echo -e "${NORMAL}$hostname, $severity9, $controlid, $stigid9, $ruleid9, $cci9, $datetime, ${GRN}PASSED, Screensaver Activation Override: The operating system prevents a user from overriding the screensaver idle-activation-enabled setting for the graphical user interface.${NORMAL}"
      else
         echo -e "${NORMAL}$hostname, $severity9, $controlid, $stigid9, $ruleid9, $cci9, $datetime, ${RED}FAILED, Screensaver Activation Override: The operating system does not prevent a user from overriding the screensaver idle-activation-enabled setting for the graphical user interface.${NORMAL}"
      fi
   else
      echo -e "${NORMAL}RESULT:    $dir9 not found${NORMAL}"
      echo -e "${NORMAL}$hostname, $severity9, $controlid, $stigid9, $ruleid9, $cci9, $datetime, ${RED}FAILED, Screensaver Activation Override: $dir9 not found${NORMAL}"
   fi

else
   echo -e "${NORMAL}RESULT:    ${BLD}GNOME server and client RPMs not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity9, $controlid, $stigid9, $ruleid9, $cci9, $datetime, ${GRN}N/A, Screensaver Activation Override: GNOME is not installed${NORMAL}"
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

dir10="/etc/dconf"
fail=1

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

gnomeinstalled="$(rpm -qa | grep gnome | egrep '(desktop|session)')"

if [[ $gnomeinstalled ]]
then
  if [[ -d $dir10 ]]
  then
    dconf="$(grep -ir 'system-db' $dir10*/*)"
    if [[ $dconf ]]
    then
      for x in ${dconf[@]}
      do
        if [[ $x =~ 'db:local' ]]
        then
          echo -e "${NORMAL}RESULT:    ${BLD}a. $x${NORMAL}"
        else
          echo -e "${NORMAL}RESULT:    a. $x${NORMAL}"
        fi
      done
    else
      echo -e "${NORMAL}RESULT:    ${RED}a. Nothing returned${NORMAL}"
    fi
    lockenabled="$(grep -ir lock-enabled $dir10*/* 2>/dev/null | grep 'locks')"
    if [[ $lockenabled ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}b. $lockenabled${NORMAL}"
      fail=0
    else
      echo -e "${NORMAL}RESULT:    ${RED}b. (nothing returned)${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}a. $dir10 not found.${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    GNOME is not installed.${NORMAL}"
  fail=3
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity10, $controlid, $stigid10, $ruleid10, $cci10, $datetime, ${GRN}PASSED, The operating system prevents a user from overriding the screensaver lock-enabled setting for the graphical user interface.${NORMAL}"
elif [[ $fail == 3 ]]
then
  echo -e "${NORMAL}$hostname, $severity10, $controlid, $stigid10, $ruleid10, $cci10, $datetime, ${GRN}PASSED, This requirement is Not Applicable because a graphical user interface is not installed.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity10, $controlid, $stigid10, $ruleid10, $cci10, $datetime, ${RED}FAILED, The operating system does not prevent a user from overriding the screensaver lock-enabled setting for the graphical user interface.${NORMAL}"
fi

exit
