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

stig="Red Hat Enterprise Linux 8 Security Technical Implementation Guide :: Version 1, Release: 13 Benchmark Date: 24 Jan 2024"

hostname="$(uname -n)"

if [[ -f /etc/redhat-release ]]
then
   os="$(cat /etc/redhat-release)"
else
   os="OS not defined"
fi

prog="$(basename $0)"

controlid="AC-11 Session Lock"

title1a="RHEL 8 must enable a user session lock until that user re-establishes access using established identification and authentication procedures for graphical user sessions."
title1b="Checking with: 'gsettings get org.gnome.desktop.screensaver lock-enabled'."
title1c="Expecting: ${YLO}true
           NOTE: This requirement assumes the use of the RHEL 8 default graphical user interface, Gnome Shell. If the system does not have any graphical user interface installed, this requirement is Not Applicable.
	   NOTE: If the setting is \"false\", this is a finding."${BLD}
cci1="CCI-000056"
stigid1="RHEL-08-020030"
severity1="CAT II"
ruleid1="SV-230347r627750_rule"
vulnid1="V-230347"

title2a="RHEL 8 must enable a user session lock until that user re-establishes access using established identification and authentication procedures for command line sessions."
title2b="Checking with: 'grep -Ei 'lock-command|lock-session' /etc/tmux.conf'."
title2c="Expecting: ${YLO}
           set -g lock-command vlock
	   bind X lock-session
           NOTE: If the \"lock-command\" is not set and \"lock-session\" is not bound to a specific keyboard key in the global settings, this is a finding."${BLD}
cci2="CCI-000056"
stigid2="RHEL-08-020040"
severity2="CAT II"
ruleid2="SV-230348r902725_rule"
vulnid2="V-230348"

title3a="RHEL 8 must ensure session control is automatically started at shell initialization."
title3b="Checking with:
           a. ps all | grep tmux | grep -v grep
	   b. grep -r tmux /etc/bashrc /etc/profile.d
	   c. cat /etc/profile.d/tmux.sh"
title3c="Expecting: ${YLO}
           a. 4     0    5270    5267  20   0 238160  6052 x64_sy S+   pts/0      0:00 tmux
	   b. /etc/profile.d/tmux.sh:  case \"$name\" in sshd|login) exec tmux ;; esac
	   c. if [ \"\$PS1\" ]; then
           c.   parent=\$(ps -o ppid= -p \$\$)
           c.   name=\$(ps -o comm= -p \$parent)
           c.   case \"\$name\" in sshd|login) exec tmux ;; esac
           c. fi
	   NOTE: If the 'ps all | grep tmux' command does not produce an output, this is a finding.
           NOTE: If \"tmux\" is not configured as the example above, is commented out, or is missing, this is a finding."${BLD}
cci3="CCI-000056"
stigid3="RHEL-08-020041"
severity3="CAT II"
ruleid3="SV-230349r917920_rule"
vulnid3="V-230349"

title4a="RHEL 8 must prevent users from disabling session control mechanisms."
title4b="Checking with: 'grep -i tmux /etc/shells'."
title4c="Expecting: ${YLO}Nothing returned
           NOTE: If any output is produced, this is a finding."${BLD}
cci4="CCI-000056"
stigid4="RHEL-08-020042"
severity4="CAT III"
ruleid4="SV-230350r627750_rule"
vulnid4="V-230350"

title5a="RHEL 8 must be able to initiate directly a session lock for all connection types using smartcard when the smartcard is removed."
title5b="Checking with: 'grep -R removal-action /etc/dconf/db/*'."
title5c="Expecting: ${YLO}/etc/dconf/db/distro.d/20-authselect:removal-action='lock-screen'
           NOTE: If the \"removal-action='lock-screen'\" setting is missing or commented out from the dconf database files, this is a finding."${BLD}
cci5="CCI-000056"
stigid5="RHEL-08-020050"
severity5="CAT II"
ruleid5="SV-230351r792899_rule"
vulnid5="V-230351"

title6a="RHEL 8 must automatically lock graphical user sessions after 15 minutes of inactivity."
title6b="Checking with: 'gsettings get org.gnome.desktop.session idle-delay'."
title6c="Expecting: ${YLO}uint32 900
           NOTE: This requirement assumes the use of the RHEL 8 default graphical user interface, Gnome Shell. If the system does not have any graphical user interface installed, this requirement is Not Applicable.
           NOTE: If \"idle-delay\" is set to \"0\" or a value greater than \"900\", this is a finding."
cci6="CCI-000057"
stigid6="RHEL-08-020060"
severity6="CAT II"
ruleid6="SV-230352r646876_rule"
vulnid6="V-230352"

title7a="RHEL 8 must automatically lock command line user sessions after 15 minutes of inactivity."
title7b="Checking with: 'grep -i lock-after-time /etc/tmux.conf'."
title7c="Expecting: ${YLO}set -g lock-after-time 900
           NOTE: If \"lock-after-time\" is not set to \"900\" or less in the global tmux configuration file to enforce session lock after inactivity, this is a finding."${BLD}
cci7="CCI-000057"
stigid7="RHEL-08-020070"
severity7="CAT II"
ruleid7="SV-230353r627750_rule"
vulnid7="V-230353"

title8a="RHEL 8 must prevent a user from overriding the session lock-delay setting for the graphical user interface."
title8b="Checking with: 
           a. grep system-db /etc/dconf/profile/user
	   b. grep -i lock-delay /etc/dconf/db/*"
title8c="Expecting: ${YLO}
           a. system-db:local
	   b. /org/gnome/desktop/screensaver/lock-delay
           NOTE: The example below is using the database \"local\" for the system, so the path is \"/etc/dconf/db/local.d\". This path must be modified if a database other than \"local\" is being used.
	   NOTE: If the command does not return at least the example result, this is a finding."${BLD}
cci8="CCI-000057"
stigid8="RHEL-08-020080"
severity8="CAT II"
ruleid8="SV-230354r743990_rule"
vulnid8="V-230354"

title9a="RHEL 8 must initiate a session lock for graphical user interfaces when the screensaver is activated."
title9b="Checking with: 'gsettings get org.gnome.desktop.screensaver lock-delay'."
title9c="Expecting: ${YLO}uint32 5
           NOTE: This requirement assumes the use of the RHEL 8 default graphical user interface, Gnome Shell. If the system does not have any graphical user interface installed, this requirement is Not Applicable.
           NOTE: If the \"uint32\" setting is set to \"0\", is missing, or is not set to \"5\" or less, this is a finding."
cci9="CCI-000057"
stigid9="RHEL-08-020031"
severity9="CAT II"
ruleid9="SV-244535r743854_rule"
vulnid9="V-244535"

title10a="RHEL 8 must have the tmux package installed."
title10b="Checking with: 'yum list installed tmux'."
title10c="Expecting: ${YLO}tmux.x86.64                     2.7-1.el8                         @repository
           NOTE: If "tmux" is not installed, this is a finding."${BLD}
cci10="CCI-000056"
stigid10="RHEL-08-020039"
severity10="CAT II"
ruleid10="SV-244537r743860_rule"
vulnid10="V-244537"

title11a="RHEL 8 must prevent a user from overriding the session idle-delay setting for the graphical user interface."
title11b="Checking with:
           a. grep system-db /etc/dconf/profile/user
	   b. grep -i idle-delay /etc/dconf/db/local.d/locks/*'."
title11c="Expecting: ${YLO}
           a. system-db:local
	   b. /org/gnome/desktop/session/idle-delay'
           NOTE: If the system does not have GNOME installed, this requirement is Not Applicable. 
	   NOTE: The example below is using the database \"local\" for the system, so the path is \"/etc/dconf/db/local.d\". This path must be modified if a database other than \"local\" is being used.
           NOTE: If the command does not return at least the example result, this is a finding."${BLD}
cci11="CCI-000057"
stigid11="RHEL-08-020081"
severity11="CAT II"
ruleid11="SV-244538r743863_rule"
vulnid11="V-244538"

title12a="RHEL 8 must prevent a user from overriding the screensaver lock-enabled setting for the graphical user interface."
title12b="Checking with:
           a. grep system-db /etc/dconf/profile/user
	   b. grep -ir lock-enabled /etc/dconf/db/local.d/locks/*'."
title12c="Expecting: ${YLO}
           a. system-db:local
	   b. /org/gnome/desktop/screensaver/lock-enabled
           NOTE: If the system does not have GNOME installed, this requirement is Not Applicable.
           NOTE: If the command does not return at least the example result, this is a finding."${BLD}
cci12="CCI-000057"
stigid12="RHEL-08-020082"
severity12="CAT II"
ruleid12="SV-244539r743866_rule"
vulnid12="V-244539"

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

dir1="/etc/dconf/db"
fail=1

IFS='
'

gnomeinstalled="$(rpm -qa | grep gnome | egrep '(desktop|session)')"

datetime="$(date +%FT%H:%M:%S)"

if [[ $gnomeinstalled ]]
then
  enabled="$(gsettings get org.gnome.desktop.screensaver lock-enabled)"
  if [[ $enabled ]]
  then
    if [[ $enabled == "true" ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$enabled${NORMAL}"
      fail=0
    else
      echo -e "${NORMAL}RESULT:    ${RED}$enabled${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}\"lock-enabled\" is not configured.${NORMAL}"
  fi

  if [[ $fail == 0 ]]
  then
    echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, RHEL 8 enables a user session lock until that user re-establishes access using established identification and authentication procedures for graphical user sessions.${NORMAL}"
  else
    echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, RHEL 8 does not enable a user session lock until that user re-establishes access using established identification and authentication procedures for graphical user sessions.${NORMAL}"
  fi

else
  echo -e "${NORMAL}RESULT:    ${BLD}GNOME is not installed${NORMAL}"
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}N/A, A graphical user interface is not installed.${NORMAL}"

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

file2="/etc/tmux.conf"

fail=1
lockcmd=0
locksession=0

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

if [[ $file2 ]]
then
  vlock="$(grep -Ei 'lock-command|lock-session' $file2)"
  if [[ $vlock ]]
  then
    for line in ${vlock[@]}
    do
      if [[ $line == 'set -g lock-command vlock' ]]
      then
        echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
        lockcmd=1
      elif [[ $line =~ 'bind' && $line =~ 'lock-session' ]]
      then
	echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
	locksession=1
      else
        echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
      fi
    done
  else
    echo -e "${NORMAL}RESULT:    ${RED}lock-command and lock-session not defined in $file2${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file2 not found${NORMAL}"
fi

if [[ $lockcmd == 1 && $locksession == 1 ]]
then
  fail=0
elif [[ $lockcmd == 0 ]]
then
  echo -e "${NORMAL}RESULT:    ${RED}lock-command not set in $file2${NORMAL}"
elif [[ $locksession == 0 ]]
then
  echo -e "${NORMAL}RESULT:    ${RED}lock-session not bound to a specific key in $file2${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, RHEL 8 enables a user session lock until that user re-establishes access using established identification and authentication procedures for command line sessions.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, RHEL 8 does not enable a user session lock until that user re-establishes access using established identification and authentication procedures for command line sessions.${NORMAL}"
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

file3a="/etc/profile.d/tmux.sh"
file3b="/mnt/shared/cst/files/tmux.sh"

isrunning=0
locationfound=0
correctconfig=0

fail=1

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

if [[ $file3a ]]
then
  running="$(ps all | grep tmux | grep -v grep)"
  if [[ $running ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}a. $running${NORMAL}"
    isrunning=1
  else
    echo -e "${NORMAL}RESULT:    ${RED}a. nothing returned${NORMAL}"
  fi
  location="$(grep -r tmux /etc/bashrc /etc/profile.d)"
  if [[ $location ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}b. $location${NORMAL}"
    locationfound=1
    tmuxfile="$(echo $location | awk -F: '{print $1}')"
  else
    echo -e "${NORMAL}RESULT:    ${RED}b. tmux.sh not found${NORMAL}"
  fi
  if cmp "$file3a" "$file3b"
  then
    tmuxshell="$(cat $file3a)"
    for line in ${tmuxshell[@]}
    do
      echo -e "${NORMAL}RESULT:    ${BLD}c. $line${NORMAL}"
      correctconfig=1
    done
  else
    echo -e "${NORMAL}RESULT:    ${RED}c. tmux.sh configuration is not correct.${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file3a not found${NORMAL}"
fi

if [[ $isrunning == 1 && $locationfound == 1 && $correctconfig == 1 ]]
then
  fail=0
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${GRN}PASSED, RHEL 8 ensures session control is automatically started at shell initialization.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${RED}FAILED, RHEL 8 does not ensure session control is automatically started at shell initialization.${NORMAL}"
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

file4="/etc/shells"

fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file4 ]]
then
  shells="$(grep -i tmux $file4 2>/dev/null)"
  if [[ $shells ]]
  then
    echo -e "${NORMAL}RESULT:    ${RED}$shells${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned.${NORMAL}"
    fail=0
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file4 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${GRN}PASSED, RHEL 8 prevents users from disabling session control mechanisms.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${RED}FAILED, RHEL 8 does not prevent users from disabling session control mechanisms.${NORMAL}"
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

dir5="/etc/dconf/db"

fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ -d $dir5 ]]
then
  removal="$(grep -R removal-action $dir5/* | grep -v "^Binary" | grep -v "locks")"
  if [[ $removal =~ "lock-screen" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$removal${NORMAL}"
    fail=0
  else
    echo -e "${NORMAL}RESULT:    ${RED}$removal${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$dir5 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${GRN}PASSED, RHEL 8 is able to initiate directly a session lock for all connection types using smartcard when the smartcard is removed.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${RED}FAILED, RHEL 8 is able to initiate directly a session lock for all connection types using smartcard when the smartcard is removed.${NORMAL}"
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

dir6="/etc/dconf/db"
fail=1

IFS='
'

gnomeinstalled="$(rpm -qa | grep gnome | egrep '(desktop|session)')"

datetime="$(date +%FT%H:%M:%S)"

if [[ $gnomeinstalled ]]
then

  if [[ -d $dir6 ]]
  then
    delay="$(gsettings get org.gnome.desktop.session idle-delay)"
    if [[ $delay ]]
     then
       idledelay="$(echo $delay | awk '{print $2}')"
       if (( $idledelay > 0 && $idledelay <= 900 ))
       then
         echo -e "${NORMAL}RESULT:    ${BLD}$delay${NORMAL}"
         fail=0
       else
         echo -e "${NORMAL}RESULT:    ${RED}$delay${NORMAL}"
       fi
     else
       echo -e "${NORMAL}RESULT:    ${RED}\"idle-delay\" is not configured in $dir6/*${NORMAL}"
     fi

     if [[ $fail == 0 ]]
     then
        echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${GRN}PASSED, RHEL 8 automatically locks graphical user sessions after 15 minutes of inactivity.${NORMAL}"
     else
        echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${RED}FAILED, RHEL 8 does not automatically lock graphical user sessions after 15 minutes of inactivity.${NORMAL}"
     fi
  else
     echo -e "${NORMAL}RESULT:    $dir6 not found${NORMAL}"
     echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${RED}FAILED, RHEL 8 does not automatically lock graphical user sessions after 15 minutes of inactivity.${NORMAL}"
  fi

else
   echo -e "${NORMAL}RESULT:    ${BLD}GNOME server and client RPMs not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${GRN}N/A, GNOME is not installed${NORMAL}"
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

file7="/etc/tmux.conf"

fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file7 ]]
then
  lockafter="$(grep -i lock-after-time $file7)"
  if [[ $lockafter == "set -g lock-after-time 900" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$lockafter${NORMAL}"
    fail=0
  else
    echo -e "${NORMAL}RESULT:    ${BLD}$lockafter${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${BLD}\"$file7\" not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${GRN}PASSED, RHEL 8 is able to initiate directly a session lock for all connection types using smartcard when the smartcard is removed.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${RED}FAILED, RHEL 8 is able to initiate directly a session lock for all connection types using smartcard when the smartcard is removed.${NORMAL}"
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

file8="/etc/dconf/profile/user"
dir8="/etc/dconf/db"

db=0
delay=0

fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file8 ]]
then
  systemdb="$(grep system-db $file8)"
  if [[ $systemdb ]]
  then
    for line in ${systemdb[@]}
    do
      if [[ $line == "system-db:local" ]]
      then
        echo -e "${NORMAL}RESULT:    ${BLD}a. $line${NORMAL}"
        db=1
      else
        echo -e "${NORMAL}RESULT:    a. $line${NORMAL}"
      fi
    done
  else
    echo -e "${NORMAL}RESULT:    ${RED}\"system-db\" not defined in $file8${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file8 not found${NORMAL}"
fi

if [[ $dir8 ]]
then
  delay="$(grep -ir lock-delay $dir8/* 2>/dev/null)"
  if [[ $delay =~ "lock-delay" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}b. $delay${NORMAL}"
    delay=1
  else
    echo -e "${NORMAL}RESULT:    ${RED}b. \"lock-delay\" is not defined in $dir8/*.${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$dir8 not found${NORMAL}"
fi

if [[ $db == 1 && $delay == 1 ]]
then
  fail=0
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cci8, $datetime, ${GRN}PASSED, RHEL 8 prevents a user from overriding the session lock-delay setting for the graphical user interface.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cci8, $datetime, ${RED}FAILED, RHEL 8 does not prevent a user from overriding the session lock-delay setting for the graphical user interface.${NORMAL}"
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

gnomeinstalled="$(rpm -qa | grep gnome | egrep '(desktop|session)')"

datetime="$(date +%FT%H:%M:%S)"

if [[ $gnomeinstalled ]]
then
  lockdelay="$(gsettings get org.gnome.desktop.screensaver lock-delay)"
  if [[ $lockdelay ]]
  then
    delayval="$(echo $lockdelay | awk '{print $2}')"
    if (( $delayval > 0 && $delayval <= 5 ))
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$lockdelay${NORMAL}"
      fail=0
    else
      echo -e "${NORMAL}RESULT:    ${RED}$lockdelay${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}\"lock-delay\" is not configured in \"org.gnome.desktop.screensaver\"${NORMAL}"
  fi

  if [[ $fail == 0 ]]
  then
    echo -e "${NORMAL}$hostname, $severity9, $controlid, $stigid9, $ruleid9, $cci9, $datetime, ${GRN}PASSED, Session Lock: The operating system initiates a session lock for graphical user interfaces 5 seconds or less after the screensaver is activated.${NORMAL}"
  else
    echo -e "${NORMAL}$hostname, $severity9, $controlid, $stigid9, $ruleid9, $cci9, $datetime, ${RED}FAILED, Session Lock: The operating system does not initiate a session lock for graphical user interfaces 5 seconds or less after the screensaver is activated.${NORMAL}"
  fi
  
else
   echo -e "${NORMAL}RESULT:    ${BLD}GNOME is not installed${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity9, $controlid, $stigid9, $ruleid9, $cci9, $datetime, ${GRN}N/A, GNOME is not installed.${NORMAL}"
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

tmuxinstalled="$(yum list installed tmux 2>/dev/null | grep tmux)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $tmuxinstalled ]]
then
  echo -e "${NORMAL}RESULT:    ${BLD}$tmuxinstalled${NORMAL}"  
  fail=0
else
  echo -e "${NORMAL}RESULT:    ${RED}The \"tmux\" package is not installed.${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity10, $controlid, $stigid10, $ruleid10, $cci10, $datetime, ${GRN}PASSED, RHEL 8 has the tmux package installed.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity10, $controlid, $stigid10, $ruleid10, $cci10, $datetime, ${RED}FAILED, RHEL 8 does not have the tmux package installed.${NORMAL}"
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

file11="/etc/dconf/profile/user"
dir11="/etc/dconf/db/local.d/locks"

db=0

fail=1

IFS='
'

gnomeinstalled="$(rpm -qa | grep gnome | egrep '(desktop|session)')"

datetime="$(date +%FT%H:%M:%S)"

if [[ $gnomeinstalled ]]
then
  systemdb="$(grep system-db $file11)"
  if [[ $systemdb ]]
  then
    for line in ${systemdb[@]}
    do
      if [[ $line =~ "local" ]]
      then
        echo -e "${NORMAL}RESULT:    ${BLD}a. $line${NORMAL}"
        db=1
      else
        echo -e "${NORMAL}RESULT:    a. $line${NORMAL}"
      fi
    done
  else
    echo -e "${NORMAL}RESULT:    ${RED}a. \"system-db\" not defined in $file11${NORMAL}"
  fi

  if [[ -d $dir11 ]]
  then
    dconf="$(grep -ir 'idle' $dir11/*)"
    if [[ $dconf =~ 'idle-delay' ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}b. $dconf${NORMAL}"
      delay=1
    else
      echo -e "${NORMAL}RESULT:    ${RED}b. \"idle-delay\" is not configured in $dir11${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}b. $dir11 not found${NORMAL}"
  fi

  if [[ $db == 1 && $delay == 1 ]]
  then
    fail=0
  fi

  if [[ $fail == 0 ]]
  then
    echo -e "${NORMAL}$hostname, $severity11, $controlid, $stigid11, $ruleid11, $cci11, $datetime, ${GRN}PASSED, RHEL 8 prevents a user from overriding the session idle-delay setting for the graphical user interface.${NORMAL}"
  else
    echo -e "${NORMAL}$hostname, $severity11, $controlid, $stigid11, $ruleid11, $cci11, $datetime, ${RED}FAILED, RHEL 8 does not prevent a user from overriding the session idle-delay setting for the graphical user interface.${NORMAL}"
  fi

else
   echo -e "${NORMAL}RESULT:    ${BLD}GNOME server and client RPMs not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity11, $controlid, $stigid11, $ruleid11, $cci11, $datetime, ${GRN}N/A, GNOME is not installed${NORMAL}"
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

file12="/etc/dconf/profile/user"
dir12="/etc/dconf/db/local.d/locks"

db=0
lock=0

fail=1

IFS='
'

gnomeinstalled="$(rpm -qa | grep gnome | egrep '(desktop|session)')"

datetime="$(date +%FT%H:%M:%S)"

if [[ $gnomeinstalled ]]
then
  systemdb="$(grep system-db $file12)"
  if [[ $systemdb ]]
  then
    for line in ${systemdb[@]}
    do
      if [[ $line =~ "local" ]]
      then
        echo -e "${NORMAL}RESULT:    ${BLD}a. $line${NORMAL}"
        db=1
      else
        echo -e "${NORMAL}RESULT:    a. $line${NORMAL}"
      fi
    done
  else
    echo -e "${NORMAL}RESULT:    ${RED}a. \"system-db\" not defined in $file12${NORMAL}"
  fi

  if [[ -d $dir12 ]]
  then
    dconf="$(grep -i 'lock-enabled' $dir12/* 2>/dev/null)"
    if [[ $dconf ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}b. $dconf${NORMAL}"
      lock=1
    else
      echo -e "${NORMAL}RESULT:    ${RED}b. \"lock-enabled\" is not configured in $dir12${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}b. $dir12 not found${NORMAL}"
  fi

  if [[ $db == 1 && $lock == 1 ]]
  then
    fail=0
  fi

  if [[ $fail == 0 ]]
  then
    echo -e "${NORMAL}$hostname, $severity12, $controlid, $stigid12, $ruleid12, $cci12, $datetime, ${GRN}PASSED, RHEL 8 prevents a user from overriding the screensaver lock-enabled setting for the graphical user interface.${NORMAL}"
  else
    echo -e "${NORMAL}$hostname, $severity12, $controlid, $stigid12, $ruleid12, $cci12, $datetime, ${RED}FAILED, RHEL 8 does not prevent a user from overriding the screensaver lock-enabled setting for the graphical user interface.${NORMAL}"
  fi

else
   echo -e "${NORMAL}RESULT:    ${BLD}GNOME server and client RPMs not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity12, $controlid, $stigid12, $ruleid12, $cci12, $datetime, ${GRN}N/A, GNOME is not installed${NORMAL}"
fi

exit
