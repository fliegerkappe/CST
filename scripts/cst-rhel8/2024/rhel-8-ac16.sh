#! /bin/bash

# AC-16 Security and Privacy Attributes

# CONTROL:
# a. Provide the  means to associate [Assignment: organization-defined typesof security and
#    privacy attributes] with [Assignment: organization-defined security andprivacy attribute
#    values] for information in storage, in process, and/or in transmission;
# b. Ensure that the attribute associations are made and retained with the information;
# c. Establish the following permitted security andprivacyattributes from the attributes defined
#    in 'AC-16a' for [Assignment: organization-defined systems]:[Assignment: organization-defined
#    security and privacyattributes];
# d. Determine the following permitted attribute values or ranges for each of the established
#    attributes: [Assignment: organization-defined attribute values or ranges for established
#    attributes];
# e. Audit changes to attributes; and
# f. Review [Assignment: organization-defined security and privacy attributes] for applicability
#    [Assignment: organization-defined frequency].

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

controlid="AC-16 Security and Privacy Attributes"

title1a="RHEL 8 must prevent nonprivileged users from executing privileged functions, including disabling, circumventing, or altering implemented security safeguards/countermeasures."
title1b="Checking with: 'semanage login -l | more'."
title1c="Expecting: ${YLO}
           Login Name           SELinux User         MLS/MCS Range        Service

           __default__          user_u               s0-s0:c0.c1023       *
           root                 unconfined_u         s0-s0:c0.c1023       *
	   system_u             system_u             s0-s0.c0.c1023       *
	   joe                  staff_u              s0-s0.c0.c1023       *
	   NOTE: All administrators must be mapped to the \"sysadm_u\", \"staff_u\", or an appropriately tailored confined role as defined by the organization.
	   NOTE: All authorized nonadministrative users must be mapped to the \"user_u\" role.
	   NOTE: If they are not mapped in this way, this is a finding."${BLD}
cci1="CCI-002265"
stigid1="RHEL-08-040400"
severity1="CAT II"
ruleid1="SV-254520r928805_rule"
vulnid1="V-254520"

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

users="$(semanage login -l)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $users ]]
then
  for line in ${users[@]}
  do
	  if [[ ($line =~ 'default' && ! $line =~ 'user_u') ||
		($line =~ 'root' && ! $line =~ 'unconfined_u') ||
		($line =~ 'system_u' && ! $line =~ 'system_u')
	     ]]
    then
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
      fail=1
    else
      echo -e "${NORMAL}RESULT:    $line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 1 ]]
then
	echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, The \"__default__\" user should be listed as \"user_u\". Have the ISSO or System Administrator verify that the operating system prevents nonprivileged users from executing privileged functions, including disabling, circumventing, or altering implemented security safeguards/countermeasures.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${CYN}VERIFY, Have the ISSO or System Administrator verify that the operating system prevents nonprivileged users from executing privileged functions, including disabling, circumventing, or altering implemented security safeguards/countermeasures.${NORMAL}"
fi  

exit
