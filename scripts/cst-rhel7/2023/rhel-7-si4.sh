#! /bin/bash

# SI-4 INFORMATION SYSTEM MONITORING

# CONTROL: The organization:
# a. Monitors the information system to detect:
#    1. Attacks and indicators of potential attacks in accordance with [Assignment: organization-defined monitoring objectives]; and
#    2. Unauthorized local, network, and remote connections;
# b. Identifies unauthorized use of the information system through [Assignment: organization-defined techniques and methods];
# c. Deploys monitoring devices: (i) strategically within the information system to collect organization-determined essential information; and (ii) at ad hoc locations within the system to track specific types of transactions of interest to the organization;
# d. Protects information obtained from intrusion-monitoring tools from unauthorized access, modification, and deletion;
# e. Heightens the level of information system monitoring activity whenever there is an indication of increased risk to organizational operations and assets, individuals, other organizations, or

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
BAR=`echo    "\e[32;1;46m"`     # aqua separator bar
NORMAL=`echo "\e[0m"`           # normal

stig="Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Version 2, Release: 5 Benchmark Date: 25 Oct 2019"

hostname="$(uname -n)"

if [[ -f /etc/redhat-release ]]
then
   os="$(cat /etc/redhat-release)"
else
   os="OS not defined"
fi

prog="$(basename $0)"

controlid="SI-4 Information System Monitoring"

title1a="The Red Hat Enterprise Linux operating system must have a host-based intrusion detection tool installed."
title1b="Checking with: rpm -qa | grep MFEhiplsm
             then: ps -ef | grep -i \"hipclient\"
             then: find / -name <daemon name>
             then: ps -ef | grep -i <daemon name>"
title1c="Expecting: Verify that the McAfee HIPS module is active on the system:
             then: If the MFEhiplsm package is not installed, check for another intrusion detection system:
             then: Where <daemon name> is the name of the primary application daemon to determine if the application is loaded on the system.
             then: Determine if the application is active on the system:
           Note: If the MFEhiplsm package is not installed and an alternate host-based intrusion detection application has not been documented for use, this is a finding.
           Note: If no host-based intrusion detection system is installed and running on the system, this is a finding.
           Note: If the system does not support the McAfee HIPS package, install and enable a supported intrusion detection system application and document its use with the Authorizing Official."
cci1="CCI-001263"
stigid1="RHEL-07-020019"
severity1="CAT II"
ruleid1="SV-102357r1_rule"
vulnid1="V-92255"

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

isinstalled="$(rpm -qa | grep MFEhiplsm)"

if [[ $isinstalled ]]
then
   echo -e "${NORMAL}RESULT:    ${BLD}$isinstalled${NORMAL}"
else
   fail=2
   echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, ${GRN}PASSED, HIPS - The Red Hat Enterprise Linux operating system has a host-based intrusion detection tool installed, enabled, and active.${NORMAL}"
elif (( $fail == 1 ))
then
   echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, ${RED}FAILED, HIPS - The Red Hat Enterprise Linux operating system has a host-based intrusion detection tool installed, but it is not active.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $rule id1, ${RED}FAILED, HIPS - The Red Hat Enterprise Linux operating system does not have a host-based intrusion detection tool installed.${NORMAL}"
fi

exit
