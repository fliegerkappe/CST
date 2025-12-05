#! /bin/bash

# CM-7 Least Functionality
#
# CONTROL: The organization:
# a. Configures the information system to provide only essential capabilities; and
# b. Prohibits or restricts the use of the following functions, ports, protocols,
#    and/or services: [Assignment: organization-defined prohibited or restricted
#    functions, ports, protocols, and/or services].

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

controlid="CM-7 Least Functionality"

title1a="RHEL 8 must disable the chrony daemon from acting as a server."
title1b="Checking with: grep -w 'port' /etc/chrony.conf"
title1c="Expecting: ${YLO}port 0
           NOTE: If the \"port\" option is not set to \"0\", is commented out or missing, this is a finding."${BLD}
cci1="CCI-000381"
stigid1="RHEL-08-030741"
severity1="CAT II"
ruleid1="SV-230485r928590_rule"
vulnid1="V-230485"

title2a="RHEL 8 must disable network management of the chrony daemon."
title2b="Checking with: grep -w 'cmdport' /etc/chrony.conf"
title2c="Expecting: ${YLO}cmdport 0
           NOTE: If the \"cmdport\" option is not set to \"0\", is commented out or missing, this is a finding."${BLD}
cci2="CCI-000381"
stigid2="RHEL-08-030742"
severity2="CAT III"
ruleid2="SV-230486r928593_rule"
vulnid2="V-230486"

title3a="RHEL 8 must not have the telnet-server package installed."
title3b="Checking with 'yum list installed | grep telnet-server'."
title3c="Expecting: Nothing returned.
           NOTE: If the telnet-server package is installed, this is a finding."
cci3="CCI-000381"
stigid3="RHEL-08-040000"
severity3="CAT I"
ruleid3="SV-230487r627750_rule"
vulnid3="V-230487"

title8a="RHEL 8 must not have any automated bug reporting tools installed."
title8b="Checking with: yum list installed abrt*"
title8c="Expecting: ${YLO}Nothing returned
           NOTE: If any automated bug reporting package is installed, this is a finding."${BLD}
cci8="CCI-000381"
stigid8="RHEL-08-040001"
severity8="CAT II"
ruleid8="SV-230488r627750_rule"
vulnid8="V-230488"

title9a="RHEL 8 must not have the sendmail package installed."
title9b="Checking with: 'yum list installed sendmail'."
title9c="Expecting: ${YLO}Nothing returned
           NOTE: If the sendmail package is installed, this is a finding."${BLD}
cci9="CCI-000381"
stigid9="RHEL-08-040002"
severity9="CAT II"
ruleid9="SV-230489r627750_rule"
vulnid9="V-230489"

title10a="RHEL 8 must enable mitigations against processor-based vulnerabilities."
title10b="Checking with: 'grub2-editenv list | grep pti'."
title10c="Expecting: ${YLO}kernelopts=root=/dev/mapper/rhel-root ro crashkernel=auto resume=/dev/mapper/rhel-swap rd.lvm.lv=rhel/root rd.lvm.lv=rhel/swap rhgb quiet fips=1 audit=1 audit_backlog_limit=8192 ${GRN}pti=on${YLO} boot=UUID=8d171156-cd61-421c-ba41-1c021ac29e82
           NOTE: If the \"pti\" entry does not equal \"on\", is missing, or the line is commented out, this is a finding."${BLD}
cci10="CCI-000381"
stigid10="RHEL-08-040004"
severity10="CAT III"
ruleid10="SV-230491r818842_rule"
vulnid10="V-230491"

title11a="RHEL 8 must not have the rsh-server package installed."
title11b="Checking with: 'yum list installed rsh-server'."
title11c="Expecting: ${YLO}Nothing returned
           NOTE: If the rsh-server package is installed, this is a finding."${BLD}
cci11="CCI-000381"
stigid11="RHEL-08-040010"
severity11="CAT I"
ruleid11="SV-230492r627750_rule"
vulnid11="V-230492"

title12a="RHEL 8 must cover or disable the built-in or attached camera when not in use."
title12b="Checking with: 
           a. modinfo uvcvideo | grep filename
	   b. modprobe uvcvideo
	   c. grep -r uvcvideo /etc/modprobe.d/* | grep \"/bin/true\"
	   d. grep -r uvcvideo /etc/modprobe.d/* | grep \"blacklist\""
title12c="Expecting: ${YLO}
           a. /lib/modules/4.18.0-372.9.1.el8.x86_64/kernel/drivers/media/usb/uvc/uvcvideo.ko.xz
	   b. (the uvcvideo module)
	   c. install uvcvideo /bin/true
	   d. blacklist uvcvideo
           NOTE: a. If the device or operating system does not have a camera installed, this requirement is not applicable. 
	   NOTE: b. If a uvcvideo module is not returned, this requirement is not applicable. 
	   NOTE: c. If the command does not return any output, or the line is commented out, and the collaborative computing device has not been authorized for use, this is a finding.
	   NOTE: d. If the command does not return any output or the output is not \"blacklist uvcvideo\", and the collaborative computing device has not been authorized for use, this is a finding."${BLD}
cci12="CCI-000381"
stigid12="RHEL-08-040020"
severity12="CAT II"
ruleid12="SV-230493r942915_rule"
vulnid12="V-230493"

title13a="RHEL 8 must disable the asynchronous transfer mode (ATM) protocol."
title13b="Checking with: 
           a. modinfo uvcvideo | grep filename
           b. modprobe uvcvideo
           c. grep -r atm /etc/modprobe.d/* | grep \"/bin/true\"
	   d. grep -r atm /etc/modprobe.d/* | grep \"blacklist\""
title13c="Expecting: ${YLO}
           a. /lib/modules/4.18.0-372.9.1.el8.x86_64/kernel/drivers/media/usb/uvc/uvcvideo.ko.xz
           b. (the atm module)
           c. install atm /bin/true
	   d. blacklist atm
	   NOTE: a. If the device or operating system does not have the ATM libraries installed, this requirement is not applicable.
           NOTE: b. If the atm module is not returned, this requirement is not applicable.
           NOTE: c. If the command does not return any output, or the line is commented out, and the collaborative computing device has not been authorized for use, this is a finding.
           NOTE: d. If the command does not return any output, or the line is commented out, and use of the ATM protocol is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding."${BLD}
cci13="CCI-000381"
stigid13="RHEL-08-040021"
severity13="CAT III"
ruleid13="SV-230494r942918_rule"
vulnid13="V-230494"

title14a="RHEL 8 must disable the controller area network (CAN) protocol."
title14b="Checking with: 
           a. grep -r can /etc/modprobe.d/* | grep \"/bin/true\"
	   b. grep -r can /etc/modprobe.d/* | grep \"blacklist\""
title14c="Expecting: ${YLO}
           a. install can /bin/true
	   b. blacklist can
           NOTE: a. If the command does not return any output, or the line is commented out, and use of the CAN protocol is not documented with the Information SystemSuecurity Officer (ISSO) as an operational requirement, this is a finding.
	   NOTE: b. If the command does not return any output, or the output is not \"blacklist can\", and use of the CAN protocol is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding."${BLD}
cci14="CCI-000381"
stigid14="RHEL-08-040022"
severity14="CAT III"
ruleid14="SV-230495r942921_rule"
vulnid14="V-230495"

title15a="RHEL 8 must disable the stream control transmission protocol (SCTP)."
title15b="Checking with: 
           a. grep -r sctp /etc/modprobe.d/* | grep \"/bin/true\"
	   b. grep -r sctp /etc/modprobe.d/* | grep \"blacklist\""
title15c="Expecting: ${YLO}
           a. install sctp /bin/true
	   b. blacklist sctp
           NOTE: a. If the command does not return any output, or the line is commented out, and use of the SCTP protocol is not documented with the Information SystemSuecurity Officer (ISSO) as an operational requirement, this is a finding.
	   NOTE: b. If the command does not return any output, or the output is not \"blacklist sctp\", and use of the SCTP protocol is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding."${BLD}
cci15="CCI-000381"
stigid15="RHEL-08-040023"
severity15="CAT III"
ruleid15="SV-230496r942924_rule"
vulnid15="V-230496"

title16a="RHEL 8 must disable the transparent inter-process communication protocol (TIPC)."
title16b="Checking with: 
           a. grep -r tipc /etc/modprobe.d/* | grep \"/bin/true\"
	   b. grep -r tipc /etc/modprobe.d/* | grep \"blacklist\""
title16c="Expecting: ${YLO}
           a. install tipc /bin/true
	   b. blacklist tipc
           NOTE: a. If the command does not return any output, or the line is commented out, and use of the TIPC protocol is not documented with the Information SystemSuecurity Officer (ISSO) as an operational requirement, this is a finding.
	   NOTE: b. If the command does not return any output, or the output is not \"blacklist tipc\", and use of the TIPC protocol is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding."${BLD}
cci16="CCI-000381"
stigid16="RHEL-08-040024"
severity16="CAT III"
ruleid16="SV-230497r942927_rule"
vulnid16="V-230497"

title17a="RHEL 8 must disable mounting of cramfs."
title17b="Checking with: 
           a. grep -r cramfs /etc/modprobe.d/* | grep \"/bin/true\"
	   b. grep -r cramfs /etc/modprobe.d/* | grep \"blacklist\""
title17c="Expecting: ${YLO}
           a. install cramfs /bin/true
	   b. blacklist cramfs
           NOTE: a. If the command does not return any output, or the line is commented out, and use of the cramfs protocol is not documented with the Information SystemSuecurity Officer (ISSO) as an operational requirement, this is a finding.
	   NOTE: b. If the command does not return any output, or the output is not \"blacklist cramfs\", and use of the crams protocol is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding."${BLD}
cci17="CCI-000381"
stigid17="RHEL-08-040025"
severity17="CAT III"
ruleid17="SV-230498r942930_rule"
vulnid17="V-230498"

title18a="RHEL 8 must disable mounting of cramfs."
title18b="Checking with: 
           a. grep -r firewire-core /etc/modprobe.d/* | grep \"/bin/true\"
	   b. grep -r firewire-core /etc/modprobe.d/* | grep \"blacklist\""
title18c="Expecting: ${YLO}
           a. install firewire-core /bin/true
	   b. blacklist firewire-core
           NOTE: a. If the command does not return any output, or the line is commented out, and use of the firewire-core protocol is not documented with the Information SystemSuecurity Officer (ISSO) as an operational requirement, this is a finding.
	   NOTE: b. If the command does not return any output, or the output is not \"blacklist firewire-core\", and use of the firewire-core protocol is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding."${BLD}
cci18="CCI-000381"
stigid18="RHEL-08-040026"
severity18="CAT III"
ruleid18="SV-230499r942933_rule"
vulnid18="V-230499"

title19a="RHEL 8 must be configured to prohibit or restrict the use of functions prots, protocols, and/or services, as defined in the Ports, Protocols, and Services Management (PPSM) Category Assignments List (CAL) and vulnerability assessments."
title19b="Checking with: 'sudo firewall-cmd --list-all-zones'."
title19c="Expecting: ${YLO}
           custom (active)
           target: DROP
           icmp-block-inversion: no
           interfaces: ens33
           sources:
           services: dhcpv6-client dns http https ldaps rpc-bind ssh
           ports:
           masquerade: no
           forward-ports:
           icmp-blocks:
           rich rules:
           NOTE: Ask the System Administrator for the site or program Ports, Ptrotocols, and Services aManagement Component Local Service Assessment (PPSM CLSA). Verify the services allowed by the firewall match the PPSM CLSA.
           NOTE: If there are additional ports, protocols, or services that are not in the PPSM CLSA, or there are ports, protocols, or services that are prohibited by the PPSM Category Assurance List (CAL), this is a finding."${BLD}
cci19="CCI-000382"
stigid19="RHEL-08-040030"
severity19="CAT II"
ruleid19="SV-230500r627750_rule"
vulnid19="V-230500"

title20a="RHEL 8 must mount /dev/shm with the nodev option"
title20b="checking with: 
           a. mount | grep /dev/shm
	   b. cat /etc/fstab | grep /dev/shm"
title20c="Expecting: ${YLO}
           a. tmpfs on /dev/shm type tmpfs (rw,${GRN}nodev${YLO},nosuid,noexec,seclabel)
	   b. tmpfs /dev/shm tmpfs defaults,${GRN}nodev${YLO},nosuid,noexec 0 0
           NOTE: If results are returned and the \"nodev\" option is missing, or if /dev/shm is mounted without the \"nodev\" option, this is a finding."${BLD}
cci20="CCI-001764"
stigid20="RHEL-08-040120"
severity20="CAT II"
ruleid20="SV-230508r854049_rule"
vulnid20="V-230508"

title21a="RHEL 8 must mount /dev/shm with the nosuid option"
title21b="checking with: 
           a. mount | grep /dev/shm
	   b. cat /etc/fstab | grep /dev/shm"
title21c="Expecting: ${YLO}
           a. tmpfs on /dev/shm type tmpfs (rw,nodev,${GRN}nosuid${YLO},noexec,seclabel)
	   b. tmpfs /dev/shm tmpfs defaults,nodev,${GRN}nosuid${YLO},noexec 0 0
           NOTE: If results are returned and the \"nosuid\" option is missing, or if /dev/shm is mounted without the \"nosuid\" option, this is a finding."${BLD}
cci21="CCI-001764"
stigid21="RHEL-08-040121"
severity21="CAT II"
ruleid21="SV-230509r854050_rule"
vulnid21="V-230509"

title22a="RHEL 8 must mount /dev/shm with the noexec option"
title22b="checking with: 
           a. mount | grep /dev/shm
	   b. cat /etc/fstab | grep /dev/shm"
title22c="Expecting: ${YLO}
           a. tmpfs on /dev/shm type tmpfs (rw,nodev,nosuid,${GRN}noexec${YLO},seclabel)
	   b. tmpfs /dev/shm tmpfs defaults,nodev,nosuid,${GRN}noexec${YLO} 0 0
           NOTE: If results are returned and the \"noexec\" option is missing, or if /dev/shm is mounted without the \"noexec\" option, this is a finding."${BLD}
cci22="CCI-001764"
stigid22="RHEL-08-040122"
severity22="CAT II"
ruleid22="SV-230510r854051_rule"
vulnid22="V-230510"

title23a="RHEL 8 must mount /tmp with the nodev option"
title23b="checking with: 
           a. mount | grep /tmp
	   b. cat /etc/fstab | grep /tmp"
title23c="Expecting: ${YLO}
           a. /dev/mapper/rhel-tmp on /tmp type xfs (rw,${GRN}nodev${YLO},nosuid,noexec,seclabel)
	   b. /dev/mapper/rhel-tmp /tmp xfs defaults,${GRN}nodev${YLO},nosuid,noexec 0 0
           NOTE: If results are returned and the \"nodev\" option is missing, or if /dev/shm is mounted without the \"nodev\" option, this is a finding."${BLD}
cci23="CCI-001764"
stigid23="RHEL-08-040123"
severity23="CAT II"
ruleid23="SV-230511r854052_rule"
vulnid23="V-230511"

title24a="RHEL 8 must mount /tmp with the nosuid option"
title24b="checking with: 
           a. mount | grep /tmp
	   b. cat /etc/fstab | grep /tmp"
title24c="Expecting: ${YLO}
           a. /dev/mapper/rhel-tmp on /tmp type xfs (rw,nodev,${GRN}nosuid${YLO},noexec,seclabel)
	   b. /dev/mapper/rhel-tmp /tmp xfs defaults,nodev,${GRN}nosuid${YLO},noexec 0 0
           NOTE: If results are returned and the \"nosuid\" option is missing, or if /dev/shm is mounted without the \"nosuid\" option, this is a finding."${BLD}
cci24="CCI-001764"
stigid24="RHEL-08-040124"
severity24="CAT II"
ruleid24="SV-230512r854053_rule"
vulnid24="V-230512"

title25a="RHEL 8 must mount /tmp with the noexec option"
title25b="checking with: 
           a. mount | grep /tmp
	   b. cat /etc/fstab | grep /tmp"
title25c="Expecting: ${YLO}
           a. /dev/mapper/rhel-tmp on /tmp type xfs (rw,nodev,nosuid,${GRN}noexec${YLO},seclabel)
	   b. /dev/mapper/rhel-tmp /tmp xfs defaults,nodev,nosuid,${GRN}noexec${YLO} 0 0
           NOTE: If results are returned and the \"noexec\" option is missing, or if /dev/shm is mounted without the \"noexec\" option, this is a finding."${BLD}
cci25="CCI-001764"
stigid25="RHEL-08-040125"
severity25="CAT II"
ruleid25="SV-230513r854054_rule"
vulnid25="V-230513"

title26a="RHEL 8 must mount /var/log with the nodev option"
title26b="checking with: 
           a. mount | grep /var/log
	   b. cat /etc/fstab | grep /var/log"
title26c="Expecting: ${YLO}
           a. /dev/mapper/rhel-var-log on /var/log type xfs (rw,${GRN}nodev${YLO},nosuid,noexec,seclabel)
	   b. /dev/mapper/rhel-var-log /var/log xfs defaults,${GRN}nodev${YLO},nosuid,noexec 0 0
           NOTE: If results are returned and the \"nodev\" option is missing, or if /var/log is mounted without the \"nodev\" option, this is a finding."${BLD}
cci26="CCI-001764"
stigid26="RHEL-08-040126"
severity26="CAT II"
ruleid26="SV-230514r854055_rule"
vulnid26="V-230514"

title27a="RHEL 8 must mount /var/log with the nosuid option"
title27b="checking with: 
           a. mount | grep /var/log
	   b. cat /etc/fstab | grep /var/log"
title27c="Expecting: ${YLO}
           a. /dev/mapper/rhel-var-log on /var/log type xfs (rw,nodev,${GRN}nosuid${YLO},noexec,seclabel)
	   b. /dev/mapper/rhel-var-log /var/log xfs defaults,nodev,${GRN}nosuid${YLO},noexec 0 0
           NOTE: If results are returned and the \"nosuid\" option is missing, or if /var/log is mounted without the \"nosuid\" option, this is a finding."${BLD}
cci27="CCI-001764"
stigid27="RHEL-08-040127"
severity27="CAT II"
ruleid27="SV-230515r854056_rule"
vulnid27="V-230515"

title28a="RHEL 8 must mount /var/log with the noexec option"
title28b="checking with: 
           a. mount | grep /var/log
	   b. cat /etc/fstab | grep /var/log"
title28c="Expecting: ${YLO}
           a. /dev/mapper/rhel-var-log on /var/log type xfs (rw,nodev,nosuid,${GRN}noexec${YLO},seclabel)
	   b. /dev/mapper/rhel-var-log /var/log xfs defaults,nodev,nosuid,${GRN}noexec${YLO} 0 0
           NOTE: If results are returned and the \"noexec\" option is missing, or if /var/log is mounted without the \"noexec\" option, this is a finding."${BLD}
cci28="CCI-001764"
stigid28="RHEL-08-040128"
severity28="CAT II"
ruleid28="SV-230516r854057_rule"
vulnid28="V-230516"

title29a="RHEL 8 must mount /var/log/audit with the nodev option"
title29b="checking with: 
           a. mount | grep /var/log/audit
	   b. cat /etc/fstab | grep /var/log/audit"
title29c="Expecting: ${YLO}
           a. /dev/mapper/rhel-var-log-audit on /var/log/audit type xfs (rw,${GRN}nodev${YLO},nosuid,noexec,seclabel)
	   b. /dev/mapper/rhel-var-log-audit /var/log/audit xfs defaults,${GRN}nodev${YLO},nosuid,noexec 0 0
           NOTE: If results are returned and the \"nodev\" option is missing, or if /var/log/audit is mounted without the \"nodev\" option, this is a finding."${BLD}
cci29="CCI-001764"
stigid29="RHEL-08-040129"
severity29="CAT II"
ruleid29="SV-230517r854058_rule"
vulnid29="V-230517"

title30a="RHEL 8 must mount /var/log/audit with the nosuid option"
title30b="checking with: 
           a. mount | grep /var/log/audit
	   b. cat /etc/fstab | grep /var/log/audit"
title30c="Expecting: ${YLO}
           a. /dev/mapper/rhel-var-log-audit on /var/log/audit type xfs (rw,nodev,${GRN}nosuid${YLO},noexec,seclabel)
	   b. /dev/mapper/rhel-var-log-audit /var/log/audit xfs defaults,nodev,${GRN}nosuid${YLO},noexec 0 0
           NOTE: If results are returned and the \"nosuid\" option is missing, or if /var/log/audit is mounted without the \"nosuid\" option, this is a finding."${BLD}
cci30="CCI-001764"
stigid30="RHEL-08-040130"
severity30="CAT II"
ruleid30="SV-230518r854059_rule"
vulnid30="V-230518"

title31a="RHEL 8 must mount /var/log/audit with the noexec option"
title31b="checking with: 
           a. mount | grep /var/log/audit
	   b. cat /etc/fstab | grep /var/log/audit"
title31c="Expecting: ${YLO}
           a. /dev/mapper/rhel-var-log-audit on /var/log/audit type xfs (rw,nodev,nosuid,${GRN}noexec${YLO},seclabel)
	   b. /dev/mapper/rhel-var-log-audit /var/log/audit xfs defaults,nodev,nosuid,${GRN}noexec${YLO} 0 0
           NOTE: If results are returned and the \"noexec\" option is missing, or if /var/log/audit is mounted without the \"noexec\" option, this is a finding."${BLD}
cci31="CCI-001764"
stigid31="RHEL-08-040131"
severity31="CAT II"
ruleid31="SV-230519r854060_rule"
vulnid31="V-230519"

title32a="RHEL 8 must mount /var/tmp with the nodev option"
title32b="checking with: 
           a. mount | grep /var/tmp
	   b. cat /etc/fstab | grep /var/tmp"
title32c="Expecting: ${YLO}
           a. /dev/mapper/rhel-var-tmp on /var/tmp type xfs (rw,${GRN}nodev${YLO},nosuid,noexec,seclabel)
	   b. /dev/mapper/rhel-var-tmp /var/tmp xfs defaults,${GRN}nodev${YLO},nosuid,noexec 0 0
           NOTE: If results are returned and the \"nodev\" option is missing, or if /var/tmp is mounted without the \"nodev\" option, this is a finding."${BLD}
cci32="CCI-001764"
stigid32="RHEL-08-040132"
severity32="CAT II"
ruleid32="SV-230520r854061_rule"
vulnid32="V-230520"

title33a="RHEL 8 must mount /var/tmp with the nosuid option"
title33b="checking with: 
           a. mount | grep /var/tmp
	   b. cat /etc/fstab | grep /var/tmp"
title33c="Expecting: ${YLO}
           a. /dev/mapper/rhel-var-tmp on /var/tmp type xfs (rw,nodev,${GRN}nosuid${YLO},noexec,seclabel)
	   b. /dev/mapper/rhel-var-tmp /var/tmp xfs defaults,nodev,${GRN}nosuid${YLO},noexec 0 0
           NOTE: If results are returned and the \"nosuid\" option is missing, or if /var/tmp is mounted without the \"nosuid\" option, this is a finding."${BLD}
cci33="CCI-001764"
stigid33="RHEL-08-040133"
severity33="CAT II"
ruleid33="SV-230521r854062_rule"
vulnid33="V-230521"

title34a="RHEL 8 must mount /var/tmp with the noexec option"
title34b="checking with: 
           a. mount | grep /var/tmp
	   b. cat /etc/fstab | grep /var/tmp"
title34c="Expecting: ${YLO}
           a. /dev/mapper/rhel-var-tmp on /var/tmp type xfs (rw,nodev,nosuid,${GRN}noexec${YLO},seclabel)
	   b. /dev/mapper/rhel-var-tmp /var/tmp xfs defaults,nodev,nosuid,${GRN}noexec${YLO} 0 0
           NOTE: If results are returned and the \"noexec\" option is missing, or if /var/tmp is mounted without the \"noexec\" option, this is a finding."${BLD}
cci34="CCI-001764"
stigid34="RHEL-08-040134"
severity34="CAT II"
ruleid34="SV-230522r854063_rule"
vulnid34="V-230522"

title35a="The RHEL 8 fapolicy module must be installed."
title35b="Checking with: 'yum list installed fapolicyd'."
title35c="Expecting: ${YLO}fapolicyd.x86_64
           NOTE: If fapolicyd is not installed, this is a finding."${BLD}
cci35="CCI-001764"
stigid35="RHEL-08-040135"
severity35="CAT II"
ruleid35="SV-230523r854064_rule"
vulnid35="V-230523"

title36a="The gssproxy package must not be installed unless mision essential on RHEL 8."
title36b="Checking with: 'yum list installed gssproxy'."
title36c="Expecting: ${YLO}Nothing returned
           NOTE: If the gssproxy package is installed and is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding."${BLD}
cci36="CCI-000381"
stigid36="RHEL-08-040370"
severity36="CAT II"
ruleid36="SV-230559r646887_rule"
vulnid36="V-230559"

title37a="The RHEL 8 fapolicy module must be enabled."
title37b="Checking with: 'systemctl status fapolicyd.service'."
title37c="Expecting: ${YLO}
           fapolicyd.service - File Access Policy Daemon
           Loaded: loaded (/usr/lib/systemd/system/fapolicyd.service; enabled; vendor preset: disabled)
           Active: active (running)
           NOTE: If fapolicyd is not enabled and running, this is a finding."${BLD}
cci37="CCI-001764"
stigid37="RHEL-08-040136"
severity37="CAT II"
ruleid37="SV-244545r854074_rule"
vulnid37="V-244545"

title38a="The RHEL 8 fapolicy module must be configured to employ a deny-all, permit-by-exception policy to allow the execution of authorized software programs."
title38b="Checking with:
           a. grep permissive /etc/fapolicyd/fapolicyd.conf
	   b. tail /etc/fapolicyd/fapolicyd.rules"
title38c="Expecting: ${YLO}
           a. permissive = 0
	   b. allow exe=/usr/bin/python3.7 : ftype=text/x-python
           b. deny_audit perm=any pattern=ld_so : all
           b. deny perm=any all : all
           NOTE: If fapolicyd is not running in enforcement mode with a deny-all, permit-by-exception policy, this is a finding."${BLD}
cci38="CCI-001764"
stigid38="RHEL-08-040137"
severity38="CAT II"
ruleid38="SV-244546r858730_rule"
vulnid38="V-244546"

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

file1="/etc/chrony.conf"

fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file1 ]]
then
  port="$(grep -w 'port' $file1 | grep -v "^#")"
  if [[ $port ]]
  then
    portnum="$(echo $port | awk '{print $2}')"
    if (( $portnum == 0 ))
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$port${NORMAL}"
      fail=0
    else
      echo -e "${NORMAL}RESULT:    ${RED}$port${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}\"port\" is not defined in $file1${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file1 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, RHEL 8 disables the chrony daemon from acting as a server.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, RHEL 8 does not disable the chrony daemon from acting as a server.${NORMAL}"
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

file2="/etc/chrony.conf"

fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file2 ]]
then
  cmdport="$(grep -w 'cmdport' $file2 | grep -v "^#")"
  if [[ $cmdport ]]
  then
    portnum="$(echo $cmdport | awk '{print $2}')"
    if (( $portnum == 0 ))
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$cmdport${NORMAL}"
      fail=0
    else
      echo -e "${NORMAL}RESULT:    ${RED}$cmdport${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}\"cmdport\" is not defined in $file2${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file2 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, RHEL 8 disables network management of the chrony daemon.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, RHEL 8 does not disable network management of the chrony daemon.${NORMAL}"
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

fail=0

isinstalled="$(yum list installed | grep telnet-server)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $isinstalled ]]
then
   for pkg in ${isinstalled[@]}
   do
      echo -e "${NORMAL}RESULT:    ${RED}$pkg${NORMAL}"
      fail=1
   done
else
   echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
fi
if (( $fail == 0 ))
then
   echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${GRN}PASSED, The 'telnet-server' package is not installed${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${RED}FAILED, The 'telnet-server' package is installed${NORMAL}"
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

installed="$(yum list installed | grep abrt)"

fail=0

datetime="$(date +%FT%H:%M:%S)"

if [[ $installed ]]
then
  for line in ${installed[@]}
  do
    echo -e "${NORMAL}RESULT:    ${RED}$installed${NORMAL}"
  done
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
  echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cci8, $datetime, ${GRN}PASSED, RHEL 8 does not have any automated bug reporting tools installed.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cck8, $datetime, ${RED}FAILED, RHEL 8 has automated bug reporting tools installed.${NORMAL}"
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

installed="$(yum list installed | grep sendmail)"

fail=0

datetime="$(date +%FT%H:%M:%S)"

if [[ $installed ]]
then
  for line in ${installed[@]}
  do
    echo -e "${NORMAL}RESULT:    ${RED}$installed${NORMAL}"
  done
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
  echo -e "${NORMAL}$hostname, $severity9, $controlid, $stigid9, $ruleid9, $cci9, $datetime, ${GRN}PASSED, RHEL 8 does not have sendmail installed.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity9, $controlid, $stigid9, $ruleid9, $cci9, $datetime, ${RED}FAILED, RHEL 8 has sendmail installed.${NORMAL}"
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

#file10="/etc/default/grub"

fail=1

datetime="$(date +%FT%H:%M:%S)"

pti="$(grub2-editenv list | grep pti)"
if [[ $pti ]]
then
  for line in ${pti[@]}
  do
    read -a fieldvals <<< ${line[@]}
    for element in ${fieldvals[@]}
    do
      if [[ $element =~ "pti=" ]]
      then
        ptival="$(echo $element | awk -F= '{print $2}' | sed 's/\"//g')"
        if [[ $ptival == "on" ]]
        then
          echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
          fail=0
        else
          echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
        fi
      fi
    done
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}\"pti\" not defined in \"grub2-editenv\".${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity10, $controlid, $stigid10, $ruleid10, $cci10, $datetime, ${GRN}PASSED, RHEL 8 enables mitigations against processor-based vulnerabilities.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity10, $controlid, $stigid10, $ruleid10, $cci10, $datetime, ${RED}FAILED, RHEL 8 does not enable mitigations against processor-based vulnerabilities.${NORMAL}"
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

installed="$(yum list installed | grep rsh-server)"

fail=0

datetime="$(date +%FT%H:%M:%S)"

if [[ $installed ]]
then
  for line in ${installed[@]}
  do
    echo -e "${NORMAL}RESULT:    ${RED}$installed${NORMAL}"
  done
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
  echo -e "${NORMAL}$hostname, $severity11, $controlid, $stigid11, $ruleid11, $cci11, $datetime, ${GRN}PASSED, RHEL 8 does not have rsh-server installed.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity11, $controlid, $stigid11, $ruleid11, $cci11, $datetime, ${RED}FAILED, RHEL 8 has rsh-server installed.${NORMAL}"
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

uvc1="$(modinfo uvcvideo | grep filename | awk '{print $2}')"
uvc2="$(modprobe uvcvideo)"
uvc3="$(grep -r uvcvideo /etc/modprobe.d/* | grep "/bin/true")"
uvc4="$(grep -r uvcvideo /etc/modprobe.d/* | grep "blacklist")"

fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ $uvc1 ]]
then
  echo -e "${NORMAL}RESULT:    ${BLD}a. $uvc1${NORMAL}"
  if [[ $uvc2 ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}b. $uvc2${NORMAL}"
    module=1
  else
    echo -e "${NORMAL}RESULT:    ${RED}b. Nothing returned${NORMAL}"
    fail=2
  fi
  if [[ $uvc3 ]]
  then
    uvc3val="$(echo $uvc3 | awk '{print $3}')"
    if [[ $uvc3val == "/bin/true" ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}c. $uvc3${NORMAL}"
      bintrue=1
    else
      echo -e "${NORMAL}RESULT:    ${RED}c. $uvc3${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}c. Nothing returned${NORMAL}"
  fi
  if [[ $uvc4 ]]
  then
    uvc4val="$(echo $uvc4 | awk '{print $2}')"
    if [[ $uvc4val == "blacklist" ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}d. $uvc4${NORMAL}"
      blacklist=1
    else
      echo -e "${NORMAL}RESULT:    ${RED}d. $uvc4${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}d. Nothing returned${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${BLD}a. A uvcvideo kernel driver is not installed.${NORMAL}"
  fail=2
fi

if [[ $module == 1 && $bintrue == 1 && $blacklist == 1 ]]
then
  fail=0
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity12, $controlid, $stigid12, $ruleid12, $cci12, $datetime, ${GRN}PASSED, RHEL 8 disables the built-in camera.${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity12, $controlid, $stigid12, $ruleid12, $cci12, $datetime, ${GRN}N/A, RHEL 8 does not have a camera installed.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity12, $controlid, $stigid12, $ruleid12, $cci12, $datetime, ${RED}FAILED, RHEL 8 does not disable the built-in camera.${NORMAL}"
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

file13="/etc/modprobe.d"

atm1="$(modinfo atm | grep filename | awk '{print $2}')"
atm2="$(modprobe atm)"
atm3="$(grep -r atm $file13/* | grep "/bin/true")"
atm4="$(grep -r uvcvideo $file13/* | grep "blacklist")"

fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ $atm1 ]]
then
  echo -e "${NORMAL}RESULT:    ${BLD}a. $atm1${NORMAL}"
  if [[ $atm2 ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}b. $atm2${NORMAL}"
    module=1
  else
    echo -e "${NORMAL}RESULT:    ${RED}b. Nothing returned${NORMAL}"
    fail=2
  fi
  if [[ $atm3 ]]
  then
    atm3val="$(echo $atm3 | awk '{print $3}')"
    if [[ $atm3val == "/bin/true" ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}c. $atm3${NORMAL}"
      bintrue=1
    else
      echo -e "${NORMAL}RESULT:    ${RED}c. $atm3${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}c. Nothing returned${NORMAL}"
  fi
  if [[ $atm4 ]]
  then
    atm4val="$(echo $atm4 | awk '{print $2}')"
    if [[ $atm4val == "blacklist" ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}d. $atm4${NORMAL}"
      blacklist=1
    else
      echo -e "${NORMAL}RESULT:    ${RED}d. $atm4${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}d. Nothing returned${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${BLD}a. An ATM kernel driver is not installed.${NORMAL}"
  fail=2
fi

if [[ $module == 1 && $bintrue == 1 && $blacklist == 1 ]]
then
  fail=0
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity13, $controlid, $stigid13, $ruleid13, $cci13, $datetime, ${GRN}PASSED, RHEL 8 disables the ability to use the ATM protocol.${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity13, $controlid, $stigid13, $ruleid13, $cci13, $datetime, ${GRN}N/A, RHEL 8 does not have the ATM kernel module installed.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity13, $controlid, $stigid13, $ruleid13, $cci13, $datetime, ${RED}FAILED, RHEL 8 does not disable the ability to use the ATM protocol.${NORMAL}"
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

dir14="/etc/modprobe.d"
fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ -d $dir14 ]]
then
  bintrue="$(grep -r can $dir14/* | grep "/bin/true")"
  if [[ $bintrue =~ "install can" ]]
  then
    installval="$(echo $bintrue | awk '{print $3}')"
    if [[ $installval == "/bin/true" ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}a. $bintrue${NORMAL}"
      blacklist="$(grep -r can $dir14/* | grep "blacklist")"
      if [[ $blacklist == "blacklist can" ]]
      then
	echo -e "${NORMAL}RESULT:    ${BLD}b. $blacklist${NORMAL}"
	fail=0
      else
	echo -e "${NORMAL}RESULT:    ${RED}b. Nothing returned${NORMAL}"
      fi
    else
      echo -e "${NORMAL}RESULT:    ${RED}a. $bintrue${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}a. \"install can\" is not defined in $dir14\*${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}a. $dir14 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity14, $controlid, $stigid14, $ruleid14, $cci14, $datetime, ${GRN}PASSED, RHEL 8 disables the controller area network (CAN) protocol.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity14, $controlid, $stigid14, $ruleid14, $cci14, $datetime, ${RED}FAILED, RHEL 8 does not disable the controller area network (CAN) protocol.${NORMAL}"
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

dir15="/etc/modprobe.d"
fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ -d $dir15 ]]
then
  bintrue="$(grep -r sctp $dir15/* | grep "/bin/true")"
  if [[ $bintrue =~ "install sctp" ]]
  then
    installval="$(echo $bintrue | awk '{print $3}')"
    if [[ $installval == "/bin/true" ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}a. $bintrue${NORMAL}"
      blacklist="$(grep -r sctp $dir15/* | grep "blacklist")"
      if [[ $blacklist == "blacklist sctp" ]]
      then
	echo -e "${NORMAL}RESULT:    ${BLD}b. $blacklist${NORMAL}"
	fail=0
      else
	echo -e "${NORMAL}RESULT:    ${RED}b. Nothing returned${NORMAL}"
      fi
    else
      echo -e "${NORMAL}RESULT:    ${RED}a. $bintrue${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}a. \"install sctp\" is not defined in $dir15\*${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}a. $dir15 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity15, $controlid, $stigid15, $ruleid15, $cci15, $datetime, ${GRN}PASSED, RHEL 8 disables the stream control transmission protocol (SCTP).${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity15, $controlid, $stigid15, $ruleid15, $cci15, $datetime, ${RED}FAILED, RHEL 8 does not disable the stream control transmission protocol (SCTP).${NORMAL}"
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

dir16="/etc/modprobe.d"
fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ -d $dir16 ]]
then
  bintrue="$(grep -r tipc $dir16/* | grep "/bin/true")"
  if [[ $bintrue =~ "install tipc" ]]
  then
    installval="$(echo $bintrue | awk '{print $3}')"
    if [[ $installval == "/bin/true" ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}a. $bintrue${NORMAL}"
      blacklist="$(grep -r tipc $dir16/* | grep "blacklist")"
      if [[ $blacklist == "blacklist sctp" ]]
      then
	echo -e "${NORMAL}RESULT:    ${BLD}b. $blacklist${NORMAL}"
	fail=0
      else
	echo -e "${NORMAL}RESULT:    ${RED}b. Nothing returned${NORMAL}"
      fi
    else
      echo -e "${NORMAL}RESULT:    ${RED}a. $bintrue${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}a. \"install tipc\" is not defined in $dir16\*${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}a. $dir16 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity16, $controlid, $stigid16, $ruleid16, $cci16, $datetime, ${GRN}PASSED, RHEL 8 disables the transparent inter-process communication (TIPC) protocol.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity16, $controlid, $stigid16, $ruleid16, $cci16, $datetime, ${RED}FAILED, RHEL 8 does not disable the transparent inter-process communication (TIPC) protocol.${NORMAL}"
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

dir17="/etc/modprobe.d"
fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ -d $dir17 ]]
then
  bintrue="$(grep -r cramfs $dir17/* | grep "/bin/true")"
  if [[ $bintrue =~ "install cramfs" ]]
  then
    installval="$(echo $bintrue | awk '{print $3}')"
    if [[ $installval == "/bin/true" ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}a. $bintrue${NORMAL}"
      blacklist="$(grep -r cramfs $dir17/* | grep "blacklist")"
      if [[ $blacklist == "blacklist cramfs" ]]
      then
	echo -e "${NORMAL}RESULT:    ${BLD}b. $blacklist${NORMAL}"
	fail=0
      else
	echo -e "${NORMAL}RESULT:    ${RED}b. Nothing returned${NORMAL}"
      fi
    else
      echo -e "${NORMAL}RESULT:    ${RED}a. $bintrue${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}a. \"install cramfs\" is not defined in $dir17\*${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}a. $dir17 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity17, $controlid, $stigid17, $ruleid17, $cci17, $datetime, ${GRN}PASSED, RHEL 8 disables mounting of cramfs.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity17, $controlid, $stigid17, $ruleid17, $cci17, $datetime, ${RED}FAILED, RHEL 8 does not disable mounting of cramfs.${NORMAL}"
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

dir18="/etc/modprobe.d"
fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ -d $dir18 ]]
then
  bintrue="$(grep -r firewire-core $dir18/* | grep "/bin/true")"
  if [[ $bintrue =~ "install firewire-core" ]]
  then
    installval="$(echo $bintrue | awk '{print $3}')"
    if [[ $installval == "/bin/true" ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}a. $bintrue${NORMAL}"
      blacklist="$(grep -r firewire-core $dir14/* | grep "blacklist")"
      if [[ $blacklist == "blacklist cramfs" ]]
      then
	echo -e "${NORMAL}RESULT:    ${BLD}b. $blacklist${NORMAL}"
	fail=0
      else
	echo -e "${NORMAL}RESULT:    ${RED}b. Nothing returned${NORMAL}"
      fi
    else
      echo -e "${NORMAL}RESULT:    ${RED}a. $bintrue${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}a. \"install firewire-core\" is not defined in $dir18\*${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}a. $dir18 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity18, $controlid, $stigid18, $ruleid18, $cci18, $datetime, ${GRN}PASSED, RHEL 8 disables IEEE 1394 (FireWire) support.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity18, $controlid, $stigid18, $ruleid18, $cci18, $datetime, ${RED}FAILED, RHEL 8 does not disable IEEE 1394 (FireWire) support.${NORMAL}"
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

services="$(firewall-cmd --list-all-zones)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $services ]]
then
  for line in ${services[@]}
  do
    echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
  done
fi

echo -e "${NORMAL}$hostname, $severity19, $controlid, $stigid19, $ruleid19, $cci19, $datetime, ${CYN}VERIFY, Inspect the firewall configuration and running services to verify it is configured to prohibit or restrict the use of functions, ports, protocols, and/or services that are unnecessary or prohibited.${NORMAL}"

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

file20="/etc/fstab"

fail=1

mount="$(mount | grep /dev/shm)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $mount ]]
then
  if [[ $mount =~ "nodev" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}a. $mount${NORMAL}"
    mounted=1
  fi
  fstab="$(cat $file20 | grep /dev/shm)"
  if [[ $fstab ]]
  then
    if [[ $fstab =~ "nodev" ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}b. $fstab${NORMAL}"
      configured=1
    else
      echo -e "${NORMAL}RESULT:    ${RED}b. $fstab${NORMAL}"
    fi
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}a. \"/dev/shm\" is not mounted.${NORMAL}"
fi

if [[ $mounted == 1 && $configured == 1 ]]
then
  fail=0
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity20, $controlid, $stigid20, $ruleid20, $cci20, $datetime, ${GRN}PASSED, RHEL 8 mounts /dev/shm with the nodev option..${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity20, $controlid, $stigid20, $ruleid20, $cci20, $datetime, ${RED}FAILED, RHEL 8 does not mount /dev/shm with the nodev option..${NORMAL}"
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

IFS='
'

file21="/etc/fstab"

mounted=$NULL
configured=$NULL

fail=1

mount="$(mount | grep /dev/shm)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $mount ]]
then
  if [[ $mount =~ "nosuid" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}a. $mount${NORMAL}"
    mounted=1
  fi
  fstab="$(cat $file21 | grep /dev/shm)"
  if [[ $fstab ]]
  then
    if [[ $fstab =~ "nosuid" ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}b. $fstab${NORMAL}"
      configured=1
    else
      echo -e "${NORMAL}RESULT:    ${RED}b. $fstab${NORMAL}"
    fi
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}a. \"/dev/shm\" is not mounted.${NORMAL}"
fi

if [[ $mounted == 1 && $configured == 1 ]]
then
  fail=0
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity21, $controlid, $stigid21, $ruleid21, $cci21, $datetime, ${GRN}PASSED, RHEL 8 mounts /dev/shm with the nosuid option..${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity21, $controlid, $stigid21, $ruleid21, $cci21, $datetime, ${RED}FAILED, RHEL 8 does not mount /dev/shm with the nosuid option..${NORMAL}"
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

IFS='
'

file22="/etc/fstab"

mounted=$NULL
configured=$NULL

fail=1

mount="$(mount | grep /dev/shm)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $mount ]]
then
  if [[ $mount =~ "noexec" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}a. $mount${NORMAL}"
    mounted=1
  fi
  fstab="$(cat $file22 | grep /dev/shm)"
  if [[ $fstab ]]
  then
    if [[ $fstab =~ "noexec" ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}b. $fstab${NORMAL}"
      configured=1
    else
      echo -e "${NORMAL}RESULT:    ${RED}b. $fstab${NORMAL}"
    fi
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}a. \"/dev/shm\" is not mounted.${NORMAL}"
fi

if [[ $mounted == 1 && $configured == 1 ]]
then
  fail=0
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity22, $controlid, $stigid22, $ruleid22, $cci22, $datetime, ${GRN}PASSED, RHEL 8 mounts /dev/shm with the noexec option..${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity22, $controlid, $stigid22, $ruleid22, $cci22, $datetime, ${RED}FAILED, RHEL 8 does not mount /dev/shm with the noexec option..${NORMAL}"
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

IFS='
'

file23="/etc/fstab"

fail=1

mount="$(mount | grep " /tmp ")"

datetime="$(date +%FT%H:%M:%S)"

if [[ $mount ]]
then
  if [[ $mount =~ "nodev" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}a. $mount${NORMAL}"
    mounted=1
  fi
  fstab="$(cat $file23 | grep " /tmp ")"
  if [[ $fstab ]]
  then
    if [[ $fstab =~ "nodev" ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}b. $fstab${NORMAL}"
      configured=1
    else
      echo -e "${NORMAL}RESULT:    ${RED}b. $fstab${NORMAL}"
    fi
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}a. \"/tmp\" is not mounted.${NORMAL}"
fi

if [[ $mounted == 1 && $configured == 1 ]]
then
  fail=0
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity23, $controlid, $stigid23, $ruleid23, $cci23, $datetime, ${GRN}PASSED, RHEL 8 mounts /tmp with the nodev option..${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity23, $controlid, $stigid23, $ruleid23, $cci23, $datetime, ${RED}FAILED, RHEL 8 does not mount /tmp with the nodev option..${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid24${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid24${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid24${NORMAL}"
echo -e "${NORMAL}CCI:       $cci24${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 24:   ${BLD}$title24a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title24b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title24c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity24${NORMAL}"

IFS='
'

file24="/etc/fstab"

mounted=$NULL
configured=$NULL

fail=1

mount="$(mount | grep " /tmp ")"

datetime="$(date +%FT%H:%M:%S)"

if [[ $mount ]]
then
  if [[ $mount =~ "nosuid" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}a. $mount${NORMAL}"
    mounted=1
  fi
  fstab="$(cat $file24 | grep " /tmp ")"
  if [[ $fstab ]]
  then
    if [[ $fstab =~ "nosuid" ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}b. $fstab${NORMAL}"
      configured=1
    else
      echo -e "${NORMAL}RESULT:    ${RED}b. $fstab${NORMAL}"
    fi
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}a. \"/tmp\" is not mounted.${NORMAL}"
fi

if [[ $mounted == 1 && $configured == 1 ]]
then
  fail=0
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity24, $controlid, $stigid24, $ruleid24, $cci24, $datetime, ${GRN}PASSED, RHEL 8 mounts /tmp with the nosuid option..${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity24, $controlid, $stigid24, $ruleid24, $cci24, $datetime, ${RED}FAILED, RHEL 8 does not mount /tmp with the nosuid option..${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid25${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid25${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid25${NORMAL}"
echo -e "${NORMAL}CCI:       $cci25${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 25:   ${BLD}$title25a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title25b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title25c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity25${NORMAL}"

IFS='
'

file25="/etc/fstab"

mounted=$NULL
configured=$NULL

fail=1

mount="$(mount | grep " /tmp ")"

datetime="$(date +%FT%H:%M:%S)"

if [[ $mount ]]
then
  if [[ $mount =~ "noexec" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}a. $mount${NORMAL}"
    mounted=1
  fi
  fstab="$(cat $file25 | grep " /tmp ")"
  if [[ $fstab ]]
  then
    if [[ $fstab =~ "noexec" ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}b. $fstab${NORMAL}"
      configured=1
    else
      echo -e "${NORMAL}RESULT:    ${RED}b. $fstab${NORMAL}"
    fi
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}a. \"/tmp\" is not mounted.${NORMAL}"
fi

if [[ $mounted == 1 && $configured == 1 ]]
then
  fail=0
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity25, $controlid, $stigid25, $ruleid25, $cci25, $datetime, ${GRN}PASSED, RHEL 8 mounts /tmp with the noexec option..${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity25, $controlid, $stigid25, $ruleid25, $cci25, $datetime, ${RED}FAILED, RHEL 8 does not mount /tmp with the noexec option..${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid26${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid26${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid26${NORMAL}"
echo -e "${NORMAL}CCI:       $cci26${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 26:   ${BLD}$title26a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title26b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title26c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity26${NORMAL}"

IFS='
'

file26="/etc/fstab"

fail=1

mounted=$NULL
configured=$NULL

mount="$(mount | grep " /var/log ")"

datetime="$(date +%FT%H:%M:%S)"

if [[ $mount ]]
then
  if [[ $mount =~ "nodev" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}a. $mount${NORMAL}"
    mounted=1
  fi
  fstab="$(cat $file26 | grep " /var/log ")"
  if [[ $fstab ]]
  then
    if [[ $fstab =~ "nodev" ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}b. $fstab${NORMAL}"
      configured=1
    else
      echo -e "${NORMAL}RESULT:    ${RED}b. $fstab${NORMAL}"
    fi
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}a. \"/var/log\" is not mounted.${NORMAL}"
fi

if [[ $mounted == 1 && $configured == 1 ]]
then
  fail=0
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity26, $controlid, $stigid26, $ruleid26, $cci26, $datetime, ${GRN}PASSED, RHEL 8 mounts /var/log with the nodev option..${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity26, $controlid, $stigid26, $ruleid26, $cci26, $datetime, ${RED}FAILED, RHEL 8 does not mount /var/log with the nodev option..${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid27${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid27${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid27${NORMAL}"
echo -e "${NORMAL}CCI:       $cci27${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 27:   ${BLD}$title27a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title27b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title27c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity27${NORMAL}"

IFS='
'

file27="/etc/fstab"

mounted=$NULL
configured=$NULL

fail=1

mount="$(mount | grep " /var/log ")"

datetime="$(date +%FT%H:%M:%S)"

if [[ $mount ]]
then
  if [[ $mount =~ "nosuid" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}a. $mount${NORMAL}"
    mounted=1
  fi
  fstab="$(cat $file27 | grep " /var/log ")"
  if [[ $fstab ]]
  then
    if [[ $fstab =~ "nosuid" ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}b. $fstab${NORMAL}"
      configured=1
    else
      echo -e "${NORMAL}RESULT:    ${RED}b. $fstab${NORMAL}"
    fi
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}a. \"/var/log\" is not mounted.${NORMAL}"
fi

if [[ $mounted == 1 && $configured == 1 ]]
then
  fail=0
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity27, $controlid, $stigid27, $ruleid27, $cci27, $datetime, ${GRN}PASSED, RHEL 8 mounts /var/log with the nosuid option..${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity27, $controlid, $stigid27, $ruleid27, $cci27, $datetime, ${RED}FAILED, RHEL 8 does not mount /var/log with the nosuid option..${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid28${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid28${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid28${NORMAL}"
echo -e "${NORMAL}CCI:       $cci28${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 28:   ${BLD}$title28a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title28b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title28c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity28${NORMAL}"

IFS='
'

file28="/etc/fstab"

mounted=$NULL
configured=$NULL

fail=1

mount="$(mount | grep " /var/log ")"

datetime="$(date +%FT%H:%M:%S)"

if [[ $mount ]]
then
  if [[ $mount =~ "noexec" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}a. $mount${NORMAL}"
    mounted=1
  fi
  fstab="$(cat $file28 | grep " /var/log ")"
  if [[ $fstab ]]
  then
    if [[ $fstab =~ "noexec" ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}b. $fstab${NORMAL}"
      configured=1
    else
      echo -e "${NORMAL}RESULT:    ${RED}b. $fstab${NORMAL}"
    fi
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}a. \"/var/log\" is not mounted.${NORMAL}"
fi

if [[ $mounted == 1 && $configured == 1 ]]
then
  fail=0
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity28, $controlid, $stigid28, $ruleid28, $cci28, $datetime, ${GRN}PASSED, RHEL 8 mounts /var/log with the noexec option..${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity28, $controlid, $stigid28, $ruleid28, $cci28, $datetime, ${RED}FAILED, RHEL 8 does not mount /var/log with the noexec option..${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid29${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid29${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid29${NORMAL}"
echo -e "${NORMAL}CCI:       $cci29${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 29:   ${BLD}$title29a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title29b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title29c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity29${NORMAL}"

IFS='
'

file29="/etc/fstab"

fail=1

mounted=$NULL
configured=$NULL

mount="$(mount | grep " /var/log/audit ")"

datetime="$(date +%FT%H:%M:%S)"

if [[ $mount ]]
then
  if [[ $mount =~ "nodev" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}a. $mount${NORMAL}"
    mounted=1
  fi
  fstab="$(cat $file29 | grep " /var/log/audit ")"
  if [[ $fstab ]]
  then
    if [[ $fstab =~ "nodev" ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}b. $fstab${NORMAL}"
      configured=1
    else
      echo -e "${NORMAL}RESULT:    ${RED}b. $fstab${NORMAL}"
    fi
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}a. \"/var/log/audit\" is not mounted.${NORMAL}"
fi

if [[ $mounted == 1 && $configured == 1 ]]
then
  fail=0
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity29, $controlid, $stigid29, $ruleid29, $cci29, $datetime, ${GRN}PASSED, RHEL 8 mounts /var/log/audit with the nodev option..${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity29, $controlid, $stigid29, $ruleid29, $cci29, $datetime, ${RED}FAILED, RHEL 8 does not mount /var/log/audit with the nodev option..${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid30${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid30${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid30${NORMAL}"
echo -e "${NORMAL}CCI:       $cci30${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 30:   ${BLD}$title30a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title30b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title30c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity30${NORMAL}"

IFS='
'

file30="/etc/fstab"

mounted=$NULL
configured=$NULL

fail=1

mount="$(mount | grep " /var/log/audit ")"

datetime="$(date +%FT%H:%M:%S)"

if [[ $mount ]]
then
  if [[ $mount =~ "nosuid" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}a. $mount${NORMAL}"
    mounted=1
  fi
  fstab="$(cat $file30 | grep " /var/log/audit ")"
  if [[ $fstab ]]
  then
    if [[ $fstab =~ "nosuid" ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}b. $fstab${NORMAL}"
      configured=1
    else
      echo -e "${NORMAL}RESULT:    ${RED}b. $fstab${NORMAL}"
    fi
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}a. \"/var/log/audit\" is not mounted.${NORMAL}"
fi

if [[ $mounted == 1 && $configured == 1 ]]
then
  fail=0
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity30, $controlid, $stigid30, $ruleid30, $cci30, $datetime, ${GRN}PASSED, RHEL 8 mounts /var/log/audit with the nosuid option..${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity30, $controlid, $stigid30, $ruleid30, $cci30, $datetime, ${RED}FAILED, RHEL 8 does not mount /var/log/audit with the nosuid option..${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid31${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid31${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid31${NORMAL}"
echo -e "${NORMAL}CCI:       $cci31${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 31:   ${BLD}$title31a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title31b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title31c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity31${NORMAL}"

IFS='
'

file31="/etc/fstab"

mounted=$NULL
configured=$NULL

fail=1

mount="$(mount | grep " /var/log/audit ")"

datetime="$(date +%FT%H:%M:%S)"

if [[ $mount ]]
then
  if [[ $mount =~ "noexec" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}a. $mount${NORMAL}"
    mounted=1
  fi
  fstab="$(cat $file31 | grep " /var/log/audit ")"
  if [[ $fstab ]]
  then
    if [[ $fstab =~ "noexec" ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}b. $fstab${NORMAL}"
      configured=1
    else
      echo -e "${NORMAL}RESULT:    ${RED}b. $fstab${NORMAL}"
    fi
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}a. \"/var/log/audit\" is not mounted.${NORMAL}"
fi

if [[ $mounted == 1 && $configured == 1 ]]
then
  fail=0
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity31, $controlid, $stigid31, $ruleid31, $cci31, $datetime, ${GRN}PASSED, RHEL 8 mounts /var/log/audit with the noexec option..${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity31, $controlid, $stigid31, $ruleid31, $cci31, $datetime, ${RED}FAILED, RHEL 8 does not mount /var/log/audit with the noexec option..${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid32${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid32${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid32${NORMAL}"
echo -e "${NORMAL}CCI:       $cci32${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 32:   ${BLD}$title32a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title32b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title32c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity32${NORMAL}"

IFS='
'

file32="/etc/fstab"

fail=1

mounted=$NULL
configured=$NULL

mount="$(mount | grep " /var/tmp ")"

datetime="$(date +%FT%H:%M:%S)"

if [[ $mount ]]
then
  if [[ $mount =~ "nodev" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}a. $mount${NORMAL}"
    mounted=1
  fi
  fstab="$(cat $file32 | grep " /var/tmp ")"
  if [[ $fstab ]]
  then
    if [[ $fstab =~ "nodev" ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}b. $fstab${NORMAL}"
      configured=1
    else
      echo -e "${NORMAL}RESULT:    ${RED}b. $fstab${NORMAL}"
    fi
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}a. \"/var/tmp\" is not mounted.${NORMAL}"
fi

if [[ $mounted == 1 && $configured == 1 ]]
then
  fail=0
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity32, $controlid, $stigid32, $ruleid32, $cci32, $datetime, ${GRN}PASSED, RHEL 8 mounts /var/tmp with the nodev option..${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity32, $controlid, $stigid32, $ruleid32, $cci32, $datetime, ${RED}FAILED, RHEL 8 does not mount /var/tmp with the nodev option..${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid33${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid33${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid33${NORMAL}"
echo -e "${NORMAL}CCI:       $cci33${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 33:   ${BLD}$title33a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title33b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title33c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity33${NORMAL}"

IFS='
'

file33="/etc/fstab"

mounted=$NULL
configured=$NULL

fail=1

mount="$(mount | grep " /var/tmp ")"

datetime="$(date +%FT%H:%M:%S)"

if [[ $mount ]]
then
  if [[ $mount =~ "nosuid" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}a. $mount${NORMAL}"
    mounted=1
  fi
  fstab="$(cat $file33 | grep " /var/tmp ")"
  if [[ $fstab ]]
  then
    if [[ $fstab =~ "nosuid" ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}b. $fstab${NORMAL}"
      configured=1
    else
      echo -e "${NORMAL}RESULT:    ${RED}b. $fstab${NORMAL}"
    fi
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}a. \"/var/tmp\" is not mounted.${NORMAL}"
fi

if [[ $mounted == 1 && $configured == 1 ]]
then
  fail=0
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity33, $controlid, $stigid33, $ruleid33, $cci33, $datetime, ${GRN}PASSED, RHEL 8 mounts /var/tmp with the nosuid option..${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity33, $controlid, $stigid33, $ruleid33, $cci33, $datetime, ${RED}FAILED, RHEL 8 does not mount /var/tmp with the nosuid option..${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid34${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid34${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid34${NORMAL}"
echo -e "${NORMAL}CCI:       $cci34${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 34:   ${BLD}$title34a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title34b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title34c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity34${NORMAL}"

IFS='
'

file34="/etc/fstab"

mounted=$NULL
configured=$NULL

fail=1

mount="$(mount | grep " /var/tmp ")"

datetime="$(date +%FT%H:%M:%S)"

if [[ $mount ]]
then
  if [[ $mount =~ "noexec" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}a. $mount${NORMAL}"
    mounted=1
  fi
  fstab="$(cat $file34 | grep " /var/tmp ")"
  if [[ $fstab ]]
  then
    if [[ $fstab =~ "noexec" ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}b. $fstab${NORMAL}"
      configured=1
    else
      echo -e "${NORMAL}RESULT:    ${RED}b. $fstab${NORMAL}"
    fi
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}a. \"/var/tmp\" is not mounted.${NORMAL}"
fi

if [[ $mounted == 1 && $configured == 1 ]]
then
  fail=0
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity34, $controlid, $stigid34, $ruleid34, $cci34, $datetime, ${GRN}PASSED, RHEL 8 mounts /var/tmp with the noexec option..${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity34, $controlid, $stigid34, $ruleid34, $cci34, $datetime, ${RED}FAILED, RHEL 8 does not mount /var/tmp with the noexec option..${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid35${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid35${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid35${NORMAL}"
echo -e "${NORMAL}CCI:       $cci35${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 35:   ${BLD}$title35a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title35b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title35c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity35${NORMAL}"

IFS='
'

installed="$(yum list installed fapolicyd | grep fapolicyd)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $installed ]]
then
  echo -e "${NORMAL}RESULT:    ${BLD}$installed${NORMAL}"
  echo -e "${NORMAL}$hostname, $severity35, $controlid, $stigid35, $ruleid35, $cci35, $datetime, ${GRN}PASSED, The RHEL 8 fapolicyd module is installed.${NORMAL}"
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
  echo -e "${NORMAL}$hostname, $severity35, $controlid, $stigid35, $ruleid35, $cci35, $datetime, ${RED}FAILED, The RHEL 8 fapolicyd module is not installed.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid36${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid36${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid36${NORMAL}"
echo -e "${NORMAL}CCI:       $cci36${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 36:   ${BLD}$title36a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title36b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title36c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity36${NORMAL}"

IFS='
'

installed="$(yum list installed gssproxy | grep gssproxy)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $installed ]]
then
  echo -e "${NORMAL}RESULT:    ${RED}$installed${NORMAL}"
  echo -e "${NORMAL}$hostname, $severity36, $controlid, $stigid36, $ruleid36, $cci36, $datetime, ${RED}FAILED, The gssproxy package is installed.${NORMAL}"
else
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
  echo -e "${NORMAL}$hostname, $severity36, $controlid, $stigid36, $ruleid36, $cci36, $datetime, ${GRN}PASSED, The gssproxy package is not installed.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid37${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid37${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid37${NORMAL}"
echo -e "${NORMAL}CCI:       $cci37${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 37:   ${BLD}$title37a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title37b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title37c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity37${NORMAL}"

IFS='
'

fail=1

enabled="$(systemctl status fapolicyd.service)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $enabled ]]
then
  for line in ${enabled[@]}
  do
    if [[ $line =~ "fapolicyd.service - File Access Policy Daemon" ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
    elif [[ $line =~ "Loaded: " ]]
    then
      loadedval="$(echo $line | awk '{print $2}')"
      if [[ $loadedval == "loaded" ]]
      then
        echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
        loaded=1
      else
	echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
      fi
    elif [[ $line =~ "Active: " ]]
    then
      activeval="$(echo $line | awk '{print $2, $3}')"
      if [[ $activeval == "active (running)" ]]
      then
        echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
        running=1
      else
	echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
      fi
    fi
  done
  if [[ $loaded == 1 && $running == 1 ]]
  then
    fail=0
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}\"fapolicyd.service\" was not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity37, $controlid, $stigid37, $ruleid37, $cci37, $datetime, ${GRN}PASSED, The fapolicyd module is installed and running.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity37, $controlid, $stigid37, $ruleid37, $cci37, $datetime, ${RED}FAILED, The fapolicyd module is not installed and running.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid38${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid38${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid38${NORMAL}"
echo -e "${NORMAL}CCI:       $cci38${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 38:   ${BLD}$title38a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title38b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title38c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity38${NORMAL}"

IFS='
'

file38="/etc/fapolicyd/fapolicyd.conf"

fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ $file38 ]]
then
  permissive="$(grep permissive $file38)"
  if [[ permissive ]]
  then
    permissiveval="$(echo $permissive | awk -F= '{print $2}')"
    if [[ $permissiveval == 0 ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}a. $permissive${NORMAL}"
      permissive=1
      deny="$(tail $file38)"
      if [[ $deny ]]
      then
	for line in ${deny[@]}
        do
	  if [[ $line =~ "^deny" ]]
	  then
	    denyval="$(echo $line | awk -F= '{print $2}')"
	    if [[ $denyval =~ "any all: all" ]]
            then
	      echo -e "${NORMAL}RESULT:    ${BLD}b. $line${NORMAL}"
	      denyall=1
	    else
	      echo -e "${NORMAL}RESULT:    ${RED}b. $line${NORMAL}"
	    fi
	  else
	    echo -e "${NORMAL}RESULT:    b. $line${NORMAL}"
	  fi
	done
      else
        echo -e "${NORMAL}RESULT:    ${RED}b. $file38 is empty${NORMAL}"
      fi
    else
      echo -e "${NORMAL}RESULT:    ${RED}a. $permissive${NORMAL}"
      echo -e "${NORMAL}RESULT:    b. (skipping)${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}a. \"permissive\" is not defined in $file38${NORMAL}"
    echo -e "${NORMAL}RESULT:    b. (skipping)${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file38 not found${NORMAL}"
fi

if [[ $permissive == 1 && $denyall == 1 ]]
then
  fail=0
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity38, $controlid, $stigid38, $ruleid38, $cci38, $datetime, ${GRN}PASSED, The RHEL 8 fapolicy module is configured to employ a deny-all, permit-by-exception policy to allow only the execution of authorized software programs.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity38, $controlid, $stigid38, $ruleid38, $cci38, $datetime, ${RED}PASSED, The RHEL 8 fapolicy module is not configured to employ a deny-all, permit-by-exception policy to allow only the execution of authorized software programs.${NORMAL}"
fi

exit
