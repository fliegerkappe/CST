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
YLO=`echo    "\e[93;1m"`        # bold yellow
BAR=`echo    "\e[11;1;44m"`     # blue separator bar
NORMAL=`echo "\e[0m"`           # normal

stig="Red Hat Enterprise Linux 9 Version: 2 Release: 5 Benchmark Date: 02 Jul 2025"

hostname="$(uname -n)"

if [[ -f /etc/redhat-release ]]
then
   os="$(cat /etc/redhat-release)"
else
   os="OS not defined"
fi

prog="$(basename $0)"

controlid="CM-7 Least Functionality"

title1a="RHEL 9 must not have the rsh-server package installed."
title1b="Checking with: dnf list --installed rsh-server"
title1c="Expecting: ${YLO}Error: No matching Packages to list
           If the \"rsh-server\" package is installed, this is a finding."${BLD}
cci1="CCI-000381"
stigid1="RHEL-09-215035"
severity1="CAT II"
ruleid1="SV-257830r958478"
vulnid1="V-257830"

title2a="RHEL 9 must mount /dev/shm with the nodev option."
title2b="Checking with: mount | grep /dev/shm"
title2c="Expecting: ${YLO}
           tmpfs on /dev/shm type tmpfs (rw,nodev,nosuid,noexec,seclabel)
	   NOTE: If the /dev/shm file system is mounted without the \"nodev\" option, this is a finding."${BLD}
cci2="CCI-001764"
stigid2="RHEL-09-231110"
severity2="CAT II"
ruleid2="SV-257863r958804"
vulnid2="V-257863"

title3a="RHEL 9 must mount /tmp with the nodev option."
title3b="Checking with:  mount | grep /tmp"
title3c="Expecting: ${YLO}
           /dev/mapper/rhel-tmp on /tmp type xfs (rw,nodev,nosuid,noexec,seclabel)
	   NOTE: If the \"/tmp\" file system is mounted without the \"node\" option, this is a finding."${BLD}
cci3="CCI-001764"
stigid3="RHEL-09-231125"
severity3="CAT II"
ruleid3="SV-257866r958804"
vulnid3="V-257866"

title4a="RHEL 9 must mount /tmp with the noexec option."
title4b="Checking with: mount | grep /tmp"
title4c="Expecting: ${YLO}
           /dev/mapper/rhel-tmp on /tmp type xfs (rw,nodev,nosuid,noexec,seclabel)
	   NOTE: If the \"/tmp\" file system is mounted without the \"noexec\" option, this is a finding."${BLD}
cci4="CCI-001764"
stigid4="RHEL-09-231130"
severity4="CAT II"
ruleid4="SV-257867r958804"
vulnid4="V-257867"

title5a="RHEL 9 must mount /tmp with the nosuid option."
title5b="Checking with: mount | grep /tmp"
title5c="Expecting: ${YLO}
           /dev/mapper/rhel-tmp on /tmp type xfs (rw,nodev,nosuid,noexec,seclabel)
	   NOTE: If the \"/tmp\" file system is mounted without the \"nosuid\" option, this is a finding."${BLD}
cci5="CCI-001764"
stigid5="RHEL-09-231135"
severity5="CAT II"
ruleid5="SV-257868r958804"
vulnid5="V-257868"

title6a="RHEL 9 must mount /var/log with the nodev option."
title6b="Checking with: mount | grep /var/log"
title6c="Expecting: ${YLO}
           /dev/mapper/rhel-var-log on /var/log type xfs (rw,nodev,nosuid,noexec,seclabel)
	   NOTE: If the \"/var/log\" file system is mounted without the \"nodev\" option, this is a finding."${BLD}
cci6="CCI-001764"
stigid6="RHEL-09-231145"
severity6="CAT II"
ruleid6="SV-257870r958804"
vulnid6="V-257870"

title7a="RHEL 9 must mount /var/log with the noexec option."
title7b="Checking with: mount | grep /var/log"
title7c="Expecting: ${YLO}
           /dev/mapper/rhel-var-log on /var/log type xfs (rw,nodev,nosuid,noexec,seclabel)
	   NOTE: If the \"/var/log\" file system is mounted without the \"noexec\" option, this is a finding."${BLD}
cci7="CCI-001764"
stigid7="RHEL-09-231150"
severity7="CAT II"
ruleid7="SV-257871r958804"
vulnid7="V-257871"

title8a="RHEL 9 must mount /var/log with the nosuid option."
title8b="Checking with: mount | grep /var/log"
title8c="Expecting: ${YLO}
           /dev/mapper/rhel-var-log on /var/log type xfs (rw,nodev,nosuid,noexec,seclabel)
	   NOTE: If the \"/var/log\" file system is mounted without the \"nosuid\" option, this is a finding."${BLD}
cci8="CCI-001764"
stigid8="RHEL-09-231155"
severity8="CAT II"
ruleid8="SV-257872r958804"
vulnid8="V-257872"

title9a="RHEL 9 must mount /var/log/audit with the nodev option."
title9b="Checking with: mount | grep /var/log/audit"
title9c="Expecting: ${YLO}
           /dev/mapper/rhel-var-log-audit on /var/log/audit type xfs (rw,nodev,nosuid,noexec,seclabel)
	   NOTE: If the \"/var/log/audit\" file system is mounted without the \"nodev\" option, this is a finding."${BLD}
cci9="CCI-001764"
stigid9="RHEL-09-231160"
severity9="CAT II"
ruleid9="SV-257873r958804"
vulnid9="V-257873"

title10a="RHEL 9 must mount /var/log/audit with the noexec option."
title10b="Checking with: mount | grep /var/log/audit"
title10c="Expecting: ${YLO}
           /dev/mapper/rhel-var-log-audit on /var/log/audit type xfs (rw,nodev,nosuid,noexec,seclabel)
	   NOTE: If the \"/var/log/audit\" file system is mounted without the \"noexec\" option, this is a finding."${BLD}
cci10="CCI-001764"
stigid10="RHEL-09-231165"
severity10="CAT II"
ruleid10="SV-257874r958804"
vulnid10="V-257874"

title11a="RHEL 9 must mount /var/log/audit with the nosuid option."
title11b="Checking with: mount | grep /var/log/audit"
title11c="Expecting: ${YLO}
           /dev/mapper/rhel-var-log-audit on /var/log/audit type xfs (rw,nodev,nosuid,noexec,seclabel)
	   NOTE: If the \"/var/log/audit\" file system is mounted without the \"nosuid\" option, this is a finding."${BLD}
cci11="CCI-001764"
stigid11="RHEL-09-231170"
severity11="CAT II"
ruleid11="SV-257875r958804"
vulnid11="V-257875"

title12a="RHEL 9 must mount /var/tmp with the nodev option."
title12b="Checking with: mount | grep /var/tmp"
title12c="Expecting: ${YLO}
           /dev/mapper/rhel-var-tmp on /var/tmp type xfs (rw,nodev,nosuid,noexec,seclabel)
	   NOTE: If the \"/var/tmp\" file system is mounted without the \"nodev\" option, this is a finding."${BLD}
cci12="CCI-001764"
stigid12="RHEL-09-231175"
severity12="CAT II"
ruleid12="SV-257876r958804"
vulnid12="V-257876"

title13a="RHEL 9 must mount /var/tmp with the noexec option."
title13b="Checking with: mount | grep /var/tmp"
title13c="Expecting: ${YLO}
           /dev/mapper/rhel-var-tmp on /var/tmp type xfs (rw,nodev,nosuid,noexec,seclabel)
	   NOTE: If the \"/var/tmp\" file system is mounted without the \"noexec\" option, this is a finding."${BLD}
cci13="CCI-001764"
stigid13="RHEL-09-231180"
severity13="CAT II"
ruleid13="SV-257877r958804"
vulnid13="V-257877"

title14a="RHEL 9 must mount /var/tmp with the nosuid option."
title14b="Checking with: mount | grep /var/tmp"
title14c="Expecting: ${YLO}
           /dev/mapper/rhel-var-tmp on /var/tmp type xfs (rw,nodev,nosuid,noexec,seclabel)
	   NOTE: If the \"/var/tmp\" file system is mounted without the \"nosuid\" option, this is a finding."${BLD}
cci14="CCI-001764"
stigid14="RHEL-09-231185"
severity14="CAT II"
ruleid14="SV-257878r958804"
vulnid14="V-257878"

title15a="RHEL 9 must disable the chrony daemon from acting as a server."
title15b="Checking with: grep -w port /etc/chrony.conf"
title15c="Expecting: ${YLO}port 0
           NOTE: If the \"port\" option is not set to \"0\", is commented out, or is missing, this is a finding."${BLD}
cci15="CCI-000381 CCI-000382"
stigid15="RHEL-09-252025"
severity15="CAT III"
ruleid15="SV-257946r958480"
vulnid15="V-257946"

title16a="RHEL 9 must disable network management of the chrony daemon."
title16b="Checking with: grep -w cmdport /etc/chrony.conf"
title16c="Expecting: ${YLO}cmdport 0
           NOTE: If the \"cmdport\" option is not set to \"0\", is commented out, or is missing, this is a finding."${BLD}
cci16="CCI-000381 CCI-000382"
stigid16="RHEL-09-252030"
severity16="CAT III"
ruleid16="SV-257947r958480"
vulnid16="V-257947"

title17a="RHEL 9 must disable the graphical user interface autorun function unless required."
title17b="Checking with: gsettings get org.gnome.desktop.media-handling autorun-never"
title17c="Expecting: ${YLO}true
           NOTE: If \"autorun-never\" is set to \"false\", and is not documented with the information system security officer (ISSO) as an operational requirement, this is a finding."${BLD}
cci17="CCI-001764"
stigid17="RHEL-09-271030"
severity17="CAT II"
ruleid17="SV-258016r958804"
vulnid17="V-258016"

title18a="RHEL 9 fapolicy module must be enabled."
title18b="Checking with: systemctl is-active fapolicyd"
title18c="Expecting: ${YLO}active
           NOTE: If fapolicyd module is not active, this is a finding."${BLD}
cci18="CCI-001764 CCI-001774"
stigid18="RHEL-09-433015"
severity18="CAT II"
ruleid18="SV-258090r958808"
vulnid18="V-258090"

title19a="RHEL 9 must enable mitigations against processor-based vulnerabilities."
title19b="Checking with: 
           a. grubby --info=ALL | grep args | grep -v 'pti=on'
	   b. grep pti /etc/default/grub"
title19c="Expecting: ${YLO}
           a. Nothing returned
	   b. GRUB_CMDLINE_LINUX=\"pti=on\"
	   NOTE: a. If any output is returned, this is a finding.
	   NOTE: b. If \"pti\" is not set to \"on\", is missing or commented out, this is a finding."${BLD}
cci19="CCI-000381 CCI-002824"
stigid19="RHEL-09-212050"
severity19="CAT III"
ruleid19="SV-257795r1044845"
vulnid19="V-257795"

title20a="RHEL 9 must be configured to disable the Asynchronous Transfer Mode kernel module."
title20b="Checking with: grep -r atm /etc/modprobe.conf /etc/modprobe.d/*"
title20c="Expecting: ${YLO}
           install atm /bin/false
           blacklist atm
           NOTE: If the command does not return any output, or the line is commented out, and use of ATM is not documented with the information system security officer (ISSO) as an operational requirement, this is a finding."${BLD}
cci20="CCI-000381"
stigid20="RHEL-09-213045"
severity20="CAT II"
ruleid20="SV-257804r1044853"
vulnid20="V-257804"

title21a="RHEL 9 must be configured to disable the Controller Area Network kernel module."
title21b="Checking with: grep -r can /etc/modprobe.conf /etc/modprobe.d/*"
title21c="Expecting: ${YLO}
           install can /bin/false
           blacklist can
           NOTE: If the command does not return any output, or the lines are commented out, and use of CAN is not documented with the information system security officer (ISSO) as an operational requirement, this is a finding."${BLD}
cci21="CCI-000381"
stigid21="RHEL-09-213050"
severity21="CAT II"
ruleid21="SV-257805r1044856"
vulnid21="V-257805"

title22a="RHEL 9 must be configured to disable the FireWire kernel module."
title22b="Checking with: grep -r firewire-core /etc/modprobe.conf /etc/modprobe.d/*"
title22c="Expecting: ${YLO}
           install firewire-core /bin/false
           blacklist firewire-core
           NOTE: If the command does not return any output, or the lines are commented out, and use of firewire-core is not documented with the information system security officer (ISSO) as an operational requirement, this is a finding."${BLD}
cci22="CCI-000381"
stigid22="RHEL-09-213055"
severity22="CAT II"
ruleid22="SV-257806r1044859"
vulnid22="V-257806"

title23a="RHEL 9 must disable the Stream Control Transmission Protocol (SCTP) kernel module."
title23b="Checking with: grep -r sctp /etc/modprobe.conf /etc/modprobe.d/*"
title23c="Expecting: ${YLO}
           install sctp /bin/false
           blacklist sctp
           NOTE: If the command does not return any output, or the lines are commented out, and use of sctp is not documented with the information system security officer (ISSO) as an operational requirement, this is a finding."${BLD}
cci23="CCI-000381"
stigid23="RHEL-09-213060"
severity23="CAT II"
ruleid23="SV-257807r1044862"
vulnid23="V-257807"

title24a="RHEL 9 must disable the Transparent Inter Process Communication (TIPC) kernel module."
title24b="Checking with: grep -r tipc /etc/modprobe.conf /etc/modprobe.d/*"
title24c="Expecting: ${YLO}
           install tipc /bin/false
           blacklist tipc
           NOTE: If the command does not return any output, or the lines are commented out, and use of tipc is not documented with the information system security officer (ISSO) as an operational requirement, this is a finding."${BLD}
cci24="CCI-000381"
stigid24="RHEL-09-213065"
severity24="CAT II"
ruleid24="SV-257808r1044865"
vulnid24="V-257808"

title25a="RHEL 9 must not have a File Transfer Protocol (FTP) server package installed."
title25b="Checking with: dnf list --installed vsftpd"
title25c="Expecting: ${YLO}Error: No matching Packages to list
           NOTE: If the \"ftp\" package is installed, this is a finding."${BLD}
cci25="CCI-000197 CCI-000381"
stigid25="RHEL-09-215015"
severity25="CAT I"
ruleid25="SV-257826r1106299"
vulnid25="V-257826"

title26a="RHEL 9 must not have the sendmail package installed."
title26b="Checking with: dnf list --installed sendmail"
title26c="Expecting: ${YLO}Error: No matching Packages to list
           NOTE: If the \"sendmail\" package is installed, this is a finding."${BLD}
cci26="CCI-000381"
stigid26="RHEL-09-215020"
severity26="CAT II"
ruleid26="SV-257827r1044892"
vulnid26="V-257827"

title27a="RHEL 9 must not have the nfs-utils package installed."
title27b="Checking with: dnf list --installed nfs-utils"
title27c="Expecting: ${YLO}Error: No matching Packages to list
           NOTE: If the \"nfs-utils\" package is installed, this is a finding."${BLD}
cci27="CCI-000381"
stigid27="RHEL-09-215025"
severity27="CAT II"
ruleid27="SV-257828r1044894"
vulnid27="V-257828"

title28a="RHEL 9 must not have the ypserv package installed."
title28b="Checking with: dnf list --installed ypserv"
title28c="Expecting: ${YLO}Error: No matching Packages to list
           NOTE: If the \"ypserv\" package is installed, this is a finding."${BLD}
cci28="CCI-000381"
stigid28="RHEL-09-215030"
severity28="CAT II"
ruleid28="SV-257829r1044896"
vulnid28="V-257829"

title29a="RHEL 9 must not have the telnet-server package installed."
title29b="Checking with: dnf list --installed telnet-server"
title29c="Expecting: ${YLO}Error: No matching Packages to list
           NOTE: If the \"telnet-server\" package is installed, this is a finding."${BLD}
cci29="CCI-000381"
stigid29="RHEL-09-215040"
severity29="CAT II"
ruleid29="SV-257831r1044898"
vulnid29="V-257831"

title30a="RHEL 9 must not have the gssproxy package installed."
title30b="Checking with: dnf list --installed gssproxy"
title30c="Expecting: ${YLO}Error: No matching Packages to list
           NOTE: If the \"gssproxy\" package is installed and is not documented with the information system security officer (ISSO) as an operational requirement, this is a finding."${BLD}
cci30="CCI-000381"
stigid30="RHEL-09-215045"
severity30="CAT II"
ruleid30="SV-257832r1044900"
vulnid30="V-257832"

title31a="RHEL 9 must not have the iprutils package installed."
title31b="Checking with: dnf list --installed iprutils"
title31c="Expecting: ${YLO}Error: No matching Packages to list
           NOTE: If the \"iprutils\" package is installed and is not documented with the information system security officer (ISSO) as an operational requirement, this is a finding."${BLD}
cci31="CCI-000381"
stigid31="RHEL-09-215050"
severity31="CAT II"
ruleid31="SV-257833r1044902"
vulnid31="V-257833"

title32a="RHEL 9 must not have the tuned package installed."
title32b="Checking with: dnf list --installed tuned"
title32c="Expecting: ${YLO}Error: No matching Packages to list
           NOTE: If the \"tuned\" package is installed and is not documented with the information system security officer (ISSO) as an operational requirement, this is a finding."${BLD}
cci32="CCI-000381"
stigid32="RHEL-09-215055"
severity32="CAT II"
ruleid32="SV-257834r1044904"
vulnid32="V-257834"

title33a="RHEL 9 must prevent device files from being interpreted on file systems that contain user home directories."
title33b="Checking with: mount | grep /home"
title33c="Expecting: ${YLO}
           tmpfs on /home type xfs (rw,${BLD}nodev${YLO},nosuid,noexec,seclabel)
	   NOTE: If the \"/home\" file system is mounted without the \"nodev\" option, this is a finding."
cci33="CCI-001764"
stigid33="RHEL-09-231045"
severity33="CAT II"
ruleid33="SV-257850r1044930"
vulnid33="V-257850"

title34a="RHEL 9 must prevent files with the setuid and setgid bit set from being executed on file systems that contain user home directories."
title34b="Checking with: mount | grep /home"
title34c="Expecting: ${YLO}tmpfs on /home type xfs (rw,nodev,${BLD}nosuid${YLO},noexec,seclabel)
           NOTE: If a separate file system has not been created for the user home directories (user home directories are mounted under \"/\"), this is automatically a finding, as the \"nodev\" option cannot be used on the \"/\" system.
	   NOTE: If the \"/home\" file system is mounted without the \"nodev\" option, this is a finding."${BLD}
cci34="CCI-001764"
stigid34="RHEL-09-231050"
severity34="CAT II"
ruleid34="SV-257851r1044932"
vulnid34="V-257851"

title35a="RHEL 9 must mount /boot with the nodev option."
title35b="Checking with: mount | grep '\s/boot\s'"
title35c="Expecting: ${YLO}
           /dev/sda1 on /boot type xfs (rw,${BLD}nodev${YLO},relatime,seclabel,attr2)
	   NOTE: If the \"/boot\" file system does not have the \"nodev\" option set, this is a finding."${BLD}
cci35="CCI-001764"
stigid35="RHEL-09-231095"
severity35="CAT II"
ruleid35="SV-257860r1044940"
vulnid35="V-257860"

title36a="RHEL 9 must prevent files with the setuid and setgid bit set from being executed on the /boot directory."
title36b="Checking with: mount | grep '\s/boot\s'"
title36c="Expecting: ${YLO}
           /dev/sda1 on /boot type xfs (rw,${BLD}nosuid${YLO},relatime,seclabe,attr2,inode64,noquota)
	   NOTE: If the \"/boot\" file system does not have the \"nosuid\" option set, this is a finding."${BLD}
cci36="CCI-001764"
stigid36="RHEL-09-231100"
severity36="CAT II"
ruleid36="SV-257861r1044941"
vulnid36="V-257861"

title37a="RHEL 9 must prevent files with the setuid and setgid bit set from being executed on the /boot/efi directory."
title37b="Checking with: mount | grep '\s/boot/efi\s'"
title37c="Expecting: ${YLO}
           /dev/sda1 on /boot/efi type vfat (rw,${BLD}nosuid${YLO},relatime,fmask=0077,dmask=0077,codepage=437,iocharset=ascii,shortname=winnt,errors=remount-ro)
	   NOTE: For systems that use BIOS, this requirement is Not Applicable.
	   NOTE: If the \"/boot/efi\" file system does not have the \"nosuid\" option set, this is a finding."${BLD}
cci37="CCI-001764"
stigid37="RHEL-09-231105"
severity37="CAT II"
ruleid37="SV-257862r1051265"
vulnid37="V-257862"

title38a="RHEL 9 must mount /dev/shm with the noexec option."
title38b="Checking with: findmnt /dev/shm"
title38c="Expecting: ${YLO}
           TARGET   SOURCE FSTYPE OPTIONS
           /dev/shm tmpfs  tmpfs  rw,nodev,nosuid,${BLD}noexec${YLO},seclabel 0 0
           NOTE: If the \"/dev/shm\" file system is mounted without the \"noexec\" option, this is a finding."${BLD}
cci38="CCI-001764"
stigid38="RHEL-09-231115"
severity38="CAT II"
ruleid38="SV-257864r1106304"
vulnid38="V-257864"

title39a="RHEL 9 must mount /dev/shm with the nosuid option."
title39b="Checking with: mount | grep /dev/shm"
title39c="Expecting: ${YLO}
           tmpfs on /dev/shm type tmpfs (rw,nodev,${BLD}nosuid${YLO},noexec,seclabel)
	   NOTE: If the \"/dev/shm\" file system is mounted without the \"nosuid\" option, this is a finding."${BLD}
cci39="CCI-001764"
stigid39="RHEL-09-231120"
severity39="CAT II"
ruleid39="SV-257865r1044946"
vulnid39="V-257865"

title40a="RHEL 9 must mount /var with the nodev option."
title40b="Checking with: mount | grep /var"
title40c="Expecting: ${YLO}
           /dev/mapper/rhel-var on /var type xfs (rw,${BLD}nodev${YLO},nosuid,noexec,seclabel)
	   NOTE: If the \"/var\" file system is mounted without the \"nodev\" option, this is a finding."${BLD}
cci40="CCI-001764"
stigid40="RHEL-09-231140"
severity40="CAT II"
ruleid40="SV-257869r1102009"
vulnid40="V-257869"

title41a="RHEL 9 must disable mounting of cramfs."
title41b="Checking with: grep -r cramfs /etc/modprobe.conf /etc/modprobe.d/*"
title41c="Expecting: ${YLO}
           install cramfs /bin/false
           blacklist cramfs
           NOTE: If the command does not return any output or the lines are commented out, and use of cramfs is not documented with the information system security officer (ISSO) as an operational requirement, this is a finding."${BLD}
cci41="CCI-000381"
stigid41="RHEL-09-231195"
severity41="CAT III"
ruleid41="SV-257880r1044951"
vulnid41="V-257880"

title42a="RHEL 9 must have the firewalld package installed."
title42b="Checking with: dnf list --installed firewalld"
title42c="Expecting: ${YLO}firewalld.noarch          1.0.0-4.el9
           NOTE: If the \"firewall\" package is not installed, this is a finding."${BLD}
cci42="CCI-000382 CCI-002314 CCI-002322"
stigid42="RHEL-09-251010"
severity42="CAT II"
ruleid42="SV-257935r1044994"
vulnid42="V-257935"

title43a="The firewalld service on RHEL 9 must be active."
title43b="Checking with: systemctl is-active firewalld"
title43c="Expecting: ${YLO}active
           NOTE: If the firewalld service is not active, this is a finding."${BLD}
cci43="CCI-000382 CCI-002314"
stigid43="RHEL-09-251015"
severity43="CAT II"
ruleid43="SV-257936r1044995"
vulnid43="V-257936"

title44a="RHEL 9 must be configured to prohibit or restrict the use of functions, ports, protocols, and/or services, as defined in the Ports, Protocols, and Services Management (PPSM) Category Assignments List (CAL) and vulnerability assessments."
title44b="Checking with: firewall-cmd --list-all-zones | grep -e \"active\" -e \"services\""
title44c="Expecting: ${YLO}Ask the system administrator for the site or program Ports, Protocols, and Services Management Component Local Service Assessment (PPSM CLSA).
           NOTE: If there are additional ports, protocols, or services that are not in the PPSM CLSA, or there are ports, protocols, or services that are prohibited by the PPSM CAL, this is a finding."${BLD}
cci44="CCI-000382"
stigid44="RHEL-09-251035"
severity44="CAT II"
ruleid44="SV-257940r1106312"
vulnid44="V-257940"

title45a="RHEL 9 must be configured to disable USB mass storage."
title45b="Checking with: grep -r usb-storage /etc/modprobe.conf /etc/modprobe.d/*"
title45c="Expecting: ${YLO}
           install usb-storage /bin/false
           blacklist usb-storage
           NOTE: If the command does not return any output, or either line is commented out, and use of USB Storage is not documented with the information system security officer (ISSO) as an operational requirement, this is a finding."${BLD}
cci45="CCI-000778 CCI-001958"
stigid45="RHEL-09-291010"
severity45="CAT II"
ruleid45="SV-258034r1051267"
vulnid45="V-258034"

title46a="RHEL 9 must have the USBGuard package installed."
title46b="Checking with: dnf list installed usbguard"
title46c="Expecting: ${YLO}
           usbguard.x86_64          1.0.0-10.el9_1.2          @rhel-9-for-x86_64-appstream-rpms
	   NOTE: If the USBGuard package is not installed, ask the SA to indicate how unauthorized peripherals are being blocked."${BLD}
cci46="CCI-001958 CCI-003959"
stigid46="RHEL-09-291015"
severity46="CAT II"
ruleid46="SV-258035r1045125"
vulnid46="V-258035"

title47a="RHEL 9 must have the USBGuard package enabled."
title47b="Checking with: systemctl is-active usbguard"
title47c="Expecting: ${YLO}active
           NOTE: If usbguard is not active, ask the SA to indicate how unauthorized peripherals are being blocked.
           NOTE: If there is no evidence that unauthorized peripherals are being blocked before establishing a connection, this is a finding."${BLD}
cci47="CCI-001958 CCI-003959"
stigid47="RHEL-09-291020"
severity47="CAT II"
ruleid47="SV-258036r1014861"
vulnid47="V-258036"

title48a="RHEL 9 Bluetooth must be disabled."
title48b="Checking with: grep -r bluetooth /etc/modprobe.conf /etc/modprobe.d/*"
title48c="Expecting: ${YLO}
           install bluetooth /bin/false
           blacklist bluetooth
           NOTE: If the command does not return any output, or the lines are commented out, and use of Bluetooth is not documented with the information system security officer (ISSO) as an operational requirement, this is a finding."${BLD}
cci48="CCI-000381 CCI-001443"
stigid48="RHEL-09-291035"
severity48="CAT II"
ruleid48="SV-258039r1045131"
vulnid48="V-258039"

title49a="RHEL 9 fapolicy module must be installed."
title49b="Checking with: dnf list --installed fapolicyd"
title49c="Expecting: ${YLO}fapolicyd.x86_64          1.1-103.el9_0
           NOTE: If the \"fapolicyd\" package is not installed, this is a finding."${BLD}
cci49="CCI-001764 CCI-001774"
stigid49="RHEL-09-433010"
severity49="CAT II"
ruleid49="SV-258089r1045179"
vulnid49="V-258089"

title50a="The RHEL 9 fapolicy module must be configured to employ a deny-all, permit-by-exception policy to allow the execution of authorized software programs."
title50b="Checking with: 
           a. grep permissive /etc/fapolicyd/fapolicyd.conf
	   b. sudo tail /etc/fapolicyd/compiled.rules"
title50c="Expecting: ${YLO}
           a. permissive = 0
	   b. allow exe=/usr/bin/python3.7 : ftype=text/x-python
           b. deny_audit perm=any pattern=ld_so : all
           b. deny perm=any all : all
           NOTE: If \"fapolicyd\" is not running in enforcement mode with a deny-all, permit-by-exception policy, this is a finding."${BLD}
cci50="CCI-001764"
stigid50="RHEL-09-433016"
severity50="CAT II"
ruleid50="SV-270180r1045182"
vulnid50="V-270180"

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

datetime="$(date +%FT%H:%M:%S)"

isinstalled="$(dnf list --installed 2>&1 rsh-server | grep -Ev 'Updating|Installed')"

if [[ $isinstalled ]]
then
  if [[ $isinstalled =~ "Error:" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$isinstalled${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$isinstalled${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, RHEL 9 does not have the rsh-server package installed.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, RHEL 9 has the rsh-server package installed.${NORMAL}"
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

datetime="$(date +%FT%H:%M:%S)"

shm="$(mount | grep " /dev/shm ")"

if [[ $shm ]]
then
  if [[ $shm =~ 'on /dev/shm ' && $shm =~ "nodev" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$shm${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$shm${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, RHEL 9 mounts /dev/shm with the nodev option.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, RHEL 9 does not mount /dev/shm with the nodev option.${NORMAL}"
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

datetime="$(date +%FT%H:%M:%S)"

datetime="$(date +%FT%H:%M:%S)"

tmp="$(mount | grep " /tmp ")"

if [[ $tmp ]]
then
  if [[ $tmp =~ 'on /tmp ' && $tmp =~ "nodev" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$tmp${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$tmp${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${GRN}PASSED, RHEL 9 mounts /tmp with the nodev option.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${RED}FAILED, RHEL 9 does not mount /tmp with the nodev option.${NORMAL}"
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

datetime="$(date +%FT%H:%M:%S)"

tmp="$(mount | grep " /tmp ")"

if [[ $tmp ]]
then
  if [[ $tmp =~ 'on /tmp ' && $tmp =~ "noexec" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$tmp${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$tmp${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${GRN}PASSED, RHEL 9 mounts /tmp with the noexec option.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${RED}FAILED, RHEL 9 does not mount /tmp with the noexec option.${NORMAL}"
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

datetime="$(date +%FT%H:%M:%S)"

tmp="$(mount | grep " /tmp ")"

if [[ $tmp ]]
then
  if [[ $tmp =~ 'on /tmp ' && $tmp =~ "nosuid" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$tmp${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$tmp${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${GRN}PASSED, RHEL 9 mounts /tmp with the nosuid option.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${RED}FAILED, RHEL 9 does not mount /tmp with the nosuid option.${NORMAL}"
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

datetime="$(date +%FT%H:%M:%S)"

vlog="$(mount | grep " /var/log ")"

if [[ $vlog ]]
then
  if [[ $vlog =~ 'on /var/log ' && $vlog =~ "nodev" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$vlog${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$vlog${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${GRN}PASSED, RHEL 9 mounts /var/log with the nodev option.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${RED}FAILED, RHEL 9 does not mount /var/log with the nodev option.${NORMAL}"
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

datetime="$(date +%FT%H:%M:%S)"

vlog="$(mount | grep " /var/log ")"

if [[ $vlog ]]
then
  if [[ $vlog =~ 'on /var/log ' && $vlog =~ "noexec" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$vlog${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$vlog${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${GRN}PASSED, RHEL 9 mounts /var/log with the noexec option.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${RED}FAILED, RHEL 9 does not mount /var/log with the noexec option.${NORMAL}"
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

datetime="$(date +%FT%H:%M:%S)"

vlog="$(mount | grep " /var/log ")"

if [[ $vlog ]]
then
  if [[ $vlog =~ 'on /var/log ' && $vlog =~ "nosuid" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$vlog${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$vlog${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cci8, $datetime, ${GRN}PASSED, RHEL 9 mounts /var/log with the nosuid option.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cci8, $datetime, ${RED}FAILED, RHEL 9 does not mount /var/log with the nosuid option.${NORMAL}"
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

datetime="$(date +%FT%H:%M:%S)"

vlogaudit="$(mount | grep " /var/log/audit ")"

if [[ $vlogaudit ]]
then
  if [[ $vlogaudit =~ 'on /var/log/audit ' && $vlogaudit =~ "nodev" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$vlogaudit${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$vlogaudit${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity9, $controlid, $stigid9, $ruleid9, $cci9, $datetime, ${GRN}PASSED, RHEL 9 mounts /var/log/audit with the nodev option.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity9, $controlid, $stigid9, $ruleid9, $cci9, $datetime, ${RED}FAILED, RHEL 9 does not mount /var/log/audit with the nodev option.${NORMAL}"
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

datetime="$(date +%FT%H:%M:%S)"

vlogaudit="$(mount | grep " /var/log/audit ")"

if [[ $vlogaudit ]]
then
  if [[ $vlogaudit =~ 'on /var/log/audit ' && $vlogaudit =~ "noexec" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$vlogaudit${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$vlogaudit${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity10, $controlid, $stigid10, $ruleid10, $cci10, $datetime, ${GRN}PASSED, RHEL 9 mounts /var/log/audit with the noexec option.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity10, $controlid, $stigid10, $ruleid10, $cci10, $datetime, ${RED}FAILED, RHEL 9 does not mount /var/log/audit with the noexec option.${NORMAL}"
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

datetime="$(date +%FT%H:%M:%S)"

vlogaudit="$(mount | grep " /var/log/audit ")"

if [[ $vlogaudit ]]
then
  if [[ $vlogaudit =~ 'on /var/log/audit ' && $vlogaudit =~ "nosuid" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$vlogaudit${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$vlogaudit${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity11, $controlid, $stigid11, $ruleid11, $cci11, $datetime, ${GRN}PASSED, RHEL 9 mounts /var/log/audit with the nosuid option.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity11, $controlid, $stigid11, $ruleid11, $cci11, $datetime, ${RED}FAILED, RHEL 9 does not mount /var/log/audit with the nosuid option.${NORMAL}"
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

datetime="$(date +%FT%H:%M:%S)"

vtmp="$(mount | grep " /var/tmp ")"

if [[ $vtmp ]]
then
  if [[ $vtmp =~ 'on /var/tmp ' && $vtmp =~ "nodev" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$vtmp${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$vtmp${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity12, $controlid, $stigid12, $ruleid12, $cci12, $datetime, ${GRN}PASSED, RHEL 9 mounts /var/tmp with the nodev option.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity12, $controlid, $stigid12, $ruleid12, $cci12, $datetime, ${RED}FAILED, RHEL 9 does not mount /var/tmp with the nodev option.${NORMAL}"
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

datetime="$(date +%FT%H:%M:%S)"

vtmp="$(mount | grep " /var/tmp ")"

if [[ $vtmp ]]
then
  if [[ $vtmp =~ 'on /var/tmp ' && $vtmp =~ "noexec" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$vtmp${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$vtmp${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity13, $controlid, $stigid13, $ruleid13, $cci13, $datetime, ${GRN}PASSED, RHEL 9 mounts /var/tmp with the noexec option.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity13, $controlid, $stigid13, $ruleid13, $cci13, $datetime, ${RED}FAILED, RHEL 9 does not mount /var/tmp with the noexec option.${NORMAL}"
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

datetime="$(date +%FT%H:%M:%S)"

vtmp="$(mount | grep " /var/tmp ")"

if [[ $vtmp ]]
then
  if [[ $vtmp =~ 'on /var/tmp ' && $vtmp =~ "nosuid" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$vtmp${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$vtmp${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity14, $controlid, $stigid14, $ruleid14, $cci14, $datetime, ${GRN}PASSED, RHEL 9 mounts /var/tmp with the nosuid option.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity14, $controlid, $stigid14, $ruleid14, $cci14, $datetime, ${RED}FAILED, RHEL 9 does not mount /var/tmp with the nosuid option.${NORMAL}"
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
echo -e "${NORMAL}TEST 15:    ${BLD}$title15a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title15b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title15c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity15${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

port="$(grep -w port /etc/chrony.conf)"

if [[ $port ]]
then
  for line in ${port[@]}
  do
    value="$(echo $line | awk '{print $2}')"
    if [[ $value == 0 && ${value:0:1} != "#" ]]
    then
      fail=0
      echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity15, $controlid, $stigid15, $ruleid15, $cci15, $datetime, ${GRN}PASSED, RHEL 9 disables the chrony daemon from acting as a server.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity15, $controlid, $stigid15, $ruleid15, $cci15, $datetime, ${RED}FAILED, RHEL 9 does not disable the chrony daemon from acting as a server.${NORMAL}"
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

datetime="$(date +%FT%H:%M:%S)"

cport="$(grep -w cmdport /etc/chrony.conf)"

if [[ $cport ]]
then
  for line in ${cport[@]}
  do
    value="$(echo $line | awk '{print $2}')"
    if [[ $value == 0 && ${value:0:1} != "#" ]]
    then
      fail=0
      echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity16, $controlid, $stigid16, $ruleid16, $cci16, $datetime, ${GRN}PASSED, RHEL 9 disables network management of the chrony daemon.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity15, $controlid, $stigid15, $ruleid15, $cci15, $datetime, ${RED}FAILED, RHEL 9 does not disable network management of the chrony daemon.${NORMAL}"
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

datetime="$(date +%FT%H:%M:%S)"

autorun="$(gsettings get org.gnome.desktop.media-handling autorun-never)"
if [[ $autorun ]]
then
  if [[ $autorun == "true" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$autorun${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$autorun${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity17, $controlid, $stigid17, $ruleid17, $cci17, $datetime, ${GRN}PASSED, RHEL 9 disables the graphical user interface autorun function unless required.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity17, $controlid, $stigid17, $ruleid17, $cci17, $datetime, ${GRN}PASSED, RHEL 9 does not disable the graphical user interface autorun function unless required.${NORMAL}"
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

datetime="$(date +%FT%H:%M:%S)"

isactive="$(systemctl is-active fapolicyd)"
if [[ $isactive ]]
then
  if [[ $isactive == "active" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$isactive${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$isactive${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity18, $controlid, $stigid18, $ruleid18, $cci18, $datetime, ${GRN}PASSED, The RHEL 9 fapolicy module is enabled.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity18, $controlid, $stigid18, $ruleid18, $cci18, $datetime, ${GRN}PASSED, The RHEL 9 fapolicy module is not enabled.${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

pti="$(grubby --info=ALL | grep args | grep -v 'pti=on')"

if [[ $pti ]]
then
  fail=1
  for line in ${pti[@]}
  do
    echo -e "${NORMAL}RESULT:    ${RED}a. $line${NORMAL}"
  done
else
  echo -e "${NORMAL}RESULT:    ${BLD}a. Nothing returned${NORMAL}"
fi

default="$(grep pti /etc/default/grub)"

if [[ $default ]]
then
  if [[ $default =~ " pti=on " ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}b. $default${NORMAL}"
  else
    fail=1
    echo -e "${NORMAL}RESULT:    ${RED}b. $default${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${BLD}b. Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity19, $controlid, $stigid19, $ruleid19, $cci19, $datetime, ${GRN}PASSED, RHEL 9 enables mitigations against processor-based vulnerabilities.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity19, $controlid, $stigid19, $ruleid19, $cci19, $datetime, ${GRN}PASSED, RHEL 9 does not enable mitigations against processor-based vulnerabilities.${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

load="$(grep -r atm 2>/dev/null /etc/modprobe.conf /etc/modprobe.d/*)"

if [[ $load ]]
then
  found=0
  for line in ${load[@]}
  do
    file="$(echo $line | awk -F: '{print $1}')"
    setting="$(echo $line | awk -F: '{print $2}')"
    if [[ $setting =~ "install atm /bin/false" && ${setting:0:1} != "#" ]]
    then
      (( found++ ))
      echo -e "${NORMAL}RESULT:    ${CYN}$file:${BLD}$setting${NORMAL}"
    elif [[ $line =~ "blacklist atm" && ${setting:0:1} != "#" ]]
    then
      (( found++ ))
      echo -e "${NORMAL}RESULT:    ${CYN}$file:${BLD}$setting${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${CYN}$file:${RED}$setting${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
fi

if (( $found >= 2 ))
then
  echo -e "${NORMAL}$hostname, $severity20, $controlid, $stigid20, $ruleid20, $cci20, $datetime, ${GRN}PASSED, RHEL 9 is configured to disable the Asynchronous Transfer Mode kernel module.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity20, $controlid, $stigid20, $ruleid20, $cci20, $datetime, ${RED}FAILED, RHEL 9 is not configured to disable the Asynchronous Transfer Mode kernel module.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

load="$(grep -r can 2>/dev/null /etc/modprobe.conf /etc/modprobe.d/*)"

if [[ $load ]]
then
  found=0
  for line in ${load[@]}
  do
    file="$(echo $line | awk -F: '{print $1}')"
    setting="$(echo $line | awk -F: '{print $2}')"
    if [[ $setting =~ "install can /bin/false" && ${setting:0:1} != "#" ]]
    then
      (( found++ ))
      echo -e "${NORMAL}RESULT:    ${CYN}$file:${BLD}$setting${NORMAL}"
    elif [[ $line =~ "blacklist can" && ${setting:0:1} != "#" ]]
    then
      (( found++ ))
      echo -e "${NORMAL}RESULT:    ${CYN}$file:${BLD}$setting${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${CYN}$file:${RED}$setting${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
fi

if (( $found >= 2 ))
then
  echo -e "${NORMAL}$hostname, $severity21, $controlid, $stigid21, $ruleid21, $cci21, $datetime, ${GRN}PASSED, RHEL 9 is configured to disable the Controller Area Network kernel module.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity21, $controlid, $stigid21, $ruleid21, $cci21, $datetime, ${RED}FAILED, RHEL 9 is not configured to disable the Controller Area Network kernel module.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

load="$(grep -r firewire-core 2>/dev/null /etc/modprobe.conf /etc/modprobe.d/*)"

if [[ $load ]]
then
  found=0
  for line in ${load[@]}
  do
    file="$(echo $line | awk -F: '{print $1}')"
    setting="$(echo $line | awk -F: '{print $2}')"
    if [[ $setting =~ "install firewire-core /bin/false" && ${setting:0:1} != "#" ]]
    then
      (( found++ ))
      echo -e "${NORMAL}RESULT:    ${CYN}$file:${BLD}$setting${NORMAL}"
    elif [[ $line =~ "blacklist firewire-core" && ${setting:0:1} != "#" ]]
    then
      (( found++ ))
      echo -e "${NORMAL}RESULT:    ${CYN}$file:${BLD}$setting${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${CYN}$file:${RED}$setting${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
fi

if (( $found >= 2 ))
then
  echo -e "${NORMAL}$hostname, $severity22, $controlid, $stigid22, $ruleid22, $cci22, $datetime, ${GRN}PASSED, RHEL 9 is configured to disable the Firewire kernel module.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity22, $controlid, $stigid22, $ruleid22, $cci22, $datetime, ${RED}FAILED, RHEL 9 is not configured to disable the Firewire kernel module.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

load="$(grep -r sctp 2>/dev/null /etc/modprobe.conf /etc/modprobe.d/*)"

if [[ $load ]]
then
  found=0
  for line in ${load[@]}
  do
    file="$(echo $line | awk -F: '{print $1}')"
    setting="$(echo $line | awk -F: '{print $2}')"
    if [[ $setting =~ "install sctp /bin/false" && ${setting:0:1} != "#" ]]
    then
      (( found++ ))
      echo -e "${NORMAL}RESULT:    ${CYN}$file:${BLD}$setting${NORMAL}"
    elif [[ $line =~ "blacklist sctp" && ${setting:0:1} != "#" ]]
    then
      (( found++ ))
      echo -e "${NORMAL}RESULT:    ${CYN}$file:${BLD}$setting${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${CYN}$file:${RED}$setting${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
fi

if (( $found >= 2 ))
then
  echo -e "${NORMAL}$hostname, $severity23, $controlid, $stigid23, $ruleid23, $cci23, $datetime, ${GRN}PASSED, RHEL 9 is configured to disable the Stream Control Transmission Protocol (SCTP) kernel module.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity23, $controlid, $stigid23, $ruleid23, $cci23, $datetime, ${RED}FAILED, RHEL 9 is not configured to disable the Stream Control Transmission Protocol (SCTP) kernel module.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

load="$(grep -r tipc 2>/dev/null /etc/modprobe.conf /etc/modprobe.d/*)"

if [[ $load ]]
then
  found=0
  for line in ${load[@]}
  do
    file="$(echo $line | awk -F: '{print $1}')"
    setting="$(echo $line | awk -F: '{print $2}')"
    if [[ $setting =~ "install tipc /bin/false" && ${setting:0:1} != "#" ]]
    then
      (( found++ ))
      echo -e "${NORMAL}RESULT:    ${CYN}$file:${BLD}$setting${NORMAL}"
    elif [[ $line =~ "blacklist tipc" && ${setting:0:1} != "#" ]]
    then
      (( found++ ))
      echo -e "${NORMAL}RESULT:    ${CYN}$file:${BLD}$setting${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${CYN}$file:${RED}$setting${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
fi

if (( $found >= 2 ))
then
  echo -e "${NORMAL}$hostname, $severity24, $controlid, $stigid24, $ruleid24, $cci24, $datetime, ${GRN}PASSED, RHEL 9 is configured to disable the Transparent Inter Process Communication (TIPC) kernel module.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity24, $controlid, $stigid24, $ruleid24, $cci24, $datetime, ${RED}FAILED, RHEL 9 is not configured to disable the Transparent Inter Process Communication (TIPC) kernel module.${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

isinstalled="$(dnf list --installed 2>&1 vsftpd | grep -Ev 'Updating|Installed')"

if [[ $installed =~ "vsftpd" ]]
then
  fail=1
  echo -e "${NORMAL}RESULT:    ${RED}$isinstalled${NORMAL}"
else
  echo -e "${NORMAL}RESULT:    ${BLD}$isinstalled${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity25, $controlid, $stigid25, $ruleid25, $cci25, $datetime, ${GRN}PASSED, RHEL 9 does not have a File Transfer Protocol (FTP) server package installed.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity25, $controlid, $stigid25, $ruleid25, $cci25, $datetime, ${RED}FAILED, RHEL 9 has a File Transfer Protocol (FTP) server package installed.${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

isinstalled="$(dnf list --installed 2>&1 sendmail | grep -Ev 'Updating|Installed')"

if [[ $installed =~ "sendmail" ]]
then
  fail=1
  echo -e "${NORMAL}RESULT:    ${RED}$isinstalled${NORMAL}"
else
  echo -e "${NORMAL}RESULT:    ${BLD}$isinstalled${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity26, $controlid, $stigid26, $ruleid26, $cci26, $datetime, ${GRN}PASSED, RHEL 9 does not have the sendmail package installed.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity26, $controlid, $stigid26, $ruleid26, $cci26, $datetime, ${RED}FAILED, RHEL 9 has the sendmail package installed.${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

isinstalled="$(dnf list --installed 2>&1 nfs-utils | grep -Ev 'Updating|Installed')"

if [[ $installed =~ "nfs-utils" ]]
then
  fail=1
  echo -e "${NORMAL}RESULT:    ${RED}$isinstalled${NORMAL}"
else
  echo -e "${NORMAL}RESULT:    ${BLD}$isinstalled${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity27, $controlid, $stigid27, $ruleid27, $cci27, $datetime, ${GRN}PASSED, RHEL 9 does not have the nfs-utils package installed.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity27, $controlid, $stigid27, $ruleid27, $cci27, $datetime, ${RED}FAILED, RHEL 9 has the nfs-utils package installed.${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

isinstalled="$(dnf list --installed 2>&1 ypserv | grep -Ev 'Updating|Installed')"

if [[ $installed =~ "ypserv" ]]
then
  fail=1
  echo -e "${NORMAL}RESULT:    ${RED}$isinstalled${NORMAL}"
else
  echo -e "${NORMAL}RESULT:    ${BLD}$isinstalled${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity28, $controlid, $stigid28, $ruleid28, $cci28, $datetime, ${GRN}PASSED, RHEL 9 does not have the ypserv package installed.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity28, $controlid, $stigid28, $ruleid28, $cci28, $datetime, ${RED}FAILED, RHEL 9 has the ypserv package installed.${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

isinstalled="$(dnf list --installed 2>&1 telnet-server | grep -Ev 'Updating|Installed')"

if [[ $installed =~ "telnet-server" ]]
then
  fail=1
  echo -e "${NORMAL}RESULT:    ${RED}$isinstalled${NORMAL}"
else
  echo -e "${NORMAL}RESULT:    ${BLD}$isinstalled${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity29, $controlid, $stigid29, $ruleid29, $cci29, $datetime, ${GRN}PASSED, RHEL 9 does not have the telnet-server package installed.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity29, $controlid, $stigid29, $ruleid29, $cci29, $datetime, ${RED}FAILED, RHEL 9 has the telnet-server package installed.${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

isinstalled="$(dnf list --installed 2>&1 gssproxy | grep -Ev 'Updating|Installed')"

if [[ $installed =~ "gssproxy" ]]
then
  fail=1
  echo -e "${NORMAL}RESULT:    ${RED}$isinstalled${NORMAL}"
else
  echo -e "${NORMAL}RESULT:    ${BLD}$isinstalled${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity30, $controlid, $stigid30, $ruleid30, $cci30, $datetime, ${GRN}PASSED, RHEL 9 does not have the gssproxy package installed.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity30, $controlid, $stigid30, $ruleid30, $cci30, $datetime, ${RED}FAILED, RHEL 9 has the gssproxy package installed.${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

isinstalled="$(dnf list --installed 2>&1 iprutils | grep -Ev 'Updating|Installed')"

if [[ $installed =~ "iprutils" ]]
then
  fail=1
  echo -e "${NORMAL}RESULT:    ${RED}$isinstalled${NORMAL}"
else
  echo -e "${NORMAL}RESULT:    ${BLD}$isinstalled${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity31, $controlid, $stigid31, $ruleid31, $cci31, $datetime, ${GRN}PASSED, RHEL 9 does not have the iprutils package installed.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity31, $controlid, $stigid31, $ruleid31, $cci31, $datetime, ${RED}FAILED, RHEL 9 has the iprutils package installed.${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

isinstalled="$(dnf list --installed 2>&1 tuned | grep -Ev 'Updating|Installed')"

if [[ $installed =~ "tuned" ]]
then
  fail=1
  echo -e "${NORMAL}RESULT:    ${RED}$isinstalled${NORMAL}"
else
  echo -e "${NORMAL}RESULT:    ${BLD}$isinstalled${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity32, $controlid, $stigid32, $ruleid32, $cci32, $datetime, ${GRN}PASSED, RHEL 9 does not have the tuned package installed.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity32, $controlid, $stigid32, $ruleid32, $cci32, $datetime, ${RED}FAILED, RHEL 9 has the tuned package installed.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

home="$(mount | grep /home)"

if [[ $home ]]
then
  if [[ $home =~ "on /home " && $home =~ "nodev" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$home${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$home${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity33, $controlid, $stigid33, $ruleid33, $cci33, $datetime, ${GRN}PASSED, RHEL 9 prevents device files from being interpreted on file systems that contain user home directories.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity33, $controlid, $stigid33, $ruleid33, $cci33, $datetime, ${RED}FAILED, RHEL 9 does not prevent device files from being interpreted on file systems that contain user home directories.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

home="$(mount | grep /home)"

if [[ $home ]]
then
  if [[ $home =~ "on /home " && $home =~ "nosuid" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$home${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$home${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity34, $controlid, $stigid34, $ruleid34, $cci34, $datetime, ${GRN}PASSED, RHEL 9 prevents files with the setuid and setgid bit set from being executed on file systems that contain user home directories.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity34, $controlid, $stigid34, $ruleid34, $cci34, $datetime, ${RED}FAILED, RHEL 9 does not prevent files with the setuid and setgid bit set from being executed on file systems that contain user home directories.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

boot="$(mount | grep '\s/boot\s')"

if [[ $boot ]]
then
  if [[ $boot =~ "on /boot " && $boot =~ "nodev" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$boot${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$boot${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity35, $controlid, $stigid35, $ruleid35, $cci35, $datetime, ${GRN}PASSED, RHEL 9 mounts /boot with the nodev option.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity35, $controlid, $stigid35, $ruleid35, $cci35, $datetime, ${RED}FAILED, RHEL 9 does not mount /boot with the nodev option.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

boot="$(mount | grep '\s/boot\s')"

if [[ $boot ]]
then
  if [[ $boot =~ "on /boot " && $boot =~ "nosuid" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$boot${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$boot${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity36, $controlid, $stigid36, $ruleid36, $cci36, $datetime, ${GRN}PASSED, RHEL 9 prevents files with the setuid and setgid bit set from being executed on the /boot directory.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity36, $controlid, $stigid36, $ruleid36, $cci36, $datetime, ${RED}FAILED, RHEL 9 does not prevent files with the setuid and setgid bit set from being executed on the /boot directory.${NORMAL}"
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

datetime="$(date +%FT%H:%M:%S)"

if [[ -d /sys/firmware/efi ]]
then

  bootefi="$(mount | grep '\s/boot/efi\s')"
  
  if [[ $bootefi ]]
  then
    if [[ $bootefi =~ "on /boot/efi " && $boot =~ "nosuid" ]]
    then
      fail=0
      echo -e "${NORMAL}RESULT:    ${BLD}$bootefi${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$bootefi${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
  fi

else
  fail=2
  echo -e "${NORMAL}RESULT:    ${BLD}The system uses BIOS${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity37, $controlid, $stigid37, $ruleid37, $cci37, $datetime, ${GRN}PASSED, RHEL 9 prevents files with the setuid and setgid bit set from being executed on the /boot/efi directory.${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity37, $controlid, $stigid37, $ruleid37, $cci37, $datetime, ${GRN}N/A, RHEL 9 uses BIOS. This requirement is Not Applicable.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity37, $controlid, $stigid37, $ruleid37, $cci37, $datetime, ${RED}FAILED, RHEL 9 does not prevent files with the setuid and setgid bit set from being executed on the /boot/efi directory.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

shm="$(findmnt /dev/shm)"

if [[ $shm ]]
then
  for line in ${shm[@]}
  do
    if [[ $line =~ "/dev/shm " && $line =~ "noexec" || $line =~ "TARGET" ]]
    then
      fail=0
      echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity38, $controlid, $stigid38, $ruleid38, $cci38, $datetime, ${GRN}PASSED, RHEL 9 mounts /dev/shm with the noexec option.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity38, $controlid, $stigid38, $ruleid38, $cci38, $datetime, ${RED}FAILED, RHEL 9 does not mount /dev/shm with the noexec option.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid39${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid39${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid39${NORMAL}"
echo -e "${NORMAL}CCI:       $cci39${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 39:   ${BLD}$title39a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title39b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title39c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity39${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

shm="$(mount 2>/dev/null | grep /dev/shm)"

if [[ $shm ]]
then
  for line in ${shm[@]}
  do
    if [[ $line =~ "nosuid" ]]
    then
      fail=0
      echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity39, $controlid, $stigid39, $ruleid39, $cci39, $datetime, ${GRN}PASSED, RHEL 9 mounts /dev/shm with the nosuid option.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity39, $controlid, $stigid39, $ruleid38, $cci39, $datetime, ${RED}FAILED, RHEL 9 does not mount /dev/shm with the nosuid option.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid40${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid40${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid40${NORMAL}"
echo -e "${NORMAL}CCI:       $cci40${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 40:   ${BLD}$title40a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title40b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title40c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity40${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

var="$(mount 2>/dev/null | grep "/var ")"

if [[ $var ]]
then
  for line in ${var[@]}
  do
    if [[ $line =~ "on /var " && $line =~ "nodev" ]]
    then
      fail=0
      echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity40, $controlid, $stigid40, $ruleid40, $cci40, $datetime, ${GRN}PASSED, RHEL 9 mounts /var with the nodev option.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity40, $controlid, $stigid40, $ruleid40, $cci40, $datetime, ${RED}FAILED, RHEL 9 does not mount /var with the nodev option.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid41${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid41${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid41${NORMAL}"
echo -e "${NORMAL}CCI:       $cci41${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 41:   ${BLD}$title41a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title41b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title41c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity41${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

cramfs="$(grep -r cramfs 2>/dev/null /etc/modprobe.conf /etc/modprobe.d/*)"

if [[ $cramfs ]]
then
  found=0
  for line in ${cramfs[@]}
  do
    file="$(echo $line | awk -F: '{print $1}')"
    setting="$(echo $line | awk -F: '{print $2}')"
    if [[ $setting =~ "install cramfs /bin/false" && ${setting:0:1} != "#" ]]
    then
      (( found++ ))
      echo -e "${NORMAL}RESULT:    ${CYN}$file:${BLD}$setting${NORMAL}"
    elif [[ $line =~ "blacklist cramfs" && ${setting:0:1} != "#" ]]
    then
      (( found++ ))
      echo -e "${NORMAL}RESULT:    ${CYN}$file:${BLD}$setting${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${CYN}$file:${RED}$setting${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if (( $found >= 2 ))
then
  echo -e "${NORMAL}$hostname, $severity41, $controlid, $stigid41, $ruleid41, $cci41, $datetime, ${GRN}PASSED, RHEL 9 disables mounting of cramfs.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity41, $controlid, $stigid41, $ruleid41, $cci41, $datetime, ${RED}FAILED, RHEL 9 disables mounting of cramfs.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid42${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid42${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid42${NORMAL}"
echo -e "${NORMAL}CCI:       $cci42${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 42:   ${BLD}$title42a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title42b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title42c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity42${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

isinstalled="$(dnf list --installed 2>&1 firewalld | grep -Ev 'Updating|Installed')"

if [[ $isinstalled ]]
then
  fail=0
  echo -e "${NORMAL}RESULT:    ${BLD}$isinstalled${NORMAL}"
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity42, $controlid, $stigid42, $ruleid42, $cci42, $datetime, ${GRN}PASSED, RHEL 9 has the firewalld package installed.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity42, $controlid, $stigid42, $ruleid42, $cci42, $datetime, ${RED}FAILED, RHEL 9 does not have the firewalld package installed.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid43${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid43${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid43${NORMAL}"
echo -e "${NORMAL}CCI:       $cci43${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 43:   ${BLD}$title43a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title43b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title43c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity43${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

isactive="$(systemctl is-active firewalld)"

if [[ $isactive == "active" ]]
then
  fail=0
  echo -e "${NORMAL}RESULT:    ${BLD}$isactive${NORMAL}"
else
  echo -e "${NORMAL}RESULT:    ${RED}$isactive${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity43, $controlid, $stigid43, $ruleid43, $cci43, $datetime, ${GRN}PASSED, The RHEL 9 firewalld service is active.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity43, $controlid, $stigid43, $ruleid43, $cci43, $datetime, ${RED}FAILED, The RHEL 9 firewalld service is not active.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid44${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid44${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid44${NORMAL}"
echo -e "${NORMAL}CCI:       $cci44${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 44:   ${BLD}$title44a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title44b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title44c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity44${NORMAL}"

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity44, $controlid, $stigid44, $ruleid44, $cci44, $datetime, ${CYN}VERIFY, Verify the services allowed by the firewall match the PPSM CLSA.${NORMAL}"

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid45${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid45${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid45${NORMAL}"
echo -e "${NORMAL}CCI:       $cci45${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 45:   ${BLD}$title45a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title45b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title45c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity45${NORMAL}"

IFS='
'

fail=0

datetime="$(date +%FT%H:%M:%S)"

usbstorage="$(grep -r usb-storage 2>/dev/null /etc/modprobe.conf /etc/modprobe.d/*)"

if [[ $usbstorage ]]
then
  found=0
  for line in ${usbstorage[@]}
  do
    file="$(echo $line | awk -F: '{print $1}')"
    setting="$(echo $line | awk -F: '{print $2}')"
    if [[ $setting =~ "install usb-storage /bin/false" && ${setting:0:1} != "#" ]]
    then
      (( found++ ))
      echo -e "${NORMAL}RESULT:    ${CYN}$file:${BLD}$setting${NORMAL}"
    elif [[ $line =~ "blacklist usb-storage" && ${setting:0:1} != "#" ]]
    then
      (( found++ ))
      echo -e "${NORMAL}RESULT:    ${CYN}$file:${BLD}$setting${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${CYN}$file:${RED}$setting${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if (( $found >= 2 ))
then
  echo -e "${NORMAL}$hostname, $severity45, $controlid, $stigid45, $ruleid45, $cci45, $datetime, ${GRN}PASSED, RHEL 9 is configured to disable USB mass storage.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity45, $controlid, $stigid45, $ruleid45, $cci45, $datetime, ${RED}FAILED, RHEL 9 is not configured to disable USB mass storage.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid46${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid46${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid46${NORMAL}"
echo -e "${NORMAL}CCI:       $cci46${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 46:   ${BLD}$title46a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title46b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title46c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity46${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

isinstalled="$(dnf list --installed 2>&1 usbguard | grep -Ev 'Updating|Installed')"

if [[ $isinstalled ]]
then
  if [[ $isinstalled =~ "Error:" ]]
  then
    echo -e "${NORMAL}RESULT:    ${RED}$isinstalled${NORMAL}"
  else
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$isinstalled${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity46, $controlid, $stigid46, $ruleid46, $cci46, $datetime, ${GRN}PASSED, RHEL 9 has the USBGuard package installed.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity46, $controlid, $stigid46, $ruleid46, $cci46, $datetime, ${RED}FAILED, RHEL 9 does not have the USBGuard package installed.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid47${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid47${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid47${NORMAL}"
echo -e "${NORMAL}CCI:       $cci47${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 47:   ${BLD}$title47a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title47b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title47c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity47${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

isactive="$(systemctl is-active usbguard)"

if [[ $isactive ]]
then
  if [[ $isactive == "active" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$isactive${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$isactive${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity47, $controlid, $stigid47, $ruleid47, $cci47, $datetime, ${GRN}PASSED, RHEL 9 has the USBGuard package enabled.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity47, $controlid, $stigid47, $ruleid47, $cci47, $datetime, ${GRN}PASSED, RHEL 9 does not have the USBGuard package enabled.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid48${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid48${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid48${NORMAL}"
echo -e "${NORMAL}CCI:       $cci48${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 48:   ${BLD}$title48a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title48b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title48c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity48${NORMAL}"

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severityi48, $controlid, $stigid48, $ruleid48, $cci48, $datetime, ${CYN}VERIFY, (See AC-18 Wireless Access: V-258039)${NORMAL}"

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid49${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid49${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid49${NORMAL}"
echo -e "${NORMAL}CCI:       $cci49${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 49:   ${BLD}$title49a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title49b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title49c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity49${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

isinstalled="$(dnf list --installed 2>&1 fapolicyd | grep -Ev 'Updating|Installed')"

if [[ $isinstalled ]]
then
  if [[ $isinstalled =~ "Error:" ]]
  then
    echo -e "${NORMAL}RESULT:    ${RED}$isinstalled${NORMAL}"
  else
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$isinstalled${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity49, $controlid, $stigid49, $ruleid49, $cci49, $datetime, ${GRN}PASSED, RHEL 9 has the fapolicy module installed.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity46, $controlid, $stigid46, $ruleid46, $cci46, $datetime, ${RED}FAILED, RHEL 9 does not have the fapolicy module installed.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid50${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid50${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid50${NORMAL}"
echo -e "${NORMAL}CCI:       $cci50${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 50:   ${BLD}$title50a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title50b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title50c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity50${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

permissive="$(grep permissive /etc/fapolicyd/fapolicyd.conf)"

if [[ $permissive ]]
then
  value="$(echo $permissive | awk -F= '{print $2}' | sed 's/ //')"
  if [[ $value == "0" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$permissive${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$permissive${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity50, $controlid, $stigid50, $ruleid50, $cci50, $datetime, ${GRN}PASSED, RHEL 9 is configured to employ a deny-all permit-by-exception policy to allow the execution of authorized software programs.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity50, $controlid, $stigid50, $ruleid50, $cci50, $datetime, ${RED}FAILED, RHEL 9 is not configured to employ a deny-all permit-by-exception policy to allow the execution of authorized software programs.${NORMAL}"
fi


