#! /bin/bash

# CM-6 Configuration Settings
#
# CONTROL: The organization:
# a. Establishes and documents configuration settings for information technology products
#    employed within the information system using [Assignment: organization-defined security
#    configuration checklists] that reflect the most restrictive mode consistent with operational
#    requirements;
# b. Implements the configuration settings;
# c. Identifies, documents, and approves any deviations from established configuration settings for
#    [Assignment: organization-defined information system components] based on [Assignment:
#    organization-defined operational requirements]; and
# d. Monitors and controls changes to the configuration settings in accordance with organizational
#    policies and procedures.

# Check if the script is being run as root
if [ "$EUID" -ne 0 ]
then
   echo "Please run with sudo or as root"
   exit
fi

# Color declarations
RED=`echo    "\e[31;1m"`	# bold red
GRN=`echo    "\e[32;1m"`	# bold green
BLD=`echo    "\e[0;1m"`		# bold black
CYN=`echo    "\e[33;1;35m"`	# bold cyan
YLO=`echo    "\e[33;1m"`        # bold yellow
BAR=`echo    "\e[32;1;46m"`	# aqua separator bar
NORMAL=`echo "\e[0m"`		# normal

stig="Red Hat Enterprise Linux 8 Security Technical Implementation Guide :: Version 1, Release: 13 Benchmark Date: 24 Jan 2024"

hostname="$(uname -n)"

if [[ -f /etc/redhat-release ]]
then
   os="$(cat /etc/redhat-release)"
else
   os="OS not defined"
fi

prog="$(basename $0)"

controlid="CM-6 Configuration Settings"

title1a="The Red Hat Enterprise Linux operating system must be a vendor supported release."
title1b="Checking with 'cat /etc/redhat-release'."
title1c="Expecting:${YLO} Red Hat Enterprise Linux Server release 8.5 (Ootpa) (or newer)
           NOTE: If the release is not supported by the vendor, this is a finding.
	   NOTE: Current End of Extended Update Support for RHEL 8.1 is 30 November 2021.
	   NOTE: Current End of Extended Update Support for RHEL 8.2 is 30 April 2022.
	   NOTE: Current End of Extended Update Support for RHEL 8.4 is 31 May 2023
	   NOTE: Current End of Maintenance Support for RHEL 8.5 is 31 May 2022.
	   NOTE: Current End of Extended Update Support for RHEL 8.6 is 31 May 2024.
	   NOTE: Current End of Maintenance Support for RHEL 8.7 is 31 May 2023.
	   NOTE: Current End of Extended Update Support for RHEL 8.8 is 31 May 2025.
	   NOTE: Current End of Maintenance Support for RHEL 8.9 is 31 May 2024.
	   NOTE: Current End of Maintenance Support for RHEL 8.10 is 31 May 2029.${BLD}"
cci1="CCI-000366"
stigid1="RHEL-08-010000"
severity1="CAT I"
ruleid1="SV-230221r743913_rule"
vulnid1="V-230221"

title2a="RHEL 8 vendor packaged system security patches and updates must be installed and up to date."
title2b="Checking with 'yum history list'."
title2c="Expecting: ${YLO}package updates are performed within program requirements.
           Note: If package updates have not been performed on the system within the timeframe the site/program documentation requires, this is a finding.${BLD}"
cci2="CCI-000366"
stigid2="RHEL-08-010010"	
severity2="CAT II"
ruleid2="SV-230222r627750_rule"
vulnid2="V-230222"

title3a="RHEL 8 must ensure the SSH server uses strong entropy."
title3b="Checking with 'grep -i ssh_use_strong_rng /etc/sysconfig/sshd'."
title3c="Expecting: ${YLO}SSH_USE_STRONG_RNG=32
           Note: If the operating system is RHEL versions 8.0 or 8.1, this requirement is ot applicable.
           Note: If the \"SSH_USE_STRONG_RNG\" line does not equal \"32\", is commented out or missing, this is a finding."${BLD}
cci3="CCI-000366"
stigid3="RHEL-08-010292"
severity3="CAT III"
ruleid3="SV-230253r627750_rule"
vulnid3="V-230253"

title4a="There must be no shosts.equiv files on the RHEL 8 operating system."
title4b="Checking with 'find / -name shosts.equiv'."
title4c="Expecting: ${YLO}No shosts.equiv files found
           NOTE: If a \"shosts.equiv\" file is found, this is a finding."${BLD}
cci4="CCI-000366"
stigid4="RHEL-08-010460"
severity4="CAT I"
ruleid4="SV-230283r627750_rule"
vulnid4="V-230283"

title5a="There must be no .shosts files on the RHEL 8 operating system."
title5b="Checking with 'find / -name '*.shosts''"
title5c="Expecting: ${YLO}No .shosts files found${BLD}
           NOTE: ${YLO}If any \".shosts\" files are found, this is a finding."${BLD}
cci5="CCI-000366"
stigid5="RHEL-08-010470"
severity5="CAT I"
ruleid5="SV-230284r627750_rule"
vulnid5="V-230284"

title6a="RHEL 8 must enable the hardware random number generator entropy gatherer service."
title6b="Checking with 'systemctl is-enabled rngd', then 'systemctl is-active rngd'."
title6c="Expecting: ${YLO}\"enabled\" : \"active\"${BLD}
           Note: ${YLO}If the service is not \"enabled\" and \"active\", this is a finding."${BLD}
cci6="CCI-000366"
stigid6="RHEL-08-010471"
severity6="CAT III"
ruleid6="SV-230285r627750_rule"
vulnid6="V-230285"

title7a="The RHEL 8 SSH public host key files must have mode 0644 or less permissive."
title7b="Checkint with 'ls -l /etc/ssh/*.pub'"
title7c="Expecting:
           ${YLO}-rw-r--r--${BLD} 1 root root 618 Nov 28 06:43 ssh_host_dsa_key.pub
           ${YLO}-rw-r--r--${BLD} 1 root root 347 Nov 28 06:43 ssh_host_key.pub
           ${YLO}-rw-r--r--${BLD} 1 root root 238 Nov 28 06:43 ssh_host_rsa_key.pub
           NOTE: ${YLO}If any key.pub file has a mode more permissive than "0644", this is a finding.${BLD}
	   NOTE: SSH public key files may be found in other directories on the system depending on the installation."
cci7="CCI-000366"
stigid7="RHEL-08-010480"
severity7="CAT II"
ruleid7="SV-230286r627750_rule"
vulnid7="V-230286"

title8a="The RHEL 8 SSH private host key files must have mode 0640 or less permissive."
title8b="Checking with 'ls -l /etc/ssh/ssh_host*key'."
title8c="Expecting:
           ${YLO}-rw-------${BLD} 1 root ssh_keys 668 Nov 28 06:43 ssh_host_dsa_key
           ${YLO}-rw-------${BLD} 1 root ssh_keys 582 Nov 28 06:43 ssh_host_key
           ${YLO}-rw-------${BLD} 1 root ssh_keys 887 Nov 28 06:43 ssh_host_rsa_key
	   NOTE: ${YLO}If any private host key file has a mode more permissive than "0640", this is a finding."${BLD}
cci8="CCI-000366"
stigid8="RHEL-08-010490"
severity8="CAT II"
ruleid8="SV-230287r743951_rule"
vulnid8="V-230287"

title9a="The RHEL 8 SSH daemon must perform strict mode checking of home directory configuration files."
title9b="Checking with 'grep -i strictmodes /etc/ssh/sshd_config'."
title9c="Expecting: ${YLO}StrictModes yes${BLD}
           NOTE: ${YLO}If \"StrictModes\" is set to \"no\", is missing, or the returned line is commented out, this is a finding."${BLD}
cci9="CCI-000366"
stigid9="RHEL-08-010500"
severity9="CAT II"
ruleid9="SV-230288r627750_rule"
vulnid9="V-230288"

title10a="The RHEL 8 SSH daemon must not allow authentication using known host’s authentication."
title10b="Checking with 'grep ^IgnoreUserKnownHosts /etc/ssh/sshd_config'."
title10c="Expecting: ${YLO}IgnoreUserKnownHosts yes${BLD}
           NOTE: ${YLO}If the value is returned as \"no\", the returned line is commented out, or no output is returned, this is a finding."${BLD}
cci10="CCI-000366"
stigid10="RHEL-08-010520"
severity10="CAT II"
ruleid10="SV-230290r627750_rule"
vulnid10="V-230290"

title11a="The RHEL 8 SSH daemon must not allow Kerberos authentication, except to fulfill documented and validated mission requirements."
title11b="Checking with 'grep ^KerberosAuthentication' /etc/ssh/sshd_config'."
title11c="Expecting: ${YLO}KerberosAuthentication no${BLD}
           NOTE: ${YLO}If the value is returned as \"yes\", the returned line is commented out, no output is returned, or has not been documented with the ISSO, this is a finding."${BLD}
cci11="CCI-000366"
stigid11="RHEL-08-010521"
severity11="CAT II"
ruleid11="SV-230291r743957_rule"
vulnid11="V-230291"

title12a="RHEL 8 must use a separate file system for /var."
title12b="Checking with 'grep /var /etc/fstab'."
title12c="Expecting: ${YLO}A separage partition exists for /var.${BLD}
           NOTE: ${YLO}If a separate entry for \"/var\" is not in use, this is a finding."${BLD}
cci12="CCI-000366"
stigid12="RHEL-08-010540"
severity12="CAT III"
ruleid12="SV-230292r627750_rule"
vulnid12="V-230292"

title13a="RHEL 8 must use a separate file system for /var/log."
title13b="Checking with 'grep /var/log /etc/fstab'."
title13c="Expecting: ${YLO}A separage partition exists for /var/log.${BLD}
           Note: ${YLO}If a separate entry for \"/var/log\" is not in use, this is a finding."${BLD}
cci13="CCI-000366"
stigid13="RHEL-08-010541"
severity13="CAT III"
ruleid13="SV-230293r627750_rule"
vulnid13="V-230293"

title14a="RHEL 8 must use a separate file system for the system audit data path."
title14b="Checking with 'grep /var/log/audit /etc/fstab'."
title14c="Expecting: ${YLO}A separate file system for the system audit data path exists.${BLD}
           NOTE: ${YLO}If a separate file system/partition does not exist for the system audit data path, this is a finding."${BLD}
cci14="CCI-000366"
stigid14="RHEL-08-010542"
severity14="CAT III"
ruleid14="SV-230294r627750_rule"
vulnid14="V-230294"

title15a="A separate RHEL 8 filesystem must be used for the /tmp directory."
title15b="Checking with 'grep /tmp /etc/fstab"
title15c="Expecting: ${YLO}A separate file system is used for /tmp.${BLD}
           NOTE: ${YLO}If a separate entry for the file system/partition \"/tmp\" does not exist, this is a finding."${BLD}
cci15="CCI-000366"
stigid15="RHEL-08-010543"
severity15="CAT II"
ruleid15="SV-230295r627750_rule"
vulnid15="V-230295"

title16a="The rsyslog service must be running in RHEL 8."
title16b="Checking with 'systemctl is-enabled rsyslog', then 'systemctl is-active rsyslog'."
title16c="Expecting: ${YLO}\"enabled\" : \"active\"${BLD}
           Note: ${YLO}If the service is not \"enabled\" and \"active\", this is a finding."${BLD}
cci16="CCI-000366"
stigid16="RHEL-08-010561"
severity16="CAT II"
ruleid16="SV-230298r627750_rule"
vulnid16="V-230298"

title17a="RHEL 8 must prevent files with the setuid and setgid bit set from being executed on file systems that contain user home directories."
title17b="Checking with:
           a. 'awk -F: '(\$3>=1000)&&(\$7 !~ /nologin/){print \$1,\$3,\$6}' /etc/passwd', then
	   b. 'more /etc/fstab'"
title17c="Expecting:${YLO}
           a. a list of user accounts showing the partition where their home directories are.
	   b. a list of filesystems showing whether the home directory has the \"nosuid\" option assigned.
	   NOTE: If a separate file system has not been created for the user home directories (user home directories are mounted under \"/\"), this is automatically a finding as the \"nosuid\" option cannot be used on the \"/\" system.
           NOTE: If a file system found in \"/etc/fstab\" refers to the user home directory file system and it does not have the \"nosuid\" option set, this is a finding."${BLD}
cci17="CCI-000366"
stigid17="RHEL-08-010570"
severity17="CAT II"
ruleid17="SV-230299r627750_rule"
vulnid17="V-230299"

title18a="RHEL 8 must prevent files with the setuid and setgid bit set from being executed on the /boot directory" 
title18b="Checking with 'mount | grep '\\s/boot\\s''."
title18c="Expecting: ${YLO}/dev/sda1 on /boot type xfs (rw,${GRN}nosuid${YLO},relatime,seclabe,attr2,inode64,noquota).
           NOTE: If the /boot file system does not have the \"nosuid\" option set, this is a finding."${BLD}
cci18="CCI-000366"
stigid18="RHEL-08-010571"
severity18="CAT II"
ruleid18="SV-230300r743959_rule"
vulnid18="V-230300"

title19a="RHEL 8 must prevent special devices on non-root local partitions." 
title19b="Checking with 'mount | grep '^/dev\\S* on/\\S' | grep --invert-match 'nodev'."
title19c="Expecting: ${YLO}no output.
           NOTE: If any output is produced, this is a finding."${BLD}
cci19="CCI-000366"
stigid19="RHEL-08-010580"
severity19="CAT II"
ruleid19="SV-230301r627750_rule"
vulnid19="V-230301"

title20a="RHEL 8 must prevent code from being executed on file systems that contain user home directories."
title20b="Checking with 'awk -F: '(\$3>=1000)&&(\$7 !~ /nologin/){print \$1,\$3,\$6}' /etc/passwd'."
title20c="Expecting: ${YLO}Separate file systems designated for user home directories are set with the \"noexec\" option.
           NOTE: If a separate file system has not been created for the user home directories (user home directories are mounted under \"/\"), this is automatically a finding as the \"noexec\" option cannot be used on the \"/\" system.
           NOTE: If a file system found in \"/etc/fstab\" refers to the user home directory file system and it does not have the \"noexec\" option set, this is a finding."${BLD}
cci20="CCI-000366"
stigid20="RHEL-08-010590"
severity20="CAT II"
ruleid20="SV-230302r627750_rule"
vulnid20="V-230302"

title21a="RHEL 8 must prevent special devices on file systems that are used with removable media." 
title21b="Checking with 'more /etc/fstab'."
title21c="Expecting: ${YLO}UUID=2bc871e4-e2a3-4f29-9ece-3be60c835222 /mnt/${GRN}usbflash${YLO} vfat noauto,owner,ro,nosuid,${GRN}nodev${YLO},noexec 0 0.
           NOTE: If a file system found in \"/etc/fstab\" refers to removable media and it does not have the \"nodev\" option set, this is a finding."${BLD}
cci21="CCI-000366"
stigid21="RHEL-08-010600"
severity21="CAT II"
ruleid21="SV-230303r627750_rule"
vulnid21="V-230303"

title22a="RHEL 8 must prevent code from being executed on file systems that are used with removable media." 
title22b="Checking with 'more /etc/fstab'."
title22c="Expecting: ${YLO}UUID=2bc871e4-e2a3-4f29-9ece-3be60c835222 /mnt/${GRN}usbflash${YLO} vfat noauto,owner,ro,nosuid,nodev,${GRN}noexec${YLO} 0 0.
           NOTE: If a file system found in \"/etc/fstab\" refers to removable media and it does not have the \"noexec\" option set, this is a finding."${BLD}
cci22="CCI-000366"
stigid22="RHEL-08-010610"
severity22="CAT II"
ruleid22="SV-230304r627750_rule"
vulnid22="V-230304"

title23a="RHEL 8 must prevent files with the setuid and setgid bit set from being executed on file systems that are used with removable media." 
title23b="Checking with 'more /etc/fstab'."
title23c="Expecting: ${YLO}UUID=2bc871e4-e2a3-4f29-9ece-3be60c835222 /mnt/${GRN}usbflash${YLO} vfat noauto,owner,ro,${GRN}nosuid${YLO},nodev,noexec 0 0.
           NOTE: If a file system found in \"/etc/fstab\" refers to removable media and it does not have the \"nosuid\" option set, this is a finding."${BLD}
cci23="CCI-000366"
stigid23="RHEL-08-010620"
severity23="CAT II"
ruleid23="SV-230305r627750_rule"
vulnid23="V-230305"

title24a="RHEL 8 must prevent code from being executed on file systems that are imported via Network File System (NFS)." 
title24b="Checking with 'grep nfs /etc/fstab | grep noexec'."
title24c="Expecting: ${YLO}UUID=e06097bb-cfcd-437b-9e4d-a691f5662a7d /store ${GRN}nfs${YLO} rw,nosuid,nodev,${GRN}noexec${YLO} 0 0.
           NOTE: If a file system found in \"/etc/fstab\" refers to NFS and it does not have the \"noexec\" option set, this is a finding."${BLD}
cci24="CCI-000366"
stigid24="RHEL-08-010630"
severity24="CAT II"
ruleid24="SV-230306r627750_rule"
vulnid24="V-230306"

title25a="RHEL 8 must prevent special devices on file systems that are imported via Network File System (NFS)." 
title25b="Checking with 'grep nfs /etc/fstab | grep nodev'."
title25c="Expecting: ${YLO}UUID=e06097bb-cfcd-437b-9e4d-a691f5662a7d /store ${GRN}nfs${YLO} rw,nosuid,${GRN}nodev${YLO},noexec 0 0.
           NOTE: If a file system found in \"/etc/fstab\" refers to NFS and it does not have the \"nodev\" option set, this is a finding."${BLD}
cci25="CCI-000366"
stigid25="RHEL-08-010640"
severity25="CAT II"
ruleid25="SV-230307r627750_rule"
vulnid25="V-230307"

title26a="RHEL 8 must prevent files with the setuid and setgid bit set from being executed on file systems that are imported via Network File System (NFS)." 
title26b="Checking with 'grep nfs /etc/fstab | grep nosuid'."
title26c="Expecting: ${YLO}UUID=e06097bb-cfcd-437b-9e4d-a691f5662a7d /store ${GRN}nfs${YLO} rw,${GRN}nosuid${YLO},nodev,noexec 0 0.
           NOTE: If a file system found in \"/etc/fstab\" refers to NFS and it does not have the \"nosuid\" option set, this is a finding."${BLD}
cci26="CCI-000366"
stigid26="RHEL-08-010650"
severity26="CAT II"
ruleid26="SV-230308r627750_rule"
vulnid26="V-230308"

title27a="Local RHEL 8 initialization files must not execute world-writable programs."
title27b="Checking with:
           a. 'find [PART] -xdev -type f -perm -0002 -print', then
           b. 'grep <file> /<homedir>/*/.*"
title27c="Expecting: ${YLO}No world-writable initialization files referenced in local user initialization files.
           Note: If any local initialization files are found to reference world-writable files, this is a finding."${BLD}
cci27="CCI-000366"
stigid27="RHEL-08-010660"
severity27="CAT II"
ruleid27="SV-230309r627750_rule"
vulnid27="V-230309"

title28a="RHEL 8 must disable kernel dumps unless needed."
title28b="Checking with 'systemctl status kdump.service'."
title28c="Expecting: ${YLO}Kernel core dumps are masked (disabled) unless needed (documented)
           if active: 
           kdump.service - Crash recovery kernel arming 
           Loaded: loaded (/usr/lib/systemd/system/kdump.service; enabled; vendor preset: enabled) 
           Active: active (exited) since Mon 2020-05-04 13:08:09 EDT; 43min ago 
           Main PID: 1130 (code=exited, status=0/SUCCESS) 
           kernel arming.
           Note: If the \"kdump\" service is active, ask the System Administrator if the use of the service is required and documented with the Information System Security Officer (ISSO).
	   Note: service is active and is not documented, this is a finding."${BLD}
cci28="CCI-000366"
stigid28="RHEL-08-010670"
severity28="CAT II"
ruleid28="SV-230310r627750_rule"
vulnid28="V-230310"

title29a="RHEL 8 must disable the kernel.core_pattern."
title29b="Checking with:
           a. 'sysctl kernel.core_pattern'
	   b. 'grep -r kernel.core_pattern /etc/sysctl.d/*.conf'"
title29c="Expecting:${YLO} 
           a. kernel.core_pattern = |/bin/false
	   b. /etc/sysctl.d/99-sysctl.conf:kernel.core_pattern = |/bin/false
           NOTE: If the returned line does not have a value of \"${GRN}|/bin/false${YLO}\", or a line is not returned and the need for core dumps is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.
	   NOTE: If \"kernel.core_pattern\" is not set to \"|/bin/false\", is missing or commented out, this is a finding.
	   NOTE: If the configuration file does not begin with \"99-\", this is a finding."${BLD}
cci29="CCI-000366"
stigid29="RHEL-08-010671"
severity29="CAT II"
ruleid29="SV-230311r792894_rule"
vulnid29="V-230311"

title30a="RHEL 8 must disable acquiring, saving, and processing core dumps."
title30b="Checking with 'systemctl status systemd-coredump.socket'."
title30c="Expecting:${YLO}
           systemd-coredump.socket
           Loaded: masked (Reason: Unit ctrl-alt-del.target is masked.)
           Active: inactive (dead)
	   NOTE: iIf the \"systemd-coredump.socket\" is loaded and not masked and the need for core dumps is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding."${BLD}
cci30="CCI-000366"
stigid30="RHEL-08-010672"
severity30="CAT II"
ruleid30="SV-230312r627750_rule"
vulnid30="V-230312"

title31a="RHEL 8 must disable core dumps for all users."
title31b="Checking with 'grep -r -s '^[^#].*core' /etc/security/limits.conf /etc/security/limits.d/*.conf'."
title313c="Expecting: ${YLO}* hard core 0
           NOTE: This can be set as a global domain (with the * wildcard) but may be set differently for multiple domains.
           NOTE: If the \"core\" item is missing, commented out, or the value is anything other than \"0\" and the need for core dumps is not documented with the Information System Security Officer (ISSO) as an operational requirement for all domains that have the \"core\" item assigned, this is a finding."${BLD}
cci31="CCI-000366"
stigid31="RHEL-08-010673"
severity31="CAT II"
ruleid31="SV-230313r627750_rule"
vulnid31="V-230313"

title32a="RHEL 8 must disable storing core dumps."
title32b="Checking with 'grep -i storage /etc/systemd/coredump.conf'."
title320c="Expecting: ${YLO}Storage=none
           NOTE: If the \"Storage\" item is missing, commented out, or the value is anything other than \"none\" and the need for core dumps is not documented with the Information System Security Officer (ISSO) as an operational requirement for all domains that have the \"core\" item assigned, this is a finding."${BLD}
cci32="CCI-000366"
stigid32="RHEL-08-010674"
severity32="CAT II"
ruleid32="SV-230314r627750_rule"
vulnid32="V-230314"

title33a="RHEL 8 must disable core dump backtraces."
title33b="Checking with 'grep -i ProcessSizeMax /etc/systemd/coredump.conf'."
title33c="Expecting: ${YLO}ProcessSizeMax=0
           NOTE: If the \"ProcessSizeMax\" item is missing, commented out, or the value is anything other than \"0\" and the need for core dumps is not documented with the Information System Security Officer (ISSO) as an operational requirement for all domains that have the \"core\" item assigned, this is a finding."${BLD}
cci33="CCI-000366"
stigid33="RHEL-08-010675"
severity33="CAT II"
ruleid33="SV-230315r627750_rule"
vulnid33="V-230315"

title34a="For RHEL 8 systems using Domain Name Servers (DNS) resolution, at least two name servers must be configured."
title34b="Checking with:
           a. 'grep hosts /etc/nsswitch.conf'.
	   b. 'grep nameserver /etc/resolv.conf'."
title34c="Expecting: ${YLO}hosts: files dns
           NOTE: a. If the DNS entry is missing from the host's line in the \"/etc/nsswitch.conf\" file, the \"/etc/resolv.conf\" file must be empty.
	   NOTE: b. If local host authentication is being used and the \"/etc/resolv.conf\" file is not empty, this is a finding.
	   NOTE: a. If the DNS entry is found on the host's line of the \"/etc/nsswitch.conf\" file, verify the operating system is configured to use two or more name servers for DNS resolution.
	   NOTE: b. If less than two lines are returned that are not commented out, this is a finding."${BLD}
cci34="CCI-000366"
stigid34="RHEL-08-010680"
severity34="CAT II"
ruleid34="SV-230316r627750_rule"
vulnid34="V-230316"

title35a="Executable search paths within the initialization files of all local interactive RHEL 8 users must only contain paths that resolve to the system default or the users home directory."
title35b="Checking with 'grep -i path= /home/*/.*'."
title35c="Expecting: ${YLO}/home/[localinteractiveuser]/.bash_profile:PATH=\$PATH:\$HOME/.local/bin:\$HOME/bin
           NOTE: If any local interactive user initialization files have executable search path statements that include directories outside of their home directory and is not documented with the ISSO as an operational requirement, this is a finding.
	   NOTE: If a local interactive user requires path variables to reference a directory owned by the application, it must be documented with the ISSO."${BLD}
cci35="CCI-000366"
stigid35="RHEL-08-010690"
severity35="CAT II"
ruleid35="SV-230317r792896_rule"
vulnid35="V-230317"

title36a="All RHEL 8 world-writable directories must be owned by root, sys, bin, or an application user."
title36b="Checking with 'find [PART] -xdev -type d -perm -0002 -uid +999 -print'."
title36c="Expecting: ${YLO}no output
           NOTE: If there is output, this is a finding."${BLD}
cci36="CCI-000366"
stigid36="RHEL-08-010700"
severity36="CAT II"
ruleid36="SV-230318r743960_rule"
vulnid36="V-230318"

title37a="All RHEL 8 world-writable directories must be group-owned by root, sys, bin, or an application group."
title37b="Checking with 'find [PART] -xdev -type d -perm -0002 -gid +999 -print'."
title37c="Expecting: ${YLO}no output.
           NOTE: If there is output, this is a finding."${BLD}
cci37="CCI-000366"
stigid37="RHEL-08-010710"
severity37="CAT II"
ruleid37="SV-230319r743961_rule"
vulnid37="V-230319"

title38a="All RHEL 8 local interactive users must have a home directory assigned in the /etc/passwd file."
title38b="Checking with 'pwck -r'."
title38c="Expecting:${YLO} 
           user 'lp': directory '/var/spool/lpd' does not exist
           user 'news': directory '/var/spool/news' does not exist
           user 'uucp': directory '/var/spool/uucp' does not exist
           user 'www-data': directory '/var/www' does not exist
	   NOTE: Ask the System Administrator (SA) if any users found without home directories are local interactive users. If the SA is unable to provide a response, check for users with a User Identifier (UID) of 1000 or greater with the following command:
	     'awk -F: '(\$3>=1000)&&(\$7 !~ /nologin/){print \$1, \$3, \$6}' /etc/passwd'
	   NOTE: If any interactive users do not have a home directory assigned, this is a finding."${BLD}
cci38="CCI-000366"
stigid38="RHEL-08-010720"
severity38="CAT II"
ruleid38="SV-230320r627750_rule"
vulnid38="V-230320"

title39a="All RHEL 8 local interactive user home directories must have mode 0750 or less permissive."
title39b="Checking with 'ls -ld \$(awk -F: '(\$3>=1000)&&(\$7 !~ /nologin/){print \$6}' /etc/passwd)"
title39c="Expecting: i${YLO}All local interactive user home directories defined in the /etc/passwd file exist.
           NOTE: This may miss interactive users that have been assigned a privileged User Identifier (UID). Evidence of interactive use may be obtained from a number of log files containing system logon information.
           NOTE: If home directories referenced in \"/etc/passwd\" do not have a mode of \"0750\" or less permissive, this is a finding."${BLD}
cci39="CCI-000366"
stigid39="RHEL-08-010730"
severity39="CAT II"
ruleid39="SV-230321r627750_rule"
vulnid39="V-230321"

title40a="All RHEL 8 local interactive user home directories must be group-owned by the home directory owner’s primary group."
title40b="Checking with:
           a. 'ls -ld \$(awk -F: '(\$3>=1000)&&(\$7 !~ /nologin/){print \$6}' /etc/passwd)', then
	   b. 'grep \$(grep smithj /etc/passwd | awk -F: ‘{print \$4}’) /etc/group."
title40c="Expecting: ${YLO}drwxr-x--- 2 smithj admin 4096 Jun 5 12:41 smithj
	   ${YLO}NOTE: This may miss local interactive users that have been assigned a privileged UID. Evidence of interactive use may be obtained from a number of log files containing system logon information. The returned directory \"/home/smithj\" is used as an example.
           Note: If the user home directory referenced in \"/etc/passwd\" is not group-owned by that user's primary GID, this is a finding."${BLD}
cci40="CCI-000366"
stigid40="RHEL-08-010740"
severity40="CAT II"
ruleid40="SV-230322r743963_rule"
vulnid40="V-230322"

title41a="All RHEL 8 local interactive user home directories defined in the /etc/passwd file must exist."
title41b="Checking with:
           a. 'ls -ld \$(awk -F: (\$3>=1000)&&(\$7 !~ /nologin/){print \$6} /etc/passwd)'
	   b. 'pwck -r'."
title41c="Expecting:${YLO} 
           a. drwxr-xr-x 2 smithj admin 4096 Jun 5 12:41 smithj
	   b. All local interactive user home directories defined in /etc/passwd exist.
           NOTE: This may miss interactive users that have been assigned a privileged User ID (UID). Evidence of interactive use may be obtained from a number of log files containing system logon information.
	   NOTE: If any home directories referenced in \"/etc/passwd\" are returned as not defined, this is a finding."${BLD}
cci41="CCI-000366"
stigid41="RHEL-08-010750"
severity41="CAT II"
ruleid41="SV-230323r627750_rule"
vulnid41="V-230323"

title42a="All RHEL 8 local interactive user accounts must be assigned a home directory upon creation."
title42b="Checking with 'grep -icreate_home /etc/login.defs'."
title42c="Expecting: ${YLO}CREATE_HOME yes
           Note: If the value for \"CREATE_HOME\" parameter is not set to \"yes\", the line is missing, or the line is commented out, this is a finding."${BLD}
cci42="CCI-000366"
stigid42="RHEL-08-010760"
severity42="CAT II"
ruleid42="SV-230324r627750_rule"
vulnid42="V-230324"

title43a="All RHEL 8 local initialization files must have mode 0740 or less permissive."
title43b="Checking with 'ls -al /home/smithj/.[^.]*'."
title43c="Expecting: 
           ${YLO}-rwxr-xr-x${BLD} 1 smithj users 896 Mar 10 2011 .profile
           ${YLO}-rwxr-xr-x${BLD} 1 smithj users 497 Jan 6 2007 .login
           ${YLO}-rwxr-xr-x${BLD} 1 smithj users 886 Jan 6 2007 .something
           Note: ${YLO}If any local initialization files have a mode more permissive than \"0740\", this is a finding."${BLD}
cci43="CCI-000366"
stigid43="RHEL-08-010770"
severity43="CAT II"
ruleid43="SV-230325r627750_rule"
vulnid43="V-230325"

title44a="All RHEL 8 local files and directories must have a valid owner."
title44b="Checking with 'find / -fstype [FSTYPE] -nouser'."
title44c="Expecting: ${YLO}no output
           NOTE: $If any files on the system do not have an assigned owner, this is a finding."${BLD}
cci44="CCI-000366"
stigid44="RHEL-08-010780"
severity44="CAT II"
ruleid44="SV-230326r627750_rule"
vulnid44="V-230326"

title45a="All RHEL 8 local files and directories must have a valid group owner."
title45b="Checking with 'find / -fstype xfs -nogroup'."
title45c="Expecting: ${YLO}no output
           NOTE: If any files on the system do not have an assigned group, this is a finding."${BLD}
cci45="CCI-000366"
stigid45="RHEL-08-010790"
severity45="CAT II"
ruleid45="SV-230327r627750_rule"
vulnid45="V-230327"

title46a="A separate RHEL 8 filesystem must be used for user home directories (such as /home or an equivalent)."
title46b="Checking with 'awk -F: '(\$3>=1000)&&(\$7 !~ /nologin/){print \$1,\$3,\$6}' /etc/passwd'."
title46c="Expecting:
           adamsj 1001 ${YLO}/home${BLD}/adamsj
           jacksonm 1002 ${YLO}/home${BLD}/jacksonm 
           smithj 1003 ${YLO}/home${BLD}/smithj${YLO}
           Note: The output of the command will give the directory/partition that contains the home directories for the non-privileged users on the system (in this example, \"${GRN}/home${YLO}\") and users’ shell. All accounts with a valid shell (such as /bin/bash) are considered interactive users.
	   NOTE: If a separate entry for the file system/partition containing the non-privileged interactive user home directories does not exist, this is a finding."${BLD}
cci46="CCI-000366"
stigid46="RHEL-08-010800"
severity46="CAT II"
ruleid46="SV-230328r627750_rule"
vulnid46="V-230328"

title47a="Unattended or automatic logon via the RHEL 8 graphical user interface must not be allowed."
title47b="Checking with 'grep -i automaticloginenable /etc/gdm/custom.conf.
           ${YLO}NOTE: This requirement assumes the use of the RHEL 8 default graphical user interface, Gnome Shell. If the system does not have any graphical user interface installed, this requirement is Not Applicable.
	   NOTE: If the value of \"AutomaticLoginEnable\" is not set to \"false\", this is a finding."${BLD}
title47c="Expecting: ${YLO}AutomaticLoginEnable=false
           NOTE: This requirement assumes the use of the RHEL 8 default graphical user interface, Gnome Shell. If the system does not have any graphical user interface installed, this requirement is Not Applicable.
	   NOTE: If the value of \"AutomaticLoginEnable\" is not set to \"false\", this is a finding."${BLD}
cci47="CCI-000366"
stigid47="RHEL-08-010820"
severity47="CAT I"
ruleid47="SV-230329r627750_rule"
vulnid47="V-230329"

title48a="RHEL 8 must not allow users to override SSH environment variables."
title48b="Checking with 'grep -i permituserenvironment /etc/ssh/sshd_config'."
title48c="Expecting: ${YLO}PermitUserEnvironment no${BLD}
           NOTE: ${YLO}If \"PermitUserEnvironment\" is set to \"yes\", is missing completely, or is commented out, this is a finding."${BLD}
cci48="CCI-000366"
stigid48="RHEL-08-010830"
severity48="CAT II"
ruleid48="SV-230330r646870_rule"
vulnid48="V-230330"

title49a="RHEL 8 must ensure the password complexity module is enabled in the password-auth file."
title49b="Checking with: cat /etc/pam.d/password-auth | grep pam_pwquality"
title49c="Expecting: ${YLO}password required pam_pwquality.so${BLD}
           NOTE: ${YLO}If the command does not return a line containing the value "pam_pwquality.so", or the line is commented out, this is a finding."${BLD}
cci49="CCI-000366"
stigid49="RHEL-08-020100"
severity49="CAT II"
ruleid49="SV-230356r809379_rule"
vulnid49="V-230356"

title50a="RHEL 8 must prevent the use of dictionary words for passwords."
title50b="Checking with 'grep dictcheck /etc/security/pwquality.conf /etc/pwquality.conf.d/*.conf'."
title50c="Expecting: dictcheck=1
           NOTE: ${YLO}If the \"dictcheck\" parameter is not set to \"1\", or is commented out, this is a finding."${BLD}
cci50="CCI-000366"
stigid50="RHEL-08-020300"
severity50="CAT II"
ruleid50="SV-230377r627750_rule"
vulnid50="V-230377"

title51a="RHEL 8 must enforce a delay of at least four seconds between logon prompts following a failed logon attempt."
title51b="Checking with 'grep -i fail_delay /etc/login.defs'."
title51c="Expecting: ${YLO}FAIL_DELAY 4${BLD}
           NOTE: ${YLO}If the value of \"FAIL_DELAY\" is not set to \"4\" or greater, or the line is commented out, this is a finding."${BLD}
cci51="CCI-000366"
stigid51="RHEL-08-020310"
severity51="CAT II"
ruleid51="SV-230378r627750_rule"
vulnid51="V-230378"

title52a="RHEL 8 must not have unnecessary accounts."
title52b="Checking with 'more/etc/passwd'." 
title52c="Expecting: ${YLO}All accounts are valid.
           NOTE: Obtain the list of authorized system accounts from the Information System Security Officer (ISSO).
	   NOTE: Accounts such as \"${RED}games${YLO}\" and \"${RED}gopher${YLO}\" are not authorized accounts as they do not support authorized system functions. 
           NOTE: If the accounts on the system do not match the provided documentation, or accounts that do not support an authorized system function are present, this is a finding."${BLD}
cci52="CCI-000366"
stigid52="RHEL-08-020320"
severity52="CAT II"
ruleid52="SV-230379r627750_rule"
vulnid52="V-230379"

title53a="RHEL 8 must not allow accounts configured with blank or null passwords."
title53b="Checking with 'grep -i permitemptypasswords /etc/ssh/sshd_config'"
title53c="Expecting: ${YLO}\"PermitEmptyPasswords no\"
	   NOTE: If \"PermitEmptyPasswords\" is set to \"yes\", this is a finding."${BLD}
cci53="CCI-000366"
stigid53="RHEL-08-020330"
severity53="CAT I"
ruleid53="SV-230380r743993_rule"
vulnid53="V-230380"

title54a="RHEL 8 must define default permissions for all authenticated users in such a way that the user can only read and modify their own files."
title54b="Checking with 'grep -i ^umask /etc/login.defs'."
title54c="Expecting: ${YLO}UMASK	077${BLD}
           NOTE: ${YLO}If the value of the \"UMASK\" parameter is set to \"000\" in \"/etc/login.defs\" file, the Severity is raised to a CAT I.${BLD}
	   NOTE: ${YLO}If the value for the \"UMASK\" parameter is not \"077\", or the \"UMASK\" parameter is missing or is commented out, this is a finding."${BLD}
cci54="CCI-000366"
stigid54="RHEL-08-020351"
severity54="CAT II"
ruleid54="SV-230383r627750_rule"
vulnid54="V-230383"

title55a=" RHEL 8 must set the umask value to 077 for all local interactive user accounts."
title55b="Checking with 'grep -i umask /home/*/.*."
title55c="Expecting: ${YLO}All interactive user initialization files are mode 077 or more restrictive.${BLD}
           NOTE: ${YLO}If any local interactive user initialization files are found to have a umask statement that has a value less restrictive than \"077\", this is a finding.${BLD}
	   NOTE: The example is for a system that is configured to create users home directories in the \"/home\" directory."
cci55="CCI-000366"
stigid55="RHEL-08-020352"
severity55="CAT II"
ruleid55="SV-230384r627750_rule"
vulnid55="V-230384"

title56a="RHEL 8 must define default permissions for logon and non-logon shells."
title56b="Checking with 'grep -i umask /etc/bashrc /etc/csh.cshrc /etc/profile'."
title56c="Expecting:
           /etc/bashrc: umask 077
           /etc/bashrc: umask 077
           /etc/csh.cshrc: umask 077 
           /etc/csh.cshrc: umask 077
           /etc/profile: umask 077 
           /etc/profile: umask 077
	   NOTE: ${YLO}If the value for the \"UMASK\" parameter is not \"077\", or the \"UMASK\" parameter is missing or is commented out, this is a finding.${BLD}
	   NOTE: ${YLO}If the value of the \"UMASK\" parameter is set to \"000\" in the \"/etc/bashrc\" the \"/etc/csh.cshrc\" or the \"/etc/profile\" files, the Severity is raised to a CAT I."${BLD}
cci56="CCI-000366"
stigid56="RHEL-08-020353"
severity56="CAT II"
ruleid56="SV-230385r792902_rule"
vulnid56="V-230385"

title57a="Cron logging must be implemented in RHEL 8."
title57b="Checking with 'grep cron /etc/rsyslog.conf /etc/rsyslog.d/*.conf'."
title57c="Expecting:
           ${YLO}/etc/rsyslog.conf:*.info;mail.none;authpriv.none;cron.none /var/log/messages
           /etc/rsyslog.conf:# Log cron stuff
           /etc/rsyslog.conf:cron.* /var/log/cron${BLD}
           NOTE: If the command does not return a response, check for cron logging all facilities with the following command.
	   'grep -s /var/log/messages /etc/rsyslog.conf /etc/rsyslog.d/*.conf'
	   NOTE: ${YLO}If \"rsyslog\" is not logging messages for the cron facility or all facilities, this is a finding."${BLD}
cci57="CCI-000366"
stigid57="RHEL-08-030010"
severity57="CAT II"
ruleid57="SV-230387r743996_rule"
vulnid57="V-230387"

title58a="The RHEL 8 audit system must audit local events."
title58b="Checking with 'grep local_events /etc/audit/auditd.conf'"
title58c="Expecting: ${YLO}local_events = yes${BLD}
           NOTE: ${YLO}If the value of the \"local_events\" option is not set to \"yes\", or the line is commented out, this is a finding."${BLD}
cci58="CCI-000366"
stigid58="RHEL-08-030061"
severity58="CAT II"
ruleid58="SV-230393r627750_rule"
vulnid58="V-230393"

title59a="RHEL 8 must resolve audit information before writing to disk."
title59b="Checking with 'grep \"log_format\" /etc/audit/auditd.conf'."
title59c="Expecting: ${YLO}log_format = ENRICHED${BLD}
           NOTE: ${YLO}If the \"log_format\" option is not \"ENRICHED\", or the line is commented out, this is a finding."${BLD}
cci59="CCI-000366"
stigid59="RHEL-08-030063"
severity59="CAT III"
ruleid59="SV-230395r627750_rule"
vulnid59="V-230395"

title60a="RHEL 8 must have the packages required for offloading audit logs installed."
title60b="Checking with 'yum list installed rsyslog'."
title60c="Expecting: ${YLO}rsyslog.x86_64 8.1911.0-3.el8 @AppStream${BLD}
           NOTE: ${YLO}If the \"rsyslog\" package is not installed, ask the administrator to indicate how audit logs are being offloaded and what packages are installed to support it. If there is no evidence of audit logs being offloaded, this is a finding."${BLD}
cci60="CCI-000366"
stigid60="RHEL-08-030670"
severity60="CAT II"
ruleid60="SV-230477r627750_rule"
vulnid60="V-230477"

title61a="RHEL 8 must have the packages required for encrypting offloaded audit logs installed."
title61b="Checking with 'yum list installed rsyslog-gnutls'."
title61c="Expecting: ${YLO}rsyslog.x86_64 8.1911.0-3.el8 @AppStream${BLD}
           NOTE: ${YLO}If the \"rsyslog-gnutls\" package is not installed, ask the administrator to indicate how audit logs are being encrypted during the offloading and what packages are installed to support it. If there is no evidence of audit logs being encrypted during offloading, this is a finding."${BLD}
cci61="CCI-000366"
stigid61="RHEL-08-030680"
severity61="CAT II"
ruleid61="SV-230478r744011_rule"
vulnid61="V-230478"

title62a="The x86 Ctrl-Alt-Delete key sequence must be masked (disabled) on RHEL8."
title62b="Checking with 'systemctl status ctrl-alt-del.target'."
title62c="Expecting:
           ctrl-alt-del.target
           ${YLO}Loaded: masked (Reason: Unit ctrl-alt-del.target is masked.)
           Active: inactive (dead)${BLD}
           NOTE: ${YLO}If the ctrl.alt.del.target is loaded and not masked, this is a finding."${BLD}
cci62="CCI-000366"
stigid62="RHEL-08-040170"
severity62="CAT I"
ruleid62="SV-230529r627750_rule"
vulnid62="V-230529"

title63a="The x86 Ctrl-Alt-Delete key sequence in RHEL 8 must be disabled if a graphical user interface is installed."
title63b="Checking with 'grep logout /etc/dconf/db/local.d/*'."
title63c="Expecting: ${YLO}logout=''${BLD}
           NOTE: ${YLO}This requirement assumes the use of the RHEL 8 default graphical user interface, Gnome Shell. If the system does not have any graphical user interface installed, this requirement is Not Applicable.${BLD}
           NOTE: ${YLO}If the \"logout\" key is bound to an action, is commented out, or is missing, this is a finding."${BLD}
cci63="CCI-000366"
stigid63="RHEL-08-040171"
severity63="CAT I"
ruleid63="SV-230530r646883_rule"
vulnid63="V-230530"

title64a="The systemd Ctrl-Alt-Delete burst key sequence in RHEL 8 must be disabled."
title64b="Checking with 'grep -i ctrl /etc/systemd/system.conf'."
title64c="Expecting: ${YLO}CtrlAltDelBurstAction=none${BLD}
           NOTE: ${YLO}If the \"CtrlAltDelBurstAction\" is not set to \"none\", commented out, or is missing, this is a finding."${BLD}
cci64="CCI-000366"
stigid64="RHEL-08-040172"
severity64="CAT I"
ruleid64="SV-230531r627750_rule"
vulnid64="V-230531"

title65a="The debug-shell systemd service must be masked (disabled) on RHEL 8."
title65b="Checking with 'systemctl status debug-shell.service'."
title65c="Expecting:
           debug-shell.service
           ${YLO}Loaded: masked${BLD} (Reason: Unit debug-shell.service is masked.)
           ${YLO}Active: inactive (dead)${BLD}
           NOTE: ${YLO}If the \"debug-shell.service\" is loaded and not masked, this is a finding."${BLD}
cci65="CCI-000366"
stigid65="RHEL-08-040180"
severity65="CAT II"
ruleid65="SV-230532r627750_rule"
vulnid65="V-230532"

title66a="The Trivial File Transfer Protocol (TFTP) server package must not be installed if not required for RHEL 8 operational support."
title66b="Checking with 'yum list installed tftp-server'."
title66c="Expecting: ${YLO}no output${BLD}
           Note: ${YLO}If TFTP is installed and the requirement for TFTP is not documented with the ISSO, this is a finding."${BLD}
cci66="CCI-000368"
stigid66="RHEL-08-040190"
severity66="CAT I"
ruleid66="SV-230533r627750_rule"
vulnid66="V-230533"

title67a="The root account must be the only account having unrestricted access to the RHEL 8 system."
title67b="Checking with 'awk -F: '(\$3 == "0") {print \$1}' /etc/passwd'."
title67c="Expecting: ${YLO}Only the 'root' account has a UID of '0'.${BLD}
           Note: ${YLO}If any accounts other than root have a UID of \"0\", this is a finding."${BLD}
cci67="CCI-000366"
stigid67="RHEL-08-040200"
severity67="CAT I"
ruleid67="SV-230534r627750_rule"
vulnid67="V-230534"

title68a="RHEL 8 must prevent IPv6 Internet Control Message Protocol (ICMP) redirect messages from being accepted."
title68b="Checking with
           a. 'grub2-editenv - list | grep kernelopts'
           b. 'sysctl net.ipv6.conf.default.accept_redirects'
	   c. 'grep -r net.ipv6.conf.default.accept_redirects /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf'"
title68c="Expecting: ${YLO}net.ipv6.conf.default.accept_redirects = 0
           NOTE: a. If IPv6 is disabled on the system ('ipv6.disable=1' in kernelopts), this requirement is Not Applicable.
           NOTE: b. If the returned line does not have a value of \"0\", a line is not returned, or the line is commented out, this is a finding.
	   NOTE: c. If \"net.ipv6.conf.default.accept_redirects\" is not set to \"0\", is missing or commented out, this is a finding.
	   NOTE: c. If the configuration file does exist this is a finding."${BLD}
cci68="CCI-000366"
stigid68="RHEL-08-040210"
severity68="CAT II"
ruleid68="SV-230535r792936_rule"
vulnid68="V-230535"

title69a="RHEL 8 must not send Internet Control Message Protocol (ICMP) redirects."
title69b="Checking with
           a. 'sysctl net.ipv4.conf.all.send_redirects'
           b. 'grep -r net.ipv4.conf.all.send_redirects /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf'"
title69c="Expecting: ${YLO}net.ipv4.conf.all.send_redirects = 0
           NOTE: a. If the returned line does not have a value of \"0\", a line is not returned, or the line is commented out, this is a finding.
           NOTE: b. If \"net.ipv4.conf.all.send_redirects\" is not set to \"0\", is missing or commented out, this is a finding.
           NOTE: b. If the configuration file does exist this is a finding."${BLD}
cci69="CCI-000366"
stigid69="RHEL-08-040220"
severity69="CAT II"
ruleid69="SV-230536r792939_rule"
vulnid69="V-230536"

title70a="RHEL 8 must not respond to Internet Control Message Protocol (ICMP) echoes sent to a broadcast address."
title70b="Checking with:
           a. 'sysctl net.ipv4.icmp_echo_ignore_broadcasts'
	   b. 'grep -r net.ipv4.icmp_echo_ignore_broadcasts /etc/sysctl.d/*.conf."
title70c="Expecting: ${YLO}net.ipv4.icmp_echo_ignore_broadcasts = 1${BLD}
	   NOTE: ${YLO}a. If the returned line does not have a value of \"1\", a line is not returned, or the retuned line is commented out, this is a finding.${BLD}
           NOTE: ${YLO}b. If \"net.ipv4.icmp_echo_ignore_broadcasts\" is not set to \"1\", is missing or commented out, this is a finding."${BLD}
cci70="CCI-000366"
stigid70="RHEL-08-040230"
severity70="CAT II"
ruleid70="SV-230537r792942_rule"
vulnid70="V-230537"

title71a=" RHEL 8 must not forward IPv6 source-routed packets."
title71b="Checking with:
           a. 'grub2-editenv - list | grep kernelopts'
           b. 'sysctl net.ipv6.conf.all.accept_source_route'
	   c. 'grep -r net.ipv6.conf.all.accept_source_route /etc/sysctl.d/*.conf'"
title71c="Expecting: ${YLO}net.ipv6.conf.all.accept_source_route = 0${BLD}
           NOTE: ${YLO}a. If IPv6 is disabled on the system (ipv6.disable=1 in kernelopts), this requirement is Not Applicable.${BLD}
	   NOTE: ${YLO}b. If the returned line does not have a value of \"0\", a line is not returned, or the line is commented out, this is a finding.${BLD}
	   NOTE: ${YLO}c. If \"net.ipv6.conf.all.accept_source_route\" is not set to \"0\", is missing or commented out, this is a finding."${BLD}
cci71="CCI-000366"
stigid71="RHEL-08-040240"
severity71="CAT II"
ruleid71="SV-230538r792945_rule"
vulnid71="V-230538"

title72a="RHEL 8 must not forward IPv6 source-routed packets by default."
title72b="Checking with:
           a. 'grub2-editenv - list | grep kernelopts'
           b. 'sysctl net.ipv6.conf.default.accept_source_route'
	   c. 'grep -r net.ipv6.conf.default.accept_source_route /etc/sysctl.d/*.conf."
title72c="Expecting: ${YLO}net.ipv6.conf.default.accept_source_route = 0${BLD}
           NOTE: ${YLO}a. If IPv6 is disabled on the system (ipv6.disabled=1 in kernelopts), this requirement is Not Applicable.${BLD}
	   NOTE: ${YLO}b. If the returned line does not have a value of \"0\", a line is not returned, or the line is commented out, this is a finding.${BLD}
	   NOTE: ${YLO}c. If \"net.ipv6.conf.default.accept_source_route\" is not set to \"0\", is missing or commented out, this is a finding."${BLD}
cci72="CCI-000366"
stigid72="RHEL-08-040250"
severity72="CAT II"
ruleid72="SV-230539r792948_rule"
vulnid72="V-230539"

title73a="RHEL 8 must not enable IPv6 packet forwarding unless the system is a router."
title73b="Checking with:
           a. 'grub2-editenv - list | grep kernelopts'
           b. 'sysctl net.ipv6.conf.all.forwarding'
	   c. 'grep -r net.ipv6.conf.all.forwarding /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf'"
title73c="Expecting: net.ipv6.conf.all.forwarding = 0
           NOTE: ${YLO}a. If IPv6 is disabled on the system, this requirement is Not Applicable.${BLD}
	   NOTE: ${YLO}b. If the IPv6 forwarding value is not \"0\" and is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.${BLD}
	   NOTE: ${YLO}c. If \"net.ipv6.conf.all.forwarding\" is not set to \"0\", is missing or commented out, this is a finding."${BLD}
cci73="CCI-000366"
stigid73="RHEL-08-040260"
severity73="CAT II"
ruleid73="SV-230540r792951_rule"
vulnid73="V-230540"

title74a="RHEL 8 must not accept router advertisements on all IPv6 interfaces."
title74b="Checking with:
           a. 'grub2-editenv - list | grep kernelopts'
           b. 'sysctl net.ipv6.conf.all.accept_ra'
	   c. 'grep -r net.ipv6.conf.all.accept_ra /etc/sysctl.d/*.conf'"
title74c="Expecting: ${YLO}net.ipv6.conf.all.accept_ra = 0${BLD}
           NOTE: ${YLO}a. If IPv6 is disabled on the system, this requirement is Not Applicable.${BLD}
	   NOTE: ${YLO}b. If the \"accept_ra\" value is not "0" and is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.${BLD}
	   NOTE: ${YLO}c. If \"net.ipv6.conf.all.accept_ra\" is not set to \"0\", is missing or commented out, this is a finding.${BLD}
	   NOTE: ${YLO}c. If the configuration file does not begin with \"99-\", this is a finding."${BLD}
cci74="CCI-000366"
stigid74="RHEL-08-040261"
severity74="CAT II"
ruleid74="SV-230541r792954_rule"
vulnid74="V-230541"

title75a="RHEL 8 must not accept router advertisements on all IPv6 interfaces by default."
title75b="Checking with:
           a. 'grub2-editenv - list | grep kernelopts'
           b. 'sysctl net.ipv6.conf.default.accept_ra'
	   c. 'grep -r net.ipv6.conf.default.accept_ra /etc/sysctl.d/*.conf'"
title75c="Expecting: ${YLO}net.ipv6.conf.default.accept_ra = 0${BLD}
           NOTE: ${YLO}a. If IPv6 is disabled on the system, this requirement is Not Applicable.${BLD}
           NOTE: ${YLO}b. If the \"accept_ra\" value is not "0" and is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.${BLD}
           NOTE: ${YLO}c. If \"net.ipv6.conf.default.accept_ra\" is not set to \"0\", is missing or commented out, this is a finding."${BLD}
cci75="CCI-000366"
stigid75="RHEL-08-040262"
severity75="CAT II"
ruleid75="SV-230542r792957_rule"
vulnid75="V-230542"

title76a="RHEL 8 must not allow interfaces to perform Internet Control Message Protocol (ICMP) redirects by default."
title76b="Checking with:
           a. 'sysctl net.ipv4.conf.default.send_redirects'
	   b. 'grep -r net.ipv4.conf.default.send_redirects /etc/sysctl.d/*.conf'"
title76c="Expecting: ${YLO}net.ipv4.conf.default.send_redirects=0${BLD}
           NOTE: ${YLO}a. If the returned line does not have a value of "0" or a line is not returned, this is a finding.${BLD}
           NOTE: ${YLO}b. If \"net.ipv4.conf.default.send_redirects\" is not set to \"0\", is missing or commented out, this is a finding."${BLD}
cci76="CCI-000366"
stigid76="RHEL-08-040270"
severity76="CAT II"
ruleid76="SV-230543r792960_rule"
vulnid76="V-230543"

title77a="RHEL 8 must ignore IPv6 Internet Control Message Protocol (ICMP) redirect messages."
title77b="Checking with:
           a. 'grub2-editenv - list | grep kernelopts'
	   b. 'sysctl net.ipv6.conf.all.accept_redirects'
	   c. 'grep -r net.ipv6.conf.all.accept_redirects /etc/sysctl.d/*.conf'"
title77c="Expecting: ${YLO}net.ipv6.conf.all.accept_redirects = 0${BLD}
           NOTE: ${YLO}a. If IPv6 is disabled on the system (ipv6.disable=1), this requirement is Not Applicable.${BLD}
           NOTE: ${YLO}b. If the returned line does not have a value of "0", a line is not returned, or the line is commented out, this is a finding.${BLD}
           NOTE: ${YLO}c. If \"net.ipv6.conf.all.accept_redirects\" is not set to \"0\", is missing or commented out, this is a finding."${BLD}
cci77="CCI-000366"
stigid77="RHEL-08-040280"
severity77="CAT II"
ruleid77="SV-230544r792963_rule"
vulnid77="V-230544"

title78a="RHEL 8 must disable access to network bpf syscall from unprivileged processes."
title78b="Checking with:
           a. 'sysctl kernel.unprivileged_bpf_disabled'
	   b. 'grep -r kernel.unprivileged_bpf_disabled /etc/sysctl.d/*.conf'."
title78c="Expecting: ${YLO}kernel.unprivileged_bpf_disabled = 1${BLD}
                     ${YLO}/etc/sysctl.d/99-sysctl.conf: kernel.unprivileged_bpf_disabled = 1${BLD}
           NOTE: ${YLO}a. If the returned line does not have a value of \"1\", or a line is not returned, this is a finding.${BLD}
	   NOTE: ${YLO}b. If \"kernel.unprivileged_bpf_disabled\" is not set to \"1\", is missing or commented out, this is a finding."${BLD}
cci78="CCI-000366"
stigid78="RHEL-08-040281"
severity78="CAT II"
ruleid78="SV-230545r792966_rule"
vulnid78="V-230545"

title79a="RHEL 8 must restrict usage of ptrace to descendant processes."
title79b="Checking with:
           a. 'sysctl kernel.yama.ptrace_scope'
	   b. 'grep -r kernel.yama.ptrace_scope /etc/sysctl.d/*.conf'"
title79c="Expecting:
           ${YLO}a. 'kernel.yama.ptrace_scope = 1${BLD}
	   ${YLO}b. '/etc/sysctl.d/99-sysctl.conf: kernel.yama.ptrace_scope = 1${BLD}
	   NOTE: ${YLO}a. If the returned line does not have a value of \"1\", or a line is not returned, this is a finding.${BLD}
	   NOTE: ${YLO}b. If \"kernel.yama.ptrace_scope\" is not set to \"1\", is missing or commented out, this is a finding.${BLD}
	   NOTE: ${YLO}b. If the configuration file does not begin with \"99-\", this is a finding."${BLD}
cci79="CCI-000366"
stigid79="RHEL-08-040282"
severity79="CAT II"
ruleid79="SV-230546r792969_rule"
vulnid79="V-230546"

title80a="RHEL 8 must restrict exposed kernel pointer addresses access."
title80b="Checking with:
           a. 'sysctl kernel.kptr_restrict'
	   b. 'grep -r kernel.kptr_restrict /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf'"
title80c="Expecting:${YLO}
           a. 'kernel.kptr_restrict = 1
	   b. '/etc/sysctl.d/99-sysctl.conf: kernel.kptr_restrict = 1
	   NOTE: a. If the returned line does not have a value of \"1\", or a line is not returned, this is a finding.
	   NOTE: b. If \"kernel.kptr_restrict\" is not set to \"1\", is missing or commented out, this is a finding."${BLD}
cci80="CCI-000366"
stigid80="RHEL-08-040283"
severity80="CAT II"
ruleid80="SV-230547r792972_rule"
vulnid80="V-230547"

title81a="RHEL 8 must disable the use of user namespaces."
title81b="Checking with:
           a. 'sysctl user.max_user_namespaces'
	   b. 'grep -r user.max_user_namespaces /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf'"
title81c="Expecting:${YLO}
           a. 'user.max_user_namespaces = 0
	   b. '/etc/sysctl.d/99-sysctl.conf: user.max_user_namespaces = 0
	   NOTE: a. If the returned line does not have a value of \"0\", or a line is not returned, this is a finding.
	   NOTE: b. If \"user.max_user_namespaces\" is not set to \"0\", is missing or commented out, this is a finding."${BLD}
cci81="CCI-000366"
stigid81="RHEL-08-040284"
severity81="CAT II"
ruleid81="SV-230548r792975_rule"
vulnid81="V-230548"

title82a="RHEL 8 must use reverse path filtering on all IPv4 interfaces."
title82b="Checking with:
           a. 'sysctl net.ipv4.conf.all.rp_filter'
	   b. 'grep -r net.ipv4.conf.all.rp_filter /etc/sysctl.d/*.conf'"
title82c="Expecting:${YLO}
           a. 'net.ipv4.conf.all.rp_filter = 1
	   b. '/etc/sysctl.d/99-sysctl.conf: net.ipv4.conf.all.rp_filter = 1
	   NOTE: a. If the returned line does not have a value of \"1\", or a line is not returned, this is a finding.
	   NOTE: b. If \"net.ipv4.conf.all.rp_filter\" is not set to \"1\", is missing or commented out, this is a finding."${BLD}
cci82="CCI-000366"
stigid82="RHEL-08-040285"
severity82="CAT II"
ruleid82="SV-230549r792978_rule"
vulnid82="V-230549"

title83a="RHEL 8 must be configured to prevent unrestricted mail relaying."
title83b="Checking with:
           a. 'yum list installed postfix'
	   b. 'postconf -n smtpd_client_restrictions'"
title83c="Expecting: ${YLO}Nothing returned${BLD}
           Note: ${YLO}If postfix is not installed, this is Not Applicable.${BLD}
	   Note: ${YLO}If the \"smtpd_client_restrictions\" parameter contains any entries other than \"permit_mynetworks\" and \"reject\", this is a finding."${BLD}
cci83="CCI-000366"
stigid83="RHEL-08-040290"
severity83="CAT II"
ruleid83="SV-230550r627750_rule"
vulnid83="V-230550"

title84a="The RHEL 8 file integrity tool must be configured to verify extended attributes."
title84b="Checking with:
           a. 'yum list installed aide'
	   b. 'find / -name aide.conf'
	   c. 'egrep \"[+]?xattrs\" /etc/aide.conf'"
title84c="Expecting: 
           ${YLO}All= p+i+n+u+g+s+m+S+sha512+acl+xattrs+selinux
           /bin All # apply the custom rule to the files in bin 
           /sbin All # apply the same custom rule to the files in sbin.${BLD}
           $YLO}NOTE: If the \"xattrs\" rule is not being used on all uncommented selection lines in the \"/etc/aide.conf\" file, or extended attributes are not being checked by another file integrity tool, this is a finding."${BLD}
cci84="CCI-000366"
stigid84="RHEL-08-040300"
severity84="CAT III"
ruleid84="SV-230551r627750_rule"
vulnid84="V-230551"

title85a="The RHEL 8 file integrity tool must be configured to verify Access Control Lists (ACLs)."
title85b="Checking with:
           a. 'yum list installed aide'
           b. 'find / -name aide.conf' 
	   c. 'egrep \"[+]?acl\" /etc/aide.conf"
title85c="Expecting:${YLO}
           a. aide.x86_64 0.16-14.el8 @AppStream
              (or another file integrity tool is installed and configured)
	   b. /etc/aide.conf
	   c. VarFile = OwnerMode+n+l+X+acl
	      (all rules that list the \"+acl\" rule or alias)
           NOTE: If the \"acl\" rule is not being used on all uncommented selection lines in the \"/etc/aide.conf\" file, or ACLs are not being checked by another file integrity tool, this is a finding."${BLD}
cci85="CCI-000366"
stigid85="RHEL-08-040310"
severity85="CAT III"
ruleid85="SV-230552r627750_rule"
vulnid85="V-230552"

title86a="The graphical display manager must not be installed on RHEL 8 unless approved."
title86b="Checking with:
           a. 'systemctl get-default'
	   b. 'rpm -qa | grep xorg | grep server'."
title86c="Expecting:
           a. ${YLO}multi-user.target${BLD}
	   b. ${YLO}xorg-x11-server-common is not installed${BLD}
	   NOTE: ${YLO}If the system default target is not set to \"multi-user.target\" and the Information System Security Officer (ISSO) lacks a documented requirement for a graphical user interface, this is a finding.${BLD}
	   NOTE: ${YLO}If the use of a graphical user interface on the system is not documented with the ISSO, this is a finding."${BLD}
cci86="CCI-000366"
stigid86="RHEL-08-040320"
severity86="CAT II"
ruleid86="SV-230553r646886_rule"
vulnid86="V-230553"

title87a="RHEL 8 network interfaces must not be in promiscuous mode."
title87b="Checking with 'ip link | grep -i promisc'."
title87c="Expecting: ${YLO}Nothing returned${BLD}
           NOTE: ${YLO}If network interfaces are found on the system in promiscuous mode and their use has not been approved by the ISSO and documented, this is a finding."${BLD}
cci87="CCI-000366"
stigid87="RHEL-08-040330"
severity87="CAT II"
ruleid87="SV-230554r627750_rule"
vulnid87="V-230554"

title88a="RHEL 8 remote X connections for interactive users must be disabled unless to fulfill documented and validated mission requirements."
title88b="Checking with 'grep -i x11forwarding /etc/ssh/sshd_config | grep -v '^#''."
title88c="Expecting: ${YLO}X11Forwarding no${BLD}
           NOTE: ${YLO}If the \"X11Forwarding\" keyword is set to \"yes\" and is not documented with the Information System Security Officer (ISSO) as an operational requirement or is missing, this is a finding."${BLD}
cci88="CCI-000366"
stigid88="RHEL-08-040340"
severity88="CAT II"
ruleid88="SV-230555r627750_rule"
vulnid88="V-230555"

title89a="The RHEL 8 SSH daemon must prevent remote hosts from connecting to the proxy display."
title89b="Checking with 'grep -i x11uselocalhost /etc/ssh/sshd_config'."
title89c="Expecting: ${YLO}X11UseLocalhost yes${BLD}
           NOTE: ${YLO}If the \"X11UseLocalhost\" keyword is set to \"no\", is missing, or is commented out, this is a finding."${BLD}
cci89="CCI-000366"
stigid89="RHEL-08-040341"
severity89="CAT II"
ruleid89="SV-230556r627750_rule"
vulnid89="V-230556"

title90a="If the Trivial File Transfer Protocol (TFTP) server is required, the RHEL 8 TFTP daemon must be configured to operate in secure mode."
title90b="Checking with:
           a. 'yum list installed | grep tftp-server'.
	   b. 'grep server_args /etc/xinetd.d/tftp'"
title90c="Expecting: ${YLO}Nothing returned - or running in secure mode.${BLD}
           NOTE: ${YLO}If a TFTP server is not installed, this is Not Applicable.${BLD}
           NOTE: ${YLO}If the \"server_args\" line does not have a \"-s\" option and a subdirectory is not assigned, this is a finding."${BLD}
cci90="CCI-000366"
stigid90="RHEL-08-040350"
severity90="CAT II"
ruleid90="SV-230557r627750_rule"
vulnid90="V-230557"

title91a="A File Transfer Protocol (FTP) server package must not be installed unless mission essential on RHEL 8."
title91b="Checking with 'yum list installed *ftpd*'."
title91c="Expecting: Nothing returned.
           NOTE: ${YLO}If an FTP server is installed and is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding."${BLD}
cci91="CCI-000366"
stigid91="RHEL-08-040360"
severity91="CAT I"
ruleid91="SV-230558r627750_rule"
vulnid91="V-230558"

title92a="The iprutils package must not be installed unless mission essential on RHEL 8."
title92b="Checking with 'yum list installed iprutils'."
title92c="Expecting: ${YLO}Nothing returned${BLD}
           NOTE: ${YLO}If the iprutils package is installed and is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding."${BLD}
cci92="CCI-000366"
stigid92="RHEL-08-040380"
severity92="CAT II"
ruleid92="SV-230560r627750_rule"
vulnid92="V-230560"

title93a="The tuned package must not be installed unless mission essential on RHEL 8."
title93b="Checking with 'yum list installed tuned'."
title93c="Expecting: ${YLO}Nothing returned${BLD}
           NOTE: ${YLO}If the tuned package is installed and is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding."${BLD}
cci93="CCI-000366"
stigid93="RHEL-08-040390"
severity93="CAT II"
ruleid93="SV-230561r627750_rule"
vulnid93="V-230561"

title94a="RHEL 8 must restrict privilege elevation to authorized personnel."
title94b="Checking with 'grep -iw 'ALL' /etc/sudoers /etc/sudoers.d/*'."
title94c="Expecting: ${YLO}If the either of the following entries are returned, this is a finding:
           ALL ALL=(ALL) ALL
	   ALL ALL=(ALL:ALL) ALL"${BLD}
cci94="CCI-000366"
stigid94="RHEL-08-010382"
severity94="CAT II"
ruleid94="SV-237641r646893_rule"
vulnid94="V-237641"

title95a="RHEL 8 must have the packages required to use the hardware random number generator entropy gatherer service."
title95b="Checking with 'yum list installed rng-tools'"
title95c="Expecting: ${YLO}rng-tools.x86_64 6.8-3.el8 @anaconda${BLD}
           NOTE: ${YLO}If the "rng-tools" package is not installed, this is a finding."${BLD}
cci95="CCI-000366"
stigid95="RHEL-08-010472"
severity95="CAT III"
ruleid95="SV-244527r743830_rule"
vulnid95="V-244527"

title96a="The RHEL 8 SSH daemon must not allow GSSAPI authentication, except to fulfill documented and validated mission requirements"
title96b="Checking with 'grep -i gssapiauthentication /etc/ssh/sshd_config'."
title96c="Expecting: ${YLO}GSSAPIAuthentication no${BLD}
           Note: ${YLO}If the value is returned as \"yes\", the returned line is commented out, no output is returned, or has not been documented with the ISSO, this is a finding."${BLD}
cci96="CCI-000366"
stigid96="RHEL-08-010522"
severity96="CAT II"
ruleid96="SV-244528r743833_rule"
vulnid96="V-244528"

title97a="RHEL 8 must use a separate file system for /var/tmp."
title97b="Checking with 'grep /var /etc/fstab'."
title97c="Expecting: ${YLO}A separage partition exists for /var/tmp.${BLD}
           NOTE: ${YLO}If a separate entry for \"/var/tmp\" is not in use, this is a finding."${BLD}
cci97="CCI-000366"
stigid97="RHEL-08-010544"
severity97="CAT II"
ruleid97="SV-244529r743836_rule"
vulnid97="V-244529"

title98a="RHEL 8 must prevent files with the setuid and setgid bit set from being executed on the /boot directory" 
title98b="Checking with 'mount | grep '\\s/boot/efi\\s''."
title98c="Expecting: /dev/sda1 on /boot type xfs (rw,${YLO}nosuid${BLD},relatime,seclabe,attr2,inode64,noquota).
           NOTE: ${YLO}If the /boot file system does not have the \"nosuid\" option set, this is a finding."${BLD}
cci98="CCI-000366"
stigid98="RHEL-08-010572"
severity98="CAT II"
ruleid98="SV-244530r743839_rule"
vulnid98="V-244530"

title99a="All RHEL 8 local interactive user home directory files must have mode 0750 or less permissive."
title99b="Checking with 'ls -lLR /home/smithj'."
title99c="Expecting: ${YLO}-rwxr-x---$ 1 smithj users 18 Mar 5 17:06 /home/smithj
           NOTE: Files that begin with a "." are excluded from this requirement.
           NOTE: If any files or directories are found with a mode more permissive than "0750", this is a finding."${BLD}
cci99="CCI-000366"
stigid99="RHEL-08-010731"
severity99="CAT II"
ruleid99="SV-244531r743842_rule"
vulnid99="V-244531"

title100a="RHEL 8 must be configured so that all files and directories contained in local interactive user home directories are group-owned by a group of which the home directory owner is a member."
title100b="Checking with:
           a. 'ls -lLR /<home directory>/<users home directory>/'
	   b. 'grep <user> /etc/group'"
title100c="Expecting:
           ${YLO}-rw-r--r-- 1 smithj smithj 18 Mar 5 17:06 file1
           -rw-r--r-- 1 smithj smithj 193 Mar 5 17:06 file2
           -rw-r--r-- 1 smithj sa 231 Mar 5 17:06 file3${BLD}
           NOTE: ${YLO}If any files or directories are group owned by a group that the directory owner is not a member of, this is a finding."${BLD}
cci100="CCI-000366"
stigid100="RHEL-08-010741"
severity100="CAT II"
ruleid100="SV-244532r743845_rule"
vulnid100="V-244532"

title101a="RHEL 8 must disable the user list at logon for graphical user interfaces."
title101b="Checking with 'gsettings get org.gnome.login-screen disable-user-list'."
title101c="Expecting: ${YLO}true${BLD}
           NOTE: ${YLO}If the setting is \"false\", this is a finding."${BLD}
cci101="CCI-000366"
stigid101="RHEL-08-020032"
severity101="CAT II"
ruleid101="SV-244536r743857_rule"
vulnid101="V-244536"

title102a="RHEL 8 must not allow blank or null passwords in the system-auth file."
title102b="Checking with 'grep nullok /etc/pam.d/system-auth'"
title102c="Expecting: ${YLO}\"no output\"${BLD}
	   ${YLO}NOTE: If output is produced, this is a finding."${BLD}
cci102="CCI-000366"
stigid102="RHEL-08-020331"
severity102="CAT I"
ruleid102="SV-244540r743869_rule"
vulnid102="V-244540"

title103a="RHEL 8 must not allow blank or null passwords in the system-auth file."
title103b="Checking with 'grep nullok /etc/pam.d/password-auth'"
title103c="Expecting: ${YLO}\"no output\"${BLD}
	   ${YLO}NOTE: If output is produced, this is a finding."${BLD}
cci103="CCI-000366"
stigid103="RHEL-08-020332"
severity103="CAT I"
ruleid103="SV-244541r743872_rule"
vulnid103="V-244541"

title104a="RHEL 8 must prevent IPv4 Internet Control Message Protocol (ICMP) redirect messages from being accepted."
title104b="Checking with:
           a. 'grub2-editenv - list | grep kernelopts'
           b. 'sysctl net.ipv4.conf.default.accept_redirects'
	   c. 'grep -r net.ipv4.conf.default.accept_redirects /etc/sysctl.d/*.conf."
title104c="Expecting: ${YLO}net.ipv4.icmp_echo_ignore_broadcasts = 1${BLD}
           NOTE: ${YLO}a. If IPv4 is disabled on the system ('ipv4.disable=1' in kernelopts), this requirement is Not Applicable.${BLD}
	   NOTE: ${YLO}b. If the returned line does not have a value of \"0\", a line is not returned, or the retuned line is commented out, this is a finding.${BLD}
           NOTE: ${YLO}c. If \"net.ipv4.conf.default.accept_redirects\" is not set to \"0\", is missing or commented out, this is a finding.${BLD}
	   NOTE: ${YLO}c. If the configuration file does not begin with \"99-\", this is a finding."${BLD}
cci104="CCI-000366"
stigid104="RHEL-08-040209"
severity104="CAT II"
ruleid104="SV-244550r792987_rule"
vulnid104="V-244550"

title105a=" RHEL 8 must not forward IPv4 source-routed packets."
title105b="Checking with:
           a. 'grub2-editenv - list | grep kernelopts'
           b. 'sysctl net.ipv4.conf.all.accept_source_route'
	   c. 'grep -r net.ipv4.conf.all.accept_source_route /etc/sysctl.d/*.conf'"
title105c="Expecting: ${YLO}net.ipv4.conf.all.accept_source_route = 0${BLD}
           NOTE: ${YLO}a. If IPv4 is disabled on the system (ipv4.disable=1 in kernelopts), this requirement is Not Applicable.${BLD}
	   NOTE: ${YLO}b. If the returned line does not have a value of \"0\", a line is not returned, or the line is commented out, this is a finding.${BLD}
	   NOTE: ${YLO}c. If \"net.ipv4.conf.all.accept_source_route\" is not set to \"0\", is missing or commented out, this is a finding.${BLD}
	   NOTE: ${YLO}c. If the configuration file does not begin with \"99-\", this is a finding."${BLD}
cci105="CCI-000366"
stigid105="RHEL-08-040239"
severity105="CAT II"
ruleid105="SV-244551r792990_rule"
vulnid105="V-244551"

title106a="RHEL 8 must not forward IPv4 source-routed packets by default."
title106b="Checking with:
           a. 'grub2-editenv - list | grep kernelopts'
           b. 'sysctl net.ipv4.conf.default.accept_source_route'
	   c. 'grep -r net.ipv4.conf.default.accept_source_route /etc/sysctl.d/*.conf'"
title106c="Expecting: ${YLO}net.ipv4.conf.default.accept_source_route = 0${BLD}
           NOTE: ${YLO}a. If IPv4 is disabled on the system (ipv4.disable=1 in kernelopts), this requirement is Not Applicable.${BLD}
	   NOTE: ${YLO}b. If the returned line does not have a value of \"0\", a line is not returned, or the line is commented out, this is a finding.${BLD}
	   NOTE: ${YLO}c. If \"net.ipv4.conf.default.accept_source_route\" is not set to \"0\", is missing or commented out, this is a finding.${BLD}
	   NOTE: ${YLO}c. If the configuration file does not begin with \"99-\", this is a finding."${BLD}
cci106="CCI-000366"
stigid106="RHEL-08-040249"
severity106="CAT II"
ruleid106="SV-244552r792993_rule"
vulnid106="V-244552"

title107a="RHEL 8 must ignore IPv4 Internet Control Message Protocol (ICMP) redirect messages."
title107b="Checking with:
           a. 'grub2-editenv - list | grep kernelopts'
           b. 'sysctl net.ipv4.conf.all.accept_redirects'
	   c. 'grep -r net.ipv4.conf.all.accept_redirects /etc/sysctl.d/*.conf'"
title107c="Expecting: ${YLO}net.ipv4.conf.all.accept_redirects = 0${BLD}
           NOTE: ${YLO}a. If IPv4 is disabled on the system (ipv4.disable=1 in kernelopts), this requirement is Not Applicable.${BLD}
	   NOTE: ${YLO}b. If the returned line does not have a value of \"0\", a line is not returned, or the line is commented out, this is a finding.${BLD}
	   NOTE: ${YLO}c. If \"net.ipv4.conf.all.accept_redirects\" is not set to \"0\", is missing or commented out, this is a finding.${BLD}
	   NOTE: ${YLO}c. If the configuration file does not begin with \"99-\", this is a finding."${BLD}
cci107="CCI-000366"
stigid107="RHEL-08-040279"
severity107="CAT II"
ruleid107="SV-244553r792996_rule"
vulnid107="V-244553"

title108a="RHEL 8 must enable hardening for the Berkeley Packet Filter Just-in-time compiler."
title108b="Checking with:
           a. 'sysctl net.core.bpf_jit_harden'
	   b. 'grep -r net.core.bpf_jit_harden /etc/sysctl.d/*.conf'"
title108c="Expecting:
           ${YLO}a. 'net.core.bpf_jit_harden = 2${BLD}
	   ${YLO}b. '/etc/sysctl.d/99-sysctl.conf: net.core.bpf_jit_harden = 2${BLD}
	   NOTE: ${YLO}a. If the returned line does not have a value of \"2\", or a line is not returned, this is a finding.${BLD}
	   NOTE: ${YLO}b. If \"net.core.bpf_jit_harden\" is not set to \"2\", is missing or commented out, this is a finding.${BLD}
	   NOTE: ${YLO}b. If the configuration file does not begin with \"99-\", this is a finding."${BLD}
cci108="CCI-000366"
stigid108="RHEL-08-040286"
severity108="CAT II"
ruleid108="SV-244554r792999_rule"
vulnid108="V-244554"

title109a="RHEL 8 must not enable IPv4 packet forwarding unless the system is a router."
title109b="Checking with:
            a. 'grub2-editenv - list | grep kernelopts'
            b. 'sysctl net.ipv4.ip_forward'
            c. 'grep -r net.ipv4.conf.all.forwarding /etc/sysctl.d/*.conf'"
title109c="Expecting: ${YLO}net.ipv4.ip_forward = 0${BLD}
           NOTE: ${YLO}a. If IPv4 is disabled on the system (ipv4.disable=1 in kernelopts), this requirement is Not Applicable.${BLD}
           NOTE: ${YLO}b. If the IPv4 forwarding value is not \"0\" and is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.${BLD}
           NOTE: ${YLO}c. If \"net.ipv4.conf.all.forwarding\" is not set to \"0\", is missing or commented out, this is a finding.${BLD}
           NOTE: ${YLO}c. If the configuration file does not begin with \"99-\", this is a finding."${BLD}
cci109="CCI-000366"
stigid109="RHEL-08-040259"
severity109="CAT II"
ruleid109="SV-250317r793008_rule"
vulnid109="V-250317"

title110a="The RHEL 8 operating system must not have accounts configured with blank or null passwords."
title110b="Checking with: awk -F: '!$2 {print $1}' /etc/shadow"
title110c="Expecting: ${YLO}Nothing returned${BLD}
           NOTE: ${YLO}If the command returns any results, this is a finding.${BLD}"
cci110="CCI-000366"
stigid110="RHEL-08-010121"
severity110="CAT I"
ruleid110="SV-251706r809342_rule"
vulnid110="V-251706"

title111a="RHEL 8 must specify the default \"include\" directory for the /etc/sudoers file."
title111b="Checking with: 
           a. grep include /etc/sudoers
	   b. grep include /etc/sudoers.d/*"
title111c="Expecting:
           a. ${YLO}#includedir /etc/sudoers.d${BLD}
	   b. ${YLO}Nothing returned${BLD}
           NOTE: a. ${YLO}If the results are not \"/etc/sudoers.d\" or additional files or directories are specified, this is a finding.${BLD}
	   NOTE: b. ${YLO}If results are returned, this is a finding.${BLD}"
cci111="CCI-000366"
stigid111="RHEL-08-010379"
severity111="CAT II"
ruleid111="SV-251711r810015_rule"
vulnid111="V-251711"

title112a="RHEL 8 must ensure the password complexity module is enabled in the system-auth file."
title112b="Checking with: cat /etc/pam.d/system-auth | grep pam_pwquality"
title112c="Expecting: ${YLO}password required pam_pwquality.so${BLD}
           NOTE: ${YLO}If the command does not return a line containing the value \"pam_pwquality.so\", or the line is commented out, this is a finding."${BLD}
cci112="CCI-000366"
stigid112="RHEL-08-020101"
severity112="CAT II"
ruleid112="SV-251713r810407_rule"
vulnid112="V-251713"

title113a="RHEL 8 systems below version 8.4 must ensure the password complexity module in the system-auth file is configured for three retries or less."
title113b="Checking with: cat /etc/pam.d/system-auth | grep pam_pwquality"
title113c="Expecting: ${YLO}password required pam_pwquality.so retry=3${BLD}
           NOTE: ${YLO}If the value of \"retry\" is set to \"0\" or greater than \"3\", this is a finding.${BLD}
	   NOTE: ${YLO}This requirement applies to RHEL versions 8.0 through 8.3. If the system is RHEL version 8.4 or newer, this requirement is not applicable."${BLD}
cci113="CCI-000366"
stigid113="RHEL-08-020102"
severity113="CAT II"
ruleid113="SV-251714r810410_rule"
vulnid113="V-251714"

title114a="RHEL 8 systems below version 8.4 must ensure the password complexity module in the password-auth file is configured for three retries or less."
title114b="Checking with: cat /etc/pam.d/password-auth | grep pam_pwquality"
title114c="Expecting: ${YLO}password required pam_pwquality.so retry=3${BLD}
           NOTE: ${YLO}If the value of \"retry\" is set to \"0\" or greater than \"3\", this is a finding.${BLD}
           NOTE: ${YLO}This requirement applies to RHEL versions 8.0 through 8.3. If the system is RHEL version 8.4 or newer, this requirement is not applicable."${BLD}
cci114="CCI-000366"
stigid114="RHEL-08-020103"
severity114="CAT II"
ruleid114="SV-251715r810412_rule"
vulnid114="V-251715"

title115a="RHEL 8 systems, version 8.4 and above, must ensure the password complexity module is configured for three retries or less."
title115b="Checking with: grep retry /etc/security/pwquality.conf"
title115c="Expecting: ${YLO}retry = 3${BLD}
           NOTE: ${YLO}If the value of \"retry\" is set to \"0\" or greater than \"3\", is commented out or missing, this is a finding.${BLD}
	   NOTE: ${YLO}This requirement applies to RHEL versions 8.4 or newer. If the system is RHEL below version 8.4, this requirement is not applicable."${BLD}
cci115="CCI-000366"
stigid115="RHEL-08-020104"
severity115="CAT II"
ruleid115="SV-251716r809372_rule"
vulnid115="V-251716"

title116a="The graphical display manager must not be the default target on RHEL 8 unless approved."
title116b="Checking with: systemctl get-default"
title116c="Expecting: ${YLO}multi-user.target${BLD}
           NOTE: ${YLO}If the system default target is not set to \"multi-user.target\" and the Information System Security Officer (ISSO) lacks a documented requirement for a graphical user interface, this is a finding."${BLD}
cci116="CCI-000366"
stigid116="RHEL-08-040321"
severity116="CAT II"
ruleid116="SV-251718r809378_rule"
vulnid116="V-251718"

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid1${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid1${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid1${NORMAL}"
echo -e "${NORMAL}CCI:       $cci1${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 1:    ${BLD}$title1a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title1b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title1c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity1${NORMAL}"

file1="/etc/redhat-release"
fail=0

year="$(date "+%Y")"
month="$(date "+%m")"

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file1 ]]
then

   osmake="$(echo $os | awk '{print $1}')"

   case $osmake in
      'Red')
          release="$(echo $os | awk '{print $6}')"
          ;;
      'CentOS')
          release="$(echo $os | awk '{print $4}')"
          ;;
   esac

   major="$(echo $release | awk -F. '{print $1}')"
   minor="$(echo $release | awk -F. '{print $2}')"

   case $major.$minor in
     8.1)
	if [[ $year > 2021 ||
	    ( $year == 2021 && $month > 11 )
	   ]]
	then
          fail=1
	fi
	;;
     8.2)
        if [[ $year > 2022 ||
            ( $year == 2022 && $month > 4 )
           ]]
        then
          fail=1
        fi
        ;;
     8.4)
        if [[ $year > 2023 ||
            ( $year == 2023 && $month > 5 )
           ]]
        then
          fail=1
        fi
        ;;
     8.5)
        if [[ $year > 2022 ||
            ( $year == 2022 && $month > 5 )
           ]]
        then
          fail=1
        fi
        ;;
     8.6)
	if [[ $year > 2024 ||
	    ( $year == 2024 && $month > 5 )
	   ]]
	then
	  fail=1
	fi
	;;
     8.7)
        if [[ $year > 2023 ||
            ( $year == 2023 && $month > 5 )
           ]]
        then
          fail=1
        fi
        ;;
     8.8)
        if [[ $year > 2025 ||
            ( $year == 2025 && $month > 5 )
           ]]
        then
          fail=1
        fi
        ;;
     8.9)
        if [[ $year > 2024 ||
            ( $year == 2024 && $month > 5 )
           ]]
        then
          fail=1
        fi
        ;;
     8.10)
        if [[ $year > 2029 ||
            ( $year == 2029 && $month > 5 )
           ]]
        then
          fail=1
        fi
        ;;
      *)
	fail=2
   esac

   if [[ $fail == 0 ]]
   then
      echo -e "${NORMAL}RESULT:    ${BLD}$os${NORMAL}"
      fail=0
   else
      echo -e "${NORMAL}RESULT:    ${RED}$os${NORMAL}"
   fi

   if [[ $fail == 0 ]]
   then
      echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, The operating system is a vendor supported release.${NORMAL}"
   elif [[ $fail == 2 ]]
   then
     echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${CYN}VERIFY, Unable to determine if the vendor supports the release.${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, The operating system is not a vendor supported release.${NORMAL}"
   fi
else
    echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, Vendor Supported OS: $file1 not found${NORMAL}"
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
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 2:    ${BLD}$title2a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title2b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title2c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity2${NORMAL}"

IFS=' '

yumhistory="$(yum history list)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $yumhistory ]]
then
  echo -e "${NORMAL}RESULT: ${BLD}$yumhistory${NORMAL}"
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${CYN}VERIFY, Verify the operating system security patches and updates are applied at a frequency determined by the site or Program Management Office (PMO). ${NORMAL}"
else
  echo -e "${NORMAL}RESULT: ${RED}No history of security updates and patches found.${NORMAL}"
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, Operating system security patches and updates could not be verified.${NORMAL}"
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
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 3:    ${BLD}$title3a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title3b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title3c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity3${NORMAL}"

IFS='
'

file3='/etc/sysconfig/sshd'
fail=0

entropystr="$(grep -i ^ssh_use_strong_rng $file3)"
entropyval="$(echo $entropystr | awk -F '=' '{print $2}')"

datetime="$(date +%FT%H:%M:%S)"

if [[ $entropystr ]]
then
  if [[ $entropyval != 32 ]]
  then
    fail=1
    echo -e "${NORMAL}RESULT:    ${RED}$entropystr${NORMAL}"
    echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${RED}FAILED, The $os operating system SSH server is not configued to use strong entropy.${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${BLD}$entropystr${NORMAL}"
    echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${GRN}PASSED, The $os operating system SSH server is configued to use strong entropy.${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}nothing found${NORMAL}"
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${RED}FAILED, Failed to find a value for ssh_use_strong_rng.${NORMAL}"
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
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 4:    ${BLD}$title4a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title4b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title4c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity4${NORMAL}"

IFS='
'

shostsequiv="$(find / -path /run/user -prune -o -name 'shosts.equiv' | grep -v /run/user 2>/dev/null)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $shostsequiv ]]
then
   for file in ${shostsequiv[@]}
   do
      echo -e "${NORMAL}RESULT:    ${RED}$file${NORMAL}"
   done
   echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${RED}FAILED, Host-based authentication files (shosts.equiv) found${NORMAL}"
else
   echo -e "${NORMAL}RESULT:    ${BLD}No Host-based authentication files (shosts.equiv) found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${GRN}PASSED, No host-based authentication files (shosts.equiv) found${NORMAL}"
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
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 5:    ${BLD}$title5a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title5b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title5c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity5${NORMAL}"

IFS='
'

shosts="$(find / -path /run/user -prune -o -name '*.shosts' | grep -v /run/user 2>/dev/null)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $shosts ]]
then
   for file in ${shosts[@]}
   do
      echo -e "${NORMAL}RESULT:    ${RED}$file${NORMAL}"
   done
   echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${RED}FAILED, Host-based authentication files (*.shosts) found${NORMAL}"
else
   echo -e "${NORMAL}RESULT:    ${BLD}No Host-based authentication files (*.shosts) found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${GRN}PASSED, No host-based authentication files (*.shosts) found${NORMAL}"
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
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 6:    ${BLD}$title6a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title6b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title6c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity6${NORMAL}"

IFS='
'

fail=0

# supressing error messages from the console output
isenabled="$(systemctl is-enabled rngd 2>/dev/null)"
isactive="$(systemctl is-active rngd 2>/dev/null)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $isenabled == 'enabled' ]]
then
  if [[ $isactive == 'active' ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$isenabled : $isactive${NORMAL}"
    echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${GRN}PASSED, The hardware random number generator entropy gatherer service is $isenabled and $isactive.${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$isenabled : $isactive${NORMAL}"
    echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${RED}FAILED, The hardware random number generator entropy gatherer service is $isenabled, but $isactive.${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}(not found) : $isactive${NORMAL}"
  echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${RED}FAILED, The hardware random number generator entropy gatherer service is $isactive.${NORMAL}"
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
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 7:    ${BLD}$title7a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title7b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title7c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity7${NORMAL}"

IFS='
'

fail=0

file7="/etc/ssh/*.pub"

pubkey="$(ls -l $file7)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $pubkey ]]
then
  for line in ${pubkey[@]}
 do
    file="$(echo $line | awk '{print $9}')"
    mode="$(stat -c %a $file)"
    if  (( ${mode:0:1} <= 6 &&
	   ${mode:1:1} <= 4 &&
	   ${mode:2:1} <= 4 
	))
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$line (mode: $mode)${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$line (mode: $mode)${NORMAL}"
      fail=1
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}No SSH public host key files found${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${GRN}PASSED, The RHEL 8 SSH public host key files are mode 0644 or are less permissive.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${RED}FAILED, The RHEL 8 SSH public host key files are not mode 0644 or less permissive.${NORMAL}"
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
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 8:    ${BLD}$title8a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title8b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title8c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity8${NORMAL}"

IFS='
'

fail=0

file8="/etc/ssh/ssh_host*key"

prikey="$(ls -l $file8)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $prikey ]]
then
  for line in ${prikey[@]}
 do
    file="$(echo $line | awk '{print $9}')"
    mode="$(stat -c %a $file)"
    if  (( ${mode:0:1} <= 6 &&
           ${mode:1:1} <= 4 &&
           ${mode:2:1} == 0
        ))
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$line (mode: $mode)${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$line (mode: $mode)${NORMAL}"
      fail=1
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}No SSH public host key files found${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cci8, $datetime, ${GRN}PASSED, The RHEL 8 SSH public host key files are mode 0640 or are less permissive.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cci8, $datetime, ${RED}FAILED, The RHEL 8 SSH public host key files are not mode 0640 or less permissive.${NORMAL}"
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
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 9:    ${BLD}$title9a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title9b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title9c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity9${NORMAL}"

IFS='
'

fail=1

file9="/etc/ssh/sshd_config"

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file9 ]]
then
  smodes="$(grep -i strictmodes $file9)"
  if [[ $smodes != '' ]]
  then
    for line in ${smodes[@]}
    do
      isstrict="$(echo $line | awk '{print $2}')"
      if [[ $isstrict == 'yes' && ${line:0:1} != '#' ]]
      then
        echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
	fail=0
      else
        echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
      fi
    done
  else
    echo -e "${NORMAL}RESULT:    ${RED}StrictModes value not found${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file9 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity9, $controlid, $stigid9, $ruleid9, $cci9, $datetime, ${GRN}PASSED, The RHEL 8 SSH daemon performs strict mode checking of home directory configuration files.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity9, $controlid, $stigid9, $ruleid9, $cci9, $datetime, ${RED}FAILED, The RHEL 8 SSH daemon does not perform strict mode checking of home directory configuration files.${NORMAL}"
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
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 10:   ${BLD}$title10a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title10b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title10c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity10${NORMAL}"

IFS='
'

file10="/etc/ssh/sshd_config"

fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file10 ]]
then
   ignoreukh="$(grep IgnoreUserKnownHosts $file10)"
   if [[ $ignoreukh ]]
   then
      for line in ${ignoreukh[@]}
      do
         ignoreukhval="$(echo $line | awk '{print $2}')"
         if [[ ${line:0:1} == '#' || $ignoreukhval == "no" ]]
         then
	    echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
	 else
            echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
	    fail=0
	 fi
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}\"IgnoreUserKnownHosts\" is not defined in $file10${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}$file10 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity10, $controlid, $stigid10, $ruleid10, $cci10, $datetime, ${GRN}PASSED, The SSH daemon does not allow authentication using known hosts authentication${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity10, $controlid, $stigid10, $ruleid10, $cci10, $datetime, ${RED}FAILED, The SSH daemon allows authentication using known hosts authentication${NORMAL}"
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
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 11:   ${BLD}$title11a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title11b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title11c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity11${NORMAL}"

IFS='
'

file11="/etc/ssh/sshd_config"

fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file11 ]]
then
   kerberosauth="$(grep ^KerberosAuthentication $file11)"
   if [[ $kerberosauth ]]
   then
      for line in ${kerberosauth[@]}
      do
         kerberosauthval="$(echo $line | awk '{print $2}')"
         if [[ ${line:0:1} == '#' || $kerberosauthval == "yes" ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
         else
            echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
            fail=0
         fi
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}\"KerberosAuthentication\" is not defined in $file11${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}$file11 was not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity11, $controlid, $stigid11, $ruleid11, $cci11, $datetime, ${GRN}PASSED, The SSH daemon does not allow Kerberos authentication${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity11, $controlid, $stigid11, $ruleid11, $cci11, $datetime, ${RED}FAILED, The SSH daemon either allows Kerberos authentication or it has not been defined to block it.${NORMAL}"
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
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 12:   ${BLD}$title12a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title12b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title12c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity12${NORMAL}"

IFS='
'

file12="/etc/fstab"
fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file12 ]]
then
   fsys="$(df -hl)"
   for fs in ${fsys[@]}
   do
      echo $fs
   done
   echo "-----------------------------------------------------"
   for fs in ${fsys[@]}
   do
      mnt="$(echo $fs | awk '{print $6}')"
      if [[ $mnt == '/var' ]]
      then
         fail=0
         echo -e "${NORMAL}RESULT:    ${BLD}$fs${NORMAL}"
      fi
   done

   if [[ $fail == 1 ]]
   then
      echo -e "${NORMAL}RESULT:    ${RED}A separate file system for /var was not found${NORMAL}"
      echo -e "${NORMAL}$hostname, $severity12, $controlid, $stigid12, $ruleid12, $cci12, $datetime, ${RED}FAILED, Separate /VAR File System: A separate file system for /var does not exist${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity12, $controlid, $stigid12, $ruleid12, $cci12, $datetime, ${GRN}PASSED, Separate /VAR File System: A separate file system for /var exists${NORMAL}"
   fi
else
   echo -e "${NORMAL}$hostname, $severity12, $controlid, $stigid12, $ruleid12, $cci12, $datetime, ${RED}FAILED, $file12 not found${NORMAL}"
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
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 13:   ${BLD}$title13a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title13b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title13c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity13${NORMAL}"

IFS='
'

file13="/etc/fstab"
fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file13 ]]
then
   fsys="$(df -hl)"
   for fs in ${fsys[@]}
   do
      echo $fs
   done
   echo "-----------------------------------------------------"
   for fs in ${fsys[@]}
   do
      mnt="$(echo $fs | awk '{print $6}')"
      if [[ $mnt == '/var/log' ]]
      then
         fail=0
         echo -e "${NORMAL}RESULT:    ${BLD}$fs${NORMAL}"
      fi
   done

   if [[ $fail == 1 ]]
   then
      echo -e "${NORMAL}RESULT:    ${RED}A separate file system for /var/log was not found${NORMAL}"
      echo -e "${NORMAL}$hostname, $severity13, $controlid, $stigid13, $ruleid13, $cci13, $datetime, ${RED}FAILED, A separate file system for /var/log does not exist${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity13, $controlid, $stigid13, $ruleid13, $cci13, $datetime, ${GRN}PASSED, A separate file system for /var/log exists${NORMAL}"
   fi
else
   echo -e "${NORMAL}$hostname, $severity13, $controlid, $stigid13, $ruleid13, $cci13, $datetime, ${RED}FAILED, $file13 not found${NORMAL}"
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
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 14:   ${BLD}$title14a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title14b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title14c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity14${NORMAL}"

IFS='
'

file14="/etc/fstab"

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file14 ]]
then
   fsys="$(df -hl) | grep -v '^find'"
   for fs in ${fsys[@]}
   do
      echo $fs
   done
   echo "-----------------------------------------------------"
   cfgpath="$(find /etc -noleaf -name auditd.conf)"
   for line in ${cfgpath[@]}
   do
      if [[ ! $line =~ 'find' ]]
      then
         cfgfile=$line
      fi
   done
   logpath="$(grep ^log_file $cfgfile | awk -F= '{print $2}' | sed -r 's/( )+//g')"
   logpartition="$(dirname $logpath)"
   echo -e "${NORMAL}RESULT:    Logs are in: $logpath"

   fail=1
   for fs in ${fsys[@]}
   do
      partition="$(echo $fs | awk '{print $6}')"
      if [[ $partition == $logpartition ]]
      then
         fail=0
         echo -e "${NORMAL}RESULT:    ${BLD}$fs${NORMAL}"
      fi
   done

   if [[ $fail == 1 ]]
   then
      echo -e "${NORMAL}RESULT:    ${RED}A separate file system for $logpartition was not found${NORMAL}"
      echo -e "${NORMAL}$hostname, $severity14, $controlid, $stigid14, $ruleid14, $cci14, $datetime, ${RED}FAILED, A separate file system for $logpartition does not exist${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity14, $controlid, $stigid14, $ruleid14, $cci14, $datetime, ${GRN}PASSED, A separate file system for $logpartition exists${NORMAL}"
   fi
else
   echo -e "${NORMAL}$hostname, $severity14, $controlid, $stigid14, $ruleid14, $cci14, $datetime, ${RED}FAILED, $file14 not found${NORMAL}"
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
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 15:   ${BLD}$title15a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title15b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title15c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity15${NORMAL}"

IFS='
'

file15="/etc/fstab"

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file15 ]]
then
   fsys="$(df -hl)"
   for fs in ${fsys[@]}
   do
      echo $fs
   done
   echo "-----------------------------------------------------"

   fail=1
   for fs in ${fsys[@]}
   do
      partition="$(echo $fs | awk '{print $6}')"
      if [[ $partition == "/tmp" ]]
      then
         echo -e "${NORMAL}RESULT:    ${BLD}$fs${NORMAL}"
	 fail=0
      fi
   done

   if [[ $fail == 1 ]]
   then
      echo -e "${NORMAL}RESULT:    ${RED}A separate file system for /tmp was not found${NORMAL}"
      echo -e "${NORMAL}$hostname, $severity15, $controlid, $stigid15, $ruleid15, $cci15, $datetime, ${RED}FAILED, A separate file system for /tmp does not exist${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity15, $controlid, $stigid15, $ruleid15, $cci15, $datetime, ${GRN}PASSED, A separate file system for /tmp exists${NORMAL}"
   fi
else
   echo -e "${NORMAL}$hostname, $severity15, $controlid, $stigid15, $ruleid15, $cci15, $datetime, ${RED}FAILED, $file15 not found${NORMAL}"
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
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 16:   ${BLD}$title16a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title16b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title16c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity16${NORMAL}"

IFS='
'

# supressing error messages from the console output
isenabled="$(systemctl is-enabled rsyslog 2>/dev/null)"
isactive="$(systemctl is-active rsyslog 2>/dev/null)"

datetime="$(date +%FT%H:%M:%S)"

if (( $isenabled == 'enabled' ))
then
  if (( $isactive == 'active' ))
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$isenabled : $isactive${NORMAL}"
    echo -e "${NORMAL}$hostname, $severity16, $controlid, $stigid16, $ruleid16, $cci16, $datetime, ${GRN}PASSED, The rsyslog service is $isenabled and $isactive.${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$isenabled : $isactive${NORMAL}"
    echo -e "${NORMAL}$hostname, $severity16, $controlid, $stigid16, $ruleid16, $cci16, $datetime, ${RED}FAILED, The rsyslog service is $isenabled, but $isactive.${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}(not found) : $isactive${NORMAL}"
  echo -e "${NORMAL}$hostname, $severity16, $controlid, $stigid16, $ruleid16, $cci16, $datetime, ${RED}FAILED, The rsyslog service is not enabled.${NORMAL}"
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
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 17:   ${BLD}$title17a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title17b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title17c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity17${NORMAL}"

IFS='
'

fail=0

file17a="/etc/passwd"
file17b="/etc/fstab"

users="$(awk -F: '($3>=1000)&&($7 !~ /nologin/){print $1,$3,$6}' $file17a)"
declare -a hdirarr

datetime="$(date +%FT%H:%M:%S)"

if [[ $users ]]
then
  echo "USERS:-----------------------------------------------"
  for user in ${users[@]}
  do
    echo "$user"
  done
  echo "FSTAB:-----------------------------------------------"
  if [[ -f $file17b ]]
  then
    fsys="$(cat $file17b)"
    for line in ${fsys[@]}
    do
      echo $line
    done
    echo "-----------------------------------------------------"
  fi
  for user in ${users[@]}
  do
    hdir="$(echo $user | awk -F ' ' '{print $3}' | awk -F'/' '{print $2}')"
    if [[ ! "${hdirarr[@]}" =~ "${hdir}" ]]
    then
      hdirarr+=($hdir)
    fi
    for dir in ${hdirarr[@]}
    do
      for fs in ${fsys[@]}
      do
	if [[ $fs =~ $dir ]]
	then
	  if [[ $fs =~ 'nosuid' ]]
          then
            echo -e "${NORMAL}RESULT:    ${BLD}$fs${NORMAL}"
	  else
	    echo -e "${NORMAL}RESULT:    ${RED}$fs${NORMAL}"
	    fail=1
	  fi
	fi
      done
    done
  done
else
  echo -e "${NORMAL}RESULT:    ${BLD}no user accounts found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity17, $controlid, $stigid17, $ruleid17, $cci17, $datetime, ${GRN}PASSED, RHEL 8 prevents files with the setuid and setgid bit set from being executed on file systems that contain user home directories.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity17, $controlid, $stigid17, $ruleid17, $cci17, $datetime, ${RED}FAILED, RHEL 8 does not prevent files with the setuid and setgid bit set from being executed on file systems that contain user home directories.${NORMAL}"
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
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 18:   ${BLD}$title18a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title18b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title18c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity18${NORMAL}"

IFS='
'

fail=0

bootmnt="$(mount | grep '\s/boot\s')"

datetime="$(date +%FT%H:%M:%S)"

if [[ $bootmnt ]]
then
  if [[ $bootmnt =~ 'nosuid' ]]
  then
    echo  -e "${NORMAL}RESULT:    ${BLD}$bootmnt${NORMAL}"
  else
    echo  -e "${NORMAL}RESULT:    ${RED}$bootmnt${NORMAL}"
    fail=1
  fi
else
  echo  -e "${NORMAL}RESULT:    ${RED}no \"/boot\" mount found${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity18, $controlid, $stigid18, $ruleid18, $cci18, $datetime, ${GRN}PASSED, RHEL 8 prevents files with the setuid and setgid bit set from being executed on the /boot directory.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity18, $controlid, $stigid18, $ruleid18, $cci18, $datetime, ${RED}FAILED, RHEL 8 does not prevent files with the setuid and setgid bit set from being executed on the /boot directory.${NORMAL}"
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
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 19:   ${BLD}$title19a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title19b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title19c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity19${NORMAL}"

IFS='
'

fail=0

rmmnt="$(mount | grep '^/dev\S* on /\S' | grep --invert-match 'nodev')"

datetime="$(date +%FT%H:%M:%S)"

if [[ $rmmnt ]]
then
  fail=1
  for line in ${rmmnt[@]}
  do
    echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
  done
else
  echo -e "${NORMAL}RESULT:    ${BLD}nothing found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity19, $controlid, $stigid19, $ruleid19, $cci19, $datetime, ${GRN}PASSED, RHEL 8 prevents special devices on non-root local partitions.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity19, $controlid, $stigid19, $ruleid19, $cci19, $datetime, ${RED}FAILED, RHEL 8 does not prevent special devices on non-root local partitions.${NORMAL}"
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
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 20:   ${BLD}$title20a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title20b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title20c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity20${NORMAL}"

IFS='
'

fail=0

file20a="/etc/passwd"
file20b="/etc/fstab"

users="$(awk -F: '($3>=1000)&&($7 !~ /nologin/){print $1,$3,$6}' $file20a)"
declare -a hdirarr

datetime="$(date +%FT%H:%M:%S)"

if [[ $users ]]
then
  echo "USERS:-----------------------------------------------"
  for user in ${users[@]}
  do
    echo "$user"
  done
  echo "FSTAB:-----------------------------------------------"
  if [[ -f $file20b ]]
  then
    fsys="$(cat $file20b)"
    for line in ${fsys[@]}
    do
      echo $line
    done
    echo "-----------------------------------------------------"
  fi
  for user in ${users[@]}
  do
    hdir="$(echo $user | awk -F ' ' '{print $3}' | awk -F'/' '{print $2}')"
    if [[ ! "${hdirarr[@]}" =~ "${hdir}" ]]
    then
      hdirarr+=($hdir)
    fi
    for dir in ${hdirarr[@]}
    do
      for fs in ${fsys[@]}
      do
	if [[ $fs =~ $dir ]]
	then
	  if [[ $fs =~ 'noexec' ]]
          then
            echo -e "${NORMAL}RESULT:    ${BLD}$fs${NORMAL}"
	  else
	    echo -e "${NORMAL}RESULT:    ${RED}$fs${NORMAL}"
	    fail=1
	  fi
	fi
      done
    done
  done
else
  echo -e "${NORMAL}RESULT:    ${BLD}no user accounts found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity20, $controlid, $stigid20, $ruleid20, $cci20, $datetime, ${GRN}PASSED, RHEL 8 prevents code from being executed on file systems that contain user home directories.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity20, $controlid, $stigid20, $ruleid20, $cci20, $datetime, ${RED}FAILED, RHEL 8 does not prevent code from being executed on file systems that contain user home directories.${NORMAL}"
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
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 21:   ${BLD}$title21a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title21b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title21c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity21${NORMAL}"

IFS='
'

fail=0
found=0

rmmnt="$(cat /etc/fstab)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $rmmnt ]]
then
  echo "FSTAB:-----------------------------------------------"
  for line in ${rmmnt[@]}
  do
    if [[ $line =~ 'usb' || $line =~ 'flash' ]]
    then
      found=1
      if [[ $line =~ 'nodev' ]]
      then
        echo -e "${BLD}$line${NORMAL}"
      else
        echo -e "${RED}$line${NORMAL}"
        fail=1
      fi
    else
      echo -e "${BLD}$line${NORMAL}"
    fi
  done
  echo "-----------------------------------------------------"
  if [[ $found == 1 ]]
  then
    if [[ $fail == 1 ]]
    then
      echo -e "${NORMAL}RESULT:    ${RED}A file systems used with removable media is not mounted with the 'nodev' option.${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${BLD}A file systems used with removable media is mounted with the 'nodev' option.${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${BLD}No file systems used with removable media were found.${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${BLD}failed to locate \"/etc/fstab\"${NORMAL}"
fi

if [[ $found == 1 ]]
then
  if [[ $fail == 0 ]]
  then
    echo -e "${NORMAL}$hostname, $severity21, $controlid, $stigid21, $ruleid21, $cci21, $datetime, ${GRN}PASSED, RHEL 8 prevents special devices on file systems that are used with removable media.${NORMAL}"
  else
    echo -e "${NORMAL}$hostname, $severity21, $controlid, $stigid21, $ruleid21, $cci21, $datetime, ${RED}FAILED, RHEL 8 does not prevent special devices on file systems that are used with removable media.${NORMAL}"
  fi
else
  echo -e "${NORMAL}$hostname, $severity21, $controlid, $stigid21, $ruleid21, $cci21, $datetime, ${GRN}PASSED, No file systems used for removable media were found.${NORMAL}"
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
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 22:   ${BLD}$title22a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title22b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title22c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity22${NORMAL}"

IFS='
'

fail=0
found=0

rmmnt="$(cat /etc/fstab)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $rmmnt ]]
then
  echo "FSTAB:-----------------------------------------------"
  for line in ${rmmnt[@]}
  do
    if [[ $line =~ 'usb' || $line =~ 'flash' ]]
    then
      found=1
      if [[ $line =~ 'noexec' ]]
      then
        echo -e "${BLD}$line${NORMAL}"
      else
        echo -e "${RED}$line${NORMAL}"
        fail=1
      fi
    else
      echo -e "${BLD}$line${NORMAL}"
    fi
  done
  echo "-----------------------------------------------------"
  if [[ $found == 1 ]]
  then
    if [[ $fail == 1 ]]
    then
      echo -e "${NORMAL}RESULT:    ${RED}A file systems used with removable media is not mounted with the 'noexec' option.${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${BLD}A file systems used with removable media is mounted with the 'noexec' option.${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${BLD}No file systems used with removable media were found.${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${BLD}nothing found${NORMAL}"
fi

if [[ $found == 1 ]]
then
  if [[ $fail == 0 ]]
  then
    echo -e "${NORMAL}$hostname, $severity22, $controlid, $stigid22, $ruleid22, $cci22, $datetime, ${GRN}PASSED, RHEL 8 prevents code from being executed on file systems that are used with removable media.${NORMAL}"
  else
    echo -e "${NORMAL}$hostname, $severity22, $controlid, $stigid22, $ruleid22, $cci22, $datetime, ${RED}FAILED, RHEL 8 does not prevent code from being executed on file systems that are used with removable media.${NORMAL}"
  fi
else
  echo -e "${NORMAL}$hostname, $severity22, $controlid, $stigid22, $ruleid22, $cci22, $datetime, ${GRN}PASSED, No file systems used for removable media were found.${NORMAL}"
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
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 23:   ${BLD}$title23a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title23b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title23c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity23${NORMAL}"

IFS='
'

fail=0
found=0

rmmnt="$(cat /etc/fstab)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $rmmnt ]]
then
  echo "FSTAB:-----------------------------------------------"
  for line in ${rmmnt[@]}
  do
    if [[ $line =~ 'usb' || $line =~ 'flash' ]]
    then
      found=1
      if [[ $line =~ 'nosuid' ]]
      then
        echo -e "${BLD}$line${NORMAL}"
      else
        echo -e "${RED}$line${NORMAL}"
        fail=1
      fi
    else
      echo -e "${BLD}$line${NORMAL}"
    fi
  done
  echo "-----------------------------------------------------"
  if [[ $found == 1 ]]
  then
    if [[ $fail == 1 ]]
    then
      echo -e "${NORMAL}RESULT:    ${RED}A file systems used with removable media is not mounted with the 'nosuid' option.${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${BLD}A file systems used with removable media is mounted with the 'nosuid' option.${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${BLD}No file systems used with removable media were found.${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${BLD}nothing found${NORMAL}"
fi

if [[ $found == 1 ]]
then
  if [[ $fail == 0 ]]
  then
    echo -e "${NORMAL}$hostname, $severity23, $controlid, $stigid23, $ruleid23, $cci23, $datetime, ${GRN}PASSED, RHEL 8 prevents files with the setuid and setgid bit set from being executed on file systems that are used with removable media.${NORMAL}"
  else
    echo -e "${NORMAL}$hostname, $severity23, $controlid, $stigid23, $ruleid23, $cci23, $datetime, ${RED}FAILED, RHEL 8 does not prevent files with the setuid and setgid bit set from being executed on file systems that are used with removable media.${NORMAL}"
  fi
else
  echo -e "${NORMAL}$hostname, $severity23, $controlid, $stigid23, $ruleid23, $cci23, $datetime, ${GRN}PASSED, No file systems used for removable media were found.${NORMAL}"
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
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 24:   ${BLD}$title24a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title24b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title24c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity24${NORMAL}"

IFS='
'

fail=0
found=0

rmmnt="$(cat /etc/fstab )"

datetime="$(date +%FT%H:%M:%S)"

if [[ $rmmnt ]]
then
  echo "FSTAB:-----------------------------------------------"
  for line in ${rmmnt[@]}
  do
    if [[ $line =~ 'nfs' ]]
    then
      found=1
      if [[ $line =~ 'noexec' ]]
      then
        echo -e "${BLD}$line${NORMAL}"
      else
        echo -e "${RED}$line${NORMAL}"
        fail=1
      fi
    else
      echo -e "${BLD}$line${NORMAL}"
    fi
  done
  echo "-----------------------------------------------------"
  if [[ $found == 1 ]]
  then
    if [[ $fail == 1 ]]
    then
	    echo -e "${NORMAL}RESULT:    ${RED}A Network File System (NFS) file systems is not mounted with the 'noexec' option.${NORMAL}"
    else
	    echo -e "${NORMAL}RESULT:    ${BLD}A Network File System (NFS) file systems is mounted with the 'noexec' option.${NORMAL}"
    fi
  else
	  echo -e "${NORMAL}RESULT:    ${BLD}No Network File System (NFS) file systems were found.${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${BLD}nothing found${NORMAL}"
fi

if [[ $found == 1 ]]
then
  if [[ $fail == 0 ]]
  then
    echo -e "${NORMAL}$hostname, $severity24, $controlid, $stigid24, $ruleid24, $cci24, $datetime, ${GRN}PASSED, RHEL 8 prevents code from being executed on file systems that are imported via Network File System (NFS).${NORMAL}"
  else
    echo -e "${NORMAL}$hostname, $severity24, $controlid, $stigid24, $ruleid24, $cci24, $datetime, ${RED}FAILED, RHEL 8 does not prevent code from being executed on file systems that are imported via Network File System (NFS).${NORMAL}"
  fi
else
  echo -e "${NORMAL}$hostname, $severity24, $controlid, $stigid24, $ruleid24, $cci24, $datetime, ${GRN}PASSED, No Network Files System (NFS) file systems were found.${NORMAL}"
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
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 25:   ${BLD}$title25a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title25b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title25c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity25${NORMAL}"

IFS='
'

fail=0
found=0

rmmnt="$(cat /etc/fstab )"

datetime="$(date +%FT%H:%M:%S)"

if [[ $rmmnt ]]
then
  echo "FSTAB:-----------------------------------------------"
  for line in ${rmmnt[@]}
  do
    if [[ $line =~ 'nfs' ]]
    then
      found=1
      if [[ $line =~ 'nodev' ]]
      then
        echo -e "${BLD}$line${NORMAL}"
      else
        echo -e "${RED}$line${NORMAL}"
        fail=1
      fi
    else
      echo -e "${BLD}$line${NORMAL}"
    fi
  done
  echo "-----------------------------------------------------"
  if [[ $found == 1 ]]
  then
    if [[ $fail == 1 ]]
    then
      echo -e "${NORMAL}RESULT:    ${RED}A Network File System (NFS) file system is not mounted with the 'nodev' option.${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${BLD}A Network File System (NFS) file system is mounted with the 'nodev' option.${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${BLD}No Network File System (NFS) file systems were found.${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${BLD}nothing found${NORMAL}"
fi

if [[ $found == 1 ]]
then
  if [[ $fail == 0 ]]
  then
    echo -e "${NORMAL}$hostname, $severity25, $controlid, $stigid25, $ruleid25, $cci25, $datetime, ${GRN}PASSED, RHEL 8 prevents special devices on file systems that are imported via Network File System (NFS).${NORMAL}"
  else
    echo -e "${NORMAL}$hostname, $severity25, $controlid, $stigid25, $ruleid25, $cci25, $datetime, ${RED}FAILED, RHEL 8 does not prevent special devices on file systems that are imported via Network File System (NFS).${NORMAL}"
  fi
else
  echo -e "${NORMAL}$hostname, $severity25, $controlid, $stigid25, $ruleid25, $cci25, $datetime, ${GRN}PASSED, No Network Files System (NFS) file systems were found.${NORMAL}"
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
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 26:   ${BLD}$title26a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title26b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title26c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity26${NORMAL}"

IFS='
'

fail=0
found=0

rmmnt="$(cat /etc/fstab )"

datetime="$(date +%FT%H:%M:%S)"

if [[ $rmmnt ]]
then
  echo "FSTAB:-----------------------------------------------"
  for line in ${rmmnt[@]}
  do
    if [[ $line =~ 'nfs' ]]
    then
      found=1
      if [[ $line =~ 'nosuid' ]]
      then
        echo -e "${BLD}$line${NORMAL}"
      else
        echo -e "${RED}$line${NORMAL}"
        fail=1
      fi
    else
      echo -e "${BLD}$line${NORMAL}"
    fi
  done
  echo "-----------------------------------------------------"
  if [[ $found == 1 ]]
  then
    if [[ $fail == 1 ]]
    then
      echo -e "${NORMAL}RESULT:    ${RED}A Network File System (NFS) file system is not mounted with the 'nosuid' option.${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${BLD}A Network File System (NFS) file system is mounted with the 'nosuid' option.${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${BLD}No Network File System (NFS) file systems were found.${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${BLD}nothing found${NORMAL}"
fi

if [[ $found == 1 ]]
then
  if [[ $fail == 0 ]]
  then
    echo -e "${NORMAL}$hostname, $severity26, $controlid, $stigid26, $ruleid26, $cci26, $datetime, ${GRN}PASSED, RHEL 8 prevents files with the setuid and setgid bit set from being executed on file systems that are imported via Network File System (NFS).${NORMAL}"
  else
    echo -e "${NORMAL}$hostname, $severity26, $controlid, $stigid26, $ruleid26, $cci26, $datetime, ${RED}FAILED, RHEL 8 does not prevent files with the setuid and setgid bit set from being executed on file systems that are imported via Network File System (NFS).${NORMAL}"
  fi
else
  echo -e "${NORMAL}$hostname, $severity26, $controlid, $stigid26, $ruleid26, $cci26, $datetime, ${GRN}PASSED, No Network Files System (NFS) file systems were found.${NORMAL}"
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
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 27:   ${BLD}$title27a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title27b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title27c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity27${NORMAL}"

IFS='
'

fail=0
found=0

file27a="/etc/passwd"
file27b="/etc/fstab"

users="$(awk -F: '($3>=1000)&&($7 !~ /nologin/){print $1,$3,$6}' $file27a 2>/dev/null)"

datetime="$(date +%FT%H:%M:%S)"

if [[ ${#users[@]} > 0 ]]
then
  echo "USERS:-----------------------------------------------"
  for user in ${users[@]}
  do
    echo "$user"
  done
  echo "PARTITIONS:------------------------------------------"
  if [[ -f $file27b ]]
  then
    fsys="$(cat $file27b | grep -v '^#' | grep -v swap | awk '{print $2}' 2>/dev/null)"
    for line in ${fsys[@]}
    do
      echo $line
      wrfarr="$(find $line -xdev -type f -perm -0002 -print 2>/dev/null)"
      if [[ $wrfarr ]]
      then
	found=1
      fi
    done
    echo "-----------------------------------------------------"
  else
    echo -e "${NORMAL}RESULT:    ${BLD}$file27b not found${NORMAL}"
  fi
  if [[ $found == 1 ]]
  then
    echo -e "${NORMAL}RESULT:    World-writable files were found${NORMAL}"
    for user in ${users[@]}
    do
      uhome="$(echo $user | awk '{print $3}')"
      hdir="$(echo $uhome | awk -F'/' '{print $2}')"
      echo -e "${NORMAL}RESULT:    Checking $uhome for references to world-writable files in initialization files${NORMAL}"
      if [[ $wrfarr ]]
      then
        for file in ${wrfarr[@]}
        do
          lclinit="$(grep $file $uhome/.*)"
          if [[ $lclinit ]]
          then
            fail=1
	    for x in ${lclinit[@]}
	    do
	      echo -e "${NORMAL}RESULT:    ${RED}  $x is referenced in $uhome/.* initialization files${NORMAL}"
            done
	  else
	    echo -e "${NORMAL}RESULT:    ${BLD}nothing found in $uhome${NORMAL}"
	  fi
        done
      fi
    done
  else
    echo -e "${NORMAL}RESULT:    ${BLD}No world-writable files found${NORMAL}"
  fi
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity27, $controlid, $stigid27, $ruleid27, $cci27, $datetime, ${GRN}PASSED, Local RHEL 8 initialization files do not execute world-writable programs.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity27, $controlid, $stigid27, $ruleid27, $cci27, $datetime, ${RED}FAILED, Local RHEL 8 initialization files execute world-writable programs.${NORMAL}"
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
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 28:   ${BLD}$title28a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title28b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title28c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity28${NORMAL}"

IFS='
'

sysctlcmd="$(command -v systemctl)"
enabled=0
active=0
fail=0

datetime="$(date +%FT%H:%M:%S)"

if [[ $sysctlcmd ]]
then
   kdump="$($sysctlcmd status kdump.service)"
   if [[ $kdump ]]
   then
      for line in ${kdump[@]}
      do
         line="$(echo $line | sed -e 's/^[[:space:]]*//')"
         if [[ $line =~ 'service; enabled' || $line =~ 'Active: active' ]]
         then
           enabled=1
           echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
	 elif [[ $line =~ 'Active: active' ]]
	 then
           active=1
           echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
         else
            echo -e "${NORMAL}RESULT:    $line${NORMAL}"
         fi
      done
   else
      echo -e "${NORMAL}RESULT:    ${BLD}The kdump service was not found${NORMAL}"
   fi
   if [[ $enabled == 1 && $active == 1 ]]
   then
     fail=1
   fi

   if (( $fail == 0 ))
   then
      echo -e "${NORMAL}$hostname, $severity28, $controlid, $stigid28, $ruleid28, $cci28, $datetime, ${GRN}PASSED, The kdump service is disabled${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity28, $controlid, $stigid28, $ruleid28, $cci28, $datetime, ${CYN}VERIFY, The kdump service is not disabled. Verify with the ISSO.${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}The 'systemctl' command was not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity28, $controlid, $stigid28, $ruleid28, $cci28, $datetime, ${CYN}VERIFY, the 'systemctl' command was not found${NORMAL}"
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
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 29:   ${BLD}$title29a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title29b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title29c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity29${NORMAL}"

IFS='
'
file29="/etc/sysctl.d/*.conf"

fail=1

kcpattern1="$(sysctl kernel.core_pattern)"
kcpattern2="$(grep -r kernel.core_pattern $file29 2>/dev/null | grep -v '# Per')"
kcp1=0
kcp2=0

datetime="$(date +%FT%H:%M:%S)"

if [[ $kcpattern1 ]]
then
  kcp1val="$(echo $kcpattern1 | awk -F= '{print $2}')"
  if [[ $kcp1val =~ "|/bin/false" ]]
  then
    kcp1=1
    echo -e "${NORMAL}RESULT:    ${BLD}a. $kcpattern1${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}a. $kcpattern1${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}\"kernel.core.pattern\" is not defined in sysctl files${NORMAL}"
fi

if [[ $kcpattern2 ]]
then
  kcp2val="$(echo $kcpattern2 | awk -F= '{print $2}')"
  if [[ $kcp2val =~ "|/bin/false" ]]
  then
    kcp2=1
    echo -e "${NORMAL}RESULT:    ${BLD}b. $kcpattern2${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}b. $kcpattern2${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}b. \"kernel.core_pattern\" is not defined in $file29 files${NORMAL}"
fi

if [[ $kcp1 == 1 && $kcp2 == 1 ]]
then
  fail=0
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity29, $controlid, $stigid29, $ruleid29, $cci29, $datetime, ${GRN}PASSED, RHEL 8 disables the kernel.core_pattern.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity29, $controlid, $stigid29, $ruleid29, $cci29, $datetime, ${RED}FAILED, RHEL 8 does not disable the kernel.core_pattern.${NORMAL}"
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
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 30:   ${BLD}$title30a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title30b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title30c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity30${NORMAL}"

IFS='
'

fail=1
masked=0

scdstat="$(systemctl status systemd-coredump.socket)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $scdstat ]]
then
  for line in ${scdstat[@]}
  do
    if [[ ($line =~ "Loaded:" && $line =~ "masked" ) ||
           $line =~ "Active:" && $line =~ "inactive (dead)" ]]
    then
      fail=0
      echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
    elif [[ ($line =~ "Loaded:" && ! $line =~ "masked") ||
            ($line =~ "Active:" && ! $line =~ "inactive (dead)") ]]
    then
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    $line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${BLD}systemd-coredump.socket is not configured${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity30, $controlid, $stigid30, $ruleid30, $cci30, $datetime, ${GRN}PASSED, RHEL 8 masks (disables) acquiring saving and processing core dumps.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity30, $controlid, $stigid30, $ruleid30, $cci30, $datetime, ${RED}FAILED, RHEL 8 does not mask (disable) acquiring saving and processing core dumps.${NORMAL}"
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
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 31:   ${BLD}$title31a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title31b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title31c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity31${NORMAL}"

IFS='
'

fail=1

cds="$(grep -r -s '^[^#].*core' /etc/security/limits.conf /etc/security/limits.d/*.conf)"
cdstat="$(echo $cds | tr -s ' ')"

datetime="$(date +%FT%H:%M:%S)"

if [[ $cdstat ]]
then
  if [[ $cdstat =~ '* hard core 0' ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$cdstat${NORMAL}"
    fail=0
  else
    echo -e "${NORMAL}RESULT:    ${RED}$cdstat${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity31, $controlid, $stigid31, $ruleid31, $cci31, $datetime, ${GRN}PASSED, RHEL 8 disables core dumps for all users.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity31, $controlid, $stigid31, $ruleid31, $cci31, $datetime, ${RED}FAILED, RHEL 8 does not disable core dumps for all users.${NORMAL}"
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
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 32:   ${BLD}$title32a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title32b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title32c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity32${NORMAL}"

IFS='
'

file32="/etc/systemd/coredump.conf"
fail=1

cds="$(grep -i storage $file32 2>/dev/null | grep -i storage)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $cds ]]
then
  for line in ${cds[@]} 
  do
    cdsval="$(echo $line | awk -F "=" '{print $2}')"
    if [[ $cdsval == 'none' && ${line:0:1} != '#' ]]
    then
      fail=0
      echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${BLD}nothing found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity32, $controlid, $stigid32, $ruleid32, $cci32, $datetime, ${GRN}PASSED, RHEL 8 disables storing core dumps.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity32, $controlid, $stigid32, $ruleid32, $cci32, $datetime, ${RED}FAILED, RHEL 8 does not disable storing core dumps.${NORMAL}"
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
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 33:   ${BLD}$title33a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title33${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title33c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity33${NORMAL}"

IFS='
'

fail=1

cdb="$(grep -i processsizemax /etc/systemd/coredump.conf 2>/dev/null | grep -i processsizemax)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $cdb ]]
then
  for line in ${cdb[@]}
  do
    cdbval="$(echo $line | awk -F "=" '{print $2}')"
    if [[ $cdbval == '0' && ${line:0:1} != '#' ]]
    then
      fail=0
      echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${BLD}nothing found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity33, $controlid, $stigid33, $ruleid33, $cci33, $datetime, ${GRN}PASSED, RHEL 8 disables core dump backtraces.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity33, $controlid, $stigid33, $ruleid33, $cci33, $datetime, ${RED}FAILED, RHEL 8 does not disable core dump backtraces.${NORMAL}"
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
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 34:   ${BLD}$title34a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title34b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title34c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity34${NORMAL}"

IFS='
'

fail=0

file34a="/etc/nsswitch.conf"
file34b="/etc/resolv.conf"

nss="$(grep ^hosts $file34a)"
res=( $(grep ^nameserver $file34b) )
isused=0
hastwo=0
isempty=0

datetime="$(date +%FT%H:%M:%S)"

if [[ $nss ]]
then
  if [[ $nss =~ 'dns' ]]
  then
    isused=1
    echo -e "${NORMAL}RESULT:    ${BLD}$file34a: $nss${NORMAL}"
    if (( ${#res[@]} >= 2 ))
    then
      hastwo=1
    fi
    if [[ $res ]]
    then
      for line in ${res[@]}
      do
        echo -e "${NORMAL}RESULT:    ${BLD}$file34b: $line${NORMAL}"
      done
    else
      isempty=1
      echo -e "${NORMAL}RESULT:    ${RED}No \"nameserver\" entries found in $file34b.${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${BLD}Domain Name Service (DNS) is not used for name resolution${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}No \'hosts\' entries found in $file34a.${NORMAL}"
  fail=1
fi

if [[ $isused == 1 && $hastwo == 1 ]]
then
  echo -e "${NORMAL}$hostname, $severity34, $controlid, $stigid34, $ruleid34, $cci34, $datetime, ${GRN}PASSED, The RHEL 8 system uses Domain Name Servers (DNS) resolution and has at least two name servers configured.${NORMAL}"
elif [[ $isused == 1 && ! $hastwo == 1 ]]
then
  echo -e "${NORMAL}$hostname, $severity34, $controlid, $stigid34, $ruleid34, $cci34, $datetime, ${RED}FAILED, The RHEL 8 system uses Domain Name Servers (DNS) resolution but does not have at least two name servers configured.${NORMAL}"
elif [[ $isused == 0 && $isempty == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity34, $controlid, $stigid34, $ruleid34, $cci34, $datetime, ${RED}FAILED, The RHEL 8 system does not use Domain Name Servers (DNS) resolution but $file34b is not empty.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity34, $controlid, $stigid34, $ruleid34, $cci34, $datetime, ${RED}FAILED, The RHEL 8 system does not use Domain Name Servers (DNS) resolution but $file34a does not have a \'hosts\' entry specifying how it resolves names otherwise.${NORMAL}"
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
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 35:   ${BLD}$title35a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title35b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title35c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity35${NORMAL}"

IFS='
'
file35="/etc/passwd"

fail=0

users="$(awk -F':' '($3>=1000)&&($7 !~ /nologin/){print $1,$3,$6}' $file35)"

datetime="$(date +%FT%H:%M:%S)"

if [[ ${#users[@]} > 0 ]]
then
  echo "USERS:-----------------------------------------------"
  for user in ${users[@]}
  do
    echo "$user"
    uhome="$(echo $user | awk -F ' ' '{print $3}')"
    hdir="$(echo $uhome | awk -F'/' '{print $2}')"
    uhpath=( $(grep -i path= $uhome/.* 2>/dev/null | grep -v .bash_history) )
    if [[ $uhpath ]]
    then
      echo $uhpath
      for uhp in ${uhpath[@]}
      do
        hpaths="$(echo $uhp | awk -F "=" '{print $2}' | tr -d '"')"
	IFS=':'
        if [[ $hpaths ]]
        then
          for path in ${hpaths[@]}
          do
            if [[ $path == "\$PATH" ]]
	    then
	      rootpath="$(env | grep PATH | awk -F '=' '{print $2}' )"
	      for rpath in ${rootpath[@]}
              do
		echo "$path: $rpath"
              done
	    else
	      if [[ ${path:0:5} == '$HOME' ]]
	      then
                echo $path
              else
		fail=1
		echo -e ${RED}$path${NORMAL}
              fi
	    fi
            #echo $path
          done
        fi
      done
      echo "-----------------------------------------------------"
    fi
  done
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity35, $controlid, $stigid35, $ruleid35, $cci35, $datetime, ${GRN}PASSED, Executable search paths within the initialization files of all local interactive RHEL 8 users only contain paths that resolve to the system default or the users home directory.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity35, $controlid, $stigid35, $ruleid35, $cci35, $datetime, ${RED}FAILED, Executable search paths within the initialization files of all local interactive RHEL 8 users contain paths that resolve to directories other than the system default or the users home directory.${NORMAL}"
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
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 36:   ${BLD}$title36a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title36b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title36c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity36${NORMAL}"

IFS='
'

fail=0
found=0

file36="/etc/fstab"

datetime="$(date +%FT%H:%M:%S)"

echo "PARTITIONS:------------------------------------------"
if [[ -f $file36 ]]
then
  fsys="$(cat $file36 | grep -v '^#' | grep -v swap | awk '{print $2}')"
  for line in ${fsys[@]}
  do
    echo $line
  done
  echo "WORLD-WRITABLE DIRECTORIES:------------------------"
  for line in ${fsys[@]}
  do
    wrdarr="$(find $line -xdev -type d -perm -0002 -uid +999 -print)"
    if [[ $wrdarr ]]
    then
      fail=1
      for dir in ${wrdarr[@]}
      do
        echo -e "${NORMAL}RESULT:    ${RED}$dir is not owned by a system account.${NORMAL}"
      done
    fi
  done
  if [[ $fail == 0 ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}nothing found${NORMAL}"
  fi
  echo "---------------------------------------------------"
else
  echo -e "${NORMAL}RESULT:    ${BLD}$file36 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity36, $controlid, $stigid36, $ruleid36, $cci36, $datetime, ${GRN}PASSED, All RHEL 8 world-writable directories are owned by a system account.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity36, $controlid, $stigid36, $ruleid36, $cci36, $datetime, ${RED}FAILED, RHEL 8 world-writable directories not owned by a system account were found.${NORMAL}"
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
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 37:   ${BLD}$title37a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title37b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title37c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity37${NORMAL}"

IFS='
'

file37="/etc/fstab"

fail=0

datetime="$(date +%FT%H:%M:%S)"

echo "PARTITIONS:------------------------------------------"
if [[ -f $file37 ]]
then
  fsys="$(cat $file37 | grep -v '^#' | grep -v swap | awk '{print $2}')"
  for line in ${fsys[@]}
  do
    echo $line
  done
  echo "FINDINGS:--------------------------------------------"
  for line in ${fsys[@]}
  do
    wrdarr="$(find $line -xdev -type d -perm -0002 -gid +999 -print)"
    if [[ $wrdarr ]]
    then
      fail=1
      for dir in ${wrdarr[@]}
      do
        echo -e "${NORMAL}RESULT:    ${RED}$dir is not group-owned by a system account.${NORMAL}"
      done
    fi
  done
  if [[ $fail == 0 ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}nothing found${NORMAL}"
    echo "---------------------------------------------------"
  fi
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity37, $controlid, $stigid37, $ruleid37, $cci37, $datetime, ${GRN}PASSED, All world-writable directories are group-owned by either root sys bin or an application group${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity37, $controlid, $stigid37, $ruleid37, $cci37, $datetime, ${RED}FAILED, All World-writable directories are not group-owned by either root sys bin or an appplication group${NORMAL}"
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
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 38:   ${BLD}$title38a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title38b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title38c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity38${NORMAL}"

IFS='
'

file38="/etc/passwd"

fail=0

nohdir="$(pwck -r)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $nohdir ]]
then
  for account in ${nohdir[@]}
  do
    if [[ ! $account =~ 'pwck' ]]
    then
      user="$(echo $account | cut -d: -f1 | cut -d \' -f2)"
      uid="$(id $user | cut -d' ' -f1 | cut -d'=' -f2 | cut -d '(' -f1)"
      hdir="$(grep $user $file38 | cut -d: -f7)"
      if (( $uid > 999 ))
      then
	if [[ $hdir ]]
	then
	  if ! [[ $hdir =~ 'sbin/nologin' || $hdir =~ 'bin/false' ]]
          then
            fail=1
            echo -e "${NORMAL}RESULT:    ${RED}$account${NORMAL}"
          else
	    echo -e "${NORMAL}RESULT:    $account${NORMAL}"
          fi
	else
          echo -e "${NORMAL}RESULT:    ${RED}$account${NORMAL}"
        fi
      else
	echo -e "${NORMAL}RESULT:    $account${NORMAL}"
      fi
    fi
  done
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity38, $controlid, $stigid38, $ruleid38, $cci38, $datetime, ${GRN}PASSED, All RHEL 8 local interactive users have a home directory assigned.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity38, $controlid, $stigid38, $ruleid38, $cci38, $datetime, ${RED}FAILED, Not all RHEL 8 local interactive users have a home directory assigned.${NORMAL}"
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
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 39:   ${BLD}$title39a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title39b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title39c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity39${NORMAL}"

IFS='
'

file39="/etc/passwd"
fail=0

uhdir="$(ls -ld $(awk -F: '($3>=1000)&&($7 !~ /nologin/){print $6}' $file39))"

datetime="$(date +%FT%H:%M:%S)"

if [[ $uhdir ]]
then
  for user in ${uhdir[@]}
  do
    usracct="$(grep $user $file39)"
    homedir="$(echo $user | awk '{print $9}')"
    if [[ -d $homedir ]]
    then
      fperm="$(ls -ld $homedir)"
      mode="$(stat -c %a $homedir)"
      if (( ${mode:0:1} <= 7 &&
	    ${mode:1:1} <= 5 &&
	    ${mode:2:1} == 0
         ))
      then
        echo -e "${NORMAL}RESULT:    ${BLD}$fperm (mode:  $mode)${NORMAL}"
      else
        echo -e "${NORMAL}RESULT:    ${RED}$fperm (mode: $mode)${NORMAL}"
      fi
    else
      echo -e "${NORMAL}RESULT:    ${RED}no home directory defined for $user${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}no home directory defined for $user${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity39, $controlid, $stigid39, $ruleid39, $cci39, $datetime, ${GRN}PASSED, All RHEL 8 local interactive user home directories are mode 0750 or are less permissive.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity39, $controlid, $stigid39, $ruleid39, $cci39, $datetime, ${RED}FAILED, All RHEL 8 local interactive user home directories are not mode 0750 or less permissive.${NORMAL}"
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
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 40:  ${BLD}$title40a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title40b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title40c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity40${NORMAL}"

IFS='
'

file40a="/etc/passwd"
file40b="/etc/group"
fail=0

datetime="$(date +%FT%H:%M:%S)"

udperm="$(ls -ld $(awk -F: '($3>=1000)&&($7 !~ /nologin/){print $6}' $file40a))"
if [[ ${#udperm[@]} > 0 ]]
then
  echo "USER HOME DIRS:--------------------------------------"
  for line in ${udperm[@]}
  do
    home="$(echo $line | awk '{print $9}')"
    user="$(echo $home | awk -F '/' '{print $3}')"
    uid="$(id $user)"
    gid="$(echo $line | awk '{print $4}')"
    pgid="$(grep $(grep $user $file40a | awk -F: '{print $4}') $file40b)"
    if [[ $(echo $pgid | awk -F: '{print $1}') == $gid ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$line is group-owned by $user's primary gid: $uid${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$line is not group-owned by $user's primary gid: $uid${NORMAL}"
      fail=1
    fi
  done
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity40, $controlid, $stigid40, $ruleid40, $cci40, $datetime, ${GRN}PASSED, The assigned home directory of all local interactive users is group-owned by the primary gid of that interactive user${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity40, $controlid, $stigid40, $ruleid40, $cci40, $datetime, ${RED}FAILED, The assigned home directory of all local interactive users is not group-owned by the primary gid of that interactive user${NORMAL}"
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
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 41:   ${BLD}$title41a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title41b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title41c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity41${NORMAL}"

IFS='
'

file41="/etc/passwd"

users="$(ls -ld $(awk -F: '($3>=1000)&&($7 !~ /nologin/){print $6}' $file41))"
nohdir="$(pwck -r)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $users ]]
then
  echo "LOCAL INTERACTIVE USERS:-----------------------------"
  for user in ${users[@]}
  do
    echo $user
  done
  echo "USERS WITH NO HOME DIRECTORY:------------------------"
fi

if [[ $nohdir ]]
then
  for account in ${nohdir[@]}
  do
    if [[ ! $account =~ 'pwck' ]]
    then
      for line in ${users[@]}
      do
        user="$(echo $line | awk -F ' ' '{print $9}')"
        if [[ $nohdir =~ $user ]]
        then
	  fail=1
	  echo -e "${NORMAL}RESULT:    ${RED}$account${NORMAL}"
	else
	  echo -e "${NORMAL}RESULT:    $account${NORMAL}"
	fi
      done
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${BLD}No accounts with missing home directories found.${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity41, $controlid, $stigid41, $ruleid41, $cci41, $datetime, ${GRN}PASSED, All RHEL 8 local interactive user home directories defined in the /etc/passwd file exist.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity41, $controlid, $stigid41, $ruleid41, $cci41, $datetime, ${RED}FAILED, Not all RHEL 8 local interactive user home directories defined in the /etc/passwd file exist.${NORMAL}"
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
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 42:   ${BLD}$title42a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title42b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title42c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity42${NORMAL}"


IFS='
'

file42="/etc/login.defs"

fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file42 ]]
then
  createhome="$(grep -i create_home $file42)"
  if [[ $createhome ]]
  then
    createhomeval="$(echo $createhome | awk '{print $2}')"
    if [[ $createhomeval == 'yes' && ${createhome:0:1} != '#' ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$createhome${NORMAL}"
      fail=0
    else
      echo -e "${NORMAL}RESULT:    ${RED}$createhome${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${BLD}CREATE_HOME was not defined in $file42${NORMAL}"
  fi
else      
   echo -e "${NORMAL}RESULT:    ${BLD}$file42 was not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity42, $controlid, $stigid42, $ruleid42, $cci42, $datetime, ${GRN}PASSED, All local interactive user accounts upon creation are assigned a home directory${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity42, $controlid, $stigid42, $ruleid42, $cci42, $datetime, ${RED}FAILED, All local interactive user accounts upon creation are not assigned a home directory${NORMAL}"
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
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 43:   ${BLD}$title43a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title43b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title43c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity43${NORMAL}"

IFS='
'

file43="/etc/passwd"

fail=0

users="$(awk -F: '($3>=1000)&&($7 !~ /nologin/){print $1,$3,$6}' $file43)"

datetime="$(date +%FT%H:%M:%S)"

if [[ ${#users[@]} > 0 ]]
then
  echo "USERS:-----------------------------------------------"
  for user in ${users[@]}
  do
    echo "$user"
  done
  echo "-----------------------------------------------------"
fi

for user in ${users[@]}
do
  homedir="$(echo $user | awk '{print $3}')"
  if [[ $homedir ]]
  then
    perm="$(ls -la $homedir/.[^.]* |  awk '{print $9}' | awk '/^\//')"
    for file in ${perm[@]}
    do
      fperm="$(ls -la $file)"
      mode="$(stat -c %a $file)"
      if (( ${mode:0:1} <= 7 &&
	    ${mode:1:1} <= 5 &&
	    ${mode:2:1} == 0
         ))
      then
        echo -e "${NORMAL}RESULT:    ${BLD}$fperm (mode: $mode)${NORMAL}"
      else
        echo -e "${NORMAL}RESULT:    ${RED}$fperm (mode: $mode)${NORMAL}"
	fail=1
      fi
    done
  else
    echo -e "${NORMAL}RESULT:    ${RED}no homdirectory defined for $user${NORMAL}"
  fi
done

if (( $fail == 0 ))
then
  echo -e "${NORMAL}$hostname, $severity43, $controlid, $stigid43, $ruleid43, $cci43, $datetime, ${GRN}PASSED, All local initialization files are mode 740 or less permissive${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity43, $controlid, $stigid43, $ruleid43, $cci43, $datetime, ${RED}FAILED, All local initialization files are not mode 740 or less permissive${NORMAL}"
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
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 44:   ${BLD}$title44a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title44b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title44c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity44${NORMAL}"

IFS='
'

file44="/etc/fstab"

fail=0

datetime="$(date +%FT%H:%M:%S)"

echo "FSTAB:-----------------------------------------------"
fsys="$(cat $file44 | grep -v '^#' | grep -v '/proc' | grep -v swap | grep -v '/run/user/1000')"
for line in ${fsys[@]}
do
  echo $line
done
echo "-----------------------------------------------------"

for line in ${fsys[@]}
do
  fs="$(echo $line | awk -F ' ' '{print $2}')"
  fstype="$(echo $line | awk -F ' ' '{print $3}')"
  nuarr="$(find $fs -xdev -fstype $fstype -nouser)"
  if (( ${#nouser[@]} > 0 ))
  then
    fail=1
    for nufile in ${nuarr[@]}
    do
      echo -e "${NORMAL}RESULT:    ${RED}$nufile${NORMAL}"
    done
  fi
done

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}RESULT:    ${BLD}no output${NORMAL}"
  echo -e "${NORMAL}$hostname, $severity44, $controlid, $stigid44, $ruleid44, $cci44, $datetime, ${GRN}PASSED, All RHEL 8 local files and directories have a valid owner.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity44, $controlid, $stigid44, $ruleid44, $cci44, $datetime, ${RED}FAILED, All RHEL 8 local files and directories do not have a valid owner.${NORMAL}"  
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid45${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid45${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid45${NORMAL}"
echo -e "${NORMAL}CCI:       $cci45${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 45:   ${BLD}$title45a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title45b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title45c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity45${NORMAL}"

IFS='
'

file45="/etc/fstab"

fail=0

datetime="$(date +%FT%H:%M:%S)"

echo "FSTAB:-----------------------------------------------"
fsys="$(cat $file45 | grep -v '^#' | grep -v '/proc' | grep -v swap | grep -v '/run/user/1000')"
for line in ${fsys[@]}
do
  echo $line
done
echo "-----------------------------------------------------"

for line in ${fsys[@]}
do
  fs="$(echo $line | awk -F ' ' '{print $2}')"
  fstype="$(echo $line | awk -F ' ' '{print $3}')"
  ngarr="$(find $fs -xdev -fstype $fstype -nogroup)"
  if (( ${#ngarr[@]} > 0 ))
  then
    for ng in ${ngarr[@]}
    do
	fail=1
        echo -e "${NORMAL}RESULT:    ${RED}$ng${NORMAL}"
    done
  fi
done

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}RESULT:    ${BLD}no output${NORMAL}"
  echo -e "${NORMAL}$hostname, $severity45, $controlid, $stigid45, $ruleid45, $cci45, $datetime, ${GRN}PASSED, All RHEL 8 local files and directories have a valid group owner.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity45, $controlid, $stigid45, $ruleid45, $cci45, $datetime, ${RED}FAILED, All RHEL 8 local files and directories do not have a valid group owner.${NORMAL}"  
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
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 46:   ${BLD}$title46a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title46b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title46c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity46${NORMAL}"

IFS='
'

file46a="/etc/fstab"
file46b="/etc/passwd"

fail=0

users="$(awk -F: '($3>=1000)&&($7 !~ /nologin/){print $1,$3,$6}' $file46b)"

datetime="$(date +%FT%H:%M:%S)"

echo "FILESYSTEM/PARTITION------------------------------------"
fsys="$(cat $file46a | grep -v '^#' | grep -v '/proc' | grep -v swap | grep -v '/run/user/1000')"
for line in ${fsys[@]}
do
  fs="$(echo $line | awk -F ' ' '{print $2}')"
  fsarr+=("$fs")
  echo $fs
done

if [[ $users ]]
then
  echo "LOCAL INTERACTIVE USERS:-----------------------------"
  for user in ${users[@]}
  do
    hdir="$(echo $user | awk -F ' ' '{print $3}' | awk -F "/" '{print $2}')"
    if [[ ${fsarr[*]} =~ "/$hdir" ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$user${NORMAL}"
    else
      fail=1
      echo -e "${NORMAL}RESULT:    ${RED}$user${NORMAL}"
    fi
  done
  echo "-----------------------------------------------------"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity46, $controlid, $stigid46, $ruleid46, $cci46, $datetime, ${GRN}PASSED, A separate file system/partition has been created for all non-privileged local interactive user home directories${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity46, $controlid, $stigid46, $ruleid46, $cci46, $datetime, ${RED}FAILED, A separate file system/partition has not been created for all non-privileged local interactive user home direcctories${NORMAL}"
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
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 47:   ${BLD}$title47a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title47b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title47c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity47${NORMAL}"

file47="/etc/gdm/custom.conf"

fail=1
installed=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file47 ]]
then # (Gnome is installed)
   installed=1
   autologin="$(grep -i automaticloginenable $file47 | grep -v "^#")"
   if [[ $autologin ]]
   then
      autologinval="$(echo $autologin | awk -F= '{print $2}')"
      if [[ $autologinval == 'False' ]]
      then
	 fail=0
         echo -e "${NORMAL}RESULT:    ${BLD}$autologin${NORMAL}"
      else
         echo -e "${NORMAL}RESULT:    ${BLD}$autologin${NORMAL}"
      fi
   else
      echo -e "${NORMAL}RESULT:    ${RED}\"AutomaticLoginEnable\" was not defined in $file47${NORMAL}"
   fi
else
  fail=0	
  echo -e "${NORMAL}RESULT:    ${BLD}GNOME is not installed${NORMAL}"
fi

if [[ $installed == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity47, $controlid, $stigid47, $ruleid47, $cci47, $datetime, ${GRN}N/A, A graphical user interface is not installed${NORMAL}"
elif [[ $fail == 0 && $installed == 1 ]]
then
  echo -e "${NORMAL}$hostname, $severity47, $controlid, $stigid47, $ruleid47, $cci47, $datetime, ${GRN}PASSED, Unattended or automatic logins are not allowed${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity47, $controlid, $stigid47, $ruleid47, $cci47, $datetime, ${RED}FAILED, Unattended or automatic logins are allowed${NORMAL}"
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
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 48:   ${BLD}$title48a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title48b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title48c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity48${NORMAL}"

file48="/etc/ssh/sshd_config"

fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file48 ]]
then
  userenv="$(grep -i permituserenvironment $file48)"
  if [[ $userenv ]]
  then
    for line in ${userenv[@]}
    do
      if [[ ${line:0:1} != "#" ]]
      then
	userenval="$(echo $userenv | awk '{print $2}')"
        if [[ $userenval == 'no' ]]
        then
	  echo -e "${NORMAL}RESULT:    ${BLD}$userenv${NORMAL}"
	  fail=0
        else
          echo -e "${NORMAL}RESULT:    ${RED}$userenv${NORMAL}"
        fi
      else
	echo -e "${NORMAL}RESULT:    ${RED}$userenv${NORMAL}"
      fi
    done
  else
    echo -e "${NORMAL}RESULT:    ${RED}\"PermitUserEnvironment\" was not defined in $file48${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file48 was not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity48, $controlid, $stigid48, $ruleid48, $cci48, $datetime, ${GRN}PASSED, Users are not allowed to override environment variables to the SSH daemon${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity48, $controlid, $stigid48, $ruleid48, $cci48, $datetime, ${RED}FAILED, Users are allowed to override environment variables to the SSH daemon${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid49${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid49${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid49${NORMAL}"
echo -e "${NORMAL}CCI:       $cci49${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 49:   ${BLD}$title49a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title49b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title49c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity49${NORMAL}"

IFS='
'

file49="/etc/pam.d/password-auth"

fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file49 ]]
then
  pwquality="$(cat $file49 | grep pam_pwquality)"
  if [[ $pwquality =~ "password" && $pwquality =~ "pam_pwquality.so" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$pwquality${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}\"pam_pwquality\" is not defined in $file49${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file49 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity49, $controlid, $stigid49, $ruleid49, $cci49, $datetime, ${GRN}PASSED, RHEL 8 ensures the password complexity module is enabled in the password-auth file.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity49, $controlid, $stigid49, $ruleid49, $cci49, $datetime, ${RED}FAILED, RHEL 8 does not ensure the password complexity module is enabled in the password-auth file.${NORMAL}"
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
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 50:   ${BLD}$title50a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title50b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title50c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity50${NORMAL}"

IFS='
'

file50="/etc/security/pwquality.conf"
dir50="/etc/pwquality.conf.d"

fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file50 ]]
then
  dict50a="$(grep -i dictcheck $file50 | grep -v "^#" | \
	     awk -F= '{print $2}' | sed 's/ //g' 2>/dev/null)"
  if [[ $dict50a == 1 ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$file50:dictcheck = $dict50a${NORMAL}"
    fail=0
  else
    echo -e "${NORMAL}RESULT:    ${RED}$file50:dictcheck = $dict50a${NORMAL}"
  fi
fi

if [[ -d $dir50 ]]
then
  dict50b="$(grep -ir dictcheck $dir50 | grep -v "^#" | \
	     awk -F= '{print $2}' | sed 's/ //g' 2>/dev/null)"
  if [[ $dict50b == 1 ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$dir50:dictcheck = $dict50b${NORMAL}"
    fail=0
  else
    echo -e "${NORMAL}RESULT:    ${RED}$dir50:dictcheck = $dict50b${NORMAL}"
  fi
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity50, $controlid, $stigid50, $ruleid50, $cci50, $datetime, ${GRN}PASSED, RHEL 8 prevents the use of dictionary words for passwords.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity50, $controlid, $stigid50, $ruleid50, $cci50, $datetime, ${RED}FAILED, RHEL 8 does not prevent the use of dictionary words for passwords.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid51${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid51${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid51${NORMAL}"
echo -e "${NORMAL}CCI:       $cci51${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 51:   ${BLD}$title51a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title51b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title51c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity51${NORMAL}"

file51="/etc/login.defs"

fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file51 ]]
then
  delay="$(grep -i fail_delay $file51 | grep -v "^#")"
  if [[ $delay ]]
  then
    delaytime="$(echo $delay | awk '{print $2}')"
    if (( $delaytime >= 4 ))
    then
      fail=0
      echo -e "${NORMAL}RESULT:    ${BLD}$delay${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$delay${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}'FAIL_DELAY' is not defined in $file51${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${BLD}$file51 was not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity51, $controlid, $stigid51, $ruleid51, $cci51, $datetime, ${GRN}PASSED, The delay between logon prompts following a failed console logon is at least four seconds between logon prompts following a failed logon attempt.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity51, $controlid, $stigid51, $ruleid51, $cci5, $datetime, ${RED}FAILED, The delay between logon prompts following a failed console logon is not at least four seconds between logon prompts following a failed logon attempt.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid52${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid52${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid52${NORMAL}"
echo -e "${NORMAL}CCI:       $cci52${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 52:   ${BLD}$title52a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title52b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title52c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity52${NORMAL}"

IFS='
'

file52="/etc/shadow"

fail=0

sysapps="$(awk -F: '($2 == "*" || $2 == "!!" || $2 == ".") {print $1}' $file52)"
usrs="$(awk -F: '($2 != "*" && $2 != "!!" && $2 != ".") {print $1}' $file52)"

datetime="$(date +%FT%H:%M:%S)"

echo
echo "SYSTEM/APPLICATION ACCOUNTS:----------------------"
if [[ $sysapps ]]
then
  for name in ${sysapps[@]}
  do
    if [[ $name == 'games' || $name == 'gopher' ]]
    then
      echo -e "${NORMAL}RESULT:    ${RED}$name${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    $name${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}No system/application accounts found${NORMAL}"
  fail=1
fi

echo "USER ACCOUNTS:-----------------------------------"
if [[ $usrs ]]
then
  for name in ${usrs[@]}
  do
    echo -e "${NORMAL}RESULT:    $name${NORMAL}"
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}No user accounts found${NORMAL}"
  fail=1
fi
echo "-------------------------------------------------"

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity52, $controlid, $stigid52, $ruleid52, $cci52, $datetime, ${CYN}VERIFY, The ISSO can verify all accounts are valid.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity52, $controlid, $stigid52, $ruleid52, $cci52, $datetime, ${RED}FAILED, No accounts were found.${NORMAL}"
fi
 
echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid53${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid53${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid53${NORMAL}"
echo -e "${NORMAL}CCI:       $cci53${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 53:   ${BLD}$title53a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title53b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title53c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity53${NORMAL}"

IFS='
'

file53="/etc/ssh/sshd_config"

fail=1

permitempty="$(grep -i permitemptypasswords $file53)"
peval="$(echo $permitempty | awk '{print $2}')"

datetime="$(date +%FT%H:%M:%S)"

if [[ $permitempty ]]
then
  if [[ $peval == 'no' && ${permitempty:0:1} != '#' ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$permitempty${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$permitempty${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}'PermitEmptyPasswords' is not defined in $file53${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity53, $controlid, $stigid53, $ruleid53, $cci53, $datetime, ${GRN}PASSED, RHEL 8 does not allow accounts configured with blank or null passwords.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity53, $controlid, $stigid53, $ruleid53, $cci53, $datetime, ${RED}FAILED, RHEL 8 allows accounts configured with blank or null passwords.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid54${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid54${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid54${NORMAL}"
echo -e "${NORMAL}CCI:       $cci54${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 54:   ${BLD}$title54a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title54b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title54c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity54${NORMAL}"

file54="/etc/login.defs"

fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file54 ]]
then
  umask="$(grep -i umask $file54 | grep -v '^#')"
  if [[ $umask ]]
  then
    umaskval="$(echo $umask | awk '{print $2}')"
    if [[ $umaskval == '077' && ${umask:0:1} != '#' ]]
    then
      fail=0
      echo -e "${NORMAL}RESULT:    ${BLD}$umask${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$umask${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}'UMASK' was not found${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file54 was not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity54, $controlid, $stigid54, $ruleid54, $cci54, $datetime, ${GRN}PASSED, RHEL 8 defines default permissions for all authenticated users in such a way that the user can only read and modify their own files.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity54, $controlid, $stigid54, $ruleid54, $cci54, $datetime, ${RED}FAILED, RHEL 8 does not define default permissions for all authenticated users in such a way that the user can only read and modify their own files.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid55${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid55${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid55${NORMAL}"
echo -e "${NORMAL}CCI:       $cci55${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 55:   ${BLD}$title55a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title55b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title55c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity55${NORMAL}"

IFS='
'

file55a="/etc/passwd"
files55b=("/etc/bashrc" "/etc/profile")

fail=0

users="$(awk -F: '($3>=1000)&&($7 !~ /nologin/){print $1,$3,$6}' $file55a)"

datetime="$(date +%FT%H:%M:%S)"

echo "DEFAULT UMASK:---------------------------------------"
for file in ${files55b[@]}
do
  dmask="$(grep -i umask $file | grep -v '#' | awk '{print $2}')"
  for umask in ${dmask[@]}
  do
    if [[ $umask == 077 ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}The default value for UMASK is set to $umask in $file${NORMAL}"
    else
      fail=1
      echo -e "${NORMAL}RESULT:    ${RED}The default value for UMASK is set to $umask in $file${NORMAL}"
    fi
  done
done

if [[ $users ]]
then
  echo "USERS:-----------------------------------------------"
  for user in ${users[@]}
  do
    echo "$user"
  done
  echo "-----------------------------------------------------"
  for user in ${users[@]}
  do
    hdir="$(echo $user | awk -F ' ' '{print $3}')"
    umaskor="$(grep -i umask $hdir/.* 2>/dev/null | awk '{print $2}')"
    if [[ $umaskor ]]
    then
      for umask in ${umaskor[@]}
      do
	      if (( $umask >= 077 ))
        then
          echo -e "${NORMAL}RESULT:    ${BLD}UMASK is overridden to $umask in $hdir${NORMAL}"
        else
          echo -e "${NORMAL}RESULT:    ${RED}UMASK is overridden to $umask in $hdir${NORMAL}"
        fi
      done
    else
      echo -e "${NORMAL}RESULT:    ${BLD}The default UMASK is not overridden in $hdir${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}No user accounts found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity55, $controlid, $stigid55, $ruleid55, $cci55, $datetime, ${GRN}PASSED, RHEL 8 sets the umask value to 077 for all local interactive user accounts.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity55, $controlid, $stigid55, $ruleid55, $cci55, $datetime, ${RED}FAILED, RHEL 8 does not set the umask value to 077 for all local interactive user accounts.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid56${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid56${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid56${NORMAL}"
echo -e "${NORMAL}CCI:       $cci56${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 56:   ${BLD}$title56a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title56b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title56c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity56${NORMAL}"

IFS='
'

file56a="/etc/bashrc"
file56b="/etc/csh.cshrc"
file56c="/etc/profile"

fail=0

mask="$(grep -i umask $file56a $file56b $file56c | grep -v "#" 2>/dev/null)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $mask ]]
then
  for line in ${mask[@]}
  do
    if [[ $line =~ 077 ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
      fail=1
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}\"umask\" is not defined.${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity56, $controlid, $stigid56, $ruleid56, $cci56, $datetime, ${GRN}PASSED, RHEL 8 define default permissions for logon and non-logon shells to umask 077.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity56, $controlid, $stigid56, $ruleid56, $cci56, $datetime, ${RED}FAILED, RHEL 8 does not define default permissions for logon and non-logon shells to umask 077.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid57${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid57${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid57${NORMAL}"
echo -e "${NORMAL}CCI:       $cci57${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 57:   ${BLD}$title57a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title57b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title57c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity57${NORMAL}"

IFS='
'

file57a="/etc/rsyslog.conf"
file57b="/etc/rsyslog.d/*.conf"
fail=1

cronjobs="$(grep -s cron $file57a $file57b | grep -v "#")"

datetime="$(date +%FT%H:%M:%S)"

if [[ $cronjobs ]]
then
  for job in ${cronjobs[@]}
  do
    if [[ $job =~ '/etc/rsyslog.conf' && $job =~ 'cron' ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$job${NORMAL}"
      fail=0
    else
      echo -e "${NORMAL}RESULT:    $job${NORMAL}"
    fi
  done
else
  cronjobs="$(grep -s /var/log/messages $file57a $file57b)"
  if [[ $cronjobs ]]
  then
    for job in ${cronjobs[@]}
    do
      if [[ $job =~ '/var/log/messages' && $job =~ 'cron' ]]
      then
	fail=0
	echo -e "${NORMAL}RESULT:    ${BLD}$job${NORMAL}"
      else
        echo -e "${NORMAL}RESULT:    $job${NORMAL}"
      fi
    done
  else
    echo -e "${NORMAL}RESULT:    ${RED}No cron jobs found${NORMAL}"
  fi
fi

if (( $fail == 0 ))
then
  echo -e "${NORMAL}$hostname, $severity57, $controlid, $stigid57, $ruleid57, $cci57, $datetime, ${GRN}PASSED, Cron logging is implemented.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity57, $controlid, $stigid57, $ruleid57, $cci57, $datetime, ${RED}FAILED, Cron logging is not implemented.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid58${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid58${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid58${NORMAL}"
echo -e "${NORMAL}CCI:       $cci58${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 58:   ${BLD}$title58a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title58b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title58c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity58${NORMAL}"

IFS='
'

file58="/etc/audit/auditd.conf"

locevt="$(grep ^local_events $file58)"
leval="$(echo $locevt | awk -F= '{print $2}')"

datetime="$(date +%FT%H:%M:%S)"

if [[ $locevt ]]
then
  if [[ $leval =~ 'yes' ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$locevt${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$locevt${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}\"local_events\" is not defined in $file58.${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity58, $controlid, $stigid58, $ruleid58, $cci58, $datetime, ${GRN}PASSED, The RHEL 8 audit system audits local events.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity58, $controlid, $stigid58, $ruleid58, $cci58, $datetime, ${RED}FAILED, The RHEL 8 audit system does not audit local events.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid59${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid59${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid59${NORMAL}"
echo -e "${NORMAL}CCI:       $cci59${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 59:   ${BLD}$title59a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title59b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title59c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity59${NORMAL}"

IFS='
'

file59="/etc/audit/auditd.conf"

logfmt="$(grep log_format $file59)"
lfval="$(echo $logfmt | awk -F= '{print $2}')"

fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ $logfmt ]]
then
  if [[ $lfval =~ 'ENRICHED' && ${logmft:0:1} != '#' ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$logfmt${NORMAL}"
  else	
    echo -e "${NORMAL}RESULT:    ${RED}$logfmt${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}\"log_format\" is not defined in $file59.${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity59, $controlid, $stigid59, $ruleid59, $cci59, $datetime, ${GRN}PASSED, RHEL 8 resolves audit information before writing to disk.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity59, $controlid, $stigid59, $ruleid59, $cci59, $datetime, ${RED}FAILED, RHEL 8 does notresolve audit information before writing to disk.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid60${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid60${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid60${NORMAL}"
echo -e "${NORMAL}CCI:       $cci60${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 60:   ${BLD}$title60a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title60b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title60c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity60${NORMAL}"

IFS='
'

fail=1

rslrpm="$(yum list installed rsyslog 2>/dev/null | grep rsyslog)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $rslrpm ]]
then
  fail=0
  for line in ${rslrpm[@]}
  do
    echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}nothing found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity60, $controlid, $stigid60, $ruleid60, $cci60, $datetime, ${GRN}PASSED, RHEL 8 has the packages required for offloading audit logs installed..${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity60, $controlid, $stigid60, $ruleid60, $cci60, $datetime, ${RED}FAILED, RHEL 8 does not have the packages required for offloading audit logs installed.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid61${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid61${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid61${NORMAL}"
echo -e "${NORMAL}CCI:       $cci61${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 61:   ${BLD}$title61a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title61b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title61c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity61${NORMAL}"

IFS='
'

fail=1

rslrpm="$(yum list installed rsyslog-gnutls 2>/dev/null | grep rsyslog-gnutls)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $rslrpm ]]
then
  fail=0
  for line in ${rslrpm[@]}
  do
    echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}nothing found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity61, $controlid, $stigid61, $ruleid61, $cci61, $datetime, ${GRN}PASSED, RHEL 8 has the packages required for encrypting offloaded audit logs installed..${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity61, $controlid, $stigid61, $ruleid61, $cci61, $datetime, ${RED}FAILED, RHEL 8 does not have the packages required for encrypting offloaded audit logs installed.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid62${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid62${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid62${NORMAL}"
echo -e "${NORMAL}CCI:       $cci62${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 62:   ${BLD}$title62a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title62b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title62c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity62${NORMAL}"

sysctlcmd="$(command -v systemctl)"

fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ $sysctlcmd ]]
then
  status="$($sysctlcmd status ctrl-alt-del.target | sed -e 's/^[ \t]*//' )"
  if [[ $status ]]
  then
    for line in ${status[@]}
    do
      if [[ $line =~ "Loaded: masked" ||
	    $line =~ "Active: inactive (dead)"
         ]]
      then
        fail=0
        echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
      elif [[ $line =~ "Loaded: loaded" ||
	      $line =~ "Active: active"
           ]]
      then
        echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
      else
	echo -e "${NORMAL}RESULT:    $line${NORMAL}"
      fi
    done
  else
    echo -e "${NORMAL}RESULT:    ${BLD}ctrl-alt-del.target was not found${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${BLD}'systemctl' command not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity62, $controlid, $stigid62, $ruleid62, $cci62, $datetime, ${GRN}PASSED, The x86 Ctrl-Alt-Delete key sequence is masked (disabled).${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity62, $controlid, $stigid62, $ruleid62, $cci62, $datetime, ${RED}FAILED, The x86 Ctrl-Alt-Delete key sequence is not masked (disabled).${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid63${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid63${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid63${NORMAL}"
echo -e "${NORMAL}CCI:       $cci63${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 63:   ${BLD}$title63a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title63b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title63c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity63${NORMAL}"

IFS='
'

file63="/etc/dconf/db/local.d/*"

fail=1

hasgraphics=0
gninstall="$(yum list installed 2>/dev/null | grep gnome)"
logoutval="$(grep -ir logout $file63 2>/dev/null | awk -F: '{print $2}' | grep ^logout)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $gninstall ]]
then
  for line in ${gninstall[@]}
  do
    if [[ $line =~ 'desktop' || $line =~ 'shell' ]]
    then
      hasgraphics=1
      echo -e "${NORMAL}RESULT:    ${BLD}$line.${NORMAL}"
    fi
  done

  if [[ $hasgraphics == 0 ]]
  then
    fail=2
    echo -e "${NORMAL}RESULT:    ${BLD}A graphical user interface is not installed.${NORMAL}"
  else
    if [[ $logoutval && ${logout:0:1} != '#' ]]
    then
      val="$(echo $logoutval | awk -F= '{print $2}')"
      if [[ $val == \'\' ]]
      then
        fail=0
        echo -e "${NORMAL}RESULT:    ${BLD}$logoutval${NORMAL}"
      else
        echo -e "${NORMAL}RESULT:    ${RED}$logoutval${NORMAL}"
      fi
    else
      echo -e "${NORMAL}RESULT:    ${RED}\"logout\" is not defined in $file63.${NORMAL}"
    fi
  fi
else
  fail=2
  echo -e "${NORMAL}RESULT:    ${BLD}A graphicaluser interface is not installed.${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity63, $controlid, $stigid63, $ruleid63, $cci63, $datetime, ${GRN}PASSED, The x86 Ctrl-Alt-Delete key sequence in RHEL 8 is disabled and a graphical user interface is installed.${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity63, $controlid, $stigid63, $ruleid63, $cci63, $datetime, ${GRN}N/A, A graphical user interface is not installed.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity63, $controlid, $stigid63, $ruleid63, $cci63, $datetime, ${RED}FAILED, The x86 Ctrl-Alt-Delete key sequence in RHEL 8 is not disabled and a graphical user interface is installed.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid64${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid64${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid64${NORMAL}"
echo -e "${NORMAL}CCI:       $cci64${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 64:   ${BLD}$title64a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title64b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title64c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity64${NORMAL}"

IFS='
'

file64="/etc/systemd/system.conf"

fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ $file64 ]]
then
  hasgraphics=0
  gninstall="$(yum list installed 2>/dev/null | grep gnome)"
  ctlaltdel="$(grep -i ctrlaltdelburstaction $file64 2>/dev/null | grep -i ctrlaltdelburstaction | grep -v "^#")"

  if [[ $gninstall ]]
  then
    for line in ${gninstall[@]}
    do
      if [[ $line =~ 'desktop' || $line =~ 'shell' ]]
      then
        hasgraphics=1
        echo -e "${NORMAL}RESULT:    ${BLD}$line.${NORMAL}"
      fi
    done
  
    if [[ $hasgraphics == 0 ]]
    then
      fail=2
      echo -e "${NORMAL}RESULT:    ${BLD}A graphical user interface is not installed.${NORMAL}"
    else
      if [[ $ctlaltdel && ${ctrlaltdel:0:1} != '#' ]]
      then
        val="$(echo $ctlaltdel | awk -F= '{print $2}')"
        if [[ $val == 'none' ]]
        then
          fail=0
          echo -e "${NORMAL}RESULT:    ${BLD}$ctlaltdel${NORMAL}"
        else
          echo -e "${NORMAL}RESULT:    ${RED}$ctlaltdel${NORMAL}"
        fi
      else
        echo -e "${NORMAL}RESULT:    ${RED}\"CtrlAltDelBurstAction\" is not defined in $file64.${NORMAL}"
      fi
    fi
  else
    fail=2
    echo -e "${NORMAL}RESULT:    ${BLD}A graphicaluser interface is not installed.${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file64 not found.${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity64, $controlid, $stigid64, $ruleid64, $cci64, $datetime, ${GRN}PASSED, The x86 Ctrl-Alt-Delete burst key sequence in RHEL 8 is disabled and a graphical user interface is installed.${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity64, $controlid, $stigid64, $ruleid64, $cci64, $datetime, ${GRN}N/A, A graphical user interface is not installed.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity64, $controlid, $stigid64, $ruleid64, $cci64, $datetime, ${RED}FAILED, The x86 Ctrl-Alt-Delete burst key sequence in RHEL 8 is not disabled and a graphical user interface is installed.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid65${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid65${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid65${NORMAL}"
echo -e "${NORMAL}CCI:       $cci65${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 65:   ${BLD}$title65a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title65b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title65c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity65${NORMAL}"

sysctlcmd="$(command -v systemctl)"

fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ $sysctlcmd ]]
then
  status="$($sysctlcmd status debug-shell.service | sed -e 's/^[ \t]*//' )"
  if [[ $status ]]
  then
    for line in ${status[@]}
    do
      if [[ $line =~ "Loaded: masked" ||
	    $line =~ "Active: inactive (dead)" 
         ]]
      then
        failed=0
        echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
      elif [[ ($line =~ "Loaded: loaded") ||
	      ($line =~ "Active: active") ]]
      then
        echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
      else
	echo -e "${NORMAL}RESULT:    $line${NORMAL}"
      fi
    done
  else
    echo -e "${NORMAL}RESULT:    ${BLD}debug-shell.service was not found${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${BLD}'systemctl' command not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity65, $controlid, $stigid65, $ruleid65, $cci65, $datetime, ${GRN}PASSED, The debug-shell.service is masked (disabled).${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity65, $controlid, $stigid65, $ruleid65, $cci65, $datetime, ${RED}FAILED, The debug-shell.service is not masked (disabled).${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid66${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid66${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid66${NORMAL}"
echo -e "${NORMAL}CCI:       $cci66${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 66:   ${BLD}$title66a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title66b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title66c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity66${NORMAL}"

IFS='
'

isinstalled="$(yum list installed  tftp-server 2>/dev/null | grep 'tftp-server')"

fail=0

datetime="$(date +%FT%H:%M:%S)"

if [[ $isinstalled ]]
then
  fail=1
  echo -e "${NORMAL}RESULT:    ${RED}$isinstalled${NORMAL}"
else
  echo -e "${NORMAL}RESULT:    ${BLD}no output${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity66, $controlid, $stigid66, $ruleid66, $cci66, $datetime, ${GRN}PASSED, TFTP server rpms are not installed${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity66, $controlid, $stigid66, $ruleid66, $cci66, $datetime, ${GRN}PASSED, TFTP server rpms are installed${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid67${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid67${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid67${NORMAL}"
echo -e "${NORMAL}CCI:       $cci67${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 67:   ${BLD}$title67a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title67b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title67c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity67${NORMAL}"

IFS='
'

file67="/etc/passwd"

fail=0

accts="$(cat $file67 | awk -F: '$3 == 0 {print $1}')"

datetime="$(date +%FT%H:%M:%S)"

echo "UNRESTRICTED ACCESS ACCOUNTS:------------------"
if [[ $accts ]]
then
  for user in ${accts[@]}
  do
    if [[ $user == 'root' ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$user${NORMAL}"
    else
      fail=1
      echo -e "${NORMAL}RESULT:    ${RED}$user${NORMAL}"
    fi
  done
else
  fail=2
  echo -e "${NORMAL}RESULT:    ${RED}No unrestricted accounts found (including root)${NORMAL}"
fi

if (( $fail == 0 ))
then
   echo -e "${NORMAL}$hostname, $severity67, $controlid, $stigid67, $ruleid67, $cci67, $datetime, ${GRN}PASSED, 'root' is the only account having unrestricted access.${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity67, $controlid, $stigid67, $ruleid67, $cci67, $datetime, ${RED}FAILED, No account, including 'root', has unrestricted access.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity67, $controlid, $stigid67, $ruleid67, $cci67, $datetime, ${RED}FAILED, 'root' is not the only account having unrestricted access.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid68${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid68${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid68${NORMAL}"
echo -e "${NORMAL}CCI:       $cci68${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 68:   ${BLD}$title68a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title68b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title68c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity68${NORMAL}"

IFS='
'

fail=0

datetime="$(date +%FT%H:%M:%S)"

v6disabled="$(cat /sys/module/ipv6/parameters/disable)"
if [[ $v6disabled == 1 ]]
then
  echo -e "${NORMAL}RESULT:    ${BLD}a. IPv6 is disabled${NORMAL}"
  fail=2
else
  echo -e "${NORMAL}RESULT:    ${BLD}a. IPv6 is not disabled${NORMAL}"
fi

acceptredir="$(sysctl net.ipv6.conf.default.accept_redirects)"
if [[ $acceptredir ]]
then
  redirval="$(echo $acceptredir | awk -F= '{print $2}' | sed 's/ //g' 2>/dev/null)"
  if [[ $redirval == 0 && ${acceptredir:0:1} != "#" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}b. $acceptredir${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}b. $acceptredir${NORMAL}"
    fail=1
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}b. \"net.ipv6.conf.default.accept_redirects\" not defined${NORMAL}"
  fail=1
fi

isconfig="$(grep -r net.ipv6.conf.default.accept_redirects /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf 2>/dev/null)"
if [[ $isconfig ]]
then
  for line in ${isconfig[@]}
  do
    isconfigval="$(echo $isconfig | awk -F= '{print $2}' | sed 's/ //g')"
    if [[ $isconfigval != 0 ]]
    then
      echo -e "${NORMAL}RESULT:    ${RED}c. $line${NORMAL}"
      fail=1
    else
      echo -e "${NORMAL}RESULT:    ${BLD}c. $line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}c. \"net.ipv6.conf.default.accept_redirects\" not defined.${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity68, $controlid, $stigid68, $ruleid68, $cci68, $datetime, ${GRN}PASSED, RHEL 8 will not accept IPv6 ICMP redirect messages.${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity68, $controlid, $stigid68, $ruleid68, $cci68, $datetime, ${RED}N/A, IPv6 is disabled by default.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity68, $controlid, $stigid68, $ruleid68, $cci68, $datetime, ${RED}FAILED, RHEL 8 accepts IPv6 ICMP redirect messages or it is not defined in a config file.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid69${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid69${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid69${NORMAL}"
echo -e "${NORMAL}CCI:       $cci69${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 69:   ${BLD}$title69a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title69b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title69c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity69${NORMAL}"

IFS='
'

fail=0

datetime="$(date +%FT%H:%M:%S)"

sendredir="$(sysctl net.ipv4.conf.all.send_redirects)"
if [[ $sendredir ]]
then
  redirval="$(echo $sendredir | awk -F= '{print $2}' | sed 's/ //g' 2>/dev/null)"
  if [[ $redirval == 0 && ${sendredir:0:1} != "#" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}a. $sendredir${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}a. $sendredir${NORMAL}"
    fail=1
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}a. \"net.ipv4.conf.all.send_redirects\" not defined${NORMAL}"
  fail=1
fi

isconfig="$(grep -r net.ipv4.conf.all.send_redirects /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf 2>/dev/null)"
if [[ $isconfig ]]
then
  for line in ${isconfig[@]}
  do
    isconfigval="$(echo $line | awk -F= '{print $2}' | sed 's/ //g')"
    if [[ $isconfigval != 0 ]]
    then
      echo -e "${NORMAL}RESULT:    ${RED}b. $line${NORMAL}"
      fail=1
    else
      echo -e "${NORMAL}RESULT:    ${BLD}b. $line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}b. \"net.ipv4.conf.all.send_redirects\" not defined.${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity69, $controlid, $stigid69, $ruleid69, $cci69, $datetime, ${GRN}PASSED, RHEL 8 does not send IPv4 Internet Control Message Protocol (ICMP) redirects.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity69, $controlid, $stigid69, $ruleid69, $cci69, $datetime, ${RED}FAILED, RHEL 8 sends IPv4 Internet Control Message Protocol (ICMP) redirects or it is not defined in a config file.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid70${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid70${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid70${NORMAL}"
echo -e "${NORMAL}CCI:       $cci70${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 70:   ${BLD}$title70a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title70b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title70c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity70${NORMAL}"

IFS='
'

fail=0

datetime="$(date +%FT%H:%M:%S)"

eignorebc="$(sysctl net.ipv4.icmp_echo_ignore_broadcasts)"
if [[ $eignorebc ]]
then
  ignoreval="$(echo $eignorebc | awk -F= '{print $2}' | sed 's/ //g' 2>/dev/null)"
  if [[ $ignoreval == 1 && ${eignorebc:0:1} != "#" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}a. $eignorebc${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}a. $eignorebc${NORMAL}"
    fail=1
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}a. \"net.ipv4.icmp_echo_ignore_broadcasts\" not defined${NORMAL}"
  fail=1
fi

isconfig="$(grep -r net.ipv4.icmp_echo_ignore_broadcasts /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf 2> /dev/null)"
if [[ $isconfig ]]
then
  for line in ${isconfig[@]}
  do
    isconfigval="$(echo $line | awk -F= '{print $2}' | awk '{print $1}' | sed 's/ //g')"
    if [[ $isconfigval != 1 ]]
    then
      echo -e "${NORMAL}RESULT:    ${RED}b. $line${NORMAL}"
      fail=1
    else
      echo -e "${NORMAL}RESULT:    ${BLD}b. $line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}b. \"net.ipv4.conf.all.send_redirects\" not defined.${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity70, $controlid, $stigid70, $ruleid70, $cci70, $datetime, ${GRN}PASSED, RHEL 8 does not respond to IPv4 Internet Control Message Protocol (ICMP) echoes sent to a broadcast address.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity70, $controlid, $stigid70, $ruleid70, $cci70, $datetime, ${RED}FAILED, .RHEL 8 responds to IPv4 Internet Control Message Protocol (ICMP) echoes sent to a broadcast address or it is not defined in a config file.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid71${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid71${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid71${NORMAL}"
echo -e "${NORMAL}CCI:       $cci71${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 71:   ${BLD}$title71a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title71b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title71c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity71${NORMAL}"

IFS='
'

fail=0

datetime="$(date +%FT%H:%M:%S)"

v6disabled="$(cat /sys/module/ipv6/parameters/disable)"
if [[ $v6disabled == 1 ]]
then
  echo -e "${NORMAL}RESULT:    ${BLD}a. IPv6 is disabled${NORMAL}"
  fail=2
else
  echo -e "${NORMAL}RESULT:    ${BLD}a. IPv6 is not disabled${NORMAL}"
fi

acceptsrcrt="$(sysctl net.ipv6.conf.all.accept_source_route)"
if [[ $acceptsrcrt ]]
then
  srcrtval="$(echo $acceptsrcrt | awk -F= '{print $2}' | sed 's/ //g' 2>/dev/null)"
  if [[ $srcrtval == 0 && ${acceptsrcrt:0:1} != "#" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}b. $acceptsrcrt${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}b. $acceptsrcrt${NORMAL}"
    fail=1
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}b. \"net.ipv6.conf.all.accept_source_route\" not defined${NORMAL}"
  fail=1
fi

isconfig="$(grep -r net.ipv6.conf.all.accept_source_route /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf 2>/dev/null)"
if [[ $isconfig ]]
then
  for line in ${isconfig[@]}
  do
    isconfigval="$(echo $line | awk -F= '{print $2}' | awk '{print $1}' | sed 's/ //g')"
    if [[ $isconfigval != 0 ]]
    then
      echo -e "${NORMAL}RESULT:    ${RED}c. $line${NORMAL}"
      fail=1
    else
      echo -e "${NORMAL}RESULT:    ${BLD}c. $line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}c. \"grep -r net.ipv6.conf.all.accept_source_route\" not defined.${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity71, $controlid, $stigid71, $ruleid71, $cci71, $datetime, ${GRN}PASSED, RHEL 8 does not forward IPv6 source-routed packets.${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity71, $controlid, $stigid71, $ruleid71, $cci71, $datetime, ${RED}N/A, IPv6 is disabled by default.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity71, $controlid, $stigid71, $ruleid71, $cci71, $datetime, ${RED}FAILED, .RHEL 8 forwards IPv6 source-routed packets or it is not defined in a config file.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid72${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid72${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid72${NORMAL}"
echo -e "${NORMAL}CCI:       $cci72${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 72:   ${BLD}$title72a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title72b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title72c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity72${NORMAL}"

IFS='
'

fail=0

datetime="$(date +%FT%H:%M:%S)"

v6disabled="$(cat /sys/module/ipv6/parameters/disable)"
if [[ $v6disabled == 1 ]]
then
  echo -e "${NORMAL}RESULT:    ${BLD}a. IPv6 is disabled${NORMAL}"
  fail=2
else
  echo -e "${NORMAL}RESULT:    ${BLD}a. IPv6 is not disabled${NORMAL}"
fi

acceptsrcrt="$(sysctl net.ipv6.conf.default.accept_source_route)"
if [[ $acceptsrcrt ]]
then
  srcrtval="$(echo $acceptsrcrt | awk -F= '{print $2}' | sed 's/ //g' 2>/dev/null)"
  if [[ $srcrtval == 0 && ${acceptsrcrt:0:1} != "#" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}b. $acceptsrcrt${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}b. $acceptsrcrt${NORMAL}"
    fail=1
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}b. \"net.ipv6.conf.default.accept_source_route\" not defined${NORMAL}"
  fail=1
fi

isconfig="$(grep -r net.ipv6.conf.default.accept_source_route /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf 2>/dev/null)"
if [[ $isconfig ]]
then
  for line in ${isconfig[@]}
  do
    isconfigval="$(echo $line | awk -F= '{print $2}' | awk '{print $1}' | sed 's/ //g')"
    if [[ $isconfigval != 0 ]]
    then
      echo -e "${NORMAL}RESULT:    ${RED}c. $line${NORMAL}"
      fail=1
    else
      echo -e "${NORMAL}RESULT:    ${BLD}c. $line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}c. \"grep -r net.ipv6.conf.default.accept_source_route\" not defined.${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity72, $controlid, $stigid72, $ruleid72, $cci72, $datetime, ${GRN}PASSED, RHEL 8 does not forward IPv6 source-routed packets by default.${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity72, $controlid, $stigid72, $ruleid72, $cci72, $datetime, ${RED}N/A, IPv6 is disabled by default.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity72, $controlid, $stigid72, $ruleid72, $cci72, $datetime, ${RED}FAILED, .RHEL 8 forwards IPv6 source-routed packets by default or it is not defined in a config file.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid73${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid73${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid73${NORMAL}"
echo -e "${NORMAL}CCI:       $cci73${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 73:   ${BLD}$title73a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title73b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title73c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity73${NORMAL}"

IFS='
'

fail=0

datetime="$(date +%FT%H:%M:%S)"

v6disabled="$(cat /sys/module/ipv6/parameters/disable)"
if [[ $v6disabled == 1 ]]
then
  echo -e "${NORMAL}RESULT:    ${BLD}a. IPv6 is disabled${NORMAL}"
  fail=2
else
  echo -e "${NORMAL}RESULT:    ${BLD}a. IPv6 is not disabled${NORMAL}"
fi

allfwd="$(sysctl net.ipv6.conf.all.forwarding)"
if [[ $acceptsrcrt ]]
then
  fwdval="$(echo $allfwd | awk -F= '{print $2}' | sed 's/ //g' 2>/dev/null)"
  if [[ $fwdval == 0 && ${allfwd:0:1} != "#" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}b. $allfwd${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}b. $allfwd${NORMAL}"
    fail=1
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}b. \"net.ipv6.conf.all.forwarding\" not defined${NORMAL}"
  fail=1
fi

isconfig="$(grep -r net.ipv6.conf.all.forwarding /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf 2>/dev/null)"
if [[ $isconfig ]]
then
  for line in ${isconfig[@]}
  do
    isconfigval="$(echo $line | awk -F= '{print $2}' | awk '{print $1}' | sed 's/ //g')"
    if [[ $isconfigval != 0 ]]
    then
      echo -e "${NORMAL}RESULT:    ${RED}c. $line${NORMAL}"
      fail=1
    else
      echo -e "${NORMAL}RESULT:    ${BLD}c. $line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}c. \"net.ipv6.conf.all.forwarding\" not defined.${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity73, $controlid, $stigid73, $ruleid73, $cci73, $datetime, ${GRN}PASSED, RHEL 8 is not performing IPv6 packet forwarding.${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity73, $controlid, $stigid73, $ruleid73, $cci73, $datetime, ${RED}N/A, IPv6 is disabled by default.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity73, $controlid, $stigid73, $ruleid73, $cci73, $datetime, ${RED}FAILED, RHEL 8 is performing IPv6 packet forwarding or it is not defined in a config file.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid74${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid74${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid74${NORMAL}"
echo -e "${NORMAL}CCI:       $cci74${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 74:   ${BLD}$title74a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title74b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title74c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity74${NORMAL}"

IFS='
'

fail=0

datetime="$(date +%FT%H:%M:%S)"

v6disabled="$(cat /sys/module/ipv6/parameters/disable)"
if [[ $v6disabled == 1 ]]
then
  echo -e "${NORMAL}RESULT:    ${BLD}a. IPv6 is disabled${NORMAL}"
  fail=2
else
  echo -e "${NORMAL}RESULT:    ${BLD}a. IPv6 is not disabled${NORMAL}"
fi

allacceptra="$(sysctl net.ipv6.conf.all.accept_ra)"
if [[ $allacceptra ]]
then
  acceptraval="$(echo $allacceptra | awk -F= '{print $2}' | sed 's/ //g' 2>/dev/null)"
  if [[ $acceptraval == 0 && ${allacceptra:0:1} != "#" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}b. $allacceptra${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}b. $allacceptra${NORMAL}"
    fail=1
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}b. \"net.ipv6.conf.all.accept_ra\" not defined${NORMAL}"
  fail=1
fi

isconfig="$(grep -r net.ipv6.conf.all.accept_ra /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf 2>/dev/null)"
if [[ $isconfig ]]
then
  for line in ${isconfig[@]}
  do
    isconfigval="$(echo $line | awk -F= '{print $2}' | awk '{print $1}' | sed 's/ //g')"
    if [[ $isconfigval != 0 ]]
    then
      echo -e "${NORMAL}RESULT:    ${RED}c. $line${NORMAL}"
      fail=1
    else
      echo -e "${NORMAL}RESULT:    ${BLD}c. $line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}c. \"net.ipv6.conf.all.accept_ra\" not defined.${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity74, $controlid, $stigid74, $ruleid74, $cci74, $datetime, ${GRN}PASSED, RHEL 8 does not accept router advertisements on all IPv6 interfaces.${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity74, $controlid, $stigid74, $ruleid74, $cci74, $datetime, ${RED}N/A, IPv6 is disabled by default.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity74, $controlid, $stigid74, $ruleid74, $cci74, $datetime, ${RED}FAILED, RHEL 8 either accepts router advertisements on all IPv6 interfaces or it is not defined in a config file.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid75${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid75${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid75${NORMAL}"
echo -e "${NORMAL}CCI:       $cci75${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 75:   ${BLD}$title75a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title75b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title75c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity75${NORMAL}"

IFS='
'

fail=0

datetime="$(date +%FT%H:%M:%S)"

v6disabled="$(cat /sys/module/ipv6/parameters/disable)"
if [[ $v6disabled == 1 ]]
then
  echo -e "${NORMAL}RESULT:    ${BLD}a. IPv6 is disabled${NORMAL}"
  fail=2
else
  echo -e "${NORMAL}RESULT:    ${BLD}a. IPv6 is not disabled${NORMAL}"
fi

defacceptra="$(sysctl net.ipv6.conf.default.accept_ra)"
if [[ $defacceptra ]]
then
  defacceptraval="$(echo $defacceptra | awk -F= '{print $2}' | sed 's/ //g' 2>/dev/null)"
  if [[ $defacceptraval == 0 && ${defacceptra:0:1} != "#" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}b. $defacceptra${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}b. $defacceptra${NORMAL}"
    fail=1
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}b. \"net.ipv6.conf.default.accept_ra\" not defined${NORMAL}"
  fail=1
fi

isconfig="$(grep -r net.ipv6.conf.default.accept_ra /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf 2>/dev/null)"
if [[ $isconfig ]]
then
  for line in ${isconfig[@]}
  do
    isconfigval="$(echo $line | awk -F= '{print $2}' | awk '{print $1}' | sed 's/ //g')"
    if [[ $isconfigval != 0 ]]
    then
      echo -e "${NORMAL}RESULT:    ${RED}c. $line${NORMAL}"
      fail=1
    else
      echo -e "${NORMAL}RESULT:    ${BLD}c. $line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}c. \"net.ipv6.conf.default.accept_ra\" not defined.${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity75, $controlid, $stigid75, $ruleid75, $cci75, $datetime, ${GRN}PASSED, RHEL 8 does not accept router advertisements on all IPv6 interfaces by default.${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity75, $controlid, $stigid75, $ruleid75, $cci75, $datetime, ${RED}N/A, IPv6 is disabled by default.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity75, $controlid, $stigid75, $ruleid75, $cci75, $datetime, ${RED}FAILED, RHEL 8 either accepts router advertisements on all IPv6 interfaces or it is not defined in a config file.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid76${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid76${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid76${NORMAL}"
echo -e "${NORMAL}CCI:       $cci76${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 76:   ${BLD}$title76a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title76b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title76c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity76${NORMAL}"

IFS='
'

fail=0

datetime="$(date +%FT%H:%M:%S)"

defsendredir="$(sysctl net.ipv4.conf.default.send_redirects)"
if [[ $defsendredir ]]
then
  defsendredirval="$(echo $defsendredir | awk -F= '{print $2}' | sed 's/ //g' 2>/dev/null)"
  if [[ $defsendredirval == 0 && ${defsendredir:0:1} != "#" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}a. $defsendredir${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}a. $defsendredir${NORMAL}"
    fail=1
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}a. \"net.ipv4.conf.default.send_redirects\" not defined${NORMAL}"
  fail=1
fi

isconfig="$(grep -r net.ipv4.conf.default.send_redirects /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf 2> /dev/null)"
if [[ $isconfig ]]
then
  for line in ${isconfig[@]}
  do
    isconfigval="$(echo $line | awk -F= '{print $2}' | awk '{print $1}' | sed 's/ //g')"
    if [[ $isconfigval != 0 ]]
    then
      echo -e "${NORMAL}RESULT:    ${RED}b. $line${NORMAL}"
      fail=1
    else
      echo -e "${NORMAL}RESULT:    ${BLD}b. $line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}b. \"net.ipv4.conf.default.send_redirects\" not defined.${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity76, $controlid, $stigid76, $ruleid76, $cci76, $datetime, ${GRN}PASSED, RHEL 8 does not allow interfaces to perform IPv4 Internet Control Message Protocol (ICMP) redirects by default.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity76, $controlid, $stigid76, $ruleid76, $cci76, $datetime, ${RED}FAILED, RHEL 8 either allows interfaces to perform IPv4 Internet Control Message Protocol (ICMP) redirects by default or it is not defined in a config file.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid77${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid77${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid77${NORMAL}"
echo -e "${NORMAL}CCI:       $cci77${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 77:   ${BLD}$title77a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title77b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title77c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity77${NORMAL}"

IFS='
'

fail=0

datetime="$(date +%FT%H:%M:%S)"

v6disabled="$(cat /sys/module/ipv6/parameters/disable)"
if [[ $v6disabled == 1 ]]
then
  echo -e "${NORMAL}RESULT:    ${BLD}a. IPv6 is disabled${NORMAL}"
  fail=2
else
  echo -e "${NORMAL}RESULT:    ${BLD}a. IPv6 is not disabled${NORMAL}"
fi

allacceptredir="$(sysctl net.ipv6.conf.all.accept_redirects)"
if [[ $allacceptredir ]]
then
  allacceptredirval="$(echo $allacceptredir | awk -F= '{print $2}' | sed 's/ //g' 2>/dev/null)"
  if [[ $allacceptredirval == 0 && ${allacceptredir:0:1} != "#" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}b. $allacceptredir${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}b. $allacceptredir${NORMAL}"
    fail=1
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}b. \"net.ipv6.conf.all.accept_redirects\" not defined${NORMAL}"
  fail=1
fi

isconfig="$(grep -r net.ipv6.conf.all.accept_redirects /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf 2>/dev/null)"
if [[ $isconfig ]]
then
  for line in ${isconfig[@]}
  do
    isconfigval="$(echo $line | awk -F= '{print $2}' | awk '{print $1}' | sed 's/ //g')"
    if [[ $isconfigval != 0 ]]
    then
      echo -e "${NORMAL}RESULT:    ${RED}c. $line${NORMAL}"
      fail=1
    else
      echo -e "${NORMAL}RESULT:    ${BLD}c. $line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}c. \"net.ipv6.conf.all.accept_redirects\" not defined.${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity77, $controlid, $stigid77, $ruleid77, $cci77, $datetime, ${GRN}PASSED, RHEL 8 ignores IPv6 Internet Control Message Protocol (ICMP) redirect messages.${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity77, $controlid, $stigid77, $ruleid77, $cci77, $datetime, ${RED}N/A, IPv6 is disabled by default.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity77, $controlid, $stigid77, $ruleid77, $cci77, $datetime, ${RED}FAILED, RHEL 8 either does not ignore IPv6 Internet Control Message Protocol (ICMP) redirect messages or it is not defined in a config file.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid78${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid78${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid78${NORMAL}"
echo -e "${NORMAL}CCI:       $cci78${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 78:   ${BLD}$title78a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title78b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title78c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity78${NORMAL}"

IFS='
'

file78="/etc/sysctl.d/*.conf"

fail=1

unpriv1="$(sysctl kernel.unprivileged_bpf_disabled)"
unpriv2="$(grep -r kernel.unprivileged_bpf_disabled $file78 2>/dev/null | grep -v '# Per')"
up1=0
up2=0

datetime="$(date +%FT%H:%M:%S)"

if [[ $unpriv1 ]]
then
  unpriv1val="$(echo $unpriv1 | awk -F= '{print $2/ //}')"
  if [[ $unpriv1val == 1 ]]
  then
    up1=1
    echo -e "${NORMAL}RESULT:    ${BLD}a. $unpriv1${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}a. $unpriv1${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}\"kernel.unprivileged_bpf_disabled\" is not defined in sysctl files${NORMAL}"
fi

if [[ $unpriv2 ]]
then
  unpriv2val="$(echo $unpriv2 | awk -F= '{print $2/ //}')"

  if [[ $unpriv2val == 1 ]]
  then
    up2=1
    echo -e "${NORMAL}RESULT:    ${BLD}b. $unpriv2${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}b. $unpriv2${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}b. \"kernel.unprivileged_bpf_disabled\" is not defined in $file78 files${NORMAL}"
  if [[ $up1 == 1 ]]
  then
    fail=2
  fi
fi

if [[ $up1 == 1 && $up2 == 1 ]]
then
  fail=0
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity78, $controlid, $stigid78, $ruleid78, $cci78, $datetime, ${GRN}PASSED, RHEL 8 disables access to network bpf syscall from unprivileged processes.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity78, $controlid, $stigid78, $ruleid78, $cci78, $datetime, ${RED}FAILED, RHEL 8 does not disable access to network bpf syscall from unprivileged processes.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid79${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid79${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid79${NORMAL}"
echo -e "${NORMAL}CCI:       $cci79${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 79:   ${BLD}$title79a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title79b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title79c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity79${NORMAL}"

IFS='
'

file79="/etc/sysctl.d/*.conf"

fail=1
dp1=0
dp2=0

dproc1="$(sysctl kernel.yama.ptrace_scope)"
dproc2="$(grep -r kernel.yama.ptrace_scope $file79 2>/dev/null | grep -v '# Per')"

datetime="$(date +%FT%H:%M:%S)"

if [[ $dproc1 ]]
then
  dproc1val="$(echo $dproc1 | awk -F= '{print $2/ //}')"
  if [[ $dproc1val == 1 ]]
  then
    dp1=1
    echo -e "${NORMAL}RESULT:    ${BLD}a. $dproc1${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}a. $dproc1${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}\"kernel.yama.ptrace_scope\" is not defined in sysctl files${NORMAL}"
fi

if [[ $dproc2 ]]
then
  dproc2val="$(echo $dproc2 | awk -F= '{print $2/ //}')"

  if [[ $dproc2val == 1 ]]
  then
    dp2=1
    echo -e "${NORMAL}RESULT:    ${BLD}b. $dproc2${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}b. $dproc2${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}b. \"kernel.yama.ptrace_scope\" is not defined in $file79 files${NORMAL}"
  if [[ $dp1 == 1 ]]
  then
    fail=2
  fi
fi

if [[ $dp1 == 1 && $dp2 == 1 ]]
then
  fail=0
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity79, $controlid, $stigid79, $ruleid79, $cci79, $datetime, ${GRN}PASSED, RHEL 8 restricts usage of ptrace to descendant processes.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity79, $controlid, $stigid79, $ruleid79, $cci79, $datetime, ${RED}FAILED, RHEL 8 does not restrict usage of ptrace to descendant processes.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid80${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid80${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid80${NORMAL}"
echo -e "${NORMAL}CCI:       $cci80${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 80:   ${BLD}$title80a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title80b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title80c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity80${NORMAL}"

IFS='
'

path95=("/run/sysctl.d" "/usr/local/lib/sysctl.d" "/usr/lib/sysctl.d" "/lib/sysctl.d" "/etc/sysctl.conf" "/etc/sysctl.d")

k1=0
k2=0

kptr="$(sysctl kernel.kptr_restrict)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $kptr ]]
then
  kptr1val="$(echo $kptr | awk -F= '{print $2}' | sed 's/ //g')"
  if [[ $kptr1val == 1 ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}a. $kptr${NORMAL}"
    k1=1
  else
    echo -e "${NORMAL}RESULT:    ${RED}a. $kptr${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}a. $kptr${NORMAL}"
fi

for path in ${path80[@]}
do
  config="$(grep -r kernel.kptr_restrict $path 2>/dev/null)"
  if [[ $config ]]
  then
    kptr2val="$(echo $config | awk -F= '{print $2}' | sed 's/ //g')"
    if [[ $kptr2val == 1 ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}b. $config${NORMAL}"
      k2=1
    else
      echo -e "${NORMAL}RESULT:    ${RED}b. $config${NORMAL}"
      k2=2
    fi
  fi
done
if [[ $k2 == 0 ]]
then
  echo -e "${NORMAL}RESULT:    ${RED}b. Nothing returned${NORMAL}"
fi

if [[ $k1 == 1 && $k2 == 1 ]]
then
  echo -e "${NORMAL}$hostname, $severity80, $controlid, $stigid80, $ruleid80, $cci80, $datetime, ${GRN}PASSED, RHEL 8 restricts exposed kernel pointer addresses access.${NORMAL}"
elif [[ $k1 == 0 && $k2 == 1 ]]
then
  echo -e "${NORMAL}$hostname, $severity80, $controlid, $stigid80, $ruleid80, $cci80, $datetime, ${RED}FAILED, RHEL 8 does not restrict exposed kernel pointer addresses access but it is set in configuration files. Reload for settings to take effect.${NORMAL}"
elif [[ $k1 == 1 && $k2 == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity80, $controlid, $stigid80, $ruleid80, $cci80, $datetime, ${RED}FAILED, RHEL 8 restricts exposed kernel pointer addresses access but it is not configured in listed paths.${NORMAL}"
elif [[ $k1 == 1 && $k2 == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity80, $controlid, $stigid80, $ruleid80, $cci80, $datetime, ${RED}FAILED, RHEL 8 restricts exposed kernel pointer addresses access but there are conflicting settings in config files.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity80, $controlid, $stigid80, $ruleid80, $cci80, $datetime, ${RED}FAILED, RHEL 8 does not restrict exposed kernel pointer addresses access.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid81${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid81${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid81${NORMAL}"
echo -e "${NORMAL}CCI:       $cci81${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 81:   ${BLD}$title81a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title81b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title81c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity81${NORMAL}"

IFS='
'

path81=("/run/sysctl.d" "/usr/local/lib/sysctl.d" "/usr/lib/sysctl.d" "/lib/sysctl.d" "/etc/sysctl.conf" "/etc/sysctl.d")

m1=0
m2=0

munspc="$(sysctl user.max_user_namespaces)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $munspc ]]
then
  mun1val="$(echo $munspc | awk -F= '{print $2}' | sed 's/ //g')"
  if [[ $mun1val == 0 ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}a. $munspc${NORMAL}"
    m1=1
  else
    echo -e "${NORMAL}RESULT:    ${RED}a. $munspc${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}a. $munspc${NORMAL}"
fi

for path in ${path81[@]}
do
  config="$(grep -r user.max_user_namespaces $path 2>/dev/null)"
  if [[ $config ]]
  then
    for line in ${config[@]} 
    do
      if ! [[ $line =~ "#" ]]
      then
        mun2val="$(echo $line | awk -F= '{print $2}' | sed 's/ //g')"
        if [[ $mun2val == 0 ]]
        then
          echo -e "${NORMAL}RESULT:    ${BLD}b. $path:$line${NORMAL}"
          m2=1
        else
          echo -e "${NORMAL}RESULT:    ${RED}b. $path:$line${NORMAL}"
          m2=2
        fi
      fi
    done
  fi
done
if [[ $m2 == 0 ]]
then
  echo -e "${NORMAL}RESULT:    ${RED}b. Nothing returned${NORMAL}"
fi

if [[ $m1 == 1 && $m2 == 1 ]]
then
  echo -e "${NORMAL}$hostname, $severity81, $controlid, $stigid81, $ruleid81, $cci81, $datetime, ${GRN}PASSED, RHEL 8 restricts exposed kernel pointer addresses access.${NORMAL}"
elif [[ $m1 == 0 && $m2 == 1 ]]
then
  echo -e "${NORMAL}$hostname, $severity81, $controlid, $stigid81, $ruleid81, $cci81, $datetime, ${RED}FAILED, RHEL 8 does not restrict exposed kernel pointer addresses access but it is set in configuration files. Reload for settings to take effect.${NORMAL}"
elif [[ $m1 == 1 && $m2 == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity81, $controlid, $stigid81, $ruleid81, $cci81, $datetime, ${RED}FAILED, RHEL 8 restricts exposed kernel pointer addresses access but it is not configured in listed paths.${NORMAL}"
elif [[ $m1 == 1 && $m2 == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity81, $controlid, $stigid81, $ruleid81, $cci81, $datetime, ${RED}FAILED, RHEL 8 restricts exposed kernel pointer addresses access but there are conflicting settings in config files.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity81, $controlid, $stigid81, $ruleid81, $cci81, $datetime, ${RED}FAILED, RHEL 8 does not restrict exposed kernel pointer addresses access.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid82${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid82${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid82${NORMAL}"
echo -e "${NORMAL}CCI:       $cci82${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 82:   ${BLD}$title82a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title82b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title82c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity82${NORMAL}"

IFS='
'

path82=("/run/sysctl.d" "/usr/local/lib/sysctl.d" "/usr/lib/sysctl.d" "/lib/sysctl.d" "/etc/sysctl.conf" "/etc/sysctl.d")

fail=1

v4allrpf="$(sysctl net.ipv4.conf.all.rp_filter)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $v4allrpf ]]
then
  rpfval="$(echo $v4allrpf | awk -F= '{print $2}' | sed 's/ //g' 2>/dev/null)"
  if [[ $rpfval == 1 && ${v4allrpf:0:1} != "#" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}a. $v4allrpf${NORMAL}"
    f1=1
  else
    echo -e "${NORMAL}RESULT:    ${RED}a. $v4allrpf${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}a. \"net.ipv4.conf.all.rp_filter\" not defined${NORMAL}"
fi

for path in ${path82[@]}
do
  config="$(grep -r net.ipv4.conf.all.rp_filter $path 2>/dev/null)"
  if [[ $config ]]
  then
    kptr2val="$(echo $config | awk -F= '{print $2}' | sed 's/ //g')"
    if [[ $kptr2val == 1 ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}b. $config${NORMAL}"
      f2=1
    else
      echo -e "${NORMAL}RESULT:    ${RED}b. $config${NORMAL}"
      f2=2
    fi
  fi
done
if [[ $f2 == 0 ]]
then
  echo -e "${NORMAL}RESULT:    ${RED}b. Nothing returned${NORMAL}"
fi

if [[ $f1 == 1 && $f2 == 1 ]]
then
  echo -e "${NORMAL}$hostname, $severity82, $controlid, $stigid82, $ruleid82, $cci82, $datetime, ${GRN}PASSED, RHEL 8 uses reverse path filtering on all IPv4 interfaces.${NORMAL}"
elif [[ $f1 == 0 && $f2 == 1 ]]
then
  echo -e "${NORMAL}$hostname, $severity82, $controlid, $stigid82, $ruleid82, $cci82, $datetime, ${RED}FAILED, RHEL 8 does not use reverse path filtering on all IPv4 interfaces but it is set in configuration files. Reload for settings to take effect.${NORMAL}"
elif [[ $f1 == 1 && $f2 == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity82, $controlid, $stigid82, $ruleid82, $cci82, $datetime, ${RED}FAILED, RHEL 8 uses reverse path filtering on all IPv4 interfaces but it is not configured in the listed paths.${NORMAL}"
elif [[ $f1 == 1 && $f2 == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity82, $controlid, $stigid82, $ruleid82, $cci82, $datetime, ${RED}FAILED, RHEL 8 must use reverse path filtering on all IPv4 interfaces but there are conflicting settings in config files.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity82, $controlid, $stigid82, $ruleid82, $cci82, $datetime, ${RED}FAILED, RHEL 8 does not use reverse path filtering on all IPv4 interfaces.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid83${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid83${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid83${NORMAL}"
echo -e "${NORMAL}CCI:       $cci83${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 83:   ${BLD}$title83a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title83b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title83c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity83${NORMAL}"

IFS='
'

postfixrpm="$(yum list installed postfix 2>/dev/null | grep postfix)"

fail=0

datetime="$(date +%FT%H:%M:%S)"

if [[ $postfixrpm ]]
then
  echo -e "${NORMAL}RESULT:    ${BLD}$postfixrpm${NORMAL}"
  reject="$(postconf -n smtpd_client_restrictions | sed 's/ //g')"
  if [[ $reject ]]
  then
    rejectvals="$(echo $reject | awk -F= '{print $2}')"
    IFS=','
    for x in ${rejectvals[@]}
    do
      if [[ $x != 'permit_mynetworks' && $x != 'reject' ]]
      then
        fail=1
      fi
    done
    if [[ $fail == 0 ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$rejectvals${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$rejectvals${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}\"smtpd_client_restrictions\" is not defined in postconf${NORMAL}"
    fail=1
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}\"postfix\" is not installed${NORMAL}"
  fail=2
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity83, $controlid, $stigid83, $ruleid83, $cci83, $datetime, ${GRN}PASSED, Unrestricted Mail Relaying: The system prevents unrestricted mail relaying.${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity83, $controlid, $stigid83, $ruleid83, $cci83, $datetime, ${GRN}PASSED, \"postfix\" is not installed. This requirement is Not Applicable.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity83, $controlid, $stigid83, $ruleid83, $cci83, $datetime, ${RED}FAILED, Unrestricted Mail Relaying: The system does not prevent unrestricted mail relaying.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid84${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid84${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid84${NORMAL}"
echo -e "${NORMAL}CCI:       $cci84${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 84:   ${BLD}$title84a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title84b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title84c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity84${NORMAL}"

IFS='
'

file84="aide.conf"
aliases=""
fail=1

isinstalled="$(yum list installed aide 2>/dev/null | grep aide)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $isinstalled ]]
then
  echo -e "${NORMAL}RESULT:    ${BLD}a. $isinstalled${NORMAL}"
  conf="$(find / 2>/dev/null -noleaf -name $file84 2>/dev/null)"
  if [[ $conf ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}b. $conf${NORMAL}"
    rules="$(cat $conf | grep -v '^#' | grep -v '^!' | grep -v '^@@' | grep -v '^[[:lower:]]')"
    if [[ $rules ]]
    then
      # Find all the aliases that contain "+acl"
      echo -e "${NORMAL}RESULT:    RULE ALIASES with \"+xattrs\" in its list of rules-------------"
      for line in ${rules[@]}
      do
        if [[ $line =~ "=" && $line =~ "+xattrs" ]]
        then
	  alias="$(echo $line | awk -F= '{print $1}' | sed 's/ //g')"
	  aliases+=($alias)

	# Check if the alias references another alias
	elif [[ $line =~ "=" ]]
	then
	  alias="$(echo $line | awk -F= '{print $1}' | sed 's/ //g')"
	  references="$(echo $line | awk -F= '{print $2}')"
	  for line in ${aliases[@]}
	  do
            if [[ $references =~ $line ]]
	    then
	      # Add the alias to the array of aliases
	      aliases+=($alias)
	    fi
	  done
        fi
      done

      # Print all the +xattrs aliases
      for line in ${aliases[@]}
      do
	echo -e "${NORMAL}RESULT:    ${BLD}c. $line${NORMAL}"
      done

      echo -e "${NORMAL}RESULT:    RULES that use the "+xattrs" aliases---------------------------"
      for rule in ${rules[@]}
      do
        if [[ $rule =~ "/bin " || $rule =~ "/sbin " ]]
	then
	  for line in ${aliases[@]}
	  do
	    if [[ $rule =~ "=" ]]
	    then
	      for line in ${aliases[@]}
	      do
	        if [[ $rule =~ $line ]]
                then 
                  echo -e "${NORMAL}RESULT:    ${BLD}c. $rule${NORMAL}"
                fi
	      done
            fi
          done  
          echo -e "${NORMAL}RESULT:    ${BLD}c. $rule${NORMAL}"
	  fail=0
        fi
      done
    else
      echo -e "${NORMAL}RESULT:    ${RED}c. The 'xattrs' rules were not found in $file84${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}b. The file $file84 was not found${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}a. AIDE is not installed${NORMAL}"
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity84, $controlid, $stigid84, $ruleid84, $cci84, $datetime, ${GRN}PASSED, AIDE is installed and the 'xattrs' rule is applied in all cases.${NORMAL}"
else 
   echo -e "${NORMAL}$hostname, $severity84, $controlid, $stigid84, $ruleid84, $cci84, $datetime, ${CYN}VERIFY, A rule for \"/bin ALL\" and \"/sbin ALL\" were not found. Have the ISSO verify whether AIDE is in compliance or whether another tool is used.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid85${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid85${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid85${NORMAL}"
echo -e "${NORMAL}CCI:       $cci85${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 85:   ${BLD}$title85a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title85b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title85c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity85${NORMAL}"

IFS='
'

file85="aide.conf"
fail=1
found=0

aliases=()

isinstalled="$(yum list installed aide 2>/dev/null | grep aide)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $isinstalled ]]
then
  echo -e "${NORMAL}RESULT:    ${BLD}a. $isinstalled${NORMAL}"
  conf="$(find / 2>/dev/null -noleaf -name $file85 2>/dev/null)"
  if [[ $conf ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}b. $conf${NORMAL}"
    rules="$(cat $conf | grep -v '^#' | grep -v '^!' | grep -v '^@@' | grep -v '^[[:lower:]]')"
    if [[ $rules ]]
    then
      # Find all the aliases that contain "+acl"
      echo -e "${NORMAL}RESULT:    RULE ALIASES with \"+acl\" in its list of rules-------------"
      for line in ${rules[@]}
      do
        if [[ $line =~ "=" && $line =~ "+acl" ]]
        then
	  alias="$(echo $line | awk -F= '{print $1}' | sed 's/ //g')"
	  aliases+=($alias)

	# Check if the alias references another alias
	elif [[ $line =~ "=" ]]
	then
	  alias="$(echo $line | awk -F= '{print $1}' | sed 's/ //g')"
	  references="$(echo $line | awk -F= '{print $2}')"
	  for line in ${aliases[@]}
	  do
            if [[ $references =~ $line ]]
	    then
	      # Add the alias to the array of aliases
	      aliases+=($alias)
	    fi
	  done
        fi
      done

      # Print all the +acl aliases
      for line in ${aliases[@]}
      do
	echo -e "${NORMAL}RESULT:    ${BLD}c. $line${NORMAL}"
      done

      echo -e "${NORMAL}RESULT:    RULES that use the "+acl" aliases---------------------------"
      for rule in ${rules[@]}
      do
	if ! [[ $rule =~ "=" ]]
	then
	  found=0
	  for line in ${aliases[@]}
	  do
	    if [[ $rule =~ $line ]]
	    then
	      found=1
	    elif [[ $rule =~ "+acl" ]]
	    then
	      found=1
	    fi
	  done
	  if [[ $found == 1 ]]
          then
            echo -e "${NORMAL}RESULT:    ${BLD}c. $rule${NORMAL}"
	    fail=0
	  else
	    echo -e "${NORMAL}RESULT:    ${RED}c. $rule${NORMAL}"
	  fi
	fi
      done
    else
      echo -e "${NORMAL}RESULT:    ${RED}c. The 'acl' rules were not found in $file85${NORMAL}"
      fail=3
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}b. The file $file85 was not found${NORMAL}"
    fail=2
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}a. AIDE is not installed${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity85, $controlid, $stigid85, $ruleid85, $cci85, $datetime, ${GRN}PASSED, AIDE is installed and the \"+acl\" (ACL) rule is applied in all cases.${NORMAL}"
elif [[ $fail == 1 ]]
then
  echo -e "${NORMAL}$hostname, $severity85, $controlid, $stigid85, $ruleidX25, $cci85, $datetime, ${CYN}VERIFY, AIDE is not installed. Have the ISSO verify whether another tool is used.${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity85, $controlid, $stigid85, $ruleid85, $cci85, $datetime, ${RED}FAILED, AIDE is installed but the ACL rule is not applied.${NORMAL}" 
elif [[ $fail == 3 ]]
then
  echo -e "${NORMAL}$hostname, $severity85, $controlid, $stigid85, $ruleid85, $cci85, $datetime, ${RED}FAILED, AIDE is installed but the ACL rule is not applied in all cases.${NORMAL}" 
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid86${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid86${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid86${NORMAL}"
echo -e "${NORMAL}CCI:       $cci86${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 86:   ${BLD}$title86a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title86b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title86c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity86${NORMAL}"

IFS='
'

fail=0

x11rpm="$(rpm -qa | grep xorg | grep server)"
nogui="$(systemctl get-default)"
fail=0

datetime="$(date +%FT%H:%M:%S)"

if [[ $nogui == 'multi-user.target' ]]
then
  fail=0
  echo -e "${NORMAL}RESULT:    ${BLD}a. $nogui${NORMAL}"
else
  fail=1
  echo -e "${NORMAL}RESULT:    ${RED}a. $nogui${NORMAL}" 
fi

if [[ $x11rpm ]]
then
   for rpm in ${x11rpm[@]}
   do
     echo -e "${NORMAL}RESULT:    ${RED}b. $rpm${NORMAL}"
   done
fi

if (( $fail == 0 ))
then
   echo -e "${NORMAL}$hostname, $severity86, $controlid, $stigid86, $ruleid86, $cci86, $datetime, ${GRN}PASSED, A Windows display manager is not installed${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity86, $controlid, $stigid86, $ruleid86, $cci86, $datetime, ${RED}FAILED, A Windows display manager is installed${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid87${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid87${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid87${NORMAL}"
echo -e "${NORMAL}CCI:       $cci87${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 87:   ${BLD}$title87a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title87b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title87c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity87${NORMAL}"

IFS='
'

fail=0

iflist="$(ifconfig | grep flags)"
ifpromiscuous="$(ip link | grep -i promisc)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $iflist ]]
then
  for line in ${iflist[@]}
  do
    if [[ $line =~ "PROMISC" || $line =~ "promisc" ]]
    then
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
      fail=1
    else
      echo -e "${NORMAL}RESULT:    $line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}No interfaces found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity87, $controlid, $stigid87, $ruleid87, $cci87, $datetime, ${GRN}PASSED, There are no network interfaces in promiscuous mode${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity87, $controlid, $stigid87, $ruleid87, $cci87, $datetime, ${RED}FAILED, There are network interfaces in promiscuous mode${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid88${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid88${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid88${NORMAL}"
echo -e "${NORMAL}CCI:       $cci88${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 88:   ${BLD}$title88a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title88b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title88c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity88${NORMAL}"

IFS='
'

dir88="/etc/ssh/"
fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ -d $dir88 ]]
then
  x11forward="$(grep -ir x11forwarding $dir88 | grep -v '^#')"
  if [[ $x11forward ]]
  then
    for line in ${x11forward[@]}
    do
      x11forwardval="$(echo $line | awk '{print $2}')"
      if [[ $x11forwardval == 'no' ]]
      then
        fail=0
        echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
      else
        echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
      fi
    done
  else
    echo -e "${NORMAL}RESULT:    ${BLD}X11Forwarding is not defined in $dir88${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${BLD}$dir88 was not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity88, $controlid, $stigid88, $ruleid88, $cci88, $datetime, ${GRN}PASSED, Remote X connections for interactive users are disabled${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity88, $controlid, $stigid88, $ruleid88, $cci88, $datetime, ${RED}FAILED, Remote X connections for interactive users are not disabled${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid89${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid89${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid89${NORMAL}"
echo -e "${NORMAL}CCI:       $cci89${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 89:   ${BLD}$title89a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title89b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title89c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity89${NORMAL}"

IFS='
'

dir89="/etc/ssh"
fail=1

datetime="$(date +%FT%H:%M:%S)"

x11fwd="$(grep -ir x11uselocalhost $dir89)"
if [[ $x11fwd ]]
then
  for line in ${x11fwd[@]}
  do
    x11fwdval="$(echo $line | awk '{print $2}')"
    if [[ $x11fwdval == 'yes' && ${line:0:1} =~ ':#' ]]
    then
      fail=0
      echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}\"x11UseLocalhost\" is not defined in $dir89${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity89, $controlid, $stigid89, $ruleid89, $cci89, $datetime, ${GRN}PASSED, The RHEL 8 SSH daemon prevents remote hosts from connecting to the proxy display.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity89, $controlid, $stigid89, $ruleid89, $cci89, $datetime, ${RED}FAILED, The RHEL 8 SSH daemon does not prevent remote hosts from connecting to the proxy display.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid90${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid90${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid90${NORMAL}"
echo -e "${NORMAL}CCI:       $cci90${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 90:   ${BLD}$title90a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title90b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title90c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity90${NORMAL}"

IFS='
'

fail=1

file90="/etc/xinetd.d/tftp"

isinstalled="$(yum list installed tftp-server 2>/dev/null | grep tftp-server)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $isinstalled ]]
then
  for pkg in ${isinstalled[@]}
  do
    echo -e "${NORMAL}RESULT:    ${BLD}$pkg${NORMAL}"
  done
  if [[ -f $file90 ]]
  then
    args="$(grep server_args $file90)"
    if [[ $args ]]
    then
      argsval="$(echo $args | awk -F= '{print $2}')"
      if [[ $args =~ '-s /var/lib/tftpboot' && ${args:0:1} != '#' ]]
      then
        fail=0
        echo -e "${NORMAL}RESULT:    ${BLD}$args${NORMAL}"
      else
        echo -e "${NORMAL}RESULT:    ${RED}$args${NORMAL}"
      fi
    else
      echo -e "${NORMAL}RESULT:    ${RED}\"server-args\" is not defined in $file90${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}$file90 not found${NORMAL}"
  fi
else
  fail=0
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity90, $controlid, $stigid90, $ruleid90, $cci90, $datetime, ${GRN}PASSED, The TFTP Server packages is not installed${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity90, $controlid, $stigid90, $ruleid90, $cci90, $datetime, ${RED}FAILED, The TFTP Server packages is installed, and $fileX37 is not configured to operate in secure mode${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid91${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid91${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid91${NORMAL}"
echo -e "${NORMAL}CCI:       $cci91${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 91:   ${BLD}$title91a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title91b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title91c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity91${NORMAL}"

IFS='
'
fail=1

isinstalled="$(yum list installed *ftpd* 2>/dev/null | grep ftpd)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $isinstalled ]]
then
   for pkg in ${isinstalled[@]}
   do
      echo -e "${NORMAL}RESULT:    ${BLD}$pkg${NORMAL}"
   done
else
  fail=0
   echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity91, $controlid, $stigid91, $ruleid91, $cci91, $datetime, ${GRN}PASSED, A File TransferProtocol (FTP) server is not installed.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity91, $controlid, $stigid91, $ruleid91, $cci91, $datetime, ${RED}FAILED, A File Transfer Protocol (FTP) server is installed.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid92${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid92${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid92${NORMAL}"
echo -e "${NORMAL}CCI:       $cci92${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 92:   ${BLD}$title92a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title92b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title92c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity92${NORMAL}"

IFS='
'
fail=1

isinstalled="$(yum list installed iprutils 2>/dev/null | grep iprutils)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $isinstalled ]]
then
   for pkg in ${isinstalled[@]}
   do
      echo -e "${NORMAL}RESULT:    ${BLD}$pkg${NORMAL}"
   done
else
  fail=0
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity92, $controlid, $stigid92, $ruleid92, $cci92, $datetime, ${GRN}PASSED, The \"iprutils\" package is not installed.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity92, $controlid, $stigid92, $ruleid92, $cci92, $datetime, ${RED}FAILED, The \"iprutils\" package is installed.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid93${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid93${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid93${NORMAL}"
echo -e "${NORMAL}CCI:       $cci93${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 93:   ${BLD}$title93a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title93b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title93c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity93${NORMAL}"

IFS='
'
fail=1

isinstalled="$(yum list installed tuned 2>/dev/null | grep tuned)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $isinstalled ]]
then
   for pkg in ${isinstalled[@]}
   do
      echo -e "${NORMAL}RESULT:    ${BLD}$pkg${NORMAL}"
   done
else
  fail=0
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity93, $controlid, $stigid93, $ruleid93, $cci93, $datetime, ${GRN}PASSED, The \"tuned\" package is not installed.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity93, $controlid, $stigid93, $ruleid93, $cci93, $datetime, ${RED}FAILED, The \"tuned\" package is installed.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid94${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid94${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid94${NORMAL}"
echo -e "${NORMAL}CCI:       $cci94${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 94:   ${BLD}$title94a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title94b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title94c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity94${NORMAL}"

IFS='
'

fail=0

sudoers="$(grep -iw 'ALL' /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep -v ':#')"

datetime="$(date +%FT%H:%M:%S)"

if [[ $sudoers ]]
then
  for line in ${sudoers[@]}
  do
    rule="$(echo $line | awk '{print $1,$2,$3}')"
    if [[ $rule =~ 'ALL ALL=ALL ALL' || $rule =~ 'ALL ALL=(ALL:ALL) ALL' ]]
    then
      fail=1
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
    fi
  done
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity94, $controlid, $stigid94, $ruleid94, $cci94, $datetime, ${GRN}PASSED, RHEL 8 restricts privilege elevation to authorized personnel.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity94, $controlid, $stigid94, $ruleid94, $cci94, $datetime, ${RED}FAILED, RHEL 8 does not restricts privilege elevation to authorized personnel.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid95${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid95${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid95${NORMAL}"
echo -e "${NORMAL}CCI:       $cci95${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 95:   ${BLD}$title95a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title95b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title95c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity95${NORMAL}"

IFS='
'
fail=1

isinstalled="$(yum list installed rng-tools 2>/dev/null | grep rng-tools)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $isinstalled ]]
then
   for pkg in ${isinstalled[@]}
   do
      echo -e "${NORMAL}RESULT:    ${BLD}$pkg${NORMAL}"
      fail=0
   done
else
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity95, $controlid, $stigid95, $ruleid95, $cci95, $datetime, ${GRN}PASSED, The \"rng-tools\" package is not installed.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity95, $controlid, $stigid95, $ruleid95, $cci95, $datetime, ${RED}FAILED, The \"rng-tools\" package is installed.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid96${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid96${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid96${NORMAL}"
echo -e "${NORMAL}CCI:       $cci96${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 96:   ${BLD}$title96a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title96b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title96c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity96${NORMAL}"

IFS='
'

dir96="/etc/ssh"

fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ -d $dir96 ]]
then
  gssapiauth="$(grep -ir gssapiauthentication $dir96 2>/dev/null | grep -v ":#" | grep -i gssapiauthentication)"
  if [[ $gssapiauth ]]
  then
    for line in ${gssapiauth[@]}
    do
      gssapiauthval="$(echo $line | awk -F "GSSAPIAuthentication" '{print $2}' | sed 's/ //g')"
      if [[ $gssapiauthval == 'no' ]]
      then
        echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
	g1=1
      else
        echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
        g2=1
      fi
    done
  else
    echo -e "${NORMAL}RESULT:    ${BLD}GSSAPIAuthentication is not defined in $dir96${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${BLD}$dir96 not found${NORMAL}"
fi

if [[ $g1 == 1 && $g2 == 1 ]]
then
  fail=2
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity96, $controlid, $stigid96, $ruleid96, $cci96, $datetime, ${GRN}PASSED, The SSH daemon does not allow GSSAPI authentication${NORMAL}"
elif [[ $fail == 2 ]]
then
echo -e "${NORMAL}$hostname, $severity96, $controlid, $stigid96, $ruleid96, $cci96, $datetime, ${RED}FAILED, There are conflicting results for \"GSAPIAuthentication\" in $dir27${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity96, $controlid, $stigid96, $ruleid96, $cci96, $datetime, ${RED}FAILED, The SSH daemon allows GSSAPI authentication${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid97${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid97${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid97${NORMAL}"
echo -e "${NORMAL}CCI:       $cci97${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 97:   ${BLD}$title97a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title97b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title97c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity97${NORMAL}"

IFS='
'

file97="/etc/fstab"
fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file97 ]]
then
   fsys="$(df -hl)"
   for fs in ${fsys[@]}
   do
      echo $fs
   done
   echo "-----------------------------------------------------"
   for fs in ${fsys[@]}
   do
      mnt="$(echo $fs | awk '{print $6}')"
      if [[ $mnt == '/var/tmp' ]]
      then
         fail=0
         echo -e "${NORMAL}RESULT:    ${BLD}$fs${NORMAL}"
      fi
   done

   if [[ $fail == 1 ]]
   then
      echo -e "${NORMAL}RESULT:    ${RED}A separate file system for /var/tmp was not found${NORMAL}"
      echo -e "${NORMAL}$hostname, $severity97, $controlid, $stigid97, $ruleid97, $cci97, $datetime, ${RED}FAILED, A separate file system for /var/tmp does not exist${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity97, $controlid, $stigid97, $ruleid97, $cci97, $datetime, ${GRN}PASSED, A separate file system for /var/tmp exists${NORMAL}"
   fi
else
   echo -e "${NORMAL}$hostname, $severity97, $controlid, $stigid97, $ruleid97, $cci97, $datetime, ${RED}FAILED, $file102 not found${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid98${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid98${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid98${NORMAL}"
echo -e "${NORMAL}CCI:       $cci98${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 98:   ${BLD}$title98a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title98b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title98c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity98${NORMAL}"

IFS='
'

fail=0

bootmnt="$(mount | grep '\s/boot/efi\s')"

datetime="$(date +%FT%H:%M:%S)"

if [[ $bootmnt ]]
then
  if [[ $bootmnt =~ 'nosuid' ]]
  then
    echo  -e "${NORMAL}RESULT:    ${BLD}$bootmnt${NORMAL}"
  else
    echo  -e "${NORMAL}RESULT:    ${RED}$bootmnt${NORMAL}"
    fail=1
  fi
else
  echo  -e "${NORMAL}RESULT:    ${RED}no /boot/efi mount found${NORMAL}"
  fail=2
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity98, $controlid, $stigid98, $ruleid98, $cci98, $datetime, ${GRN}PASSED, RHEL 8 prevents files with the setuid and setgid bit set from being executed on the /boot/efi directory.${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity98, $controlid, $stigid98, $ruleid98, $cci98, $datetime, ${GRN}N/A, The RHEL 8 host uses BIOS.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity98, $controlid, $stigid98, $ruleid98, $cci98, $datetime, ${RED}FAILED, RHEL 8 does not prevent files with the setuid and setgid bit set from being executed on the /boot/efi directory.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid99${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid99${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid99${NORMAL}"
echo -e "${NORMAL}CCI:       $cci99${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 99:   ${BLD}$title99a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title99b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title99c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity99${NORMAL}"

IFS='
'

fail=0

file99a="/etc/passwd"
file99b="/etc/fstab"

users="$(awk -F: '($3>=1000)&&($7 !~ /nologin/){print $1,$3,$6}' $file99a)"
declare -a hdirarr

datetime="$(date +%FT%H:%M:%S)"

if [[ $users ]]
then
  echo "USERS:-----------------------------------------------"
  for user in ${users[@]}
  do
    echo "$user"
  done
  echo "-----------------------------------------------------"
  for user in ${users[@]}
  do
    hdir="$(echo $user | awk '{print $3}')"
    uhdfilesndirs="$(ls -lLR $hdir 2>/dev/null | grep -v '^total')"
    for filendir in ${uhdfilesndirs[@]}
    do
      if [[ ${filendir:0:1} == "/" ]]
      then
        hd="$(echo ${filendir%?})"
      elif [[ ${filendir:0:1} == "d" ]]
      then
	file="$(echo $filendir | awk '{print $9}')"
	mode="$(stat -c %a $hdir/$file)"
	if (( ${mode:0:1} <= 7 &&
	      ${mode:1:1} <= 5 &&
	      ${mode:2:1} == 0
           ))
	then
          echo -e "${NORMAL}RESULT:    ${BLD}$hdir: $filendir ($mode)" ${NORMAL} 
	else
          fail=1
          echo -e "${NORMAL}RESULT:    ${RED}$hdir: $filendir ($mode)" ${NORMAL}
	fi
      else
	file="$(echo $filendir | tr -s ' ' | sed 's/ /&=/8' | awk -F= '{print $2}')"
	mode="$(stat -c %a $hd/$file)"
        if (( ${mode:0:1} <= 7 &&
              ${mode:1:1} <= 5 &&
              ${mode:2:1} == 0 
           ))   
	then
	  echo -e "${NORMAL}RESULT:    ${BLD}$hd: $filendir ($mode)" ${NORMAL}
        else
	  fail=1
	  echo -e "${NORMAL}RESULT:    ${RED}$hd: $filendir ($mode)" ${NORMAL}
	fi
      fi
    done
  done
  echo "-----------------------------------------------------"
fi  

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity99, $controlid, $stigid99, $ruleid99, $cci99, $datetime, ${GRN}PASSED, All RHEL 8 local interactive user home directory files and directories are mode 0750 or are less permissive.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity99, $controlid, $stigid99, $ruleid99, $cci99, $datetime, ${RED}FAILED, All RHEL 8 local interactive user home directory files and directories are not mode 0750 or less permissive.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid100${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid100${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid100${NORMAL}"
echo -e "${NORMAL}CCI:       $cci100${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 100:  ${BLD}$title100a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title100b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title100c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity100${NORMAL}"

IFS='
'

file100a="/etc/passwd"
file100b="/etc/shadow"
fail=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file100a && -f $file100b ]]
then
   usraccts="$(awk -F: '($2 != "*" && $2 != "!!") {print $1}' $file100b)"
   for account in ${usraccts[@]}
   do
      IFS=' ' ismemberof="$(groups $account | awk -F: '{print $2}' | sed -e 's/ //')" IFS=$'\n'
      echo
      echo -e "${NORMAL}RESULT:    ${BLD}$account's groups: $ismemberof${NORMAL}"
      echo "------------------------------------------------------------------"
      usracct="$(grep $account $file100a)"
      homedir="$(echo $usracct | awk -F: '{print $6}')"
      if [[ -d $homedir ]]
      then
         hdirperm="$(ls -ld $homedir)"
         gowner="$(ls -ld $homedir | awk '{print $4}')"
         IFS=' ' ismemberof="$(groups $account | awk -F: '{print $2}' | sed -e 's/ //')" IFS=$'\n'
         subtree="$(ls -ilR $homedir | grep -v 'total' | grep -v '/')"
         if [[ $subtree ]]
         then
            for line in ${subtree[@]}
            do
               if [[ $line != "" ]]
               then
                  subgowner="$(echo $line | awk '{print $5}')"
                  if [[ ! $ismemberof =~ $subgowner ]]
                  then
                     echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
                     fail=1
                  else
                     echo -e "${NORMAL}RESULT:    $line${NORMAL}"
                  fi
               fi
            done
         else
            echo -e "${NORMAL}RESULT:    ${RED}No subfiles and folders found under $homedir${NORMAL}"
            fail=1
         fi
         if (( $fail == 0 ))
         then
            echo -e "${NORMAL}RESULT:    ${BLD}All subfiles and folders for $homedir are group-owned by one of $account's groups${NORMAL}"
         else
            echo -e "${NORMAL}RESULT:    ${BLD}All subfiles and folders for $homedir are not group-owned by one of $account's groups${NORMAL}"
         fi
      else
         echo -e "${NORMAL}RESULT:    $homedir does not exist${NORMAL}"
      fi
   done
   if (( $fail == 0 ))
   then
      echo -e "${NORMAL}$hostname, $severity100, $controlid, $stigid100, $ruleid100, $cci100, $datetime, ${GRN}PASSED, All files and directories contained in local interactive user home directories are group-owned by a group of which the home directory owner is a member.${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity100, $controlid, $stigid100, $ruleid100, $cci100, $datetime, ${RED}FAILED, All files and directories contained in local interactive user home directories are not group-owned by a group of which the home directory owner is a member.${NORMAL}"
   fi
else
   echo -e "${NORMAL}$hostname, $severity100, $controlid, $stigid100, $ruleid100, $cci100, $datetime, ${RED}FAILED, $file100a and $file100b were not found.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid101${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid101${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid101${NORMAL}"
echo -e "${NORMAL}CCI:       $cci101${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 101:  ${BLD}$title101a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title101b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title101c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity101${NORMAL}"

IFS='
'
fail=1

gsdul="$(gsettings get org.gnome.login-screen disable-user-list)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $gsdul == "true" ]]
then
  fail=0
  echo  -e "${NORMAL}RESULT:    ${BLD}disable-user-list=$gsdul${NORMAL}"
else
  echo  -e "${NORMAL}RESULT:    ${RED}disable-user-list=$gsdul${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity101, $controlid, $stigid101, $ruleid101, $cci101, $datetime, ${GRN}PASSED, RHEL 8 disables the user list at logon for graphical user interfaces..${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity101, $controlid, $stigid101, $ruleid101, $cci101, $datetime, ${RED}FAILED, RHEL 8 does not disable the user list at logon for graphical user interfaces."${NORMAL}
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid102${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid102${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid102${NORMAL}"
echo -e "${NORMAL}CCI:       $cci102${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 102:  ${BLD}$title102a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title102b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title102c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity102${NORMAL}"

IFS='
'
file102="/etc/pam.d/system-auth"

fail=0

nullok="$(grep -i nullok $file102)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $nullok ]]
then
  fail=1
  for line in ${nullok[@]}
  do
    echo  -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
  done
else
  echo  -e "${NORMAL}RESULT:    ${BLD}no output${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity102, $controlid, $stigid102, $ruleid102, $cci102, $datetime, ${GRN}PASSED, RHEL 8 does not allow blank or null passwords in the system-auth file.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity102, $controlid, $stigid102, $ruleid102, $cci102, $datetime, ${RED}FAILED, RHEL 8 allows blank or null passwords in the system-auth file."${NORMAL}
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid103${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid103${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid1036${NORMAL}"
echo -e "${NORMAL}CCI:       $cci103${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 103:  ${BLD}$title103a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title103b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title103c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity103${NORMAL}"

IFS='
'
file103="/etc/pam.d/password-auth"

fail=0

nullok="$(grep -i nullok $file103)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $nullok ]]
then
  fail=1
  for line in ${nullok[@]}
  do
    echo  -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
  done
else
  echo  -e "${NORMAL}RESULT:    ${BLD}no output${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity103, $controlid, $stigid103, $ruleid103, $cci103, $datetime, ${GRN}PASSED, RHEL 8 does not allow blank or null passwords in the password-auth file.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity103, $controlid, $stigid103, $ruleid103, $cci103, $datetime, ${RED}FAILED, RHEL 8 allows blank or null passwords in the password-auth file."${NORMAL}
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid104${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid104${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid104${NORMAL}"
echo -e "${NORMAL}CCI:       $cci104${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 104:  ${BLD}$title104a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title104b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title104c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity104${NORMAL}"

IFS='
'

file104="/etc/sysctl.d/*.conf"

fail=1

datetime="$(date +%FT%H:%M:%S)"

# Check if IPv4 is disabled by default
isdisabled="$(grub2-editenv - list | grep kernelopts)"
echo "BOOT CONFIGURATION:------------------------------"
if [[ $isdisabled =~ 'ipv4.disable=1' ]]
then
  fail=3
  echo -e "${NORMAL}RESULT:    ${RED}a. $isdisabled${NORMAL}"
else
  echo -e "${NORMAL}RESULT:    ${RED}a. $isdisabled${NORMAL}"
  echo "IPv4 CONFIGURATION:-----------------------------"

  v4car1="$(sysctl net.ipv4.conf.default.accept_redirects)"
  v4car2="$(grep -r net.ipv4.conf.default.accept_redirects $file104 2>/dev/null | grep -v '# Per')"
  v41=0
  v42=0
  
  if [[ $v4car1 ]]
  then
    v4car1val="$(echo $v4car1 | awk -F= '{print $2/ //}')"
    if [[ $v4car1val == 0 ]]
    then
      v41=1
      echo -e "${NORMAL}RESULT:    ${BLD}b. $v4car1${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}b. $v4car1${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}\"net.ipv4.conf.default.accept_redirects\" is not defined in sysctl files${NORMAL}"
  fi
  
  if [[ $v4car2 ]]
  then
    for file in ${v4car2[@]}
    do
      v4car2val="$(echo $v4car2 | awk -F= '{print $2/ //}')"
      if [[ $v4car2val == 0 ]]
      then
        v42filenum="$(echo $v4car2 | awk -F: '{print $1}' | awk -F"/" '{print $4}' | cut -c -3)"
        if [[ $v42filenum == "99-" ]]
        then
	  v42=1
          echo -e "${NORMAL}RESULT:    ${BLD}c. $v4car2${NORMAL}"
        else
	  fail=2
	  echo -e "${NORMAL}RESULT:    ${RED}c. $v4car2${NORMAL}"
	fi
      else
        echo -e "${NORMAL}RESULT:    ${RED}c. $v4car2${NORMAL}"
      fi
    done
  else
    echo -e "${NORMAL}RESULT:    ${RED}c. \"net.ipv4.conf.default.accept_redirects\" is not defined in $file104 files${NORMAL}"
    if [[ $v61 == 1 ]]
    then
      fail=2
    fi
  fi
 
  if [[ $v41 == 1 && $v42 == 1 ]]
  then
    fail=0
  fi
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity104, $controlid, $stigid104, $ruleid104, $cci104, $datetime, ${GRN}PASSED, RHEL 8 prevents IPv4 Internet Control Message Protocol (ICMP) redirect messages from being accepted.${NORMAL}"
elif [[ $fail == 3 ]]
then
  echo -e "${NORMAL}$hostname, $severity104, $controlid, $stigid104, $ruleid104, $cci104, $datetime, ${GRN}PASSED, This requirement is Not Applicable because IPv4 is disabled on the system.${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity104, $controlid, $stigid104, $ruleid104, $cci104, $datetime, ${RED}FAILED, RHEL 8 prevents IPv4 Internet Control Message Protocol (ICMP) redirect messages from being accepted but the file it's configured in does not begin with '99-'.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity104, $controlid, $stigid104, $ruleid104, $cci104, $datetime, ${RED}FAILED, RHEL 8 does not prevent IPv4 Internet Control Message Protocol (ICMP) redirect messages from being accepted.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid105${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid105${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid105${NORMAL}"
echo -e "${NORMAL}CCI:       $cci105${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 105:  ${BLD}$title105a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title105b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title105c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity105${NORMAL}"

IFS='
'

file105="/etc/sysctl.d/*.conf"

fail=1

datetime="$(date +%FT%H:%M:%S)"

# Check if IPv4 is disabled by default
isdisabled="$(grub2-editenv - list | grep kernelopts)"
echo "BOOT CONFIGURATION:------------------------------"
if [[ $isdisabled =~ 'ipv4.disable=1' ]]
then
  fail=3
  echo -e "${NORMAL}RESULT:    ${RED}a. $isdisabled${NORMAL}"
else
  echo -e "${NORMAL}RESULT:    ${RED}a. $isdisabled${NORMAL}"
  echo "IPv4 CONFIGURATION:-----------------------------"

  v4caasr1="$(sysctl net.ipv4.conf.all.accept_source_route)"
  v4caasr2="$(grep -r net.ipv4.conf.all.accept_source_route $file105 2>/dev/null | grep -v '# Per')"
  v41=0
  v42=0
  
  if [[ $v4caasr1 ]]
  then
    v4caasr1val="$(echo $v4caasr1 | awk -F= '{print $2/ //}')"
    if [[ $v4caasr1val == 0 ]]
    then
      v41=1
      echo -e "${NORMAL}RESULT:    ${BLD}b. $v4caasr1${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}b. $v4caasr1${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}\"net.ipv4.conf.all.accept_source_route\" is not defined in sysctl files${NORMAL}"
  fi
  
  if [[ $v4caasr2 ]]
  then
    for file in ${v4caasr2[@]}
    do
      v4caasr2val="$(echo $v4caasr2 | awk -F= '{print $2/ //}')"
      if [[ $v4caasr2val == 0 ]]
      then
        v42filenum="$(echo $v4caasr2 | awk -F: '{print $1}' | awk -F"/" '{print $4}' | cut -c -3)"
        if [[ $v42filenum == "99-" ]]
        then
	  v42=1
          echo -e "${NORMAL}RESULT:    ${BLD}c. $v4caasr2${NORMAL}"
        else
	  fail=2
	  echo -e "${NORMAL}RESULT:    ${RED}c. $v4caasr2${NORMAL}"
	fi
      else
        echo -e "${NORMAL}RESULT:    ${RED}c. $v4caasr2${NORMAL}"
      fi
    done
  else
    echo -e "${NORMAL}RESULT:    ${RED}c. \"net.ipv4.conf.all.accept_source_route\" is not defined in $file105 files${NORMAL}"
    if [[ $v61 == 1 ]]
    then
      fail=2
    fi
  fi
 
  if [[ $v41 == 1 && $v42 == 1 ]]
  then
    fail=0
  fi
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity105, $controlid, $stigid105, $ruleid105, $cci105, $datetime, ${GRN}PASSED, RHEL 8 does not forward IPv4 source-routed packets.${NORMAL}"
elif [[ $fail == 3 ]]
then
  echo -e "${NORMAL}$hostname, $severity105, $controlid, $stigid105, $ruleid105, $cci105, $datetime, ${GRN}PASSED, This requirement is Not Applicable because IPv4 is disabled on the system.${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity105, $controlid, $stigid105, $ruleid105, $cci105, $datetime, ${RED}FAILED, RHEL 8 does not forward IPv4 source-routed packets but the file it's configured in does not begin with '99-'.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity105, $controlid, $stigid105, $ruleid105, $cci105, $datetime, ${RED}FAILED, RHEL 8 forwards IPv4 source-routed packets.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid106${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid106${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid106${NORMAL}"
echo -e "${NORMAL}CCI:       $cci106${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 106:  ${BLD}$title106a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title106b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title106c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity106${NORMAL}"

IFS='
'

file106="/etc/sysctl.d/*.conf"

fail=1

datetime="$(date +%FT%H:%M:%S)"

# Check if IPv4 is disabled by default
isdisabled="$(grub2-editenv - list | grep kernelopts)"
echo "BOOT CONFIGURATION:------------------------------"
if [[ $isdisabled =~ 'ipv4.disable=1' ]]
then
  fail=3
  echo -e "${NORMAL}RESULT:    ${RED}a. $isdisabled${NORMAL}"
else
  echo -e "${NORMAL}RESULT:    ${RED}a. $isdisabled${NORMAL}"
  echo "IPv4 CONFIGURATION:-----------------------------"

  v4cdasr1="$(sysctl net.ipv4.conf.default.accept_source_route)"
  v4cdasr2="$(grep -r net.ipv4.conf.default.accept_source_route $file106 2>/dev/null | grep -v '# Per')"
  v41=0
  v42=0
  
  if [[ $v4cdasr1 ]]
  then
    v4cdasr1val="$(echo $v4cdasr1 | awk -F= '{print $2/ //}')"
    if [[ $v4cdasr1val == 0 ]]
    then
      v41=1
      echo -e "${NORMAL}RESULT:    ${BLD}b. $v4cdasr1${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}b. $v4cdasr1${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}\"net.ipv4.conf.default.accept_source_route\" is not defined in sysctl files${NORMAL}"
  fi
  
  if [[ $v4cdasr2 ]]
  then
    for file in ${v4cdasr2[@]}
    do
      v4cdasr2val="$(echo $v4cdasr2 | awk -F= '{print $2/ //}')"
      if [[ $v4cdasr2val == 0 ]]
      then
        v42filenum="$(echo $v4cdasr2 | awk -F: '{print $1}' | awk -F"/" '{print $4}' | cut -c -3)"
        if [[ $v42filenum == "99-" ]]
        then
	  v42=1
          echo -e "${NORMAL}RESULT:    ${BLD}c. $v4cdasr2${NORMAL}"
        else
	  fail=2
	  echo -e "${NORMAL}RESULT:    ${RED}c. $v4cdasr2${NORMAL}"
	fi
      else
        echo -e "${NORMAL}RESULT:    ${RED}c. $v4cdasr2${NORMAL}"
      fi
    done
  else
    echo -e "${NORMAL}RESULT:    ${RED}c. \"net.ipv4.conf.default.accept_source_route\" is not defined in $file106 files${NORMAL}"
    if [[ $v61 == 1 ]]
    then
      fail=2
    fi
  fi
 
  if [[ $v41 == 1 && $v42 == 1 ]]
  then
    fail=0
  fi
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity106, $controlid, $stigid106, $ruleid106, $cci106, $datetime, ${GRN}PASSED, RHEL 8 does not forward IPv4 source-routed packets by default.${NORMAL}"
elif [[ $fail == 3 ]]
then
  echo -e "${NORMAL}$hostname, $severity106, $controlid, $stigid106, $ruleid106, $cci106, $datetime, ${GRN}PASSED, This requirement is Not Applicable because IPv4 is disabled on the system.${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity106, $controlid, $stigid106, $ruleid106, $cci106, $datetime, ${RED}FAILED, RHEL 8 does not forward IPv4 source-routed packets by default but the file it's configured in does not begin with '99-'.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity106, $controlid, $stigid106, $ruleid106, $cci106, $datetime, ${RED}FAILED, RHEL 8 forwards IPv4 source-routed packets by default.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid107${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid107${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid107${NORMAL}"
echo -e "${NORMAL}CCI:       $cci107${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 107:  ${BLD}$title107a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title107b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title107c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity107${NORMAL}"

IFS='
'

file107="/etc/sysctl.d/*.conf"

fail=1

datetime="$(date +%FT%H:%M:%S)"

# Check if IPv4 is disabled by default
isdisabled="$(grub2-editenv - list | grep kernelopts)"
echo "BOOT CONFIGURATION:------------------------------"
if [[ $isdisabled =~ 'ipv4.disable=1' ]]
then
  fail=3
  echo -e "${NORMAL}RESULT:    ${RED}a. $isdisabled${NORMAL}"
else
  echo -e "${NORMAL}RESULT:    ${RED}a. $isdisabled${NORMAL}"
  echo "IPv4 CONFIGURATION:-----------------------------"

  v4caar1="$(sysctl net.ipv4.conf.all.accept_redirects)"
  v4caar2="$(grep -r net.ipv4.conf.all.accept_redirects $file107 2>/dev/null | grep -v '# Per')"
  v41=0
  v42=0
  
  if [[ $v4caar1 ]]
  then
    v4caar1val="$(echo $v4caar1 | awk -F= '{print $2/ //}')"
    if [[ $v4caar1val == 0 ]]
    then
      v41=1
      echo -e "${NORMAL}RESULT:    ${BLD}b. $v4caar1${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}b. $v4caar1${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}\"net.ipv4.conf.all.accept_redirects\" is not defined in sysctl files${NORMAL}"
  fi
  
  if [[ $v4caar2 ]]
  then
    for file in ${v4caar2[@]}
    do
      v4caar2val="$(echo $v4caar2 | awk -F= '{print $2/ //}')"
      if [[ $v4caar2val == 0 ]]
      then
        v42filenum="$(echo $v4caar2 | awk -F: '{print $1}' | awk -F"/" '{print $4}' | cut -c -3)"
        if [[ $v42filenum == "99-" ]]
        then
	  v42=1
          echo -e "${NORMAL}RESULT:    ${BLD}c. $v4caar2${NORMAL}"
        else
	  fail=2
	  echo -e "${NORMAL}RESULT:    ${RED}c. $v4caar2${NORMAL}"
	fi
      else
        echo -e "${NORMAL}RESULT:    ${RED}c. $v4caar2${NORMAL}"
      fi
    done
  else
    echo -e "${NORMAL}RESULT:    ${RED}c. \"net.ipv4.conf.all.accept_redirects\" is not defined in $file107 files${NORMAL}"
    if [[ $v61 == 1 ]]
    then
      fail=2
    fi
  fi
 
  if [[ $v41 == 1 && $v42 == 1 ]]
  then
    fail=0
  fi
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity107, $controlid, $stigid107, $ruleid107, $cci107, $datetime, ${GRN}PASSED, RHEL 8 ignores IPv4 Internet Control Message Protocol (ICMP) redirect messages.${NORMAL}"
elif [[ $fail == 3 ]]
then
  echo -e "${NORMAL}$hostname, $severity107, $controlid, $stigid107, $ruleid107, $cci107, $datetime, ${GRN}PASSED, This requirement is Not Applicable because IPv4 is disabled on the system.${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity107, $controlid, $stigid107, $ruleid107, $cci107, $datetime, ${RED}FAILED, RHEL 8 ignores IPv4 Internet Control Message Protocol (ICMP) redirect messages but the file it's configured in does not begin with '99-'.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity107, $controlid, $stigid107, $ruleid107, $cci107, $datetime, ${RED}FAILED, RHEL 8 does not ignore IPv4 Internet Control Message Protocol (ICMP) redirect messages.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid108${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid108${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid108${NORMAL}"
echo -e "${NORMAL}CCI:       $cci108${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 108:  ${BLD}$title108a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title108b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title108c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity108${NORMAL}"

IFS='
'

file108="/etc/sysctl.d/*.conf"

fail=1

bpfjit1="$(sysctl net.core.bpf_jit_harden)"
bpfjit2="$(grep -r net.core.bpf_jit_harden $file108 2>/dev/null | grep -v '# Per')"
bpf1=0
bpf2=0

datetime="$(date +%FT%H:%M:%S)"

if [[ $bpfjit1 ]]
then
  bpfjit1val="$(echo $bpfjit1 | awk -F= '{print $2/ //}')"
  if [[ $bpfjit1val == 2 ]]
  then
    bpf1=1
    echo -e "${NORMAL}RESULT:    ${BLD}a. $bpfjit1${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}a. $bpfjit1${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}\"net.core.bpf_jit_harden\" is not defined in sysctl files${NORMAL}"
fi

if [[ $bpfjit2 ]]
then
  bpfjit2val="$(echo $bpfjit2 | awk -F= '{print $2/ //}')"
  bpf2filename="$(echo $bpfjit2 | awk -F: '{print $1}' | awk -F"/" '{print $4}' | cut -c -3)"
  if [[ $bpf2filename != "99-" ]]
  then
    fail=2
  fi

  if [[ $bpfjit2val == 2 ]]
  then
    bpf2=1
    echo -e "${NORMAL}RESULT:    ${BLD}b. $bpfjit2${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}b. $bpfjit2${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}b. \"net.core.bpf_jit_harden\" is not defined in $file108 files${NORMAL}"
  if [[ $bpf1 == 1 ]]
  then
    fail=2
  fi
fi

if [[ $bpf1 == 1 && $bpf2 == 1 ]]
then
  fail=0
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity108, $controlid, $stigid108, $ruleid108, $cci108, $datetime, ${GRN}PASSED, RHEL 8 enables hardening for the Berkeley Packet Filter Just-in-time compiler.${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity108, $controlid, $stigid108, $ruleid108, $cci108, $datetime, ${RED}FAILED, RHEL 8 enables hardening for the Berkeley Packet Filter Just-in-time compiler but the file it's configured in does not begin with '99-'.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity108, $controlid, $stigid108, $ruleid108, $cci108, $datetime, ${RED}FAILED, RHEL 8 does not enable hardening for the Berkeley Packet Filter Just-in-time compiler.${NORMAL}"
fi
   
echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid109${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid109${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid109${NORMAL}"
echo -e "${NORMAL}CCI:       $cci109${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 109:  ${BLD}$title109a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title109b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title109c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity109${NORMAL}"

IFS='
'

file109="/etc/sysctl.d/*.conf"

fail=1

datetime="$(date +%FT%H:%M:%S)"

# Check if IPv4 is disabled by default
isdisabled="$(grub2-editenv - list | grep kernelopts)"
echo "BOOT CONFIGURATION:------------------------------"
if [[ $isdisabled =~ 'ipv4.disable=1' ]]
then
  fail=3
  echo -e "${NORMAL}RESULT:    ${RED}a. $isdisabled${NORMAL}"
else
  echo -e "${NORMAL}RESULT:    ${RED}a. $isdisabled${NORMAL}"
  echo "IPv4 CONFIGURATION:-----------------------------"

  v4caf1="$(sysctl net.ipv4.ip_forward)"
  v4caf2="$(grep -r net.ipv4.conf.all.forwarding $file109 2>/dev/null | grep -v '# Per')"
  v41=0
  v42=0
  
  if [[ $v4caf1 ]]
  then
    v4caf1val="$(echo $v4caf1 | awk -F= '{print $2/ //}')"
    if [[ $v4caf1val == 0 ]]
    then
      v41=1
      echo -e "${NORMAL}RESULT:    ${BLD}b. $v4caf1${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}b. $v4caf1${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}\"net.ipv4.conf.all.forwarding\" is not defined in sysctl files${NORMAL}"
  fi
  
  if [[ $v4caf2 ]]
  then
    for file in ${v4caf2[@]}
    do
      v4caf2val="$(echo $v4caf2 | awk -F= '{print $2/ //}')"
      if [[ $v4caf2val == 0 ]]
      then
        v42filenum="$(echo $v4caf2 | awk -F: '{print $1}' | awk -F"/" '{print $4}' | cut -c -3)"
        if [[ $v42filenum == "99-" ]]
        then
	  v42=1
          echo -e "${NORMAL}RESULT:    ${BLD}c. $v4caf2${NORMAL}"
        else
	  fail=2
	  echo -e "${NORMAL}RESULT:    ${RED}c. $v4caf2${NORMAL}"
	fi
      else
        echo -e "${NORMAL}RESULT:    ${RED}c. $v4caf2${NORMAL}"
      fi
    done
  else
    echo -e "${NORMAL}RESULT:    ${RED}c. \"net.ipv4.conf.all.forwarding\" is not defined in $file109 files${NORMAL}"
    if [[ $v61 == 1 ]]
    then
      fail=2
    fi
  fi
 
  if [[ $v41 == 1 && $v42 == 1 ]]
  then
    fail=0
  fi
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity109, $controlid, $stigid109, $ruleid109, $cci109, $datetime, ${GRN}PASSED, RHEL 8 does not enable IPv4 packet forwarding.${NORMAL}"
elif [[ $fail == 3 ]]
then
  echo -e "${NORMAL}$hostname, $severity109, $controlid, $stigid109, $ruleid109, $cci109, $datetime, ${GRN}PASSED, This requirement is Not Applicable because IPv4 is disabled on the system.${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity109, $controlid, $stigid109, $ruleid109, $cci109, $datetime, ${RED}FAILED, RHEL 8 does not enable IPv4 packet forwarding but the file it's configured in does not begin with '99-'.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity109, $controlid, $stigid109, $ruleid109, $cci109, $datetime, ${RED}FAILED, RHEL 8 enables IPv4 packet forwarding.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid110${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid110${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid110${NORMAL}"
echo -e "${NORMAL}CCI:       $cci110${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 110:  ${BLD}$title110a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title110b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title110c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity110${NORMAL}"

IFS='
'

file110="/etc/shadow"

fail=0

blanksallowed="$(awk -F: '!$2 {print $1}' $file110)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $blanksallowed ]]
then
  fail=1
  for line in ${blanksallowed[@]}
  do
    echo -e "${NORMAL}RESULT:    ${RED}$pwquality${NORMAL}"
  done
else
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity110, $controlid, $stigid110, $ruleid110, $cci110, $datetime, ${GRN}PASSED, The RHEL 8 operating system does not have accounts configured with blank or null passwords.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity110, $controlid, $stigid110, $ruleid110, $cci110, $datetime, ${RED}FAILED, The RHEL 8 operating system has accounts configured with blank or null passwords.${NORMAL}"
fi
  
echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid111${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid111${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid111${NORMAL}"
echo -e "${NORMAL}CCI:       $cci111${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 111:  ${BLD}$title111a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title111b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title111c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity111${NORMAL}"

IFS='
'

file111="/etc/sudoers"
dir111="/etc/sudoers.d"

fail=1
found=0
notdefault=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file111 ]]
then
  includes1="$(grep include $file111)"
  if [[ $includes1 ]]
  then
    for i in ${includes1[@]}
    do
      if [[ $i != "#includedir /etc/sudoers.d" ]]
      then
        echo -e "${NORMAL}RESULT:    ${RED}a. $i${NORMAL}"
	notdefault=1
      else
        echo -e "${NORMAL}RESULT:    ${BLD}a. $i${NORMAL}"
	found=1
      fi
    done
    if [[ $found == 1 && $notdefault == 0 ]]
    then
      fail=0
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}a. \"include\" is not defined in $file111${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}a. $file111 does not exist${NORMAL}"
fi

if [[ -d $dir111 ]]
then
  includes2="$(grep include $dir111/* 2>/dev/null)"
  if [[ $includes2 ]]
  then
    for i in ${includes2[@]}
    do
      echo -e "${NORMAL}RESULT:    ${RED}b. $i${NORMAL}"
      fail=1
    done
  else
    echo -e "${NORMAL}RESULT:    ${BLD}b. Nothing returned${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${BLD}b. $file111 does not exist${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity111, $controlid, $stigid111, $ruleid111, $cci111, $datetime, ${GRN}PASSED, RHEL 8 specifies the default "include" directory for the /etc/sudoers file.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity111, $controlid, $stigid111, $ruleid111, $cci111, $datetime, ${RED}FAILED, RHEL 8 does not specify the default "include" directory properly for the /etc/sudoers file.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid112${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid112${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid112${NORMAL}"
echo -e "${NORMAL}CCI:       $cci112${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 112:  ${BLD}$title112a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title112b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title112c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity112${NORMAL}"

IFS='
'

file112="/etc/pam.d/system-auth"

fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file112 ]]
then
  pwquality="$(cat $file112 | grep pam_pwquality)"
  if [[ $pwquality =~ "password" && $pwquality =~ "required" && $pwquality =~ "pam_pwquality.so" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$pwquality${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}\"pam_pwquality\" is not defined in $file112${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file112 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity112, $controlid, $stigid112, $ruleid112, $cci112, $datetime, ${GRN}PASSED, RHEL 8 ensures the password complexity module is enabled in the system-auth file.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity112, $controlid, $stigid112, $ruleid112, $cci112, $datetime, ${RED}FAILED, RHEL 8 does not ensure the password complexity module is enabled in the system-auth file.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid113${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid113${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid113${NORMAL}"
echo -e "${NORMAL}CCI:       $cci113${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 113:  ${BLD}$title113a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title113b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title113c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity113${NORMAL}"

IFS='
'

file113="/etc/pam.d/system-auth"
major="$(echo $os | awk -F. '{print $1}')"
minor="$(echo $os | awk -F. '{print $2}')"

fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ $major == 8 && $minor < 4 ]]
then
  if [[ -f $file113 ]]
  then
    retry="$(cat $file113 | grep pam_pwquality)"
    if [[ $retry =~ "retry=3" || $retry =~ "retry=2" || $retry =~ "retry=1" ]]
    then
      fail=0
      echo -e "${NORMAL}RESULT:    ${BLD}$retry${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$retry${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}$file113 not found${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${BLD}The RHEL operating system is version $os${NORMAL}"
  fail=2
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity113, $controlid, $stigid113, $ruleid113, $cci113, $datetime, ${GRN}PASSED, RHEL 8 systems below version 8.4 ensure the password complexity module in the system-auth file is configured for three retries or less.${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity113, $controlid, $stigid113, $ruleid113, $cci113, $datetime, ${GRN}N/A, Does not apply to this version of the OS.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity113, $controlid, $stigid113, $ruleid113, $cci113, $datetime, ${RED}FAILED, RHEL 8 systems below version 8.4 do not ensure the password complexity module in the system-auth file is configured for three retries or less.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid114${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid114${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid114${NORMAL}"
echo -e "${NORMAL}CCI:       $cci114${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 114:  ${BLD}$title114a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title114b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title114c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity114${NORMAL}"

IFS='
'

file114="/etc/pam.d/password-auth"
major="$(echo $os | awk -F. '{print $1}')"
minor="$(echo $os | awk -F. '{print $2}')"

fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ $major == 8 && $minor < 4 ]]
then
  if [[ -f $file114 ]]
  then
    retry="$(cat $file114 | grep pam_pwquality)"
    if [[ $retry =~ "retry=3" || $retry =~ "retry=2" || $retry =~ "retry=1" ]]
    then
      fail=0
      echo -e "${NORMAL}RESULT:    ${BLD}$retry${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$retry${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}$file114 not found${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${BLD}The RHEL operating system is version $os${NORMAL}"
  fail=2
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity114, $controlid, $stigid114, $ruleid114, $cci114, $datetime, ${GRN}PASSED, RHEL 8 systems below version 8.4 ensure the password complexity module in the system-auth file is configured for three retries or less.${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity114, $controlid, $stigid114, $ruleid114, $cci114, $datetime, ${GRN}N/A, Does not apply to this version of the OS.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity114, $controlid, $stigid114, $ruleid114, $cci114, $datetime, ${RED}FAILED, RHEL 8 systems below version 8.4 do not ensure the password complexity module in the system-auth file is configured for three retries or less.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid115${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid115${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid115${NORMAL}"
echo -e "${NORMAL}CCI:       $cci115${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 115:  ${BLD}$title115a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title115b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title115c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity115${NORMAL}"

IFS='
'

file115="/etc/security/pwquality.conf"
major="$(echo $os | awk -F. '{print $1}')"
minor="$(echo $os | awk -F. '{print $2}')"

fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ $major == 8 && $minor > 3 ]]
then
  if [[ -f $file115 ]]
  then
    retry="$(grep retry $file115 | grep -v "^#")"
    if [[ $retry =~ "retry = 3" || $retry =~ "retry = 2" || $retry =~ "retry = 1" ]]
    then
      fail=0
      echo -e "${NORMAL}RESULT:    ${BLD}$retry${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$retry${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}$file115 not found${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${BLD}The RHEL operating system is version $os${NORMAL}"
  fail=2
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity115, $controlid, $stigid115, $ruleid115, $cci115, $datetime, ${GRN}PASSED, RHEL 8 systems above version 8.3 ensure the password complexity module in the system-auth file is configured for three retries or less.${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity115, $controlid, $stigid115, $ruleid115, $cci115, $datetime, ${GRN}N/A, Does not apply to this version of the OS.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity115, $controlid, $stigid115, $ruleid115, $cci115, $datetime, ${RED}FAILED, RHEL 8 systems below version 8.4 do not ensure the password complexity module in the system-auth file is configured for three retries or less.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid116${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid116${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid116${NORMAL}"
echo -e "${NORMAL}CCI:       $cci116${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 116:  ${BLD}$title116a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title116b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title116c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity116${NORMAL}"

IFS='
'

fail=1
target="$(systemctl get-default)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $target ]]
then
  if [[ $target != "multi-user.target" ]]
  then
    echo -e "${NORMAL}RESULT:    ${RED}$target${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${BLD}$target${NORMAL}"
    fail=0
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity116, $controlid, $stigid116, $ruleid116, $cci116, $datetime, ${GRN}PASSED, The system is configured to boot to the command line:.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity116, $controlid, $stigid116, $ruleid116, $cci116, $datetime, ${RED}FAILED, The system is not configured to boot to the command line.${NORMAL}"
fi

exit
