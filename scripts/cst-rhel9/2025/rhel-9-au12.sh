#! /bin/bash

# AU-12 Audit Generation
#
# Control: The information system:
# a. Provides audit record generation capability for the auditable events defined in AU-2 a. at 
#    [Assignment: organization-defined information system components];
# b. Allows [Assignment: organization-defined personnel or roles] to select which auditable
#    events are to be audited by specific components of the information system; and
# c. Generates audit records for the events defined in AU-2 d. with the content defined in AU-3.

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

IFS='
'

controlid="AU-12 Audit Generation"

title1a="RHEL 9 must generate audit records for all account creations modifications disabling and termination events that affect /var/log/tallylog."
title1b="Checking with: auditctl -l | grep /var/log/tallylog"
title1c="Expecting: ${YLO}-w /var/log/tallylog -p wa -k logins
           NOTE: If the command does not return a line, or the line is commented out, is a finding."${BLD}
cci1="CCI-000172 CCI-002884"
stigid1="RHEL-09-654260"
severity1="CAT II"
ruleid1="SV-258226r958846"
vulnid1="V-258226"

title2a="RHEL 9 audit system must protect logon UIDs from unauthorized change."
title2b="Checking with: grep -i immutable /etc/audit/audit.rules"
title2c="Expecting: ${YLO}--loginuid-immutable
           NOTE: If the \"--loginuid-immutable\" option is not returned in the \"/etc/audit/audit.rules\", or the line is commented out, this is a finding."${BLD}
cci2="CCI-000162 CCI-000163 CCI-000164 CCI-000172"
stigid2="RHEL-09-654270"
severity2="CAT II"
ruleid2="SV-258228r991572"
vulnid2="V-258228"

title3a="RHEL 9 must enable auditing of processes that start prior to the audit daemon."
title3b="Checking with: 
           a. grubby --info=ALL | grep args | grep -v 'audit=1'
	   b. grep audit /etc/default/grub"
title3c="Expecting: ${YLO}
           a. Nothing returned
	   b. GRUB_CMDLINE_LINUX=\"audit=1\"
           NOTE a: If any output is returned, this is a finding.
	   NOTE b: If \"audit\" is not set to \"1\", is missing, or is commented out, this is a finding."${BLD}
cci3="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-001464 CCI-002884"
stigid3="RHEL-09-212055"
severity3="CAT III"
ruleid3="SV-257796r1044847"
vulnid3="V-257796"

title4a="RHEL 9 must enable Linux audit logging for the USBGuard daemon."
title4b="Checking with: grep AuditBackend /etc/usbguard/usbguard-daemon.conf"
title4c="Expecting: ${YLO}AuditBackend=LinuxAudit
           NOTE: If \"AuditBackend\" is not set to \"LinuxAudit\", this is a finding."${BLD}
cci4="CCI-000169"
stigid4="RHEL-09-291025"
severity4="CAT III"
ruleid4="SV-258037r1014863"
vulnid4="V-258037"

title5a="The RHEL 9 audit package must be installed."
title5b="Checking with: 'dnf list --installed audit'"
title5c="Expecting: ${YLO}(example) audit.x86_64       3.1.5-4.el9       @System 
           NOTE: If the \"audit\" package is not installed, this is a finding."${BLD}
cci5="CCI-000130 CCI-000131 CCI-000132 CCI-000133 CCI-000134 CCI-000135 CCI-000154 CCI-000158 CCI-000159 CCI-000169 CCI-000172 CCI-001464 CCI-001487 CCI-003938 CCI-001876 CCI-001877 CCI-001878 CCI-001879 CCI-001880 CCI-001881 CCI-001882 CCI-001889 CCI-001914 CCI-002884 CCI-001814"
stigid5="RHEL-09-653010"
severity5="CAT II"
ruleid5="SV-258151r1045298"
vulnid5="V-258151"

title6a="RHEL 9 audit records must contain information to establish what type of events occurred, the source of events, where events occurred, and the outcome of events."
title6b="Checking with 'systemctl status auditd.service'."
title6c="Expecting:${YLO}
           auditd.service - Security Auditing Service
           Loaded:loaded (/usr/lib/systemd/system/auditd.service; enabled; vendor preset: enabled)
           Active: active (running) since Tues 2020-12-11 12:56:56 EST; 4 weeks 0 days ago
           NOTE: If the audit service is not \"active\" and \"running\", this is a finding."${BLD}
cci6="CCI-000130 CCI-000131 CCI-000132 CCI-000133 CCI-000134 CCI-000135 CCI-000154 CCI-000158 CCI-000169 CCI-000172 CCI-001464 CCI-001487 CCI-003938 CCI-001875 CCI-001876 CCI-001877 CCI-001878 CCI-001879 CCI-001880 CCI-001881 CCI-001882 CCI-001889 CCI-001914 CCI-002884 CCI-004188 CCI-001814"
stigid6="RHEL-09-653015"
severity6="CAT II"
ruleid6="SV-258152r1015127"
vulnid6="V-258152"

title7a="RHEL 9 audit system must audit local events."
title7b="Checking with: grep local_events /etc/audit/auditd.conf"
title7c="Expecting: ${YLO}local_events = yes
           NOTE: If \"local_events\" isn't set to \"yes\", if the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci7="CCI-000169"
stigid7="RHEL-09-653075"
severity7="CAT II"
ruleid7="SV-258164r1045301"
vulnid7="V-258164"

title8a=" RHEL 9 must allow only the Information System Security Manager (ISSM) (or individuals or roles appointed by the ISSM) to select which auditable events are to be audited."
title8b="Checking with 'find /etc/audit/rules.d/ /etc/audit/audit.rules /etc/audit/auditd.conf -type f -exec stat -c \"%a %n\" {} \;'"
title8c="Expecting: ${YLO}
           600 /etc/audit/rules.d/audit.rules
           640 /etc/audit/audit.rules
           640 /etc/audit/auditd.conf
           NOTE: If the files in the \"/etc/audit/rules.d/\" directory or the \"/etc/audit/auditd.conf\" file have a mode more permissive than \"0640\", this is a finding."${BLD}
cci8="CCI-000171"
stigid8="RHEL-09-653110"
severity8="CAT II"
ruleid8="SV-258171r1045308"
vulnid8="V-258171"

title9a="RHEL 9 must audit all uses of the chmod, fchmod, and fchmodat system calls."
title9b="Checking with: auditctl -l | grep chmod"
title9c="Expecting: ${YLO}
           -a always,exit -S arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_mod
           -a always,exit -S arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_mod
           NOTE: If both the \"b32\" and \"b64\" audit rules are not defined for the \"chmod\", \"fchmod\", and \"fchmodat\" system calls, this is a finding."${BLD}
cci9="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-002884"
stigid9="RHEL-09-654015"
severity9="CAT II"
ruleid9="SV-258177r1106368"
vulnid9="V-258177"

title10a="RHEL 9 must audit all uses of the chown, fchown, fchownat, and lchown system calls."
title10b="Checking with: 'auditctl -l | grep chown'."
title10c="Expecting: ${YLO}
           -a always,exit -S arch=b32 -S lchown,fchown,chown,fchownat -F auid>=1000 -F auid!=-1 -F key=perm_mod
           -a always,exit -S arch=b64 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=-1 -F key=perm_mod
           NOTE: If both the \"b32\" and \"b64\" audit rules are not defined for the \"chown\", \"fchown\", \"fchownat\", and \"lchown\" system calls, this is a finding."${BLD}
cci10="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-002884"
stigid10="RHEL-09-654020"
severity10="CAT II"
ruleid10="SV-258178r1106370"
vulnid10="V-258178"

title11a="RHEL 9 must audit all uses of the setxattr, fsetxattr, lsetxattr, removexattr, fremovexattr, and lremovexattr system calls."
title11b="Checking with: 'auditctl -l | grep xattr'."
title11c="Expecting: ${YLO}
           -a always,exit -S arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=-1 -F key=perm_mod
           -a always,exit -S arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=-1 -F key=perm_mod
           -a always,exit -S arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid=0 -F key=perm_mod
           -a always,exit -S arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid=0 -F key=perm_mod
           NOTE: If both the \"b32\" and \"b64\" audit rules are not defined for the \"setxattr\", \"fsetxattr\", \"lsetxattr\", \"removexattr\", \"fremovexattr\", and \"lremovexattr\" system calls, or any of the lines returned are commented out, this is a finding."${BLD}
cci11="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-002884"
stigid11="RHEL-09-654025"
severity11="CAT II"
ruleid11="SV-258179r1106371"
vulnid11="V-258179"

title12a="RHEL 9 must audit all uses of umount system calls."
title12b="Checking with: 'auditctl -l | grep /usr/bin/umount'."
title12c="Expecting: ${YLO}
           -a always,exit -S all -F path=/usr/bin/umount -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-mount
           NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci12="CCI-000130 CCI-000169 CCI-000172 CCI-002884"
stigid12="RHEL-09-654030"
severity12="CAT II"
ruleid12="SV-258180r1045325"
vulnid12="V-258180"

title13a="RHEL 9 must audit all uses of the chacl command."
title13b="Checking with: 'auditctl -l | grep chacl'."
title13c="Expecting: ${YLO}
           -a always,exit -S all -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=-1 -F key=perm_mod
           NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci13="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-002884"
stigid13="RHEL-09-654035"
severity13="CAT II"
ruleid13="SV-258181r1045328"
vulnid13="V-258181"

title14a="RHEL 9 must audit all uses of the setfacl command."
title14b="Checking with: 'auditctl -l | grep setfacl'."
title14c="Expecting: ${YLO}
           -a always,exit -S all -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=-1 -F key=perm_mod
           NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci14="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-002884"
stigid14="RHEL-09-654040"
severity14="CAT II"
ruleid14="SV-258182r1045331"
vulnid14="V-258182"

title15a="RHEL 9 must audit all uses of the chcon command."
title15b="Checking with: 'auditctl -l | grep chcon'."
title15c="Expecting: ${YLO}
           -a always,exit -S all -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=-1 -F key=perm_mod
           NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci15="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-002884"
stigid15="RHEL-09-654045"
severity15="CAT II"
ruleid15="SV-258183r1045334"
vulnid15="V-258183"

title16a="RHEL 9 must audit all uses of the semanage command."
title16b="Checking with: 'auditctl -l | grep semanage'."
title16c="Expecting: ${YLO}
           -a always,exit -F path=/usr/sbin/semanage -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update
           NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci16="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-002884"
stigid16="RHEL-09-654050"
severity16="CAT II"
ruleid16="SV-258184r1045337"
vulnid16="V-258184"

title17a="RHEL 9 must audit all uses of the setfiles command."
title17b="Checking with: 'auditctl -l | grep setfiles'."
title17c="Expecting: ${YLO}
           -a always,exit -F path=/usr/sbin/setfiles -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update
           NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci17="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-002884"
stigid17="RHEL-09-654055"
severity17="CAT II"
ruleid17="SV-258185r1045340"
vulnid17="V-258185"

title18a="RHEL 9 must audit all uses of the setsebool command."
title18b="Checking with: 'auditctl -l | grep setsebool'."
title18c="Expecting: ${YLO}
           -a always,exit -S all -F path=/usr/sbin/setsebool -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged
           NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci18="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-002884"
stigid18="RHEL-09-654060"
severity18="CAT II"
ruleid18="SV-258186r1045343"
vulnid18="V-258186"

title19a="RHEL 9 must audit all uses of the rename unlink rmdir, renameat, and unlinkat system calls."
title19b="Checking with: auditctl -l | grep 'rename\|unlink\|rmdir'."
title19c="Expecting: ${YLO}
           -a always,exit -S arch=b32 -S unlink,rename,rmdir,unlinkat,renameat -F auid>=1000 -F auid!=-1 -F key=delete
           -a always,exit -S arch=b64 -S rename,rmdir,unlink,unlinkat,renameat -F auid>=1000 -F auid!=-1 -F key=delete
           NOTE: If the command does not return an audit rule for \"rename\", \"unlink\", \"rmdir\", \"renameat\", and \"unlinkat\" or any of the lines returned are commented out, this is a finding."${BLD}
cci19="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-002884"
stigid19="RHEL-09-654065"
severity19="CAT II"
ruleid19="SV-258187r1106373"
vulnid19="V-258187"

title20a="RHEL 9 must audit all uses of the truncate, ftruncate, creat, open, openat, and open_by_handle_at system calls."
title20b="Checking with: auditctl -l | grep 'open\\\\b\|openat\|open_by_handle_at\|truncate\|creat'."
title20c="Expecting: ${YLO}
           -a always,exit -S arch=b32 -S open,creat,truncate,ftruncate,openat,open_by_handle_at -F exit=-EPERM -F auid>=1000 -S auid!=-1 -F key=perm_access
           -a always,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat,open_by_handle_at -F exit=-EPERM -F auid>=1000 -S auid!=-1 -F key=perm_access
           -a always,exit -F arch=b32 -S open,creat,truncate,ftruncate,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -S auid!=-1 -F key=perm_access
           -a always,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -S auid!=-1 -F key=perm_access
           NOTE: If the output does not produce rules containing \"-F exit=-EPERM\", this is a finding.
	   NOTE: If the output does not produce rules containing \"-F exit=-EACCES\", this is a finding."${BLD}
cci20="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-002884"
stigid20="RHEL-09-654070"
severity20="CAT II"
ruleid20="SV-258188r1106375"
vulnid20="V-258188"

title21a="RHEL 9 must audit all uses of the delete_module system call."
title21b="Checking with: auditctl -l | grep delete_module"
title21c="Expecting: ${YLO}
           -a always,exit -S arch=b32 -S delete_module -F auid>=1000 -F auid!=-1 -F key=module_chng
           -a always,exit -S arch=b64 -S delete_module -F auid>=1000 -F auid!=-1 -F key=module_chng
           NOTE: If both the \"b32\" and \"b64\" audit rules are not defined for the \"delete_module\" system call, or any of the lines returned are commented out, this is a finding."${BLD}
cci21="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-002884"
stigid21="RHEL-09-654075"
severity21="CAT II"
ruleid21="SV-258189r1106377"
vulnid21="V-258189"

title22a="RHEL 9 must audit all uses of the init_module and finit_module system calls."
title22b="Checking with: auditctl -l | grep init_module."
title22c="Expecting: ${YLO}
           -a always,exit -S arch=b32 -S init_module,finit_module -F auid>=1000 -F auid!=-1 -F key=module_chng
           -a always,exit -S arch=b64 -S init_module,finit_module -F auid>=1000 -F auid!=-1 -F key=module_chng
           NOTE: If both the \"b32\" and \"b64\" audit rules are not defined for the \"init_module\" system call, or any of the lines returned are commented out, this is a finding."${BLD}
cci22="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-002884"
stigid22="RHEL-09-654080"
severity22="CAT II"
ruleid22="SV-258190r1106379"
vulnid22="V-258190"

title23a="RHEL 9 must audit all uses of the chage command."
title23b="Checking with: auditctl -l | grep chage"
title23c="Expecting: ${YLO}
           -a always,exit -S all -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-chage
           NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci23="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-002884"
stigid23="RHEL-09-654085"
severity23="CAT II"
ruleid23="SV-258191r1045358"
vulnid23="V-258191"

title24a="RHEL 9 must audit all uses of the chsh command."
title24b="Checking with: auditctl -l | grep chsh"
title24c="Expecting: ${YLO}
           -a always,exit -S all -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=-1 -F key=priv_cmd
           NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci24="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-002884"
stigid24="RHEL-09-654090"
severity24="CAT II"
ruleid24="SV-258192r1045361"
vulnid24="V-258192"

title25a="RHEL 9 must audit all uses of the crontab command."
title25b="Checking with: sudo auditctl -l | grep crontab"
title25c="Expecting: ${YLO}
           -a always,exit -S all -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-crontab
           NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci25="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-002884"
stigid25="RHEL-09-654095"
severity25="CAT II"
ruleid25="SV-258193r1045364"
vulnid25="V-258193"

title26a="RHEL 9 must audit all uses of the gpasswd command."
title26b="Checking with: auditctl -l | grep gpasswd"
title26c="Expecting: ${YLO}
           -a always,exit -S all -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-gpasswd
           NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci26="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-002884"
stigid26="RHEL-09-654100"
severity26="CAT II"
ruleid26="SV-258194r1045367"
vulnid26="V-258194"

title27a="RHEL 9 must audit all uses of the kmod command."
title27b="Checking with: auditctl -l | grep kmod"
title27c="Expecting: ${YLO}
           -a always,exit -S all -F path=/usr/bin/kmod -F perm=x -F auid>=1000 -F auid!=-1 -F key=modules
           NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci27="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-002884"
stigid27="RHEL-09-654105"
severity27="CAT II"
ruleid27="SV-258195r1045370"
vulnid27="V-258195"

title28a="RHEL 9 must audit all uses of the newgrp command."
title28b="Checking with: auditctl -l | grep newgrp"
title28c="Expecting: ${YLO}
           -a always,exit -S all -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=-1 -F key=priv_cmd
           NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci28="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-002884"
stigid28="RHEL-09-654110"
severity28="CAT II"
ruleid28="SV-258196r1045373"
vulnid28="V-258196"

title29a="RHEL 9 must audit all uses of the pam_timestamp_check command."
title29b="Checking with: auditctl -l | grep timestamp"
title29c="Expecting: ${YLO}
           -a always,exit -S all -F path=/usr/sbin/pam_timestamp_check -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-pam_timestamp_check
           NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci29="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-002884"
stigid29="RHEL-09-654115"
severity29="CAT II"
ruleid29="SV-258197r1045376"
vulnid29="V-258197"

title30a="RHEL 9 must audit all uses of the passwd command."
title30b="Checking with: auditctl -l | egrep '(/usr/bin/passwd)'"
title30c="Expecting: ${YLO}
           -a always,exit -S all -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-passwd
           NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci30="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-002884"
stigid30="RHEL-09-654120"
severity30="CAT II"
ruleid30="SV-258198r1045379"
vulnid30="V-258198"

title31a="RHEL 9 must audit all uses of the postdrop command."
title31b="Checking with: auditctl -l | grep postdrop"
title31c="Expecting: ${YLO}
           -a always,exit -S all -F path=/usr/sbin/postdrop -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-unix-update
           NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci31="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-002884"
stigid31="RHEL-09-654125"
severity31="CAT II"
ruleid31="SV-258199r1045382"
vulnid31="V-258199"

title32a="RHEL 9 must audit all uses of the postqueue command."
title32b="Checking with: auditctl -l | grep postqueue"
title32c="Expecting: ${YLO}
           -a always,exit -S all -F path=/usr/sbin/postqueue -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-unix-update
           NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci32="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-002884"
stigid32="RHEL-09-654130"
severity32="CAT II"
ruleid32="SV-258200r1045385"
vulnid32="V-258200"

title33a="RHEL 9 must audit all uses of the ssh-agent command."
title33b="Checking with: auditctl -l | grep ssh-agent"
title33c="Expecting: ${YLO}
           -a always,exit -S all -F path=/usr/bin/ssh-agent -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-ssh
           NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci33="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-002884"
stigid33="RHEL-09-654135"
severity33="CAT II"
ruleid33="SV-258201r1045388"
vulnid33="V-258201"

title34a="RHEL 9 must audit all uses of the ssh-keysign command."
title34b="Checking with: auditctl -l | grep ssh-keysign"
title34c="Expecting: ${YLO}
           -a always,exit -S all -F path=/usr/libexec/openssh/ssh-keysign -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-ssh
           NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci34="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-002884"
stigid34="RHEL-09-654140"
severity34="CAT II"
ruleid34="SV-258202r1045391"
vulnid34="V-258202"

title35a="RHEL 9 must audit all uses of the su command."
title35b="Checking with: auditctl -l | grep '/usr/bin/su\b'"
title35c="Expecting: ${YLO}
           -a always,exit -S all -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-priv_change
           NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci35="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-002884"
stigid35="RHEL-09-654145"
severity35="CAT II"
ruleid35="SV-258203r1045394"
vulnid35="V-258203"

title36a="RHEL 9 must audit all uses of the sudo command."
title36b="Checking with: auditctl -l | grep '/usr/bin/sudo\b'"
title36c="Expecting: ${YLO}
           -a always,exit -S all -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=-1 -F key=priv_cmd
           NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci36="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-002884"
stigid36="RHEL-09-654150"
severity36="CAT II"
ruleid36="SV-258204r1045397"
vulnid36="V-258204"

title37a="RHEL 9 must audit all uses of the sudoedit command."
title37b="Checking with: $ sudo auditctl -l | grep /usr/bin/sudoedit"
title37c="Expecting: ${YLO}
           -a always,exit -S all -F path=/usr/bin/sudoedit -F perm=x -F auid>=1000 -F auid!=-1 -F key=priv_cmd
           NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci37="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-002884"
stigid37="RHEL-09-654155"
severity37="CAT II"
ruleid37="SV-258205r1045400"
vulnid37="V-258205"

title38a="RHEL 9 must audit all uses of the unix_chkpwd command."
title38b="Checking with: auditctl -l | grep unix_chkpwd"
title38c="Expecting: ${YLO}
           -a always,exit -S all -F path=/usr/sbin/unix_chkpwd -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-unix-update

           NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci38="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-002884"
stigid38="RHEL-09-654160"
severity38="CAT II"
ruleid38="SV-258206r1045403"
vulnid38="V-258206"

title39a="RHEL 9 must audit all uses of the unix_update command."
title39b="Checking with: auditctl -l | grep unix_update"
title39c="Expecting: ${YLO}
           -a always,exit -S all -F path=/usr/sbin/unix_update -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-unix-update
           NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci39="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-002884"
stigid39="RHEL-09-654165"
severity39="CAT II"
ruleid39="SV-258207r1045406"
vulnid39="V-258207"

title40a="RHEL 9 must audit all uses of the userhelper command."
title40b="Checking with: auditctl -l | grep userhelper"
title40c="Expecting: ${YLO}
           -a always,exit -S all -F path=/usr/sbin/userhelper -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-unix-update
           NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci40="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-002884"
stigid40="RHEL-09-654170"
severity40="CAT II"
ruleid40="SV-258208r1045409"
vulnid40="V-258208"

title41a="RHEL 9 must audit all uses of the usermod command."
title41b="Checking with: auditctl -l | grep usermod"
title41c="Expecting: ${YLO}
           -a always,exit -S all -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-usermod
           NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci41="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-002884"
stigid41="RHEL-09-654175"
severity41="CAT II"
ruleid41="SV-258209r1045412"
vulnid41="V-258209"

title42a="RHEL 9 must audit all uses of the mount command."
title42b="Checking with: auditctl -l | grep /usr/bin/mount"
title42c="Expecting: ${YLO}
           -a always,exit -S all -F path=/usr/bin/mount -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-mount
           NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci42="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-002884"
stigid42="RHEL-09-654180"
severity42="CAT II"
ruleid42="SV-258210r1045415"
vulnid42="V-258210"

title43a="Successful/unsuccessful uses of the init command in RHEL 9 must generate an audit record."
title43b="Checking with: auditctl -l | grep /usr/sbin/init"
title43c="Expecting: ${YLO}
           -a always,exit -S all -F path=/usr/sbin/init -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-init
           NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci43="CCI-000172"
stigid43="RHEL-09-654185"
severity43="CAT II"
ruleid43="SV-258211r1045418"
vulnid43="V-258211"

title44a="Successful/unsuccessful uses of the poweroff command in RHEL 9 must generate an audit record."
title44b="Checking with: auditctl -l | grep poweroff"
title44c="Expecting: ${YLO}
           -a always,exit -S all -F path=/usr/sbin/poweroff -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-poweroff
           NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci44="CCI-000172"
stigid44="RHEL-09-654190"
severity44="CAT II"
ruleid44="SV-258212r1045421"
vulnid44="V-258212"

title45a="Successful/unsuccessful uses of the reboot command in RHEL 9 must generate an audit record."
title45b="Checking with: auditctl -l | grep reboot"
title45c="Expecting: ${YLO}
           -a always,exit -S all -F path=/usr/sbin/reboot -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-reboot
           NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci45="CCI-000172"
stigid45="RHEL-09-654195"
severity45="CAT II"
ruleid45="SV-258213r1045424"
vulnid45="V-258213"

title46a="Successful/unsuccessful uses of the shutdown command in RHEL 9 must generate an audit record."
title46b="Checking with: cat /etc/audit/rules.d/* | grep shutdown"
title46c="Expecting: ${YLO}
           -a always,exit -S all -F path=/usr/sbin/shutdown -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-shutdown
           NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci46="CCI-000172"
stigid46="RHEL-09-654200"
severity46="CAT II"
ruleid46="SV-258214r1045427"
vulnid46="V-258214"

title47a="Successful/unsuccessful uses of the umount system call in RHEL 9 must generate an audit record."
title47b="Checking with: auditctl -l | grep b32 | grep 'umount\\\\b'"
title47c="Expecting: ${YLO}
           -a always,exit -S arch=b32 -S umount -F auid>=1000 -F auid!=-1 -F key=privileged-umount
           NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci47="CCI-000130 CCI-000169 CCI-000172 CCI-002884"
stigid47="RHEL-09-654205"
severity47="CAT II"
ruleid47="SV-258215r1106381"
vulnid47="V-258215"

title48a="Successful/unsuccessful uses of the umount2 system call in RHEL 9 must generate an audit record."
title48b="Checking with: auditctl -l | grep umount2"
title48c="Expecting: ${YLO}
           -a always,exit -S arch=b64 -S umount2 -F auid>=1000 -F auid!=-1 -F key=privileged-umount
           -a always,exit -S arch=b32 -S umount2 -F auid>=1000 -F auid!=-1 -F key=privileged-umount
           NOTE: If no line is returned, this is a finding."${BLD}
cci48="CCI-000130 CCI-000169 CCI-000172 CCI-002884"
stigid48="RHEL-09-654210"
severity48="CAT II"
ruleid48="SV-258216r1102090"
vulnid48="V-258216"

title49a="RHEL 9 must generate audit records for all account creations modifications disabling and termination events that affect /etc/sudoers."
title49b="Checking with: auditctl -l | grep '/etc/sudoers[^.]'"
title49c="Expecting: ${YLO}-w /etc/sudoers -p wa -k identity
           NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci49="CCI-000018 CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-001403 CCI-001404 CCI-001405 CCI-002130 CCI-000015 CCI-002884 CCI-002132"
stigid49="RHEL-09-654215"
severity49="CAT II"
ruleid49="SV-258217r1045436"
vulnid49="V-258217"

title50a="RHEL 9 must generate audit records for all account creations modifications disabling and termination events that affect /etc/sudoers.d/ directory."
title50b="Checking with: auditctl -l | grep /etc/sudoers.d"
title50c="Expecting: ${YLO}-w /etc/sudoers.d/ -p wa -k identity
           NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci50="CCI-000018 CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-001403 CCI-001404 CCI-001405 CCI-002130 CCI-000015 CCI-002884 CCI-002132"
stigid50="RHEL-09-654220"
severity50="CAT II"
ruleid50="SV-258218r1101981"
vulnid50="V-258218"

title51a="RHEL 9 must generate audit records for all account creations modifications disabling and termination events that affect /etc/group."
title51b="Checking with: auditctl -l | egrep '(/etc/group)'"
title51c="Expecting: ${YLO}-w /etc/group -p wa -k identity
           NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci51="CCI-000018 CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-001403 CCI-001404 CCI-001405 CCI-002130 CCI-000015 CCI-002884 CCI-002132"
stigid51="RHEL-09-654225"
severity51="CAT II"
ruleid51="SV-258219r1015130"
vulnid51="V-258219"

title52a="RHEL 9 must generate audit records for all account creations modifications disabling and termination events that affect /etc/gshadow."
title52b="Checking with: auditctl -l | egrep '(/etc/gshadow)'"
title52c="Expecting: ${YLO}-w /etc/gshadow -p wa -k identity
           NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci52="CCI-000018 CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-001403 CCI-001404 CCI-001405 CCI-002130 CCI-000015 CCI-002884 CCI-002132"
stigid52="RHEL-09-654230"
severity52="CAT II"
ruleid52="SV-258220r1015131"
vulnid52="V-258220"

title53a="RHEL 9 must generate audit records for all account creations modifications disabling and termination events that affect /etc/opasswd."
title53b="Checking with: auditctl -l | egrep '(/etc/security/opasswd)'"
title53c="Expecting: ${YLO}-w /etc/security/opasswd -p wa -k identity
           NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci53="CCI-000018 CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-001403 CCI-001404 CCI-001405 CCI-002130 CCI-000015 CCI-002884 CCI-002132"
stigid53="RHEL-09-654235"
severity53="CAT II"
ruleid53="SV-258221r1015132"
vulnid53="V-258221"

title54a="RHEL 9 must generate audit records for all account creations modifications disabling and termination events that affect /etc/passwd."
title543b="Checking with: auditctl -l | egrep '(/etc/passwd)'"
title54c="Expecting: ${YLO}-w /etc/passwd -p wa -k identity
           NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci54="CCI-000015 CCI-000018 CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-001403 CCI-001404 CCI-001405 CCI-002130 CCI-000015 CCI-002884 CCI-002132"
stigid54="RHEL-09-654240"
severity54="CAT II"
ruleid54="SV-258222r1015133"
vulnid54="V-258222"

title55a="RHEL 9 must generate audit records for all account creations modifications disabling and termination events that affect /etc/shadow."
title55b="Checking with: auditctl -l | egrep '(/etc/shadow)'"
title55c="Expecting: ${YLO}-w /etc/shadow -p wa -k identity
           NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci55="CCI-000018 CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-001403 CCI-001404 CCI-001405 CCI-002130 CCI-000015 CCI-002884 CCI-002132"
stigid55="RHEL-09-654245"
severity55="CAT II"
ruleid55="SV-258223r1015134"
vulnid55="V-258223"

title56a="RHEL 9 must generate audit records for all account creations modifications disabling and termination events that affect /var/log/faillock."
title56b="Checking with: auditctl -l | grep /var/log/faillock"
title56c="Expecting: ${YLO}-w /var/log/faillock -p wa -k logins
           NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci56="CCI-000172 CCI-002884"
stigid56="RHEL-09-654250"
severity56="CAT II"
ruleid56="SV-258224r1014988"
vulnid56="V-258224"

title57a="RHEL 9 must generate audit records for all account creations modifications disabling and termination events that affect /var/log/lastlog."
title57b="Checking with: auditctl -l | grep /var/log/lastlog"
title57c="Expecting: ${YLO}-w /var/log/lastlog -p wa -k logins
           NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci57="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-002884"
stigid57="RHEL-09-654255"
severity57="CAT II"
ruleid57="SV-258225r1014990"
vulnid57="V-258225"

title58a="RHEL 9 must audit any script or executable called by cron as root or by any privileged user."
title58b="Checking with: 
           a. auditctl -l | grep /etc/cron.d
	   b. auditctl -l | grep /var/spool/cron"
title58c="Expecting: ${YLO}
           a. -w /etc/cron.d -p wa -k cronjobs
	   b. -w /var/spool/cron -p wa -k cronjobs
           NOTE: If either of these commands do not return the expected output, or the lines are commented out, this is a finding."${BLD}
cci58="CCI-000172"
stigid58="RHEL-09-654096"
severity58="CAT II"
ruleid58="SV-274878r1120758"
vulnid58="V-274878"

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

fail=2

datetime="$(date +%FT%H:%M:%S)"

rule="$(auditctl -l | grep /var/log/tallylog)"

if [[ $rule ]]
then
  if [[ $rule == "-w /var/log/tallylog -p wa -k logins" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
  elif ! [[ $rule =~ "-w" || "-p wa" || "-k logins" ]]
  then
    fail=1
    echo -e "${NORMAL}RESULT:    ${YLO}$rule${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, RHEL 9 generates audit records for all account creations modifications disabling and termination events that affect /var/log/tallylog.${NORMAL}"
elif [[ $fail == 1 ]]
then
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${CYN}VERIFY, RHEL 9 generates audit records for all account creations modifications disabling and termination events that affect /var/log/tallylog, but check the configuration.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, RHEL 9 does not generate audit records for all account creations modifications disabling and termination events that affect /var/log/tallylog.${NORMAL}"
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

isimmutable="$(grep -i immutable /etc/audit/audit.rules)"

if [[ $isimmutable ]]
then
  if [[ $isimmutable == "--loginuid-immutable" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$isimmutable${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$isimmutable${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, RHEL 9 audit system protects logon UIDs from unauthorized change.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, RHEL 9 audit system does not protect logon UIDs from unauthorized change.${NORMAL}"
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

datetime="$(date +%FT%H:%M:%S)"

auenabled="$(grubby --info=ALL | grep args | grep -v 'audit=1')"

if [[ $auenabled ]]
then
  fail=1
  for line in ${auenabled[@]}
  do
    echo -e "${NORMAL}RESULT:    ${RED}a. $line${NORMAL}"
  done
else
  echo -e "${NORMAL}RESULT:    ${BLD}a. Nothing returned${NORMAL}"
fi

default="$(grep audit /etc/default/grub)"

if [[ $default ]]
then
  if [[ $default =~ "GRUB_CMDLINE_LINUX" && $default =~ " audit=1 " ]]
  then 
    echo -e "${NORMAL}RESULT:    ${BLD}b. $default${NORMAL}"
  else
    fail=1
    echo -e "${NORMAL}RESULT:    ${RED}b. $default${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}b. Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${GRN}PASSED, RHEL 9 enables auditing of processes that start prior to the audit daemon.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${RED}FAILED, RHEL 9 does not enable auditing of processes that start prior to the audit daemon.${NORMAL}"
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

file4="/etc/usbguard/usbguard-daemon.conf"
fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file4 ]]
then
  aubackend="$(grep -i auditbackend $file4)"
  if [[ $aubackend ]]
  then
    if [[ $aubackend == 'AuditBackend=LinuxAudit' ]]
    then
      fail=0
      echo -e "${NORMAL}RESULT:    ${BLD}$aubackend${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$aubackend${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file4 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${GRN}PASSED, RHEL 9 enables Linux audit logging for the USBGuard daemon.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${RED}FAILED, RHEL 9 does not enable Linux audit logging for the USBGuard daemon.${NORMAL}"
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

aupkg="$(dnf list --installed audit | grep audit)"

if [[ $aupkg ]]
then
  fail=0
  echo -e "${NORMAL}RESULT:    ${BLD}$aupkg${NORMAL}"
else
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${GRN}PASSED, The RHEL 9 audit package is installed.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${RED}FAILED, The RHEL 9 audit package is not installed.${NORMAL}"
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

sysctlcmd="$(command -v systemctl)"
enabled=0
active=0
running=0
fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ $sysctlcmd ]]
then
  ausvc="$($sysctlcmd status auditd.service)"
  if [[ $ausvc ]]
  then
    for line in ${ausvc[@]}
    do
      line="$(echo $line | sed -e 's/^[[:space:]]*//')"
      if [[ $line =~ 'enabled' ]]
      then
        enabled=1
        echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
      elif [[ $line =~ 'Active' ]]
      then
        active=1
        if [[ $line =~ 'running' ]]
        then
          echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
          running=1
        else
          echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
        fi
      else
        echo -e "${NORMAL}RESULT:    $line${NORMAL}"
      fi
    done
  else
    echo -e "${NORMAL}RESULT:    ${BLD}The kdump service was not found${NORMAL}"
  fi
  if [[ $enabled == 1 && $active == 1 && $running == 1 ]]
  then
    fail=0
  fi

  if (( $fail == 0 ))
  then
    echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${GRN}PASSED, The RHEL 9 audit service is configured to produce audit records.${NORMAL}"
  else
    echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${RED}FAILED. The RHEL 9 audit service is not configured to produce audit records.${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${BLD}The 'systemctl' command was not found${NORMAL}"
  echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${CYN}VERIFY, the 'systemctl' command was not found${NORMAL}"
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

localevt="$(grep local_events /etc/audit/auditd.conf)"
if [[ $localevt ]]
then
  val="$(echo $localevt | awk -F " = " '{print $2}')"
  if [[ $val == yes ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$localevt${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$localevt${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${GRN}PASSED, The RHEL 9 audit system audits local events.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${RED}FAILED, The RHEL 9 audit system does not audit local events.${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

files="$(find 2>/dev/null /etc/audit/rules.d/ /etc/audit/audit.rules /etc/audit/auditd.conf -type f -exec stat -c "%a %n" {} \;)"

if [[ $files ]]
then
  line=""
  for line in ${files[@]}
  do
    mode="$(echo $line | awk '{print $1}')"
    if (( $mode <= 640 ))
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
    else
      fail=1
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cci8, $datetime, ${GRN}PASSED, RHEL 9 allows only the Information System Security Manager (ISSM) (or individuals or roles appointed by the ISSM) to select which auditable events are to be audited.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cci8, $datetime, ${RED}FAILED, RHEL 9 does not allow only the Information System Security Manager (ISSM) (or individuals or roles appointed by the ISSM) to select which auditable events are to be audited.${NORMAL}"
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
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity9${NORMAL}"i

IFS='
'

fail=0

chmod=0
fchmod=0
fchmodat=0
b32=0
b64=0

datetime="$(date +%FT%H:%M:%S)"

aurules=""
aurules="$(auditctl -l | grep chmod)"
if [[ $aurules ]]
then
  rule=""
  for rule in ${aurules[@]}
  do
    if ! [[ $rule =~ '-a always,exit' && $rule =~ 'perm_mod' ]]
    then
      fail=2
    fi

    IFS=' ' read -a fieldvals <<< "${rule}"
    for field in ${fieldvals[@]}
    do
      if [[ $field =~ 'b32' ]]
      then
        (( b32++ ))
      elif [[ $field =~ 'b64' ]]
      then
        (( b64++ ))
      elif [[ $field =~ 'auid>=' ]]
      then
        auidval="$(echo $field | awk -F'>=' '{print $2}')"
        if [[ $auidval > 1000 ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
          fail=1
        fi
      elif [[ $field =~ 'auid!=' ]]
      then
        auidval="$(echo $field | awk -F'!=' '{print $2}')"
        if [[ $auidval != '-1' && $auidval != '4294967295' && $auidval != 'unset' ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be a form of unset; \"-1\", \"4294967295\", or \"unset\".${NORMAL}"
          fail=1
        fi
      fi
      if [[ $field =~ 'chmod' ]]
      then
        chmod=1
      fi
      if [[ $field =~ 'fchmod' ]]
      then
        fchmod=1
      fi
      if [[ $field =~ 'fchmodat' ]]
      then
        fchmodat=1
      fi
    done
    if [[ $chmod == 0 || $fchmod == 0 || $fchmodat == 0 ]]
    then
      fail=2
    fi

    if [[ $fail == 0 ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$rule${NORMAL}"
    fi
  done
  if [[ $b32 == 0 ]]
  then
    echo -e "${NORMAL}RESULT:    ${RED}auditctl is missing a rule for \"b32\" 'chmod'${NORMAL}"
    fail=1
  fi
  if [[ $b64 == 0 ]]
  then
    echo -e "${NORMAL}RESULT:    ${RED}auditctl is missing a rule for \"b64\" 'chmod'${NORMAL}"
    fail=1
  fi

else
  echo -e "${NORMAL}RESULT:    ${RED}auditctl is missing a rule for 'chmod'${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity9, $controlid, $stigid9, $ruleid9, $cci9, $datetime, ${GRN}PASSED, Use of the chmod system calls is audited${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity9, $controlid, $stigid9, $ruleid9, $cci9, $datetime, ${RED}FAILED, Use of the chmod system calls is not configured correctly${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity9, $controlid, $stigid9, $ruleid9, $cci9, $datetime, ${RED}FAILED, Use of the chmod system calls is not audited${NORMAL}"
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

fail=0

chown=0
fchown=0
fchownat=0
lchown=0
b32=0
b64=0

datetime="$(date +%FT%H:%M:%S)"

aurules=""
aurules="$(auditctl -l | grep chown)"
if [[ $aurules ]]
then
  rule=""
  for rule in ${aurules[@]}
  do
    if ! [[ $rule =~ '-a always,exit' && $rule =~ 'perm_mod' ]]
    then
      fail=2
    fi

    IFS=' ' read -a fieldvals <<< "${rule}"

    for field in ${fieldvals[@]}
    do
      if [[ $field =~ 'b32' ]]
      then
        (( b32++ ))
      elif [[ $field =~ 'b64' ]]
      then
        (( b64++ ))
      elif [[ $field =~ 'auid>=' ]]
      then
        auidval="$(echo $field | awk -F'>=' '{print $2}')"
        if [[ $auidval > 1000 ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
          fail=1
        fi
      elif [[ $field =~ 'auid!=' ]]
      then
        auidval="$(echo $field | awk -F'!=' '{print $2}')"
        if [[ $auidval != '-1' && $auidval != '4294967295' && $auidval != 'unset' ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be a form of unset; \"-1\", \"4294967295\", or \"unset\".${NORMAL}"
          fail=1
        fi
      fi
      if [[ $field =~ 'chown' ]]
      then
        chown=1
      fi
      if [[ $field =~ 'fchown' ]]
      then
        fchown=1
      fi
      if [[ $field =~ 'fchownat' ]]
      then
        fchownat=1
      fi
      if [[ $field =~ 'lchown' ]]
      then
        lchown=1
      fi
    done
    if [[ $chown == 0 || $fchown == 0 || $fchownat == 0 || $lchown == 0 ]]
    then
      fail=2
    fi

    if [[ $fail == 0 ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$rule${NORMAL}"
    fi
  done
  if [[ $b32 == 0 ]]
  then
    echo -e "${NORMAL}RESULT:    ${RED}auditctl is missing a rule for \"b32\" 'chown'${NORMAL}"
    fail=1
  fi
  if [[ $b64 == 0 ]]
  then
    echo -e "${NORMAL}RESULT:    ${RED}auditctl is missing a rule for \"b64\" 'chown'${NORMAL}"
    fail=1
  fi

else
  echo -e "${NORMAL}RESULT:    ${RED}auditctl is missing a rule for 'chown'${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity10, $controlid, $stigid10, $ruleid10, $cci10, $datetime, ${GRN}PASSED, Use of the chown system calls is audited${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity10, $controlid, $stigid10, $ruleid10, $cci10, $datetime, ${RED}FAILED, Use of the chown system calls is not configured correctly${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity10, $controlid, $stigid10, $ruleid10, $cci10, $datetime, ${RED}FAILED, Use of the chown system calls is not audited${NORMAL}"
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

fail=0

setxattr=0
fsetxattr=0
lsetxattr=0
removexattr=0
fremovexattr=0
lremovexattr=0
b32=0
b64=0

datetime="$(date +%FT%H:%M:%S)"

aurules=""
aurules="$(auditctl -l | grep xattr)"
if [[ $aurules ]]
then
  rule=""
  for rule in ${aurules[@]}
  do
    if ! [[ $rule =~ '-a always,exit' && $rule =~ 'perm_mod' ]]
    then
      fail=2
    fi

    IFS=' ' read -a fieldvals <<< "${rule}"

    for field in ${fieldvals[@]}
    do
      if [[ $field =~ 'b32' ]]
      then
        (( b32++ ))
      elif [[ $field =~ 'b64' ]]
      then
        (( b64++ ))
      elif [[ $field =~ 'auid>=' ]]
      then
        auidval="$(echo $field | awk -F'>=' '{print $2}')"
        if [[ $auidval > 1000 ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
          fail=1
        fi
      elif [[ $field =~ 'auid!=' ]]
      then
        auidval="$(echo $field | awk -F'!=' '{print $2}')"
        if [[ $auidval != '-1' && $auidval != '4294967295' && $auidval != 'unset' ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be a form of unset; \"-1\", \"4294967295\", or \"unset\".${NORMAL}"
          fail=1
        fi
      fi
      if [[ $field =~ 'setxattr' ]]
      then
        setxattr=1
      fi
      if [[ $field =~ 'fsetxattr' ]]
      then
        fsetxattr=1
      fi
      if [[ $field =~ 'lsetxattr' ]]
      then
        lsetxattr=1
      fi
      if [[ $field =~ 'removexattr' ]]
      then
        removexattr=1
      fi
      if [[ $field =~ 'fremovexattr' ]]
      then
        fremovexattr=1
      fi
      if [[ $field =~ 'lremovexattr' ]]
      then
        lremovexattr=1
      fi
    done
    if [[ $setxattr == 0 || $fsetxattr == 0 || $lsetxattr == 0 || $removexattr == 0 || $fremovexattr == 0 || $lremovexattr == 0 ]]
    then
      fail=2
    fi

    if [[ $fail == 0 ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$rule${NORMAL}"
    fi
  done
  if (( $b32 < 2 ))
  then
    echo -e "${NORMAL}RESULT:    ${RED}auditctl is missing a rule for \"b32\" 'xattr'${NORMAL}"
    fail=1
  fi
  if (( $b64 < 2 ))
  then
    echo -e "${NORMAL}RESULT:    ${RED}auditctl is missing a rule for \"b64\" 'xattr'${NORMAL}"
    fail=1
  fi

else
  echo -e "${NORMAL}RESULT:    ${RED}auditctl is missing a rule for 'xattr'${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity11, $controlid, $stigid11, $ruleid11, $cci11, $datetime, ${GRN}PASSED, Use of the xattr system calls is audited${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity11, $controlid, $stigid11, $ruleid11, $cci11, $datetime, ${RED}FAILED, Use of the xattr system calls is not configured correctly${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity11, $controlid, $stigid11, $ruleid11, $cci11, $datetime, ${RED}FAILED, Use of the xattr system calls is not audited${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

aurules=""
aurules="$(auditctl -l | grep /usr/bin/umount)"
if [[ $aurules ]]
then
  rule=""
  for rule in ${aurules[@]}
  do
    #if ! [[ $rule =~ '-a always,exit' && $rule =~ '-S all' && $rule =~ '-F perm=x' && $rule =~ 'privileged-mount' ]]
    if ! [[ $rule =~ '-a always,exit' && $rule =~ 'privileged-mount' ]]
    then
      fail=2
    fi

    IFS=' ' read -a fieldvals <<< "${rule}"

    for field in ${fieldvals[@]}
    do
      if [[ $field =~ 'auid>=' ]]
      then
        auidval="$(echo $field | awk -F'>=' '{print $2}')"
        if [[ $auidval > 1000 ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
          fail=2
        fi
      elif [[ $field =~ 'auid!=' ]]
      then
        auidval="$(echo $field | awk -F'!=' '{print $2}')"
        if [[ $auidval != '-1' && $auidval != '4294967295' && $auidval != 'unset' ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be a form of unset; \"-1\", \"4294967295\", or \"unset\".${NORMAL}"
          fail=2
        fi
      fi
    done
  done

  if [[ $fail == 0 ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$rule${NORMAL}"
  fi

else
  echo -e "${NORMAL}RESULT:    ${RED}auditctl is missing a rule for 'umount'${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity12, $controlid, $stigid12, $ruleid12, $cci12, $datetime, ${GRN}PASSED, Use of the umount system call is audited${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity12, $controlid, $stigid12, $ruleid12, $cci12, $datetime, ${RED}FAILED, Use of the umount system call is not configured correctly${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity12, $controlid, $stigid12, $ruleid12, $cci12, $datetime, ${RED}FAILED, Use of the umount system call is not audited${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

aurules=""
aurules="$(auditctl -l | grep chacl)"
if [[ $aurules ]]
then
  rule=""
  for rule in ${aurules[@]}
  do
    if ! [[ $rule =~ '-a always,exit' && $rule =~ '-S all' && $rule =~ '/usr/bin' && $rule =~ '-F perm=x' && $rule =~ 'perm_mod' ]]
    then
      fail=2
    fi

    IFS=' ' read -a fieldvals <<< "${rule}"

    for field in ${fieldvals[@]}
    do
      if [[ $field =~ 'auid>=' ]]
      then
        auidval="$(echo $field | awk -F'>=' '{print $2}')"
        if [[ $auidval > 1000 ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
          fail=2
        fi
      elif [[ $field =~ 'auid!=' ]]
      then
        auidval="$(echo $field | awk -F'!=' '{print $2}')"
        if [[ $auidval != '-1' && $auidval != '4294967295' && $auidval != 'unset' ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be a form of unset; \"-1\", \"4294967295\", or \"unset\".${NORMAL}"
          fail=2
        fi
      fi
    done
  done

  if [[ $fail == 0 ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$rule${NORMAL}"
  fi

else
  echo -e "${NORMAL}RESULT:    ${RED}auditctl is missing a rule for 'chacl'${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity13, $controlid, $stigid13, $ruleid13, $cci13, $datetime, ${GRN}PASSED, Use of the chacl command is audited${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity13, $controlid, $stigid13, $ruleid13, $cci13, $datetime, ${RED}FAILED, Use of the chacl command is not configured correctly${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity13, $controlid, $stigid13, $ruleid13, $cci13, $datetime, ${RED}FAILED, Use of the chacl command is not audited${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

aurules=""
aurules="$(auditctl -l | grep setfacl)"
if [[ $aurules ]]
then
  rule=""
  for rule in ${aurules[@]}
  do
    if ! [[ $rule =~ '-a always,exit' && $rule =~ '-S all' && $rule =~ 'usr/bin' && $rule =~ '-F perm=x' && $rule =~ 'perm_mod' ]]
    then
      fail=2
    fi

    IFS=' ' read -a fieldvals <<< "${rule}"

    for field in ${fieldvals[@]}
    do
      if [[ $field =~ 'auid>=' ]]
      then
        auidval="$(echo $field | awk -F'>=' '{print $2}')"
        if [[ $auidval > 1000 ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
          fail=2
        fi
      elif [[ $field =~ 'auid!=' ]]
      then
        auidval="$(echo $field | awk -F'!=' '{print $2}')"
        if [[ $auidval != '-1' && $auidval != '4294967295' && $auidval != 'unset' ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be a form of unset; \"-1\", \"4294967295\", or \"unset\".${NORMAL}"
          fail=2
        fi
      fi
    done
  done

  if [[ $fail == 0 ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$rule${NORMAL}"
  fi

else
  echo -e "${NORMAL}RESULT:    ${RED}auditctl is missing a rule for 'setfacl'${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity14, $controlid, $stigid14, $ruleid14, $cci14, $datetime, ${GRN}PASSED, Use of the setfacl command is audited${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity14, $controlid, $stigid14, $ruleid14, $cci14, $datetime, ${RED}FAILED, Use of the setacl command is not configured correctly${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity14, $controlid, $stigid14, $ruleid14, $cci14, $datetime, ${RED}FAILED, Use of the setacl command is not audited${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

aurules=""
aurules="$(auditctl -l | grep chcon)"
if [[ $aurules ]]
then
  rule=""
  for rule in ${aurules[@]}
  do
    if ! [[ $rule =~ '-a always,exit' && $rule =~ '-S all' && $rule =~ 'usr/bin' && $rule =~ '-F perm=x' && $rule =~ 'perm_mod' ]]
    then
      fail=2
    fi

    IFS=' ' read -a fieldvals <<< "${rule}"

    for field in ${fieldvals[@]}
    do
      if [[ $field =~ 'auid>=' ]]
      then
        auidval="$(echo $field | awk -F'>=' '{print $2}')"
        if [[ $auidval > 1000 ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
          fail=2
        fi
      elif [[ $field =~ 'auid!=' ]]
      then
        auidval="$(echo $field | awk -F'!=' '{print $2}')"
        if [[ $auidval != '-1' && $auidval != '4294967295' && $auidval != 'unset' ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be a form of unset; \"-1\", \"4294967295\", or \"unset\".${NORMAL}"
          fail=2
        fi
      fi
    done
  done

  if [[ $fail == 0 ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$rule${NORMAL}"
  fi

else
  echo -e "${NORMAL}RESULT:    ${RED}auditctl is missing a rule for 'chcon'${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity15, $controlid, $stigid15, $ruleid15, $cci15, $datetime, ${GRN}PASSED, Use of the chcon command is audited${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity15, $controlid, $stigid15, $ruleid15, $cci15, $datetime, ${RED}FAILED, Use of the chcon command is not configured correctly${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity15, $controlid, $stigid15, $ruleid15, $cci15, $datetime, ${RED}FAILED, Use of the chcon command is not audited${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

aurules=""
aurules="$(auditctl -l | grep semanage)"
if [[ $aurules ]]
then
  rule=""
  for rule in ${aurules[@]}
  do
    if ! [[ $rule =~ '-a always,exit' && $rule =~ '-S all' && $rule =~ '/usr/sbin' && $rule =~ '-F perm=x' && $rule =~ 'privileged-unix-update' ]]
    then
      fail=2
    fi

    IFS=' ' read -a fieldvals <<< "${rule}"

    for field in ${fieldvals[@]}
    do
      if [[ $field =~ 'auid>=' ]]
      then
        auidval="$(echo $field | awk -F'>=' '{print $2}')"
        if [[ $auidval > 1000 ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
          fail=2
        fi
      elif [[ $field =~ 'auid!=' ]]
      then
        auidval="$(echo $field | awk -F'!=' '{print $2}')"
        if [[ $auidval != '-1' && $auidval != '4294967295' && $auidval != 'unset' ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be a form of unset; \"-1\", \"4294967295\", or \"unset\".${NORMAL}"
          fail=2
        fi
      fi
    done
  done

  if [[ $fail == 0 ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$rule${NORMAL}"
  fi

else
  echo -e "${NORMAL}RESULT:    ${RED}auditctl is missing a rule for 'semanage'${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity16, $controlid, $stigid16, $ruleid16, $cci16, $datetime, ${GRN}PASSED, Use of the semanage command is audited${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity16, $controlid, $stigid16, $ruleid16, $cci16, $datetime, ${RED}FAILED, Use of the semanage command is not configured correctly${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity16, $controlid, $stigid16, $ruleid16, $cci16, $datetime, ${RED}FAILED, Use of the semanage command is not audited${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

aurules=""
aurules="$(auditctl -l | grep setfiles)"
if [[ $aurules ]]
then
  rule=""
  for rule in ${aurules[@]}
  do
    if ! [[ $rule =~ '-a always,exit' && $rule =~ '-S all' && $rule =~ '/usr/sbin/' && $rule =~ '-F perm=x' && $rule =~ 'privileged-unix-update' ]]
    then
      fail=2
    fi

    IFS=' ' read -a fieldvals <<< "${rule}"

    for field in ${fieldvals[@]}
    do
      if [[ $field =~ 'auid>=' ]]
      then
        auidval="$(echo $field | awk -F'>=' '{print $2}')"
        if [[ $auidval > 1000 ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
          fail=2
        fi
      elif [[ $field =~ 'auid!=' ]]
      then
        auidval="$(echo $field | awk -F'!=' '{print $2}')"
        if [[ $auidval != '-1' && $auidval != '4294967295' && $auidval != 'unset' ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be a form of unset; \"-1\", \"4294967295\", or \"unset\".${NORMAL}"
          fail=2
        fi
      fi
    done
  done

  if [[ $fail == 0 ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$rule${NORMAL}"
  fi

else
  echo -e "${NORMAL}RESULT:    ${RED}auditctl is missing a rule for 'setfiles'${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity17, $controlid, $stigid17, $ruleid17, $cci17, $datetime, ${GRN}PASSED, Use of the setfiles command is audited${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity17, $controlid, $stigid17, $ruleid17, $cci17, $datetime, ${RED}FAILED, Use of the setfiles command is not configured correctly${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity17, $controlid, $stigid17, $ruleid17, $cci17, $datetime, ${RED}FAILED, Use of the setfiles command is not audited${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

aurules=""
aurules="$(auditctl -l | grep setsebool)"
if [[ $aurules ]]
then
  rule=""
  for rule in ${aurules[@]}
  do
    if ! [[ $rule =~ '-a always,exit' && $rule =~ '-S all' && $rule =~ '/usr/sbin/' && $rule =~ '-F perm=x' && $rule =~ 'privileged' ]]
    then
      fail=2
    fi

    IFS=' ' read -a fieldvals <<< "${rule}"

    for field in ${fieldvals[@]}
    do
      if [[ $field =~ 'auid>=' ]]
      then
        auidval="$(echo $field | awk -F'>=' '{print $2}')"
        if [[ $auidval > 1000 ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
          fail=2
        fi
      elif [[ $field =~ 'auid!=' ]]
      then
        auidval="$(echo $field | awk -F'!=' '{print $2}')"
        if [[ $auidval != '-1' && $auidval != '4294967295' && $auidval != 'unset' ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be a form of unset; \"-1\", \"4294967295\", or \"unset\".${NORMAL}"
          fail=2
        fi
      fi
    done
  done

  if [[ $fail == 0 ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$rule${NORMAL}"
  fi

else
  echo -e "${NORMAL}RESULT:    ${RED}auditctl is missing a rule for 'setfiles'${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity18, $controlid, $stigid18, $ruleid18, $cci18, $datetime, ${GRN}PASSED, Use of the setfiles command is audited${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity18, $controlid, $stigid18, $ruleid18, $cci18, $datetime, ${RED}FAILED, Use of the setfiles command is not configured correctly${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity18, $controlid, $stigid18, $ruleid18, $cci18, $datetime, ${RED}FAILED, Use of the setfiles command is not audited${NORMAL}"
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
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity19${NORMAL}"i

IFS='
'

fail=0

chmod=0
rename=0
unlink=0
rmdir=0
renameat=0
unlinkat=0
b32=0
b64=0

datetime="$(date +%FT%H:%M:%S)"

aurules=""
aurules="$(auditctl -l | grep 'rename\|unlink\|rmdir')"
if [[ $aurules ]]
then
  rule=""
  for rule in ${aurules[@]}
  do
    if ! [[ $rule =~ '-a always,exit' && $rule =~ 'key=delete' ]]
    then
      fail=2
    fi

    IFS=' ' read -a fieldvals <<< "${rule}"
    for field in ${fieldvals[@]}
    do
      if [[ $field =~ 'b32' ]]
      then
        (( b32++ ))
      elif [[ $field =~ 'b64' ]]
      then
        (( b64++ ))
      elif [[ $field =~ 'auid>=' ]]
      then
        auidval="$(echo $field | awk -F'>=' '{print $2}')"
        if [[ $auidval > 1000 ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
          fail=1
        fi
      elif [[ $field =~ 'auid!=' ]]
      then
        auidval="$(echo $field | awk -F'!=' '{print $2}')"
        if [[ $auidval != '-1' && $auidval != '4294967295' && $auidval != 'unset' ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be a form of unset; \"-1\", \"4294967295\", or \"unset\".${NORMAL}"
          fail=1
        fi
      fi
      if [[ $field =~ 'rename' ]]
      then
        rename=1
      fi
      if [[ $field =~ 'unlink' ]]
      then
        unlink=1
      fi
      if [[ $field =~ 'rmdir' ]]
      then
        rmdir=1
      fi
      if [[ $field =~ 'renameat' ]]
      then
        renameat=1
      fi
      if [[ $field =~ 'unlinkat' ]]
      then
        unlinkat=1
      fi
    done
    if [[ $rename == 0 || $unlink == 0 || $rmdir == 0 || $renameat == 0 || $unlinkat == 0 ]]
    then
      fail=2
    fi

    if [[ $fail == 0 ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$rule${NORMAL}"
    fi
  done
  if [[ $b32 == 0 ]]
  then
    echo -e "${NORMAL}RESULT:    ${RED}auditctl is missing a rule for \"b32\" 'rename' 'unlink' or 'rmdir'.${NORMAL}"
    fail=1
  fi
  if [[ $b64 == 0 ]]
  then
    echo -e "${NORMAL}RESULT:    ${RED}auditctl is missing a rule for \"b64\" 'rename' 'unlink' or 'rmdir'.${NORMAL}"
    fail=1
  fi

else
 echo -e "${NORMAL}RESULT:    ${RED}auditctl is missing a rule for one or more of the following commands: \"rename\" \"unlink\" \"rmdir\" \"renameat\" or \"unlinkat\".${NORMAL}"
 fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity19, $controlid, $stigid19, $ruleid19, $cci19, $datetime, ${GRN}PASSED, Use of the rename unlink and rmdir system calls is audited${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity19, $controlid, $stigid19, $ruleid19, $cci19, $datetime, ${RED}FAILED, Use of the rename unlink and rmdir system calls is not configured correctly${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity19, $controlid, $stigid19, $ruleid19, $cci19, $datetime, ${RED}FAILED, Use of the rename unlink and rmdir system calls is not audited${NORMAL}"
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
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity20${NORMAL}"i

IFS='
'

fail=0

truncate=0
ftruncate=0
creat=0
open=0
openat=0
open_by_handle_at=0
b32=0
b64=0

datetime="$(date +%FT%H:%M:%S)"

aurules=""
aurules="$(auditctl -l | grep 'open\b\|openat\|open_by_handle_at\|truncate\|creat')"
if [[ $aurules ]]
then
  rule=""
  for rule in ${aurules[@]}
  do
    if ! [[ $rule =~ '-a always,exit' && $rule =~ 'perm_access' ]]
    then
      fail=2
    fi

    IFS=' ' read -a fieldvals <<< "${rule}"
    for field in ${fieldvals[@]}
    do
      if [[ $field =~ 'b32' ]]
      then
        (( b32++ ))
      elif [[ $field =~ 'b64' ]]
      then
        (( b64++ ))
      elif [[ $field =~ 'auid>=' ]]
      then
        auidval="$(echo $field | awk -F'>=' '{print $2}')"
        if [[ $auidval > 1000 ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
          fail=1
        fi
      elif [[ $field =~ 'auid!=' ]]
      then
        auidval="$(echo $field | awk -F'!=' '{print $2}')"
        if [[ $auidval != '-1' && $auidval != '4294967295' && $auidval != 'unset' ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be a form of unset; \"-1\", \"4294967295\", or \"unset\".${NORMAL}"
          fail=1
        fi
      fi
      if [[ $field =~ 'truncate' ]]
      then
        truncate=1
      fi
      if [[ $field =~ 'ftruncate' ]]
      then
        ftruncate=1
      fi
      if [[ $field =~ 'creat' ]]
      then
        creat=1
      fi
      if [[ $field =~ 'open' ]]
      then
        open=1
      fi
      if [[ $field =~ 'openat' ]]
      then
        openat=1
      fi
      if [[ $field =~ 'open_by_handle_at' ]]
      then
        open_by_handle_at=1
      fi
    done
    if [[ $truncate == 0 || $ftruncate == 0 || $creat == 0 || $open == 0 || $openat == 0 || $open_by_handle_at == 0 ]]
    then
      fail=2
    fi
    if ! [[ $rule =~ 'exit=-EPERM' || $rule =~ 'exit=-EACCES' ]]
    then
      echo -e "${NORMAL}RESULT:    ${RED}Missing \"exit=-EPERM or -EACCES'${NORMAL}"
      fail=2
    fi
    if [[ $fail == 0 ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$rule${NORMAL}"
    fi
  done
  if (( $b32 < 2 ))
  then
    echo -e "${NORMAL}RESULT:    ${RED}auditctl is missing a rule for \"b32\" 'truncate' 'ftruncate' 'creat' 'open' 'openat or 'open_by_handle_at'.${NORMAL}"
    fail=1
  fi
  if (( $b64 < 2 ))
  then
    echo -e "${NORMAL}RESULT:    ${RED}auditctl is missing a rule for \"b64\" 'truncate' 'ftruncate' 'creat' 'open' 'openat or 'open_by_handle_at'.${NORMAL}"
    fail=1
  fi

else
 echo -e "${NORMAL}RESULT:    ${RED}auditctl is missing a rule for one or more of the following commands: \"truncate\" \"ftruncate\" \"creat\" \"open\" \"openat\" or \"open_by_handle_at\".${NORMAL}"
 fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity20, $controlid, $stigid20, $ruleid20, $cci20, $datetime, ${GRN}PASSED, Use of the truncate ftruncate creat open openat and open_by_handle_at system calls is audited${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity20, $controlid, $stigid20, $ruleid20, $cci20, $datetime, ${RED}FAILED, Use of the truncate ftruncate creat open openat and open_by_handle_at system calls is not configured correctly${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity20, $controlid, $stigid20, $ruleid20, $cci20, $datetime, ${RED}FAILED, Use of the truncate ftruncate creat open openat and open_by_handle_at system calls is not audited${NORMAL}"
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

fail=0

b32=0
b64=0

datetime="$(date +%FT%H:%M:%S)"

aurules=""
aurules="$(auditctl -l | grep delete_module)"
if [[ $aurules ]]
then
  rule=""
  for rule in ${aurules[@]}
  do
    if ! [[ $rule =~ '-a always,exit' && $rule =~ 'module_chng' ]]
    then
      fail=2
    fi

    IFS=' ' read -a fieldvals <<< "${rule}"

    for field in ${fieldvals[@]}
    do
      if [[ $field =~ 'b32' ]]
      then
        (( b32++ ))
      elif [[ $field =~ 'b64' ]]
      then
        (( b64++ ))
      fi
      if [[ $field =~ 'auid>=' ]]
      then
        auidval="$(echo $field | awk -F'>=' '{print $2}')"
        if [[ $auidval > 1000 ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
          fail=2
        fi
      elif [[ $field =~ 'auid!=' ]]
      then
        auidval="$(echo $field | awk -F'!=' '{print $2}')"
        if [[ $auidval != '-1' && $auidval != '4294967295' && $auidval != 'unset' ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be a form of unset; \"-1\" \"4294967295\" or \"unset\".${NORMAL}"
          fail=2
        fi
      fi
    done

    if [[ $fail == 0 ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$rule${NORMAL}"
    fi

  done

  if [[ $b32 == 0 ]]
  then
    echo -e "${NORMAL}RESULT:    ${RED}auditctl is missing a rule for \"b32\" 'delete_module'${NORMAL}"
    fail=1
  fi
  if [[ $b64 == 0 ]]
  then
    echo -e "${NORMAL}RESULT:    ${RED}auditctl is missing a rule for \"b64\" 'delete_module'${NORMAL}"
    fail=1
  fi

else
  echo -e "${NORMAL}RESULT:    ${RED}auditctl is missing a rule for 'delete_module'${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity21, $controlid, $stigid21, $ruleid21, $cci21, $datetime, ${GRN}PASSED, Use of the delete_module system call is audited${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity21, $controlid, $stigid21, $ruleid21, $cci21, $datetime, ${RED}FAILED, Use of the delete_module system call is not configured correctly${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity21, $controlid, $stigid21, $ruleid21, $cci21, $datetime, ${RED}FAILED, Use of the delete_module system call is not audited${NORMAL}"
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
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity21${NORMAL}"

IFS='
'

fail=0

b32=0
b64=0
init=0
finit=0

datetime="$(date +%FT%H:%M:%S)"

aurules=""
aurules="$(auditctl -l | grep init_module)"
if [[ $aurules ]]
then
  rule=""
  for rule in ${aurules[@]}
  do
    if ! [[ $rule =~ '-a always,exit' && $rule =~ 'module_chng' ]]
    then
      fail=2
    fi

    IFS=' ' read -a fieldvals <<< "${rule}"

    for field in ${fieldvals[@]}
    do
      if [[ $field =~ 'b32' ]]
      then
        (( b32++ ))
      elif [[ $field =~ 'b64' ]]
      then
        (( b64++ ))
      fi
      if [[ $field =~ 'auid>=' ]]
      then
        auidval="$(echo $field | awk -F'>=' '{print $2}')"
        if [[ $auidval > 1000 ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
          fail=2
        fi
      elif [[ $field =~ 'auid!=' ]]
      then
        auidval="$(echo $field | awk -F'!=' '{print $2}')"
        if [[ $auidval != '-1' && $auidval != '4294967295' && $auidval != 'unset' ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be a form of unset; \"-1\" \"4294967295\" or \"unset\".${NORMAL}"
          fail=2
        fi
      fi
    done

    if [[ $fail == 0 ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$rule${NORMAL}"
    fi

  done

  if [[ $b32 == 0 ]]
  then
    echo -e "${NORMAL}RESULT:    ${RED}auditctl is missing a rule for \"b32\" 'init_module'${NORMAL}"
    fail=1
  fi
  if [[ $b64 == 0 ]]
  then
    echo -e "${NORMAL}RESULT:    ${RED}auditctl is missing a rule for \"b64\" 'init_module'${NORMAL}"
    fail=1
  fi

else
  echo -e "${NORMAL}RESULT:    ${RED}auditctl is missing a rule for 'init_module'${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity22, $controlid, $stigid22, $ruleid22, $cci22, $datetime, ${GRN}PASSED, Use of the init_module system calls is audited${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity22, $controlid, $stigid22, $ruleid22, $cci22, $datetime, ${RED}FAILED, Use of the init_module system calls is not configured correctly${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity22, $controlid, $stigid22, $ruleid22, $cci22, $datetime, ${RED}FAILED, Use of the init_module system calls is not audited${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

aurules=""
aurules="$(auditctl -l | grep chage)"
if [[ $aurules ]]
then
  rule=""
  for rule in ${aurules[@]}
  do
    if ! [[ $rule =~ '-a always,exit' && $rule =~ '-S all' && $rule =~ 'usr/bin' && $rule =~ '-F perm=x' && $rule =~ 'privileged-chage' ]]
    then
      fail=2
    fi

    IFS=' ' read -a fieldvals <<< "${rule}"

    for field in ${fieldvals[@]}
    do
      if [[ $field =~ 'auid>=' ]]
      then
        auidval="$(echo $field | awk -F'>=' '{print $2}')"
        if [[ $auidval > 1000 ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
          fail=2
        fi
      elif [[ $field =~ 'auid!=' ]]
      then
        auidval="$(echo $field | awk -F'!=' '{print $2}')"
        if [[ $auidval != '-1' && $auidval != '4294967295' && $auidval != 'unset' ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be a form of unset; \"-1\" \"4294967295\" or \"unset\".${NORMAL}"
          fail=2
        fi
      fi
    done
  done

  if [[ $fail == 0 ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$rule${NORMAL}"
  fi

else
  echo -e "${NORMAL}RESULT:    ${RED}auditctl is missing a rule for 'chage'${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity23, $controlid, $stigid23, $ruleid23, $cci23, $datetime, ${GRN}PASSED, Use of the chage command is audited${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity23, $controlid, $stigid23, $ruleid23, $cci23, $datetime, ${RED}FAILED, Use of the chage command is not configured correctly${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity23, $controlid, $stigid23, $ruleid23, $cci23, $datetime, ${RED}FAILED, Use of the chage command is not audited${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

aurules=""
aurules="$(auditctl -l | grep chsh)"
if [[ $aurules ]]
then
  rule=""
  for rule in ${aurules[@]}
  do
    if ! [[ $rule =~ '-a always,exit' && $rule =~ '-S all' && $rule =~ 'usr/bin' && $rule =~ '-F perm=x' && $rule =~ 'priv_cmd' ]]
    then
      fail=2
    fi

    IFS=' ' read -a fieldvals <<< "${rule}"

    for field in ${fieldvals[@]}
    do
      if [[ $field =~ 'auid>=' ]]
      then
        auidval="$(echo $field | awk -F'>=' '{print $2}')"
        if [[ $auidval > 1000 ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
          fail=2
        fi
      elif [[ $field =~ 'auid!=' ]]
      then
        auidval="$(echo $field | awk -F'!=' '{print $2}')"
        if [[ $auidval != '-1' && $auidval != '4294967295' && $auidval != 'unset' ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be a form of unset; \"-1\" \"4294967295\" or \"unset\".${NORMAL}"
          fail=2
        fi
      fi
    done
  done

  if [[ $fail == 0 ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$rule${NORMAL}"
  fi

else
  echo -e "${NORMAL}RESULT:    ${RED}auditctl is missing a rule for 'chsh'${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity24, $controlid, $stigid24, $ruleid24, $cci24, $datetime, ${GRN}PASSED, Use of the chsh command is audited${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity24, $controlid, $stigid24, $ruleid24, $cci24, $datetime, ${RED}FAILED, Use of the chsh command is not configured correctly${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity24, $controlid, $stigid24, $ruleid24, $cci24, $datetime, ${RED}FAILED, Use of the chsh command is not audited${NORMAL}"
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

aurules=""
aurules="$(auditctl -l | grep crontab)"
if [[ $aurules ]]
then
  rule=""
  for rule in ${aurules[@]}
  do
    if ! [[ $rule =~ '-a always,exit' && $rule =~ '-S all' && $rule =~ 'usr/bin' && $rule =~ '-F perm=x' && $rule =~ 'privileged-crontab' ]]
    then
      fail=2
    fi

    IFS=' ' read -a fieldvals <<< "${rule}"

    for field in ${fieldvals[@]}
    do
      if [[ $field =~ 'auid>=' ]]
      then
        auidval="$(echo $field | awk -F'>=' '{print $2}')"
        if [[ $auidval > 1000 ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
          fail=2
        fi
      elif [[ $field =~ 'auid!=' ]]
      then
        auidval="$(echo $field | awk -F'!=' '{print $2}')"
        if [[ $auidval != '-1' && $auidval != '4294967295' && $auidval != 'unset' ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be a form of unset; \"-1\" \"4294967295\" or \"unset\".${NORMAL}"
          fail=2
        fi
      fi
    done
  done

  if [[ $fail == 0 ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$rule${NORMAL}"
  fi

else
  echo -e "${NORMAL}RESULT:    ${RED}auditctl is missing a rule for 'crontab'${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity25, $controlid, $stigid25, $ruleid25, $cci25, $datetime, ${GRN}PASSED, Use of the crontab command is audited${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity25, $controlid, $stigid25, $ruleid25, $cci25, $datetime, ${RED}FAILED, Use of the crontab command is not configured correctly${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity25, $controlid, $stigid25, $ruleid25, $cci25, $datetime, ${RED}FAILED, Use of the crontab command is not audited${NORMAL}"
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

aurules=""
aurules="$(auditctl -l | grep gpasswd)"
if [[ $aurules ]]
then
  rule=""
  for rule in ${aurules[@]}
  do
    if ! [[ $rule =~ '-a always,exit' && $rule =~ '-S all' && $rule =~ 'usr/bin' && $rule =~ '-F perm=x' && $rule =~ 'privileged-gpasswd' ]]
    then
      fail=2
    fi

    IFS=' ' read -a fieldvals <<< "${rule}"

    for field in ${fieldvals[@]}
    do
      if [[ $field =~ 'auid>=' ]]
      then
        auidval="$(echo $field | awk -F'>=' '{print $2}')"
        if [[ $auidval > 1000 ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
          fail=2
        fi
      elif [[ $field =~ 'auid!=' ]]
      then
        auidval="$(echo $field | awk -F'!=' '{print $2}')"
        if [[ $auidval != '-1' && $auidval != '4294967295' && $auidval != 'unset' ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be a form of unset; \"-1\" \"4294967295\" or \"unset\".${NORMAL}"
          fail=2
        fi
      fi
    done
  done

  if [[ $fail == 0 ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$rule${NORMAL}"
  fi

else
  echo -e "${NORMAL}RESULT:    ${RED}auditctl is missing a rule for 'gpasswd'${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity26, $controlid, $stigid26, $ruleid26, $cci26, $datetime, ${GRN}PASSED, Use of the gpasswd command is audited${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity26, $controlid, $stigid26, $ruleid26, $cci26, $datetime, ${RED}FAILED, Use of the gpasswd command is not configured correctly${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity26, $controlid, $stigid26, $ruleid26, $cci26, $datetime, ${RED}FAILED, Use of the gpasswd command is not audited${NORMAL}"
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

aurules=""
aurules="$(auditctl -l | grep kmod)"
if [[ $aurules ]]
then
  rule=""
  for rule in ${aurules[@]}
  do
    if ! [[ $rule =~ '-a always,exit' && $rule =~ '-S all' && $rule =~ 'usr/bin' && $rule =~ '-F perm=x' && $rule =~ 'key=modules' ]]
    then
      fail=2
    fi

    IFS=' ' read -a fieldvals <<< "${rule}"

    for field in ${fieldvals[@]}
    do
      if [[ $field =~ 'auid>=' ]]
      then
        auidval="$(echo $field | awk -F'>=' '{print $2}')"
        if [[ $auidval > 1000 ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
          fail=2
        fi
      elif [[ $field =~ 'auid!=' ]]
      then
        auidval="$(echo $field | awk -F'!=' '{print $2}')"
        if [[ $auidval != '-1' && $auidval != '4294967295' && $auidval != 'unset' ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be a form of unset; \"-1\", \"4294967295\", or \"unset\".${NORMAL}"
          fail=2
        fi
      fi
    done
  done

  if [[ $fail == 0 ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$rule${NORMAL}"
  fi

else
  echo -e "${NORMAL}RESULT:    ${RED}auditctl is missing a rule for 'kmod'${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity27, $controlid, $stigid27, $ruleid27, $cci27, $datetime, ${GRN}PASSED, Use of the kmod command is audited${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity27, $controlid, $stigid27, $ruleid27, $cci27, $datetime, ${RED}FAILED, Use of the kmod command is not configured correctly${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity27, $controlid, $stigid27, $ruleid27, $cci27, $datetime, ${RED}FAILED, Use of the kmod command is not audited${NORMAL}"
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

aurules=""
aurules="$(auditctl -l | grep newgrp)"
if [[ $aurules ]]
then
  rule=""
  for rule in ${aurules[@]}
  do
    if ! [[ $rule =~ '-a always,exit' && $rule =~ '-S all' && $rule =~ 'usr/bin' && $rule =~ '-F perm=x' && $rule =~ 'key=priv_cmd' ]]
    then
      fail=2
    fi

    IFS=' ' read -a fieldvals <<< "${rule}"

    for field in ${fieldvals[@]}
    do
      if [[ $field =~ 'auid>=' ]]
      then
        auidval="$(echo $field | awk -F'>=' '{print $2}')"
        if [[ $auidval > 1000 ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
          fail=2
        fi
      elif [[ $field =~ 'auid!=' ]]
      then
        auidval="$(echo $field | awk -F'!=' '{print $2}')"
        if [[ $auidval != '-1' && $auidval != '4294967295' && $auidval != 'unset' ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be a form of unset; \"-1\", \"4294967295\", or \"unset\".${NORMAL}"
          fail=2
        fi
      fi
    done
  done

  if [[ $fail == 0 ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$rule${NORMAL}"
  fi

else
  echo -e "${NORMAL}RESULT:    ${RED}auditctl is missing a rule for 'newgrp'${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity28, $controlid, $stigid28, $ruleid28, $cci28, $datetime, ${GRN}PASSED, Use of the newgrp command is audited${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity28, $controlid, $stigid28, $ruleid28, $cci28, $datetime, ${RED}FAILED, Use of the newgrp command is not configured correctly${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity28, $controlid, $stigid28, $ruleid28, $cci28, $datetime, ${RED}FAILED, Use of the newgrp command is not audited${NORMAL}"
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

aurules=""
aurules="$(auditctl -l | grep pam_timestamp_check)"
if [[ $aurules ]]
then
  rule=""
  for rule in ${aurules[@]}
  do
    if ! [[ $rule =~ '-a always,exit' && $rule =~ '-S all' && $rule =~ 'usr/sbin' && $rule =~ '-F perm=x' && $rule =~ 'key=privileged-pam_timestamp_check' ]]
    then
      fail=2
    fi

    IFS=' ' read -a fieldvals <<< "${rule}"

    for field in ${fieldvals[@]}
    do
      if [[ $field =~ 'auid>=' ]]
      then
        auidval="$(echo $field | awk -F'>=' '{print $2}')"
        if [[ $auidval > 1000 ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
          fail=2
        fi
      elif [[ $field =~ 'auid!=' ]]
      then
        auidval="$(echo $field | awk -F'!=' '{print $2}')"
        if [[ $auidval != '-1' && $auidval != '4294967295' && $auidval != 'unset' ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be a form of unset; \"-1\", \"4294967295\", or \"unset\".${NORMAL}"
          fail=2
        fi
      fi
    done
  done

  if [[ $fail == 0 ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$rule${NORMAL}"
  fi

else
  echo -e "${NORMAL}RESULT:    ${RED}auditctl is missing a rule for 'pam_timestamp_check'${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity29, $controlid, $stigid29, $ruleid29, $cci29, $datetime, ${GRN}PASSED, Use of the pam_timestamp_check command is audited${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity29, $controlid, $stigid29, $ruleid29, $cci29, $datetime, ${RED}FAILED, Use of the pam_timestamp_check command is not configured correctly${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity29, $controlid, $stigid29, $ruleid29, $cci29, $datetime, ${RED}FAILED, Use of the pam_timestamp_check command is not audited${NORMAL}"
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

aurules=""
aurules="$(auditctl -l | egrep '(/usr/bin/passwd)')"
if [[ $aurules ]]
then
  rule=""
  for rule in ${aurules[@]}
  do
    if ! [[ $rule =~ '-a always,exit' && $rule =~ '-S all' && $rule =~ '-F perm=x' && $rule =~ 'key=privileged-passwd' ]]
    then
      fail=2
    fi

    IFS=' ' read -a fieldvals <<< "${arule}"

    for field in ${fieldvals[@]}
    do
      if [[ $field =~ 'auid>=' ]]
      then
        auidval="$(echo $field | awk -F'>=' '{print $2}')"
        if [[ $auidval > 1000 ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
          fail=2
        fi
      elif [[ $field =~ 'auid!=' ]]
      then
        auidval="$(echo $field | awk -F'!=' '{print $2}')"
        if [[ $auidval != '-1' && $auidval != '4294967295' && $auidval != 'unset' ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be a form of unset; \"-1\", \"4294967295\", or \"unset\".${NORMAL}"
          fail=2
        fi
      fi
    done

    if [[ $fail == 0 ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$rule${NORMAL}"
    fi

  done

else
  echo -e "${NORMAL}RESULT:    ${RED}auditctl is missing a rule for '/usr/bin/passwd'${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity30, $controlid, $stigid30, $ruleid30, $cci30, $datetime, ${GRN}PASSED, Use of the /usr/bin/passwd command is audited${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity30, $controlid, $stigid30, $ruleid30, $cci30, $datetime, ${RED}FAILED, Use of the /usr/bin/passwd command is not configured correctly${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity30, $controlid, $stigid30, $ruleid30, $cci30, $datetime, ${RED}FAILED, Use of the /usr/bin/passwd command is not audited${NORMAL}"
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

aurules=""
aurules="$(auditctl -l | grep postdrop)"
if [[ $aurules ]]
then
  rule=""
  for rule in ${aurules[@]}
  do
    if ! [[ $rule =~ '-a always,exit' && $rule =~ '-S all' && $rule =~ '/usr/sbin' && $rule =~ '-F perm=x' && $rule =~ 'key=privileged-unix-update' ]]
    then
      fail=2
    fi

    IFS=' ' read -a fieldvals <<< "${arule}"

    for field in ${fieldvals[@]}
    do
      if [[ $field =~ 'auid>=' ]]
      then
        auidval="$(echo $field | awk -F'>=' '{print $2}')"
        if [[ $auidval > 1000 ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
          fail=2
        fi
      elif [[ $field =~ 'auid!=' ]]
      then
        auidval="$(echo $field | awk -F'!=' '{print $2}')"
        if [[ $auidval != '-1' && $auidval != '4294967295' && $auidval != 'unset' ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be a form of unset; \"-1\", \"4294967295\", or \"unset\".${NORMAL}"
          fail=2
        fi
      fi
    done

    if [[ $fail == 0 ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$rule${NORMAL}"
    fi

  done

else
  echo -e "${NORMAL}RESULT:    ${RED}auditctl is missing a rule for 'postdrop'${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity31, $controlid, $stigid31, $ruleid31, $cci31, $datetime, ${GRN}PASSED, Use of the postdrop command is audited${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity31, $controlid, $stigid31, $ruleid31, $cci31, $datetime, ${RED}FAILED, Use of the postdrop command is not configured correctly${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity31, $controlid, $stigid31, $ruleid31, $cci31, $datetime, ${RED}FAILED, Use of the postdrop command is not audited${NORMAL}"
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

aurules=""
aurules="$(auditctl -l | grep postqueue)"
if [[ $aurules ]]
then
  rule=""
  for rule in ${aurules[@]}
  do
    if ! [[ $rule =~ '-a always,exit' && $rule =~ '-S all' && $rule =~ '/usr/sbin' && $rule =~ '-F perm=x' && $rule =~ 'key=privileged-unix-update' ]]
    then
      fail=2
    fi

    IFS=' ' read -a fieldvals <<< "${arule}"

    for field in ${fieldvals[@]}
    do
      if [[ $field =~ 'auid>=' ]]
      then
        auidval="$(echo $field | awk -F'>=' '{print $2}')"
        if [[ $auidval > 1000 ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
          fail=2
        fi
      elif [[ $field =~ 'auid!=' ]]
      then
        auidval="$(echo $field | awk -F'!=' '{print $2}')"
        if [[ $auidval != '-1' && $auidval != '4294967295' && $auidval != 'unset' ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be a form of unset; \"-1\", \"4294967295\", or \"unset\".${NORMAL}"
          fail=2
        fi
      fi
    done

    if [[ $fail == 0 ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$rule${NORMAL}"
    fi

  done

else
  echo -e "${NORMAL}RESULT:    ${RED}auditctl is missing a rule for 'postqueue'${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity32, $controlid, $stigid32, $ruleid32, $cci32, $datetime, ${GRN}PASSED, Use of the postqueue command is audited${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity32, $controlid, $stigid32, $ruleid32, $cci32, $datetime, ${RED}FAILED, Use of the postqueue command is not configured correctly${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity32, $controlid, $stigid32, $ruleid32, $cci32, $datetime, ${RED}FAILED, Use of the postqueue command is not audited${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

aurules=""
aurules="$(auditctl -l | grep ssh-agent)"
if [[ $aurules ]]
then
  rule=""
  for rule in ${aurules[@]}
  do
    if ! [[ $rule =~ '-a always,exit' && $rule =~ '-S all' && $rule =~ '/usr/bin' && $rule =~ '-F perm=x' && $rule =~ 'key=privileged-ssh' ]]
    then
      fail=2
    fi

    IFS=' ' read -a fieldvals <<< "${arule}"

    for field in ${fieldvals[@]}
    do
      if [[ $field =~ 'auid>=' ]]
      then
        auidval="$(echo $field | awk -F'>=' '{print $2}')"
        if [[ $auidval > 1000 ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
          fail=2
        fi
      elif [[ $field =~ 'auid!=' ]]
      then
        if [[ $auidval != '-1' && $auidval != '4294967295' && $auidval != 'unset' ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be a form of unset; \"-1\", \"4294967295\", or \"unset\".${NORMAL}"
          fail=2
        fi
      fi
    done

    if [[ $fail == 0 ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$rule${NORMAL}"
    fi

  done

else
  echo -e "${NORMAL}RESULT:    ${RED}auditctl is missing a rule for 'ssh-agent'${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity33, $controlid, $stigid33, $ruleid33, $cci33, $datetime, ${GRN}PASSED, Use of the ssh-agent command is audited${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity33, $controlid, $stigid33, $ruleid33, $cci33, $datetime, ${RED}FAILED, Use of the ssh-agent command is not configured correctly${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity33, $controlid, $stigid33, $ruleid33, $cci33, $datetime, ${RED}FAILED, Use of the ssh-agent command is not audited${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

aurules=""
aurules="$(auditctl -l | grep ssh-keysign)"
if [[ $aurules ]]
then
  rule=""
  for rule in ${aurules[@]}
  do
    if ! [[ $rule =~ '-a always,exit' && $rule =~ '-S all' && $rule =~ '/usr/libexec/openssh' && $rule =~ '-F perm=x' && $rule =~ 'key=privileged-ssh' ]]
    then
      fail=2
    fi

    IFS=' ' read -a fieldvals <<< "${arule}"

    for field in ${fieldvals[@]}
    do
      if [[ $field =~ 'auid>=' ]]
      then
        auidval="$(echo $field | awk -F'>=' '{print $2}')"
        if [[ $auidval > 1000 ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
          fail=2
        fi
      elif [[ $field =~ 'auid!=' ]]
      then
        if [[ $auidval != '-1' && $auidval != '4294967295' && $auidval != 'unset' ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be a form of unset; \"-1\", \"4294967295\", or \"unset\".${NORMAL}"
          fail=2
        fi
      fi
    done

    if [[ $fail == 0 ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$rule${NORMAL}"
    fi

  done

else
  echo -e "${NORMAL}RESULT:    ${RED}auditctl is missing a rule for 'ssh-keysign'${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity34, $controlid, $stigid34, $ruleid34, $cci34, $datetime, ${GRN}PASSED, Use of the ssh-keysign command is audited${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity34, $controlid, $stigid34, $ruleid34, $cci34, $datetime, ${RED}FAILED, Use of the ssh-keysign command is not configured correctly${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity34, $controlid, $stigid34, $ruleid34, $cci34, $datetime, ${RED}FAILED, Use of the ssh-keysign command is not audited${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

aurules=""
aurules="$(auditctl -l | grep '/usr/bin/su\b')"
if [[ $aurules ]]
then
  rule=""
  for rule in ${aurules[@]}
  do
    if ! [[ $rule =~ '-a always,exit' && $rule =~ '-S all' && $rule =~ '/usr/bin' && $rule =~ '-F perm=x' && $rule =~ 'key=privileged-priv_change' ]]
    then
      fail=2
    fi

    IFS=' ' read -a fieldvals <<< "${arule}"

    for field in ${fieldvals[@]}
    do
      if [[ $field =~ 'auid>=' ]]
      then
        if [[ $auidval != '-1' && $auidval != '4294967295' && $auidval != 'unset' ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be a form of unset; \"-1\", \"4294967295\", or \"unset\".${NORMAL}"
          fail=2
        fi
      fi
    done

    if [[ $fail == 0 ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$rule${NORMAL}"
    fi

  done

else
  echo -e "${NORMAL}RESULT:    ${RED}auditctl is missing a rule for 'su'${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity35, $controlid, $stigid35, $ruleid35, $cci35, $datetime, ${GRN}PASSED, Use of the su command is audited${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity35, $controlid, $stigid35, $ruleid35, $cci35, $datetime, ${RED}FAILED, Use of the su command is not configured correctly${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity35, $controlid, $stigid35, $ruleid35, $cci35, $datetime, ${RED}FAILED, Use of the su command is not audited${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

aurules=""
aurules="$(auditctl -l | grep '/usr/bin/sudo\b')"
if [[ $aurules ]]
then
  rule=""
  for rule in ${aurules[@]}
  do
    if ! [[ $rule =~ '-a always,exit' && $rule =~ '-S all' && $rule =~ '-F perm=x' && $rule =~ 'key=priv_cmd' ]]
    then
      fail=2
    fi

    IFS=' ' read -a fieldvals <<< "${arule}"

    for field in ${fieldvals[@]}
    do
      if [[ $field =~ 'auid>=' ]]
      then
        if [[ $auidval != '-1' && $auidval != '4294967295' && $auidval != 'unset' ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be a form of unset; \"-1\", \"4294967295\", or \"unset\".${NORMAL}"
          fail=2
        fi
      fi
    done

    if [[ $fail == 0 ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$rule${NORMAL}"
    fi

  done

else
  echo -e "${NORMAL}RESULT:    ${RED}auditctl is missing a rule for 'sudo'${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity36, $controlid, $stigid36, $ruleid36, $cci36, $datetime, ${GRN}PASSED, Use of the sudo command is audited${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity36, $controlid, $stigid36, $ruleid36, $cci36, $datetime, ${RED}FAILED, Use of the sudo command is not configured correctly${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity36, $controlid, $stigid36, $ruleid36, $cci36, $datetime, ${RED}FAILED, Use of the sudo command is not audited${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

aurules=""
aurules="$(auditctl -l | grep /usr/bin/sudoedit)"
if [[ $aurules ]]
then
  rule=""
  for rule in ${aurules[@]}
  do
    if ! [[ $rule =~ '-a always,exit' && $rule =~ '-S all' && $rule =~ '-F perm=x' && $rule =~ 'key=priv_cmd' ]]
    then
      fail=2
    fi

    IFS=' ' read -a fieldvals <<< "${arule}"

    for field in ${fieldvals[@]}
    do
      if [[ $field =~ 'auid>=' ]]
      then
        if [[ $auidval != '-1' && $auidval != '4294967295' && $auidval != 'unset' ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be a form of unset; \"-1\", \"4294967295\", or \"unset\".${NORMAL}"
          fail=2
        fi
      fi
    done

    if [[ $fail == 0 ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$rule${NORMAL}"
    fi

  done

else
  echo -e "${NORMAL}RESULT:    ${RED}auditctl is missing a rule for 'sudoedit'${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity37, $controlid, $stigid37, $ruleid37, $cci37, $datetime, ${GRN}PASSED, Use of the sudoedit command is audited${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity37, $controlid, $stigid37, $ruleid37, $cci37, $datetime, ${RED}FAILED, Use of the sudoedit command is not configured correctly${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity37, $controlid, $stigid37, $ruleid37, $cci37, $datetime, ${RED}FAILED, Use of the sudoedit command is not audited${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

aurules=""
aurules="$(auditctl -l | grep unix_chkpwd)"
if [[ $aurules ]]
then
  rule=""
  for rule in ${aurules[@]}
  do
    if ! [[ $rule =~ '-a always,exit' && $rule =~ '-S all' && $rule =~ '/usr/sbin' && $rule =~ '-F perm=x' && $rule =~ 'key=privileged-unix-update' ]]
    then
      fail=2
    fi

    IFS=' ' read -a fieldvals <<< "${arule}"

    for field in ${fieldvals[@]}
    do
      if [[ $field =~ 'auid>=' ]]
      then
        if [[ $auidval != '-1' && $auidval != '4294967295' && $auidval != 'unset' ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be a form of unset; \"-1\", \"4294967295\", or \"unset\".${NORMAL}"
          fail=2
        fi
      fi
    done

    if [[ $fail == 0 ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$rule${NORMAL}"
    fi

  done

else
  echo -e "${NORMAL}RESULT:    ${RED}auditctl is missing a rule for 'unix_chkpwd'${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity38, $controlid, $stigid38, $ruleid38, $cci38, $datetime, ${GRN}PASSED, Use of the unix_chkpwd command is audited${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity38, $controlid, $stigid38, $ruleid38, $cci38, $datetime, ${RED}FAILED, Use of the unix_chkpwd command is not configured correctly${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity38, $controlid, $stigid38, $ruleid38, $cci38, $datetime, ${RED}FAILED, Use of the unix_chkpwd command is not audited${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

aurules=""
aurules="$(auditctl -l | grep unix_update)"
if [[ $aurules ]]
then
  rule=""
  for rule in ${aurules[@]}
  do
    if ! [[ $rule =~ '-a always,exit' && $rule =~ '-S all' && $rule =~ '/usr/sbin' && $rule =~ '-F perm=x' && $rule =~ 'key=privileged-unix-update' ]]
    then
      fail=2
    fi

    IFS=' ' read -a fieldvals <<< "${arule}"

    for field in ${fieldvals[@]}
    do
      if [[ $field =~ 'auid>=' ]]
      then
        if [[ $auidval != '-1' && $auidval != '4294967295' && $auidval != 'unset' ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be a form of unset; \"-1\", \"4294967295\", or \"unset\".${NORMAL}"
          fail=2
        fi
      fi
    done

    if [[ $fail == 0 ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$rule${NORMAL}"
    fi

  done

else
  echo -e "${NORMAL}RESULT:    ${RED}auditctl is missing a rule for 'unix_update'${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity39, $controlid, $stigid39, $ruleid39, $cci39, $datetime, ${GRN}PASSED, Use of the unix_update command is audited${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity39, $controlid, $stigid39, $ruleid39, $cci39, $datetime, ${RED}FAILED, Use of the unix_update command is not configured correctly${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity39, $controlid, $stigid39, $ruleid39, $cci39, $datetime, ${RED}FAILED, Use of the unix_update command is not audited${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

aurules=""
aurules="$(auditctl -l | grep userhelper)"
if [[ $aurules ]]
then
  rule=""
  for rule in ${aurules[@]}
  do
    if ! [[ $rule =~ '-a always,exit' && $rule =~ '-S all' && $rule =~ '/usr/sbin' && $rule =~ '-F perm=x' && $rule =~ 'key=privileged-unix-update' ]]
    then
      fail=2
    fi

    IFS=' ' read -a fieldvals <<< "${arule}"

    for field in ${fieldvals[@]}
    do
      if [[ $field =~ 'auid>=' ]]
      then
        if [[ $auidval != '-1' && $auidval != '4294967295' && $auidval != 'unset' ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be a form of unset; \"-1\", \"4294967295\", or \"unset\".${NORMAL}"
          fail=2
        fi
      fi
    done

    if [[ $fail == 0 ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$rule${NORMAL}"
    fi

  done

else
  echo -e "${NORMAL}RESULT:    ${RED}auditctl is missing a rule for 'userhelper'${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity40, $controlid, $stigid40, $ruleid40, $cci40, $datetime, ${GRN}PASSED, Use of the userhelper command is audited${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity40, $controlid, $stigid40, $ruleid40, $cci40, $datetime, ${RED}FAILED, Use of the userhelper command is not configured correctly${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity40, $controlid, $stigid40, $ruleid40, $cci40, $datetime, ${RED}FAILED, Use of the userhelper command is not audited${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

aurules=""
aurules="$(auditctl -l | grep usermod)"
if [[ $aurules ]]
then
  rule=""
  for rule in ${aurules[@]}
  do
    if ! [[ $rule =~ '-a always,exit' && $rule =~ '-S all' && $rule =~ '/usr/sbin' && $rule =~ '-F perm=x' && $rule =~ 'key=privileged-usermod' ]]
    then
      fail=2
    fi

    IFS=' ' read -a fieldvals <<< "${arule}"

    for field in ${fieldvals[@]}
    do
      if [[ $field =~ 'auid>=' ]]
      then
        if [[ $auidval != '-1' && $auidval != '4294967295' && $auidval != 'unset' ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be a form of unset; \"-1\", \"4294967295\", or \"unset\".${NORMAL}"
          fail=2
        fi
      fi
    done

    if [[ $fail == 0 ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$rule${NORMAL}"
    fi

  done

else
  echo -e "${NORMAL}RESULT:    ${RED}auditctl is missing a rule for 'usermod'${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity41, $controlid, $stigid41, $ruleid41, $cci41, $datetime, ${GRN}PASSED, Use of the usermod command is audited${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity41, $controlid, $stigid41, $ruleid41, $cci41, $datetime, ${RED}FAILED, Use of the usermod command is not configured correctly${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity41, $controlid, $stigid41, $ruleid41, $cci41, $datetime, ${RED}FAILED, Use of the usermod command is not audited${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

aurules=""
aurules="$(auditctl -l | grep /usr/bin/mount)"
if [[ $aurules ]]
then
  rule=""
  for rule in ${aurules[@]}
  do
    if ! [[ $rule =~ '-a always,exit' && $rule =~ '-S all' && $rule =~ '-F perm=x' && $rule =~ 'key=privileged-mount' ]]
    then
      fail=2
    fi

    IFS=' ' read -a fieldvals <<< "${arule}"

    for field in ${fieldvals[@]}
    do
      if [[ $field =~ 'auid>=' ]]
      then
        if [[ $auidval != '-1' && $auidval != '4294967295' && $auidval != 'unset' ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be a form of unset; \"-1\", \"4294967295\", or \"unset\".${NORMAL}"
          fail=2
        fi
      fi
    done

    if [[ $fail == 0 ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$rule${NORMAL}"
    fi

  done

else
  echo -e "${NORMAL}RESULT:    ${RED}auditctl is missing a rule for 'mount'${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity42, $controlid, $stigid42, $ruleid42, $cci42, $datetime, ${GRN}PASSED, Use of the mount command is audited${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity42, $controlid, $stigid42, $ruleid42, $cci42, $datetime, ${RED}FAILED, Use of the mount command is not configured correctly${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity42, $controlid, $stigid42, $ruleid42, $cci42, $datetime, ${RED}FAILED, Use of the mount command is not audited${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

aurules=""
aurules="$(auditctl -l | grep /usr/sbin/init)"
if [[ $aurules ]]
then
  rule=""
  for rule in ${aurules[@]}
  do
    if ! [[ $rule =~ '-a always,exit' && $rule =~ '-S all' && $rule =~ '-F perm=x' && $rule =~ 'key=privileged-init' ]]
    then
      fail=2
    fi

    IFS=' ' read -a fieldvals <<< "${arule}"

    for field in ${fieldvals[@]}
    do
      if [[ $field =~ 'auid>=' ]]
      then
        if [[ $auidval != '-1' && $auidval != '4294967295' && $auidval != 'unset' ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be a form of unset; \"-1\", \"4294967295\", or \"unset\".${NORMAL}"
          fail=2
        fi
      fi
    done

    if [[ $fail == 0 ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$rule${NORMAL}"
    fi

  done

else
  echo -e "${NORMAL}RESULT:    ${RED}auditctl is missing a rule for 'init'${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity43, $controlid, $stigid43, $ruleid43, $cci43, $datetime, ${GRN}PASSED, Use of the init command is audited${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity43, $controlid, $stigid43, $ruleid43, $cci43, $datetime, ${RED}FAILED, Use of the init command is not configured correctly${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity43, $controlid, $stigid43, $ruleid43, $cci43, $datetime, ${RED}FAILED, Use of the init command is not audited${NORMAL}"
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

IFS='
'

fail=0

datetime="$(date +%FT%H:%M:%S)"

aurules=""
aurules="$(auditctl -l | grep poweroff)"
if [[ $aurules ]]
then
  rule=""
  for rule in ${aurules[@]}
  do
    if ! [[ $rule =~ '-a always,exit' && $rule =~ '-S all' && $rule =~ '/usr/sbin' && $rule =~ '-F perm=x' && $rule =~ 'key=privileged-poweroff' ]]
    then
      fail=2
    fi

    IFS=' ' read -a fieldvals <<< "${arule}"

    for field in ${fieldvals[@]}
    do
      if [[ $field =~ 'auid>=' ]]
      then
        if [[ $auidval != '-1' && $auidval != '4294967295' && $auidval != 'unset' ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be a form of unset; \"-1\", \"4294967295\", or \"unset\".${NORMAL}"
          fail=2
        fi
      fi
    done

    if [[ $fail == 0 ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$rule${NORMAL}"
    fi

  done

else
  echo -e "${NORMAL}RESULT:    ${RED}auditctl is missing a rule for 'poweroff'${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity44, $controlid, $stigid44, $ruleid44, $cci44, $datetime, ${GRN}PASSED, Use of the poweroff command is audited${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity44, $controlid, $stigid44, $ruleid44, $cci44, $datetime, ${RED}FAILED, Use of the poweroff command is not configured correctly${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity44, $controlid, $stigid44, $ruleid44, $cci44, $datetime, ${RED}FAILED, Use of the poweroff command is not audited${NORMAL}"
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
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 45:   ${BLD}$title45a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title45b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title45c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity45${NORMAL}"

IFS='
'

fail=0

datetime="$(date +%FT%H:%M:%S)"

aurules=""
aurules="$(auditctl -l | grep reboot)"
if [[ $aurules ]]
then
  rule=""
  for rule in ${aurules[@]}
  do
    if ! [[ $rule =~ '-a always,exit' && $rule =~ '-S all' && $rule =~ '/usr/sbin' && $rule =~ '-F perm=x' && $rule =~ 'key=privileged-reboot' ]]
    then
      fail=2
    fi

    IFS=' ' read -a fieldvals <<< "${arule}"

    for field in ${fieldvals[@]}
    do
      if [[ $field =~ 'auid>=' ]]
      then
        if [[ $auidval != '-1' && $auidval != '4294967295' && $auidval != 'unset' ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be a form of unset; \"-1\", \"4294967295\", or \"unset\".${NORMAL}"
          fail=2
        fi
      fi
    done

    if [[ $fail == 0 ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$rule${NORMAL}"
    fi

  done

else
  echo -e "${NORMAL}RESULT:    ${RED}auditctl is missing a rule for 'reboot'${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity45, $controlid, $stigid45, $ruleid45, $cci45, $datetime, ${GRN}PASSED, Use of the reboot command is audited${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity45, $controlid, $stigid45, $ruleid45, $cci45, $datetime, ${RED}FAILED, Use of the reboot command is not configured correctly${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity45, $controlid, $stigid45, $ruleid45, $cci45, $datetime, ${RED}FAILED, Use of the reboot command is not audited${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

aurules=""
aurules="$(cat /etc/audit/rules.d/* | grep shutdown)"
if [[ $aurules ]]
then
  rule=""
  for rule in ${aurules[@]}
  do
    if ! [[ $rule =~ '-a always,exit' && $rule =~ '/usr/sbin' && $rule =~ '-F perm=x' && $rule =~ 'key=privileged-shutdown' ]]
    then
      fail=2
    fi

    IFS=' ' read -a fieldvals <<< "${arule}"

    for field in ${fieldvals[@]}
    do
      if [[ $field =~ 'auid>=' ]]
      then
        if [[ $auidval != '-1' && $auidval != '4294967295' && $auidval != 'unset' ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be a form of unset; \"-1\", \"4294967295\", or \"unset\".${NORMAL}"
          fail=2
        fi
      fi
    done

    if [[ $fail == 0 ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$rule${NORMAL}"
    fi

  done

else
  echo -e "${NORMAL}RESULT:    ${RED}auditctl is missing a rule for 'shutdown'${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity46, $controlid, $stigid46, $ruleid46, $cci46, $datetime, ${GRN}PASSED, Use of the shutdown command is audited${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity46, $controlid, $stigid46, $ruleid46, $cci46, $datetime, ${RED}FAILED, Use of the shutdown command is not configured correctly${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity46, $controlid, $stigid46, $ruleid46, $cci46, $datetime, ${RED}FAILED, Use of the shutdown command is not audited${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

aurules=""
aurules="$(auditctl -l | grep b32 | grep 'umount\b')"
if [[ $aurules ]]
then
  rule=""
  for rule in ${aurules[@]}
  do
    if ! [[ $rule =~ '-a always,exit' && $rule =~ 'key=privileged-umount' ]]
    then
      fail=2
    fi

    IFS=' ' read -a fieldvals <<< "${arule}"

    for field in ${fieldvals[@]}
    do
      if [[ $field =~ 'auid>=' ]]
      then
        if [[ $auidval != '-1' && $auidval != '4294967295' && $auidval != 'unset' ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be a form of unset; \"-1\", \"4294967295\", or \"unset\".${NORMAL}"
          fail=2
        fi
      fi
    done

    if [[ $fail == 0 ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$rule${NORMAL}"
    fi

  done

else
  echo -e "${NORMAL}RESULT:    ${RED}auditctl is missing a rule for 'umount'${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity47, $controlid, $stigid47, $ruleid47, $cci47, $datetime, ${GRN}PASSED, Use of the umount command is audited${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity47, $controlid, $stigid47, $ruleid47, $cci47, $datetime, ${RED}FAILED, Use of the umount command is not configured correctly${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity47, $controlid, $stigid47, $ruleid47, $cci47, $datetime, ${RED}FAILED, Use of the umount command is not audited${NORMAL}"
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

IFS='
'

fail=0

datetime="$(date +%FT%H:%M:%S)"

aurules=""
aurules="$(auditctl -l | grep 'umount2')"
if [[ $aurules ]]
then
  rule=""
  for rule in ${aurules[@]}
  do
    if ! [[ $rule =~ '-a always,exit' && $rule =~ 'key=privileged-umount' ]]
    then
      fail=2
    fi

    IFS=' ' read -a fieldvals <<< "${arule}"

    for field in ${fieldvals[@]}
    do
      if [[ $field =~ 'auid>=' ]]
      then
        if [[ $auidval != '-1' && $auidval != '4294967295' && $auidval != 'unset' ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be a form of unset; \"-1\", \"4294967295\", or \"unset\".${NORMAL}"
          fail=2
        fi
      fi
    done

    if [[ $fail == 0 ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$rule${NORMAL}"
    fi

  done

else
  echo -e "${NORMAL}RESULT:    ${RED}auditctl is missing a rule for 'umount2'${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity48, $controlid, $stigid48, $ruleid48, $cci48, $datetime, ${GRN}PASSED, Use of the umount2 command is audited${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity48, $controlid, $stigid48, $ruleid48, $cci48, $datetime, ${RED}FAILED, Use of the umount2 command is not configured correctly${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity48, $controlid, $stigid48, $ruleid48, $cci48, $datetime, ${RED}FAILED, Use of the umount2 command is not audited${NORMAL}"
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
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 49:   ${BLD}$title49a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title49b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title49c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity49${NORMAL}"

IFS='
'

fail=0

datetime="$(date +%FT%H:%M:%S)"

aurules=""
aurules="$(auditctl -l | grep '/etc/sudoers[^.]')"
if [[ $aurules ]]
then
  rule=""
  for rule in ${aurules[@]}
  do
    if ! [[ $rule =~ '-w /etc/sudoers' && $rule =~ '-p wa' ]]
    then
      fail=2
    fi

    if [[ $fail == 0 ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$rule${NORMAL}"
    fi

  done

else
  echo -e "${NORMAL}RESULT:    ${RED}auditctl is missing a rule for 'sudoers'${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity49, $controlid, $stigid49, $ruleid49, $cci49, $datetime, ${GRN}PASSED, RHEL 9 generates audit records for all account creations modifications disabling and termination events that affect /etc/sudoers.${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity49, $controlid, $stigid49, $ruleid49, $cci49, $datetime, ${RED}FAILED, Use of sudoers is not configured correctly${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity49, $controlid, $stigid49, $ruleid49, $cci49, $datetime, ${RED}FAILED, RHEL 9 does not generate audit records for all account creations modifications disabling and termination events that affect /etc/sudoers.${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

aurules=""
aurules="$(auditctl -l | grep '/etc/sudoers.d')"
if [[ $aurules ]]
then
  rule=""
  for rule in ${aurules[@]}
  do
    if ! [[ $rule =~ '-w' && $rule =~ '-p wa' && $rule =~ '-k identity' ]]
    then
      fail=2
    fi

    if [[ $fail == 0 ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$rule${NORMAL}"
    fi

  done

else
  echo -e "${NORMAL}RESULT:    ${RED}auditctl is missing a rule for 'sudoers.d'${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity50, $controlid, $stigid50, $ruleid50, $cci50, $datetime, ${GRN}PASSED, RHEL 9 generates audit records for all account creations modifications disabling and termination events that affect /etc/sudoers.d/ directory.${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity50, $controlid, $stigid50, $ruleid50, $cci50, $datetime, ${RED}FAILED, Use of the sudoers.d directory is not configured correctly${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity50, $controlid, $stigid50, $ruleid50, $cci50, $datetime, ${RED}FAILED, RHEL 9 does not generate audit records for all account creations modifications disabling and termination events that affect /etc/sudoers.d/ directory.${NORMAL}"
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
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 51:   ${BLD}$title51a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title51b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title51c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity51${NORMAL}"

IFS='
'

fail=0

datetime="$(date +%FT%H:%M:%S)"

aurules=""
aurules="$(auditctl -l | egrep '/etc/group')"
if [[ $aurules ]]
then
  rule=""
  for rule in ${aurules[@]}
  do
    if ! [[ $rule =~ '-w' && $rule =~ '-p wa' && $rule =~ '-k identity' ]]
    then
      fail=2
    fi

    if [[ $fail == 0 ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$rule${NORMAL}"
    fi

  done

else
  echo -e "${NORMAL}RESULT:    ${RED}auditctl is missing a rule for 'group'${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity51, $controlid, $stigid51, $ruleid51, $cci51, $datetime, ${GRN}PASSED, RHEL 9 generates audit records for all account creations modifications disabling and termination events that affect /etc/group.${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity51, $controlid, $stigid51, $ruleid51, $cci51, $datetime, ${RED}FAILED, Use of group is not configured correctly${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity51, $controlid, $stigid51, $ruleid51, $cci51, $datetime, ${RED}FAILED, RHEL 9 does not generate audit records for all account creations modifications disabling and termination events that affect /etc/group.${NORMAL}"
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
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 52:   ${BLD}$title52a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title52b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title52c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity52${NORMAL}"

IFS='
'

fail=0

datetime="$(date +%FT%H:%M:%S)"

aurules=""
aurules="$(auditctl -l | egrep '/etc/gshadow')"
if [[ $aurules ]]
then
  rule=""
  for rule in ${aurules[@]}
  do
    if ! [[ $rule =~ '-w' && $rule =~ '-p wa' && $rule =~ '-k identity' ]]
    then
      fail=2
    fi

    if [[ $fail == 0 ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$rule${NORMAL}"
    fi

  done

else
  echo -e "${NORMAL}RESULT:    ${RED}auditctl is missing a rule for 'gshadow'${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity52, $controlid, $stigid52, $ruleid52, $cci52, $datetime, ${GRN}PASSED, RHEL 9 generates audit records for all account creations modifications disabling and termination events that affect /etc/gshadow.${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity52, $controlid, $stigid52, $ruleid52, $cci52, $datetime, ${RED}FAILED, Use of gshadow is not configured correctly${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity52, $controlid, $stigid52, $ruleid52, $cci52, $datetime, ${RED}FAILED, RHEL 9 does not generate audit records for all account creations modifications disabling and termination events that affect /etc/gshadow.${NORMAL}"
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
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 53:   ${BLD}$title53a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title53b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title53c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity53${NORMAL}"

IFS='
'

fail=0

datetime="$(date +%FT%H:%M:%S)"

aurules=""
aurules="$(auditctl -l | egrep '/etc/security/opasswd')"
if [[ $aurules ]]
then
  rule=""
  for rule in ${aurules[@]}
  do
    if ! [[ $rule =~ '-w' && $rule =~ '-p wa' && $rule =~ '-k identity' ]]
    then
      fail=2
    fi

    if [[ $fail == 0 ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$rule${NORMAL}"
    fi

  done

else
  echo -e "${NORMAL}RESULT:    ${RED}auditctl is missing a rule for 'opasswd'${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity53, $controlid, $stigid53, $ruleid53, $cci53, $datetime, ${GRN}PASSED, RHEL 9 generates audit records for all account creations modifications disabling and termination events that affect /etc/security/opasswd.${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity53, $controlid, $stigid53, $ruleid53, $cci53, $datetime, ${RED}FAILED, Use of opasswd is not configured correctly${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity53, $controlid, $stigid53, $ruleid53, $cci53, $datetime, ${RED}FAILED, RHEL 9 does not generate audit records for all account creations modifications disabling and termination events that affect /etc/security/opasswd.${NORMAL}"
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
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 54:   ${BLD}$title54a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title54b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title54c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity54${NORMAL}"

IFS='
'

fail=0

datetime="$(date +%FT%H:%M:%S)"

aurules=""
aurules="$(auditctl -l | egrep '/etc/passwd')"
if [[ $aurules ]]
then
  rule=""
  for rule in ${aurules[@]}
  do
    if ! [[ $rule =~ '-w' && $rule =~ '-p wa' && $rule =~ '-k identity' ]]
    then
      fail=2
    fi

    if [[ $fail == 0 ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$rule${NORMAL}"
    fi

  done

else
  echo -e "${NORMAL}RESULT:    ${RED}auditctl is missing a rule for 'passwd'${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity54, $controlid, $stigid54, $ruleid54, $cci54, $datetime, ${GRN}PASSED, RHEL 9 generates audit records for all account creations modifications disabling and termination events that affect /etc/security/passwd.${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity54, $controlid, $stigid54, $ruleid54, $cci54, $datetime, ${RED}FAILED, Use of passwd is not configured correctly${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity54, $controlid, $stigid54, $ruleid54, $cci54, $datetime, ${RED}FAILED, RHEL 9 does not generate audit records for all account creations modifications disabling and termination events that affect /etc/security/passwd.${NORMAL}"
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
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 55:   ${BLD}$title55a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title55b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title55c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity55${NORMAL}"

IFS='
'

fail=0

datetime="$(date +%FT%H:%M:%S)"

aurules=""
aurules="$(auditctl -l | egrep '/etc/shadow')"
if [[ $aurules ]]
then
  rule=""
  for rule in ${aurules[@]}
  do
    if ! [[ $rule =~ '-w' && $rule =~ '-p wa' && $rule =~ '-k identity' ]]
    then
      fail=2
    fi

    if [[ $fail == 0 ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$rule${NORMAL}"
    fi

  done

else
  echo -e "${NORMAL}RESULT:    ${RED}auditctl is missing a rule for 'shadow'${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity55, $controlid, $stigid55, $ruleid55, $cci55, $datetime, ${GRN}PASSED, RHEL 9 generates audit records for all account creations modifications disabling and termination events that affect /etc/shadow.${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity55, $controlid, $stigid55, $ruleid55, $cci55, $datetime, ${RED}FAILED, Use of /etc/shadow is not configured correctly${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity55, $controlid, $stigid55, $ruleid55, $cci55, $datetime, ${RED}FAILED, RHEL 9 does not generate audit records for all account creations modifications disabling and termination events that affect /etc/shadow.${NORMAL}"
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
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 56:   ${BLD}$title56a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title56b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title56c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity56${NORMAL}"

IFS='
'

fail=0

datetime="$(date +%FT%H:%M:%S)"

aurules=""
aurules="$(auditctl -l | grep /var/log/faillock)"
if [[ $aurules ]]
then
  rule=""
  for rule in ${aurules[@]}
  do
    if ! [[ $rule =~ '-w' && $rule =~ '-p wa' && $rule =~ '-k logins' ]]
    then
      fail=2
    fi

    if [[ $fail == 0 ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$rule${NORMAL}"
    fi

  done

else
  echo -e "${NORMAL}RESULT:    ${RED}auditctl is missing a rule for '/var/log/faillock'${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity56, $controlid, $stigid56, $ruleid56, $cci56, $datetime, ${GRN}PASSED, RHEL 9 generates audit records for all account creations modifications disabling and termination events that affect /var/log/faillock.${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity56, $controlid, $stigid56, $ruleid56, $cci56, $datetime, ${RED}FAILED, Use of /var/log/faillock is not configured correctly${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity56, $controlid, $stigid56, $ruleid56, $cci56, $datetime, ${RED}FAILED, RHEL 9 does not generate audit records for all account creations modifications disabling and termination events that affect /var/log/faillock.${NORMAL}"
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
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 57:   ${BLD}$title57a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title57b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title57c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity57${NORMAL}"

IFS='
'

fail=0

datetime="$(date +%FT%H:%M:%S)"

aurules=""
aurules="$(auditctl -l | grep /var/log/lastlog)"
if [[ $aurules ]]
then
  rule=""
  for rule in ${aurules[@]}
  do
    if ! [[ $rule =~ '-w' && $rule =~ '-p wa' && $rule =~ '-k logins' ]]
    then
      fail=2
    fi

    if [[ $fail == 0 ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$rule${NORMAL}"
    fi

  done

else
  echo -e "${NORMAL}RESULT:    ${RED}auditctl is missing a rule for '/var/log/lastlog'${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity57, $controlid, $stigid57, $ruleid57, $cci57, $datetime, ${GRN}PASSED, RHEL 9 generates audit records for all account creations modifications disabling and termination events that affect /var/log/lastlog.${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity57, $controlid, $stigid57, $ruleid57, $cci57, $datetime, ${RED}FAILED, Use of /var/log/lastlog is not configured correctly${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity57, $controlid, $stigid57, $ruleid57, $cci57, $datetime, ${RED}FAILED, RHEL 9 does not generate audit records for all account creations modifications disabling and termination events that affect /var/log/lastlog.${NORMAL}"
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
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 58:   ${BLD}$title58a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title58b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title58c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity58${NORMAL}"

IFS='
'

fail=0

datetime="$(date +%FT%H:%M:%S)"

search=("/etc/cron.d" "/var/spool/cron")

for item in ${search[@]}
do
  itemfail=0
  aurules=""
  aurules="$(auditctl -l | grep $item)"
  if [[ $aurules ]]
  then
    rule=""
    for rule in ${aurules[@]}
    do
      if ! [[ $rule =~ '-w' && $rule =~ '-p wa' && $rule =~ '-k cronjobs' ]]
      then
        fail=2
	itemfail=2
      fi
  
      if [[ $itemfail == 0 ]]
      then
        echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
      else
        echo -e "${NORMAL}RESULT:    ${RED}$rule${NORMAL}"
      fi
    done
  
  else
    echo -e "${NORMAL}RESULT:    ${RED}auditctl is missing a rule for $item${NORMAL}"
    fail=1
  fi
 
done

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity58, $controlid, $stigid58, $ruleid58, $cci58, $datetime, ${GRN}PASSED, RHEL 9 audits any script or executable called by cron as root or by any privileged user.${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity58, $controlid, $stigid58, $ruleid58, $cci58, $datetime, ${RED}FAILED, Auditing scripts or exacutables called by cron as root or by any privileged user is not configured correctly${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity58, $controlid, $stigid58, $ruleid58, $cci58, $datetime, ${RED}FAILED, RHEL 9 does not audit any script or executable called by cron as root or by any privileged user.${NORMAL}"
fi

exit

