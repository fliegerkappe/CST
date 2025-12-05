#! /bin/bash

# SC-28 Protection of Information At Rest
#
# CONTROL: Protect the [Selection (one or more): confidentiality; integrity] of the following
# information at rest: [Assignment: organization-defined information at rest].

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

controlid="SC-28 Protection of Information At Rest"

title1a="All RHEL 9 local disk partitions must implement cryptographic mechanisms to prevent unauthorized disclosure or modification of all information that requires at rest protection."
title1b="Checking with:
           a. lsblk --tree
	   b. cryptsetup status luks-b74f6910-2547-4399-86b2-8b0252d926d7"
title1c="Expecting: ${YLO}
           a. NAME                       MAJ:MIN  RM   SIZE     RO    TYPE    MOUNTPOINTS
           a. zram0                      252:0    0    8G       0     disk    [SWAP]
           a. nvme0n1                    259:0    0    476.9G   0     disk
           a. |-nvme0n1p1                259:1    0    1G       0     part    /boot/efi
           a. |-nvme0n1p2                259:2    0    1G       0     part    /boot
           a. |-nvme0n1p3                259:3    0    474.9G   0     part
           a. ${BLD}  |-luks-<encrypted_id>    253:0    0    474.9G   0     crypt${YLO}
           a.     |-rhel-root            253:1    0    16G      0     lvm     /
           a.     |-rhel-varcache        253:2    0    8G       0     lvm     /var/cache
           a.     |-rhel-vartmp          253:3    0    4G       0     lvm     /var/tmp
           a.     |-rhel-varlog          253:4    0    4G       0     lvm     /var/log
           a.     |-rhel-home            253:5    0    64G      0     lvm     /home
           a.     |-rhel-varlogaudit     253:6    0    4G       0     lvm     /var/log/audit
           b. ${BLD}/dev/mapper/luks-b74f6910-2547-4399-86b2-8b0252d926d7 is active and is in use.${YLO}
           b.   type:    LUKS2
           b.   cipher:  aes-xts-plain64
           b.   keysize: 512 bits
           b.   key location: keyring
           b.   device:  /dev/nvme0n1p3
           b.   sector size:  512
           b.   offset:  32768 sectors
           b.   size:    995986063 sectors
           b.   mode:    read/write
           NOTE: If there are persistent filesystems (other than /boot or /boot/efi) whose block device trees do not have a crypt block device of type LUKS, ask the administrator to indicate how persistent filesystems are encrypted. 
           NOTE: If there is no evidence that persistent filesystems are encrypted, this is a finding."${BLD}
cci1="CCI-001199 CCI-002475 CCI-002476"
stigid1="RHEL-09-231190"
severity1="CAT I"
ruleid1="SV-257879r1045454"
vulnid1="V-257879"

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

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

blktree="$(lsblk --tree)"

found=0

for branch in ${blktree[@]}
do
  if [[ $branch =~ 'luks' && $branch =~ 'crypt' ]]
  then
    found=1
    echo -e "${NORMAL}RESULT:    ${BLD}a. $branch${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    a. $branch${NORMAL}"
  fi
done

if [[ $found == 1 ]]
then
  luks="$(cryptsetup status luks-b74f6910-2547-4399-86b2-8b0252d926d7)"
  if [[ $luks ]]
  then
    for line in ${luks[@]}
    do
      if [[ $line =~ "is active and is in use" ]]
      then
        fail=0
        echo -e "${NORMAL}RESULT:    ${BLD}b. $line${NORMAL}"
      else
        echo -e "${NORMAL}RESULT:    b. $line${NORMAL}"
      fi
    done
  else
    echo -e "${NORMAL}RESULT:    ${RED}b. Nothing returned${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}b. No blocks of type \"crypt\" returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, RHEL 9 local disk partitions implements cryptographic mechanisms to prevent unauthorized disclosure or modification of all information that requires at rest protection.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, RHEL 9 local disk partitions do not implement cryptographic mechanisms to prevent unauthorized disclosure or modification of all information that requires at rest protection.${NORMAL}"
fi

exit
