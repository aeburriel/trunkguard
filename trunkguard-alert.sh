#!/bin/sh

# trunkguard-alert.sh
# Arguments:
#  1: Alert type
#  2: Timestamp
#  3: Source MAC address
#  4: Network device
#  5: VLAN number or 'None'
#  6: Source MAC vendor or '' if unknown

alert=$1
timestamp=$2
mac=$3
dev=$4
vlan=$5
vendor=$6

rcpt_to="operator@organization.local, noc@organization.local"
subject="[TrunkGuard] Intruder $mac detected"

cat << EOF | mail -s "$subject" "$rcpt_to"
Security Alert !

Type:       $alert
Timestamp:  $timestamp
Source MAC: $mac (vendor: ${vendor:=**unknown**})
Device:     $dev
VLAN:       $vlan

Host:       $(hostname)
EOF
