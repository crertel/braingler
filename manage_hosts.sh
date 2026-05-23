#!/usr/bin/env bash

# File containing hostnames and MAC addresses
FILE=~/host_macs

# Check if the file exists
if [[ ! -f $FILE ]]; then
  echo "File $FILE not found!"
  exit 1
fi

# Display list of known hosts
echo "Known hosts:"
HOSTS=()
while IFS= read -r line; do
  HOST=$(echo $line | awk '{print $1}')
  MAC=$(echo $line | awk '{print $2}')
  HOSTS+=("$HOST $MAC")
  echo "$HOST"
done < $FILE

# Prompt user to select a host
echo
read -p "Enter the hostname to select: " SELECTED_HOST

# Check if the selected host is in the list
HOST_FOUND=0
for ENTRY in "${HOSTS[@]}"; do
  if [[ $ENTRY == "$SELECTED_HOST "* ]]; then
    HOST_FOUND=1
    MAC_ADDRESS=$(echo $ENTRY | awk '{print $2}')
    break
  fi
done

if [[ $HOST_FOUND -eq 0 ]]; then
  echo "Host not found!"
  exit 1
fi

# Prompt user for an action
echo "Select an action:"
echo "1. Ping the host to see if it's awake"
echo "2. Turn off the host via SSH"
echo "3. Turn on the host via Wake-on-LAN (wakelan)"
read -p "Enter the action number: " ACTION

# Perform the selected action
case $ACTION in
  1)
    echo "Pinging $SELECTED_HOST..."
    ping -c 4 $SELECTED_HOST
    ;;
  2)
    echo "Turning off $SELECTED_HOST via SSH..."
    ssh $SELECTED_HOST 'sudo -S shutdown -hP now'
    ;;
  3)
    echo "Turning on $SELECTED_HOST via Wake-on-LAN..."
    wakelan $MAC_ADDRESS 192.168.1.255
    ;;
  *)
    echo "Invalid action selected!"
    ;;
esac

