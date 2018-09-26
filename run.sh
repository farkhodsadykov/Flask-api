#!/bin/bash
DATE=$(date +%F)
while True ; do
  clear
  echo "1. Run Flask"
  echo "2. Take a backup logs"
  echo "3. Kill Flask"
  read -p "option :" chose
  while True ; do
    if [[ $chose = '1' ]]; then
      nohup  python app.py & > nohup.out
      echo "Flask is start and runing"
    elif [[ $chose = '2' ]]; then
      tar -cfz $DATE.tar.gz nohup.out
      echo " " > nohup.out
      echo "2"
      sleep 0.5
      break
    elif [[ $chose = '3' ]]; then
      echo "3"
      sleep 0.5
      break
    else
      echo "Wrong option "
      sleep 0.5
      break

    fi
  done


done
