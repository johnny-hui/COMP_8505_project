#!/bin/bash

# Create two files
touch file1.txt
touch file2.txt
touch bob.txt

# Provide some content for the files
echo "bob" > file1.txt
echo "I love cats" > file2.txt
echo "[+] Files created successfully: file1.txt, file2.txt"

# Print the current date and time
current_datetime=$(date +"%Y-%m-%d %H:%M:%S")
echo "The current date and time is: $current_datetime"
