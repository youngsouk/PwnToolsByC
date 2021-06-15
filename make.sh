#!/bin/bash

file=$(ls -c | grep '.c$' | head -1 | rev | cut -c 3- | rev)
file_name=$(ls -c | grep '.c$' | head -1)

echo "gcc -o $file $file_name"
gcc -o $file $file_name
