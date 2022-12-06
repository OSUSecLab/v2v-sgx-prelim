#!/bin/bash
for i in {1..500}
do
   echo "Welcome $i times"
   ./app
   sleep 10
done

