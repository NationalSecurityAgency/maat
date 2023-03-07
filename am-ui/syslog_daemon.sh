# Copyright 2023 United States Government
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
#

#
# syslog_daemon.sh: Bash script to catch log messages tagged with
# PRESENTATION MODE and forward them to the AM UI.
# 


#!/bin/bash

regex="PRESENTATION MODE \(([a-z]+)\): (.*)"

cat /etc/os-release | grep -qi 'ubuntu'
if [[ $? == 0 ]]
then
	log_path="/var/log/syslog"
else
	log_path="/var/log/messages"
fi

while read line
do
	if [[ $line =~ $regex ]]
	then
		dir="${BASH_REMATCH[1]}"
		message="${BASH_REMATCH[2]}"
		message_no_space=${message// /+}
		url="http://127.0.0.1:5000/update/steps?dir=${dir}&message=${message_no_space}"
		curl -X PUT  ${url}
		echo "found $? $line"
	fi
done < <(sudo tail -F -n 0 $log_path)

