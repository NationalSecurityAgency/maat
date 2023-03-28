#!/bin/bash

# Collect results from saracode

function issue_file() {
    echo $1 | cut -d ',' -f 4 | sed -e 's|^maat/||';
}

function issue_line(){
    echo $1 | cut -d ',' -f 5;
}

function issue_message(){
    echo $1 | cut -d ',' -f 9-;
}

function issue_tool(){
    echo $1 | cut -d ',' -f 3;
}

function note_for_issue(){
    echo -e "$(issue_file $1):$(issue_line $1)\\n\\n$(issue_message $1)\\n\\nReported by $(issue_tool $1)";
}

function issue_file_changed(){
    git diff --name-only origin/develop | grep -q "$(issue_file $1)";
}

COMMENT_URL=https://gitlab.jhuapl.edu/api/v4/projects/14/repository/commits/$(git rev-list HEAD -1)/comments
function post_comment(){ curl -f -k -X POST ${COMMENT_URL} --header "private-token: $COMMENT_POSTING_TOKEN" --form "note=$(note_for_issue $1)" --form "path=$(issue_file $1)" --form "line=$(issue_line $1)" --form "line_type=new" || echo "failed to post";
}

HDR="X-Auth-Token: ${SARACODE_TOKEN}"

. ./saracode_build_id

echo BUILD_ID=${BUILD_ID}

# Wait for saracode to ready
while [ "x$(curl -s -k -H "${HDR}" ${SARACODE_ROOT}/analysis/${BUILD_ID}/ready)" = "xfalse" ]; do sleep 5; done

curl -s -k -H "${HDR}" ${SARACODE_ROOT}/issues/${BUILD_ID} > issues.csv
curl -s -k -H "${HDR}" ${SARACODE_ROOT}/analysis/${BUILD_ID}/console > console.txt

( read ; while read issue; do if issue_file_changed $issue; then echo "Adding comment for issue: $issue"; post_comment "$issue"; fi; done ) < issues.csv
