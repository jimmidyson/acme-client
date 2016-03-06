#!/bin/bash

echo "Auto-merging pull request ${CI_PULL_REQUEST}"
STATUS_CODE=$(curl -qSfsw '\n%{http_code}' -XPUT -H "Authorization: token ${GITHUB_ACCESS_TOKEN}" -d"{\"sha\":\"${CIRCLE_SHA1}\"}" ${CI_PULL_REQUEST}/merge)
echo "Received ${STATUS_CODE}"
if [[ "$STATUS_CODE" -ne "200" ]]; then
  echo "Auto-merge failed..."
  exit 1
fi

