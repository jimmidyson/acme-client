#!/bin/bash

echo "Auto-merging pull request ${CI_PULL_REQUEST}"
MERGE_URL=${CI_PULL_REQUEST/\/pull\//\/pulls\/}/merge
MERGE_URL=${MERGE_URL/github.com\//api.github.com\/repos\/}
STATUS_CODE=$(curl -qSfsw '\n%{http_code}' -XPUT -H "Authorization: token ${GITHUB_ACCESS_TOKEN}" -d"{\"sha\":\"${CIRCLE_SHA1}\"}" -H 'Accept: application/vnd.github.v3+json' ${MERGE_URL})
echo "Received ${STATUS_CODE}"
if [[ "$STATUS_CODE" -ne "200" ]]; then
  echo "Auto-merge failed..."
  exit 1
fi

