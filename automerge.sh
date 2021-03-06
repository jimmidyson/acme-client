#!/bin/bash
#
# Copyright (C) 2016 Red Hat, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

if [[ "${CI_PULL_REQUEST}" == "" ]]; then
  echo "Not a PR... nothing to merge"
  exit 0
fi

echo "Auto-merging pull request ${CI_PULL_REQUEST}"
MERGE_URL=${CI_PULL_REQUEST/\/pull\//\/pulls\/}/merge
MERGE_URL=${MERGE_URL/github.com\//api.github.com\/repos\/}
STATUS_CODE=$(curl -qSfsw '%{http_code}' -o /dev/null -XPUT -H "Authorization: token ${GITHUB_ACCESS_TOKEN}" -d"{\"sha\":\"${CIRCLE_SHA1}\"}" -H 'Accept: application/vnd.github.v3+json' ${MERGE_URL})
echo "Received ${STATUS_CODE}"
if [[ "$STATUS_CODE" != "200" ]]; then
  echo "Auto-merge failed..."
  exit 1
fi

echo "Deleting PR branch ${CIRCLE_BRANCH}"
DELETE_BRANCH_URL=https://api.github.com/repos/${CIRCLE_PROJECT_USERNAME}/${CIRCLE_PROJECT_REPONAME}/git/refs/heads/${CIRCLE_BRANCH}
STATUS_CODE=$(curl -qSfsw '%{http_code}' -o /dev/null -XDELETE -H "Authorization: token ${GITHUB_ACCESS_TOKEN}" -H 'Accept: application/vnd.github.v3+json' ${DELETE_BRANCH_URL})
echo "Received ${STATUS_CODE}"
if [[ "$STATUS_CODE" != "204" ]]; then
  echo "Delete branch failed - you'll have to do this manually..."
fi

COMMENT_URL=${CI_PULL_REQUEST/\/pull\//\/issues\/}/comments
COMMENT_URL=${COMMENT_URL/github.com\//api.github.com\/repos\/}
STATUS_CODE=$(curl -qSfsw '%{http_code}' -o /dev/null -XPOST -H "Authorization: token ${GITHUB_ACCESS_TOKEN}" -d'{"body":"PR merged & branch deleted!"}' -H 'Accept: application/vnd.github.v3+json' ${COMMENT_URL})
echo "Received ${STATUS_CODE}"
if [[ "$STATUS_CODE" != "201" ]]; then
  echo "Failed to comment - sorry, I did try though..."
fi

