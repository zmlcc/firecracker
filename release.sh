#!/bin/bash

PrivateToken="BdxfJEJpY4F1zjR1sU2y"
RequestEndpoint="https://git.ucloudadmin.com/api/v4/projects/5347/releases"

curl --header 'Content-Type: application/json' --header "PRIVATE-TOKEN: $PrivateToken" \
     --data "{ \"name\": \"$CI_COMMIT_TAG\", \"tag_name\": \"$CI_COMMIT_TAG\", \"description\": \"Need to write\", \"assets\": { \"links\": [{ \"name\": \"firecracker\", \"url\": \"https://git.ucloudadmin.com/torpedo/firecracker/-/jobs/$CI_JOB_ID/artifacts/raw/bin/firecracker\" }] } }" \
     --request POST $RequestEndpoint
