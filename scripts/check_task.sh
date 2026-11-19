#!/usr/bin/env bash
set -euo pipefail
task="${1:?usage: Scripts/check_tasks.sh tasks/<name>}"
run() {  # $1 = vuln | fixed
  local tmp; tmp="$(mktemp -d)"   # create a temporary directory to run the task
  cp -r "$task/$1/." "$tmp/" #copy the task folder into the temp directory
  mkdir -p "$tmp/test"      #create a directory to run the foundry test in the temp dir.
  cp "$task/grader/Exploit.t.sol" "$tmp/test/Exploit.t.sol"   #copy the solution file into the test dir
  #
  if (cd "$tmp" && forge test --match-path test/Exploit.t.sol >/dev/null 2>&1); then echo pass; else echo fail; fi
  rm -rf "$tmp"    # delete the temporary directory 
}
v=$(run vuln); f=$(run fixed)   #store the vulnerable and fixed run in two separate variables
echo "vuln : exploit test $v   (expected: pass)"  #run the vulnerable
echo "fixed: exploit test $f   (expected: fail)"   #run the fixed
#if the exploit runs successfully on the vulnerable and fails on the fixed, then say task is valid else, say it isn't.
if [ "$v" = pass ] && [ "$f" = fail ]; then echo "OK: task is valid"; else echo "TASK INVALID"; exit 1; fi