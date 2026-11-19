#!/usr/bin/env bash
set -euo pipefail
task="${1:?usage: Scripts/check_tasks.sh tasks/<name>}"
lib_dir="${2:?usage: Scripts/check_tasks.sh tasks/<name> tasks/lib}"
log_file="${3:-$(pwd)/foundry.log}"  # optional log file, default to ./foundry.log if not provided

: > "$log_file"  # first clear the log file

run() {  # $1 = vuln | fixed
  local tmp; tmp="$(mktemp -d)"   # create a temporary directory to run the task
  cp -r "$task/$1/." "$tmp/" #copy the task folder into the temp directory
  mkdir -p "$tmp/test" "$tmp/src" "$tmp/lib"  #create the test, src and lib directories in the temp directory

  local src_file
  src_file="$(find "$task/$1" -name '*.sol' | head -n 1)"
  if [ -z "$src_file" ]; then echo "No source file found in $task/$1"; exit 1; fi
  cp "$src_file" "$tmp/src/$(basename "$src_file")"  #copy the source file into the src dir
  cp "$task/grader/Solution.t.sol" "$tmp/test/Solution.t.sol"   #copy the solution file into the test dir
  
  #copy the dependencies folder into the temporary directory
  cp -r "$lib_dir/." "$tmp/lib/"
  
  {
    echo "========================================================================================="
    echo "Running from source: $src_file"
    echo "========================================================================================="
  } >> "$log_file" 2>&1

  if (cd "$tmp" && forge test --match-path test/Solution.t.sol >>"$log_file" 2>&1); then echo pass; else echo fail; fi
  rm -rf "$tmp"    # delete the temporary directory 
}


v=$(run Vulnerable); f=$(run Fixed)   #store the vulnerable and fixed run in two separate variables
echo "Vulnerable : exploit test $v   (expected: pass)"  #run the vulnerable
echo "Fixed: exploit test $f   (expected: fail)"   #run the fixed
#if the exploit runs successfully on the vulnerable and fails on the fixed, then say task is valid else, say it isn't.
if [ "$v" = pass ] && [ "$f" = fail ]; then echo "OK: task is valid"; else echo "TASK INVALID"; exit 1; fi