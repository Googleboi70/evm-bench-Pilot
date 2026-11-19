chech_tasks.sh is a bash script that orchestrates the whole test run for our custom comparison

The script takes three arguments, two mandatory, one optional, namely:

  -The folder where the fixed source, vulnerable source and the ground truth resides
  -The dependencies folder
  -The log file

The script has a run function that takes an argument of the name of folder to pick a source file from: Vulnerable or Fixed
The run function mainly does the following:
  -Creates a temporary directory where the whole testing will take place
  -Copies the necessary folders(test/, src/ lib/) and files into it
  -based on the function argument,run the foundry test
  -if the test passes, echo pass, else echo fail
The script also invokes the run function twice, with different arguments. and stores the output (pass/fail) in a variable.
Then if the vulnerable run passes and the fixed run fails, it echoes task is valid, else, it echoes task is inalid.





