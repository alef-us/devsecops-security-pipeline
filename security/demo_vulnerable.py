"""Negative-test fixture only: Bandit must report the intentional subprocess issue."""

import subprocess

user_supplied_command = input("fixture only: ")
subprocess.run(user_supplied_command, shell=True, check=False)
