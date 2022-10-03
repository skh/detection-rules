# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Potential SSH Brute Force Detected on Privileged Account
# RTA: brute_force_ssh.py
# ATT&CK: T1110
# Description: Simulates brute force or password spraying tactics.
#              Remote audit failures must be enabled to trigger: `auditpol /set /subcategory:"Logon" /failure:enable`

import random
import string
import sys
import time

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="a5f0d057-d540-44f5-924d-c6a2ae92f045", # this was created in a python shell with uuid.uuid4() -- proper way?
    platforms=["linux"],
    endpoint=[],
    siem=[
        {"rule_id": "a5f0d057-d540-44f5-924d-c6a2ae92f045", "rule_name": "Potential SSH Brute Force Detected on Privileged Account"}
    ],
    techniques=["T1110"],
)


@common.requires_os(metadata.platforms)
def main(remote_host=None):
    if not remote_host:
        common.log("A remote host is required to detonate this RTA", "!")
        return common.MISSING_REMOTE_HOST

    # nope, not available on linux
    # common.enable_logon_auditing(remote_host)

    common.log("Brute forcing login with invalid password against root@{}".format(remote_host))

    command = ["sshpass", "-p", "NotThePassword", "ssh", "root@{}".format(remote_host)] # root hardcoded. could be expanded to also test non-privileged accounts

    # try 10 times - the first 9 concurrently and wait for the final to complete
    for i in range(10):
        common.execute(command, wait=(i==9))

    # allow time for audit event to process
    time.sleep(2)


if __name__ == "__main__":
    exit(main(*sys.argv[1:]))
