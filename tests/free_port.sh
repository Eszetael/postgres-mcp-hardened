#!/bin/sh
# Prints one TCP port that is free on this machine, right now.
#
# Why this exists. The test suite and CI used to hardcode ports — 5432, 8080, 15500, 15501, 8099.
# That is safe on a hosted runner, which is a disposable virtual machine belonging to the job, and it
# is a mine everywhere else. On our own machine two of those constants were already taken: the
# database collided with a production PostgreSQL and the server collided with something on 8080, and
# six jobs died on `AddrInUse` with a Rust panic. Choosing a different constant is the same bug with
# a different number; the machine has to be asked.
#
# The range is deliberate. Anything inside the ephemeral range (32768-60999) is eventually taken by
# an unrelated outgoing connection, and the suite then fails as "fixture failed" for reasons that
# have nothing to do with the code under test. That cost an afternoon once.
#
# There is a window between this check and the caller binding. It is milliseconds wide and it is a
# strictly smaller window than "hope 8080 is free", which is what this replaces.
set -eu

command -v python3 >/dev/null 2>&1 || {
  echo "free_port.sh needs python3 (the acceptance and adversarial suites already do)" >&2
  exit 1
}

exec python3 -c '
import random, socket, sys

for _ in range(200):
    port = random.randint(15000, 30000)
    s = socket.socket()
    try:
        # Every interface, not just loopback: a service bound to 0.0.0.0 owns this port even when
        # 127.0.0.1 looks free, and the container job publishes on 0.0.0.0.
        s.bind(("", port))
    except OSError:
        continue
    finally:
        s.close()
    print(port)
    sys.exit(0)

sys.exit("no free port found between 15000 and 30000")
'
