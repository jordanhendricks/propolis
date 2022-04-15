#!/bin/bash
#:
#: name = "test"
#: variety = "basic"
#: target = "lab"
#: output_rules = [
#:	"/tmp/*.log",
#: ]
#:
#: [dependencies.build]
#: job = "build-tests"
#:

set -o errexit
set -o pipefail
set -o xtrace

banner 'Inputs'
find /input -ls

rm -rf /tmp/tests
mkdir /tmp/tests
for p in /input/build/work/tests/*.gz; do
	f="/tmp/tests/$(basename "$p")"
	rm -f "$f"
	gzip < "$p" > "$f"
	chmod +x "$f"
done

banner 'Tests'
for f in /tmp/tests; do
	ptime -m "$f" --show-output --test-threads 1
	rc=$?

	echo
	echo "exit status for $f: $rc"
	echo
done
