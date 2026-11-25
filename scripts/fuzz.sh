#!/bin/sh
# fuzz.sh PACKAGE TARGET FUZZTIME runs one fuzz target.
#
# The Go fuzzing engine can stop with "context deadline exceeded" when
# -fuzztime ends in the middle of its own work. That is not a finding: a
# finding always writes its input under testdata/fuzz. Such a run passes;
# every other failure fails.
set -u
pkg=$1 target=$2 fuzztime=$3

out=$(go test -run='^$' -fuzz="^${target}\$" -fuzztime="$fuzztime" "$pkg" 2>&1)
status=$?
printf '%s\n' "$out" | grep -v '^fuzz: elapsed'

if [ "$status" -ne 0 ] &&
	printf '%s' "$out" | grep -q 'context deadline exceeded' &&
	! printf '%s' "$out" | grep -q 'Failing input written to'; then
	echo "fuzz engine stopped at the deadline without a finding: pass"
	exit 0
fi
exit "$status"
