#!/bin/sh

# program that generates an estimate of how many
# strings are in an executable file

# uselessness: 6/10

# LIMITATIONS:
#
# - 'strings -a -n 1' searches for printable sequences of
# at lesat one character throughout the file
#
# - 'awk' does not count '\0' characters
#
# - the result does not necessarily represent the actual
# number of bytes in stirngs: printable sequences
# may appear in data that are not strings, and strings
# may contain non-printable bytes
#
# - the percentage may be higher than the actual proportion
# of data allocated to strings, especially in binaries
# containing a large amount of printable data that is
# not text



if [ "$#" -ne 1 ] || [ ! -f "$1" ]; then
	printf 'usage: %s <executable>\n' '"$0"' >&2
	exit 1
fi

binary=$1

bin_size=$(stat -c '%s' "$binary") || exit 1

string_bytes=$(strings -a -n 1 "$binary" |
	awk '{ total += length($0) } END { print total + 0 }')

awk -v total="$bin_size" -v strings="$string_bytes" '
BEGIN {
	printf "executable: %s bytes\n", total
	printf "strings:    %s bytes (estimate)\n", strings
	printf "proportion: %.2f%%\n", 100 * strings / total
}
'