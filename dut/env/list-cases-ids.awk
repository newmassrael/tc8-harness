# SSOT: extract the case-id token from each case line of a
# `tc8-harness test --list-cases` listing read on stdin; print one id per line.
#
# In that listing, case lines are the ONLY indented lines — suite banners
# (`== suite: demo ==`), category headers, blank separators and the trailing
# summary are all flush-left (see src/cli/test_command.cpp runListCases). So an
# INDENT anchor is the robust, suite-name-agnostic class test: it captures a
# bare `ARP_01` and a qualified `demo:ARP_01` alike, and `$1` is the id token
# (the id/`suite:id` display id never contains an intra-token space).
#
# A charset anchor such as `/^  [A-Z]/` was WRONG: the CLI prints a non-default
# suite's `suite:` prefix verbatim, and it may begin lowercase (`hkmc:...`) or
# with any case (`Vendor_X:...`) — the registry constrains neither. Such lines
# start with a non-uppercase char and were silently dropped, so every override
# / probe keyed on a qualified id mis-fired as "unknown case".
#
# `NF` guards against a whitespace-only line yielding an empty `$1`.
NF && /^[[:space:]]/ { print $1 }
