#!/bin/bash
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"

t_backref_reorder() {
	td=$1; out=$(printf 'apple, banana, cherry\n' | "$PROG" '([a-z]+), ([a-z]+), ([a-z]+)' '\\3, \\1, \\2' -RE 2>/dev/null)
	[ "$out" = 'cherry, apple, banana' ] && echo PASS > "$td/result" || echo "FAIL: expected [cherry, apple, banana] got [$out]" > "$td/result"
}

t_backref_duplicate_word() {
	td=$1; out=$(printf 'the the word\n' | "$PROG" '([a-z]+) \\1' '\\1' -RE 2>/dev/null)
	[ "$out" = 'the word' ] && echo PASS > "$td/result" || echo "FAIL: expected [the word] got [$out]" > "$td/result"
}

t_backref_nested_groups() {
	td=$1; out=$(printf 'date: 2023-10-25\n' | "$PROG" '(([0-9]{4})-([0-9]{2})-([0-9]{2}))' 'Year: \\2, Month: \\3, Day: \\4 (Full: \\1)' -RE 2>/dev/null)
	[ "$out" = 'date: Year: 2023, Month: 10, Day: 25 (Full: 2023-10-25)' ] && echo PASS > "$td/result" || echo "FAIL: expected [date: Year: 2023, Month: 10, Day: 25 (Full: 2023-10-25)] got [$out]" > "$td/result"
}

t_backref_xml_tags() {
	td=$1; out=$(printf '<div>content</div>\n' | "$PROG" '<([a-z]+)>(.*)</\\1>' '[\\1: \\2]' -RE 2>/dev/null)
	[ "$out" = '[div: content]' ] && echo PASS > "$td/result" || echo "FAIL: expected [[div: content]] got [$out]" > "$td/result"
}

t_regex_alternation_capture() {
	td=$1; out=$(printf 'Start ERROR: disk full End\n' | "$PROG" '(ERROR|WARN|INFO): ([a-z ]+)' '[\\1] - \\2' -RE 2>/dev/null)
	[ "$out" = 'Start [ERROR] - disk full End' ] && echo PASS > "$td/result" || echo "FAIL: expected [Start [ERROR] - disk full End] got [$out]" > "$td/result"
}

t_regex_email_parse() {
	td=$1; out=$(printf 'user@domain.com\n' | "$PROG" '^([a-z]+)@([a-z]+)\.([a-z]+)$' 'User=\\1 Domain=\\2 TLD=\\3' -RE 2>/dev/null)
	[ "$out" = 'User=user Domain=domain TLD=com' ] && echo PASS > "$td/result" || echo "FAIL: expected [User=user Domain=domain TLD=com] got [$out]" > "$td/result"
}

t_backref_max_digits() {
	td=$1; out=$(printf '1 2 3 4 5 6 7 8 9\n' | "$PROG" '([0-9]) ([0-9]) ([0-9]) ([0-9]) ([0-9]) ([0-9]) ([0-9]) ([0-9]) ([0-9])' '\\9 \\8 \\7 \\6 \\5 \\4 \\3 \\2 \\1' -RE 2>/dev/null)
	[ "$out" = '9 8 7 6 5 4 3 2 1' ] && echo PASS > "$td/result" || echo "FAIL: expected [9 8 7 6 5 4 3 2 1] got [$out]" > "$td/result"
}

t_regex_ip_address() {
	td=$1; out=$(printf '192.168.1.1\n' | "$PROG" '([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})' 'IP: \\1|\\2|\\3|\\4' -RE 2>/dev/null)
	[ "$out" = 'IP: 192|168|1|1' ] && echo PASS > "$td/result" || echo "FAIL: expected [IP: 192|168|1|1] got [$out]" > "$td/result"
}

t_regex_negated_class() {
	td=$1; out=$(printf '"hello" and "world"\n' | "$PROG" '"([^"]+)"' '{\\1}' -REg 2>/dev/null)
	[ "$out" = '{hello} and {world}' ] && echo PASS > "$td/result" || echo "FAIL: expected [{hello} and {world}] got [$out]" > "$td/result"
}

t_regex_url_protocol() {
	td=$1; out=$(printf 'https://www.example.com\n' | "$PROG" '^(https?)://(www\.)?([a-z0-9-]+)\.([a-z]+)$' 'Proto:\\1 Domain:\\3 Ext:\\4' -RE 2>/dev/null)
	[ "$out" = 'Proto:https Domain:example Ext:com' ] && echo PASS > "$td/result" || echo "FAIL: expected [Proto:https Domain:example Ext:com] got [$out]" > "$td/result"
}

t_regex_greedy() {
	td=$1; out=$(printf 'a---b---c\n' | "$PROG" '.*' 'X' -REg 2>/dev/null)
	expected=$(printf 'XX\nX\n')
	[ "$out" = "$expected" ] && echo PASS > "$td/result" || echo "FAIL: greedy regex expected [X] got [$out]" > "$td/result"
}

t_regex_repeat_quantifiers() {
	td=$1; out=$(printf 'aaa123\n' | "$PROG" 'a{2,4}' 'A' -REg 2>/dev/null)
	[ "$out" = 'A123' ] && echo PASS > "$td/result" || echo "FAIL: repeat quantifiers expected [A123] got [$out]" > "$td/result"
}

t_regex_multiple_groups() {
	td=$1; out=$(printf 'a b c d e\n' | "$PROG" '([a-z]) ([a-z]) ([a-z]) ([a-z]) ([a-z])' '\\5 \\4 \\3 \\2 \\1' -RE 2>/dev/null)
	[ "$out" = 'e d c b a' ] && echo PASS > "$td/result" || echo "FAIL: multiple groups expected [e d c b a] got [$out]" > "$td/result"
}

t_regex_escaped_dot() {
	td=$1; out=$(printf 'file.txt\n' | "$PROG" 'file\\.txt' 'document.txt' -R 2>/dev/null)
	[ "$out" = 'document.txt' ] && echo PASS > "$td/result" || echo "FAIL: escaped dot expected [document.txt] got [$out]" > "$td/result"
}

TESTS="
t_backref_reorder
t_backref_duplicate_word
t_backref_nested_groups
t_backref_xml_tags
t_regex_alternation_capture
t_regex_email_parse
t_backref_max_digits
t_regex_ip_address
t_regex_negated_class
t_regex_url_protocol
t_regex_greedy
t_regex_repeat_quantifiers
t_regex_multiple_groups
t_regex_escaped_dot
"
run_suite "complex regex tests" "$TESTS"
