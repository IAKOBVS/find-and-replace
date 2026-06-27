#!/bin/sh
# Parallel find-and-replace integration tests (Complex Regex & Backreferences)

PROG="$(cd "$(dirname "$0")/.." && pwd)/find-and-replace"
PASS=0
FAIL=0
FAIL_LIST=''

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }

td_root=$(mktemp -d)
trap 'rm -rf "$td_root"' EXIT

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

printf '\n=== find-and-replace complex regex tests ===\n\n'

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
"

for t in $TESTS; do
	(
		mkdir -p "$td_root/$t"
		"$t" "$td_root/$t"
	) &
done
wait

for t in $TESTS; do
	r=$(cat "$td_root/$t/result" 2>/dev/null)
	case "$r" in
		PASS*) PASS=$((PASS+1)); green PASS ;;
		FAIL*) FAIL=$((FAIL+1)); red "FAIL (${r#FAIL: })" ;;
		*)     FAIL=$((FAIL+1)); red "FAIL ($t: no result)" ;;
	esac
done

printf '\n=== %d passed, %d failed ===\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
