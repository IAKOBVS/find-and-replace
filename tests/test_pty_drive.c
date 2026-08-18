#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

typedef struct {
	int delay_ms;
	unsigned char *data;
	size_t len;
} action_t;

int parse_phase(const char *spec, int default_delay_ms, action_t *out);
int decode_tail(const char *text, int default_delay_ms, action_t *out);
int split_winsize(const char *spec, int *rows, int *cols);
const char *outcome_from_status(int status);

static int hex_val(char c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

int parse_phase(const char *spec, int default_delay_ms, action_t *out)
{
	const char *at;
	const char *hex;
	int delay;
	size_t hexlen;
	size_t i;
	int hi, lo;
	unsigned char *data;

	at = strrchr(spec, '@');
	if (at != NULL) {
		hex = spec;
		hexlen = (size_t)(at - spec);
		delay = atoi(at + 1);
	} else {
		hex = spec;
		hexlen = strlen(spec);
		delay = default_delay_ms;
	}

	if (hexlen == 0 || hexlen % 2 != 0)
		return -1;

	data = malloc(hexlen / 2);
	if (data == NULL)
		return -1;

	for (i = 0; i < hexlen; i += 2) {
		hi = hex_val(hex[i]);
		lo = hex_val(hex[i + 1]);
		if (hi < 0 || lo < 0) {
			free(data);
			return -1;
		}
		data[i / 2] = (unsigned char)((hi << 4) | lo);
	}

	out->delay_ms = delay;
	out->data = data;
	out->len = hexlen / 2;
	return 0;
}

int decode_tail(const char *text, int default_delay_ms, action_t *out)
{
	size_t len;
	size_t i;
	size_t j;
	unsigned char *buf;
	int hi, lo;

	len = strlen(text);
	buf = malloc(len + 1);
	if (buf == NULL)
		return -1;

	i = 0;
	j = 0;
	while (i < len) {
		if (text[i] == '\\') {
			if (i + 1 >= len) {
				free(buf);
				return -1;
			}
			i++;
			switch (text[i]) {
			case 'n':  buf[j++] = '\n'; i++; break;
			case 'r':  buf[j++] = '\r'; i++; break;
			case 't':  buf[j++] = '\t'; i++; break;
			case 'a':  buf[j++] = '\a'; i++; break;
			case 'b':  buf[j++] = '\b'; i++; break;
			case 'f':  buf[j++] = '\f'; i++; break;
			case 'v':  buf[j++] = '\v'; i++; break;
			case '0':  buf[j++] = '\0'; i++; break;
			case '\\': buf[j++] = '\\'; i++; break;
			case 'x':
				if (i + 2 < len) {
					hi = hex_val(text[i + 1]);
					lo = hex_val(text[i + 2]);
					if (hi >= 0 && lo >= 0) {
						buf[j++] = (unsigned char)((hi << 4) | lo);
						i += 3;
						break;
					}
				}
				buf[j++] = '\\';
				i++;
				break;
			default:
				buf[j++] = '\\';
				buf[j++] = (unsigned char)text[i++];
				break;
			}
		} else {
			buf[j++] = (unsigned char)text[i++];
		}
	}

	out->delay_ms = default_delay_ms;
	out->data = buf;
	out->len = j;
	return 0;
}

int split_winsize(const char *spec, int *rows, int *cols)
{
	const char *x;
	const char *x2;
	char lower[64];
	size_t len;
	size_t i;

	len = strlen(spec);
	if (len == 0 || len >= sizeof(lower))
		return -1;

	for (i = 0; i < len; i++) {
		lower[i] = spec[i];
		if (lower[i] >= 'A' && lower[i] <= 'Z')
			lower[i] = (char)(lower[i] + ('a' - 'A'));
	}
	lower[len] = '\0';

	x = strchr(lower, 'x');
	if (x == NULL || x == lower || *(x + 1) == '\0')
		return -1;

	x2 = strchr(x + 1, 'x');
	if (x2 != NULL)
		return -1;

	*rows = atoi(lower);
	*cols = atoi(x + 1);
	return 0;
}

const char *outcome_from_status(int status)
{
	static char buf[32];

	if (WIFEXITED(status)) {
		sprintf(buf, "%d", WEXITSTATUS(status));
		return buf;
	}
	if (WIFSIGNALED(status)) {
		sprintf(buf, "sig:%d", WTERMSIG(status));
		return buf;
	}
	return "timeout";
}

static int n_run;
static int n_failed;

static int run_one(const char *name, int (*fn)(void))
{
	int rc;

	n_run++;
	rc = fn();
	if (rc == 0)
		printf("PASS %s\n", name);
	else
		printf("FAIL %s\n", name);
	n_failed += rc;
	return rc;
}

static int t_parse_simple(void)
{
	action_t a;

	if (parse_phase("414243", 100, &a) != 0) return 1;
	if (a.delay_ms != 100) return 1;
	if (a.len != 3) return 1;
	if (a.data[0] != 0x41 || a.data[1] != 0x42 || a.data[2] != 0x43) return 1;
	free(a.data);
	return 0;
}

static int t_parse_with_delay(void)
{
	action_t a;

	if (parse_phase("414243@500", 100, &a) != 0) return 1;
	if (a.delay_ms != 500) return 1;
	if (a.len != 3) return 1;
	free(a.data);
	return 0;
}

static int t_parse_single_byte(void)
{
	action_t a;

	if (parse_phase("ff", 100, &a) != 0) return 1;
	if (a.len != 1 || a.data[0] != 0xff) return 1;
	free(a.data);
	return 0;
}

static int t_parse_empty(void)
{
	action_t a;

	if (parse_phase("", 100, &a) != -1) return 1;
	return 0;
}

static int t_parse_odd_length(void)
{
	action_t a;

	if (parse_phase("123", 100, &a) != -1) return 1;
	return 0;
}

static int t_parse_invalid_hex(void)
{
	action_t a;

	if (parse_phase("ZZZZ", 100, &a) != -1) return 1;
	return 0;
}

static int t_parse_delay_zero(void)
{
	action_t a;

	if (parse_phase("41@0", 100, &a) != 0) return 1;
	if (a.delay_ms != 0) return 1;
	if (a.len != 1 || a.data[0] != 0x41) return 1;
	free(a.data);
	return 0;
}

static int t_parse_multiple_at(void)
{
	action_t a;

	if (parse_phase("41@100@200", 100, &a) != -1) return 1;
	return 0;
}

static int t_parse_empty_hex_with_delay(void)
{
	action_t a;

	if (parse_phase("@500", 100, &a) != -1) return 1;
	return 0;
}

static int t_parse_mixed_case(void)
{
	action_t a;

	if (parse_phase("AbCd", 100, &a) != 0) return 1;
	if (a.len != 2) return 1;
	if (a.data[0] != 0xab || a.data[1] != 0xcd) return 1;
	free(a.data);
	return 0;
}

static int t_parse_zero_default(void)
{
	action_t a;

	if (parse_phase("41", 0, &a) != 0) return 1;
	if (a.delay_ms != 0) return 1;
	free(a.data);
	return 0;
}

static int t_decode_plain(void)
{
	action_t a;

	if (decode_tail("hello", 100, &a) != 0) return 1;
	if (a.len != 5) return 1;
	if (memcmp(a.data, "hello", 5) != 0) return 1;
	free(a.data);
	return 0;
}

static int t_decode_newline(void)
{
	action_t a;

	if (decode_tail("\\n", 100, &a) != 0) return 1;
	if (a.len != 1 || a.data[0] != '\n') return 1;
	free(a.data);
	return 0;
}

static int t_decode_cr(void)
{
	action_t a;

	if (decode_tail("\\r", 100, &a) != 0) return 1;
	if (a.len != 1 || a.data[0] != '\r') return 1;
	free(a.data);
	return 0;
}

static int t_decode_tab(void)
{
	action_t a;

	if (decode_tail("\\t", 100, &a) != 0) return 1;
	if (a.len != 1 || a.data[0] != '\t') return 1;
	free(a.data);
	return 0;
}

static int t_decode_backslash(void)
{
	action_t a;

	if (decode_tail("\\\\", 100, &a) != 0) return 1;
	if (a.len != 1 || a.data[0] != '\\') return 1;
	free(a.data);
	return 0;
}

static int t_decode_hex(void)
{
	action_t a;

	if (decode_tail("\\x41", 100, &a) != 0) return 1;
	if (a.len != 1 || a.data[0] != 'A') return 1;
	free(a.data);
	return 0;
}

static int t_decode_mixed(void)
{
	action_t a;

	if (decode_tail("ab\\ncd", 100, &a) != 0) return 1;
	if (a.len != 5) return 1;
	if (a.data[0] != 'a' || a.data[1] != 'b' || a.data[2] != '\n') return 1;
	if (a.data[3] != 'c' || a.data[4] != 'd') return 1;
	free(a.data);
	return 0;
}

static int t_decode_empty(void)
{
	action_t a;

	if (decode_tail("", 100, &a) != 0) return 1;
	if (a.len != 0) return 1;
	free(a.data);
	return 0;
}

static int t_decode_bell(void)
{
	action_t a;

	if (decode_tail("\\a", 100, &a) != 0) return 1;
	if (a.len != 1 || a.data[0] != '\a') return 1;
	free(a.data);
	return 0;
}

static int t_decode_backspace(void)
{
	action_t a;

	if (decode_tail("\\b", 100, &a) != 0) return 1;
	if (a.len != 1 || a.data[0] != '\b') return 1;
	free(a.data);
	return 0;
}

static int t_decode_formfeed(void)
{
	action_t a;

	if (decode_tail("\\f", 100, &a) != 0) return 1;
	if (a.len != 1 || a.data[0] != '\f') return 1;
	free(a.data);
	return 0;
}

static int t_decode_vtab(void)
{
	action_t a;

	if (decode_tail("\\v", 100, &a) != 0) return 1;
	if (a.len != 1 || a.data[0] != '\v') return 1;
	free(a.data);
	return 0;
}

static int t_decode_nul(void)
{
	action_t a;

	if (decode_tail("\\0", 100, &a) != 0) return 1;
	if (a.len != 1 || a.data[0] != '\0') return 1;
	free(a.data);
	return 0;
}

static int t_decode_hex_nul(void)
{
	action_t a;

	if (decode_tail("\\x00", 100, &a) != 0) return 1;
	if (a.len != 1 || a.data[0] != '\0') return 1;
	free(a.data);
	return 0;
}

static int t_decode_bad_escape(void)
{
	action_t a;

	if (decode_tail("\\z", 100, &a) != 0) return 1;
	if (a.len != 2) return 1;
	if (a.data[0] != '\\' || a.data[1] != 'z') return 1;
	free(a.data);
	return 0;
}

static int t_decode_trailing_backslash(void)
{
	action_t a;

	if (decode_tail("abc\\", 100, &a) != -1) return 1;
	return 0;
}

static int t_decode_hex_incomplete(void)
{
	action_t a;

	if (decode_tail("\\x4", 100, &a) != 0) return 1;
	if (a.len != 2) return 1;
	if (a.data[0] != '\\' || a.data[1] != '4') return 1;
	free(a.data);
	return 0;
}

static int t_decode_hex_bad_digit(void)
{
	action_t a;

	if (decode_tail("\\xGG", 100, &a) != 0) return 1;
	if (a.len != 3) return 1;
	if (a.data[0] != '\\' || a.data[1] != 'G' || a.data[2] != 'G') return 1;
	free(a.data);
	return 0;
}

static int t_decode_multiple_escapes(void)
{
	action_t a;

	if (decode_tail("\\t\\n\\r", 100, &a) != 0) return 1;
	if (a.len != 3) return 1;
	if (a.data[0] != '\t' || a.data[1] != '\n' || a.data[2] != '\r') return 1;
	free(a.data);
	return 0;
}

static int t_winsize_basic(void)
{
	int r, c;

	if (split_winsize("24x80", &r, &c) != 0) return 1;
	if (r != 24 || c != 80) return 1;
	return 0;
}

static int t_winsize_upper(void)
{
	int r, c;

	if (split_winsize("12X40", &r, &c) != 0) return 1;
	if (r != 12 || c != 40) return 1;
	return 0;
}

static int t_winsize_one(void)
{
	int r, c;

	if (split_winsize("1x1", &r, &c) != 0) return 1;
	if (r != 1 || c != 1) return 1;
	return 0;
}

static int t_winsize_large(void)
{
	int r, c;

	if (split_winsize("100x200", &r, &c) != 0) return 1;
	if (r != 100 || c != 200) return 1;
	return 0;
}

static int t_winsize_no_x(void)
{
	int r, c;

	if (split_winsize("24", &r, &c) != -1) return 1;
	return 0;
}

static int t_winsize_empty(void)
{
	int r, c;

	if (split_winsize("", &r, &c) != -1) return 1;
	return 0;
}

static int t_winsize_no_rows(void)
{
	int r, c;

	if (split_winsize("x80", &r, &c) != -1) return 1;
	return 0;
}

static int t_winsize_no_cols(void)
{
	int r, c;

	if (split_winsize("24x", &r, &c) != -1) return 1;
	return 0;
}

static int t_winsize_zero(void)
{
	int r, c;

	if (split_winsize("0x0", &r, &c) != 0) return 1;
	if (r != 0 || c != 0) return 1;
	return 0;
}

static int t_winsize_multi_x(void)
{
	int r, c;

	if (split_winsize("5x10x20", &r, &c) != -1) return 1;
	return 0;
}

static int t_winsize_mixed_case_multi_x(void)
{
	int r, c;

	if (split_winsize("5x10X20", &r, &c) != -1) return 1;
	return 0;
}

static int t_winsize_single_number(void)
{
	int r, c;

	if (split_winsize("0", &r, &c) != -1) return 1;
	return 0;
}

static int t_outcome_exit0(void)
{
	int pid, status;
	const char *s;

	pid = fork();
	if (pid == 0) _exit(0);
	waitpid(pid, &status, 0);
	s = outcome_from_status(status);
	if (strcmp(s, "0") != 0) return 1;
	return 0;
}

static int t_outcome_exit1(void)
{
	int pid, status;
	const char *s;

	pid = fork();
	if (pid == 0) _exit(1);
	waitpid(pid, &status, 0);
	s = outcome_from_status(status);
	if (strcmp(s, "1") != 0) return 1;
	return 0;
}

static int t_outcome_exit42(void)
{
	int pid, status;
	const char *s;

	pid = fork();
	if (pid == 0) _exit(42);
	waitpid(pid, &status, 0);
	s = outcome_from_status(status);
	if (strcmp(s, "42") != 0) return 1;
	return 0;
}

static int t_outcome_signal(void)
{
	int pid, status;
	const char *s;

	pid = fork();
	if (pid == 0) { raise(SIGKILL); _exit(1); }
	waitpid(pid, &status, 0);
	s = outcome_from_status(status);
	if (strncmp(s, "sig:", 4) != 0) return 1;
	if (atoi(s + 4) != SIGKILL) return 1;
	return 0;
}

static int t_outcome_signal_segv(void)
{
	int pid, status;
	const char *s;

	pid = fork();
	if (pid == 0) { raise(SIGSEGV); _exit(1); }
	waitpid(pid, &status, 0);
	s = outcome_from_status(status);
	if (strncmp(s, "sig:", 4) != 0) return 1;
	if (atoi(s + 4) != SIGSEGV) return 1;
	return 0;
}

static int t_outcome_timeout(void)
{
	int pid, status;
	const char *s;

	pid = fork();
	if (pid == 0) { raise(SIGSTOP); _exit(1); }
	waitpid(pid, &status, WUNTRACED);
	s = outcome_from_status(status);
	kill(pid, SIGCONT);
	kill(pid, SIGKILL);
	waitpid(pid, &status, 0);
	if (strcmp(s, "timeout") != 0) return 1;
	return 0;
}

int main(void)
{
	n_run = 0;
	n_failed = 0;

	run_one("parse_simple", t_parse_simple);
	run_one("parse_with_delay", t_parse_with_delay);
	run_one("parse_single_byte", t_parse_single_byte);
	run_one("parse_empty", t_parse_empty);
	run_one("parse_odd_length", t_parse_odd_length);
	run_one("parse_invalid_hex", t_parse_invalid_hex);
	run_one("parse_delay_zero", t_parse_delay_zero);
	run_one("parse_multiple_at", t_parse_multiple_at);
	run_one("parse_empty_hex_with_delay", t_parse_empty_hex_with_delay);
	run_one("parse_mixed_case", t_parse_mixed_case);
	run_one("parse_zero_default", t_parse_zero_default);

	run_one("decode_plain", t_decode_plain);
	run_one("decode_newline", t_decode_newline);
	run_one("decode_cr", t_decode_cr);
	run_one("decode_tab", t_decode_tab);
	run_one("decode_backslash", t_decode_backslash);
	run_one("decode_hex", t_decode_hex);
	run_one("decode_mixed", t_decode_mixed);
	run_one("decode_empty", t_decode_empty);
	run_one("decode_bell", t_decode_bell);
	run_one("decode_backspace", t_decode_backspace);
	run_one("decode_formfeed", t_decode_formfeed);
	run_one("decode_vtab", t_decode_vtab);
	run_one("decode_nul", t_decode_nul);
	run_one("decode_hex_nul", t_decode_hex_nul);
	run_one("decode_bad_escape", t_decode_bad_escape);
	run_one("decode_trailing_backslash", t_decode_trailing_backslash);
	run_one("decode_hex_incomplete", t_decode_hex_incomplete);
	run_one("decode_hex_bad_digit", t_decode_hex_bad_digit);
	run_one("decode_multiple_escapes", t_decode_multiple_escapes);

	run_one("winsize_basic", t_winsize_basic);
	run_one("winsize_upper", t_winsize_upper);
	run_one("winsize_one", t_winsize_one);
	run_one("winsize_large", t_winsize_large);
	run_one("winsize_no_x", t_winsize_no_x);
	run_one("winsize_empty", t_winsize_empty);
	run_one("winsize_no_rows", t_winsize_no_rows);
	run_one("winsize_no_cols", t_winsize_no_cols);
	run_one("winsize_zero", t_winsize_zero);
	run_one("winsize_multi_x", t_winsize_multi_x);
	run_one("winsize_mixed_case_multi_x", t_winsize_mixed_case_multi_x);
	run_one("winsize_single_number", t_winsize_single_number);

	run_one("outcome_exit0", t_outcome_exit0);
	run_one("outcome_exit1", t_outcome_exit1);
	run_one("outcome_exit42", t_outcome_exit42);
	run_one("outcome_signal", t_outcome_signal);
	run_one("outcome_signal_segv", t_outcome_signal_segv);
	run_one("outcome_timeout", t_outcome_timeout);

	printf("\n%d/%d passed\n", n_run - n_failed, n_run);
	return n_failed > 0 ? 1 : 0;
}
