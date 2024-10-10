# find-and-replace

Like sed but defaults to fixed strings instead of regexes. Substitution is done on the whole file instead of line-by-line (like sed with the -z flag).

## Rationale:

Substituting fixed strings with sed which only offers regex substitution is a massive pain. Also, often we want to replace strings that spread across multiple lines, though that works with sed with the -z flag.

## Installation:

```
sudo ./setup && ./build && sudo ./install
```

## Usage:

```
find-and-replace [FIND] [REPLACE] [OPTIONS]... [FILES]...
Options:
  -G (default)
    Replace first occurence of FIND with REPLACE.
  -g
    Replace all occurrences of FIND with REPLACE, negates -G flag.
  -i[SUFFIX]
    Replace files in-place. The default is printing to stdout.
    If SUFFIX is provided, backup the original file suffixed with SUFFIX.
  -r
    Recurse on the directories in FILES.
  --include GLOB
    File glob to match when -r is used. Glob is a wildcard.
  --exclude GLOB
    The reverse of --include. Skip files that match glob.
    This applies to the passed command line files.
  -F (default)
    Treat FIND as a fixed-string.
  -R
    Treat FIND as a regex, negates -F flag.
  -E
    Use POSIX Extended Regular Expressions syntax.
    REG_EXTENDED is passed as the cflag to regexec.
  -I
    Ignore case.
    REG_ICASE is passed as the cflag to regexec.
  -Z (default)
    Anchors match newlines.
    REG_NEWLINE is passed as the cflag to regexec.
  -z
    Anchors only match the start or end of the string not newlines, negates -Z flag.
    You can still use newlines in the FIND string, different from sed.
    REG_NEWLINE is not passed as the cflag to regexec.

FIND and REPLACE shall be placed in that exact order.

\b, \f, \n, \r, \t, \v, and \ooo (octal) in FIND and REPLACE will be unescaped.
Otherwise, unescaped backslashes will be removed, so use two backslashes for a backslash.
For example: '\\(this\\)' and '\\1' instead of '\(this\)' and '\1', unlike what
you would do with sed.

Filenames shall not start with - as they will be interpreted as a flag.

Single character flags starting with a single dash can be combined.
For example: -EI is equal to -E -I.

-E (Extended Regex) and -I (ignore case) imply -R (Regex), so using -E or -I automatically
enables -R.

If no file was passed, read from stdin.
```
