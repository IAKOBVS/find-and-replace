# find-and-replace

Like sed but defaults to fixed strings instead of regexes. Substitution is done on the whole file instead of line-by-line (like sed with the -z flag).

## Rationale:

Substituting fixed strings with sed which only offers regex substitution is a massive pain. Also, often we want to replace strings that spread across multiple lines, though that works with sed with the -z flag.

## Installation:

```
./setup && ./build && sudo ./install
```
## Usage:
find-and-replace \[FIND\] \[REPLACE\] \[OPTIONS\]... \[FILES\]...<br>
Options:<br>
  -i\[SUFFIX\]<br>
    Replace files in-place. The default is printing to stdout.<br>
    If SUFFIX is provided, backup the original file suffixed with SUFFIX.<br>
  -r<br>
    Recurse on the directories in FILES.<br>
  --include GLOB<br>
    File glob to match when -r is used. Glob is a wildcard.<br>
  --exclude GLOB<br>
    The reverse of --include. Skip files that match glob.<br>
    This applies to the passed command line files.<br>
  -F<br>
    Treat FIND as a fixed-string. This is the default.<br>
  -R<br>
    Treat FIND as a regex include\_glob.<br>
  -E<br>
    Use POSIX Extended Regular Expressions syntax.<br>
    REG\_EXTENDED is passed as the cflag to regexec.<br>
  -I<br>
    Ignore case if FIND is a regex include\_glob.<br>
    REG\_ICASE is passed as the cflag to regexec.<br>
<br>
FIND and REPLACE shall be placed in that exact order.<br>
<br>
\b, \f, \n, \r, \t, \v, and \ooo \(octal\) in FIND and REPLACE will be unescaped.<br>
Otherwise, unescaped backslashes will be removed, so use two backslashes for a backslash.<br>
For example: '\\\(this\\\)' and '\\1' instead of '\\(this\\)' and '\1', unlike what<br>
you would do with sed.<br>
<br>
Filenames shall not start with - as they will be interpreted as a flag.<br>
<br>
Single character flags starting with a single dash can be combined.<br>
For example: -EI is equal to -E -i.<br>
<br>
-E \(Extended Regex\) and -I \(ignore case\) imply -R \(Regex\), so using -E or -I automatically<br>
enables -R.<br>
<br>
If no file was passed, read from stdin.<br>
