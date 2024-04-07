# find-and-replace

Like sed but defaults to fixed strings instead of regexes. Substitutions are done on the whole file instead of line-by-line (like sed with the -z flag).

## Rationale:

Substituting fixed strings with sed which only offers regex substitution is a massive pain. Also, often we want to replace strings that spread across multiple lines, though that works with sed with the -z flag.

## Installation:

```
./setup && ./build && sudo ./install
```

## Usage:

If no or invalid arguments are provided, it will display help.

```
find-and-replace
```
