# Snippet: no eval / no command substitution

Drop this into a CLAUDE.md to discourage shell substitution-based code paths.

- Do not use `eval`. If a command needs to be parameterised, use an array
  variable and call it directly.
- Avoid `$(...)` and backticks. Where they are necessary (for example,
  capturing `$(date +%s)` into a variable), keep the substitution on its
  own line and document why.
- Avoid process substitution `<(...)` and `>(...)`. Write intermediate
  files in a temp directory and clean up with `trap`.

The `bash-structural-guard` hook records every substitution as a structural
risk. Strict and regulated profiles block; baseline warns.
