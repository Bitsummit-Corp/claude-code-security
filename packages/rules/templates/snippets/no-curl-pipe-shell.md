# Snippet: never pipe network output to a shell

Drop this into a CLAUDE.md to forbid the pipe-to-shell pattern.

- Do not run `curl ... | sh`, `curl ... | bash`, `wget ... | sh`, or any
  variant that streams remote content into an interpreter.
- If an installer requires this pattern, download the script to a file
  first, read the file, then run it explicitly.

The `pipe-to-shell-guard` hook always blocks across profiles. The
`bash-structural-guard` hook also surfaces unicode-lookalike pipes
(U+FF5C) used for evasion.
