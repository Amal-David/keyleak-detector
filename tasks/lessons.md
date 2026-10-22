# Lessons

- When the configured workspace contains a symlink, try the verified physical
  checkout path before concluding repository access is unavailable. An executor
  may still fail because its configured writable root retains the symlink;
  explain that distinction and use approved physical-path access. Preserve dirty
  primary checkouts and implement in an isolated worktree.
