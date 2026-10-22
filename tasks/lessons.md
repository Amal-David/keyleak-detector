# Lessons

- Read newly updated review-comment bodies before running a merge command.
  Green checks do not mean late feedback is addressed; keep inspection and the
  merge as separate steps so new findings can change the decision.

- A request to launch an incident checker for Hacker News concerns other users'
  projects. Do not infer that the user's own systems are affected or expand into
  a personal exposure audit. Keep deployment and scanner-product work separate
  from credential rotation or local environment changes.

- When the configured workspace contains a symlink, try the verified physical
  checkout path before concluding repository access is unavailable. An executor
  may still fail because its configured writable root retains the symlink;
  explain that distinction and use approved physical-path access. Preserve dirty
  primary checkouts and implement in an isolated worktree.
