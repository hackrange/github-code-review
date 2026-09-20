/* Which lines of a file this person actually changed.
 *
 * A plugin that opens showing two thousand findings gets uninstalled that
 * afternoon, and none of those two thousand are the author's.  So the default
 * is to show findings on lines that differ from HEAD and to keep the rest out
 * of the way.
 *
 * git is asked, rather than a diff being worked out here.  Every machine this
 * runs on has it, it already knows about submodules, renames and line endings,
 * and a wrong answer here silently hides findings.  When it cannot answer -
 * no git, no repository, a file that was never committed - the answer is null,
 * which every caller reads as "all of it", because hiding findings on the
 * strength of a failed command is the wrong way to be wrong.
 */
"use strict";

const { execFile } = require("child_process");
const path = require("path");

const GIT_TIMEOUT = 5000;

function run(args, cwd) {
  return new Promise((resolve) => {
    execFile("git", args, { cwd: cwd, timeout: GIT_TIMEOUT, maxBuffer: 8 << 20 },
      (err, stdout) => resolve(err ? null : String(stdout || "")));
  });
}

/* The @@ -a,b +c,d @@ headers of a unified diff, as the lines they name.
 *
 * -U0 means each hunk is exactly the changed lines and no context, which is
 * the point: context lines are not this person's work. */
function linesFromHunks(diff) {
  const lines = new Set();
  const header = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/;
  for (const line of String(diff || "").split("\n")) {
    const match = line.match(header);
    if (!match) { continue; }
    const start = parseInt(match[1], 10);
    const count = match[2] === undefined ? 1 : parseInt(match[2], 10);
    for (let i = 0; i < count; i += 1) { lines.add(start + i); }
  }
  return lines;
}

/* changedLines(root, absolutePath, base) -> Set of 1 based line numbers, or null
 *
 * null means "could not tell", and the caller shows everything.
 */
async function changedLines(root, file, base) {
  if (!root || !file) { return null; }
  const relative = path.relative(root, file);
  if (!relative || relative.startsWith("..")) { return null; }

  const inside = await run(["rev-parse", "--is-inside-work-tree"], root);
  if (!inside || inside.trim() !== "true") { return null; }

  /* A file git has never seen is entirely this person's work.  Asking for a
   * diff of it returns nothing, which would read as "no changed lines" and
   * hide every finding in a file somebody just wrote. */
  const tracked = await run(["ls-files", "--error-unmatch", "--", relative], root);
  if (tracked === null) { return null; }

  const against = String(base || "HEAD");
  const diff = await run(["diff", "--no-color", "--no-ext-diff", "-U0",
                          against, "--", relative], root);
  if (diff === null) { return null; }
  return linesFromHunks(diff);
}

/* Keep the diagnostics on lines that changed, and say how many were put away.
 *
 * Nothing is thrown away silently: the count comes back so the editor can say
 * "and 41 older findings in this file", which is the difference between a
 * filter somebody trusts and one they wonder about. */
function onlyChanged(diagnostics, lines) {
  if (!lines) { return { kept: diagnostics, hidden: 0 }; }
  const kept = diagnostics.filter((d) => lines.has(d.range.start.line + 1));
  return { kept: kept, hidden: diagnostics.length - kept.length };
}

module.exports = { changedLines, onlyChanged, linesFromHunks };
