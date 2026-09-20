/* A finding from /api/v1/review, turned into something an editor underlines.
 *
 * The shape on the wire is the one `ghscan review` writes and the API passes
 * through: kind, file, line, start_column, end_column, rule, severity, title,
 * message, and for a credential a redacted preview.  Lines and columns are
 * counted from one there, and from zero in the Language Server Protocol, which
 * is the kind of off-by-one nobody notices until they are staring at the line
 * above the problem.  It is converted in exactly one place: here.
 */
"use strict";

/* LSP severities.  An editor draws 1 in red and 4 not at all unless asked. */
const ERROR = 1, WARNING = 2, INFORMATION = 3, HINT = 4;

/* What each of ours is worth on that scale.
 *
 * A credential is an error whatever its severity says, because a live key in a
 * file being edited is the one thing here that cannot wait for a review. */
const BY_SEVERITY = {
  critical: ERROR, high: ERROR, medium: WARNING, low: INFORMATION,
  info: HINT, informational: HINT, unknown: HINT
};

/* Verdicts the triage reaches that mean "not this team's problem, or not a
 * problem at all".  The server already drops placeholders; these are the ones
 * it keeps but grades down, and an editor that shows them in red is an editor
 * somebody turns off. */
const GRADED_ASIDE = { not_applicable: true, third_party: true, advisory: true };

function verdictOf(finding) {
  const raw = finding && finding.triage;
  if (!raw) { return ""; }
  if (typeof raw === "string") { return raw; }
  return String(raw.verdict || "");
}

function severityOf(finding) {
  if (finding.kind === "credential") { return ERROR; }
  const level = BY_SEVERITY[String(finding.severity || "").toLowerCase()];
  return level || WARNING;
}

/* Where to underline.
 *
 * Columns are there when the engine reported them and zero when it did not, so
 * a finding with no column underlines the whole line rather than one character
 * at the start of it.  `lineText` is what the editor has, used only to know
 * where the line ends. */
function rangeOf(finding, lineText) {
  const line = Math.max(0, (Number(finding.line) || 1) - 1);
  const start = Number(finding.start_column) || 0;
  const end = Number(finding.end_column) || 0;
  if (start > 0) {
    const from = start - 1;
    const to = end > start ? end - 1 : from + 1;
    return { start: { line: line, character: from },
             end: { line: line, character: to } };
  }
  const width = typeof lineText === "string" ? lineText.length : 0;
  return { start: { line: line, character: 0 },
           end: { line: line, character: width > 0 ? width : 1 } };
}

/* The sentence somebody reads in the editor.
 *
 * The title says what it is, the message says why it is that, and the triage
 * reason says why it survived the filter.  That last one is the whole reason
 * this is bearable next to a bare semgrep: a finding that arrives with the
 * argument for itself is one somebody can disagree with. */
function messageOf(finding) {
  const parts = [];
  const title = String(finding.title || "").trim();
  const body = String(finding.message || "").trim();
  parts.push(title || String(finding.rule || "finding"));
  if (body && body.toLowerCase() !== title.toLowerCase()) { parts.push(body); }

  if (finding.kind === "credential" && finding.preview) {
    /* The redacted form, never the value.  The server masks it before it
     * leaves, and putting the whole thing back in an editor's problem list
     * would write it to a log file we do not control. */
    parts.push("Value looks like: " + finding.preview);
  }
  const reason = String(finding.triage_reason || "").trim();
  if (reason) { parts.push("Triage: " + reason); }

  const engines = Array.isArray(finding.engines) ? finding.engines : [];
  if (engines.length > 1) {
    parts.push(engines.length + " engines agree (" + engines.join(", ") + ")");
  }
  const fix = String(finding.resolution || "").trim();
  if (fix) { parts.push(fix); }
  return parts.join("\n");
}

/* One finding -> one diagnostic, in the shape the protocol uses.
 *
 * The VS Code front end converts these to its own objects, which is a field
 * rename and no decisions; every decision worth getting right is made here and
 * made once. */
function toDiagnostic(finding, lineText) {
  const aside = GRADED_ASIDE[verdictOf(finding)] === true;
  return {
    range: rangeOf(finding, lineText),
    /* Something the triage set aside is still shown, quietly.  Hiding it would
     * mean the editor disagreeing with the report without saying so. */
    severity: aside ? HINT : severityOf(finding),
    code: String(finding.rule || ""),
    source: "Git Code Review",
    message: messageOf(finding),
    /* Carried for the front ends: which kind it is decides the icon, and the
     * verdict decides whether it is counted in the summary. */
    gcr: {
      kind: String(finding.kind || ""),
      severity: String(finding.severity || ""),
      verdict: verdictOf(finding),
      aside: aside,
      help: String(finding.help_url || "")
    }
  };
}

/* Everything for one file, in the order somebody should look at it. */
function toDiagnostics(findings, lines) {
  const rows = Array.isArray(findings) ? findings : [];
  const out = rows.map((finding) => {
    const at = Math.max(0, (Number(finding.line) || 1) - 1);
    return toDiagnostic(finding, lines ? lines[at] : undefined);
  });
  out.sort((a, b) => (a.severity - b.severity)
                     || (a.range.start.line - b.range.start.line));
  return out;
}

/* A short line for a status bar: what was found, without a wall of numbers. */
function summarize(diagnostics) {
  const kept = diagnostics.filter((d) => !d.gcr.aside);
  const credentials = kept.filter((d) => d.gcr.kind === "credential").length;
  if (credentials > 0) {
    return credentials + (credentials === 1 ? " credential" : " credentials")
           + (kept.length > credentials
              ? ", " + (kept.length - credentials) + " other" : "");
  }
  if (kept.length === 0) { return "nothing to fix"; }
  return kept.length + (kept.length === 1 ? " finding" : " findings");
}

module.exports = { toDiagnostic, toDiagnostics, summarize, severityOf,
                   ERROR, WARNING, INFORMATION, HINT };
