"""The security report as a Word document.

Built from the same context the PDF is typeset from, so the two never say
different things.  Word because the people who act on a report edit it,
comment on it and pass it on, and a PDF is the wrong shape for that.

No model is asked anything here: the report was written when it was run, and
this only lays it out.  Same house style as the PDF: US English, about a tenth
grade reading level, two spaces between sentences, no em dashes.
"""

from __future__ import annotations

import base64
import io
import re

from docx import Document
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_CELL_VERTICAL_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor

NAVY = RGBColor(0x1F, 0x3A, 0x5F)
GRAY = RGBColor(0x55, 0x5B, 0x66)
WHITE = RGBColor(0xFF, 0xFF, 0xFF)
FILL = {"Critical": "C00000", "High": "E36C0A", "Medium": "FFC000", "Low": "70AD47",
        "Informational": "5B9BD5"}
DARK_TEXT = {"Medium"}
HEAT = {"critical": "F4B6B6", "high": "F8CBAD", "medium": "FFE699", "low": "C6E0B4"}
VERDICT_FILL = {"stop": "C00000", "caution": "FFC000", "go": "548235"}
RATINGS = ["Critical", "High", "Medium", "Low", "Informational"]


def spaced(text) -> str:
    """No em or en dashes, and two spaces between sentences."""
    t = str(text or "").replace(chr(0x2014), ", ").replace(chr(0x2013), "-")
    t = re.sub(r"([a-z0-9)\"'][.!?]) (?=[A-Z\"(])", r"\1  ", t)
    return t


def _shade(cell, fill):
    pr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), fill)
    pr.append(shd)


def _margins(table, v=60, h=90):
    pr = table._tbl.tblPr
    mar = OxmlElement("w:tblCellMar")
    for side, val in (("top", v), ("bottom", v), ("left", h), ("right", h)):
        el = OxmlElement(f"w:{side}")
        el.set(qn("w:w"), str(val))
        el.set(qn("w:type"), "dxa")
        mar.append(el)
    pr.append(mar)


def _widths(table, inches):
    table.autofit = False
    pr = table._tbl.tblPr
    layout = OxmlElement("w:tblLayout")
    layout.set(qn("w:type"), "fixed")
    pr.append(layout)
    for old in pr.findall(qn("w:tblW")):
        pr.remove(old)
    tw = OxmlElement("w:tblW")
    tw.set(qn("w:w"), str(int(sum(inches) * 1440)))
    tw.set(qn("w:type"), "dxa")
    pr.append(tw)
    cols = table._tbl.tblGrid.findall(qn("w:gridCol"))
    for i, w in enumerate(inches):
        if i < len(cols):
            cols[i].set(qn("w:w"), str(int(w * 1440)))
        table.columns[i].width = Inches(w)
    for row in table.rows:
        for i, w in enumerate(inches):
            row.cells[i].width = Inches(w)


def _row_flags(row, header=False):
    pr = row._tr.get_or_add_trPr()
    pr.append(OxmlElement("w:tblHeader" if header else "w:cantSplit"))


def _cell(cell, text, bold=False, color=None, size=8.5, align=None, mono=False):
    cell.text = ""
    para = cell.paragraphs[0]
    para.paragraph_format.space_after = Pt(0)
    if align is not None:
        para.alignment = align
    run = para.add_run(str(text) if mono else spaced(text))
    run.bold = bold
    run.font.size = Pt(size)
    if mono:
        run.font.name = "Consolas"
    if color is not None:
        run.font.color.rgb = color
    cell.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER


def _badge(cell, rating, size=8.5):
    _cell(cell, rating, bold=True, size=size, align=WD_ALIGN_PARAGRAPH.CENTER,
          color=RGBColor(0, 0, 0) if rating in DARK_TEXT else WHITE)
    _shade(cell, FILL.get(rating, "7F8C8D"))


class _Doc:
    def __init__(self, footer: str, header: str):
        self.doc = Document()
        sec = self.doc.sections[0]
        sec.page_width, sec.page_height = Inches(8.5), Inches(11)
        sec.left_margin = sec.right_margin = Inches(0.9)
        sec.top_margin = sec.bottom_margin = Inches(0.85)
        st = self.doc.styles
        st["Normal"].font.name = "Calibri"
        st["Normal"].font.size = Pt(10.5)
        st["Normal"].paragraph_format.space_after = Pt(6)
        for name, size, before in (("Heading 1", 16, 16), ("Heading 2", 13, 12),
                                   ("Heading 3", 11.5, 10)):
            h = st[name]
            h.font.name = "Calibri"
            h.element.rPr.rFonts.set(qn("w:ascii"), "Calibri")
            h.element.rPr.rFonts.set(qn("w:hAnsi"), "Calibri")
            h.font.size, h.font.bold, h.font.color.rgb = Pt(size), True, NAVY
            h.paragraph_format.space_before = Pt(before)
            h.paragraph_format.space_after = Pt(6)
            h.paragraph_format.keep_with_next = True
        hp = sec.header.paragraphs[0]
        r = hp.add_run(spaced(header))
        r.font.size, r.font.color.rgb = Pt(8), GRAY
        fp = sec.footer.paragraphs[0]
        fp.alignment = WD_ALIGN_PARAGRAPH.CENTER
        r = fp.add_run(spaced(footer + "  Page ") if footer else "Page ")
        r.font.size = Pt(8)
        self._page_number(fp)

    @staticmethod
    def _page_number(para):
        for kind, val in (("begin", None), ("instr", "PAGE"), ("separate", None),
                          ("t", "1"), ("end", None)):
            run = para.add_run()
            run.font.size = Pt(8)
            if kind == "instr":
                el = OxmlElement("w:instrText")
                el.set(qn("xml:space"), "preserve")
                el.text = val
            elif kind == "t":
                el = OxmlElement("w:t")
                el.text = val
            else:
                el = OxmlElement("w:fldChar")
                el.set(qn("w:fldCharType"), kind)
            run._r.append(el)

    def h(self, text, level=1):
        return self.doc.add_heading(spaced(text), level=level)

    def p(self, text, bold=False, italic=False, size=None, color=None, after=None,
          align=None):
        para = self.doc.add_paragraph()
        run = para.add_run(spaced(text))
        run.bold, run.italic = bold, italic
        if size:
            run.font.size = Pt(size)
        if color is not None:
            run.font.color.rgb = color
        if after is not None:
            para.paragraph_format.space_after = Pt(after)
        if align is not None:
            para.alignment = align
        return para

    def _link_run(self, para, text, url):
        """A clickable external hyperlink inside an existing paragraph."""
        r_id = para.part.relate_to(
            url,
            "http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink",
            is_external=True)
        link = OxmlElement("w:hyperlink")
        link.set(qn("r:id"), r_id)
        run = OxmlElement("w:r")
        rpr = OxmlElement("w:rPr")
        color = OxmlElement("w:color")
        color.set(qn("w:val"), "0B5FA5")
        rpr.append(color)
        under = OxmlElement("w:u")
        under.set(qn("w:val"), "single")
        rpr.append(under)
        sz = OxmlElement("w:sz")
        sz.set(qn("w:val"), "18")  # 9pt
        rpr.append(sz)
        run.append(rpr)
        t = OxmlElement("w:t")
        t.text = text
        run.append(t)
        link.append(run)
        para._p.append(link)
        return link

    def identity(self, item):
        """Finding number, platform id and a clickable link, under a heading."""
        para = self.doc.add_paragraph()
        para.paragraph_format.space_after = Pt(4)
        label = "Finding %s" % item["id"]
        if item.get("finding_id") is not None:
            label += "   ·   ID %s" % item["finding_id"]
        run = para.add_run(label)
        run.font.size, run.font.color.rgb = Pt(9), GRAY
        if item.get("finding_link"):
            sep = para.add_run("   ·   ")
            sep.font.size, sep.font.color.rgb = Pt(9), GRAY
            self._link_run(para, "View this finding", item["finding_link"])
        return para

    def labeled(self, label, text):
        para = self.doc.add_paragraph()
        r = para.add_run(label + "  ")
        r.bold, r.font.color.rgb = True, NAVY
        para.add_run(spaced(text))

    def bullets(self, items, numbered=False):
        # Word's own numbered list keeps counting from one list to the next
        # across the whole document, so numbered steps are written out and
        # every list starts again at 1.
        for n, item in enumerate(items, start=1):
            if numbered:
                para = self.doc.add_paragraph()
                para.paragraph_format.left_indent = Inches(0.3)
                para.paragraph_format.first_line_indent = Inches(-0.22)
                lead = para.add_run(f"{n}.  ")
                lead.bold = True
            else:
                para = self.doc.add_paragraph(style="List Bullet")
            para.paragraph_format.space_after = Pt(2)
            para.add_run(spaced(item))

    def code(self, text, caption=None):
        if not text:
            return
        if caption:
            self.p(caption, bold=True, size=9, color=GRAY, after=1)
        t = self.doc.add_table(rows=1, cols=1)
        cell = t.rows[0].cells[0]
        _shade(cell, "F3F5F8")
        _margins(t, 80, 120)
        _widths(t, [6.7])
        cell.text = ""
        para = cell.paragraphs[0]
        para.paragraph_format.space_after = Pt(0)
        lines = str(text).split("\n")[:40]
        for n, line in enumerate(lines):
            run = para.add_run(line[:150])
            run.font.name = "Consolas"
            run._element.rPr.rFonts.set(qn("w:eastAsia"), "Consolas")
            run.font.size = Pt(8)
            if n < len(lines) - 1:
                run.add_break()
        self.doc.add_paragraph().paragraph_format.space_after = Pt(2)

    def table(self, header, rows, widths, badge_col=None, size=8.5):
        t = self.doc.add_table(rows=1, cols=len(header))
        t.style = "Table Grid"
        t.alignment = WD_TABLE_ALIGNMENT.CENTER
        _margins(t)
        for i, name in enumerate(header):
            _cell(t.rows[0].cells[i], name, bold=True, color=WHITE, size=size)
            _shade(t.rows[0].cells[i], "1F3A5F")
        _row_flags(t.rows[0], header=True)
        for n, row in enumerate(rows):
            cells = t.add_row().cells
            _row_flags(t.rows[-1])
            for i, value in enumerate(row):
                if badge_col is not None and i == badge_col and value in FILL:
                    _badge(cells[i], value, size)
                else:
                    _cell(cells[i], value, size=size)
                    if n % 2:
                        _shade(cells[i], "F7F9FB")
        _widths(t, widths)
        self.doc.add_paragraph().paragraph_format.space_after = Pt(2)
        return t

    def banner(self, text, fill, dark=False):
        t = self.doc.add_table(rows=1, cols=1)
        cell = t.rows[0].cells[0]
        _shade(cell, fill)
        _margins(t, 140, 180)
        _cell(cell, text, bold=True, size=12, align=WD_ALIGN_PARAGRAPH.CENTER,
              color=RGBColor(0, 0, 0) if dark else WHITE)
        _widths(t, [6.7])

    def page_break(self):
        self.doc.add_paragraph().add_run().add_break(WD_BREAK.PAGE)


def _logo(doc, logo: str):
    m = re.match(r"data:image/(png|jpeg|jpg);base64,(.+)$", logo or "", re.S)
    if not m:
        return
    try:
        doc.add_picture(io.BytesIO(base64.b64decode(m.group(2))), width=Inches(1.6))
    except Exception:          # a bad logo never stops the report
        return


def build(context: dict) -> bytes:
    """-> the .docx bytes for one security report."""
    r, items = context["r"], context["items"]
    tally = context["tally"]
    org = context.get("organization_name") or ""
    D = _Doc(context.get("footer_text") or "Confidential.",
             f"Security Assessment: {r['repository']}")
    doc = D.doc

    # ---- cover
    _logo(doc, context.get("logo") or "")
    for _ in range(3):
        D.p("")
    D.p("Security Assessment", bold=True, size=26, color=NAVY, after=2)
    D.p(r["repository"].split("/")[-1], size=16, color=GRAY, after=12)
    cover = [("Repository", r["repository"]), ("Branch", r.get("branch") or "default")]
    if r.get("commit"):
        cover.append(("Commit reviewed", r["commit"][:12]))
    cover.append(("Report date", context.get("issued_at") or ""))
    cover.append(("Overall rating", r.get("overall") or ""))
    if org:
        cover.append(("Prepared by", org))
    if context.get("footer_text"):
        cover.append(("Classification", context["footer_text"]))
    D.table(["Item", "Detail"], cover, [1.8, 4.9], size=9.5)
    verdict = context.get("verdict")
    if verdict:
        D.p("")
        D.banner(verdict["text"], VERDICT_FILL[verdict["level"]], verdict["level"] == "caution")
    D.page_break()

    # ---- 1 executive summary
    D.h("1.  Executive Summary")
    for paragraph in r["summary"].get("summary") or []:
        D.p(paragraph)
    D.p(f"We rate the overall risk as {r['overall']}.  We rated {tally['Critical']} "
        f"issues Critical, {tally['High']} High, {tally['Medium']} Medium and "
        f"{tally['Low']} Low." + (f"  {tally['Informational']} scanner alert groups "
                                   "turned out to be false alarms." if tally['Informational'] else ""))
    D.h("Findings at a glance", 2)
    t = D.table(RATINGS + ["Total"], [[str(tally[x]) for x in RATINGS]
                                      + [str(sum(1 for i in items if not i.get("waived")))]],
                [1.1] * 5 + [1.2], size=11)
    for n, rating in enumerate(RATINGS):
        _badge(t.rows[1].cells[n], str(tally[rating]), 11)
        _shade(t.rows[1].cells[n], FILL[rating])
    if r.get("waived_issues"):
        D.p(f"{r['waived_issues']} more issues are waived: a person accepted the risk for "
            "now.  A waiver does not fix anything, so each waived issue keeps its rating "
            "here, and waived issues are not counted in the overall rating.")
    top = [i for i in items if i["rating"] != "Informational" and not i.get("waived")][:5]
    if top:
        D.h("Key findings", 2)
        for i in top:
            para = doc.add_paragraph(style="List Bullet")
            run = para.add_run(spaced(f"{i['id']}  {i['title']} ({i['rating']}).") + "  ")
            run.bold = True
            para.add_run(spaced(i.get("what") or ""))
    actions = r["summary"].get("actions") or []
    if actions:
        D.h("What leadership needs to do", 2)
        D.bullets([f"{a['lead']}.  {a['text']}" for a in actions], numbered=True)

    # ---- 2 scope
    D.page_break()
    D.h("2.  Scope and Approach")
    scope = [("Repository", r["repository"]), ("Branch", r.get("branch") or "default")]
    if r.get("commit"):
        scope.append(("Commit", r["commit"]))
    if r.get("file_count"):
        scope.append(("Files", str(r["file_count"])))
    counts = r.get("counts") or {}
    scope.append(("Open scanner alerts", f"{counts.get('open', 0)}, in "
                                         f"{counts.get('groups', 0)} groups by rule and file"))
    if (r.get("overview") or {}).get("what_it_is"):
        scope.append(("What it holds", r["overview"]["what_it_is"]))
    D.table(["Item", "Detail"], scope, [1.8, 4.9])
    D.h("Method", 2)
    D.bullets([
        "Automated scanning.  Secret, code, dependency and configuration scanning of "
        "the branch and its history.",
        "Review of each alert.  Alerts were grouped by rule and file, and each group "
        "was judged against the code around it.  An alert a person already graded "
        "keeps that grade.",
        "Review of the repository.  The file tree and key files were read for problems "
        "a scanner does not look for, such as access settings and trust placed in "
        "browser code."])
    D.h("Limits of this review", 2)
    D.p("This review was produced by automated analysis of the code and the scanner "
        "results.  A person should confirm each finding before acting on it.  No traffic "
        "was sent to any running system.  Credentials were never sent for analysis.  "
        "Issues marked as needing confirmation in the running system depend on settings "
        "the code does not show.")
    for note in r.get("notes") or []:
        D.p(note, italic=True, size=9, color=GRAY)

    # ---- 3 rating method
    D.h("3.  How Risks Are Rated")
    D.p("Each issue gets a likelihood score and an impact score from 1 to 5.  The risk "
        "score is the two multiplied together, and the score sets the rating.  The CVSS "
        "3.1 base score is worked out from each issue's vector and shown beside it.")
    D.table(["Score", "Rating", "Meaning"], [
        ["20 to 25", "Critical", "Act now.  Exposure is direct and the harm is serious."],
        ["10 to 16", "High", "Fix within days.  Real harm is likely if left alone."],
        ["5 to 9", "Medium", "Fix within 30 days."],
        ["1 to 4", "Low", "Fix as part of normal work."],
        ["Not scored", "Informational", "No risk.  Recorded for accuracy, such as a false alarm."]],
        [1.1, 1.2, 4.4], badge_col=1)

    # ---- 4 risk matrix
    D.page_break()
    D.h("4.  Risk Matrix")
    rows = []
    for i in items:
        scored = i["rating"] != "Informational" and not i.get("decided")
        rows.append([i["id"], i["title"] + (" (waived)" if i.get("waived") else ""),
                     str(i["likelihood"]) if scored else "N/A",
                     str(i["impact"]) if scored else "N/A",
                     str(i["score"]) if scored else "N/A",
                     f"{i['cvss_score']:.1f}" if i.get("cvss_score") is not None else "N/A",
                     i["rating"]])
    D.table(["ID", "Issue", "Likelihood", "Impact", "Score", "CVSS", "Rating"], rows,
            [0.5, 3.0, 0.75, 0.6, 0.55, 0.5, 0.8], badge_col=6, size=8)
    D.h("Heat map", 2)
    words = context.get("impact_words") or {}
    matrix = context.get("matrix") or []
    t = doc.add_table(rows=len(matrix) + 1, cols=6)
    t.style = "Table Grid"
    _margins(t, 80, 80)
    for r_n, row in enumerate(matrix):
        _cell(t.rows[r_n].cells[0], f"{row['likelihood']} {row['label']}", bold=True, size=8)
        _shade(t.rows[r_n].cells[0], "D6DCE4")
        for c_n, cell in enumerate(row["cells"]):
            _cell(t.rows[r_n].cells[c_n + 1], ", ".join(cell["ids"]) or " ", size=8,
                  align=WD_ALIGN_PARAGRAPH.CENTER)
            _shade(t.rows[r_n].cells[c_n + 1], HEAT.get(cell["rating"], "FFFFFF"))
    last = t.rows[len(matrix)]
    _cell(last.cells[0], "", size=8)
    for n in range(1, 6):
        _cell(last.cells[n], f"{n} {words.get(n, '')}", bold=True, size=8,
              align=WD_ALIGN_PARAGRAPH.CENTER)
        _shade(last.cells[n], "D6DCE4")
    _widths(t, [1.2] + [1.1] * 5)
    D.p("Rows are likelihood and columns are impact.  False alarms and ratings decided "
        "before this review have no scores and are not shown.", italic=True, size=8.5,
        color=GRAY)

    # ---- 5 detailed findings
    D.page_break()
    D.h("5.  Detailed Findings")
    for i in items:
        D.h(f"{i['id']}  {i['title']}", 3)
        D.identity(i)
        info = [("Rating", i["rating"] + ("  (waived)" if i.get("waived") else ""))]
        if i.get("location"):
            info.append(("Location", i["location"]))
        if i.get("cvss"):
            info.append(("CVSS 3.1", f"{i['cvss_score']:.1f} {i.get('cvss_band', '')}  ({i['cvss']})"))
        if i["rating"] != "Informational" and not i.get("decided"):
            info.append(("Likelihood x Impact", f"{i['likelihood']} x {i['impact']} = {i['score']}"))
        if i.get("cwe_label"):
            info.append(("Weakness", i["cwe_label"]))
        owasp = "; ".join(x for x in (
            f"{i['owasp']}:2021 {i['owasp_name']}" if i.get("owasp") else "",
            f"{i['api']}:2023 {i['api_name']}" if i.get("api") else "") if x)
        if owasp:
            info.append(("OWASP", owasp))
        if i.get("status") == "confirmed_in_source":
            info.append(("Evidence status", "Confirmed in the source code."))
        elif i.get("status") == "needs_runtime":
            info.append(("Evidence status", "Needs confirmation in the running system.  "
                         + (i.get("runtime_check") or "")))
        if i.get("waived") and i.get("waiver"):
            w = i["waiver"]
            info.append(("Why it is waived", (w.get("reason") or "No reason was recorded.")
                         + "  The risk is accepted, not removed."))
        if i.get("source") == "scanner" and i.get("rule"):
            info.append(("Scanner reference", f"{i.get('count', 0)} alerts of rule {i['rule']}"))
        elif i.get("source") == "review":
            info.append(("Source", "Review of the repository"))
        t = D.table(["Attribute", "Value"], info, [1.5, 5.2])
        _badge(t.rows[1].cells[1], i["rating"])
        if i.get("what"):
            D.labeled("What we found.", i["what"])
        if i.get("evidence"):
            D.labeled("Evidence.", i["evidence"])
        D.code(i.get("code"), "The code involved")
        if i.get("why"):
            D.labeled("Why it matters.", i["why"])
        if i.get("attack"):
            D.p("How an attacker could abuse it.", bold=True, color=NAVY, after=2)
            D.bullets(i["attack"], numbered=True)
        if i.get("fixes"):
            D.p("What to do.", bold=True, color=NAVY, after=2)
            D.bullets(i["fixes"])
        D.code(i.get("fix_example"), "Example of the fix")
        if i.get("retest"):
            D.labeled("How to confirm the fix.", i["retest"])
        if i.get("references"):
            D.p("References:  " + "   ".join(i["references"]), size=8, color=GRAY)

    # ---- 6 to 9
    overview = r.get("overview") or {}
    if overview.get("positives"):
        D.h("6.  Positive Observations")
        D.bullets(overview["positives"])
    roadmap = r["summary"].get("roadmap") or []
    if roadmap:
        D.h("7.  Remediation Roadmap")
        D.table(["Timeframe", "Action", "Issues", "Owner"],
                [[s["timeframe"], s["action"], s["issues"], s["owner"]] for s in roadmap],
                [1.2, 3.2, 1.1, 1.2])
    cov = context.get("coverage")
    if cov:
        D.page_break()
        D.h("8.  OWASP Coverage")
        D.p("Each issue is placed in the OWASP category its weakness (CWE) belongs to.  "
            "None found means no issue in this report falls in that category.  It is not a "
            "promise that the category was fully tested.")
        D.h("OWASP Top 10 (2021)", 2)
        D.table(["Category", "Issues"], [[f"{c['code']}  {c['name']}",
                                          ", ".join(c["ids"]) or "None found"]
                                         for c in cov["top10"]], [3.6, 3.1])
        D.h("OWASP API Security Top 10 (2023)", 2)
        D.table(["Category", "Issues"], [[f"{c['code']}  {c['name']}",
                                          ", ".join(c["ids"]) or "None found"]
                                         for c in cov["api"]], [3.6, 3.1])
    retests = context.get("retests") or []
    if retests:
        D.h("9.  Retest Plan")
        D.p("Run these checks after each fix, against a test copy where possible.  A fix "
            "is done when its check passes.")
        D.table(["ID", "Issue", "Check", "Rating"],
                [[i["id"], i["title"], i["retest"], i["rating"]] for i in retests],
                [0.55, 2.0, 3.25, 0.9], badge_col=3)
    if r["summary"].get("conclusion"):
        D.h("10.  Conclusion")
        D.p(r["summary"]["conclusion"])

    # ---- appendices
    by_rule = counts.get("by_rule") or []
    if by_rule:
        D.page_break()
        D.h("Appendix A.  Open Scanner Alerts")
        D.table(["Rule or package", "Kind", "Alerts", "Files"],
                [[x["rule"], x["kind"], str(x["count"]), str(x["files"])] for x in by_rule]
                + [["Total", "", str(counts.get("open", 0)), ""]],
                [3.4, 1.3, 1.0, 1.0])
    if context.get("standards"):
        D.h("Appendix B.  Standards Used")
        D.bullets(context["standards"])

    out = io.BytesIO()
    doc.core_properties.title = f"Security Assessment: {r['repository']}"
    doc.core_properties.author = org or "Security Assessment"
    doc.save(out)
    return out.getvalue()
