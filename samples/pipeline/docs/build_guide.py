#!/usr/bin/env python3
"""Builds the pipeline guide as Word, then PDF.

    python3 build_guide.py            writes Git-Code-Review-Pipeline-Guide.docx
    soffice --headless --convert-to pdf Git-Code-Review-Pipeline-Guide.docx

Needs python-docx.  This script is not part of the kit zip; only what it
writes is.  The writing rules: US English, plain words, no em dashes, two
spaces between sentences.
"""

from __future__ import annotations

import sys
from datetime import date
from pathlib import Path

from docx import Document
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor

HERE = Path(__file__).resolve().parent
OUT = HERE / "Git-Code-Review-Pipeline-Guide.docx"
VERSION = "1.0.1"

# The product's own colors, from app/web/static/app.css.
INK = RGBColor(0x14, 0x14, 0x14)
SOFT = RGBColor(0x5C, 0x5C, 0x5C)
BLUE = RGBColor(0x1F, 0x4F, 0x82)
GREEN = RGBColor(0x1A, 0x7F, 0x37)
RED = RGBColor(0xB4, 0x23, 0x18)
AMBER = RGBColor(0x9A, 0x67, 0x00)
FILLS = {"code": "F6F6F6", "tip": "EAF1F8", "warn": "FDF6E3", "danger": "FDECEB",
         "ok": "EAF4EC", "head": "141414", "zebra": "FAFAFA"}
EDGES = {"code": "C8C8C8", "tip": "1F4F82", "warn": "9A6700", "danger": "B42318",
         "ok": "1A7F37"}
BODY_FONT, CODE_FONT = "Arial", "Consolas"
URL = "https://gcr.example.com/api/v1"


# -- low level helpers -------------------------------------------------------

def shade(cell, fill):
    props = cell._tc.get_or_add_tcPr()
    node = OxmlElement("w:shd")
    node.set(qn("w:val"), "clear")
    node.set(qn("w:color"), "auto")
    node.set(qn("w:fill"), fill)
    props.append(node)


def borders(cell, color, left_only=False, size=8):
    props = cell._tc.get_or_add_tcPr()
    edges = OxmlElement("w:tcBorders")
    for side in ("top", "left", "bottom", "right"):
        node = OxmlElement(f"w:{side}")
        if left_only and side != "left":
            node.set(qn("w:val"), "nil")
        else:
            node.set(qn("w:val"), "single")
            node.set(qn("w:sz"), str(24 if left_only else size))
            node.set(qn("w:color"), color)
        edges.append(node)
    props.append(edges)


def margins(cell, top=80, bottom=80, left=140, right=140):
    props = cell._tc.get_or_add_tcPr()
    mar = OxmlElement("w:tcMar")
    for side, value in (("top", top), ("left", left), ("bottom", bottom), ("right", right)):
        node = OxmlElement(f"w:{side}")
        node.set(qn("w:w"), str(value))
        node.set(qn("w:type"), "dxa")
        mar.append(node)
    props.append(mar)


def no_split(table):
    """Keep each row on one page."""
    for row in table.rows:
        props = row._tr.get_or_add_trPr()
        node = OxmlElement("w:cantSplit")
        node.set(qn("w:val"), "true")
        props.append(node)


def keep_with_next(paragraph):
    paragraph.paragraph_format.keep_with_next = True


def spacing(paragraph, before=0, after=6, line=None):
    fmt = paragraph.paragraph_format
    fmt.space_before = Pt(before)
    fmt.space_after = Pt(after)
    if line:
        fmt.line_spacing = line


def runs(paragraph, text, size=None, color=None, bold=None, font=None):
    """Add text where `code` spans in backticks are set in the code font."""
    parts = text.split("`")
    for index, part in enumerate(parts):
        if not part:
            continue
        run = paragraph.add_run(part)
        if index % 2 == 1:
            run.font.name = CODE_FONT
            run.font.size = Pt((size or 10.5) - 1)
            run.font.color.rgb = BLUE
        else:
            if font:
                run.font.name = font
            if size:
                run.font.size = Pt(size)
            if color is not None:
                run.font.color.rgb = color
            if bold:
                run.bold = True
    return paragraph


def bold_lead(paragraph, lead, rest, size=None):
    run = paragraph.add_run(lead)
    run.bold = True
    if size:
        run.font.size = Pt(size)
    runs(paragraph, rest, size=size)
    return paragraph


class Guide:
    def __init__(self):
        self.doc = Document()
        self.number = 0
        self._styles()
        self._page()

    # -- setup ---------------------------------------------------------------

    def _styles(self):
        styles = self.doc.styles
        normal = styles["Normal"]
        normal.font.name = BODY_FONT
        normal.font.size = Pt(10.5)
        normal.font.color.rgb = INK
        normal.element.rPr.rFonts.set(qn("w:eastAsia"), BODY_FONT)
        normal.paragraph_format.space_after = Pt(6)
        normal.paragraph_format.line_spacing = 1.15
        for level, size, color in ((1, 20, INK), (2, 14, BLUE), (3, 12, INK)):
            style = styles[f"Heading {level}"]
            style.font.name = BODY_FONT
            style.font.size = Pt(size)
            style.font.bold = True
            style.font.color.rgb = color
            fonts = style.element.rPr.rFonts
            for attr in ("w:asciiTheme", "w:hAnsiTheme", "w:eastAsiaTheme", "w:cstheme"):
                if fonts.get(qn(attr)) is not None:
                    del fonts.attrib[qn(attr)]
            for attr in ("w:ascii", "w:hAnsi", "w:eastAsia", "w:cs"):
                fonts.set(qn(attr), BODY_FONT)
            style.paragraph_format.space_before = Pt(18 if level == 1 else 12)
            style.paragraph_format.space_after = Pt(6)
            style.paragraph_format.keep_with_next = True
        for name in ("List Bullet", "List Number"):
            styles[name].font.name = BODY_FONT
            styles[name].font.size = Pt(10.5)

    def _page(self):
        section = self.doc.sections[0]
        section.page_width, section.page_height = Inches(8.5), Inches(11)
        for side in ("left_margin", "right_margin"):
            setattr(section, side, Inches(1))
        section.top_margin, section.bottom_margin = Inches(0.9), Inches(0.9)
        section.different_first_page_header_footer = True

        header = section.header.paragraphs[0]
        header.add_run().add_picture(str(HERE / "assets" / "logo.png"), width=Inches(0.22))
        runs(header, "   Git Code Review", size=9, bold=True)
        runs(header, "   |   Pipeline Guide", size=9, color=SOFT)
        self._rule(header)

        footer = section.footer.paragraphs[0]
        footer.alignment = WD_ALIGN_PARAGRAPH.CENTER
        runs(footer, f"Git Code Review {VERSION}   |   Page ", size=8, color=SOFT)
        self._field(footer, "PAGE", size=8)

    def _rule(self, paragraph, color="C8C8C8"):
        props = paragraph._p.get_or_add_pPr()
        border = OxmlElement("w:pBdr")
        bottom = OxmlElement("w:bottom")
        bottom.set(qn("w:val"), "single")
        bottom.set(qn("w:sz"), "6")
        bottom.set(qn("w:space"), "4")
        bottom.set(qn("w:color"), color)
        border.append(bottom)
        props.append(border)

    def _field(self, paragraph, code, size=8):
        run = paragraph.add_run()
        run.font.size = Pt(size)
        run.font.color.rgb = SOFT
        for kind, text in (("begin", None), (None, code), ("separate", None),
                           (None, "1"), ("end", None)):
            if kind:
                node = OxmlElement("w:fldChar")
                node.set(qn("w:fldCharType"), kind)
            elif text == code:
                node = OxmlElement("w:instrText")
                node.set(qn("xml:space"), "preserve")
                node.text = f" {code} "
            else:
                node = OxmlElement("w:t")
                node.text = text
            run._r.append(node)

    # -- content blocks --------------------------------------------------------

    def cover(self):
        doc = self.doc
        for _ in range(5):
            spacing(doc.add_paragraph(), after=12)
        logo = doc.add_paragraph()
        logo.add_run().add_picture(str(HERE / "assets" / "logo.png"), width=Inches(1.1))
        title = doc.add_paragraph()
        runs(title, "Git Code Review", size=34, bold=True)
        spacing(title, before=12, after=0)
        sub = doc.add_paragraph()
        runs(sub, "Pipeline Guide", size=24, color=BLUE)
        spacing(sub, after=14)
        self._rule(sub, "141414")
        lead = doc.add_paragraph()
        runs(lead, "Find and fix security problems before your code ships.  "
                   "A step by step guide to the sample scripts and GitHub Actions "
                   "workflows, written for people who are new to pipelines.",
             size=13, color=SOFT)
        spacing(lead, before=10, after=40)
        meta = doc.add_paragraph()
        runs(meta, f"Version {VERSION}   |   {date.today():%B %Y}", size=10, color=SOFT)
        doc.add_paragraph().add_run().add_break(WD_BREAK.PAGE)

    def h1(self, text, numbered=True):
        if numbered:
            self.number += 1
            text = f"{self.number}.  {text}"
        heading = self.doc.add_heading(text, level=1)
        self._rule(heading)
        return heading

    def h2(self, text):
        return self.doc.add_heading(text, level=2)

    def h3(self, text):
        return self.doc.add_heading(text, level=3)

    def p(self, text, size=None, color=None, after=6):
        paragraph = runs(self.doc.add_paragraph(), text, size=size, color=color)
        spacing(paragraph, after=after)
        return paragraph

    def bullets(self, items, style="List Bullet"):
        for item in items:
            paragraph = self.doc.add_paragraph(style=style)
            if isinstance(item, tuple):
                bold_lead(paragraph, item[0], item[1])
            else:
                runs(paragraph, item)
            spacing(paragraph, after=3)

    def steps(self, items):
        """A numbered list that starts again at 1."""
        numbering = self.doc.part.numbering_part.numbering_definitions._numbering
        style_num = self.doc.styles["List Number"].element.pPr.numPr.numId.val
        abstract = numbering.num_having_numId(style_num).abstractNumId.val
        fresh = numbering.add_num(abstract)
        override = OxmlElement("w:lvlOverride")
        override.set(qn("w:ilvl"), "0")
        start = OxmlElement("w:startOverride")
        start.set(qn("w:val"), "1")
        override.append(start)
        fresh.append(override)
        for item in items:
            paragraph = self.doc.add_paragraph(style="List Number")
            props = paragraph._p.get_or_add_pPr()
            num_pr = OxmlElement("w:numPr")
            level = OxmlElement("w:ilvl")
            level.set(qn("w:val"), "0")
            num_id = OxmlElement("w:numId")
            num_id.set(qn("w:val"), str(fresh.numId))
            num_pr.append(level)
            num_pr.append(num_id)
            props.append(num_pr)
            if isinstance(item, tuple):
                bold_lead(paragraph, item[0], item[1])
            else:
                runs(paragraph, item)
            spacing(paragraph, after=3)

    def code(self, text, label=""):
        """A shaded box in a fixed width font, the way code is shown."""
        if label:
            caption = runs(self.doc.add_paragraph(), label, size=9, color=SOFT)
            spacing(caption, before=4, after=2)
            keep_with_next(caption)
        table = self.doc.add_table(rows=1, cols=1)
        table.alignment = WD_TABLE_ALIGNMENT.CENTER
        cell = table.rows[0].cells[0]
        shade(cell, FILLS["code"])
        borders(cell, EDGES["code"], size=4)
        margins(cell, 100, 100, 160, 160)
        cell.width = Inches(6.5)
        lines = text.strip("\n").split("\n")
        first = cell.paragraphs[0]
        for index, line in enumerate(lines):
            paragraph = first if index == 0 else cell.add_paragraph()
            spacing(paragraph, after=0, line=1.0)
            run = paragraph.add_run(line if line else " ")
            run.font.name = CODE_FONT
            run.font.size = Pt(8.5)
            run._r.get_or_add_rPr().get_or_add_rFonts().set(qn("w:eastAsia"), CODE_FONT)
            if line.lstrip().startswith("#"):
                run.font.color.rgb = SOFT
        if len(lines) <= 40:
            no_split(table)
        spacing(self.doc.add_paragraph(), after=2)

    def callout(self, kind, title, text):
        """Tip, warning or danger box with a colored bar on the left."""
        table = self.doc.add_table(rows=1, cols=1)
        cell = table.rows[0].cells[0]
        shade(cell, FILLS[kind])
        borders(cell, EDGES[kind], left_only=True)
        margins(cell, 100, 100, 200, 160)
        cell.width = Inches(6.5)
        head = cell.paragraphs[0]
        color = {"tip": BLUE, "warn": AMBER, "danger": RED, "ok": GREEN}[kind]
        runs(head, title, bold=True, color=color)
        spacing(head, after=2)
        for chunk in text if isinstance(text, list) else [text]:
            paragraph = runs(cell.add_paragraph(), chunk)
            spacing(paragraph, after=2)
        no_split(table)
        spacing(self.doc.add_paragraph(), after=2)

    def table(self, header, rows, widths):
        table = self.doc.add_table(rows=1, cols=len(header))
        table.alignment = WD_TABLE_ALIGNMENT.CENTER
        for index, text in enumerate(header):
            cell = table.rows[0].cells[index]
            shade(cell, FILLS["head"])
            margins(cell, 60, 60, 100, 100)
            cell.width = Inches(widths[index])
            run = cell.paragraphs[0].add_run(text)
            run.bold = True
            run.font.size = Pt(9.5)
            run.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
        for number, row in enumerate(rows):
            cells = table.add_row().cells
            for index, text in enumerate(row):
                cell = cells[index]
                cell.width = Inches(widths[index])
                margins(cell, 50, 50, 100, 100)
                borders(cell, "E0E0E0", size=4)
                if number % 2:
                    shade(cell, FILLS["zebra"])
                runs(cell.paragraphs[0], text, size=9.5)
                spacing(cell.paragraphs[0], after=0)
        # Repeat the header row when a table runs onto another page.
        header_props = table.rows[0]._tr.get_or_add_trPr()
        repeat = OxmlElement("w:tblHeader")
        repeat.set(qn("w:val"), "true")
        header_props.append(repeat)
        no_split(table)
        spacing(self.doc.add_paragraph(), after=2)

    def faq(self, question, error, meaning, todo):
        self.h3(question)
        if error:
            self.code(error, "The message looks like this:")
        keep_with_next(bold_lead(self.doc.add_paragraph(), "What it means:  ", meaning))
        paragraph = self.doc.add_paragraph()
        run = paragraph.add_run("What to do:")
        run.bold = True
        keep_with_next(paragraph)
        self.steps(todo) if isinstance(todo, list) else runs(paragraph, "  " + todo)

    def page_break(self):
        self.doc.add_paragraph().add_run().add_break(WD_BREAK.PAGE)

    def _schema_order(self):
        """Put property elements in the order the Word schema requires.

        They are added in whatever order the helpers above run, and Word is
        strict about it: out of order, it can call the file damaged.
        """
        orders = {
            "pPr": ["pStyle", "keepNext", "keepLines", "pageBreakBefore", "framePr",
                    "widowControl", "numPr", "suppressLineNumbers", "pBdr", "shd", "tabs",
                    "suppressAutoHyphens", "kinsoku", "wordWrap", "overflowPunct",
                    "topLinePunct", "autoSpaceDE", "autoSpaceDN", "bidi", "adjustRightInd",
                    "snapToGrid", "spacing", "ind", "contextualSpacing", "mirrorIndents",
                    "suppressOverlap", "jc", "textDirection", "textAlignment",
                    "textboxTightWrap", "outlineLvl", "divId", "cnfStyle", "rPr",
                    "sectPr", "pPrChange"],
            "tcPr": ["cnfStyle", "tcW", "gridSpan", "hMerge", "vMerge", "tcBorders", "shd",
                     "noWrap", "tcMar", "textDirection", "tcFitText", "vAlign", "hideMark"],
        }
        for part in [self.doc.part] + [s.header.part for s in self.doc.sections] \
                + [s.footer.part for s in self.doc.sections]:
            for tag, order in orders.items():
                rank = {name: i for i, name in enumerate(order)}
                for props in part.element.iter(qn(f"w:{tag}")):
                    children = list(props)
                    children.sort(key=lambda c: rank.get(c.tag.split("}")[-1], len(order)))
                    for child in children:
                        props.remove(child)
                        props.append(child)
        zoom = self.doc.settings.element.find(qn("w:zoom"))
        if zoom is not None and zoom.get(qn("w:percent")) is None:
            zoom.set(qn("w:percent"), "100")

    def save(self, path):
        self._schema_order()
        self.doc.core_properties.title = "Git Code Review Pipeline Guide"
        self.doc.core_properties.subject = "Using Git Code Review from build pipelines"
        self.doc.core_properties.author = "Git Code Review"
        self.doc.save(str(path))


# -- the guide ---------------------------------------------------------------

SAMPLE_PLAN = """## Fix plan for `acme/payments` on `main`

### 1. Secrets in the code: do these first
| Severity | What                 | Where              | Live?                  |
| high     | AWS key AKIA****WXYZ | src/config.js:3    | YES, confirmed working |

### 2. Packages to upgrade
| Package       | Now     | Upgrade to | Worst | Declared in       |
| lodash (npm)  | 4.17.20 | 4.17.21    | high  | package-lock.json |

### 3. Container images to rebuild
- node:18 (critical): openssl 3.0.0

### 4. Problems in the build and CI files
- medium .github/workflows/build.yml:14 unpinned action reference.

### 5. Code fixes reviewed by AI
- high src/report.py:42 SQL built from request input
  - Fix: Pass month as a bound parameter to cursor.execute.
  - Until then: Give the report user read access only."""


def write(g: Guide):
    g.cover()

    # Contents, by hand: a Word field would need updating before it shows.
    g.h1("Contents", numbered=False)
    for line in ("1.  What this kit does", "2.  Words you will see",
                 "3.  Before you start", "4.  Step 1: Make a token",
                 "5.  Step 2: Store the token in GitHub",
                 "6.  Step 3: Add the files to your repository",
                 "7.  Step 4: Choose what the pipeline should do",
                 "8.  Running the scripts on your own computer",
                 "9.  Command reference", "10.  Security best practices",
                 "11.  FAQ and troubleshooting", "12.  Getting help"):
        spacing(runs(g.doc.add_paragraph(), line, size=11), after=3)
    g.page_break()

    # 1 -----------------------------------------------------------------------
    g.h1("What this kit does")
    g.p("Git Code Review scans your code on a schedule and keeps a list of what "
        "it found.  This kit lets your build pipeline ask for that list, so the "
        "people who build and ship the code see the problems at the moment they "
        "can act on them.")
    g.p("The main tool is the fix plan.  It turns the findings for one repository "
        "into a short to-do list, in the order things should be done:")
    g.table(["Order", "What it lists", "What you do about it"], [
        ["1", "Secrets in the code, such as passwords and API keys",
         "Rotate the secret first, then remove it from the code."],
        ["2", "Packages with known vulnerabilities",
         "Upgrade to the version shown in the plan."],
        ["3", "Container images with vulnerable software inside",
         "Move to a newer base image tag and rebuild."],
        ["4", "Problems in build files, such as GitHub Actions workflows and Dockerfiles",
         "Follow the advice on the finding's page."],
        ["5", "Code problems that an AI review has already read",
         "Apply the fix the review suggests."],
    ], [0.6, 2.9, 3.0])
    g.p("The kit can also:")
    g.bullets([
        ("Stop a deploy ", "when something serious is found, before it reaches your servers."),
        ("Attach an SBOM ", "(a list of every software package in the code) to each release."),
        ("Warn you ", "before your token expires, so the pipeline does not break suddenly."),
        ("Ask for an exception ", "when a finding is an accepted risk.  An administrator approves it."),
    ])
    g.callout("tip", "Code fixes come only from AI reviews",
              "The plan suggests a code change only when an AI review has read "
              "that finding and the code has not changed since.  Other code "
              "findings are counted, and you can open them in Git Code Review.  "
              "Ask an administrator to run an AI review if you want advice on them.")

    # 2 -----------------------------------------------------------------------
    g.h1("Words you will see")
    g.table(["Word", "What it means"], [
        ["Pipeline", "The steps that run automatically when code changes: build, test, deploy."],
        ["GitHub Actions", "GitHub's pipeline service.  It runs the steps for you."],
        ["Workflow", "A file in `.github/workflows/` that tells GitHub Actions what to run and when."],
        ["Runner", "The computer that runs a workflow.  GitHub provides them, or you can run your own."],
        ["Token", "A long password made for a program, not a person.  Ours start with `gcr_`."],
        ["Scope", "What a token is allowed to do.  A pipeline token needs only `reports`."],
        ["Secret (GitHub)", "A value GitHub stores encrypted and hands to a workflow without showing it."],
        ["Finding", "One problem the scanner found, such as a vulnerable package or a password in code."],
        ["Severity", "How serious a finding is: critical, high, medium, low or info."],
        ["CVE / GHSA", "The public ID of a known vulnerability, such as CVE-2021-23337."],
        ["Known exploited", "Attackers are already using this vulnerability.  Fix these first."],
        ["SBOM", "Software Bill of Materials: a list of every package in the code and its version."],
        ["Exit code", "A number a script ends with.  0 means OK.  Anything else stops the pipeline."],
    ], [1.6, 4.9])

    # 3 -----------------------------------------------------------------------
    g.h1("Before you start")
    g.p("Check each of these.  Most problems people hit come from one of them.")
    g.table(["You need", "How to check", "If you do not have it"], [
        ["An account on Git Code Review that can see your repository",
         "Sign in and find the repository on the Repositories page.",
         "Ask an administrator to give you access."],
        ["Permission to change your repository's settings in GitHub",
         "You can open Settings in the repository.",
         "Ask the repository owner, or have them do steps 2 and 3."],
        ["A network path from the runner to Git Code Review",
         "See the FAQ: \"HTTP 403: refused before it reached the API\".",
         "Ask an administrator to allow the runner's IP address."],
        ["Your repository is being scanned",
         "It has findings, or a last scanned date, in Git Code Review.",
         "Ask an administrator to add it, and the branch you deploy, to a scan."],
    ], [2.0, 2.3, 2.2])
    g.callout("warn", "GitHub's own runners and IP allow lists",
              ["If your server only accepts known IP addresses, GitHub's hosted runners "
               "(`runs-on: ubuntu-latest`) will usually be refused.  They come from "
               "thousands of addresses that change all the time.",
               "Use a self-hosted runner inside your network, or GitHub's larger runners "
               "with a static IP range, and ask an administrator to allow that address.  "
               "The workflows in this kit read the runner to use from a variable named "
               "`GCR_RUNNER`, so you can switch without editing them."])

    # 4 -----------------------------------------------------------------------
    g.h1("Step 1: Make a token")
    g.steps([
        "Sign in to Git Code Review.",
        "Click **IDE tokens** in the menu on the left.".replace("**", ""),
        "In the \"Make one\" box, type a name that says where it will be used, for "
        "example `payments repository pipeline`.",
        "Set \"Expires after\" to 90 days or less.",
        "Tick only `reports`.  Untick everything else.",
        "Click \"Make the token\".",
        "Copy the token straight away.  It is shown once and never again.",
    ])
    g.p("What each scope allows:")
    g.table(["Scope", "What it is for", "Give it to"], [
        ["reports", "Reads your findings, fix plan, SBOMs and trends, runs the deploy check, "
                    "and asks for, changes and withdraws your own exceptions.  Sees only "
                    "repositories your account can open.  On an administrator's account it "
                    "can also revoke exceptions and exclusions.",
         "Build and deploy pipelines.  This kit uses only this one."],
        ["approve", "Approves and rejects exceptions, and adds exclusions.  Only an "
                    "administrator's token can have it.  It takes findings out of the reports.",
         "An administrator's own scripts.  Never a pipeline."],
        ["review", "Sends code to be checked and gets problems back.  Nothing is saved.",
         "Editor plugins."],
        ["rules", "Reads the triage rules, so an editor hides the same noise.", "Editor plugins."],
        ["gate", "Runs the pull request gate, which scans only what a pull request changed.",
         "Pull request checks."],
    ], [0.9, 3.7, 1.9])
    g.callout("danger", "Treat the token like a password",
              ["Never paste it into a workflow file, a script, a chat message or a ticket.  "
               "Anybody who has it can read your findings.",
               "If it is ever exposed, revoke it on the IDE tokens page at once and make a new one."])

    # 5 -----------------------------------------------------------------------
    g.h1("Step 2: Store the token in GitHub")
    g.p("GitHub keeps secrets encrypted and hands them to your workflow without "
        "ever showing them in the logs.")
    g.steps([
        "Open your repository on GitHub.",
        "Click Settings (at the top of the repository, not your profile settings).",
        "In the left menu, click Secrets and variables, then Actions.",
        "On the Secrets tab, click New repository secret.  Name: `GCR_TOKEN`.  "
        "Secret: paste the token.  Click Add secret.",
        "On the Variables tab, click New repository variable.  Name: `GCR_URL`.  "
        "Value: your server's API address.  It is in the kit's `.env.example` file, "
        f"and looks like `{URL}`.  Click Add variable.",
        "Optional: add a variable `GCR_RUNNER` with the label of your self-hosted "
        "runner, such as `self-hosted`.",
    ])
    g.callout("tip", "Many repositories?",
              "An organization owner can add `GCR_TOKEN` and `GCR_URL` once under the "
              "organization's settings and share them with chosen repositories.  Use a "
              "separate token for each team, so one can be revoked without breaking the others.")

    # 6 -----------------------------------------------------------------------
    g.h1("Step 3: Add the files to your repository")
    g.p("Unzip the kit.  Copy two folders and one workflow into your repository, "
        "so it looks like this:")
    g.code("""your-repository/
  .github/
    gcr/
      bash/          <- copy the kit's bash folder here
      python/        <- copy the kit's python folder here
    workflows/
      gcr-fix-plan.yml   <- copy one or more files from github-actions/""")
    g.p("On a computer with Git, from the folder where you unzipped the kit:")
    g.code("""# Change this to where your repository is
REPO=~/code/your-repository

mkdir -p "$REPO/.github/gcr" "$REPO/.github/workflows"
cp -r gcr-pipeline-samples/bash gcr-pipeline-samples/python "$REPO/.github/gcr/"
cp gcr-pipeline-samples/github-actions/gcr-fix-plan.yml "$REPO/.github/workflows/"

cd "$REPO"
git add .github
git commit -m "Add Git Code Review checks"
git push""", "Copy the files and push them")
    g.p("Then open the Actions tab of your repository on GitHub.  You will see "
        "the workflow run.  Click it, and the fix plan is on the Summary page.")

    # 7 -----------------------------------------------------------------------
    g.h1("Step 4: Choose what the pipeline should do")
    g.p("Each workflow in the kit does one job.  Use any of them, alone or together.")

    g.h2("7.1  See a fix plan every week and on every pull request")
    g.p("File: `github-actions/gcr-fix-plan.yml`.  It never fails a build because "
        "of findings.  It shows the to-do list on the run's Summary page, and keeps "
        "it as a download.  It also warns when the token has less than 14 days left.")
    g.code(SAMPLE_PLAN, "What the Summary page shows (shortened):")
    g.p("On a pull request, the plan is for the branch being merged into, because "
        "that is the branch the scanner has read.")

    g.h2("7.2  Stop a deploy when something serious is found")
    g.p("File: `github-actions/gcr-deploy-gate.yml`.  The check job runs first, and "
        "the deploy job only runs if it passes.  To add the check to a workflow you "
        "already have, copy the `security-check` job and add "
        "`needs: security-check` to your deploy job.")
    g.code("""  security-check:
    runs-on: ${{ vars.GCR_RUNNER || 'ubuntu-latest' }}
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
        with:
          persist-credentials: false
      - name: Check for anything to fix
        env:
          GCR_URL: ${{ vars.GCR_URL }}
          GCR_TOKEN: ${{ secrets.GCR_TOKEN }}
        run: bash .github/gcr/bash/gcr-deploy-check.sh --fail-on high

  deploy:
    needs: security-check""", "The part to copy")
    g.p("The check answers one of three ways:")
    g.table(["Answer", "Exit code", "What happens"], [
        ["PASS", "0", "Nothing at or above the level you chose.  The deploy goes ahead."],
        ["FAIL", "1", "Something must be fixed.  The run lists each item, with the fix, "
                      "and marks the file it is in."],
        ["UNKNOWN", "2", "That branch was never scanned, so there is nothing to check.  "
                         "The deploy stops.  See the FAQ."],
    ], [1.0, 0.9, 4.6])
    g.p("To change how strict it is, change `--fail-on high`:")
    g.bullets([
        ("--fail-on critical ", "stops only for critical findings.  A good place to start."),
        ("--fail-on high ", "stops for high and critical.  The usual choice."),
        ("--warn-only ", "reports everything but never stops the deploy.  Good for a trial week."),
    ])
    g.callout("tip", "Known exploited packages always stop the deploy",
              "A package attackers are already using stops the deploy at any severity.  "
              "Add `--no-block-exploited` (Python) only if you have a strong reason.")

    g.h2("7.3  Attach an SBOM to every release")
    g.p("File: `github-actions/gcr-release-sbom.yml`.  When you publish a release on "
        "GitHub, it downloads the SBOM in two standard formats, CycloneDX and SPDX, "
        "and attaches both to the release.  Customers and auditors often ask for these.")

    g.h2("7.4  Ask for an exception from a script")
    g.p("When a finding is an accepted risk, for example a tool that never runs in "
        "production, you can ask for an exception.  It waits for an administrator.  "
        "Nothing changes until they approve it in Git Code Review.")
    g.code("""bash bash/gcr-request-exception.sh \\
  -i 4182 \\
  -e 2027-01-31 \\
  -m "Only used by the build, never shipped to servers." \\
  -t SEC-1203""", "Ask for an exception on finding 4182")
    g.p("The finding number is the `id` in the fix plan's details link, or in "
        "the address of the finding's page.")
    g.p("You can look at, change or withdraw your own exception later.  Nobody "
        "else's is visible to you.  Changing one that was already approved sends "
        "it back to waiting, and the finding comes back into the reports until "
        "an administrator agrees again.")
    g.code("""bash bash/gcr-exception.sh list -s requested
bash bash/gcr-exception.sh edit -i 77 -e 2027-03-31
bash bash/gcr-exception.sh withdraw -i 77""", "Follow, change or withdraw your own")

    g.h2("7.5  For administrators: approve, revoke and exclude")
    g.p("With a `reports` token, an administrator can revoke an approved exception "
        "and revoke exclusions.  Revoking only ever puts findings back into the "
        "reports.  Approving, rejecting and adding an exclusion take findings out, "
        "so they need a separate token with the `approve` scope.  Keep that token "
        "out of every pipeline.")
    g.code("""bash bash/gcr-exception.sh approve -i 77 -n "Agreed for one quarter."
bash bash/gcr-exception.sh revoke -i 77
bash bash/gcr-exclusion.sh add -p cred:4f1c9a0b7e2d6c35 -m "Test key from the vendor docs."
bash bash/gcr-exclusion.sh revoke -p cred:4f1c9a0b7e2d6c35""",
           "Sign off, take back, exclude a value and take that back")
    g.p("A revoked exclusion stays on the Exclusions page, marked revoked.  The "
        "finding page also lists any exclusion that covers it, with a button to "
        "revoke it.")

    g.h2("7.6  Fail when things get worse")
    g.p("`bash/gcr-trend-guard.sh` fails when a severity has gone up over a period.  "
        "Run it weekly to catch a team falling behind.")
    g.code("bash .github/gcr/bash/gcr-trend-guard.sh --days 30 --severity critical")

    # 8 -----------------------------------------------------------------------
    g.h1("Running the scripts on your own computer")
    g.p("Useful for trying things out before adding them to a pipeline.  You "
        "need Python 3.8 or newer for the Python script, or `curl` and `jq` for "
        "the bash scripts.  Windows users: use WSL (Windows Subsystem for Linux) or "
        "Git Bash for the bash scripts.")
    g.h2("8.1  Set up the .env file")
    g.p("The `.env` file holds your settings.  It is the standard way to keep "
        "settings out of code.  The kit's `.gitignore` already stops it from being "
        "committed.")
    g.code("""cd gcr-pipeline-samples
cp .env.example .env
chmod 600 .env        # only you can read it""", "From the unzipped kit folder")
    g.h2("8.2  Keep the token encrypted on disk")
    g.p("The safest way to keep the token on your computer is encrypted, so a copy "
        "of your files or a backup does not expose it.  The kit includes a helper "
        "that does this with GPG, a standard encryption tool.")
    g.code("""bash bash/gcr-token-store.sh save
# Paste your Git Code Review token (it will not be shown):
# Choose a passphrase to protect it:
# Saved to /home/you/.config/gcr/token.gpg
# Add this line to your .env file:
#   GCR_TOKEN_COMMAND=gpg --quiet --decrypt /home/you/.config/gcr/token.gpg""",
           "Save the token encrypted")
    g.p("Add the line it prints to `.env`.  When a script needs the token, it runs "
        "that command, and GPG asks for your passphrase.  GPG remembers it for a "
        "while, so you are not asked every time.")
    g.p("If you prefer your computer's own password store, use one of these "
        "in `.env` instead:")
    g.table(["System", "Save the token once", "Line for .env"], [
        ["macOS Keychain", "`security add-generic-password -s gcr-token -a $USER -w`",
         "`GCR_TOKEN_COMMAND=security find-generic-password -w -s gcr-token`"],
        ["Linux (GNOME, KDE)", "`secret-tool store --label=gcr service gcr-token`",
         "`GCR_TOKEN_COMMAND=secret-tool lookup service gcr-token`"],
        ["1Password CLI", "Save it in 1Password as usual",
         "`GCR_TOKEN_COMMAND=op read op://Private/gcr/token`"],
    ], [1.3, 2.6, 2.6])
    g.callout("warn", "Avoid putting the token itself in .env",
              "`GCR_TOKEN=` in `.env` works, but the token then sits on disk in plain "
              "text.  Use it only on a machine nobody else uses.  The scripts refuse "
              "a `.env` holding a token if other users can read it.")
    g.h2("8.3  Try it")
    g.code("""# Is the token working?
python3 python/gcr_api.py ping

# What should I fix in this repository?
python3 python/gcr_api.py fix-plan --repo your-org/your-repo --branch main

# Would a deploy pass?
bash bash/gcr-deploy-check.sh -r your-org/your-repo -b main""")

    # 9 -----------------------------------------------------------------------
    g.h1("Command reference")
    g.p("Every feature is in the Python script.  The bash scripts cover the same "
        "ground for places without Python.  Leave out `--repo` and `--branch` "
        "inside GitHub Actions, and they are filled in for you.")
    g.table(["Python: gcr_api.py ...", "Bash script", "What it does"], [
        ["ping", "gcr-token-check.sh", "Checks the token works and shows when it expires."],
        ["token-expiry --warn-days 14", "gcr-token-check.sh -w 14", "Warns when the token expires soon."],
        ["fix-plan", "gcr-fix-plan.sh", "The to-do list: secrets, upgrades, images, build files, AI code fixes."],
        ["check --fail-on high", "gcr-deploy-check.sh -f high", "Pass, fail or unknown for a deploy."],
        ["findings --format csv", "gcr-findings-summary.sh --csv f.csv", "Lists open findings, or saves them for a spreadsheet."],
        ["sbom --format cdx", "gcr-sbom.sh -f cdx", "Downloads the SBOM (cdx or spdx)."],
        ["trends --days 30", "gcr-trend-guard.sh -d 30", "Shows how the numbers moved; can fail when they rise."],
        ["exceptions", "gcr-exception.sh list", "Lists the exceptions you asked for."],
        ["request-exception", "gcr-request-exception.sh", "Asks for an exception on one finding."],
        ["exception --id N", "gcr-exception.sh show -i N", "Shows one of your exceptions."],
        ["edit-exception", "gcr-exception.sh edit", "Changes your own exception."],
        ["withdraw-exception", "gcr-exception.sh withdraw", "Takes back your own exception."],
        ["revoke-exception", "gcr-exception.sh revoke", "Administrators: revokes an approved exception."],
        ["approve-exception, reject-exception", "gcr-exception.sh approve, reject",
         "Administrators, approve scope: decides a waiting exception."],
        ["exclusions", "gcr-exclusion.sh list", "Administrators: lists exclusions."],
        ["exclude", "gcr-exclusion.sh add", "Administrators, approve scope: excludes a fingerprint or finding."],
        ["revoke-exclusion", "gcr-exclusion.sh revoke", "Administrators: revokes by id or fingerprint."],
        ["", "gcr-token-store.sh save", "Saves your token encrypted on your computer."],
    ], [2.1, 2.1, 2.3])
    g.p("Add `--help` to any command to see every option, for example "
        "`python3 python/gcr_api.py check --help`.")
    g.h2("Exit codes")
    g.table(["Code", "Meaning"], [
        ["0", "Worked, or the check passed."],
        ["1", "There is something to fix (the check failed, or a limit was passed)."],
        ["2", "Unknown: the branch was never scanned."],
        ["3", "The call itself failed: no token, no network, or a wrong setting.  The message says which."],
    ], [0.8, 5.7])

    # 10 ----------------------------------------------------------------------
    g.h1("Security best practices")
    g.p("This kit follows these rules, and your pipelines should too.")
    g.table(["Practice", "Why it matters", "How the kit helps"], [
        ["Least privilege", "A leaked token can only do what its scope allows.",
         "Pipelines need only `reports`.  It cannot approve, change settings or send code."],
        ["One token per pipeline", "You can revoke one without breaking the rest.",
         "Name each token after where it is used."],
        ["Short expiry, then rotate", "An old forgotten token is a common way in.",
         "`token-expiry` warns 14 days before."],
        ["Secrets in a secret store", "Files get copied, backed up and committed.",
         "GitHub secrets in CI.  Encrypted file or keychain on your computer."],
        ["Never commit settings", "Git history keeps everything forever.",
         "`.gitignore` excludes `.env`, token files and `.gpg` files."],
        ["Private files", "Other users of a shared machine must not read your token.",
         "The scripts refuse a token file or `.env` others can read (`chmod 600`)."],
        ["Encrypt in transit", "A token sent over plain HTTP can be read on the network.",
         "The scripts refuse `http://` and always check the server certificate."],
        ["Keep tokens off command lines", "Other users can see running commands' arguments.",
         "The token is passed to `curl` through a file descriptor, never as an argument."],
        ["Pin what you run", "A changed action could run anything in your pipeline.",
         "The workflows pin each action to an exact commit."],
        ["Read-only workflow permissions", "Limits what a compromised step can change.",
         "`permissions: contents: read`, except the release job, which must attach files."],
        ["Check what you download", "Confirms the kit is the one the server sent.",
         "`SHA256SUMS` in the zip, and the zip's checksum on the download page."],
    ], [1.6, 2.4, 2.5])
    g.code("""cd gcr-pipeline-samples
sha256sum -c SHA256SUMS          # Linux
shasum -a 256 -c SHA256SUMS      # macOS""", "Check the files after unzipping")

    # 11 ----------------------------------------------------------------------
    g.h1("FAQ and troubleshooting")
    g.p("Find the message you see, then follow the steps.  The messages are "
        "shown exactly as the scripts print them.")

    g.faq("The pipeline says the request was refused before it reached the API",
          "Git Code Review API: HTTP 403: refused before it reached the API.  The runner's IP\n"
          "is probably not allowed through the load balancer.",
          "Your server only accepts connections from approved IP addresses, and the "
          "computer running the pipeline is not one of them.",
          ["Find the runner's public IP address.  Add this step to the workflow, run it "
           "once, and read the output: `run: curl -s https://api.ipify.org`",
           "Send that address to your Git Code Review administrator and ask them to allow it.",
           "If the runner is GitHub-hosted (`ubuntu-latest`), its address changes every run.  "
           "Ask for a self-hosted runner inside your network, or GitHub larger runners with a "
           "static IP, and set the `GCR_RUNNER` variable to its label.",
           "Run the workflow again."])

    g.faq("The token was refused",
          "Git Code Review API: HTTP 401: the token was refused.  It may be wrong, expired,\n"
          "revoked, or missing the scope this call needs.",
          "The server did not accept the token.",
          ["On the IDE tokens page, check the token is listed, has not expired, and has "
           "the `reports` scope.",
           "Check the GitHub secret is named exactly `GCR_TOKEN`, in capitals.",
           "If unsure, make a new token and paste it into the secret again.  Copy the whole "
           "value, starting with `gcr_`."])

    g.faq("No token",
          "No token.  Set GCR_TOKEN, GCR_TOKEN_COMMAND or GCR_TOKEN_FILE.",
          "The script could not find a token anywhere.",
          ["In GitHub Actions: check the step has `GCR_TOKEN: ${{ secrets.GCR_TOKEN }}` "
           "under `env:`, and that the secret exists.",
           "Pull requests from forks do not get secrets, by GitHub's design.  The check "
           "cannot run for them.",
           "On your computer: check `.env` has one of the token lines filled in."])

    g.faq("No server address",
          "No server address.  Set GCR_URL, or copy .env.example to .env.",
          "The script does not know where Git Code Review is.",
          "In GitHub, add the `GCR_URL` variable (Step 2).  On your computer, copy "
          "`.env.example` to `.env`.")

    g.faq("GCR_URL must start with https",
          "GCR_URL must start with https://.  A token sent over plain http can be read by\n"
          "anybody on the network.",
          "The address starts with `http://`.  The scripts refuse it so the token is never "
          "sent unencrypted.",
          "Change the address to start with `https://`.")

    g.faq("Other users can read the settings file",
          ".env holds a token but other users can read it.  Run: chmod 600 .env",
          "The file holding your token is readable by other accounts on the computer.",
          "Run the command it shows, `chmod 600 .env`, then try again.")

    g.faq("The token command did not print a token",
          "GCR_TOKEN_COMMAND did not print a token.",
          "The command that decrypts or looks up your token did not work.",
          ["Run `bash bash/gcr-token-store.sh test` to check the encrypted token.",
           "If GPG asks for a passphrase and none appears, run "
           "`export GPG_TTY=$(tty)` first.",
           "If you forgot the passphrase, run `bash bash/gcr-token-store.sh save` again."])

    g.faq("The branch has not been scanned",
          "UNKNOWN: Branch release/2.4 of acme/payments has not been scanned, so there is\n"
          "nothing to check it against.",
          "Git Code Review has never read this branch, so it cannot say whether it is safe.  "
          "The check stops rather than pass something unknown.",
          ["Ask an administrator to add the branch to the repository's scan scope.",
           "Or check the branch the pipeline deploys is the one you expect.  On a pull "
           "request the scripts use the branch being merged into.",
           "Only if your team agrees: add `--allow-unknown` to let it pass."])

    g.faq("No such repository",
          "Git Code Review API: HTTP 404: No such repository.",
          "Either the name is wrong, or your account cannot see that repository.",
          ["Use the full name, `organization/repository`, spelled exactly as in GitHub.",
           "Sign in to Git Code Review as the token's owner and check the repository is on "
           "the Repositories page.  If not, ask an administrator for access."])

    g.faq("No SBOM yet",
          "Git Code Review API: HTTP 404: No SBOM on file for that repository yet.",
          "The repository has not been through a scan that writes SBOMs.",
          "Wait for the next scheduled scan, or ask an administrator to run one.")

    g.faq("There is already an exception",
          "Git Code Review API: HTTP 409: There is already an exception on this one.",
          "Somebody already asked for an exception on this finding, or one was approved.",
          "Look at the finding in Git Code Review.  Nothing more is needed.")

    g.faq("The reason is too short",
          "Git Code Review API: HTTP 400: Say a bit more about why this is acceptable, at\n"
          "least 20 characters.",
          "An exception needs a real reason, so a reviewer can judge it.",
          "Write a sentence explaining why the risk is acceptable, and try again.")

    g.faq("Certificate errors",
          "could not reach https://gcr.example.com/api/v1: [SSL: CERTIFICATE_VERIFY_FAILED]",
          "The server's certificate comes from a company authority your computer does not "
          "know.  The scripts never skip this check.",
          "Ask IT for the company CA file (a `.pem` file), and set "
          "`GCR_CA_BUNDLE=/path/to/company-ca.pem` in `.env` or the workflow's `env:`.")

    g.faq("Too many calls",
          "Git Code Review API: HTTP 429: too many calls.  Wait a minute and try again.",
          "Many pipelines called at once.  The scripts already retry twice.",
          "Run it again in a minute.  If it happens often, run heavy jobs at different times.")

    g.faq("jq or curl is missing",
          "jq is required.",
          "The bash scripts need two small tools.",
          "Ubuntu: `sudo apt install jq curl`.  macOS: `brew install jq`.  Or use the "
          "Python script, which needs nothing extra.")

    g.faq("Why is there no code fix for most code findings?", "",
          "Code advice is shown only when an AI review has read that finding and the code "
          "has not changed since.  A general tip for a rule is not advice about your code.",
          "Ask an administrator to run an AI review on the findings that matter to you.")

    g.faq("I deleted the secret from the code, but it is still listed", "",
          "The secret is still in the git history, where anybody with a copy of the "
          "repository can find it.",
          "Rotate the secret at its provider so the old value stops working.  That is "
          "what makes it safe.  Because the old value is still in the history, the "
          "finding can stay listed.  Tell your administrator it has been rotated, so "
          "they can record that on the finding.")

    g.faq("The plan says \"a range\" under Now", "",
          "The file names a version range, such as `^4.17.0`, rather than one exact version.  "
          "The lock file next to it shows the version actually installed.",
          "Raise the lower end of the range to the Upgrade to version, then rebuild so the "
          "lock file updates.")

    g.faq("Can I put the token in the workflow file to save time?", "",
          "No.  Workflow files are part of the repository, so anybody who can read the "
          "code could read the token, and it stays in the history forever.",
          "Always use the `GCR_TOKEN` repository secret.")

    # 12 ----------------------------------------------------------------------
    g.h1("Getting help")
    g.bullets([
        "The **API reference** tab on the IDE tokens page lists every call, and lets you "
        "try each one with your token.".replace("**", ""),
        "Your Git Code Review administrator can grant access, allow IP addresses, add "
        "branches to scans and run AI reviews.",
        "When you ask for help, include the exact message and the exit code, and never "
        "the token.",
    ])


def main():
    guide = Guide()
    write(guide)
    guide.save(OUT)
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
