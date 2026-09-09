# Trends, and drilling down to a branch

How the numbers have moved, where the work sits, and a document to send
upstairs.  Every filter narrows the same query, and the PDF report is generated
from exactly that scope, so what somebody exports is what they were looking at.

## The three things on the page

**The chart** is one line per severity over the period, stacked.  History from
before daily recording started is worked out from what each finding says about
when it was first seen and when it was resolved, so a chart exists on the first
day rather than ninety days after the product is installed.  Those counts are
exact.  The severity split uses today's grades applied backwards, so the chart
marks where the reconstruction ends rather than drawing one line across two
things that do not mean the same.

**The risk matrix** is impact down the side and likelihood across the top, with
the cell colored by what the pair means.  Those two questions are asked
separately and answered from different evidence, so a critical in a package
nothing imports and a medium somebody proved live land in different cells.

**The grid** is one row per organization, repository or branch depending on how
far down you are, with a column per severity and a total.

## Drilling down

The grid is the same widget at every level, and going down a level narrows the
whole page rather than opening a different one.

```
every repository  ->  one organization  ->  one repository  ->  one branch
```

Each row carries two buttons, on the right.

| Button | What it does |
|---|---|
| Drill down | Stays on this page and narrows it to that row.  Still the question "how much". |
| Findings | Leaves this page and opens the findings themselves.  The question "which ones". |

There is nothing below a branch, so a branch row offers only the findings.  The
row name is a link to the same place the drill down button goes, except at
branch level where it opens the findings.

Every figure in the grid is a link, and the list it opens holds exactly what
the figure counted: every state, every exception, ungrouped.  A drill down that
lands on a different number is worse than no link at all.

## Sorting and paging

Every column heading sorts on that column, and clicking the same heading again
turns it around.  An arrow says which way it is reading.

The default order is worst first by grade rather than by volume, so three
criticals outrank two hundred informational findings.  That is the right answer
to "who is in the most trouble" and the wrong answer to "who has the most
lows", which is what the sorting is for.

Both the sort and the paging run on the server, over every row at that scope.
A browser can only sort the page it was given, which looks identical and
answers a different question.

Twenty five rows to a page, with the count of what is behind it underneath.

Everything is in the address, so a view can be sent to somebody else and it
will be the same view when they open it:

```
/trends?org=example-org&days=90&sort=critical&dir=desc&hpage=2
```

| Parameter | What it does |
|---|---|
| `org`, `repo`, `branch` | How far down the drill down you are |
| `connection` | One account rather than all of them |
| `days` | 7, 30, 90 or 365 |
| `basis` | `actions` counts the work, `advisories` counts the findings |
| `sort` | `name`, `critical`, `high`, `medium`, `low`, `info` or `total` |
| `dir` | `asc` or `desc` |
| `hpage` | Which page of the grid |

## The report

Whatever is on screen writes a PDF through the same permission scoped query, so
it can never hold a repository the reader could not open and can never disagree
with the page it came from.
