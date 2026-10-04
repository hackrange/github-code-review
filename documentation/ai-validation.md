# Validating a finding with AI

A scanner grades a finding from what its engine said and what this installation
knows about the repository.  It cannot read the code the way a reviewer does:
notice that the redirect target came out of the server's own database, or that
the broken half of a package is a WebSocket client nothing constructs.  That is
the question somebody brings to a finding before they fix it or argue an
exception, and Validate with AI asks it of a language model.

## Setting it up

Sign in as an administrator, open the sidebar, expand **Administration** and
choose **AI analysis**, between Notifications and Triage rules.  The address is
`/ai` on your installation.  The section only appears for administrators: a
developer or reader sees neither the menu entry nor the page.

Pick one provider:

| Provider | What it needs |
|---|---|
| Anthropic (Claude) | An API key.  The model defaults to `claude-opus-5-5`, and Effort to `high`. |
| OpenAI | An API key and a model name.  The address can point at anything with the same chat completions API: Azure OpenAI, a gateway, a self hosted server. |
| Custom | An address, and the headers and body the way curl writes them.  The word `SAMPLE` in the body is replaced with the question. |

A custom template looks like this:

```
-H 'Content-Type: application/json'
-H 'x-app-id: your-app-id'
--data-raw '{"model_class":"strong-fast","input_text":"SAMPLE"}'
```

Put the secret in the Secret header fields rather than the template.  The
template is shown back on the page; the secret is stored encrypted and never
is.  If the answer is not at `output_text`, `choices.0.message.content` or one
of the other common places, say where it is in *Where the answer is*.

**List models** asks the saved key what it can use.  **Send a test question**
asks one short question with nothing from any repository in it.  Both use what
is saved, not what is typed, so save first.

Every address has to be https and cannot be a link-local address, because it is
where source code goes.

## Using it

A finding shows **Validate with AI** once a provider is switched on and
complete.  To validate many, tick them on the findings list, or use *Select
all matching these filters*, and press **Validate with AI** in the bar that
appears.  A bulk run works in the background, and the **Learned rules** page
shows how far it has got, how many findings went to the model, how many a
learned rule answered for nothing, and the tokens spent.  Two questions run at
once at most.

The answer is kept on the finding, newest first, with the model, the person who
asked and when.  *What it was given* lists every piece of evidence that went
out.

### When the model reads it lower

A reading lower than the finding's grade lowers it, and the finding says the
grade came from AI validation and what it was before.  It never raises a
grade.  It never lowers a credential, because nothing a model reads in the
code shows a secret is dead, and never a package on the known exploited list.
Those get the answer as advice and keep their grade.  A bulk run does not send
them at all.

A person's own regrade always has the last word.  An AI grade under it is kept,
and stands again if the regrade is cleared.

### What it learns

Every answer also says which other findings deserve the same grade for the
same reason: the same rule in the same files with the same call on the flagged
line, or every advisory on a package only a build tool pulls in.  That is kept
as a **learned rule**, with a synthetic test beside it.  The finding it came
from must match the rule, and anything a model later refused to lower must
not.

A new rule grades the other findings it covers straight away, and from then
on it answers instead of the model: pressing Validate with AI on a finding a
rule covers costs nothing, and so does every later scan.  A bulk run puts
findings about the same thing next to each other, so the first answer usually
settles the rest.  Tick *Ask the model anyway* on a finding to go past the
rule.

A rule applies in the repository it was learned in.  **Apply everywhere** on
the Learned rules page lets it answer in every repository, and is an
administrator's decision.  **Retire** stops a rule and puts back every grade
it gave.  A model asked again that disagrees with a rule retires it on its
own, and keeps the finding it got wrong as a case the rule must not match.
**Run the synthetic tests** checks every live rule and retires any that fail.

### A decision holds until the code changes

A grade decision, a person's regrade or an AI grade, records the code it was
made against: the flagged lines for code and configuration, the version and
advisory for a package.  A later scan of the same code keeps it, so nobody is
asked twice.  When the flagged lines change, the decision is lifted, the
finding goes back to the engine's grade, and its page says who decided what
and that the code it was about has changed.  A credential's regrade is never
lifted this way, because a secret's identity is the secret itself.

## What is sent

Always:

- the finding, the reasons behind its grade, and the line the engine flagged,
  masked the way the scanner stores it (never for a credential);
- what is recorded about the repository: visibility, what it holds, an
  administrator's description;
- up to twelve findings nearby (same file, package or rule) with any exception
  or regrade reason somebody gave;
- this tool's own definition of the rule, when it is one of ours.

When ticked:

- **the code**: the lines around a code or configuration finding, or the places
  a vulnerable package is used, read from the branch at that moment and not
  stored.  Never for a credential, whatever the box says, because the lines
  around a credential contain the credential;
- **the advisory** from osv.dev for a vulnerable package.  Only the public id
  goes to osv.dev.

Never: who can reach the repository, who wrote the commit, or the credential
itself.

Sending code means your source leaves this installation for the provider you
picked.  Check that is somewhere your organization allows it to go before
ticking the box.

## Who can do what

Administrators and developers can validate a finding, one at a time or in
bulk, and see the Learned rules page.  Readers see the answers but have no
button.  Only administrators can change the configuration, apply a rule
everywhere, retire one or run the synthetic tests.  Every validation, bulk run,
save, test and rule decision is in the audit log.
