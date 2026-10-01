# Validating a finding with AI

A scanner grades a finding from what its engine said and what this installation
knows about the repository.  It cannot read the code the way a reviewer does:
notice that the redirect target came out of the server's own database, or that
the broken half of a package is a WebSocket client nothing constructs.  That is
the question somebody brings to a finding before they fix it or argue an
exception, and Validate with AI asks it of a language model.

## Setting it up

AI analysis, in the admin menu.  Pick one provider:

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

A finding shows one button, **Validate with AI**, once a provider is switched
on and complete.  Nothing runs on its own and there is no bulk version: every
question is a person pressing the button, because every question is paid for.
Two run at once at most; a third is told to wait.

The answer is kept on the finding, newest first, with the model, the person who
asked and when.  *What it was given* lists every piece of evidence that went
out.  It is advice.  It changes no grade, state or exception, and a model can be
wrong, or misled by something written in the code it read.

## What is sent

Always:

- the finding, and the reasons behind its grade;
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

Administrators and developers can validate a finding.  Readers see the answers
but have no button.  Only administrators can change the configuration.  Every
validation, save and test is in the audit log.
