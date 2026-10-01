"""Asking a language model one question, whichever one is configured.

Three ways to reach one, picked on the AI page, and only one in use at a time:

  anthropic  Claude, through Anthropic's own SDK.
  openai     OpenAI's chat completions, or anything that speaks the same shape:
             a gateway, a self hosted server, a proxy in front of either.
  custom     Whatever an organization's own inference service wants, described
             the way curl would send it.  An administrator pastes the -H lines
             and the --data-raw body, and the word SAMPLE in the body is where
             the question goes.  This is the shape internal AI gateways tend to
             have, with an application id in one header, a secret in another,
             and a body nobody else uses.

Everything here answers in the same shape, a dict with ok, text and error,
because the one caller should not have to know which of three wire formats it
was talking to.

Nothing here decides what to send.  analysis.py builds the question; this
carries it.
"""

from __future__ import annotations

import json
import logging
import re
import time
from urllib.parse import urlparse

import httpx

log = logging.getLogger("gcr.ai")

PROVIDERS = ("disabled", "anthropic", "openai", "custom")
EFFORTS = ("low", "medium", "high", "xhigh", "max")

ANTHROPIC_DEFAULT_BASE = "https://api.anthropic.com"
ANTHROPIC_DEFAULT_MODEL = "claude-opus-5-5"
OPENAI_DEFAULT_URL = "https://api.openai.com/v1/chat/completions"

# The settings this reads, in the same shape as settings_store.DEFAULTS, which
# takes them from here.  key: (default, is_secret, what it is)
#
# Off until an administrator picks a provider, because turning it on sends what
# a finding is about, and usually the lines of code around it, to a service
# outside this installation.  That is a decision about where an organization's
# source code may go, and a default is not the place to make it.
SETTINGS = {
    "ai.provider":             ("disabled", False,
                                "disabled, anthropic, openai, or custom."),
    "ai.anthropic_base_url":   (ANTHROPIC_DEFAULT_BASE, False,
                                "The Claude API. Change it only for a gateway in front of it."),
    "ai.anthropic_key":        ("", True, "A Claude API key. Stored encrypted."),
    "ai.anthropic_model":      (ANTHROPIC_DEFAULT_MODEL, False, "The Claude model to ask."),
    "ai.anthropic_effort":     ("high", False,
                                "How hard Claude works at it: low, medium, high, xhigh "
                                "or max. Empty sends nothing, for a model that does not "
                                "take the setting."),
    "ai.openai_url":           (OPENAI_DEFAULT_URL, False,
                                "An OpenAI chat completions endpoint, or anything that "
                                "speaks the same shape."),
    "ai.openai_key":           ("", True, "An OpenAI API key. Stored encrypted."),
    "ai.openai_model":         ("", False, "The model to ask."),
    "ai.openai_temperature":   ("", False,
                                "Empty sends none, which is what the reasoning models "
                                "want. 0 to 2 otherwise."),
    "ai.custom_url":           ("", False, "Where the request goes."),
    "ai.custom_template":      ("", False,
                                "Headers and a body, the way curl writes them. The "
                                "word SAMPLE in the body is replaced with the question."),
    "ai.custom_secret_header_name":  ("x-app-secret", False,
                                      "The header the secret below is sent in."),
    "ai.custom_secret_header_value": ("", True,
                                      "The secret header's value. Stored encrypted."),
    "ai.custom_response_path": ("", False,
                                "Where the answer is in the reply, as a dotted path "
                                "such as output_text or choices.0.message.content. "
                                "Empty tries the common shapes."),
    "ai.max_tokens":           (16000, False, "The longest answer to accept."),
    "ai.timeout":              (300, False, "Seconds to wait for an answer."),
    "ai.send_code":            (True, False,
                                "Send the lines around a finding, and the places a "
                                "vulnerable package is used, along with it. Never for "
                                "a credential."),
    "ai.context_lines":        (40, False, "Lines either side of a finding to send."),
    "ai.fetch_advisories":     (True, False,
                                "Read the advisory text from osv.dev for a dependency "
                                "finding. Only the advisory id is sent."),
}

SECRET_KEYS = tuple(key for key, (_d, secret, _w) in SETTINGS.items() if secret)


def read_form(form, text, number, url, checked) -> dict:
    """The AI page's form, checked.  -> {key: value} for every non secret

    The web layer hands over its own checkers, so a bad value fails the same
    way it does on every other page, and this module stays free of anything
    that knows about requests.  Secrets are not in the answer: a secret left
    empty keeps the stored one, which is the caller's to decide.  Raises
    ValueError with a sentence for anything that is wrong here rather than in
    the checkers.
    """
    provider = str(form.get("ai.provider", "disabled")).strip().lower()
    if provider not in PROVIDERS:
        raise ValueError("Pick a provider.")
    effort = str(form.get("ai.anthropic_effort", "")).strip().lower()
    if effort and effort not in EFFORTS:
        raise ValueError("Effort is low, medium, high, xhigh or max.")
    temperature = str(form.get("ai.openai_temperature", "")).strip()
    if temperature:
        try:
            if not 0 <= float(temperature) <= 2:
                raise ValueError
        except ValueError:
            raise ValueError("Temperature is a number from 0 to 2, or empty.")

    template = str(form.get("ai.custom_template", ""))
    if len(template) > 20_000:
        raise ValueError("The template is too long.")
    header_name = text(form.get("ai.custom_secret_header_name"),
                       "Secret header name", 100)
    if header_name and not re.fullmatch(r"[A-Za-z0-9!#$%&'*+.^_`|~-]+", header_name):
        raise ValueError("A header name is letters, digits and dashes.")
    response_path = text(form.get("ai.custom_response_path"), "Answer path", 200)
    if response_path and not re.fullmatch(r"[A-Za-z0-9_.-]+", response_path):
        raise ValueError("The answer path is field names and numbers separated by dots.")

    # Every one of these is an address this server will send source code to,
    # which is exactly what the url checker is for.
    return {
        "ai.provider": provider,
        "ai.anthropic_base_url": (url(form.get("ai.anthropic_base_url"), "Claude API address")
                                  or ANTHROPIC_DEFAULT_BASE).rstrip("/"),
        "ai.anthropic_model": text(form.get("ai.anthropic_model"), "Claude model", 120)
                              or ANTHROPIC_DEFAULT_MODEL,
        "ai.anthropic_effort": effort,
        "ai.openai_url": url(form.get("ai.openai_url"), "OpenAI address")
                         or OPENAI_DEFAULT_URL,
        "ai.openai_model": text(form.get("ai.openai_model"), "OpenAI model", 120),
        "ai.openai_temperature": temperature,
        "ai.custom_url": url(form.get("ai.custom_url"), "Custom address"),
        "ai.custom_template": template.replace("\r\n", "\n").strip(),
        "ai.custom_secret_header_name": header_name,
        "ai.custom_response_path": response_path,
        "ai.max_tokens": number(form.get("ai.max_tokens") or 16000,
                                "Answer length", 1000, 128000),
        "ai.timeout": number(form.get("ai.timeout") or 300, "Time limit", 30, 1800),
        "ai.context_lines": number(form.get("ai.context_lines") or 40,
                                   "Lines of context", 5, 200),
        "ai.send_code": checked("ai.send_code"),
        "ai.fetch_advisories": checked("ai.fetch_advisories"),
    }

# The models that take the server side fallback.  On these a request the
# model's safety classifiers decline is run again on another model, inside the
# same call, rather than coming back empty.  Security analysis of exploitable
# code is exactly what those classifiers look at hardest, so without this a
# perfectly ordinary question about an open redirect can come back as a
# refusal.  Sent only to Anthropic's own API: a gateway in front of it may not
# pass the parameter through.
_FALLBACK_MODELS = {"claude-fable-5-1", "claude-opus-5-5", "claude-opus-5",
                    "claude-sonnet-5-5"}
_FALLBACK_BETA = "server-side-fallback-2026-07-01"

# The example shown in an empty template box.  Only headers and a body: the
# address comes from its own field.
CUSTOM_EXAMPLE = """\
-H 'Content-Type: application/json'
-H 'x-app-id: your-app-id'
-H 'x-user-name: firstname.lastname@example.com'
--data-raw '{"model_class":"strong-fast","input_text":"SAMPLE"}'"""

_HEADER = re.compile(r"""(?:-H|--header)\s+'([^'\r\n]+)'|(?:-H|--header)\s+"([^"\r\n]+)\"""")
# The body is one single quoted argument, wherever it sits among the headers.
# Inside it, curl's way of writing a literal quote is '\'' and that is
# understood; anything else ends the argument.
_BODY = re.compile(r"""(?:--data-raw|--data-binary|--data|-d)\s+'((?:[^']|'\\'')*)'""")


def config(session) -> dict:
    """Every ai.* setting, secrets decrypted.  For this module only."""
    from app.core import settings_store as store

    return {key: store.get(session, key) for key in store.DEFAULTS
            if key.startswith("ai.")}


def enabled(cfg: dict) -> bool:
    return (cfg.get("ai.provider") or "disabled") in PROVIDERS[1:]


def missing(cfg: dict) -> str:
    """What is still needed before a question can go.  Empty when nothing is."""
    provider = cfg.get("ai.provider") or "disabled"
    if provider == "anthropic":
        if not cfg.get("ai.anthropic_key"):
            return "Paste a Claude API key on the AI page."
        if not cfg.get("ai.anthropic_model"):
            return "Name the Claude model to ask on the AI page."
    elif provider == "openai":
        if not cfg.get("ai.openai_key"):
            return "Paste an OpenAI API key on the AI page."
        if not cfg.get("ai.openai_model"):
            return "Name the model to ask on the AI page."
        if not cfg.get("ai.openai_url"):
            return "Give the chat completions address on the AI page."
    elif provider == "custom":
        if not cfg.get("ai.custom_url"):
            return "Give the address requests go to on the AI page."
        if not _BODY.search(cfg.get("ai.custom_template") or ""):
            return ("The template on the AI page has no --data-raw '...' body "
                    "for the question to go into.")
        if "SAMPLE" not in (cfg.get("ai.custom_template") or ""):
            return ("The template's body has no SAMPLE in it, so there is "
                    "nowhere for the question to go.")
    else:
        return "AI analysis is switched off on the AI page."
    return ""


def describe_model(cfg: dict) -> str:
    """The model a question would go to, for a page to say before it goes."""
    provider = cfg.get("ai.provider") or "disabled"
    if provider == "anthropic":
        return cfg.get("ai.anthropic_model") or ""
    if provider == "openai":
        return cfg.get("ai.openai_model") or ""
    if provider == "custom":
        host = urlparse(cfg.get("ai.custom_url") or "").hostname or ""
        return f"the service at {host}" if host else "the custom service"
    return ""


def complete(cfg: dict, system: str, prompt: str, *, max_tokens: int = None,
             timeout: float = None) -> dict:
    """Ask once.  -> {ok, text, error, provider, model, input_tokens,
    output_tokens, duration_ms}

    Never raises for anything the far end does.  A refused key, a timeout or a
    reply in the wrong shape all come back as ok False with a sentence, because
    the caller is a page and a stack trace is not something to show on one.
    """
    provider = cfg.get("ai.provider") or "disabled"
    out = {"ok": False, "text": "", "error": "", "provider": provider,
           "model": "", "input_tokens": 0, "output_tokens": 0,
           "duration_ms": 0}

    problem = missing(cfg)
    if problem:
        out["error"] = problem
        return out

    max_tokens = int(max_tokens or cfg.get("ai.max_tokens") or 16000)
    timeout = float(timeout or cfg.get("ai.timeout") or 300)
    started = time.monotonic()
    try:
        if provider == "anthropic":
            out.update(_anthropic(cfg, system, prompt, max_tokens, timeout))
        elif provider == "openai":
            out.update(_openai(cfg, system, prompt, max_tokens, timeout))
        else:
            out.update(_custom(cfg, system, prompt, timeout))
    except Exception as exc:  # pragma: no cover - the last line of defence
        log.exception("AI request to %s failed", provider)
        out["ok"] = False
        out["error"] = f"The request failed: {type(exc).__name__}."
    out["duration_ms"] = int((time.monotonic() - started) * 1000)
    if out["ok"] and not (out.get("text") or "").strip():
        out["ok"] = False
        out["error"] = "The model answered with nothing."
    return out


def test(cfg: dict) -> dict:
    """One tiny question, to prove the wiring before a real one costs money."""
    return complete(cfg, "Answer in as few words as possible.",
                    'Reply with exactly the words "Connection works" and '
                    "nothing else.", max_tokens=2000, timeout=60)


# ---------------------------------------------------------------- anthropic

def _anthropic_client(cfg: dict, timeout: float):
    import anthropic

    base = (cfg.get("ai.anthropic_base_url") or ANTHROPIC_DEFAULT_BASE).rstrip("/")
    return anthropic.Anthropic(api_key=cfg.get("ai.anthropic_key"),
                               base_url=base, timeout=timeout, max_retries=2)


def _is_anthropic_itself(cfg: dict) -> bool:
    base = (cfg.get("ai.anthropic_base_url") or ANTHROPIC_DEFAULT_BASE).rstrip("/")
    return base == ANTHROPIC_DEFAULT_BASE


def _anthropic(cfg: dict, system: str, prompt: str, max_tokens: int,
               timeout: float) -> dict:
    import anthropic

    model = cfg.get("ai.anthropic_model") or "claude-opus-5-5"
    effort = (cfg.get("ai.anthropic_effort") or "").strip().lower()

    params = {
        "model": model,
        "max_tokens": max_tokens,
        "system": system,
        "messages": [{"role": "user", "content": prompt}],
    }
    # Thinking is left to the model's own default, which on the current models
    # is adaptive: it thinks as hard as the question needs.  Effort is the
    # dial, and it is sent explicitly because the defaults differ by model.
    if effort in EFFORTS:
        params["output_config"] = {"effort": effort}
    if model in _FALLBACK_MODELS and _is_anthropic_itself(cfg):
        params["betas"] = [_FALLBACK_BETA]
        params["fallbacks"] = "default"

    client = _anthropic_client(cfg, timeout)
    try:
        response = client.beta.messages.create(**params)
    except anthropic.AuthenticationError:
        return {"ok": False, "error": "Anthropic refused the API key."}
    except anthropic.PermissionDeniedError:
        return {"ok": False,
                "error": "The API key is not allowed to use that model."}
    except anthropic.NotFoundError:
        return {"ok": False,
                "error": f"Anthropic does not know a model called {model}."}
    except anthropic.RateLimitError:
        return {"ok": False,
                "error": "Anthropic is rate limiting this key. Try again in a minute."}
    except anthropic.BadRequestError as exc:
        return {"ok": False, "error": "Anthropic turned the request down: "
                                      + _short(getattr(exc, "message", "") or str(exc))}
    except anthropic.APIStatusError as exc:
        return {"ok": False,
                "error": f"Anthropic answered {exc.status_code}. Try again later."}
    except anthropic.APITimeoutError:
        return {"ok": False, "error": "Anthropic took too long to answer."}
    except anthropic.APIConnectionError:
        return {"ok": False, "error": "Could not reach Anthropic from here."}

    usage = getattr(response, "usage", None)
    out = {"model": getattr(response, "model", "") or model,
           "input_tokens": int(getattr(usage, "input_tokens", 0) or 0),
           "output_tokens": int(getattr(usage, "output_tokens", 0) or 0)}

    # Checked before the content, because a declined request carries none.
    if response.stop_reason == "refusal":
        details = getattr(response, "stop_details", None)
        category = getattr(details, "category", None) if details else None
        out.update(ok=False, error="The model declined to answer"
                   + (f" ({category})." if category else "."))
        return out

    text = "".join(block.text for block in response.content
                   if getattr(block, "type", "") == "text")
    if response.stop_reason == "max_tokens":
        text += ("\n\n[Cut off at the answer length limit. Raise it on the "
                 "AI page for a complete answer.]")
    out.update(ok=True, text=text.strip())
    return out


# ------------------------------------------------------------------- openai

def _openai(cfg: dict, system: str, prompt: str, max_tokens: int,
            timeout: float) -> dict:
    url = cfg.get("ai.openai_url")
    model = cfg.get("ai.openai_model")
    payload = {
        "model": model,
        "messages": [{"role": "system", "content": system},
                     {"role": "user", "content": prompt}],
    }
    # OpenAI's own API wants the newer name and its reasoning models refuse
    # the old one.  Everything else that copies the shape still mostly reads
    # the old one, so it is chosen by who is on the other end.
    if (urlparse(url).hostname or "").endswith("openai.com"):
        payload["max_completion_tokens"] = max_tokens
    else:
        payload["max_tokens"] = max_tokens
    temperature = str(cfg.get("ai.openai_temperature") or "").strip()
    if temperature:
        try:
            payload["temperature"] = max(0.0, min(2.0, float(temperature)))
        except ValueError:
            pass

    headers = {"Authorization": "Bearer " + cfg.get("ai.openai_key"),
               "Content-Type": "application/json",
               "Accept": "application/json"}
    reply = _post(url, headers, json.dumps(payload), timeout, "OpenAI")
    if not reply["ok"]:
        return reply
    data = reply["data"]
    choice = ((data.get("choices") or [{}])[0]) if isinstance(data, dict) else {}
    text = ((choice.get("message") or {}).get("content")) or ""
    if choice.get("finish_reason") == "length":
        text += ("\n\n[Cut off at the answer length limit. Raise it on the "
                 "AI page for a complete answer.]")
    usage = data.get("usage") or {}
    return {"ok": True, "text": str(text).strip(),
            "model": data.get("model") or model,
            "input_tokens": int(usage.get("prompt_tokens") or 0),
            "output_tokens": int(usage.get("completion_tokens") or 0)}


# ------------------------------------------------------------------- custom

def parse_template(template: str) -> tuple:
    """-> (headers as a list of (name, value), body template or "")."""
    headers = []
    for single, double in _HEADER.findall(template or ""):
        line = single or double
        name, sep, value = line.partition(":")
        if not sep or not name.strip():
            continue
        headers.append((name.strip(), value.strip()))
    match = _BODY.search(template or "")
    body = match.group(1).replace("'\\''", "'") if match else ""
    return headers, body


def _custom_headers(cfg: dict) -> dict:
    """The template's headers with the stored secret spliced in.

    The secret lives in its own encrypted setting rather than in the template,
    so the template can be shown on the page, copied and sent to somebody
    without it.  A header of the same name in the template is replaced, so a
    placeholder left there does not go out beside the real one.
    """
    headers, _body = parse_template(cfg.get("ai.custom_template") or "")
    name = (cfg.get("ai.custom_secret_header_name") or "").strip()
    value = cfg.get("ai.custom_secret_header_value") or ""
    if name and value:
        headers = [(k, v) for k, v in headers if k.lower() != name.lower()]
        headers.append((name, value))
    out = {}
    for key, val in headers:
        out[key] = val
    if not any(k.lower() == "content-type" for k in out):
        out["Content-Type"] = "application/json"
    return out


def _custom(cfg: dict, system: str, prompt: str, timeout: float) -> dict:
    _headers, body_template = parse_template(cfg.get("ai.custom_template") or "")
    # One string, because a body with one slot has room for one.  The system
    # half is marked so a service that does have a notion of one is not left
    # guessing which part is the instructions.
    flat = f"[System]\n{system}\n\n{prompt}"
    escaped = json.dumps(flat, ensure_ascii=False)[1:-1]
    body = body_template.replace("SAMPLE", escaped)

    reply = _post(cfg.get("ai.custom_url"), _custom_headers(cfg), body, timeout,
                  "The custom service")
    if not reply["ok"]:
        return reply
    data = reply["data"]
    text = _pluck(data, cfg.get("ai.custom_response_path") or "")
    if text is None:
        return {"ok": False,
                "error": "The custom service answered, but not where the answer "
                         "was expected. Set where the answer is on the AI page."}
    usage = data.get("usage") if isinstance(data, dict) else None
    usage = usage if isinstance(usage, dict) else {}
    return {"ok": True, "text": str(text).strip(),
            "model": str((data.get("model") if isinstance(data, dict) else "")
                         or describe_model(cfg)),
            "input_tokens": int(usage.get("input_tokens")
                                or usage.get("prompt_tokens") or 0),
            "output_tokens": int(usage.get("output_tokens")
                                 or usage.get("completion_tokens") or 0)}


def _pluck(data, path: str):
    """The answer out of a reply.  -> str, or None when it is not there.

    A path someone set wins.  Without one, the shapes in common use are tried
    in turn: a top level output_text, an OpenAI style choices list, an
    Anthropic style content list, and a handful of single field answers.
    """
    def walk(node, steps):
        for step in steps:
            if isinstance(node, list):
                if not step.isdigit() or int(step) >= len(node):
                    return None
                node = node[int(step)]
            elif isinstance(node, dict):
                if step not in node:
                    return None
                node = node[step]
            else:
                return None
        return node

    if path.strip():
        found = walk(data, [s for s in path.strip().split(".") if s])
        return found if isinstance(found, str) else None

    for candidate in ("output_text", "choices.0.message.content",
                      "content.0.text", "output", "response", "answer",
                      "text", "result"):
        found = walk(data, candidate.split("."))
        if isinstance(found, str) and found.strip():
            return found
    return None


# ------------------------------------------------------------------- shared

def _post(url: str, headers: dict, body: str, timeout: float, who: str) -> dict:
    """POST and read JSON back.  -> {ok, data} or {ok False, error}."""
    try:
        with httpx.Client(timeout=httpx.Timeout(timeout, connect=10.0),
                          follow_redirects=False) as client:
            response = client.post(url, headers=headers,
                                   content=body.encode("utf-8"))
    except httpx.TimeoutException:
        return {"ok": False, "error": f"{who} took too long to answer."}
    except httpx.HTTPError as exc:
        # "the custom service" mid sentence, "OpenAI" either way.
        named = "t" + who[1:] if who.startswith("The ") else who
        return {"ok": False,
                "error": f"Could not reach {named}: {type(exc).__name__}."}
    except ValueError as exc:
        # httpx refuses a header with a newline in it, among other things.
        return {"ok": False, "error": f"The request could not be built: {_short(str(exc))}"}

    if response.status_code != 200:
        detail = ""
        try:
            parsed = response.json()
            if isinstance(parsed, dict):
                err = parsed.get("error")
                detail = (err.get("message") if isinstance(err, dict) else err) \
                    or parsed.get("detail") or parsed.get("message") or ""
        except ValueError:
            detail = response.text
        message = f"{who} answered {response.status_code}"
        if detail:
            message += ": " + _short(str(detail))
        return {"ok": False, "error": message}

    try:
        return {"ok": True, "data": response.json()}
    except ValueError:
        return {"ok": False, "error": f"{who} answered, but not with JSON."}


def _short(text: str, limit: int = 300) -> str:
    text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", text or "")).strip()
    return text if len(text) <= limit else text[:limit] + "..."


def list_models(cfg: dict, provider: str) -> dict:
    """The models a provider offers this key.  -> {ok, models, error}

    Asked of whichever provider the page is showing, from the saved key, so
    the list follows the panel somebody is editing.  The custom service has no
    agreed way to ask, so it does not.
    """
    if provider == "anthropic":
        if not cfg.get("ai.anthropic_key"):
            return {"ok": False, "models": [],
                    "error": "Save a Claude API key first."}
        import anthropic
        try:
            client = _anthropic_client(cfg, 20)
            models = [{"id": m.id, "name": getattr(m, "display_name", "") or m.id}
                      for m in client.models.list(limit=100)]
        except anthropic.AuthenticationError:
            return {"ok": False, "models": [], "error": "Anthropic refused the API key."}
        except anthropic.APIError as exc:
            return {"ok": False, "models": [],
                    "error": "Could not list models: " + _short(str(exc), 200)}
        return {"ok": bool(models), "models": models,
                "error": "" if models else "Anthropic listed no models."}

    if provider == "openai":
        url, key = cfg.get("ai.openai_url") or "", cfg.get("ai.openai_key") or ""
        if not (url and key):
            return {"ok": False, "models": [],
                    "error": "Save the address and an API key first."}
        models_url = re.sub(r"/chat/completions/?$", "/models", url)
        if models_url == url:
            models_url = url.rstrip("/") + "/models"
        try:
            with httpx.Client(timeout=20, follow_redirects=False) as client:
                response = client.get(models_url, headers={
                    "Authorization": "Bearer " + key, "Accept": "application/json"})
        except httpx.HTTPError as exc:
            return {"ok": False, "models": [],
                    "error": f"Could not reach it: {type(exc).__name__}."}
        if response.status_code != 200:
            return {"ok": False, "models": [],
                    "error": f"Listing models answered {response.status_code}."}
        try:
            data = response.json()
        except ValueError:
            return {"ok": False, "models": [], "error": "The list was not JSON."}
        rows = data.get("data", []) if isinstance(data, dict) else data
        models, seen = [], set()
        for row in rows or []:
            ident = row.get("id") if isinstance(row, dict) else row
            if isinstance(ident, str) and ident and ident not in seen:
                seen.add(ident)
                models.append({"id": ident, "name": ident})
        models.sort(key=lambda m: m["id"].lower())
        return {"ok": bool(models), "models": models,
                "error": "" if models else "It listed no models."}

    return {"ok": False, "models": [],
            "error": "There is no standard way to ask a custom service for its models."}
