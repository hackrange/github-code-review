"""The scanner's built in configuration.

The scanner is a bash program and it wants a JSON file.  That file used to sit
in the source tree, which meant the names of whatever somebody scanned got
committed along with it.  The shape of the file lives here now, in code, and
the parts that differ from one install to the next come out of the database
when a scan starts.

Nothing here is site specific.  These are detection rules, placeholder
patterns and sensible limits, and they are the same for everybody.
"""

from __future__ import annotations

import copy

TEMPLATE = {
        "github": {
            "api_url": "https://api.github.com",
            "web_url": "https://github.com",
            "graphql_url": "https://api.github.com/graphql",
            "auth": {
                "method": "app",
                "pat": {
                    "token_env": "GITHUB_TOKEN",
                    "token_file": ""
                },
                "app": {
                    "app_id": "${GHSCAN_APP_ID}",
                    "installation_id": "${GHSCAN_INSTALLATION_ID}",
                    "private_key_path": "/etc/ghscan/ghscan-app.private-key.pem"
                }
            },
            "scope": {
                "orgs": [],
                "auto_discover_orgs": True,
                "include_collaborator_repos": True,
                "affiliation": "owner,collaborator,organization_member",
                "users": [],
                "include_repos": [],
                "exclude_repos": [],
                "exclude_repo_regex": "",
                "include_archived": False,
                "include_forks": False,
                "include_templates": True,
                "visibility": "all",
                "max_repos": 0
            },
            "branches": {
                "mode": "all",
                "include": [],
                "exclude": [
                    "dependabot/*",
                    "renovate/*",
                    "gh-readonly-queue/*"
                ],
                "max_per_repo": 0,
                "stale_days": 0,
                "scan_full_history": True
            }
        },
        "clone": {
            "workdir": "/var/tmp/ghscan-work",
            "keep_clones": False,
            "depth": 0,
            "max_repo_size_mb": 4096
        },
        "scan": {
            "secrets": {
                "enabled": True,
                "engines": [
                    "gitleaks",
                    "trufflehog",
                    "github_secret_scanning",
                    "detect_secrets"
                ],
                "resolve_commit_authors": True,
                "trufflehog": {
                    "verify": True,
                    "results": "verified,unverified,unknown",
                    "concurrency": 8,
                    "include_detectors": [],
                    "exclude_detectors": []
                },
                "gitleaks": {
                    "config_path": "gitleaks-extra.toml",
                    "redact_in_engine": False,
                    "max_target_megabytes": 0
                },
                "severity": {
                    "credential": "critical",
                    "test_fixture": "high",
                    "verified_bonus": True
                },
                "triage": {
                    "min_entropy": 3.0,
                    "min_length": 12,
                    "drop_unverified_below_entropy": True,
                    "placeholder_patterns": [
                        "(?i)^(x{4,}|y{4,}|z{4,}|a{4,}|0{4,}|1{4,}|\\*{3,}|\\.{3,})$",
                        "(?i)(?<![A-Za-z0-9])(example|placeholder|redacted|dummy|sample|changeme|change[-_]?me|replace[-_]?me|yourkey|your[-_]?(api|secret|token|key|password))(?![A-Za-z0-9])",
                        "(?i)(insert|enter|add)[-_ ]?(your|the)?[-_ ]?(key|token|secret|password)",
                        "(?i)^(test|testing|foo|bar|baz|qux|abc123|password|passwd|secret|token|admin|root|hunter2|123456|letmein)$",
                        # The lookarounds are not decoration.  These words are
                        # short, and base64 is random, so "fake", "mock" and
                        # "stub" turn up inside perfectly real keys by chance
                        # about four times in a thousand.  Without a boundary
                        # this filtered a genuine 2048 bit RSA key roughly one
                        # scan in two hundred, and a dropped private key is the
                        # worst thing this tool can do quietly.  Requiring the
                        # word to stand on its own keeps "fake_key" and
                        # "mock-token" caught and leaves "MIIfakeEog" alone.
                        "(?i)(?<![A-Za-z0-9])(not[-_]?a[-_]?real|fake|mock|stub|lorem|ipsum|deadbeef|cafebabe)(?![A-Za-z0-9])",
                        "(?i)^(<|\\{\\{|\\$\\{|%|\\[)",
                        "(?i)(AKIAIOSFODNN7EXAMPLE|wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY)",
                        "(?i)\\b(place|put|insert|enter|fill|paste|type|replace|specify|provide|supply|set)\\b[^\\n]{0,40}\\b(here|below|later|value|this|yours)\\b",
                        "(?i)([-_ ]here|[-_ ]below|[-_ ]later)$",
                        # A label is not a password.  This rule fires on
                        # 'profile.new_password' => 'Cambiar contrasena'
                        # because the key says password and the value is
                        # quoted, and a translation file is nothing but
                        # that shape.  On one repository it produced
                        # eighteen criticals and not one credential.
                        #
                        # What separates them is that a label is language:
                        # letters, spaces and light punctuation, and no
                        # digits.  A real password nearly always carries a
                        # digit or a symbol, and a token never has a space
                        # in it.
                        #
                        # The trade is worth stating rather than hiding.  A
                        # passphrase of plain words with no digits, the
                        # "correct horse battery staple" shape, reads as a
                        # label to this and is set aside.  It lands in
                        # placeholders_filtered with the rule that dropped
                        # it, like everything else here, so it can be found
                        # and argued with rather than silently lost.
                        # The backslash is in there for an escaped quote.  Two
                        # of these survived the first pass on a real repository
                        # because French and Italian write l\'enregistrement,
                        # and a class with no backslash in it cannot match the
                        # whole string.
                        "^\\p{L}[\\p{L}\\p{M}\\s.,:;/&()'!?\\\\-]*\\s[\\p{L}\\p{M}\\s.,:;/&()'!?\\\\-]*$",
                        "(?i)\\bgoes[-_ ]here\\b",
                        # A value that trails off was shortened by whoever
                        # wrote the page it is on.  Nothing that still works
                        # ends in an ellipsis, and a truncated token in an
                        # OpenAPI file or a README is the commonest way a
                        # documented example gets reported as a live one.
                        "\\.{3,}$|\\x{2026}$",
                        "^[A-Za-z][A-Za-z ]{6,}$",
                        "^[A-Z][A-Z_]{7,}$",
                        "(?i)^(my|your|our|the)[-_ ]",
                        "(?i)^(todo|tbd|fixme|none|null|nil|undefined|unset|n/a|na)\\b"
                    ],
                    "placeholder_paths": [
                        "(?i)(^|/)(test|tests|spec|specs|__tests__|fixtures?|testdata|examples?|samples?|demo|docs?|mock(s|data)?)(/|$)",
                        "(?i)\\.(md|mdx|rst|txt|adoc|po|pot|snap|golden)$",
                        "(?i)(^|/)(vendor|node_modules|third_party|\\.venv|site-packages|bower_components)(/|$)",
                        "(?i)\\.(lock|sum)$|(^|/)(package-lock\\.json|yarn\\.lock|pnpm-lock\\.yaml|Gemfile\\.lock|poetry\\.lock|Cargo\\.lock|go\\.sum)$",
                        "(?i)(^|/)(CHANGELOG|LICENSE|NOTICE|COPYING)",
                        # Where an application keeps the words it shows people.
                        # Nothing in here is a credential, it is all labels.
                        "(?i)(^|/)(i18n|l10n|lang|langs|locale|locales|translations?|messages)(/|$)",
                        # A theme somebody bought, and the assets a build made.
                        # code_triage.py has known about these on the code side
                        # since it was written; the secrets side did not, and a
                        # demo key in a template kit came out as a critical.
                        "(?i)(^|/)app/template/",
                        "(?i)[.-](min|bundle|pack)\\.(js|css)$"
                    ],
                    "path_rule_downgrades_only": True,
                    "allowlist_file": "allowlist.json"
                }
            },
            # The files that decide where the application runs.  trivy reads
            # Terraform, CloudFormation, Kubernetes, Helm, Ansible and
            # Dockerfiles off the same checkout the SBOM pass already makes.
            "iac": {
                "enabled": True,
                # trivy fetches its policy bundle on first use.  Turn this on
                # for a builder with no route out.
                "offline": False,
                "skip_dirs": [],
                "timeout_sec": 600
            },
            # The build pipeline.  A workflow an outsider can trigger takes the
            # whole organization rather than one service, and nothing else here
            # opens .github/workflows.
            "workflows": {
                "enabled": True,
                # regular keeps the false positives down.  pedantic and auditor
                # trade that for reach.
                "persona": "regular",
                # Some audits ask GitHub about an action.  Turning this off
                # hands this tool's token to another binary, so it is a choice.
                "offline": True,
                "timeout_sec": 300
            },
            "code_analysis": {
                "enabled": True,
                # Judge each finding in its context before anybody reads it.
                "triage": True,
                # gosec, bandit and njsscan beside semgrep, on the languages
                # that are actually in the tree.  gosec adds depth semgrep
                # does not have; the other two corroborate and are not sold
                # as more than that.
                "second_engine": True,
                "muted_rules": [],
                "rulesets": [
                    "p/default",
                    "p/owasp-top-ten",
                    "p/secrets",
                    "p/javascript",
                    "p/typescript",
                    "p/nodejs",
                    "p/react",
                    "p/python",
                    "p/django",
                    "p/flask",
                    "p/java",
                    "p/kotlin",
                    "p/php",
                    "p/golang",
                    "p/ruby",
                    "p/csharp",
                    "p/xss",
                    "p/sql-injection",
                    "p/command-injection",
                    "p/jwt",
                    "p/insecure-transport"
                ],
                "jobs": 2,
                "timeout_sec": 900
            },
            "sbom": {
                "enabled": True,
                # A library somebody copied into the tree has no manifest
                # entry, so nothing asks an advisory database about it and the
                # report comes back clean.  On by default: a missing finding
                # looks exactly like a repository with nothing wrong.
                "vendored": True,
                "formats": [
                    "cyclonedx-json",
                    "spdx-json"
                ],
                "write_per_repo_files": True,
                "write_combined_files": True,
                "sources": [
                    "syft",
                    "github_dependency_graph"
                ],
                "enrich": [
                    "all"
                ],
                "include_file_components": False,
                "scan_branches": "default",
                "catalogers": "+javascript-package-cataloger,+python-package-cataloger,+java-pom-cataloger",
                "license_policy": {
                    "enabled": True,
                    "denied": [
                        "AGPL-3.0-only",
                        "AGPL-3.0-or-later",
                        "SSPL-1.0",
                        "BUSL-1.1",
                        "Commons-Clause"
                    ],
                    "flagged": [
                        "GPL-2.0-only",
                        "GPL-3.0-only",
                        "GPL-3.0-or-later",
                        "LGPL-3.0-only",
                        "CDDL-1.0",
                        "EPL-2.0",
                        "MPL-2.0"
                    ],
                    "allow_unknown": True
                }
            },
            "access": {
                "enabled": True,
                "sources": [
                    "collaborators",
                    "teams",
                    "branches",
                    "invitations",
                    "deploy_keys",
                    "org_members",
                    "outside_collaborators"
                ],
                "branch_protection_detail": False,
                "include_bots": True,
                "collect_2fa_status": True,
                "flag": {
                    "outside_collaborator_admin": True,
                    "write_deploy_keys": True,
                    "stale_invitations_days": 30,
                    "admin_repo_count_threshold": 25
                }
            },
            "pull_history": {
                "enabled": True,
                "state": "all",
                "since_days": 365,
                "max_per_repo": 2000,
                "include_clone_traffic": True
            },
            # Dynamic testing.  Only the free half of it exists so far.
            "dast": {
                # Ask, of every repository, whether a dynamic pass could run
                # against it at all.  This reads the compose file and the
                # Dockerfile and nothing else: no build, no container, no
                # request.  On by default because it costs a file read, and
                # because the answer is the only way to know what fraction of
                # an estate a dynamic pass could ever cover before anybody
                # spends a week building one.
                #
                # The test is deliberately narrow.  A service has to build from
                # the repository being scanned and something has to publish a
                # port.  A compose file that pulls a published image by tag
                # does not qualify: standing that up would test a release
                # somebody built at some point rather than the commit in hand,
                # and reporting evidence about a different version of the code
                # is the same mistake as closing a finding nobody probed.
                "qualify": True,
                # Building and running the application, sending probes at it,
                # and recording what came back.  Not implemented.  The key is
                # here so that turning it on is a decision somebody makes
                # rather than something that arrives switched on with a
                # release, and it does nothing today.
                "enabled": False
            },
            "images": {
                # Read the base image each Dockerfile names.  Nothing is built
                # and nothing is pushed; the image is pulled from its registry
                # and read.  Off by default because it is the one stage that
                # downloads something big.
                "enabled": False,
                "timeout_sec": 600,
            },
            "vulnerabilities": {
                # Whether the application can actually reach each vulnerable
                # package.  Adds a verdict, never removes a finding.
                "reachability": True,
                # Typosquats, install hooks and dependencies that do not come
                # from a registry.  None of these has a CVE, which is the
                # point of looking for them.
                "malicious": True,
                "enabled": True,
                "sources": [
                    "grype",
                    "osv",
                    "github_dependabot",
                    "github_code_scanning"
                ],
                "min_severity": "all",
                "fail_on_severity": "",
                "ignore_states": [
                    "fixed",
                    "dismissed",
                    "auto_dismissed"
                ],
                "grype": {
                    "only_fixed": False,
                    "db_auto_update": True
                },
                "osv": {
                    # Whether osv-scanner may work out the dependency tree
                    # itself when a manifest has no lock file beside it.
                    #
                    # Off, because what it does in that case is take the lower
                    # bound of every constraint it cannot pin.  A dependency
                    # declared >=0.0.9 is reported as 0.0.9, the oldest version
                    # that satisfies it and so the one carrying the most
                    # advisories, which is neither what would be installed nor
                    # what is on any machine.  Python packaging is mostly >=,
                    # so left on it grades every transitive dependency in every
                    # repository at its floor and presents the result as fact.
                    #
                    # Direct pins and lock files are unaffected either way:
                    # those are read rather than resolved.  Turning this on
                    # buys transitive coverage at the price of inventing the
                    # versions it reports, which is not a trade this makes by
                    # default.
                    "resolve_transitive": False
                }
            },
            "threat_intel": {
                "enabled": True,
                "kev_url": "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv",
                "epss_url": "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
                "epss_min_score": 0.01,
                "max_age_hours": 24
            },
            # Whether the order of a scan changes between runs.
            #
            # Every list here is sorted, which is right for reading and wrong
            # for scanning.  A run cut short by its time limit, its API budget
            # or a failure part way stops wherever it had got to, so a stable
            # order means the tail of the alphabet is never reached and the
            # same repositories are missed every night.  Not scanned reads
            # exactly like nothing found.
            #
            # max_repos makes that worse rather than better: capped at fifty, a
            # sorted list scans the same fifty forever.  Shuffled, the cap is a
            # sample that moves and a month of runs covers the estate.
            #
            # Off gives a stable order, which is easier to follow when
            # comparing two runs by eye.  The order actually used is logged
            # either way, so a run stays reproducible.
            "randomize_order": True,
            "parallel_repos": 4,
            "timeout_per_repo_sec": 3600,
            "exclusions": {
                "enabled": True,
                "file": "exclusions.csv"
            }
        },
        "redaction": {
            "enabled": True,
            "prefix_chars": 4,
            "suffix_chars": 3,
            "max_mask_chars": 12,
            "include_fingerprint": True,
            "include_line_context": False
        },
        "output": {
            "dir": "./out",
            "report_name": "ghscan-report",
            "per_repo_files": True,
            "pretty": True,
            "gzip": False,
            # The same findings again, for everything that does not read our
            # own format.  Needs python in the scanner venv, which is there in
            # the container and might not be on a hand built host.
            "sarif": True,
            "include_clean_repos": True,
            "csv": {
                "enabled": True,
                "expand_branches": True,
                "delimiter": ","
            }
        },
        "rate_limit": {
            "min_remaining": 100,
            "sleep_on_exhaustion": True,
            "max_sleep_sec": 3900,
            "retries": 5,
            "retry_base_delay_sec": 2,
            "adaptive_pacing": True,
            "pace_below_fraction": 0.25,
            "max_pace_sleep_sec": 30,
            "secondary_backoff_sec": 60,
            "jitter_sec": 3,
            "preflight_estimate": True
        }
    }


def template() -> dict:
    """A fresh copy, so a caller editing it cannot change the original."""
    return copy.deepcopy(TEMPLATE)
