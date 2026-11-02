#!/usr/bin/env bash
# What to fix in a repository, grouped and in order:
#   1. secrets in the code   2. packages to upgrade   3. container images
#   4. build and CI files    5. code fixes an AI review has suggested
#
#   gcr-fix-plan.sh [-r org/name] [-b branch] [-o plan.md] [--fail-on-secrets]
#
# Prints the plan as Markdown.  Inside GitHub Actions it also goes on the
# job summary page.  Exit 0, or 1 with --fail-on-secrets when a secret is found.
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/gcr-common.sh"

repo="" branch="" out="" fail_on_secrets=0
while (( $# )); do
  case "$1" in
    -r|--repo) repo="$2"; shift 2 ;;
    -b|--branch) branch="$2"; shift 2 ;;
    -o|--out) out="$2"; shift 2 ;;
    --fail-on-secrets) fail_on_secrets=1; shift ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) echo "unknown option $1" >&2; exit 3 ;;
  esac
done
repo="$(gcr_default_repo "$repo")"; branch="$(gcr_default_branch "$branch")"
[[ -n "$repo" ]] || { echo "Give -r org/name, or run inside GitHub Actions." >&2; exit 3; }
site="${GCR_URL%/api/v1}"

# Every open finding on the repository, 1000 at a time.
all='[]' offset=0
while :; do
  page="$(gcr_get /findings "repo=$repo" "branch=$branch" "limit=1000" "offset=$offset")" || exit 3
  all="$(jq -s '.[0] + .[1].findings' <(printf '%s' "$all") <(printf '%s' "$page"))"
  offset="$(jq length <<<"$all")"
  (( $(jq .count <<<"$page") == 0 || offset >= $(jq .total <<<"$page") )) && break
done

plan="$(jq -r --arg repo "$repo" --arg branch "$branch" --arg site "$site" '
  def rank: {"critical":5,"high":4,"medium":3,"low":2,"info":1,"unknown":0}[.] // 0;
  def vkey: [splits("[.+-]") | if test("^[0-9]+$") then [0, tonumber, ""] else [1, 0, .] end];
  def link: if $site != "" then " [details](\($site)/findings/\(.id))" else "" end;
  def build_file: ascii_downcase | test("\\.github/(workflows|actions)/|dockerfile|containerfile|jenkinsfile|\\.gitlab-ci|azure-pipelines|bitbucket-pipelines|buildspec|cloudbuild|\\.circleci/|makefile|compose\\.y");

  [ .[] | select(.kind == "credential") ] as $secrets |
  [ .[] | select(.kind == "dependency" and ((.package.image // "") == "")) ] as $deps |
  [ .[] | select(.kind == "dependency" and ((.package.image // "") != "")) ] as $imgs |
  [ .[] | select(.kind == "misconfiguration" and (.file | build_file)) ] as $build |
  [ .[] | select((.kind == "code" or (.kind == "misconfiguration" and (.file | build_file | not)))
                 and ((.ai_review.fix // "") != "")) ] as $code |
  ([ .[] | select((.kind == "code" or (.kind == "misconfiguration" and (.file | build_file | not)))
                  and ((.ai_review.fix // "") == "")) ] | length) as $unreviewed |

  # One row per package and the file that declares it.
  ($deps | group_by([.package.ecosystem, .package.name, (.package.declared_in // "" | ltrimstr("/"))])
   | map({
       package: .[0].package.name, ecosystem: .[0].package.ecosystem,
       declared_in: (.[0].package.declared_in // "" | ltrimstr("/")),
       now: ([.[].package.version | select(. != "")] | unique | join(", ")),
       upgrade_to: ([.[].package.fixed_in // "" | splits("[ ,]+") | select(. != "")] | unique
                    | sort_by(vkey) | last // ""),
       worst: (map(.severity) | max_by(rank)),
       exploited: (map(.vulnerability.known_exploited // false) | any),
       build_only: (map((.reachability.scope // "") == "development") | all),
       advisories: ([.[].vulnerability.id // "" | select(. != "")] | unique)})
   | sort_by(-(.worst | rank), .package)) as $upgrades |

  ($imgs | group_by(.package.image) | map({image: .[0].package.image,
       worst: (map(.severity) | max_by(rank)),
       packages: ([.[] | "\(.package.name) \(.package.version)"] | unique)})) as $images |

  [ "## Fix plan for `\($repo)`" + (if $branch != "" then " on `\($branch)`" else "" end) ] +
  ( [ (if ($secrets | length) > 0 then
        ["### Secrets in the code: do these first", "",
         "Rotate each one at its provider (make a new key and turn the old one off), then move it out of the code into a secret store.  Deleting the line is not enough, because the old value stays in the git history.", "",
         "| Severity | What | Where | Live? |", "|---|---|---|---|"] +
        ($secrets | sort_by(-(.severity | rank)) | map("| \(.severity) | \(.title) `\(.credential.preview // "")`\(link) | `\(.file):\(.line)` | \(if .credential.verified then "YES, confirmed working" else "not confirmed" end) |"))
      else empty end),
      (if ($upgrades | length) > 0 then
        ["### Packages to upgrade", "",
         "Change each package to the version in **Upgrade to**, or newer, in the file named under **Declared in**.  Then rebuild so the lock file updates.", "",
         "| Package | Now | Upgrade to | Worst | Declared in | Advisories |", "|---|---|---|---|---|---|"] +
        ($upgrades | map("| \(.package)\(if (.ecosystem // "") != "" then " (\(.ecosystem))" else "" end) | \(if .now == "" then "a range" else .now end) | **\(if .upgrade_to == "" then "no fix yet" else .upgrade_to end)** | \(.worst)\(if .exploited then " (known exploited)" else "" end)\(if .build_only then ", build only" else "" end) | `\(.declared_in)` | \(.advisories[:4] | join(", "))\(if (.advisories | length) > 4 then " ..." else "" end) |"))
      else empty end),
      (if ($images | length) > 0 then
        ["### Container images to rebuild", "",
         "Move to a newer tag of the base image, or rebuild it so the operating system packages update.", ""] +
        ($images | map("- `\(.image)` (\(.worst)): \(.packages[:6] | join(", "))"))
      else empty end),
      (if ($build | length) > 0 then
        ["### Problems in the build and CI files", ""] +
        ($build | sort_by(-(.severity | rank)) | map("- **\(.severity)** `\(.file):\(.line)` \(.title).\(if (.ai_review.fix // "") != "" then "  Fix: \(.ai_review.fix)" else "" end)\(link)"))
      else empty end),
      (if ($code | length) > 0 then
        ["### Code fixes reviewed by AI", ""] +
        ($code | map("- **\(.ai_review.severity // .severity)** `\(.file):\(.line)` \(.title)\(link)\n  - What it is: \(.ai_review.summary)\n  - Fix: \(.ai_review.fix)" + (if (.ai_review.what_to_check // "") != "" then "\n  - Check: \(.ai_review.what_to_check)" else "" end) + (if (.ai_review.compensating_controls // "") != "" then "\n  - Until then: \(.ai_review.compensating_controls)" else "" end)))
      else empty end)
    ] | to_entries | map(.key as $k | .value[0] |= "\n### \($k + 1). \(ltrimstr("### "))") | map(.value[]) ) +
  (if $unreviewed > 0 then ["", "\($unreviewed) other code or configuration finding(s) have not been reviewed by AI yet, so no fix is suggested for them.  They are on the Findings page."] else [] end) +
  (if length == 1 then ["", "Nothing to fix.  No open findings on this repository."] else [] end)
  | join("\n")' <<<"$all")"

printf '%s\n' "$plan"
[[ -n "$out" ]] && printf '%s\n' "$plan" > "$out"
gcr_summary "$plan"

secrets="$(jq '[.[] | select(.kind == "credential")] | length' <<<"$all")"
if [[ "${GITHUB_ACTIONS:-}" == true ]]; then
  jq -r '.[] | select(.kind == "credential") |
    def p: gsub("%";"%25") | gsub(":";"%3A") | gsub(",";"%2C");
    "::error file=\(.file | p),line=\(.line),title=Secret in the code%3A rotate it::\(.title).  Rotate it first, then remove it."' <<<"$all"
fi
(( fail_on_secrets && secrets > 0 )) && exit 1
exit 0
