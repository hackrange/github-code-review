#!/usr/bin/env bash
# Keep your token encrypted on disk, for running the samples on your own
# computer.  (In GitHub Actions, use a repository secret instead.)
#
#   gcr-token-store.sh save      ask for the token and save it encrypted
#   gcr-token-store.sh test      check the saved token can be read back
#   gcr-token-store.sh remove    delete the saved token
#
# The token is encrypted with GPG (AES-256) under a passphrase you choose,
# and saved to ~/.config/gcr/token.gpg, readable only by you.  Your .env then
# says how to read it back:
#
#   GCR_TOKEN_COMMAND=gpg --quiet --decrypt ~/.config/gcr/token.gpg
#
# gpg-agent remembers the passphrase for a while, so you are not asked on
# every run.
set -euo pipefail
umask 077

STORE="${GCR_TOKEN_STORE:-$HOME/.config/gcr/token.gpg}"
command -v gpg >/dev/null || {
  echo "gpg is not installed.  Ubuntu: sudo apt install gnupg   macOS: brew install gnupg" >&2
  exit 3
}

case "${1:-}" in
  save)
    mkdir -p "$(dirname "$STORE")"
    chmod 700 "$(dirname "$STORE")"
    # -s keeps the token off the screen and out of the shell history.
    read -r -s -p "Paste your Git Code Review token (it will not be shown): " token
    echo
    [[ "$token" == gcr_* ]] || { echo "That does not look like a token.  They start with gcr_" >&2; exit 3; }
    printf '%s' "$token" | gpg --batch --yes --quiet --symmetric --cipher-algo AES256 \
        --pinentry-mode loopback --passphrase-fd 3 --output "$STORE" 3< <(
          read -r -s -p "Choose a passphrase to protect it: " p1 </dev/tty; echo >/dev/tty
          read -r -s -p "Type the passphrase again: " p2 </dev/tty; echo >/dev/tty
          [[ -n "$p1" && "$p1" == "$p2" ]] || { echo "The passphrases did not match." >/dev/tty; exit 1; }
          printf '%s' "$p1")
    unset token
    chmod 600 "$STORE"
    echo "Saved to $STORE"
    echo "Add this line to your .env file:"
    echo "  GCR_TOKEN_COMMAND=gpg --quiet --decrypt $STORE"
    ;;
  test)
    if gpg --quiet --decrypt "$STORE" 2>/dev/null | grep -q '^gcr_'; then
      echo "The saved token can be read."
    else
      echo "Could not read $STORE.  Save it again with: $0 save" >&2; exit 1
    fi
    ;;
  remove)
    rm -f "$STORE" && echo "Removed $STORE"
    ;;
  *)
    sed -n '2,18p' "$0"; exit 2 ;;
esac
