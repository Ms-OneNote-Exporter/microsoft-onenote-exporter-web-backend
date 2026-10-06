#!/usr/bin/env bash
# Nothing logs the Microsoft account, or any other request header.
#
# ## Why this is a script and not a test
#
# "Nothing logs the account identifier" is not a property of one function. It is a
# property of every line of code in `api/src` — now, and in whatever comes after —
# plus the proxy in front of it. A unit test can only check the lines it was written
# against, which is how the CSRF-cookie bug survived review: the property was true
# everywhere the reviewer looked and false in a file nobody opened.
#
# So it is a grep over the source, failing the build. Deliberately crude: a regex
# cannot understand what a log call means, and this does not try. It catches the
# realistic mistakes — someone logging the whole request, or a header bag, without
# having to decide what was meant.
#
# ## The cost of a false positive
#
# A grep that fires on harmless code becomes a rule people disable, and a disabled
# rule is worse than no rule. So each pattern below is narrow enough that logging a
# header *variable* is still fine — the thing forbidden is handing the header bag
# itself to a log.

set -euo pipefail

cd "$(dirname "$0")/.."

fail() {
  echo "FAIL: $1"
  echo
  echo "  The account identifier is not a secret the way the password is, but it is"
  echo "  still an identifier, and headers are logged by more things than bodies are."
  echo "  If you need to log something here, log a specific value you have chosen to"
  echo "  disclose — not the header bag."
  exit 1
}

# ---- 1. no whole-request or whole-headers logging in the api -----------------

# `request.headers`, `req.headers`, `.headers` passed to a log call.
if grep -rnE '\.(request|req)\.headers[^;]*\b(log|logger)\b' api/src/ ; then
  fail "api/src logs a whole header bag"
fi

if grep -rnE '\blog(ger)?\.[a-z]+\([^)]*headers\s*[:=]' api/src/ ; then
  fail "api/src passes a headers object to a logger"
fi

# A `log.*` call that destructures the request and reaches for headers.
if grep -rnE 'log(ger)?\.[a-z]+\([^)]*(headers|req\.headers|request\.headers)' api/src/ ; then
  fail "api/src logs headers"
fi

# ---- 2. the credential route must not log the account it received -----------

if grep -rnE 'ACCOUNT_HEADER|account' api/src/routes.ts | grep -iE '\blog\.' ; then
  fail "the credential route logs the account"
fi

# ---- 3. Caddy must not have an access log ----------------------------------

# The Caddyfile discards the global logger, which is what keeps both bodies and
# headers out of the proxy's logs. An access log anywhere — even `log { output
# file-... }` inside one site block — undoes it.
if grep -nE '^\s*output\s+(?!discard)' infra/Caddyfile 2>/dev/null | grep -vP 'discard' ; then
  fail "infra/Caddyfile configures a log output other than discard"
fi

if grep -nE '^\s*log\s*\{' infra/Caddyfile >/dev/null 2>&1; then
  # A log block exists; every output in it must be discard.
  outputs=$(grep -oP '^\s*output\s+\K\S+' infra/Caddyfile | sort -u)
  for out in $outputs; do
    if [ "$out" != "discard" ]; then
      fail "infra/Caddyfile has a log output of '$out'"
    fi
  done
fi

# ---- 4. fastify must not be configured to log headers ----------------------

if grep -rnE 'logger:\s*\{[^}]*headers' api/src/ ; then
  fail "api configures pino to log headers"
fi

echo "ok    nothing logs a request header, and no access log is configured"