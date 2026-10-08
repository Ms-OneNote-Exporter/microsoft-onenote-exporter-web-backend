# The runner image.
#
# ## What is different from the api image
#
# This one **does** carry Playwright, Chromium and a browser's worth of Node
# modules, because it is the component that runs the `@msout` packages. The api's
# multi-stage build exists to keep exactly that out of the component that holds the
# session secret; here it is the point.
#
# Everything else is borrowed from the api's Dockerfile, including the reasons
# given there rather than restated.

# ---- build ---------------------------------------------------------------
# Which commit this image is. Injected by compose from IMAGE_TAG. No default: an
# unset BUILD_ID is a packaging mistake and the resulting image reports "local",
# which is visibly wrong rather than invisibly wrong.
ARG BUILD_ID

FROM node:22.13.0-bookworm-slim AS build

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY tsconfig.json ./
COPY src ./src

# No `npm run build` here — the typecheck is the point of this stage. A build that
# produces dist/ from code that does not typecheck is a way to ship one that
# works by accident.
RUN npm run typecheck
RUN npm run build

# ---- runtime -------------------------------------------------------------
FROM node:22.13.0-bookworm-slim AS runtime

ARG BUILD_ID
ENV BUILD_ID=${BUILD_ID}

# Chromium's own dependencies, and nothing else.
#
# `chromium` from the Debian archive rather than Playwright's download, because the
# archive version is patched by the distro's security team and does not carry a
# separate copy of the same browser. `PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1` stops
# `npm ci` fetching a second, unpatched one — which is what happens by default
# when the `playwright` package is installed, and which is why this stage is not
# simply "the api's plus a browser".
ENV PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1

# Where Playwright looks for its browsers, and **not** the default
# `~/.cache/ms-playwright` — because the orchestrator mounts a tmpfs over
# `/home/node/.cache` in every runner it creates, which would mask whatever is
# installed there. A location outside every tmpfs, so a browser installed in the image
# is a browser the runner can actually launch.
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      chromium \
      ca-certificates \
      fonts-liberation \
      fonts-noto-color-emoji \
 && rm -rf /var/lib/apt/lists/*

# Verified here rather than assumed. Chromium resolving to nothing is a container
# that starts, passes its health check, and then fails every login with a message
# that reads like a network problem.
RUN test -n "$(command -v chromium)" || (echo "chromium did not install" && exit 1)

RUN mkdir -p /data /artifacts && chown -R node:node /data /artifacts

# Numerically, and not `USER node`.
#
# `node` in this base image *is* uid 1000, so the two are the same user -- but a named
# uid cannot be compared against the orchestrator's by anything reading this file, and
# comparing them is the point: the two share `/srv/msout/data`, and when they did not
# agree every login failed with `EACCES: permission denied, mkdir '/data/<guid>'` from
# a container the orchestrator had just created, with a correct mount and a correct
# path.
#
# `.github/assert-compose.mjs` reads `USER` from this file and from
# `orchestrator/Dockerfile` and requires them to be equal. It *refuses* a named uid
# rather than passing it, because a check that cannot compare is not a check.
#
# Safe to lose the name: nothing resolves this user. `$HOME` is not read from the image
# -- each session sets its own `homeDir` for child processes, precisely so nothing lands
# in a shared home -- and Chromium's sandbox uses the numeric uid.
USER 1000:1000

WORKDIR /app

ENV NODE_ENV=production
ENV MSOUT_DATA_ROOT=/data
ENV MSOUT_ARTIFACT_ROOT=/artifacts

COPY package.json package-lock.json ./
# `--omit=dev` gives a tree with no compiler and no test runner. The `@msout`
# packages *are* kept: they are the reason this container exists.
RUN npm ci --omit=dev && npm cache clean --force

# ---- Playwright's browser registry -------------------------------------------
#
# Placed **here**, after `npm ci` and not next to the `chromium` install above,
# because it reads Playwright's own revision and Playwright does not exist until
# `npm ci` has run. The first attempt put it beside the apt step, where
# `require("playwright")` is `MODULE_NOT_FOUND` — and `set -e` turned that into an
# opaque build failure with no line to point at.
#
# And `USER 0` for the step itself, because it writes to `/opt` — which uid 1000
# cannot. Without it the build failed with `mkdir: cannot create directory
# '/opt/ms-playwright': Permission denied`, which is the same class as the bug being
# fixed: a correct step, a wrong identity. `USER` is restored immediately after, so
# nothing below runs privileged.
USER 0

# `PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1` plus `chromium.launch({headless})` and no
# `executablePath` leaves Playwright with **no browser at all**. `microsoft-webauth`
# calls it exactly that way and exposes no knob, so the image has to put the system
# Chromium where Playwright will look for it:
#
#     browserType.launch: Executable doesn't exist at
#     /home/node/.cache/ms-playwright/chromium_headless_shell-1243/…/chrome-headless-shell
#
# — from a container that was healthy, correctly mounted, correctly addressed, and had
# a working `/usr/bin/chromium` the whole time.
#
# **Both registry paths, because Playwright 1.63's `headless: true` wants the headless
# shell, not the full browser.** The error above names `chromium_headless_shell-1243`
# while `chromium.executablePath()` resolves `chromium-1243`. Linking only the latter
# produces the identical error with a different path in it.
#
# **The revision is read from Playwright at build time**, not written here, so a
# Playwright bump cannot leave this pointing at a directory that no longer exists —
# which would be the same silent failure one layer in.
#
# The probe then *launches and renders*, as the unprivileged user, because Chromium
# refuses to run as root without `--no-sandbox` and that flag is a control this
# repository asserts the absence of. A symlink that exists, or even resolves, is not
# evidence that a browser starts.
#
# It is written **into /app**, not /tmp, because `require("playwright")` resolves from
# the script's own directory. In /tmp it is `MODULE_NOT_FOUND` — which is the probe
# failing to find the thing it is probing, and reads like Playwright being broken.
RUN set -eux; \
    system_chromium="$(command -v chromium)"; \
    rev="$(node -e 'const {chromium}=require("playwright"); const m=chromium.executablePath().match(/\/([^/]+)\/chrome-linux64\/[^/]+$/); if(!m) { console.error("could not read the browser revision from", chromium.executablePath()); process.exit(1); } process.stdout.write(m[1]);')"; \
    mkdir -p \
      "${PLAYWRIGHT_BROWSERS_PATH}/${rev}/chrome-linux64" \
      "${PLAYWRIGHT_BROWSERS_PATH}/chromium_headless_shell-${rev#chromium-}/chrome-headless-shell-linux64"; \
    ln -s "$system_chromium" "${PLAYWRIGHT_BROWSERS_PATH}/${rev}/chrome-linux64/chrome"; \
    ln -s "$system_chromium" \
      "${PLAYWRIGHT_BROWSERS_PATH}/chromium_headless_shell-${rev#chromium-}/chrome-headless-shell-linux64/chrome-headless-shell"; \
    printf '%s\n' "$rev" > "${PLAYWRIGHT_BROWSERS_PATH}/REVISION"; \
    chown -R 1000:1000 "$PLAYWRIGHT_BROWSERS_PATH"; \
    printf '%s\n' \
      'const {chromium}=require("playwright");' \
      '(async()=>{' \
      '  const b=await chromium.launch({headless:true});' \
      '  const p=await b.newPage();' \
      '  await p.setContent("<title>msout-probe</title>");' \
      '  const t=await p.title();' \
      '  const v=await b.version();' \
      '  await b.close();' \
      '  if(t!=="msout-probe"){console.error("rendered",JSON.stringify(t));process.exit(1);}' \
      '  console.log("chromium launched:",v,"rendered:",t);' \
      '})().catch(e=>{console.error("LAUNCH FAILED:",e.message);process.exit(1);});' \
      > /app/msout-chromium-probe.cjs; \
    chown 1000:1000 /app/msout-chromium-probe.cjs; \
    su -s /bin/sh node -c 'node /app/msout-chromium-probe.cjs'; \
    rm -f /app/msout-chromium-probe.cjs

USER 1000:1000

# The session and artifact roots, created while this stage is still root and then
# handed to the unprivileged user. It has to be *here*, before the first
# `USER 1000` below: a RUN after that line executes unprivileged, which cannot chown anything.
#
# Load-bearing, the same way the api's volume ownership is: Docker creates a fresh
# named volume from the image's directory *and its ownership*, so a path absent
# from the image yields a root-owned volume that uid 1000 cannot write to.

COPY --from=build /app/dist ./dist

# No test material in the image. `tsconfig.json` includes only `src/**`, so this
# is structural — but the control is still CI's grep, and the grep uses word
# boundaries for a reason worth recording: a plain `grep "it("` matches
# `slot.describe()`, `process.exit(1)` and any `wait(` in the codebase, so it
# reports failures that have nothing to do with test material and gets ignored.
# CI's pattern is `(describe|it|test)\(` preceded by a non-identifier character,
# which matches the call and not the substring.

# ---- the runtime dependency set, checked in the image ---------------------
#
# The api asserts exactly {fastify}. The runner cannot: it needs Playwright,
# archiver and the three packages. What it *can* assert is that the set is
# exactly what it expects, so a dependency added by accident is caught at build
# time rather than discovered in a supply-chain review three months later.
# Written as a `node -p` one-liner rather than a multi-line `node -e "…"`.
# A quoted string does not continue across lines in a Dockerfile RUN — the parser
# treats each line as a new instruction — so the multi-line form fails with
# `unknown instruction: const`. Exactly the mistake the api's Dockerfile already
# documents and works around; recorded here because it is the same trap and this
# file is new.
RUN test "$(node -p "Object.keys(require('./package.json').dependencies).sort().join(',')")" = "@msout/microsoft-onenote-export-notebook,@msout/microsoft-onenote-list-notebooks,@msout/microsoft-webauth,archiver,fastify" \
 && echo "runtime dependency set is as expected"

EXPOSE 3100

# The token arrives as a Docker secret file, never as an env var — see
# .env.example for MSOUT_RUNNER_TOKEN_FILE. There is no CSRF key and no session
# secret here: this process holds credential bytes and nothing else, and the
# capability suite in CI asserts that neither appears in its environment.
CMD ["node", "dist/index.js"]
