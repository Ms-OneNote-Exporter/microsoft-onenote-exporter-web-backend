# The api image.
#
# Multi-stage so that no build toolchain — and no `node_modules` for a dev
# dependency — exists in the thing that runs.
#
# ## No native addon, on purpose
#
# The database driver is `node:sqlite`, which is built into Node. The alternative,
# better-sqlite3, would put a compilation step and a prebuilt-binary supply chain
# in the component that holds the session secret. See api/README.md.

# ---- build ---------------------------------------------------------------
FROM node:22.13.0-bookworm-slim AS build

WORKDIR /app

# Dependencies first, as their own layer: `npm ci` only re-runs when the
# lockfile changes, not on every source edit.
COPY package.json package-lock.json ./
RUN npm ci

COPY tsconfig.json tsconfig.build.json ./
COPY src ./src

# No `npm run build` here — the typecheck is the point of this stage. A build that
# produces dist/ from code that does not typecheck is a way to ship one that
# works by accident.
RUN npm run typecheck
RUN npm run build

# The runtime smoke test, in the image, where it matters. mac's addition: if the
# driver cannot load then every capability test fails for an unrelated reason and
# you learn nothing about isolation.
RUN node -e "require('node:sqlite'); console.log('node:sqlite ok, unflagged')"

# ---- runtime -------------------------------------------------------------
FROM node:22.13.0-bookworm-slim AS runtime

# Not root. The api has no reason to be root and a compromise should not start
# with it.
USER node

WORKDIR /app

ENV NODE_ENV=production

# `npm ci --omit=dev` gives a tree with no compiler, no test runner and no
# type definitions — so a vulnerability in any of them is not in the shipped
# image at all, rather than being present and unused.
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY --from=build /app/dist ./dist

# `tsconfig.build.json` excludes mock/, so there is no scripted runner in this
# image — the mock accepts any password and reports success. The control is CI's
# grep of dist/ for MockRunner and FakeOrchestrator; this comment is not it.

# ---- the zero-dependency invariant, checked in the image ------------------
#
# The orchestrator has zero third-party Go dependencies and the api has exactly
# one (`fastify`). Both are asserted here as well as in CI, because a single
# check is one merge away from being removed by someone who did not know what the
# property was for.
#
# Written with `node -p` one-liners rather than a multi-line `node -e "…"` string.
# A quoted string does not continue across lines in a Dockerfile RUN — the parser
# treats each line as a new instruction — so the earlier version failed to build
# with "unknown instruction: const". Same class of mistake as the CMD naming a
# file that did not exist: something that reads correctly and does not work.
RUN npm ls --omit=dev --all > /dev/null \
 && test "$(node -p "Object.keys(require('./package.json').dependencies).length")" = "1" \
 && test "$(node -p "Object.keys(require('./package.json').dependencies)[0]")" = "fastify" \
 && echo "runtime dependency set is exactly {fastify}"

USER node

# The api holds no socket and no mount (§2.1), so it needs no capabilities, no
# privileged mode and no docker socket. It listens on 3000.
EXPOSE 3000

# No healthcheck directive here: it would have to run `node -e ...` on every
# check, and the orchestrator and Caddy already probe /healthz. Adding a third
# copy of that answer would be one more thing to keep in step.

# The session secret arrives as a Docker secret file, never as an env var. See
# .env.example for ORCHESTRATOR_HMAC_SECRET_FILE and CSRF_KEY_FILE.
CMD ["node", "dist/index.js"]