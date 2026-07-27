# License and attribution status

Status: **unresolved — release blocked**

Before any application source or binary is released or distributed outside the
authorized migration workspace, an authorized reviewer must record:

- ownership and reuse permission for the application source;
- ownership and reuse permission for every customized dependency patch;
- all required copyright notices, licenses, NOTICE files, and attribution;
- the license inventory and SBOM for every shipped binary and asset;
- the usage authorization for the WorkAgent2 name and all WorkAgent brand assets.

The approval record must identify the reviewer, approval authority, UTC review
time and an externally retained decision/reference. It must cover, at minimum:

| Release family | Required review coverage |
|---|---|
| control | WorkAgent2 source, embedded assets, Go modules, configuration and documentation shipped in `/opt/workagent/control` |
| runtime | AionUi `.21` and its Windows `.20` reference material, AionCore `.10`, Renderer, `@noble/hashes`, Codex, Kimi Code, Python and every packaged transitive dependency/asset |
| shared | CLIProxyAPI, `per-key-models.4`, `cpa-key-policy`, ChatForward, extension, Node.js, `ws` and every packaged transitive dependency/asset |
| migration | the separately distributed offline Windows migration tool and any copied compatibility material |

The generated `licenses.review.json` is a private, deliberately unapproved
draft. An authorized reviewer must provide one real SPDX expression and
copyright entry per component, include every required license/NOTICE file in
the signed tree, and only then set `approved: true`. Placeholder values such as
`NONE`, `NOASSERTION`, `unknown`, `TODO`, `TBD`, `review_required` or unresolved
are not approval and are rejected by release verification.

No license is granted by this placeholder. Repository maintainers and migration
operators must not infer or self-approve rights from source availability.
