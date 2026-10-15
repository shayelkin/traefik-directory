# traefik-directory

A lightweight Go service that queries the local Traefik API and serves a page with links to the
available HTTP routers.

Tagged releases are published to `ghcr.io/shayelkin/traefik-directory:<version>`.

## Configuration

All of the configuration is set through environment variables:

| Variable          | Default                 | Description                                                              |
| ----------------- | ----------------------- | ------------------------------------------------------------------------ |
| `ENTRYPOINTS`     | (required)              | Comma-separated Traefik entrypoint names to include, e.g. `web,websecure` |
| `TRAEFIK_API_URL` | `http://localhost:8080` | Base URL of the Traefik API                                              |
| `LISTEN_ADDR`     | `:8081`                 | Address the service listens on                                           |
| `DEFAULT_HOST`    | (unset)                 | Bare host (optionally `host:port`) used to link path-only routers        |

**Important:** Traefik's API must be enabled, e.g. `--api.insecure=true` or an entrypoint/router exposing `api@internal`.

## Acknowledging AI Use

This software was written with assistance from the following AI models:

* Claude Sonnet 5.5 (Anthropic)
* Claude Opus 5.5 (Anthropic)

## License

This software is licensed under the terms of the [MIT license](LICENSE).
