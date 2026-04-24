# postq-sdk-all

Official PostQ SDKs for **JavaScript/TypeScript**, **Python**, and **.NET**.

These wrap the [PostQ REST API](https://api.postq.dev) — submit quantum-risk scans from your own scanners or CI pipelines and read scan history for your org.

| Language                 | Package      | Install                              | Source                            | Status |
| ------------------------ | ------------ | ------------------------------------ | --------------------------------- | ------ |
| JavaScript / TypeScript  | [`@postq/sdk`](https://www.npmjs.com/package/@postq/sdk)      | `npm install @postq/sdk`             | [`sdks/js/`](sdks/js/)            | ![npm](https://img.shields.io/npm/v/@postq/sdk?label=) |
| Python                   | [`postq-sdk`](https://pypi.org/project/postq-sdk/)            | `pip install postq-sdk`              | [`sdks/python/`](sdks/python/)    | ![PyPI](https://img.shields.io/pypi/v/postq-sdk?label=) |
| .NET                     | [`PostQ.Sdk`](https://www.nuget.org/packages/PostQ.Sdk)       | `dotnet add package PostQ.Sdk`       | [`sdks/dotnet/`](sdks/dotnet/)    | ![NuGet](https://img.shields.io/nuget/v/PostQ.Sdk?label=) |

All three expose the same surface, idiomatic to each language:

- `pq.scans.submit({...})` → `POST /v1/scans`
- `pq.scans.submit_cloud({...})` / `submitCloud` / `SubmitCloudAsync` → `POST /v1/scans/cloud` (cloud KMS scans, **0.3.0+**)
- `pq.scans.list({limit})` → `GET /v1/scans`
- `pq.scans.iter_all()` / `iterAll()` / `IterAllAsync()` — auto-paginated stream
- `pq.assets.list({...})` → `GET /v1/assets` (cryptographic inventory, **0.3.0+**)
- `pq.keys.list({...})` → `GET /v1/keys` (key inventory, **0.3.0+**)
- `pq.assets.iter_all()` / `pq.keys.iter_all()` and equivalents — auto-paginated
- `pq.health()` → `GET /health`

The full machine-readable API contract lives in [`postq-site/apps/api/openapi.yaml`](https://github.com/PostQDev/postq-site/blob/main/apps/api/openapi.yaml).

Get an API key (`pq_live_…`) from your dashboard at <https://app.postq.dev>.

## Quick example (Python)

```python
from postq import PostQ, Finding

pq = PostQ()  # reads POSTQ_API_KEY

result = pq.scans.submit(
    type="url",
    target="example.com",
    risk_score=85,
    risk_level="High",
    findings=[Finding(severity="high", title="RSA-2048 public key")],
)
print(result.url)
```

See each SDK's README for full docs:
- [JavaScript / TypeScript](sdks/js/README.md)
- [Python](sdks/python/README.md)
- [.NET](sdks/dotnet/README.md)

## Releasing

Tag-triggered publish workflows live in [`.github/workflows/`](.github/workflows). Each SDK ships independently:

| SDK    | Bump version in                                                         | Tag           | Workflow                                                           |
| ------ | ----------------------------------------------------------------------- | ------------- | ------------------------------------------------------------------ |
| JS     | [`sdks/js/package.json`](sdks/js/package.json)                          | `js-vX.Y.Z`   | [`publish-npm.yml`](.github/workflows/publish-npm.yml)             |
| Python | [`sdks/python/pyproject.toml`](sdks/python/pyproject.toml)              | `py-vX.Y.Z`   | [`publish-pypi.yml`](.github/workflows/publish-pypi.yml)           |
| .NET   | [`sdks/dotnet/src/PostQ.Sdk/PostQ.Sdk.csproj`](sdks/dotnet/src/PostQ.Sdk/PostQ.Sdk.csproj) | `dotnet-vX.Y.Z` | [`publish-nuget.yml`](.github/workflows/publish-nuget.yml) |

Each workflow verifies that the package version matches the tag before publishing, so a typo can't ship the wrong version.

### One-time setup

- **npm**: create the `@postq` org and a granular access token; add as repo secret `NPM_TOKEN`.
- **PyPI**: configure Trusted Publishing for `postq-sdk` pointing at this repo + the `pypi` environment. No secret needed.
- **NuGet**: create an API key scoped `PostQ.*` push; add as repo secret `NUGET_API_KEY`.

## License

MIT — see [LICENSE](LICENSE).
