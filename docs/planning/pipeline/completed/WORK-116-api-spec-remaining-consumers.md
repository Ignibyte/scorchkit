# WORK-116 (WORK-108b): Remaining 5 API spec consumers
| Status | Complete (archived) |
| Forge Ticket | #116 |

Consumer hooks added to scanner::csrf, scanner::idor, scanner::graphql, scanner::auth, scanner::ratelimit. Each reads engine::api_spec::read_api_spec and runs module-specific tests against discovered endpoints. ratelimit::probe_spec_endpoints extracted as a helper to keep run() under the 100-line clippy cap. docs/architecture/api-spec-shared-data.md updated. Tests 636 unchanged. Lib clippy clean.
