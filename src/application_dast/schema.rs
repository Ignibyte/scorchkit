use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};

use scorchkit_core::{
    sha256_hex, ApplicationDastSchemaIdentity, ApplicationDastSchemaKind, Result, ScorchError,
};
use url::Url;

use super::{path_is_under, ApplicationDastSchemaRequest};

const MAX_SCHEMA_OPERATIONS: usize = 10_000;
const HTTP_METHODS: [&str; 8] =
    ["get", "put", "post", "delete", "options", "head", "patch", "trace"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaOperation {
    pub route: String,
    pub method: String,
    pub operation_id: Option<String>,
    pub schema_sha256: String,
}

#[derive(Debug, Clone)]
pub struct ValidatedDastSchema {
    pub bytes: Vec<u8>,
    pub identity: ApplicationDastSchemaIdentity,
    pub operations: Vec<SchemaOperation>,
}

pub fn canonical_schema_path(request: &ApplicationDastSchemaRequest) -> Result<PathBuf> {
    let supplied_metadata =
        std::fs::symlink_metadata(&request.path).map_err(|error| ScorchError::InvalidTarget {
            target: request.path.display().to_string(),
            reason: format!("cannot inspect DAST schema: {error}"),
        })?;
    if supplied_metadata.file_type().is_symlink() {
        return Err(ScorchError::InvalidTarget {
            target: request.path.display().to_string(),
            reason: "DAST schema path must not be a symbolic link".to_string(),
        });
    }
    let canonical = request.path.canonicalize().map_err(|error| ScorchError::InvalidTarget {
        target: request.path.display().to_string(),
        reason: format!("cannot canonicalize DAST schema: {error}"),
    })?;
    let metadata = std::fs::symlink_metadata(&canonical)?;
    if !metadata.is_file() {
        return Err(ScorchError::InvalidTarget {
            target: canonical.display().to_string(),
            reason: "DAST schema must resolve to one regular file".to_string(),
        });
    }
    Ok(canonical)
}

pub fn validate_schema(
    request: &ApplicationDastSchemaRequest,
    canonical_path: &Path,
    target: &Url,
    limit: usize,
) -> Result<ValidatedDastSchema> {
    validate_digest(&request.sha256)?;
    let mut file = open_schema_file(canonical_path)?;
    let read_limit = u64::try_from(limit.saturating_add(1)).unwrap_or(u64::MAX);
    let mut bytes = Vec::with_capacity(limit.min(64 * 1024));
    Read::by_ref(&mut file).take(read_limit).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(ScorchError::Config(format!(
            "DAST schema '{}' exceeds the {limit}-byte limit",
            canonical_path.display()
        )));
    }
    let actual = sha256_hex(&bytes);
    if actual != request.sha256.to_ascii_lowercase() {
        return Err(ScorchError::Config(format!(
            "DAST schema '{}' does not match its declared SHA-256",
            canonical_path.display()
        )));
    }

    let (operations, endpoint) = match request.kind {
        ApplicationDastSchemaKind::OpenApi => {
            if request.endpoint.is_some() {
                return Err(ScorchError::Config(
                    "OpenAPI schema must not declare a GraphQL endpoint".to_string(),
                ));
            }
            (
                parse_openapi(&bytes, &actual)?
                    .into_iter()
                    .map(|mut operation| {
                        operation.route = target_scoped_route(target.path(), &operation.route);
                        operation
                    })
                    .collect(),
                None,
            )
        }
        ApplicationDastSchemaKind::GraphQl => {
            let endpoint = request.endpoint.as_deref().ok_or_else(|| {
                ScorchError::Config("GraphQL schema requires an explicit endpoint".to_string())
            })?;
            let endpoint = validate_same_origin_endpoint(target, endpoint)?;
            let operations = parse_graphql(&bytes, endpoint.path(), &actual)?;
            (operations, Some(endpoint.to_string()))
        }
    };
    let source_name = scorchkit_core::observation::redact_text(
        canonical_path.file_name().and_then(|name| name.to_str()).unwrap_or("schema"),
    );
    Ok(ValidatedDastSchema {
        bytes,
        identity: ApplicationDastSchemaIdentity {
            kind: request.kind,
            sha256: actual,
            source_name,
            endpoint,
        },
        operations,
    })
}

fn open_schema_file(canonical_path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(canonical_path)?;
    if !file.metadata()?.is_file() || canonical_path.canonicalize()? != canonical_path {
        return Err(ScorchError::InvalidTarget {
            target: canonical_path.display().to_string(),
            reason: "DAST schema changed after authorization".to_string(),
        });
    }
    Ok(file)
}

fn validate_digest(value: &str) -> Result<()> {
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(ScorchError::Config(
            "DAST schema SHA-256 must be exactly 64 hexadecimal characters".to_string(),
        ))
    }
}

fn validate_same_origin_endpoint(target: &Url, endpoint: &str) -> Result<Url> {
    let endpoint = Url::parse(endpoint).map_err(|error| ScorchError::InvalidTarget {
        target: endpoint.to_string(),
        reason: format!("invalid GraphQL endpoint: {error}"),
    })?;
    if endpoint.scheme() != target.scheme()
        || endpoint.host_str() != target.host_str()
        || endpoint.port_or_known_default() != target.port_or_known_default()
        || !path_is_under(target.path(), endpoint.path())
        || endpoint.username() != ""
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
    {
        return Err(ScorchError::InvalidTarget {
            target: endpoint.to_string(),
            reason: "GraphQL endpoint must be credential-free, same-origin, and under the authorized target path"
                .to_string(),
        });
    }
    Ok(endpoint)
}

fn parse_openapi(bytes: &[u8], digest: &str) -> Result<Vec<SchemaOperation>> {
    let yaml: serde_yaml::Value =
        serde_yaml::from_slice(bytes).map_err(|error| ScorchError::ToolOutputParse {
            tool: "openapi-schema".to_string(),
            reason: error.to_string(),
        })?;
    let document = serde_json::to_value(yaml)?;
    let object = document.as_object().ok_or_else(|| ScorchError::ToolOutputParse {
        tool: "openapi-schema".to_string(),
        reason: "schema root must be an object".to_string(),
    })?;
    let supported = object
        .get("openapi")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|value| value.starts_with("3."))
        || object
            .get("swagger")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|value| value.starts_with("2."));
    if !supported {
        return Err(ScorchError::ToolOutputParse {
            tool: "openapi-schema".to_string(),
            reason: "expected Swagger 2.x or OpenAPI 3.x".to_string(),
        });
    }
    reject_external_references(&document)?;
    let paths = object.get("paths").and_then(serde_json::Value::as_object).ok_or_else(|| {
        ScorchError::ToolOutputParse {
            tool: "openapi-schema".to_string(),
            reason: "OpenAPI paths object is missing".to_string(),
        }
    })?;
    let mut operations = Vec::new();
    for (route, item) in paths {
        validate_openapi_route(route)?;
        let item = item.as_object().ok_or_else(|| ScorchError::ToolOutputParse {
            tool: "openapi-schema".to_string(),
            reason: format!("path '{route}' must be an object"),
        })?;
        for method in HTTP_METHODS {
            if let Some(operation) = item.get(method) {
                if !operation.is_object() {
                    return Err(ScorchError::ToolOutputParse {
                        tool: "openapi-schema".to_string(),
                        reason: format!("operation {method} {route} must be an object"),
                    });
                }
                operations.push(SchemaOperation {
                    route: normalized_route(route),
                    method: method.to_ascii_uppercase(),
                    operation_id: operation
                        .get("operationId")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_string),
                    schema_sha256: digest.to_string(),
                });
                if operations.len() > MAX_SCHEMA_OPERATIONS {
                    return Err(ScorchError::Config(format!(
                        "OpenAPI operation count exceeds {MAX_SCHEMA_OPERATIONS}"
                    )));
                }
            }
        }
    }
    if operations.is_empty() {
        return Err(ScorchError::ToolOutputParse {
            tool: "openapi-schema".to_string(),
            reason: "OpenAPI schema contains no HTTP operations".to_string(),
        });
    }
    operations.sort_by(|left, right| {
        (&left.route, &left.method, &left.operation_id).cmp(&(
            &right.route,
            &right.method,
            &right.operation_id,
        ))
    });
    Ok(operations)
}

fn validate_openapi_route(route: &str) -> Result<()> {
    let unsafe_segment = route.split('/').any(|segment| {
        matches!(
            segment.to_ascii_lowercase().as_str(),
            "." | ".." | "%2e" | "%2e%2e" | ".%2e" | "%2e."
        )
    });
    if !route.starts_with('/')
        || route.starts_with("//")
        || route.contains('?')
        || route.contains('#')
        || route.contains('\\')
        || route.chars().any(char::is_control)
        || unsafe_segment
    {
        return Err(ScorchError::ToolOutputParse {
            tool: "openapi-schema".to_string(),
            reason: format!("OpenAPI path '{route}' is not a safe absolute application route"),
        });
    }
    Ok(())
}

fn reject_external_references(value: &serde_json::Value) -> Result<()> {
    match value {
        serde_json::Value::Object(object) => {
            for (key, value) in object {
                if key == "$ref" {
                    let reference = value.as_str().ok_or_else(|| {
                        ScorchError::Config("OpenAPI $ref must be a string".to_string())
                    })?;
                    if !reference.starts_with('#') {
                        return Err(ScorchError::Config(format!(
                            "OpenAPI external reference '{reference}' is not allowed"
                        )));
                    }
                }
                reject_external_references(value)?;
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                reject_external_references(value)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn parse_graphql(bytes: &[u8], endpoint: &str, digest: &str) -> Result<Vec<SchemaOperation>> {
    let text = std::str::from_utf8(bytes).map_err(|error| ScorchError::ToolOutputParse {
        tool: "graphql-schema".to_string(),
        reason: error.to_string(),
    })?;
    if text.lines().any(graphql_line_is_import) {
        return Err(ScorchError::Config("GraphQL schema imports are not allowed".to_string()));
    }
    let document = graphql_parser::parse_schema::<String>(text).map_err(|error| {
        ScorchError::ToolOutputParse {
            tool: "graphql-schema".to_string(),
            reason: format!("invalid GraphQL SDL: {error}"),
        }
    })?;
    let mut query_type = "Query".to_string();
    let mut mutation_type = "Mutation".to_string();
    for definition in &document.definitions {
        if let graphql_parser::schema::Definition::SchemaDefinition(schema) = definition {
            if let Some(query) = &schema.query {
                query_type.clone_from(query);
            }
            if let Some(mutation) = &schema.mutation {
                mutation_type.clone_from(mutation);
            }
        }
    }
    let mut fields = BTreeSet::new();
    for definition in document.definitions {
        if let graphql_parser::schema::Definition::TypeDefinition(
            graphql_parser::schema::TypeDefinition::Object(object),
        ) = definition
        {
            let operation = if object.name == query_type {
                Some("query")
            } else if object.name == mutation_type {
                Some("mutation")
            } else {
                None
            };
            if let Some(operation) = operation {
                for field in object.fields {
                    fields.insert((operation.to_string(), field.name));
                }
            }
        }
    }
    if fields.is_empty() {
        return Err(ScorchError::ToolOutputParse {
            tool: "graphql-schema".to_string(),
            reason: "GraphQL schema contains no query or mutation root fields".to_string(),
        });
    }
    if fields.len() > MAX_SCHEMA_OPERATIONS {
        return Err(ScorchError::Config(format!(
            "GraphQL operation count exceeds {MAX_SCHEMA_OPERATIONS}"
        )));
    }
    Ok(fields
        .into_iter()
        .map(|(operation, field)| SchemaOperation {
            route: normalized_route(endpoint),
            method: "POST".to_string(),
            operation_id: Some(format!("graphql:{operation}:{field}")),
            schema_sha256: digest.to_string(),
        })
        .collect())
}

fn graphql_line_is_import(line: &str) -> bool {
    line.trim_start_matches(['\u{feff}', ' ', '\t']).strip_prefix('#').is_some_and(|comment| {
        comment
            .trim_start()
            .split_ascii_whitespace()
            .next()
            .is_some_and(|word| word.eq_ignore_ascii_case("import"))
    })
}

fn normalized_route(route: &str) -> String {
    let route = route.trim();
    if route.starts_with('/') {
        route.to_string()
    } else {
        format!("/{route}")
    }
}

fn target_scoped_route(target_path: &str, schema_route: &str) -> String {
    let base = target_path.trim_end_matches('/');
    let route = schema_route.trim_start_matches('/');
    match (base.is_empty(), route.is_empty()) {
        (true, true) => "/".to_string(),
        (true, false) => format!("/{route}"),
        (false, true) => format!("{base}/"),
        (false, false) => format!("{base}/{route}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write as _;

    fn openapi_request(path: PathBuf, bytes: &[u8]) -> ApplicationDastSchemaRequest {
        ApplicationDastSchemaRequest {
            kind: ApplicationDastSchemaKind::OpenApi,
            path,
            sha256: sha256_hex(bytes),
            endpoint: None,
        }
    }

    #[test]
    fn openapi_preserves_operations_and_rejects_external_refs() {
        let valid = br"openapi: 3.0.3
paths:
  /users/{id}:
    get:
      operationId: getUser
";
        let operations = parse_openapi(valid, "aa").expect("valid OpenAPI");
        assert_eq!(operations.len(), 1);
        assert_eq!(operations[0].route, "/users/{id}");
        assert_eq!(operations[0].operation_id.as_deref(), Some("getUser"));

        let remote = br"openapi: 3.0.3
paths:
  /x:
    get:
      responses:
        default:
          $ref: https://example.com/response.yaml
";
        assert!(parse_openapi(remote, "aa").is_err());

        let nested_remote = serde_json::json!({
            "items": [{"schema": {"$ref": "https://example.com/response.yaml"}}]
        });
        assert!(reject_external_references(&nested_remote).is_err());

        for route in [
            "relative",
            "//outside.example/x",
            "/../admin",
            "/%2e%2e/admin",
            "/x?next=/admin",
            "/x#fragment",
            "/x\\admin",
            "/x\u{0007}admin",
        ] {
            let schema =
                format!("openapi: 3.0.3\npaths:\n  {route}:\n    get:\n      responses: {{}}\n");
            assert!(parse_openapi(schema.as_bytes(), "aa").is_err(), "accepted {route}");
        }
    }

    #[test]
    fn schema_operation_limits_accept_the_limit_and_reject_one_more() {
        let mut openapi = String::from("openapi: 3.0.3\npaths:\n");
        for index in 0..MAX_SCHEMA_OPERATIONS {
            writeln!(openapi, "  /route-{index}:\n    get: {{}}").expect("OpenAPI fixture");
        }
        assert_eq!(
            parse_openapi(openapi.as_bytes(), "aa").expect("limit OpenAPI schema").len(),
            MAX_SCHEMA_OPERATIONS
        );
        writeln!(openapi, "  /overflow:\n    get: {{}}").expect("OpenAPI overflow fixture");
        assert!(parse_openapi(openapi.as_bytes(), "aa").is_err());

        let mut graphql = String::from("type Query {\n");
        for index in 0..MAX_SCHEMA_OPERATIONS {
            writeln!(graphql, "field{index}: Int").expect("GraphQL fixture");
        }
        graphql.push_str("}\n");
        assert_eq!(
            parse_graphql(graphql.as_bytes(), "/graphql", "bb")
                .expect("limit GraphQL schema")
                .len(),
            MAX_SCHEMA_OPERATIONS
        );
        graphql.insert_str(graphql.len() - 2, "overflow: Int\n");
        assert!(parse_graphql(graphql.as_bytes(), "/graphql", "bb").is_err());
    }

    #[test]
    fn graphql_preserves_root_fields_and_rejects_imports() {
        let operations = parse_graphql(
            b"type Query {\n viewer: User\n user(id: ID!): User\n}\ntype User { id: ID! }",
            "/graphql",
            "bb",
        )
        .expect("valid GraphQL");
        assert_eq!(operations.len(), 2);
        assert_eq!(operations[0].method, "POST");
        assert_eq!(operations[0].operation_id.as_deref(), Some("graphql:query:user"));
        assert!(parse_graphql(b"#import other.graphql\ntype Query { x: Int }", "/graphql", "bb")
            .is_err());
        assert!(parse_graphql(b"# import other.graphql\ntype Query { x: Int }", "/graphql", "bb")
            .is_err());
        assert!(parse_graphql(
            "\u{feff}# IMPORT other.graphql\ntype Query { x: Int }".as_bytes(),
            "/graphql",
            "bb"
        )
        .is_err());
        assert!(parse_graphql(b"type Query { broken: }", "/graphql", "bb").is_err());

        let custom = parse_graphql(
            b"schema { query: Root mutation: Writes }\ntype Root { viewer: String }\ntype Writes { save: Boolean }",
            "/graphql",
            "bb",
        )
        .expect("custom roots");
        assert!(custom
            .iter()
            .any(|operation| operation.operation_id.as_deref() == Some("graphql:mutation:save")));
    }

    #[test]
    fn graphql_endpoint_requires_an_authorized_path_segment() {
        let target = Url::parse("https://example.com/app").expect("target");
        assert!(validate_same_origin_endpoint(&target, "https://example.com/app/graphql").is_ok());
        for endpoint in [
            "http://example.com/app/graphql",
            "https://outside.example/app/graphql",
            "https://example.com:8443/app/graphql",
            "https://example.com/application/graphql",
            "https://user@example.com/app/graphql",
            "https://user:password@example.com/app/graphql",
            "https://example.com/app/graphql?query=x",
            "https://example.com/app/graphql#fragment",
        ] {
            assert!(
                validate_same_origin_endpoint(&target, endpoint).is_err(),
                "accepted {endpoint}"
            );
        }
    }

    #[test]
    fn schema_digest_file_and_byte_limits_are_exact() {
        assert!(validate_digest(&"a".repeat(64)).is_ok());
        assert!(validate_digest(&"A".repeat(64)).is_ok());
        assert!(validate_digest(&"a".repeat(63)).is_err());
        assert!(validate_digest(&format!("{}g", "a".repeat(63))).is_err());

        let directory = tempfile::tempdir().expect("directory");
        let bytes = b"openapi: 3.0.3\npaths:\n  /items:\n    get: {}\n";
        let path = directory.path().join("schema.yaml");
        std::fs::write(&path, bytes).expect("schema");
        let canonical = path.canonicalize().expect("canonical schema");
        let request = openapi_request(path, bytes);
        let target = Url::parse("https://example.com/app").expect("target");

        let validated =
            validate_schema(&request, &canonical, &target, bytes.len()).expect("exact byte limit");
        assert_eq!(validated.bytes, bytes);
        assert_eq!(validated.identity.sha256, sha256_hex(bytes));
        assert_eq!(validated.operations[0].route, "/app/items");
        assert!(validate_schema(&request, &canonical, &target, bytes.len() - 1).is_err());

        let mut wrong = request;
        wrong.sha256 = "b".repeat(64);
        assert!(validate_schema(&wrong, &canonical, &target, bytes.len()).is_err());
        assert!(open_schema_file(directory.path()).is_err());

        let nested = directory.path().join("nested");
        std::fs::create_dir(&nested).expect("nested directory");
        let noncanonical = nested.join("..").join("schema.yaml");
        assert!(open_schema_file(&noncanonical).is_err());
    }

    #[test]
    fn openapi_routes_are_scoped_to_the_authorized_target_base() {
        assert_eq!(target_scoped_route("/", "/users/{id}"), "/users/{id}");
        assert_eq!(target_scoped_route("/app", "/users/{id}"), "/app/users/{id}");
        assert_eq!(target_scoped_route("/app/", "/"), "/app/");
    }

    #[cfg(unix)]
    #[test]
    fn schema_intake_rejects_a_supplied_symbolic_link() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let schema = directory.path().join("schema.yaml");
        let link = directory.path().join("linked-schema.yaml");
        std::fs::write(&schema, b"openapi: 3.0.3\npaths: {}\n").expect("schema fixture");
        std::os::unix::fs::symlink(&schema, &link).expect("schema symlink");
        let request = ApplicationDastSchemaRequest {
            kind: ApplicationDastSchemaKind::OpenApi,
            path: link,
            sha256: "a".repeat(64),
            endpoint: None,
        };

        let error = canonical_schema_path(&request).expect_err("symlink must be rejected");
        assert!(error.to_string().contains("symbolic link"));
    }
}
