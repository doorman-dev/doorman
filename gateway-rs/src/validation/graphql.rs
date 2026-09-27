//! GraphQL validation port: depth, complexity field cost, and introspection control.

use std::sync::LazyLock;

static DOUBLE_QUOTED: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r#""[^"]*""#).expect("string expression is valid"));
static SINGLE_QUOTED: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"'[^']*'").expect("string expression is valid"));
static GRAPHQL_WORD: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"\b[a-zA-Z_][a-zA-Z0-9_]*\b").expect("field expression is valid")
});

#[derive(Debug, Clone)]
pub struct GraphqlValidationConfig {
    pub max_depth: usize,
    pub max_cost: usize,
    pub allow_introspection: bool,
}

impl Default for GraphqlValidationConfig {
    fn default() -> Self {
        Self {
            max_depth: 10,
            max_cost: 500,
            allow_introspection: true,
        }
    }
}

pub fn validate_graphql_query(query: &str, config: &GraphqlValidationConfig) -> Result<(), String> {
    if !config.allow_introspection && (query.contains("__schema") || query.contains("__type")) {
        return Err("GraphQL introspection query is prohibited by security policy".to_owned());
    }

    let depth = calculate_graphql_depth(query);
    if depth > config.max_depth {
        return Err(format!(
            "GraphQL query depth {depth} exceeds limit of {}",
            config.max_depth
        ));
    }

    let cost = calculate_graphql_cost(query);
    if cost > config.max_cost {
        return Err(format!(
            "GraphQL query estimated complexity {cost} exceeds limit of {}",
            config.max_cost
        ));
    }

    Ok(())
}

pub fn calculate_graphql_depth(query: &str) -> usize {
    let without_comments = query
        .lines()
        .map(|line| line.split_once('#').map_or(line, |(prefix, _)| prefix))
        .collect::<Vec<_>>()
        .join("\n");
    let without_strings = DOUBLE_QUOTED.replace_all(&without_comments, "\"\"");
    let without_strings = SINGLE_QUOTED.replace_all(&without_strings, "''");
    let mut depth = 0usize;
    let mut max_depth = 0usize;
    for ch in without_strings.chars() {
        if ch == '{' {
            depth += 1;
            if depth > max_depth {
                max_depth = depth;
            }
        } else if ch == '}' {
            depth = depth.saturating_sub(1);
        }
    }

    max_depth
}

pub fn calculate_graphql_cost(query: &str) -> usize {
    if query.is_empty() {
        return 0;
    }
    let without_comments = query
        .lines()
        .map(|line| line.split_once('#').map_or(line, |(prefix, _)| prefix))
        .collect::<Vec<_>>()
        .join("\n");
    let without_strings = DOUBLE_QUOTED.replace_all(&without_comments, "");
    GRAPHQL_WORD
        .find_iter(&without_strings)
        .filter(|word| !is_graphql_keyword(&word.as_str().to_ascii_lowercase()))
        .count()
}

fn is_graphql_keyword(word: &str) -> bool {
    matches!(
        word,
        "query" | "mutation" | "subscription" | "fragment" | "on"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_depth_and_cost() {
        let config = GraphqlValidationConfig {
            max_depth: 3,
            max_cost: 10,
            allow_introspection: false,
        };
        let query = "query { user { id name } }";
        assert!(validate_graphql_query(query, &config).is_ok());

        let introspection = "query { __schema { types { name } } }";
        assert!(validate_graphql_query(introspection, &config).is_err());

        assert_eq!(calculate_graphql_depth("{ field(arg: '{') { child } }"), 2);
        assert_eq!(calculate_graphql_cost("query { user { id name } }"), 3);
        assert_eq!(calculate_graphql_cost(""), 0);
    }
}
