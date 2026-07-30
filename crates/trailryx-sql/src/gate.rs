//! What SQL is allowed to be, checked before the engine ever sees it.
//!
//! # The defect this exists to prevent, measured
//!
//! A plain DataFusion `SessionContext` accepts this:
//!
//! ```sql
//! CREATE EXTERNAL TABLE leak (a INT, b VARCHAR)
//!   STORED AS CSV LOCATION '/etc/passwd';
//! SELECT * FROM leak;
//! ```
//!
//! It plans, it executes, and it returns the file. So a Postgres port that forwards
//! arbitrary SQL to a `SessionContext` is **arbitrary local file read on the host
//! running the store**, and anybody following the architecture's wiring without
//! thinking about statement kinds would ship exactly that. It was confirmed by
//! running it before this module existed, not reasoned about.
//!
//! The store's whole value is that it is believed by somebody who does not trust the
//! operator. A read surface that hands out the operator's filesystem is a worse
//! failure than anything the ingest side could do, because ingest can only add
//! records and this can exfiltrate everything else on the machine.
//!
//! # Why the check is on the parsed statement and not on the text
//!
//! Prefix matching on a string is defeated by a comment, by leading whitespace, by
//! a second statement after a semicolon, and by case. So the gate parses with
//! **DataFusion's own parser**, the same one the engine will use, and decides on the
//! AST. Two parsers disagreeing about where a statement ends is the same defect
//! class as request smuggling, and using the engine's parser is what removes it.
//!
//! # What is allowed, and why each one is
//!
//! An allowlist, because a denylist of dangerous statements is a list somebody has to
//! keep complete as `sqlparser` grows:
//!
//! - **`SELECT`, and `WITH ... SELECT`.** The point of the facade.
//! - **`EXPLAIN`.** Reads nothing; a client that cannot explain cannot be tuned.
//! - **`SHOW`, `SET`, `RESET`.** Every Postgres client sends these on connect.
//!   `psql` sends `SET client_encoding`, Grafana sets `extra_float_digits`, and a
//!   session that refuses them refuses the client. None of them reads a file.
//! - **`BEGIN`, `COMMIT`, `ROLLBACK`.** Drivers wrap even read-only work in a
//!   transaction. Accepted and meaningless here, which is better than accepted and
//!   pretended: there is nothing to commit because nothing can write.
//!
//! Everything else is refused **by name**, so the error says which statement kind
//! and not "syntax error". `CREATE EXTERNAL TABLE` and `COPY` get their own messages
//! because they are the two that read and write the filesystem, and somebody who
//! tries one deserves to know it was refused deliberately.

use datafusion::sql::parser::{DFParser, Statement};
use datafusion::sql::sqlparser::ast::Statement as SqlStatement;

/// Why a statement was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// It did not parse. The engine's own parser said so.
    Unparseable(String),
    /// More than one statement in one string.
    ///
    /// Refused rather than split: a gate that checked the first and ran the rest is
    /// the shape of every SQL injection ever written.
    Multiple(usize),
    /// A statement kind this facade does not serve.
    NotAllowed(&'static str),
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unparseable(why) => write!(f, "this statement does not parse: {why}"),
            Self::Multiple(n) => write!(
                f,
                "{n} statements in one request; this server runs one at a time"
            ),
            Self::NotAllowed(what) => write!(f, "{what}"),
        }
    }
}

/// Whether this SQL may reach the engine.
pub fn allow(sql: &str) -> Result<(), Refusal> {
    let statements = DFParser::parse_sql(sql).map_err(|e| Refusal::Unparseable(e.to_string()))?;
    if statements.len() != 1 {
        return Err(Refusal::Multiple(statements.len()));
    }
    classify(&statements[0])
}

fn classify(statement: &Statement) -> Result<(), Refusal> {
    match statement {
        // The two that touch the filesystem, named individually because a caller who
        // tries one has to learn it was a decision.
        Statement::CreateExternalTable(_) => Err(Refusal::NotAllowed(
            "CREATE EXTERNAL TABLE is refused: it would let a query name a path on this \
             host and read it, which is arbitrary local file read. Records arrive through \
             a Source and nowhere else",
        )),
        Statement::CopyTo(_) => Err(Refusal::NotAllowed(
            "COPY is refused: it writes to a path on this host. An export is produced by \
             the projection layer, where what it contains is decided rather than named \
             by whoever is connected",
        )),
        Statement::Explain(_) => Ok(()),
        Statement::Reset(_) => Ok(()),
        Statement::Statement(inner) => classify_ansi(inner),
    }
}

/// The same decision, for a statement somebody else already parsed.
///
/// The pgwire query hook receives `sqlparser`'s AST rather than text, so it needs the
/// classification without the parse step. `CREATE EXTERNAL TABLE` reaches this path as
/// a `CreateTable` with a location, which the object-creation arm refuses, so the
/// dangerous statement is refused on both routes into the engine.
pub fn allow_statement(statement: &SqlStatement) -> Result<(), Refusal> {
    classify_ansi(statement)
}

fn classify_ansi(statement: &SqlStatement) -> Result<(), Refusal> {
    match statement {
        SqlStatement::Query(_) => Ok(()),
        SqlStatement::Explain { .. } | SqlStatement::ExplainTable { .. } => Ok(()),
        // Session chatter every client sends on connect. None of it reads anything.
        SqlStatement::ShowVariable { .. }
        | SqlStatement::ShowVariables { .. }
        | SqlStatement::ShowFunctions { .. }
        | SqlStatement::Set(_) => Ok(()),
        // Drivers wrap read-only work in a transaction. Accepted and inert: there is
        // nothing to commit, because nothing here can write.
        SqlStatement::StartTransaction { .. }
        | SqlStatement::Commit { .. }
        | SqlStatement::Rollback { .. } => Ok(()),

        // Everything below is refused, and the messages say what rather than "no".
        SqlStatement::Insert(_) => Err(Refusal::NotAllowed(
            "INSERT is refused: records arrive through a Source, never through SQL. A \
             second way in would be a second way to write a record nobody chained",
        )),
        SqlStatement::Update { .. } | SqlStatement::Delete(_) => Err(Refusal::NotAllowed(
            "UPDATE and DELETE are refused: this is an append-only record of what \
             happened, and editing it is the thing the hash chain exists to detect",
        )),
        SqlStatement::CreateTable(_)
        | SqlStatement::CreateView { .. }
        | SqlStatement::CreateSchema { .. }
        | SqlStatement::CreateDatabase { .. }
        | SqlStatement::CreateFunction(_) => Err(Refusal::NotAllowed(
            "creating objects is refused: the tables a session can see are the ones the \
             store registered, and a session that could add one could add a path",
        )),
        SqlStatement::Drop { .. } | SqlStatement::Truncate { .. } => Err(Refusal::NotAllowed(
            "DROP and TRUNCATE are refused: nothing served here is a session's to remove",
        )),
        _ => Err(Refusal::NotAllowed(
            "this statement kind is not served: the facade answers queries and the \
             session chatter clients need, and refuses everything else by default \
             rather than by list",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The finding this module exists for, as a test rather than a comment. It was
    /// confirmed against a bare `SessionContext` first: the statement planned,
    /// executed, and returned the file's contents.
    #[test]
    fn the_two_statements_that_read_and_write_the_filesystem_are_refused_by_name() {
        let create =
            allow("CREATE EXTERNAL TABLE leak (a INT) STORED AS CSV LOCATION '/etc/passwd'")
                .expect_err("must be refused");
        assert!(
            create.to_string().contains("arbitrary local file read"),
            "{create}"
        );

        let copy = allow("COPY (SELECT 1) TO '/tmp/out.csv'").expect_err("must be refused");
        assert!(copy.to_string().contains("writes to a path"), "{copy}");
    }

    #[test]
    fn a_query_is_allowed_in_every_shape_a_client_writes_one() {
        for sql in [
            "SELECT * FROM records",
            "select run_id from records where run_id = 'a'",
            "WITH x AS (SELECT 1 AS n) SELECT n FROM x",
            "SELECT count(*) FROM records GROUP BY agent_id HAVING count(*) > 1",
            "  \n\t SELECT 1",
            "-- a leading comment\nSELECT 1",
            "SELECT 1;",
        ] {
            assert!(
                allow(sql).is_ok(),
                "{sql:?} should be allowed: {:?}",
                allow(sql)
            );
        }
    }

    /// A client that cannot send its session chatter is a client that cannot connect,
    /// so refusing these would refuse psql, Grafana and every driver.
    #[test]
    fn the_session_chatter_every_client_sends_is_allowed() {
        for sql in [
            "SET client_encoding TO 'UTF8'",
            "SET extra_float_digits = 3",
            "SHOW ALL",
            "SHOW TIME ZONE",
            "BEGIN",
            "COMMIT",
            "ROLLBACK",
            "EXPLAIN SELECT * FROM records",
        ] {
            assert!(
                allow(sql).is_ok(),
                "{sql:?} should be allowed: {:?}",
                allow(sql)
            );
        }
    }

    #[test]
    fn every_way_of_writing_is_refused() {
        for sql in [
            "INSERT INTO records VALUES (1)",
            "UPDATE records SET run_id = 'x'",
            "DELETE FROM records",
            "TRUNCATE TABLE records",
            "DROP TABLE records",
            "CREATE TABLE t (a INT)",
            "CREATE VIEW v AS SELECT 1",
            "CREATE SCHEMA s",
        ] {
            assert!(allow(sql).is_err(), "{sql:?} should be refused");
        }
    }

    /// A gate that checked the first statement and ran the rest is the shape of every
    /// SQL injection ever written. Refused rather than split.
    #[test]
    fn two_statements_in_one_request_are_refused_rather_than_split() {
        let refusal = allow(
            "SELECT 1; CREATE EXTERNAL TABLE leak (a INT) STORED AS CSV LOCATION '/etc/passwd'",
        )
        .expect_err("must be refused");
        assert_eq!(refusal, Refusal::Multiple(2), "{refusal}");

        // And the reverse order, so nobody can rely on the first one being the
        // harmless one.
        assert!(matches!(
            allow("DROP TABLE records; SELECT 1"),
            Err(Refusal::Multiple(2))
        ));
    }

    /// A comment cannot smuggle a statement past the gate, because the gate reads the
    /// parse tree and not the text.
    #[test]
    fn a_comment_cannot_hide_a_statement() {
        assert!(allow("/* SELECT 1 */ DROP TABLE records").is_err());
        assert!(allow("SELECT 1 /* ; DROP TABLE records */").is_ok());
    }

    /// Anything the allowlist does not name is refused, including statement kinds
    /// that do not exist yet. A denylist would need updating every time `sqlparser`
    /// grows a variant, and the update would be somebody remembering.
    #[test]
    fn an_unnamed_statement_kind_is_refused_by_default() {
        for sql in [
            "GRANT SELECT ON records TO alice",
            "ANALYZE records",
            "PREPARE p AS SELECT 1",
            "CREATE ROLE alice",
        ] {
            let outcome = allow(sql);
            assert!(
                outcome.is_err(),
                "{sql:?} should be refused by default, got {outcome:?}"
            );
        }
    }

    #[test]
    fn nonsense_is_refused_as_unparseable_and_says_so() {
        let refusal = allow("this is not sql at all").expect_err("must fail");
        assert!(matches!(refusal, Refusal::Unparseable(_)), "{refusal}");
        assert!(allow("").is_err(), "an empty request is not a query");
    }
}
