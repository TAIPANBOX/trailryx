//! The gate, as a pgwire query hook.
//!
//! # Why the hook and not a wrapper
//!
//! A Postgres client does not send text to one function. It sends a simple query, or
//! it parses a statement and executes a portal later, possibly many times, and a
//! wrapper around one of those paths leaves the others open. `datafusion-postgres`
//! exposes a hook that is consulted on **all three** phases, so the gate sits where
//! every route into the engine passes.
//!
//! Returning `None` means "not my business, carry on". Returning `Some(Err(..))`
//! refuses. So the hook is ordered first, ahead of the library's own cursor, `SET`
//! and transaction hooks: a gate consulted after something else has already answered
//! is a gate that did not run.
//!
//! # The Arrow to Postgres conversion is not ours
//!
//! `DfSessionService` does it, through `arrow-pg`. Forty-two columns including four
//! list columns is a lot of encoding to get subtly wrong, and the library's version is
//! exercised by more clients than ours would be. What we keep is the decision about
//! what may run, which is the part that is ours to be right about.

use std::sync::Arc;

use datafusion::common::ParamValues;
use datafusion::logical_expr::LogicalPlan;
use datafusion::prelude::SessionContext;
use datafusion::sql::sqlparser::ast::Statement;
use datafusion_postgres::hooks::{HookClient, QueryHook};
use pgwire::api::ClientInfo;
use pgwire::api::results::Response;
use pgwire::error::{ErrorInfo, PgWireError, PgWireResult};

/// Refuses any statement [`crate::gate`] does not serve, on every phase.
#[derive(Debug, Default)]
pub struct GateHook;

impl GateHook {
    fn refuse(statement: &Statement) -> Option<PgWireError> {
        crate::gate::allow_statement(statement)
            .err()
            .map(|refusal| {
                // 42501 is `insufficient_privilege`, which is what this is: the statement
                // is well formed and the server will not run it. A syntax error would send
                // a client looking for a typo it does not have.
                PgWireError::UserError(Box::new(ErrorInfo::new(
                    "ERROR".to_owned(),
                    "42501".to_owned(),
                    refusal.to_string(),
                )))
            })
    }
}

#[async_trait::async_trait]
impl QueryHook for GateHook {
    async fn handle_simple_query(
        &self,
        statement: &Statement,
        _session_context: &SessionContext,
        _client: &mut dyn HookClient,
    ) -> Option<PgWireResult<Response>> {
        Self::refuse(statement).map(Err)
    }

    async fn handle_extended_parse_query(
        &self,
        statement: &Statement,
        _session_context: &SessionContext,
        _client: &(dyn ClientInfo + Send + Sync),
    ) -> Option<PgWireResult<LogicalPlan>> {
        // Refused at parse, so a client cannot prepare a statement now and execute it
        // later past a gate that only watched execution.
        Self::refuse(statement).map(Err)
    }

    async fn handle_extended_query(
        &self,
        statement: &Statement,
        _logical_plan: &LogicalPlan,
        _params: &ParamValues,
        _session_context: &SessionContext,
        _client: &mut dyn HookClient,
    ) -> Option<PgWireResult<Response>> {
        // And again at execute. Checking twice costs a match on an enum and removes
        // the question of whether a plan could have arrived by another route.
        Self::refuse(statement).map(Err)
    }
}

/// The library's own hooks, behind ours.
///
/// Order is load-bearing: a hook consulted after something else has already answered
/// is a hook that did not run.
pub fn hooks() -> Vec<Arc<dyn QueryHook>> {
    vec![
        Arc::new(GateHook),
        Arc::new(datafusion_postgres::hooks::cursor::CursorStatementHook),
        Arc::new(datafusion_postgres::hooks::set_show::SetShowHook),
        Arc::new(datafusion_postgres::hooks::transactions::TransactionStatementHook),
    ]
}
