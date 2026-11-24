use anyhow::{anyhow, ensure, Result};
use rusqlite::{params, Connection, Row, TransactionBehavior};
use serde::Serialize;
use std::{
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Clone)]
pub struct Audit {
    writer: Arc<Mutex<Connection>>,
    reader: Arc<Mutex<Connection>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{env, fs};

    #[test]
    fn history_is_bound_to_the_task_roles_and_mode() -> Result<()> {
        let path = env::temp_dir().join(format!("keyheron-audit-{}.sqlite3", uuid::Uuid::new_v4()));
        let open =
            |task, applicant, approver, mode| Audit::open(&path, task, applicant, approver, mode);
        let db = open("review", "alice", "owner", "external")?;
        db.record("alice", None, "example", "catalog", "allowed", "")?;
        drop(db);
        for (task, applicant, approver, mode) in [
            ("new", "alice", "owner", "external"),
            ("review", "other", "owner", "external"),
            ("review", "alice", "other", "external"),
            ("review", "alice", "owner", "demo"),
        ] {
            assert!(open(task, applicant, approver, mode).is_err());
        }
        let db = open("review", "alice", "owner", "external")?;
        assert_eq!(db.list(None, None, 100)?.len(), 1);
        drop(db);
        // Model a database written by the previous preview, which had no ownership row.
        Connection::open(&path)?.execute("DROP TABLE audit_context", [])?;
        assert!(open("review", "alice", "owner", "external").is_err());
        let old = Connection::open(&path)?;
        assert_eq!(
            old.query_row("SELECT count(*) FROM events", [], |r| r.get::<_, i64>(0))?,
            1
        );
        assert_eq!(
            old.query_row(
                "SELECT count(*) FROM sqlite_schema WHERE name='audit_context'",
                [],
                |r| r.get::<_, i64>(0)
            )?,
            0
        );
        old.execute("DELETE FROM events", [])?;
        drop(old);
        drop(open("new", "alice", "owner", "external")?);
        fs::remove_file(path)?;
        Ok(())
    }
}

#[derive(Serialize)]
pub struct Event {
    pub id: i64,
    pub at: i64,
    pub actor: String,
    pub environment: Option<String>,
    pub action: String,
    pub resource: String,
    pub result: String,
    pub detail: String,
}

fn event(row: &Row<'_>) -> rusqlite::Result<Event> {
    Ok(Event {
        id: row.get(0)?,
        at: row.get(1)?,
        actor: row.get(2)?,
        environment: row.get(3)?,
        action: row.get(4)?,
        resource: row.get(5)?,
        result: row.get(6)?,
        detail: row.get(7)?,
    })
}

impl Audit {
    pub fn open(
        path: impl AsRef<Path>,
        task: &str,
        applicant: &str,
        approver: &str,
        mode: &str,
    ) -> Result<Self> {
        let mut writer = Connection::open(path.as_ref())?;
        writer.busy_timeout(Duration::from_secs(3))?;
        let tx = writer.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch(
            "CREATE TABLE IF NOT EXISTS audit_context (
                id INTEGER PRIMARY KEY CHECK (id = 1), task TEXT NOT NULL,
                applicant TEXT NOT NULL, approver TEXT NOT NULL, mode TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY, at INTEGER NOT NULL, actor TEXT NOT NULL,
                environment TEXT, action TEXT NOT NULL, resource TEXT NOT NULL,
                result TEXT NOT NULL, detail TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS events_env_cursor ON events(environment, id);",
        )?;
        let bound: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM audit_context)", [], |r| {
            r.get(0)
        })?;
        if !bound {
            let history: bool =
                tx.query_row("SELECT EXISTS(SELECT 1 FROM events)", [], |r| r.get(0))?;
            ensure!(
                !history,
                "旧审计记录缺少归属信息，请保留原库并选择新的状态目录"
            );
            tx.execute(
                "INSERT INTO audit_context(id, task, applicant, approver, mode) VALUES (1, ?1, ?2, ?3, ?4)",
                params![task, applicant, approver, mode],
            )?;
        } else {
            let matches: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM audit_context WHERE id = 1 AND task = ?1
                 AND applicant = ?2 AND approver = ?3 AND mode = ?4)",
                params![task, applicant, approver, mode],
                |r| r.get(0),
            )?;
            ensure!(
                matches,
                "此审计库属于其他任务、参与人或运行模式，请使用独立状态目录"
            );
        }
        tx.commit()?;
        writer.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;")?;
        let reader =
            Connection::open_with_flags(path.as_ref(), rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        reader.busy_timeout(Duration::from_secs(3))?;
        Ok(Self {
            writer: Arc::new(Mutex::new(writer)),
            reader: Arc::new(Mutex::new(reader)),
        })
    }

    pub fn record(
        &self,
        actor: &str,
        environment: Option<&str>,
        action: &str,
        resource: &str,
        result: &str,
        detail: &str,
    ) -> Result<()> {
        let at = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as i64;
        let db = self
            .writer
            .lock()
            .map_err(|_| anyhow!("audit writer unavailable"))?;
        let mut insert = db.prepare_cached(
            "INSERT INTO events(at,actor,environment,action,resource,result,detail)
             VALUES (?1,?2,?3,?4,?5,?6,?7)",
        )?;
        insert.execute(params![
            at,
            actor,
            environment,
            action,
            resource,
            result,
            detail
        ])?;
        Ok(())
    }

    pub fn list(
        &self,
        environment: Option<&str>,
        before: Option<i64>,
        limit: u32,
    ) -> Result<Vec<Event>> {
        let db = self
            .reader
            .lock()
            .map_err(|_| anyhow!("audit reader unavailable"))?;
        let before = before.unwrap_or(i64::MAX);
        let limit = limit.clamp(1, 100);
        // Separate statements let SQLite seek directly into either cursor index.
        let rows = if let Some(env) = environment {
            let mut query = db.prepare_cached(
                "SELECT id,at,actor,environment,action,resource,result,detail
                FROM events WHERE environment=?1 AND id<?2 ORDER BY id DESC LIMIT ?3",
            )?;
            let rows = query.query_map(params![env, before, limit], event)?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        } else {
            let mut query = db.prepare_cached(
                "SELECT id,at,actor,environment,action,resource,result,detail
                FROM events WHERE id<?1 ORDER BY id DESC LIMIT ?2",
            )?;
            let rows = query.query_map(params![before, limit], event)?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };
        Ok(rows)
    }
}
