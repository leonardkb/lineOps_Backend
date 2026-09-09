// ==========================================================================
// holidays.js
//
// NON-WORKING DAYS for the Plan Board.
//
// A holiday row marks a DAY (optionally a single LINE) as unavailable:
//   • the Plan Board paints that day column / cell as blocked and refuses drops
//   • POST /line-assignments and POST /pre-order-holds reject that date
//   • /available-lines skips it
//
// line_no = NULL  -> the whole plant is off that day (Navidad, 16 de septiembre)
// line_no = 'L8'  -> only that line is down (mantenimiento, paro de línea)
//
// Register-module in the same shape as merchant-plan.js / work-orders.js /
// pre-order-holds.js.
//
// --------------------------------------------------------------------------
// SETUP  (server.js)
// --------------------------------------------------------------------------
// 1. Near the other requires:
//        const registerHolidays = require("./holidays");
// 2. In the async startup block, by the other initSchema calls:
//        await registerHolidays.initSchema({ pool, setSchema });
// 3. Where the other modules register:
//        registerHolidays(app, { authenticateToken, pool, setSchema });
//
// Gated by authenticateToken only; the calendar is ORG-WIDE like the plan.
// created_by records who blocked the day.
//
// Endpoints
//   GET    /api/holidays[?from=&to=&lineNo=]  -> { success, holidays:[...] }
//   POST   /api/holidays                      -> block one day or a range
//   DELETE /api/holidays?id=                  -> unblock ONE row
//   DELETE /api/holidays?date=[&lineNo=]      -> unblock a day (of a line)
//
// POST body (camelCase from the board):
//   { date: "YYYY-MM-DD", to?: "YYYY-MM-DD", name, lineNo? }
//   `to` blocks the whole inclusive range (vacaciones, semana santa).
//   Re-blocking the same day/line just updates its name.
//
// Also exported for other modules:
//   registerHolidays.initSchema({ pool, setSchema })
//   registerHolidays.isHoliday(client, { date, lineNo })  -> row | null
//   registerHolidays.holidaysBetween(client, { from, to }) -> rows
// ==========================================================================

const TABLE = "production_holidays";
const MAX_RANGE_DAYS = 366; // a POST can't block more than a year at once

async function initSchema({ pool, setSchema }) {
  const client = await pool.connect();
  try {
    await setSchema(client);
    await client.query(`
      CREATE TABLE IF NOT EXISTS ${TABLE}(
        id            BIGSERIAL PRIMARY KEY,
        holiday_date  DATE NOT NULL,
        name          VARCHAR(150) NOT NULL DEFAULT '',
        line_no       TEXT,                       -- NULL = todas las líneas
        created_by    BIGINT,
        created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
      );
    `);
    // One row per (day, line). NULL line_no folds to '*' so a plant-wide day
    // and a line-specific day can coexist without duplicating either.
    await client.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS uq_${TABLE}
        ON ${TABLE} (holiday_date, COALESCE(line_no, '*'));
    `);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_${TABLE}_date ON ${TABLE}(holiday_date);`);
    console.log("\u2705 production_holidays table ready in prod_db_schema");
  } finally {
    client.release();
  }
}

// --- coercion helpers ------------------------------------------------------
const txt = (v, n) => (v == null ? null : String(v).trim().slice(0, n || 200) || null);
const isYmd = (v) => typeof v === "string" && /^\d{4}-\d{2}-\d{2}$/.test(v);
const lineOrNull = (v) => {
  const s = String(v == null ? "" : v).trim();
  return s === "" || s.toUpperCase() === "ALL" || s === "*" ? null : s.slice(0, 40);
};
const daysBetween = (a, b) => Math.round((Date.parse(b) - Date.parse(a)) / 86400000);

// --------------------------------------------------------------------------
// Shared guards — used by line-assignments / pre-order-holds before writing.
// Both take an *already schema-scoped* client.
// --------------------------------------------------------------------------

// Is this line closed on this day? Returns the blocking row, or null.
// A plant-wide holiday (line_no IS NULL) blocks every line.
async function isHoliday(client, { date, lineNo } = {}) {
  if (!isYmd(date)) return null;
  const { rows } = await client.query(
    `SELECT id, to_char(holiday_date,'YYYY-MM-DD') AS holiday_date, name, line_no
       FROM ${TABLE}
      WHERE holiday_date = $1
        AND (line_no IS NULL OR line_no = $2)
      ORDER BY line_no NULLS FIRST
      LIMIT 1`,
    [date, lineOrNull(lineNo)]
  );
  return rows[0] || null;
}

// Every blocked day in a window — one query for a whole board render.
async function holidaysBetween(client, { from, to } = {}) {
  const params = [];
  const where = [];
  if (isYmd(from)) { params.push(from); where.push(`holiday_date >= $${params.length}`); }
  if (isYmd(to)) { params.push(to); where.push(`holiday_date <= $${params.length}`); }
  const { rows } = await client.query(
    `SELECT id, to_char(holiday_date,'YYYY-MM-DD') AS holiday_date, name, line_no, updated_at
       FROM ${TABLE}
      ${where.length ? "WHERE " + where.join(" AND ") : ""}
      ORDER BY holiday_date, line_no NULLS FIRST`,
    params
  );
  return rows;
}

// What is already sitting on the days we are about to block? Best-effort:
// if either table is missing/renamed we just report null instead of failing.
async function countConflicts(client, { from, to, lineNo }) {
  const line = lineOrNull(lineNo);
  const out = { assignments: null, preOrderHolds: null };
  try {
    const { rows } = await client.query(
      `SELECT COUNT(*)::int AS n FROM line_assignments
        WHERE assigned_date BETWEEN $1 AND $2
          AND ($3::text IS NULL OR line_no = $3)`,
      [from, to, line]
    );
    out.assignments = rows[0].n;
  } catch { /* table/column not there — skip the warning */ }
  try {
    const { rows } = await client.query(
      `SELECT COUNT(*)::int AS n FROM pre_order_day_holds
        WHERE assigned_date BETWEEN $1 AND $2
          AND ($3::text IS NULL OR line_no = $3)`,
      [from, to, line]
    );
    out.preOrderHolds = rows[0].n;
  } catch { /* same */ }
  return out;
}

function registerHolidays(app, deps) {
  const { authenticateToken, pool, setSchema } = deps;

  // ---- GET: blocked days (optionally within a window / for one line) -----
  app.get("/api/holidays", authenticateToken, async (req, res) => {
    const from = isYmd(req.query.from) ? req.query.from : null;
    const to = isYmd(req.query.to) ? req.query.to : null;
    const line = lineOrNull(req.query.lineNo ?? req.query.line_no);
    const client = await pool.connect();
    try {
      await setSchema(client);
      let rows = await holidaysBetween(client, { from, to });
      // Asking for one line still includes the plant-wide days: they close it too.
      if (line) rows = rows.filter((r) => r.line_no == null || r.line_no === line);
      res.json({ success: true, holidays: rows });
    } catch (err) {
      console.error("\u274c GET /api/holidays:", err.message);
      res.status(500).json({ success: false, error: err.message });
    } finally {
      client.release();
    }
  });

  // ---- POST: block one day, or every day in an inclusive range -----------
  app.post("/api/holidays", authenticateToken, async (req, res) => {
    const b = req.body || {};
    const from = b.date ?? b.from ?? b.holidayDate ?? b.holiday_date ?? null;
    const to = b.to ?? b.endDate ?? b.end_date ?? from;
    const name = txt(b.name ?? b.reason ?? b.motivo, 150) || "";
    const line = lineOrNull(b.lineNo ?? b.line_no);

    if (!isYmd(from) || !isYmd(to)) {
      return res.status(400).json({ success: false, error: "date (YYYY-MM-DD) es obligatoria; to debe ser YYYY-MM-DD" });
    }
    const span = daysBetween(from, to);
    if (span < 0) {
      return res.status(400).json({ success: false, error: "La fecha final no puede ser anterior a la inicial" });
    }
    if (span + 1 > MAX_RANGE_DAYS) {
      return res.status(400).json({ success: false, error: `El rango no puede exceder ${MAX_RANGE_DAYS} días` });
    }

    const client = await pool.connect();
    try {
      await setSchema(client);
      const conflicts = await countConflicts(client, { from, to, lineNo: line });
      const { rows } = await client.query(
        `INSERT INTO ${TABLE} (holiday_date, name, line_no, created_by, created_at, updated_at)
         SELECT d::date, $3, $4, $5, NOW(), NOW()
           FROM generate_series($1::date, $2::date, interval '1 day') AS d
         ON CONFLICT (holiday_date, COALESCE(line_no, '*')) DO UPDATE SET
           name       = EXCLUDED.name,
           updated_at = NOW()
         RETURNING id, to_char(holiday_date,'YYYY-MM-DD') AS holiday_date, name, line_no`,
        [from, to, name, line, req.user?.id ?? null]
      );
      res.json({ success: true, holidays: rows, blocked: rows.length, conflicts });
    } catch (err) {
      console.error("\u274c POST /api/holidays:", err.message);
      res.status(500).json({ success: false, error: err.message });
    } finally {
      client.release();
    }
  });

  // ---- DELETE: one row (?id=) or one day (?date=[&lineNo=]) --------------
  app.delete("/api/holidays", authenticateToken, async (req, res) => {
    const id = req.query.id ?? req.body?.id ?? null;
    const date = req.query.date ?? req.body?.date ?? null;
    const hasLine = (req.query.lineNo ?? req.query.line_no ?? req.body?.lineNo) !== undefined;
    const line = lineOrNull(req.query.lineNo ?? req.query.line_no ?? req.body?.lineNo);

    if (id == null && !isYmd(date)) {
      return res.status(400).json({ success: false, error: "id o date (YYYY-MM-DD) es obligatorio" });
    }
    const client = await pool.connect();
    try {
      await setSchema(client);
      let rowCount;
      if (id != null) {
        ({ rowCount } = await client.query(`DELETE FROM ${TABLE} WHERE id = $1`, [parseInt(id, 10)]));
      } else if (hasLine) {
        // Explicit line (or "all lines" when blank) -> delete just that row.
        ({ rowCount } = await client.query(
          `DELETE FROM ${TABLE} WHERE holiday_date = $1 AND COALESCE(line_no,'*') = COALESCE($2,'*')`,
          [date, line]
        ));
      } else {
        // No line given -> free the whole day, line-specific rows included.
        ({ rowCount } = await client.query(`DELETE FROM ${TABLE} WHERE holiday_date = $1`, [date]));
      }
      res.json({ success: true, deleted: rowCount });
    } catch (err) {
      console.error("\u274c DELETE /api/holidays:", err.message);
      res.status(500).json({ success: false, error: err.message });
    } finally {
      client.release();
    }
  });
}

registerHolidays.initSchema = initSchema;
registerHolidays.isHoliday = isHoliday;
registerHolidays.holidaysBetween = holidaysBetween;
module.exports = registerHolidays;