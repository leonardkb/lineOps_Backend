// ==========================================================================
// merchant-analytics.js
//
// Read-only analytics for the MERCHANT side, the twin of /api/quality/analytics:
// it answers "what did the merchants put into the system, when is it planned,
// where did the planner drop it, and how much of it is actually sewn?".
//
//   • POs created by each merchant          -> work_orders.created_by -> users
//   • The week each PO belongs to (semana)  -> merchant_week_plan.week_start
//                                              (falls back to the week the PO
//                                               was created)
//   • The day/line the planner assigned it  -> line_assignments
//   • Status + produced quantity            -> work_orders.status + the SAME
//                                              packing/finishing detection the
//                                              planner uses (work-orders.js)
//
// Nothing is captured twice: every number here is read from tables that already
// exist. Register-module in the same shape as work-orders.js / merchant-plan.js:
// one require, one initSchema, one register call.
//
// --------------------------------------------------------------------------
// SETUP  (server1.js)
// --------------------------------------------------------------------------
// 1. Near your other requires (~line 751, next to registerMerchantPlan):
//        const registerMerchantAnalytics = require("./merchant-analytics");
//
// 2. In the async startup block, alongside the other initSchema calls:
//        await registerMerchantAnalytics.initSchema({ pool, setSchema });
//
// 3. Where the other modules register:
//        registerMerchantAnalytics(app, { authenticateToken, pool, setSchema });
//
//    The role gate is INLINE (same as /api/quality/analytics) because
//    requireMerchantAccess is defined further down in server1.js than the
//    registration point.
//
// --------------------------------------------------------------------------
// IMPORTANT — who created the PO
// --------------------------------------------------------------------------
// work_orders never stored an author. initSchema adds work_orders.created_by
// and backfills it from merchant_week_plan.created_by where the board knows it,
// but NEW POs only get an author once you pass req.user.id in the two INSERTs
// inside work-orders.js. See PATCH-work-orders.md — until then every new PO
// shows up as "Sin merchant".
//
// Endpoint
//   GET /api/merchant/analytics
//     ?startDate=YYYY-MM-DD&endDate=YYYY-MM-DD   (defaults: last 30 days)
//     &merchant=<userId|all>                     (filter by author)
//     &status=<all|pending|assigned|in_progress|completed|cancelled>
//     &weekBasis=<plan|created>                  (which week a PO counts in)
//
//   The date range always filters on wo.created_at (when the merchant raised
//   the PO). weekBasis only decides which bucket the PO falls into:
//     plan    -> the Monday it sits on in the merchant board, and only when the
//                board doesn't know it, the week it was created
//     created -> always the week it was created
// ==========================================================================

// Reused so the packing/finishing detection lives in exactly ONE place.
const workOrders = require("./work-orders");

async function initSchema({ pool, setSchema }) {
  const client = await pool.connect();
  try {
    await setSchema(client);

    // Author of the PO. Nullable: everything created before this column existed
    // keeps NULL and is reported as "Sin merchant".
    await client.query(
      `ALTER TABLE work_orders ADD COLUMN IF NOT EXISTS created_by BIGINT REFERENCES users(id) ON DELETE SET NULL;`
    );
    // season is selected by the list route but was never created in server1.js.
    await client.query(`ALTER TABLE work_orders ADD COLUMN IF NOT EXISTS season VARCHAR(30);`);
    await client.query("CREATE INDEX IF NOT EXISTS idx_work_orders_created_by ON work_orders(created_by);");
    await client.query("CREATE INDEX IF NOT EXISTS idx_work_orders_created_at ON work_orders(created_at);");

    // Idempotent backfill: the merchant board already recorded who touched each
    // order, so old POs get an author instead of an empty dashboard column.
    // Only fills headers that are still NULL — it never overwrites.
    const { rowCount } = await client.query(`
      UPDATE work_orders wo
         SET created_by = src.created_by
        FROM (
          SELECT DISTINCT ON (work_order_id) work_order_id, created_by
            FROM merchant_week_plan
           WHERE created_by IS NOT NULL
           ORDER BY work_order_id, created_at
        ) src
       WHERE src.work_order_id = wo.id
         AND wo.created_by IS NULL;
    `);
    console.log(`\u2705 work_orders.created_by ready in prod_db_schema (backfilled ${rowCount})`);
  } finally {
    client.release();
  }
}

// --- helpers ---------------------------------------------------------------
const num = (v) => {
  const n = Number(v);
  return isFinite(n) ? n : 0;
};
const ymd = (d) => d.toISOString().split("T")[0];
const isYmd = (v) => typeof v === "string" && /^\d{4}-\d{2}-\d{2}$/.test(v);

const STATUSES = ["pending", "assigned", "in_progress", "completed", "cancelled"];
const READ_ROLES = [
  "engineer", "supervisor", "master", "soporte_it", "skyrina",
  "merchant", "admin", "planner",
];

// Monday of the ISO week a date belongs to. Used only for the fallback bucket
// computed in JS; Postgres date_trunc('week') already returns Monday.
function mondayOf(ymdStr) {
  const d = new Date(ymdStr + "T00:00:00");
  const dow = (d.getDay() + 6) % 7; // 0 = Monday
  d.setDate(d.getDate() - dow);
  return ymd(d);
}

// Push a value into a Map<key, accumulator>, creating the accumulator on first use.
function bump(map, key, seed, apply) {
  if (!map.has(key)) map.set(key, seed());
  apply(map.get(key));
}

function registerMerchantAnalytics(app, deps) {
  const { authenticateToken, pool, setSchema } = deps;

  app.get("/api/merchant/analytics", authenticateToken, async (req, res) => {
    const client = await pool.connect();
    try {
      await setSchema(client);

      if (!READ_ROLES.includes(req.user?.role)) {
        return res.status(403).json({ success: false, error: "Access denied" });
      }

      // ---- params -------------------------------------------------------
      const today = ymd(new Date());
      const defaultStart = (() => {
        const d = new Date();
        d.setDate(d.getDate() - 29);
        return ymd(d);
      })();
      const startDate = isYmd(req.query.startDate) ? req.query.startDate : defaultStart;
      const endDate = isYmd(req.query.endDate) ? req.query.endDate : today;
      const merchant = req.query.merchant && req.query.merchant !== "all" ? req.query.merchant : null;
      const status = STATUSES.includes(req.query.status) ? req.query.status : null;
      const weekBasis = req.query.weekBasis === "created" ? "created" : "plan";

      const params = [startDate, endDate];
      const filters = [];
      if (merchant === "none") {
        filters.push("wo.created_by IS NULL");
      } else if (merchant) {
        params.push(Number(merchant));
        filters.push(`wo.created_by = $${params.length}`);
      }
      if (status) {
        params.push(status);
        filters.push(`wo.status = $${params.length}`);
      }
      const extra = filters.length ? ` AND ${filters.join(" AND ")}` : "";

      // ---- 1. one row per PO --------------------------------------------
      // plan  = where the merchant board put it (a PO can hold several colors,
      //         so the earliest Monday wins)
      // asg   = what the planner did with it (cancelled cells don't count)
      const detailSql = `
        WITH plan AS (
          SELECT work_order_id,
                 MIN(week_start)  AS plan_week,
                 COUNT(*)::int    AS plan_colors,
                 MAX(updated_at)  AS plan_updated_at
            FROM merchant_week_plan
           GROUP BY work_order_id
        ),
        asg AS (
          SELECT work_order_id,
                 MIN(assigned_date)                 AS first_assigned_day,
                 MAX(assigned_date)                 AS last_assigned_day,
                 COUNT(DISTINCT assigned_date)::int AS assigned_days,
                 string_agg(DISTINCT line_no, ', ' ORDER BY line_no) AS assigned_lines,
                 COALESCE(SUM(assigned_quantity), 0) AS assigned_quantity
            FROM line_assignments
           WHERE status <> 'cancelled'
           GROUP BY work_order_id
        )
        SELECT
          wo.id,
          wo.work_order_no,
          wo.customer_name,
          wo.customer_po,
          wo.style_code,
          wo.estilo,
          wo.style_description,
          wo.color,
          wo.season,
          wo.status,
          wo.quantity,
          COALESCE(wo.total_to_produce, wo.quantity) AS target_quantity,
          to_char(wo.created_at AT TIME ZONE 'America/Mexico_City', 'YYYY-MM-DD') AS created_date,
          to_char(wo.created_at AT TIME ZONE 'America/Mexico_City', 'HH24:MI')    AS created_time,
          to_char(date_trunc('week', wo.created_at AT TIME ZONE 'America/Mexico_City')::date, 'YYYY-MM-DD') AS created_week,
          to_char(wo.commitment_date, 'YYYY-MM-DD') AS commitment_date,
          wo.created_by                              AS merchant_id,
          COALESCE(NULLIF(TRIM(u.full_name), ''), u.username, 'Sin merchant') AS merchant,
          to_char(p.plan_week, 'YYYY-MM-DD')         AS plan_week,
          COALESCE(p.plan_colors, 0)                 AS plan_colors,
          to_char(a.first_assigned_day, 'YYYY-MM-DD') AS first_assigned_day,
          to_char(a.last_assigned_day, 'YYYY-MM-DD')  AS last_assigned_day,
          COALESCE(a.assigned_days, 0)                AS assigned_days,
          a.assigned_lines,
          COALESCE(a.assigned_quantity, 0)            AS assigned_quantity
        FROM work_orders wo
        LEFT JOIN users u ON u.id = wo.created_by
        LEFT JOIN plan p  ON p.work_order_id = wo.id
        LEFT JOIN asg  a  ON a.work_order_id = wo.id
        WHERE (wo.created_at AT TIME ZONE 'America/Mexico_City')::date BETWEEN $1 AND $2${extra}
        ORDER BY wo.created_at DESC
      `;
      const { rows } = await client.query(detailSql, params);
      const ids = rows.map((r) => Number(r.id));

      // ---- 2. produced, per PO and per day -------------------------------
      // Same detection the planner sees (packing/finishing operations only), so
      // a PO can never show a different "producido" in two screens.
      let producedByOrder = new Map();
      let producedByDay = new Map();
      try {
        const byLine = await workOrders.producedByLineForMany(client, ids);
        for (const [orderId, lines] of byLine.entries()) {
          producedByOrder.set(orderId, lines.reduce((s, l) => s + num(l.finished), 0));
        }
        const perDay = await workOrders.producedByLineDayForMany(client, { workOrderIds: ids });
        for (const r of perDay) {
          producedByDay.set(r.day, num(producedByDay.get(r.day)) + num(r.produced));
        }
      } catch (err) {
        // Production stays at 0 rather than taking the whole dashboard down —
        // exactly how work-orders.js degrades when detection fails.
        console.warn("\u26a0\ufe0f  merchant analytics: produced sin resolver:", err.message);
      }

      // ---- 3. what the planner assigned, per day -------------------------
      const assignedByDay = new Map();
      if (ids.length) {
        const { rows: dayRows } = await client.query(
          `SELECT to_char(assigned_date, 'YYYY-MM-DD')      AS day,
                  COALESCE(SUM(assigned_quantity), 0)       AS assigned,
                  COUNT(DISTINCT work_order_id)::int        AS orders,
                  COUNT(DISTINCT line_no)::int              AS lines
             FROM line_assignments
            WHERE status <> 'cancelled' AND work_order_id = ANY($1)
            GROUP BY 1
            ORDER BY 1`,
          [ids]
        );
        for (const r of dayRows) assignedByDay.set(r.day, r);
      }

      // ---- 4. shape the rows the UI reads --------------------------------
      const detail = rows.map((r) => {
        const target = num(r.target_quantity) || num(r.quantity);
        const produced = num(producedByOrder.get(Number(r.id)));
        const week = weekBasis === "created" ? r.created_week : (r.plan_week || r.created_week);
        return {
          id: Number(r.id),
          work_order_no: r.work_order_no,
          customer_name: r.customer_name,
          customer_po: r.customer_po,
          style_code: r.style_code,
          estilo: r.estilo,
          style_description: r.style_description,
          color: r.color,
          season: r.season,
          status: r.status,
          quantity: num(r.quantity),
          target_quantity: target,
          produced_quantity: produced,
          balance: Math.max(target - produced, 0),
          progress: target > 0 ? Math.round((produced / target) * 100) : 0,
          merchant_id: r.merchant_id == null ? null : Number(r.merchant_id),
          merchant: r.merchant,
          created_date: r.created_date,
          created_time: r.created_time,
          created_week: r.created_week,
          commitment_date: r.commitment_date,
          plan_week: r.plan_week,
          plan_colors: Number(r.plan_colors) || 0,
          planned: !!r.plan_week,
          week,                                        // the bucket in use
          first_assigned_day: r.first_assigned_day,
          last_assigned_day: r.last_assigned_day,
          assigned_days: Number(r.assigned_days) || 0,
          assigned_lines: r.assigned_lines || null,
          assigned_quantity: num(r.assigned_quantity),
          assigned: !!r.first_assigned_day,
        };
      });

      // ---- 5. aggregates --------------------------------------------------
      const merchantMap = new Map();
      const weekMap = new Map();
      const statusMap = new Map();
      const customerMap = new Map();

      for (const d of detail) {
        const mKey = d.merchant_id == null ? "none" : String(d.merchant_id);
        bump(merchantMap, mKey,
          () => ({ merchant_id: d.merchant_id, merchant: d.merchant, pos: 0, pieces: 0, produced: 0, planned: 0, assigned: 0, completed: 0 }),
          (a) => {
            a.pos += 1;
            a.pieces += d.target_quantity;
            a.produced += d.produced_quantity;
            if (d.planned) a.planned += 1;
            if (d.assigned) a.assigned += 1;
            if (d.status === "completed") a.completed += 1;
          });

        if (d.week) {
          bump(weekMap, d.week,
            () => ({ week_start: d.week, pos: 0, pieces: 0, produced: 0, merchants: new Set() }),
            (a) => {
              a.pos += 1;
              a.pieces += d.target_quantity;
              a.produced += d.produced_quantity;
              a.merchants.add(d.merchant);
            });
        }

        bump(statusMap, d.status,
          () => ({ status: d.status, pos: 0, pieces: 0, produced: 0 }),
          (a) => { a.pos += 1; a.pieces += d.target_quantity; a.produced += d.produced_quantity; });

        bump(customerMap, d.customer_name || "Sin cliente",
          () => ({ customer_name: d.customer_name || "Sin cliente", pos: 0, pieces: 0, produced: 0 }),
          (a) => { a.pos += 1; a.pieces += d.target_quantity; a.produced += d.produced_quantity; });
      }

      const byMerchant = [...merchantMap.values()].sort((a, b) => b.pieces - a.pieces);
      const byWeek = [...weekMap.values()]
        .map((w) => ({ ...w, merchants: w.merchants.size }))
        .sort((a, b) => a.week_start.localeCompare(b.week_start));
      const byStatus = STATUSES
        .map((s) => statusMap.get(s) || { status: s, pos: 0, pieces: 0, produced: 0 })
        .filter((s) => s.pos > 0);
      const byCustomer = [...customerMap.values()].sort((a, b) => b.pieces - a.pieces).slice(0, 15);

      // Planner view: every day that has either an assignment or production.
      const dayKeys = new Set([...assignedByDay.keys(), ...producedByDay.keys()]);
      const byDay = [...dayKeys].sort().map((day) => {
        const a = assignedByDay.get(day);
        return {
          day,
          week_start: mondayOf(day),
          assigned: num(a?.assigned),
          produced: num(producedByDay.get(day)),
          orders: Number(a?.orders) || 0,
          lines: Number(a?.lines) || 0,
        };
      });

      const pieces = detail.reduce((s, d) => s + d.target_quantity, 0);
      const produced = detail.reduce((s, d) => s + d.produced_quantity, 0);
      const summary = {
        total_pos: detail.length,
        total_pieces: pieces,
        produced_pieces: produced,
        progress: pieces > 0 ? Math.round((produced / pieces) * 100) : 0,
        merchants: byMerchant.length,
        weeks: byWeek.length,
        planned_pos: detail.filter((d) => d.planned).length,
        assigned_pos: detail.filter((d) => d.assigned).length,
        unassigned_pos: detail.filter((d) => !d.assigned).length,
        completed_pos: detail.filter((d) => d.status === "completed").length,
        open_pieces: detail
          .filter((d) => d.status !== "completed" && d.status !== "cancelled")
          .reduce((s, d) => s + d.balance, 0),
      };

      res.json({
        success: true,
        range: { startDate, endDate },
        weekBasis,
        summary,
        byMerchant,
        byWeek,
        byStatus,
        byDay,
        byCustomer,
        detail,
      });
    } catch (err) {
      console.error("\u274c GET /api/merchant/analytics:", err.message);
      res.status(500).json({ success: false, error: err.message });
    } finally {
      client.release();
    }
  });
}

registerMerchantAnalytics.initSchema = initSchema;
module.exports = registerMerchantAnalytics;