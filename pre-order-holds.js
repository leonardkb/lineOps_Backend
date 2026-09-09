// ==========================================================================
// pre-order-holds.js
//
// PLAN BOARD "holds" for PRE#### pre-orders.
//
// A pre-order is not yet a real PO, so it can't live in line_assignments
// (that table's work_order_id is NOT NULL -> work_orders, and it feeds
// settle-day / completion / production, none of which apply to something with
// nothing to produce yet). Instead the planner can drop a PRE#### onto a
// LINE + DAY cell as a *hold*: a soft reservation that
//   • renders on the Plan Board as a violet PRE cell, and
//   • RESERVES that line/day's capacity, so a real PO can't silently take the
//     slot (server.js adds these into /available-lines and the POST
//     /line-assignments capacity guard).
// A hold never enters settle-day, completion or production. When the merchant
// converts the pre-order, pre-orders.js drops its holds and the planner then
// assigns the real PO(s) to days normally.
//
// Register-module in the same shape as merchant-plan.js / work-orders.js.
//
// --------------------------------------------------------------------------
// SETUP  (server.js)
// --------------------------------------------------------------------------
// 1. Near the other requires (by registerMerchantPlan):
//        const registerPreOrderHolds = require("./pre-order-holds");
// 2. In the async startup block, by the other initSchema calls:
//        await registerPreOrderHolds.initSchema({ pool, setSchema });
// 3. Where the other modules register:
//        registerPreOrderHolds(app, { authenticateToken, pool, setSchema });
//
// Gated by authenticateToken only. created_by records who placed the hold; the
// board is ORG-WIDE like the merchant plan.
//
// Endpoints
//   GET    /api/pre-order-holds[?from=&to=]     -> { success, holds:[...] }
//   POST   /api/pre-order-holds                 -> upsert ONE line/day/color
//   DELETE /api/pre-order-holds?id=             -> remove ONE hold row
//   DELETE /api/pre-order-holds?preOrderId=     -> remove ALL holds of a PRE
//
// POST item (camelCase from the board):
//   { preOrderId, lineNo, assignedDate,  // assignedDate = "YYYY-MM-DD"
//     quantity, color,
//     preOrderNo, customerName, styleCode, estilo }
// Re-dropping the same pre-order+line+day+color ADDS to the existing quantity
// (the board walks a PO across days, sending only what fits each day).
// ==========================================================================

async function initSchema({ pool, setSchema }) {
  const client = await pool.connect();
  try {
    await setSchema(client);
    await client.query(`
      CREATE TABLE IF NOT EXISTS pre_order_day_holds(
        id             BIGSERIAL PRIMARY KEY,
        pre_order_id   BIGINT NOT NULL REFERENCES pre_orders(id) ON DELETE CASCADE,
        line_no        TEXT   NOT NULL,
        assigned_date  DATE   NOT NULL,
        quantity       NUMERIC(12,2) NOT NULL DEFAULT 0,
        color          VARCHAR(50)  NOT NULL DEFAULT '',
        pre_order_no   VARCHAR(80),
        customer_name  VARCHAR(150),
        style_code     VARCHAR(20),
        estilo         VARCHAR(120),
        created_by     BIGINT,
        created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
        CONSTRAINT chk_pre_order_day_holds_qty CHECK (quantity > 0)
      );
    `);
    // One row per (pre-order, line, day, color): a re-drop merges into it.
    await client.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS uq_pre_order_day_holds
        ON pre_order_day_holds (pre_order_id, line_no, assigned_date, color);
    `);
    await client.query("CREATE INDEX IF NOT EXISTS idx_pre_order_day_holds_cell ON pre_order_day_holds(line_no, assigned_date);");
    await client.query("CREATE INDEX IF NOT EXISTS idx_pre_order_day_holds_pre ON pre_order_day_holds(pre_order_id);");
    console.log("\u2705 pre_order_day_holds table ready in prod_db_schema");
  } finally {
    client.release();
  }
}

// --- coercion helpers ------------------------------------------------------
const txt = (v, n) => (v == null ? null : String(v).trim().slice(0, n || 200) || null);
const col = (v) => String(v == null ? "" : v).trim().toUpperCase().slice(0, 50);
const numOr = (v, d = 0) => { const n = Number(v); return isNaN(n) ? d : n; };
const isYmd = (v) => typeof v === "string" && /^\d{4}-\d{2}-\d{2}$/.test(v);

function registerPreOrderHolds(app, deps) {
  const { authenticateToken, pool, setSchema } = deps;

  // ---- GET: all holds (optionally within a date window) ------------------
  app.get("/api/pre-order-holds", authenticateToken, async (req, res) => {
    const from = isYmd(req.query.from) ? req.query.from : null;
    const to = isYmd(req.query.to) ? req.query.to : null;
    const client = await pool.connect();
    try {
      await setSchema(client);
      const params = [];
      const where = [];
      if (from) { params.push(from); where.push(`assigned_date >= $${params.length}`); }
      if (to) { params.push(to); where.push(`assigned_date <= $${params.length}`); }
      const { rows } = await client.query(
        `SELECT id, pre_order_id, line_no,
                to_char(assigned_date, 'YYYY-MM-DD') AS assigned_date,
                quantity, color, pre_order_no, customer_name, style_code, estilo, updated_at
           FROM pre_order_day_holds
          ${where.length ? "WHERE " + where.join(" AND ") : ""}
          ORDER BY assigned_date, line_no, pre_order_no`,
        params
      );
      res.json({ success: true, holds: rows });
    } catch (err) {
      console.error("\u274c GET /api/pre-order-holds:", err.message);
      res.status(500).json({ success: false, error: err.message });
    } finally {
      client.release();
    }
  });

  // ---- POST: upsert one hold (merges quantity on conflict) ---------------
  app.post("/api/pre-order-holds", authenticateToken, async (req, res) => {
    const b = req.body || {};
    const preOrderId = b.preOrderId ?? b.pre_order_id ?? null;
    const lineNo = b.lineNo ?? b.line_no ?? null;
    const assignedDate = b.assignedDate ?? b.assigned_date ?? null;
    const quantity = numOr(b.quantity);
    if (preOrderId == null || lineNo == null || String(lineNo).trim() === "" || !isYmd(assignedDate) || quantity <= 0) {
      return res.status(400).json({ success: false, error: "preOrderId, lineNo, assignedDate (YYYY-MM-DD) y quantity (>0) son obligatorios" });
    }
    const client = await pool.connect();
    try {
      await setSchema(client);
      const { rows } = await client.query(
        `INSERT INTO pre_order_day_holds
           (pre_order_id, line_no, assigned_date, quantity, color,
            pre_order_no, customer_name, style_code, estilo, created_by, created_at, updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NOW(),NOW())
         ON CONFLICT (pre_order_id, line_no, assigned_date, color) DO UPDATE SET
           quantity      = pre_order_day_holds.quantity + EXCLUDED.quantity,
           pre_order_no  = EXCLUDED.pre_order_no,
           customer_name = EXCLUDED.customer_name,
           style_code    = EXCLUDED.style_code,
           estilo        = EXCLUDED.estilo,
           updated_at    = NOW()
         RETURNING id, to_char(assigned_date,'YYYY-MM-DD') AS assigned_date, quantity`,
        [
          parseInt(preOrderId, 10),
          String(lineNo).trim(),
          assignedDate,
          quantity,
          col(b.color),
          txt(b.preOrderNo ?? b.pre_order_no, 80),
          txt(b.customerName ?? b.customer_name, 150),
          txt(b.styleCode ?? b.style_code, 20),
          txt(b.estilo, 120),
          req.user?.id ?? null,
        ]
      );
      res.json({ success: true, hold: rows[0] });
    } catch (err) {
      console.error("\u274c POST /api/pre-order-holds:", err.message);
      res.status(500).json({ success: false, error: err.message });
    } finally {
      client.release();
    }
  });

  // ---- DELETE: one hold (?id=) or every hold of a pre-order (?preOrderId=)
  app.delete("/api/pre-order-holds", authenticateToken, async (req, res) => {
    const id = req.query.id ?? req.body?.id ?? null;
    const preOrderId = req.query.preOrderId ?? req.body?.preOrderId ?? null;
    if (id == null && preOrderId == null) {
      return res.status(400).json({ success: false, error: "id o preOrderId es obligatorio" });
    }
    const client = await pool.connect();
    try {
      await setSchema(client);
      const { rowCount } = id != null
        ? await client.query("DELETE FROM pre_order_day_holds WHERE id = $1", [parseInt(id, 10)])
        : await client.query("DELETE FROM pre_order_day_holds WHERE pre_order_id = $1", [parseInt(preOrderId, 10)]);
      res.json({ success: true, deleted: rowCount });
    } catch (err) {
      console.error("\u274c DELETE /api/pre-order-holds:", err.message);
      res.status(500).json({ success: false, error: err.message });
    } finally {
      client.release();
    }
  });
}

registerPreOrderHolds.initSchema = initSchema;
module.exports = registerPreOrderHolds;