// ==========================================================================
// merchant-plan.js
//
// Persists the MERCHANT planning board: one row per work-order + color, holding
// the WEEK it's scheduled into (the Monday) plus a snapshot of the order detail
// as it was when planned (cantidad, SAM, equivalencia, equivalent pieces, size
// breakdown, estilo…). The snapshot means the plan stays readable for reporting
// even if the underlying order later changes.
//
// Register-module in the same shape as work-orders.js: one require, one
// initSchema, one register call.
//
// --------------------------------------------------------------------------
// SETUP  (server1.js / server.js)
// --------------------------------------------------------------------------
// 1. Near your other requires:
//        const registerMerchantPlan = require("./merchant-plan");
//
// 2. In the async startup block, alongside the other initSchema calls:
//        await registerMerchantPlan.initSchema({ pool, setSchema });
//
// 3. Where the other modules register:
//        registerMerchantPlan(app, { authenticateToken, pool, setSchema });
//
//    Gated by authenticateToken only (mirrors work-orders.js). created_by /
//    updated_by use req.user.id. The plan is ORG-WIDE (not per-user): every
//    merchant sees and edits the same board; the *_by columns just record who
//    last touched a row.
//
// Endpoints
//   GET    /api/merchant-plan            -> { success, plan:[...], equivalence }
//   POST   /api/merchant-plan            -> upsert ONE color (body below)
//   DELETE /api/merchant-plan?workOrderId=&color=   -> remove ONE color
//   PUT    /api/merchant-plan            -> replace the WHOLE board (bulk)
//
// POST / PUT item shape (camelCase from the React board):
//   { workOrderId | preOrderId, color, weekStart,  // weekStart = "YYYY-MM-DD" (Mon)
//     workOrderNo, customerName, customerPo,
//     styleCode, estilo, styleDescription,
//     cantidad, samMinutes, equivalence, eqPerPiece, eqPieces,
//     sizes:[{talla,quantity}], isPreOrder }        // isPreOrder = flagged pre-order
//
// FILAS DE PRE-ORDEN
//   El tablero acepta dos tipos de fila:
//     • work_order_id  -> una PO real (con color)
//     • pre_order_id   -> una PRE#### que todavía no se convierte en PO
//   Una fila tiene UNO de los dos (el otro va en NULL). Las de pre-orden nacen
//   con is_pre_order = true, así el merchant no tiene que marcarlas a mano.
//   Al convertir la pre-orden, pre-orders.js mueve la semana a las POs nuevas
//   y borra la fila de pre-orden.
// ==========================================================================

async function initSchema({ pool, setSchema }) {
  const client = await pool.connect();
  try {
    await setSchema(client);
    await client.query(`
      CREATE TABLE IF NOT EXISTS merchant_week_plan(
        id                BIGSERIAL PRIMARY KEY,
        work_order_id     BIGINT,                             -- NULL en filas de pre-orden
        pre_order_id      BIGINT,                             -- NULL en filas de PO real
        color             VARCHAR(50)  NOT NULL DEFAULT '',
        week_start        DATE         NOT NULL,           -- the Monday of the week
        work_order_no     VARCHAR(80),
        customer_name     VARCHAR(150),
        customer_po       VARCHAR(60),
        style_code        VARCHAR(20),
        estilo            VARCHAR(120),
        style_description TEXT,
        cantidad          NUMERIC(12,2) NOT NULL DEFAULT 0,
        sam_minutes       NUMERIC(10,2) NOT NULL DEFAULT 0,
        equivalence       NUMERIC(10,4) NOT NULL DEFAULT 10,
        eq_per_piece      NUMERIC(12,4) NOT NULL DEFAULT 0,
        eq_pieces         NUMERIC(14,4) NOT NULL DEFAULT 0,
        sizes             JSONB         NOT NULL DEFAULT '[]'::jsonb,
        is_pre_order      BOOLEAN       NOT NULL DEFAULT false,   -- flagged as a pre-order on the board
        created_by        BIGINT,
        updated_by        BIGINT,
        created_at        TIMESTAMPTZ   NOT NULL DEFAULT now(),
        updated_at        TIMESTAMPTZ   NOT NULL DEFAULT now(),
        CONSTRAINT chk_merchant_week_plan_owner
          CHECK (work_order_id IS NOT NULL OR pre_order_id IS NOT NULL)
      );
    `);
    // Migration: CREATE TABLE IF NOT EXISTS won't add columns to a table that
    // already exists in prod, so add is_pre_order explicitly (no-op if present).
    await client.query("ALTER TABLE merchant_week_plan ADD COLUMN IF NOT EXISTS is_pre_order BOOLEAN NOT NULL DEFAULT false;");
    // Filas de pre-orden: work_order_id pasa a ser opcional y aparece pre_order_id.
    // La unicidad ya no puede ser una constraint simple porque una de las dos
    // columnas siempre va en NULL (y NULL nunca choca con NULL en Postgres):
    // se reemplaza por un índice único sobre COALESCE de ambas + color.
    await client.query("ALTER TABLE merchant_week_plan ADD COLUMN IF NOT EXISTS pre_order_id BIGINT;");
    await client.query("ALTER TABLE merchant_week_plan ALTER COLUMN work_order_id DROP NOT NULL;");
    await client.query("ALTER TABLE merchant_week_plan DROP CONSTRAINT IF EXISTS uq_merchant_week_plan;");
    await client.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS uq_merchant_week_plan_row
        ON merchant_week_plan (COALESCE(work_order_id, 0), COALESCE(pre_order_id, 0), color);
    `);
    // CONJUNTOS: la chamarra y el pantalon son DOS filas (dos POs, dos cargas
    // de minutos distintas), pero UN solo compromiso con el cliente. Guardar el
    // conjunto deja que el tablero las pinte juntas sin fusionar la capacidad.
    // order-sets.js crea estas mismas columnas; aqui se repiten por si este
    // modulo migra primero (ADD COLUMN IF NOT EXISTS es idempotente).
    await client.query("ALTER TABLE merchant_week_plan ADD COLUMN IF NOT EXISTS set_id BIGINT;");
    await client.query("ALTER TABLE merchant_week_plan ADD COLUMN IF NOT EXISTS set_component VARCHAR(20);");
    await client.query("CREATE INDEX IF NOT EXISTS idx_merchant_week_plan_set ON merchant_week_plan(set_id);");
    await client.query("CREATE INDEX IF NOT EXISTS idx_merchant_week_plan_pre ON merchant_week_plan(pre_order_id);");
    await client.query("CREATE INDEX IF NOT EXISTS idx_merchant_week_plan_week ON merchant_week_plan(week_start);");
    await client.query("CREATE INDEX IF NOT EXISTS idx_merchant_week_plan_wo ON merchant_week_plan(work_order_id);");
    console.log("\u2705 merchant_week_plan table ready in prod_db_schema");
  } finally {
    client.release();
  }
}

// --- coercion helpers ------------------------------------------------------
const txt = (v, n) => (v == null ? null : String(v).trim().slice(0, n || 200) || null);
const col = (v) => String(v == null ? "" : v).trim().toUpperCase().slice(0, 50); // '' when no color
const numOr = (v, d = 0) => { const n = Number(v); return isNaN(n) ? d : n; };
const isYmd = (v) => typeof v === "string" && /^\d{4}-\d{2}-\d{2}$/.test(v);
const sizesJson = (v) => {
  if (!Array.isArray(v)) return "[]";
  const clean = v
    .filter((s) => s && s.talla != null)
    .map((s) => ({ talla: String(s.talla).slice(0, 6), quantity: numOr(s.quantity) }));
  return JSON.stringify(clean);
};

// One shared column list for INSERT ... ON CONFLICT.
const UPSERT_SQL = `
  INSERT INTO merchant_week_plan
    (work_order_id, pre_order_id, color, week_start, work_order_no, customer_name,
     customer_po, style_code, estilo, style_description, cantidad, sam_minutes,
     equivalence, eq_per_piece, eq_pieces, sizes, is_pre_order, set_id, set_component,
     created_by, updated_by, created_at, updated_at)
  VALUES
    ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16::jsonb,$17,$18,$19,$20,$20,NOW(),NOW())
  ON CONFLICT (COALESCE(work_order_id, 0), COALESCE(pre_order_id, 0), color) DO UPDATE SET
    week_start        = EXCLUDED.week_start,
    work_order_no     = EXCLUDED.work_order_no,
    customer_name     = EXCLUDED.customer_name,
    customer_po       = EXCLUDED.customer_po,
    style_code        = EXCLUDED.style_code,
    estilo            = EXCLUDED.estilo,
    style_description = EXCLUDED.style_description,
    cantidad          = EXCLUDED.cantidad,
    sam_minutes       = EXCLUDED.sam_minutes,
    equivalence       = EXCLUDED.equivalence,
    eq_per_piece      = EXCLUDED.eq_per_piece,
    eq_pieces         = EXCLUDED.eq_pieces,
    sizes             = EXCLUDED.sizes,
    is_pre_order      = EXCLUDED.is_pre_order,
    set_id            = EXCLUDED.set_id,
    set_component     = EXCLUDED.set_component,
    updated_by        = EXCLUDED.updated_by,
    updated_at        = NOW()
  RETURNING id
`;

// Build the positional params for one item. Returns null if the item is invalid.
function upsertParams(item, userId) {
  const workOrderId = item?.workOrderId ?? item?.work_order_id ?? null;
  const preOrderId = item?.preOrderId ?? item?.pre_order_id ?? null;
  const weekStart = item?.weekStart ?? item?.week_start;
  // Una fila es de PO o de pre-orden, nunca de las dos ni de ninguna.
  if ((workOrderId == null && preOrderId == null) || !isYmd(weekStart)) return null;
  // Las filas de pre-orden siempre viajan marcadas: es justo el punto de que el
  // merchant no tenga que taggearlas en el tablero.
  const isPre = preOrderId != null || item.isPreOrder === true || item.is_pre_order === true;
  return [
    preOrderId != null ? null : workOrderId, // $1
    preOrderId,                        // $2
    col(item.color),                   // $3
    weekStart,                         // $4
    txt(item.workOrderNo, 80),         // $5
    txt(item.customerName, 150),       // $6
    txt(item.customerPo, 60),          // $7
    txt(item.styleCode, 20),           // $8
    txt(item.estilo, 120),             // $9
    txt(item.styleDescription, 2000),  // $10
    numOr(item.cantidad),              // $11
    numOr(item.samMinutes),            // $12
    numOr(item.equivalence, 10),       // $13
    numOr(item.eqPerPiece),            // $14
    numOr(item.eqPieces),              // $15
    sizesJson(item.sizes),             // $16
    isPre,                             // $17
    // Conjunto (chamarra + pantalon). Null en una fila normal.
    item.setId ?? item.set_id ?? null, // $18
    txt(item.setComponent ?? item.set_component, 20), // $19
    userId ?? null,                    // $20 (created_by / updated_by)
  ];
}

function registerMerchantPlan(app, deps) {
  const { authenticateToken, pool, setSchema } = deps;

  // ---- GET: whole board ---------------------------------------------------
  app.get("/api/merchant-plan", authenticateToken, async (req, res) => {
    const client = await pool.connect();
    try {
      await setSchema(client);
      const { rows } = await client.query(
        `SELECT id, work_order_id, pre_order_id, color,
                to_char(week_start, 'YYYY-MM-DD') AS week_start,
                work_order_no, customer_name, customer_po, style_code, estilo,
                style_description, cantidad, sam_minutes, equivalence,
                eq_per_piece, eq_pieces, sizes, is_pre_order,
                set_id, set_component, updated_at
           FROM merchant_week_plan
          ORDER BY week_start, COALESCE(set_id, 0), work_order_no, color`
      );
      // The factor is global; surface the most-recently-touched value so the
      // board can restore the same equivalencia the plan was built with.
      const eqRow = rows.reduce((a, r) => (!a || new Date(r.updated_at) > new Date(a.updated_at) ? r : a), null);
      res.json({ success: true, plan: rows, equivalence: eqRow ? Number(eqRow.equivalence) : null });
    } catch (err) {
      console.error("\u274c GET /api/merchant-plan:", err.message);
      res.status(500).json({ success: false, error: err.message });
    } finally {
      client.release();
    }
  });

  // ---- POST: upsert one color --------------------------------------------
  app.post("/api/merchant-plan", authenticateToken, async (req, res) => {
    const params = upsertParams(req.body || {}, req.user?.id);
    if (!params) return res.status(400).json({ success: false, error: "workOrderId y weekStart (YYYY-MM-DD) son obligatorios" });
    const client = await pool.connect();
    try {
      await setSchema(client);
      const { rows } = await client.query(UPSERT_SQL, params);
      res.json({ success: true, id: rows[0].id });
    } catch (err) {
      console.error("\u274c POST /api/merchant-plan:", err.message);
      res.status(500).json({ success: false, error: err.message });
    } finally {
      client.release();
    }
  });

  // ---- DELETE: remove one color ------------------------------------------
  // Acepta ?workOrderId= (PO real) o ?preOrderId= (fila de pre-orden).
  app.delete("/api/merchant-plan", authenticateToken, async (req, res) => {
    const workOrderId = req.query.workOrderId ?? req.body?.workOrderId ?? null;
    const preOrderId = req.query.preOrderId ?? req.body?.preOrderId ?? null;
    if (workOrderId == null && preOrderId == null) {
      return res.status(400).json({ success: false, error: "workOrderId o preOrderId es obligatorio" });
    }
    const color = col(req.query.color ?? req.body?.color);
    const client = await pool.connect();
    try {
      await setSchema(client);
      const { rowCount } = preOrderId != null
        ? await client.query(
            "DELETE FROM merchant_week_plan WHERE pre_order_id = $1 AND color = $2",
            [preOrderId, color]
          )
        : await client.query(
            "DELETE FROM merchant_week_plan WHERE work_order_id = $1 AND color = $2",
            [workOrderId, color]
          );
      res.json({ success: true, deleted: rowCount });
    } catch (err) {
      console.error("\u274c DELETE /api/merchant-plan:", err.message);
      res.status(500).json({ success: false, error: err.message });
    } finally {
      client.release();
    }
  });

  // ---- PUT: replace the whole board (bulk save) --------------------------
  // Body: { items:[ ...upsert items ], equivalence }. Runs in a transaction:
  // clears the board, then inserts everything provided. Used by "save all",
  // "clear all", and to refresh snapshots when the equivalencia factor changes.
  app.put("/api/merchant-plan", authenticateToken, async (req, res) => {
    const items = Array.isArray(req.body?.items) ? req.body.items : [];
    const userId = req.user?.id ?? null;
    const client = await pool.connect();
    try {
      await setSchema(client);
      await client.query("BEGIN");
      await client.query("DELETE FROM merchant_week_plan");
      let saved = 0, skipped = 0;
      for (const item of items) {
        const params = upsertParams(item, userId);
        if (!params) { skipped++; continue; }
        await client.query(UPSERT_SQL, params);
        saved++;
      }
      await client.query("COMMIT");
      res.json({ success: true, saved, skipped });
    } catch (err) {
      await client.query("ROLLBACK").catch(() => {});
      console.error("\u274c PUT /api/merchant-plan:", err.message);
      res.status(500).json({ success: false, error: err.message });
    } finally {
      client.release();
    }
  });
}

registerMerchantPlan.initSchema = initSchema;
module.exports = registerMerchantPlan;