// ==========================================================================
// pre-orders.js
//
// PRE-ÓRDENES: el pedido "ligero" que el merchant captura cuando el cliente
// todavía no manda todo el detalle. Solo pide lo mínimo:
//
//      ESTILO (tipo + modelo + correlativo)   ·   CLIENTE   ·   PIEZAS
//
// Cuando llega el resto de la información (tallas, colores, telas, entregas,
// SAM, foto…) la pre-orden se abre en NuevaOrdenWizard, se completa, y al
// crearse la(s) PO(s) reales la pre-orden queda marcada como CONVERTIDA con
// los números de orden que produjo. Nunca se borra el historial: la pre-orden
// se queda como el registro de cuándo se comprometió el pedido.
//
// Register-module con la misma forma que work-orders.js / merchant-plan.js:
// un require, un initSchema, un register.
//
// --------------------------------------------------------------------------
// SETUP  (server1.js)
// --------------------------------------------------------------------------
// 1. Junto a los otros requires (~línea 867, con registerMerchantPlan):
//        const registerPreOrders = require("./pre-orders");
//        registerPreOrders(app, { authenticateToken, pool, setSchema });
//
// 2. En el bloque async de arranque (~línea 622), con los otros initSchema:
//        await registerPreOrders.initSchema({ pool, setSchema });
//
//    Va después de que work_orders y customers existan (usa FKs a ambas).
//    Protegido solo con authenticateToken, igual que work-orders.js;
//    created_by / updated_by / converted_by usan req.user.id.
//
// Endpoints
//   GET    /api/pre-orders?status=pending|converted|cancelled|all
//   GET    /api/pre-orders/next-number      -> { sequence: "PRE0007" }
//   GET    /api/pre-orders/:id
//   POST   /api/pre-orders                  -> crea (auto-numera PRE####)
//   PUT    /api/pre-orders/:id              -> edita (solo si sigue pending)
//   POST   /api/pre-orders/:id/convert      -> { workOrderIds, workOrderNos }
//   POST   /api/pre-orders/:id/cancel
//   DELETE /api/pre-orders/:id
//
// Body de POST / PUT (camelCase, como lo manda PreOrdenWizard):
//   { tipo, modelo, correlativo, estilo?, styleDescription?,
//     customerId, clienteCode, customerPo?, pieces, samMinutes?, targetDate?, notes? }
// ==========================================================================

async function initSchema({ pool, setSchema }) {
  const client = await pool.connect();
  try {
    await setSchema(client);
    await client.query(`
      CREATE TABLE IF NOT EXISTS pre_orders(
        id                BIGSERIAL PRIMARY KEY,
        pre_order_no      VARCHAR(30)  NOT NULL UNIQUE,     -- PRE0001
        tipo              VARCHAR(3),
        modelo            VARCHAR(3),
        correlativo       VARCHAR(2),
        style_code        VARCHAR(20),                      -- tipo+modelo+correlativo
        estilo            VARCHAR(6),                       -- estilo cliente (opcional)
        style_description TEXT,
        customer_id       BIGINT REFERENCES customers(id) ON DELETE SET NULL,
        customer_name     VARCHAR(150),
        cliente_code      VARCHAR(3),
        customer_po       VARCHAR(60),
        pieces            NUMERIC(12,2) NOT NULL DEFAULT 0, -- lo cuantitativo
        sam_minutes       NUMERIC(10,2) NOT NULL DEFAULT 0,  -- SAM del estilo (opcional al capturar)
        target_date       DATE,
        notes             TEXT,
        status            VARCHAR(20)  NOT NULL DEFAULT 'pending', -- pending|converted|cancelled
        work_order_ids    BIGINT[]     NOT NULL DEFAULT '{}',      -- POs que salieron de aquí
        work_order_nos    TEXT,                                    -- "SKM0012-INV-…, SKM0013-…"
        converted_at      TIMESTAMPTZ,
        converted_by      BIGINT,
        created_by        BIGINT,
        updated_by        BIGINT,
        created_at        TIMESTAMPTZ  NOT NULL DEFAULT now(),
        updated_at        TIMESTAMPTZ  NOT NULL DEFAULT now(),
        CONSTRAINT chk_pre_order_status CHECK (status IN ('pending','partially_converted','converted','cancelled'))
      );
    `);
    // Migraciones aditivas (no-op si ya existen): CREATE TABLE IF NOT EXISTS
    // no agrega columnas a una tabla que ya vive en prod.
    await client.query("ALTER TABLE pre_orders ADD COLUMN IF NOT EXISTS customer_po VARCHAR(60);");
    await client.query("ALTER TABLE pre_orders ADD COLUMN IF NOT EXISTS target_date DATE;");
    // SAM guardado desde la captura: alimenta la carga equivalente de la ficha
    // de pre-orden en el tablero (eq/pza = SAM ÷ equivalencia) sin esperar a la PO.
    await client.query("ALTER TABLE pre_orders ADD COLUMN IF NOT EXISTS sam_minutes NUMERIC(10,2) NOT NULL DEFAULT 0;");
    await client.query("ALTER TABLE pre_orders ADD COLUMN IF NOT EXISTS notes TEXT;");
    await client.query("ALTER TABLE pre_orders ADD COLUMN IF NOT EXISTS work_order_ids BIGINT[] NOT NULL DEFAULT '{}';");
    await client.query("ALTER TABLE pre_orders ADD COLUMN IF NOT EXISTS work_order_nos TEXT;");
    // La semana en la que el merchant la puso en el tablero, guardada TAMBIÉN
    // aquí. merchant_week_plan es la fuente para pintar el tablero, pero al
    // convertir necesitamos la semana sí o sí: si esa fila se perdió (board
    // offline, POST fallido, tabla vieja), esta columna la salva y la PO nueva
    // aterriza donde estaba la pre-orden en vez de caer en "por asignar".
    await client.query("ALTER TABLE pre_orders ADD COLUMN IF NOT EXISTS planned_week DATE;");
    // Conversión incremental: una pre-orden con varias POs de cliente puede
    // convertirse por partes (cuando llega la tela de cada PO). converted_pieces
    // es el contador de lo ya convertido; mientras quede pieza por convertir la
    // pre-orden vive como 'partially_converted'. La constraint de status se
    // recrea para admitir el nuevo valor (no-op si ya lo admite).
    await client.query("ALTER TABLE pre_orders ADD COLUMN IF NOT EXISTS converted_pieces NUMERIC(12,2) NOT NULL DEFAULT 0;");
    await client.query("ALTER TABLE pre_orders DROP CONSTRAINT IF EXISTS chk_pre_order_status;");
    await client.query("ALTER TABLE pre_orders ADD CONSTRAINT chk_pre_order_status CHECK (status IN ('pending','partially_converted','converted','cancelled'));");
    await client.query("CREATE INDEX IF NOT EXISTS idx_pre_orders_status ON pre_orders(status);");
    await client.query("CREATE INDEX IF NOT EXISTS idx_pre_orders_customer ON pre_orders(customer_id);");
    await client.query("CREATE INDEX IF NOT EXISTS idx_pre_orders_created_at ON pre_orders(created_at);");
    console.log("\u2705 pre_orders table ready in prod_db_schema");
  } finally {
    client.release();
  }
}

// --- helpers ---------------------------------------------------------------
const up = (v, n) => String(v == null ? "" : v).toUpperCase().replace(/[^A-Z0-9]/g, "").slice(0, n);
const txt = (v, n) => (v == null ? null : String(v).trim().slice(0, n || 200) || null);
const numOr = (v, d = 0) => { const n = parseFloat(v); return isNaN(n) ? d : n; };
const isYmd = (v) => typeof v === "string" && /^\d{4}-\d{2}-\d{2}$/.test(v);
const dateOr = (v) => (isYmd(v) ? v : null);

const SELECT_COLS = `
  id, pre_order_no, tipo, modelo, correlativo, style_code, estilo,
  style_description, customer_id, customer_name, cliente_code, customer_po,
  pieces, sam_minutes,
  converted_pieces,
  GREATEST(pieces - converted_pieces, 0) AS remaining_pieces,
  to_char(target_date, 'YYYY-MM-DD') AS target_date,
  to_char(planned_week, 'YYYY-MM-DD') AS planned_week, notes, status,
  work_order_ids, work_order_nos,
  converted_at, converted_by, created_by, updated_by, created_at, updated_at
`;

// Lee y valida el cuerpo compartido por POST y PUT.
function parseBody(body) {
  const tipo = up(body?.tipo, 3);
  const modelo = up(body?.modelo, 3);
  const correlativo = up(body?.correlativo, 2);
  const customerId = body?.customerId == null || body.customerId === "" ? null : parseInt(body.customerId, 10);
  const pieces = numOr(body?.pieces, 0);
  // SAM es opcional al capturar (se confirma en la PO); 0 = todavía sin dato.
  const samMinutes = Math.max(0, numOr(body?.samMinutes ?? body?.sam_minutes ?? body?.sam, 0));

  const errors = [];
  if (!tipo) errors.push("tipo");
  if (!modelo) errors.push("modelo");
  if (correlativo.length !== 2) errors.push("correlativo (2 dígitos)");
  if (!customerId || isNaN(customerId)) errors.push("cliente");
  if (!(pieces > 0)) errors.push("piezas mayor a 0");

  return {
    errors,
    data: {
      tipo, modelo, correlativo,
      styleCode: `${tipo}${modelo}${correlativo}`,
      estilo: up(body?.estilo, 6) || null,
      styleDescription: txt(body?.styleDescription ?? body?.description, 2000),
      customerId,
      clienteCode: up(body?.clienteCode, 3) || null,
      customerPo: txt(body?.customerPo, 60),
      pieces,
      samMinutes,
      targetDate: dateOr(body?.targetDate),
      notes: txt(body?.notes, 2000),
    },
  };
}

async function nextPreOrderNo(client) {
  const { rows } = await client.query(
    `SELECT COALESCE(MAX((substring(pre_order_no from '^PRE([0-9]+)'))::int), 0) AS maxseq
       FROM pre_orders WHERE pre_order_no LIKE 'PRE%'`
  );
  return `PRE${String((rows[0]?.maxseq || 0) + 1).padStart(4, "0")}`;
}

// --------------------------------------------------------------------------
// TABLERO DE PLANEACIÓN
// --------------------------------------------------------------------------
// Una pre-orden aparece en merchant_week_plan como fila propia (pre_order_id,
// is_pre_order = true) en cuanto el merchant la arrastra a una semana. Cuando
// se convierte, esa fila deja de tener sentido: la semana se hereda a las POs
// que salieron de ella (una fila por color, con su desglose real) y la fila de
// pre-orden se borra.
//
// Es best-effort: si algo falla aquí, la conversión ya ocurrió y no se toca.
// Lo peor que pasa es que el merchant reacomode las nuevas POs a mano.
async function carryPlanToWorkOrders(client, preOrderId, workOrderIds, fallbackWeek = null, opts = {}) {
  // finalize=true (default) = comportamiento de siempre: al heredar la semana a
  // las POs, la ficha PRE del tablero se borra. finalize=false (conversión
  // parcial) mete las POs nuevas al tablero pero CONSERVA la ficha PRE, solo la
  // encoge por convertedPieces (lo que ya salió como PO real).
  const finalize = opts.finalize !== false;
  const convertedPieces = Math.max(0, Number(opts.convertedPieces) || 0);

  const { rows: planRows } = await client.query(
    `SELECT to_char(week_start,'YYYY-MM-DD') AS week_start, equivalence, created_by
       FROM merchant_week_plan WHERE pre_order_id = $1 LIMIT 1`,
    [preOrderId]
  );
  const plan = planRows[0] || null;
  // La semana sale de la fila del tablero; si no existe, de pre_orders.planned_week.
  const week = plan?.week_start || fallbackWeek || null;
  if (!week || !workOrderIds.length) {
    if (finalize) await client.query("DELETE FROM merchant_week_plan WHERE pre_order_id = $1", [preOrderId]);
    return 0;
  }

  const eq = Number(plan?.equivalence) > 0 ? Number(plan.equivalence) : 10;
  const { rows: wos } = await client.query(
    `SELECT id, work_order_no, customer_name, customer_po, style_code, estilo,
            style_description, sam_minutes, quantity, color
       FROM work_orders WHERE id = ANY($1::bigint[])`,
    [workOrderIds]
  );
  const { rows: lines } = await client.query(
    `SELECT work_order_id, color, estilo, talla, quantity
       FROM work_order_lines WHERE work_order_id = ANY($1::bigint[])`,
    [workOrderIds]
  );

  // Un renglón del tablero por (orden + color), con su desglose de tallas.
  const byWoColor = new Map();
  for (const l of lines) {
    const key = `${l.work_order_id}\u0000${l.color || ""}`;
    let g = byWoColor.get(key);
    if (!g) { g = { woId: l.work_order_id, color: l.color || "", cantidad: 0, sizes: new Map(), estilos: new Set() }; byWoColor.set(key, g); }
    const q = Number(l.quantity) || 0;
    g.cantidad += q;
    if (l.talla) g.sizes.set(l.talla, (g.sizes.get(l.talla) || 0) + q);
    if (l.estilo) g.estilos.add(l.estilo);
  }

  let inserted = 0;
  for (const wo of wos) {
    const groups = [...byWoColor.values()].filter((g) => String(g.woId) === String(wo.id));
    // Sin líneas (no debería pasar viniendo del wizard): una sola fila con el
    // color del encabezado y la cantidad total.
    const rows = groups.length ? groups : [{
      color: (wo.color || "").split(",")[0].trim(),
      cantidad: Number(wo.quantity) || 0,
      sizes: new Map(),
      estilos: new Set(wo.estilo ? [wo.estilo] : []),
    }];
    for (const g of rows) {
      const sam = Number(wo.sam_minutes) || 0;
      const eqPerPiece = sam / eq;
      await client.query(
        `INSERT INTO merchant_week_plan
           (work_order_id, pre_order_id, color, week_start, work_order_no, customer_name,
            customer_po, style_code, estilo, style_description, cantidad, sam_minutes,
            equivalence, eq_per_piece, eq_pieces, sizes, is_pre_order,
            created_by, updated_by, created_at, updated_at)
         VALUES ($1,NULL,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15::jsonb,false,$16,$16,NOW(),NOW())
         ON CONFLICT (COALESCE(work_order_id, 0), COALESCE(pre_order_id, 0), color)
         DO UPDATE SET week_start = EXCLUDED.week_start, updated_at = NOW()`,
        [
          wo.id,
          String(g.color || "").toUpperCase().slice(0, 50),
          week,
          wo.work_order_no, wo.customer_name, wo.customer_po,
          wo.style_code, [...g.estilos].join(", ") || wo.estilo, wo.style_description,
          g.cantidad, sam, eq, eqPerPiece, g.cantidad * eqPerPiece,
          JSON.stringify([...g.sizes.entries()].map(([talla, quantity]) => ({ talla, quantity }))),
          plan?.created_by ?? null,
        ]
      );
      inserted++;
    }
  }
  // Cierre de la ficha PRE en el tablero.
  if (finalize) {
    // Todo convertido: la ficha PRE ya no tiene sentido.
    await client.query("DELETE FROM merchant_week_plan WHERE pre_order_id = $1", [preOrderId]);
  } else if (convertedPieces > 0) {
    // Parcial: la ficha PRE SE QUEDA en su semana (para que el planner no la
    // pierda) pero encoge por lo que ya salió como PO real, manteniendo honesto
    // el snapshot del tablero. No se borra aunque llegue a 0.
    await client.query(
      `UPDATE merchant_week_plan
          SET cantidad  = GREATEST(cantidad - $2, 0),
              eq_pieces = GREATEST(cantidad - $2, 0) * eq_per_piece,
              updated_at = NOW()
        WHERE pre_order_id = $1`,
      [preOrderId, convertedPieces]
    );
  }
  return inserted;
}

// Suelta capacidad de los "holds" del Plan Board proporcional a lo convertido:
// camina los holds de la pre-orden (más antiguos primero) restando piezas hasta
// agotar convertedPieces. Los que llegan a 0 se borran; el resto baja su cantidad
// (siempre > 0, respetando el CHECK de la tabla).
async function shrinkPreOrderHolds(client, preOrderId, byPieces) {
  let remaining = Math.max(0, Number(byPieces) || 0);
  if (remaining <= 0) return;
  const { rows } = await client.query(
    `SELECT id, quantity FROM pre_order_day_holds
      WHERE pre_order_id = $1 ORDER BY assigned_date, id`,
    [preOrderId]
  );
  for (const h of rows) {
    if (remaining <= 0) break;
    const q = Number(h.quantity) || 0;
    if (q <= remaining) {
      await client.query("DELETE FROM pre_order_day_holds WHERE id = $1", [h.id]);
      remaining -= q;
    } else {
      await client.query(
        "UPDATE pre_order_day_holds SET quantity = quantity - $2, updated_at = NOW() WHERE id = $1",
        [h.id, remaining]
      );
      remaining = 0;
    }
  }
}

function registerPreOrders(app, deps) {
  const { authenticateToken, pool, setSchema } = deps;

  // ---- GET: siguiente número (para mostrarlo en el wizard) ---------------
  // Se registra ANTES de /:id — Express es first-match-wins y "next-number"
  // entraría como :id.
  app.get("/api/pre-orders/next-number", authenticateToken, async (req, res) => {
    const client = await pool.connect();
    try {
      await setSchema(client);
      res.json({ success: true, sequence: await nextPreOrderNo(client) });
    } catch (err) {
      console.error("\u274c GET /api/pre-orders/next-number:", err.message);
      res.status(500).json({ success: false, error: err.message });
    } finally {
      client.release();
    }
  });

  // ---- GET: lista --------------------------------------------------------
  // ?status=pending (default) | converted | cancelled | all
  // ?customerId=  ?search=  (busca en PRE####, estilo, cliente, descripción)
  app.get("/api/pre-orders", authenticateToken, async (req, res) => {
    const status = String(req.query.status || "pending").toLowerCase();
    const client = await pool.connect();
    try {
      await setSchema(client);
      const where = [];
      const params = [];
      if (["pending", "partially_converted", "converted", "cancelled"].includes(status)) {
        params.push(status);
        where.push(`status = $${params.length}`);
      }
      if (req.query.customerId) {
        params.push(parseInt(req.query.customerId, 10));
        where.push(`customer_id = $${params.length}`);
      }
      const search = txt(req.query.search, 80);
      if (search) {
        params.push(`%${search}%`);
        const p = `$${params.length}`;
        where.push(`(pre_order_no ILIKE ${p} OR style_code ILIKE ${p} OR estilo ILIKE ${p}
                     OR customer_name ILIKE ${p} OR style_description ILIKE ${p}
                     OR customer_po ILIKE ${p})`);
      }
      const { rows } = await client.query(
        `SELECT ${SELECT_COLS}
           FROM pre_orders
          ${where.length ? `WHERE ${where.join(" AND ")}` : ""}
          ORDER BY (status IN ('pending','partially_converted')) DESC, created_at DESC
          LIMIT 500`,
        params
      );
      // Conteos por estado para las pestañas del listado.
      const { rows: counts } = await client.query(
        "SELECT status, COUNT(*)::int AS n FROM pre_orders GROUP BY status"
      );
      const byStatus = counts.reduce((a, r) => ({ ...a, [r.status]: r.n }), {});
      res.json({
        success: true,
        preOrders: rows,
        counts: {
          pending: byStatus.pending || 0,
          partially_converted: byStatus.partially_converted || 0,
          converted: byStatus.converted || 0,
          cancelled: byStatus.cancelled || 0,
          all: counts.reduce((s, r) => s + r.n, 0),
        },
      });
    } catch (err) {
      console.error("\u274c GET /api/pre-orders:", err.message);
      res.status(500).json({ success: false, error: err.message });
    } finally {
      client.release();
    }
  });

  // ---- GET: una pre-orden (la usa el wizard para hidratarse) -------------
  app.get("/api/pre-orders/:id", authenticateToken, async (req, res) => {
    const client = await pool.connect();
    try {
      await setSchema(client);
      const { rows } = await client.query(
        `SELECT ${SELECT_COLS} FROM pre_orders WHERE id = $1`,
        [parseInt(req.params.id, 10)]
      );
      if (rows.length === 0) return res.status(404).json({ success: false, error: "Pre-orden no encontrada" });
      res.json({ success: true, preOrder: rows[0] });
    } catch (err) {
      console.error("\u274c GET /api/pre-orders/:id:", err.message);
      res.status(500).json({ success: false, error: err.message });
    } finally {
      client.release();
    }
  });

  // ---- POST: crear -------------------------------------------------------
  app.post("/api/pre-orders", authenticateToken, async (req, res) => {
    const { errors, data } = parseBody(req.body || {});
    if (errors.length) {
      return res.status(400).json({ success: false, error: `Faltan datos: ${errors.join(", ")}` });
    }
    const client = await pool.connect();
    try {
      await setSchema(client);
      const cust = await client.query("SELECT name, code FROM customers WHERE id = $1", [data.customerId]);
      if (cust.rows.length === 0) return res.status(400).json({ success: false, error: "Cliente no encontrado" });
      const customerName = cust.rows[0].name;
      const clienteCode = data.clienteCode || up(cust.rows[0].code, 3) || null;

      // El número se calcula y se inserta en el mismo intento; si dos merchants
      // guardan a la vez, el UNIQUE dispara 23505 y reintentamos con el siguiente.
      let row = null;
      for (let attempt = 0; attempt < 5 && !row; attempt++) {
        const preOrderNo = await nextPreOrderNo(client);
        try {
          const { rows } = await client.query(
            `INSERT INTO pre_orders
               (pre_order_no, tipo, modelo, correlativo, style_code, estilo,
                style_description, customer_id, customer_name, cliente_code,
                customer_po, pieces, sam_minutes, target_date, notes, status,
                created_by, updated_by, created_at, updated_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,'pending',$16,$16,NOW(),NOW())
             RETURNING ${SELECT_COLS}`,
            [preOrderNo, data.tipo, data.modelo, data.correlativo, data.styleCode,
             data.estilo, data.styleDescription, data.customerId, customerName,
             clienteCode, data.customerPo, data.pieces, data.samMinutes, data.targetDate,
             data.notes, req.user?.id ?? null]
          );
          row = rows[0];
        } catch (e) {
          if (e.code !== "23505") throw e;   // otra cosa: que suba
        }
      }
      if (!row) return res.status(409).json({ success: false, error: "No se pudo asignar número de pre-orden, intenta de nuevo" });
      res.json({ success: true, preOrder: row });
    } catch (err) {
      console.error("\u274c POST /api/pre-orders:", err.message);
      res.status(500).json({ success: false, error: err.message });
    } finally {
      client.release();
    }
  });

  // ---- PUT: editar (solo mientras siga pendiente) ------------------------
  app.put("/api/pre-orders/:id", authenticateToken, async (req, res) => {
    const { errors, data } = parseBody(req.body || {});
    if (errors.length) {
      return res.status(400).json({ success: false, error: `Faltan datos: ${errors.join(", ")}` });
    }
    const id = parseInt(req.params.id, 10);
    const client = await pool.connect();
    try {
      await setSchema(client);
      const cur = await client.query("SELECT status FROM pre_orders WHERE id = $1", [id]);
      if (cur.rows.length === 0) return res.status(404).json({ success: false, error: "Pre-orden no encontrada" });
      if (cur.rows[0].status === "converted") {
        return res.status(400).json({ success: false, error: "La pre-orden ya se convirtió en PO; edita la orden de producción" });
      }
      const cust = await client.query("SELECT name FROM customers WHERE id = $1", [data.customerId]);
      if (cust.rows.length === 0) return res.status(400).json({ success: false, error: "Cliente no encontrado" });

      const { rows } = await client.query(
        `UPDATE pre_orders SET
            tipo = $2, modelo = $3, correlativo = $4, style_code = $5, estilo = $6,
            style_description = $7, customer_id = $8, customer_name = $9,
            cliente_code = $10, customer_po = $11, pieces = $12, sam_minutes = $13,
            target_date = $14, notes = $15, updated_by = $16, updated_at = NOW()
          WHERE id = $1
          RETURNING ${SELECT_COLS}`,
        [id, data.tipo, data.modelo, data.correlativo, data.styleCode, data.estilo,
         data.styleDescription, data.customerId, cust.rows[0].name, data.clienteCode,
         data.customerPo, data.pieces, data.samMinutes, data.targetDate, data.notes,
         req.user?.id ?? null]
      );
      res.json({ success: true, preOrder: rows[0] });
    } catch (err) {
      console.error("\u274c PUT /api/pre-orders/:id:", err.message);
      res.status(500).json({ success: false, error: err.message });
    } finally {
      client.release();
    }
  });

  // ---- POST /:id/convert: marcar como convertida (total o parcial) -------
  // La llama NuevaOrdenWizard DESPUÉS de que POST /api/production-orders
  // regresó OK, con los IDs y números de las órdenes que se crearon.
  // Idempotente: volver a llamarla une los números nuevos a los ya guardados.
  //
  // CONVERSIÓN INCREMENTAL
  //   Una pre-orden puede traer varias POs de cliente y la tela de cada una
  //   llega por separado. Con { partial:true, convertedPieces } el wizard
  //   convierte SOLO la(s) PO cuya tela ya llegó: se crean sus POs reales, se
  //   heredan al tablero, y la pre-orden queda 'partially_converted' con su
  //   ficha PRE encogida por lo convertido — lista para volver a abrirse cuando
  //   llegue la siguiente tela. Sin `partial` (o cuando el contador ya cubrió
  //   todas las piezas) cierra la pre-orden con el comportamiento de siempre.
  app.post("/api/pre-orders/:id/convert", authenticateToken, async (req, res) => {
    const id = parseInt(req.params.id, 10);
    const ids = (Array.isArray(req.body?.workOrderIds) ? req.body.workOrderIds : [])
      .map((v) => parseInt(v, 10))
      .filter((v) => !isNaN(v));
    const nos = (Array.isArray(req.body?.workOrderNos) ? req.body.workOrderNos : [])
      .map((v) => txt(v, 80))
      .filter(Boolean);
    const partial = req.body?.partial === true;
    const convertedPieces = Math.max(0, numOr(req.body?.convertedPieces, 0));

    const client = await pool.connect();
    try {
      await setSchema(client);
      const cur = await client.query(
        `SELECT work_order_ids, work_order_nos, pieces, converted_pieces,
                to_char(planned_week,'YYYY-MM-DD') AS planned_week
           FROM pre_orders WHERE id = $1`, [id]);
      if (cur.rows.length === 0) return res.status(404).json({ success: false, error: "Pre-orden no encontrada" });

      const prevIds = cur.rows[0].work_order_ids || [];
      const prevNos = (cur.rows[0].work_order_nos || "").split(",").map((s) => s.trim()).filter(Boolean);
      const mergedIds = [...new Set([...prevIds.map(Number), ...ids])];
      const mergedNos = [...new Set([...prevNos, ...nos])];

      const totalPieces = Number(cur.rows[0].pieces) || 0;
      const newConvertedPieces = (Number(cur.rows[0].converted_pieces) || 0) + convertedPieces;
      // Final si el que llama no pidió parcial, o si el contador ya cubrió todo.
      const isFinal = !partial || newConvertedPieces >= totalPieces;
      const newStatus = isFinal ? "converted" : "partially_converted";

      const { rows } = await client.query(
        `UPDATE pre_orders SET
            status = $5,
            work_order_ids = $2,
            work_order_nos = $3,
            converted_pieces = $6,
            converted_at = CASE WHEN $7 THEN COALESCE(converted_at, NOW()) ELSE converted_at END,
            converted_by = CASE WHEN $7 THEN COALESCE(converted_by, $4) ELSE converted_by END,
            updated_by = $4,
            updated_at = NOW()
          WHERE id = $1
          RETURNING ${SELECT_COLS}`,
        [id, mergedIds, mergedNos.join(", ") || null, req.user?.id ?? null, newStatus, newConvertedPieces, isFinal]
      );

      // Hereda la semana del tablero a las POs nuevas. Nunca tumba la conversión.
      let planned = 0;
      try {
        if (isFinal) {
          // Comportamiento de siempre: borra la ficha PRE y suelta todos los holds.
          planned = await carryPlanToWorkOrders(client, id, mergedIds, cur.rows[0].planned_week, { finalize: true });
          await client.query("UPDATE pre_orders SET planned_week = NULL WHERE id = $1", [id]);
          // Protegido por si el módulo pre-order-holds aún no está desplegado.
          try {
            await client.query("DELETE FROM pre_order_day_holds WHERE pre_order_id = $1", [id]);
          } catch (e) {
            console.warn("\u26a0\ufe0f  no se pudieron soltar los holds de la pre-orden", id, e.message);
          }
        } else {
          // Parcial: mete las POs nuevas al tablero SIN borrar la ficha PRE, y
          // encoge la ficha + los holds por lo que ya salió. Conserva planned_week
          // para que el resto siga reservando su semana.
          planned = await carryPlanToWorkOrders(client, id, mergedIds, cur.rows[0].planned_week,
            { finalize: false, convertedPieces });
          try {
            await shrinkPreOrderHolds(client, id, convertedPieces);
          } catch (e) {
            console.warn("\u26a0\ufe0f  no se pudieron encoger los holds de la pre-orden", id, e.message);
          }
        }
      } catch (e) {
        console.warn("\u26a0\ufe0f  plan carry-over falló para pre-orden", id, e.message);
      }

      res.json({ success: true, preOrder: rows[0], plannedRows: planned, partial: !isFinal });
    } catch (err) {
      console.error("\u274c POST /api/pre-orders/:id/convert:", err.message);
      res.status(500).json({ success: false, error: err.message });
    } finally {
      client.release();
    }
  });

  // ---- POST /:id/week: la semana del tablero ------------------------------
  // La llama MerchantPlanner al soltar (o quitar) una pre-orden en una semana,
  // además de guardar la fila en merchant_week_plan. Es el respaldo que hace
  // que la PO nueva herede la semana aunque el tablero no haya podido guardar.
  // Body: { weekStart: "YYYY-MM-DD" } — null o vacío la limpia.
  app.post("/api/pre-orders/:id/week", authenticateToken, async (req, res) => {
    const id = parseInt(req.params.id, 10);
    const raw = req.body?.weekStart ?? req.body?.week_start ?? null;
    const weekStart = isYmd(raw) ? raw : null;
    if (raw && !weekStart) {
      return res.status(400).json({ success: false, error: "weekStart debe ser YYYY-MM-DD" });
    }
    const client = await pool.connect();
    try {
      await setSchema(client);
      const { rows } = await client.query(
        `UPDATE pre_orders
            SET planned_week = $2, updated_by = $3, updated_at = NOW()
          WHERE id = $1 AND status IN ('pending','partially_converted')
          RETURNING ${SELECT_COLS}`,
        [id, weekStart, req.user?.id ?? null]
      );
      if (rows.length === 0) {
        return res.status(400).json({ success: false, error: "No existe o ya no es planeable (pendiente o parcial)" });
      }
      res.json({ success: true, preOrder: rows[0] });
    } catch (err) {
      console.error("\u274c POST /api/pre-orders/:id/week:", err.message);
      res.status(500).json({ success: false, error: err.message });
    } finally {
      client.release();
    }
  });

  // ---- POST /:id/cancel --------------------------------------------------
  app.post("/api/pre-orders/:id/cancel", authenticateToken, async (req, res) => {
    const id = parseInt(req.params.id, 10);
    const client = await pool.connect();
    try {
      await setSchema(client);
      const { rows } = await client.query(
        `UPDATE pre_orders
            SET status = 'cancelled', updated_by = $2, updated_at = NOW()
          WHERE id = $1 AND status <> 'converted'
          RETURNING ${SELECT_COLS}`,
        [id, req.user?.id ?? null]
      );
      if (rows.length === 0) {
        return res.status(400).json({ success: false, error: "No existe o ya se convirtió en PO" });
      }
      // Cancelada = fuera del tablero de planeación (semana del merchant + holds del planner).
      await client.query("DELETE FROM merchant_week_plan WHERE pre_order_id = $1", [id])
        .catch((e) => console.warn("no se pudo limpiar el tablero:", e.message));
      await client.query("DELETE FROM pre_order_day_holds WHERE pre_order_id = $1", [id])
        .catch((e) => console.warn("no se pudieron limpiar los holds:", e.message));
      res.json({ success: true, preOrder: rows[0] });
    } catch (err) {
      console.error("\u274c POST /api/pre-orders/:id/cancel:", err.message);
      res.status(500).json({ success: false, error: err.message });
    } finally {
      client.release();
    }
  });

  // ---- DELETE ------------------------------------------------------------
  // Las convertidas no se borran: son el rastro de dónde nació la PO.
  app.delete("/api/pre-orders/:id", authenticateToken, async (req, res) => {
    const client = await pool.connect();
    try {
      await setSchema(client);
      const id = parseInt(req.params.id, 10);
      const { rowCount } = await client.query(
        "DELETE FROM pre_orders WHERE id = $1 AND status <> 'converted'",
        [id]
      );
      if (rowCount > 0) {
        await client.query("DELETE FROM merchant_week_plan WHERE pre_order_id = $1", [id])
          .catch((e) => console.warn("no se pudo limpiar el tablero:", e.message));
      }
      if (rowCount === 0) {
        return res.status(400).json({ success: false, error: "No existe o ya se convirtió en PO" });
      }
      res.json({ success: true, deleted: rowCount });
    } catch (err) {
      console.error("\u274c DELETE /api/pre-orders/:id:", err.message);
      res.status(500).json({ success: false, error: err.message });
    } finally {
      client.release();
    }
  });
}

registerPreOrders.initSchema = initSchema;
module.exports = registerPreOrders;