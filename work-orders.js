// ==========================================================================
// work-orders.js  (consolidated)
//
// Register-module (like mechanics-summary.js) that owns BOTH:
//   • the work-order routes  (list / next-number / :id / create) with a
//     per-color breakdown  -> work_order_colors
//   • the production-order routes used by the step-by-step wizard, which
//     create master codes + PO together with a size×color breakdown
//     -> work_order_lines
//
// One require, one initSchema, one register call.
//
// --------------------------------------------------------------------------
// SETUP
// --------------------------------------------------------------------------
// 1. In server.js DELETE the original handlers this module re-registers
//    (Express is first-match-wins, so leaving them shadows these):
//        app.get("/api/work-orders", ...)      (the list route)
//        app.get("/api/work-orders/:id", ...)
//        app.post("/api/work-orders", ...)
//    LEAVE your PUT /:id and status routes as they are.
//
// 2. Near your other requires (~line 946):
//        const registerWorkOrders = require("./work-orders");
//
// 3. In the async startup block (~line 417), so initSchema can await:
//        await registerWorkOrders.initSchema({ pool, setSchema });
//
// 4. Where the other modules register (~line 949):
//        registerWorkOrders(app, {
//          authenticateToken,
//          pool,
//          setSchema,
//          generatePresignedGetUrl,   // presignCache (already required at top)
//          uploadBufferToS3,        // s3-raw (already required at top)
//          makeStylePhotoKey,       // s3-raw (already required at top)
//        });
//
//    The last two are only used by POST /api/production-orders (photo upload);
//    the plain work-order routes ignore them. Gated by authenticateToken only,
//    because requireMerchantAccess is defined lower in server.js than this
//    registration point. created_by uses req.user.id.
// --------------------------------------------------------------------------
// AUTOR DE LA ORDEN (work_orders.created_by)
// --------------------------------------------------------------------------
// Las dos rutas que crean ordenes (POST /api/work-orders y
// POST /api/production-orders) guardan req.user.id en work_orders.created_by,
// e initSchema crea la columna. Sin eso el dashboard de merchants no puede
// decir QUIEN capturo cada PO. Las ordenes anteriores quedan en NULL; el
// backfill desde merchant_week_plan vive en merchant-analytics.js.
// GET /api/work-orders ya regresa created_by y created_by_name.
// ==========================================================================

// CONJUNTOS (chamarra + pantalon vendidos como uno solo). Solo se usa el helper
// que inserta la cabecera; el esquema lo crea order-sets.initSchema, que DEBE
// correr antes que este (ver el orden en server1.js).
const { createSetInTx } = require("./order-sets");

// --- Startup migration: both breakdown tables ----------------------------
async function initSchema({ pool, setSchema }) {
  const client = await pool.connect();
  try {
    await setSchema(client);

    // per-color breakdown (used by POST /api/work-orders)
    await client.query(`
      CREATE TABLE IF NOT EXISTS work_order_colors(
        id BIGSERIAL PRIMARY KEY,
        work_order_id BIGINT NOT NULL REFERENCES work_orders(id) ON DELETE CASCADE,
        color VARCHAR(50) NOT NULL,
        quantity NUMERIC(12,2) NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        CONSTRAINT chk_wo_color_qty_positive CHECK (quantity > 0)
      );
    `);
    await client.query("CREATE INDEX IF NOT EXISTS idx_work_order_colors_wo ON work_order_colors(work_order_id);");
    await client.query("CREATE UNIQUE INDEX IF NOT EXISTS idx_work_order_colors_unique ON work_order_colors(work_order_id, color);");
    console.log("✅ work_order_colors table ready in prod_db_schema");

    // size × color breakdown (used by POST /api/production-orders / wizard)
    await client.query(`
      CREATE TABLE IF NOT EXISTS work_order_lines(
        id BIGSERIAL PRIMARY KEY,
        work_order_id BIGINT NOT NULL REFERENCES work_orders(id) ON DELETE CASCADE,
        master_code_id BIGINT REFERENCES master_codes(id) ON DELETE SET NULL,
        talla VARCHAR(3) NOT NULL,
        color VARCHAR(3) NOT NULL,
        estilo VARCHAR(6),
        quantity NUMERIC(12,2) NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        CONSTRAINT chk_wo_line_qty_positive CHECK (quantity > 0)
      );
    `);
    // Additive migration for databases created before per-color estilo existed.
    await client.query("ALTER TABLE work_order_lines ADD COLUMN IF NOT EXISTS estilo VARCHAR(6);");
    await client.query("ALTER TABLE work_order_lines ADD COLUMN IF NOT EXISTS customer_po VARCHAR(60);");
    // Delivery date, fabric, fabric code and yield are captured per line in
    // step 2 (one value per color+estilo row) and stored here. work_orders also
    // keeps a representative copy of the first line's values for the list view.
    await client.query("ALTER TABLE work_order_lines ADD COLUMN IF NOT EXISTS commitment_date DATE;");
    await client.query("ALTER TABLE work_order_lines ADD COLUMN IF NOT EXISTS fabric_name VARCHAR(150);");
    await client.query("ALTER TABLE work_order_lines ADD COLUMN IF NOT EXISTS fabric_code VARCHAR(60);");
    await client.query("ALTER TABLE work_order_lines ADD COLUMN IF NOT EXISTS yield_per_piece NUMERIC(10,4);");
    // Full list of telas for the line: [{ name, code, yield }, ...]. The scalar
    // fabric_name/fabric_code/yield_per_piece above are kept as a representative
    // (first-tela) copy for the header and list views.
    await client.query("ALTER TABLE work_order_lines ADD COLUMN IF NOT EXISTS fabrics JSONB NOT NULL DEFAULT '[]'::jsonb;");
    // La cantidad de cada talla se captura en dos partes (piezas): packing
    // (surtido) y SKU (talla sólida). quantity = packing_qty + sku_qty.
    await client.query("ALTER TABLE work_order_lines ADD COLUMN IF NOT EXISTS packing_qty NUMERIC(12,2) NOT NULL DEFAULT 0;");
    await client.query("ALTER TABLE work_order_lines ADD COLUMN IF NOT EXISTS sku_qty NUMERIC(12,2) NOT NULL DEFAULT 0;");
    // Reemplaza el esquema anterior de piezas-por-caja (nunca llegó a producción).
    await client.query("ALTER TABLE work_order_lines DROP COLUMN IF EXISTS pack_per_box;");
    await client.query("ALTER TABLE work_order_lines DROP COLUMN IF EXISTS sku_per_box;");
    await client.query("CREATE INDEX IF NOT EXISTS idx_work_order_lines_wo ON work_order_lines(work_order_id);");
    // Uniqueness must include estilo: the same color+talla can appear under two
    // different estilos within one PO. Drop the older (wo,talla,color) index and
    // recreate it with estilo so those legitimate rows don't collide.
    await client.query("DROP INDEX IF EXISTS idx_work_order_lines_unique;");
    await client.query("CREATE UNIQUE INDEX IF NOT EXISTS idx_work_order_lines_unique ON work_order_lines(work_order_id, talla, color, estilo);");
    console.log("✅ work_order_lines table ready in prod_db_schema");

    // Per-PO customer purchase-order reference (nullable).
    await client.query("ALTER TABLE work_orders ADD COLUMN IF NOT EXISTS customer_po VARCHAR(60);");

    // Representative copy of the first line's fabric/yield on the PO header, so
    // the list view and searches don't have to join work_order_lines.
    // commitment_date already exists on work_orders (created in server.js schema).
    await client.query("ALTER TABLE work_orders ADD COLUMN IF NOT EXISTS fabric_name VARCHAR(150);");
    await client.query("ALTER TABLE work_orders ADD COLUMN IF NOT EXISTS fabric_code VARCHAR(60);");
    await client.query("ALTER TABLE work_orders ADD COLUMN IF NOT EXISTS yield_per_piece NUMERIC(10,4);");

    // One-time backfill: POs created while these values were stored per line get
    // the first non-null line value promoted onto the header. Idempotent — it
    // only touches headers that are still empty.
    await client.query(`
      UPDATE work_orders wo
         SET fabric_name     = COALESCE(wo.fabric_name, src.fabric_name),
             fabric_code     = COALESCE(wo.fabric_code, src.fabric_code),
             yield_per_piece = COALESCE(wo.yield_per_piece, src.yield_per_piece),
             commitment_date = COALESCE(wo.commitment_date, src.commitment_date)
        FROM (
          SELECT DISTINCT ON (work_order_id)
                 work_order_id, fabric_name, fabric_code, yield_per_piece, commitment_date
            FROM work_order_lines
           WHERE fabric_name IS NOT NULL
              OR fabric_code IS NOT NULL
              OR yield_per_piece IS NOT NULL
              OR commitment_date IS NOT NULL
           ORDER BY work_order_id, id
        ) src
       WHERE src.work_order_id = wo.id
         AND (wo.fabric_name IS NULL OR wo.fabric_code IS NULL
              OR wo.yield_per_piece IS NULL OR wo.commitment_date IS NULL);
    `);
    console.log("\u2705 work_orders fabric/yield header columns ready in prod_db_schema");

    // Autor de la orden: QUIEN (que merchant) la capturo. Nullable, porque las
    // ordenes creadas antes de que existiera esta columna no lo saben. El
    // dashboard de merchants (merchant-analytics.js) lee de aqui y ademas
    // rellena las viejas desde merchant_week_plan.created_by.
    await client.query("ALTER TABLE work_orders ADD COLUMN IF NOT EXISTS created_by BIGINT REFERENCES users(id) ON DELETE SET NULL;");
    await client.query("CREATE INDEX IF NOT EXISTS idx_work_orders_created_by ON work_orders(created_by);");
    await client.query("CREATE INDEX IF NOT EXISTS idx_work_orders_created_at ON work_orders(created_at);");
    console.log("\u2705 work_orders.created_by ready in prod_db_schema");

    // Auto-cierre de celda: cuando el lider de linea captura >= lo asignado ese
    // dia, la asignacion se marca 'completed' y aqui se guarda CUANTAS piezas se
    // cosieron ese dia (produced_quantity) y CUANDO se cerro (completed_at).
    // Ambas nullable: las asignaciones abiertas las dejan en NULL.
    await client.query("ALTER TABLE line_assignments ADD COLUMN IF NOT EXISTS produced_quantity NUMERIC(12,2);");
    await client.query("ALTER TABLE line_assignments ADD COLUMN IF NOT EXISTS completed_at TIMESTAMPTZ;");
    console.log("\u2705 line_assignments produced_quantity/completed_at columns ready in prod_db_schema");
  } finally {
    client.release();
  }

  // Detecta como leer la produccion real desde las corridas del lider de linea.
  await resolveProducedSubquery({ pool, setSchema });
}

// The per-color breakdown as a JSON array, reused by both GET routes.
const COLORS_SUBQUERY = `
  COALESCE((
    SELECT json_agg(json_build_object('color', c.color, 'quantity', c.quantity) ORDER BY c.color)
    FROM work_order_colors c WHERE c.work_order_id = wo.id
  ), '[]') AS colors
`;

// Everything captured per color+estilo row in step 2. The expandable detail in
// WorkOrderTable renders straight from this; wo.fabric_name / fabric_code /
// yield_per_piece / commitment_date are the header-level copies.
const LINES_SUBQUERY = `
  COALESCE((
    SELECT json_agg(json_build_object(
             'talla', l.talla,
             'color', l.color,
             'estilo', l.estilo,
             'customerPo', l.customer_po,
             'commitmentDate', to_char(l.commitment_date, 'YYYY-MM-DD'),
             'fabricName', l.fabric_name,
             'fabricCode', l.fabric_code,
             'fabrics', COALESCE(l.fabrics, '[]'::jsonb),
             'yield', l.yield_per_piece,
             'packingQty', l.packing_qty,
             'skuQty', l.sku_qty,
             'quantity', l.quantity
           ) ORDER BY l.color, l.talla)
    FROM work_order_lines l WHERE l.work_order_id = wo.id
  ), '[]') AS lines
`;

// --------------------------------------------------------------------------
// PRODUCED QUANTITY (lo realmente cosido en piso)
// --------------------------------------------------------------------------
// La produccion NO se captura aparte: ya vive en la data por hora que el lider
// de linea guarda con POST /api/lineleader/update-sewed/:runId. Aqui solo se
// LEE para que el planeador vea el avance real contra la meta.
//
// Se cuentan unicamente las operaciones de empaque/terminado. Sumar todas las
// operaciones multiplicaria cada pieza por el numero de operaciones de la
// linea. Estas palabras clave son las mismas que usa finishedGarmentsTotal en
// LineLeaderPage.jsx: si cambias una, cambia la otra.
const PACKING_KEYWORDS = ["pack", "emp", "termin", "finish"];

// Se resuelve en initSchema contra el esquema real. Si algo no cuadra queda en
// 0 y la app sigue funcionando (la barra de produccion se queda en cero) en vez
// de tronar cada consulta del planeador.
let PRODUCED_SUBQUERY = "0::numeric AS produced_quantity";

// Resolvidos en resolveProducedSubquery() y guardados a nivel de modulo para que
// producedByLineFor() reutilice EXACTAMENTE la misma deteccion (mismo enlace
// line_runs -> orden y las mismas operaciones de empaque/terminado). Si quedan
// en null es que la deteccion fallo; el desglose por linea regresa vacio.
let RESOLVED_RUN_LINK = null;   // { column, on }  — on usa alias lr y wo
let PACKING_LIKES_SQL = null;   // "lower(oo.operation_name) LIKE '%..%' OR ..."

// Tablas reales donde vive la captura por hora del lider de linea:
//   line_runs                (id, ... , enlace a la orden)
//   operator_operations      (id, run_id, operation_name, ...)
//   operation_sewed_entries  (run_id, operation_id, slot_id, sewed_qty)
//
// Lo unico que varia entre instalaciones es COMO line_runs apunta a la orden,
// asi que eso si se detecta. Se prueban en orden; el primero que exista gana.
const RUN_LINK_CANDIDATES = [
  { column: "work_order_id", on: "lr.work_order_id = wo.id" },
  { column: "work_order_no", on: "lr.work_order_no = wo.work_order_no" },
  { column: "work_order",    on: "lr.work_order = wo.work_order_no" },
  { column: "po_id",         on: "lr.po_id = wo.id" },
];

async function tableColumns(client, table) {
  const { rows } = await client.query(
    `SELECT column_name FROM information_schema.columns
      WHERE table_schema = current_schema() AND table_name = $1`,
    [table]
  );
  return new Set(rows.map((r) => r.column_name));
}

// Construye el subquery de produccion.
// Wrapper para el flujo de migraciones: abre su propio client. initSchema lo
// sigue llamando igual que antes.
async function resolveProducedSubquery({ pool, setSchema }) {
  const client = await pool.connect();
  try {
    await setSchema(client);
    await detectProducedSubquery(client);
  } catch (err) {
    console.warn("\u26a0\ufe0f  resolveProducedSubquery fallo:", err.message);
  } finally {
    client.release();
  }
}

// La deteccion real. Recibe un client que YA tiene el search_path puesto, para
// poder reusar el de la peticion en curso sin abrir otra conexion.
async function detectProducedSubquery(client) {
  const runCols = await tableColumns(client, "line_runs");
  const sewCols = await tableColumns(client, "operation_sewed_entries");
  const opCols = await tableColumns(client, "operator_operations");

  const missing = [];
  if (runCols.size === 0) missing.push("line_runs");
  if (!sewCols.has("sewed_qty") || !sewCols.has("operation_id")) missing.push("operation_sewed_entries");
  if (!opCols.has("operation_name")) missing.push("operator_operations");

  if (missing.length) {
    console.warn(
      "\u26a0\ufe0f  produced_quantity quedara en 0. Tablas no encontradas o sin las " +
      `columnas esperadas: ${missing.join(", ")}.`
    );
    return;
  }

  const link = RUN_LINK_CANDIDATES.find((c) => runCols.has(c.column));
  if (!link) {
    console.warn(
      "\u26a0\ufe0f  produced_quantity quedara en 0: line_runs no tiene ninguna columna " +
      `conocida hacia la orden (${RUN_LINK_CANDIDATES.map((c) => c.column).join(", ")}). ` +
      "Agrega la correcta a RUN_LINK_CANDIDATES en work-orders.js."
    );
    return;
  }

  const likes = PACKING_KEYWORDS
    .map((k) => `lower(oo.operation_name) LIKE '%${k}%'`)
    .join(" OR ");

  // Solo las operaciones de empaque/terminado. Sumar todas las operaciones
  // contaria cada prenda una vez por operacion de la linea.
  PRODUCED_SUBQUERY = `
    COALESCE((
      SELECT SUM(se.sewed_qty)
        FROM operation_sewed_entries se
        JOIN operator_operations oo ON oo.id = se.operation_id
        JOIN line_runs lr           ON lr.id = se.run_id
       WHERE ${link.on}
         AND (${likes})
    ), 0) AS produced_quantity
  `;

  // Guardar para el desglose por linea (finished-warehouse los reutiliza).
  RESOLVED_RUN_LINK = link;
  PACKING_LIKES_SQL = likes;

  console.log(`\u2705 produced_quantity resuelto (line_runs.${link.column})`);

  // Aviso temprano: si ninguna operacion capturada coincide con las palabras
  // clave, el total sera 0 aunque la linea si este produciendo.
  const { rows } = await client.query(
    `SELECT COUNT(*)::int AS n FROM operator_operations oo WHERE ${likes}`
  );
  if (rows[0].n === 0) {
    console.warn(
      "\u26a0\ufe0f  Ninguna operacion coincide con PACKING_KEYWORDS " +
      `[${PACKING_KEYWORDS.join(", ")}]; produced_quantity sera 0. ` +
      "Revisa como se llaman tus operaciones de empaque y ajusta la lista."
    );
  }
}

// Detección resuelta una sola vez por proceso, bajo demanda.
//
// NO puede depender de runMigrations(): en Lambda RUN_MIGRATIONS=false y esa
// funcion ni siquiera se invoca, asi que initSchema nunca corre. Sin este
// candado PRODUCED_SUBQUERY se queda en el literal "0::numeric" durante toda la
// vida del proceso y el planeador ve 0 producido aunque el piso si haya cosido.
let producedResolution = null;

async function ensureProducedResolved(client) {
  if (RESOLVED_RUN_LINK) return;              // ya resuelto en este proceso
  if (!producedResolution) {
    producedResolution = detectProducedSubquery(client)
      .catch((err) => {
        // Error duro (p.ej. conexion): se loguea y se deja caer al finally, que
        // limpia el memo para reintentar en la siguiente peticion.
        console.warn("\u26a0\ufe0f  detectProducedSubquery fallo:", err.message);
      })
      .finally(() => {
        // CLAVE EN LAMBDA: detectProducedSubquery NO lanza cuando faltan las
        // tablas o no encuentra el enlace hacia la orden; solo hace warn y
        // regresa, dejando RESOLVED_RUN_LINK en null. Si dejaramos el memo
        // "resuelto" en ese estado, el contenedor entero se quedaria con
        // PRODUCED_SUBQUERY = "0::numeric" de por vida (producido = 0 en la lista
        // Y en el recalculo de estado). Eso pasa cuando la PRIMERA peticion que
        // toca produccion en ese contenedor corre antes de que el search_path del
        // tenant este puesto. Limpiando el memo cuando NO se resolvio, la
        // siguiente peticion (ya con el schema correcto) vuelve a intentar.
        if (!RESOLVED_RUN_LINK) producedResolution = null;
      });
  }
  await producedResolution;
}

const up = (v, n) => String(v || "").trim().toUpperCase().replace(/[^A-Z0-9]/g, "").slice(0, n);

const toTxt = (v) => (v == null ? null : String(v).trim() || null);
const toNum = (v) => (v === "" || v == null || isNaN(parseFloat(v)) ? null : parseFloat(v));

// Normalise a line's telas into [{ name, code, yield }], dropping blank names
// and duplicate name+code pairs. Each tela keeps its OWN yield. Accepts the new
// `fabrics` array or a legacy scalar {fabricName, fabricCode, yield}; `fb`
// supplies order-level fallbacks used by the create route.
const buildLineFabrics = (l, fb = {}) => {
  const out = [];
  const seen = new Set();
  const push = (name, code, y) => {
    const nm = toTxt(name);
    if (!nm) return;
    const cd = toTxt(code);
    const key = `${nm}|${cd || ""}`.toUpperCase();
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ name: nm, code: cd, yield: toNum(y) });
  };
  if (Array.isArray(l.fabrics) && l.fabrics.length) {
    for (const f of l.fabrics) push(f?.name, f?.code, f?.yield ?? f?.yieldPerPiece);
  } else {
    push(l.fabricName ?? fb.fabricName, l.fabricCode ?? fb.fabricCode, l.yield ?? fb.yieldPerPiece);
  }
  return out;
};

const VALID_STATUSES = ["pending", "assigned", "in_progress", "completed", "cancelled"];

/**
 * Registers the work-order + production-order routes on the given Express app.
 * @param {import('express').Express} app
 * @param {object} deps
 * @param {import('express').RequestHandler} deps.authenticateToken
 * @param {import('pg').Pool} deps.pool
 * @param {(client: any) => Promise<void>} deps.setSchema
 * @param {(filename: string) => string} deps.generatePresignedGetUrl
 * @param {(buffer: Buffer, key: string, mime: string) => Promise<{url:string}>} [deps.uploadBufferToS3]
 * @param {(filename: string) => string} [deps.makeStylePhotoKey]
 */
function registerWorkOrders(app, deps) {
  const { authenticateToken, pool, setSchema, uploadBufferToS3, makeStylePhotoKey, deleteFromS3 } = deps;
  // Different server files inject the presigned-GET helper under different names:
  //   server1.js → generatePresignedGetUrl (from s3-raw)
  //   server.js  → getCachedPresignedUrl   (from presignCache)
  // Accept whichever is provided so this module works with either.
  const generatePresignedGetUrl = deps.generatePresignedGetUrl || deps.getCachedPresignedUrl;
  // =====================================================================
  //  WORK-ORDER ROUTES (per-color breakdown)
  // =====================================================================

  // ---- GET /api/work-orders  (list) -------------------------------------
  app.get("/api/work-orders", authenticateToken, async (req, res) => {
    const client = await pool.connect();
    try {
      await setSchema(client);
      // PRODUCED_SUBQUERY se interpola abajo: hay que resolverlo ANTES de armar
      // el string de la consulta, o se cuela el literal 0.
      await ensureProducedResolved(client);
      const { status, lineNo, startDate, endDate } = req.query;

      let query = `
        SELECT
          wo.id, wo.work_order_no, wo.quantity, wo.customer_id, wo.customer_name,
          wo.style_description, wo.color, wo.fabric_supplier, wo.fabrics,
          wo.style_code, wo.estilo, wo.line_no,
          to_char(wo.run_date, 'YYYY-MM-DD') AS run_date, wo.warehouse_stock,
          wo.extra_quantity, wo.total_to_produce,
          to_char(wo.commitment_date, 'YYYY-MM-DD') AS commitment_date,
          wo.master_code_id, wo.sam_minutes, wo.customer_po,
          wo.fabric_name, wo.fabric_code, wo.yield_per_piece,
          wo.created_at, wo.updated_at,wo.season,wo.status,
          wo.created_by,
          -- CONJUNTO: NULL en una PO suelta. La tabla lo usa solo para pintar
          -- la insignia; produccion sigue viendo una PO normal.
          wo.set_id, wo.set_component, wo.set_ratio,
          (SELECT os.set_no FROM order_sets os WHERE os.id = wo.set_id) AS set_no,
          (SELECT COALESCE(NULLIF(TRIM(u.full_name), ''), u.username)
             FROM users u WHERE u.id = wo.created_by) AS created_by_name,
          ${COLORS_SUBQUERY},
          ${LINES_SUBQUERY},
          MAX(mc.photo_filename) as master_code_photo_filename,
          COALESCE(SUM(la.assigned_quantity) FILTER (WHERE la.status NOT IN ('cancelled', 'rejected')), 0) as assigned_quantity,
          ${PRODUCED_SUBQUERY}
        FROM work_orders wo
        LEFT JOIN line_assignments la ON la.work_order_id = wo.id
        LEFT JOIN master_codes mc ON mc.id = wo.master_code_id
        WHERE 1=1
      `;

      const params = [];
      let i = 1;
      if (status)    { query += ` AND wo.status = $${i++}`;     params.push(status); }
      if (lineNo)    { query += ` AND wo.line_no = $${i++}`;    params.push(lineNo); }
      if (startDate) { query += ` AND wo.run_date >= $${i++}`;  params.push(startDate); }
      if (endDate)   { query += ` AND wo.run_date <= $${i++}`;  params.push(endDate); }

      query += ` GROUP BY wo.id ORDER BY wo.created_at DESC`;

      const result = await client.query(query, params);
      const workOrders = result.rows.map((row) => {
        const url = row.master_code_photo_filename
          ? generatePresignedGetUrl(row.master_code_photo_filename, 3600)
          : null;
        delete row.master_code_photo_filename;
        return { ...row, master_code_photo_url: url };
      });

      res.json({ success: true, workOrders });
    } catch (err) {
      console.error("❌ Error fetching work orders:", err.message);
      res.status(500).json({ success: false, error: err.message });
    } finally {
      client.release();
    }
  });

  // ---- GET /api/work-orders/next-number ---------------------------------
  // MUST be registered before /:id so "next-number" isn't captured as an id.
  app.get("/api/work-orders/next-number", authenticateToken, async (req, res) => {
    const client = await pool.connect();
    try {
      await setSchema(client);
      const year = new Date().getFullYear();
      const prefix = `OP-${year}-`;
      const result = await client.query(
        `SELECT work_order_no FROM work_orders
         WHERE work_order_no LIKE $1
         ORDER BY work_order_no DESC LIMIT 1`,
        [`${prefix}%`]
      );
      let next = 1;
      if (result.rows.length > 0) {
        const last = parseInt(result.rows[0].work_order_no.split("-").pop(), 10);
        if (!isNaN(last)) next = last + 1;
      }
      res.json({ success: true, nextWorkOrderNo: `${prefix}${String(next).padStart(4, "0")}` });
    } catch (err) {
      console.error("❌ Error getting next work order number:", err.message);
      res.status(500).json({ success: false, error: err.message });
    } finally {
      client.release();
    }
  });

  // ---- GET /api/work-orders/:id -----------------------------------------
  app.get("/api/work-orders/:id", authenticateToken, async (req, res) => {
    const client = await pool.connect();
    try {
      await setSchema(client);
      await ensureProducedResolved(client);
      const { id } = req.params;

      const result = await client.query(
        `
        SELECT
          wo.*,
          ${COLORS_SUBQUERY},
          ${PRODUCED_SUBQUERY},
          (SELECT os.set_no FROM order_sets os WHERE os.id = wo.set_id) AS set_no,
          mc.code as master_code,
          mc.photo_filename as master_code_photo_filename,
          json_agg(
            json_build_object(
              'id', la.id, 'line_no', la.line_no, 'assigned_date', la.assigned_date,
              'assigned_quantity', la.assigned_quantity, 'status', la.status,
              'planned_start_date', la.planned_start_date, 'planned_end_date', la.planned_end_date
            )
          ) FILTER (WHERE la.id IS NOT NULL) as assignments
        FROM work_orders wo
        LEFT JOIN line_assignments la ON wo.id = la.work_order_id
        LEFT JOIN master_codes mc ON mc.id = wo.master_code_id
        WHERE wo.id = $1
        GROUP BY wo.id, mc.code, mc.photo_filename
        `,
        [id]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({ success: false, error: "Work order not found" });
      }

      const workOrder = result.rows[0];
      workOrder.master_code_photo_url = workOrder.master_code_photo_filename
        ? generatePresignedGetUrl(workOrder.master_code_photo_filename, 3600)
        : null;
      delete workOrder.master_code_photo_filename;

      res.json({ success: true, workOrder });
    } catch (err) {
      console.error("❌ Error fetching work order:", err.message);
      res.status(500).json({ success: false, error: err.message });
    } finally {
      client.release();
    }
  });

  // ---- GET /api/line-assignments/day-balances ---------------------------
  //
  // Una fila por celda del tablero (orden + linea + dia):
  //   assigned    piezas que el planeador puso en esa celda
  //   produced    piezas de empaque/terminado que reporto esa linea ESE dia
  //   balance     assigned - produced  (nunca negativo)
  //   run_linked  si existe corrida de esa linea ese dia ligada a la orden
  //
  // Hasta ahora la produccion se conocia a nivel ORDEN (produced_quantity) y a
  // nivel ORDEN+LINEA (producedByLineFor). Ninguno decia EN QUE DIA se cosio,
  // asi que el planeador no podia ver que el martes se asignaron 501 pzas y
  // solo entraron 301. line_runs si tiene run_date: agrupando por
  // (orden, linea, run_date) sale el tercer eje que faltaba.
  //
  // run_linked=false con balance completo casi siempre significa que el lider
  // guardo la corrida SIN seleccionar la orden, no que la linea no cosio. Sin
  // ese dato el planeador reasignaria piezas que ya estan hechas.
  //
  // Se agrupa por (orden, linea, dia) y NO por asignacion: una celda puede
  // tener varias filas en line_assignments (una por color) y la produccion no
  // se captura por color, asi que restarla contra cada fila la contaria de mas.
  app.get("/api/line-assignments/day-balances", authenticateToken, async (req, res) => {
    const client = await pool.connect();
    try {
      await setSchema(client);
      await ensureProducedResolved(client);

      const { from, to, workOrderId, lineNo, onlyPending } = req.query;

      // Sin deteccion resuelta no hay forma de saber que se cosio: mejor decirlo
      // que devolver saldos que serian el 100% de lo asignado.
      if (!RESOLVED_RUN_LINK || !PACKING_LIKES_SQL) {
        return res.json({
          success: true,
          resolved: false,
          rows: [],
          warning:
            "No se pudo ligar la captura de piso con las ordenes; el saldo por dia no esta disponible.",
        });
      }

      const params = [];
      const where = ["la.status NOT IN ('cancelled', 'rejected')"];

      if (from) { params.push(from); where.push(`la.assigned_date >= $${params.length}::date`); }
      if (to)   { params.push(to);   where.push(`la.assigned_date <= $${params.length}::date`); }
      if (workOrderId) { params.push(parseInt(workOrderId, 10)); where.push(`la.work_order_id = $${params.length}`); }
      if (lineNo)      { params.push(String(lineNo));            where.push(`la.line_no = $${params.length}`); }

      const { rows } = await client.query(
        `
        WITH prod AS (
          SELECT wo.id       AS work_order_id,
                 lr.line_no,
                 lr.run_date,
                 COALESCE(SUM(se.sewed_qty) FILTER (WHERE (${PACKING_LIKES_SQL})), 0) AS produced,
                 MAX(se.updated_at) AS last_reported_at
            FROM work_orders wo
            JOIN line_runs lr               ON ${RESOLVED_RUN_LINK.on}
            JOIN operation_sewed_entries se ON se.run_id = lr.id
            JOIN operator_operations oo     ON oo.id = se.operation_id
           GROUP BY wo.id, lr.line_no, lr.run_date
        ),
        runs AS (
          SELECT lr.line_no,
                 lr.run_date,
                 COUNT(*)::int AS n_runs
            FROM line_runs lr
           GROUP BY lr.line_no, lr.run_date
        ),
        cells AS (
          SELECT la.work_order_id,
                 la.line_no,
                 la.assigned_date,
                 SUM(la.assigned_quantity)       AS assigned,
                 ARRAY_AGG(la.id ORDER BY la.id) AS assignment_ids,
                 ARRAY_AGG(DISTINCT la.color) FILTER (WHERE la.color IS NOT NULL) AS colors
            FROM line_assignments la
           WHERE ${where.join(" AND ")}
           GROUP BY la.work_order_id, la.line_no, la.assigned_date
        )
        SELECT c.work_order_id,
               wo.work_order_no,
               wo.style_description,
               wo.customer_name,
               c.line_no,
               to_char(c.assigned_date, 'YYYY-MM-DD') AS assigned_date,
               c.assigned::numeric                     AS assigned,
               COALESCE(p.produced, 0)::numeric        AS produced,
               GREATEST(c.assigned - COALESCE(p.produced, 0), 0)::numeric AS balance,
               GREATEST(COALESCE(p.produced, 0) - c.assigned, 0)::numeric AS over_qty,
               c.assignment_ids,
               COALESCE(c.colors, ARRAY[]::text[])     AS colors,
               p.last_reported_at,
               COALESCE(r.n_runs, 0)                   AS runs_on_day,
               (p.produced IS NOT NULL)                AS run_linked,
               (COALESCE(r.n_runs, 0) > 1)             AS shared_day,
               (c.assigned_date <  CURRENT_DATE)       AS is_past,
               (c.assigned_date =  CURRENT_DATE)       AS is_today
          FROM cells c
          JOIN work_orders wo ON wo.id = c.work_order_id
          LEFT JOIN prod p ON p.work_order_id = c.work_order_id
                          AND p.line_no       = c.line_no
                          AND p.run_date      = c.assigned_date
          LEFT JOIN runs r ON r.line_no  = c.line_no
                          AND r.run_date = c.assigned_date
         ORDER BY c.assigned_date DESC, c.line_no
        `,
        params
      );

      const out = rows.map((r) => {
        const assigned = Number(r.assigned) || 0;
        const produced = Number(r.produced) || 0;
        const balance = Number(r.balance) || 0;
        const state = r.is_today ? "today"
          : !r.is_past ? "future"
          : balance > 0 ? "short"
          : "met";
        return {
          work_order_id: Number(r.work_order_id),
          work_order_no: r.work_order_no,
          style_description: r.style_description,
          customer_name: r.customer_name,
          line_no: r.line_no,
          assigned_date: r.assigned_date,
          assigned,
          produced,
          balance,
          over: Number(r.over_qty) || 0,
          pct: assigned > 0 ? Math.min((produced / assigned) * 100, 100) : 0,
          assignment_ids: r.assignment_ids || [],
          colors: r.colors || [],
          run_linked: !!r.run_linked,
          runs_on_day: Number(r.runs_on_day) || 0,
          shared_day: !!r.shared_day,
          is_past: !!r.is_past,
          is_today: !!r.is_today,
          last_reported_at: r.last_reported_at,
          state,
        };
      });

      const pending = out.filter((r) => r.is_past && r.balance > 0);

      res.json({
        success: true,
        resolved: true,
        rows: onlyPending ? pending : out,
        totals: {
          cells: out.length,
          pendingCells: pending.length,
          pendingPieces: Math.round(pending.reduce((s, r) => s + r.balance, 0)),
          unlinkedCells: pending.filter((r) => !r.run_linked && r.runs_on_day > 0).length,
        },
      });
    } catch (err) {
      console.error("\u274c Error en day-balances:", err.message);
      res.status(500).json({ success: false, error: err.message });
    } finally {
      client.release();
    }
  });

  // ---- POST /api/line-assignments/settle-day ----------------------------
  //
  // Cierra una celda por lo que REALMENTE se cosio y devuelve el saldo.
  //
  // Hace falta antes de reasignar. Si se crean celdas nuevas dejando la vieja
  // intacta, el martes queda con 501 pzas asignadas (de las que solo se hicieron
  // 301) MAS 200 el miercoles: 701 asignadas para 501 de trabajo real. Como el
  // pool del tablero se llena con total - assigned_quantity, la orden se veria
  // totalmente asignada y el saldo desapareceria de Estado de Ordenes justo
  // cuando el planeador mas lo necesita.
  //
  // El reparto entre colores es proporcional porque la produccion se captura por
  // orden, no por color: no hay dato para hacerlo de otra forma.
  app.post("/api/line-assignments/settle-day", authenticateToken, async (req, res) => {
    const client = await pool.connect();
    try {
      await setSchema(client);
      await ensureProducedResolved(client);

      const { workOrderId, lineNo, date } = req.body || {};
      if (!workOrderId || !lineNo || !date) {
        return res.status(400).json({ success: false, error: "Faltan workOrderId, lineNo o date." });
      }
      if (!RESOLVED_RUN_LINK || !PACKING_LIKES_SQL) {
        return res.status(409).json({
          success: false,
          error: "No se puede liquidar el dia: la captura de piso no esta ligada a las ordenes.",
        });
      }

      await client.query("BEGIN");

      // Bloquear las filas para que dos planeadores no liquiden el mismo dia al
      // mismo tiempo y el saldo salga reasignado dos veces.
      const cellRes = await client.query(
        `SELECT id, color, assigned_quantity
           FROM line_assignments
          WHERE work_order_id = $1
            AND line_no = $2
            AND assigned_date = $3::date
            AND status NOT IN ('cancelled', 'rejected')
          ORDER BY id
          FOR UPDATE`,
        [parseInt(workOrderId, 10), String(lineNo), date]
      );

      if (cellRes.rows.length === 0) {
        await client.query("ROLLBACK");
        return res.status(404).json({ success: false, error: "No hay asignacion en esa celda." });
      }

      const prodRes = await client.query(
        `SELECT COALESCE(SUM(se.sewed_qty) FILTER (WHERE (${PACKING_LIKES_SQL})), 0) AS produced
           FROM work_orders wo
           JOIN line_runs lr               ON ${RESOLVED_RUN_LINK.on}
           JOIN operation_sewed_entries se ON se.run_id = lr.id
           JOIN operator_operations oo     ON oo.id = se.operation_id
          WHERE wo.id = $1
            AND lr.line_no = $2
            AND lr.run_date = $3::date`,
        [parseInt(workOrderId, 10), String(lineNo), date]
      );

      const produced = Number(prodRes.rows[0]?.produced) || 0;
      const assigned = cellRes.rows.reduce((s, r) => s + (Number(r.assigned_quantity) || 0), 0);
      const balance = Math.max(assigned - produced, 0);

      if (balance <= 0) {
        await client.query(
          `UPDATE line_assignments SET status = 'completed', updated_at = now() WHERE id = ANY($1)`,
          [cellRes.rows.map((r) => r.id)]
        );
        await client.query("COMMIT");
        return res.json({
          success: true,
          settled: true,
          assigned, produced, balance: 0,
          updated: cellRes.rows.length, deleted: 0,
          message: "El dia alcanzo su meta; no hay saldo que reasignar.",
        });
      }

      // Reparto proporcional. El residuo del redondeo va a la fila mas grande,
      // para que la suma de las partes sea exactamente `produced` y no aparezcan
      // saldos fantasma de 1 pza.
      const parts = cellRes.rows.map((r) => ({
        id: r.id,
        color: r.color,
        assigned: Number(r.assigned_quantity) || 0,
      }));
      let repartido = 0;
      parts.forEach((r) => {
        r.keep = assigned > 0 ? Math.floor((r.assigned / assigned) * produced) : 0;
        repartido += r.keep;
      });
      const residuo = produced - repartido;
      if (residuo > 0) {
        parts.slice().sort((a, b) => b.assigned - a.assigned)[0].keep += residuo;
      }

      const toDelete = parts.filter((r) => r.keep <= 0).map((r) => r.id);
      const toUpdate = parts.filter((r) => r.keep > 0);

      for (const r of toUpdate) {
        await client.query(
          `UPDATE line_assignments
              SET assigned_quantity = $2, status = 'completed', updated_at = now()
            WHERE id = $1`,
          [r.id, r.keep]
        );
      }
      // assigned_quantity tiene CHECK (> 0): una celda sin nada cosido no se
      // puede dejar en cero, hay que borrarla.
      if (toDelete.length) {
        await client.query(`DELETE FROM line_assignments WHERE id = ANY($1)`, [toDelete]);
      }

      await client.query("COMMIT");

      // El saldo NO se reasigna aqui a proposito: a donde van esas piezas es
      // decision del planeador (misma linea manana, otra linea, o de regreso al
      // pool). El frontend recibe `balance` y llama a la asignacion normal, que
      // ya sabe repartir respetando la capacidad diaria de cada linea.
      res.json({
        success: true,
        settled: true,
        assigned,
        produced,
        balance,
        updated: toUpdate.length,
        deleted: toDelete.length,
        colors: parts.filter((r) => r.color).map((r) => r.color),
      });
    } catch (err) {
      await client.query("ROLLBACK").catch(() => {});
      console.error("\u274c Error en settle-day:", err.message);
      res.status(500).json({ success: false, error: err.message });
    } finally {
      client.release();
    }
  });

  // ---- POST /api/work-orders --------------------------------------------
  app.post("/api/work-orders", authenticateToken, async (req, res) => {
    const client = await pool.connect();
    try {
      await setSchema(client);

      const {
        workOrderNo, warehouseStock, extraQuantity, totalToProduce, totalQuantity,
        commitmentDate, customerId, styleDescription, styleCode, estilo, color,
        fabricSupplier, fabrics, lineNo, runDate, masterCodeId, samMinutes,
        colors,
      } = req.body;

      const colorRows = Array.isArray(colors)
        ? colors
            .map((c) => ({ color: String(c.color || "").trim().toUpperCase(), quantity: parseFloat(c.quantity) }))
            .filter((c) => c.color && !isNaN(c.quantity) && c.quantity > 0)
        : [];

      const orderedQty = colorRows.reduce((s, c) => s + c.quantity, 0);
      const resolvedQuantity =
        orderedQty > 0 ? orderedQty : parseFloat(totalQuantity) || parseFloat(totalToProduce);

      const wStock = parseFloat(warehouseStock) || 0;
      const xtra = parseFloat(extraQuantity) || 0;
      const resolvedTotalToProduce =
        totalToProduce != null && totalToProduce !== ""
          ? parseFloat(totalToProduce)
          : Math.max(resolvedQuantity - wStock + xtra, 0);

      if (!workOrderNo || !customerId || !styleDescription) {
        return res.status(400).json({ success: false, error: "Missing required fields: workOrderNo, customerId, styleDescription" });
      }
      if (colorRows.length === 0 && !resolvedQuantity) {
        return res.status(400).json({ success: false, error: "Provide at least one color with a quantity (or a total quantity)." });
      }

      await client.query("BEGIN");

      const existingCheck = await client.query("SELECT id FROM work_orders WHERE work_order_no = $1", [workOrderNo]);
      if (existingCheck.rows.length > 0) {
        await client.query("ROLLBACK");
        return res.status(400).json({ success: false, error: "Work order number already exists" });
      }

      const customerResult = await client.query("SELECT name FROM customers WHERE id = $1", [parseInt(customerId)]);
      if (customerResult.rows.length === 0) {
        await client.query("ROLLBACK");
        return res.status(400).json({ success: false, error: "Customer not found" });
      }
      const customerName = customerResult.rows[0].name;

      let resolvedSamMinutes = samMinutes ? parseFloat(samMinutes) : null;
      if (masterCodeId && resolvedSamMinutes === null) {
        const mc = await client.query("SELECT sam_minutes FROM master_codes WHERE id = $1", [parseInt(masterCodeId)]);
        if (mc.rows.length > 0) resolvedSamMinutes = parseFloat(mc.rows[0].sam_minutes);
      }

      const colorSummary = colorRows.length > 0 ? colorRows.map((c) => c.color).join(", ") : color || null;

      const result = await client.query(
        `
        INSERT INTO work_orders (
          work_order_no, quantity, customer_id, customer_name, style_description,
          color, fabric_supplier, style_code, estilo, fabrics, line_no, run_date,
          warehouse_stock, extra_quantity, total_to_produce, commitment_date,
          master_code_id, sam_minutes, created_by, created_at, updated_at, status
        )
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,NOW(),NOW(),'pending')
        RETURNING *
        `,
        [
          workOrderNo, resolvedQuantity, parseInt(customerId), customerName, styleDescription,
          colorSummary, fabricSupplier || (Array.isArray(fabrics) ? fabrics[0] : null) || null,
          styleCode || null, estilo || null, Array.isArray(fabrics) ? fabrics : [], lineNo || null,
          runDate || null, wStock, xtra, resolvedTotalToProduce, commitmentDate || null,
          masterCodeId ? parseInt(masterCodeId) : null, resolvedSamMinutes,
          req.user?.id ?? null,                       // created_by: el merchant que la capturo
        ]
      );

      const workOrder = result.rows[0];

      for (const c of colorRows) {
        await client.query(
          `INSERT INTO work_order_colors (work_order_id, color, quantity) VALUES ($1, $2, $3)`,
          [workOrder.id, c.color, c.quantity]
        );
      }

      await client.query("COMMIT");

      workOrder.colors = colorRows;
      if (workOrder.master_code_id) {
        const mcResult = await client.query("SELECT photo_filename FROM master_codes WHERE id = $1", [workOrder.master_code_id]);
        workOrder.master_code_photo_url = mcResult.rows[0]?.photo_filename
          ? generatePresignedGetUrl(mcResult.rows[0].photo_filename, 3600)
          : null;
      }

      res.json({ success: true, message: "Work order created successfully", workOrder });
    } catch (err) {
      await client.query("ROLLBACK").catch(() => {});
      console.error("❌ Error creating work order:", err.message);
      if (err.code === "23505") {
        return res.status(400).json({ success: false, error: "Work order number already exists" });
      }
      res.status(500).json({ success: false, error: err.message });
    } finally {
      client.release();
    }
  });

  // =====================================================================
  //  PRODUCTION-ORDER ROUTES (wizard: master codes + PO, size×color grid)
  // =====================================================================

  // ---- next PO number: SKM#### sequence ---------------------------------
  app.get("/api/production-orders/next-number", authenticateToken, async (req, res) => {
    const client = await pool.connect();
    try {
      await setSchema(client);
      const result = await client.query(
        `SELECT COALESCE(MAX((substring(work_order_no from '^SKM([0-9]+)'))::int), 0) AS maxseq
         FROM work_orders WHERE work_order_no LIKE 'SKM%'`
      );
      const next = (result.rows[0]?.maxseq || 0) + 1;
      res.json({ success: true, sequence: `SKM${String(next).padStart(4, "0")}` });
    } catch (err) {
      console.error("❌ Error getting next PO number:", err.message);
      res.status(500).json({ success: false, error: err.message });
    } finally {
      client.release();
    }
  });

  // ---- combined create: master codes + one or more POs ----------------
  // Accepts EITHER:
  //   • { ...style, lines, commitmentDate, workOrderNo? }       → 1 PO (legacy)
  //   • { ...style, orders: [{ lines, commitmentDate }, ...] }  → N POs
  // The wizard groups color rows by (color+estilo): distinct rows go into one
  // PO; each REPEATED (color+estilo) row is sent as its own entry in `orders`
  // and becomes its own auto-numbered PO. Same customer for all.
  app.post("/api/production-orders", authenticateToken, async (req, res) => {
    const client = await pool.connect();
    let photoUrl = null;
    let photoKey = null;
    try {
      await setSchema(client);

      const {
        tipo, modelo, correlativo,
        clienteCode, customerId, estilo,
        description, sam,
        photoKey: incomingPhotoKey,   // browser uploaded the image straight to S3 (presigned PUT)
        lines, orders, workOrderNo,
        commitmentDate, season, fabrics, warehouseStock, extraQuantity, customerPo,
        // PO-header fabric/yield (legacy single-PO payload; per-order values
        // inside `orders` win when present).
        fabricName: bodyFabricName, fabricCode: bodyFabricCode, yield: bodyYield,
        // ---- CONJUNTOS (chamarra + pantalon vendidos como una unidad) ------
        // components[] = una PRENDA por elemento, cada una con su propio estilo
        // (tipo/modelo/correlativo), su SAM, su descripcion, su foto y su ratio
        // (piezas por conjunto). Sin components[] el cuerpo es el de siempre y
        // todo se comporta exactamente igual que antes: UNA prenda.
        components,
        // { label, notes, setNo } — solo se usa cuando hay 2+ componentes.
        set: setMeta,
      } = req.body;

      const CLI = up(clienteCode, 3), EST = up(estilo, 6); // fallback default only

      const txt = (v) => (v == null ? null : String(v).trim() || null);
      const num = (v) =>
        v === "" || v == null || isNaN(parseFloat(v)) ? null : parseFloat(v);
      const ratioOf = (v) => {
        const n = parseFloat(v);
        return !isFinite(n) || n <= 0 ? 1 : n;
      };

      // Una prenda suelta es "un conjunto de un solo componente": asi el resto
      // del handler tiene UN solo camino en vez de dos.
      const rawComponents = Array.isArray(components) && components.length > 0
        ? components
        : [{ tipo, modelo, correlativo, estilo, description, sam, photoKey: incomingPhotoKey,
             orders, lines, warehouseStock, extraQuantity }];
      const isSet = rawComponents.length > 1;

      // El estilo del primer componente sigue siendo el "estilo de la orden"
      // para todo lo que espera un solo styleCode (numero de PO, respuestas).
      const T = up(rawComponents[0].tipo ?? tipo, 3);
      const M = up(rawComponents[0].modelo ?? modelo, 3);
      const C = up(rawComponents[0].correlativo ?? correlativo, 2);
      const styleCode = `${T}${M}${C}`;
      const multi = Array.isArray(orders) && orders.length > 0;

      // Each line carries its own customer PO, delivery date, fabric, fabric
      // code and yield (entered per color+estilo row in step 2). The order-level
      // values are used as a fallback for lines that leave them blank.
      // defEst  = estilo cliente por defecto de ESTE componente
      // scale   = piezas por conjunto (ratio). Solo se aplica cuando el
      //           componente HEREDA la rejilla compartida del conjunto: si el
      //           cliente mando las cantidades propias del componente, ya vienen
      //           multiplicadas y scale = 1.
      const parseCells = (arr, fb = {}, defEst = EST, scale = 1) =>
        (Array.isArray(arr) ? arr : [])
          .map((l) => {
            // Each line may carry several telas, each with its own code and yield.
            const fabrics = buildLineFabrics(l, fb);
            const primary = fabrics[0] || {};
            return {
              talla: up(l.talla, 3),
              color: up(l.color, 3),
              estilo: up(l.estilo, 6) || defEst,
              customerPo: txt(l.customerPo),
              commitmentDate: (l.commitmentDate || fb.commitmentDate || "").toString().slice(0, 10) || null,
              fabrics,
              // Representative (first-tela) scalars for the header/list views.
              fabricName: primary.name || fb.fabricName || null,
              fabricCode: primary.code || fb.fabricCode || null,
              yieldPerPiece: primary.yield ?? fb.yieldPerPiece ?? null,
              // Cantidad por talla en dos partes (piezas): packing + SKU.
              // El servidor recalcula quantity = packing + sku (autoritativo);
              // si no vienen, cae al quantity enviado por compatibilidad.
              packingQty: Math.max(parseFloat(l.packingQty) || 0, 0) * scale,
              skuQty: Math.max(parseFloat(l.skuQty) || 0, 0) * scale,
              quantity: (() => {
                const p = Math.max(parseFloat(l.packingQty) || 0, 0);
                const s = Math.max(parseFloat(l.skuQty) || 0, 0);
                const sum = p + s;
                return (sum > 0 ? sum : parseFloat(l.quantity)) * scale;
              })(),
            };
          })
          .filter((l) => l.talla && l.color && !isNaN(l.quantity) && l.quantity > 0);

      // ------------------------------------------------------------------
      // UN COMPONENTE = UNA PRENDA (chamarra, pantalon...). Cada uno trae su
      // propio estilo, SAM, descripcion, foto y ratio. Sin conjunto hay uno
      // solo y todo esto se reduce al comportamiento de siempre.
      //
      // Las CANTIDADES pueden venir de dos formas:
      //   • component.orders  -> el cliente ya calculo la rejilla del componente
      //     (telas propias, cantidades ya multiplicadas). scale = 1.
      //   • heredadas         -> se reusa la rejilla compartida del conjunto y
      //     se multiplica por el ratio del componente.
      // ------------------------------------------------------------------
      const compSpecs = rawComponents.map((c, ci) => {
        const cT = up(c.tipo ?? tipo, 3), cM = up(c.modelo ?? modelo, 3), cC = up(c.correlativo ?? correlativo, 2);
        const own = Array.isArray(c.orders) && c.orders.length > 0;
        const ratio = ratioOf(c.ratio);
        const rawOrders = own
          ? c.orders
          : (multi ? orders : [{ lines: c.lines ?? lines, commitmentDate,
                                 fabricName: bodyFabricName, fabricCode: bodyFabricCode, yield: bodyYield }]);
        const defEst = up(c.estilo ?? estilo, 6);
        const orderSpecs = (Array.isArray(rawOrders) ? rawOrders : [])
          .map((o) => {
            const fb = {
              commitmentDate: (o.commitmentDate || commitmentDate || "").toString().slice(0, 10) || null,
              fabricName: txt(o.fabricName ?? bodyFabricName),
              fabricCode: txt(o.fabricCode ?? bodyFabricCode),
              yieldPerPiece: num(o.yield ?? bodyYield),
            };
            // Solo se escala lo HEREDADO: lo propio ya viene en piezas reales.
            return { cells: parseCells(o.lines, fb, defEst, own ? 1 : ratio), ...fb };
          })
          .filter((o) => o.cells.length > 0);
        return {
          index: ci,
          T: cT, M: cM, C: cC,
          styleCode: `${cT}${cM}${cC}`,
          // Etiqueta del componente dentro del conjunto: CHAMARRA, PANTALON...
          // Sin conjunto queda en NULL y la PO es una PO suelta de siempre.
          component: isSet
            ? (String(c.label || c.component || `PARTE${ci + 1}`).trim().toUpperCase().slice(0, 20) || `PARTE${ci + 1}`)
            : null,
          ratio,
          description: txt(c.description ?? description),
          sam: c.sam ?? sam,
          photoKey: c.photoKey ?? (ci === 0 ? incomingPhotoKey : null),
          // Stock y extras son POR PRENDA: el stock de chamarras no descuenta
          // pantalones. Sin components[] se conserva el comportamiento previo.
          warehouseStock: parseFloat(c.warehouseStock ?? (ci === 0 ? warehouseStock : 0)) || 0,
          extraQuantity: parseFloat(c.extraQuantity ?? (ci === 0 ? extraQuantity : 0)) || 0,
          orderSpecs,
        };
      });

      if (!CLI) return res.status(400).json({ success: false, error: "clienteCode is required" });
      if (!customerId) return res.status(400).json({ success: false, error: "customerId is required" });
      for (const cs of compSpecs) {
        const who = isSet ? ` (${cs.component})` : "";
        if (!cs.T || !cs.M || !cs.C || !cs.description || !cs.sam) {
          return res.status(400).json({ success: false, error: `Missing style fields: tipo, modelo, correlativo, description, sam${who}` });
        }
        if (cs.orderSpecs.length === 0) {
          return res.status(400).json({ success: false, error: `Enter at least one size/color quantity${who}` });
        }
        // Every cell needs a 6-char estilo (per-color estilo cliente).
        for (const o of cs.orderSpecs) {
          const bad = o.cells.find((x) => !x.estilo || x.estilo.length !== 6);
          if (bad) return res.status(400).json({ success: false, error: `Falta el estilo cliente (6 caracteres) para el color ${bad.color || "?"}${who}` });
        }
      }
      // Un conjunto necesita etiquetas DISTINTAS: son las que FWH usa para
      // saber que pieza le falta para armar la caja.
      if (isSet && new Set(compSpecs.map((c) => c.component)).size !== compSpecs.length) {
        return res.status(400).json({ success: false, error: "Cada prenda del conjunto necesita un nombre distinto (ej. CHAMARRA / PANTALON)" });
      }

      // ------------------------------------------------------------------
      // ONE PO PER (color + estilo + customer PO + delivery date).
      // Whatever grouping the client sent — a single `lines` payload or an
      // `orders` array — is re-bucketed here so every distinct combination of
      // color, estilo cliente, PO cliente and fecha de entrega becomes its own
      // auto-numbered work order. The rest of the details (tallas, cantidades,
      // telas, código de tela, rendimiento) travel with the bucket.
      //
      // Cells that fall in the same bucket are merged; a repeated talla within a
      // bucket has its quantity summed and its telas unioned, because the
      // (work_order_id, talla, color, estilo) unique index allows only one line
      // per size in a PO.
      //
      // El styleCode entra en la llave: en un conjunto la chamarra y el
      // pantalon comparten color, estilo cliente, PO y fecha, asi que sin el
      // se fusionarian en UNA sola PO y despues chocarian contra el indice
      // unico (work_order_id, talla, color, estilo).
      const bucketKey = (c) =>
        [c.styleCode || "", c.color, c.estilo, c.customerPo || "", c.commitmentDate || ""].join("\u0001");
      const unionFabrics = (a = [], b = []) => {
        const out = [];
        const seen = new Set();
        for (const f of [...a, ...b]) {
          const nm = toTxt(f?.name);
          if (!nm) continue;
          const cd = toTxt(f?.code);
          const key = `${nm}|${cd || ""}`.toUpperCase();
          if (seen.has(key)) continue;
          seen.add(key);
          out.push({ name: nm, code: cd, yield: toNum(f?.yield) });
        }
        return out;
      };
      const poSpecs = [];
      for (const cs of compSpecs) {
      for (const spec of cs.orderSpecs) {
        const byKey = new Map();
        for (const cell0 of spec.cells) {
          // La celda arrastra a que prenda pertenece para que el bucket no
          // mezcle componentes y la PO nazca ya etiquetada.
          const cell = { ...cell0, styleCode: cs.styleCode };
          const key = bucketKey(cell);
          let bucket = byKey.get(key);
          if (!bucket) {
            bucket = {
              cells: [],
              styleCode: cs.styleCode,
              commitmentDate: cell.commitmentDate ?? spec.commitmentDate ?? null,
              fabricName: spec.fabricName ?? null,
              fabricCode: spec.fabricCode ?? null,
              yieldPerPiece: spec.yieldPerPiece ?? null,
            };
            byKey.set(key, bucket);
          }
          const dup = bucket.cells.find((x) => x.talla === cell.talla);
          if (dup) {
            dup.quantity += cell.quantity;
            dup.fabrics = unionFabrics(dup.fabrics, cell.fabrics);
            const primary = dup.fabrics[0] || {};
            dup.fabricName = primary.name || dup.fabricName;
            dup.fabricCode = primary.code || dup.fabricCode;
            dup.yieldPerPiece = primary.yield ?? dup.yieldPerPiece;
            // packing y sku son piezas: se suman igual que la cantidad.
            dup.packingQty = (dup.packingQty || 0) + (cell.packingQty || 0);
            dup.skuQty = (dup.skuQty || 0) + (cell.skuQty || 0);
          } else {
            bucket.cells.push({ ...cell });
          }
        }
        for (const bucket of byKey.values()) poSpecs.push({ ...bucket, comp: cs });
      }
      }
      if (poSpecs.length === 0) return res.status(400).json({ success: false, error: "Enter at least one size/color quantity" });

      // Auto-number whenever more than one PO results (the split created extras)
      // or the caller is already in multi mode. A lone legacy PO keeps using the
      // caller-provided workOrderNo.
      // Un conjunto SIEMPRE se autonumera: son varias POs por definicion.
      const autoNumber = multi || isSet || poSpecs.length > 1;

      await client.query("BEGIN");

      const cust = await client.query("SELECT name FROM customers WHERE id = $1", [parseInt(customerId)]);
      if (cust.rows.length === 0) {
        await client.query("ROLLBACK");
        return res.status(400).json({ success: false, error: "Customer not found" });
      }
      const customerName = cust.rows[0].name;

      // Photo was uploaded straight to S3 by the browser (presigned PUT); the
      // request carries only its key. Cada prenda puede traer la suya: la
      // chamarra y el pantalon no son la misma foto.
      if (incomingPhotoKey) {
        photoKey = incomingPhotoKey;
        photoUrl = generatePresignedGetUrl(photoKey, 3600);
      }
      for (const cs of compSpecs) {
        cs.photoUrl = cs.photoKey ? generatePresignedGetUrl(cs.photoKey, 3600) : null;
      }

      // ---- CABECERA DEL CONJUNTO ---------------------------------------
      // Se crea DENTRO de esta transaccion: si una sola PO falla, el conjunto
      // tampoco queda. La fecha del conjunto es la MAS TARDIA de sus prendas:
      // el conjunto no sale hasta que sale su ultima pieza.
      let orderSet = null;
      if (isSet) {
        const allDates = poSpecs.map((p) => p.commitmentDate).filter(Boolean).sort();
        const allPos = [...new Set(poSpecs.flatMap((p) => p.cells.map((c) => c.customerPo)).filter(Boolean))];
        orderSet = await createSetInTx(client, {
          setNo: setMeta?.setNo,
          clienteCode: CLI,
          label: setMeta?.label || compSpecs.map((c) => c.component).join(" + "),
          customerId, customerName,
          customerPo: setMeta?.customerPo || customerPo || allPos[0] || null,
          season: season || null,
          commitmentDate: allDates.length ? allDates[allDates.length - 1] : null,
          notes: setMeta?.notes || null,
          userId: req.user?.id ?? null,
        });
      }

      // For auto-numbered submissions we assign sequential SKM#### numbers ourselves.
      let seq = 0;
      if (autoNumber) {
        const maxRes = await client.query(
          `SELECT COALESCE(MAX((substring(work_order_no from '^SKM([0-9]+)'))::int), 0) AS maxseq
             FROM work_orders WHERE work_order_no LIKE 'SKM%'`
        );
        seq = parseInt(maxRes.rows[0].maxseq, 10);
      }

      const codeToId = {};           // code -> master_code id (shared across POs)
      let created = 0, reused = 0;
      const createdOrders = [];

      // Cuantas POs lleva ya cada prenda: el stock de almacen y los extras se
      // aplican a la PRIMERA PO de SU prenda, no a la primera del envio.
      const posPerComponent = new Map();

      for (let i = 0; i < poSpecs.length; i++) {
        const { cells, commitmentDate: specDate, fabricName: specFabricName,
                fabricCode: specFabricCode, yieldPerPiece: specYield, comp } = poSpecs[i];
        // Datos de la prenda a la que pertenece esta PO.
        const { T, M, C } = comp;
        const description = comp.description;
        const samNum = parseFloat(comp.sam) || 0;
        const photoKey = comp.photoKey || null;
        const photoUrl = comp.photoUrl || null;
        const nthOfComponent = (posPerComponent.get(comp.index) || 0);
        posPerComponent.set(comp.index, nthOfComponent + 1);
        // A PO may carry several customer POs (one per line). Store a distinct,
        // comma-joined summary on the header for display/search; the authoritative
        // per-line values live in work_order_lines.customer_po.
        const cPo = [...new Set(cells.map((c) => c.customerPo).filter(Boolean))].join(", ") || null;
        // Delivery date, fabric, code and yield are per line. The header keeps a
        // representative copy — the first line that has a value — so the PO list
        // can show them without joining work_order_lines. fabrics[] collects the
        // distinct fabric names across this PO's lines.
        const firstOf = (k) => cells.find((c) => c[k] != null && c[k] !== "")?.[k] ?? null;
        const headerDate = firstOf("commitmentDate") || specDate || null;
        const hFabricName = firstOf("fabricName") || specFabricName || null;
        const hFabricCode = firstOf("fabricCode") || specFabricCode || null;
        const hYield = firstOf("yieldPerPiece") ?? specYield ?? null;
        const fabricNamesArr = [...new Set(
          cells.flatMap((c) => (c.fabrics || []).map((f) => f.name)).filter(Boolean)
        )];
        const fabricSupplier = hFabricName || fabricNamesArr[0] || null;

        // Upsert the master codes this PO needs (deduped across the whole request).
        for (const cell of cells) {
          const code = `${T}${M}${C}${cell.talla}${CLI}-${cell.color}-${cell.estilo}`;
          if (codeToId[code] === undefined) {
            const r = await client.query(
              `INSERT INTO master_codes
                 (code,type,modelo,correlativo,talla,cliente,color,estilo,description,sam_minutes,photo_url,photo_filename,created_by,created_at,updated_at)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,NOW(),NOW())
               ON CONFLICT (code) DO UPDATE SET updated_at = NOW()
               RETURNING id, (xmax = 0) AS inserted`,
              [code, T, M, C, cell.talla, CLI, cell.color, cell.estilo, description, samNum, photoUrl, photoKey, req.user.id]
            );
            codeToId[code] = r.rows[0].id;
            if (r.rows[0].inserted) created++; else reused++;
          }
        }

        // PO number: auto sequence when splitting/multi; provided number only for
        // a single legacy PO.
        let woNo;
        if (autoNumber) {
          seq += 1;
          woNo = `SKM${String(seq).padStart(4, "0")}-${CLI}-${comp.styleCode}`;
        } else {
          woNo = workOrderNo;
          if (!woNo) { await client.query("ROLLBACK"); return res.status(400).json({ success: false, error: "workOrderNo is required" }); }
        }

        const dup = await client.query("SELECT id FROM work_orders WHERE work_order_no = $1", [woNo]);
        if (dup.rows.length > 0) { await client.query("ROLLBACK"); return res.status(400).json({ success: false, error: `PO number already exists: ${woNo}` }); }

        const orderedQty = cells.reduce((s, c) => s + c.quantity, 0);
        // Warehouse stock / extras apply to the first PO OF EACH GARMENT: el
        // stock de chamarras no puede descontar pantalones.
        const wStock = nthOfComponent === 0 ? comp.warehouseStock : 0;
        const xtra = nthOfComponent === 0 ? comp.extraQuantity : 0;
        const totalToProduce = Math.max(orderedQty - wStock + xtra, 0);
        const colorSummary = [...new Set(cells.map((c) => c.color))].join(", ");
        const estiloSummary = [...new Set(cells.map((c) => c.estilo))].join(", ");
        const primaryEstilo = cells[0].estilo;
        const firstCode = `${T}${M}${C}${cells[0].talla}${CLI}-${cells[0].color}-${cells[0].estilo}`;
        const primaryMasterCodeId = codeToId[firstCode];

        const woResult = await client.query(
          `INSERT INTO work_orders (
              work_order_no, quantity, customer_id, customer_name, style_description,
              color, fabric_supplier, style_code, estilo, fabrics, warehouse_stock,
              extra_quantity, total_to_produce, commitment_date, master_code_id,
              sam_minutes, season, customer_po, fabric_name, fabric_code,
              yield_per_piece, created_by, set_id, set_component, set_ratio,
              created_at, updated_at, status
           )
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,NOW(),NOW(),'pending')
           RETURNING *`,
          [
            woNo, orderedQty, parseInt(customerId), customerName, description,
            colorSummary, fabricSupplier, comp.styleCode, primaryEstilo,
            fabricNamesArr.length ? fabricNamesArr : (Array.isArray(fabrics) ? fabrics : []),
            wStock, xtra, totalToProduce,
            headerDate, primaryMasterCodeId, samNum, season || null, cPo || null,
            hFabricName, hFabricCode, hYield,
            req.user?.id ?? null,                     // created_by: el merchant que la capturo
            // Etiqueta del conjunto. NULL en una PO suelta: produccion no ve
            // ninguna diferencia, solo FWH y el tablero del merchant.
            orderSet?.id ?? null, comp.component, comp.ratio,
          ]
        );
        const workOrder = woResult.rows[0];

        for (const cell of cells) {
          const code = `${T}${M}${C}${cell.talla}${CLI}-${cell.color}-${cell.estilo}`;
          await client.query(
            `INSERT INTO work_order_lines
               (work_order_id, master_code_id, talla, color, estilo, customer_po,
                commitment_date, fabric_name, fabric_code, yield_per_piece, quantity, fabrics,
                packing_qty, sku_qty)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
            [workOrder.id, codeToId[code], cell.talla, cell.color, cell.estilo,
             cell.customerPo || null, cell.commitmentDate || null, cell.fabricName || null,
             cell.fabricCode || null, cell.yieldPerPiece, cell.quantity,
             JSON.stringify(cell.fabrics || []),
             cell.packingQty ?? 0, cell.skuQty ?? 0]
          );
        }

        workOrder.lines = cells;
        workOrder.estilos = estiloSummary;
        workOrder.set_no = orderSet?.set_no ?? null;
        if (photoKey) workOrder.master_code_photo_url = generatePresignedGetUrl(photoKey, 3600);
        createdOrders.push(workOrder);
      }

      // El tablero del merchant pinta juntas las filas del mismo conjunto.
      // Las POs nuevas todavia no estan en el tablero; esto cubre el caso de
      // reconvertir una pre-orden que ya tenia semana asignada.
      if (orderSet) {
        await client.query(
          `UPDATE merchant_week_plan p
              SET set_id = wo.set_id, set_component = wo.set_component
             FROM work_orders wo
            WHERE p.work_order_id = wo.id AND wo.set_id = $1`,
          [orderSet.id]
        );
      }

      await client.query("COMMIT");

      res.json({
        success: true,
        message: createdOrders.length > 1 ? `${createdOrders.length} production orders created` : "Production order created",
        workOrder: createdOrders[0],      // backward-compat: first PO
        workOrders: createdOrders,        // all POs created in this request
        // Presente solo cuando se capturo un conjunto (2+ prendas).
        set: orderSet,
        masterCodes: { created, reused, total: Object.keys(codeToId).length },
      });
    } catch (err) {
      await client.query("ROLLBACK").catch(() => {});
      console.error("❌ Error creating production order:", err.message);
      if (err.code === "23505") return res.status(400).json({ success: false, error: "PO number already exists" });
      res.status(500).json({ success: false, error: err.message });
    } finally {
      client.release();
    }
  });

  // ---- full update: header + size/color breakdown -----------------------
  // PUT /api/production-orders/:id
  //
  // Unlike PUT /api/work-orders/:id (header columns only), this rewrites
  // work_order_lines, so the edit modal can change colors, estilos, tallas,
  // quantities, PO cliente, delivery date, fabric, code and yield. Body:
  //   { customerId?, styleDescription?, status?, season?, samMinutes?,
  //     warehouseStock?, extraQuantity?, totalToProduce?, customerPo?,
  //     commitmentDate?, fabricName?, fabricCode?, yield?,
  //     lines?: [{ talla, color, estilo, customerPo, commitmentDate,
  //                fabricName, fabricCode, yield, quantity }] }
  // Omit `lines` to leave the breakdown untouched. When `lines` IS sent it
  // replaces the whole set, and quantity / color / estilo / master_code_id /
  // total_to_produce plus the header fabric+date copies are recomputed.
  app.put("/api/production-orders/:id", authenticateToken, async (req, res) => {
    const client = await pool.connect();
    let uploadedPhotoKey = null; // replacement image key; dropped from S3 only if the txn fails
    try {
      await setSchema(client);
      const { id } = req.params;
      const {
        customerId, styleDescription, status, season, samMinutes,
        warehouseStock, extraQuantity, totalToProduce,
        customerPo, commitmentDate, fabricName, fabricCode, yield: yieldPerPiece,
        lines,
        photoKey: photoKeyInput,   // replacement style image (from /api/master-codes/photo-upload-url)
        removePhoto,               // boolean: clear the style image
      } = req.body;

      // Photo swap/remove applies to EVERY master code this order uses (the image
      // is a property of the style, not of one code). newPhotoFilename:
      //   string  -> swap to this key
      //   null    -> remove the image
      //   undefined -> leave photos untouched
      const wantPhotoSwap = typeof photoKeyInput === "string" && photoKeyInput.trim() !== "";
      const wantPhotoRemove = removePhoto === true || removePhoto === "true";
      const newPhotoFilename = wantPhotoSwap ? photoKeyInput.trim() : (wantPhotoRemove ? null : undefined);
      const photoChanged = newPhotoFilename !== undefined;
      let oldPhotoKeys = [];              // deleted from S3 after a successful commit
      uploadedPhotoKey = wantPhotoSwap ? photoKeyInput.trim() : null; // dropped if the txn fails

      const txt = (v) => (v == null ? null : String(v).trim() || null);
      const num = (v) =>
        v === "" || v == null || isNaN(parseFloat(v)) ? null : parseFloat(v);

      if (status !== undefined && !VALID_STATUSES.includes(status)) {
        return res.status(400).json({ success: false, error: `Invalid status. Must be one of: ${VALID_STATUSES.join(", ")}` });
      }

      await client.query("BEGIN");

      const cur = await client.query("SELECT * FROM work_orders WHERE id = $1 FOR UPDATE", [id]);
      if (cur.rows.length === 0) {
        await client.query("ROLLBACK");
        return res.status(404).json({ success: false, error: "Work order not found" });
      }
      const wo = cur.rows[0];

      const set = {};   // column -> value

      // -------- header fields the caller sent explicitly -------------------
      if (customerId !== undefined) {
        const c = await client.query("SELECT name FROM customers WHERE id = $1", [parseInt(customerId)]);
        if (c.rows.length === 0) {
          await client.query("ROLLBACK");
          return res.status(400).json({ success: false, error: "Customer not found" });
        }
        set.customer_id = parseInt(customerId);
        set.customer_name = c.rows[0].name;
      }
      if (styleDescription !== undefined) set.style_description = txt(styleDescription) || wo.style_description;
      if (status !== undefined) set.status = status;
      if (season !== undefined) set.season = txt(season);
      if (samMinutes !== undefined) set.sam_minutes = num(samMinutes);

      const wStock = warehouseStock !== undefined ? (parseFloat(warehouseStock) || 0) : parseFloat(wo.warehouse_stock) || 0;
      const xtra = extraQuantity !== undefined ? (parseFloat(extraQuantity) || 0) : parseFloat(wo.extra_quantity) || 0;
      if (warehouseStock !== undefined) set.warehouse_stock = wStock;
      if (extraQuantity !== undefined) set.extra_quantity = xtra;

      // -------- breakdown ---------------------------------------------------
      if (Array.isArray(lines)) {
        // Each line may carry several telas, each with its own code and yield.
        // The scalars below stay as the representative (first-tela) header copy.
        const cells = lines
          .map((l) => {
            const fabrics = buildLineFabrics(l);
            const primary = fabrics[0] || {};
            return {
              talla: up(l.talla, 3),
              color: up(l.color, 3),
              estilo: up(l.estilo, 6),
              customerPo: txt(l.customerPo),
              commitmentDate: (l.commitmentDate || "").toString().slice(0, 10) || null,
              fabrics,
              fabricName: primary.name || null,
              fabricCode: primary.code || null,
              yieldPerPiece: primary.yield ?? null,
              packingQty: Math.max(parseFloat(l.packingQty) || 0, 0),
              skuQty: Math.max(parseFloat(l.skuQty) || 0, 0),
              quantity: (() => {
                const p = Math.max(parseFloat(l.packingQty) || 0, 0);
                const s = Math.max(parseFloat(l.skuQty) || 0, 0);
                const sum = p + s;
                return sum > 0 ? sum : parseFloat(l.quantity);
              })(),
            };
          })
          .filter((l) => l.talla && l.color && !isNaN(l.quantity) && l.quantity > 0);

        if (cells.length === 0) {
          await client.query("ROLLBACK");
          return res.status(400).json({ success: false, error: "Enter at least one size/color quantity" });
        }
        const badEstilo = cells.find((c) => !c.estilo || c.estilo.length !== 6);
        if (badEstilo) {
          await client.query("ROLLBACK");
          return res.status(400).json({ success: false, error: `Falta el estilo cliente (6 caracteres) para el color ${badEstilo.color || "?"}` });
        }
        // One PO cannot hold the same talla+color+estilo twice (unique index).
        const dupKey = new Set();
        for (const c of cells) {
          const k = `${c.talla}|${c.color}|${c.estilo}`;
          if (dupKey.has(k)) {
            await client.query("ROLLBACK");
            return res.status(400).json({ success: false, error: `Línea repetida: ${c.color} · ${c.estilo} · talla ${c.talla}. Un color+estilo repetido necesita su propia orden.` });
          }
          dupKey.add(k);
        }

        // Master codes for the (possibly new) combinations. The style prefix is
        // fixed for this PO; the 3-letter customer code comes from an existing
        // master code, falling back to customers.code.
        const styleCode = wo.style_code || "";
        let CLI = null;
        let photoUrl = null, photoKey = null;   // reuse the style photo for new codes
        if (wo.master_code_id) {
          const mc = await client.query(
            "SELECT cliente, photo_url, photo_filename FROM master_codes WHERE id = $1",
            [wo.master_code_id]
          );
          CLI = mc.rows[0]?.cliente || null;
          photoUrl = mc.rows[0]?.photo_url || null;
          photoKey = mc.rows[0]?.photo_filename || null;
        }
        // If the caller is swapping/removing the image, any NEW code created for
        // these lines must carry the new one (existing codes are updated below).
        if (photoChanged) {
          photoKey = newPhotoFilename;                                             // null on remove
          photoUrl = newPhotoFilename ? generatePresignedGetUrl(newPhotoFilename, 3600) : null;
        }
        if (!CLI) {
          const cid = set.customer_id ?? wo.customer_id;
          const cc = await client.query("SELECT code FROM customers WHERE id = $1", [cid]);
          CLI = up(cc.rows[0]?.code, 3) || null;
        }
        if (!styleCode || !CLI) {
          await client.query("ROLLBACK");
          return res.status(400).json({ success: false, error: "No se pudo resolver el código de estilo o el código de cliente de esta orden" });
        }

        const T = styleCode.slice(0, 3), M = styleCode.slice(3, 6), C = styleCode.slice(6, 8);
        const description = set.style_description ?? wo.style_description;
        const samNum = set.sam_minutes ?? (parseFloat(wo.sam_minutes) || 0);
        const codeToId = {};
        for (const cell of cells) {
          const code = `${styleCode}${cell.talla}${CLI}-${cell.color}-${cell.estilo}`;
          if (codeToId[code] === undefined) {
            const r = await client.query(
              `INSERT INTO master_codes
                 (code,type,modelo,correlativo,talla,cliente,color,estilo,description,sam_minutes,photo_url,photo_filename,created_by,created_at,updated_at)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,NOW(),NOW())
               ON CONFLICT (code) DO UPDATE SET updated_at = NOW()
               RETURNING id`,
              [code, T, M, C, cell.talla, CLI, cell.color, cell.estilo, description, samNum, photoUrl, photoKey, req.user.id]
            );
            codeToId[code] = r.rows[0].id;
          }
        }

        // Replace the whole breakdown.
        await client.query("DELETE FROM work_order_lines WHERE work_order_id = $1", [id]);
        for (const cell of cells) {
          const code = `${styleCode}${cell.talla}${CLI}-${cell.color}-${cell.estilo}`;
          await client.query(
            `INSERT INTO work_order_lines
               (work_order_id, master_code_id, talla, color, estilo, customer_po,
                commitment_date, fabric_name, fabric_code, yield_per_piece, quantity, fabrics,
                packing_qty, sku_qty)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
            [id, codeToId[code], cell.talla, cell.color, cell.estilo,
             cell.customerPo, cell.commitmentDate, cell.fabricName,
             cell.fabricCode, cell.yieldPerPiece, cell.quantity,
             JSON.stringify(cell.fabrics || []),
             cell.packingQty ?? 0, cell.skuQty ?? 0]
          );
        }

        // Recompute everything the breakdown owns.
        const orderedQty = cells.reduce((s, c) => s + c.quantity, 0);
        const firstOf = (k) => cells.find((c) => c[k] != null && c[k] !== "")?.[k] ?? null;
        set.quantity = orderedQty;
        set.color = [...new Set(cells.map((c) => c.color))].join(", ");
        set.estilo = cells[0].estilo;
        set.master_code_id = codeToId[`${styleCode}${cells[0].talla}${CLI}-${cells[0].color}-${cells[0].estilo}`];
        set.total_to_produce = Math.max(orderedQty - wStock + xtra, 0);
        set.customer_po = [...new Set(cells.map((c) => c.customerPo).filter(Boolean))].join(", ") || null;
        set.commitment_date = firstOf("commitmentDate");
        set.fabric_name = firstOf("fabricName");
        set.fabric_code = firstOf("fabricCode");
        set.yield_per_piece = firstOf("yieldPerPiece");
        set.fabrics = [...new Set(
          cells.flatMap((c) => (c.fabrics || []).map((f) => f.name)).filter(Boolean)
        )];
        set.fabric_supplier = set.fabric_name;
      }

      // -------- style image (applies to EVERY master code of this order) ----
      // Runs after the breakdown is (re)written so it picks up any codes just
      // created, and also covers the case where `lines` wasn't sent at all.
      if (photoChanged) {
        const idRes = await client.query(
          `SELECT DISTINCT master_code_id AS id
             FROM work_order_lines
            WHERE work_order_id = $1 AND master_code_id IS NOT NULL
           UNION
           SELECT master_code_id AS id
             FROM work_orders
            WHERE id = $1 AND master_code_id IS NOT NULL`,
          [id]
        );
        const mcIds = idRes.rows.map((r) => r.id);
        if (mcIds.length > 0) {
          // Remember the old objects so we can delete them from S3 after commit.
          const oldRes = await client.query(
            `SELECT DISTINCT photo_filename
               FROM master_codes
              WHERE id = ANY($1::bigint[]) AND photo_filename IS NOT NULL`,
            [mcIds]
          );
          oldPhotoKeys = oldRes.rows
            .map((r) => r.photo_filename)
            .filter((k) => k && k !== newPhotoFilename);

          const newUrl = newPhotoFilename ? generatePresignedGetUrl(newPhotoFilename, 3600) : null;
          await client.query(
            `UPDATE master_codes
                SET photo_filename = $1, photo_url = $2, updated_at = NOW()
              WHERE id = ANY($3::bigint[])`,
            [newPhotoFilename, newUrl, mcIds]
          );
        }
      }

      // Explicit header values win over the ones derived from the lines.
      if (customerPo !== undefined) set.customer_po = txt(customerPo);
      if (commitmentDate !== undefined) set.commitment_date = commitmentDate || null;
      if (fabricName !== undefined) {
        set.fabric_name = txt(fabricName);
        set.fabric_supplier = txt(fabricName);
      }
      if (fabricCode !== undefined) set.fabric_code = txt(fabricCode);
      if (yieldPerPiece !== undefined) set.yield_per_piece = num(yieldPerPiece);
      if (totalToProduce !== undefined && totalToProduce !== "") set.total_to_produce = parseFloat(totalToProduce) || 0;
      else if (!Array.isArray(lines) && (warehouseStock !== undefined || extraQuantity !== undefined)) {
        set.total_to_produce = Math.max((parseFloat(wo.quantity) || 0) - wStock + xtra, 0);
      }

      const cols = Object.keys(set);
      if (cols.length === 0 && !Array.isArray(lines) && !photoChanged) {
        await client.query("ROLLBACK");
        return res.status(400).json({ success: false, error: "No fields to update" });
      }

      let workOrder = wo;
      if (cols.length > 0) {
        const assigns = cols.map((c, i) => `${c} = $${i + 1}`).join(", ");
        const upd = await client.query(
          `UPDATE work_orders SET ${assigns}, updated_at = NOW() WHERE id = $${cols.length + 1} RETURNING *`,
          [...cols.map((c) => set[c]), id]
        );
        workOrder = upd.rows[0];
      }

      await client.query("COMMIT");

      // The previous image(s) are now unreferenced by this order — clean up
      // (best effort; a leftover object is harmless, a failed request isn't).
      if (photoChanged && oldPhotoKeys.length > 0 && typeof deleteFromS3 === "function") {
        for (const k of oldPhotoKeys) {
          try { await deleteFromS3(k); } catch (e) { console.error("⚠️  deleteFromS3 (old style photo):", e.message); }
        }
      }

      // Return the saved row with its fresh breakdown.
      const back = await client.query(
        `SELECT wo.*, to_char(wo.commitment_date, 'YYYY-MM-DD') AS commitment_date,
                ${LINES_SUBQUERY}, mc.photo_filename AS master_code_photo_filename
           FROM work_orders wo
           LEFT JOIN master_codes mc ON mc.id = wo.master_code_id
          WHERE wo.id = $1`,
        [id]
      );
      const row = back.rows[0] || workOrder;
      if (row.master_code_photo_filename) {
        row.master_code_photo_url = generatePresignedGetUrl(row.master_code_photo_filename, 3600);
        delete row.master_code_photo_filename;
      }

      res.json({ success: true, message: "Production order updated", workOrder: row });
    } catch (err) {
      await client.query("ROLLBACK").catch(() => {});
      // The browser already pushed the replacement image to S3; if the DB write
      // failed nothing references it, so drop it to avoid an orphan.
      if (uploadedPhotoKey && typeof deleteFromS3 === "function") {
        await deleteFromS3(uploadedPhotoKey).catch(() => {});
      }
      console.error("❌ Error updating production order:", err.message);
      if (err.code === "23505") return res.status(400).json({ success: false, error: "Línea duplicada para esta orden (talla+color+estilo)" });
      res.status(500).json({ success: false, error: err.message });
    } finally {
      client.release();
    }
  });
}


// Produced (producido) total for a single work order, using the same packing-
// operation subquery the planner uses. Order-level only — production is not
// captured per talla/color. Other modules (e.g. finished-warehouse) reuse this
// so the logic lives in exactly one place.
async function producedQuantityFor(client, workOrderId) {
  await ensureProducedResolved(client);
  const { rows } = await client.query(
    `SELECT ${PRODUCED_SUBQUERY} FROM work_orders wo WHERE wo.id = $1`,
    [workOrderId]
  );
  return Number(rows[0]?.produced_quantity) || 0;
}

// Recalcula el ESTADO de la ORDEN a partir de lo PRODUCIDO, con la misma
// aritmetica que ve el planeador en OrderStatus.jsx:
//   • producido > 0                          -> 'in_progress' (En proceso)
//   • producido >= asignado  (y asignado>0)  -> 'completed'   (Terminada)
//
// La produccion SOLO empuja hacia adelante (pending/assigned -> in_progress ->
// completed): nunca "descompleta" ni degrada una orden. Es el mismo criterio de
// una sola direccion que autoCompleteDay, para no pelear con el flujo manual del
// planeador si despues corrige una captura hacia abajo. No toca canceladas y es
// idempotente.
//
// NOTA de diseno: "terminada" se decide contra lo ASIGNADO, no contra
// total_to_produce. Es lo que se pidio (producido == asignado => cerrar), pero
// implica que una orden puede quedar 'completed' aunque todavia le falte cantidad
// por ASIGNAR a alguna linea. Si prefieres que solo cierre cuando ademas este
// totalmente asignada, pon REQUIRE_FULL_ASSIGNMENT = true.
const REQUIRE_FULL_ASSIGNMENT = false;

// Orden de avance para garantizar que la produccion solo suba el estado.
const WO_STATUS_RANK = { pending: 0, assigned: 1, in_progress: 2, completed: 3 };

// Devuelve { changed:true, from, to } si movio el estado, o { changed:false }.
async function refreshWorkOrderStatusFromProduction(client, workOrderId) {
  const wo = Number(workOrderId);
  if (!Number.isFinite(wo)) return { changed: false };

  await ensureProducedResolved(client);

  // Estado actual, meta y total asignado (mismo filtro que la lista de ordenes).
  const { rows } = await client.query(
    `SELECT wo.status,
            COALESCE(wo.total_to_produce, wo.quantity, 0) AS target,
            COALESCE(SUM(la.assigned_quantity)
              FILTER (WHERE la.status NOT IN ('cancelled', 'rejected')), 0) AS assigned
       FROM work_orders wo
       LEFT JOIN line_assignments la ON la.work_order_id = wo.id
      WHERE wo.id = $1
      GROUP BY wo.id`,
    [wo]
  );
  const row = rows[0];
  if (!row) return { changed: false };

  const current = row.status;
  // La produccion no manda sobre ordenes canceladas.
  if (current === "cancelled") return { changed: false };

  const assigned = Number(row.assigned) || 0;
  const target = Number(row.target) || 0;
  const produced = await producedQuantityFor(client, wo);

  const fullyAssigned = !REQUIRE_FULL_ASSIGNMENT || (target > 0 && assigned >= target);

  let desired = current;
  if (assigned > 0 && produced >= assigned && fullyAssigned) {
    desired = "completed";
  } else if (produced > 0) {
    desired = "in_progress";
  }

  // Diagnóstico (visible en CloudWatch). Si en AWS ves aquí produced=0 pero la
  // línea sí capturó, el problema es la resolución de PRODUCED_SUBQUERY en ese
  // contenedor Lambda (RESOLVED_RUN_LINK), no este cálculo de estado.
  console.log(
    `[wo-status] id=${wo} produced=${produced} assigned=${assigned} ` +
    `target=${target} current=${current} desired=${desired} ` +
    `linkResolved=${Boolean(RESOLVED_RUN_LINK)}`
  );

  // Solo hacia adelante: nunca degradar por una correccion a la baja.
  if ((WO_STATUS_RANK[desired] ?? 0) <= (WO_STATUS_RANK[current] ?? 0)) {
    return { changed: false, from: current, to: current };
  }

  await client.query(
    `UPDATE work_orders SET status = $1, updated_at = now() WHERE id = $2`,
    [desired, wo]
  );
  return { changed: true, from: current, to: desired };
}

// Produccion terminada por LINEA para VARIAS ordenes en una sola consulta (evita
// N+1 en el dashboard). Regresa Map<work_order_id, [{ line_no, finished,
// last_reported_at }]>. Mismo enlace y mismas operaciones de empaque/terminado
// que producedQuantityFor. Vacio si la deteccion no resolvio.
async function producedByLineForMany(client, workOrderIds) {
  await ensureProducedResolved(client);
  const ids = (workOrderIds || []).map((x) => Number(x)).filter((x) => Number.isFinite(x));
  if (ids.length === 0 || !RESOLVED_RUN_LINK || !PACKING_LIKES_SQL) return new Map();
  const { rows } = await client.query(
    `SELECT wo.id AS work_order_id,
            lr.line_no,
            COALESCE(SUM(se.sewed_qty) FILTER (WHERE (${PACKING_LIKES_SQL})), 0) AS finished,
            MAX(se.updated_at) AS last_reported_at
       FROM work_orders wo
       JOIN line_runs lr               ON ${RESOLVED_RUN_LINK.on}
       JOIN operation_sewed_entries se ON se.run_id = lr.id
       JOIN operator_operations oo     ON oo.id = se.operation_id
      WHERE wo.id = ANY($1)
      GROUP BY wo.id, lr.line_no
      ORDER BY wo.id, lr.line_no`,
    [ids]
  );
  const map = new Map();
  for (const r of rows) {
    const key = Number(r.work_order_id);
    const arr = map.get(key) || [];
    arr.push({ line_no: r.line_no, finished: Number(r.finished) || 0, last_reported_at: r.last_reported_at });
    map.set(key, arr);
  }
  return map;
}

// Produccion terminada por LINEA para una orden. Usa el mismo enlace
// line_runs->orden y las mismas operaciones de empaque/terminado que
// producedQuantityFor, pero agrupado por line_no y con la ultima captura del
// lider de linea, para que el Almacen PT vea "que entro de cada linea" y decida
// cuando armar la lista de pre-empaque. Regresa [] si la deteccion no resolvio.
//
//   [{ line_no, finished, last_reported_at }]
//
// finished          = piezas terminadas reportadas por esa linea para la orden
// last_reported_at  = ultima captura por hora de esa linea (cualquier operacion),
//                     para que se vea actividad aunque aun no llegue a empaque.
async function producedByLineFor(client, workOrderId) {
  const map = await producedByLineForMany(client, [workOrderId]);
  return map.get(Number(workOrderId)) || [];
}

// Piezas terminadas por (ORDEN, LINEA, DIA). Mismo enlace line_runs->orden y
// las mismas operaciones de empaque/terminado que producedQuantityFor, solo
// que ademas agrupado por lr.run_date: ese es el eje que faltaba para saber
// que un dia cerro incompleto. Regresa [] si la deteccion no resolvio.
//
//   [{ work_order_id, line_no, day: 'YYYY-MM-DD', produced, last_reported_at }]
//
// OJO con line_runs: la UNIQUE es (line_no, run_date, style), o sea UNA corrida
// por linea/dia/estilo, y esa corrida apunta a UNA orden. Si una linea cose dos
// ordenes distintas el mismo dia (el tablero si permite varios POs por celda),
// el piso solo puede reportar contra una de ellas y el saldo de la otra saldra
// completo. No es un bug de esta consulta: es el limite del modelo actual.
async function producedByLineDayForMany(client, { workOrderIds = null, from = null, to = null } = {}) {
  await ensureProducedResolved(client);
  if (!RESOLVED_RUN_LINK || !PACKING_LIKES_SQL) return [];

  const params = [];
  const where = [];

  const ids = Array.isArray(workOrderIds)
    ? workOrderIds.map(Number).filter(Number.isFinite)
    : null;
  if (ids && ids.length) {
    params.push(ids);
    where.push(`wo.id = ANY($${params.length})`);
  }
  if (from) { params.push(from); where.push(`lr.run_date >= $${params.length}::date`); }
  if (to)   { params.push(to);   where.push(`lr.run_date <= $${params.length}::date`); }

  const { rows } = await client.query(
    `SELECT wo.id                              AS work_order_id,
            lr.line_no,
            to_char(lr.run_date, 'YYYY-MM-DD') AS day,
            COALESCE(SUM(se.sewed_qty) FILTER (WHERE (${PACKING_LIKES_SQL})), 0) AS produced,
            MAX(se.updated_at)                 AS last_reported_at
       FROM work_orders wo
       JOIN line_runs lr               ON ${RESOLVED_RUN_LINK.on}
       JOIN operation_sewed_entries se ON se.run_id = lr.id
       JOIN operator_operations oo     ON oo.id = se.operation_id
      ${where.length ? "WHERE " + where.join(" AND ") : ""}
      GROUP BY wo.id, lr.line_no, lr.run_date
      ORDER BY lr.run_date, lr.line_no`,
    params
  );

  return rows.map((r) => ({
    work_order_id: Number(r.work_order_id),
    line_no: r.line_no,
    day: r.day,
    produced: Number(r.produced) || 0,
    last_reported_at: r.last_reported_at,
  }));
}

// Marca como 'completed' las asignaciones de UNA celda del tablero (orden +
// linea + dia) cuando lo COSIDO ese dia ya alcanzo o supero lo ASIGNADO, y
// guarda cuanto se produjo (produced_quantity) y cuando se cerro (completed_at).
//
// Es el gemelo AUTOMATICO de settle-day: settle-day lo dispara el planeador a
// mano y ademas reasigna el faltante cuando la linea quedo corta. Esto, en
// cambio, lo dispara la propia captura del lider de linea, y SOLO actua en el
// caso "meta alcanzada" (producido >= asignado): no encoge cantidades, no borra
// filas y no reasigna nada. El faltante se sigue manejando con settle-day.
//
// Propiedades importantes:
//   • Una sola direccion: nunca "descompleta" una celda. Asi no pelea con el
//     flujo manual del planeador si despues corrige la captura hacia abajo.
//   • Idempotente: si la celda ya esta completa no toca nada.
//   • Multi-color: una celda puede tener varias filas (una por color) y la
//     produccion se captura por ORDEN, no por color, asi que produced_quantity
//     se reparte proporcional (residuo del redondeo a la fila mas grande) para
//     que SUM(produced_quantity) de la celda == lo cosido ese dia.
//   • Abre su PROPIA transaccion, asi que el client que reciba NO debe estar ya
//     dentro de un BEGIN. Devuelve null si no hubo cambios.
//
// Regresa null (sin cambios) o
//   { workOrderId, lineNo, day, assigned, produced, completed: [ids...] }
async function autoCompleteDay(client, { workOrderId, lineNo, day }) {
  await ensureProducedResolved(client);
  if (!RESOLVED_RUN_LINK || !PACKING_LIKES_SQL) return null;

  const wo = Number(workOrderId);
  const ln = String(lineNo == null ? "" : lineNo);
  if (!Number.isFinite(wo) || !ln || !day) return null;

  await client.query("BEGIN");
  try {
    // Piezas de empaque/terminado que reporto esa linea para esa orden ESE dia.
    // Mismo enlace y mismas operaciones que producedQuantityFor / day-balances.
    const prodRes = await client.query(
      `SELECT COALESCE(SUM(se.sewed_qty) FILTER (WHERE (${PACKING_LIKES_SQL})), 0) AS produced
         FROM work_orders wo
         JOIN line_runs lr               ON ${RESOLVED_RUN_LINK.on}
         JOIN operation_sewed_entries se ON se.run_id = lr.id
         JOIN operator_operations oo     ON oo.id = se.operation_id
        WHERE wo.id = $1
          AND lr.line_no = $2
          AND lr.run_date = $3::date`,
      [wo, ln, day]
    );
    const produced = Number(prodRes.rows[0]?.produced) || 0;
    if (produced <= 0) { await client.query("ROLLBACK"); return null; }

    // Filas de la celda que aun estan abiertas. Se bloquean para no competir con
    // settle-day ni con dos capturas simultaneas.
    const cellRes = await client.query(
      `SELECT id, color, assigned_quantity
         FROM line_assignments
        WHERE work_order_id = $1
          AND line_no = $2
          AND assigned_date = $3::date
          AND status NOT IN ('completed', 'cancelled', 'rejected')
        ORDER BY id
        FOR UPDATE`,
      [wo, ln, day]
    );
    if (cellRes.rows.length === 0) { await client.query("ROLLBACK"); return null; }

    const assigned = cellRes.rows.reduce((s, r) => s + (Number(r.assigned_quantity) || 0), 0);
    // Aun no alcanza la meta: se deja abierta (en proceso) y no se toca nada.
    if (assigned <= 0 || produced < assigned) { await client.query("ROLLBACK"); return null; }

    // Reparto proporcional de lo cosido entre las filas de color; el residuo del
    // redondeo va a la fila mas grande para que la suma cuadre exacto.
    const parts = cellRes.rows.map((r) => ({ id: r.id, assigned: Number(r.assigned_quantity) || 0, share: 0 }));
    let repartido = 0;
    parts.forEach((r) => { r.share = assigned > 0 ? Math.floor((r.assigned / assigned) * produced) : 0; repartido += r.share; });
    const residuo = produced - repartido;
    if (residuo > 0) parts.slice().sort((a, b) => b.assigned - a.assigned)[0].share += residuo;

    for (const r of parts) {
      await client.query(
        `UPDATE line_assignments
            SET status = 'completed',
                produced_quantity = $2,
                completed_at = now(),
                updated_at = now()
          WHERE id = $1`,
        [r.id, r.share]
      );
    }

    await client.query("COMMIT");
    return { workOrderId: wo, lineNo: ln, day, assigned, produced, completed: parts.map((r) => r.id) };
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    throw err;
  }
}

registerWorkOrders.initSchema = initSchema;
registerWorkOrders.autoCompleteDay = autoCompleteDay;
registerWorkOrders.producedQuantityFor = producedQuantityFor;
registerWorkOrders.refreshWorkOrderStatusFromProduction = refreshWorkOrderStatusFromProduction;
registerWorkOrders.producedByLineFor = producedByLineFor;
registerWorkOrders.producedByLineForMany = producedByLineForMany;
registerWorkOrders.producedByLineDayForMany = producedByLineDayForMany;
module.exports = registerWorkOrders;