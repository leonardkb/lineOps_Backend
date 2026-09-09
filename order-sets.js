// ==========================================================================
// order-sets.js
//
// CONJUNTOS (sets): un pedido que el cliente compra como UNA unidad pero que la
// planta produce como VARIAS ordenes. Caso Reebok: chamarra + pantalon.
//
//   El merchant captura UNA vez  ->  produccion ve N POs normales  ->  FWH ve
//   UNA linea "500 conjuntos".
//
// El conjunto NO reemplaza a la PO: es una ETIQUETA encima de POs normales.
// Cada componente sigue siendo una work_orders con su propio estilo, su propio
// SAM, sus propias telas y su propia carga en linea. Por eso nada de produccion
// (cortes, asignaciones, eficiencia, merchant-plan) tiene que cambiar.
//
//   order_sets                      1 fila por conjunto (el numero SET####)
//   work_orders.set_id              a que conjunto pertenece la PO (NULL = PO suelta)
//   work_orders.set_component       'JACKET' / 'PANT' / lo que el merchant escriba
//   work_orders.set_ratio           piezas de ESTE componente por conjunto (default 1)
//
// La cantidad del conjunto NO se guarda: se DERIVA.
//     conjuntos_pedidos  = MIN sobre componentes de (piezas_pedidas / ratio)
//     conjuntos_listos   = MIN sobre componentes de floor(piezas_recibidas / ratio)
// Guardarla seria un tercer numero que se desincroniza con las POs.
//
// --------------------------------------------------------------------------
// SETUP  (server1.js)
// --------------------------------------------------------------------------
// 1. Junto a los otros requires:
//        const registerOrderSets = require("./order-sets");
//
// 2. En el bloque async de arranque, ANTES de registerWorkOrders.initSchema
//    (work-orders.js escribe en las columnas que este modulo crea):
//        await registerOrderSets.initSchema({ pool, setSchema });
//
// 3. Donde se registran los demas modulos:
//        registerOrderSets(app, { authenticateToken, pool, setSchema });
//
// Endpoints
//   GET    /api/order-sets                  -> lista de conjuntos + sus componentes
//   GET    /api/order-sets/:id              -> un conjunto con el detalle por PO
//   GET    /api/finished-warehouse/sets     -> ROLLUP para FWH: conjuntos listos
//   POST   /api/order-sets/link             -> agrupar POs YA existentes (backfill)
//   DELETE /api/order-sets/:id              -> desagrupar (las POs NO se borran)
//
// La creacion normal NO pasa por aqui: la hace POST /api/production-orders
// (work-orders.js) llamando a createSetInTx dentro de su misma transaccion.
// ==========================================================================

// --------------------------------------------------------------------------
// RECIBOS DE ALMACEN DE PRODUCTO TERMINADO
// --------------------------------------------------------------------------
// finished-warehouse.js guarda lo recibido, pero el nombre de esa tabla varia
// entre instalaciones. En vez de hardcodearlo se detecta contra el esquema real,
// igual que work-orders.js hace con line_runs. Si no se encuentra nada, el
// rollup responde resolved:false y recibido = 0 — la pantalla sigue abriendo en
// vez de tronar.
const RECEIPT_TABLE_CANDIDATES = [
  "finished_warehouse_entries",
  "finished_warehouse_receipts",
  "finished_warehouse_items",
  "finished_goods_receipts",
  "fwh_receipts",
  "warehouse_receipts",
];
const RECEIPT_WO_COLUMNS = ["work_order_id", "wo_id", "po_id"];
const RECEIPT_QTY_COLUMNS = ["received_qty", "quantity", "qty", "pieces", "received_quantity"];

// Resuelto una vez por proceso. null = no detectado (recibido queda en 0).
let RECEIPTS = null;

async function tableColumns(client, table) {
  const { rows } = await client.query(
    `SELECT column_name FROM information_schema.columns
      WHERE table_schema = current_schema() AND table_name = $1`,
    [table]
  );
  return new Set(rows.map((r) => r.column_name));
}

async function detectReceipts(client) {
  for (const table of RECEIPT_TABLE_CANDIDATES) {
    const cols = await tableColumns(client, table);
    if (cols.size === 0) continue;
    const woCol = RECEIPT_WO_COLUMNS.find((c) => cols.has(c));
    const qtyCol = RECEIPT_QTY_COLUMNS.find((c) => cols.has(c));
    if (!woCol || !qtyCol) continue;
    RECEIPTS = {
      table,
      woCol,
      qtyCol,
      hasTalla: cols.has("talla") || cols.has("size"),
      tallaCol: cols.has("talla") ? "talla" : cols.has("size") ? "size" : null,
      hasColor: cols.has("color"),
    };
    console.log(
      `\u2705 order-sets: recibos de FWH detectados en ${table}(${woCol}, ${qtyCol})` +
      `${RECEIPTS.tallaCol ? " por talla" : ""}${RECEIPTS.hasColor ? "+color" : ""}`
    );
    return;
  }
  console.warn(
    "\u26a0\ufe0f  order-sets: no se encontro la tabla de recibos de FWH " +
    `(probadas: ${RECEIPT_TABLE_CANDIDATES.join(", ")}). Los conjuntos listos ` +
    "quedaran en 0. Agrega el nombre real a RECEIPT_TABLE_CANDIDATES."
  );
}

// Expresion SQL de lo recibido para una fila del CTE `comp` (alias c).
// Cuando la tabla de recibos NO guarda talla/color, el detalle por talla no se
// puede calcular: en ese caso el rollup se responde a nivel PO (granularity).
function receivedExpr({ byLine }) {
  if (!RECEIPTS) return "0::numeric";
  const { table, woCol, qtyCol, tallaCol, hasColor } = RECEIPTS;
  const conds = [`r.${woCol} = c.work_order_id`];
  if (byLine && tallaCol) conds.push(`r.${tallaCol} = c.talla`);
  if (byLine && hasColor) conds.push(`r.color = c.color`);
  return `COALESCE((SELECT SUM(r.${qtyCol})::numeric FROM ${table} r WHERE ${conds.join(" AND ")}), 0)`;
}

const receiptsByLine = () => !!(RECEIPTS && RECEIPTS.tallaCol && RECEIPTS.hasColor);

// --------------------------------------------------------------------------
// SCHEMA
// --------------------------------------------------------------------------
async function initSchema({ pool, setSchema }) {
  const client = await pool.connect();
  try {
    await setSchema(client);

    await client.query(`
      CREATE TABLE IF NOT EXISTS order_sets(
        id              BIGSERIAL PRIMARY KEY,
        set_no          VARCHAR(40)  NOT NULL UNIQUE,   -- SET0001-REB
        label           VARCHAR(120),                   -- "Chamarra + pantalon"
        customer_id     BIGINT REFERENCES customers(id) ON DELETE SET NULL,
        customer_name   VARCHAR(150),
        customer_po     VARCHAR(60),
        season          VARCHAR(10),
        commitment_date DATE,
        notes           TEXT,
        created_by      BIGINT REFERENCES users(id) ON DELETE SET NULL,
        created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
      );
    `);
    await client.query("CREATE INDEX IF NOT EXISTS idx_order_sets_customer ON order_sets(customer_id);");
    await client.query("CREATE INDEX IF NOT EXISTS idx_order_sets_po ON order_sets(customer_po);");

    // Pertenencia: vive en la PO, no en una tabla puente. Una PO pertenece a lo
    // sumo a UN conjunto, asi que la tabla puente solo agregaria un JOIN.
    // ON DELETE SET NULL: borrar el conjunto NO borra ordenes de produccion.
    await client.query(
      "ALTER TABLE work_orders ADD COLUMN IF NOT EXISTS set_id BIGINT REFERENCES order_sets(id) ON DELETE SET NULL;"
    );
    await client.query("ALTER TABLE work_orders ADD COLUMN IF NOT EXISTS set_component VARCHAR(20);");
    // Piezas de este componente por conjunto. Hoy siempre 1 (1 chamarra +
    // 1 pantalon), pero "1 chamarra + 2 pantalones" no debe pedir migracion.
    await client.query("ALTER TABLE work_orders ADD COLUMN IF NOT EXISTS set_ratio NUMERIC(6,2) NOT NULL DEFAULT 1;");
    await client.query("CREATE INDEX IF NOT EXISTS idx_work_orders_set ON work_orders(set_id);");

    // El tablero del merchant guarda las dos filas (chamarra y pantalon consumen
    // minutos distintos), pero necesita saber que son el mismo compromiso para
    // pintarlas juntas. merchant-plan.js copia estos valores en su snapshot.
    await client.query("ALTER TABLE merchant_week_plan ADD COLUMN IF NOT EXISTS set_id BIGINT;");
    await client.query("ALTER TABLE merchant_week_plan ADD COLUMN IF NOT EXISTS set_component VARCHAR(20);");
    await client.query("CREATE INDEX IF NOT EXISTS idx_merchant_week_plan_set ON merchant_week_plan(set_id);");

    console.log("\u2705 order_sets + work_orders.set_id ready in prod_db_schema");

    await detectReceipts(client);
  } finally {
    client.release();
  }
}

// Deteccion perezosa: en Lambda RUN_MIGRATIONS=false y initSchema nunca corre.
let receiptsResolution = null;
async function ensureReceiptsResolved(client) {
  if (RECEIPTS) return;
  if (!receiptsResolution) {
    receiptsResolution = detectReceipts(client)
      .catch((err) => console.warn("\u26a0\ufe0f  detectReceipts fallo:", err.message))
      // Si no se resolvio, limpiar el memo para reintentar en la siguiente
      // peticion (la primera pudo correr antes del search_path del tenant).
      .finally(() => { if (!RECEIPTS) receiptsResolution = null; });
  }
  await receiptsResolution;
}

// --------------------------------------------------------------------------
// HELPERS compartidos con work-orders.js
// --------------------------------------------------------------------------
const txt = (v, n) => (v == null ? null : String(v).trim().slice(0, n || 200) || null);
const upper = (v, n) => String(v || "").trim().toUpperCase().replace(/[^A-Z0-9_ -]/g, "").slice(0, n).trim() || null;
const ratioOf = (v) => {
  const n = parseFloat(v);
  return !isFinite(n) || n <= 0 ? 1 : Math.round(n * 100) / 100;
};

// Siguiente SET####-CLI. Se llama DENTRO de la transaccion que crea las POs.
async function nextSetNo(client, clienteCode) {
  const { rows } = await client.query(
    `SELECT COALESCE(MAX((substring(set_no from '^SET([0-9]+)'))::int), 0) AS maxseq
       FROM order_sets WHERE set_no LIKE 'SET%'`
  );
  const seq = parseInt(rows[0].maxseq, 10) + 1;
  const cli = upper(clienteCode, 3) || "GEN";
  return `SET${String(seq).padStart(4, "0")}-${cli}`;
}

/**
 * Crea la fila del conjunto usando un client que YA está en transacción.
 * Lo usa POST /api/production-orders para que el conjunto y sus POs nazcan o
 * fracasen juntos.
 * @returns {Promise<{id:number, set_no:string}>}
 */
async function createSetInTx(client, {
  clienteCode, label, customerId, customerName, customerPo,
  season, commitmentDate, notes, userId, setNo,
}) {
  const no = txt(setNo, 40) || (await nextSetNo(client, clienteCode));
  const { rows } = await client.query(
    `INSERT INTO order_sets
       (set_no, label, customer_id, customer_name, customer_po, season,
        commitment_date, notes, created_by, created_at, updated_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,NOW(),NOW())
     RETURNING id, set_no`,
    [
      no, txt(label, 120), customerId ? parseInt(customerId, 10) : null,
      txt(customerName, 150), txt(customerPo, 60), txt(season, 10),
      commitmentDate || null, txt(notes, 2000), userId ?? null,
    ]
  );
  return rows[0];
}

// Los componentes de un conjunto, con lo pedido y lo asignado por PO.
const MEMBERS_SUBQUERY = `
  COALESCE((
    SELECT json_agg(json_build_object(
             'workOrderId',   m.id,
             'workOrderNo',   m.work_order_no,
             'component',     m.set_component,
             'ratio',         m.set_ratio,
             'styleCode',     m.style_code,
             'estilo',        m.estilo,
             'color',         m.color,
             'description',   m.style_description,
             'samMinutes',    m.sam_minutes,
             'quantity',      m.quantity,
             'totalToProduce', m.total_to_produce,
             'commitmentDate', to_char(m.commitment_date, 'YYYY-MM-DD'),
             'status',        m.status
           ) ORDER BY m.set_component, m.work_order_no)
      FROM work_orders m WHERE m.set_id = s.id
  ), '[]') AS members
`;

// Estado del conjunto = el MENOS avanzado de sus componentes. Un conjunto no
// está completo hasta que TODAS sus piezas lo están.
const SET_STATUS_SUBQUERY = `
  (SELECT CASE
            WHEN COUNT(*) = 0 THEN 'empty'
            WHEN COUNT(*) FILTER (WHERE m.status = 'cancelled') = COUNT(*) THEN 'cancelled'
            WHEN COUNT(*) FILTER (WHERE m.status = 'completed') = COUNT(*) THEN 'completed'
            WHEN COUNT(*) FILTER (WHERE m.status IN ('in_progress','assigned','completed')) > 0 THEN 'in_progress'
            ELSE 'pending'
          END
     FROM work_orders m WHERE m.set_id = s.id) AS status
`;

// Conjuntos PEDIDOS = el componente más escaso manda.
const SET_ORDERED_SUBQUERY = `
  COALESCE((
    SELECT MIN(FLOOR(m.quantity / GREATEST(m.set_ratio, 0.01)))
      FROM work_orders m WHERE m.set_id = s.id AND m.status <> 'cancelled'
  ), 0) AS sets_ordered
`;

function registerOrderSets(app, deps) {
  const { authenticateToken, pool, setSchema } = deps;

  // ---- GET /api/order-sets  (lista) --------------------------------------
  app.get("/api/order-sets", authenticateToken, async (req, res) => {
    const client = await pool.connect();
    try {
      await setSchema(client);
      const { customerId, customerPo, season } = req.query;
      let sql = `
        SELECT s.id, s.set_no, s.label, s.customer_id, s.customer_name,
               s.customer_po, s.season,
               to_char(s.commitment_date, 'YYYY-MM-DD') AS commitment_date,
               s.notes, s.created_by, s.created_at,
               (SELECT COALESCE(NULLIF(TRIM(u.full_name), ''), u.username)
                  FROM users u WHERE u.id = s.created_by) AS created_by_name,
               ${SET_STATUS_SUBQUERY},
               ${SET_ORDERED_SUBQUERY},
               ${MEMBERS_SUBQUERY}
          FROM order_sets s
         WHERE 1=1`;
      const params = [];
      let i = 1;
      if (customerId) { sql += ` AND s.customer_id = $${i++}`; params.push(parseInt(customerId, 10)); }
      if (customerPo) { sql += ` AND s.customer_po ILIKE $${i++}`; params.push(`%${customerPo}%`); }
      if (season) { sql += ` AND s.season = $${i++}`; params.push(season); }
      sql += " ORDER BY s.created_at DESC";
      const { rows } = await client.query(sql, params);
      res.json({ success: true, sets: rows });
    } catch (err) {
      console.error("\u274c GET /api/order-sets:", err.message);
      res.status(500).json({ success: false, error: err.message });
    } finally {
      client.release();
    }
  });

  // ---- GET /api/finished-warehouse/sets  (ROLLUP para FWH) ---------------
  //
  // Lo que el almacén de producto terminado necesita ver: UNA línea por
  // conjunto y, al expandirla, cuántos conjuntos COMPLETOS puede empacar hoy.
  //
  //   conjuntos_listos = MIN sobre componentes de floor(recibido / ratio)
  //   piezas_sueltas   = recibido - conjuntos_listos * ratio
  //
  // Las piezas sueltas son el número que hoy se descubre empacando: 200
  // chamarras M con 120 pantalones M son 120 conjuntos y 80 chamarras varadas.
  //
  // MUST be registered before any /api/finished-warehouse/:id route in
  // finished-warehouse.js, or "sets" gets captured as an id.
  app.get("/api/finished-warehouse/sets", authenticateToken, async (req, res) => {
    const client = await pool.connect();
    try {
      await setSchema(client);
      await ensureReceiptsResolved(client);
      const byLine = receiptsByLine();
      const { setId, status } = req.query;

      // Nivel PO: una fila por componente del conjunto.
      const orderSql = `
        WITH comp AS (
          SELECT wo.set_id, wo.id AS work_order_id, wo.work_order_no,
                 COALESCE(wo.set_component, '?') AS set_component,
                 GREATEST(wo.set_ratio, 0.01) AS ratio,
                 wo.quantity AS ordered, wo.status
            FROM work_orders wo
           WHERE wo.set_id IS NOT NULL AND wo.status <> 'cancelled'
             ${setId ? "AND wo.set_id = $1" : ""}
        )
        SELECT c.*, ${receivedExpr({ byLine: false })} AS received
          FROM comp c`;
      const { rows: compRows } = await client.query(orderSql, setId ? [parseInt(setId, 10)] : []);

      // Nivel talla+color: sólo si los recibos guardan talla y color.
      let lineRows = [];
      if (byLine) {
        const lineSql = `
          WITH comp AS (
            SELECT wo.set_id, wo.id AS work_order_id,
                   COALESCE(wo.set_component, '?') AS set_component,
                   GREATEST(wo.set_ratio, 0.01) AS ratio,
                   l.color, l.talla, SUM(l.quantity) AS ordered
              FROM work_orders wo
              JOIN work_order_lines l ON l.work_order_id = wo.id
             WHERE wo.set_id IS NOT NULL AND wo.status <> 'cancelled'
               ${setId ? "AND wo.set_id = $1" : ""}
             GROUP BY 1,2,3,4,5,6
          )
          SELECT c.*, ${receivedExpr({ byLine: true })} AS received
            FROM comp c`;
        lineRows = (await client.query(lineSql, setId ? [parseInt(setId, 10)] : [])).rows;
      }

      // Cabeceras.
      const headSql = `
        SELECT s.id, s.set_no, s.label, s.customer_name, s.customer_po, s.season,
               to_char(s.commitment_date, 'YYYY-MM-DD') AS commitment_date,
               ${SET_STATUS_SUBQUERY},
               ${SET_ORDERED_SUBQUERY}
          FROM order_sets s
         ${setId ? "WHERE s.id = $1" : ""}
         ORDER BY s.commitment_date NULLS LAST, s.set_no`;
      const { rows: heads } = await client.query(headSql, setId ? [parseInt(setId, 10)] : []);

      const num = (v) => Number(v) || 0;
      const groupBy = (rows, key) => rows.reduce((m, r) => {
        (m[r[key]] = m[r[key]] || []).push(r); return m;
      }, {});
      const bySet = groupBy(compRows, "set_id");
      const linesBySet = groupBy(lineRows, "set_id");

      const sets = heads.map((h) => {
        const comps = bySet[h.id] || [];
        // El componente más escaso manda: no se puede empacar más conjuntos que
        // eso, por muchas piezas del otro componente que haya.
        const setsReady = comps.length
          ? Math.min(...comps.map((c) => Math.floor(num(c.received) / num(c.ratio))))
          : 0;
        const components = comps.map((c) => ({
          workOrderId: c.work_order_id,
          workOrderNo: c.work_order_no,
          component: c.set_component,
          ratio: num(c.ratio),
          status: c.status,
          ordered: num(c.ordered),
          received: num(c.received),
          // Piezas que llegaron pero no tienen con qué formar conjunto.
          loose: Math.max(num(c.received) - setsReady * num(c.ratio), 0),
          missing: Math.max(num(c.ordered) - num(c.received), 0),
        }));

        // Matriz talla × color: dónde exactamente está el desbalance.
        let matrix = [];
        if (byLine) {
          const cells = new Map();
          for (const r of linesBySet[h.id] || []) {
            const key = `${r.color}|${r.talla}`;
            if (!cells.has(key)) cells.set(key, { color: r.color, talla: r.talla, byComponent: {} });
            cells.get(key).byComponent[r.set_component] = {
              ratio: num(r.ratio), ordered: num(r.ordered), received: num(r.received),
            };
          }
          matrix = [...cells.values()].map((cell) => {
            const parts = Object.values(cell.byComponent);
            const ready = parts.length
              ? Math.min(...parts.map((p) => Math.floor(p.received / (p.ratio || 1))))
              : 0;
            const loose = {};
            for (const [name, p] of Object.entries(cell.byComponent)) {
              loose[name] = Math.max(p.received - ready * (p.ratio || 1), 0);
            }
            return { ...cell, setsReady: ready, loose };
          }).sort((a, b) => a.color.localeCompare(b.color) || a.talla.localeCompare(b.talla));
        }

        return {
          ...h,
          sets_ordered: num(h.sets_ordered),
          setsReady,
          setsPending: Math.max(num(h.sets_ordered) - setsReady, 0),
          // Piezas que ya llegaron pero siguen sin pareja. Este es el número que
          // hoy se descubre hasta que se están armando las cajas.
          looseTotal: components.reduce((s, c) => s + c.loose, 0),
          components,
          matrix,
        };
      });

      res.json({
        success: true,
        // false = no se detectó la tabla de recibos: todo lo recibido sale en 0.
        resolved: !!RECEIPTS,
        granularity: byLine ? "line" : "order",
        sets: status ? sets.filter((s) => s.status === status) : sets,
      });
    } catch (err) {
      console.error("\u274c GET /api/finished-warehouse/sets:", err.message);
      res.status(500).json({ success: false, error: err.message });
    } finally {
      client.release();
    }
  });

  // ---- GET /api/order-sets/:id -------------------------------------------
  app.get("/api/order-sets/:id", authenticateToken, async (req, res) => {
    const client = await pool.connect();
    try {
      await setSchema(client);
      const { rows } = await client.query(
        `SELECT s.*, ${SET_STATUS_SUBQUERY}, ${SET_ORDERED_SUBQUERY}, ${MEMBERS_SUBQUERY}
           FROM order_sets s WHERE s.id = $1`,
        [parseInt(req.params.id, 10)]
      );
      if (rows.length === 0) return res.status(404).json({ success: false, error: "Conjunto no encontrado" });
      res.json({ success: true, set: rows[0] });
    } catch (err) {
      console.error("\u274c GET /api/order-sets/:id:", err.message);
      res.status(500).json({ success: false, error: err.message });
    } finally {
      client.release();
    }
  });

  // ---- POST /api/order-sets/link  (BACKFILL) -----------------------------
  // Agrupa POs que YA existen. Es la ruta para arreglar lo que ya está en prod
  // (el pedido Reebok capturado antes de que existieran los conjuntos) sin
  // tocar números de PO ni nada de producción.
  //
  // Body: { setNo?, label?, customerPo?, notes?,
  //         members:[{ workOrderId, component, ratio? }] }
  app.post("/api/order-sets/link", authenticateToken, async (req, res) => {
    const members = Array.isArray(req.body?.members) ? req.body.members : [];
    if (members.length < 2) {
      return res.status(400).json({ success: false, error: "Un conjunto necesita al menos 2 órdenes" });
    }
    const client = await pool.connect();
    try {
      await setSchema(client);
      await client.query("BEGIN");

      const ids = members.map((m) => parseInt(m.workOrderId, 10)).filter(Boolean);
      const { rows: wos } = await client.query(
        `SELECT id, work_order_no, customer_id, customer_name, customer_po, season,
                to_char(commitment_date,'YYYY-MM-DD') AS commitment_date, set_id
           FROM work_orders WHERE id = ANY($1::bigint[])`,
        [ids]
      );
      if (wos.length !== ids.length) {
        await client.query("ROLLBACK");
        return res.status(400).json({ success: false, error: "Alguna orden no existe" });
      }
      const taken = wos.find((w) => w.set_id != null);
      if (taken) {
        await client.query("ROLLBACK");
        return res.status(400).json({ success: false, error: `${taken.work_order_no} ya pertenece a un conjunto` });
      }

      const head = wos[0];
      const clienteCode = (head.work_order_no || "").split("-")[1] || null;
      const set = await createSetInTx(client, {
        setNo: req.body?.setNo,
        clienteCode,
        label: req.body?.label,
        customerId: head.customer_id,
        customerName: head.customer_name,
        customerPo: req.body?.customerPo || head.customer_po,
        season: head.season,
        // La fecha del conjunto es la MÁS TARDÍA: el conjunto no sale hasta que
        // sale su última pieza.
        commitmentDate: wos.map((w) => w.commitment_date).filter(Boolean).sort().pop() || null,
        notes: req.body?.notes,
        userId: req.user?.id ?? null,
      });

      for (const m of members) {
        await client.query(
          "UPDATE work_orders SET set_id = $1, set_component = $2, set_ratio = $3, updated_at = NOW() WHERE id = $4",
          [set.id, upper(m.component, 20), ratioOf(m.ratio), parseInt(m.workOrderId, 10)]
        );
      }
      // El tablero del merchant pinta las filas juntas si conoce el conjunto.
      await client.query(
        `UPDATE merchant_week_plan p
            SET set_id = wo.set_id, set_component = wo.set_component
           FROM work_orders wo
          WHERE p.work_order_id = wo.id AND wo.set_id = $1`,
        [set.id]
      );

      await client.query("COMMIT");
      res.json({ success: true, set, linked: members.length });
    } catch (err) {
      await client.query("ROLLBACK").catch(() => {});
      console.error("\u274c POST /api/order-sets/link:", err.message);
      if (err.code === "23505") return res.status(400).json({ success: false, error: "Ese número de conjunto ya existe" });
      res.status(500).json({ success: false, error: err.message });
    } finally {
      client.release();
    }
  });

  // ---- DELETE /api/order-sets/:id  (desagrupar) --------------------------
  // Borra la etiqueta, NUNCA las órdenes. Las POs vuelven a ser POs sueltas.
  app.delete("/api/order-sets/:id", authenticateToken, async (req, res) => {
    const client = await pool.connect();
    try {
      await setSchema(client);
      await client.query("BEGIN");
      const id = parseInt(req.params.id, 10);
      await client.query(
        "UPDATE work_orders SET set_id = NULL, set_component = NULL, set_ratio = 1 WHERE set_id = $1",
        [id]
      );
      await client.query(
        "UPDATE merchant_week_plan SET set_id = NULL, set_component = NULL WHERE set_id = $1",
        [id]
      );
      const { rowCount } = await client.query("DELETE FROM order_sets WHERE id = $1", [id]);
      await client.query("COMMIT");
      res.json({ success: true, deleted: rowCount });
    } catch (err) {
      await client.query("ROLLBACK").catch(() => {});
      console.error("\u274c DELETE /api/order-sets/:id:", err.message);
      res.status(500).json({ success: false, error: err.message });
    } finally {
      client.release();
    }
  });
}

registerOrderSets.initSchema = initSchema;
// work-orders.js los usa dentro de SU transacción, para que el conjunto y sus
// POs nazcan o fallen juntos.
registerOrderSets.createSetInTx = createSetInTx;
registerOrderSets.nextSetNo = nextSetNo;
module.exports = registerOrderSets;