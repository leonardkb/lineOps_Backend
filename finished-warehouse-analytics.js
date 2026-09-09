// finished-warehouse-analytics.js
// ---------------------------------------------------------------------------
// Analítica del Almacén de Producto Terminado.
//
// Responde la pregunta del almacén: ¿cuánto se RECIBIÓ (escaneando tickets) por
// orden de trabajo y por PO cliente, y cómo se compara contra lo que el
// MERCHANT asignó (work_order_lines) y contra lo que produjo/imprimió cada
// LÍNEA? Al abrir una fila, se ve el desglose por talla: recibido (escaneado)
// vs asignado (merchant) vs producido (línea), y DE QUÉ LÍNEA vinieron las
// piezas recibidas.
//
// Se registra igual que los demás módulos (mismo shape que merchant-analytics):
//   const registerFinishedWarehouseAnalytics = require("./finished-warehouse-analytics");
//   await registerFinishedWarehouseAnalytics.initSchema({ pool, setSchema }); // no-op, sin tablas propias
//   registerFinishedWarehouseAnalytics(app, { authenticateToken, pool, setSchema });
//
// Fuentes de verdad (ninguna tabla nueva; solo lee):
//   scanned_tickets   -> lo RECIBIDO en el almacén (un renglón = un ticket escaneado)
//   work_order_lines  -> lo ASIGNADO por el merchant (desglose talla×color de la orden)
//   ticket_prints     -> lo PRODUCIDO/impreso por la línea (talla×color×PO)
//   line_runs         -> línea (line_no) y día de la corrida; enlaza run_id -> línea
//   work_orders       -> encabezado (cliente, estilo, PO cliente por defecto)
//
// Enlace "de qué línea": scanned_tickets.run_id -> line_runs.id -> line_runs.line_no.
// Los tickets viejos sin run_id caen al cubo de línea "—" (desconocida).
// ---------------------------------------------------------------------------

// Talla -> etiqueta imprimible (misma tabla parcial que finished-warehouse.js).
// scanned_tickets ya guarda size_label; esto es solo para el lado ASIGNADO
// (work_order_lines guarda la talla, no la etiqueta). Cualquier código no listado
// se muestra tal cual, así una talla nunca queda en blanco.
const SIZE_LABELS = {
  "130": "xxxs", "132": "xxs", "134": "xs", "136": "(S)", "138": "(M)",
  "140": "L", "142": "XL", "144": "XXL",
  "004": "I-XS", "006": "S", "008": "M", "010": "L",
};
const sizeLabelOf = (code) => {
  const k = String(code ?? "").trim();
  return SIZE_LABELS[k] ?? k;
};

const num = (v) => Number(v) || 0;
const nz = (v) => String(v ?? "").trim();
const keyOf = (...parts) => parts.map(nz).join("\u0000");

// Rango de fechas seguro (YYYY-MM-DD). Por defecto: últimos 30 días.
function resolveRange(query) {
  const isYmd = (s) => /^\d{4}-\d{2}-\d{2}$/.test(String(s ?? "").trim());
  const today = new Date();
  const iso = (d) => d.toISOString().slice(0, 10);
  const def = new Date(today); def.setDate(def.getDate() - 29);
  const startDate = isYmd(query.startDate) ? query.startDate.trim() : iso(def);
  const endDate = isYmd(query.endDate) ? query.endDate.trim() : iso(today);
  // Si vienen invertidas, se ordenan.
  return startDate <= endDate ? { startDate, endDate } : { startDate: endDate, endDate: startDate };
}

// initSchema es no-op: este módulo no crea tablas, solo lee de las existentes.
// Se mantiene para encajar en el mismo patrón de registro que los demás.
async function initSchema() {
  console.log("✅ finished-warehouse-analytics ready (read-only, sin tablas propias)");
}

function registerFinishedWarehouseAnalytics(app, deps) {
  const { authenticateToken, pool, setSchema } = deps;

  const withClient = (handler) => async (req, res) => {
    const client = await pool.connect();
    try {
      await setSchema(client);
      await handler(req, res, client);
    } catch (err) {
      try { await client.query("ROLLBACK"); } catch {}
      console.error("❌ finished-warehouse-analytics:", err.message);
      if (!res.headersSent) res.status(500).json({ success: false, error: err.message });
    } finally {
      client.release();
    }
  };

  // =======================================================================
  //  RESUMEN  ->  filas (orden de trabajo · PO cliente) con lo recibido,
  //               comparado contra asignado (merchant) y producido (línea).
  // =======================================================================
  //  GET /api/finished-warehouse/analytics
  //     ?startDate=YYYY-MM-DD & endDate=YYYY-MM-DD   (rango de HORA DE ESCANEO)
  //     &customerId=<id>                              (opcional)
  //     &q=<texto>                                    (opcional: orden / PO / cliente / color / estilo)
  //
  //  Devuelve:
  //     summary  : totales del rango
  //     detail   : [{ work_order_no, customer_po, customer_name, style,
  //                   received, tickets, sizes, assigned, produced,
  //                   pct, lines:[{line_no, received}], first_scan, last_scan }]
  //     byLine   : [{ line_no, received, tickets }]           (de qué línea entró)
  //     byDay    : [{ day, received, tickets }]               (recibido por día)
  //     byCustomer:[{ customer_id, customer_name, received, tickets, orders }]
  // -----------------------------------------------------------------------
  app.get("/api/finished-warehouse/analytics", authenticateToken, withClient(async (req, res, client) => {
    const { startDate, endDate } = resolveRange(req.query);
    const customerId = /^\d+$/.test(String(req.query.customerId ?? "")) ? Number(req.query.customerId) : null;
    const q = nz(req.query.q);

    // Filtro común sobre scanned_tickets (por HORA DE ESCANEO).
    const stParams = [startDate, endDate];
    let stWhere = "WHERE st.scanned_at::date BETWEEN $1 AND $2";
    if (customerId != null) { stParams.push(customerId); stWhere += ` AND st.customer_id = $${stParams.length}`; }
    if (q) {
      stParams.push(`%${q}%`);
      const i = stParams.length;
      stWhere += ` AND (st.work_order_no ILIKE $${i} OR st.customer_po ILIKE $${i}
                     OR st.customer_name ILIKE $${i} OR st.color ILIKE $${i} OR st.style ILIKE $${i})`;
    }

    // (1) RECIBIDO por (orden · PO cliente). MAX() para arrastrar el encabezado.
    const recvRes = await client.query(
      `SELECT st.work_order_no,
              COALESCE(st.customer_po, '')            AS customer_po,
              MAX(st.customer_id)                     AS customer_id,
              MAX(st.customer_name)                   AS customer_name,
              MAX(st.customer_code)                   AS customer_code,
              MAX(st.style)                           AS style,
              SUM(st.pieces)::numeric                 AS received,
              COUNT(*)::int                           AS tickets,
              COUNT(DISTINCT st.size_code)::int       AS sizes,
              MIN(st.scanned_at)                      AS first_scan,
              MAX(st.scanned_at)                      AS last_scan
         FROM scanned_tickets st
         ${stWhere}
        GROUP BY st.work_order_no, COALESCE(st.customer_po, '')
        ORDER BY received DESC
        LIMIT 500`,
      stParams
    );
    const detail = recvRes.rows.map((r) => ({
      work_order_no: r.work_order_no,
      customer_po: r.customer_po || "",
      customer_id: r.customer_id,
      customer_name: r.customer_name,
      customer_code: r.customer_code,
      style: r.style,
      received: Math.round(num(r.received)),
      tickets: num(r.tickets),
      sizes: num(r.sizes),
      first_scan: r.first_scan,
      last_scan: r.last_scan,
      assigned: 0,
      produced: 0,
      pct: 0,
      lines: [],
    }));

    const woNos = [...new Set(detail.map((d) => d.work_order_no).filter(Boolean))];
    const byWoPo = new Map(detail.map((d) => [keyOf(d.work_order_no, d.customer_po), d]));

    // (2) ASIGNADO (merchant) por (orden · PO cliente efectivo). El PO efectivo de
    //     una línea es su propio customer_po o, si viene vacío, el del encabezado.
    if (woNos.length) {
      try {
        const asgRes = await client.query(
          `SELECT wo.work_order_no,
                  COALESCE(NULLIF(l.customer_po, ''), wo.customer_po, '') AS eff_po,
                  SUM(l.quantity)::numeric AS assigned
             FROM work_orders wo
             JOIN work_order_lines l ON l.work_order_id = wo.id
            WHERE wo.work_order_no = ANY($1)
            GROUP BY wo.work_order_no, COALESCE(NULLIF(l.customer_po, ''), wo.customer_po, '')`,
          [woNos]
        );
        // Sumatoria por orden (todas las POs) para poder repartir cuando el PO no cuadra.
        const asgByWo = new Map();
        for (const r of asgRes.rows) {
          const row = byWoPo.get(keyOf(r.work_order_no, r.eff_po));
          if (row) row.assigned += Math.round(num(r.assigned));
          asgByWo.set(r.work_order_no, (asgByWo.get(r.work_order_no) || 0) + Math.round(num(r.assigned)));
        }
        // Filas cuyo PO no empató con ningún PO de línea (p. ej. PO combinada
        // antigua): si la orden tiene una sola fila recibida, hereda el total
        // asignado de la orden, para no mostrar 0 injustamente.
        const rowsByWo = new Map();
        for (const d of detail) {
          const arr = rowsByWo.get(d.work_order_no) || []; arr.push(d); rowsByWo.set(d.work_order_no, arr);
        }
        for (const [wo, rows] of rowsByWo) {
          if (rows.length === 1 && rows[0].assigned === 0) rows[0].assigned = asgByWo.get(wo) || 0;
        }
      } catch (e) {
        console.warn("analytics: work_order_lines no disponible:", e.message);
      }

      // (3) PRODUCIDO (línea) por (orden · PO cliente efectivo) desde ticket_prints.
      try {
        const prodRes = await client.query(
          `SELECT wo.work_order_no,
                  COALESCE(NULLIF(tp.customer_po, ''), wo.customer_po, '') AS eff_po,
                  SUM(tp.quantity)::numeric AS produced
             FROM ticket_prints tp
             JOIN work_orders wo ON wo.id = tp.work_order_id
            WHERE wo.work_order_no = ANY($1)
            GROUP BY wo.work_order_no, COALESCE(NULLIF(tp.customer_po, ''), wo.customer_po, '')`,
          [woNos]
        );
        for (const r of prodRes.rows) {
          const row = byWoPo.get(keyOf(r.work_order_no, r.eff_po));
          if (row) row.produced += Math.round(num(r.produced));
        }
      } catch (e) {
        console.warn("analytics: ticket_prints no disponible:", e.message);
      }
    }

    // (4) De QUÉ LÍNEA entró lo recibido, por (orden · PO cliente).
    try {
      const lineRes = await client.query(
        `SELECT st.work_order_no,
                COALESCE(st.customer_po, '')         AS customer_po,
                COALESCE(NULLIF(lr.line_no, ''), '—') AS line_no,
                SUM(st.pieces)::numeric              AS received,
                COUNT(*)::int                        AS tickets
           FROM scanned_tickets st
           LEFT JOIN line_runs lr ON lr.id = st.run_id
           ${stWhere}
          GROUP BY st.work_order_no, COALESCE(st.customer_po, ''), COALESCE(NULLIF(lr.line_no, ''), '—')`,
        stParams
      );
      for (const r of lineRes.rows) {
        const row = byWoPo.get(keyOf(r.work_order_no, r.customer_po || ""));
        if (row) row.lines.push({ line_no: r.line_no, received: Math.round(num(r.received)), tickets: num(r.tickets) });
      }
      for (const d of detail) d.lines.sort((a, b) => b.received - a.received);
    } catch (e) {
      console.warn("analytics: line_runs no disponible:", e.message);
    }

    // Porcentaje recibido contra lo asignado por el merchant.
    for (const d of detail) d.pct = d.assigned > 0 ? Math.round((d.received / d.assigned) * 100) : 0;

    // ---- Agregados para gráficas ----
    let byLine = [];
    try {
      const r = await client.query(
        `SELECT COALESCE(NULLIF(lr.line_no, ''), '—') AS line_no,
                SUM(st.pieces)::numeric AS received,
                COUNT(*)::int           AS tickets
           FROM scanned_tickets st
           LEFT JOIN line_runs lr ON lr.id = st.run_id
           ${stWhere}
          GROUP BY COALESCE(NULLIF(lr.line_no, ''), '—')
          ORDER BY received DESC`,
        stParams
      );
      byLine = r.rows.map((x) => ({ line_no: x.line_no, received: Math.round(num(x.received)), tickets: num(x.tickets) }));
    } catch (e) { console.warn("analytics byLine:", e.message); }

    const dayRes = await client.query(
      `SELECT to_char(st.scanned_at::date, 'YYYY-MM-DD') AS day,
              SUM(st.pieces)::numeric AS received,
              COUNT(*)::int           AS tickets
         FROM scanned_tickets st
         ${stWhere}
        GROUP BY st.scanned_at::date
        ORDER BY day ASC`,
      stParams
    );
    const byDay = dayRes.rows.map((x) => ({ day: x.day, received: Math.round(num(x.received)), tickets: num(x.tickets) }));

    const custRes = await client.query(
      `SELECT st.customer_id,
              MAX(st.customer_name)                       AS customer_name,
              SUM(st.pieces)::numeric                     AS received,
              COUNT(*)::int                               AS tickets,
              COUNT(DISTINCT st.work_order_no)::int       AS orders
         FROM scanned_tickets st
         ${stWhere}
        GROUP BY st.customer_id
        ORDER BY received DESC`,
      stParams
    );
    const byCustomer = custRes.rows.map((x) => ({
      customer_id: x.customer_id,
      customer_name: x.customer_name || "—",
      received: Math.round(num(x.received)),
      tickets: num(x.tickets),
      orders: num(x.orders),
    }));

    const summary = detail.reduce(
      (s, d) => {
        s.received += d.received;
        s.tickets += d.tickets;
        s.assigned += d.assigned;
        s.produced += d.produced;
        return s;
      },
      { received: 0, tickets: 0, assigned: 0, produced: 0 }
    );
    summary.orders = new Set(detail.map((d) => d.work_order_no)).size;
    summary.pos = new Set(detail.map((d) => keyOf(d.work_order_no, d.customer_po))).size;
    summary.customers = new Set(byCustomer.map((c) => c.customer_id)).size;
    summary.lines = new Set(byLine.map((l) => l.line_no).filter((x) => x !== "—")).size;
    summary.pct = summary.assigned > 0 ? Math.round((summary.received / summary.assigned) * 100) : 0;

    res.json({ success: true, range: { startDate, endDate }, summary, detail, byLine, byDay, byCustomer });
  }));

  // =======================================================================
  //  DESGLOSE POR TALLA de una fila (orden · PO cliente).
  // =======================================================================
  //  GET /api/finished-warehouse/analytics/breakdown
  //     ?workOrder=<work_order_no>   (requerido)
  //     &po=<customer_po>            (opcional; omitir o "__ALL__" = todas las PO)
  //     &startDate & endDate         (rango de HORA DE ESCANEO para lo recibido)
  //
  //  Por cada talla×color:
  //     assigned  = piezas que el MERCHANT asignó (work_order_lines)
  //     produced  = piezas que la LÍNEA imprimió   (ticket_prints)
  //     received  = piezas RECIBIDAS al escanear   (scanned_tickets)
  //     pending   = max(0, assigned - received)
  //     byLine    = [{ line_no, received, produced }]  (de qué línea vinieron)
  // -----------------------------------------------------------------------
  app.get("/api/finished-warehouse/analytics/breakdown", authenticateToken, withClient(async (req, res, client) => {
    const workOrder = nz(req.query.workOrder);
    if (!workOrder) return res.status(400).json({ success: false, error: "Falta workOrder" });

    const { startDate, endDate } = resolveRange(req.query);
    const rawPo = req.query.po;
    const scopeAll = rawPo === undefined || rawPo === "__ALL__";
    const po = scopeAll ? null : nz(rawPo); // '' es un PO válido (sin PO cliente)

    const woRes = await client.query(
      `SELECT id, work_order_no, customer_po AS mo, customer_name,
              COALESCE(estilo, style_code) AS style
         FROM work_orders WHERE work_order_no = $1 LIMIT 1`,
      [workOrder]
    );
    if (woRes.rows.length === 0) return res.status(404).json({ success: false, error: "Orden no encontrada" });
    const wo = woRes.rows[0];
    const headerMo = nz(wo.mo);
    const effMo = (v) => nz(v) || headerMo;
    const inScope = (effPo) => scopeAll || effPo === po;

    const map = new Map(); // talla|color -> fila
    const get = (talla, color) => {
      const k = keyOf(talla, color);
      let row = map.get(k);
      if (!row) {
        row = {
          size_code: talla, size_label: sizeLabelOf(talla), color: nz(color),
          estilo: "", style_code: "",
          assigned: 0, produced: 0, received: 0,
          _lines: new Map(), // line_no -> { received, produced }
        };
        map.set(k, row);
      }
      return row;
    };
    const bumpLine = (row, line_no, field, val) => {
      const ln = nz(line_no) || "—";
      const cur = row._lines.get(ln) || { received: 0, produced: 0 };
      cur[field] += Math.round(num(val));
      row._lines.set(ln, cur);
    };

    // (1) ASIGNADO por talla×color (merchant). estilo cliente para mostrar.
    const asg = await client.query(
      `SELECT talla AS size_code, COALESCE(color, '') AS color,
              COALESCE(estilo, '') AS estilo, customer_po,
              SUM(quantity)::numeric AS assigned
         FROM work_order_lines
        WHERE work_order_id = $1
        GROUP BY talla, COALESCE(color, ''), COALESCE(estilo, ''), customer_po`,
      [wo.id]
    );
    for (const r of asg.rows) {
      if (!inScope(effMo(r.customer_po))) continue;
      const row = get(r.size_code, r.color);
      row.assigned += Math.round(num(r.assigned));
      if (!row.estilo) row.estilo = nz(r.estilo);
    }

    // (2) PRODUCIDO por talla×color×línea (ticket_prints -> line_runs.line_no).
    try {
      const prod = await client.query(
        `SELECT tp.talla AS size_code, COALESCE(tp.color, '') AS color,
                COALESCE(tp.estilo, '') AS estilo, tp.customer_po,
                COALESCE(NULLIF(lr.line_no, ''), '—') AS line_no,
                SUM(tp.quantity)::numeric AS produced
           FROM ticket_prints tp
           JOIN line_runs lr ON lr.id = tp.run_id
          WHERE tp.work_order_id = $1
          GROUP BY tp.talla, COALESCE(tp.color, ''), COALESCE(tp.estilo, ''),
                   tp.customer_po, COALESCE(NULLIF(lr.line_no, ''), '—')`,
        [wo.id]
      );
      for (const r of prod.rows) {
        if (!inScope(effMo(r.customer_po))) continue;
        const row = get(r.size_code, r.color);
        row.produced += Math.round(num(r.produced));
        if (!row.style_code) row.style_code = nz(r.estilo);
        bumpLine(row, r.line_no, "produced", r.produced);
      }
    } catch (e) {
      console.warn("breakdown: ticket_prints no disponible:", e.message);
    }

    // (3) RECIBIDO por talla×color×línea (scanned_tickets -> line_runs.line_no).
    const recvParams = [wo.work_order_no, startDate, endDate];
    let recvWhere = "WHERE st.work_order_no = $1 AND st.scanned_at::date BETWEEN $2 AND $3";
    if (!scopeAll) { recvParams.push(po); recvWhere += ` AND COALESCE(st.customer_po, '') = $${recvParams.length}`; }
    const recv = await client.query(
      `SELECT st.size_code, COALESCE(st.color, '') AS color,
              COALESCE(NULLIF(lr.line_no, ''), '—') AS line_no,
              MAX(st.size_label) AS size_label,
              SUM(st.pieces)::numeric AS received,
              COUNT(*)::int AS tickets
         FROM scanned_tickets st
         LEFT JOIN line_runs lr ON lr.id = st.run_id
         ${recvWhere}
        GROUP BY st.size_code, COALESCE(st.color, ''), COALESCE(NULLIF(lr.line_no, ''), '—')`,
      recvParams
    );
    for (const r of recv.rows) {
      const row = get(r.size_code, r.color);
      row.received += Math.round(num(r.received));
      if ((!row.size_label || row.size_label === row.size_code) && nz(r.size_label)) row.size_label = nz(r.size_label);
      bumpLine(row, r.line_no, "received", r.received);
    }

    // Serializa filas por talla; ordena color, luego talla.
    const sizes = [...map.values()]
      .map((s) => {
        const byLine = [...s._lines.entries()]
          .map(([line_no, v]) => ({ line_no, received: v.received, produced: v.produced }))
          .sort((a, b) => b.received - a.received || b.produced - a.produced);
        return {
          size_code: s.size_code,
          size_label: s.size_label,
          color: s.color,
          estilo: s.estilo,        // estilo cliente (work_order_lines)
          style_code: s.style_code, // código tipo+modelo (line_runs.style)
          assigned: s.assigned,
          produced: s.produced,
          received: s.received,
          pending: Math.max(0, s.assigned - s.received),
          pct: s.assigned > 0 ? Math.round((s.received / s.assigned) * 100) : 0,
          byLine,
        };
      })
      .sort((a, b) => String(a.color).localeCompare(String(b.color)) || String(a.size_code).localeCompare(String(b.size_code)));

    const totals = sizes.reduce(
      (t, s) => {
        t.assigned += s.assigned; t.produced += s.produced;
        t.received += s.received; t.pending += s.pending;
        return t;
      },
      { assigned: 0, produced: 0, received: 0, pending: 0 }
    );
    totals.pct = totals.assigned > 0 ? Math.round((totals.received / totals.assigned) * 100) : 0;

    // Resumen de líneas que aportaron piezas recibidas (para chips en la cabecera).
    const lineTotals = new Map();
    for (const s of sizes) for (const l of s.byLine) {
      const cur = lineTotals.get(l.line_no) || { received: 0, produced: 0 };
      cur.received += l.received; cur.produced += l.produced;
      lineTotals.set(l.line_no, cur);
    }
    const lines = [...lineTotals.entries()]
      .map(([line_no, v]) => ({ line_no, received: v.received, produced: v.produced }))
      .sort((a, b) => b.received - a.received);

    res.json({
      success: true,
      workOrder: { work_order_no: wo.work_order_no, customer_name: wo.customer_name, style: wo.style, mo: wo.mo },
      po: scopeAll ? null : po,
      range: { startDate, endDate },
      sizes, totals, lines,
    });
  }));
}

registerFinishedWarehouseAnalytics.initSchema = initSchema;
module.exports = registerFinishedWarehouseAnalytics;