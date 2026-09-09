// finished-warehouse.js
// ---------------------------------------------------------------------------
// Almacén de Producto Terminado (Finished-goods warehouse) module.
//
// Follows the same shape as work-orders.js:
//   const registerFinishedWarehouse = require("./finished-warehouse");
//   await registerFinishedWarehouse.initSchema({ pool, setSchema });
//   registerFinishedWarehouse(app, { authenticateToken, pool, setSchema });
//
// Provides:
//   • Pre-packing lists (draft) with boxes, auto-filled from a work order (PO).
//   • Confirming a list pushes its boxes into finished_inventory (per SKU).
//   • Inventory + a light dashboard.
//
// Field mapping agreed with the team:
//   PO  = work_orders.work_order_no      (our work order)
//   MO  = work_orders.customer_po        (PO cliente)
//   box_code default = "CT_KUBOT_STANDARD"
//   gross/net weight default 0, encasement_qrcode left blank (system field).
// ---------------------------------------------------------------------------

const DEFAULT_BOX_CODE = "CT_KUBOT_STANDARD";

// Reused for the order-level "producido" total (production isn't tracked per size).
const workOrders = require("./work-orders");

// The columns that identify one finished-goods SKU. Confirming a list adds the
// box quantity onto the matching SKU (or creates it).
const SKU_FIELDS = ["customer_code", "po", "style", "color_code", "size_code", "sex", "fabric_code"];
const skuKeyOf = (b) => SKU_FIELDS.map((f) => String(b[f] ?? "").trim()).join("|");

// SheetJS is only needed for Excel export. Load it lazily so the module still
// boots (and CSV export still works) if the package isn't installed yet.
let XLSX = null;
try { XLSX = require("xlsx"); } catch { /* run `npm install xlsx` to enable .xlsx/.xls */ }

// Codigo de color = color + talla (e.g. color "NEG" + talla "M" -> "NEGM").
const colorCodeOf = (color, talla) => `${String(color ?? "").trim()}${String(talla ?? "").trim()}`;

// Size code -> printable label for the packing list. The DB stores only the code
// (work_order_lines.talla / master_codes.talla); this maps it to the label the
// customer expects. PARTIAL LIST — extend as new size codes appear. Any code not
// found here falls back to printing the code itself, so a size is never blank.
const SIZE_LABELS = {
  "130": "xxxs",
  "132": "xxs",
  "134": "xs",
  "136": "(S)",
  "138": "(M)",
  "140": "L",
  "142": "XL",
  "144": "XXL",
  "004": "I-XS",
  "006": "S",
  "008": "M",
  "010": "L",
};
const sizeLabelOf = (code) => {
  const k = String(code ?? "").trim();
  return SIZE_LABELS[k] ?? k;
};

// BoxRegistry rule agreed with the team: for cliente C&A it is "NCA", blank otherwise.
// Detection is by customer name containing "C&A" (case-insensitive).
const boxRegistryFor = (customerName) =>
  String(customerName ?? "").toUpperCase().includes("C&A") ? "NCA" : null;

// ---------------------------------------------------------------------------
// Escaneo de tickets (intake por escáner)
// ---------------------------------------------------------------------------
// El líder de línea imprime tickets cuyo QR trae TODA la información de ese
// tanto de piezas. En el almacén, el operador escanea cada ticket físico y el
// sistema registra lo que trae + la hora de escaneo. `parseTicketScan` acepta el
// texto crudo que suelta el escáner (o la cámara) y lo normaliza.
//
// Formato principal (QR JSON, generado en LineLeaderPage.generateTickets):
//   {"tn":"T-55-AB-3","wo":"WO-1234","style":"DAMCHA01","talla":"138",
//    "label":"M","color":"NEG","po":"po-1","qty":50,"runId":55,"seq":3,
//    "date":"2026-08-18"}
// Formato alterno (QR de la etiqueta ZPL):
//   WO:WO-1234|RUN:55|T:138|CLR:NEG|PO:po-1|Q:50|S:3/12
const _s = (v) => { const t = String(v ?? "").trim(); return t.length ? t : null; };
const _dateOrNull = (v) => {
  const t = String(v ?? "").trim();
  return /^\d{4}-\d{2}-\d{2}/.test(t) ? t.slice(0, 10) : null;
};

// Base32 (RFC 4648, sin relleno). Los QR nuevos vienen como "FGW1"+base32(JSON):
// solo letras A-Z y dígitos 2-7, idénticos en cualquier distribución de teclado,
// para que un lector configurado en otro idioma no corrompa el contenido.
const _B32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function base32Decode(s) {
  const map = {};
  for (let i = 0; i < _B32_ALPHABET.length; i++) map[_B32_ALPHABET[i]] = i;
  let bits = 0, value = 0;
  const out = [];
  for (const ch of String(s).toUpperCase()) {
    if (!(ch in map)) continue;              // ignora cualquier caracter fuera del alfabeto
    value = (value << 5) | map[ch];
    bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 0xff); bits -= 8; }
  }
  return Buffer.from(out).toString("utf8");
}

// Normaliza el objeto del ticket (venga de JSON directo o de Base32).
function _normalizeTicketObj(o, rawText) {
  const runId = o.runId ?? o.run ?? null;
  const seq = o.seq ?? null;
  const ticketNo = _s(o.tn ?? o.ticketNo ?? o.ticket_no) ||
    (runId != null && seq != null ? `T-${runId}-${seq}` : null);
  return {
    ticket_no: ticketNo,
    work_order_no: _s(o.wo ?? o.workOrderNo ?? o.work_order_no),
    customer_po: _s(o.po ?? o.customerPo ?? o.customer_po),
    style: _s(o.style),
    size_code: _s(o.talla ?? o.size ?? o.size_code),
    size_label: _s(o.label ?? o.size_label) || sizeLabelOf(o.talla ?? o.size),
    color: _s(o.color),
    pieces: Math.max(0, Math.round(Number(o.qty ?? o.pieces) || 0)),
    production_date: _dateOrNull(o.date ?? o.production_date),
    run_id: runId != null ? (Number(runId) || null) : null,
    seq: seq != null ? (Number(seq) || null) : null,
    raw: rawText,
  };
}

// Intento de rescate: tickets viejos con QR JSON leídos por un escáner con
// distribución de teclado distinta llegan con signos cambiados (: -> Ñ, " -> [).
// Revertimos esos cambios comunes y reintentamos. Solo se usa como último recurso
// y solo si el resultado se parece a un ticket (trae wo/qty/talla).
function _repairMangledJson(text) {
  let s = String(text)
    .replace(/[Ññ]/g, ":")
    .replace(/[\[\]]/g, '"');
  if (!s.trim().startsWith("{")) s = "{" + s.replace(/^[^{]*\{?/, "");
  if (!s.trim().endsWith("}")) s = s.replace(/\}?[^}]*$/, "") + "}";
  try {
    const o = JSON.parse(s);
    if (o && (o.wo || o.qty != null || o.talla)) return o;
  } catch { /* no se pudo rescatar */ }
  return null;
}

function parseTicketScan(raw) {
  const text = String(raw ?? "").trim();
  if (!text) return null;

  // 0) QR nuevo compacto, a prueba de teclado: "FGW2" + Base32(posicional "|").
  //    Orden fijo: tn, wo, talla, color, po, qty, date, runId, seq.
  if (/^FGW2[A-Z2-7]/i.test(text)) {
    try {
      const dec = base32Decode(text.slice(4));
      const a = dec.split("|");
      const o = {
        tn: a[0], wo: a[1], talla: a[2], color: a[3], po: a[4],
        qty: a[5], date: a[6], runId: a[7], seq: a[8],
      };
      return _normalizeTicketObj(o, text);
    } catch { /* sigue a los demás formatos */ }
  }

  // 0b) QR anterior a prueba de teclado: "FGW1" + Base32(JSON).
  if (/^FGW1[A-Z2-7]/i.test(text)) {
    try {
      const json = base32Decode(text.slice(4));
      const o = JSON.parse(json);
      return _normalizeTicketObj(o, text);
    } catch { /* sigue a los demás formatos */ }
  }

  // 1) QR JSON directo (lo que devuelve la cámara, o tickets previos).
  if (text.startsWith("{")) {
    try {
      return _normalizeTicketObj(JSON.parse(text), text);
    } catch { /* no era JSON válido, seguimos al formato de tubería */ }
  }

  // 2) Formato de tubería de la etiqueta ZPL antigua (no trae estilo/fecha/número).
  if (/(^|\|)\s*(WO|RUN|T|Q)\s*:/i.test(text)) {
    const map = {};
    for (const part of text.split("|")) {
      const i = part.indexOf(":");
      if (i > 0) map[part.slice(0, i).trim().toUpperCase()] = part.slice(i + 1).trim();
    }
    const clean = (v) => (v && v !== "-" ? v : null);
    const runId = map.RUN ? (Number(map.RUN) || null) : null;
    const seq = map.S ? (Number(String(map.S).split("/")[0]) || null) : null;
    return {
      ticket_no: runId != null && seq != null ? `T-${runId}-${seq}` : null,
      work_order_no: clean(map.WO),
      customer_po: clean(map.PO),
      style: null,
      size_code: clean(map.T),
      size_label: sizeLabelOf(map.T),
      color: clean(map.CLR),
      pieces: Math.max(0, Math.round(Number(map.Q) || 0)),
      production_date: null,
      run_id: runId,
      seq,
      raw: text,
    };
  }

  // 3) Último recurso: JSON viejo corrompido por el teclado (: -> Ñ, " -> [).
  const repaired = _repairMangledJson(text);
  if (repaired) return _normalizeTicketObj(repaired, text);

  return null;
}

// ---------------------------------------------------------------------------
// Desglose de capturas (cuándo entró cada tanto de piezas)
// ---------------------------------------------------------------------------
// El acumulado por talla sale de sumar ticket_prints. Para que el operador vea
// CÓMO se llegó a ese número (p. ej. 50 el lunes + 50 el viernes) necesitamos
// las capturas sin agrupar por completo. Las columnas exactas de ticket_prints /
// line_runs han ido cambiando, así que en vez de asumirlas las consultamos una
// vez y armamos el SELECT con las que existan; si falta alguna, esa parte del
// desglose simplemente sale vacía en lugar de tronar la consulta.
const _colCache = new Map();
async function columnsOf(client, table) {
  if (_colCache.has(table)) return _colCache.get(table);
  let cols = new Map();   // nombre -> data_type
  try {
    const { rows } = await client.query(
      `SELECT column_name, data_type
         FROM information_schema.columns
        WHERE table_name = $1
          AND table_schema = ANY (current_schemas(false))
        ORDER BY ordinal_position`,
      [table]
    );
    cols = new Map(rows.map((r) => [r.column_name, r.data_type]));
  } catch (e) {
    console.warn(`columnsOf(${table}): ${e.message}`);
  }
  _colCache.set(table, cols);
  return cols;
}

// Primera columna de fecha/hora utilizable de una tabla: se prefieren los
// nombres conocidos y, si ninguno está, CUALQUIER columna timestamp. Así el
// desglose funciona aunque la columna se llame distinto de lo esperado.
const TIME_NAME_PREFERENCE = [
  "printed_at", "created_at", "printed_on", "registered_at", "inserted_at",
  "fecha_hora", "fecha", "timestamp", "ts", "updated_at",
];
function timeColumnOf(cols) {
  const isTime = (n) => /^timestamp/.test(String(cols.get(n) ?? ""));
  for (const n of TIME_NAME_PREFERENCE) if (cols.has(n) && isTime(n)) return n;
  for (const n of cols.keys()) if (isTime(n)) return n;
  return null;
}

// Siguiente folio consecutivo para un prefijo (p. ej. "SKM" -> "SKM0001",
// "SKM0002"…). Incremento atómico en ticket_folio_counters, así dos escaneos a
// la vez nunca reciben el mismo número. Se siembra el contador desde el mayor
// folio ya existente la primera vez, para no chocar con datos previos.
async function nextFolio(client, prefix) {
  const p = String(prefix || "TKT").toUpperCase();
  const seedRes = await client.query(
    `SELECT COALESCE(MAX((substring(folio from '^' || $1 || '([0-9]+)'))::int), 0) AS maxseq
       FROM scanned_tickets WHERE folio LIKE $2`,
    [p, `${p}%`]
  );
  const seed = Number(seedRes.rows[0]?.maxseq) || 0;

  const up = await client.query(
    `INSERT INTO ticket_folio_counters (prefix, last_no)
       VALUES ($1, GREATEST($2, 0) + 1)
     ON CONFLICT (prefix) DO UPDATE
       SET last_no = GREATEST(ticket_folio_counters.last_no, $2) + 1
     RETURNING last_no`,
    [p, seed]
  );
  const n = Number(up.rows[0].last_no) || 1;
  return `${p}${String(n).padStart(4, "0")}`;
}

// Número de línea de producción, ya sea en la corrida o en el propio ticket.
const LINE_NAME_PREFERENCE = ["line_no", "line_number", "linea", "line", "no_linea"];
function lineColumnOf(cols) {
  return LINE_NAME_PREFERENCE.find((n) => cols.has(n)) || null;
}

// Capturas individuales de tickets de una orden, hasta la fecha de corte.
// Un renglón = un momento de captura (una impresión de tickets): su fecha, hora
// exacta, línea y piezas. Sumar los renglones de una talla da su acumulado.
//
// Se agrupa por la HORA EXACTA, no por día ni por minuto: dos capturas del mismo
// día (p. ej. 50 a las 21:50 y 50 a las 22:43) tienen que verse por separado,
// que es justo lo que el operador necesita saber. Si la tabla no tuviera columna
// de tiempo, se cae a un renglón por registro (tp.id) para no fusionar capturas.
async function ticketEntriesFor(client, workOrderId, asOfDate) {
  const tp = await columnsOf(client, "ticket_prints");
  const lr = await columnsOf(client, "line_runs");

  const tpTime = timeColumnOf(tp);
  const lrTime = timeColumnOf(lr);
  const tsExpr = tpTime ? `tp."${tpTime}"` : (lrTime ? `lr."${lrTime}"` : "NULL::timestamptz");

  // Día de producción: el mismo eje que usa el resto del sistema (run_date).
  const dayExpr = lr.has("run_date") ? "lr.run_date" : `(${tsExpr})::date`;

  const lineCol = lineColumnOf(lr);
  const tpLineCol = lineColumnOf(tp);
  const lineExpr = lineCol ? `lr."${lineCol}"` : (tpLineCol ? `tp."${tpLineCol}"` : "NULL::int");

  // Sin columna de tiempo, cada registro es su propia captura.
  const grainExpr = (tpTime || lrTime) ? tsExpr : "tp.id";

  const { rows } = await client.query(
    `SELECT tp.talla                          AS size_code,
            COALESCE(tp.color, '')            AS color,
            COALESCE(tp.estilo, '')           AS estilo,
            tp.customer_po,
            to_char(${dayExpr}, 'YYYY-MM-DD') AS day,
            ${lineExpr}                       AS line_no,
            MIN(${tsExpr})                    AS at,
            SUM(tp.quantity)::numeric         AS qty,
            COUNT(*)::int                     AS tickets
       FROM ticket_prints tp
       JOIN line_runs lr ON lr.id = tp.run_id
      WHERE tp.work_order_id = $1
        AND ($2::date IS NULL OR ${dayExpr} <= $2::date)
      GROUP BY tp.talla, COALESCE(tp.color, ''), COALESCE(tp.estilo, ''), tp.customer_po,
               ${dayExpr}, ${lineExpr}, ${grainExpr}
      ORDER BY 5 ASC, 7 ASC NULLS FIRST
      LIMIT 2000`,
    [workOrderId, asOfDate]
  );

  // Se devuelve también QUÉ columnas se usaron: si el desglose sale raro, la
  // respuesta del endpoint dice de dónde salió la hora y la línea.
  return { rows, meta: { timeColumn: tpTime ? `ticket_prints.${tpTime}` : (lrTime ? `line_runs.${lrTime}` : null),
                         lineColumn: lineCol ? `line_runs.${lineCol}` : (tpLineCol ? `ticket_prints.${tpLineCol}` : null) } };
}

// Split an integer `total` across `weights` proportionally, returning whole
// numbers that sum EXACTLY to `total` (largest-remainder / Hamilton method).
// Used to spread the order-level producido across size×color lines by ordered qty.
function allocateProportional(total, weights) {
  const n = weights.length;
  if (n === 0) return [];
  const T = Math.max(0, Math.round(Number(total) || 0));
  const w = weights.map((x) => Math.max(0, Number(x) || 0));
  const sum = w.reduce((s, x) => s + x, 0);

  // No ordered basis to split on -> fall back to an even split.
  const shares = sum > 0 ? w.map((x) => (x / sum) * T) : w.map(() => T / n);

  const parts = shares.map(Math.floor);
  let left = T - parts.reduce((s, x) => s + x, 0);

  // Hand the leftover units to the largest fractional remainders, one each.
  const order = shares
    .map((s, i) => ({ i, frac: s - Math.floor(s) }))
    .sort((a, b) => b.frac - a.frac);
  for (let k = 0; k < order.length && left > 0; k++, left--) parts[order[k].i]++;

  return parts;
}

// Build the box rows for a list straight from its work order's size×color lines.
// One box per work_order_lines row, every field pre-filled from the DB so the
// operator only has to export. Inserts the rows and returns them.
//
// `moFilter` (optional): when given, only the lines whose PO cliente (line
// customer_po, or the order MO if the line has none) equals it are used — this
// is how one order is split into one list per PO cliente. If nothing matches
// (e.g. a legacy list whose mo is a combined value), it falls back to all lines.
//
// `opts.asOfDate` (optional, 'YYYY-MM-DD'): cut-off production day. When given,
// each box's pieces are the ACUMULADO por talla up to and including that day
// (tickets whose run's run_date <= asOfDate). This is how the operator sees "lo
// que llevan las líneas a esta fecha". When omitted, all tickets to date count
// and (for orders without any tickets) we fall back to the proportional split.
//
// NOTE: caller runs inside its own transaction; this only issues queries.
async function generateBoxesFromOrder(client, list, moFilter, opts = {}) {
  if (!list.work_order_id) return [];

  // Cut-off day for the accumulated per-size production (null = all time).
  const asOfDate = /^\d{4}-\d{2}-\d{2}$/.test(String(opts.asOfDate ?? "").trim())
    ? String(opts.asOfDate).trim()
    : (/^\d{4}-\d{2}-\d{2}/.test(String(list.as_of_date ?? "")) // fall back to the list's stored day
        ? String(list.as_of_date).slice(0, 10)
        : null);

  const woRes = await client.query(
    `SELECT work_order_no AS po, customer_po AS mo FROM work_orders WHERE id = $1`,
    [list.work_order_id]
  );
  if (woRes.rows.length === 0) return [];
  const header = woRes.rows[0];

  const linesRes = await client.query(
    `SELECT talla        AS size_code,
            color        AS color_name,
            estilo       AS style,
            customer_po  AS mo,
            fabric_code,
            quantity
       FROM work_order_lines
      WHERE work_order_id = $1
      ORDER BY color, talla`,
    [list.work_order_id]
  );

  const po = header.po || list.po || null;
  const boxRegistry = boxRegistryFor(list.customer_name);

  // Each line's effective PO cliente: its own customer_po, else the order MO.
  const headerMo = String(header.mo ?? "").trim();
  const effMo = (l) => { const m = String(l.mo ?? "").trim(); return m || headerMo; };

  // ── Piezas por talla: lo REALMENTE producido, desde el registro de tickets ──
  // Cada vez que la línea imprime tickets de lo que terminó, queda un renglón en
  // ticket_prints con su talla + color + PO cliente + estilo y las piezas de ese
  // ticket (POST /api/lineleader/confirm-tickets/:runId). Esa es la producción
  // real POR TALLA, así que la usamos directo en lugar de repartir un total de la
  // orden según lo ordenado. Si una orden todavía no tiene tickets registrados
  // (órdenes viejas), caemos al reparto proporcional de siempre para no romper
  // nada.
  const nz = (v) => String(v ?? "").trim();
  const fullKey  = (t, c, po, e) => `${nz(t)}\u0000${nz(c)}\u0000${nz(po)}\u0000${nz(e)}`;
  const looseKey = (t, c, po)    => `${nz(t)}\u0000${nz(c)}\u0000${nz(po)}`;

  const ticketsFull  = new Map();  // talla|color|PO|estilo -> piezas
  const ticketsLoose = new Map();  // talla|color|PO        -> piezas (todas las estilos)
  let ticketsTotal = 0;
  try {
    // Acumulado por talla hasta el día seleccionado: se filtra por el run_date de
    // la corrida (mismo eje "día" que usa el resto del sistema), no por la hora en
    // que se imprimió, para que cuadre con lo que reporta el líder de línea.
    const tRes = await client.query(
      `SELECT tp.talla,
              COALESCE(tp.color, '')       AS color,
              COALESCE(tp.customer_po, '') AS customer_po,
              COALESCE(tp.estilo, '')      AS estilo,
              SUM(tp.quantity)::numeric    AS produced
         FROM ticket_prints tp
         JOIN line_runs lr ON lr.id = tp.run_id
        WHERE tp.work_order_id = $1
          AND ($2::date IS NULL OR lr.run_date <= $2::date)
        GROUP BY tp.talla, COALESCE(tp.color,''), COALESCE(tp.customer_po,''), COALESCE(tp.estilo,'')`,
      [list.work_order_id, asOfDate]
    );
    for (const r of tRes.rows) {
      const q = Number(r.produced) || 0;
      if (q <= 0) continue;
      ticketsTotal += q;
      ticketsFull.set(fullKey(r.talla, r.color, r.customer_po, r.estilo), q);
      const lk = looseKey(r.talla, r.color, r.customer_po);
      ticketsLoose.set(lk, (ticketsLoose.get(lk) || 0) + q);
    }
  } catch (e) {
    // ticket_prints ausente/inaccesible → nos quedamos con el reparto proporcional.
    console.warn("generateBoxesFromOrder: ticket_prints no disponible:", e.message);
  }

  // Piezas producidas para una línea (talla×color×estilo×PO cliente) desde tickets.
  // Preferimos el match exacto con estilo; si el estilo no cuadra, caemos al match
  // por talla+color+PO. El PO cliente de la línea puede venir en la propia línea o
  // heredarse del encabezado, así que probamos ambos, y también el caso sin PO.
  const producedFromTickets = (l) => {
    const t = l.size_code, c = l.color_name, e = l.style;
    const poRaw = nz(l.mo), poEff = effMo(l);
    for (const k of [fullKey(t, c, poRaw, e), fullKey(t, c, poEff, e), fullKey(t, c, "", e)])
      if (ticketsFull.has(k)) return ticketsFull.get(k);
    for (const k of [looseKey(t, c, poRaw), looseKey(t, c, poEff), looseKey(t, c, "")])
      if (ticketsLoose.has(k)) return ticketsLoose.get(k);
    return 0;
  };

  let rows;
  if (ticketsTotal > 0 || asOfDate) {
    // Fuente de verdad por talla: los tickets impresos por la línea, acumulados a
    // la fecha. Una talla sin ticket queda en 0 (aún no se ha producido esa talla
    // a esa fecha), no en un estimado. Cuando se pidió una fecha NO caemos al
    // reparto proporcional: ese total es de todo el tiempo y no conoce la fecha.
    rows = linesRes.rows.map((l) => ({ ...l, _alloc: producedFromTickets(l) }));
  } else {
    // Sin fecha y sin tickets registrados (órdenes previas a la captura por
    // ticket): reparto proporcional del producido de la orden por lo ordenado —
    // comportamiento anterior. Se hace sobre TODAS las líneas primero para que, al
    // acotar a un PO cliente, cada quien reciba solo su parte y el total cuadre.
    const producedTotal = await workOrders.producedQuantityFor(client, list.work_order_id);
    const allocation = allocateProportional(
      producedTotal,
      linesRes.rows.map((l) => Number(l.quantity) || 0)
    );
    rows = linesRes.rows.map((l, i) => ({ ...l, _alloc: allocation[i] }));
  }

  // Scope to one PO cliente when asked (fall back to all lines if none match).
  if (moFilter != null && String(moFilter).trim() !== "") {
    const want = String(moFilter).trim();
    const scoped = rows.filter((l) => effMo(l) === want);
    if (scoped.length > 0) rows = scoped;
  }

  const inserted = [];
  for (const l of rows) {
    const { rows: ins } = await client.query(
      `INSERT INTO pre_packing_boxes
         (list_id, box_qrcode, encasement_qrcode, mo, po, style, fabric_code, sex,
          size_code, color_name, color_code, quantity, box_code, box_registry,
          gross_weight, net_weight, customer_code, customer_name)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
       RETURNING *`,
      [
        list.id,
        null,                                   // box_qrcode — ticket is the PO on export
        null,                                   // encasement_qrcode (system field)
        effMo(l) || list.mo || null,
        po,
        l.style || null,                        // "label" = estilo -> Estyle column
        l.fabric_code || null,
        null,                                   // sex -> Genero 0 on export
        l.size_code || null,
        l.color_name || null,
        colorCodeOf(l.color_name, l.size_code) || null,
        l._alloc,                               // piezas reales por talla (tickets); reparto proporcional solo si no hay tickets
        DEFAULT_BOX_CODE,
        boxRegistry,
        0,
        0,
        list.customer_code || null,
        list.customer_name || null,
      ]
    );
    inserted.push(ins[0]);
  }
  return inserted;
}

// Distinct PO cliente (MO) values across a work order's lines. A line with no
// customer_po falls back to the order-level MO. Drives the "one list per PO
// cliente" split at create time. Returned sorted for stable list numbering.
async function distinctLineMos(client, workOrderId, headerMo) {
  const { rows } = await client.query(
    `SELECT DISTINCT COALESCE(NULLIF(TRIM(customer_po), ''), $2) AS mo
       FROM work_order_lines
      WHERE work_order_id = $1`,
    [workOrderId, String(headerMo ?? "").trim()]
  );
  return rows
    .map((r) => String(r.mo ?? "").trim())
    .filter((m) => m.length > 0)
    .sort((a, b) => a.localeCompare(b));
}

async function initSchema({ pool, setSchema }) {
  const client = await pool.connect();
  try {
    await setSchema(client);

    // Header: one pre-packing list, tied to a client and (optionally) a work order.
    await client.query(`
      CREATE TABLE IF NOT EXISTS pre_packing_lists(
        id BIGSERIAL PRIMARY KEY,
        list_no VARCHAR(20) UNIQUE,
        customer_id BIGINT REFERENCES customers(id) ON DELETE SET NULL,
        customer_code VARCHAR(20),
        customer_name VARCHAR(150),
        work_order_id BIGINT REFERENCES work_orders(id) ON DELETE SET NULL,
        po VARCHAR(60),
        mo VARCHAR(60),
        status VARCHAR(20) NOT NULL DEFAULT 'draft',
        notes TEXT,
        created_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        confirmed_at TIMESTAMPTZ,
        CONSTRAINT chk_pp_status CHECK (status IN ('draft','confirmed','cancelled'))
      );
    `);
    await client.query("CREATE INDEX IF NOT EXISTS idx_pp_lists_customer ON pre_packing_lists(customer_id);");
    await client.query("CREATE INDEX IF NOT EXISTS idx_pp_lists_status ON pre_packing_lists(status);");
    // Día de corte de la lista: las piezas por talla son el acumulado de la
    // producción de las líneas hasta este día (null = todo el tiempo).
    await client.query("ALTER TABLE pre_packing_lists ADD COLUMN IF NOT EXISTS as_of_date DATE;");

    // One row = one box.
    await client.query(`
      CREATE TABLE IF NOT EXISTS pre_packing_boxes(
        id BIGSERIAL PRIMARY KEY,
        list_id BIGINT NOT NULL REFERENCES pre_packing_lists(id) ON DELETE CASCADE,
        box_qrcode VARCHAR(120),
        encasement_qrcode VARCHAR(120),
        mo VARCHAR(60),
        po VARCHAR(60),
        style VARCHAR(60),
        fabric_code VARCHAR(60),
        sex VARCHAR(10),
        size_code VARCHAR(20),
        color_name VARCHAR(60),
        color_code VARCHAR(20),
        quantity NUMERIC(12,2) NOT NULL DEFAULT 0,
        box_code VARCHAR(60) DEFAULT '${DEFAULT_BOX_CODE}',
        box_registry VARCHAR(60),
        gross_weight NUMERIC(12,3) NOT NULL DEFAULT 0,
        net_weight NUMERIC(12,3) NOT NULL DEFAULT 0,
        customer_code VARCHAR(20),
        customer_name VARCHAR(150),
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        CONSTRAINT chk_pp_box_qty CHECK (quantity >= 0)
      );
    `);
    await client.query("CREATE INDEX IF NOT EXISTS idx_pp_boxes_list ON pre_packing_boxes(list_id);");

    // Aggregated finished-goods stock. sku_key is maintained by the app so the
    // confirm step can upsert with a plain ON CONFLICT.
    await client.query(`
      CREATE TABLE IF NOT EXISTS finished_inventory(
        id BIGSERIAL PRIMARY KEY,
        sku_key TEXT UNIQUE NOT NULL,
        customer_id BIGINT REFERENCES customers(id) ON DELETE SET NULL,
        customer_code VARCHAR(20),
        customer_name VARCHAR(150),
        po VARCHAR(60),
        mo VARCHAR(60),
        style VARCHAR(60),
        fabric_code VARCHAR(60),
        sex VARCHAR(10),
        size_code VARCHAR(20),
        color_name VARCHAR(60),
        color_code VARCHAR(20),
        quantity NUMERIC(14,2) NOT NULL DEFAULT 0,
        box_count INT NOT NULL DEFAULT 0,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );
    `);

    // Audit trail of every stock movement (one row per confirmed box).
    await client.query(`
      CREATE TABLE IF NOT EXISTS finished_inventory_movements(
        id BIGSERIAL PRIMARY KEY,
        inventory_id BIGINT REFERENCES finished_inventory(id) ON DELETE SET NULL,
        list_id BIGINT REFERENCES pre_packing_lists(id) ON DELETE SET NULL,
        box_id BIGINT,
        direction VARCHAR(6) NOT NULL DEFAULT 'in',
        quantity NUMERIC(14,2) NOT NULL,
        created_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        CONSTRAINT chk_fim_dir CHECK (direction IN ('in','out','adjust'))
      );
    `);
    await client.query("CREATE INDEX IF NOT EXISTS idx_fim_list ON finished_inventory_movements(list_id);");

    // Tickets escaneados en el almacén de producto terminado. Un renglón = un
    // ticket físico escaneado. ticket_no es único para poder ignorar re-escaneos
    // del mismo ticket (idempotente). scanned_at es la HORA DE ESCANEO (servidor).
    await client.query(`
      CREATE TABLE IF NOT EXISTS scanned_tickets(
        id BIGSERIAL PRIMARY KEY,
        ticket_no VARCHAR(80) UNIQUE,
        work_order_no VARCHAR(60),
        customer_po VARCHAR(60),
        style VARCHAR(60),
        size_code VARCHAR(20),
        size_label VARCHAR(30),
        color VARCHAR(60),
        pieces NUMERIC(12,2) NOT NULL DEFAULT 0,
        production_date DATE,
        run_id BIGINT,
        seq INT,
        raw TEXT,
        scanned_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
        scanned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        CONSTRAINT chk_scan_pieces CHECK (pieces >= 0)
      );
    `);
    await client.query("CREATE INDEX IF NOT EXISTS idx_scan_wo ON scanned_tickets(work_order_no);");
    await client.query("CREATE INDEX IF NOT EXISTS idx_scan_at ON scanned_tickets(scanned_at DESC);");

    // Folio de recepción (consecutivo tipo SKM0001, SKM0002…) + cliente. El folio
    // se asigna al escanear; el cliente se resuelve desde la orden de trabajo.
    // ADD COLUMN IF NOT EXISTS para actualizar bases ya creadas sin perder datos.
    await client.query("ALTER TABLE scanned_tickets ADD COLUMN IF NOT EXISTS folio VARCHAR(30);");
    await client.query("ALTER TABLE scanned_tickets ADD COLUMN IF NOT EXISTS customer_id BIGINT;");
    await client.query("ALTER TABLE scanned_tickets ADD COLUMN IF NOT EXISTS customer_code VARCHAR(20);");
    await client.query("ALTER TABLE scanned_tickets ADD COLUMN IF NOT EXISTS customer_name VARCHAR(150);");
    await client.query("CREATE UNIQUE INDEX IF NOT EXISTS idx_scan_folio ON scanned_tickets(folio) WHERE folio IS NOT NULL;");

    // Contador de folios por prefijo (p. ej. 'SKM'), incremento atómico para que
    // dos escaneos simultáneos nunca tomen el mismo número.
    await client.query(`
      CREATE TABLE IF NOT EXISTS ticket_folio_counters(
        prefix VARCHAR(20) PRIMARY KEY,
        last_no INT NOT NULL DEFAULT 0
      );
    `);

    console.log("✅ finished-warehouse tables ready in prod_db_schema");
  } finally {
    client.release();
  }
}

function registerFinishedWarehouse(app, deps) {
  const { authenticateToken, pool, setSchema } = deps;

  // Small helper to run a handler with a schema-scoped client.
  const withClient = (handler) => async (req, res) => {
    const client = await pool.connect();
    try {
      await setSchema(client);
      await handler(req, res, client);
    } catch (err) {
      try { await client.query("ROLLBACK"); } catch {}
      console.error("❌ finished-warehouse:", err.message);
      if (!res.headersSent) res.status(500).json({ success: false, error: err.message });
    } finally {
      client.release();
    }
  };

  // ======================================================================
  //  LOOKUPS (populate the Pre-empaque form)
  // ======================================================================

  // Clients for the "select client" dropdown.
  app.get("/api/finished-warehouse/clients", authenticateToken, withClient(async (req, res, client) => {
    const { rows } = await client.query(
      `SELECT id, code, name, market_type FROM customers ORDER BY name ASC`
    );
    res.json({ success: true, clients: rows });
  }));

  // Work orders (POs) — optionally filtered by client — with the fields we
  // auto-fill from. po = work_order_no, mo = customer_po.
  app.get("/api/finished-warehouse/work-orders", authenticateToken, withClient(async (req, res, client) => {
    const { customerId } = req.query;
    const params = [];
    let where = "WHERE wo.status <> 'cancelled'";
    if (customerId) { params.push(customerId); where += ` AND wo.customer_id = $${params.length}`; }
    const { rows } = await client.query(
      `SELECT wo.id,
              wo.work_order_no                     AS po,
              wo.customer_po                       AS mo,
              COALESCE(wo.estilo, wo.style_code)   AS style,
              wo.fabric_code,
              wo.color                             AS color_name,
              wo.customer_id,
              wo.customer_name,
              c.code                               AS customer_code
         FROM work_orders wo
         LEFT JOIN customers c ON c.id = wo.customer_id
         ${where}
         ORDER BY wo.created_at DESC
         LIMIT 500`,
      params
    );
    res.json({ success: true, workOrders: rows });
  }));

  // Everything needed to pre-fill the box form for one work order, plus its
  // size×color lines so the operator can pick a row instead of retyping.
  app.get("/api/finished-warehouse/autofill/:workOrderId", authenticateToken, withClient(async (req, res, client) => {
    const woId = parseInt(req.params.workOrderId, 10);
    const woRes = await client.query(
      `SELECT wo.id,
              wo.work_order_no                     AS po,
              wo.customer_po                       AS mo,
              COALESCE(wo.estilo, wo.style_code)   AS style,
              wo.fabric_code,
              wo.color                             AS color_name,
              wo.customer_id,
              wo.customer_name,
              c.code                               AS customer_code
         FROM work_orders wo
         LEFT JOIN customers c ON c.id = wo.customer_id
        WHERE wo.id = $1`,
      [woId]
    );
    if (woRes.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Orden de trabajo no encontrada" });
    }
    const header = woRes.rows[0];

    const linesRes = await client.query(
      `SELECT l.talla        AS size_code,
              l.color        AS color_name,
              l.estilo       AS style,
              l.customer_po  AS mo,
              l.fabric_code,
              l.quantity
         FROM work_order_lines l
        WHERE l.work_order_id = $1
        ORDER BY l.color, l.talla`,
      [woId]
    );

    res.json({ success: true, header, lines: linesRes.rows });
  }));

  // Line-leader INPUT for one work order: what each production line has reported
  // as finished (packing/terminado ops), plus ordered vs produced totals. Lets
  // the Almacén PT operator see "qué entró de cada línea" and judge WHEN a work
  // order has enough finished to build its pre-packing list. Read-only.
  app.get("/api/finished-warehouse/work-orders/:workOrderId/line-production", authenticateToken, withClient(async (req, res, client) => {
    const woId = parseInt(req.params.workOrderId, 10);
    const woRes = await client.query(
      `SELECT id, work_order_no AS po, customer_po AS mo FROM work_orders WHERE id = $1`, [woId]
    );
    if (woRes.rows.length === 0) return res.status(404).json({ success: false, error: "Orden de trabajo no encontrada" });

    // Ordered = sum of the order's size×color lines. Produced = order-level total
    // from the same packing-operation logic the planner uses (single source).
    const ordRes = await client.query(
      `SELECT COALESCE(SUM(quantity), 0) AS ordered FROM work_order_lines WHERE work_order_id = $1`, [woId]
    );
    const orderedTotal = Number(ordRes.rows[0].ordered) || 0;

    const lines = await workOrders.producedByLineFor(client, woId);   // [{ line_no, finished, last_reported_at }]
    const producedTotal = await workOrders.producedQuantityFor(client, woId);

    res.json({ success: true, workOrder: woRes.rows[0], orderedTotal, producedTotal, lines });
  }));

  // DASHBOARD feed: work orders that have line production, most recently active
  // first, each with ordered/produced totals, the per-line breakdown, and any
  // pre-packing lists already started. This is what the "Entrada de líneas" view
  // reads so the operator can spot which orders are ready to pre-empaque.
  app.get("/api/finished-warehouse/line-input", authenticateToken, withClient(async (req, res, client) => {
    const limit = Math.min(200, Math.max(1, parseInt(req.query.limit, 10) || 60));

    // Candidate orders: any with production runs, not cancelled, newest activity first.
    const woRes = await client.query(
      `SELECT wo.id,
              wo.work_order_no                   AS po,
              wo.customer_po                     AS mo,
              COALESCE(wo.estilo, wo.style_code) AS style,
              wo.customer_id,
              wo.customer_name,
              c.code                             AS customer_code,
              MAX(lr.updated_at)                 AS last_activity
         FROM work_orders wo
         JOIN line_runs lr ON lr.work_order_id = wo.id
         LEFT JOIN customers c ON c.id = wo.customer_id
        WHERE wo.status <> 'cancelled'
        GROUP BY wo.id, c.code
        ORDER BY MAX(lr.updated_at) DESC NULLS LAST
        LIMIT $1`,
      [limit]
    );
    const orders = woRes.rows;
    if (orders.length === 0) return res.json({ success: true, orders: [] });
    const ids = orders.map((o) => o.id);

    // Ordered totals, existing lists, and per-line production — one query each.
    const ordRes = await client.query(
      `SELECT work_order_id, COALESCE(SUM(quantity), 0) AS ordered
         FROM work_order_lines WHERE work_order_id = ANY($1) GROUP BY work_order_id`, [ids]
    );
    const orderedBy = new Map(ordRes.rows.map((r) => [Number(r.work_order_id), Number(r.ordered) || 0]));

    const listRes = await client.query(
      `SELECT work_order_id, list_no, status FROM pre_packing_lists
        WHERE work_order_id = ANY($1) ORDER BY id ASC`, [ids]
    );
    const listsBy = new Map();
    for (const r of listRes.rows) {
      const key = Number(r.work_order_id);
      const arr = listsBy.get(key) || [];
      arr.push({ list_no: r.list_no, status: r.status });
      listsBy.set(key, arr);
    }

    const lineMap = await workOrders.producedByLineForMany(client, ids);

    const result = orders.map((o) => {
      const lines = lineMap.get(Number(o.id)) || [];
      const producedTotal = lines.reduce((s, l) => s + (Number(l.finished) || 0), 0);
      return {
        id: o.id,
        po: o.po,
        mo: o.mo,
        style: o.style,
        customer_id: o.customer_id,
        customer_name: o.customer_name,
        customer_code: o.customer_code,
        orderedTotal: orderedBy.get(Number(o.id)) || 0,
        producedTotal,
        lastActivity: o.last_activity,
        lines,
        lists: listsBy.get(Number(o.id)) || [],
      };
    });

    res.json({ success: true, orders: result });
  }));

  // ======================================================================
  //  ESCANEO DE TICKETS (intake por escáner en el almacén)
  // ======================================================================

  // Un ticket escaneado -> un renglón. El body puede traer:
  //   { raw: "<texto tal cual salió del escáner>" }   (recomendado)
  // o los campos ya decodificados por el cliente. El servidor decodifica el QR
  // (JSON o formato de tubería ZPL), y guarda el ticket con la HORA DE ESCANEO.
  // Es idempotente por ticket_no: re-escanear el mismo ticket NO duplica; regresa
  // { duplicate: true } con el registro original.
  app.post("/api/finished-warehouse/scan", authenticateToken, withClient(async (req, res, client) => {
    const body = req.body || {};

    // Aceptamos el texto crudo (lo normal) o un objeto ya parseado por el front.
    const parsed = body.raw != null
      ? parseTicketScan(body.raw)
      : parseTicketScan(JSON.stringify(body));

    if (!parsed || (!parsed.work_order_no && !parsed.ticket_no)) {
      return res.status(400).json({ success: false, error: "No se pudo leer el ticket. Verifique el código QR." });
    }

    // Número impreso en el QR (T-…): sirve como llave para NO duplicar re-escaneos.
    // Si el código no lo trae (formatos viejos), derivamos uno estable del contenido.
    if (!parsed.ticket_no) {
      const basis = [parsed.work_order_no, parsed.size_code, parsed.color, parsed.customer_po, parsed.run_id, parsed.seq]
        .map((x) => String(x ?? "")).join("|");
      let h = 0;
      for (let i = 0; i < basis.length; i++) h = (h * 31 + basis.charCodeAt(i)) >>> 0;
      parsed.ticket_no = `SCAN-${h.toString(36).toUpperCase()}`;
    }

    // ── Re-escaneo: si el mismo ticket ya se escaneó, devolvemos el original
    //    (con su folio y cliente) y NO consumimos un folio nuevo. ────────────
    const existing = await client.query(`SELECT * FROM scanned_tickets WHERE ticket_no = $1`, [parsed.ticket_no]);
    if (existing.rows.length > 0) {
      return res.json({ success: true, duplicate: true, ticket: existing.rows[0] });
    }

    // ── Cliente: se resuelve desde la orden de trabajo (wo = work_order_no). ──
    let customer = { id: null, code: null, name: null };
    if (parsed.work_order_no) {
      const cRes = await client.query(
        `SELECT wo.customer_id, wo.customer_name, c.code AS customer_code
           FROM work_orders wo
           LEFT JOIN customers c ON c.id = wo.customer_id
          WHERE wo.work_order_no = $1
          LIMIT 1`,
        [parsed.work_order_no]
      );
      if (cRes.rows.length) {
        customer = { id: cRes.rows[0].customer_id, code: cRes.rows[0].customer_code, name: cRes.rows[0].customer_name };
      }
    }

    // ── Folio consecutivo (SKM0001, SKM0002…). El prefijo sale de las letras
    //    iniciales del No. de orden (SKM0001-… → "SKM"); si no hay, usamos "TKT".
    const folioPrefix = (String(parsed.work_order_no ?? "").match(/^[A-Za-z]+/)?.[0] || "TKT").toUpperCase();
    const folio = await nextFolio(client, folioPrefix);

    const ins = await client.query(
      `INSERT INTO scanned_tickets
         (folio, ticket_no, work_order_no, customer_id, customer_code, customer_name,
          customer_po, style, size_code, size_label, color, pieces, production_date,
          run_id, seq, raw, scanned_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
       ON CONFLICT (ticket_no) DO NOTHING
       RETURNING *`,
      [
        folio, parsed.ticket_no, parsed.work_order_no, customer.id, customer.code, customer.name,
        parsed.customer_po, parsed.style, parsed.size_code, parsed.size_label, parsed.color,
        parsed.pieces, parsed.production_date, parsed.run_id, parsed.seq, parsed.raw, req.user?.id ?? null,
      ]
    );

    if (ins.rows.length > 0) {
      return res.json({ success: true, duplicate: false, ticket: ins.rows[0] });
    }

    // Carrera rarísima (dos escaneos idénticos a la vez): devolvemos el que ganó.
    const prev = await client.query(`SELECT * FROM scanned_tickets WHERE ticket_no = $1`, [parsed.ticket_no]);
    return res.json({ success: true, duplicate: true, ticket: prev.rows[0] || null });
  }));

  // Lista de tickets escaneados (más reciente primero) + totales. Filtros
  // opcionales: q (texto), workOrder (No. de orden), po, date (YYYY-MM-DD).
  app.get("/api/finished-warehouse/scanned-tickets", authenticateToken, withClient(async (req, res, client) => {
    const { q, workOrder, po, date } = req.query;
    const limit = Math.min(1000, Math.max(1, parseInt(req.query.limit, 10) || 300));
    const params = [];
    let where = "WHERE 1=1";
    if (workOrder) { params.push(workOrder); where += ` AND work_order_no = $${params.length}`; }
    if (po)        { params.push(po);        where += ` AND customer_po = $${params.length}`; }
    if (date && /^\d{4}-\d{2}-\d{2}$/.test(String(date))) {
      params.push(date); where += ` AND scanned_at::date = $${params.length}::date`;
    }
    if (q) {
      params.push(`%${q}%`);
      where += ` AND (ticket_no ILIKE $${params.length} OR work_order_no ILIKE $${params.length}
                   OR customer_po ILIKE $${params.length} OR color ILIKE $${params.length}
                   OR style ILIKE $${params.length})`;
    }
    params.push(limit);
    const { rows } = await client.query(
      `SELECT * FROM scanned_tickets ${where} ORDER BY scanned_at DESC LIMIT $${params.length}`, params
    );
    const totals = rows.reduce(
      (t, r) => { t.tickets += 1; t.pieces += Number(r.pieces) || 0; return t; },
      { tickets: 0, pieces: 0 }
    );
    res.json({ success: true, tickets: rows, totals });
  }));

  // Deshacer un escaneo (p. ej. un ticket escaneado por error).
  app.delete("/api/finished-warehouse/scanned-tickets/:id", authenticateToken, withClient(async (req, res, client) => {
    const id = parseInt(req.params.id, 10);
    const del = await client.query(`DELETE FROM scanned_tickets WHERE id = $1 RETURNING id`, [id]);
    if (del.rows.length === 0) return res.status(404).json({ success: false, error: "Ticket no encontrado" });
    res.json({ success: true });
  }));

  // ======================================================================
  //  PRE-PACKING LISTS
  // ======================================================================

  // List index with box_count + total_qty.
  app.get("/api/pre-packing-lists", authenticateToken, withClient(async (req, res, client) => {
    const { status, customerId, q } = req.query;
    const params = [];
    let where = "WHERE 1=1";
    if (status)     { params.push(status);     where += ` AND l.status = $${params.length}`; }
    if (customerId) { params.push(customerId); where += ` AND l.customer_id = $${params.length}`; }
    if (q)          { params.push(`%${q}%`);   where += ` AND (l.list_no ILIKE $${params.length} OR l.po ILIKE $${params.length} OR l.mo ILIKE $${params.length} OR l.customer_name ILIKE $${params.length})`; }

    const { rows } = await client.query(
      `SELECT l.*,
              COALESCE(b.box_count, 0)  AS box_count,
              COALESCE(b.total_qty, 0)  AS total_qty
         FROM pre_packing_lists l
         LEFT JOIN (
           SELECT list_id, COUNT(*) AS box_count, SUM(quantity) AS total_qty
             FROM pre_packing_boxes GROUP BY list_id
         ) b ON b.list_id = l.id
         ${where}
         ORDER BY l.created_at DESC
         LIMIT 500`,
      params
    );
    res.json({ success: true, lists: rows });
  }));

  // One list with its boxes.
  app.get("/api/pre-packing-lists/:id", authenticateToken, withClient(async (req, res, client) => {
    const id = parseInt(req.params.id, 10);
    const listRes = await client.query(`SELECT * FROM pre_packing_lists WHERE id = $1`, [id]);
    if (listRes.rows.length === 0) return res.status(404).json({ success: false, error: "Lista no encontrada" });
    const boxesRes = await client.query(
      `SELECT * FROM pre_packing_boxes WHERE list_id = $1 ORDER BY id ASC`, [id]
    );
    res.json({ success: true, list: listRes.rows[0], boxes: boxesRes.rows });
  }));

  // Progreso POR TALLA para una lista, a una fecha de corte.
  //   GET /api/pre-packing-lists/:id/size-progress?date=YYYY-MM-DD
  // Para cada talla (× color × estilo) de la orden, scoped al PO cliente de la
  // lista, regresa:
  //   ordered   = total de esa talla en la orden ("cuánto hay que alcanzar")
  //   produced  = ACUMULADO por talla hasta la fecha (tickets de la línea)
  //   remaining = ordered - produced (lo que falta para llegar)
  // Más `availableDays`: los días con producción por talla, para poblar el
  // selector de fecha. Read-only; no toca cajas.
  app.get("/api/pre-packing-lists/:id/size-progress", authenticateToken, withClient(async (req, res, client) => {
    const id = parseInt(req.params.id, 10);
    const listRes = await client.query(
      `SELECT id, work_order_id, mo, as_of_date FROM pre_packing_lists WHERE id = $1`, [id]
    );
    if (listRes.rows.length === 0) return res.status(404).json({ success: false, error: "Lista no encontrada" });
    const list = listRes.rows[0];
    if (!list.work_order_id) {
      return res.json({ success: true, date: null, mo: list.mo, availableDays: [], sizes: [], totals: { ordered: 0, produced: 0, remaining: 0 } });
    }

    // Fecha efectiva: query > la guardada en la lista > null (todo el tiempo).
    const rawDate = String(req.query.date ?? "").trim();
    const asOfDate = /^\d{4}-\d{2}-\d{2}$/.test(rawDate)
      ? rawDate
      : (list.as_of_date ? String(list.as_of_date).slice(0, 10) : null);

    const woRes = await client.query(`SELECT customer_po AS mo FROM work_orders WHERE id = $1`, [list.work_order_id]);
    const headerMo = String(woRes.rows[0]?.mo ?? "").trim();
    const effMo = (po) => { const m = String(po ?? "").trim(); return m || headerMo; };
    const nz = (v) => String(v ?? "").trim();
    // OJO con "estilo": NO es el mismo campo en los dos lados.
    //   work_order_lines.estilo = estilo CLIENTE (6 caracteres, p. ej. 030800)
    //   ticket_prints.estilo    = viene de line_runs.style, que es el código de
    //                             estilo tipo+modelo+correlativo (p. ej. DAMCHA01)
    // Compararlos como texto nunca cuadra y partía cada talla en dos renglones
    // (uno con la meta y otro con lo producido). El cruce real es por
    // talla × color × PO cliente; cada código se conserva solo para mostrarse.
    const key = (t, c, mo) => `${nz(t)}\u0000${nz(c)}\u0000${nz(mo)}`;

    // Ordenado por talla×color×estilo×PO cliente.
    const ordRes = await client.query(
      `SELECT talla AS size_code, COALESCE(color,'') AS color, COALESCE(estilo,'') AS estilo,
              customer_po, SUM(quantity)::numeric AS ordered
         FROM work_order_lines
        WHERE work_order_id = $1
        GROUP BY talla, COALESCE(color,''), COALESCE(estilo,''), customer_po`,
      [list.work_order_id]
    );

    // Producido acumulado a la fecha (por run_date de la corrida).
    let prodRows = [];
    try {
      const prodRes = await client.query(
        `SELECT tp.talla AS size_code, COALESCE(tp.color,'') AS color, COALESCE(tp.estilo,'') AS estilo,
                tp.customer_po, SUM(tp.quantity)::numeric AS produced
           FROM ticket_prints tp
           JOIN line_runs lr ON lr.id = tp.run_id
          WHERE tp.work_order_id = $1
            AND ($2::date IS NULL OR lr.run_date <= $2::date)
          GROUP BY tp.talla, COALESCE(tp.color,''), COALESCE(tp.estilo,''), tp.customer_po`,
        [list.work_order_id, asOfDate]
      );
      prodRows = prodRes.rows;
    } catch (e) {
      console.warn("size-progress: ticket_prints no disponible:", e.message);
    }

    // Capturas individuales (día · línea · hora → piezas), para explicar el
    // acumulado de cada talla. Mismo filtro de fecha que el agregado de arriba.
    let entryRows = [];
    let entriesMeta = null;
    try {
      const e = await ticketEntriesFor(client, list.work_order_id, asOfDate);
      entryRows = e.rows;
      entriesMeta = e.meta;
    } catch (e) {
      console.warn("size-progress: desglose de capturas no disponible:", e.message);
    }
    const entriesBy = new Map();
    for (const r of entryRows) {
      const k = key(r.size_code, r.color, effMo(r.customer_po));
      const arr = entriesBy.get(k) || [];
      arr.push({
        day: r.day,
        at: r.at,
        // line_runs.line_no es TEXT en este esquema (puede ser "1" o "A1"), así
        // que se pasa tal cual en vez de convertirlo a número.
        line_no: r.line_no == null ? null : (String(r.line_no).trim() || null),
        qty: Math.round(Number(r.qty) || 0),
        tickets: Number(r.tickets) || 0,
      });
      entriesBy.set(k, arr);
    }

    // Merge ordenado + producido por talla×color×estilo×PO cliente efectivo.
    const map = new Map();
    const bump = (r, field, val) => {
      const mo = effMo(r.customer_po);
      const k = key(r.size_code, r.color, mo);
      let row = map.get(k);
      if (!row) { row = { size_code: r.size_code, color: r.color, estilo: "", style_code: "", mo, ordered: 0, produced: 0 }; map.set(k, row); }
      // El estilo cliente lo pone la orden; el código tipo+modelo+correlativo, el ticket.
      if (field === "ordered" && !row.estilo) row.estilo = nz(r.estilo);
      if (field === "produced" && !row.style_code) row.style_code = nz(r.estilo);
      row[field] += Number(val) || 0;
    };
    for (const r of ordRes.rows) bump(r, "ordered", r.ordered);
    for (const r of prodRows)    bump(r, "produced", r.produced);

    // Scope al PO cliente de la lista (si tiene uno).
    const wantMo = nz(list.mo);
    let sizes = [...map.values()];
    if (wantMo) {
      const scoped = sizes.filter((s) => nz(s.mo) === wantMo);
      if (scoped.length > 0) sizes = scoped;
    }

    sizes = sizes
      .map((s) => {
        // Capturas de esta talla, en orden cronológico, con el acumulado que
        // llevaba después de cada una: así se lee "50 el lunes → 100 el viernes".
        const raw = (entriesBy.get(key(s.size_code, s.color, s.mo)) || [])
          .slice()
          .sort((a, b) =>
            String(a.day).localeCompare(String(b.day)) ||
            String(a.at ?? "").localeCompare(String(b.at ?? ""))
          );
        let running = 0;
        const entries = raw.map((e) => { running += e.qty; return { ...e, running }; });

        return {
          size_code: s.size_code,
          size_label: sizeLabelOf(s.size_code),
          color: s.color,
          estilo: s.estilo,           // estilo cliente (work_order_lines)
          style_code: s.style_code,   // tipo+modelo+correlativo (line_runs.style)
          mo: s.mo,
          ordered: Math.round(s.ordered),
          produced: Math.round(s.produced),
          remaining: Math.max(0, Math.round(s.ordered) - Math.round(s.produced)),
          entries,
        };
      })
      .sort((a, b) => String(a.color).localeCompare(String(b.color)) || String(a.size_code).localeCompare(String(b.size_code)));

    const totals = sizes.reduce(
      (t, s) => { t.ordered += s.ordered; t.produced += s.produced; t.remaining += s.remaining; return t; },
      { ordered: 0, produced: 0, remaining: 0 }
    );

    // Días con producción por talla (para el selector de fecha).
    let availableDays = [];
    try {
      const daysRes = await client.query(
        `SELECT DISTINCT to_char(lr.run_date, 'YYYY-MM-DD') AS day
           FROM ticket_prints tp
           JOIN line_runs lr ON lr.id = tp.run_id
          WHERE tp.work_order_id = $1 AND lr.run_date IS NOT NULL
          ORDER BY day DESC`,
        [list.work_order_id]
      );
      availableDays = daysRes.rows.map((r) => r.day);
    } catch { /* sin tickets todavía */ }

    res.json({ success: true, date: asOfDate, mo: list.mo, availableDays, sizes, totals, entriesMeta });
  }));

  // (Re)build a draft list's boxes from its work order. Clears existing boxes
  // and regenerates one per size×color line — used to seed older lists or to
  // refresh after the order's lines changed.
  app.post("/api/pre-packing-lists/:id/generate-boxes", authenticateToken, withClient(async (req, res, client) => {
    const id = parseInt(req.params.id, 10);
    await client.query("BEGIN");
    const listRes = await client.query(`SELECT * FROM pre_packing_lists WHERE id = $1 FOR UPDATE`, [id]);
    if (listRes.rows.length === 0) { await client.query("ROLLBACK"); return res.status(404).json({ success: false, error: "Lista no encontrada" }); }
    const list = listRes.rows[0];
    if (list.status !== "draft") { await client.query("ROLLBACK"); return res.status(400).json({ success: false, error: "La lista ya fue confirmada" }); }
    if (!list.work_order_id) { await client.query("ROLLBACK"); return res.status(400).json({ success: false, error: "La lista no tiene una orden asociada" }); }

    // Optional cut-off day: when sent, remember it on the list and regenerate the
    // accumulated per-size production up to that day. When absent, keep whatever
    // day the list already had.
    const rawDate = String(req.body?.asOfDate ?? req.body?.date ?? "").trim();
    let asOfDate = list.as_of_date ? String(list.as_of_date).slice(0, 10) : null;
    if (rawDate !== "") {
      asOfDate = /^\d{4}-\d{2}-\d{2}$/.test(rawDate) ? rawDate : null; // "" clears back to all-time
      await client.query(`UPDATE pre_packing_lists SET as_of_date = $2, updated_at = now() WHERE id = $1`, [id, asOfDate]);
      list.as_of_date = asOfDate;
    }

    await client.query(`DELETE FROM pre_packing_boxes WHERE list_id = $1`, [id]);
    const boxes = await generateBoxesFromOrder(client, list, list.mo, { asOfDate });
    await client.query("COMMIT");
    res.json({ success: true, boxes, boxesGenerated: boxes.length, asOfDate });
  }));

  // Export a list's boxes as CSV (opens in Excel). One row per box.
  app.get("/api/pre-packing-lists/:id/export", authenticateToken, withClient(async (req, res, client) => {
    const id = parseInt(req.params.id, 10);
    const listRes = await client.query(`SELECT * FROM pre_packing_lists WHERE id = $1`, [id]);
    if (listRes.rows.length === 0) return res.status(404).json({ success: false, error: "Lista no encontrada" });
    const list = listRes.rows[0];
    const boxesRes = await client.query(`SELECT * FROM pre_packing_boxes WHERE list_id = $1 ORDER BY id ASC`, [id]);

    // Exact packing template: header label, value, and cell kind ("num" for
    // numeric cells). Constants per the agreed format: Genero=0, BoxType="no",
    // and BoxNo / GrossWeight / NetWeight / Material box barcode left blank.
    const columns = [
      ["ticket",               (b) => b.po],          // ticket = PO number
      ["Orden Produccion",     (b) => b.mo],
      ["PO",                   (b) => b.po],
      ["Estyle",               (b) => b.style],
      ["Genero",               () => 0, "num"],
      ["Codigo Fabric",        (b) => b.fabric_code],
      ["Size",                 (b) => sizeLabelOf(b.size_code)],
      ["Color",                (b) => b.color_name],
      ["Codigo De Color",      (b) => b.color_code],
      ["Piezas",               (b) => b.quantity, "num"],
      ["BoxType",              () => "no"],
      ["BoxNo",                () => ""],
      ["BoxRegistry",          (b) => b.box_registry],
      ["GrossWeight",          () => ""],
      ["NetWeight",            () => ""],
      ["CustomerCode",         (b) => b.customer_code],
      ["CustomerName",         (b) => b.customer_name],
      ["Material box barcode", () => ""],
    ];

    const cellVal = (col, b) => {
      const v = col[1](b);
      if (col[2] === "num") return Number(v) || 0;
      return v === null || v === undefined ? "" : v;
    };

    const format = String(req.query.format || "xlsx").toLowerCase();
    const base = list.list_no || `pre-empaque-${list.id}`;
    const headerRow = columns.map((c) => c[0]);

    // CSV needs no dependency.
    if (format === "csv") {
      const esc = (v) => {
        const s = v === null || v === undefined ? "" : String(v);
        return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
      };
      const body = boxesRes.rows.map((b) => columns.map((c) => esc(cellVal(c, b))).join(","));
      const csv = "\uFEFF" + [headerRow.join(","), ...body].join("\r\n");   // BOM so Excel reads UTF-8
      res.setHeader("Content-Type", "text/csv; charset=utf-8");
      res.setHeader("Content-Disposition", `attachment; filename="${base}.csv"`);
      return res.send(csv);
    }

    // Excel (.xlsx / .xls) via SheetJS.
    if (!XLSX) {
      return res.status(501).json({
        success: false,
        error: "Exportación Excel no disponible: ejecute 'npm install xlsx' en el servidor, o exporte en formato CSV.",
      });
    }

    const aoa = [headerRow, ...boxesRes.rows.map((b) => columns.map((c) => cellVal(c, b)))];
    const ws = XLSX.utils.aoa_to_sheet(aoa);
    ws["!cols"] = headerRow.map((h) => ({ wch: Math.max(10, h.length + 2) }));
    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, "Pre-empaque");

    const bookType = format === "xls" ? "xls" : "xlsx";
    const buf = XLSX.write(wb, { type: "buffer", bookType });
    const mime = bookType === "xls"
      ? "application/vnd.ms-excel"
      : "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";
    res.setHeader("Content-Type", mime);
    res.setHeader("Content-Disposition", `attachment; filename="${base}.${bookType}"`);
    return res.send(buf);
  }));

  // Create a list. Snapshots client + PO/MO from the chosen work order.
  app.post("/api/pre-packing-lists", authenticateToken, withClient(async (req, res, client) => {
    const { customerId, workOrderId, notes } = req.body;
    if (!customerId) return res.status(400).json({ success: false, error: "Seleccione un cliente" });

    // Día de la lista (acumulado por talla hasta este día). Formato 'YYYY-MM-DD';
    // cualquier otra cosa => null (todo el tiempo).
    const rawDate = String(req.body.asOfDate ?? req.body.date ?? "").trim();
    const asOfDate = /^\d{4}-\d{2}-\d{2}$/.test(rawDate) ? rawDate : null;

    await client.query("BEGIN");

    const cRes = await client.query(`SELECT id, code, name FROM customers WHERE id = $1`, [customerId]);
    if (cRes.rows.length === 0) { await client.query("ROLLBACK"); return res.status(400).json({ success: false, error: "Cliente no válido" }); }
    const cust = cRes.rows[0];

    let woId = null, po = null, headerMo = null;
    if (workOrderId) {
      const wRes = await client.query(`SELECT id, work_order_no, customer_po FROM work_orders WHERE id = $1`, [workOrderId]);
      if (wRes.rows.length) { woId = wRes.rows[0].id; po = wRes.rows[0].work_order_no; headerMo = wRes.rows[0].customer_po; }
    }

    // One order can carry several PO cliente (customer_po) across its lines. When
    // it does, create ONE pre-packing list per PO cliente, each seeded only with
    // that PO cliente's size×color lines (e.g. PP-000010 → 23456, PP-000011 → po-1234).
    let mos = [];
    if (woId) mos = await distinctLineMos(client, woId, headerMo);
    if (mos.length === 0) mos = [headerMo ? String(headerMo).trim() : null]; // no order / no per-line PO cliente

    const created = [];
    for (const mo of mos) {
      const insRes = await client.query(
        `INSERT INTO pre_packing_lists
           (customer_id, customer_code, customer_name, work_order_id, po, mo, notes, as_of_date, created_by)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
         RETURNING *`,
        [cust.id, cust.code, cust.name, woId, po, mo, notes || null, asOfDate, req.user?.id ?? null]
      );
      const listRow = insRes.rows[0];
      const upd = await client.query(
        `UPDATE pre_packing_lists SET list_no = $2 WHERE id = $1 RETURNING *`,
        [listRow.id, `PP-${String(listRow.id).padStart(6, "0")}`]
      );
      // Auto-fill this list from the order, scoped to its PO cliente, acumulado a la fecha.
      const boxes = await generateBoxesFromOrder(client, upd.rows[0], mo, { asOfDate });
      created.push({ list: upd.rows[0], boxesGenerated: boxes.length });
    }

    await client.query("COMMIT");
    // `lists` is the full set; `list`/`boxesGenerated` (first list) kept for compat.
    res.json({
      success: true,
      lists: created,
      count: created.length,
      list: created[0]?.list ?? null,
      boxesGenerated: created[0]?.boxesGenerated ?? 0,
    });
  }));

  // Update header (only while draft).
  app.patch("/api/pre-packing-lists/:id", authenticateToken, withClient(async (req, res, client) => {
    const id = parseInt(req.params.id, 10);
    const cur = await client.query(`SELECT status FROM pre_packing_lists WHERE id = $1`, [id]);
    if (cur.rows.length === 0) return res.status(404).json({ success: false, error: "Lista no encontrada" });
    if (cur.rows[0].status !== "draft") return res.status(400).json({ success: false, error: "La lista ya fue confirmada" });

    const { notes, workOrderId, customerId } = req.body;
    const sets = [], params = [];
    const add = (col, val) => { params.push(val); sets.push(`${col} = $${params.length}`); };
    if (notes !== undefined) add("notes", notes);
    if (customerId !== undefined) {
      const cRes = await client.query(`SELECT id, code, name FROM customers WHERE id = $1`, [customerId]);
      if (cRes.rows.length) { add("customer_id", cRes.rows[0].id); add("customer_code", cRes.rows[0].code); add("customer_name", cRes.rows[0].name); }
    }
    if (workOrderId !== undefined) {
      const wRes = await client.query(`SELECT id, work_order_no, customer_po FROM work_orders WHERE id = $1`, [workOrderId]);
      if (wRes.rows.length) { add("work_order_id", wRes.rows[0].id); add("po", wRes.rows[0].work_order_no); add("mo", wRes.rows[0].customer_po); }
    }
    if (sets.length === 0) return res.json({ success: true });

    params.push(id);
    const { rows } = await client.query(
      `UPDATE pre_packing_lists SET ${sets.join(", ")}, updated_at = now() WHERE id = $${params.length} RETURNING *`,
      params
    );
    res.json({ success: true, list: rows[0] });
  }));

  // Delete a list (drops its boxes; only while draft).
  app.delete("/api/pre-packing-lists/:id", authenticateToken, withClient(async (req, res, client) => {
    const id = parseInt(req.params.id, 10);
    const cur = await client.query(`SELECT status FROM pre_packing_lists WHERE id = $1`, [id]);
    if (cur.rows.length === 0) return res.status(404).json({ success: false, error: "Lista no encontrada" });
    if (cur.rows[0].status !== "draft") return res.status(400).json({ success: false, error: "No se puede eliminar una lista confirmada" });
    await client.query(`DELETE FROM pre_packing_lists WHERE id = $1`, [id]);
    res.json({ success: true });
  }));

  // ======================================================================
  //  BOXES
  // ======================================================================

  const listMustBeDraft = async (client, listId) => {
    const r = await client.query(`SELECT id, status, customer_code, customer_name, po, mo FROM pre_packing_lists WHERE id = $1`, [listId]);
    return r.rows[0] || null;
  };

  // Add a box. Missing fields fall back to list snapshot / defaults.
  app.post("/api/pre-packing-lists/:id/boxes", authenticateToken, withClient(async (req, res, client) => {
    const listId = parseInt(req.params.id, 10);
    const list = await listMustBeDraft(client, listId);
    if (!list) return res.status(404).json({ success: false, error: "Lista no encontrada" });
    if (list.status !== "draft") return res.status(400).json({ success: false, error: "La lista ya fue confirmada" });

    const b = req.body || {};
    const { rows } = await client.query(
      `INSERT INTO pre_packing_boxes
         (list_id, box_qrcode, encasement_qrcode, mo, po, style, fabric_code, sex,
          size_code, color_name, color_code, quantity, box_code, box_registry,
          gross_weight, net_weight, customer_code, customer_name)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
       RETURNING *`,
      [
        listId,
        b.box_qrcode || null,
        b.encasement_qrcode || null,            // system field; blank is fine
        b.mo ?? list.mo ?? null,
        b.po ?? list.po ?? null,
        b.style || null,
        b.fabric_code || null,
        b.sex || null,
        b.size_code || null,
        b.color_name || null,
        b.color_code || null,
        Number(b.quantity) || 0,
        b.box_code || DEFAULT_BOX_CODE,
        b.box_registry || null,
        Number(b.gross_weight) || 0,
        Number(b.net_weight) || 0,
        b.customer_code ?? list.customer_code ?? null,
        b.customer_name ?? list.customer_name ?? null,
      ]
    );
    res.json({ success: true, box: rows[0] });
  }));

  // Edit a box (only while its list is draft).
  app.patch("/api/pre-packing-boxes/:id", authenticateToken, withClient(async (req, res, client) => {
    const id = parseInt(req.params.id, 10);
    const cur = await client.query(
      `SELECT b.id, l.status FROM pre_packing_boxes b JOIN pre_packing_lists l ON l.id = b.list_id WHERE b.id = $1`, [id]
    );
    if (cur.rows.length === 0) return res.status(404).json({ success: false, error: "Caja no encontrada" });
    if (cur.rows[0].status !== "draft") return res.status(400).json({ success: false, error: "La lista ya fue confirmada" });

    const editable = ["box_qrcode","encasement_qrcode","mo","po","style","fabric_code","sex","size_code",
      "color_name","color_code","quantity","box_code","box_registry","gross_weight","net_weight","customer_code","customer_name"];
    const numeric = new Set(["quantity","gross_weight","net_weight"]);
    const sets = [], params = [];
    for (const col of editable) {
      if (req.body[col] !== undefined) {
        params.push(numeric.has(col) ? (Number(req.body[col]) || 0) : req.body[col]);
        sets.push(`${col} = $${params.length}`);
      }
    }
    if (sets.length === 0) return res.json({ success: true });
    params.push(id);
    const { rows } = await client.query(
      `UPDATE pre_packing_boxes SET ${sets.join(", ")}, updated_at = now() WHERE id = $${params.length} RETURNING *`, params
    );
    res.json({ success: true, box: rows[0] });
  }));

  // Delete a box (only while its list is draft).
  app.delete("/api/pre-packing-boxes/:id", authenticateToken, withClient(async (req, res, client) => {
    const id = parseInt(req.params.id, 10);
    const cur = await client.query(
      `SELECT b.id, l.status FROM pre_packing_boxes b JOIN pre_packing_lists l ON l.id = b.list_id WHERE b.id = $1`, [id]
    );
    if (cur.rows.length === 0) return res.status(404).json({ success: false, error: "Caja no encontrada" });
    if (cur.rows[0].status !== "draft") return res.status(400).json({ success: false, error: "La lista ya fue confirmada" });
    await client.query(`DELETE FROM pre_packing_boxes WHERE id = $1`, [id]);
    res.json({ success: true });
  }));

  // ======================================================================
  //  CONFIRM  ->  push boxes into finished_inventory
  // ======================================================================
  app.post("/api/pre-packing-lists/:id/confirm", authenticateToken, withClient(async (req, res, client) => {
    const listId = parseInt(req.params.id, 10);
    await client.query("BEGIN");

    const listRes = await client.query(`SELECT * FROM pre_packing_lists WHERE id = $1 FOR UPDATE`, [listId]);
    if (listRes.rows.length === 0) { await client.query("ROLLBACK"); return res.status(404).json({ success: false, error: "Lista no encontrada" }); }
    const list = listRes.rows[0];
    if (list.status !== "draft") { await client.query("ROLLBACK"); return res.status(400).json({ success: false, error: "La lista ya fue confirmada" }); }

    const boxesRes = await client.query(`SELECT * FROM pre_packing_boxes WHERE list_id = $1`, [listId]);
    if (boxesRes.rows.length === 0) { await client.query("ROLLBACK"); return res.status(400).json({ success: false, error: "La lista no tiene cajas" }); }

    let piecesAdded = 0;
    for (const box of boxesRes.rows) {
      const sku_key = skuKeyOf(box);
      const qty = Number(box.quantity) || 0;

      const invRes = await client.query(
        `INSERT INTO finished_inventory
           (sku_key, customer_id, customer_code, customer_name, po, mo, style, fabric_code,
            sex, size_code, color_name, color_code, quantity, box_count)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,1)
         ON CONFLICT (sku_key) DO UPDATE SET
           quantity  = finished_inventory.quantity + EXCLUDED.quantity,
           box_count = finished_inventory.box_count + 1,
           updated_at = now()
         RETURNING id`,
        [
          sku_key, list.customer_id, box.customer_code || list.customer_code, box.customer_name || list.customer_name,
          box.po, box.mo, box.style, box.fabric_code, box.sex, box.size_code,
          box.color_name, box.color_code, qty,
        ]
      );
      const inventoryId = invRes.rows[0].id;

      await client.query(
        `INSERT INTO finished_inventory_movements (inventory_id, list_id, box_id, direction, quantity, created_by)
         VALUES ($1,$2,$3,'in',$4,$5)`,
        [inventoryId, listId, box.id, qty, req.user?.id ?? null]
      );
      piecesAdded += qty;
    }

    const upd = await client.query(
      `UPDATE pre_packing_lists SET status = 'confirmed', confirmed_at = now(), updated_at = now() WHERE id = $1 RETURNING *`,
      [listId]
    );

    await client.query("COMMIT");
    res.json({ success: true, list: upd.rows[0], boxes: boxesRes.rows.length, piecesAdded });
  }));

  // ======================================================================
  //  INVENTORY  +  DASHBOARD
  // ======================================================================
  app.get("/api/finished-inventory", authenticateToken, withClient(async (req, res, client) => {
    const { customerId, q } = req.query;
    const params = [];
    let where = "WHERE quantity <> 0";
    if (customerId) { params.push(customerId); where += ` AND customer_id = $${params.length}`; }
    if (q)          { params.push(`%${q}%`);   where += ` AND (style ILIKE $${params.length} OR po ILIKE $${params.length} OR color_name ILIKE $${params.length} OR customer_name ILIKE $${params.length})`; }
    const { rows } = await client.query(
      `SELECT * FROM finished_inventory ${where} ORDER BY customer_name, style, color_name, size_code LIMIT 1000`, params
    );
    const totalPieces = rows.reduce((s, r) => s + (Number(r.quantity) || 0), 0);
    res.json({ success: true, inventory: rows, totalPieces });
  }));

  app.get("/api/finished-warehouse/dashboard", authenticateToken, withClient(async (req, res, client) => {
    const [lists, boxes, inv, recent] = await Promise.all([
      client.query(`SELECT status, COUNT(*)::int AS n FROM pre_packing_lists GROUP BY status`),
      client.query(`SELECT COUNT(*)::int AS n, COALESCE(SUM(quantity),0) AS qty FROM pre_packing_boxes`),
      client.query(`SELECT COALESCE(SUM(quantity),0) AS pieces, COUNT(*)::int AS skus, COALESCE(SUM(box_count),0)::int AS boxes FROM finished_inventory`),
      client.query(`SELECT id, list_no, customer_name, po, mo, status, created_at FROM pre_packing_lists ORDER BY created_at DESC LIMIT 8`),
    ]);
    const byStatus = Object.fromEntries(lists.rows.map((r) => [r.status, r.n]));
    res.json({
      success: true,
      dashboard: {
        lists: { draft: byStatus.draft || 0, confirmed: byStatus.confirmed || 0, total: (byStatus.draft || 0) + (byStatus.confirmed || 0) },
        prePacking: { boxes: boxes.rows[0].n, pieces: Number(boxes.rows[0].qty) || 0 },
        inventory: { pieces: Number(inv.rows[0].pieces) || 0, skus: inv.rows[0].skus, boxes: inv.rows[0].boxes },
        recentLists: recent.rows,
      },
    });
  }));
}

registerFinishedWarehouse.initSchema = initSchema;
module.exports = registerFinishedWarehouse;