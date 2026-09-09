// ==========================================================================
// supermarket-plan.js
//
// Register-module (same shape as work-orders.js / mechanics-summary.js) that
// owns the "planner -> supermercado" hand-off:
//
//   • El planner elige UNA O VARIAS SEMANAS en el Plan Board (cualquier semana,
//     no solo la actual, incluidas las semanas que traen pre-ordenes PRE####)
//     y las ENVIA al supermercado.
//   • Al enviar se guarda un SNAPSHOT de esa semana: exactamente los mismos
//     datos que el Plan Board del planner tiene en memoria para pintarse.
//   • El supermercado lee ese snapshot y pinta el MISMO Plan Board, en modo
//     solo lectura, restringido a las semanas publicadas.
//
// POR QUE UN SNAPSHOT Y NO DATOS EN VIVO
// --------------------------------------------------------------------------
// El supermercado surte material contra lo que el planner COMPROMETIO. Si
// leyera en vivo, el planner moveria una casilla y el kit del supermercado
// cambiaria debajo de sus pies, sin aviso. Publicar es un compromiso: el
// snapshot se congela y solo cambia cuando el planner vuelve a enviar la
// semana (crea una revision nueva). El front avisa cuando el tablero del
// planner ya no coincide con lo publicado.
//
// El snapshot lo arma el CLIENTE (PlanBoard ya tiene los datos cargados y en
// la forma exacta que consume) y este modulo solo lo valida y lo guarda como
// JSONB. Eso lo desacopla por completo del esquema de line_assignments /
// merchant_week_plan / pre_order_holds: si esas tablas cambian, este archivo
// no se entera.
//
// --------------------------------------------------------------------------
// SETUP (server.js)
// --------------------------------------------------------------------------
// 1. Con los demas requires:
//        const registerSupermarketPlan = require("./supermarket-plan");
//
// 2. En el bloque async de arranque, junto a los otros initSchema:
//        await registerSupermarketPlan.initSchema({ pool, setSchema });
//
// 3. Donde se registran los otros modulos:
//        registerSupermarketPlan(app, { authenticateToken, pool, setSchema });
//
// Opcional: pasar `publisherRoles` / `viewerRoles` para acotar quien publica
// y quien lee. Por defecto publica cualquiera con rol de planeacion y lee
// cualquiera autenticado.
// ==========================================================================

const MAX_SNAPSHOT_BYTES = 6 * 1024 * 1024; // ~6 MB por semana; una semana real ronda 50-300 KB
const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/;
const MS_PER_DAY = 24 * 60 * 60 * 1000;

// Cuántas semanas hacia adelante puede publicar el planner. El supermercado
// surte material del horizonte cercano; enviar semanas lejanas no ayuda (el
// plan aún va a moverse), enviar semanas pasadas no tiene sentido, y la SEMANA
// ACTUAL tampoco se envía (ya está en piso: no hay tiempo de surtir contra
// ella). Se puede sobreescribir desde server.js con `minWeeksAhead` /
// `maxWeeksAhead`.
const DEFAULT_MIN_WEEKS_AHEAD = 1; // 1 = excluye la semana actual (0)
const DEFAULT_MAX_WEEKS_AHEAD = 2;

// --- helpers --------------------------------------------------------------

// El tablero trabaja con semanas que empiezan en LUNES (weekStartsOn: 1, igual
// que date-fns en PlanBoard). Normalizamos aqui para que dos clientes con
// husos distintos no creen dos "semanas" para el mismo lunes.
function mondayOf(ymd) {
  if (!ISO_DATE.test(String(ymd || ""))) return null;
  const d = new Date(`${ymd}T00:00:00Z`);
  if (isNaN(d.getTime())) return null;
  const dow = d.getUTCDay();            // 0=domingo ... 6=sabado
  const delta = dow === 0 ? -6 : 1 - dow; // retrocede al lunes
  d.setUTCDate(d.getUTCDate() + delta);
  return d.toISOString().slice(0, 10);
}

const toTxt = (v) => (v == null ? null : String(v).trim() || null);

// Semanas enteras entre dos lunes (ISO YYYY-MM-DD). Negativo = `b` es anterior
// a `a`. Ambos deben venir ya normalizados por mondayOf().
function weeksBetweenMondays(a, b) {
  if (!ISO_DATE.test(String(a || "")) || !ISO_DATE.test(String(b || ""))) return null;
  const da = new Date(`${a}T00:00:00Z`);
  const db = new Date(`${b}T00:00:00Z`);
  if (isNaN(da.getTime()) || isNaN(db.getTime())) return null;
  return Math.round((db - da) / (7 * MS_PER_DAY));
}

// --- Startup migration ----------------------------------------------------
async function initSchema({ pool, setSchema }) {
  const client = await pool.connect();
  try {
    await setSchema(client);

    await client.query(`
      CREATE TABLE IF NOT EXISTS supermarket_publications(
        id            BIGSERIAL PRIMARY KEY,
        week_start    DATE        NOT NULL,
        revision      INT         NOT NULL DEFAULT 1,
        status        VARCHAR(16) NOT NULL DEFAULT 'active',
        note          TEXT,
        snapshot      JSONB       NOT NULL DEFAULT '{}'::jsonb,
        counts        JSONB       NOT NULL DEFAULT '{}'::jsonb,
        has_pre_orders BOOLEAN    NOT NULL DEFAULT false,
        published_by  BIGINT,
        published_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
        revoked_by    BIGINT,
        revoked_at    TIMESTAMPTZ,
        CONSTRAINT chk_sm_pub_status CHECK (status IN ('active','revoked'))
      );
    `);

    // Una sola publicacion viva por semana. Reenviar la semana revoca la
    // anterior y crea una revision nueva, asi que el historial queda completo
    // pero el supermercado siempre ve una sola verdad por semana.
    await client.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS idx_sm_pub_active_week
        ON supermarket_publications(week_start)
        WHERE status = 'active';
    `);
    await client.query(
      "CREATE INDEX IF NOT EXISTS idx_sm_pub_week ON supermarket_publications(week_start);"
    );
    await client.query(
      "CREATE INDEX IF NOT EXISTS idx_sm_pub_published_at ON supermarket_publications(published_at DESC);"
    );

    console.log("✅ supermarket_publications table ready in prod_db_schema");
  } catch (err) {
    console.error("❌ supermarket-plan initSchema failed:", err.message);
    throw err;
  } finally {
    client.release();
  }
}

// --- Routes ---------------------------------------------------------------
function registerSupermarketPlan(app, deps) {
  const { authenticateToken, pool, setSchema } = deps;

  // Roles que pueden ENVIAR al supermercado. Se pueden sobreescribir desde
  // server.js. `null` = cualquiera autenticado (util en instalaciones que aun
  // no tienen roles cableados).
  const publisherRoles = deps.publisherRoles || ["admin", "planner", "planeacion", "planning", "supermarcado", "supervisor", "master", "soporte_it", "skyrina"];

  // Horizonte de envío: sólo se pueden publicar las semanas entre
  // `minWeeksAhead` y `maxWeeksAhead` contando desde la semana actual (0).
  // Por defecto [1, 2]: excluye la semana actual y publica las dos siguientes.
  const minWeeksAhead = Number.isFinite(Number(deps.minWeeksAhead))
    ? Math.max(0, Math.trunc(Number(deps.minWeeksAhead)))
    : DEFAULT_MIN_WEEKS_AHEAD;
  const maxWeeksAhead = Number.isFinite(Number(deps.maxWeeksAhead))
    ? Math.max(minWeeksAhead, Math.trunc(Number(deps.maxWeeksAhead)))
    : Math.max(minWeeksAhead, DEFAULT_MAX_WEEKS_AHEAD);

  // Las semanas con pre-órdenes (PRE####) NO se pueden enviar al supermercado:
  // una pre-orden no es un pedido en firme y no hay material que surtir todavía.
  // El merchant debe convertirla a PO real antes de publicar la semana. Se
  // puede permitir explícitamente desde server.js con `allowPreOrders: true`.
  const allowPreOrders = deps.allowPreOrders === true;

  // Reenvío: por defecto una semana que YA tiene una publicación activa no se
  // puede volver a enviar (hay que retirarla primero). Poner `allowResend: true`
  // en server.js restaura el comportamiento anterior (revoca la viva y sube
  // revisión al reenviar).
  const allowResend = deps.allowResend === true;

  const roleOf = (req) =>
    String(req.user?.role || req.user?.rol || "").trim().toLowerCase();

  const canPublish = (req) => {
    if (!publisherRoles || publisherRoles.length === 0) return true;
    const r = roleOf(req);
    if (!r) return true; // sin rol en el token: no bloqueamos, authenticateToken ya filtro
    return publisherRoles.map((x) => x.toLowerCase()).includes(r);
  };

  const userId = (req) => {
    const id = req.user?.id;
    return id == null ? null : (Number.isFinite(Number(id)) ? Number(id) : null);
  };

  // =====================================================================
  //  GET /api/supermarket-plan/weeks
  //  Selector del planner: estado de publicacion por semana.
  //  No trae snapshots (pesan) — solo lo necesario para pintar la lista.
  // =====================================================================
  app.get("/api/supermarket-plan/weeks", authenticateToken, async (req, res) => {
    const client = await pool.connect();
    try {
      await setSchema(client);
      const { rows } = await client.query(`
        SELECT p.id,
               to_char(p.week_start, 'YYYY-MM-DD') AS week_start,
               p.revision,
               p.status,
               p.note,
               p.counts,
               p.has_pre_orders,
               p.published_by,
               p.published_at,
               u.name AS published_by_name
          FROM supermarket_publications p
          LEFT JOIN users u ON u.id = p.published_by
         WHERE p.status = 'active'
         ORDER BY p.week_start ASC
      `).catch(async (e) => {
        // Instalaciones sin tabla `users` (o con otro nombre): degradamos sin
        // el nombre del autor en vez de tumbar el selector.
        if (!/users/i.test(e.message)) throw e;
        return client.query(`
          SELECT p.id,
                 to_char(p.week_start, 'YYYY-MM-DD') AS week_start,
                 p.revision, p.status, p.note, p.counts, p.has_pre_orders,
                 p.published_by, p.published_at,
                 NULL::text AS published_by_name
            FROM supermarket_publications p
           WHERE p.status = 'active'
           ORDER BY p.week_start ASC
        `);
      });

      res.json({ success: true, publications: rows, canPublish: canPublish(req) });
    } catch (err) {
      console.error("GET /api/supermarket-plan/weeks:", err);
      res.status(500).json({ success: false, error: "No se pudieron cargar las semanas publicadas" });
    } finally {
      client.release();
    }
  });

  // =====================================================================
  //  POST /api/supermarket-plan/publish
  //  Body: { note?, weeks: [ { weekStart, snapshot, counts?, hasPreOrders? } ] }
  //  Publica (o re-publica) una o varias semanas. Re-publicar una semana
  //  revoca la publicacion viva y sube revision.
  // =====================================================================
  app.post("/api/supermarket-plan/publish", authenticateToken, async (req, res) => {
    if (!canPublish(req)) {
      return res.status(403).json({ success: false, error: "Su usuario no puede enviar al supermercado" });
    }

    const note = toTxt(req.body?.note);
    const weeksIn = Array.isArray(req.body?.weeks) ? req.body.weeks : [];

    if (weeksIn.length === 0) {
      return res.status(400).json({ success: false, error: "Seleccione al menos una semana para enviar" });
    }
    if (weeksIn.length > 26) {
      return res.status(400).json({ success: false, error: "Maximo 26 semanas por envio" });
    }

    // Validacion previa: si una semana viene mal, no publicamos ninguna.
    const thisMonday = mondayOf(new Date().toISOString().slice(0, 10));
    const prepared = [];
    for (const w of weeksIn) {
      const weekStart = mondayOf(w?.weekStart);
      if (!weekStart) {
        return res.status(400).json({
          success: false,
          error: `Semana invalida: ${w?.weekStart}. Se espera una fecha YYYY-MM-DD.`,
        });
      }

      // Regla de horizonte: sólo se puede enviar el plan de las semanas entre
      // `minWeeksAhead` y `maxWeeksAhead` (0 = semana actual). Ni la semana
      // actual, ni semanas pasadas, ni semanas más allá del horizonte.
      const ahead = weeksBetweenMondays(thisMonday, weekStart);
      if (ahead == null || ahead < minWeeksAhead) {
        const msg =
          ahead != null && ahead < 0
            ? `La semana ${weekStart} ya pasó`
            : `La semana actual (${weekStart}) no se puede enviar al supermercado`;
        return res.status(400).json({
          success: false,
          error: `${msg}; sólo se pueden enviar las semanas ${minWeeksAhead} a ${maxWeeksAhead} a partir de la actual.`,
        });
      }
      if (ahead > maxWeeksAhead) {
        return res.status(400).json({
          success: false,
          error: `La semana ${weekStart} está fuera del horizonte: sólo se pueden enviar las semanas ${minWeeksAhead} a ${maxWeeksAhead} a partir de la actual.`,
        });
      }
      const snapshot = w?.snapshot;
      if (!snapshot || typeof snapshot !== "object" || Array.isArray(snapshot)) {
        return res.status(400).json({
          success: false,
          error: `La semana ${weekStart} viene sin datos del tablero.`,
        });
      }
      const json = JSON.stringify(snapshot);
      if (Buffer.byteLength(json, "utf8") > MAX_SNAPSHOT_BYTES) {
        return res.status(413).json({
          success: false,
          error: `La semana ${weekStart} excede el tamano maximo permitido.`,
        });
      }
      // Marcamos la semana como "con pre-ordenes" si el cliente lo dice o si el
      // snapshot trae holds PRE####. Sirve para el badge del supermercado.
      const holds = Array.isArray(snapshot.holds) ? snapshot.holds : [];
      const planRows = Array.isArray(snapshot.merchantPlan) ? snapshot.merchantPlan : [];
      const hasPre =
        w?.hasPreOrders === true ||
        holds.some((h) => h && h.pre_order_id != null) ||
        planRows.some((r) => r && (r.pre_order_id != null || r.is_pre_order === true));

      // Bloqueo de pre-órdenes: una semana con PRE#### no se surte todavía.
      if (hasPre && !allowPreOrders) {
        return res.status(400).json({
          success: false,
          error: `La semana ${weekStart} contiene pre-órdenes (PRE####) y no se puede enviar al supermercado. Convierta las pre-órdenes a PO real y vuelva a intentarlo.`,
        });
      }

      prepared.push({
        weekStart,
        snapshot: json,
        counts: JSON.stringify(w?.counts && typeof w.counts === "object" ? w.counts : {}),
        hasPre,
      });
    }

    // Regla de "no reenviar": si alguna de las semanas ya tiene una publicación
    // activa, se rechaza el lote completo (all-or-nothing, como el resto de las
    // validaciones). El planner debe retirarla antes de volver a enviarla.
    if (!allowResend) {
      const already = await (async () => {
        const c = await pool.connect();
        try {
          await setSchema(c);
          const r = await c.query(
            `SELECT to_char(week_start,'YYYY-MM-DD') AS week_start
               FROM supermarket_publications
              WHERE status = 'active' AND week_start = ANY($1::date[])
              ORDER BY week_start`,
            [prepared.map((p) => p.weekStart)]
          );
          return r.rows.map((x) => x.week_start);
        } finally {
          c.release();
        }
      })();
      if (already.length) {
        return res.status(409).json({
          success: false,
          error:
            already.length === 1
              ? `La semana ${already[0]} ya fue enviada al supermercado y no se puede reenviar. Retírela primero si necesita cambiarla.`
              : `Estas semanas ya fueron enviadas al supermercado y no se pueden reenviar: ${already.join(", ")}. Retírelas primero si necesita cambiarlas.`,
        });
      }
    }

    try {
      await client_tx(pool, setSchema, async (client) => {
        const uid = userId(req);
        const out = [];

        for (const p of prepared) {
          // Revision = siguiente numero para esa semana (incluye revocadas, el
          // historial no se reusa).
          const revRes = await client.query(
            `SELECT COALESCE(MAX(revision), 0) + 1 AS next
               FROM supermarket_publications
              WHERE week_start = $1::date`,
            [p.weekStart]
          );
          const revision = revRes.rows[0].next;

          // Revocar la viva (si hay) para respetar el indice unico parcial.
          await client.query(
            `UPDATE supermarket_publications
                SET status = 'revoked', revoked_by = $2, revoked_at = now()
              WHERE week_start = $1::date AND status = 'active'`,
            [p.weekStart, uid]
          );

          const ins = await client.query(
            `INSERT INTO supermarket_publications
               (week_start, revision, status, note, snapshot, counts, has_pre_orders, published_by)
             VALUES ($1::date, $2, 'active', $3, $4::jsonb, $5::jsonb, $6, $7)
             RETURNING id, to_char(week_start,'YYYY-MM-DD') AS week_start,
                       revision, published_at`,
            [p.weekStart, revision, note, p.snapshot, p.counts, p.hasPre, uid]
          );
          out.push(ins.rows[0]);
        }

        res.json({
          success: true,
          published: out,
          message:
            out.length === 1
              ? `Semana enviada al supermercado`
              : `${out.length} semanas enviadas al supermercado`,
        });
      });
    } catch (err) {
      console.error("POST /api/supermarket-plan/publish:", err);
      res.status(500).json({ success: false, error: "No se pudo enviar al supermercado" });
    }
  });

  // =====================================================================
  //  GET /api/supermarket-plan
  //  Vista del SUPERMERCADO. Devuelve las semanas publicadas y, fusionados,
  //  los datos del tablero en la MISMA forma que consume PlanBoard.
  //  ?week=YYYY-MM-DD  -> solo esa semana
  // =====================================================================
  app.get("/api/supermarket-plan", authenticateToken, async (req, res) => {
    const client = await pool.connect();
    try {
      await setSchema(client);

      const params = [];
      let where = "status = 'active'";
      if (req.query.week) {
        const wk = mondayOf(req.query.week);
        if (!wk) return res.status(400).json({ success: false, error: "Semana invalida" });
        params.push(wk);
        where += ` AND week_start = $${params.length}::date`;
      }

      const { rows } = await client.query(
        `SELECT id,
                to_char(week_start,'YYYY-MM-DD') AS week_start,
                revision, note, counts, has_pre_orders,
                published_by, published_at, snapshot
           FROM supermarket_publications
          WHERE ${where}
          ORDER BY week_start ASC`,
        params
      );

      // Fusion: PlanBoard espera arreglos planos (assignments, holds, ...).
      // Concatenamos las semanas publicadas y deduplicamos por id para que dos
      // snapshots que compartan una orden no la pinten dos veces.
      const merged = {
        assignments: [], holds: [], holidays: [], workOrders: [],
        lineRuns: [], plannerLines: [], merchantPlan: [],
      };
      const seen = { assignments: new Set(), holds: new Set(), workOrders: new Set(), lineRuns: new Set() };

      const pushDedup = (bucket, rowsIn, keyFn) => {
        (Array.isArray(rowsIn) ? rowsIn : []).forEach((r) => {
          if (!r) return;
          const k = keyFn ? keyFn(r) : null;
          if (k != null) {
            if (seen[bucket].has(k)) return;
            seen[bucket].add(k);
          }
          merged[bucket].push(r);
        });
      };

      let equivalence = null;
      let lineOrder = null;

      rows.forEach((p) => {
        const s = p.snapshot || {};
        pushDedup("assignments", s.assignments, (r) => (r.id != null ? `a${r.id}` : null));
        pushDedup("holds", s.holds, (r) => (r.holdId ?? r.id) != null ? `h${r.holdId ?? r.id}` : null);
        pushDedup("workOrders", s.workOrders, (r) => (r.id != null ? `w${r.id}` : null));
        pushDedup("lineRuns", s.lineRuns, (r) => (r.id != null ? `r${r.id}` : null));
        pushDedup("holidays", s.holidays, null);
        pushDedup("plannerLines", s.plannerLines, null);
        pushDedup("merchantPlan", s.merchantPlan, null);
        if (equivalence == null && Number(s.equivalence) > 0) equivalence = Number(s.equivalence);
        if (lineOrder == null && Array.isArray(s.lineOrder) && s.lineOrder.length) lineOrder = s.lineOrder;
      });

      // Las semanas publicadas: PlanBoard las usa para recortar el calendario a
      // exactamente lo que el planner envio.
      const weeks = rows.map((p) => ({
        id: p.id,
        weekStart: p.week_start,
        revision: p.revision,
        note: p.note,
        counts: p.counts || {},
        hasPreOrders: p.has_pre_orders,
        publishedAt: p.published_at,
      }));

      res.json({
        success: true,
        weeks,
        equivalence: equivalence || 10,
        lineOrder: lineOrder || [],
        ...merged,
      });
    } catch (err) {
      console.error("GET /api/supermarket-plan:", err);
      res.status(500).json({ success: false, error: "No se pudo cargar el plan del supermercado" });
    } finally {
      client.release();
    }
  });

  // =====================================================================
  //  POST /api/supermarket-plan/revoke   Body: { weeks: ["YYYY-MM-DD", ...] }
  //  Retira semanas del supermercado sin borrar el historial.
  // =====================================================================
  app.post("/api/supermarket-plan/revoke", authenticateToken, async (req, res) => {
    if (!canPublish(req)) {
      return res.status(403).json({ success: false, error: "Su usuario no puede retirar semanas" });
    }
    const weeks = (Array.isArray(req.body?.weeks) ? req.body.weeks : [])
      .map(mondayOf)
      .filter(Boolean);
    if (weeks.length === 0) {
      return res.status(400).json({ success: false, error: "Seleccione al menos una semana" });
    }
    const client = await pool.connect();
    try {
      await setSchema(client);
      const r = await client.query(
        `UPDATE supermarket_publications
            SET status = 'revoked', revoked_by = $2, revoked_at = now()
          WHERE status = 'active' AND week_start = ANY($1::date[])
          RETURNING to_char(week_start,'YYYY-MM-DD') AS week_start`,
        [weeks, userId(req)]
      );
      res.json({
        success: true,
        revoked: r.rows.map((x) => x.week_start),
        message: r.rowCount === 1 ? "Semana retirada del supermercado" : `${r.rowCount} semanas retiradas`,
      });
    } catch (err) {
      console.error("POST /api/supermarket-plan/revoke:", err);
      res.status(500).json({ success: false, error: "No se pudo retirar la semana" });
    } finally {
      client.release();
    }
  });
}

// Pequeno helper de transaccion (BEGIN/COMMIT/ROLLBACK + release garantizado).
async function client_tx(pool, setSchema, fn) {
  const client = await pool.connect();
  try {
    await setSchema(client);
    await client.query("BEGIN");
    await fn(client);
    await client.query("COMMIT");
  } catch (err) {
    try { await client.query("ROLLBACK"); } catch {}
    throw err;
  } finally {
    client.release();
  }
}

registerSupermarketPlan.initSchema = initSchema;
module.exports = registerSupermarketPlan;