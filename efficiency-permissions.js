// ==========================================================================
// efficiency-permissions.js  (register-module, same shape as work-orders.js)
//
// Per-STYLE efficiency changes for the Plan Board, gated by CEO approval.
//
//   Flow:
//     1) The planner opens "Cambiar Eficiencia", sees every style's current
//        plan-board efficiency and asks to change one → a PENDING request is
//        created (nothing changes yet).
//     2) The request shows up in Analíticas de Planeación → "Permisos de
//        eficiencia" (CEO / master view).
//     3) When the CEO APPROVES, and only then, the new efficiency is written to
//        every line_run of that style and each run's target_pcs / target_per_hour
//        / slot_targets are recomputed. Because the Plan Board reads its daily
//        capacity from line_runs.target_pcs, the day's capacity changes at that
//        moment — for the Plan Board only. Merchant SAM (work_orders.sam_minutes)
//        is never touched.
//
//   Two tables:
//     • efficiency_change_requests   the approval queue + full audit trail.
//     • style_efficiency_overrides   the current APPROVED efficiency per style;
//                                     new runs of that style inherit it (see the
//                                     helper wired into POST /api/line-runs).
//
//   SETUP in server1.js (3 spots, mirrors the other modules):
//     a) near the other requires / registrations (~line 900):
//          const registerEfficiencyPermissions = require("./efficiency-permissions");
//          registerEfficiencyPermissions(app, {
//            authenticateToken, pool, setSchema, allowRoles,
//          });
//     b) in the async startup block, with the other initSchema calls (~line 630):
//          await registerEfficiencyPermissions.initSchema({ pool, setSchema });
//     c) (optional but recommended) inside POST /api/line-runs, right before the
//        INSERT, so future runs of a style inherit its approved efficiency:
//          const effOverride = await registerEfficiencyPermissions.effForStyle(client, style);
//          const effToUse = effOverride != null ? effOverride : (parseFloat(efficiency) || 0.7);
//        then pass `effToUse` (and a target recomputed from it) into the INSERT.
// --------------------------------------------------------------------------

// Roles allowed to APPROVE / REJECT a request. "master" is the CEO account
// (Salvador Cassab); "skyrina" is the owner/company account. Trim this list if
// you want the decision to be the CEO alone.
const CEO_ROLES = ["master", "skyrina", "soporte_it"];

const norm = (s) => String(s || "").trim().toUpperCase();
const clampEff = (v) => {
  const n = Number(v);
  if (!Number.isFinite(n)) return null;
  // Accept either a fraction (0.85) or a percentage (85); normalise to fraction.
  const frac = n > 1 ? n / 100 : n;
  if (!(frac > 0) || frac > 1) return null;
  return Math.round(frac * 1000) / 1000; // NUMERIC(4,3) friendly
};

// piecesAt100 = operators × hours × 60 ÷ SAM ; target = piecesAt100 × eff.
const recomputeTargets = ({ operators, workingHours, sam, eff }) => {
  const ops = parseFloat(operators) || 0;
  const wh = parseFloat(workingHours) || 0;
  const s = parseFloat(sam) || 0;
  const e = parseFloat(eff) || 0;
  const totalMinutes = ops * wh * 60;
  const piecesAt100 = s > 0 ? totalMinutes / s : 0;
  const targetPcs = piecesAt100 * e;
  const targetPerHour = wh > 0 ? targetPcs / wh : 0;
  return { targetPcs, targetPerHour };
};

async function initSchema({ pool, setSchema }) {
  const client = await pool.connect();
  try {
    await setSchema(client);

    // The current APPROVED plan-board efficiency for a style. One row per style.
    await client.query(`
      CREATE TABLE IF NOT EXISTS style_efficiency_overrides(
        id BIGSERIAL PRIMARY KEY,
        style TEXT NOT NULL,
        efficiency NUMERIC(4,3) NOT NULL,
        approved_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
        approved_by_name TEXT,
        source_request_id BIGINT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        CONSTRAINT chk_style_eff_range CHECK (efficiency > 0 AND efficiency <= 1)
      );
    `);
    // Case-insensitive uniqueness on the style code (DAMBOD01 == dambod01).
    await client.query(
      "CREATE UNIQUE INDEX IF NOT EXISTS idx_style_eff_override_style ON style_efficiency_overrides (UPPER(TRIM(style)));"
    );

    // The approval queue + audit trail. A request captures a snapshot of the
    // "current" efficiency at submit time so the CEO can see the before/after.
    await client.query(`
      CREATE TABLE IF NOT EXISTS efficiency_change_requests(
        id BIGSERIAL PRIMARY KEY,
        style TEXT NOT NULL,
        style_description TEXT,
        current_efficiency NUMERIC(4,3),
        requested_efficiency NUMERIC(4,3) NOT NULL,
        reason TEXT,
        status TEXT NOT NULL DEFAULT 'pending',
        requested_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
        requested_by_name TEXT,
        requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        decided_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
        decided_by_name TEXT,
        decided_at TIMESTAMPTZ,
        decision_note TEXT,
        applied_runs INT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        CONSTRAINT chk_eff_req_status CHECK (status IN ('pending','approved','rejected')),
        CONSTRAINT chk_eff_req_range CHECK (requested_efficiency > 0 AND requested_efficiency <= 1)
      );
    `);
    await client.query(
      "CREATE INDEX IF NOT EXISTS idx_eff_req_status ON efficiency_change_requests (status, requested_at DESC);"
    );
    // At most ONE pending request per style at a time.
    await client.query(
      "CREATE UNIQUE INDEX IF NOT EXISTS idx_eff_req_one_pending ON efficiency_change_requests (UPPER(TRIM(style))) WHERE status = 'pending';"
    );

    console.log("✅ efficiency_change_requests + style_efficiency_overrides ready in prod_db_schema");
  } finally {
    client.release();
  }
}

// Returns the approved override efficiency (fraction) for a style, or null.
// Exposed so POST /api/line-runs can make new runs inherit the approved value.
async function effForStyle(client, style) {
  try {
    const r = await client.query(
      "SELECT efficiency FROM style_efficiency_overrides WHERE UPPER(TRIM(style)) = $1",
      [norm(style)]
    );
    return r.rows.length ? parseFloat(r.rows[0].efficiency) : null;
  } catch {
    return null; // never let this break a line-run insert
  }
}

function registerEfficiencyPermissions(app, deps) {
  const { authenticateToken, pool, setSchema, allowRoles } = deps;

  // Fallback guard if the host didn't pass allowRoles for some reason.
  const requireCeo =
    typeof allowRoles === "function"
      ? allowRoles(...CEO_ROLES)
      : (req, res, next) => {
          if (!req.user) return res.status(401).json({ success: false, error: "Not authenticated" });
          if (!CEO_ROLES.includes(req.user.role)) {
            return res.status(403).json({ success: false, error: "Access denied. CEO approval required." });
          }
          next();
        };

  // ---- LIST: every style with its current plan-board efficiency ------------
  // Sourced from line_runs (the styles actually in production), enriched with
  // the approved override, a work-order description and any pending request.
  app.get("/api/style-efficiencies", authenticateToken, async (req, res, next) => {
    const client = await pool.connect();
    try {
      await setSchema(client);

      // Most-recent run per style → its operators/hours/sam/efficiency baseline.
      const latest = await client.query(`
        SELECT DISTINCT ON (UPPER(TRIM(style)))
               UPPER(TRIM(style))              AS style_key,
               style                           AS style_label,
               efficiency                      AS latest_efficiency,
               operators_count, working_hours, sam_minutes, target_pcs,
               to_char(run_date, 'YYYY-MM-DD') AS latest_run_date
          FROM line_runs
         WHERE style IS NOT NULL AND TRIM(style) <> ''
         ORDER BY UPPER(TRIM(style)), run_date DESC, id DESC
      `);

      // Run count + efficiency spread, so the UI can flag inconsistent styles.
      const agg = await client.query(`
        SELECT UPPER(TRIM(style)) AS style_key,
               COUNT(*)::int      AS run_count,
               MIN(efficiency)    AS min_eff,
               MAX(efficiency)    AS max_eff
          FROM line_runs
         WHERE style IS NOT NULL AND TRIM(style) <> ''
         GROUP BY UPPER(TRIM(style))
      `);
      const aggByKey = new Map(agg.rows.map((r) => [r.style_key, r]));

      // Style description (best effort) from work orders.
      const desc = await client.query(`
        SELECT DISTINCT ON (UPPER(TRIM(COALESCE(style_code, estilo))))
               UPPER(TRIM(COALESCE(style_code, estilo))) AS style_key,
               style_description
          FROM work_orders
         WHERE COALESCE(style_code, estilo) IS NOT NULL
           AND TRIM(COALESCE(style_code, estilo)) <> ''
         ORDER BY UPPER(TRIM(COALESCE(style_code, estilo))), id DESC
      `);
      const descByKey = new Map(desc.rows.map((r) => [r.style_key, r.style_description]));

      const overrides = await client.query(
        "SELECT UPPER(TRIM(style)) AS style_key, efficiency, to_char(updated_at, 'YYYY-MM-DD') AS approved_at, approved_by_name FROM style_efficiency_overrides"
      );
      const ovByKey = new Map(overrides.rows.map((r) => [r.style_key, r]));

      const pending = await client.query(
        "SELECT id, UPPER(TRIM(style)) AS style_key, requested_efficiency, requested_by_name, to_char(requested_at, 'YYYY-MM-DD') AS requested_at FROM efficiency_change_requests WHERE status = 'pending'"
      );
      const pendByKey = new Map(pending.rows.map((r) => [r.style_key, r]));

      const styles = latest.rows.map((r) => {
        const a = aggByKey.get(r.style_key) || {};
        const ov = ovByKey.get(r.style_key) || null;
        const pend = pendByKey.get(r.style_key) || null;
        const latestEff = r.latest_efficiency != null ? parseFloat(r.latest_efficiency) : null;
        const current = ov ? parseFloat(ov.efficiency) : latestEff;
        const minEff = a.min_eff != null ? parseFloat(a.min_eff) : null;
        const maxEff = a.max_eff != null ? parseFloat(a.max_eff) : null;
        return {
          style: r.style_label,
          styleKey: r.style_key,
          description: descByKey.get(r.style_key) || "",
          currentEfficiency: current,
          source: ov ? "override" : "run",
          latestEfficiency: latestEff,
          minEfficiency: minEff,
          maxEfficiency: maxEff,
          inconsistent: minEff != null && maxEff != null && Math.abs(maxEff - minEff) > 0.0005,
          runCount: a.run_count || 0,
          latestRunDate: r.latest_run_date || null,
          operators: r.operators_count != null ? Number(r.operators_count) : null,
          workingHours: r.working_hours != null ? Number(r.working_hours) : null,
          samMinutes: r.sam_minutes != null ? Number(r.sam_minutes) : null,
          targetPcs: r.target_pcs != null ? Number(r.target_pcs) : null,
          approvedAt: ov ? ov.approved_at : null,
          approvedByName: ov ? ov.approved_by_name : null,
          pendingRequest: pend
            ? {
                id: pend.id,
                requestedEfficiency: parseFloat(pend.requested_efficiency),
                requestedByName: pend.requested_by_name,
                requestedAt: pend.requested_at,
              }
            : null,
        };
      });

      styles.sort((x, y) => String(x.style).localeCompare(String(y.style)));
      res.json({ success: true, styles });
    } catch (err) {
      next(err);
    } finally {
      client.release();
    }
  });

  // ---- CREATE: submit an efficiency change for CEO approval -----------------
  app.post("/api/efficiency-change-requests", authenticateToken, async (req, res, next) => {
    const client = await pool.connect();
    try {
      await setSchema(client);

      const style = String(req.body.style || "").trim();
      const requestedEfficiency = clampEff(req.body.requestedEfficiency);
      const reason = String(req.body.reason || "").trim();

      if (!style) {
        return res.status(400).json({ success: false, error: "Falta el estilo." });
      }
      if (requestedEfficiency == null) {
        return res.status(400).json({
          success: false,
          error: "La eficiencia debe estar entre 1% y 100%.",
        });
      }

      // Snapshot the current efficiency: approved override first, else the most
      // recent run for the style.
      const ov = await client.query(
        "SELECT efficiency FROM style_efficiency_overrides WHERE UPPER(TRIM(style)) = $1",
        [norm(style)]
      );
      let currentEfficiency = ov.rows.length ? parseFloat(ov.rows[0].efficiency) : null;
      if (currentEfficiency == null) {
        const run = await client.query(
          `SELECT efficiency FROM line_runs
            WHERE UPPER(TRIM(style)) = $1
            ORDER BY run_date DESC, id DESC LIMIT 1`,
          [norm(style)]
        );
        currentEfficiency = run.rows.length ? parseFloat(run.rows[0].efficiency) : null;
      }

      const desc = await client.query(
        `SELECT style_description FROM work_orders
          WHERE UPPER(TRIM(COALESCE(style_code, estilo))) = $1
          ORDER BY id DESC LIMIT 1`,
        [norm(style)]
      );
      const styleDescription = desc.rows.length ? desc.rows[0].style_description : null;

      let inserted;
      try {
        inserted = await client.query(
          `INSERT INTO efficiency_change_requests
             (style, style_description, current_efficiency, requested_efficiency, reason,
              status, requested_by, requested_by_name)
           VALUES ($1, $2, $3, $4, $5, 'pending', $6, $7)
           RETURNING id`,
          [
            style,
            styleDescription,
            currentEfficiency,
            requestedEfficiency,
            reason || null,
            req.user?.id || null,
            req.user?.full_name || req.user?.username || null,
          ]
        );
      } catch (e) {
        // idx_eff_req_one_pending → a pending request already exists for the style.
        if (e.code === "23505") {
          return res.status(409).json({
            success: false,
            error: "Ya hay una solicitud pendiente para este estilo. Espere la decisión del CEO.",
          });
        }
        throw e;
      }

      res.json({
        success: true,
        message: "Solicitud enviada al CEO para su aprobación.",
        requestId: inserted.rows[0].id,
      });
    } catch (err) {
      next(err);
    } finally {
      client.release();
    }
  });

  // ---- LIST requests (CEO queue + planner's own status tracking) -----------
  //   ?status=pending|approved|rejected|all   (default: all)
  app.get("/api/efficiency-change-requests", authenticateToken, async (req, res, next) => {
    const client = await pool.connect();
    try {
      await setSchema(client);
      const status = String(req.query.status || "all").toLowerCase();
      const where =
        ["pending", "approved", "rejected"].includes(status) ? "WHERE status = $1" : "";
      const params = where ? [status] : [];
      const result = await client.query(
        `SELECT id, style, style_description, current_efficiency, requested_efficiency,
                reason, status, requested_by, requested_by_name,
                to_char(requested_at, 'YYYY-MM-DD"T"HH24:MI:SS') AS requested_at,
                decided_by, decided_by_name,
                to_char(decided_at, 'YYYY-MM-DD"T"HH24:MI:SS')  AS decided_at,
                decision_note, applied_runs
           FROM efficiency_change_requests
           ${where}
           ORDER BY (status = 'pending') DESC, requested_at DESC`,
        params
      );
      const requests = result.rows.map((r) => ({
        ...r,
        current_efficiency: r.current_efficiency != null ? parseFloat(r.current_efficiency) : null,
        requested_efficiency: parseFloat(r.requested_efficiency),
      }));
      const pendingCount = requests.filter((r) => r.status === "pending").length;
      res.json({ success: true, requests, pendingCount });
    } catch (err) {
      next(err);
    } finally {
      client.release();
    }
  });

  // ---- OVERRIDES map (for the Plan Board's in-memory capacity math) ---------
  // Returns the approved per-style efficiency as { STYLEKEY: efficiency }. The
  // Plan Board fetches this and applies it when it sums/colors capacity, so the
  // board matches the server's assignment capacity — without changing any run.
  app.get("/api/style-efficiency-overrides", authenticateToken, async (req, res, next) => {
    const client = await pool.connect();
    try {
      await setSchema(client);
      const r = await client.query(
        "SELECT UPPER(TRIM(style)) AS style_key, efficiency FROM style_efficiency_overrides"
      );
      const overrides = {};
      for (const row of r.rows) overrides[row.style_key] = parseFloat(row.efficiency);
      res.json({ success: true, overrides });
    } catch (err) {
      next(err);
    } finally {
      client.release();
    }
  });

  // ---- DECISION: CEO approves or rejects -----------------------------------
  //   body: { decision: "approved" | "rejected", note?: string }
  //
  // Plan-board-only: approval NEVER touches line_runs / slot_targets. It only
  // records the approved efficiency in style_efficiency_overrides. The capacity
  // math (getLineCapacityForDate on the server, and PlanBoard on the client)
  // reads that override and recomputes capacity IN MEMORY. Production run
  // configs and the floor's hourly targets stay exactly as engineering set them.
  app.post(
    "/api/efficiency-change-requests/:id/decision",
    authenticateToken,
    requireCeo,
    async (req, res, next) => {
      const client = await pool.connect();
      try {
        await setSchema(client);
        await client.query("BEGIN");

        const { id } = req.params;
        const decision = String(req.body.decision || "").toLowerCase();
        const note = String(req.body.note || "").trim();

        if (!["approved", "rejected"].includes(decision)) {
          await client.query("ROLLBACK");
          return res.status(400).json({ success: false, error: "Decisión inválida." });
        }

        // Lock the request row so two CEOs can't both decide it.
        const reqRes = await client.query(
          "SELECT * FROM efficiency_change_requests WHERE id = $1 FOR UPDATE",
          [id]
        );
        if (reqRes.rows.length === 0) {
          await client.query("ROLLBACK");
          return res.status(404).json({ success: false, error: "Solicitud no encontrada." });
        }
        const request = reqRes.rows[0];
        if (request.status !== "pending") {
          await client.query("ROLLBACK");
          return res.status(409).json({
            success: false,
            error: `Esta solicitud ya fue ${request.status === "approved" ? "aprobada" : "rechazada"}.`,
          });
        }

        const decidedByName = req.user?.full_name || req.user?.username || null;

        if (decision === "approved") {
          const eff = clampEff(request.requested_efficiency);
          if (eff == null) {
            await client.query("ROLLBACK");
            return res.status(400).json({ success: false, error: "Eficiencia solicitada inválida." });
          }

          // Record the approved override ONLY — no run / slot writes. This is
          // the single source of truth the plan-board capacity math consults.
          await client.query(
            `INSERT INTO style_efficiency_overrides
               (style, efficiency, approved_by, approved_by_name, source_request_id, updated_at)
             VALUES ($1, $2, $3, $4, $5, NOW())
             ON CONFLICT ((UPPER(TRIM(style))))
             DO UPDATE SET efficiency = EXCLUDED.efficiency,
                           approved_by = EXCLUDED.approved_by,
                           approved_by_name = EXCLUDED.approved_by_name,
                           source_request_id = EXCLUDED.source_request_id,
                           updated_at = NOW()`,
            [request.style, eff, req.user?.id || null, decidedByName, request.id]
          );
        }

        // Close out the request either way. applied_runs stays NULL — nothing is
        // written to runs under the plan-board-only model.
        await client.query(
          `UPDATE efficiency_change_requests
              SET status = $1, decided_by = $2, decided_by_name = $3,
                  decided_at = NOW(), decision_note = $4, applied_runs = NULL, updated_at = NOW()
            WHERE id = $5`,
          [decision, req.user?.id || null, decidedByName, note || null, request.id]
        );

        await client.query("COMMIT");
        res.json({
          success: true,
          message:
            decision === "approved"
              ? `Eficiencia aprobada para el estilo ${request.style}. La capacidad del Plan Board se actualizará (sin cambiar las corridas ni las metas de producción).`
              : "Solicitud rechazada.",
          status: decision,
        });
      } catch (err) {
        await client.query("ROLLBACK");
        next(err);
      } finally {
        client.release();
      }
    }
  );
}

registerEfficiencyPermissions.initSchema = initSchema;
registerEfficiencyPermissions.effForStyle = effForStyle;
module.exports = registerEfficiencyPermissions;