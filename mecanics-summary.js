// ==========================================================================
// mechanics-summary.js
//
// A single VMware-side proxy endpoint that fans out to the AWS API
// (skyrina-backend, behind API Gateway in mx-central-1), merges the two
// relevant responses, and returns one clean payload for the frontend.
//
// It calls, in parallel:
//   1. GET /rh/bonos/semana/{semana}      -> per-mechanic bonus + closed/assigned + location
//   2. GET /supervisor/dashboard/stats    -> global created/closed totals
//
// The AWS key/secret lives ONLY here on the server, never in the browser.
//
// --------------------------------------------------------------------------
// SETUP
// --------------------------------------------------------------------------
// 1. Requires Node 18+ (uses the built-in global `fetch`). If you're on an
//    older Node, install node-fetch and uncomment the require at the bottom
//    of this comment block, OR switch to axios — see the note near the fetch call.
//
// 2. Add these to your .env on the VMware server:
//      AWS_API_BASE=https://<api-id>.execute-api.mx-central-1.amazonaws.com/<stage>
//      AWS_API_KEY=<the key/token issued for this integration>
//    (No trailing slash on AWS_API_BASE. Include the stage, e.g. /prod.)
//    If your FastAPI app mounts everything under a global /api prefix, append
//    it here too: .../<stage>/api
//
// 3. Wire it into server.js after `authenticateToken` is defined:
//      const registerMechanicsSummary = require("./mechanics-summary");
//      registerMechanicsSummary(app, authenticateToken);
//
//    (If you prefer, paste the body of `registerMechanicsSummary` directly
//     into server.js instead — it's written to match your existing style.)
//
// const fetch = require("node-fetch"); // <- only if on Node < 18
// ==========================================================================

// --- Config -------------------------------------------------------------
const AWS_API_BASE = process.env.AWS_API_BASE; // e.g. https://abc.execute-api.mx-central-1.amazonaws.com/prod
const AWS_API_KEY = process.env.AWS_API_KEY;

// API Gateway hard-kills requests at 29s. Stay comfortably under that so a
// slow AWS call fails fast instead of hanging your frontend.
const AWS_TIMEOUT_MS = 15000;

// --- Helpers ------------------------------------------------------------

// Monday of the current week as YYYY-MM-DD, matching the Python
// get_week_monday() the AWS /rh routes expect.
function currentWeekMonday(ref = new Date()) {
  const d = new Date(Date.UTC(ref.getUTCFullYear(), ref.getUTCMonth(), ref.getUTCDate()));
  const day = d.getUTCDay();                 // 0 = Sunday, 1 = Monday, ...
  const diff = (day === 0 ? -6 : 1 - day);   // shift back to Monday
  d.setUTCDate(d.getUTCDate() + diff);
  return d.toISOString().slice(0, 10);
}

// Basic YYYY-MM-DD sanity check for the optional ?semana= override.
function isValidWeek(s) {
  return typeof s === "string" && /^\d{4}-\d{2}-\d{2}$/.test(s) && !isNaN(Date.parse(s));
}

// One fetch with a timeout + auth header + JSON parsing, with useful errors.
async function awsGet(path) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), AWS_TIMEOUT_MS);

  try {
    const res = await fetch(`${AWS_API_BASE}${path}`, {
      method: "GET",
      headers: {
        // NOTE: adjust this header to whatever your API Gateway actually
        // expects. `x-api-key` is the API-key style. If you use a bearer
        // token instead, replace with: Authorization: `Bearer ${AWS_API_KEY}`
        "x-api-key": AWS_API_KEY,
        Accept: "application/json",
      },
      signal: controller.signal,
    });

    if (!res.ok) {
      const text = await res.text().catch(() => "");
      throw new Error(`AWS ${path} -> ${res.status} ${res.statusText} ${text}`.trim());
    }
    return await res.json();
  } catch (err) {
    if (err.name === "AbortError") {
      throw new Error(`AWS ${path} timed out after ${AWS_TIMEOUT_MS}ms`);
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

// Prefer the RH-adjusted final amount when set, else the calculated one.
function effectiveBonus(m) {
  return m.monto_final_mxn != null ? m.monto_final_mxn : (m.monto_bono_mxn || 0);
}

// --- Registration -------------------------------------------------------

/**
 * Registers GET /api/mechanics-summary on the given Express app.
 * @param {import('express').Express} app
 * @param {import('express').RequestHandler} authenticateToken  reuse your existing middleware
 */
module.exports = function registerMechanicsSummary(app, authenticateToken) {
  if (!AWS_API_BASE || !AWS_API_KEY) {
    console.warn(
      "⚠️  mechanics-summary: AWS_API_BASE or AWS_API_KEY not set — /api/mechanics-summary will return 500 until configured."
    );
  }

  app.get("/api/mechanics-summary", authenticateToken, async (req, res) => {
    try {
      if (!AWS_API_BASE || !AWS_API_KEY) {
        return res.status(500).json({
          success: false,
          error: "AWS integration not configured (missing AWS_API_BASE / AWS_API_KEY).",
        });
      }

      // Optional ?semana=YYYY-MM-DD, defaults to this week's Monday.
      const semana = isValidWeek(req.query.semana) ? req.query.semana : currentWeekMonday();

      // Fire all AWS calls in parallel.
      const [bonos, supervisor, perf] = await Promise.all([
        awsGet(`/rh/bonos/semana/${semana}`),
        awsGet(`/supervisor/dashboard/stats`),
        awsGet(`/supervisor/mechanics/performance`),
      ]);

      const mecanicos = Array.isArray(bonos.mecanicos) ? bonos.mecanicos : [];
      const stats = supervisor.stats || {};

      // Per-mechanic performance, keyed by id for merging.
      // NOTE: avg_resolution_minutes here is ALL-TIME (across every ticket the
      // mechanic has closed), not just the selected week — the weekly bono route
      // doesn't expose a per-mechanic time. Labelled accordingly in the UI.
      const perfById = {};
      for (const p of Array.isArray(perf.mechanics) ? perf.mechanics : []) {
        perfById[p.mecanico_id] = p;
      }

      // Per-mechanic, renamed to clean camelCase for the frontend.
      const mechanics = mecanicos.map((m) => ({
        id: m.id,
        name: m.nombre,
        location: m.asignacion,                 // piso | taller | muestras
        ticketsAssigned: m.tickets_asignados,   // assigned to this mechanic (this week)
        ticketsClosed: m.tickets_cerrados,       // closed by this mechanic (this week)
        bonusMxn: effectiveBonus(m),             // final if adjusted, else calculated
        bonusCalculatedMxn: m.monto_bono_mxn,    // raw calculated amount
        bonusFinalMxn: m.monto_final_mxn,        // null until RH adjusts it
        bonusPct: m.bono_pct,
        avgCloseMinutes: perfById[m.id]?.avg_resolution_minutes ?? null, // all-time avg
        delayedTickets: perfById[m.id]?.delayed_tickets ?? null,         // all-time delayed
      }));

      // Total bonus across all mechanics for the week (sum of effective amounts).
      const totalBonusAllMechanics = mechanics.reduce((sum, m) => sum + (m.bonusMxn || 0), 0);

      return res.json({
        success: true,
        semana,
        weekBonoClosed: bonos.cerrado === true, // whether RH has locked this week
        global: {
          ticketsCreated: stats.totalTickets,       // all non-cancelled tickets in system
          ticketsClosed: stats.closedTickets,       // globally closed
          activeTickets: stats.activeTickets,
          pendingValidation: stats.pendingValidation,
          avgClosingMinutes: stats.avgClosing,
          totalBonusAllMechanics,                   // summed per-mechanic (this week)
        },
        mechanics,
      });
    } catch (err) {
      console.error("❌ /api/mechanics-summary error:", err.message);
      return res.status(502).json({
        success: false,
        error: "Failed to fetch data from AWS backend.",
        detail: err.message,
      });
    }
  });
};