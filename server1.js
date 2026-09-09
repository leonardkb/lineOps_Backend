require("dotenv").config();
const express = require("express");
const { Pool } = require("pg");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const compression = require("compression");
const morgan = require("morgan");
const { body, validationResult, param, query } = require("express-validator");
const winston = require("winston");
const fs = require("fs");
const { uploadBufferToS3, deleteFromS3, makeStylePhotoKey, generatePresignedGetUrl, generatePresignedPutUrl } = require("./s3-raw");

// ----------------------------------------------------------------------
// 1. LOGGER (Winston)
// ----------------------------------------------------------------------
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || "info",
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.splat(),
    winston.format.json()
  ),
  defaultMeta: { service: "production-backend" },
  transports: [
    // Lambda's filesystem is read-only except /tmp; log to stdout and let
    // CloudWatch capture it. (File transports would crash on Lambda.)
    new winston.transports.Console({
      format: winston.format.json(),
    }),
  ],
});

// ----------------------------------------------------------------------
// 2. EXPRESS SETUP
// ----------------------------------------------------------------------
const app = express();

app.use(helmet());
app.set("etag", false);
app.use("/api/", (req, res, next) => {
  res.set("Cache-Control", "no-store");
  next();
});
app.use(compression());
app.use(express.json({ limit: "12mb" }));

const allowedOrigins = process.env.CORS_ORIGINS
  ? process.env.CORS_ORIGINS.split(",")
  : ["http://localhost:3000"];
app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin || allowedOrigins.includes(origin) || process.env.NODE_ENV !== "production") {
        callback(null, true);
      } else {
        callback(new Error("Not allowed by CORS"));
      }
    },
    credentials: true,
  })
);

app.use(
  morgan("combined", {
    stream: { write: (message) => logger.info(message.trim()) },
  })
);

// ----------------------------------------------------------------------
// 3. RATE LIMITING
// ----------------------------------------------------------------------
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { success: false, error: "Too many authentication attempts, please try again later." },
  standardHeaders: true,
  legacyHeaders: false,
});

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 300,
  message: { success: false, error: "Too many requests, please slow down." },
  standardHeaders: true,
  legacyHeaders: false,
});
app.use("/api/", apiLimiter);

// ----------------------------------------------------------------------
// 4. DATABASE POOL
// ----------------------------------------------------------------------
const pool = new Pool({
  host: process.env.PG_HOST,
  port: Number(process.env.PG_PORT),
  database: process.env.PG_DB,
  user: process.env.PG_USER,
  password: process.env.PG_PASSWORD,
  ssl:
    process.env.PG_SSL === "true"
      ? {
          rejectUnauthorized: true,
          ca: fs
            .readFileSync(process.env.PG_CA_CERT || "/app/global-bundle.pem")
            .toString(),
        }
      : false,
  max: Number(process.env.PG_POOL_MAX) || 2, // low: one small pool per Lambda instance, behind RDS Proxy
  idleTimeoutMillis: Number(process.env.PG_IDLE_TIMEOUT) || 30000,
  connectionTimeoutMillis: Number(process.env.PG_CONNECTION_TIMEOUT) || 5000,
});

pool.on("error", (err) => {
  logger.error("Unexpected database pool error", { error: err.message, stack: err.stack });
  process.exit(-1);
});

const setSchema = async (client) => {
  await client.query("SET search_path TO prod_db_schema");
   // Set time zone to factory local (default Mexico City)
  const timeZone = 'America/Mexico_City';
  await client.query(`SET TIME ZONE '${timeZone}'`);
};

// ----------------------------------------------------------------------
// 5. JWT CONFIGURATION
// ----------------------------------------------------------------------
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  logger.error("JWT_SECRET environment variable is not set");
  process.exit(1);
}
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || "24h";

// ----------------------------------------------------------------------
// 6. DATABASE MIGRATIONS
// ----------------------------------------------------------------------
const runMigrations = async () => {
  if (process.env.RUN_MIGRATIONS !== "true") {
    logger.info("Migrations skipped (RUN_MIGRATIONS != true)");
    return;
  }

  const client = await pool.connect();
  try {
    logger.info("🔄 Running database migrations in prod_db_schema...");
    await setSchema(client);
    await client.query("BEGIN");

    // Create tables (IF NOT EXISTS)
    await client.query(`
      CREATE TABLE IF NOT EXISTS users(
        id BIGSERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role VARCHAR(20) NOT NULL DEFAULT 'line_leader',
        line_number INT NULL,
        full_name VARCHAR(100) NULL,
        is_active BOOLEAN NOT NULL DEFAULT TRUE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        CONSTRAINT chk_role CHECK (role IN ('engineer', 'line_leader', 'supervisor','soporte_it', 'skyrina','master')),
        CONSTRAINT chk_line_number CHECK (line_number IS NULL OR (line_number >= 1 AND line_number <= 26))
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS line_runs(
        id BIGSERIAL PRIMARY KEY,
        line_no TEXT NOT NULL,
        run_date DATE NOT NULL,
        style TEXT NOT NULL,
        operators_count INT NOT NULL DEFAULT 0,
        working_hours NUMERIC(6,2) NOT NULL,
        sam_minutes NUMERIC(10,2) NOT NULL,
        efficiency NUMERIC(4,3) NOT NULL,
        target_pcs NUMERIC(12,2) NOT NULL DEFAULT 0,
        target_per_hour NUMERIC(12,2) NOT NULL DEFAULT 0,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        CONSTRAINT uq_line_run UNIQUE (line_no, run_date, style),
        CONSTRAINT chk_efficiency_range CHECK (efficiency > 0 AND efficiency <= 1),
        CONSTRAINT chk_working_hours_positive CHECK (working_hours > 0),
        CONSTRAINT chk_sam_positive CHECK (sam_minutes > 0)
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS shift_slots(
        id BIGSERIAL PRIMARY KEY,
        run_id BIGINT NOT NULL REFERENCES line_runs(id) ON DELETE CASCADE,
        slot_order INT NOT NULL,
        slot_label TEXT NOT NULL,
        slot_start TIME NULL,
        slot_end TIME NULL,
        planned_hours NUMERIC(6,3) NOT NULL,
        UNIQUE (run_id, slot_order),
        UNIQUE (run_id, slot_label),
        CONSTRAINT chk_planned_hours_nonnegative CHECK (planned_hours >= 0)
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS run_operators(
        id BIGSERIAL PRIMARY KEY,
        run_id BIGINT NOT NULL REFERENCES line_runs(id) ON DELETE CASCADE,
        operator_no INT NOT NULL,
        operator_name TEXT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        UNIQUE (run_id, operator_no),
        CONSTRAINT chk_operator_no_positive CHECK (operator_no > 0)
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS operator_operations(
        id BIGSERIAL PRIMARY KEY,
        run_id BIGINT NOT NULL REFERENCES line_runs(id) ON DELETE CASCADE,
        run_operator_id BIGINT NOT NULL REFERENCES run_operators(id) ON DELETE CASCADE,
        operation_name TEXT NOT NULL,
        t1_sec NUMERIC(10,2) NULL,
        t2_sec NUMERIC(10,2) NULL,
        t3_sec NUMERIC(10,2) NULL,
        t4_sec NUMERIC(10,2) NULL,
        t5_sec NUMERIC(10,2) NULL,
        capacity_per_hour NUMERIC(12,3) NOT NULL DEFAULT 0,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        UNIQUE (run_operator_id, operation_name)
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS operation_hourly_entries(
        id BIGSERIAL PRIMARY KEY,
        run_id BIGINT NOT NULL REFERENCES line_runs(id) ON DELETE CASCADE,
        operation_id BIGINT NOT NULL REFERENCES operator_operations(id) ON DELETE CASCADE,
        slot_id BIGINT NOT NULL REFERENCES shift_slots(id) ON DELETE CASCADE,
        stitched_qty NUMERIC(12,2) NOT NULL DEFAULT 0,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        UNIQUE (operation_id, slot_id),
        CONSTRAINT chk_stitched_qty_nonnegative CHECK (stitched_qty >= 0)
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS operation_sewed_entries(
        id BIGSERIAL PRIMARY KEY,
        run_id BIGINT NOT NULL REFERENCES line_runs(id) ON DELETE CASCADE,
        operation_id BIGINT NOT NULL REFERENCES operator_operations(id) ON DELETE CASCADE,
        slot_id BIGINT NOT NULL REFERENCES shift_slots(id) ON DELETE CASCADE,
        sewed_qty NUMERIC(12,2) NOT NULL DEFAULT 0,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        UNIQUE (operation_id, slot_id),
        CONSTRAINT chk_sewed_qty_nonnegative CHECK (sewed_qty >= 0)
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS slot_targets(
        id BIGSERIAL PRIMARY KEY,
        run_id BIGINT NOT NULL REFERENCES line_runs(id) ON DELETE CASCADE,
        slot_id BIGINT NOT NULL REFERENCES shift_slots(id) ON DELETE CASCADE,
        slot_target NUMERIC(12,2) NOT NULL DEFAULT 0,
        cumulative_target NUMERIC(12,2) NOT NULL DEFAULT 0,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        UNIQUE (run_id, slot_id)
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS line_balancing_assignments (
        id BIGSERIAL PRIMARY KEY,
        run_id BIGINT NOT NULL REFERENCES line_runs(id) ON DELETE CASCADE,
        source_operator_id BIGINT NOT NULL REFERENCES run_operators(id) ON DELETE CASCADE,
        target_operator_id BIGINT NOT NULL REFERENCES run_operators(id) ON DELETE CASCADE,
        operation_id BIGINT NOT NULL REFERENCES operator_operations(id) ON DELETE CASCADE,
        assigned_quantity_per_hour NUMERIC(12,2) NOT NULL DEFAULT 0,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        UNIQUE (run_id, source_operator_id, target_operator_id, operation_id)
      );
    `);
    logger.info("✅ line_balancing_assignments table ready");

        // 7. Add to createAllTables function after other table creations
await client.query(`
  CREATE TABLE IF NOT EXISTS operator_capacity_history (
    id BIGSERIAL PRIMARY KEY,
    operation_id BIGINT NOT NULL REFERENCES operator_operations(id) ON DELETE CASCADE,
    old_capacity NUMERIC(12,3) NOT NULL,
    new_capacity NUMERIC(12,3) NOT NULL,
    changed_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
    changed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT chk_capacity_positive CHECK (new_capacity >= 0)
  );
`);
console.log("✅ operator_capacity_history table ready in prod_db_schema");

// 8. Create quality_inspections table
await client.query(`
  CREATE TABLE IF NOT EXISTS quality_inspections(
    id BIGSERIAL PRIMARY KEY,
    line_no TEXT NOT NULL,
    style TEXT,
    inspector_name VARCHAR(100) NOT NULL,
    inspection_date DATE NOT NULL DEFAULT CURRENT_DATE,
    shift_slot VARCHAR(50),
    total_defects INT DEFAULT 0,
    total_checked_quantity NUMERIC(12,2) DEFAULT 0,
    bad_type TEXT,
    bad_reason TEXT,
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
  );
`);
// Add bad_type / bad_reason columns to existing databases (no-op if already present)
await client.query("ALTER TABLE quality_inspections ADD COLUMN IF NOT EXISTS bad_type TEXT;");
await client.query("ALTER TABLE quality_inspections ADD COLUMN IF NOT EXISTS bad_reason TEXT;");
await client.query("ALTER TABLE quality_inspections ADD COLUMN IF NOT EXISTS style TEXT;");
console.log("✅ quality_inspections table ready");

// 9. Create quality_defect_types table (master data)
await client.query(`
  CREATE TABLE IF NOT EXISTS quality_defect_types(
    id BIGSERIAL PRIMARY KEY,
    defect_code VARCHAR(20) UNIQUE NOT NULL,
    defect_name VARCHAR(100) NOT NULL,
    category VARCHAR(50) NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    sort_order INT DEFAULT 0
  );
`);
console.log("✅ quality_defect_types table ready");
    // Planner-defined lines (engineering hasn't configured them yet) + draft flag.
    await client.query(`
      CREATE TABLE IF NOT EXISTS planner_lines(
        line_no TEXT PRIMARY KEY,
        operators_count INT NOT NULL DEFAULT 20,
        working_hours NUMERIC(6,2) NOT NULL DEFAULT 8,
        sam_minutes NUMERIC(10,2) NOT NULL DEFAULT 3.5,
        efficiency NUMERIC(4,3) NOT NULL DEFAULT 0.85,
        target_pcs NUMERIC(12,2) NOT NULL DEFAULT 0,
        target_per_hour NUMERIC(12,2) NOT NULL DEFAULT 0,
        created_by TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        CONSTRAINT chk_planner_eff CHECK (efficiency > 0 AND efficiency <= 1),
        CONSTRAINT chk_planner_hours CHECK (working_hours > 0),
        CONSTRAINT chk_planner_sam CHECK (sam_minutes > 0)
      );
    `);
    await client.query("ALTER TABLE line_runs ADD COLUMN IF NOT EXISTS is_draft BOOLEAN NOT NULL DEFAULT false;");
    console.log("✅ planner_lines + line_runs.is_draft ready in prod_db_schema");
// 10. Create quality_defect_reasons table (master data)
await client.query(`
  CREATE TABLE IF NOT EXISTS quality_defect_reasons(
    id BIGSERIAL PRIMARY KEY,
    defect_type_id BIGINT NOT NULL REFERENCES quality_defect_types(id) ON DELETE CASCADE,
    reason_code VARCHAR(20) NOT NULL,
    reason_description TEXT NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    sort_order INT DEFAULT 0,
    UNIQUE(defect_type_id, reason_code)
  );
`);
console.log("✅ quality_defect_reasons table ready");

// 11. Create quality_defect_entries table (actual defects recorded)
await client.query(`
  CREATE TABLE IF NOT EXISTS quality_defect_entries(
    id BIGSERIAL PRIMARY KEY,
    inspection_id BIGINT NOT NULL REFERENCES quality_inspections(id) ON DELETE CASCADE,
    defect_type_id BIGINT NOT NULL REFERENCES quality_defect_types(id),
    defect_reason_id BIGINT REFERENCES quality_defect_reasons(id),
    defect_quantity INT NOT NULL DEFAULT 1,
    operation_name VARCHAR(100),
    operator_no INT,
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
  );
`);
console.log("✅ quality_defect_entries table ready");

// 12. Create indexes for quality tables
await client.query("CREATE INDEX IF NOT EXISTS idx_quality_inspections_line_date ON quality_inspections(line_no, inspection_date);");
await client.query("CREATE INDEX IF NOT EXISTS idx_quality_inspections_inspector ON quality_inspections(inspector_name);");
await client.query("CREATE INDEX IF NOT EXISTS idx_quality_defect_entries_inspection ON quality_defect_entries(inspection_id);");
await client.query("CREATE INDEX IF NOT EXISTS idx_quality_defect_entries_type ON quality_defect_entries(defect_type_id);");

// ----------------------------------------------------------------------
// 13. WORK ORDERS, CUSTOMERS, FABRICS, LINE ASSIGNMENTS, MASTER CODES
// (ported from server.js — these tables are used by the work-orders,
// customers, fabrics, line-assignments, and master-codes endpoints
// below, plus the planning/dashboard queries earlier in this file)
// ----------------------------------------------------------------------
await client.query(`
  CREATE TABLE IF NOT EXISTS work_orders(
    id BIGSERIAL PRIMARY KEY,
    work_order_no VARCHAR(50) UNIQUE NOT NULL,
    quantity NUMERIC(12,2) NOT NULL,
    customer_name VARCHAR(100) NOT NULL,
    style_description TEXT NOT NULL,
    color VARCHAR(50),
    fabric_supplier VARCHAR(100),
    style_code VARCHAR(50),
    line_no VARCHAR(20),
    run_date DATE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    CONSTRAINT chk_quantity_positive CHECK (quantity > 0),
    CONSTRAINT chk_status CHECK (status IN ('pending', 'assigned', 'in_progress', 'completed'))
  );
`);
console.log("✅ work_orders table ready in prod_db_schema");

// Customers table (referenced by work_orders.customer_id)
await client.query(`
  CREATE TABLE IF NOT EXISTS customers(
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(150) UNIQUE NOT NULL,
    market_type VARCHAR(20) NOT NULL DEFAULT 'domestico',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT chk_market_type CHECK (market_type IN ('domestico', 'export'))
  );
`);
console.log("✅ customers table ready in prod_db_schema");

// Links a customer to the 3-letter "cliente" code segment used inside
// master codes (e.g. NIK), so selecting a master code can auto-select
// the matching customer instead of the planner having to pick it by hand.
await client.query(`ALTER TABLE customers ADD COLUMN IF NOT EXISTS code VARCHAR(10);`);
await client.query(`DROP INDEX IF EXISTS idx_customers_code_unique;`);
await client.query(`CREATE UNIQUE INDEX idx_customers_code_unique ON customers (code) WHERE code IS NOT NULL;`);
console.log("✅ customers.code ready in prod_db_schema");

// Fabrics table (referenced by work_orders.fabrics[])
await client.query(`
  CREATE TABLE IF NOT EXISTS fabrics(
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(150) UNIQUE NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
  );
`);
console.log("✅ fabrics table ready in prod_db_schema");

// Bring work_orders up to date with what WorkOrderForm.jsx actually sends,
// and link it to a merchant master_code so the real style SAM travels with the order.
await client.query(`ALTER TABLE work_orders ADD COLUMN IF NOT EXISTS customer_id BIGINT REFERENCES customers(id) ON DELETE SET NULL;`);
await client.query(`ALTER TABLE work_orders ADD COLUMN IF NOT EXISTS warehouse_stock NUMERIC(12,2) NOT NULL DEFAULT 0;`);
await client.query(`ALTER TABLE work_orders ADD COLUMN IF NOT EXISTS extra_quantity NUMERIC(12,2) NOT NULL DEFAULT 0;`);
await client.query(`ALTER TABLE work_orders ADD COLUMN IF NOT EXISTS total_to_produce NUMERIC(12,2);`);
await client.query(`ALTER TABLE work_orders ADD COLUMN IF NOT EXISTS commitment_date DATE;`);
await client.query(`ALTER TABLE work_orders ADD COLUMN IF NOT EXISTS fabrics TEXT[] NOT NULL DEFAULT '{}';`);
await client.query(`ALTER TABLE work_orders ADD COLUMN IF NOT EXISTS estilo VARCHAR(20);`);
await client.query(`ALTER TABLE work_orders ADD COLUMN IF NOT EXISTS sam_minutes NUMERIC(8,2);`);
// 'cancelled' is used by the soft-delete route below but was missing from the original check constraint
await client.query(`ALTER TABLE work_orders DROP CONSTRAINT IF EXISTS chk_status;`);
await client.query(`
  ALTER TABLE work_orders ADD CONSTRAINT chk_status CHECK (
    status IN ('pending', 'assigned', 'in_progress', 'completed', 'cancelled')
  );
`);
console.log("✅ work_orders columns updated in prod_db_schema");

// Junction table between work_orders and line_runs
await client.query(`
  CREATE TABLE IF NOT EXISTS line_assignments(
    id BIGSERIAL PRIMARY KEY,
    work_order_id BIGINT NOT NULL REFERENCES work_orders(id) ON DELETE CASCADE,
    line_run_id BIGINT REFERENCES line_runs(id) ON DELETE SET NULL,
    line_no TEXT NOT NULL,
    assigned_date DATE NOT NULL,
    assigned_quantity NUMERIC(12,2) NOT NULL,
    available_minutes NUMERIC(12,2) NOT NULL,
    required_production_rate NUMERIC(12,2) NOT NULL,
    planned_start_date DATE,
    planned_end_date DATE,
    priority INT DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    status VARCHAR(20) NOT NULL DEFAULT 'planned',
    CONSTRAINT chk_assigned_quantity_positive CHECK (assigned_quantity > 0),
    CONSTRAINT chk_assignment_status CHECK (status IN ('planned', 'released', 'completed', 'cancelled'))
  );
`);
console.log("✅ line_assignments table ready in prod_db_schema");

await client.query(`
  CREATE TABLE IF NOT EXISTS master_codes(
    id BIGSERIAL PRIMARY KEY,
    code VARCHAR(50) UNIQUE NOT NULL,
    type VARCHAR(3) NOT NULL,
    modelo VARCHAR(3) NOT NULL,
    correlativo VARCHAR(2) NOT NULL,
    talla VARCHAR(3) NOT NULL,
    cliente VARCHAR(3) NOT NULL,
    color VARCHAR(3) NOT NULL,
    estilo VARCHAR(6) NOT NULL,
    description TEXT NOT NULL,
    sam_minutes NUMERIC(8,2) NOT NULL,
    photo_url TEXT,
    photo_filename VARCHAR(255),
    created_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
  );
`);
console.log("✅ master_codes table ready in prod_db_schema");

await client.query("CREATE INDEX IF NOT EXISTS idx_master_codes_code ON master_codes(code);");
await client.query("CREATE INDEX IF NOT EXISTS idx_master_codes_type ON master_codes(type);");
await client.query("CREATE INDEX IF NOT EXISTS idx_master_codes_modelo ON master_codes(modelo);");
await client.query("CREATE INDEX IF NOT EXISTS idx_master_codes_talla ON master_codes(talla);");

// work_orders.master_code_id can only be added now that master_codes exists
await client.query(`ALTER TABLE work_orders ADD COLUMN IF NOT EXISTS master_code_id BIGINT REFERENCES master_codes(id) ON DELETE SET NULL;`);
console.log("✅ work_orders.master_code_id linked to master_codes");


// ---- Printed production tickets --------------------------------------------
// Every confirmed print batch from the line-leader ticket builder is logged
// here (one row per talla+color+PO per confirm). The sum of `quantity` for a
// (work_order_id, estilo, talla, color, customer_po) is subtracted from the
// merchant size breakdown in /api/get-run-data, so the "Asignado" quantity the
// builder shows keeps decreasing as tickets are printed. Scoped to the work
// order (not the run) on purpose: a new run/day for the same WO still sees the
// already-printed amounts removed.
await client.query(`
  CREATE TABLE IF NOT EXISTS ticket_prints(
    id BIGSERIAL PRIMARY KEY,
    run_id BIGINT NOT NULL REFERENCES line_runs(id) ON DELETE CASCADE,
    work_order_id BIGINT REFERENCES work_orders(id) ON DELETE SET NULL,
    estilo VARCHAR(20),
    talla VARCHAR(20) NOT NULL,
    color VARCHAR(40) NOT NULL DEFAULT '',
    customer_po VARCHAR(80) NOT NULL DEFAULT '',
    quantity NUMERIC(12,2) NOT NULL,
    ticket_count INT NOT NULL DEFAULT 0,
    printed_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT chk_ticket_print_qty_positive CHECK (quantity > 0)
  );
`);
await client.query("CREATE INDEX IF NOT EXISTS idx_ticket_prints_run ON ticket_prints(run_id);");
await client.query("CREATE INDEX IF NOT EXISTS idx_ticket_prints_wo ON ticket_prints(work_order_id, estilo, talla, color, customer_po);");
console.log("✅ ticket_prints table ready in prod_db_schema");



await client.query("CREATE INDEX IF NOT EXISTS idx_work_orders_status ON work_orders(status);");
await client.query("CREATE INDEX IF NOT EXISTS idx_work_orders_wo_no ON work_orders(work_order_no);");
await client.query("CREATE INDEX IF NOT EXISTS idx_line_assignments_line ON line_assignments(line_no, assigned_date);");
await client.query("CREATE INDEX IF NOT EXISTS idx_line_assignments_work_order ON line_assignments(work_order_id);");
// ---- One work-order+color = one cell per line-day ---------------------------
// A single (work_order, line, day, color) must live in ONE planned row. Before
// this rule existed, repeated packing could leave several slivers of the same
// order+color stacked in one cell (e.g. 386 + 21 + 11). Collapse any such
// leftovers into a single row (summing the pieces), then add a partial unique
// index so fragments can never reappear. Only 'planned' rows are touched;
// completed/cancelled history is left exactly as it is.
// NOTE: runMigrations() already wraps this whole block in one transaction, so
// these run atomically — no local BEGIN/COMMIT (that would close the outer tx).
//
// Sum every duplicate group into its oldest row...
await client.query(`
  WITH dups AS (
    SELECT MIN(id) AS keep_id,
           SUM(assigned_quantity) AS total_qty,
           MIN(planned_start_date) AS start_d,
           MAX(planned_end_date)   AS end_d
      FROM line_assignments
     WHERE status = 'planned'
     GROUP BY work_order_id, line_no, assigned_date, COALESCE(color, '')
    HAVING COUNT(*) > 1
  )
  UPDATE line_assignments la
     SET assigned_quantity  = d.total_qty,
         planned_start_date = COALESCE(d.start_d, la.planned_start_date),
         planned_end_date   = COALESCE(d.end_d,   la.planned_end_date),
         updated_at = now()
    FROM dups d
   WHERE la.id = d.keep_id;
`);
// ...then drop the now-redundant slivers (everything but the oldest per group).
await client.query(`
  DELETE FROM line_assignments la
   USING (
     SELECT id,
            ROW_NUMBER() OVER (
              PARTITION BY work_order_id, line_no, assigned_date, COALESCE(color, '')
              ORDER BY id
            ) AS rn
       FROM line_assignments
      WHERE status = 'planned'
   ) r
   WHERE la.id = r.id AND r.rn > 1;
`);
// Backstop: at most one planned row per work-order+line+day+color from now on.
await client.query(
  `CREATE UNIQUE INDEX IF NOT EXISTS uq_line_assign_planned_cell
     ON line_assignments (work_order_id, line_no, assigned_date, (COALESCE(color, '')))
   WHERE status = 'planned';`
);
console.log("✅ line_assignments consolidated to one planned row per cell (wo+line+day+color)");
// ── INSERTAR AQUÍ ─────────────────────────────────────────────────────────
// line_runs.work_order_id se INSERTA en /api/save-production pero nunca se creo
// en el CREATE TABLE de arriba. Sin esta columna resolveProducedSubquery no
// encuentra como ligar la corrida con la orden y produced_quantity queda en 0.
await client.query(`ALTER TABLE line_runs ADD COLUMN IF NOT EXISTS work_order_id BIGINT REFERENCES work_orders(id) ON DELETE SET NULL;`);
await client.query("CREATE INDEX IF NOT EXISTS idx_line_runs_work_order ON line_runs(work_order_id);");
// ────
await registerEfficiencyPermissions.initSchema({ pool, setSchema });
await registerSupermarketPlan.initSchema({ pool, setSchema });   // ← nueva
await registerHolidays.initSchema({ pool, setSchema });
await registerFinishedWarehouseAnalytics.initSchema({ pool, setSchema });
// ~línea 622, en el bloque async de arranque, junto a los otros initSchema:
await registerPreOrders.initSchema({ pool, setSchema });
await registerMerchantAnalytics.initSchema({ pool, setSchema });
await registerMerchantPlan.initSchema({ pool, setSchema });
await registerPreOrderHolds.initSchema({ pool, setSchema });   // ← add
await registerCutOrders.initSchema({ pool, setSchema });
await registerFinishedWarehouse.initSchema({ pool, setSchema });
await registerOrderSets.initSchema({ pool, setSchema });   // ← must come first
await registerWorkOrders.initSchema({ pool, setSchema });   // ← add this

    // Create index for faster queries
    await client.query("CREATE INDEX IF NOT EXISTS idx_capacity_history_operation ON operator_capacity_history(operation_id);");
    await client.query("CREATE INDEX IF NOT EXISTS idx_capacity_history_changed_at ON operator_capacity_history(changed_at);");

    // Indexes
    await client.query("CREATE INDEX IF NOT EXISTS idx_sewed_run ON operation_sewed_entries(run_id);");
    await client.query("CREATE INDEX IF NOT EXISTS idx_sewed_slot ON operation_sewed_entries(slot_id);");
    await client.query("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username) WHERE is_active = TRUE;");
    await client.query("CREATE INDEX IF NOT EXISTS idx_users_role ON users(role, line_number);");
    await client.query("CREATE INDEX IF NOT EXISTS idx_line_runs_line_date ON line_runs (line_no, run_date);");
    await client.query("CREATE INDEX IF NOT EXISTS idx_shift_slots_run ON shift_slots(run_id);");
    await client.query("CREATE INDEX IF NOT EXISTS idx_run_operators_run ON run_operators(run_id);");
    await client.query("CREATE INDEX IF NOT EXISTS idx_operator_ops_run ON operator_operations(run_id);");
    await client.query("CREATE INDEX IF NOT EXISTS idx_operator_ops_operator ON operator_operations(run_operator_id);");
    await client.query("CREATE INDEX IF NOT EXISTS idx_hourly_entries_run ON operation_hourly_entries(run_id);");
    await client.query("CREATE INDEX IF NOT EXISTS idx_hourly_entries_operation ON operation_hourly_entries(operation_id);");
    await client.query("CREATE INDEX IF NOT EXISTS idx_hourly_entries_slot ON operation_hourly_entries(slot_id);");

    logger.info("✅ All tables and indexes created successfully");

    await seedDefaultUsers(client);

    await client.query("COMMIT");
    logger.info("✅ Migrations completed successfully.");
  } catch (err) {
    await client.query("ROLLBACK");
    logger.error("❌ Migration failed", { error: err.message, stack: err.stack });
    throw err;
  } finally {
    client.release();
  }
};

const seedDefaultUsers = async (client) => {
  const defaultUsers = [
    { username: "engineer", password: "engineer", role: "engineer", full_name: "System Engineer" },
    { username: "supervisor", password: "supervisor123", role: "supervisor", full_name: "Production Supervisor" },
    { username: "soporte_it", password: "soporte_it123", role: "soporte_it", full_name: "IT Support" },
    { username: "skyrina", password: "skyrina123", role: "skyrina", full_name: "Skyrina" },
    { username: "Salvador", password: "Cassab", role: "master", full_name: "Salvador Cassab" },
  ];
  for (let i = 1; i <= 26; i++) {
    defaultUsers.push({
      username: `line${i}`,
      password: `line${i}`,
      role: "line_leader",
      line_number: i,
      full_name: `Line ${i} Leader`,
    });
  }

  for (const user of defaultUsers) {
    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(user.password, saltRounds);
    await client.query(
      `
      INSERT INTO users (username, password_hash, role, line_number, full_name, is_active)
      VALUES ($1, $2, $3, $4, $5, $6)
      ON CONFLICT (username) DO NOTHING
      `,
      [user.username, passwordHash, user.role, user.line_number || null, user.full_name || user.username, true]
    );
  }
  logger.info(`✅ Default users seeded.`);
};

// ----------------------------------------------------------------------
// 7. AUTHENTICATION MIDDLEWARE
// ----------------------------------------------------------------------
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    logger.warn("Authentication failed: no token provided", { ip: req.ip });
    return res.status(401).json({ success: false, error: "Authentication required" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const client = await pool.connect();
    try {
      await setSchema(client);
      const userResult = await client.query(
        `SELECT id, username, role, line_number, full_name
         FROM users
         WHERE id = $1 AND is_active = TRUE`,
        [decoded.id]
      );
      if (userResult.rows.length === 0) {
        logger.warn("Authentication failed: user not found or inactive", { userId: decoded.id });
        return res.status(401).json({ success: false, error: "User not found or inactive" });
      }
      req.user = userResult.rows[0];
      next();
    } finally {
      client.release();
    }
  } catch (err) {
    logger.warn("Authentication failed: invalid token", { error: err.message });
    return res.status(403).json({ success: false, error: "Invalid or expired token" });
  }
};

const allowRoles = (...roles) => (req, res, next) => {
  if (!req.user) return res.status(401).json({ success: false, error: "Not authenticated" });
  if (!roles.includes(req.user.role)) {
    logger.warn("Access denied: insufficient role", { user: req.user.username, role: req.user.role, required: roles });
    return res.status(403).json({ success: false, error: "Access denied. Insufficient permissions." });
  }
  next();
};

// ----------------------------------------------------------------------
// 8. VALIDATION HELPERS
// ----------------------------------------------------------------------
const validate = (validations) => {
  return async (req, res, next) => {
    await Promise.all(validations.map((validation) => validation.run(req)));

    const errors = validationResult(req);
    if (errors.isEmpty()) {
      return next();
    }

    const extractedErrors = errors.array().map((err) => ({ [err.param]: err.msg }));
    logger.warn("Validation error", { errors: extractedErrors, body: req.body });
    return res.status(400).json({
      success: false,
      error: "Validation failed",
      details: extractedErrors,
    });
  };
};

// ----------------------------------------------------------------------
// 9. ERROR HANDLING MIDDLEWARE
// ----------------------------------------------------------------------
const errorHandler = (err, req, res, next) => {
  logger.error("Unhandled error", { error: err.message, stack: err.stack, url: req.url, method: req.method });
  res.status(err.status || 500).json({
    success: false,
    error: process.env.NODE_ENV === "production" ? "Internal server error" : err.message,
  });
};

// ----------------------------------------------------------------------
// 10. HEALTH CHECK
// ----------------------------------------------------------------------
app.get("/api/health", async (req, res, next) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
    await client.query("SELECT 1");
    res.json({
      success: true,
      message: "Server and database are running",
      schema: "prod_db_schema",
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    next(err);
  } finally {
    client.release();
  }
});

// ----------------------------------------------------------------------
// 11. AUTHENTICATION ENDPOINTS
// ----------------------------------------------------------------------
app.post(
  "/api/login",
  authLimiter,
  validate([
    body("username").notEmpty().withMessage("Username is required"),
    body("password").notEmpty().withMessage("Password is required"),
  ]),
  async (req, res, next) => {
    const client = await pool.connect();
    try {
      await setSchema(client);
      const { username, password } = req.body;

      const userResult = await client.query(
        `SELECT id, username, password_hash, role, line_number, full_name, is_active
         FROM users
         WHERE username = $1 AND is_active = TRUE`,
        [username]
      );

      if (userResult.rows.length === 0) {
        logger.warn("Login failed: user not found", { username });
        return res.status(401).json({ success: false, error: "Invalid username or password" });
      }

      const user = userResult.rows[0];
      const isValidPassword = await bcrypt.compare(password, user.password_hash);
      if (!isValidPassword) {
        logger.warn("Login failed: invalid password", { username });
        return res.status(401).json({ success: false, error: "Invalid username or password" });
      }

      const token = jwt.sign(
        { id: user.id, username: user.username, role: user.role },
        JWT_SECRET,
        { expiresIn: JWT_EXPIRES_IN }
      );

      delete user.password_hash;

      logger.info("Login successful", { username: user.username, role: user.role });

      res.json({
        success: true,
        message: "Login successful",
        user,
        token,
      });
    } catch (err) {
      next(err);
    } finally {
      client.release();
    }
  }
);

app.get("/api/me", authenticateToken, (req, res) => {
  res.json({ success: true, user: req.user });
});
const registerHolidays = require("./holidays");
registerHolidays(app, { authenticateToken, pool, setSchema });
// ~línea 867, junto a registerMerchantPlan:
const registerPreOrders = require("./pre-orders");
registerPreOrders(app, { authenticateToken, pool, setSchema });
// with the other requires / registrations, near registerFinishedWarehouse:
const registerFinishedWarehouseAnalytics = require("./finished-warehouse-analytics");
registerFinishedWarehouseAnalytics(app, { authenticateToken, pool, setSchema });

const registerPreOrderHolds = require("./pre-order-holds");
registerPreOrderHolds(app, { authenticateToken, pool, setSchema });

const registerCutOrderAnalytics = require("./cut-order-analytics");
registerCutOrderAnalytics(app, { authenticateToken, pool, setSchema });

const registerMerchantAnalytics = require("./merchant-analytics");
registerMerchantAnalytics(app, { authenticateToken, pool, setSchema });

const registerMerchantPlan = require("./merchant-plan");
registerMerchantPlan(app, { authenticateToken, pool, setSchema });

const registerFinishedWarehouse = require("./finished-warehouse");
registerFinishedWarehouse(app, { authenticateToken, pool, setSchema });

const registerCutOrders = require("./cut-orders");
registerCutOrders(app, { authenticateToken, pool, setSchema });

const registerOrderSets = require("./order-sets");
registerOrderSets(app, { authenticateToken, pool, setSchema });

const registerWorkOrders = require("./work-orders");
registerWorkOrders(app, {
  authenticateToken,
  pool,
  setSchema,
  generatePresignedGetUrl,
   uploadBufferToS3,      // add
  makeStylePhotoKey,     // add
  deleteFromS3,          // ← add this line
});
const registerMechanicsSummary = require("./mecanics-summary");
registerMechanicsSummary(app, authenticateToken);

const registerSupermarketPlan = require("./supermarket-plan");
registerSupermarketPlan(app, {
  authenticateToken,
  pool,
  setSchema,
  publisherRoles: ["planner", "supervisor", "master", "soporte_it", "skyrina", "admin","supermarcado"],
});

const registerEfficiencyPermissions = require("./efficiency-permissions");
registerEfficiencyPermissions(app, { authenticateToken, pool, setSchema });

app.post("/api/logout", (req, res) => {
  res.json({ success: true, message: "Logged out successfully" });
});

// ----------------------------------------------------------------------
// 12. PRODUCTION DATA ENDPOINTS (engineer/supervisor)
// ----------------------------------------------------------------------
app.post(
  "/api/save-production",
  authenticateToken,
  allowRoles("engineer", "supervisor"),
  validate([
    body("line").notEmpty().withMessage("Line is required"),
    body("date").isDate().withMessage("Valid date required"),
    body("style").notEmpty().withMessage("Style is required"),
    body("color").optional({ nullable: true }).isString().withMessage("Color must be a string if provided"),
    body("operators").isInt({ min: 0 }).withMessage("Operators must be a non‑negative integer"),
    body("workingHours").isFloat({ min: 0.1 }).withMessage("Working hours must be positive"),
    body("sam").isFloat({ min: 0.01 }).withMessage("SAM must be positive"),
    body("efficiency").optional().isFloat({ min: 0.01, max: 1 }).withMessage("Efficiency must be between 0.01 and 1"),
    body("target").optional().isFloat({ min: 0 }).withMessage("Target must be non‑negative"),
    body("targetPerHour").optional().isFloat({ min: 0 }).withMessage("Target per hour must be non‑negative"),
    body("slots").isArray({ min: 1 }).withMessage("At least one shift slot required"),
    body("slots.*.label").notEmpty().withMessage("Slot label required"),
    body("slots.*.hours").isFloat({ min: 0 }).withMessage("Planned hours must be non‑negative"),
    body("workOrderId").optional({ nullable: true }).isInt({ min: 1 }).withMessage("workOrderId must be a positive integer"),
  ]),
  async (req, res, next) => {
    const client = await pool.connect();
    try {
      await setSchema(client);
      await client.query("BEGIN");

      const { line, date, style, color, operators, workingHours, sam, efficiency, target, targetPerHour, slots , workOrderId } = req.body;

      // style stays the plain estilo (tipo+modelo+correlativo, e.g. DAMBOD01);
      // color is stored separately so two colors of the same style coexist as
      // distinct runs (unique on line_no, run_date, style, color).
      const lineRunResult = await client.query(
        `INSERT INTO line_runs (line_no, run_date, style, color, operators_count, working_hours, sam_minutes, efficiency, target_pcs, target_per_hour, work_order_id, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW(), NOW())
         RETURNING id`,
        [
          line,
          date,
          style,
          (color || "").trim(),
          parseInt(operators, 10) || 0,
          parseFloat(workingHours),
          parseFloat(sam),
          parseFloat(efficiency) || 0.7,
          parseFloat(target) || 0,
          parseFloat(targetPerHour) || 0,
          workOrderId || null,
        ]
      );

      const runId = lineRunResult.rows[0].id;
      logger.info(`Line run created`, { runId, line, date, style, color: (color || "").trim() });

      const slotIds = {};
      for (let i = 0; i < slots.length; i++) {
        const slot = slots[i];
        const slotResult = await client.query(
          `INSERT INTO shift_slots (run_id, slot_order, slot_label, slot_start, slot_end, planned_hours)
           VALUES ($1, $2, $3, $4, $5, $6)
           RETURNING id, slot_label`,
          [runId, i + 1, slot.label, slot.startTime || null, slot.endTime || null, parseFloat(slot.hours) || 0]
        );
        slotIds[slot.label] = slotResult.rows[0].id;
      }

      await client.query("COMMIT");
      res.json({ success: true, message: "Production data saved", lineRunId: runId, slotIds });
    } catch (err) {
      await client.query("ROLLBACK");
      // Unique (line_no, run_date, style, color) collision -> friendly message.
      if (err.code === "23505") {
        return res.status(409).json({
          success: false,
          error: "Ya existe una corrida para esa línea, fecha, estilo y color. Elige otro color o fecha.",
        });
      }
      next(err);
    } finally {
      client.release();
    }
  }
);

app.post(
  "/api/save-operations",
  authenticateToken,
  allowRoles("engineer", "supervisor"),
  validate([
    body("runId").isInt({ gt: 0 }).withMessage("Valid run ID required"),
    body("operations").isArray({ min: 1 }).withMessage("At least one operation required"),
  ]),
  async (req, res, next) => {
    const client = await pool.connect();
    try {
      await setSchema(client);
      await client.query("BEGIN");

      const { runId, operations, slotTargets, cumulativeTargets } = req.body;

      const runCheck = await client.query("SELECT id FROM line_runs WHERE id = $1", [runId]);
      if (runCheck.rows.length === 0) {
        return res.status(404).json({ success: false, error: "Line run not found" });
      }

      const slotsResult = await client.query(
        "SELECT id, slot_label FROM shift_slots WHERE run_id = $1 ORDER BY slot_order",
        [runId]
      );
      const slotMap = Object.fromEntries(slotsResult.rows.map((s) => [s.slot_label, s.id]));

      const operatorMap = {};
      let savedOperations = 0;

      for (const op of operations) {
        const { operatorNo, operatorName, operation: operationName, t1, t2, t3, t4, t5, capacityPerHour } = op;
        if (!operatorNo || !operationName) continue;

        const operatorResult = await client.query(
          `INSERT INTO run_operators (run_id, operator_no, operator_name, created_at)
           VALUES ($1, $2, $3, NOW())
           ON CONFLICT (run_id, operator_no) DO UPDATE SET operator_name = EXCLUDED.operator_name
           RETURNING id`,
          [runId, parseInt(operatorNo, 10), operatorName || null]
        );
        const operatorId = operatorResult.rows[0].id;
        operatorMap[operatorNo] = operatorId;

        await client.query(
          `INSERT INTO operator_operations (run_id, run_operator_id, operation_name, t1_sec, t2_sec, t3_sec, t4_sec, t5_sec, capacity_per_hour, created_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
           ON CONFLICT (run_operator_id, operation_name) DO UPDATE SET
             t1_sec = EXCLUDED.t1_sec,
             t2_sec = EXCLUDED.t2_sec,
             t3_sec = EXCLUDED.t3_sec,
             t4_sec = EXCLUDED.t4_sec,
             t5_sec = EXCLUDED.t5_sec,
             capacity_per_hour = EXCLUDED.capacity_per_hour`,
          [
            runId,
            operatorId,
            operationName,
            t1 ? parseFloat(t1) : null,
            t2 ? parseFloat(t2) : null,
            t3 ? parseFloat(t3) : null,
            t4 ? parseFloat(t4) : null,
            t5 ? parseFloat(t5) : null,
            parseFloat(capacityPerHour) || 0,
          ]
        );
        savedOperations++;
      }

      if (slotTargets && cumulativeTargets && slotsResult.rows.length) {
        for (let i = 0; i < slotsResult.rows.length; i++) {
          const slot = slotsResult.rows[i];
          await client.query(
            `INSERT INTO slot_targets (run_id, slot_id, slot_target, cumulative_target, created_at, updated_at)
             VALUES ($1, $2, $3, $4, NOW(), NOW())
             ON CONFLICT (run_id, slot_id) DO UPDATE SET
               slot_target = EXCLUDED.slot_target,
               cumulative_target = EXCLUDED.cumulative_target,
               updated_at = NOW()`,
            [runId, slot.id, parseFloat(slotTargets[i] || 0), parseFloat(cumulativeTargets[i] || 0)]
          );
        }
      }

      await client.query("COMMIT");
      logger.info(`Operations saved`, { runId, operations: savedOperations });
      res.json({ success: true, message: "Operations saved", operationsCount: savedOperations });
    } catch (err) {
      await client.query("ROLLBACK");
      next(err);
    } finally {
      client.release();
    }
  }
);

app.post(
  "/api/save-hourly-data",
  authenticateToken,
  async (req, res, next) => {
    if (req.user.role === "line_leader") {
      const { entries } = req.body;
      if (!entries || !entries.length) return res.status(400).json({ success: false, error: "No entries" });
      const runId = entries[0].runId;
      const client = await pool.connect();
      try {
        await setSchema(client);
        const run = await client.query("SELECT line_no FROM line_runs WHERE id = $1", [runId]);
        if (run.rows.length === 0 || String(run.rows[0].line_no) !== String(req.user.line_number)) {
          logger.warn("Line leader attempted to access another line", {
            user: req.user.username,
            requestedLine: run.rows[0]?.line_no,
            userLine: req.user.line_number,
          });
          return res.status(403).json({ success: false, error: "You can only update your own line" });
        }
      } catch (e) {
        return next(e);
      } finally {
        client.release();
      }
    }
    next();
  },
  validate([
    body("entries").isArray().withMessage("Entries must be an array"),
    body("entries.*.runId").isInt({ gt: 0 }).withMessage("Valid run ID required"),
    body("entries.*.operatorNo").isInt({ gt: 0 }).withMessage("Operator number required"),
    body("entries.*.operationName").notEmpty().withMessage("Operation name required"),
    body("entries.*.slotLabel").notEmpty().withMessage("Slot label required"),
    body("entries.*.stitchedQty").isFloat({ min: 0 }).withMessage("Stitched quantity must be >= 0"),
  ]),
  async (req, res, next) => {
    const client = await pool.connect();
    try {
      await setSchema(client);
      await client.query("BEGIN");

      const { entries } = req.body;
      let savedCount = 0,
        skippedCount = 0;

      for (const entry of entries) {
        const { runId, operatorNo, operationName, slotLabel, stitchedQty } = entry;

        const opResult = await client.query(
          `SELECT o.id as op_id
           FROM operator_operations o
           JOIN run_operators ro ON o.run_operator_id = ro.id
           WHERE o.run_id = $1 AND ro.operator_no = $2 AND o.operation_name = $3
           LIMIT 1`,
          [runId, parseInt(operatorNo, 10), operationName]
        );

        if (opResult.rows.length === 0) {
          skippedCount++;
          continue;
        }
        const operationId = opResult.rows[0].op_id;

        const slotResult = await client.query(
          "SELECT id FROM shift_slots WHERE run_id = $1 AND slot_label = $2",
          [runId, slotLabel]
        );
        if (slotResult.rows.length === 0) {
          skippedCount++;
          continue;
        }
        const slotId = slotResult.rows[0].id;

        await client.query(
          `INSERT INTO operation_hourly_entries (run_id, operation_id, slot_id, stitched_qty, created_at, updated_at)
           VALUES ($1, $2, $3, $4, NOW(), NOW())
           ON CONFLICT (operation_id, slot_id) DO UPDATE SET
             stitched_qty = EXCLUDED.stitched_qty,
             updated_at = NOW()`,
          [runId, operationId, slotId, parseFloat(stitchedQty) || 0]
        );
        savedCount++;
      }

      await client.query("COMMIT");
      logger.info(`Hourly data saved`, { runId: entries[0]?.runId, saved: savedCount, skipped: skippedCount });
      res.json({ success: true, message: "Hourly data saved", savedCount, skippedCount });
    } catch (err) {
      await client.query("ROLLBACK");
      next(err);
    } finally {
      client.release();
    }
  }
);

app.post(
  "/api/lineleader/update-sewed/:runId",
  authenticateToken,
  allowRoles("line_leader", "engineer", "supervisor"),
  async (req, res, next) => {
    if (req.user.role === "line_leader") {
      const client = await pool.connect();
      try {
        await setSchema(client);
        const run = await client.query("SELECT line_no FROM line_runs WHERE id = $1", [req.params.runId]);
        if (run.rows.length === 0 || String(run.rows[0].line_no) !== String(req.user.line_number)) {
          return res.status(403).json({ success: false, error: "You can only update your own line" });
        }
      } catch (e) {
        return next(e);
      } finally {
        client.release();
      }
    }
    next();
  },
  validate([
    param("runId").isInt({ gt: 0 }).withMessage("Valid run ID required"),
    body("entries").isArray().withMessage("Entries must be an array"),
  ]),
  async (req, res, next) => {
    const client = await pool.connect();
    try {
      await setSchema(client);
      await client.query("BEGIN");

      const { runId } = req.params;
      const { entries } = req.body;
      let updatedCount = 0;

      for (const entry of entries) {
        const { operatorNo, operationName, slotLabel, sewedQty } = entry;

        const opResult = await client.query(
          `SELECT o.id as op_id
           FROM operator_operations o
           JOIN run_operators ro ON o.run_operator_id = ro.id
           WHERE o.run_id = $1 AND ro.operator_no = $2 AND o.operation_name = $3
           LIMIT 1`,
          [runId, parseInt(operatorNo, 10), operationName]
        );
        if (opResult.rows.length === 0) continue;
        const operationId = opResult.rows[0].op_id;

        const slotResult = await client.query(
          "SELECT id FROM shift_slots WHERE run_id = $1 AND slot_label = $2",
          [runId, slotLabel]
        );
        if (slotResult.rows.length === 0) continue;
        const slotId = slotResult.rows[0].id;

        await client.query(
          `INSERT INTO operation_sewed_entries (run_id, operation_id, slot_id, sewed_qty, created_at, updated_at)
           VALUES ($1, $2, $3, $4, NOW(), NOW())
           ON CONFLICT (operation_id, slot_id) DO UPDATE SET
             sewed_qty = EXCLUDED.sewed_qty,
             updated_at = NOW()`,
          [runId, operationId, slotId, parseFloat(sewedQty) || 0]
        );
        updatedCount++;
      }

      await client.query("COMMIT");

       let autoCompleted = null;
      try {
        const runInfo = await client.query(
          `SELECT work_order_id, line_no, to_char(run_date, 'YYYY-MM-DD') AS day
             FROM line_runs WHERE id = $1`,
          [runId]
        );
        const r = runInfo.rows[0];
        if (r && r.work_order_id) {
          autoCompleted = await registerWorkOrders.autoCompleteDay(client, {
            workOrderId: r.work_order_id,
            lineNo: r.line_no,
            day: r.day,
          });
        }
      } catch (e) {
        console.warn("⚠️  auto-cierre de celda falló (el guardado sí se realizó):", e.message);
      }

      // Mueve el estado de la ORDEN según lo producido: producido>0 -> en proceso,
      // producido>=asignado -> terminada. Solo empuja hacia adelante y nunca
      // degrada. Es aparte del auto-cierre de celda (autoCompleteDay), que solo
      // toca line_assignments; esto actualiza wo.status, que es lo que ve el
      // planeador en OrderStatus.jsx.
      let statusChange = null;
      try {
        const runInfo2 = await client.query(
          `SELECT work_order_id FROM line_runs WHERE id = $1`,
          [runId]
        );
        const woId = runInfo2.rows[0]?.work_order_id;
        if (woId) {
          statusChange = await registerWorkOrders.refreshWorkOrderStatusFromProduction(client, woId);
        }
      } catch (e) {
        console.warn("⚠️  recálculo de estado de la orden falló (el guardado sí se realizó):", e.message);
      }

      res.json({ success: true, updatedCount, autoCompleted, statusChange });
    } catch (err) {
      await client.query("ROLLBACK");
      next(err);
    } finally {
      client.release();
    }
  }
);

// ============================================================================
// VERIFICADOR — corrección de la captura por hora del líder de línea
// ----------------------------------------------------------------------------
// Flujo del frontend (VerificadorPage.jsx): el verificador elige FECHA -> LÍNEA
// -> ESTILO (cada estilo es una corrida / line_run) y luego edita la cuadrícula
// operación × hora. A diferencia del líder de línea, aquí NO hay bloqueo de
// celdas: el verificador puede sobrescribir cualquier valor ya guardado.
//
// Mismo modelo de datos que /api/lineleader/update-sewed:
//   line_runs, shift_slots, run_operators, operator_operations,
//   operation_sewed_entries (unique (operation_id, slot_id)).
// ============================================================================

// Roles autorizados a verificar/corregir. Debe incluir "verificador".
const requireVerificador = (req, res, next) => {
  const allowed = [
    "verificador", "planner", "engineer", "supervisor",
    "soporte_it", "skyrina", "master", "inspector",
    "quality_head", "admin",
  ];
  if (!allowed.includes(req.user?.role)) {
    return res.status(403).json({
      success: false,
      error: "Access denied. Verificador role required.",
    });
  }
  next();
};

/**
 * GET /api/verificador/dates
 * Fechas distintas con corridas (para el selector de fecha).
 */
app.get("/api/verificador/dates", authenticateToken, requireVerificador, async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
    const result = await client.query(
      `SELECT DISTINCT to_char(run_date, 'YYYY-MM-DD') AS run_date
         FROM line_runs
        WHERE run_date IS NOT NULL
        ORDER BY run_date DESC`
    );
    res.json({ success: true, dates: result.rows.map((r) => r.run_date) });
  } catch (err) {
    console.error("❌ /api/verificador/dates error:", err.message);
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});

/**
 * GET /api/verificador/lines?date=YYYY-MM-DD
 * Líneas (con run id + estilo) que tienen corridas en la fecha dada.
 */
app.get("/api/verificador/lines", authenticateToken, requireVerificador, async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
    const { date } = req.query;
    if (!date) {
      return res.status(400).json({ success: false, error: "date parameter required" });
    }
    const result = await client.query(
      `SELECT id AS run_id, line_no, style
         FROM line_runs
        WHERE to_char(run_date, 'YYYY-MM-DD') = $1
        ORDER BY line_no, style`,
      [date]
    );
    res.json({ success: true, lines: result.rows });
  } catch (err) {
    console.error("❌ /api/verificador/lines error:", err.message);
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});

/**
 * GET /api/verificador/run/:runId/sewed
 * Devuelve slots (horas), operaciones y la cantidad cosida actual por slot,
 * para que el verificador elija operación y edite lo producido.
 */
app.get("/api/verificador/run/:runId/sewed", authenticateToken, requireVerificador, async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
    const { runId } = req.params;

    const runResult = await client.query(
      `SELECT id, line_no, to_char(run_date, 'YYYY-MM-DD') AS run_date, style
         FROM line_runs WHERE id = $1`,
      [runId]
    );
    if (runResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Run not found" });
    }

    const slotsResult = await client.query(
      `SELECT id AS slot_id, slot_order, slot_label
         FROM shift_slots
        WHERE run_id = $1
        ORDER BY slot_order`,
      [runId]
    );

    const rowsResult = await client.query(
      `SELECT ro.operator_no,
              ro.operator_name,
              oo.id AS operation_id,
              oo.operation_name,
              ss.id AS slot_id,
              ss.slot_label,
              ss.slot_order,
              COALESCE(se.sewed_qty, 0) AS sewed_qty
         FROM run_operators ro
         JOIN operator_operations oo ON oo.run_operator_id = ro.id
         CROSS JOIN shift_slots ss
         LEFT JOIN operation_sewed_entries se
                ON se.operation_id = oo.id AND se.slot_id = ss.id
        WHERE ro.run_id = $1 AND oo.run_id = $1 AND ss.run_id = $1
        ORDER BY ro.operator_no, oo.operation_name, ss.slot_order`,
      [runId]
    );

    res.json({
      success: true,
      run: runResult.rows[0],
      slots: slotsResult.rows,
      rows: rowsResult.rows,
    });
  } catch (err) {
    console.error("❌ /api/verificador/run/sewed error:", err.message);
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});

/**
 * POST /api/verificador/update-sewed/:runId
 * body: { entries: [{ operatorNo, operationName, slotLabel, sewedQty }] }
 * Sobrescribe las cantidades cosidas capturadas por el líder de línea.
 */
app.post("/api/verificador/update-sewed/:runId", authenticateToken, requireVerificador, async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
    await client.query("BEGIN");

    const { runId } = req.params;
    const { entries } = req.body;

    if (!entries || !Array.isArray(entries)) {
      await client.query("ROLLBACK");
      return res.status(400).json({ success: false, error: "Missing entries array" });
    }

    let updatedCount = 0;

    for (const entry of entries) {
      const { operatorNo, operationName, slotLabel, sewedQty } = entry;
      if (!operatorNo || !operationName || !slotLabel) continue;

      const opResult = await client.query(
        `SELECT o.id AS op_id
           FROM operator_operations o
           JOIN run_operators ro ON o.run_operator_id = ro.id
          WHERE o.run_id = $1 AND ro.operator_no = $2 AND o.operation_name = $3
          LIMIT 1`,
        [runId, parseInt(operatorNo), operationName]
      );
      if (opResult.rows.length === 0) continue;
      const operationId = opResult.rows[0].op_id;

      const slotResult = await client.query(
        `SELECT id FROM shift_slots WHERE run_id = $1 AND slot_label = $2 LIMIT 1`,
        [runId, slotLabel]
      );
      if (slotResult.rows.length === 0) continue;
      const slotId = slotResult.rows[0].id;

      await client.query(
        `INSERT INTO operation_sewed_entries (run_id, operation_id, slot_id, sewed_qty, created_at, updated_at)
         VALUES ($1, $2, $3, $4, now(), now())
         ON CONFLICT (operation_id, slot_id)
         DO UPDATE SET sewed_qty = EXCLUDED.sewed_qty, updated_at = now()`,
        [runId, operationId, slotId, Number(sewedQty || 0)]
      );
      updatedCount++;
    }

    await client.query("COMMIT");

    // Recalcula el estado de la ORDEN según lo producido (mismo criterio que el
    // líder de línea). Va fuera de la transacción ya commiteada, para que lea las
    // piezas recién guardadas. Si falla, el guardado ya se realizó.
    let statusChange = null;
    try {
      const runInfo = await client.query(
        `SELECT work_order_id FROM line_runs WHERE id = $1`,
        [runId]
      );
      const woId = runInfo.rows[0]?.work_order_id;
      if (woId) {
        statusChange = await registerWorkOrders.refreshWorkOrderStatusFromProduction(client, woId);
      }
    } catch (e) {
      console.warn("⚠️  recálculo de estado de la orden falló (el guardado sí se realizó):", e.message);
    }

    res.json({ success: true, updatedCount, statusChange });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("❌ /api/verificador/update-sewed error:", err.message);
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});


// ✅ Confirm & save a batch of printed tickets.
// Called from the line-leader ticket builder when the leader presses
// "Confirmar y guardar" on the generated tickets. Persists what was printed so
// the merchant size breakdown returned by /api/get-run-data is reduced by the
// printed amount on subsequent loads (see the ticket_prints subtraction below).
//
// Body: { tickets: [{ talla, color?, customerPo?, qty, count? }, ...] }
//   - qty:   pieces on that ticket/line
//   - count: how many physical tickets it represents (optional, for the log)
// Multiple entries for the same talla+color+PO are aggregated into one row.
app.post("/api/lineleader/confirm-tickets/:runId", authenticateToken, async (req, res, next) => {
  const client = await pool.connect();
  try {
    await setSchema(client);

    const { runId } = req.params;
    const { tickets } = req.body;

    if (!Array.isArray(tickets) || tickets.length === 0) {
      return res.status(400).json({ success: false, error: "Missing tickets array" });
    }

    // Resolve the run so we can scope the print log to the work order + estilo.
    const runResult = await client.query(
      `SELECT id, work_order_id, style FROM line_runs WHERE id = $1`,
      [runId]
    );
    if (runResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Run not found" });
    }
    const { work_order_id: workOrderId, style: estilo } = runResult.rows[0];

    // Aggregate incoming tickets by talla+color+PO.
    const norm = (v) => String(v == null ? "" : v).trim();
    const agg = new Map(); // key -> { talla, color, customerPo, quantity, count }
    for (const t of tickets) {
      const talla = norm(t.talla);
      if (!talla) continue;
      const color = norm(t.color);
      const customerPo = norm(t.customerPo ?? t.customer_po);
      const qty = Math.max(0, Math.floor(Number(t.qty) || 0));
      if (qty <= 0) continue;
      const count = Math.max(0, Math.floor(Number(t.count) || 1));
      const key = `${talla}||${color}||${customerPo}`;
      const cur = agg.get(key) || { talla, color, customerPo, quantity: 0, count: 0 };
      cur.quantity += qty;
      cur.count += count;
      agg.set(key, cur);
    }

    const rows = [...agg.values()];
    if (rows.length === 0) {
      return res.status(400).json({ success: false, error: "No valid ticket quantities to save" });
    }

    // Defensive guard: never let confirmed prints exceed the merchant quantity
    // assigned to a size. We compare (already printed + this batch) against the
    // work-order size breakdown, using the same COALESCE grouping as
    // get-run-data so the keys line up.
    if (workOrderId) {
      const overflow = [];
      for (const r of rows) {
        let assignedRes = await client.query(
          `SELECT COALESCE(SUM(quantity), 0)::numeric AS qty
             FROM work_order_lines
            WHERE work_order_id = $1 AND estilo = $2
              AND talla = $3 AND COALESCE(color,'') = $4 AND COALESCE(customer_po,'') = $5`,
          [workOrderId, estilo, r.talla, r.color, r.customerPo]
        );
        let assigned = Number(assignedRes.rows[0]?.qty || 0);
        if (assigned === 0) {
          assignedRes = await client.query(
            `SELECT COALESCE(SUM(quantity), 0)::numeric AS qty
               FROM work_order_lines
              WHERE work_order_id = $1
                AND talla = $2 AND COALESCE(color,'') = $3 AND COALESCE(customer_po,'') = $4`,
            [workOrderId, r.talla, r.color, r.customerPo]
          );
          assigned = Number(assignedRes.rows[0]?.qty || 0);
        }

        const printedRes = await client.query(
          `SELECT COALESCE(SUM(quantity), 0)::numeric AS qty
             FROM ticket_prints
            WHERE work_order_id = $1 AND (estilo = $2 OR estilo IS NULL)
              AND talla = $3 AND color = $4 AND customer_po = $5`,
          [workOrderId, estilo, r.talla, r.color, r.customerPo]
        );
        const alreadyPrinted = Number(printedRes.rows[0]?.qty || 0);

        // Only enforce when we actually have a merchant assignment to compare
        // against; sizes without a breakdown (assigned = 0) are left unguarded.
        if (assigned > 0 && alreadyPrinted + r.quantity > assigned) {
          overflow.push({
            talla: r.talla,
            color: r.color,
            customerPo: r.customerPo,
            assigned,
            alreadyPrinted,
            requested: r.quantity,
            remaining: Math.max(0, assigned - alreadyPrinted),
          });
        }
      }
      if (overflow.length > 0) {
        return res.status(409).json({
          success: false,
          error: "La cantidad a imprimir excede lo asignado para una o más tallas.",
          overflow,
        });
      }
    }

    // Persist one log row per aggregated size.
    await client.query("BEGIN");
    let savedQty = 0;
    let savedTickets = 0;
    for (const r of rows) {
      await client.query(
        `INSERT INTO ticket_prints
           (run_id, work_order_id, estilo, talla, color, customer_po, quantity, ticket_count, printed_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
        [runId, workOrderId, estilo, r.talla, r.color, r.customerPo, r.quantity, r.count, req.user?.id || null]
      );
      savedQty += r.quantity;
      savedTickets += r.count;
    }
    await client.query("COMMIT");

    // Return the new remaining per size so the client can update immediately.
    const remaining = [];
    if (workOrderId) {
      for (const r of rows) {
        let assignedRes = await client.query(
          `SELECT COALESCE(SUM(quantity), 0)::numeric AS qty
             FROM work_order_lines
            WHERE work_order_id = $1 AND estilo = $2
              AND talla = $3 AND COALESCE(color,'') = $4 AND COALESCE(customer_po,'') = $5`,
          [workOrderId, estilo, r.talla, r.color, r.customerPo]
        );
        let assigned = Number(assignedRes.rows[0]?.qty || 0);
        if (assigned === 0) {
          assignedRes = await client.query(
            `SELECT COALESCE(SUM(quantity), 0)::numeric AS qty
               FROM work_order_lines
              WHERE work_order_id = $1
                AND talla = $2 AND COALESCE(color,'') = $3 AND COALESCE(customer_po,'') = $4`,
            [workOrderId, r.talla, r.color, r.customerPo]
          );
          assigned = Number(assignedRes.rows[0]?.qty || 0);
        }
        const printedRes = await client.query(
          `SELECT COALESCE(SUM(quantity), 0)::numeric AS qty
             FROM ticket_prints
            WHERE work_order_id = $1 AND (estilo = $2 OR estilo IS NULL)
              AND talla = $3 AND color = $4 AND customer_po = $5`,
          [workOrderId, estilo, r.talla, r.color, r.customerPo]
        );
        const printed = Number(printedRes.rows[0]?.qty || 0);
        remaining.push({
          talla: r.talla,
          color: r.color,
          customerPo: r.customerPo,
          printed,
          remaining: Math.max(0, assigned - printed),
        });
      }
    }

    return res.json({
      success: true,
      savedQty,
      savedTickets,
      savedRows: rows.length,
      remaining,
    });
  } catch (err) {
    try { await client.query("ROLLBACK"); } catch (_) {}
    console.error("❌ confirm-tickets error:", err.message);
    next(err);
  } finally {
    client.release();
  }
});

// ----------------------------------------------------------------------
// 13. DATA RETRIEVAL ENDPOINTS
// ----------------------------------------------------------------------
app.get("/api/get-run-data/:runId", authenticateToken, async (req, res, next) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
    const { runId } = req.params;

     const runResult = await client.query(
  `SELECT lr.*, wo.work_order_no
   FROM line_runs lr
   LEFT JOIN work_orders wo ON wo.id = lr.work_order_id
   WHERE lr.id = $1`,
  [runId]
);
    if (runResult.rows.length === 0) return res.status(404).json({ success: false, error: "Run not found" });

    const slotsResult = await client.query(
      "SELECT id, slot_order, slot_label, slot_start, slot_end, planned_hours FROM shift_slots WHERE run_id = $1 ORDER BY slot_order",
      [runId]
    );
    const operatorsResult = await client.query(
      "SELECT id, operator_no, operator_name FROM run_operators WHERE run_id = $1 ORDER BY operator_no",
      [runId]
    );
    const slotTargetsResult = await client.query(
      `SELECT s.slot_label, t.slot_target, t.cumulative_target
       FROM slot_targets t
       JOIN shift_slots s ON t.slot_id = s.id
       WHERE t.run_id = $1
       ORDER BY s.slot_order`,
      [runId]
    );

    // ---- Merchant size breakdown (talla + color + PO + cantidad) ----------
    // One row per talla+color+PO so each printed ticket can carry its own color
    // and PO cliente. Prefer lines matching this run's estilo; fall back to all
    // lines on the work order. Wrapped in try/catch so an older DB without
    // work_order_lines never breaks the run screen (sizes just come back []).
    let sizes = [];
    try {
      const woId = runResult.rows[0].work_order_id;
      if (woId) {
        const styleName = runResult.rows[0].style;
        let sizesResult = await client.query(
          `SELECT talla,
                  COALESCE(color, '')       AS color,
                  COALESCE(customer_po, '') AS customer_po,
                  SUM(quantity)::numeric    AS quantity
             FROM work_order_lines
            WHERE work_order_id = $1 AND estilo = $2
            GROUP BY talla, color, customer_po
            ORDER BY talla, color`,
          [woId, styleName]
        );
        if (sizesResult.rows.length === 0) {
          sizesResult = await client.query(
            `SELECT talla,
                    COALESCE(color, '')       AS color,
                    COALESCE(customer_po, '') AS customer_po,
                    SUM(quantity)::numeric    AS quantity
               FROM work_order_lines
              WHERE work_order_id = $1
              GROUP BY talla, color, customer_po
              ORDER BY talla, color`,
            [woId]
          );
        }
        sizes = sizesResult.rows.map((r) => ({
          talla: r.talla,
          color: r.color || "",
          customerPo: r.customer_po || "",
          quantity: Number(r.quantity) || 0,
        }));
      }
    } catch (e) {
      console.warn("get-run-data: size breakdown unavailable:", e.message);
      sizes = [];
    }

    // ---- Subtract already-printed tickets from the size breakdown ----------
    // The line-leader ticket builder seeds each size's editable quantity from
    // `quantity` above, so returning the *remaining* (assigned − printed) makes
    // the "Asignado" figure shrink as tickets get confirmed. Scoped to the work
    // order + estilo so a new run/day for the same WO still reflects prior
    // prints. Wrapped in try/catch so a missing ticket_prints table never breaks
    // the run screen. `assignedQuantity`/`printedQuantity` are added for the UI.
    try {
      if (sizes.length) {
        const woId = runResult.rows[0].work_order_id;
        const styleName = runResult.rows[0].style;
        if (woId) {
          const printedResult = await client.query(
            `SELECT talla,
                    COALESCE(color, '')       AS color,
                    COALESCE(customer_po, '') AS customer_po,
                    SUM(quantity)::numeric    AS printed
               FROM ticket_prints
              WHERE work_order_id = $1 AND (estilo = $2 OR estilo IS NULL)
              GROUP BY talla, color, customer_po`,
            [woId, styleName]
          );
          const printedMap = new Map();
          for (const p of printedResult.rows) {
            const key = `${p.talla}||${p.color || ""}||${p.customer_po || ""}`;
            printedMap.set(key, Number(p.printed) || 0);
          }
          sizes = sizes.map((s) => {
            const key = `${s.talla}||${s.color || ""}||${s.customerPo || ""}`;
            const printed = printedMap.get(key) || 0;
            const assigned = Number(s.quantity) || 0;
            return {
              ...s,
              assignedQuantity: assigned,                 // original merchant qty
              printedQuantity: printed,                   // total already printed
              quantity: Math.max(0, assigned - printed),  // remaining -> builder
            };
          });
        }
      }
    } catch (e) {
      console.warn("get-run-data: printed-ticket subtraction skipped:", e.message);
    }

    const operationsData = [];
    for (const operator of operatorsResult.rows) {
      const opsResult = await client.query(
        `SELECT o.id, o.operation_name, o.t1_sec, o.t2_sec, o.t3_sec, o.t4_sec, o.t5_sec, o.capacity_per_hour,
                json_object_agg(COALESCE(s.slot_label, ''), COALESCE(h.stitched_qty, 0)) as stitched_data,
                json_object_agg(COALESCE(s2.slot_label, ''), COALESCE(se.sewed_qty, 0)) as sewed_data
         FROM operator_operations o
         LEFT JOIN operation_hourly_entries h ON o.id = h.operation_id
         LEFT JOIN shift_slots s ON h.slot_id = s.id
         LEFT JOIN operation_sewed_entries se ON o.id = se.operation_id
         LEFT JOIN shift_slots s2 ON se.slot_id = s2.id
         WHERE o.run_operator_id = $1 AND o.run_id = $2
         GROUP BY o.id
         ORDER BY o.id`,
        [operator.id, runId]
      );
      operationsData.push({ operator, operations: opsResult.rows });
    }

    res.json({
      success: true,
      run: runResult.rows[0],
      slots: slotsResult.rows,
      operators: operatorsResult.rows,
      operations: operationsData,
      slotTargets: slotTargetsResult.rows,
      sizes,
    });
  } catch (err) {
    next(err);
  } finally {
    client.release();
  }
});

app.get("/api/line-runs", authenticateToken, async (req, res, next) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
    const result = await client.query(
      `SELECT id, line_no, run_date, style,color, operators_count, working_hours, sam_minutes,
              efficiency, target_pcs, target_per_hour, is_draft, created_at
       FROM line_runs
       ORDER BY run_date DESC, line_no`
    );
    res.json({ success: true, runs: result.rows });
  } catch (err) {
    next(err);
  } finally {
    client.release();
  }
});


/* ===========================================================================
   INTEGRATION EDITS  (apply these where noted)
   ---------------------------------------------------------------------------

   (B) WIRING — server1.js line ~890. Add recomputeStyleSafely to deps:

         registerWorkOrders(app, {
           authenticateToken, pool, setSchema,
           generatePresignedGetUrl, uploadBufferToS3, makeStylePhotoKey, deleteFromS3,
           recomputeStyleSafely,          // <-- add
         });

   ---------------------------------------------------------------------------
   (C) HOOK — work-orders.js, in the update handler, AFTER the COMMIT at
       line ~1615 (the same handler that sets sam_minutes at line 1404).
       `deps` is the 2nd param of registerWorkOrders(app, deps). Fire-and-forget:

         if (samMinutes !== undefined && deps.recomputeStyleSafely) {
           const woStyle = (wo.style_code || wo.estilo || "").trim();
           if (woStyle) deps.recomputeStyleSafely({ style: woStyle }).catch(() => {});
         }

   ---------------------------------------------------------------------------
   (D) STORE PROVENANCE AT CREATION — server1.js assignment INSERT ~line 6341.
       You already have `source`/`basedOnStyle` from resolveTemplateRun; add the
       two columns so recompute knows this run is an estimate:

         INSERT INTO line_runs
           (line_no, run_date, style, operators_count, working_hours, sam_minutes,
            efficiency, target_pcs, target_per_hour, work_order_id,
            param_source, based_on_style, is_draft, created_at, updated_at)
         VALUES ($1,$2::date,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,true,NOW(),NOW())
         ON CONFLICT ON CONSTRAINT uq_line_run DO NOTHING
         RETURNING id
         -- append to the params array: , source, basedOnStyle

   ---------------------------------------------------------------------------
   (E) REFRESH A RE-TOUCHED CELL — server1.js assignment path, the
       `existing.rowCount > 0` branch ~line 6297, after linkAssignments(runId):

         await recomputeRun(client, runId);

   ---------------------------------------------------------------------------
   (F) STAMP 'manual' ON PLANNER SAVE — server1.js operators modal. So a
       confirmed roster is never reseeded:
         • UPDATE ~line 2000:  add  param_source = 'manual'  to the SET list
         • INSERT ~line 2029:  add the param_source column with value 'manual'

   ---------------------------------------------------------------------------
   (G) OPTIONAL manual "recompute" endpoint — server1.js, near your other
       /api/line-runs routes (~line 2062):

         app.post("/api/line-runs/:runId/recompute", authenticateToken, async (req, res) => {
           const client = await pool.connect();
           try {
             await setSchema(client);
             await client.query("BEGIN");
             const r = await recomputeRun(client, parseInt(req.params.runId, 10));
             await client.query("COMMIT");
             res.json({ success: true, ...r });
           } catch (e) {
             await client.query("ROLLBACK").catch(() => {});
             res.status(500).json({ success: false, error: e.message });
           } finally {
             client.release();
           }
         });
   =========================================================================== */
   
// Resolve the real style SAM (minutes/piece) for a line_run about to be CREATED,
// taken from the OWNING order rather than a template/most-recent run.
async function resolveOrderSam(client, { workOrderId = null, lineNo = null, runDate = null, style = null }) {
  try {
    if (workOrderId != null) {
      const r = await client.query("SELECT sam_minutes FROM work_orders WHERE id = $1", [workOrderId]);
      const s = parseFloat(r.rows[0]?.sam_minutes) || 0;
      if (s > 0) return s;
    }
    if (lineNo != null && runDate != null && style != null && String(style).trim() !== "") {
      const r = await client.query(
        `SELECT wo.sam_minutes
           FROM line_assignments la
           JOIN work_orders wo ON wo.id = la.work_order_id
          WHERE la.line_no = $1
            AND la.assigned_date = $2::date
            AND la.status NOT IN ('cancelled', 'rejected')
            AND UPPER(TRIM(COALESCE(wo.style_code, wo.estilo, ''))) = UPPER(TRIM($3))
          ORDER BY la.created_at DESC
          LIMIT 1`,
        [String(lineNo), runDate, String(style)]
      );
      const s = parseFloat(r.rows[0]?.sam_minutes) || 0;
      if (s > 0) return s;
    }
  } catch (e) {
    console.warn("⚠️  resolveOrderSam failed:", e.message);
  }
  return 0;
}


// PATCH /api/line-runs/operators  —  add to server.js (near the other
// /api/line-runs routes). Changing the number of sewers (operators) on a line
// recomputes its daily capacity:
//
//   available minutes/day = operators × working_hours × 60 × efficiency
//   target_pcs (per day)  = available minutes/day ÷ SAM
//   target_per_hour       = target_pcs ÷ working_hours
//
// By default it applies to ALL runs of the line (each recomputed with its own
// working_hours / efficiency / SAM). Pass an optional `style` to scope it to a
// single style (e.g. "DP-441") on that line, `from` (YYYY-MM-DD, inclusive) to
// only touch runs on/after that date so historical months stay intact, and/or
// `date` to scope it to a single run_date.
//
// If a `style` + effective date (`date` or `from`) is given but no run exists on
// that day for that style, a run is CREATED for that day — cloning the line's
// most recent run parameters (hours/efficiency/SAM) — so per-style operator
// changes take effect even on planned days that had no run yet. Earlier runs are
// never modified.
// ---------------------------------------------------------------------------
app.patch("/api/line-runs/operators", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
    const { lineNo, operators, date, style, from } = req.body;
    const ops = parseInt(operators);

    if (lineNo === undefined || lineNo === null || String(lineNo).trim() === "" || isNaN(ops) || ops < 0) {
      return res.status(400).json({ success: false, error: "lineNo y operators (>= 0) son obligatorios" });
    }

    const styleStr = (style !== undefined && style !== null && String(style).trim() !== "") ? String(style).trim() : null;
    const anchor = date || from || null; // the day the change should take effect

    // Recompute a run's daily capacity for the new operator count.
    const calc = (wh, eff, sam) => {
      const availableMin = ops * wh * 60 * eff;
      const targetPcs = sam > 0 ? availableMin / sam : 0;
      const targetPerHour = wh > 0 ? targetPcs / wh : 0;
      return { targetPcs, targetPerHour };
    };

    // 1) Existing runs in scope (line [+ style] [+ from/date]).
    const params = [String(lineNo)];
    let where = "WHERE line_no = $1";
    if (styleStr) { params.push(styleStr); where += ` AND style = $${params.length}`; }
    // `from` (inclusive) keeps historical months intact: only runs on/after this
    // date are recomputed, so past capacity/efficiency figures never change.
    if (from) { params.push(from); where += ` AND run_date >= $${params.length}`; }
    if (date) { params.push(date); where += ` AND run_date = $${params.length}`; }

    const runs = await client.query(
      `SELECT id, to_char(run_date, 'YYYY-MM-DD') AS run_date, working_hours, efficiency, sam_minutes
         FROM line_runs ${where}`,
      params
    );

    await client.query("BEGIN");

    let updated = 0;
    for (const r of runs.rows) {
      const wh = parseFloat(r.working_hours) || 0;
      const eff = parseFloat(r.efficiency) || 0;
      const orderSam = await resolveOrderSam(client, { lineNo: String(lineNo), runDate: anchor, style: styleStr });
      const sam = orderSam || parseFloat(tmpl.rows[0].sam_minutes) || 0;
      const { targetPcs, targetPerHour } = calc(wh, eff, sam);
      await client.query(
        `UPDATE line_runs
            SET operators_count = $1, target_pcs = $2, target_per_hour = $3, updated_at = now()
          WHERE id = $4`,
        [ops, targetPcs, targetPerHour, r.id]
      );
      updated++;
    }

    // 2) If a style + effective date were given but no run exists on that exact
    //    day for that style, create one so the change actually takes effect.
    //    We clone the line's most recent run parameters (hours / efficiency /
    //    SAM) — history is never touched, we only ADD a new dated run.
    let created = 0;
    const hasAnchorRun = anchor ? runs.rows.some((r) => r.run_date === anchor) : true;

    if (styleStr && anchor && !hasAnchorRun) {
      const tmpl = await client.query(
        `SELECT working_hours, efficiency, sam_minutes
           FROM line_runs
          WHERE line_no = $1
          ORDER BY (style = $2) DESC, (run_date <= $3) DESC, run_date DESC
          LIMIT 1`,
        [String(lineNo), styleStr, anchor]
      );
      if (tmpl.rows.length > 0) {
        const wh = parseFloat(tmpl.rows[0].working_hours) || 0;
        const eff = parseFloat(tmpl.rows[0].efficiency) || 0;
        const sam = parseFloat(tmpl.rows[0].sam_minutes) || 0;
        const { targetPcs, targetPerHour } = calc(wh, eff, sam);
        await client.query(
          `INSERT INTO line_runs
             (line_no, run_date, style, operators_count, working_hours, sam_minutes, efficiency, target_pcs, target_per_hour, created_at, updated_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, now(), now())
           ON CONFLICT (line_no, run_date, style)
           DO UPDATE SET operators_count = EXCLUDED.operators_count,
                         target_pcs      = EXCLUDED.target_pcs,
                         target_per_hour = EXCLUDED.target_per_hour,
                         updated_at      = now()`,
          [String(lineNo), anchor, styleStr, ops, wh, sam, eff, targetPcs, targetPerHour]
        );
        created++;
      }
    }

    if (updated === 0 && created === 0) {
      await client.query("ROLLBACK");
      return res.status(404).json({
        success: false,
        error: "No hay corridas ni configuración base para esa línea; no se pudo aplicar el cambio.",
      });
    }

    await client.query("COMMIT");
    res.json({ success: true, updated, created, operators: ops, style: styleStr, from: from ?? null, date: date ?? null });
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    console.error("❌ Error updating line operators:", err.message);
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});

app.get("/api/line-runs/:lineNo", authenticateToken, async (req, res, next) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
    const { lineNo } = req.params;
    const result = await client.query(
      `SELECT id, line_no, run_date, style, operators_count, working_hours, sam_minutes,
              efficiency, target_pcs, target_per_hour, created_at
       FROM line_runs
       WHERE line_no = $1
       ORDER BY run_date DESC`,
      [lineNo]
    );
    res.json({ success: true, runs: result.rows });
  } catch (err) {
    next(err);
  } finally {
    client.release();
  }
});

// ---------------------------------------------------------------------------
// mergeOrInsertAssignment — keep one planned row per (work_order, line, day,
// color). If a matching planned/released row already exists for that cell, add
// the pieces to it instead of creating a second sliver; otherwise insert a new
// row. Completed/cancelled rows are never merged into (their produced history
// must stay intact), so those always insert a fresh row.
//
//   a = { workOrderId, lineRunId, lineNo, assignedDate, quantity,
//         availableMinutes, requiredRate, startDate, endDate, status, color }
// Must be called inside an open transaction on `client`.
// ---------------------------------------------------------------------------
async function mergeOrInsertAssignment(client, a) {
  const mergeable = a.status === "planned" || a.status === "released";

  const findExisting = () => client.query(
    `SELECT id FROM line_assignments
      WHERE work_order_id = $1
        AND line_no = $2
        AND assigned_date = $3
        AND COALESCE(color, '') = COALESCE($4, '')
        AND status = $5
      ORDER BY id ASC
      LIMIT 1
      FOR UPDATE`,
    [a.workOrderId, String(a.lineNo), a.assignedDate, a.color ?? null, a.status]
  );

  const applyMerge = async (id) => (await client.query(
    `UPDATE line_assignments
        SET assigned_quantity        = assigned_quantity + $2,
            available_minutes        = $3,
            required_production_rate  = $4,
            planned_start_date        = LEAST(COALESCE(planned_start_date, $5::date), $5::date),
            planned_end_date          = GREATEST(COALESCE(planned_end_date, $6::date), $6::date),
            line_run_id               = COALESCE($7, line_run_id),
            updated_at                = now()
      WHERE id = $1
    RETURNING *`,
    [id, a.quantity, a.availableMinutes, a.requiredRate, a.startDate, a.endDate, a.lineRunId ?? null]
  )).rows[0];

  if (mergeable) {
    const found = await findExisting();
    if (found.rows.length) return applyMerge(found.rows[0].id);
  }

  // No mergeable row yet → insert. A rare concurrent insert can trip the
  // partial unique index; if so, roll back just this statement and merge into
  // whatever landed first.
  await client.query("SAVEPOINT ins_assign");
  try {
    const ins = await client.query(
      `INSERT INTO line_assignments
         (work_order_id, line_run_id, line_no, assigned_date, assigned_quantity,
          available_minutes, required_production_rate, planned_start_date, planned_end_date, status, color)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
       RETURNING *`,
      [a.workOrderId, a.lineRunId ?? null, String(a.lineNo), a.assignedDate, a.quantity,
       a.availableMinutes, a.requiredRate, a.startDate, a.endDate, a.status, a.color ?? null]
    );
    await client.query("RELEASE SAVEPOINT ins_assign");
    return ins.rows[0];
  } catch (e) {
    if (e.code === "23505" && mergeable) {
      await client.query("ROLLBACK TO SAVEPOINT ins_assign");
      const found = await findExisting();
      if (found.rows.length) return applyMerge(found.rows[0].id);
    }
    throw e;
  }
}

// ---------------------------------------------------------------------------
// PATCH /api/line-assignments/:id/move  —  add to server.js near the other
// line-assignments routes.
//
// Moves an existing assignment to another line and/or day. Revalidates the
// target's daily capacity (target_pcs of the line's run for that date, minus
// what's already assigned there — excluding this assignment itself).
// ---------------------------------------------------------------------------
app.patch("/api/line-assignments/:id/move", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  // Add whole days to a YYYY-MM-DD string without any timezone drift.
  const addDaysStr = (ymdStr, n) => {
    const [y, m, d] = ymdStr.split("-").map(Number);
    const dt = new Date(Date.UTC(y, m - 1, d));
    dt.setUTCDate(dt.getUTCDate() + n);
    return dt.toISOString().slice(0, 10);
  };
  // True for Saturday/Sunday (no timezone drift). No production on weekends.
  const isWeekend = (ymdStr) => {
    const [y, m, d] = ymdStr.split("-").map(Number);
    const dow = new Date(Date.UTC(y, m - 1, d)).getUTCDay(); // 0 = Sun, 6 = Sat
    return dow === 0 || dow === 6;
  };
  try {
    await setSchema(client);
    const id = parseInt(req.params.id);
    const { lineNo, assignedDate } = req.body;

    if (!lineNo || !assignedDate) {
      return res.status(400).json({ success: false, error: "lineNo y assignedDate son obligatorios" });
    }

    await client.query("BEGIN");

    const cur = await client.query(
      "SELECT id, work_order_id, assigned_quantity, color, status, line_no, to_char(assigned_date, 'YYYY-MM-DD') AS assigned_date_str FROM line_assignments WHERE id = $1",
      [id]
    );
    if (cur.rows.length === 0) {
      await client.query("ROLLBACK");
      return res.status(404).json({ success: false, error: "Assignment not found" });
    }
    const original = cur.rows[0];
    // Remember where this block sat so we can drop its (now stale) draft run if
    // the day ends up empty after the move.
    const sourceLineNo = String(original.line_no);
    const sourceDate = original.assigned_date_str;

    const totalQty = parseFloat(original.assigned_quantity) || 0;
    const workOrderId = original.work_order_id;
    const color = original.color || null;
    const status = ["planned", "released", "completed", "cancelled"].includes(original.status)
      ? original.status
      : "planned";

    // Prefer the work order's own SAM for the informational rate columns.
    const woRes = await client.query(
      "SELECT sam_minutes FROM work_orders WHERE id = $1",
      [workOrderId]
    );
    const woSam = parseFloat(woRes.rows[0]?.sam_minutes) || 0;

    // Free the original's capacity first so the re-flow can reuse its old slot.
    // Everything happens in one transaction, so a shortfall rolls this back and
    // leaves the assignment exactly where it was.
    await client.query("DELETE FROM line_assignments WHERE id = $1", [id]);

    // Walk the target line day by day from assignedDate, filling each day's
    // remaining capacity and carrying the remainder forward — the same packing
    // rule as a pool placement. Weekends, days with no run configured, or days
    // already full are skipped. All-or-nothing: if the whole quantity can't fit
    // within the horizon, roll back and report the shortfall.
        const MAX_DAYS = 180;
    let remaining = totalQty;
    let dayStr = assignedDate;
    let scanned = 0;
    const createdRows = [];

    // Registered holidays (días festivos / paros) block a day just like weekends,
    // so the forward walk hops over them instead of stacking onto a blocked cell.
    // Plant-wide rows (line_no NULL) block every line. Best-effort: if the module
    // isn't there we fall back to skipping weekends only.
    const holidaySet = new Set();
    try {
      const hrows = await registerHolidays.holidaysBetween(client, { from: assignedDate, to: addDaysStr(assignedDate, 730) });
      for (const h of hrows) if (h.line_no == null || String(h.line_no) === String(lineNo)) holidaySet.add(h.holiday_date);
    } catch (e) { console.warn("⚠️  holidays not available for move:", e.message); }

    while (remaining > 0 && scanned < MAX_DAYS) {
      scanned++;
      if (isWeekend(dayStr) || holidaySet.has(dayStr)) { dayStr = addDaysStr(dayStr, 1); continue; }  // no weekend / holiday work
      const { lines } = await getLineCapacityForDate(client, dayStr);
      const lineData = lines.find((l) => String(l.line_no) === String(lineNo));
      if (!lineData) { dayStr = addDaysStr(dayStr, 1); continue; }  // no capacity configured -> skip

      const usedRes = await client.query(
        `SELECT COALESCE(SUM(assigned_quantity), 0) AS used
           FROM line_assignments
          WHERE line_no = $1 AND assigned_date = $2 AND status NOT IN ('cancelled', 'rejected')`,
        [String(lineNo), dayStr]
      );
      const used = parseFloat(usedRes.rows[0].used) || 0;
      const capacity = parseFloat(lineData.target_pcs) || 0;
      const available = Math.max(0, capacity - used);
      if (available <= 0) { dayStr = addDaysStr(dayStr, 1); continue; }  // full -> next day

      const chunk = Math.min(remaining, available);

      const operators = parseInt(lineData.operators_count) || 20;
      const workingHours = parseFloat(lineData.working_hours) || 8;
      const efficiency = parseFloat(lineData.efficiency) || 0.85;
      const samMinutes = woSam || parseFloat(lineData.sam_minutes) || 3.5;
      const effectiveDailyMinutes = operators * workingHours * 60 * efficiency;
      const piecesPerDay = samMinutes > 0 ? effectiveDailyMinutes / samMinutes : 0;

      const ins = await client.query(
        `INSERT INTO line_assignments
           (work_order_id, line_run_id, line_no, assigned_date, assigned_quantity,
            available_minutes, required_production_rate, planned_start_date, planned_end_date, status, color)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $4, $4, $9, $8)
         RETURNING *`,
        [workOrderId, lineData.id || null, String(lineNo), dayStr, chunk,
         effectiveDailyMinutes, piecesPerDay, color, status]
      );
      createdRows.push(ins.rows[0]);
      // NOTE: drafts are no longer auto-created on move. The planner pushes work
      // to the line leaders explicitly via POST /api/line-assignments/confirm.
      remaining -= chunk;
      dayStr = addDaysStr(dayStr, 1);
    }

    if (remaining > 0) {
      await client.query("ROLLBACK");
      return res.status(400).json({
        success: false,
        error: `La línea ${lineNo} no tiene capacidad suficiente para mover ${Math.round(totalQty)} pzas desde el ${assignedDate} (faltan ${Math.round(remaining)}).`,
      });
    }

    // The source day may now be empty. If it only had an unconfirmed draft run
    // (created before the planner confirmed), drop it so line leaders don't keep
    // seeing a draft for a day the order was moved away from.
    await cleanupOrphanDraftRuns(client, sourceLineNo, sourceDate);

    await client.query("COMMIT");
    res.json({
      success: true,
      assignment: createdRows[0] || null,
      assignments: createdRows,
      cells: createdRows.length,
    });
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    console.error("❌ Error moving line assignment:", err.message);
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});


// ---------------------------------------------------------------------------
// PATCH /api/line-assignments/:id/insert-shift
//
// "Insert" a moved assignment onto an OCCUPIED day and push the whole tail of
// that line forward by one workday. Concretely: drop order A onto line L / day D
// where D already has an order, and A takes D while every PLANNED assignment on
// line L with assigned_date >= D (except A itself) slides to its next workday.
// Gaps are preserved — each affected block simply shifts +1 workday (Fri -> Mon),
// so the relative sequence and spacing on the line are kept intact.
//
// Contrast with /move (which packs A into the day's remaining capacity and
// spills the REMAINDER forward, never displacing the existing occupant). Here
// the occupant is displaced.
//
// Safety:
//  - One transaction: any failure rolls the entire ripple back.
//  - The tail shift is applied row-by-row from the LATEST date backward so no
//    two planned rows ever momentarily share a (work_order,line,day,color) slot
//    and trip uq_line_assign_planned_cell (the classic shift-by-one collision).
//  - Only status='planned' rows shift; released/completed/cancelled history is
//    left untouched.
//  - Weekends are skipped (a Friday block lands on the following Monday).
// ---------------------------------------------------------------------------
app.patch("/api/line-assignments/:id/insert-shift", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  const addDaysStr = (ymdStr, k) => {
    const [y, m, d] = ymdStr.split("-").map(Number);
    const dt = new Date(Date.UTC(y, m - 1, d));
    dt.setUTCDate(dt.getUTCDate() + k);
    return dt.toISOString().slice(0, 10);
  };
  const isWeekend = (ymdStr) => {
    const [y, m, d] = ymdStr.split("-").map(Number);
    const dow = new Date(Date.UTC(y, m - 1, d)).getUTCDay();
    return dow === 0 || dow === 6;
  };
  // Next production day: +1, then hop over Sat/Sun.
  const nextWorkday = (ymdStr) => {
    let d = addDaysStr(ymdStr, 1);
    while (isWeekend(d)) d = addDaysStr(d, 1);
    return d;
  };
  try {
    await setSchema(client);
    const id = parseInt(req.params.id);
    const { lineNo, assignedDate } = req.body;
    if (!lineNo || !assignedDate) {
      return res.status(400).json({ success: false, error: "lineNo y assignedDate son obligatorios" });
    }
    if (isWeekend(assignedDate)) {
      return res.status(400).json({ success: false, error: "No se puede insertar en fin de semana. Elija un dia entre semana." });
    }

    await client.query("BEGIN");

    const cur = await client.query(
      "SELECT id, work_order_id, assigned_quantity, available_minutes, required_production_rate, color, status, line_no, to_char(assigned_date, 'YYYY-MM-DD') AS assigned_date_str FROM line_assignments WHERE id = $1",
      [id]
    );
    if (cur.rows.length === 0) {
      await client.query("ROLLBACK");
      return res.status(404).json({ success: false, error: "Assignment not found" });
    }
    const a = cur.rows[0];
    const sourceLineNo = String(a.line_no);
    const sourceDate = a.assigned_date_str;
    const targetLine = String(lineNo);
    const D = assignedDate;

    // 1) Remove the moved block up front (we re-insert it at the target below).
    //    Deleting first — rather than excluding it by id — means a same-order
    //    sibling slice on the previous workday can shift into this block's old
    //    day without tripping uq_line_assign_planned_cell. Same delete-then-
    //    reinsert shape the /move route uses.
    await client.query("DELETE FROM line_assignments WHERE id = $1", [id]);

    // 2) Push the whole tail of the target line forward one workday, latest
    //    first, so each block lands on a slot the next block already vacated.
    //    The occupant of D itself is part of the tail, so D ends up empty.
    const tail = await client.query(
      `SELECT id, to_char(assigned_date, 'YYYY-MM-DD') AS d
         FROM line_assignments
        WHERE line_no = $1
          AND assigned_date >= $2
          AND status = 'planned'
        ORDER BY assigned_date DESC, id DESC`,
      [targetLine, D]
    );
    for (const row of tail.rows) {
      const nd = nextWorkday(row.d);
      await client.query(
        `UPDATE line_assignments
            SET assigned_date = $1, planned_start_date = $1, planned_end_date = $1, updated_at = now()
          WHERE id = $2`,
        [nd, row.id]
      );
    }

    // 3) Re-insert the moved order on the now-vacated target cell. Recompute the
    //    informational rate columns from the target line's run for D when one
    //    exists; otherwise keep the block's own values (columns are NOT NULL).
    const woRes = await client.query("SELECT sam_minutes FROM work_orders WHERE id = $1", [a.work_order_id]);
    const woSam = parseFloat(woRes.rows[0]?.sam_minutes) || 0;
    const { lines } = await getLineCapacityForDate(client, D);
    const lineData = lines.find((l) => String(l.line_no) === targetLine);

    let availableMinutes = parseFloat(a.available_minutes) || 0;
    let requiredRate = parseFloat(a.required_production_rate) || 0;
    let lineRunId = null;
    if (lineData) {
      const operators = parseInt(lineData.operators_count) || 20;
      const workingHours = parseFloat(lineData.working_hours) || 8;
      const efficiency = parseFloat(lineData.efficiency) || 0.85;
      const samMinutes = woSam || parseFloat(lineData.sam_minutes) || 3.5;
      availableMinutes = operators * workingHours * 60 * efficiency;
      requiredRate = samMinutes > 0 ? availableMinutes / samMinutes : 0;
      lineRunId = lineData.id || null;
    }

    const status = ["planned", "released", "completed", "cancelled"].includes(a.status) ? a.status : "planned";
    const placed = await client.query(
      `INSERT INTO line_assignments
          (work_order_id, line_run_id, line_no, assigned_date, assigned_quantity,
           available_minutes, required_production_rate, planned_start_date, planned_end_date, status, color)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        RETURNING *`,
      [a.work_order_id, lineRunId, targetLine, D, a.assigned_quantity,
       availableMinutes, requiredRate, D, D, status, a.color || null]
    );

    // 4) The block's old cell may now be empty — drop any orphan draft run there.
    if (!(sourceLineNo === targetLine && sourceDate === D)) {
      await cleanupOrphanDraftRuns(client, sourceLineNo, sourceDate);
    }

    await client.query("COMMIT");
    res.json({
      success: true,
      assignment: placed.rows[0] || null,
      shifted: tail.rows.length,
    });
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    console.error("❌ Error inserting/shifting line assignment:", err.message);
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});

// ---------------------------------------------------------------------------
// POST /api/line-assignments/move-batch
//
// Pile several existing assignments into ONE target line, starting at
// `assignedDate`, and re-pack them forward day by day. All selected blocks may
// come from different lines, days, orders or colors; each keeps its own row.
// The packing rule is identical to the single move: fill each day's remaining
// capacity, spill the rest to the next day. Rows inserted earlier in this same
// transaction count as "used", so consecutive blocks stack naturally onto the
// following days. All-or-nothing: if the whole selection can't fit within the
// horizon, roll back and leave every block exactly where it was.
// ---------------------------------------------------------------------------
app.post("/api/line-assignments/move-batch", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  const addDaysStr = (ymdStr, n) => {
    const [y, m, d] = ymdStr.split("-").map(Number);
    const dt = new Date(Date.UTC(y, m - 1, d));
    dt.setUTCDate(dt.getUTCDate() + n);
    return dt.toISOString().slice(0, 10);
  };
  const isWeekend = (ymdStr) => {
    const [y, m, d] = ymdStr.split("-").map(Number);
    const dow = new Date(Date.UTC(y, m - 1, d)).getUTCDay(); // 0 = Sun, 6 = Sat
    return dow === 0 || dow === 6;
  };
  try {
    await setSchema(client);
    const { ids, lineNo, assignedDate } = req.body;
    const idList = Array.isArray(ids)
      ? [...new Set(ids.map((n) => parseInt(n)).filter((n) => Number.isInteger(n)))]
      : [];

    if (idList.length === 0 || !lineNo || !assignedDate) {
      return res.status(400).json({
        success: false,
        error: "ids (no vacío), lineNo y assignedDate son obligatorios",
      });
    }

    await client.query("BEGIN");

    // Load the selected assignments. Order them by their current position so the
    // re-pack is deterministic (earliest day first, then id).
    const cur = await client.query(
      `SELECT id, work_order_id, assigned_quantity, color, status,
              line_no, to_char(assigned_date, 'YYYY-MM-DD') AS assigned_date_str
         FROM line_assignments
        WHERE id = ANY($1::int[])
        ORDER BY assigned_date ASC, id ASC`,
      [idList]
    );
    if (cur.rows.length === 0) {
      await client.query("ROLLBACK");
      return res.status(404).json({ success: false, error: "No se encontraron las asignaciones" });
    }

    // Remember every (line, day) these blocks came from so we can drop their
    // stale draft runs afterwards if the source day ends up empty.
    const sourceCells = [
      ...new Map(
        cur.rows.map((r) => [`${r.line_no}|${r.assigned_date_str}`, { lineNo: String(r.line_no), date: r.assigned_date_str }])
      ).values(),
    ];

    // Free every selected block first so their old slots can be reused.
    await client.query("DELETE FROM line_assignments WHERE id = ANY($1::int[])", [idList]);

        const MAX_DAYS = 180;
    const createdRows = [];

    // Registered holidays (días festivos / paros) block a day like weekends, so
    // the re-pack hops over them instead of stacking onto a blocked cell. Loaded
    // once for the single target line. Best-effort: fall back to weekends-only if
    // the module isn't available.
    const holidaySet = new Set();
    try {
      const hrows = await registerHolidays.holidaysBetween(client, { from: assignedDate, to: addDaysStr(assignedDate, 730) });
      for (const h of hrows) if (h.line_no == null || String(h.line_no) === String(lineNo)) holidaySet.add(h.holiday_date);
    } catch (e) { console.warn("⚠️  holidays not available for move-batch:", e.message); }

    for (const original of cur.rows) {
      const totalQty = parseFloat(original.assigned_quantity) || 0;
      if (totalQty <= 0) continue;
      const workOrderId = original.work_order_id;
      const color = original.color || null;
      const status = ["planned", "released", "completed", "cancelled"].includes(original.status)
        ? original.status
        : "planned";

      // Prefer the work order's own SAM for the informational rate columns.
      const woRes = await client.query(
        "SELECT sam_minutes FROM work_orders WHERE id = $1",
        [workOrderId]
      );
      const woSam = parseFloat(woRes.rows[0]?.sam_minutes) || 0;

      let remaining = totalQty;
      let dayStr = assignedDate;
      let scanned = 0;

      while (remaining > 0 && scanned < MAX_DAYS) {
        scanned++;
        if (isWeekend(dayStr) || holidaySet.has(dayStr)) { dayStr = addDaysStr(dayStr, 1); continue; } // no weekend / holiday work
        const { lines } = await getLineCapacityForDate(client, dayStr);
        const lineData = lines.find((l) => String(l.line_no) === String(lineNo));
        if (!lineData) { dayStr = addDaysStr(dayStr, 1); continue; }  // no run -> skip

        const usedRes = await client.query(
          `SELECT COALESCE(SUM(assigned_quantity), 0) AS used
             FROM line_assignments
            WHERE line_no = $1 AND assigned_date = $2 AND status NOT IN ('cancelled', 'rejected')`,
          [String(lineNo), dayStr]
        );
        const used = parseFloat(usedRes.rows[0].used) || 0;
        const capacity = parseFloat(lineData.target_pcs) || 0;
        const available = Math.max(0, capacity - used);
        if (available <= 0) { dayStr = addDaysStr(dayStr, 1); continue; }  // full -> next day

        const chunk = Math.min(remaining, available);

        const operators = parseInt(lineData.operators_count) || 20;
        const workingHours = parseFloat(lineData.working_hours) || 8;
        const efficiency = parseFloat(lineData.efficiency) || 0.85;
        const samMinutes = woSam || parseFloat(lineData.sam_minutes) || 3.5;
        const effectiveDailyMinutes = operators * workingHours * 60 * efficiency;
        const piecesPerDay = samMinutes > 0 ? effectiveDailyMinutes / samMinutes : 0;

        const row = await mergeOrInsertAssignment(client, {
          workOrderId,
          lineRunId: lineData.id || null,
          lineNo: String(lineNo),
          assignedDate: dayStr,
          quantity: chunk,
          availableMinutes: effectiveDailyMinutes,
          requiredRate: piecesPerDay,
          startDate: dayStr,
          endDate: dayStr,
          status,
          color,
        });
        createdRows.push(row);
        // NOTE: drafts are no longer auto-created on move. Line leaders receive
        // work only when the planner confirms (POST /api/line-assignments/confirm).
        remaining -= chunk;
        dayStr = addDaysStr(dayStr, 1);
      }

      if (remaining > 0) {
        await client.query("ROLLBACK");
        return res.status(400).json({
          success: false,
          error: `La línea ${lineNo} no tiene capacidad suficiente para reacomodar todas las casillas seleccionadas desde el ${assignedDate}.`,
        });
      }
    }

    // Drop any now-empty source day's unconfirmed draft run so line leaders stop
    // seeing drafts for days these blocks were moved away from.
    for (const cell of sourceCells) {
      await cleanupOrphanDraftRuns(client, cell.lineNo, cell.date);
    }

    await client.query("COMMIT");
    res.json({
      success: true,
      assignments: createdRows,
      cells: createdRows.length,
      moved: idList.length,
    });
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    console.error("❌ Error moving batch of line assignments:", err.message);
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});

// ---------------------------------------------------------------------------
// POST /api/line-assignments/insert-shift-batch
//
// Multi-order version of PATCH /insert-shift. Take one OR several selected
// assignments and INSERT them as consecutive workday cells starting at
// (lineNo, assignedDate), pushing the whole PLANNED tail of the target line
// forward by exactly as many workdays as there are inserted cells. Relative
// sequence and spacing on the line are preserved — the tail just slides by N
// workdays (a Friday block lands on the following Monday), same idea as the
// single-order insert but for N cells at once.
//
// The single drag-and-drop insert now routes here too (ids:[oneId]) so BOTH the
// single and multi insert are reversible through the exact same undo token.
//
// Body:    { ids: number[], lineNo, assignedDate }
// Returns: { success, inserted, shifted, firstDate, lastDate, undo }
//          `undo` is an opaque snapshot the client posts to /insert-shift-undo
//          to reverse the entire ripple in one shot.
//
// Safety:
//  - One transaction: any failure rolls the whole ripple back.
//  - Selected rows are deleted BEFORE the tail is read, so a selected block that
//    lived on the target line at/after D is not double-counted in the shift.
//  - The tail shift is applied LATEST-day first so no two planned rows ever
//    momentarily share a (work_order,line,day,color) slot and trip
//    uq_line_assign_planned_cell.
//  - Only status='planned' rows shift; released/completed/cancelled history is
//    left untouched. Weekends AND registered holidays are skipped.
// ---------------------------------------------------------------------------
app.post("/api/line-assignments/insert-shift-batch", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  const addDaysStr = (ymdStr, k) => {
    const [y, m, d] = ymdStr.split("-").map(Number);
    const dt = new Date(Date.UTC(y, m - 1, d));
    dt.setUTCDate(dt.getUTCDate() + k);
    return dt.toISOString().slice(0, 10);
  };
  const isWeekend = (ymdStr) => {
    const [y, m, d] = ymdStr.split("-").map(Number);
    const dow = new Date(Date.UTC(y, m - 1, d)).getUTCDay();
    return dow === 0 || dow === 6;
  };
  // Days blocked for the target line (registered holidays / line stoppages),
  // populated once per request below — before any workday hop consults it.
  const holidaySet = new Set();
  const isBlocked = (ymdStr) => isWeekend(ymdStr) || holidaySet.has(ymdStr);
  const nextWorkday = (ymdStr) => {
    let d = addDaysStr(ymdStr, 1);
    while (isBlocked(d)) d = addDaysStr(d, 1);
    return d;
  };
  const thisOrNextWorkday = (ymdStr) => {
    let d = ymdStr;
    while (isBlocked(d)) d = addDaysStr(d, 1);
    return d;
  };
  // Full, timezone-safe snapshot of a row — enough to recreate it verbatim.
  const SNAP_COLS = `id, work_order_id, line_run_id, line_no,
           to_char(assigned_date, 'YYYY-MM-DD')      AS assigned_date,
           assigned_quantity, available_minutes, required_production_rate,
           to_char(planned_start_date, 'YYYY-MM-DD') AS planned_start_date,
           to_char(planned_end_date, 'YYYY-MM-DD')   AS planned_end_date,
           priority, status, color`;
  try {
    await setSchema(client);
    const { ids, lineNo, assignedDate } = req.body;
    const idList = Array.isArray(ids)
      ? [...new Set(ids.map((n) => parseInt(n)).filter((n) => Number.isInteger(n)))]
      : [];
    if (idList.length === 0 || !lineNo || !assignedDate) {
      return res.status(400).json({ success: false, error: "ids (no vacío), lineNo y assignedDate son obligatorios" });
    }
    if (isWeekend(assignedDate)) {
      return res.status(400).json({ success: false, error: "No se puede insertar en fin de semana. Elija un dia entre semana." });
    }
    const targetLine = String(lineNo);

    // Preload every blocked day for this line across a generous horizon so the
    // workday hops below skip registered holidays (plant-wide OR line-specific)
    // just like weekends — both the inserted orders and the rippled tail avoid
    // them. Best-effort: if the holidays module/table isn't there we fall back
    // to skipping weekends only.
    try {
      const hrows = await registerHolidays.holidaysBetween(client, {
        from: assignedDate,
        to: addDaysStr(assignedDate, 730),
      });
      for (const h of hrows) {
        if (h.line_no == null || String(h.line_no) === targetLine) holidaySet.add(h.holiday_date);
      }
    } catch (e) {
      console.warn("⚠️  holidays not available for insert-shift-batch:", e.message);
    }

    // The destination day itself must be a working day for this line.
    if (holidaySet.has(assignedDate)) {
      let hol = null;
      try { hol = await registerHolidays.isHoliday(client, { date: assignedDate, lineNo: targetLine }); } catch { /* keep generic message */ }
      const scope = hol?.line_no ? `la Línea ${hol.line_no}` : "toda la planta";
      return res.status(400).json({
        success: false,
        error: `${assignedDate} es un día no laborable para ${scope}${hol?.name ? ` (${hol.name})` : ""}.`,
        holiday: hol || undefined,
      });
    }

    await client.query("BEGIN");

    // 1) Snapshot the selected rows (for undo) in a deterministic order — their
    //    current position — then delete them. Deleting first frees their old
    //    planned cells AND keeps them out of the tail query below.
    const sel = await client.query(
      `SELECT ${SNAP_COLS}
         FROM line_assignments
        WHERE id = ANY($1::bigint[])
        ORDER BY assigned_date ASC, id ASC`,
      [idList]
    );
    if (sel.rows.length === 0) {
      await client.query("ROLLBACK");
      return res.status(404).json({ success: false, error: "No se encontraron las asignaciones" });
    }
    const selectedRows = sel.rows;
    const N = selectedRows.length;

    // Remember every (line, day) the selection came from so we can drop their
    // now-empty draft runs afterwards.
    const sourceCells = [
      ...new Map(
        selectedRows.map((r) => [`${r.line_no}|${r.assigned_date}`, { lineNo: String(r.line_no), date: r.assigned_date }])
      ).values(),
    ];

    await client.query("DELETE FROM line_assignments WHERE id = ANY($1::bigint[])", [idList]);

    // 2) The N consecutive workday slots the newcomers will occupy, from D.
    const slots = [];
    let cursor = thisOrNextWorkday(assignedDate);
    for (let i = 0; i < N; i++) { slots.push(cursor); cursor = nextWorkday(cursor); }
    const D = slots[0];
    const lastSlot = slots[N - 1];

    // 3) Push the planned tail of the target line (>= D) forward by N workdays,
    //    latest-day first. Snapshot it first for undo. Shifting every tail row by
    //    the same N workdays preserves inter-block spacing and clears slots
    //    D..lastSlot for the newcomers.
    const tailRes = await client.query(
      `SELECT ${SNAP_COLS}
         FROM line_assignments
        WHERE line_no = $1 AND assigned_date >= $2 AND status = 'planned'
        ORDER BY assigned_date DESC, id DESC`,
      [targetLine, D]
    );
    const tailSnapshot = tailRes.rows;
    for (const row of tailSnapshot) {
      let nd = row.assigned_date;
      for (let k = 0; k < N; k++) nd = nextWorkday(nd);   // + N workdays
      await client.query(
        `UPDATE line_assignments
            SET assigned_date = $1, planned_start_date = $1, planned_end_date = $1, updated_at = now()
          WHERE id = $2`,
        [nd, row.id]
      );
    }

    // 4) Place the N newcomers on slots[0..N-1] in selection order. Recompute the
    //    informational rate columns from the target line's run for each slot when
    //    one exists; otherwise keep the block's own values (columns are NOT NULL).
    const createdIds = [];
    for (let i = 0; i < N; i++) {
      const a = selectedRows[i];
      const day = slots[i];
      const woRes = await client.query("SELECT sam_minutes FROM work_orders WHERE id = $1", [a.work_order_id]);
      const woSam = parseFloat(woRes.rows[0]?.sam_minutes) || 0;
      const { lines } = await getLineCapacityForDate(client, day);
      const lineData = lines.find((l) => String(l.line_no) === targetLine);

      let availableMinutes = parseFloat(a.available_minutes) || 0;
      let requiredRate = parseFloat(a.required_production_rate) || 0;
      let lineRunId = a.line_run_id || null;
      if (lineData) {
        const operators = parseInt(lineData.operators_count) || 20;
        const workingHours = parseFloat(lineData.working_hours) || 8;
        const efficiency = parseFloat(lineData.efficiency) || 0.85;
        const samMinutes = woSam || parseFloat(lineData.sam_minutes) || 3.5;
        availableMinutes = operators * workingHours * 60 * efficiency;
        requiredRate = samMinutes > 0 ? availableMinutes / samMinutes : 0;
        lineRunId = lineData.id || null;
      }
      const status = ["planned", "released", "completed", "cancelled"].includes(a.status) ? a.status : "planned";
      const placed = await client.query(
        `INSERT INTO line_assignments
            (work_order_id, line_run_id, line_no, assigned_date, assigned_quantity,
             available_minutes, required_production_rate, planned_start_date, planned_end_date,
             priority, status, color)
          VALUES ($1, $2, $3, $4, $5, $6, $7, $4, $4, $8, $9, $10)
          RETURNING id`,
        [a.work_order_id, lineRunId, targetLine, day, a.assigned_quantity,
         availableMinutes, requiredRate, a.priority ?? 0, status, a.color || null]
      );
      createdIds.push(placed.rows[0].id);
    }

    // 5) Drop any now-empty source day's orphan draft run.
    for (const cell of sourceCells) {
      await cleanupOrphanDraftRuns(client, cell.lineNo, cell.date);
    }

    await client.query("COMMIT");

    res.json({
      success: true,
      inserted: createdIds.length,
      shifted: tailSnapshot.length,
      firstDate: D,
      lastDate: lastSlot,
      undo: {
        op: "insert-shift-batch",
        lineNo: targetLine,
        createdIds,             // newcomer rows to delete on undo
        restore: selectedRows,  // original selected rows (recreate verbatim)
        tail: tailSnapshot,     // original tail rows, pre-shift (recreate verbatim)
      },
    });
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    console.error("❌ Error inserting/shifting batch of line assignments:", err.message);
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});

// ---------------------------------------------------------------------------
// POST /api/line-assignments/insert-shift-undo
//
// Reverse a previous /insert-shift-batch. The client passes back the opaque
// `undo` token it received. We wipe every row the operation produced — the
// inserted newcomers plus the shifted tail (which kept their ids) — and then
// re-create the exact pre-operation snapshot, original ids and all. Deleting the
// whole affected slice BEFORE re-inserting means the restore can never trip the
// planned-cell unique index.
//
// Guarded: if any inserted newcomer is already gone (deleted / confirmed / moved
// since), or a fresh order now conflicts with a restored slot, the board has
// diverged — we refuse (409) rather than clobber newer edits.
//
// Body: { undo: <token from insert-shift-batch> }
// ---------------------------------------------------------------------------
app.post("/api/line-assignments/insert-shift-undo", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  const reinsert = async (r) => {
    // line_run_id: keep only if the run still exists (matches ON DELETE SET NULL).
    await client.query(
      `INSERT INTO line_assignments
          (id, work_order_id, line_run_id, line_no, assigned_date, assigned_quantity,
           available_minutes, required_production_rate, planned_start_date, planned_end_date,
           priority, status, color)
        VALUES ($1, $2,
                (SELECT lr.id FROM line_runs lr WHERE lr.id = $3),
                $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
        ON CONFLICT (id) DO NOTHING`,
      [r.id, r.work_order_id, r.line_run_id, r.line_no, r.assigned_date, r.assigned_quantity,
       r.available_minutes, r.required_production_rate, r.planned_start_date, r.planned_end_date,
       r.priority ?? 0, r.status, r.color || null]
    );
  };
  try {
    await setSchema(client);
    const undo = req.body?.undo;
    if (!undo || undo.op !== "insert-shift-batch" || !Array.isArray(undo.createdIds)) {
      return res.status(400).json({ success: false, error: "Token para deshacer invalido." });
    }
    const createdIds = undo.createdIds.map((n) => parseInt(n)).filter(Number.isInteger);
    const restore = Array.isArray(undo.restore) ? undo.restore : [];
    const tail = Array.isArray(undo.tail) ? undo.tail : [];
    const shiftedIds = tail.map((r) => parseInt(r.id)).filter(Number.isInteger);

    await client.query("BEGIN");

    // Guard: every newcomer must still be present. If not, the board changed
    // after the insert and undoing could wipe out newer work.
    if (createdIds.length) {
      const chk = await client.query(
        "SELECT COUNT(*)::int AS n FROM line_assignments WHERE id = ANY($1::bigint[])",
        [createdIds]
      );
      if (chk.rows[0].n !== createdIds.length) {
        await client.query("ROLLBACK");
        return res.status(409).json({ success: false, error: "No se puede deshacer: el tablero cambio desde la insercion." });
      }
    }

    // Cells the newcomers sat on — tidy their draft runs after we restore.
    const createdCells = createdIds.length
      ? (await client.query(
          `SELECT DISTINCT line_no, to_char(assigned_date, 'YYYY-MM-DD') AS d
             FROM line_assignments WHERE id = ANY($1::bigint[])`,
          [createdIds]
        )).rows
      : [];

    // 1) Remove everything the op produced: newcomers + the shifted tail rows.
    //    Afterwards the affected slice is empty, so the restore below can't
    //    collide with the very rows it is replacing.
    if (createdIds.length) await client.query("DELETE FROM line_assignments WHERE id = ANY($1::bigint[])", [createdIds]);
    if (shiftedIds.length) await client.query("DELETE FROM line_assignments WHERE id = ANY($1::bigint[])", [shiftedIds]);

    // 2) Re-create the pre-op snapshot verbatim (original ids, dates, values).
    for (const r of restore) await reinsert(r);
    for (const r of tail) await reinsert(r);

    // 3) Drop any orphan draft runs on the cells the newcomers vacated.
    for (const c of createdCells) await cleanupOrphanDraftRuns(client, String(c.line_no), c.d);

    await client.query("COMMIT");
    res.json({ success: true, restored: restore.length, unshifted: tail.length });
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    // A unique-cell violation means a newer order now sits where a restored block
    // needs to go — the board diverged, so report it as a conflict, not a crash.
    if (err.code === "23505") {
      return res.status(409).json({ success: false, error: "No se puede deshacer: el tablero cambio desde la insercion." });
    }
    console.error("❌ Error undoing insert-shift:", err.message);
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});

app.get("/api/lineleader/latest-run", authenticateToken, allowRoles("line_leader", "engineer", "supervisor"), async (req, res, next) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
    const line = req.query.line;
    if (!line) return res.status(400).json({ success: false, error: "line query parameter required" });

    if (req.user.role === "line_leader" && String(line) !== String(req.user.line_number)) {
      return res.status(403).json({ success: false, error: "You can only access your own line" });
    }

    const runQ = await client.query(
      `SELECT * FROM line_runs
         WHERE line_no = $1 AND is_draft = false AND run_date <= CURRENT_DATE
         ORDER BY run_date DESC, created_at DESC
         LIMIT 1`,
      [line]
    );
    if (runQ.rowCount === 0) {
      return res.json({ success: false, error: `No runs found for line ${line}` });
    }
    const run = runQ.rows[0];

    const slotsQ = await client.query(
      `SELECT * FROM shift_slots WHERE run_id = $1 ORDER BY slot_order ASC`,
      [run.id]
    );

    res.json({ success: true, run, slots: slotsQ.rows });
  } catch (err) {
    next(err);
  } finally {
    client.release();
  }
});
/**
 * lines with multiple runs endpoint
 */

/**
 * POST /api/multi-style/create-group
 * Create a style group with multiple styles for the same line and date
 */
app.post("/api/multi-style/create-group", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
    await client.query("BEGIN");

    const { line, date, styles } = req.body;

    if (!line || !date || !styles || !Array.isArray(styles) || styles.length === 0) {
      return res.status(400).json({
        success: false,
        error: "Missing required fields: line, date, and at least one style",
      });
    }

    // Create the first style as the "parent" run
    const firstStyle = styles[0];
    const parentResult = await client.query(
      `INSERT INTO line_runs (
        line_no, run_date, style, operators_count, working_hours,
        sam_minutes, efficiency, target_pcs, target_per_hour,
        created_at, updated_at, style_group_name
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW(), $10)
      RETURNING id`,
      [
        line,
        date,
        firstStyle.styleCode,
        firstStyle.operatorsCount,
        firstStyle.workingHours,
        firstStyle.sam,
        firstStyle.efficiency || 0.7,
        firstStyle.targetPcs,
        firstStyle.targetPerHour,
        `Group_${line}_${date}_${firstStyle.styleCode}`
      ]
    );

    const groupId = parentResult.rows[0].id;
    const savedStyles = [{ id: groupId, style_code: firstStyle.styleCode }];

    // Create additional styles as child runs linked to the parent
    for (let i = 1; i < styles.length; i++) {
      const style = styles[i];
      const childResult = await client.query(
        `INSERT INTO line_runs (
          line_no, run_date, style, operators_count, working_hours,
          sam_minutes, efficiency, target_pcs, target_per_hour,
          style_group_id, style_group_name, created_at, updated_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW(), NOW())
        RETURNING id`,
        [
          line,
          date,
          style.styleCode,
          style.operatorsCount,
          style.workingHours,
          style.sam,
          style.efficiency || 0.7,
          style.targetPcs,
          style.targetPerHour,
          groupId,
          `Group_${line}_${date}_${firstStyle.styleCode}`
        ]
      );

      savedStyles.push({ id: childResult.rows[0].id, style_code: style.styleCode });
    }

    // Save slots for each style
    for (let i = 0; i < styles.length; i++) {
      const style = styles[i];
      const runId = savedStyles[i].id;

      if (style.slots && style.slots.length > 0) {
        for (let j = 0; j < style.slots.length; j++) {
          const slot = style.slots[j];
          await client.query(
            `INSERT INTO shift_slots (
              run_id, slot_order, slot_label, slot_start, slot_end, planned_hours
            )
            VALUES ($1, $2, $3, $4, $5, $6)`,
            [
              runId,
              j + 1,
              slot.label,
              slot.startTime || null,
              slot.endTime || null,
              parseFloat(slot.hours) || 0,
            ]
          );
        }
      }
    }

    await client.query("COMMIT");

    res.json({
      success: true,
      message: "Style group created successfully",
      groupId,
      styles: savedStyles,
    });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("❌ Error creating style group:", err.message);
    res.status(500).json({
      success: false,
      error: err.message,
    });
  } finally {
    client.release();
  }
});

/**
 * GET /api/multi-style/group-runs?line=8&date=2024-03-27
 * Get all styles for a line on a specific date
 */
app.get("/api/multi-style/group-runs", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);

    const { line, date } = req.query;
    if (!line || !date) {
      return res.status(400).json({
        success: false,
        error: "line and date parameters are required",
      });
    }

    // Find runs on this line and date
    const runs = await client.query(
      `SELECT * FROM line_runs
       WHERE line_no = $1 AND run_date = $2
       ORDER BY style_group_id NULLS FIRST, id`,
      [line, date]
    );

    if (runs.rows.length === 0) {
      return res.json({
        success: false,
        error: `No runs found for line ${line} on ${date}`,
      });
    }

    // Group by style_group_id
    const grouped = {};
    for (const run of runs.rows) {
      const groupKey = run.style_group_id || run.id;
      if (!grouped[groupKey]) {
        grouped[groupKey] = {
          groupId: groupKey,
          groupName: run.style_group_name || run.style,
          line_no: run.line_no,
          run_date: run.run_date,
          styles: [],
        };
      }
      
      // Get slots for this run
      const slots = await client.query(
        `SELECT * FROM shift_slots
         WHERE run_id = $1
         ORDER BY slot_order`,
        [run.id]
      );
      
      grouped[groupKey].styles.push({
        ...run,
        slots: slots.rows,
      });
    }

    res.json({
      success: true,
      groups: Object.values(grouped),
    });
  } catch (err) {
    console.error("❌ Error fetching style groups:", err.message);
    res.status(500).json({
      success: false,
      error: err.message,
    });
  } finally {
    client.release();
  }
});

/**
 * GET /api/multi-style/latest-group?line=8
 * Get the latest style group for a line
 */
app.get("/api/multi-style/latest-group", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);

    const line = String(req.query.line || "").trim();
    if (!line) {
      return res.status(400).json({ success: false, error: "line is required" });
    }

    // Get the latest run date for this line
    const latestDate = await client.query(
      `SELECT DISTINCT run_date FROM line_runs
       WHERE line_no = $1 AND is_draft = false AND run_date <= CURRENT_DATE
       ORDER BY run_date DESC
       LIMIT 1`,
      [line]
    );

    if (latestDate.rows.length === 0) {
      return res.json({
        success: false,
        error: `No runs found for line ${line}`,
      });
    }

    const date = latestDate.rows[0].run_date;

    // Now get all runs for that date
    const runs = await client.query(
      `SELECT * FROM line_runs
       WHERE line_no = $1 AND run_date = $2 AND is_draft = false
       ORDER BY style_group_id NULLS FIRST, id`,
      [line, date]
    );

    // Group by style_group_id
    const styles = [];
    for (const run of runs.rows) {
      // Get slots
      const slots = await client.query(
        `SELECT * FROM shift_slots
         WHERE run_id = $1
         ORDER BY slot_order`,
        [run.id]
      );
      
      // Get operators
      const operators = await client.query(
        `SELECT * FROM run_operators
         WHERE run_id = $1
         ORDER BY operator_no`,
        [run.id]
      );
      
      // Get slot targets
      const slotTargets = await client.query(
        `SELECT s.slot_label, t.slot_target, t.cumulative_target
         FROM slot_targets t
         JOIN shift_slots s ON t.slot_id = s.id
         WHERE t.run_id = $1
         ORDER BY s.slot_order`,
        [run.id]
      );
      
      styles.push({
        run,
        slots: slots.rows,
        operators: operators.rows,
        slotTargets: slotTargets.rows,
      });
    }

    res.json({
      success: true,
      date,
      styles,
    });
  } catch (err) {
    console.error("❌ Error fetching latest style group:", err.message);
    res.status(500).json({
      success: false,
      error: err.message,
    });
  } finally {
    client.release();
  }
});

// Compatibility routes (server.js style)
app.get("/api/run/:runId", async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);

    const { runId } = req.params;

    // Get line run data
    const runResult = await client.query("SELECT lr.*, wo.work_order_no FROM line_runs lr LEFT JOIN work_orders wo ON wo.id = lr.work_order_id WHERE lr.id = $1", [runId]);

    if (runResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: "Run not found",
      });
    }

    const runData = runResult.rows[0];

    // Get shift slots
    const slotsResult = await client.query(
      `SELECT id, slot_order, slot_label, slot_start, slot_end, planned_hours 
       FROM shift_slots 
       WHERE run_id = $1 
       ORDER BY slot_order`,
      [runId]
    );

    // Get operators
    const operatorsResult = await client.query(
      `SELECT id, operator_no, operator_name 
       FROM run_operators 
       WHERE run_id = $1 
       ORDER BY operator_no`,
      [runId]
    );

    // Get slot targets
    const slotTargetsResult = await client.query(
      `SELECT s.slot_label, t.slot_target, t.cumulative_target
       FROM slot_targets t
       JOIN shift_slots s ON t.slot_id = s.id
       WHERE t.run_id = $1
       ORDER BY s.slot_order`,
      [runId]
    );

    // Get operations with their hourly data (both stitched and sewed)
    const operationsData = [];

    for (const operator of operatorsResult.rows) {
      const operationsResult = await client.query(
        `SELECT 
          o.id,
          o.operation_name,
          o.t1_sec,
          o.t2_sec,
          o.t3_sec,
          o.t4_sec,
          o.t5_sec,
          o.capacity_per_hour,
          COALESCE(
            jsonb_object_agg(
              COALESCE(s.slot_label, ''),
              COALESCE(h.stitched_qty, 0)
            ) FILTER (WHERE s.slot_label IS NOT NULL),
            '{}'::jsonb
          ) as stitched_data,
          COALESCE(
            jsonb_object_agg(
              COALESCE(s2.slot_label, ''),
              COALESCE(se.sewed_qty, 0)
            ) FILTER (WHERE s2.slot_label IS NOT NULL),
            '{}'::jsonb
          ) as sewed_data
         FROM operator_operations o
         LEFT JOIN operation_hourly_entries h ON o.id = h.operation_id
         LEFT JOIN shift_slots s ON h.slot_id = s.id
         LEFT JOIN operation_sewed_entries se ON o.id = se.operation_id
         LEFT JOIN shift_slots s2 ON se.slot_id = s2.id
         WHERE o.run_operator_id = $1 AND o.run_id = $2
         GROUP BY o.id
         ORDER BY o.created_at`,
        [operator.id, runId]
      );

      operationsData.push({
        operator,
        operations: operationsResult.rows,
      });
    }

    res.json({
      success: true,
      run: runData,
      slots: slotsResult.rows,
      operators: operatorsResult.rows,
      operations: operationsData,
      slotTargets: slotTargetsResult.rows,
    });
  } catch (err) {
    console.error("❌ Error fetching run data:", err.message);
    res.status(500).json({
      success: false,
      error: err.message,
    });
  } finally {
    client.release();
  }
});

app.post(
  "/api/update-hourly-data/:runId",
  authenticateToken,
  allowRoles("engineer", "supervisor", "line_leader"),
  validate([
    param("runId").isInt({ gt: 0 }).withMessage("Valid run ID required"),
    body("entries").isArray().withMessage("Entries must be an array"),
    body("entries.*.operatorNo").isInt({ gt: 0 }).withMessage("Operator number required"),
    body("entries.*.operationName").notEmpty().withMessage("Operation name required"),
    body("entries.*.slotLabel").notEmpty().withMessage("Slot label required"),
    body("entries.*.stitchedQty").isFloat({ min: 0 }).withMessage("Stitched quantity must be >= 0"),
  ]),
  async (req, res, next) => {
    const client = await pool.connect();
    try {
      await setSchema(client);
      await client.query("BEGIN");

      const { runId } = req.params;
      const { entries } = req.body;

      if (req.user.role === "line_leader") {
        const runQ = await client.query("SELECT line_no FROM line_runs WHERE id = $1", [runId]);
        if (runQ.rows.length === 0) {
          await client.query("ROLLBACK");
          return res.status(404).json({ success: false, error: "Run not found" });
        }
        if (String(runQ.rows[0].line_no) !== String(req.user.line_number)) {
          await client.query("ROLLBACK");
          return res.status(403).json({ success: false, error: "You can only update your own line" });
        }
      }

      let savedCount = 0;
      let updatedCount = 0;

      for (const entry of entries) {
        const { operatorNo, operationName, slotLabel, stitchedQty } = entry;

        const opResult = await client.query(
          `SELECT o.id as op_id
           FROM operator_operations o
           JOIN run_operators ro ON o.run_operator_id = ro.id
           WHERE o.run_id = $1
             AND ro.operator_no = $2
             AND o.operation_name = $3
           LIMIT 1`,
          [runId, parseInt(operatorNo, 10), operationName]
        );
        if (opResult.rows.length === 0) continue;

        const operationId = opResult.rows[0].op_id;

        const slotResult = await client.query(
          "SELECT id FROM shift_slots WHERE run_id = $1 AND slot_label = $2",
          [runId, slotLabel]
        );
        if (slotResult.rows.length === 0) continue;

        const slotId = slotResult.rows[0].id;

        const existingResult = await client.query(
          "SELECT id FROM operation_hourly_entries WHERE operation_id = $1 AND slot_id = $2",
          [operationId, slotId]
        );

        if (existingResult.rows.length > 0) {
          await client.query(
            `UPDATE operation_hourly_entries
             SET stitched_qty = $1, updated_at = NOW()
             WHERE operation_id = $2 AND slot_id = $3`,
            [parseFloat(stitchedQty) || 0, operationId, slotId]
          );
          updatedCount++;
        } else {
          await client.query(
            `INSERT INTO operation_hourly_entries (run_id, operation_id, slot_id, stitched_qty, created_at, updated_at)
             VALUES ($1, $2, $3, $4, NOW(), NOW())`,
            [runId, operationId, slotId, parseFloat(stitchedQty) || 0]
          );
          savedCount++;
        }
      }

      await client.query("COMMIT");
      res.json({ success: true, message: "Hourly data updated", savedCount, updatedCount });
    } catch (err) {
      await client.query("ROLLBACK");
      next(err);
    } finally {
      client.release();
    }
  }
);

app.post(
  "/api/add-operation/:runId",
  authenticateToken,
  allowRoles("engineer", "supervisor"),
  validate([
    param("runId").isInt({ gt: 0 }).withMessage("Valid run ID required"),
    body("operatorNo").isInt({ gt: 0 }).withMessage("operatorNo required"),
    body("operationName").notEmpty().withMessage("operationName required"),
    body("capacityPerHour").optional().isFloat({ min: 0 }).withMessage("capacityPerHour must be >= 0"),
  ]),
  async (req, res, next) => {
    const client = await pool.connect();
    try {
      await setSchema(client);
      await client.query("BEGIN");

      const { runId } = req.params;
      const { operatorNo, operatorName, operationName, t1, t2, t3, t4, t5, capacityPerHour } = req.body;

      const operatorResult = await client.query(
        `INSERT INTO run_operators (run_id, operator_no, operator_name, created_at)
         VALUES ($1, $2, $3, NOW())
         ON CONFLICT (run_id, operator_no)
         DO UPDATE SET operator_name = EXCLUDED.operator_name
         RETURNING id`,
        [runId, parseInt(operatorNo, 10), operatorName || null]
      );
      const operatorId = operatorResult.rows[0].id;

      const operationResult = await client.query(
        `INSERT INTO operator_operations (
            run_id, run_operator_id, operation_name,
            t1_sec, t2_sec, t3_sec, t4_sec, t5_sec,
            capacity_per_hour, created_at
         )
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
         ON CONFLICT (run_operator_id, operation_name)
         DO UPDATE SET
           t1_sec = EXCLUDED.t1_sec,
           t2_sec = EXCLUDED.t2_sec,
           t3_sec = EXCLUDED.t3_sec,
           t4_sec = EXCLUDED.t4_sec,
           t5_sec = EXCLUDED.t5_sec,
           capacity_per_hour = EXCLUDED.capacity_per_hour
         RETURNING id`,
        [
          runId,
          operatorId,
          operationName,
          t1 ? parseFloat(t1) : null,
          t2 ? parseFloat(t2) : null,
          t3 ? parseFloat(t3) : null,
          t4 ? parseFloat(t4) : null,
          t5 ? parseFloat(t5) : null,
          parseFloat(capacityPerHour) || 0,
        ]
      );

      await client.query("COMMIT");
      res.json({
        success: true,
        message: "Operation added successfully",
        operationId: operationResult.rows[0].id,
      });
    } catch (err) {
      await client.query("ROLLBACK");
      next(err);
    } finally {
      client.release();
    }
  }
);

// ----------------------------------------------------------------------
// 14. To Delete RUN ENDPOINT (from server.js)
// ----------------------------------------------------------------------

// ✅ Delete a line run and all associated data
app.delete("/api/run/:runId", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
    await client.query("BEGIN");

    const { runId } = req.params;

    // Check if run exists
    const runCheck = await client.query(
      "SELECT id, line_no, run_date FROM line_runs WHERE id = $1",
      [runId]
    );

    if (runCheck.rows.length === 0) {
      await client.query("ROLLBACK");
      return res.status(404).json({
        success: false,
        error: "Run not found",
      });
    }

    const run = runCheck.rows[0];

    // Check if user has permission to delete (engineer, supervisor, master, soporte_it)
    const allowedRoles = ['engineer', 'supervisor', 'master', 'soporte_it'];
    if (!allowedRoles.includes(req.user.role)) {
      await client.query("ROLLBACK");
      return res.status(403).json({
        success: false,
        error: "Access denied. Only engineers, supervisors, or support can delete runs.",
      });
    }

    // Delete the run (CASCADE will handle all related data)
    await client.query("DELETE FROM line_runs WHERE id = $1", [runId]);

    await client.query("COMMIT");

    console.log(`✅ Run ${runId} (Line ${run.line_no}, ${run.run_date}) deleted by user ${req.user.username}`);

    res.json({
      success: true,
      message: `Run from line ${run.line_no} on ${run.run_date} deleted successfully`,
    });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("❌ Error deleting run:", err.message);
    res.status(500).json({
      success: false,
      error: err.message,
    });
  } finally {
    client.release();
  }
});


// ----------------------------------------------------------------------
// 14. DUPLICATE RUN ENDPOINT (from server.js)
// ----------------------------------------------------------------------
app.post("/api/duplicate-run/:runId", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
    await client.query("BEGIN");

    const { runId } = req.params;
    const { newDate } = req.body;            // required: YYYY-MM-DD
    const newLineNo = req.body.newLineNo;    // optional – if omitted, same line_no is used
    const workOrderId = req.body.workOrderId; // optional – work order assigned to the line for that day
    const newStyle = req.body.newStyle;       // optional – tipo+modelo+correlativo of the chosen order
    const newColor = req.body.newColor;       // optional – color of the chosen order (stored separately)

    if (!newDate) {
      return res.status(400).json({ success: false, error: "newDate is required" });
    }

    // 1. Get source run (includes its style + color)
    const sourceRunRes = await client.query(
      `SELECT line_no, style, color, operators_count, working_hours,
              sam_minutes, efficiency, target_pcs, target_per_hour
       FROM line_runs WHERE id = $1`,
      [runId]
    );
    if (sourceRunRes.rowCount === 0) {
      return res.status(404).json({ success: false, error: "Source run not found" });
    }
    const src = sourceRunRes.rows[0];

    // 2. Insert new line_run.
    //    When an order is chosen, the run takes that order's style
    //    (tipo+modelo+correlativo) and color as its own field. Otherwise it keeps
    //    the source run's style/color. Uniqueness is (line_no, run_date, style, color).
    const styleToUse =
      newStyle && String(newStyle).trim() !== "" ? String(newStyle).trim() : src.style;
    const colorToUse =
      newColor !== undefined && newColor !== null && String(newColor).trim() !== ""
        ? String(newColor).trim()
        : (src.color || "");

    const newRunRes = await client.query(
      `INSERT INTO line_runs
         (line_no, run_date, style, color, operators_count, working_hours,
          sam_minutes, efficiency, target_pcs, target_per_hour, work_order_id, created_at, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW(), NOW())
       RETURNING id`,
      [
        newLineNo || src.line_no,
        newDate,
        styleToUse,
        colorToUse,
        src.operators_count,
        src.working_hours,
        src.sam_minutes,
        src.efficiency,
        src.target_pcs,
        src.target_per_hour,
        workOrderId || null,
      ]
    );
    const newRunId = newRunRes.rows[0].id;

    // 3. Copy shift_slots – store mapping old slot_id -> new slot_id
    const slotMap = new Map(); // old slot_id -> new slot_id
    const slotsRes = await client.query(
      `SELECT id, slot_order, slot_label, slot_start, slot_end, planned_hours
       FROM shift_slots WHERE run_id = $1 ORDER BY slot_order`,
      [runId]
    );
    for (const slot of slotsRes.rows) {
      const newSlotRes = await client.query(
        `INSERT INTO shift_slots
           (run_id, slot_order, slot_label, slot_start, slot_end, planned_hours)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING id`,
        [newRunId, slot.slot_order, slot.slot_label, slot.slot_start, slot.slot_end, slot.planned_hours]
      );
      slotMap.set(slot.id, newSlotRes.rows[0].id);
    }

    // 4. Copy run_operators – store mapping old operator_id -> new operator_id
    const operatorMap = new Map();
    const operatorsRes = await client.query(
      `SELECT id, operator_no, operator_name FROM run_operators WHERE run_id = $1`,
      [runId]
    );
    for (const op of operatorsRes.rows) {
      const newOpRes = await client.query(
        `INSERT INTO run_operators (run_id, operator_no, operator_name, created_at)
         VALUES ($1, $2, $3, NOW())
         RETURNING id`,
        [newRunId, op.operator_no, op.operator_name]
      );
      operatorMap.set(op.id, newOpRes.rows[0].id);
    }

    // 5. Copy operator_operations (using operatorMap)
    for (const [oldOpId, newOpId] of operatorMap.entries()) {
      const opsRes = await client.query(
        `SELECT operation_name, t1_sec, t2_sec, t3_sec, t4_sec, t5_sec, capacity_per_hour
         FROM operator_operations WHERE run_operator_id = $1`,
        [oldOpId]
      );
      for (const opData of opsRes.rows) {
        await client.query(
          `INSERT INTO operator_operations
             (run_id, run_operator_id, operation_name, t1_sec, t2_sec, t3_sec, t4_sec, t5_sec,
              capacity_per_hour, created_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())`,
          [
            newRunId,
            newOpId,
            opData.operation_name,
            opData.t1_sec,
            opData.t2_sec,
            opData.t3_sec,
            opData.t4_sec,
            opData.t5_sec,
            opData.capacity_per_hour,
          ]
        );
      }
    }

    // 6. Copy slot_targets (using slotMap)
    const targetsRes = await client.query(
      `SELECT slot_id, slot_target, cumulative_target
       FROM slot_targets WHERE run_id = $1`,
      [runId]
    );
    for (const tgt of targetsRes.rows) {
      const newSlotId = slotMap.get(tgt.slot_id);
      if (newSlotId) {
        await client.query(
          `INSERT INTO slot_targets (run_id, slot_id, slot_target, cumulative_target, created_at, updated_at)
           VALUES ($1, $2, $3, $4, NOW(), NOW())`,
          [newRunId, newSlotId, tgt.slot_target, tgt.cumulative_target]
        );
      }
    }

    await client.query("COMMIT");
    res.json({ success: true, newRunId });
  } catch (err) {
    await client.query("ROLLBACK");
    // Unique (line_no, run_date, style, color) collision -> friendly message.
    if (err.code === "23505") {
      return res.status(409).json({
        success: false,
        error: "Ya existe una corrida para esa línea, fecha, estilo y color. Elige otro color o fecha.",
      });
    }
    console.error("❌ Error duplicating run:", err.message);
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});
// ----------------------------------------------------------------------
// 14.5 OPERATOR MANAGEMENT ENDPOINTS (add/delete operators)
// ----------------------------------------------------------------------

/**
 * POST /api/run/:runId/operators
 * Add a new operator to an existing run
 */
app.post(
  "/api/run/:runId/operators",
  authenticateToken,
  allowRoles("engineer", "supervisor"),
  validate([
    param("runId").isInt({ gt: 0 }).withMessage("Valid run ID required"),
    body("operatorNo").isInt({ gt: 0 }).withMessage("Operator number must be a positive integer"),
    body("operatorName").optional().isString().trim().withMessage("Operator name must be a string"),
  ]),
  async (req, res, next) => {
    const client = await pool.connect();
    try {
      await setSchema(client);
      await client.query("BEGIN");

      const { runId } = req.params;
      const { operatorNo, operatorName } = req.body;

      // Check if operator already exists in this run
      const existingOp = await client.query(
        `SELECT id FROM run_operators 
         WHERE run_id = $1 AND operator_no = $2`,
        [runId, parseInt(operatorNo, 10)]
      );

      if (existingOp.rows.length > 0) {
        await client.query("ROLLBACK");
        return res.status(400).json({
          success: false,
          error: `Operator ${operatorNo} already exists in this run`,
        });
      }

      // Insert new operator
      const result = await client.query(
        `INSERT INTO run_operators (run_id, operator_no, operator_name, created_at)
         VALUES ($1, $2, $3, NOW())
         RETURNING id, operator_no, operator_name`,
        [runId, parseInt(operatorNo, 10), operatorName || null]
      );

      await client.query("COMMIT");

      logger.info("Operator added to run", { 
        runId, 
        operatorNo, 
        operatorId: result.rows[0].id,
        addedBy: req.user.username 
      });

      res.json({
        success: true,
        message: `Operator ${operatorNo} added successfully`,
        operator: result.rows[0],
      });
    } catch (err) {
      await client.query("ROLLBACK");
      next(err);
    } finally {
      client.release();
    }
  }
);

/**
 * DELETE /api/run/:runId/operators/:operatorId
 * Delete an operator from an existing run (cascades to operations and hourly entries)
 */
app.delete(
  "/api/run/:runId/operators/:operatorId",
  authenticateToken,
  allowRoles("engineer", "supervisor"),
  validate([
    param("runId").isInt({ gt: 0 }).withMessage("Valid run ID required"),
    param("operatorId").isInt({ gt: 0 }).withMessage("Valid operator ID required"),
  ]),
  async (req, res, next) => {
    const client = await pool.connect();
    try {
      await setSchema(client);
      await client.query("BEGIN");

      const { runId, operatorId } = req.params;

      // Check if operator exists and belongs to this run
      const operatorCheck = await client.query(
        `SELECT id, operator_no FROM run_operators 
         WHERE id = $1 AND run_id = $2`,
        [operatorId, runId]
      );

      if (operatorCheck.rows.length === 0) {
        await client.query("ROLLBACK");
        return res.status(404).json({
          success: false,
          error: "Operator not found in this run",
        });
      }

      const operatorNo = operatorCheck.rows[0].operator_no;

      // Delete operator (cascades to operations and hourly entries due to foreign keys)
      await client.query(
        `DELETE FROM run_operators WHERE id = $1`,
        [operatorId]
      );

      await client.query("COMMIT");

      logger.info("Operator deleted from run", { 
        runId, 
        operatorNo, 
        operatorId,
        deletedBy: req.user.username 
      });

      res.json({
        success: true,
        message: `Operator ${operatorNo} deleted successfully`,
      });
    } catch (err) {
      await client.query("ROLLBACK");
      next(err);
    } finally {
      client.release();
    }
  }
);

/**
 * GET /api/run/:runId/operators
 * Get all operators for a run with their operations count
 */
app.get(
  "/api/run/:runId/operators",
  authenticateToken,
  validate([
    param("runId").isInt({ gt: 0 }).withMessage("Valid run ID required"),
  ]),
  async (req, res, next) => {
    const client = await pool.connect();
    try {
      await setSchema(client);

      const { runId } = req.params;

      // First verify the run exists
      const runCheck = await client.query(
        "SELECT id FROM line_runs WHERE id = $1",
        [runId]
      );

      if (runCheck.rows.length === 0) {
        return res.status(404).json({
          success: false,
          error: "Run not found",
        });
      }

      // For line leaders, verify they can only access their own line
      if (req.user.role === "line_leader") {
        const lineCheck = await client.query(
          "SELECT line_no FROM line_runs WHERE id = $1",
          [runId]
        );
        if (lineCheck.rows.length > 0 && 
            String(lineCheck.rows[0].line_no) !== String(req.user.line_number)) {
          logger.warn("Line leader attempted to access another line's operators", {
            user: req.user.username,
            requestedRun: runId,
            userLine: req.user.line_number,
          });
          return res.status(403).json({
            success: false,
            error: "You can only access your own line's operators",
          });
        }
      }

      const result = await client.query(
        `SELECT 
          ro.id,
          ro.operator_no,
          ro.operator_name,
          ro.created_at,
          COUNT(oo.id) as operations_count
         FROM run_operators ro
         LEFT JOIN operator_operations oo ON ro.id = oo.run_operator_id
         WHERE ro.run_id = $1
         GROUP BY ro.id
         ORDER BY ro.operator_no`,
        [runId]
      );

      res.json({
        success: true,
        operators: result.rows,
      });
    } catch (err) {
      next(err);
    } finally {
      client.release();
    }
  }
);
// --------------------------------------------------------------
// update the operator count  ENDPOINTS
// --------------------------------------------------------------
// ✅ Update operator count for a run and recalculate target
app.put("/api/update-operator-count/:runId", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
    await client.query("BEGIN");

    const { runId } = req.params;
    const { operatorsCount } = req.body;

    if (!operatorsCount || operatorsCount <= 0) {
      return res.status(400).json({
        success: false,
        error: "Valid operators count is required",
      });
    }

    // Get current run data
    const runResult = await client.query(
      `SELECT working_hours, sam_minutes, efficiency, target_pcs, target_per_hour
       FROM line_runs WHERE id = $1`,
      [runId]
    );

    if (runResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: "Run not found",
      });
    }

    const run = runResult.rows[0];
    
    // Recalculate target based on new operator count
    const operators = parseFloat(operatorsCount);
    const wh = parseFloat(run.working_hours) || 0;
    const sam = parseFloat(run.sam_minutes) || 0;
    const efficiency = parseFloat(run.efficiency) || 0.7;

    // Calculate new target
    const totalMinutes = operators * wh * 60;
    const piecesAt100 = sam > 0 ? totalMinutes / sam : 0;
    const newTarget = piecesAt100 * efficiency;
    
    // Calculate new target per hour
    const newTargetPerHour = wh > 0 ? newTarget / wh : 0;

    // Update the run with new operator count and recalculated targets
    await client.query(
      `UPDATE line_runs 
       SET operators_count = $1, 
           target_pcs = $2,
           target_per_hour = $3,
           updated_at = NOW()
       WHERE id = $4`,
      [operators, newTarget, newTargetPerHour, runId]
    );

    // Also update slot targets (redistribute target across slots proportionally)
    const slotsResult = await client.query(
      `SELECT id, planned_hours FROM shift_slots WHERE run_id = $1 ORDER BY slot_order`,
      [runId]
    );

    if (slotsResult.rows.length > 0) {
      const totalPlannedHours = slotsResult.rows.reduce((sum, slot) => sum + parseFloat(slot.planned_hours), 0);
      
      let cumulativeTarget = 0;
      for (const slot of slotsResult.rows) {
        const slotHours = parseFloat(slot.planned_hours);
        const slotTarget = totalPlannedHours > 0 ? (slotHours / totalPlannedHours) * newTarget : 0;
        cumulativeTarget += slotTarget;

        await client.query(
          `UPDATE slot_targets 
           SET slot_target = $1, cumulative_target = $2, updated_at = NOW()
           WHERE run_id = $3 AND slot_id = $4`,
          [slotTarget, cumulativeTarget, runId, slot.id]
        );
      }
    }

    await client.query("COMMIT");

    res.json({
      success: true,
      message: "Operator count updated successfully",
      newTarget,
      newTargetPerHour,
      operatorsCount: operators
    });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("❌ Error updating operator count:", err.message);
    res.status(500).json({
      success: false,
      error: err.message,
    });
  } finally {
    client.release();
  }
});

// --------------------------------------------------------------
// update-working-hours (FIXED)
// --------------------------------------------------------------

// --------------------------------------------------------------
// update-working-hours (FIXED)
// --------------------------------------------------------------

// ✅ Update working hours for a run and recalculate target
app.put("/api/update-working-hours/:runId", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
    await client.query("BEGIN");

    const { runId } = req.params;
    const { workingHours } = req.body;

    if (!workingHours || workingHours <= 0) {
      return res.status(400).json({
        success: false,
        error: "Valid working hours are required",
      });
    }

    // Get current run data
    const runResult = await client.query(
      `SELECT operators_count, sam_minutes, efficiency, target_pcs, target_per_hour
       FROM line_runs WHERE id = $1`,
      [runId]
    );

    if (runResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: "Run not found",
      });
    }

    const run = runResult.rows[0];
    
    // Recalculate target based on new working hours
    const operators = parseFloat(run.operators_count) || 0;
    const sam = parseFloat(run.sam_minutes) || 0;
    const efficiency = parseFloat(run.efficiency) || 0.7;
    const wh = parseFloat(workingHours);

    // Calculate new target
    const totalMinutes = operators * wh * 60;
    const piecesAt100 = sam > 0 ? totalMinutes / sam : 0;
    const newTarget = piecesAt100 * efficiency;
    
    // Calculate new target per hour
    const newTargetPerHour = wh > 0 ? newTarget / wh : 0;

    // Update the run with new working hours and recalculated targets
    await client.query(
      `UPDATE line_runs 
       SET working_hours = $1, 
           target_pcs = $2,
           target_per_hour = $3,
           updated_at = NOW()
       WHERE id = $4`,
      [wh, newTarget, newTargetPerHour, runId]
    );

    // Also update slot targets (redistribute target across slots proportionally)
    const slotsResult = await client.query(
      `SELECT id, planned_hours FROM shift_slots WHERE run_id = $1 ORDER BY slot_order`,
      [runId]
    );

    if (slotsResult.rows.length > 0) {
      const totalPlannedHours = slotsResult.rows.reduce((sum, slot) => sum + parseFloat(slot.planned_hours), 0);
      
      let cumulativeTarget = 0;
      for (const slot of slotsResult.rows) {
        const slotHours = parseFloat(slot.planned_hours);
        const slotTarget = totalPlannedHours > 0 ? (slotHours / totalPlannedHours) * newTarget : 0;
        cumulativeTarget += slotTarget;

        await client.query(
          `UPDATE slot_targets 
           SET slot_target = $1, cumulative_target = $2, updated_at = NOW()
           WHERE run_id = $3 AND slot_id = $4`,
          [slotTarget, cumulativeTarget, runId, slot.id]
        );
      }
    }

    await client.query("COMMIT");

    res.json({
      success: true,
      message: "Working hours updated successfully",
      newTarget,
      newTargetPerHour,
      workingHours: wh
    });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("❌ Error updating working hours:", err.message);
    res.status(500).json({
      success: false,
      error: err.message,
    });
  } finally {
    client.release();
  }
});

// --------------------------------------------------------------
//  Update shift slot planned hours for a run
// --------------------------------------------------------------
app.put("/api/update-shift-slots/:runId", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
    await client.query("BEGIN");

    const { runId } = req.params;
    const { slots } = req.body; // Array of { slotId, plannedHours, slotLabel }

    if (!slots || !Array.isArray(slots)) {
      return res.status(400).json({
        success: false,
        error: "Slots array is required",
      });
    }

    // Get current run data for target recalculation
    const runResult = await client.query(
      `SELECT operators_count, working_hours, sam_minutes, efficiency, target_pcs
       FROM line_runs WHERE id = $1`,
      [runId]
    );

    if (runResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: "Run not found",
      });
    }

    const run = runResult.rows[0];
    
    // Update each slot's planned hours
    for (const slot of slots) {
      await client.query(
        `UPDATE shift_slots 
         SET planned_hours = $1
         WHERE id = $2 AND run_id = $3`,
        [parseFloat(slot.plannedHours), slot.slotId, runId]
      );
    }

    // Recalculate total working hours from slots
    const slotsResult = await client.query(
      `SELECT planned_hours FROM shift_slots WHERE run_id = $1 ORDER BY slot_order`,
      [runId]
    );

    const totalPlannedHours = slotsResult.rows.reduce(
      (sum, slot) => sum + parseFloat(slot.planned_hours), 
      0
    );

    // Recalculate target based on new total working hours
    const operators = parseFloat(run.operators_count) || 0;
    const sam = parseFloat(run.sam_minutes) || 0;
    const efficiency = parseFloat(run.efficiency) || 0.7;
    const wh = totalPlannedHours;

    const totalMinutes = operators * wh * 60;
    const piecesAt100 = sam > 0 ? totalMinutes / sam : 0;
    const newTarget = piecesAt100 * efficiency;
    const newTargetPerHour = wh > 0 ? newTarget / wh : 0;

    // Update line_runs with new working hours and targets
    await client.query(
      `UPDATE line_runs 
       SET working_hours = $1,
           target_pcs = $2,
           target_per_hour = $3,
           updated_at = NOW()
       WHERE id = $4`,
      [wh, newTarget, newTargetPerHour, runId]
    );

    // Update slot targets (redistribute target across slots proportionally)
    let cumulativeTarget = 0;
    for (const slot of slotsResult.rows) {
      const slotHours = parseFloat(slot.planned_hours);
      const slotTarget = totalPlannedHours > 0 ? (slotHours / totalPlannedHours) * newTarget : 0;
      cumulativeTarget += slotTarget;

      await client.query(
        `UPDATE slot_targets 
         SET slot_target = $1, cumulative_target = $2, updated_at = NOW()
         WHERE run_id = $3 AND slot_id = $4`,
        [slotTarget, cumulativeTarget, runId, slot.id]
      );
    }

    await client.query("COMMIT");

    res.json({
      success: true,
      message: "Shift slots updated successfully",
      workingHours: wh,
      newTarget,
      newTargetPerHour,
      slots: slotsResult.rows.map(slot => ({
        ...slot,
        planned_hours: parseFloat(slot.planned_hours)
      }))
    });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("❌ Error updating shift slots:", err.message);
    res.status(500).json({
      success: false,
      error: err.message,
    });
  } finally {
    client.release();
  }
});

// --------------------------------------------------------------
// update the operator number ENDPOINTS
// --------------------------------------------------------------

// ✅ Update operator number for an existing run
app.put("/api/run/:runId/operators/:operatorId", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
    await client.query("BEGIN");

    const { runId, operatorId } = req.params;
    const { operatorNo, operatorName } = req.body;

    if (!operatorNo) {
      return res.status(400).json({
        success: false,
        error: "Operator number is required",
      });
    }

    // Check if the new operator number already exists in this run
    const existingCheck = await client.query(
      `SELECT id FROM run_operators 
       WHERE run_id = $1 AND operator_no = $2 AND id != $3`,
      [runId, parseInt(operatorNo), operatorId]
    );

    if (existingCheck.rows.length > 0) {
      return res.status(400).json({
        success: false,
        error: `Operator number ${operatorNo} already exists in this run`,
      });
    }

    // Get current operator info for logging
    const currentOp = await client.query(
      `SELECT operator_no FROM run_operators WHERE id = $1`,
      [operatorId]
    );

    // Update the operator
    const result = await client.query(
      `UPDATE run_operators 
       SET operator_no = $1, operator_name = COALESCE($2, operator_name)
       WHERE id = $3 AND run_id = $4
       RETURNING id, operator_no, operator_name`,
      [parseInt(operatorNo), operatorName || null, operatorId, runId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: "Operator not found in this run",
      });
    }

    await client.query("COMMIT");

    console.log(`✅ Operator ${currentOp.rows[0]?.operator_no} → ${operatorNo} updated in run ${runId}`);

    res.json({
      success: true,
      message: `Operator number updated successfully`,
      operator: result.rows[0],
    });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("❌ Error updating operator number:", err.message);
    res.status(500).json({
      success: false,
      error: err.message,
    });
  } finally {
    client.release();
  }
});
// --------------------------------------------------------------
// update the line efficiency ENDPOINTS
// --------------------------------------------------------------

// ✅ Update efficiency for a run and recalculate target
app.put("/api/update-efficiency/:runId", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
    await client.query("BEGIN");

    const { runId } = req.params;
    const { efficiency } = req.body;

    if (!efficiency || efficiency <= 0 || efficiency > 1) {
      return res.status(400).json({
        success: false,
        error: "Valid efficiency between 0 and 1 is required",
      });
    }

    // Get current run data
    const runResult = await client.query(
      `SELECT operators_count, working_hours, sam_minutes, target_pcs, target_per_hour
       FROM line_runs WHERE id = $1`,
      [runId]
    );

    if (runResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: "Run not found",
      });
    }

    const run = runResult.rows[0];
    
    // Recalculate target based on new efficiency
    const operators = parseFloat(run.operators_count) || 0;
    const sam = parseFloat(run.sam_minutes) || 0;
    const wh = parseFloat(run.working_hours) || 0;
    const eff = parseFloat(efficiency);

    // Calculate new target
    const totalMinutes = operators * wh * 60;
    const piecesAt100 = sam > 0 ? totalMinutes / sam : 0;
    const newTarget = piecesAt100 * eff;
    
    // Calculate new target per hour
    const newTargetPerHour = wh > 0 ? newTarget / wh : 0;

    // Update the run with new efficiency and recalculated targets
    await client.query(
      `UPDATE line_runs 
       SET efficiency = $1, 
           target_pcs = $2,
           target_per_hour = $3,
           updated_at = NOW()
       WHERE id = $4`,
      [eff, newTarget, newTargetPerHour, runId]
    );

    // Also update slot targets (redistribute target across slots proportionally)
    const slotsResult = await client.query(
      `SELECT id, planned_hours FROM shift_slots WHERE run_id = $1 ORDER BY slot_order`,
      [runId]
    );

    if (slotsResult.rows.length > 0) {
      const totalPlannedHours = slotsResult.rows.reduce((sum, slot) => sum + parseFloat(slot.planned_hours), 0);
      
      let cumulativeTarget = 0;
      for (const slot of slotsResult.rows) {
        const slotHours = parseFloat(slot.planned_hours);
        const slotTarget = totalPlannedHours > 0 ? (slotHours / totalPlannedHours) * newTarget : 0;
        cumulativeTarget += slotTarget;

        await client.query(
          `UPDATE slot_targets 
           SET slot_target = $1, cumulative_target = $2, updated_at = NOW()
           WHERE run_id = $3 AND slot_id = $4`,
          [slotTarget, cumulativeTarget, runId, slot.id]
        );
      }
    }

    await client.query("COMMIT");

    res.json({
      success: true,
      message: "Efficiency updated successfully",
      newTarget,
      newTargetPerHour,
      efficiency: eff
    });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("❌ Error updating efficiency:", err.message);
    res.status(500).json({
      success: false,
      error: err.message,
    });
  } finally {
    client.release();
  }
});

// --------------------------------------------------------------
// update the operator capacity ENDPOINTS
// --------------------------------------------------------------

app.put("/api/update-operation/:runId", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
    await client.query("BEGIN");

    const { runId } = req.params;
    const { operatorNo, operationName, t1, t2, t3, t4, t5, capacityPerHour } = req.body;

    if (!operatorNo || !operationName) {
      return res.status(400).json({
        success: false,
        error: "Operator number and operation name are required",
      });
    }

    // Find the operation ID and get current capacity
    const opResult = await client.query(
      `
      SELECT o.id as op_id, o.capacity_per_hour as old_capacity
      FROM operator_operations o
      JOIN run_operators ro ON o.run_operator_id = ro.id
      WHERE o.run_id = $1 
        AND ro.operator_no = $2 
        AND o.operation_name = $3
      LIMIT 1
      `,
      [runId, parseInt(operatorNo), operationName]
    );

    if (opResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: "Operation not found",
      });
    }

    const operationId = opResult.rows[0].op_id;
    const oldCapacity = parseFloat(opResult.rows[0].old_capacity) || 0;
    const newCapacity = capacityPerHour || 0;

    // Update the operation - REMOVED updated_at reference
    const updateResult = await client.query(
      `
      UPDATE operator_operations
      SET 
        t1_sec = $1,
        t2_sec = $2,
        t3_sec = $3,
        t4_sec = $4,
        t5_sec = $5,
        capacity_per_hour = $6
      WHERE id = $7
      RETURNING id
      `,
      [
        t1 || null,
        t2 || null,
        t3 || null,
        t4 || null,
        t5 || null,
        newCapacity,
        operationId,
      ]
    );

    if (updateResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: "Failed to update operation",
      });
    }

    // Save to history table if capacity changed
    if (Math.abs(oldCapacity - newCapacity) > 0.001) {
      await client.query(
        `
        INSERT INTO operator_capacity_history 
          (operation_id, old_capacity, new_capacity, changed_by, changed_at)
        VALUES ($1, $2, $3, $4, NOW())
        `,
        [operationId, oldCapacity, newCapacity, req.user.id]
      );
      console.log(`✅ Capacity history recorded for operation ${operationId}: ${oldCapacity} → ${newCapacity}`);
    }

    await client.query("COMMIT");

    res.json({
      success: true,
      message: "Operation updated successfully",
      operationId: updateResult.rows[0].id,
      capacityChanged: Math.abs(oldCapacity - newCapacity) > 0.001
    });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("❌ Error updating operation:", err.message);
    res.status(500).json({
      success: false,
      error: err.message,
    });
  } finally {
    client.release();
  }
});

// ✅ Get capacity history for an operation
app.get("/api/operation-capacity-history/:operationId", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
    
    const { operationId } = req.params;
    
    const result = await client.query(
      `
      SELECT 
        h.id,
        h.old_capacity,
        h.new_capacity,
        h.changed_at,
        u.username as changed_by_username,
        u.full_name as changed_by_name
      FROM operator_capacity_history h
      LEFT JOIN users u ON h.changed_by = u.id
      WHERE h.operation_id = $1
      ORDER BY h.changed_at DESC
      `,
      [operationId]
    );
    
    res.json({
      success: true,
      history: result.rows
    });
  } catch (err) {
    console.error("❌ Error fetching capacity history:", err.message);
    res.status(500).json({
      success: false,
      error: err.message,
    });
  } finally {
    client.release();
  }
});

// ✅ Get all capacity changes for a run
app.get("/api/run-capacity-history/:runId", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
    
    const { runId } = req.params;
    
    const result = await client.query(
      `
      SELECT 
        h.id,
        h.old_capacity,
        h.new_capacity,
        h.changed_at,
        u.username as changed_by_username,
        u.full_name as changed_by_name,
        ro.operator_no,
        ro.operator_name,
        oo.operation_name
      FROM operator_capacity_history h
      JOIN operator_operations oo ON h.operation_id = oo.id
      JOIN run_operators ro ON oo.run_operator_id = ro.id
      LEFT JOIN users u ON h.changed_by = u.id
      WHERE oo.run_id = $1
      ORDER BY h.changed_at DESC
      `,
      [runId]
    );
    
    res.json({
      success: true,
      history: result.rows
    });
  } catch (err) {
    console.error("❌ Error fetching run capacity history:", err.message);
    res.status(500).json({
      success: false,
      error: err.message,
    });
  } finally {
    client.release();
  }
});

// ========== QUALITY INSPECTOR ROUTES ==========
// Make sure this is AFTER authenticateToken is defined

// Helper middleware for quality inspector access
const requireQualityInspector = (req, res, next) => {
  const allowedRoles = ['quality_inspector', 'engineer', 'supervisor', 'soporte_it', 'master','quality_head'];
  if (!allowedRoles.includes(req.user?.role)) {
    return res.status(403).json({
      success: false,
      error: "Access denied. Quality inspector role required.",
    });
  }
  next();
};

/**
 * GET /api/quality/lines
 * Returns all lines that have active runs (for line selection)
 */
app.get("/api/quality/lines", authenticateToken, requireQualityInspector, async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
    
    const result = await client.query(`
      WITH distinct_lines AS (
        SELECT DISTINCT ON (line_no) 
          line_no,
          style as current_style,
          created_at
        FROM line_runs
        WHERE line_no IS NOT NULL AND line_no != ''
        ORDER BY line_no, created_at DESC
      )
      SELECT line_no, current_style
      FROM distinct_lines
      ORDER BY line_no::int
    `);
    
    res.json({
      success: true,
      lines: result.rows.map(row => ({
        line_no: row.line_no,
        current_style: row.current_style,
        has_today_run: false
      })),
    });
  } catch (err) {
    console.error("❌ Error fetching quality lines:", err.message);
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});

/**
 * GET /api/quality/lines/:lineNo/runs
 * Returns runs for a specific line (distinct by date and style)
 */
app.get("/api/quality/lines/:lineNo/runs", authenticateToken, requireQualityInspector, async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
    
    const { lineNo } = req.params;
    
    // Get distinct runs (remove duplicates if any)
    const result = await client.query(`
      SELECT DISTINCT ON (run_date, style)
        id, 
        line_no, 
        run_date, 
        style, 
        target_pcs, 
        operators_count, 
        working_hours
      FROM line_runs
      WHERE line_no = $1
      ORDER BY run_date DESC, style, id DESC
    `, [lineNo]);
    
    console.log(`✅ Found ${result.rows.length} distinct runs for line ${lineNo}`);
    
    res.json({
      success: true,
      runs: result.rows,
    });
  } catch (err) {
    console.error("❌ Error fetching line runs:", err.message);
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});

/**
 * GET /api/quality/inspections/:lineNo
 * Returns inspections for a specific line
 */
app.get("/api/quality/inspections/:lineNo", authenticateToken, requireQualityInspector, async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
    
    const { lineNo } = req.params;
    
    const result = await client.query(`
      SELECT i.*, 
             to_char(i.inspection_date, 'YYYY-MM-DD') as inspection_date,
             COUNT(de.id) as total_defect_entries,
             COALESCE(SUM(de.defect_quantity), 0) as total_defects
      FROM quality_inspections i
      LEFT JOIN quality_defect_entries de ON i.id = de.inspection_id
      WHERE i.line_no = $1
      GROUP BY i.id
      ORDER BY i.inspection_date DESC, i.created_at DESC
    `, [lineNo]);
    
    res.json({
      success: true,
      inspections: result.rows,
    });
  } catch (err) {
    console.error("❌ Error fetching inspections:", err.message);
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});

/**
 * GET /api/quality/inspection/:inspectionId
 * Returns full inspection details
 */
app.get("/api/quality/inspection/:inspectionId", authenticateToken, requireQualityInspector, async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
    
    const { inspectionId } = req.params;
    
    const inspectionResult = await client.query(`
      SELECT * FROM quality_inspections WHERE id = $1
    `, [inspectionId]);
    
    if (inspectionResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Inspection not found" });
    }
    
    const defectsResult = await client.query(`
      SELECT 
        de.*,
        dt.defect_code,
        dt.defect_name,
        dt.category,
        dr.reason_code,
        dr.reason_description
      FROM quality_defect_entries de
      JOIN quality_defect_types dt ON de.defect_type_id = dt.id
      LEFT JOIN quality_defect_reasons dr ON de.defect_reason_id = dr.id
      WHERE de.inspection_id = $1
      ORDER BY de.created_at DESC
    `, [inspectionId]);
    
    res.json({
      success: true,
      inspection: inspectionResult.rows[0],
      defects: defectsResult.rows,
    });
  } catch (err) {
    console.error("❌ Error fetching inspection details:", err.message);
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});


app.get("/api/quality/defect-types", authenticateToken, requireQualityInspector, async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
    
    const result = await client.query(`
      SELECT 
        dt.id,
        dt.defect_code,
        dt.defect_name,
        dt.category,
        dt.sort_order,
        COALESCE(
          (SELECT json_agg(
            json_build_object(
              'id', dr.id,
              'reason_code', dr.reason_code,
              'reason_description', dr.reason_description
            ) ORDER BY dr.sort_order
          )
          FROM quality_defect_reasons dr
          WHERE dr.defect_type_id = dt.id AND dr.is_active = true),
          '[]'::json
        ) as reasons
      FROM quality_defect_types dt
      WHERE dt.is_active = true
      ORDER BY dt.sort_order
    `);
    
    // Add this debug log
    console.log('Defect types with reasons:');
    result.rows.forEach(row => {
      console.log(`  ${row.sort_order}. ${row.defect_name}: ${row.reasons?.length || 0} reasons`);
    });
    
    res.json({
      success: true,
      defectTypes: result.rows,
    });
  } catch (err) {
    console.error("❌ Error fetching defect types:", err.message);
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});
/**
 * POST /api/quality/inspection
 * Create a new inspection
 */
app.post("/api/quality/inspection", authenticateToken, requireQualityInspector, async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
    await client.query("BEGIN");
    
    const { 
      lineNo, 
      style,
      inspectorName, 
      inspectionDate,
      shiftSlot,
      totalCheckedQuantity,
      notes,
      defects 
    } = req.body;
    
    if (!lineNo || !inspectorName || !defects || !Array.isArray(defects)) {
      return res.status(400).json({
        success: false,
        error: "Missing required fields: lineNo, inspectorName, and defects array"
      });
    }
    
    const totalDefects = defects.reduce((sum, d) => sum + (d.quantity || 1), 0);
    
    const inspectionResult = await client.query(`
      INSERT INTO quality_inspections (
        line_no, style, inspector_name, inspection_date, shift_slot, 
        total_defects, total_checked_quantity, notes, created_at, updated_at
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())
      RETURNING id
    `, [
      lineNo,
      style || null,
      inspectorName,
      inspectionDate || new Date().toISOString().split('T')[0],
      shiftSlot || null,
      totalDefects,
      totalCheckedQuantity || 0,
      notes || null
    ]);
    
    const inspectionId = inspectionResult.rows[0].id;
    
    for (const defect of defects) {
      await client.query(`
        INSERT INTO quality_defect_entries (
          inspection_id, defect_type_id, defect_reason_id, 
          defect_quantity, operation_name, operator_no, notes
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7)
      `, [
        inspectionId,
        defect.defectTypeId,
        defect.defectReasonId || null,
        defect.quantity || 1,
        defect.operationName || null,
        defect.operatorNo ? parseInt(defect.operatorNo) : null,
        defect.notes || null
      ]);
    }
    
    // Also save the bad type / bad reason names on the quality_inspections row
    // (aggregated, since one inspection can contain several defect types)
    await client.query(`
      UPDATE quality_inspections qi
      SET bad_type = sub.types,
          bad_reason = sub.reasons,
          updated_at = NOW()
      FROM (
        SELECT
          string_agg(DISTINCT dt.defect_code || ' - ' || dt.defect_name, '; ') AS types,
          string_agg(DISTINCT dr.reason_code || ' - ' || dr.reason_description, '; ') AS reasons
        FROM quality_defect_entries de
        JOIN quality_defect_types dt ON de.defect_type_id = dt.id
        LEFT JOIN quality_defect_reasons dr ON de.defect_reason_id = dr.id
        WHERE de.inspection_id = $1
      ) sub
      WHERE qi.id = $1
    `, [inspectionId]);
    
    await client.query("COMMIT");
    
    res.json({
      success: true,
      message: "Inspection saved successfully",
      inspectionId: inspectionId,
    });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("❌ Error saving inspection:", err.message);
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});

/**
 * DELETE /api/quality/inspection/:inspectionId
 * Delete an inspection
 */
app.delete("/api/quality/inspection/:inspectionId", authenticateToken, requireQualityInspector, async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
    await client.query("BEGIN");
    
    const { inspectionId } = req.params;
    
    const checkResult = await client.query(
      `SELECT id FROM quality_inspections WHERE id = $1`,
      [inspectionId]
    );
    
    if (checkResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Inspection not found" });
    }
    
    await client.query(`DELETE FROM quality_inspections WHERE id = $1`, [inspectionId]);
    
    await client.query("COMMIT");
    
    res.json({
      success: true,
      message: "Inspection deleted successfully",
    });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("❌ Error deleting inspection:", err.message);
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});

/**
 * GET /api/quality/run-operators/:runId
 * Returns operators for a specific run
 */
app.get("/api/quality/run-operators/:runId", authenticateToken, requireQualityInspector, async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
    
    const { runId } = req.params;
    
    const result = await client.query(`
      SELECT ro.id, ro.operator_no, ro.operator_name
      FROM run_operators ro
      WHERE ro.run_id = $1
      ORDER BY ro.operator_no
    `, [runId]);
    
    res.json({
      success: true,
      operators: result.rows,
    });
  } catch (err) {
    console.error("❌ Error fetching run operators:", err.message);
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});

/**
 * GET /api/quality/analytics
 * CEO analytical view of the quality_inspections table.
 * Query params: startDate=YYYY-MM-DD, endDate=YYYY-MM-DD (defaults to today),
 *   line (optional), style (optional).
 * Returns aggregated defect data for the selected period.
 */
app.get("/api/quality/analytics", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);

    if (!['skyrina', 'master', 'engineer', 'supervisor', 'soporte_it', 'quality_inspector', 'quality_head'].includes(req.user?.role)) {
      return res.status(403).json({ success: false, error: "Access denied" });
    }

    const today = new Date().toISOString().split('T')[0];
    const startDate = req.query.startDate || today;
    const endDate = req.query.endDate || startDate;
    const { line, style } = req.query;

    // Build the optional line/style filter that applies to the inspections table (alias i)
    const filters = [];
    const params = [startDate, endDate];
    let p = 3;
    if (line && line !== 'all') { filters.push(`i.line_no = $${p++}`); params.push(line); }
    if (style && style !== 'all') { filters.push(`i.style = $${p++}`); params.push(style); }
    const extra = filters.length ? ` AND ${filters.join(' AND ')}` : '';
    const dateWhere = `i.inspection_date BETWEEN $1 AND $2${extra}`;

    // 1. Headline KPIs. Defect totals come from the entries; checked quantity is a
    // per-inspection figure, so it is summed in a separate subquery to avoid the
    // row multiplication caused by joining the entries table.
    const summary = await client.query(`
      SELECT
        COALESCE((
          SELECT SUM(de.defect_quantity)
          FROM quality_defect_entries de
          JOIN quality_inspections i ON de.inspection_id = i.id
          WHERE ${dateWhere}
        ), 0)::int                                AS total_defects,
        COUNT(DISTINCT i.id)::int                  AS total_inspections,
        COUNT(DISTINCT i.line_no)::int             AS active_lines,
        COUNT(DISTINCT i.style)::int               AS active_styles,
        COUNT(DISTINCT i.inspector_name)::int      AS active_inspectors,
        COALESCE(SUM(i.total_checked_quantity), 0)::numeric AS total_checked
      FROM quality_inspections i
      WHERE ${dateWhere}
    `, params);

    // 2. Defects by line
    const byLine = await client.query(`
      SELECT i.line_no,
             COALESCE(SUM(de.defect_quantity), 0)::int AS total_defects,
             COUNT(DISTINCT i.id)::int AS inspections
      FROM quality_inspections i
      LEFT JOIN quality_defect_entries de ON de.inspection_id = i.id
      WHERE ${dateWhere}
      GROUP BY i.line_no
      ORDER BY total_defects DESC
    `, params);

    // 3. Defects by type
    const byType = await client.query(`
      SELECT dt.defect_code, dt.defect_name, dt.category,
             COALESCE(SUM(de.defect_quantity), 0)::int AS total_defects
      FROM quality_defect_entries de
      JOIN quality_inspections i ON de.inspection_id = i.id
      JOIN quality_defect_types dt ON de.defect_type_id = dt.id
      WHERE ${dateWhere}
      GROUP BY dt.id, dt.defect_code, dt.defect_name, dt.category
      ORDER BY total_defects DESC
    `, params);

    // 4. Defects by reason
    const byReason = await client.query(`
      SELECT dr.reason_code, dr.reason_description, dt.defect_name,
             COALESCE(SUM(de.defect_quantity), 0)::int AS total_defects
      FROM quality_defect_entries de
      JOIN quality_inspections i ON de.inspection_id = i.id
      JOIN quality_defect_types dt ON de.defect_type_id = dt.id
      LEFT JOIN quality_defect_reasons dr ON de.defect_reason_id = dr.id
      WHERE ${dateWhere} AND dr.id IS NOT NULL
      GROUP BY dr.id, dr.reason_code, dr.reason_description, dt.defect_name
      ORDER BY total_defects DESC
      LIMIT 15
    `, params);

    // 5. Defects by inspector
    const byInspector = await client.query(`
      SELECT i.inspector_name,
             COALESCE(SUM(de.defect_quantity), 0)::int AS total_defects,
             COUNT(DISTINCT i.id)::int AS inspections
      FROM quality_inspections i
      LEFT JOIN quality_defect_entries de ON de.inspection_id = i.id
      WHERE ${dateWhere}
      GROUP BY i.inspector_name
      ORDER BY total_defects DESC
    `, params);

    // 6. Defects by style
    const byStyle = await client.query(`
      SELECT COALESCE(i.style, 'Sin estilo') AS style,
             COALESCE(SUM(de.defect_quantity), 0)::int AS total_defects
      FROM quality_inspections i
      LEFT JOIN quality_defect_entries de ON de.inspection_id = i.id
      WHERE ${dateWhere}
      GROUP BY i.style
      ORDER BY total_defects DESC
    `, params);

    // 7. Hourly trend (intraday) based on entry creation time
    const hourly = await client.query(`
      SELECT to_char(de.created_at, 'HH24:00') AS hour,
             COALESCE(SUM(de.defect_quantity), 0)::int AS total_defects
      FROM quality_defect_entries de
      JOIN quality_inspections i ON de.inspection_id = i.id
      WHERE ${dateWhere}
      GROUP BY to_char(de.created_at, 'HH24:00')
      ORDER BY hour
    `, params);

    // 8. Detail rows for the table
    const detail = await client.query(`
      SELECT i.id,
             to_char(i.inspection_date, 'YYYY-MM-DD') AS inspection_date,
             i.line_no, i.style, i.inspector_name, i.shift_slot,
             i.bad_type, i.bad_reason,
             to_char(i.created_at AT TIME ZONE 'America/Mexico_City', 'HH24:MI') AS time,
             COALESCE(SUM(de.defect_quantity), 0)::int AS total_defects
      FROM quality_inspections i
      LEFT JOIN quality_defect_entries de ON de.inspection_id = i.id
      WHERE ${dateWhere}
      GROUP BY i.id
      ORDER BY i.created_at DESC
    `, params);

    res.json({
      success: true,
      range: { startDate, endDate },
      summary: summary.rows[0],
      byLine: byLine.rows,
      byType: byType.rows,
      byReason: byReason.rows,
      byInspector: byInspector.rows,
      byStyle: byStyle.rows,
      hourly: hourly.rows,
      detail: detail.rows,
    });
  } catch (err) {
    console.error("❌ Error fetching quality analytics:", err.message);
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});


// --------------------------------------------------------------
// SUPERVISOR DASHBOARD ENDPOINTS (FIXED)
// --------------------------------------------------------------

const requireSupervisor = (req, res, next) => {
  if (req.user.role !== "supervisor" && req.user.role !== "soporte_it" && req.user.role !== "skyrina" && req.user.role !== "master") {
    return res.status(403).json({
      success: false,
      error: "Access denied. Supervisor, IT Support, Skyrina, or Master role required.",
    });
  }
  next();
};

/**
 * GET /api/supervisor/summary?date=YYYY-MM-DD
 * Returns global totals for the selected date
 */

app.get("/api/supervisor/summary", authenticateToken, requireSupervisor, async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);

    const { date } = req.query;
    if (!date) {
      return res.status(400).json({ success: false, error: "date parameter required" });
    }

    // 1) Total target – direct sum
    const targetResult = await client.query(
  `SELECT COALESCE(SUM(t), 0) AS total_target
     FROM (SELECT line_no, style, MAX(target_pcs) AS t
             FROM line_runs WHERE run_date = $1
            GROUP BY line_no, style) s`,
  [date]
);
    const totalTarget = parseFloat(targetResult.rows[0].total_target) || 0;

  // 2) Total sewed (finished garments) – sum of packing operation outputs
const sewedResult = await client.query(
  `SELECT COALESCE(SUM(se.sewed_qty), 0) AS total_sewed
   FROM line_runs lr
   JOIN run_operators ro ON lr.id = ro.run_id
   JOIN operator_operations oo ON ro.id = oo.run_operator_id
   JOIN operation_sewed_entries se ON oo.id = se.operation_id
   WHERE lr.run_date = $1
     AND (oo.operation_name ILIKE '%pack%' OR oo.operation_name ILIKE '%emp%')`,
  [date]
);
const totalSewed = parseFloat(sewedResult.rows[0].total_sewed) || 0;
// 👇 ADD THIS LOG
console.log(`[DEBUG] Summary for ${date}: totalSewed = ${totalSewed}`);

    // 3) Total operators – distinct count
    const operatorsResult = await client.query(
      `SELECT COUNT(DISTINCT ro.operator_no) as total_operators
       FROM run_operators ro
       JOIN line_runs lr ON ro.run_id = lr.id
       WHERE lr.run_date = $1`,
      [date]
    );
    const totalOperators = parseInt(operatorsResult.rows[0].total_operators) || 0;


// 4) Efficiency – using packing output (finished garments) to count total SAM produced
const efficiencyResult = await client.query(
  `
  WITH run_available_minutes AS (
    -- Capacity once per (line, style): a color split shares one crew, so
    -- 12 operators for BLA + 12 for NEG of the same style counts as 12, not 24.
    SELECT
      line_no,
      style,
      MAX(working_hours * operators_count * 60) AS available_minutes
    FROM line_runs
    WHERE run_date = $1
    GROUP BY line_no, style
  ),
  run_packing_totals AS (
    -- Production still sums across every run/color.
    SELECT
      lr.id AS run_id,
      lr.sam_minutes,
      COALESCE(SUM(se.sewed_qty), 0) AS packing_total
    FROM line_runs lr
    JOIN run_operators ro ON lr.id = ro.run_id
    JOIN operator_operations oo ON ro.id = oo.run_operator_id
    LEFT JOIN operation_sewed_entries se ON oo.id = se.operation_id
    WHERE lr.run_date = $1
      AND (oo.operation_name ILIKE '%pack%' OR oo.operation_name ILIKE '%emp%')
    GROUP BY lr.id, lr.sam_minutes
  )
  SELECT
    COALESCE((SELECT SUM(available_minutes) FROM run_available_minutes), 0) AS total_available_minutes,
    COALESCE((SELECT SUM(packing_total * sam_minutes) FROM run_packing_totals), 0) AS total_sam_output;
`,
  [date]
);

    const row = efficiencyResult.rows[0];
    const totalSamOutput = parseFloat(row.total_sam_output) || 0;
    const totalAvailableMinutes = parseFloat(row.total_available_minutes) || 0;
    const overallEfficiency = totalAvailableMinutes > 0 ? (totalSamOutput / totalAvailableMinutes) * 100 : 0;

    // 5) Target achievement
    const targetAchievement = totalTarget > 0 ? (totalSewed / totalTarget) * 100 : 0;

    res.json({
      success: true,
      date,
      summary: {
        totalTarget: Math.round(totalTarget * 100) / 100,
        totalSewed: Math.round(totalSewed * 100) / 100,
        totalOperators,
        targetAchievement: Math.round(targetAchievement * 100) / 100,
        overallEfficiency: Math.round(overallEfficiency * 100) / 100,
      },
    });
  } catch (err) {
    console.error("❌ /api/supervisor/summary error:", err.message);
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});

/**
 * GET /api/supervisor/alert-count?date=YYYY-MM-DD
 * Returns count of operators with production alerts (variance > 10% or production zero)
 */
app.get("/api/supervisor/alert-count", authenticateToken, requireSupervisor, async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);

    const { date } = req.query;
    if (!date) {
      return res.status(400).json({ success: false, error: "date parameter required" });
    }

    const alertQuery = `
      WITH operator_planned AS (
        SELECT 
          ro.operator_no,
          COALESCE(SUM(h.stitched_qty), 0) AS planned_total
        FROM line_runs lr
        JOIN run_operators ro ON lr.id = ro.run_id
        JOIN operator_operations oo ON ro.id = oo.run_operator_id
        LEFT JOIN operation_hourly_entries h ON oo.id = h.operation_id
        WHERE lr.run_date = $1
        GROUP BY ro.operator_no
      ),
      operator_actual AS (
        SELECT 
          ro.operator_no,
          COALESCE(SUM(se.sewed_qty), 0) AS actual_total
        FROM line_runs lr
        JOIN run_operators ro ON lr.id = ro.run_id
        JOIN operator_operations oo ON ro.id = oo.run_operator_id
        LEFT JOIN operation_sewed_entries se ON oo.id = se.operation_id
        WHERE lr.run_date = $1
        GROUP BY ro.operator_no
      )
      SELECT COUNT(*) AS alert_count
      FROM operator_planned p
      JOIN operator_actual a ON p.operator_no = a.operator_no
      WHERE a.actual_total < p.planned_total * 0.9
         OR (p.planned_total > 0 AND a.actual_total = 0);
    `;

    const result = await client.query(alertQuery, [date]);
    const alertCount = parseInt(result.rows[0].alert_count) || 0;

    res.json({ success: true, date, alertCount });
  } catch (err) {
    console.error("❌ /api/supervisor/alert-count error:", err.message);
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});

/**
 * GET /api/supervisor/line-performance?date=YYYY-MM-DD
 * Returns per-line: line_no, totalTarget, totalSewed, achievement, operators
 */

app.get("/api/supervisor/line-performance", authenticateToken, requireSupervisor, async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);

    const { date } = req.query;
    if (!date) {
      return res.status(400).json({ success: false, error: "date parameter required" });
    }

    // Current time in the server's timezone (you may want to use client time later)
    const now = new Date();
    const todayStr = date; // YYYY-MM-DD

    const query = `
      WITH line_targets AS (
        SELECT lr.id AS run_id, lr.line_no, lr.target_pcs AS total_target
        FROM line_runs lr
        WHERE lr.run_date = $1
      ),
      -- Get all slots with their targets for each line
      line_slots AS (
        SELECT
          lt.line_no,
          ss.slot_start,
          ss.slot_end,
          st.slot_target
        FROM line_targets lt
        JOIN shift_slots ss ON lt.run_id = ss.run_id
        LEFT JOIN slot_targets st ON ss.id = st.slot_id
        WHERE ss.slot_start IS NOT NULL AND ss.slot_end IS NOT NULL
      ),
      -- Compute real‑time cumulative for each line
      line_realtime AS (
        SELECT
          line_no,
          SUM(
            CASE
              WHEN $2::timestamp AT TIME ZONE 'UTC' >= (($1 || ' ' || slot_end)::timestamp) THEN slot_target
              WHEN $2::timestamp AT TIME ZONE 'UTC' >= (($1 || ' ' || slot_start)::timestamp)
                   AND $2::timestamp AT TIME ZONE 'UTC' < (($1 || ' ' || slot_end)::timestamp)
              THEN slot_target * (
                EXTRACT(EPOCH FROM ($2::timestamp AT TIME ZONE 'UTC' - ($1 || ' ' || slot_start)::timestamp)) /
                EXTRACT(EPOCH FROM (($1 || ' ' || slot_end)::timestamp - ($1 || ' ' || slot_start)::timestamp))
              )
              ELSE 0
            END
          ) AS realtime_target
        FROM line_slots
        GROUP BY line_no
      ),
      operator_production AS (
        SELECT 
          lr.line_no,
          ro.operator_no,
          COALESCE(SUM(se.sewed_qty), 0) AS operator_production
        FROM line_runs lr
        JOIN run_operators ro ON lr.id = ro.run_id
        JOIN operator_operations oo ON ro.id = oo.run_operator_id
        LEFT JOIN operation_sewed_entries se ON oo.id = se.operation_id
        WHERE lr.run_date = $1
          AND (oo.operation_name ILIKE '%pack%' OR oo.operation_name ILIKE '%emp%')
        GROUP BY lr.line_no, ro.operator_no
      ),
      line_sewed AS (
        SELECT line_no, SUM(operator_production) AS total_sewed
        FROM operator_production
        GROUP BY line_no
      ),
      line_operators AS (
        SELECT lr.line_no, COUNT(DISTINCT ro.operator_no) AS operators_count
        FROM line_runs lr
        JOIN run_operators ro ON lr.id = ro.run_id
        WHERE lr.run_date = $1
        GROUP BY lr.line_no
      )
      SELECT 
        lt.line_no,
        lt.total_target,
        COALESCE(ls.total_sewed, 0) AS total_sewed,
        COALESCE(lo.operators_count, 0) AS operators_count,
        COALESCE(lr.realtime_target, 0) AS realtime_target,
        CASE 
          WHEN lt.total_target > 0 
          THEN (COALESCE(ls.total_sewed, 0) / lt.total_target) * 100 
          ELSE 0 
        END AS achievement
      FROM line_targets lt
      LEFT JOIN line_sewed ls ON lt.line_no = ls.line_no
      LEFT JOIN line_operators lo ON lt.line_no = lo.line_no
      LEFT JOIN line_realtime lr ON lt.line_no = lr.line_no
      ORDER BY lt.line_no;
    `;

    const result = await client.query(query, [date, now]);

    const lines = result.rows.map((row) => ({
      lineNo: row.line_no,
      totalTarget: parseFloat(row.total_target) || 0,
      totalSewed: parseFloat(row.total_sewed) || 0,
      operators: parseInt(row.operators_count) || 0,
      realtimeTarget: Math.round(parseFloat(row.realtime_target) * 100) / 100, // two decimals
      achievement: Math.round((parseFloat(row.achievement) || 0) * 100) / 100,
    }));

    res.json({ success: true, date, lines });
  } catch (err) {
    console.error("❌ /api/supervisor/line-performance error:", err.message);
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});

app.get("/api/supervisor/line-performance", authenticateToken, requireSupervisor, async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);

    const { date } = req.query;
    if (!date) {
      return res.status(400).json({ success: false, error: "date parameter required" });
    }

    // Current time in the server's timezone (you may want to use client time later)
    const now = new Date();
    const todayStr = date; // YYYY-MM-DD

    const query = `
      WITH line_targets AS (
        SELECT lr.id AS run_id, lr.line_no, lr.target_pcs AS total_target
        FROM line_runs lr
        WHERE lr.run_date = $1
      ),
      -- Get all slots with their targets for each line
      line_slots AS (
        SELECT
          lt.line_no,
          ss.slot_start,
          ss.slot_end,
          st.slot_target
        FROM line_targets lt
        JOIN shift_slots ss ON lt.run_id = ss.run_id
        LEFT JOIN slot_targets st ON ss.id = st.slot_id
        WHERE ss.slot_start IS NOT NULL AND ss.slot_end IS NOT NULL
      ),
      -- Compute real‑time cumulative for each line
      line_realtime AS (
        SELECT
          line_no,
          SUM(
            CASE
              WHEN $2::timestamp AT TIME ZONE 'UTC' >= (($1 || ' ' || slot_end)::timestamp) THEN slot_target
              WHEN $2::timestamp AT TIME ZONE 'UTC' >= (($1 || ' ' || slot_start)::timestamp)
                   AND $2::timestamp AT TIME ZONE 'UTC' < (($1 || ' ' || slot_end)::timestamp)
              THEN slot_target * (
                EXTRACT(EPOCH FROM ($2::timestamp AT TIME ZONE 'UTC' - ($1 || ' ' || slot_start)::timestamp)) /
                EXTRACT(EPOCH FROM (($1 || ' ' || slot_end)::timestamp - ($1 || ' ' || slot_start)::timestamp))
              )
              ELSE 0
            END
          ) AS realtime_target
        FROM line_slots
        GROUP BY line_no
      ),
      operator_production AS (
        SELECT 
          lr.line_no,
          ro.operator_no,
          COALESCE(SUM(se.sewed_qty), 0) AS operator_production
        FROM line_runs lr
        JOIN run_operators ro ON lr.id = ro.run_id
        JOIN operator_operations oo ON ro.id = oo.run_operator_id
        LEFT JOIN operation_sewed_entries se ON oo.id = se.operation_id
        WHERE lr.run_date = $1
          AND (oo.operation_name ILIKE '%pack%' OR oo.operation_name ILIKE '%emp%')
        GROUP BY lr.line_no, ro.operator_no
      ),
      line_sewed AS (
        SELECT line_no, SUM(operator_production) AS total_sewed
        FROM operator_production
        GROUP BY line_no
      ),
      line_operators AS (
        SELECT lr.line_no, COUNT(DISTINCT ro.operator_no) AS operators_count
        FROM line_runs lr
        JOIN run_operators ro ON lr.id = ro.run_id
        WHERE lr.run_date = $1
        GROUP BY lr.line_no
      )
      SELECT 
        lt.line_no,
        lt.total_target,
        COALESCE(ls.total_sewed, 0) AS total_sewed,
        COALESCE(lo.operators_count, 0) AS operators_count,
        COALESCE(lr.realtime_target, 0) AS realtime_target,
        CASE 
          WHEN lt.total_target > 0 
          THEN (COALESCE(ls.total_sewed, 0) / lt.total_target) * 100 
          ELSE 0 
        END AS achievement
      FROM line_targets lt
      LEFT JOIN line_sewed ls ON lt.line_no = ls.line_no
      LEFT JOIN line_operators lo ON lt.line_no = lo.line_no
      LEFT JOIN line_realtime lr ON lt.line_no = lr.line_no
      ORDER BY lt.line_no;
    `;

    const result = await client.query(query, [date, now]);

    const lines = result.rows.map((row) => ({
      lineNo: row.line_no,
      totalTarget: parseFloat(row.total_target) || 0,
      totalSewed: parseFloat(row.total_sewed) || 0,
      operators: parseInt(row.operators_count) || 0,
      realtimeTarget: Math.round(parseFloat(row.realtime_target) * 100) / 100, // two decimals
      achievement: Math.round((parseFloat(row.achievement) || 0) * 100) / 100,
    }));

    res.json({ success: true, date, lines });
  } catch (err) {
    console.error("❌ /api/supervisor/line-performance error:", err.message);
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});

// ========== planning api endpoints ==========

/**
 * Shared helper: returns per-line daily capacity for a given date.
 * Prefers line_runs configured for that exact date; if none exist,
 * falls back to the most recent prior configuration for each line
 * (capacitySource: 'fallback') so planning isn't blocked on days
 * nobody has entered a line_run for yet.
 */
async function getLineCapacityForDate(client, date) {
  // Each line resolves to its OWN most-recent config on/before `date` (else its
  // closest future one), so a line never disappears just because another line
  // ran more recently — that was the cause of "faltan" on future dates.
  const perLine = await client.query(
    `SELECT DISTINCT ON (line_no)
            id, line_no, run_date, style, operators_count, working_hours,
            sam_minutes, efficiency, target_pcs, target_per_hour
       FROM line_runs
      ORDER BY line_no,
               (run_date <= $1) DESC,
               ABS(run_date - $1::date) ASC`,
    [date]
  );
  const lines = perLine.rows;

  // Merge in planner-defined lines (engineering hasn't configured yet) for any
  // line_no not already present. Inlined so this function has no dependency.
  const present = new Set(lines.map((l) => String(l.line_no)));
  const seeds = await client.query(
    `SELECT line_no, operators_count, working_hours, sam_minutes,
            efficiency, target_pcs, target_per_hour
       FROM planner_lines`
  );
  const extra = seeds.rows
    .filter((r) => !present.has(String(r.line_no)))
    .map((r) => ({
      id: null,
      line_no: r.line_no,
      run_date: date,
      style: null,
      operators_count: r.operators_count,
      working_hours: r.working_hours,
      sam_minutes: r.sam_minutes,
      efficiency: r.efficiency,
      target_pcs: r.target_pcs,
      target_per_hour: r.target_per_hour,
    }));

    const allLines = extra.length ? [...lines, ...extra] : lines;

  // Apply CEO-approved per-style efficiency overrides for the Plan Board ONLY.
  // These recompute the line's capacity (efficiency + target_pcs) in memory for
  // this date's calculation. The stored line_runs / slot_targets (production
  // targets) are never modified — this is the "plan-board-only" behavior.
  try {
    const ov = await client.query(
      "SELECT UPPER(TRIM(style)) AS k, efficiency FROM style_efficiency_overrides"
    );
    if (ov.rows.length) {
      const overrideByStyle = new Map(ov.rows.map((r) => [r.k, parseFloat(r.efficiency)]));
      for (const l of allLines) {
        const key = String(l.style || "").trim().toUpperCase();
        const eff = key ? overrideByStyle.get(key) : null;
        if (eff != null && eff > 0) {
          const ops = parseInt(l.operators_count, 10) || 0;
          const wh = parseFloat(l.working_hours) || 0;
          const sam = parseFloat(l.sam_minutes) || 0;
          const piecesAt100 = sam > 0 ? (ops * wh * 60) / sam : 0;
          l.efficiency = eff;
          l.target_pcs = piecesAt100 * eff;
          l.target_per_hour = wh > 0 ? l.target_pcs / wh : 0;
        }
      }
    }
  } catch { /* overrides are best-effort; never block capacity */ }

  return {
    lines: allLines,
    capacitySource: lines.length ? "per-line" : (allLines.length ? "planner" : "none"),
    capacityDate: date,
  };

}

// GET /api/planning/lines — planner-defined lines (engineering hasn't
// configured them yet). The board shows these as empty lines so orders can be
// dropped before any run exists.
app.get("/api/planning/lines", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
    const result = await client.query(
      `SELECT line_no, operators_count, working_hours, sam_minutes,
              efficiency, target_pcs, target_per_hour, created_at
         FROM planner_lines ORDER BY line_no::int`
    );
    res.json({ success: true, lines: result.rows });
  } catch (err) {
    console.error("❌ Error listing planner lines:", err.message);
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});
// POST /api/planning/lines — create a planner line (not configured by
// engineering). Stored in planner_lines, NOT line_runs. Assigning an order to
// it later auto-creates a draft run. efficiency accepts 0.85 or 85.
app.post(
  "/api/planning/lines",
  authenticateToken,
  async (req, res) => {
    const client = await pool.connect();
    try {
      await setSchema(client);
      const { lineNo, operatorsCount, workingHours, efficiency, samMinutes } = req.body;
      const line = String(lineNo ?? "").trim();
      if (!line) return res.status(400).json({ success: false, error: "lineNo is required" });

      const existingRun = await client.query("SELECT 1 FROM line_runs WHERE line_no = $1 LIMIT 1", [line]);
      if (existingRun.rowCount > 0) {
        return res.status(409).json({ success: false, error: `La línea ${line} ya está configurada por ingeniería.` });
      }

      const operators = Number.isFinite(+operatorsCount) && +operatorsCount > 0 ? Math.floor(+operatorsCount) : 20;
      const hours = Number.isFinite(+workingHours) && +workingHours > 0 ? +workingHours : 8;
      let eff = Number.isFinite(+efficiency) && +efficiency > 0 ? +efficiency : 0.85;
      if (eff > 1) eff = eff / 100;
      if (eff > 1) eff = 1;
      const sam = Number.isFinite(+samMinutes) && +samMinutes > 0 ? +samMinutes : 3.5;
      const targetPcs = Math.round((operators * hours * 60 * eff) / sam);
      const targetPerHour = hours > 0 ? Math.round(targetPcs / hours) : 0;

      const result = await client.query(
        `INSERT INTO planner_lines
           (line_no, operators_count, working_hours, sam_minutes, efficiency,
            target_pcs, target_per_hour, created_by, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())
         ON CONFLICT (line_no) DO UPDATE
           SET operators_count = EXCLUDED.operators_count,
               working_hours   = EXCLUDED.working_hours,
               sam_minutes     = EXCLUDED.sam_minutes,
               efficiency      = EXCLUDED.efficiency,
               target_pcs      = EXCLUDED.target_pcs,
               target_per_hour = EXCLUDED.target_per_hour,
               updated_at      = NOW()
         RETURNING *`,
        [line, operators, hours, sam, eff, targetPcs, targetPerHour, req.user?.username || null]
      );
      res.json({ success: true, line: result.rows[0] });
    } catch (err) {
      console.error("❌ Error creating planner line:", err.message);
      res.status(500).json({ success: false, error: err.message });
    } finally {
      client.release();
    }
  }
);
// DELETE /api/planning/lines/:lineNo — remove a planner line (blocked if it
// still has assignments).
app.delete(
  "/api/planning/lines/:lineNo",
  authenticateToken,
  async (req, res) => {
    const client = await pool.connect();
    try {
      await setSchema(client);
      const line = String(req.params.lineNo ?? "").trim();
      const used = await client.query(
        `SELECT COUNT(*)::int AS n FROM line_assignments
          WHERE line_no = $1 AND status NOT IN ('cancelled', 'rejected')`,
        [line]
      );
      if ((used.rows[0]?.n || 0) > 0) {
        return res.status(409).json({ success: false, error: `La línea ${line} tiene asignaciones. Quítelas primero.` });
      }
      await client.query("DELETE FROM planner_lines WHERE line_no = $1", [line]);
      res.json({ success: true, lineNo: line });
    } catch (err) {
      console.error("❌ Error deleting planner line:", err.message);
      res.status(500).json({ success: false, error: err.message });
    } finally {
      client.release();
    }
  }
);

// POST /api/run/:runId/confirm — clear the draft flag on an auto-created run.
app.post(
  "/api/run/:runId/confirm",
  authenticateToken,
  async (req, res) => {
    const client = await pool.connect();
    try {
      await setSchema(client);
      const runId = parseInt(req.params.runId);
      const r = await client.query(
        "UPDATE line_runs SET is_draft = false, updated_at = NOW() WHERE id = $1 RETURNING id, line_no, run_date, style, is_draft",
        [runId]
      );
      if (r.rowCount === 0) return res.status(404).json({ success: false, error: "Run not found" });
      res.json({ success: true, run: r.rows[0] });
    } catch (err) {
      console.error("❌ Error confirming run:", err.message);
      res.status(500).json({ success: false, error: err.message });
    } finally {
      client.release();
    }
  }
);
/**
 * GET /api/planning/available-lines?date=YYYY-MM-DD
 * Per-line capacity for a date, minus whatever is already assigned that date.
 */
app.get("/api/planning/available-lines", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
    const { date } = req.query;
    if (!date) {
      return res.status(400).json({ success: false, error: "date parameter is required" });
    }

    const { lines, capacitySource, capacityDate } = await getLineCapacityForDate(client, date);

    const assignedResult = await client.query(
      `SELECT line_no, COALESCE(SUM(assigned_quantity), 0) as assigned
       FROM line_assignments
       WHERE assigned_date = $1 AND status NOT IN ('cancelled', 'rejected')
       GROUP BY line_no`,
      [date]
    );
    const assignedByLine = {};
    assignedResult.rows.forEach((r) => { assignedByLine[r.line_no] = parseFloat(r.assigned) || 0; });

    // ── add: pre-order holds occupy capacity too ──
    try {
      const heldResult = await client.query(
        `SELECT line_no, COALESCE(SUM(quantity), 0) AS held
           FROM pre_order_day_holds
          WHERE assigned_date = $1
          GROUP BY line_no`,
        [date]
      );
      heldResult.rows.forEach((r) => {
        assignedByLine[r.line_no] = (assignedByLine[r.line_no] || 0) + (parseFloat(r.held) || 0);
      });
    } catch (e) {
      console.warn("⚠️  pre_order_day_holds not available for capacity:", e.message);
    }

    // Which work orders make up each line's load that day (for the dashboard bar)
    const workOrdersResult = await client.query(
      `SELECT la.line_no,
              wo.work_order_no,
              SUM(la.assigned_quantity) as assigned_quantity
       FROM line_assignments la
       JOIN work_orders wo ON wo.id = la.work_order_id
       WHERE la.assigned_date = $1 AND la.status NOT IN ('cancelled', 'rejected')
       GROUP BY la.line_no, wo.work_order_no
       ORDER BY assigned_quantity DESC`,
      [date]
    );
    const workOrdersByLine = {};
    workOrdersResult.rows.forEach((r) => {
      if (!workOrdersByLine[r.line_no]) workOrdersByLine[r.line_no] = [];
      workOrdersByLine[r.line_no].push({
        work_order_no: r.work_order_no,
        assigned_quantity: Math.round((parseFloat(r.assigned_quantity) || 0) * 100) / 100,
      });
    });
        // Días festivos / paros close the day for the whole plant (line_no NULL) or
    // for a single line. A blocked line reports zero available capacity so the
    // board won't spill work onto it. Best-effort: ignore if the module is absent.
    let plantHoliday = null;
    const lineHolidays = new Set();
    try {
      const hrows = await registerHolidays.holidaysBetween(client, { from: date, to: date });
      for (const h of hrows) {
        if (h.line_no == null) plantHoliday = h;
        else lineHolidays.add(String(h.line_no));
      }
    } catch (e) {
      console.warn("⚠️  holidays not available for capacity:", e.message);
    }

    const linesWithAvailability = lines.map((line) => {
      const targetPcs = parseFloat(line.target_pcs) || 0;
      const assigned = assignedByLine[line.line_no] || 0;
      const blocked = !!plantHoliday || lineHolidays.has(String(line.line_no));
      const available = blocked ? 0 : Math.max(0, targetPcs - assigned);
      const utilizationPercentage = targetPcs > 0 ? (assigned / targetPcs) * 100 : 0;
      return {
        ...line,
        assigned_quantity: Math.round(assigned * 100) / 100,
        available_capacity: Math.round(available * 100) / 100,
        utilization_percentage: Math.round(utilizationPercentage * 10) / 10,
        holiday: blocked ? (plantHoliday || { line_no: line.line_no }) : null,
      };
    });

    res.json({ success: true, lines: linesWithAvailability, capacitySource, capacityDate, holiday: plantHoliday || null });
    
  } catch (err) {
    console.error("❌ Error fetching available lines:", err.message);
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});

app.get("/api/planning/line-work-orders", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
    const { line, date } = req.query;
    if (line == null || String(line).trim() === "") {
      return res.status(400).json({ success: false, error: "line parameter is required" });
    }

    const params = [String(line)]; // line_assignments.line_no is TEXT
    let query = `
      SELECT
        la.id              AS assignment_id,
        la.work_order_id,
        la.line_no,
        la.assigned_date,
        la.assigned_quantity,
        la.planned_start_date,
        la.planned_end_date,
        la.priority,
        la.status          AS assignment_status,
        wo.work_order_no,
        wo.customer_name,
        wo.style_description,
        wo.style_code,
        wo.estilo,
        wo.color,
        wo.total_to_produce,
        wo.commitment_date,
        wo.sam_minutes     AS sam,
        wo.status          AS work_order_status,
        mc.type            AS tipo,
        mc.modelo          AS modelo,
        mc.correlativo     AS correlativo,
        mc.color           AS mc_color,
        -- style = tipo‖modelo‖correlativo (e.g. DAM+BOD+01 = DAMBOD01); falls back
        -- to the client estilo / style_code when there is no master code linked.
        COALESCE(NULLIF(TRIM(CONCAT(mc.type, mc.modelo, mc.correlativo)), ''), wo.estilo, wo.style_code, '') AS style_from_code,
        COALESCE(NULLIF(mc.color, ''), wo.color, '') AS order_color
      FROM line_assignments la
      JOIN work_orders wo ON wo.id = la.work_order_id
      LEFT JOIN master_codes mc ON mc.id = wo.master_code_id
      WHERE la.line_no = $1
        AND la.status <> 'cancelled'
    `;
    if (date) {
      params.push(date);
      query += ` AND la.assigned_date = $${params.length}`;
    }
    query += ` ORDER BY la.priority DESC, la.assigned_date ASC, la.created_at DESC;`;

    const result = await client.query(query, params);
    res.json({ success: true, workOrders: result.rows });
  } catch (err) {
    console.error("❌ Error fetching planning line work orders:", err.message);
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});

/**
 * GET /api/planning/dashboard?date=YYYY-MM-DD
 */
app.get("/api/planning/dashboard", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
    const { date } = req.query;
    if (!date) {
      return res.status(400).json({ success: false, error: "date parameter is required" });
    }

    const orderCounts = await client.query(`
      SELECT
        COUNT(*) FILTER (WHERE status != 'cancelled') as total_work_orders,
        COUNT(*) FILTER (WHERE status = 'pending') as pending_orders,
        COUNT(*) FILTER (WHERE status = 'assigned') as assigned_orders,
        COUNT(*) FILTER (WHERE status = 'completed') as completed_orders
      FROM work_orders
    `);

    const assignedResult = await client.query(
      `SELECT COALESCE(SUM(assigned_quantity), 0) as total, COUNT(DISTINCT line_no) as lines_utilized
       FROM line_assignments WHERE assigned_date = $1 AND status NOT IN ('cancelled', 'rejected')`,
      [date]
    );

    const { lines, capacitySource, capacityDate } = await getLineCapacityForDate(client, date);
    const totalCapacity = lines.reduce((sum, l) => sum + (parseFloat(l.target_pcs) || 0), 0);
    const totalAssigned = parseFloat(assignedResult.rows[0].total) || 0;
    const capacityUtilization = totalCapacity > 0 ? (totalAssigned / totalCapacity) * 100 : 0;

    const deadlinesResult = await client.query(
      `SELECT
         wo.id, wo.work_order_no, wo.customer_name, wo.commitment_date,
         la.line_no, la.assigned_quantity, la.planned_end_date
       FROM work_orders wo
       JOIN line_assignments la ON la.work_order_id = wo.id
       WHERE wo.status NOT IN ('completed', 'cancelled')
         AND la.status NOT IN ('cancelled', 'rejected')
         AND la.planned_end_date BETWEEN $1::date AND $1::date + INTERVAL '3 days'
       ORDER BY la.planned_end_date ASC
       LIMIT 20`,
      [date]
    );

    res.json({
      success: true,
      summary: {
        total_work_orders: parseInt(orderCounts.rows[0].total_work_orders) || 0,
        pending_orders: parseInt(orderCounts.rows[0].pending_orders) || 0,
        assigned_orders: parseInt(orderCounts.rows[0].assigned_orders) || 0,
        completed_orders: parseInt(orderCounts.rows[0].completed_orders) || 0,
        total_assigned_quantity: totalAssigned,
        capacity_utilization: capacityUtilization,
        lines_utilized: parseInt(assignedResult.rows[0].lines_utilized) || 0,
        active_lines: lines.length,
        capacitySource,
        capacityDate,
      },
      upcomingDeadlines: deadlinesResult.rows,
    });
  } catch (err) {
    console.error("❌ Error fetching planning dashboard:", err.message);
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});

/**
 * GET /api/line-assignments?workOrderId=123
 */

/**
 * GET /api/line-assignments?workOrderId=123
 */
app.get("/api/line-assignments", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
    const { workOrderId, lineNo, date } = req.query;

    let query = `
      SELECT la.*,
             wo.work_order_no,
             wo.style_description,
             wo.customer_name
        FROM line_assignments la
        JOIN work_orders wo ON wo.id = la.work_order_id
       WHERE 1=1`;
    const params = [];
    let paramIndex = 1;
 
    if (workOrderId) {
      query += ` AND la.work_order_id = $${paramIndex++}`;
      params.push(parseInt(workOrderId));
    }
    if (lineNo) {
      query += ` AND la.line_no = $${paramIndex++}`;
      params.push(lineNo);
    }
    if (date) {
      query += ` AND la.assigned_date = $${paramIndex++}`;
      params.push(date);
    }
    query += " ORDER BY la.created_at DESC";

    const result = await client.query(query, params);
    res.json({ success: true, assignments: result.rows });
  } catch (err) {
    console.error("❌ Error fetching line assignments:", err.message);
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});


// Server-side port of the frontend utils/timeSlots.js `buildShiftSlots`. A draft
// run needs the same hourly distribution the engineering save produces, so the
// line engineers see it the moment the planner sends the order — instead of a
// single lumped "Turno" slot. Keep the defaults in sync with the frontend util.
function buildDraftShiftSlots({
  workingHours,
  startHour = 9,
  endHour = 17,
  lunchHour = 13,
  firstSlotHours = 0.75,
  lunchSlotHours = 0.5,
  lastSlotHours = 0.6,
  lastSlotLabelMinutes = 36,
}) {
  const wh = Number(workingHours);
  if (!Number.isFinite(wh) || wh <= 0) return [];

  const pad = (n) => String(n).padStart(2, "0");
  const lastLabel = `${endHour}:${pad(lastSlotLabelMinutes)}`;

  const labels = [];
  for (let h = startHour; h <= endHour; h++) labels.push(`${h}`);
  labels.push(lastLabel);

  const base = labels.map((lab) => {
    const hourOnly = Number(lab.split(":")[0]);
    if (lab === lastLabel) return lastSlotHours;
    if (hourOnly === startHour) return firstSlotHours;
    if (hourOnly === lunchHour) return lunchSlotHours;
    return 1;
  });

  const baseSum = base.reduce((a, b) => a + b, 0) || 1;
  const scale = wh / baseSum;

  const slots = [];
  let currentTime = new Date();
  currentTime.setHours(startHour, 0, 0, 0);

  for (let i = 0; i < labels.length; i++) {
    const hours = Number((base[i] * scale).toFixed(2));
    const endTime = new Date(currentTime.getTime() + hours * 60 * 60 * 1000);
    const startStr = `${pad(currentTime.getHours())}:${pad(currentTime.getMinutes())}:${pad(currentTime.getSeconds())}`;
    const endStr = `${pad(endTime.getHours())}:${pad(endTime.getMinutes())}:${pad(endTime.getSeconds())}`;
    slots.push({ label: labels[i], hours, startTime: startStr, endTime: endStr });
    currentTime = endTime;
  }

  // Correct tiny rounding drift so the slot hours sum to the working hours exactly.
  const sum = slots.reduce((a, s) => a + s.hours, 0);
  const diff = Number((wh - sum).toFixed(2));
  if (Math.abs(diff) >= 0.01 && slots.length > 0) {
    const last = slots[slots.length - 1];
    last.hours = Number((last.hours + diff).toFixed(2));
    const prevEnd = new Date();
    if (slots.length > 1) {
      const [ph, pm, ps] = slots[slots.length - 2].endTime.split(":").map(Number);
      prevEnd.setHours(ph, pm, ps || 0);
    } else {
      prevEnd.setHours(startHour, 0, 0, 0);
    }
    const newEnd = new Date(prevEnd.getTime() + last.hours * 60 * 60 * 1000);
    last.endTime = `${pad(newEnd.getHours())}:${pad(newEnd.getMinutes())}:${pad(newEnd.getSeconds())}`;
  }

  return slots;
}

async function ensureDraftRunForAssignment(client, { lineNo, runDate, workOrderId, style }) {
  const line = String(lineNo);
  if (!runDate) return { runId: null, created: false };
 
  // Style must be resolved BEFORE the existence check — it is part of the key.
  let runStyle = style;
  if (!runStyle && workOrderId != null) {
    const wo = await client.query(
      "SELECT style_code, estilo FROM work_orders WHERE id = $1",
      [workOrderId]
    );
    runStyle = wo.rows[0]?.style_code || wo.rows[0]?.estilo || null;
  }
  runStyle = runStyle || "SIN ESTILO";
 
  // Point this order's cells on this line-day at `runId`, whatever they held
  // before. Re-pointing a stale link is the entire purpose of this step.
  const linkAssignments = async (runId) => {
    const upd = await client.query(
      `UPDATE line_assignments
          SET line_run_id = $1, updated_at = NOW()
        WHERE line_no = $2
          AND assigned_date = $3::date
          AND status NOT IN ('cancelled', 'rejected')
          AND ($4::bigint IS NULL OR work_order_id = $4::bigint)
          AND line_run_id IS DISTINCT FROM $1`,
      [runId, line, runDate, workOrderId ?? null]
    );
    console.log(`   ↳ linked ${upd.rowCount} assignment(s) to run ${runId}`);
    return upd.rowCount;
  };
 
  const existing = await client.query(
    "SELECT id FROM line_runs WHERE line_no = $1 AND run_date = $2::date AND style = $3 LIMIT 1",
    [line, runDate, runStyle]
  );
  if (existing.rowCount > 0) {
    const runId = existing.rows[0].id;
    console.log(`   ↳ run ${runId} already exists for L${line} ${runDate} "${runStyle}"`);
    await linkAssignments(runId);
    return { runId, created: false };
  }
 
  // Template = the line's most recent run, preferring the SAME style. Supplies
  // the capacity numbers and the operator roster. Falls back to planner_lines,
  // then to hardcoded defaults, for a planner-defined line with no runs yet.
  const tpl = await client.query(
    `SELECT id, operators_count, working_hours, sam_minutes, efficiency
       FROM line_runs
      WHERE line_no = $1
      ORDER BY (style = $2) DESC, run_date DESC, created_at DESC
      LIMIT 1`,
    [line, runStyle]
  );
  let src = tpl.rows[0];
  const templateRunId = src?.id ?? null;
  if (!src) {
    const pl = await client.query(
      `SELECT operators_count, working_hours, sam_minutes, efficiency
         FROM planner_lines WHERE line_no = $1`,
      [line]
    );
    src = pl.rows[0];
  }
 
  const operators = parseInt(src?.operators_count) || 20;
  const hours = parseFloat(src?.working_hours) || 8;
  let eff = parseFloat(src?.efficiency) || 0.85;
  if (eff > 1) eff = eff / 100;   // tolerate 85 meaning 0.85
  if (eff > 1) eff = 1;           // chk_efficiency_range: 0 < eff <= 1
  const orderSam = await resolveOrderSam(client, { workOrderId, lineNo: line, runDate, style: runStyle });
  const sam = orderSam || parseFloat(src?.sam_minutes) || 3.5;
  const targetPcs = Math.round((operators * hours * 60 * eff) / sam);
  const targetPerHour = hours > 0 ? Math.round(targetPcs / hours) : 0;
 
  console.log(
    `   ↳ inserting draft L${line} ${runDate} "${runStyle}" ` +
    `(ops=${operators} h=${hours} sam=${sam} eff=${eff} target=${targetPcs}) tpl=${templateRunId}`
  );
 
  const ins = await client.query(
    `INSERT INTO line_runs
       (line_no, run_date, style, operators_count, working_hours, sam_minutes,
        efficiency, target_pcs, target_per_hour, work_order_id, is_draft, created_at, updated_at)
     VALUES ($1, $2::date, $3, $4, $5, $6, $7, $8, $9, $10, true, NOW(), NOW())
     ON CONFLICT ON CONSTRAINT uq_line_run DO NOTHING
     RETURNING id`,
    [line, runDate, runStyle, operators, hours, sam, eff, targetPcs, targetPerHour, workOrderId ?? null]
  );
 
  // Lost a race with a concurrent confirm: adopt the winner instead of bailing.
  if (ins.rowCount === 0) {
    const again = await client.query(
      "SELECT id FROM line_runs WHERE line_no = $1 AND run_date = $2::date AND style = $3 LIMIT 1",
      [line, runDate, runStyle]
    );
    if (!again.rows[0]) {
      console.warn(`   ↳ INSERT did nothing and no row found for L${line} ${runDate} "${runStyle}"`);
      return { runId: null, created: false };
    }
    await linkAssignments(again.rows[0].id);
    return { runId: again.rows[0].id, created: false };
  }
 
  const runId = ins.rows[0].id;
  console.log(`   ↳ created run ${runId}`);
 
    // Give the draft the full hourly time-slot distribution (the same breakdown the
  // engineering save produces), so line engineers see it as soon as the planner
  // sends the order. Fall back to a single "Turno" slot only if hours are unbuildable.
  const draftSlots = buildDraftShiftSlots({ workingHours: hours });
  if (draftSlots.length > 0) {
    for (let i = 0; i < draftSlots.length; i++) {
      const s = draftSlots[i];
      await client.query(
        `INSERT INTO shift_slots (run_id, slot_order, slot_label, slot_start, slot_end, planned_hours)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [runId, i + 1, s.label, s.startTime || null, s.endTime || null, s.hours]
      );
    }
  } else {
    await client.query(
      `INSERT INTO shift_slots (run_id, slot_order, slot_label, slot_start, slot_end, planned_hours)
       VALUES ($1, 1, $2, NULL, NULL, $3)`,
      [runId, "Turno", hours]
    );
  }
 
    // Inherit the operator roster from the template, then the operations each
  // operator runs (time studies + capacity), so line engineers see the full plan
  // in the draft instead of an empty operations panel. Operations are matched to
  // the freshly-copied roster by operator_no.
  if (templateRunId) {
    await client.query(
      `INSERT INTO run_operators (run_id, operator_no, operator_name, created_at)
       SELECT $1, operator_no, operator_name, NOW()
         FROM run_operators WHERE run_id = $2
       ON CONFLICT (run_id, operator_no) DO NOTHING`,
      [runId, templateRunId]
    );

    await client.query(
      `INSERT INTO operator_operations
         (run_id, run_operator_id, operation_name,
          t1_sec, t2_sec, t3_sec, t4_sec, t5_sec, capacity_per_hour, created_at)
       SELECT $1, dst_ro.id, oo.operation_name,
              oo.t1_sec, oo.t2_sec, oo.t3_sec, oo.t4_sec, oo.t5_sec,
              oo.capacity_per_hour, NOW()
         FROM operator_operations oo
         JOIN run_operators src_ro
           ON src_ro.id = oo.run_operator_id AND src_ro.run_id = $2
         JOIN run_operators dst_ro
           ON dst_ro.run_id = $1 AND dst_ro.operator_no = src_ro.operator_no
       ON CONFLICT (run_operator_id, operation_name) DO NOTHING`,
      [runId, templateRunId]
    );
  }
 
  await linkAssignments(runId);
  return { runId, created: true };
}

// Remove an auto-created DRAFT run for a (line, day) once that cell no longer
// has any active planner assignment. Confirmed runs (is_draft = false) — ones a
// line leader already accepted, or that engineering configured directly — are
// never touched, and days that still hold an assignment are left alone. Child
// rows (shift_slots, run_operators, …) cascade on delete; line_assignments.
// line_run_id is ON DELETE SET NULL, so any stray link just clears.
async function cleanupOrphanDraftRuns(client, lineNo, runDate) {
  if (!lineNo || !runDate) return 0;
  const del = await client.query(
    `DELETE FROM line_runs lr
      WHERE lr.line_no = $1
        AND lr.run_date = $2
        AND lr.is_draft = true
        AND NOT EXISTS (
          SELECT 1 FROM line_assignments la
           WHERE la.line_no = lr.line_no
             AND la.assigned_date = lr.run_date
             AND la.status NOT IN ('cancelled', 'rejected')
        )
      RETURNING lr.id`,
    [String(lineNo), runDate]
  );
  return del.rowCount;
}

// ---------------------------------------------------------------------------
// POST /api/line-assignments/confirm
//
// The planner's explicit "send to line leaders" step. Given a set of assignment
// ids (the cells the planner selected), create a DRAFT run for every distinct
// (line, day) among them that doesn't already have a run. This replaces the old
// behaviour where a draft was auto-created on every assign/move — which left a
// stale draft behind each time an order was dragged to a new day.
//
// Body: { ids: number[] }   (assignment ids)
// Returns: { success, created, alreadyPresent, cells, message }
// ---------------------------------------------------------------------------
app.post("/api/line-assignments/confirm", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  console.log("🔵 CONFIRM hit:", JSON.stringify(req.body), "user:", req.user?.id ?? req.user?.username);
  try {
    await setSchema(client);
 
    const idList = Array.isArray(req.body?.ids)
      ? [...new Set(req.body.ids.map((n) => parseInt(n)).filter((n) => Number.isInteger(n)))]
      : [];
    console.log("🔵 idList:", idList);
 
    if (idList.length === 0) {
      return res.status(400).json({ success: false, error: "ids (no vacío) es obligatorio" });
    }
 
    await client.query("BEGIN");
 
    // Resolve the selected assignments to their distinct (line, day, order)
    // cells. COALESCE guards a NULL status, which would otherwise make
    // `status NOT IN (...)` evaluate to NULL and silently drop the row.
    const rows = await client.query(
      `SELECT DISTINCT line_no,
              to_char(assigned_date, 'YYYY-MM-DD') AS run_date,
              work_order_id
         FROM line_assignments
        WHERE id = ANY($1::bigint[])
          AND assigned_date IS NOT NULL
          AND COALESCE(status, 'planned') NOT IN ('cancelled', 'rejected')`,
      [idList]
    );
    console.log("🔵 cells resolved:", rows.rows);
 
    if (rows.rows.length === 0) {
      await client.query("ROLLBACK");
      return res.status(404).json({ success: false, error: "No se encontraron asignaciones para confirmar" });
    }
 
    let created = 0;
    let alreadyPresent = 0;
    let failed = 0;
    const confirmedCells = [];
    const runIds = [];
 
    for (const cell of rows.rows) {
      const lineNo = String(cell.line_no);
      const runDate = cell.run_date;
 
      const { runId, created: isNew } = await ensureDraftRunForAssignment(client, {
        lineNo,
        runDate,
        workOrderId: cell.work_order_id,
        style: null,
      });
 
      if (!runId) {
        failed++;
        console.warn(`🟠 no run produced for L${lineNo} ${runDate} wo=${cell.work_order_id}`);
        continue;
      }
 
      if (isNew) created++;
      else alreadyPresent++;
      runIds.push(runId);
      confirmedCells.push({ lineNo, runDate, runId, isNew });
    }
 
    await client.query("COMMIT");
    console.log(`🟢 CONFIRM done: created=${created} already=${alreadyPresent} failed=${failed} runIds=${runIds}`);
 
    res.json({
      success: true,
      created,
      alreadyPresent,
      failed,
      runIds,
      cells: confirmedCells.length,
      message:
        `Se enviaron ${confirmedCells.length} casilla(s) a los líderes de línea ` +
        `(${created} nueva(s), ${alreadyPresent} ya existente(s)` +
        (failed > 0 ? `, ${failed} con error` : "") + `).`,
    });
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    console.error("❌ CONFIRM failed:", err.code, err.constraint, err.message);
    console.error(err.stack);
    res.status(500).json({ success: false, error: err.message, code: err.code });
  } finally {
    client.release();
  }
});

app.post("/api/line-assignments", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
    await client.query("BEGIN");

    const { workOrderId, lineNo, assignedDate, quantity, plannedStartDate,color  } = req.body;

    if (!workOrderId || !lineNo || !assignedDate || !quantity || parseFloat(quantity) <= 0) {
      await client.query("ROLLBACK");
      return res.status(400).json({ success: false, error: "workOrderId, lineNo, assignedDate and a positive quantity are required" });
    }

    // No production on weekends: reject Sat/Sun assignment dates outright.
    const isWeekendYmd = (ymdStr) => {
      const [y, m, d] = String(ymdStr).split("-").map(Number);
      const dow = new Date(Date.UTC(y, m - 1, d)).getUTCDay(); // 0 = Sun, 6 = Sat
      return dow === 0 || dow === 6;
    };
    if (isWeekendYmd(assignedDate)) {
      await client.query("ROLLBACK");
      return res.status(400).json({ success: false, error: "No se puede asignar en fin de semana (sábado o domingo)." });
    }

    // No production on non-working days (Días festivos / paros). A plant-wide
    // holiday blocks every line; a line-specific one blocks just that line.
    // If the holidays module/table isn't available we don't block assignments.
    try {
      const hol = await registerHolidays.isHoliday(client, { date: assignedDate, lineNo });
      if (hol) {
        await client.query("ROLLBACK");
        const scope = hol.line_no ? `la Línea ${hol.line_no}` : "toda la planta";
        return res.status(400).json({
          success: false,
          error: `${assignedDate} es un día no laborable para ${scope}${hol.name ? ` (${hol.name})` : ""}.`,
          holiday: hol,
        });
      }
    } catch (e) {
      console.warn("⚠️  holiday check skipped:", e.message);
    }

    const woResult = await client.query(
      "SELECT id, total_to_produce, sam_minutes FROM work_orders WHERE id = $1",
      [parseInt(workOrderId)]
    );
    if (woResult.rows.length === 0) {
      await client.query("ROLLBACK");
      return res.status(404).json({ success: false, error: "Work order not found" });
    }
    const workOrder = woResult.rows[0];

    const { lines } = await getLineCapacityForDate(client, assignedDate);
    const lineData = lines.find((l) => l.line_no === lineNo);
    if (!lineData) {
      await client.query("ROLLBACK");
      return res.status(400).json({ success: false, error: `No capacity configuration found for line ${lineNo}` });
    }

    // Prefer the work order's own SAM (from its master code) over the line's generic SAM
    const samMinutes = parseFloat(workOrder.sam_minutes) || parseFloat(lineData.sam_minutes) || 3.5;
    const operators = parseInt(lineData.operators_count) || 20;
    const workingHours = parseFloat(lineData.working_hours) || 8;
    const efficiency = parseFloat(lineData.efficiency) || 0.85;

    const dailyAvailableMinutes = operators * workingHours * 60;
    const effectiveDailyMinutes = dailyAvailableMinutes * efficiency;
    const piecesPerDay = effectiveDailyMinutes / samMinutes;

    const qty = parseFloat(quantity);
    const totalMinutesNeeded = qty * samMinutes;
    const daysNeeded = Math.ceil(totalMinutesNeeded / effectiveDailyMinutes);

    const startDate = plannedStartDate || assignedDate;
    const endDateObj = new Date(startDate);
    endDateObj.setDate(endDateObj.getDate() + daysNeeded);
    const plannedEndDate = endDateObj.toISOString().slice(0, 10);

    // Guard against double-booking beyond the line's daily target for that date
    const alreadyAssignedResult = await client.query(
      `SELECT COALESCE(SUM(assigned_quantity), 0) as total FROM line_assignments
       WHERE line_no = $1 AND assigned_date = $2 AND status NOT IN ('cancelled', 'rejected')`,
      [lineNo, assignedDate]
    );
    const alreadyAssigned = parseFloat(alreadyAssignedResult.rows[0].total) || 0;

    // ── add: holds on this line/day also occupy capacity ──
    let heldOnCell = 0;
    try {
      const heldRes = await client.query(
        `SELECT COALESCE(SUM(quantity), 0) AS total FROM pre_order_day_holds
          WHERE line_no = $1 AND assigned_date = $2`,
        [lineNo, assignedDate]
      );
      heldOnCell = parseFloat(heldRes.rows[0].total) || 0;
    } catch (e) {
      heldOnCell = 0;
    }

    // change this line to also subtract heldOnCell:
    const availableCapacity = Math.max(0, parseFloat(lineData.target_pcs) - alreadyAssigned - heldOnCell);

    if (qty > availableCapacity) {
      await client.query("ROLLBACK");
      return res.status(400).json({
        success: false,
        error: `Line ${lineNo} only has capacity for ${Math.floor(availableCapacity)} pieces on ${assignedDate}`,
      });
    }

    
    // One planned row per (work_order, line, day, color): if this cell already
    // holds pieces of the same order+color, add to that row instead of stacking
    // a second sliver. Spilling to the next day still happens upstream, since
    // the caller only sends what fits in this day's remaining capacity.
    const assignment = await mergeOrInsertAssignment(client, {
      workOrderId: parseInt(workOrderId),
      lineRunId: lineData.id || null,
      lineNo,
      assignedDate,
      quantity: qty,
      availableMinutes: effectiveDailyMinutes,
      requiredRate: piecesPerDay,
      startDate,
      endDate: plannedEndDate,
      status: "planned",
      color: color || null,
    });

    // Move the work order out of 'pending' now that it has at least one assignment
    await client.query(
      "UPDATE work_orders SET status = CASE WHEN status = 'pending' THEN 'assigned' ELSE status END, updated_at = NOW() WHERE id = $1",
      [parseInt(workOrderId)]
    );

    

    await client.query("COMMIT");

    res.json({ success: true, message: "Line assignment created", assignment });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("❌ Error creating line assignment:", err.message);
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});



app.delete("/api/line-assignments/:id", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
    await client.query("BEGIN");

    const { id } = req.params;

    const existing = await client.query(
      "SELECT work_order_id, assigned_date, line_no, to_char(assigned_date, 'YYYY-MM-DD') AS assigned_date_str, (assigned_date < CURRENT_DATE) AS is_past FROM line_assignments WHERE id = $1",
      [parseInt(id)]
    );
    if (existing.rows.length === 0) {
      await client.query("ROLLBACK");
      return res.status(404).json({ success: false, error: "Assignment not found" });
    }
    const delLineNo = String(existing.rows[0].line_no);
    const delDate = existing.rows[0].assigned_date_str;
    // Safety net: never delete a cell dated before today (old assigned quantity).
    if (existing.rows[0].is_past) {
      await client.query("ROLLBACK");
      return res.status(409).json({
        success: false,
        error: "No se puede eliminar una asignación de un día anterior a hoy (cantidad ya asignada).",
      });
    }
    const workOrderId = existing.rows[0].work_order_id;
    const row = existing.rows[0];

    // A cell that already has production behind it must never be hard-deleted:
    // SUM(assigned_quantity) would silently lose pieces that were really sewn,
    // and the board would re-assign work the floor already did.
    const cellProduced =
      Number(row.produced_quantity) > 0
        ? Number(row.produced_quantity)
        : (
            await client.query(
              `SELECT COALESCE(SUM(se.sewed_qty), 0) AS produced
                 FROM line_runs lr
                 JOIN operation_sewed_entries se ON se.run_id = lr.id
                WHERE lr.line_no = $1 AND lr.run_date = $2::date`,
              [String(row.line_no), row.assigned_date]
            )
          ).rows[0].produced;

    if (Number(cellProduced) > 0 && !req.query.force) {
      await client.query("ROLLBACK");
      return res.status(409).json({
        success: false,
        error:
          `Esa celda ya tiene ${Number(cellProduced)} piezas reportadas. ` +
          `Liquidala con /api/line-assignments/settle-day, o repite con ?force=true ` +
          `para cancelarla (no se borra: se conserva el historial).`,
        produced: Number(cellProduced),
        assigned: Number(row.assigned_quantity) || 0,
      });
    }

    if (Number(cellProduced) > 0) {
      // Forced: cancel, never delete. Cancelled rows are excluded from every
      // assigned SUM, so the pool frees up exactly as a delete would, but the
      // produced history survives.
      await client.query(
        `UPDATE line_assignments SET status = 'cancelled', updated_at = NOW() WHERE id = $1`,
        [parseInt(id)]
      );
    } else {
      await client.query("DELETE FROM line_assignments WHERE id = $1", [parseInt(id)]);
    }

    // Whether the cell was hard-deleted or soft-cancelled, the day may now have
    // no active assignment. Drop its unconfirmed draft run so line leaders don't
    // keep seeing a draft for an emptied cell. (Cancelled rows count as inactive,
    // and a cell with real production has a confirmed run, which is never touched.)
    await cleanupOrphanDraftRuns(client, delLineNo, delDate);

    // If no active assignments remain, return the work order to 'pending'
    // (mirror of the POST, which moves 'pending' -> 'assigned').
    const remainingActive = await client.query(
      `SELECT COALESCE(SUM(assigned_quantity), 0) AS total
         FROM line_assignments
        WHERE work_order_id = $1 AND status NOT IN ('cancelled')`,
      [workOrderId]
    );
    const stillAssigned = parseFloat(remainingActive.rows[0].total) || 0;
    if (stillAssigned <= 0) {
      await client.query(
        "UPDATE work_orders SET status = CASE WHEN status = 'assigned' THEN 'pending' ELSE status END, updated_at = NOW() WHERE id = $1",
        [workOrderId]
      );
    }

    await client.query("COMMIT");
    res.json({ success: true, message: "Line assignment removed", workOrderId });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("❌ Error deleting line assignment:", err.message);
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});


// ========== overview api endpoints ==========


/**
 * GET /api/skyrina/style-performance?startDate=YYYY-MM-DD&endDate=YYYY-MM-DD&style=xxx&lineNo=xxx
 * Returns style performance with SAM-based efficiency (most accurate)
 */
/**
 * GET /api/skyrina/style-performance?startDate=YYYY-MM-DD&endDate=YYYY-MM-DD&style=xxx&lineNo=xxx
 * Returns style performance with SAM-based efficiency (most accurate)
 */
app.get("/api/skyrina/style-performance", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
    
    const { startDate, endDate, style, lineNo } = req.query;
    if (!startDate || !endDate) {
      return res.status(400).json({ 
        success: false, 
        error: "startDate and endDate parameters required" 
      });
    }
    
    if (!['skyrina', 'engineer', 'supervisor', 'soporte_it', 'master'].includes(req.user.role)) {
      return res.status(403).json({ success: false, error: "Access denied" });
    }
    
    let query = `
      WITH style_packing_data AS (
        SELECT 
          lr.style,
          lr.run_date,
          lr.sam_minutes,
          lr.operators_count,
          lr.working_hours,
          lr.target_pcs,
          lr.line_no,
          COALESCE(SUM(se.sewed_qty), 0) as total_sewed
        FROM line_runs lr
        JOIN run_operators ro ON lr.id = ro.run_id
        JOIN operator_operations oo ON ro.id = oo.run_operator_id
        LEFT JOIN operation_sewed_entries se ON oo.id = se.operation_id
        WHERE lr.run_date BETWEEN $1 AND $2
          AND (oo.operation_name ILIKE '%pack%' OR oo.operation_name ILIKE '%emp%')
    `;
    
    const params = [startDate, endDate];
    let paramIndex = 3;
    
    if (style && style !== 'all') {
      query += ` AND lr.style = $${paramIndex++}`;
      params.push(style);
    }
    
    if (lineNo && lineNo !== 'all') {
      query += ` AND lr.line_no = $${paramIndex++}`;
      params.push(lineNo);
    }
    
    query += `
        GROUP BY lr.id, lr.style, lr.run_date, lr.sam_minutes, lr.operators_count, lr.working_hours, lr.target_pcs, lr.line_no
      ),
      -- ONE CREW per (day, line, style). A colour split (same style, BLA + NEG)
      -- is the same operators for the same hours, so its target and its capacity
      -- are counted ONCE — taking MAX across the colour rows, not SUM. MAX (and
      -- not MIN/AVG) guards against a stray 0 or half-filled colour row.
      style_crews AS (
        SELECT
          style,
          run_date,
          line_no,
          MAX(target_pcs)                           AS crew_target,
          MAX(operators_count * working_hours * 60) AS crew_available_minutes
        FROM style_packing_data
        GROUP BY style, run_date, line_no
      ),
      style_capacity AS (
        SELECT
          style,
          SUM(crew_target)            AS total_target,
          SUM(crew_available_minutes) AS total_available_minutes
        FROM style_crews
        GROUP BY style
      ),
      -- Output still SUMS across every run/colour: each colour really does sew
      -- and pack its own pieces.
      style_output AS (
        SELECT
          style,
          SUM(total_sewed)               AS total_produced,
          SUM(total_sewed * sam_minutes) AS total_sam_output
        FROM style_packing_data
        GROUP BY style
      )
      SELECT 
        o.style,
        o.total_produced,
        c.total_target,
        o.total_sam_output,
        c.total_available_minutes,
        -- SAM-based efficiency (most accurate): per-colour output over one crew's capacity
        CASE 
          WHEN c.total_available_minutes > 0 
          THEN (o.total_sam_output / c.total_available_minutes) * 100
          ELSE 0
        END as efficiency,
        -- Production compliance (for reference only)
        CASE 
          WHEN c.total_target > 0 
          THEN (o.total_produced / c.total_target) * 100 
          ELSE 0 
        END as compliance
      FROM style_output o
      JOIN style_capacity c ON c.style IS NOT DISTINCT FROM o.style
      ORDER BY efficiency DESC
    `;
    
    const result = await client.query(query, params);
    
    const styles = result.rows.map(row => ({
      style: row.style || 'No Style',
      target: parseFloat(row.total_target) || 0,
      produced: parseFloat(row.total_produced) || 0,
      efficiency: parseFloat(row.efficiency) || 0,  // SAM-based efficiency
      compliance: parseFloat(row.compliance) || 0,  // Production compliance
      total_sam_output: parseFloat(row.total_sam_output) || 0,
      total_available_minutes: parseFloat(row.total_available_minutes) || 0
    }));
    
    res.json({
      success: true,
      period: { startDate, endDate },
      styles
    });
  } catch (err) {
    console.error("❌ Error fetching style performance:", err.message);
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});

/**
 * GET /api/skyrina/line-performance-detail?startDate=YYYY-MM-DD&endDate=YYYY-MM-DD&style=xxx&lineNo=xxx
 * Returns line performance with SAM-based efficiency
 */
app.get("/api/skyrina/line-performance-detail", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
    
    const { startDate, endDate, style, lineNo } = req.query;
    if (!startDate || !endDate) {
      return res.status(400).json({ 
        success: false, 
        error: "startDate and endDate parameters required" 
      });
    }
    
    if (!['skyrina', 'engineer', 'supervisor', 'soporte_it', 'master'].includes(req.user.role)) {
      return res.status(403).json({ success: false, error: "Access denied" });
    }
    
    let query = `
      WITH line_packing_data AS (
        SELECT 
          lr.style,
          lr.line_no,
          lr.run_date,
          lr.sam_minutes,
          lr.operators_count,
          lr.working_hours,
          lr.target_pcs,
          COALESCE(SUM(se.sewed_qty), 0) as total_sewed
        FROM line_runs lr
        JOIN run_operators ro ON lr.id = ro.run_id
        JOIN operator_operations oo ON ro.id = oo.run_operator_id
        LEFT JOIN operation_sewed_entries se ON oo.id = se.operation_id
        WHERE lr.run_date BETWEEN $1 AND $2
          AND (oo.operation_name ILIKE '%pack%' OR oo.operation_name ILIKE '%emp%')
    `;
    
    const params = [startDate, endDate];
    let paramIndex = 3;
    
    if (style && style !== 'all') {
      query += ` AND lr.style = $${paramIndex++}`;
      params.push(style);
    }
    
    if (lineNo && lineNo !== 'all') {
      query += ` AND lr.line_no = $${paramIndex++}`;
      params.push(lineNo);
    }
    
    query += `
        GROUP BY lr.id, lr.style, lr.line_no, lr.run_date, lr.sam_minutes, lr.operators_count, lr.working_hours, lr.target_pcs
      ),
      -- ONE CREW per (day, line, style): a colour split shares the crew, so its
      -- target/capacity is counted once (MAX across colours), never summed.
      line_crews AS (
        SELECT
          style,
          line_no,
          run_date,
          MAX(target_pcs)                           AS crew_target,
          MAX(operators_count * working_hours * 60) AS crew_available_minutes
        FROM line_packing_data
        GROUP BY style, line_no, run_date
      ),
      line_capacity AS (
        SELECT
          style,
          line_no,
          SUM(crew_target)            AS total_target,
          SUM(crew_available_minutes) AS total_available_minutes
        FROM line_crews
        GROUP BY style, line_no
      ),
      -- Produced/SAM output still sums across every colour.
      line_output AS (
        SELECT
          style,
          line_no,
          SUM(total_sewed)               AS total_produced,
          SUM(total_sewed * sam_minutes) AS total_sam_output
        FROM line_packing_data
        GROUP BY style, line_no
      ),
      line_aggregates AS (
        SELECT
          o.style,
          o.line_no,
          o.total_produced,
          c.total_target,
          o.total_sam_output,
          c.total_available_minutes
        FROM line_output o
        JOIN line_capacity c
          ON c.line_no = o.line_no
         AND c.style IS NOT DISTINCT FROM o.style
      )
      SELECT 
        style,
        line_no,
        total_target as target,
        total_produced as produced,
        -- SAM-based efficiency
        CASE 
          WHEN total_available_minutes > 0 
          THEN (total_sam_output / total_available_minutes) * 100
          ELSE 0
        END as efficiency,
        -- Production compliance (for reference)
        CASE 
          WHEN total_target > 0 
          THEN (total_produced / total_target) * 100 
          ELSE 0 
        END as compliance
      FROM line_aggregates
      ORDER BY line_no::int, efficiency DESC
    `;
    
    const result = await client.query(query, params);
    
    const lines = result.rows.map(row => ({
      style: row.style || 'No Style',
      lineNo: row.line_no,
      target: Math.round(parseFloat(row.target) * 100) / 100,
      produced: Math.round(parseFloat(row.produced) * 100) / 100,
      efficiency: parseFloat(row.efficiency) || 0,  // SAM-based efficiency
      compliance: parseFloat(row.compliance) || 0   // Production compliance
    }));
    
    res.json({
      success: true,
      period: { startDate, endDate },
      lines
    });
  } catch (err) {
    console.error("❌ Error fetching line performance detail:", err.message);
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});

/**
 * GET /api/skyrina/available-styles?startDate=YYYY-MM-DD&endDate=YYYY-MM-DD
 * Returns list of unique styles in the date range
 */
app.get("/api/skyrina/available-styles", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
    
    const { startDate, endDate } = req.query;
    if (!startDate || !endDate) {
      return res.status(400).json({ 
        success: false, 
        error: "startDate and endDate parameters required" 
      });
    }
    
    const result = await client.query(
      `SELECT DISTINCT style FROM line_runs 
       WHERE run_date BETWEEN $1 AND $2 AND style IS NOT NULL AND style != ''
       ORDER BY style`,
      [startDate, endDate]
    );
    
    const styles = result.rows.map(row => row.style);
    
    res.json({
      success: true,
      styles
    });
  } catch (err) {
    console.error("❌ Error fetching available styles:", err.message);
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});

/**
 * GET /api/skyrina/available-lines?startDate=YYYY-MM-DD&endDate=YYYY-MM-DD
 * Returns list of unique line numbers in the date range
 */
app.get("/api/skyrina/available-lines", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
    
    const { startDate, endDate } = req.query;
    if (!startDate || !endDate) {
      return res.status(400).json({ 
        success: false, 
        error: "startDate and endDate parameters required" 
      });
    }
    
    // Fix: Cast line_no to integer in SELECT as well, or remove ORDER BY cast
    const result = await client.query(
      `SELECT DISTINCT line_no, line_no::int as line_no_int 
       FROM line_runs 
       WHERE run_date BETWEEN $1 AND $2 AND line_no IS NOT NULL
       ORDER BY line_no_int`,
      [startDate, endDate]
    );
    
    const lines = result.rows.map(row => row.line_no);
    
    res.json({
      success: true,
      lines
    });
  } catch (err) {
    console.error("❌ Error fetching available lines:", err.message);
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});

/**
 * GET /api/skyrina/period-summary?startDate=YYYY-MM-DD&endDate=YYYY-MM-DD&style=xxx&lineNo=xxx
 * Returns aggregated summary for a date range with CORRECT efficiency calculation
 * Uses weighted average based on total SAM output vs total available minutes
 */
/**
 * GET /api/skyrina/period-summary?startDate=YYYY-MM-DD&endDate=YYYY-MM-DD&style=xxx&lineNo=xxx
 * Returns aggregated summary for a date range with CORRECT efficiency calculation
 * Uses weighted average based on total SAM output vs total available minutes
 */
app.get("/api/skyrina/period-summary", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
    
    const { startDate, endDate, style, lineNo } = req.query;
    if (!startDate || !endDate) {
      return res.status(400).json({ 
        success: false, 
        error: "startDate and endDate parameters required" 
      });
    }
    
    if (!['master', 'skyrina', 'engineer', 'supervisor'].includes(req.user.role)) {
      return res.status(403).json({ success: false, error: "Access denied" });
    }
    
    // Build optional filters that apply to the ALL-RUNS available-minutes set,
    // so the denominator matches the proven-correct query (identical to the pgAdmin result).
    const params = [startDate, endDate];
    let paramIndex = 3;
    let runFilters = "";

    if (style && style !== 'all') {
      runFilters += ` AND lr.style = $${paramIndex++}`;
      params.push(style);
    }

    if (lineNo && lineNo !== 'all') {
      runFilters += ` AND lr.line_no = $${paramIndex++}`;
      params.push(lineNo);
    }

    // CORRECT global (diario) efficiency:
    //   available minutes are summed over EVERY run on the date (matching the working query),
    //   NOT only over runs that happen to contain a packing operation.
    const query = `
      WITH filtered_runs AS (
        SELECT
          lr.id            AS run_id,
          lr.line_no       AS line_no,
          lr.style         AS style,
          lr.run_date      AS run_date,
          lr.target_pcs    AS target_pcs,
          lr.operators_count,
          lr.working_hours,
          lr.sam_minutes,
          (lr.working_hours * lr.operators_count * 60) AS available_minutes
        FROM line_runs lr
        WHERE lr.run_date BETWEEN $1 AND $2${runFilters}
      ),
      -- ONE CREW per (day, line, style). Same style / different colour = the same
      -- operators working the same hours, so Meta and available minutes are
      -- counted once per crew (MAX across colours) instead of once per colour.
      -- Without this, a two-colour split doubles both the target and the
      -- efficiency denominator.
      crew_capacity AS (
        SELECT
          run_date,
          line_no,
          style,
          MAX(target_pcs)        AS crew_target,
          MAX(available_minutes) AS crew_available_minutes
        FROM filtered_runs
        GROUP BY run_date, line_no, style
      ),
      run_packing_totals AS (
        SELECT
          fr.run_id,
          fr.sam_minutes,
          COALESCE(SUM(se.sewed_qty), 0) AS packing_total
        FROM filtered_runs fr
        JOIN run_operators ro ON fr.run_id = ro.run_id
        JOIN operator_operations oo ON ro.id = oo.run_operator_id
        LEFT JOIN operation_sewed_entries se ON oo.id = se.operation_id
        WHERE (oo.operation_name ILIKE '%pack%' OR oo.operation_name ILIKE '%emp%')
        GROUP BY fr.run_id, fr.sam_minutes
      )
      SELECT
        (SELECT COUNT(*) FROM filtered_runs)                             AS total_runs,
        (SELECT COUNT(DISTINCT line_no) FROM filtered_runs)             AS lines_used,
        COALESCE((SELECT SUM(packing_total) FROM run_packing_totals),0) AS total_sewed,
        COALESCE((SELECT SUM(crew_target) FROM crew_capacity),0)        AS total_target,
        CASE
          WHEN (SELECT SUM(crew_available_minutes) FROM crew_capacity) > 0
          THEN (
                 COALESCE((SELECT SUM(packing_total * sam_minutes) FROM run_packing_totals),0)
                 / (SELECT SUM(crew_available_minutes) FROM crew_capacity)
               ) * 100
          ELSE 0
        END                                                             AS avg_efficiency
    `;
    
    const result = await client.query(query, params);
    
    const summary = result.rows[0] || {
      total_runs: 0,
      lines_used: 0,
      total_sewed: 0,
      total_target: 0,
      avg_efficiency: 0
    };
    
    const avgEfficiency = parseFloat(summary.avg_efficiency) || 0;
    
    res.json({
      success: true,
      period: { startDate, endDate },
      summary: {
        totalRuns: parseInt(summary.total_runs) || 0,
        linesUsed: parseInt(summary.lines_used) || 0,
        totalTarget: parseFloat(summary.total_target) || 0,  // NO ROUNDING
        totalSewed: parseFloat(summary.total_sewed) || 0,    // NO ROUNDING
        avgEfficiency: avgEfficiency  // NO ROUNDING - keep exact value
      }
    });
  } catch (err) {
    console.error("❌ Error fetching period summary:", err.message);
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});

/**
 * Paste into server1.js next to the other /api/skyrina routes.
 *
 * GET /api/skyrina/daily-production?startDate=YYYY-MM-DD&endDate=YYYY-MM-DD&style=xxx&lineNo=xxx
 *
 * Returns one row per calendar day in the range (days with no runs come back as
 * zeros, so the chart keeps its gaps instead of silently closing them).
 *
 * Produced = packing/empaque sewed quantities, matching /api/skyrina/period-summary.
 * Meta     = sum of target_pcs across that day's runs.
 *
 * Overview.jsx works without this — it falls back to one period-summary call per
 * day. This route turns 30 round trips into 1.
 */
/**
 * Paste into server1.js next to the other /api/skyrina routes.
 *
 * GET /api/skyrina/daily-production?startDate=YYYY-MM-DD&endDate=YYYY-MM-DD&style=xxx&lineNo=xxx
 *
 * Returns one row per calendar day in the range (days with no runs come back as
 * zeros, so the chart keeps its gaps instead of silently closing them).
 *
 * Produced = packing/empaque sewed quantities, matching /api/skyrina/period-summary.
 * Meta     = target_pcs summed once per CREW (day, line, style) — a same-style
 *            colour split shares one crew, so its target counts once, not twice.
 *
 * Overview.jsx works without this — it falls back to one period-summary call per
 * day. This route turns 30 round trips into 1.
 */
app.get("/api/skyrina/daily-production", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);

    const { startDate, endDate, style, lineNo } = req.query;
    if (!startDate || !endDate) {
      return res.status(400).json({
        success: false,
        error: "startDate and endDate parameters required",
      });
    }

    if (!['master', 'skyrina', 'engineer', 'supervisor'].includes(req.user.role)) {
      return res.status(403).json({ success: false, error: "Access denied" });
    }

    const params = [startDate, endDate];
    let paramIndex = 3;
    let runFilters = "";

    if (style && style !== 'all') {
      runFilters += ` AND lr.style = $${paramIndex++}`;
      params.push(style);
    }
    if (lineNo && lineNo !== 'all') {
      runFilters += ` AND lr.line_no = $${paramIndex++}`;
      params.push(lineNo);
    }

    const query = `
      WITH calendar AS (
        SELECT generate_series($1::date, $2::date, '1 day')::date AS day
      ),
      filtered_runs AS (
        SELECT
          lr.id          AS run_id,
          lr.run_date    AS run_date,
          lr.line_no     AS line_no,
          lr.style       AS style,
          lr.target_pcs  AS target_pcs,
          lr.sam_minutes AS sam_minutes,
          (lr.working_hours * lr.operators_count * 60) AS available_minutes
        FROM line_runs lr
        WHERE lr.run_date BETWEEN $1 AND $2${runFilters}
      ),
      -- ONE CREW per (day, line, style): same style / different colour is the
      -- same crew, so Meta and capacity count once (MAX across colours).
      daily_crews AS (
        SELECT
          run_date,
          line_no,
          style,
          MAX(target_pcs)        AS crew_target,
          MAX(available_minutes) AS crew_available_minutes
        FROM filtered_runs
        GROUP BY run_date, line_no, style
      ),
      -- Denominator: available minutes are summed over EVERY crew on the day,
      -- not only over runs that happen to contain a packing operation. This is
      -- the same rule /api/skyrina/period-summary applies to the whole range.
      daily_target AS (
        SELECT
          dc.run_date,
          (SELECT COUNT(*) FROM filtered_runs fr WHERE fr.run_date = dc.run_date) AS runs,
          COALESCE(SUM(dc.crew_target), 0)            AS target,
          COALESCE(SUM(dc.crew_available_minutes), 0) AS available_minutes
        FROM daily_crews dc
        GROUP BY dc.run_date
      ),
      run_packing_totals AS (
        SELECT
          fr.run_id,
          fr.run_date,
          fr.sam_minutes,
          COALESCE(SUM(se.sewed_qty), 0) AS packing_total
        FROM filtered_runs fr
        JOIN run_operators ro          ON fr.run_id = ro.run_id
        JOIN operator_operations oo    ON ro.id = oo.run_operator_id
        LEFT JOIN operation_sewed_entries se ON oo.id = se.operation_id
        WHERE (oo.operation_name ILIKE '%pack%' OR oo.operation_name ILIKE '%emp%')
        GROUP BY fr.run_id, fr.run_date, fr.sam_minutes
      ),
      -- Numerator: SAM output = packed pieces * SAM of the run they came from.
      daily_produced AS (
        SELECT
          run_date,
          COALESCE(SUM(packing_total), 0)               AS produced,
          COALESCE(SUM(packing_total * sam_minutes), 0) AS sam_output
        FROM run_packing_totals
        GROUP BY run_date
      )
      SELECT
        c.day                              AS date,
        COALESCE(dt.runs, 0)               AS runs,
        COALESCE(dp.produced, 0)           AS produced,
        COALESCE(dt.target, 0)             AS target,
        COALESCE(dt.available_minutes, 0)  AS available_minutes,
        COALESCE(dp.sam_output, 0)         AS sam_output,
        CASE
          WHEN COALESCE(dt.available_minutes, 0) > 0
          THEN (COALESCE(dp.sam_output, 0) / dt.available_minutes) * 100
          ELSE 0
        END                                AS efficiency
      FROM calendar c
      LEFT JOIN daily_produced dp ON dp.run_date = c.day
      LEFT JOIN daily_target   dt ON dt.run_date = c.day
      ORDER BY c.day ASC
    `;

    const result = await client.query(query, params);

    const days = result.rows.map((row) => ({
      // send a plain YYYY-MM-DD string so the client never re-parses in UTC
      date: row.date instanceof Date
        ? `${row.date.getFullYear()}-${String(row.date.getMonth() + 1).padStart(2, '0')}-${String(row.date.getDate()).padStart(2, '0')}`
        : String(row.date).slice(0, 10),
      runs: parseInt(row.runs, 10) || 0,
      produced: parseFloat(row.produced) || 0,
      target: parseFloat(row.target) || 0,
      // NO ROUNDING - keep the exact value, same as period-summary
      availableMinutes: parseFloat(row.available_minutes) || 0,
      samOutput: parseFloat(row.sam_output) || 0,
      efficiency: parseFloat(row.efficiency) || 0,
    }));

    res.json({
      success: true,
      period: { startDate, endDate },
      days,
    });
  } catch (err) {
    console.error("❌ Error fetching daily production:", err.message);
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});



/**
 * GET /api/skyrina/product-breakdown?date=YYYY-MM-DD
 * Returns product (style) breakdown with sewed quantities for a specific date
 */
app.get("/api/skyrina/product-breakdown", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
    
    const { date } = req.query;
    if (!date) {
      return res.status(400).json({ success: false, error: "date parameter required" });
    }
    
    // Check if user has access
    if (!['master', 'skyrina', 'engineer', 'supervisor'].includes(req.user.role)) {
      return res.status(403).json({ success: false, error: "Access denied" });
    }
    
    const query = `
      SELECT 
        lr.style,
        COALESCE(SUM(se.sewed_qty), 0) as sewed,
        lr.target_pcs as target,
        lr.line_no
      FROM line_runs lr
      JOIN run_operators ro ON lr.id = ro.run_id
      JOIN operator_operations oo ON ro.id = oo.run_operator_id
      LEFT JOIN operation_sewed_entries se ON oo.id = se.operation_id
      WHERE lr.run_date = $1
        AND (oo.operation_name ILIKE '%pack%' OR oo.operation_name ILIKE '%emp%')
      GROUP BY lr.id, lr.style, lr.target_pcs, lr.line_no
      ORDER BY sewed DESC
    `;
    
    const result = await client.query(query, [date]);
    
    // Group by style (in case same style runs on multiple lines)
    const styleMap = new Map();
    
    for (const row of result.rows) {
      const style = row.style || 'Sin Estilo';
      const current = styleMap.get(style) || { 
        style, 
        sewed: 0, 
        target: 0
      };
      
      current.sewed += parseFloat(row.sewed) || 0;
      current.target += parseFloat(row.target) || 0;
      
      styleMap.set(style, current);
    }
    
    const products = Array.from(styleMap.values())
      .sort((a, b) => b.sewed - a.sewed);
    
    res.json({
      success: true,
      date,
      products,
      totalProducts: products.length
    });
  } catch (err) {
    console.error("❌ Error fetching product breakdown:", err.message);
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});
// Add this new endpoint in server.js (before the period-summary endpoint)

/**
 * GET /api/skyrina/line-efficiency?startDate=YYYY-MM-DD&endDate=YYYY-MM-DD&style=xxx&lineNo=xxx
 * Returns per-line efficiency calculated with SAM formula (server-side) with filters
 */
app.get("/api/skyrina/line-efficiency", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
    
    const { startDate, endDate, style, lineNo } = req.query;
    if (!startDate || !endDate) {
      return res.status(400).json({ 
        success: false, 
        error: "startDate and endDate parameters required" 
      });
    }
    
    if (!['master', 'skyrina', 'engineer', 'supervisor'].includes(req.user.role)) {
      return res.status(403).json({ success: false, error: "Access denied" });
    }
    
    let query = `
      WITH packing_sewed AS (
        SELECT 
          lr.id as run_id,
          lr.line_no,
          lr.operators_count,
          lr.working_hours,
          lr.sam_minutes,
          lr.target_pcs,
          COALESCE(SUM(se.sewed_qty), 0) as total_sewed
        FROM line_runs lr
        LEFT JOIN run_operators ro ON lr.id = ro.run_id
        LEFT JOIN operator_operations oo ON ro.id = oo.run_operator_id
        LEFT JOIN operation_sewed_entries se ON oo.id = se.operation_id
        WHERE lr.run_date BETWEEN $1 AND $2
          AND (oo.operation_name ILIKE '%pack%' OR oo.operation_name ILIKE '%emp%' OR oo.operation_name IS NULL)
    `;
    
    const params = [startDate, endDate];
    let paramIndex = 3;
    
    if (style && style !== 'all') {
      query += ` AND lr.style = $${paramIndex++}`;
      params.push(style);
    }
    
    if (lineNo && lineNo !== 'all') {
      query += ` AND lr.line_no = $${paramIndex++}`;
      params.push(lineNo);
    }
    
    query += `
        GROUP BY lr.id, lr.line_no, lr.operators_count, lr.working_hours, lr.sam_minutes, lr.target_pcs
      ),
      line_aggregates AS (
        SELECT
          line_no,
          SUM(total_sewed) as total_sewed,
          SUM(target_pcs) as total_target,
          SUM(operators_count * working_hours * 60) as total_available_minutes,
          SUM(total_sewed * sam_minutes) as total_sam_output
        FROM packing_sewed
        GROUP BY line_no
      )
      SELECT 
        line_no,
        total_sewed as quantity,
        total_target as target,
        CASE 
          WHEN total_available_minutes > 0 
          THEN (total_sam_output / total_available_minutes) * 100
          ELSE 0
        END as efficiency
      FROM line_aggregates
      ORDER BY line_no::int
    `;
    
    const result = await client.query(query, params);
    
    const lines = result.rows.map(row => ({
      lineNo: row.line_no,
      quantity: parseFloat(row.quantity) || 0,
      target: parseFloat(row.target) || 0,
      efficiency: parseFloat(row.efficiency) || 0  // NO ROUNDING - keep exact value
    }));
    
    res.json({
      success: true,
      period: { startDate, endDate },
      lines
    });
  } catch (err) {
    console.error("❌ Error fetching line efficiency:", err.message);
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});
/**
 * GET /api/skyrina/style-efficiency-sam?startDate=YYYY-MM-DD&endDate=YYYY-MM-DD&style=xxx&lineNo=xxx
 * Returns style efficiency calculated using SAM (standard allowed minutes)
 * This is more accurate than production compliance
 */
app.get("/api/skyrina/style-efficiency-sam", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
    
    const { startDate, endDate, style, lineNo } = req.query;
    if (!startDate || !endDate) {
      return res.status(400).json({ 
        success: false, 
        error: "startDate and endDate parameters required" 
      });
    }
    
    if (!['master', 'skyrina', 'engineer', 'supervisor'].includes(req.user.role)) {
      return res.status(403).json({ success: false, error: "Access denied" });
    }
    
    let query = `
      WITH style_packing_data AS (
        SELECT 
          lr.style,
          lr.sam_minutes,
          lr.operators_count,
          lr.working_hours,
          lr.target_pcs,
          lr.line_no,
          COALESCE(SUM(se.sewed_qty), 0) as total_sewed
        FROM line_runs lr
        JOIN run_operators ro ON lr.id = ro.run_id
        JOIN operator_operations oo ON ro.id = oo.run_operator_id
        LEFT JOIN operation_sewed_entries se ON oo.id = se.operation_id
        WHERE lr.run_date BETWEEN $1 AND $2
          AND (oo.operation_name ILIKE '%pack%' OR oo.operation_name ILIKE '%emp%')
    `;
    
    const params = [startDate, endDate];
    let paramIndex = 3;
    
    if (style && style !== 'all') {
      query += ` AND lr.style = $${paramIndex++}`;
      params.push(style);
    }
    
    if (lineNo && lineNo !== 'all') {
      query += ` AND lr.line_no = $${paramIndex++}`;
      params.push(lineNo);
    }
    
    query += `
        GROUP BY lr.id, lr.style, lr.sam_minutes, lr.operators_count, lr.working_hours, lr.target_pcs, lr.line_no
      )
      SELECT 
        style,
        SUM(total_sewed) as total_produced,
        SUM(target_pcs) as total_target,
        SUM(total_sewed * sam_minutes) as total_sam_output,
        SUM(operators_count * working_hours * 60) as total_available_minutes,
        CASE 
          WHEN SUM(operators_count * working_hours * 60) > 0 
          THEN (SUM(total_sewed * sam_minutes) / SUM(operators_count * working_hours * 60)) * 100
          ELSE 0
        END as efficiency,
        CASE 
          WHEN SUM(target_pcs) > 0 
          THEN (SUM(total_sewed) / SUM(target_pcs)) * 100 
          ELSE 0 
        END as compliance
      FROM style_packing_data
      GROUP BY style
      ORDER BY efficiency DESC
    `;
    
    const result = await client.query(query, params);
    
    const styles = result.rows.map(row => ({
      style: row.style || 'No Style',
      target: parseFloat(row.total_target) || 0,
      produced: parseFloat(row.total_produced) || 0,
      efficiency: parseFloat(row.efficiency) || 0,  // SAM-based efficiency
      compliance: parseFloat(row.compliance) || 0,  // Production compliance
      total_sam_output: parseFloat(row.total_sam_output) || 0,
      total_available_minutes: parseFloat(row.total_available_minutes) || 0
    }));
    
    res.json({
      success: true,
      period: { startDate, endDate },
      styles
    });
  } catch (err) {
    console.error("❌ Error fetching style efficiency (SAM):", err.message);
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});
/**
 * GET /api/skyrina/line-performance-detail?startDate=YYYY-MM-DD&endDate=YYYY-MM-DD
 * Returns line performance with style, target, produced, and compliance
 */
/**
 * GET /api/skyrina/line-performance-detail?startDate=YYYY-MM-DD&endDate=YYYY-MM-DD&style=xxx&lineNo=xxx
 * Returns line performance with SAM-based efficiency
 */
app.get("/api/skyrina/line-performance-detail", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
    
    const { startDate, endDate, style, lineNo } = req.query;
    if (!startDate || !endDate) {
      return res.status(400).json({ 
        success: false, 
        error: "startDate and endDate parameters required" 
      });
    }
    
    if (!['skyrina', 'engineer', 'supervisor', 'soporte_it', 'master'].includes(req.user.role)) {
      return res.status(403).json({ success: false, error: "Access denied" });
    }
    
    let query = `
      WITH line_packing_data AS (
        SELECT 
          lr.style,
          lr.line_no,
          lr.run_date,
          lr.sam_minutes,
          lr.operators_count,
          lr.working_hours,
          lr.target_pcs,
          COALESCE(SUM(se.sewed_qty), 0) as total_sewed
        FROM line_runs lr
        JOIN run_operators ro ON lr.id = ro.run_id
        JOIN operator_operations oo ON ro.id = oo.run_operator_id
        LEFT JOIN operation_sewed_entries se ON oo.id = se.operation_id
        WHERE lr.run_date BETWEEN $1 AND $2
          AND (oo.operation_name ILIKE '%pack%' OR oo.operation_name ILIKE '%emp%')
    `;
    
    const params = [startDate, endDate];
    let paramIndex = 3;
    
    if (style && style !== 'all') {
      query += ` AND lr.style = $${paramIndex++}`;
      params.push(style);
    }
    
    if (lineNo && lineNo !== 'all') {
      query += ` AND lr.line_no = $${paramIndex++}`;
      params.push(lineNo);
    }
    
    query += `
        GROUP BY lr.id, lr.style, lr.line_no, lr.run_date, lr.sam_minutes, lr.operators_count, lr.working_hours, lr.target_pcs
      ),
      -- ONE CREW per (day, line, style): a colour split shares the crew, so its
      -- target/capacity is counted once (MAX across colours), never summed.
      line_crews AS (
        SELECT
          style,
          line_no,
          run_date,
          MAX(target_pcs)                           AS crew_target,
          MAX(operators_count * working_hours * 60) AS crew_available_minutes
        FROM line_packing_data
        GROUP BY style, line_no, run_date
      ),
      line_capacity AS (
        SELECT
          style,
          line_no,
          SUM(crew_target)            AS total_target,
          SUM(crew_available_minutes) AS total_available_minutes
        FROM line_crews
        GROUP BY style, line_no
      ),
      -- Produced/SAM output still sums across every colour.
      line_output AS (
        SELECT
          style,
          line_no,
          SUM(total_sewed)               AS total_produced,
          SUM(total_sewed * sam_minutes) AS total_sam_output
        FROM line_packing_data
        GROUP BY style, line_no
      ),
      line_aggregates AS (
        SELECT
          o.style,
          o.line_no,
          o.total_produced,
          c.total_target,
          o.total_sam_output,
          c.total_available_minutes
        FROM line_output o
        JOIN line_capacity c
          ON c.line_no = o.line_no
         AND c.style IS NOT DISTINCT FROM o.style
      )
      SELECT 
        style,
        line_no,
        total_target as target,
        total_produced as produced,
        -- SAM-based efficiency
        CASE 
          WHEN total_available_minutes > 0 
          THEN (total_sam_output / total_available_minutes) * 100
          ELSE 0
        END as efficiency,
        -- Production compliance (for reference)
        CASE 
          WHEN total_target > 0 
          THEN (total_produced / total_target) * 100 
          ELSE 0 
        END as compliance
      FROM line_aggregates
      ORDER BY line_no::int, efficiency DESC
    `;
    
    const result = await client.query(query, params);
    
    const lines = result.rows.map(row => ({
      style: row.style || 'No Style',
      lineNo: row.line_no,
      target: Math.round(parseFloat(row.target) * 100) / 100,
      produced: Math.round(parseFloat(row.produced) * 100) / 100,
      efficiency: parseFloat(row.efficiency) || 0,  // SAM-based efficiency
      compliance: parseFloat(row.compliance) || 0   // Production compliance
    }));
    
    res.json({
      success: true,
      period: { startDate, endDate },
      lines
    });
  } catch (err) {
    console.error("❌ Error fetching line performance detail:", err.message);
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});

/**
 * GET /api/skyrina/product-performance?startDate=YYYY-MM-DD&endDate=YYYY-MM-DD
 * Returns product performance with style, target, produced, and compliance
 */
app.get("/api/skyrina/product-performance", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
    
    const { startDate, endDate } = req.query;
    if (!startDate || !endDate) {
      return res.status(400).json({ 
        success: false, 
        error: "startDate and endDate parameters required" 
      });
    }
    
    // Check if user has access
    if (!['skyrina', 'engineer', 'supervisor', 'soporte_it', 'master'].includes(req.user.role)) {
      return res.status(403).json({ success: false, error: "Access denied" });
    }
    
    const query = `
      WITH product_data AS (
        SELECT 
          lr.style,
          lr.target_pcs as target,
          COALESCE(SUM(se.sewed_qty), 0) as produced,
          lr.line_no,
          lr.run_date
        FROM line_runs lr
        JOIN run_operators ro ON lr.id = ro.run_id
        JOIN operator_operations oo ON ro.id = oo.run_operator_id
        LEFT JOIN operation_sewed_entries se ON oo.id = se.operation_id
        WHERE lr.run_date BETWEEN $1 AND $2
          AND (oo.operation_name ILIKE '%pack%' OR oo.operation_name ILIKE '%emp%' OR oo.operation_name IS NULL)
        GROUP BY lr.id, lr.style, lr.target_pcs, lr.line_no, lr.run_date
      )
      SELECT 
        style,
        SUM(target) as total_target,
        SUM(produced) as total_produced,
        CASE 
          WHEN SUM(target) > 0 
          THEN (SUM(produced) / SUM(target)) * 100 
          ELSE 0 
        END as compliance
      FROM product_data
      GROUP BY style
      ORDER BY total_produced DESC
    `;
    
    const result = await client.query(query, [startDate, endDate]);
    
    const products = result.rows.map(row => ({
      style: row.style || 'Sin Estilo',
      target: Math.round(parseFloat(row.total_target) * 100) / 100,
      produced: Math.round(parseFloat(row.total_produced) * 100) / 100,
      compliance: Math.min(Math.round(parseFloat(row.compliance) * 100) / 100, 100)
    }));
    
    res.json({
      success: true,
      period: { startDate, endDate },
      products
    });
  } catch (err) {
    console.error("❌ Error fetching product performance:", err.message);
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});

// Add this endpoint to your server.js (without validate)
// ========== BATCH ENDPOINT FOR SKYRINA DASHBOARD ==========
app.post(
  "/api/batch/line-runs-data",
  authenticateToken,
  async (req, res) => {
    const client = await pool.connect();
    try {
      await setSchema(client);
      
      const { lines, date } = req.body;
      
      // Validate inputs manually
      if (!lines || !Array.isArray(lines)) {
        return res.status(400).json({ success: false, error: "lines array required" });
      }
      if (!date) {
        return res.status(400).json({ success: false, error: "date required" });
      }
      
      const results = {};
      
      for (const lineNo of lines) {
        // Get runs for this line
                // Get runs for this line, joined to their work order via the canonical
        // link (line_runs.work_order_id -> work_orders.id). LEFT JOIN so runs
        // with no linked order still return (work_order_no just null).
        const runsResult = await client.query(
          `SELECT lr.id, lr.line_no, lr.run_date, lr.style, lr.color,
                  lr.operators_count, lr.working_hours, lr.sam_minutes,
                  lr.efficiency, lr.target_pcs, lr.target_per_hour, lr.created_at,
                  lr.work_order_id,
                  wo.work_order_no,
                  wo.style_description AS work_order_style,
                  wo.customer_name     AS work_order_customer,
                  wo.color             AS work_order_color
           FROM line_runs lr
           LEFT JOIN work_orders wo ON wo.id = lr.work_order_id
           WHERE lr.line_no = $1 AND lr.run_date = $2
           ORDER BY lr.run_date DESC`,
          [lineNo, date]
        );
        
        const lineRuns = [];
        
        for (const run of runsResult.rows) {
          // Get full run data
          const runData = await getFullRunDataBatch(client, run.id);
          lineRuns.push({
            ...run,
            runData
          });
        }
        
        results[lineNo] = lineRuns;
      }
      
      res.json({ success: true, data: results });
    } catch (err) {
      console.error("❌ Error in batch endpoint:", err.message);
      res.status(500).json({ success: false, error: err.message });
    } finally {
      client.release();
    }
  }
);

// Helper function for batch endpoint (different name to avoid conflict)
async function getFullRunDataBatch(client, runId) {
  // Get slots
  const slotsResult = await client.query(
    "SELECT id, slot_order, slot_label, slot_start, slot_end, planned_hours FROM shift_slots WHERE run_id = $1 ORDER BY slot_order",
    [runId]
  );
  
  // Get operators
  const operatorsResult = await client.query(
    "SELECT id, operator_no, operator_name FROM run_operators WHERE run_id = $1 ORDER BY operator_no",
    [runId]
  );
  
  // Get slot targets
  const slotTargetsResult = await client.query(
    `SELECT s.slot_label, t.slot_target, t.cumulative_target
     FROM slot_targets t
     JOIN shift_slots s ON t.slot_id = s.id
     WHERE t.run_id = $1
     ORDER BY s.slot_order`,
    [runId]
  );
  
  // Get operations with their data
  const operationsData = [];
  for (const operator of operatorsResult.rows) {
    const operationsResult = await client.query(
      `SELECT 
        o.id,
        o.operation_name,
        o.t1_sec,
        o.t2_sec,
        o.t3_sec,
        o.t4_sec,
        o.t5_sec,
        o.capacity_per_hour,
        COALESCE(
          jsonb_object_agg(
            COALESCE(s.slot_label, ''),
            COALESCE(h.stitched_qty, 0)
          ) FILTER (WHERE s.slot_label IS NOT NULL),
          '{}'::jsonb
        ) as stitched_data,
        COALESCE(
          jsonb_object_agg(
            COALESCE(s2.slot_label, ''),
            COALESCE(se.sewed_qty, 0)
          ) FILTER (WHERE s2.slot_label IS NOT NULL),
          '{}'::jsonb
        ) as sewed_data
       FROM operator_operations o
       LEFT JOIN operation_hourly_entries h ON o.id = h.operation_id
       LEFT JOIN shift_slots s ON h.slot_id = s.id
       LEFT JOIN operation_sewed_entries se ON o.id = se.operation_id
       LEFT JOIN shift_slots s2 ON se.slot_id = s2.id
       WHERE o.run_operator_id = $1 AND o.run_id = $2
       GROUP BY o.id
       ORDER BY o.created_at`,
      [operator.id, runId]
    );
    
    operationsData.push({
      operator,
      operations: operationsResult.rows,
    });
  }
  
  return {
    slots: slotsResult.rows,
    operators: operatorsResult.rows,
    operations: operationsData,
    slotTargets: slotTargetsResult.rows,
  };
}

// Add the helper function getFullRunData


// Helper function to get full run data
async function getFullRunData(client, runId) {
  // Get slots
  const slotsResult = await client.query(
    "SELECT id, slot_order, slot_label, slot_start, slot_end, planned_hours FROM shift_slots WHERE run_id = $1 ORDER BY slot_order",
    [runId]
  );
  
  // Get operators
  const operatorsResult = await client.query(
    "SELECT id, operator_no, operator_name FROM run_operators WHERE run_id = $1 ORDER BY operator_no",
    [runId]
  );
  
  // Get slot targets
  const slotTargetsResult = await client.query(
    `SELECT s.slot_label, t.slot_target, t.cumulative_target
     FROM slot_targets t
     JOIN shift_slots s ON t.slot_id = s.id
     WHERE t.run_id = $1
     ORDER BY s.slot_order`,
    [runId]
  );
  
  // Get operations with their data
  const operationsData = [];
  for (const operator of operatorsResult.rows) {
    const operationsResult = await client.query(
      `SELECT 
        o.id,
        o.operation_name,
        o.t1_sec,
        o.t2_sec,
        o.t3_sec,
        o.t4_sec,
        o.t5_sec,
        o.capacity_per_hour,
        COALESCE(
          jsonb_object_agg(
            COALESCE(s.slot_label, ''),
            COALESCE(h.stitched_qty, 0)
          ) FILTER (WHERE s.slot_label IS NOT NULL),
          '{}'::jsonb
        ) as stitched_data,
        COALESCE(
          jsonb_object_agg(
            COALESCE(s2.slot_label, ''),
            COALESCE(se.sewed_qty, 0)
          ) FILTER (WHERE s2.slot_label IS NOT NULL),
          '{}'::jsonb
        ) as sewed_data
       FROM operator_operations o
       LEFT JOIN operation_hourly_entries h ON o.id = h.operation_id
       LEFT JOIN shift_slots s ON h.slot_id = s.id
       LEFT JOIN operation_sewed_entries se ON o.id = se.operation_id
       LEFT JOIN shift_slots s2 ON se.slot_id = s2.id
       WHERE o.run_operator_id = $1 AND o.run_id = $2
       GROUP BY o.id
       ORDER BY o.created_at`,
      [operator.id, runId]
    );
    
    operationsData.push({
      operator,
      operations: operationsResult.rows,
    });
  }
  
  return {
    slots: slotsResult.rows,
    operators: operatorsResult.rows,
    operations: operationsData,
    slotTargets: slotTargetsResult.rows,
  };
}

// ----------------------------------------------------------------------
// 15. ENGINEER LINE BALANCING ENDPOINTS
// ----------------------------------------------------------------------
const requireEngineer = (req, res, next) => {
  if (req.user.role !== "engineer") {
    return res.status(403).json({
      success: false,
      error: "Access denied. Engineer role required.",
    });
  }
  next();
};

app.get("/api/engineer/line-balancing/:runId", authenticateToken, requireEngineer, async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
    const { runId } = req.params;

    const runRes = await client.query(
      `SELECT id, line_no, target_per_hour, working_hours, operators_count
       FROM line_runs WHERE id = $1`,
      [runId]
    );
    if (runRes.rowCount === 0) {
      return res.status(404).json({ success: false, error: "Run not found" });
    }
    const run = runRes.rows[0];

    const opsRes = await client.query(
      `SELECT
          ro.id AS operator_id,
          ro.operator_no,
          ro.operator_name,
          oo.id AS operation_id,
          oo.operation_name,
          oo.capacity_per_hour,
          (COALESCE(oo.t1_sec,0) + COALESCE(oo.t2_sec,0) + COALESCE(oo.t3_sec,0) + COALESCE(oo.t4_sec,0) + COALESCE(oo.t5_sec,0))
          / NULLIF(
            (CASE WHEN oo.t1_sec IS NOT NULL THEN 1 ELSE 0 END +
             CASE WHEN oo.t2_sec IS NOT NULL THEN 1 ELSE 0 END +
             CASE WHEN oo.t3_sec IS NOT NULL THEN 1 ELSE 0 END +
             CASE WHEN oo.t4_sec IS NOT NULL THEN 1 ELSE 0 END +
             CASE WHEN oo.t5_sec IS NOT NULL THEN 1 ELSE 0 END), 0
          ) AS avg_cycle_sec
       FROM run_operators ro
       JOIN operator_operations oo ON ro.id = oo.run_operator_id
       WHERE ro.run_id = $1
       ORDER BY ro.operator_no, oo.id`,
      [runId]
    );

    const operators = [];
    const operatorMap = new Map();
    for (const row of opsRes.rows) {
      if (!operatorMap.has(row.operator_id)) {
        operatorMap.set(row.operator_id, {
          operator_id: row.operator_id,
          operator_no: row.operator_no,
          operator_name: row.operator_name,
          operations: []
        });
        operators.push(operatorMap.get(row.operator_id));
      }
      operatorMap.get(row.operator_id).operations.push({
        operation_id: row.operation_id,
        operation_name: row.operation_name,
        capacity_per_hour: Number(row.capacity_per_hour),
        avg_cycle_sec: Number(row.avg_cycle_sec)
      });
    }

    res.json({
      success: true,
      run,
      operators
    });
  } catch (err) {
    console.error("❌ /api/engineer/line-balancing error:", err.message);
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});

app.post("/api/engineer/line-balancing/:runId/assign", authenticateToken, requireEngineer, async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
    await client.query("BEGIN");
    const { runId } = req.params;
    const { assignments } = req.body;

    for (const a of assignments) {
      await client.query(
        `INSERT INTO line_balancing_assignments
           (run_id, source_operator_id, target_operator_id, operation_id, assigned_quantity_per_hour)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (run_id, source_operator_id, target_operator_id, operation_id)
         DO UPDATE SET assigned_quantity_per_hour = EXCLUDED.assigned_quantity_per_hour,
                       updated_at = NOW()`,
        [runId, a.sourceOperatorId, a.targetOperatorId, a.operationId, a.assignedQtyPerHour]
      );
    }

    await client.query("COMMIT");
    res.json({ success: true });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("❌ /api/engineer/line-balancing/assign error:", err.message);
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});

// ----------------------------------------------------------------------
// 16. LINE LEADER ASSIGNMENTS ENDPOINT
// ----------------------------------------------------------------------
app.get("/api/lineleader/assignments/:runId", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
    const { runId } = req.params;

    const query = `
      SELECT 
        lba.id,
        lba.source_operator_id,
        lba.target_operator_id,
        lba.operation_id,
        lba.assigned_quantity_per_hour,
        source.operator_no AS source_operator_no,
        source.operator_name AS source_operator_name,
        target.operator_no AS target_operator_no,
        target.operator_name AS target_operator_name,
        oo.operation_name
      FROM line_balancing_assignments lba
      JOIN run_operators source ON lba.source_operator_id = source.id
      JOIN run_operators target ON lba.target_operator_id = target.id
      JOIN operator_operations oo ON lba.operation_id = oo.id
      WHERE lba.run_id = $1
      ORDER BY source.operator_no, target.operator_no;
    `;
    const result = await client.query(query, [runId]);
    res.json({ success: true, assignments: result.rows });
  } catch (err) {
    console.error("❌ Error fetching lineleader assignments:", err);
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});

// ----------------------------------------------------------------------
// 17. SUPERVISOR ASSIGNMENTS ENDPOINT
// ----------------------------------------------------------------------
app.get("/api/supervisor/assignments", authenticateToken, requireSupervisor, async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
    const { date } = req.query;
    if (!date) {
      return res.status(400).json({ success: false, error: "date parameter required" });
    }

    const query = `
      SELECT 
        lr.line_no,
        lba.source_operator_id,
        lba.target_operator_id,
        lba.assigned_quantity_per_hour,
        lr.working_hours,
        (lba.assigned_quantity_per_hour * lr.working_hours) AS total_helped_pieces,
        source.operator_no AS source_operator_no,
        source.operator_name AS source_operator_name,
        target.operator_no AS target_operator_no,
        target.operator_name AS target_operator_name
      FROM line_balancing_assignments lba
      JOIN line_runs lr ON lba.run_id = lr.id
      JOIN run_operators source ON lba.source_operator_id = source.id
      JOIN run_operators target ON lba.target_operator_id = target.id
      WHERE lr.run_date = $1
      ORDER BY lr.line_no, source.operator_no, target.operator_no;
    `;
    const result = await client.query(query, [date]);
    res.json({ success: true, assignments: result.rows });
  } catch (err) {
    console.error("❌ Error fetching supervisor assignments:", err);
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});

// ========== PLANNER: EDIT OPERATION (SEWED QTY) ==========

const requirePlanner = (req, res, next) => {
  const allowedRoles = ["planner", "engineer", "supervisor", "soporte_it", "skyrina", "master", "inspector",'verificador'];
  if (!allowedRoles.includes(req.user?.role)) {
    return res.status(403).json({
      success: false,
      error: "Access denied. Planner role required.",
    });
  }
  next();
};

/**
 * GET /api/planner/dates
 * Distinct run dates that have runs (for the date dropdown)
 */
app.get("/api/planner/dates", authenticateToken, requirePlanner, async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
    const result = await client.query(
      `SELECT DISTINCT run_date FROM line_runs ORDER BY run_date DESC`
    );
    res.json({ success: true, dates: result.rows.map((r) => r.run_date) });
  } catch (err) {
    console.error("❌ /api/planner/dates error:", err.message);
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});

/**
 * GET /api/planner/lines?date=YYYY-MM-DD
 * Lines (with run id + style) that have runs on the given date
 */
app.get("/api/planner/lines", authenticateToken, requirePlanner, async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
    const { date } = req.query;
    if (!date) {
      return res.status(400).json({ success: false, error: "date parameter required" });
    }
    const result = await client.query(
      `SELECT id AS run_id, line_no, style
         FROM line_runs
        WHERE run_date = $1
        ORDER BY line_no, style`,
      [date]
    );
    res.json({ success: true, lines: result.rows });
  } catch (err) {
    console.error("❌ /api/planner/lines error:", err.message);
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});

/**
 * GET /api/planner/run/:runId/sewed
 * Returns slots, operators, operations and the current sewed qty per slot
 * so the planner can pick an operator/operation and edit produced (sewed) data.
 */
app.get("/api/planner/run/:runId/sewed", authenticateToken, requirePlanner, async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
    const { runId } = req.params;

    const runResult = await client.query(
      `SELECT id, line_no, run_date, style FROM line_runs WHERE id = $1`,
      [runId]
    );
    if (runResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Run not found" });
    }

    const slotsResult = await client.query(
      `SELECT id AS slot_id, slot_order, slot_label
         FROM shift_slots
        WHERE run_id = $1
        ORDER BY slot_order`,
      [runId]
    );

    const rowsResult = await client.query(
      `SELECT ro.operator_no,
              ro.operator_name,
              oo.id AS operation_id,
              oo.operation_name,
              ss.id AS slot_id,
              ss.slot_label,
              ss.slot_order,
              COALESCE(se.sewed_qty, 0) AS sewed_qty
         FROM run_operators ro
         JOIN operator_operations oo ON oo.run_operator_id = ro.id
         CROSS JOIN shift_slots ss
         LEFT JOIN operation_sewed_entries se
                ON se.operation_id = oo.id AND se.slot_id = ss.id
        WHERE ro.run_id = $1 AND oo.run_id = $1 AND ss.run_id = $1
        ORDER BY ro.operator_no, oo.operation_name, ss.slot_order`,
      [runId]
    );

    res.json({
      success: true,
      run: runResult.rows[0],
      slots: slotsResult.rows,
      rows: rowsResult.rows,
    });
  } catch (err) {
    console.error("❌ /api/planner/run/sewed error:", err.message);
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});

/**
 * POST /api/planner/update-sewed/:runId
 * body: { entries: [{ operatorNo, operationName, slotLabel, sewedQty }] }
 * Updates the produced (sewed) quantities the line leader entered.
 */
app.post("/api/planner/update-sewed/:runId", authenticateToken, requirePlanner, async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
    await client.query("BEGIN");

    const { runId } = req.params;
    const { entries } = req.body;

    if (!entries || !Array.isArray(entries)) {
      await client.query("ROLLBACK");
      return res.status(400).json({ success: false, error: "Missing entries array" });
    }

    let updatedCount = 0;

    for (const entry of entries) {
      const { operatorNo, operationName, slotLabel, sewedQty } = entry;
      if (!operatorNo || !operationName || !slotLabel) continue;

      const opResult = await client.query(
        `SELECT o.id AS op_id
           FROM operator_operations o
           JOIN run_operators ro ON o.run_operator_id = ro.id
          WHERE o.run_id = $1 AND ro.operator_no = $2 AND o.operation_name = $3
          LIMIT 1`,
        [runId, parseInt(operatorNo), operationName]
      );
      if (opResult.rows.length === 0) continue;
      const operationId = opResult.rows[0].op_id;

      const slotResult = await client.query(
        `SELECT id FROM shift_slots WHERE run_id = $1 AND slot_label = $2 LIMIT 1`,
        [runId, slotLabel]
      );
      if (slotResult.rows.length === 0) continue;
      const slotId = slotResult.rows[0].id;

      await client.query(
        `INSERT INTO operation_sewed_entries (run_id, operation_id, slot_id, sewed_qty, created_at, updated_at)
         VALUES ($1, $2, $3, $4, now(), now())
         ON CONFLICT (operation_id, slot_id)
         DO UPDATE SET sewed_qty = EXCLUDED.sewed_qty, updated_at = now()`,
        [runId, operationId, slotId, Number(sewedQty || 0)]
      );
      updatedCount++;
    }

    await client.query("COMMIT");

    // Mueve el estado de la ORDEN según lo producido (mismo criterio que el
    // endpoint del líder de línea): producido>0 -> en proceso, producido>=asignado
    // -> terminada. Solo empuja hacia adelante. Va fuera de la transacción, ya
    // commiteada, para que lea las piezas recién guardadas.
    let statusChange = null;
    try {
      const runInfo = await client.query(
        `SELECT work_order_id FROM line_runs WHERE id = $1`,
        [runId]
      );
      const woId = runInfo.rows[0]?.work_order_id;
      if (woId) {
        statusChange = await registerWorkOrders.refreshWorkOrderStatusFromProduction(client, woId);
      }
    } catch (e) {
      console.warn("⚠️  recálculo de estado de la orden falló (el guardado sí se realizó):", e.message);
    }

    res.json({ success: true, updatedCount, statusChange });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("❌ /api/planner/update-sewed error:", err.message);
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});

// ========== MASTER CODE MANAGEMENT ==========

const requireMerchantAccess = (req, res, next) => {
  const allowedRoles = ['engineer', 'supervisor', 'master', 'soporte_it', 'skyrina', 'merchant', 'admin', 'planner'];
  if (!allowedRoles.includes(req.user?.role)) {
    return res.status(403).json({
      success: false,
      error: "Access denied. Merchant access required.",
    });
  }
  next();
};

/**
 * GET /api/master-codes/next-correlativo
 * Get the next correlativo number for a given type and modelo
 * IMPORTANT: This must come BEFORE /api/master-codes/:id to avoid route conflicts
 */
app.get("/api/master-codes/next-correlativo", authenticateToken, requireMerchantAccess, async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);

    const { type, modelo } = req.query;

    if (!type || !modelo) {
      return res.status(400).json({
        success: false,
        error: "type and modelo parameters are required"
      });
    }

    // Highest correlativo across BOTH real master codes and pending pre-orders.
    const result = await client.query(
      `SELECT COALESCE(MAX(c), 0) AS maxseq
         FROM (
           SELECT correlativo::int AS c
             FROM master_codes
            WHERE type = $1 AND modelo = $2
              AND correlativo ~ '^[0-9]+$'
           UNION ALL
           SELECT correlativo::int AS c
             FROM pre_orders
            WHERE tipo = $1 AND modelo = $2
              AND status = 'pending'
              AND correlativo ~ '^[0-9]+$'
         ) t`,
      [type, modelo]
    );

    let nextCorrelativo = "01";
    const maxseq = parseInt(result.rows[0]?.maxseq, 10);
    if (!isNaN(maxseq) && maxseq > 0) {
      nextCorrelativo = String(maxseq + 1).padStart(2, "0");
    }

    res.json({
      success: true,
      nextCorrelativo,
      type,
      modelo
    });
  } catch (err) {
    console.error("❌ Error getting next correlativo:", err.message);
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});

/**
 * GET /api/master-codes
 * Get all master codes with optional filters
 */
app.get("/api/master-codes", authenticateToken, requireMerchantAccess, async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
    
    const { q, tipo, modelo, talla, cliente, estilo } = req.query;
    
    let query = `
      SELECT 
        id,
        code,
        type,
        modelo,
        correlativo,
        talla,
        cliente,
        color,
        estilo,
        description,
        sam_minutes as sam,
        photo_url as "photoUrl",
        photo_filename,
        created_at as "createdAt",
        created_by
      FROM master_codes
      WHERE 1=1
    `;
    
    const params = [];
    let paramIndex = 1;
    
    if (q) {
      query += ` AND (code ILIKE $${paramIndex} OR description ILIKE $${paramIndex} OR cliente ILIKE $${paramIndex} OR estilo ILIKE $${paramIndex})`;
      params.push(`%${q}%`);
      paramIndex++;
    }
    
    if (tipo) {
      query += ` AND type = $${paramIndex++}`;
      params.push(tipo);
    }
    
    if (modelo) {
      query += ` AND modelo = $${paramIndex++}`;
      params.push(modelo);
    }
    
    if (talla) {
      query += ` AND talla = $${paramIndex++}`;
      params.push(talla);
    }
    
    if (cliente) {
      query += ` AND cliente = $${paramIndex++}`;
      params.push(cliente);
    }
    
    if (estilo) {
      query += ` AND estilo = $${paramIndex++}`;
      params.push(estilo);
    }
    
    query += ` ORDER BY created_at DESC`;
    
    const result = await client.query(query, params);

    // Bucket is private now — sign a fresh temporary URL for each photo instead
    // of trusting the (now-inaccessible) permanent URL stored at upload time.
    const rows = result.rows.map((row) => ({
      ...row,
      photoUrl: row.photo_filename ? generatePresignedGetUrl(row.photo_filename, 3600) : null,
    }));
    
    res.json(rows);
  } catch (err) {
    console.error("❌ Error fetching master codes:", err.message);
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});

/**
 * GET /api/master-codes/:id
 * Get a specific master code by ID or code
 * Fix: Properly handle both numeric IDs and string codes
 */
app.get("/api/master-codes/:id", authenticateToken, requireMerchantAccess, async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
    
    const { id } = req.params;
    
    // Check if the parameter is numeric (ID) or string (code)
    const isNumeric = /^\d+$/.test(id);
    
    let query;
    let params;
    
    if (isNumeric) {
      // Search by ID (numeric)
      query = `
        SELECT 
          id,
          code,
          type,
          modelo,
          correlativo,
          talla,
          cliente,
          color,
          estilo,
          description,
          sam_minutes as sam,
          photo_url as "photoUrl",
          photo_filename,
          created_at as "createdAt",
          created_by
        FROM master_codes
        WHERE id = $1
      `;
      params = [parseInt(id, 10)];
    } else {
      // Search by code (string)
      query = `
        SELECT 
          id,
          code,
          type,
          modelo,
          correlativo,
          talla,
          cliente,
          color,
          estilo,
          description,
          sam_minutes as sam,
          photo_url as "photoUrl",
          photo_filename,
          created_at as "createdAt",
          created_by
        FROM master_codes
        WHERE code = $1
      `;
      params = [id];
    }
    
    const result = await client.query(query, params);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Master code not found" });
    }

    const row = result.rows[0];
    row.photoUrl = row.photo_filename ? generatePresignedGetUrl(row.photo_filename, 3600) : null;
    
    res.json(row);
  } catch (err) {
    console.error("❌ Error fetching master code:", err.message);
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});

app.post("/api/master-codes/photo-upload-url", authenticateToken, requireMerchantAccess, async (req, res) => {
  try {
    const { filename, contentType } = req.body;
    if (!contentType || !/^image\//.test(contentType)) {
      return res.status(400).json({ success: false, error: "Valid image contentType required" });
    }
    const photoKey = makeStylePhotoKey(filename || "");
    const uploadUrl = generatePresignedPutUrl(photoKey, 300);   // no contentType arg
    res.json({ success: true, uploadUrl, photoKey });
  } catch (err) {
    console.error("❌ presign error:", err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * POST /api/master-codes
 * Create a new master code
 */
app.post("/api/master-codes", authenticateToken, requireMerchantAccess, async (req, res) => {
  const client = await pool.connect();
  let photoUrl = null;
  let photoKey = null;
  try {
    await setSchema(client);
    await client.query("BEGIN");
    
    const { 
      code, 
      type, 
      modelo, 
      correlativo, 
      talla, 
      cliente, 
      color, 
      estilo, 
      description, 
      sam,
      photoBase64,    // e.g. "data:image/png;base64,iVBORw0KG..."
      photoFilename,  // original filename, used only to infer extension
       photoKey: incomingPhotoKey,   // 
    } = req.body;
    
    // Validate required fields
    if (!code || !type || !modelo || !correlativo || !talla || !cliente || !color || !estilo || !description || !sam) {
      return res.status(400).json({ 
        success: false, 
        error: "All fields are required" 
      });
    }
    
    // Check if code already exists
    const existingCheck = await client.query(
      "SELECT id FROM master_codes WHERE code = $1",
      [code]
    );
    
    if (existingCheck.rows.length > 0) {
      return res.status(400).json({ 
        success: false, 
        error: "Master code already exists" 
      });
    }

    // Upload the photo to S3, if one was sent
    // The browser already uploaded the file straight to S3 via a presigned URL,
    // so we just persist the key it returned. A fresh GET URL is signed on read.
    if (incomingPhotoKey) {
      photoKey = incomingPhotoKey;
      photoUrl = generatePresignedGetUrl(photoKey, 3600);
    }
    
    const result = await client.query(
      `
      INSERT INTO master_codes (
        code,
        type,
        modelo,
        correlativo,
        talla,
        cliente,
        color,
        estilo,
        description,
        sam_minutes,
        photo_url,
        photo_filename,
        created_by,
        created_at,
        updated_at
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NOW(), NOW())
      RETURNING id, code, photo_url as "photoUrl", created_at as "createdAt"
      `,
      [
        code,
        type,
        modelo,
        correlativo,
        talla,
        cliente,
        color,
        estilo,
        description,
        parseFloat(sam) || 0,
        photoUrl,
        photoKey,
        req.user.id
      ]
    );
    
    await client.query("COMMIT");

    const masterCode = result.rows[0];
    if (photoKey) {
      masterCode.photoUrl = generatePresignedGetUrl(photoKey, 3600);
    }
    
    res.json({
      success: true,
      message: "Master code created successfully",
      masterCode
    });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("❌ Error creating master code:", err.message);

    if (photoKey) await deleteFromS3(photoKey); // avoid orphaned S3 objects
    
    if (err.code === "23505") {
      return res.status(400).json({ 
        success: false, 
        error: "Master code already exists" 
      });
    }
    
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});

/**
 * DELETE /api/master-codes/:id
 * Delete a master code
 * Fix: Properly handle both numeric IDs and string codes
 */
app.delete("/api/master-codes/:id", authenticateToken, requireMerchantAccess, async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
    await client.query("BEGIN");
    
    const { id } = req.params;
    
    // Check if the parameter is numeric (ID) or string (code)
    const isNumeric = /^\d+$/.test(id);
    
    let query;
    let params;
    let deletedCode;
    
    if (isNumeric) {
      // Delete by ID (numeric)
      query = "DELETE FROM master_codes WHERE id = $1 RETURNING id, code, photo_filename";
      params = [parseInt(id, 10)];
    } else {
      // Delete by code (string)
      query = "DELETE FROM master_codes WHERE code = $1 RETURNING id, code, photo_filename";
      params = [id];
    }
    
    const result = await client.query(query, params);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ 
        success: false, 
        error: "Master code not found" 
      });
    }
    
    deletedCode = result.rows[0].code;
    const deletedPhotoKey = result.rows[0].photo_filename;
    
    await client.query("COMMIT");

    if (deletedPhotoKey) {
      await deleteFromS3(deletedPhotoKey);
    }
    
    res.json({
      success: true,
      message: `Master code ${deletedCode} deleted successfully`
    });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("❌ Error deleting master code:", err.message);
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});

/**
 * PUT /api/master-codes/:id
 * Update an existing master code (fix a mistake). Accepts a numeric id or the
 * code string, mirroring GET/DELETE. Any subset of fields may be sent.
 *
 * Photo:
 *   - send  photoKey   (from /api/master-codes/photo-upload-url) to replace it
 *   - send  removePhoto: true   to clear it
 *   - send neither to leave the current photo untouched
 */
app.put("/api/master-codes/:id", authenticateToken, requireMerchantAccess, async (req, res) => {
  const client = await pool.connect();
  let newPhotoKey = null; // set if the caller uploaded a replacement photo
  let oldPhotoKey = null; // deleted from S3 only after a successful swap/remove
  try {
    await setSchema(client);
    await client.query("BEGIN");
 
    const { id } = req.params;
    const isNumeric = /^\d+$/.test(id);
 
    // Load the current row first (we need its id + old photo key).
    const currentRes = await client.query(
      isNumeric
        ? "SELECT id, code, photo_filename FROM master_codes WHERE id = $1"
        : "SELECT id, code, photo_filename FROM master_codes WHERE code = $1",
      [isNumeric ? parseInt(id, 10) : id]
    );
 
    if (currentRes.rows.length === 0) {
      await client.query("ROLLBACK");
      return res.status(404).json({ success: false, error: "Master code not found" });
    }
 
    const current = currentRes.rows[0];
    const rowId = current.id;
 
    const {
      code,
      type,
      modelo,
      correlativo,
      talla,
      cliente,
      color,
      estilo,
      description,
      sam,
      photoKey,     // replacement image key (optional)
      removePhoto,  // boolean, clear the image (optional)
    } = req.body;
 
    // If the code itself is being changed, make sure no OTHER row already uses it.
    if (code && code !== current.code) {
      const dup = await client.query(
        "SELECT id FROM master_codes WHERE code = $1 AND id <> $2",
        [code, rowId]
      );
      if (dup.rows.length > 0) {
        await client.query("ROLLBACK");
        return res.status(400).json({ success: false, error: "Master code already exists" });
      }
    }
 
    // Build the UPDATE dynamically so partial edits work too.
    const updates = [];
    const values = [];
    let i = 1;
    const setField = (col, val) => {
      updates.push(`${col} = $${i++}`);
      values.push(val);
    };
 
    if (code !== undefined) setField("code", code);
    if (type !== undefined) setField("type", type);
    if (modelo !== undefined) setField("modelo", modelo);
    if (correlativo !== undefined) setField("correlativo", correlativo);
    if (talla !== undefined) setField("talla", talla);
    if (cliente !== undefined) setField("cliente", cliente);
    if (color !== undefined) setField("color", color);
    if (estilo !== undefined) setField("estilo", estilo);
    if (description !== undefined) setField("description", description);
    if (sam !== undefined) setField("sam_minutes", parseFloat(sam) || 0);
 
    if (photoKey) {
      newPhotoKey = photoKey;
      oldPhotoKey = current.photo_filename || null;
      setField("photo_filename", photoKey);
      setField("photo_url", generatePresignedGetUrl(photoKey, 3600));
    } else if (removePhoto) {
      oldPhotoKey = current.photo_filename || null;
      setField("photo_filename", null);
      setField("photo_url", null);
    }
 
    if (updates.length === 0) {
      await client.query("ROLLBACK");
      return res.status(400).json({ success: false, error: "No fields to update" });
    }
 
    updates.push(`updated_at = NOW()`);
    values.push(rowId);
 
    const result = await client.query(
      `
      UPDATE master_codes
      SET ${updates.join(", ")}
      WHERE id = $${i}
      RETURNING
        id, code, type, modelo, correlativo, talla, cliente, color, estilo,
        description, sam_minutes AS sam, photo_filename,
        created_at AS "createdAt"
      `,
      values
    );
 
    await client.query("COMMIT");
 
    // The previous image is now unreferenced — clean it up (best effort).
    if (oldPhotoKey && oldPhotoKey !== newPhotoKey) {
      await deleteFromS3(oldPhotoKey);
    }
 
    const row = result.rows[0];
    row.photoUrl = row.photo_filename ? generatePresignedGetUrl(row.photo_filename, 3600) : null;
 
    res.json({
      success: true,
      message: "Master code updated successfully",
      masterCode: row,
    });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("❌ Error updating master code:", err.message);
    // Don't leak the object we just uploaded if the DB write failed.
    if (newPhotoKey) await deleteFromS3(newPhotoKey);
    if (err.code === "23505") {
      return res.status(400).json({ success: false, error: "Master code already exists" });
    }
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});

// ----------------------------------------------------------------------
// 18. USER MANAGEMENT
// ----------------------------------------------------------------------
app.get("/api/users", authenticateToken, allowRoles("engineer", "supervisor", "soporte_it", "skyrina","master"), async (req, res, next) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
    const result = await client.query(
      `SELECT id, username, role, line_number, full_name, is_active, created_at, updated_at
       FROM users
       ORDER BY
         CASE role WHEN 'engineer' THEN 1 WHEN 'supervisor' THEN 2 WHEN 'line_leader' THEN 3 WHEN 'soporte_it' THEN 4 WHEN 'skyrina' THEN 5 WHEN 'master' THEN 6 ELSE 7 END,
         line_number NULLS FIRST,
         username`
    );
    res.json({ success: true, users: result.rows });
  } catch (err) {
    next(err);
  } finally {
    client.release();
  }
});

app.post(
  "/api/users",
  authenticateToken,
  allowRoles("engineer", "supervisor","master"),
  validate([
    body("username").notEmpty().withMessage("Username required"),
    body("password").isLength({ min: 8 }).withMessage("Password must be at least 8 characters"),
    body("role").isIn(["engineer", "line_leader", "supervisor", "soporte_it", "skyrina", "master"]).withMessage("Invalid role"),
    body("line_number").if(body("role").equals("line_leader")).isInt({ min: 1, max: 26 }).withMessage("Line number 1-26 required for line leader"),
  ]),
  async (req, res, next) => {
    const client = await pool.connect();
    try {
      await setSchema(client);
      const { username, password, role, line_number, full_name } = req.body;

      if (role === "line_leader") {
        const existing = await client.query(
          "SELECT username FROM users WHERE role = 'line_leader' AND line_number = $1 AND is_active = TRUE",
          [line_number]
        );
        if (existing.rows.length > 0) {
          return res.status(400).json({
            success: false,
            error: `Line ${line_number} is already assigned to user: ${existing.rows[0].username}`,
          });
        }
      }

      const saltRounds = 10;
      const passwordHash = await bcrypt.hash(password, saltRounds);
      const result = await client.query(
        `INSERT INTO users (username, password_hash, role, line_number, full_name, is_active)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING id, username, role, line_number, full_name, is_active, created_at`,
        [username, passwordHash, role, line_number || null, full_name || username, true]
      );

      logger.info("User created", { username, role, createdBy: req.user.username });
      res.json({ success: true, message: "User created successfully", user: result.rows[0] });
    } catch (err) {
      if (err.code === "23505") {
        return res.status(400).json({ success: false, error: "Username already exists" });
      }
      next(err);
    } finally {
      client.release();
    }
  }
);

app.put("/api/users/:id", authenticateToken, allowRoles("engineer", "supervisor", "master"), async (req, res, next) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
    const { id } = req.params;
    const { username, password, role, line_number, full_name, is_active } = req.body;

    if (parseInt(id, 10) === req.user.id && is_active === false) {
      return res.status(400).json({ success: false, error: "You cannot deactivate your own account" });
    }

    const updates = [];
    const values = [];
    let idx = 1;

    if (username !== undefined) {
      updates.push(`username = $${idx++}`);
      values.push(username);
    }
    if (password !== undefined) {
      const saltRounds = 10;
      const passwordHash = await bcrypt.hash(password, saltRounds);
      updates.push(`password_hash = $${idx++}`);
      values.push(passwordHash);
    }
    if (role !== undefined) {
      updates.push(`role = $${idx++}`);
      values.push(role);
    }
    if (line_number !== undefined) {
      updates.push(`line_number = $${idx++}`);
      values.push(line_number);
    }
    if (full_name !== undefined) {
      updates.push(`full_name = $${idx++}`);
      values.push(full_name);
    }
    if (is_active !== undefined) {
      updates.push(`is_active = $${idx++}`);
      values.push(is_active);
    }

    updates.push(`updated_at = NOW()`);
    if (updates.length === 1) {
      return res.status(400).json({ success: false, error: "No fields to update" });
    }

    values.push(id);
    const query = `UPDATE users SET ${updates.join(", ")} WHERE id = $${idx} RETURNING id, username, role, line_number, full_name, is_active, created_at, updated_at`;
    const result = await client.query(query, values);
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: "User not found" });
    }

    logger.info("User updated", { userId: id, updatedBy: req.user.username });
    res.json({ success: true, message: "User updated successfully", user: result.rows[0] });
  } catch (err) {
    next(err);
  } finally {
    client.release();
  }
});

app.delete("/api/users/:id", authenticateToken, allowRoles("engineer", "supervisor", "master"), async (req, res, next) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
    const { id } = req.params;
    if (parseInt(id, 10) === req.user.id) {
      return res.status(400).json({ success: false, error: "Cannot delete your own account" });
    }

    const result = await client.query(
      `UPDATE users SET is_active = FALSE, updated_at = NOW() WHERE id = $1 AND is_active = TRUE RETURNING id, username`,
      [id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: "User not found or already inactive" });
    }

    logger.info("User deactivated", { userId: id, deactivatedBy: req.user.username });
    res.json({ success: true, message: "User deactivated successfully" });
  } catch (err) {
    next(err);
  } finally {
    client.release();
  }
});

// ----------------------------------------------------------------------
// 18.5 WORK ORDERS, CUSTOMERS & FABRICS ENDPOINTS (from server.js)
// ----------------------------------------------------------------------
/**
 * GET /api/work-orders
 * Get all work orders with optional filters
 */
/**
 * GET /api/customers
 * POST /api/customers
 */
app.get("/api/customers", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
    const result = await client.query("SELECT id, name, market_type, code, created_at FROM customers ORDER BY name");
    res.json({ success: true, customers: result.rows });
  } catch (err) {
    logger.error("❌ Error fetching customers:", err.message);
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});

app.post("/api/customers", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
    const { name, market_type, code } = req.body;
    if (!name || !name.trim()) {
      return res.status(400).json({ success: false, error: "Customer name is required" });
    }
    const marketType = market_type === "export" ? "export" : "domestico";
    const customerCode = code && code.trim() ? code.trim().toUpperCase() : null;
    const result = await client.query(
      "INSERT INTO customers (name, market_type, code) VALUES ($1, $2, $3) RETURNING id, name, market_type, code, created_at",
      [name.trim(), marketType, customerCode]
    );
    res.json({ success: true, customer: result.rows[0] });
  } catch (err) {
    logger.error("❌ Error creating customer:", err.message);
    if (err.code === "23505") {
      const isCodeConflict = err.constraint === "idx_customers_code_unique";
      return res.status(400).json({
        success: false,
        error: isCodeConflict
          ? "Another customer already uses that code"
          : "A customer with that name already exists",
      });
    }
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});

/**
 * GET /api/fabrics
 * POST /api/fabrics
 */
app.get("/api/fabrics", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
    const result = await client.query("SELECT id, name, code, created_at FROM fabrics ORDER BY name");
    res.json({ success: true, fabrics: result.rows });
  } catch (err) {
    logger.error("❌ Error fetching fabrics:", err.message);
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});

app.post("/api/fabrics", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
   const { name } = req.body;
    if (!name || !name.trim()) {
      return res.status(400).json({ success: false, error: "Fabric name is required" });
    }
    const result = await client.query(
      "INSERT INTO fabrics (name, code) VALUES ($1, $2) RETURNING id, name, code, created_at",
      [name.trim(), null]
    );
    res.json({ success: true, fabric: result.rows[0] });
  } catch (err) {
    logger.error("❌ Error creating fabric:", err.message);
    if (err.code === "23505") {
      return res.status(400).json({ success: false, error: "That fabric already exists" });
    }
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});



/**
 * GET /api/work-orders/:id
 * Get a specific work order by ID
 */


/**
 * POST /api/work-orders
 * Create a new work order
 */


/**
 * PUT /api/work-orders/:id
 * Update an existing work order
 */
app.put("/api/work-orders/:id", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
    
    const { id } = req.params;
    const {
      totalQuantity,
      warehouseStock,
      extraQuantity,
      totalToProduce,
      commitmentDate,
      customerId,
      styleDescription,
      styleCode,
      estilo,
      color,
      fabricSupplier,
      fabrics,
      lineNo,
      runDate,
      status,
      masterCodeId,
      samMinutes,
      customerPo,
      fabricName,        // ← new
      fabricCode,        // ← new
      yieldPerPiece,
    } = req.body;
    
    // Build update query dynamically
    const updates = [];
    const values = [];
    let paramIndex = 1;

    if (totalQuantity !== undefined) {
      updates.push(`quantity = $${paramIndex++}`);
      values.push(parseFloat(totalQuantity) || 0);
    }

    if (customerId !== undefined) {
      const customerResult = await client.query("SELECT name FROM customers WHERE id = $1", [parseInt(customerId)]);
      if (customerResult.rows.length === 0) {
        return res.status(400).json({ success: false, error: "Customer not found" });
      }
      updates.push(`customer_id = $${paramIndex++}`);
      values.push(parseInt(customerId));
      updates.push(`customer_name = $${paramIndex++}`);
      values.push(customerResult.rows[0].name);
    }
    
    if (styleDescription !== undefined) {
      updates.push(`style_description = $${paramIndex++}`);
      values.push(styleDescription);
    }
    
    if (color !== undefined) {
      updates.push(`color = $${paramIndex++}`);
      values.push(color || null);
    }
    
    if (fabricSupplier !== undefined) {
      updates.push(`fabric_supplier = $${paramIndex++}`);
      values.push(fabricSupplier || null);
    }

    if (fabrics !== undefined) {
      updates.push(`fabrics = $${paramIndex++}`);
      values.push(Array.isArray(fabrics) ? fabrics : []);
    }

    if (customerPo !== undefined) {
      updates.push(`customer_po = $${paramIndex++}`);
      values.push(customerPo || null);
    }

    // Header copy of the line-level fabric/yield, kept for the PO list view.
    if (fabricName !== undefined) {
      updates.push(`fabric_name = $${paramIndex++}`);
      values.push(fabricName || null);
      // keep the legacy display column in sync
      updates.push(`fabric_supplier = $${paramIndex++}`);
      values.push(fabricName || null);
    }

    if (fabricCode !== undefined) {
      updates.push(`fabric_code = $${paramIndex++}`);
      values.push(fabricCode || null);
    }

    if (yieldPerPiece !== undefined) {
      updates.push(`yield_per_piece = $${paramIndex++}`);
      values.push(
        yieldPerPiece === "" || yieldPerPiece === null || isNaN(parseFloat(yieldPerPiece))
          ? null
          : parseFloat(yieldPerPiece)
      );
    }

    if (styleCode !== undefined) {
      updates.push(`style_code = $${paramIndex++}`);
      values.push(styleCode || null);
    }

    if (estilo !== undefined) {
      updates.push(`estilo = $${paramIndex++}`);
      values.push(estilo || null);
    }
    
    if (lineNo !== undefined) {
      updates.push(`line_no = $${paramIndex++}`);
      values.push(lineNo || null);
    }
    
    if (runDate !== undefined) {
      updates.push(`run_date = $${paramIndex++}`);
      values.push(runDate || null);
    }

    if (warehouseStock !== undefined) {
      updates.push(`warehouse_stock = $${paramIndex++}`);
      values.push(parseFloat(warehouseStock) || 0);
    }

    if (extraQuantity !== undefined) {
      updates.push(`extra_quantity = $${paramIndex++}`);
      values.push(parseFloat(extraQuantity) || 0);
    }

    if (totalToProduce !== undefined) {
      updates.push(`total_to_produce = $${paramIndex++}`);
      values.push(parseFloat(totalToProduce) || 0);
    }

    if (commitmentDate !== undefined) {
      updates.push(`commitment_date = $${paramIndex++}`);
      values.push(commitmentDate || null);
    }

    if (masterCodeId !== undefined) {
      updates.push(`master_code_id = $${paramIndex++}`);
      values.push(masterCodeId ? parseInt(masterCodeId) : null);
    }

    if (samMinutes !== undefined) {
      updates.push(`sam_minutes = $${paramIndex++}`);
      values.push(samMinutes ? parseFloat(samMinutes) : null);
    }
    
    if (status !== undefined) {
      updates.push(`status = $${paramIndex++}`);
      values.push(status);
    }
    
    updates.push(`updated_at = NOW()`);
    
    if (updates.length === 1) {
      return res.status(400).json({
        success: false,
        error: "No fields to update",
      });
    }
    
    values.push(id);
    
    const query = `
      UPDATE work_orders 
      SET ${updates.join(", ")}
      WHERE id = $${paramIndex}
      RETURNING *
    `;
    
    const result = await client.query(query, values);
    
    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: "Work order not found",
      });
    }
    
    res.json({
      success: true,
      message: "Work order updated successfully",
      workOrder: result.rows[0],
    });
  } catch (err) {
    logger.error("❌ Error updating work order:", err.message);
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});

/**
 * PUT /api/work-orders/:id/status
 * Update work order status
 */
app.put("/api/work-orders/:id/status", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
    
    const { id } = req.params;
    const { status } = req.body;
    
    const validStatuses = ['pending', 'assigned', 'in_progress', 'completed', 'cancelled'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({
        success: false,
        error: "Invalid status. Must be one of: " + validStatuses.join(', '),
      });
    }
    
    const result = await client.query(
      `
      UPDATE work_orders
      SET status = $1, updated_at = NOW()
      WHERE id = $2
      RETURNING id, work_order_no, status
      `,
      [status, id]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Work order not found" });
    }
    
    res.json({
      success: true,
      message: "Work order status updated",
      workOrder: result.rows[0],
    });
  } catch (err) {
    logger.error("❌ Error updating work order status:", err.message);
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});

/**
 * DELETE /api/work-orders/:id
 * Soft delete a work order
 */
/**
 * POST /api/work-orders/recalculate-status
 * Recomputes each work order's status from its actual line assignments:
 * pending (nothing assigned) -> assigned (partially) -> in_progress (a line has started)
 * -> completed (fully assigned and every assignment is completed).
 */
app.post("/api/work-orders/recalculate-status", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
    await client.query("BEGIN");

    const orders = await client.query(`
      SELECT
        wo.id,
        wo.status,
        wo.total_to_produce,
        COALESCE(SUM(la.assigned_quantity) FILTER (WHERE la.status NOT IN ('cancelled', 'rejected')), 0) as assigned_quantity,
        COUNT(la.id) FILTER (WHERE la.status = 'in_progress') as in_progress_count,
        COUNT(la.id) FILTER (WHERE la.status NOT IN ('cancelled', 'rejected')) as active_count,
        COUNT(la.id) FILTER (WHERE la.status = 'completed') as completed_count
      FROM work_orders wo
      LEFT JOIN line_assignments la ON la.work_order_id = wo.id
      WHERE wo.status != 'cancelled'
      GROUP BY wo.id
    `);

    let updated = 0;
    for (const o of orders.rows) {
      const totalToProduce = parseFloat(o.total_to_produce) || 0;
      const assigned = parseFloat(o.assigned_quantity) || 0;
      const activeCount = parseInt(o.active_count) || 0;
      const completedCount = parseInt(o.completed_count) || 0;
      const inProgressCount = parseInt(o.in_progress_count) || 0;

      let newStatus = "pending";
      if (activeCount > 0 && completedCount === activeCount && assigned >= totalToProduce && totalToProduce > 0) {
        newStatus = "completed";
      } else if (inProgressCount > 0) {
        newStatus = "in_progress";
      } else if (activeCount > 0) {
        newStatus = "assigned";
      }

      if (newStatus !== o.status) {
        await client.query("UPDATE work_orders SET status = $1, updated_at = NOW() WHERE id = $2", [newStatus, o.id]);
        updated++;
      }
    }

    await client.query("COMMIT");

    res.json({ success: true, message: `Recalculated status for ${orders.rows.length} work orders`, updated });
  } catch (err) {
    await client.query("ROLLBACK");
    logger.error("❌ Error recalculating work order statuses:", err.message);
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});

app.delete("/api/work-orders/:id", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
    await client.query("BEGIN");
    
    const { id } = req.params;
    
    // Check if work order has active assignments
    const assignmentsCheck = await client.query(
      `
      SELECT id FROM line_assignments 
      WHERE work_order_id = $1 AND status IN ('planned', 'released', 'in_progress')
      `,
      [id]
    );
    
    if (assignmentsCheck.rows.length > 0) {
      return res.status(400).json({
        success: false,
        error: "Cannot delete work order with active assignments. Cancel assignments first.",
      });
    }
    
    // Soft delete by setting status to 'cancelled'
    const result = await client.query(
      `
      UPDATE work_orders
      SET status = 'cancelled', updated_at = NOW()
      WHERE id = $1 AND status != 'completed'
      RETURNING id, work_order_no
      `,
      [id]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: "Work order not found or already completed",
      });
    }
    
    await client.query("COMMIT");
    
    res.json({
      success: true,
      message: "Work order cancelled successfully",
    });
  } catch (err) {
    await client.query("ROLLBACK");
    logger.error("❌ Error cancelling work order:", err.message);
    res.status(500).json({ success: false, error: err.message });
  } finally {
    client.release();
  }
});

// ----------------------------------------------------------------------
// 19. CONDITIONAL DEVELOPMENT ENDPOINTS
// ----------------------------------------------------------------------
if (process.env.NODE_ENV !== "production") {
  app.post("/api/reset-database", authenticateToken, allowRoles("engineer"), async (req, res, next) => {
    const client = await pool.connect();
    try {
      await setSchema(client);
      await client.query("BEGIN");
      await client.query("DELETE FROM operation_sewed_entries");
      await client.query("DELETE FROM operation_hourly_entries");
      await client.query("DELETE FROM slot_targets");
      await client.query("DELETE FROM operator_operations");
      await client.query("DELETE FROM run_operators");
      await client.query("DELETE FROM shift_slots");
      await client.query("DELETE FROM line_runs");
      await client.query("COMMIT");
      logger.warn("Database reset performed", { user: req.user.username });
      res.json({ success: true, message: "Database cleared (development only)" });
    } catch (err) {
      await client.query("ROLLBACK");
      next(err);
    } finally {
      client.release();
    }
  });
}

// ----------------------------------------------------------------------
// 20. CENTRAL ERROR HANDLING
// ----------------------------------------------------------------------
app.use(errorHandler);

// ----------------------------------------------------------------------
// 21. GRACEFUL SHUTDOWN
// ----------------------------------------------------------------------
const server = app.listen(process.env.PORT || 5000, async () => {
  logger.info(`🚀 Server listening on port ${process.env.PORT || 5000}`);
  logger.info(`📁 Schema: prod_db_schema`);
  logger.info(`🗄️  Database: ${process.env.PG_DB || "prod_db"}`);

  // Migrations are NOT run at startup on Lambda: cold starts would run them
  // repeatedly and concurrently. Run them once as a separate step and keep
  // RUN_MIGRATIONS=false on the function. (runMigrations remains defined below.)
});

const gracefulShutdown = async (signal) => {
  logger.info(`${signal} received, closing server...`);
  server.close(async () => {
    logger.info("HTTP server closed.");
    try {
      await pool.end();
      logger.info("Database pool closed.");
      process.exit(0);
    } catch (err) {
      logger.error("Error during shutdown", { error: err.message });
      process.exit(1);
    }
  });
};

process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));
process.on("SIGINT", () => gracefulShutdown("SIGINT"));

module.exports = { app, pool };