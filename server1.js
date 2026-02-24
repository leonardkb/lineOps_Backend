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
    new winston.transports.File({ filename: "logs/error.log", level: "error" }),
    new winston.transports.File({ filename: "logs/combined.log" }),
  ],
});

if (process.env.NODE_ENV !== "production") {
  logger.add(
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      ),
    })
  );
}

// ----------------------------------------------------------------------
// 2. EXPRESS SETUP
// ----------------------------------------------------------------------
const app = express();

app.use(helmet());
app.use(compression());
app.use(express.json({ limit: "1mb" }));

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
  max: 20,
  message: { success: false, error: "Too many authentication attempts, please try again later." },
  standardHeaders: true,
  legacyHeaders: false,
});

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
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
  ssl: false, // adjust for production if needed
  max: Number(process.env.PG_POOL_MAX) || 20,
  idleTimeoutMillis: Number(process.env.PG_IDLE_TIMEOUT) || 30000,
  connectionTimeoutMillis: Number(process.env.PG_CONNECTION_TIMEOUT) || 5000,
});

pool.on("error", (err) => {
  logger.error("Unexpected database pool error", { error: err.message, stack: err.stack });
  process.exit(-1);
});

const setSchema = async (client) => {
  await client.query("SET search_path TO prod_db_schema");
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
        CONSTRAINT chk_role CHECK (role IN ('engineer', 'line_leader', 'supervisor')),
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
    body("operators").isInt({ min: 0 }).withMessage("Operators must be a non‑negative integer"),
    body("workingHours").isFloat({ min: 0.1 }).withMessage("Working hours must be positive"),
    body("sam").isFloat({ min: 0.01 }).withMessage("SAM must be positive"),
    body("efficiency").optional().isFloat({ min: 0.01, max: 1 }).withMessage("Efficiency must be between 0.01 and 1"),
    body("target").optional().isFloat({ min: 0 }).withMessage("Target must be non‑negative"),
    body("targetPerHour").optional().isFloat({ min: 0 }).withMessage("Target per hour must be non‑negative"),
    body("slots").isArray({ min: 1 }).withMessage("At least one shift slot required"),
    body("slots.*.label").notEmpty().withMessage("Slot label required"),
    body("slots.*.hours").isFloat({ min: 0 }).withMessage("Planned hours must be non‑negative"),
  ]),
  async (req, res, next) => {
    const client = await pool.connect();
    try {
      await setSchema(client);
      await client.query("BEGIN");

      const { line, date, style, operators, workingHours, sam, efficiency, target, targetPerHour, slots } = req.body;

      const lineRunResult = await client.query(
        `INSERT INTO line_runs (line_no, run_date, style, operators_count, working_hours, sam_minutes, efficiency, target_pcs, target_per_hour, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW())
         RETURNING id`,
        [
          line,
          date,
          style,
          parseInt(operators, 10) || 0,
          parseFloat(workingHours),
          parseFloat(sam),
          parseFloat(efficiency) || 0.7,
          parseFloat(target) || 0,
          parseFloat(targetPerHour) || 0,
        ]
      );

      const runId = lineRunResult.rows[0].id;
      logger.info(`Line run created`, { runId, line, date, style });

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
      res.json({ success: true, updatedCount });
    } catch (err) {
      await client.query("ROLLBACK");
      next(err);
    } finally {
      client.release();
    }
  }
);

// ----------------------------------------------------------------------
// 13. DATA RETRIEVAL ENDPOINTS
// ----------------------------------------------------------------------
app.get("/api/get-run-data/:runId", authenticateToken, async (req, res, next) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
    const { runId } = req.params;

    const runResult = await client.query("SELECT * FROM line_runs WHERE id = $1", [runId]);
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
      `SELECT id, line_no, run_date, style, operators_count, working_hours, sam_minutes,
              efficiency, target_pcs, target_per_hour, created_at
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
      `SELECT * FROM line_runs WHERE line_no = $1 ORDER BY created_at DESC LIMIT 1`,
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

// Compatibility routes (server.js style)
app.get("/api/run/:runId", authenticateToken, async (req, res, next) => {
  const client = await pool.connect();
  try {
    await setSchema(client);

    const { runId } = req.params;

    const runResult = await client.query("SELECT * FROM line_runs WHERE id = $1", [runId]);
    if (runResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Run not found" });
    }
    const runData = runResult.rows[0];

    const slotsResult = await client.query(
      `SELECT id, slot_order, slot_label, slot_start, slot_end, planned_hours
       FROM shift_slots
       WHERE run_id = $1
       ORDER BY slot_order`,
      [runId]
    );

    const operatorsResult = await client.query(
      `SELECT id, operator_no, operator_name
       FROM run_operators
       WHERE run_id = $1
       ORDER BY operator_no`,
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
          json_object_agg(
            COALESCE(s.slot_label, ''),
            COALESCE(h.stitched_qty, 0)
          ) as stitched_data
         FROM operator_operations o
         LEFT JOIN operation_hourly_entries h ON o.id = h.operation_id
         LEFT JOIN shift_slots s ON h.slot_id = s.id
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
    next(err);
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

// --------------------------------------------------------------
// SUPERVISOR DASHBOARD ENDPOINTS (FIXED)
// --------------------------------------------------------------

const requireSupervisor = (req, res, next) => {
  if (req.user.role !== "supervisor") {
    return res.status(403).json({
      success: false,
      error: "Access denied. Supervisor role required.",
    });
  }
  next();
};

/**
 * GET /api/supervisor/summary?date=YYYY-MM-DD
 * Returns global totals for the selected date
 */
app.get(
  "/api/supervisor/summary",
  authenticateToken,
  requireSupervisor,
  async (req, res) => {
    const client = await pool.connect();
    try {
    await setSchema(client);

    const { date } = req.query;
    if (!date) {
      return res.status(400).json({ success: false, error: "date parameter required" });
    }

    // 1) Total target – direct sum
    const targetResult = await client.query(
      `SELECT COALESCE(SUM(target_pcs), 0) as total_target
       FROM line_runs
       WHERE run_date = $1`,
      [date]
    );
    const totalTarget = parseFloat(targetResult.rows[0].total_target) || 0;

    // 2) Total sewed – per operator per line: max of operation totals, then sum across lines
    // Replace the old totalSewed query with:
const sewedResult = await client.query(
  `SELECT COALESCE(SUM(line_min), 0) AS total_sewed
   FROM (
     SELECT 
       lr.line_no,
       MIN(COALESCE(op_total, 0)) AS line_min
     FROM line_runs lr
     JOIN run_operators ro ON lr.id = ro.run_id
     JOIN operator_operations oo ON ro.id = oo.run_operator_id
     LEFT JOIN (
       SELECT operation_id, SUM(sewed_qty) AS op_total
       FROM operation_sewed_entries
       GROUP BY operation_id
     ) se ON oo.id = se.operation_id
     WHERE lr.run_date = $1
     GROUP BY lr.line_no
   ) line_totals`,
  [date]
);
    const totalSewed = parseFloat(sewedResult.rows[0].total_sewed) || 0;

    // 3) Total operators – distinct count
    const operatorsResult = await client.query(
      `SELECT COUNT(DISTINCT ro.operator_no) as total_operators
       FROM run_operators ro
       JOIN line_runs lr ON ro.run_id = lr.id
       WHERE lr.run_date = $1`,
      [date]
    );
    const totalOperators = parseInt(operatorsResult.rows[0].total_operators) || 0;

    // 4) Efficiency – using bottleneck per run (min pieces) to count garments correctly
    const efficiencyResult = await client.query(
      `
      WITH run_available_minutes AS (
        SELECT 
          id AS run_id,
          (working_hours * operators_count * 60) AS available_minutes
        FROM line_runs
        WHERE run_date = $1
      ),
      run_operation_totals AS (
        SELECT 
          lr.id AS run_id,
          lr.sam_minutes,
          oo.id AS operation_id,
          COALESCE(SUM(se.sewed_qty), 0) AS op_total
        FROM line_runs lr
        JOIN run_operators ro ON lr.id = ro.run_id
        JOIN operator_operations oo ON ro.id = oo.run_operator_id
        LEFT JOIN operation_sewed_entries se ON oo.id = se.operation_id
        WHERE lr.run_date = $1
        GROUP BY lr.id, lr.sam_minutes, oo.id
      ),
      run_min_pieces AS (
        SELECT 
          run_id,
          sam_minutes,
          MIN(op_total) AS min_pieces   -- bottleneck determines completed garments
        FROM run_operation_totals
        GROUP BY run_id, sam_minutes
      )
      SELECT 
        COALESCE(SUM(ram.available_minutes), 0) AS total_available_minutes,
        COALESCE(SUM(rmp.min_pieces * rmp.sam_minutes), 0) AS total_sam_output
      FROM run_available_minutes ram
      LEFT JOIN run_min_pieces rmp ON ram.run_id = rmp.run_id;
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
app.get(
  "/api/supervisor/alert-count",
  authenticateToken,
  requireSupervisor,
  async (req, res) => {
    const client = await pool.connect();
    try {
      await setSchema(client);

      const { date } = req.query;
      if (!date) {
        return res
          .status(400)
          .json({ success: false, error: "date parameter required" });
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
  }
);

/**
 * GET /api/supervisor/line-performance?date=YYYY-MM-DD
 * Returns per‑line: line_no, totalTarget, totalSewed, achievement, operators
 */
app.get(
  "/api/supervisor/line-performance",
  authenticateToken,
  requireSupervisor,
  async (req, res) => {
    const client = await pool.connect();
    try {
    await setSchema(client);

    const { date } = req.query;
    if (!date) {
      return res.status(400).json({ success: false, error: "date parameter required" });
    }

    const query = `
      WITH line_targets AS (
        SELECT line_no, SUM(target_pcs) AS total_target
        FROM line_runs
        WHERE run_date = $1
        GROUP BY line_no
      ),
      line_operation_totals AS (
        SELECT 
          lr.line_no,
          oo.id AS operation_id,
          COALESCE(SUM(se.sewed_qty), 0) AS op_total
        FROM line_runs lr
        JOIN run_operators ro ON lr.id = ro.run_id
        JOIN operator_operations oo ON ro.id = oo.run_operator_id
        LEFT JOIN operation_sewed_entries se ON oo.id = se.operation_id
        WHERE lr.run_date = $1
        GROUP BY lr.line_no, oo.id
      ),
      line_sewed AS (
        SELECT line_no, MIN(op_total) AS total_sewed
        FROM line_operation_totals
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
        CASE 
          WHEN lt.total_target > 0 
          THEN (COALESCE(ls.total_sewed, 0) / lt.total_target) * 100 
          ELSE 0 
        END AS achievement
      FROM line_targets lt
      LEFT JOIN line_sewed ls ON lt.line_no = ls.line_no
      LEFT JOIN line_operators lo ON lt.line_no = lo.line_no
      ORDER BY lt.line_no;
    `;

    const result = await client.query(query, [date]);

    const lines = result.rows.map((row) => ({
      lineNo: row.line_no,
      totalTarget: parseFloat(row.total_target) || 0,
      totalSewed: parseFloat(row.total_sewed) || 0,
      operators: parseInt(row.operators_count) || 0,
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

// ----------------------------------------------------------------------
// 18. USER MANAGEMENT
// ----------------------------------------------------------------------
app.get("/api/users", authenticateToken, allowRoles("engineer", "supervisor"), async (req, res, next) => {
  const client = await pool.connect();
  try {
    await setSchema(client);
    const result = await client.query(
      `SELECT id, username, role, line_number, full_name, is_active, created_at, updated_at
       FROM users
       ORDER BY
         CASE role WHEN 'engineer' THEN 1 WHEN 'supervisor' THEN 2 WHEN 'line_leader' THEN 3 ELSE 4 END,
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
  allowRoles("engineer", "supervisor"),
  validate([
    body("username").notEmpty().withMessage("Username required"),
    body("password").isLength({ min: 8 }).withMessage("Password must be at least 8 characters"),
    body("role").isIn(["engineer", "line_leader", "supervisor"]).withMessage("Invalid role"),
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

app.put("/api/users/:id", authenticateToken, allowRoles("engineer", "supervisor"), async (req, res, next) => {
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

app.delete("/api/users/:id", authenticateToken, allowRoles("engineer", "supervisor"), async (req, res, next) => {
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

  try {
    await runMigrations();
  } catch (err) {
    logger.error("Migrations failed, exiting...");
    process.exit(1);
  }
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