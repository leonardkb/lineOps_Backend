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
  ssl: false, // adjust for production if needed
  max: Number(process.env.PG_POOL_MAX) || 50,
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
       WHERE line_no = $1
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
       WHERE line_no = $1 AND run_date = $2
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
    const runResult = await client.query("SELECT * FROM line_runs WHERE id = $1", [runId]);

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
// 14. DUPLICATE RUN ENDPOINT (from server.js)
// ----------------------------------------------------------------------
app.post(
  "/api/duplicate-run/:runId",
  authenticateToken,
  validate([
    param("runId").isInt({ gt: 0 }).withMessage("Valid run ID required"),
    body("newDate").isDate().withMessage("Valid newDate (YYYY-MM-DD) required"),
    body("newLineNo").optional().isString().withMessage("newLineNo must be a string if provided"),
  ]),
  async (req, res, next) => {
    const client = await pool.connect();
    try {
      await setSchema(client);
      await client.query("BEGIN");

      const { runId } = req.params;
      const { newDate } = req.body;            // required: YYYY-MM-DD
      const newLineNo = req.body.newLineNo;    // optional – if omitted, same line_no is used

      // 1. Get source run
      const sourceRunRes = await client.query(
        `SELECT line_no, style, operators_count, working_hours,
                sam_minutes, efficiency, target_pcs, target_per_hour
         FROM line_runs WHERE id = $1`,
        [runId]
      );
      if (sourceRunRes.rowCount === 0) {
        return res.status(404).json({ success: false, error: "Source run not found" });
      }
      const src = sourceRunRes.rows[0];

      // 2. Insert new line_run
      const newRunRes = await client.query(
        `INSERT INTO line_runs
           (line_no, run_date, style, operators_count, working_hours,
            sam_minutes, efficiency, target_pcs, target_per_hour, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW())
         RETURNING id`,
        [
          newLineNo || src.line_no,
          newDate,
          src.style,
          src.operators_count,
          src.working_hours,
          src.sam_minutes,
          src.efficiency,
          src.target_pcs,
          src.target_per_hour,
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
      next(err);
    } finally {
      client.release();
    }
  }
);
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
      `SELECT COALESCE(SUM(target_pcs), 0) as total_target
       FROM line_runs
       WHERE run_date = $1`,
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

    // 4) Efficiency – using bottleneck per run (min pieces) to count garments correctly
      // 4) Efficiency – using packing output (finished garments) to count total SAM produced
const efficiencyResult = await client.query(
  `
  WITH run_available_minutes AS (
    SELECT
      id AS run_id,
      (working_hours * operators_count * 60) AS available_minutes
    FROM line_runs
    WHERE run_date = $1
  ),
  run_packing_totals AS (
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
    COALESCE(SUM(ram.available_minutes), 0) AS total_available_minutes,
    COALESCE(SUM(rpt.packing_total * rpt.sam_minutes), 0) AS total_sam_output
  FROM run_available_minutes ram
  LEFT JOIN run_packing_totals rpt ON ram.run_id = rpt.run_id;
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

// ========== overview api endpoints ==========


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
        -- SAM-based efficiency (most accurate)
        CASE 
          WHEN SUM(operators_count * working_hours * 60) > 0 
          THEN (SUM(total_sewed * sam_minutes) / SUM(operators_count * working_hours * 60)) * 100
          ELSE 0
        END as efficiency,
        -- Production compliance (for reference only)
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
        GROUP BY lr.id, lr.style, lr.line_no, lr.sam_minutes, lr.operators_count, lr.working_hours, lr.target_pcs
      ),
      line_aggregates AS (
        SELECT
          style,
          line_no,
          SUM(total_sewed) as total_produced,
          SUM(target_pcs) as total_target,
          SUM(total_sewed * sam_minutes) as total_sam_output,
          SUM(operators_count * working_hours * 60) as total_available_minutes
        FROM line_packing_data
        GROUP BY style, line_no
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
 * Returns aggregated summary for a date range with filters
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
    
    let query = `
      WITH packing_sewed AS (
        SELECT 
          lr.id as run_id,
          lr.line_no,
          lr.target_pcs,
          lr.operators_count,
          lr.working_hours,
          lr.sam_minutes,
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
        GROUP BY lr.id, lr.line_no, lr.target_pcs, lr.operators_count, lr.working_hours, lr.sam_minutes
      )
      SELECT 
        COUNT(DISTINCT run_id) as total_runs,
        COUNT(DISTINCT line_no) as lines_used,
        COALESCE(SUM(total_sewed), 0) as total_sewed,
        COALESCE(SUM(target_pcs), 0) as total_target,
        -- CORRECT EFFICIENCY: Total SAM output / Total available minutes (NO ROUNDING)
        CASE 
          WHEN SUM(operators_count * working_hours * 60) > 0 
          THEN (SUM(total_sewed * sam_minutes) / SUM(operators_count * working_hours * 60)) * 100
          ELSE 0
        END as avg_efficiency
      FROM packing_sewed
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
app.get("/api/skyrina/line-performance-detail", authenticateToken, async (req, res) => {
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
    if (!['master', 'skyrina', 'engineer', 'supervisor'].includes(req.user.role)) {
      return res.status(403).json({ success: false, error: "Access denied" });
    }
    
    const query = `
      WITH line_data AS (
        SELECT 
          lr.style,
          lr.line_no,
          lr.target_pcs as target,
          COALESCE(SUM(se.sewed_qty), 0) as produced,
          lr.run_date
        FROM line_runs lr
        JOIN run_operators ro ON lr.id = ro.run_id
        JOIN operator_operations oo ON ro.id = oo.run_operator_id
        LEFT JOIN operation_sewed_entries se ON oo.id = se.operation_id
        WHERE lr.run_date BETWEEN $1 AND $2
          AND (oo.operation_name ILIKE '%pack%' OR oo.operation_name ILIKE '%emp%' OR oo.operation_name IS NULL)
        GROUP BY lr.id, lr.style, lr.line_no, lr.target_pcs, lr.run_date
      )
      SELECT 
        style,
        line_no,
        SUM(target) as total_target,
        SUM(produced) as total_produced,
        CASE 
          WHEN SUM(target) > 0 
          THEN (SUM(produced) / SUM(target)) * 100 
          ELSE 0 
        END as compliance
      FROM line_data
      GROUP BY style, line_no
      ORDER BY line_no::int, total_produced DESC
    `;
    
    const result = await client.query(query, [startDate, endDate]);
    
    const lines = result.rows.map(row => ({
      style: row.style || 'Sin Estilo',
      lineNo: row.line_no,
      target: Math.round(parseFloat(row.total_target) * 100) / 100,
      produced: Math.round(parseFloat(row.total_produced) * 100) / 100,
      compliance: Math.min(Math.round(parseFloat(row.compliance) * 100) / 100, 100)
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