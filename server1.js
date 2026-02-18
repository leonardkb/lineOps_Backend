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

// If not in production, also log to console with pretty format
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

// Security & utility middleware
app.use(helmet());
app.use(compression());
app.use(express.json({ limit: "1mb" }));

// CORS – restrict origins in production
const allowedOrigins = process.env.CORS_ORIGINS
  ? process.env.CORS_ORIGINS.split(",")
  : ["http://localhost:3000"]; // default for dev
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

// HTTP request logging (morgan) integrated with winston
app.use(
  morgan("combined", {
    stream: { write: (message) => logger.info(message.trim()) },
  })
);

// ----------------------------------------------------------------------
// 3. RATE LIMITING
// ----------------------------------------------------------------------
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20, // limit each IP to 20 requests per windowMs
  message: { success: false, error: "Too many authentication attempts, please try again later." },
  standardHeaders: true,
  legacyHeaders: false,
});

const apiLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 100, // limit each IP to 100 requests per minute
  message: { success: false, error: "Too many requests, please slow down." },
  standardHeaders: true,
  legacyHeaders: false,
});
app.use("/api/", apiLimiter); // apply to all /api routes

// ----------------------------------------------------------------------
// 4. DATABASE POOL (SSL ENFORCED IN PRODUCTION)
// ----------------------------------------------------------------------
const pool = new Pool({
  host: process.env.PG_HOST,
  port: Number(process.env.PG_PORT),
  database: process.env.PG_DB,
  user: process.env.PG_USER,
  password: process.env.PG_PASSWORD,
  ssl:
   
       false,
  max: Number(process.env.PG_POOL_MAX) || 20,
  idleTimeoutMillis: Number(process.env.PG_IDLE_TIMEOUT) || 30000,
  connectionTimeoutMillis: Number(process.env.PG_CONNECTION_TIMEOUT) || 5000,
});

pool.on("error", (err) => {
  logger.error("Unexpected database pool error", { error: err.message, stack: err.stack });
  process.exit(-1);
});

// Helper: set search path
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
// 6. DATABASE MIGRATIONS / SCHEMA SETUP
//    (Run only if explicitly enabled, not on every startup)
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

    // Create tables (IF NOT EXISTS) – idempotent
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
    logger.info("✅ users table ready");

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
    logger.info("✅ line_runs table ready");

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
    logger.info("✅ shift_slots table ready");

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
    logger.info("✅ run_operators table ready");

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
    logger.info("✅ operator_operations table ready");

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
    logger.info("✅ operation_hourly_entries table ready");

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
    logger.info("✅ operation_sewed_entries table ready");

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
    logger.info("✅ slot_targets table ready");

    // Create indexes
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

    // Seed default users if the table is empty
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

// Separate seeding function (idempotent – ON CONFLICT DO NOTHING)
const seedDefaultUsers = async (client) => {
  const defaultUsers = [
    { username: "engineer", password: "engineer", role: "engineer", full_name: "System Engineer" },
    { username: "supervisor", password: "supervisor123", role: "supervisor", full_name: "Production Supervisor" },
  ];
  // line leaders 1–26
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
// 7. AUTHENTICATION MIDDLEWARE (JWT)
// ----------------------------------------------------------------------
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1]; // Bearer TOKEN

  if (!token) {
    logger.warn("Authentication failed: no token provided", { ip: req.ip });
    return res.status(401).json({ success: false, error: "Authentication required" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    // Fetch user from database to ensure still active
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

// Role‑based access control
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
// 9. ERROR HANDLING MIDDLEWARE (central)
// ----------------------------------------------------------------------
const errorHandler = (err, req, res, next) => {
  logger.error("Unhandled error", { error: err.message, stack: err.stack, url: req.url, method: req.method });
  res.status(err.status || 500).json({
    success: false,
    error: process.env.NODE_ENV === "production" ? "Internal server error" : err.message,
  });
};

// ----------------------------------------------------------------------
// 10. HEALTH CHECK (public)
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
  authLimiter, // stricter rate limit
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

      // Create JWT
      const token = jwt.sign(
        { id: user.id, username: user.username, role: user.role },
        JWT_SECRET,
        { expiresIn: JWT_EXPIRES_IN }
      );

      // Remove sensitive data
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
  // JWT is stateless; client discards token
  res.json({ success: true, message: "Logged out successfully" });
});

// ----------------------------------------------------------------------
// 12. PRODUCTION DATA ENDPOINTS (ALL AUTHENTICATED + ROLE CHECKS)
// ----------------------------------------------------------------------

// Save line inputs and shift slots – requires engineer or supervisor
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

      // Insert shift slots
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

// Save operators and operations – requires engineer or supervisor
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

      // Verify run exists
      const runCheck = await client.query("SELECT id FROM line_runs WHERE id = $1", [runId]);
      if (runCheck.rows.length === 0) {
        return res.status(404).json({ success: false, error: "Line run not found" });
      }

      // Get slot IDs for this run
      const slotsResult = await client.query(
        "SELECT id, slot_label FROM shift_slots WHERE run_id = $1 ORDER BY slot_order",
        [runId]
      );
      const slotMap = Object.fromEntries(slotsResult.rows.map((s) => [s.slot_label, s.id]));

      // Process operations
      const operatorMap = {};
      let savedOperations = 0;

      for (const op of operations) {
        const { operatorNo, operatorName, operation: operationName, t1, t2, t3, t4, t5, capacityPerHour } = op;
        if (!operatorNo || !operationName) continue;

        // Insert / update operator
        const operatorResult = await client.query(
          `INSERT INTO run_operators (run_id, operator_no, operator_name, created_at)
           VALUES ($1, $2, $3, NOW())
           ON CONFLICT (run_id, operator_no) DO UPDATE SET operator_name = EXCLUDED.operator_name
           RETURNING id`,
          [runId, parseInt(operatorNo, 10), operatorName || null]
        );
        const operatorId = operatorResult.rows[0].id;
        operatorMap[operatorNo] = operatorId;

        // Insert / update operation
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

      // Save slot targets if provided
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

// Save hourly stitched data – requires engineer, supervisor, or line leader (must match line)
app.post(
  "/api/save-hourly-data",
  authenticateToken,
  async (req, res, next) => {
    // Additional line leader validation: only allowed for their own line
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

        // Find operation ID
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

        // Find slot ID
        const slotResult = await client.query(
          "SELECT id FROM shift_slots WHERE run_id = $1 AND slot_label = $2",
          [runId, slotLabel]
        );
        if (slotResult.rows.length === 0) {
          skippedCount++;
          continue;
        }
        const slotId = slotResult.rows[0].id;

        // Upsert
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

// Line leader update sewed entries – similar role & line check
app.post(
  "/api/lineleader/update-sewed/:runId",
  authenticateToken,
  allowRoles("line_leader", "engineer", "supervisor"),
  async (req, res, next) => {
    // Additional line check for line leaders
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
// 13. DATA RETRIEVAL ENDPOINTS (authenticated, role‑based as needed)
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

    // If line leader, enforce that they can only request their own line
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

// ----------------------------------------------------------------------
// 13.X. COMPATIBILITY ROUTES (same as server.js)  ✅
// Add these to keep frontend routes exactly matching server.js
// ----------------------------------------------------------------------

// ✅ GET full run data (server.js: GET /api/run/:runId)
// Note: server1 already has /api/get-run-data/:runId; this adds the server.js route name too.
app.get("/api/run/:runId", authenticateToken, async (req, res, next) => {
  const client = await pool.connect();
  try {
    await setSchema(client);

    const { runId } = req.params;

    // Get line run data
    const runResult = await client.query("SELECT * FROM line_runs WHERE id = $1", [runId]);
    if (runResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Run not found" });
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

    // Get operations with their hourly stitched data
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

// ✅ Update hourly stitched data for a specific run (server.js: POST /api/update-hourly-data/:runId)
// This is DIFFERENT from /api/save-hourly-data because it takes :runId in params and matches server.js contract.
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

      // If line leader, enforce only their own line
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

        // Get operation ID
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

        // Get slot ID
        const slotResult = await client.query(
          "SELECT id FROM shift_slots WHERE run_id = $1 AND slot_label = $2",
          [runId, slotLabel]
        );
        if (slotResult.rows.length === 0) continue;

        const slotId = slotResult.rows[0].id;

        // Check existing
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

// ✅ Add operation to existing run (server.js: POST /api/add-operation/:runId)
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

      // Get or create operator
      const operatorResult = await client.query(
        `INSERT INTO run_operators (run_id, operator_no, operator_name, created_at)
         VALUES ($1, $2, $3, NOW())
         ON CONFLICT (run_id, operator_no)
         DO UPDATE SET operator_name = EXCLUDED.operator_name
         RETURNING id`,
        [runId, parseInt(operatorNo, 10), operatorName || null]
      );
      const operatorId = operatorResult.rows[0].id;

      // Add or update operation
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
// 14. SUPERVISOR DASHBOARD ENDPOINTS
// ----------------------------------------------------------------------
app.get(
  "/api/supervisor/summary",
  authenticateToken,
  allowRoles("supervisor"),
  validate([query("date").isDate().withMessage("Valid date required")]),
  async (req, res, next) => {
    const client = await pool.connect();
    try {
      await setSchema(client);
      const { date } = req.query;

      const targetResult = await client.query(
        "SELECT COALESCE(SUM(target_pcs), 0) as total_target FROM line_runs WHERE run_date = $1",
        [date]
      );
      const totalTarget = parseFloat(targetResult.rows[0].total_target) || 0;

      const sewedResult = await client.query(
        `SELECT COALESCE(SUM(se.sewed_qty), 0) as total_sewed
         FROM operation_sewed_entries se
         JOIN line_runs lr ON se.run_id = lr.id
         WHERE lr.run_date = $1`,
        [date]
      );
      const totalSewed = parseFloat(sewedResult.rows[0].total_sewed) || 0;

      const operatorsResult = await client.query(
        `SELECT COUNT(DISTINCT ro.operator_no) as total_operators
         FROM run_operators ro
         JOIN line_runs lr ON ro.run_id = lr.id
         WHERE lr.run_date = $1`,
        [date]
      );
      const totalOperators = parseInt(operatorsResult.rows[0].total_operators, 10) || 0;

      const efficiencyResult = await client.query(
        `WITH
          run_available_minutes AS (
            SELECT id, (working_hours * operators_count * 60) AS available_minutes
            FROM line_runs
            WHERE run_date = $1
          ),
          run_sam_output AS (
            SELECT lr.id, SUM(lr.sam_minutes * se.sewed_qty) AS sam_output
            FROM line_runs lr
            JOIN operation_sewed_entries se ON lr.id = se.run_id
            WHERE lr.run_date = $1
            GROUP BY lr.id
          )
        SELECT
          COALESCE(SUM(ram.available_minutes), 0) AS total_available_minutes,
          COALESCE(SUM(rso.sam_output), 0) AS total_sam_output
        FROM run_available_minutes ram
        LEFT JOIN run_sam_output rso ON ram.id = rso.id`,
        [date]
      );
      const totalSamOutput = parseFloat(efficiencyResult.rows[0].total_sam_output) || 0;
      const totalAvailableMinutes = parseFloat(efficiencyResult.rows[0].total_available_minutes) || 0;
      const overallEfficiency = totalAvailableMinutes > 0 ? (totalSamOutput / totalAvailableMinutes) * 100 : 0;
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
      next(err);
    } finally {
      client.release();
    }
  }
);

app.get(
  "/api/supervisor/line-performance",
  authenticateToken,
  allowRoles("supervisor"),
  validate([query("date").isDate().withMessage("Valid date required")]),
  async (req, res, next) => {
    const client = await pool.connect();
    try {
      await setSchema(client);
      const { date } = req.query;

      const queryText = `
        WITH
          line_targets AS (
            SELECT line_no, SUM(target_pcs) AS total_target
            FROM line_runs
            WHERE run_date = $1
            GROUP BY line_no
          ),
          line_sewed AS (
            SELECT lr.line_no, COALESCE(SUM(se.sewed_qty), 0) AS total_sewed
            FROM line_runs lr
            JOIN run_operators ro ON lr.id = ro.run_id
            JOIN operator_operations oo ON ro.id = oo.run_operator_id
            JOIN operation_sewed_entries se ON oo.id = se.operation_id
            WHERE lr.run_date = $1
            GROUP BY lr.line_no
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
          CASE WHEN lt.total_target > 0 THEN (COALESCE(ls.total_sewed, 0) / lt.total_target) * 100 ELSE 0 END AS achievement
        FROM line_targets lt
        LEFT JOIN line_sewed ls ON lt.line_no = ls.line_no
        LEFT JOIN line_operators lo ON lt.line_no = lo.line_no
        ORDER BY lt.line_no
      `;

      const result = await client.query(queryText, [date]);
      const lines = result.rows.map((row) => ({
        lineNo: row.line_no,
        totalTarget: parseFloat(row.total_target) || 0,
        totalSewed: parseFloat(row.total_sewed) || 0,
        operators: parseInt(row.operators_count, 10) || 0,
        achievement: Math.round((parseFloat(row.achievement) || 0) * 100) / 100,
      }));

      res.json({ success: true, date, lines });
    } catch (err) {
      next(err);
    } finally {
      client.release();
    }
  }
);

// ----------------------------------------------------------------------
// 15. USER MANAGEMENT (engineer / supervisor only)
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

      // Check line number not already assigned for line leader
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

    // Prevent self‑deactivation
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
// 16. CONDITIONAL DEVELOPMENT ENDPOINTS
// ----------------------------------------------------------------------
if (process.env.NODE_ENV !== "production") {
  // Development‑only: reset database (requires authentication + engineer)
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
      // Do not delete users
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
// 17. CENTRAL ERROR HANDLING
// ----------------------------------------------------------------------
app.use(errorHandler);

// ----------------------------------------------------------------------
// 18. GRACEFUL SHUTDOWN
// ----------------------------------------------------------------------
const server = app.listen(process.env.PORT || 5000, async () => {
  logger.info(`🚀 Server listening on port ${process.env.PORT || 5000}`);
  logger.info(`📁 Schema: prod_db_schema`);
  logger.info(`🗄️  Database: ${process.env.PG_DB || "prod_db"}`);

  // Run migrations if enabled
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

// ----------------------------------------------------------------------
// 19. EXPORT FOR TESTING (optional)
// ----------------------------------------------------------------------
module.exports = { app, pool };