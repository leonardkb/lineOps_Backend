// Zero-dependency S3 client: uploads/deletes objects using Node's built-in
// `https` and `crypto` modules, signing requests with AWS Signature V4 by hand.
// No @aws-sdk/*, no multer, no multer-s3 — nothing to npm install.

const https = require("https");
const crypto = require("crypto");

const REQUIRED_ENV = ["AWS_REGION", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "S3_BUCKET_NAME"];
for (const key of REQUIRED_ENV) {
  if (!process.env[key]) {
    console.warn(`⚠️ Missing env var ${key} — S3 photo uploads will fail until it is set`);
  }
}

const REGION = process.env.AWS_REGION;
const ACCESS_KEY = process.env.AWS_ACCESS_KEY_ID;
const SECRET_KEY = process.env.AWS_SECRET_ACCESS_KEY;
const BUCKET = process.env.S3_BUCKET_NAME;
const HOST = `${BUCKET}.s3.${REGION}.amazonaws.com`;

// --- AWS SigV4 helpers -----------------------------------------------------

function sha256Hex(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}

function hmac(key, data) {
  return crypto.createHmac("sha256", key).update(data, "utf8").digest();
}

// AWS requires a specific percent-encoding: unreserved chars (A-Z a-z 0-9 - _ . ~)
// are left alone, everything else is %XX encoded, and '/' in the path is preserved.
function awsUriEncode(str, encodeSlash = true) {
  let out = "";
  for (const ch of str) {
    if (/[A-Za-z0-9\-_.~]/.test(ch)) {
      out += ch;
    } else if (ch === "/") {
      out += encodeSlash ? "%2F" : "/";
    } else {
      const bytes = Buffer.from(ch, "utf8");
      for (const b of bytes) {
        out += "%" + b.toString(16).toUpperCase().padStart(2, "0");
      }
    }
  }
  return out;
}

function canonicalPath(key) {
  // encode each path segment, keep the separating slashes
  return "/" + key.split("/").map((seg) => awsUriEncode(seg, true)).join("/");
}

function signRequest({ method, key, headers, payloadHash }) {
  const now = new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, ""); // e.g. 20260706T201530Z
  const dateStamp = amzDate.slice(0, 8);

  const allHeaders = {
    host: HOST,
    "x-amz-content-sha256": payloadHash,
    "x-amz-date": amzDate,
    ...headers,
  };

  const sortedHeaderKeys = Object.keys(allHeaders).sort();
  const canonicalHeaders = sortedHeaderKeys.map((k) => `${k}:${allHeaders[k]}\n`).join("");
  const signedHeaders = sortedHeaderKeys.join(";");

  const canonicalRequest = [
    method,
    canonicalPath(key),
    "", // no query string
    canonicalHeaders,
    signedHeaders,
    payloadHash,
  ].join("\n");

  const credentialScope = `${dateStamp}/${REGION}/s3/aws4_request`;
  const stringToSign = [
    "AWS4-HMAC-SHA256",
    amzDate,
    credentialScope,
    sha256Hex(canonicalRequest),
  ].join("\n");

  const kDate = hmac(`AWS4${SECRET_KEY}`, dateStamp);
  const kRegion = hmac(kDate, REGION);
  const kService = hmac(kRegion, "s3");
  const kSigning = hmac(kService, "aws4_request");
  const signature = crypto.createHmac("sha256", kSigning).update(stringToSign, "utf8").digest("hex");

  const authorization =
    `AWS4-HMAC-SHA256 Credential=${ACCESS_KEY}/${credentialScope}, ` +
    `SignedHeaders=${signedHeaders}, Signature=${signature}`;

  return { ...allHeaders, Authorization: authorization };
}

function request({ method, key, body, contentType }) {
  return new Promise((resolve, reject) => {
    const payloadHash = sha256Hex(body || Buffer.alloc(0));
    const extraHeaders = {};
    if (contentType) extraHeaders["content-type"] = contentType;
    if (body) extraHeaders["content-length"] = String(body.length);

    const headers = signRequest({ method, key, headers: extraHeaders, payloadHash });

    const req = https.request(
      {
        method,
        host: HOST,
        path: canonicalPath(key),
        headers,
      },
      (res) => {
        let data = "";
        res.on("data", (chunk) => (data += chunk));
        res.on("end", () => {
          if (res.statusCode >= 200 && res.statusCode < 300) {
            resolve({ statusCode: res.statusCode, body: data });
          } else {
            reject(new Error(`S3 ${method} failed (${res.statusCode}): ${data}`));
          }
        });
      }
    );
    req.on("error", reject);
    if (body) req.write(body);
    req.end();
  });
}

// --- Public API --------------------------------------------------------------

/**
 * Uploads a buffer to S3 and returns its public URL + key.
 */
async function uploadBufferToS3(buffer, key, contentType) {
  await request({ method: "PUT", key, body: buffer, contentType });
  return {
    url: `https://${HOST}/${canonicalPath(key).slice(1)}`,
    key,
  };
}

async function deleteFromS3(key) {
  if (!key) return;
  try {
    await request({ method: "DELETE", key });
  } catch (err) {
    console.error("⚠️ Failed to delete S3 object:", key, err.message);
  }
}

function makeStylePhotoKey(originalName = "") {
  const ext = (originalName.match(/\.[a-zA-Z0-9]+$/) || [""])[0].toLowerCase();
  return `style-photos/${Date.now()}-${crypto.randomUUID()}${ext}`;
}

/**
 * Generates a temporary signed GET URL for a private S3 object using
 * AWS SigV4 query-string signing (no request is made — this just builds a URL).
 */
function generatePresignedGetUrl(key, expiresInSeconds = 3600) {
  if (!key) return null;

  const now = new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, "");
  const dateStamp = amzDate.slice(0, 8);
  const credentialScope = `${dateStamp}/${REGION}/s3/aws4_request`;

  const queryParams = {
    "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
    "X-Amz-Credential": `${ACCESS_KEY}/${credentialScope}`,
    "X-Amz-Date": amzDate,
    "X-Amz-Expires": String(expiresInSeconds),
    "X-Amz-SignedHeaders": "host",
  };

  // Build canonical query string: sorted by key, both key and value percent-encoded
  const canonicalQueryString = Object.keys(queryParams)
    .sort()
    .map((k) => `${awsUriEncode(k, true)}=${awsUriEncode(queryParams[k], true)}`)
    .join("&");

  const canonicalHeaders = `host:${HOST}\n`;
  const signedHeaders = "host";
  const payloadHash = "UNSIGNED-PAYLOAD";

  const canonicalRequest = [
    "GET",
    canonicalPath(key),
    canonicalQueryString,
    canonicalHeaders,
    signedHeaders,
    payloadHash,
  ].join("\n");

  const stringToSign = [
    "AWS4-HMAC-SHA256",
    amzDate,
    credentialScope,
    sha256Hex(canonicalRequest),
  ].join("\n");

  const kDate = hmac(`AWS4${SECRET_KEY}`, dateStamp);
  const kRegion = hmac(kDate, REGION);
  const kService = hmac(kRegion, "s3");
  const kSigning = hmac(kService, "aws4_request");
  const signature = crypto.createHmac("sha256", kSigning).update(stringToSign, "utf8").digest("hex");

  return `https://${HOST}${canonicalPath(key)}?${canonicalQueryString}&X-Amz-Signature=${signature}`;
}

module.exports = { uploadBufferToS3, deleteFromS3, makeStylePhotoKey, generatePresignedGetUrl };