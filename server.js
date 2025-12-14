import http from "http";
import { spawn } from "child_process";
import os from "os";
import fs from "fs";
import path from "path";
import Busboy from "busboy";

const ORIGIN_ALLOWLIST = new Set([
  "https://docjoiner.com",
  "https://www.docjoiner.com"
]);

function send(res, code, body, headers = {}) {
  res.writeHead(code, { "Content-Type": "text/plain; charset=utf-8", ...headers });
  res.end(body);
}

function corsHeaders(origin) {
  if (origin && ORIGIN_ALLOWLIST.has(origin)) {
    return {
      "Access-Control-Allow-Origin": origin,
      "Vary": "Origin",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type"
    };
  }
  return {};
}

// Protect: AES-256 encrypt
function qpdfProtect({ inPath, outPath, password }) {
  return new Promise((resolve, reject) => {
    const args = [
      "--encrypt",
      password,
      password,
      "256",
      "--",
      inPath,
      outPath
    ];

    const proc = spawn("qpdf", args, { stdio: ["ignore", "pipe", "pipe"] });

    let stderr = "";
    proc.stderr.on("data", d => (stderr += d.toString()));

    proc.on("close", code => {
      if (code === 0) return resolve();
      reject(new Error(stderr || `qpdf protect failed (${code})`));
    });
  });
}

// Unlock: decrypt (remove open password) using provided password
function qpdfUnlock({ inPath, outPath, password }) {
  return new Promise((resolve, reject) => {
    const args = [
      `--password=${password}`,
      "--decrypt",
      "--",
      inPath,
      outPath
    ];

    const proc = spawn("qpdf", args, { stdio: ["ignore", "pipe", "pipe"] });

    let stderr = "";
    proc.stderr.on("data", d => (stderr += d.toString()));

    proc.on("close", code => {
      if (code === 0) return resolve();
      reject(new Error(stderr || `qpdf unlock failed (${code})`));
    });
  });
}

async function parseMultipartPdfAndPassword(req, { inPath }) {
  let password = "";
  let gotFile = false;
  let fileTooLarge = false;

  const bb = Busboy({
    headers: req.headers,
    limits: { fileSize: 60 * 1024 * 1024 } // 60 MB
  });

  bb.on("file", (name, file) => {
    if (name !== "file") {
      file.resume();
      return;
    }
    gotFile = true;

    file.on("limit", () => {
      fileTooLarge = true;
      file.resume();
    });

    file.pipe(fs.createWriteStream(inPath));
  });

  bb.on("field", (n, v) => {
    if (n === "password") password = String(v || "");
  });

  await new Promise((resolve, reject) => {
    bb.on("finish", resolve);
    bb.on("error", reject);
    req.on("error", reject);
    req.pipe(bb);
  });

  return { password, gotFile, fileTooLarge };
}

const server = http.createServer(async (req, res) => {
  const origin = req.headers.origin;
  const cors = corsHeaders(origin);

  if (req.method === "OPTIONS") {
    res.writeHead(204, cors);
    return res.end();
  }

  // Only POST endpoints we support
  const isProtect = req.url === "/api/protect" && req.method === "POST";
  const isUnlock = req.url === "/api/unlock" && req.method === "POST";

  if (!isProtect && !isUnlock) {
    return send(res, 404, "Not found", cors);
  }

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), isProtect ? "dj-protect-" : "dj-unlock-"));
  const inPath = path.join(tmpDir, "input.pdf");
  const outPath = path.join(tmpDir, "output.pdf");

  try {
    const { password, gotFile, fileTooLarge } = await parseMultipartPdfAndPassword(req, { inPath });

    if (fileTooLarge) return send(res, 413, "File too large (max 60MB).", cors);
    if (!gotFile) return send(res, 400, "Missing file.", cors);

    // For unlock we allow any length >= 1 (some PDFs have 1-2 char passwords)
    if (isProtect) {
      if (!password || password.length < 3) return send(res, 400, "Password too short.", cors);
      await qpdfProtect({ inPath, outPath, password });
    } else {
      if (!password) return send(res, 400, "Missing password.", cors);
      try {
        await qpdfUnlock({ inPath, outPath, password });
      } catch (e) {
        // Wrong password / cannot decrypt -> 403
        return send(res, 403, "Incorrect password or cannot unlock this PDF.", cors);
      }
    }

    const pdf = fs.readFileSync(outPath);

    res.writeHead(200, {
      ...cors,
      "Content-Type": "application/pdf",
      "Content-Disposition": isProtect
        ? 'attachment; filename="protected.pdf"'
        : 'attachment; filename="unlocked.pdf"',
      "Cache-Control": "no-store"
    });
    res.end(pdf);

  } catch (e) {
    const label = isProtect ? "Protect failed: " : "Unlock failed: ";
    return send(res, 500, label + (e.message || e), cors);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

server.listen(3000, () => console.log("DocJoiner API running (/api/protect + /api/unlock)"));
