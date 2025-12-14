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

function runQpdf({ inPath, outPath, password }) {
  return new Promise((resolve, reject) => {
    // 🔒 FORCE AES-256 (no weak crypto)
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
    proc.stderr.on("data", d => stderr += d.toString());

    proc.on("close", code => {
      if (code === 0) return resolve();
      reject(new Error(stderr || `qpdf failed (${code})`));
    });
  });
}

const server = http.createServer(async (req, res) => {
  const origin = req.headers.origin;
  const cors = corsHeaders(origin);

  if (req.method === "OPTIONS") {
    res.writeHead(204, cors);
    return res.end();
  }

  if (req.url !== "/api/protect" || req.method !== "POST") {
    return send(res, 404, "Not found");
  }

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "dj-protect-"));
  const inPath = path.join(tmpDir, "input.pdf");
  const outPath = path.join(tmpDir, "output.pdf");

  let password = "";
  let gotFile = false;

  try {
    const bb = Busboy({ headers: req.headers, limits: { fileSize: 60 * 1024 * 1024 } });

    bb.on("file", (name, file) => {
      if (name !== "file") { file.resume(); return; }
      gotFile = true;
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

    if (!gotFile) return send(res, 400, "Missing file.", cors);
    if (!password || password.length < 3) return send(res, 400, "Password too short.", cors);

    await runQpdf({ inPath, outPath, password });

    const pdf = fs.readFileSync(outPath);
    res.writeHead(200, {
      ...cors,
      "Content-Type": "application/pdf",
      "Content-Disposition": 'attachment; filename="protected.pdf"',
      "Cache-Control": "no-store"
    });
    res.end(pdf);
  } catch (e) {
    return send(res, 500, "Protect failed: " + (e.message || e), cors);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

server.listen(3000, () => console.log("Protect API running (AES-256 only)"));
