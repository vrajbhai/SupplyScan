#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

function main() {
  if (shouldSkipHooks()) {
    process.exit(0);
  }
  const target = resolveTarget();
  if (!target) {
    process.exit(0);
  }
  const result = runSupplyScan(target);
  if (result.blocked) {
    renderBlock(result);
    process.exit(1);
  }
  process.exit(0);
}

function shouldSkipHooks() {
  return Boolean(process.env.SUPPLYSCAN_DISABLE_HOOKS || process.env.npm_config_user_agent?.includes("supplyscan"));
}

function resolveTarget() {
  const args = process.argv.slice(2);
  for (const arg of args) {
    if (!arg || arg.startsWith("-")) {
      continue;
    }
    const parsed = parsePackageSpec(arg);
    if (parsed) {
      return parsed;
    }
    return { name: arg, version: null, source: "npm" };
  }
  const npmPackage = process.env.npm_package_name;
  if (npmPackage) {
    return { name: npmPackage, version: process.env.npm_package_version || null, source: "npm" };
  }
  return null;
}

function parsePackageSpec(spec) {
  if (!spec || spec.startsWith("-")) {
    return null;
  }
  if (spec.startsWith("@")) {
    const secondAt = spec.indexOf("@", 1);
    if (secondAt > 0) {
      return { name: spec.slice(0, secondAt), version: spec.slice(secondAt + 1) || null, source: "npm" };
    }
    return { name: spec, version: null, source: "npm" };
  }
  if (spec.includes("@")) {
    const [name, version] = spec.split("@", 2);
    return { name: name || spec, version: version || null, source: "npm" };
  }
  return { name: spec, version: null, source: "npm" };
}

function runSupplyScan(target) {
  const cli = locateSupplyScanCli();
  if (!cli) {
    return { blocked: false, reason: "SupplyScan CLI not found" };
  }
  const payload = JSON.stringify(target);
  const result = spawnSync(cli.command, cli.args.concat(["check", target.name, "--version", target.version || ""]), {
    env: Object.assign({}, process.env, {
      SUPPLYSCAN_DISABLE_HOOKS: "1",
      SUPPLYSCAN_NPM_TARGET: payload,
    }),
    encoding: "utf8",
  });
  if (result.error) {
    process.stderr.write(`SupplyScan npm hook warning: ${result.error.message}\n`);
    return {
      blocked: false,
      reason: result.error.message,
      output: "",
      target,
    };
  }
  const output = `${result.stdout || ""}\n${result.stderr || ""}`;
  const blocked = result.status !== 0;
  return {
    blocked,
    reason: output.trim() || "SupplyScan returned a non-zero status",
    output,
    target,
  };
}

function locateSupplyScanCli() {
  const localBin = path.join(process.cwd(), "node_modules", ".bin", "supplyscan");
  if (fs.existsSync(localBin)) {
    return { command: localBin, args: [] };
  }
  const npmGlobal = process.env.npm_config_prefix;
  if (npmGlobal) {
    const candidate = path.join(npmGlobal, "bin", "supplyscan");
    if (fs.existsSync(candidate)) {
      return { command: candidate, args: [] };
    }
  }
  const fallback = process.platform === "win32" ? "supplyscan.cmd" : "supplyscan";
  return { command: fallback, args: [] };
}

function renderBlock(result) {
  const lines = [
    "SupplyScan blocked npm install",
    `Package: ${result.target.name}`,
    `Version: ${result.target.version || "unspecified"}`,
    `Reason: ${result.reason}`,
  ];
  process.stderr.write(lines.join("\n") + "\n");
}

main();
