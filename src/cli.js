#!/usr/bin/env node

import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { analyzeEvidenceSet } from "./security-analysis.js";

function formatDelta(delta) {
  return delta > 0 ? `+${delta}` : String(delta);
}

function printAuthorization(result) {
  console.log(`${result.id} 跨层级授权边界`);
  console.log(`  高级能力 entitlement: ${result.entitled ? "present" : "absent"}`);
  console.log(`  实际到达阶段: ${result.observedStage}`);
  const anomalyTypes = result.anomalies.map(({ type }) => type).join(", ");
  console.log(`  检出异常: ${anomalyTypes || "none"}`);
}

function printAccounting(result) {
  console.log(`\n${result.id} 配额约束对照`);
  const testedPathByQuota = new Map(result.testedPath.map((item) => [item.quotaName, item]));
  for (const control of result.control) {
    const testedPath = testedPathByQuota.get(control.quotaName);
    if (control.delta !== null && testedPath?.delta !== null) {
      console.log(
        `  ${control.quotaName}: 对照 ${formatDelta(control.delta)}，越权路径 ${formatDelta(testedPath.delta)}`,
      );
    }
  }
  console.log(`  检出异常: ${result.anomalies.length}`);
}

function printConsistency(result) {
  console.log(`\n${result.id} 计数器归属一致性`);
  for (const change of result.changes) {
    if (change.delta !== null) {
      console.log(`  ${change.quotaName}: ${formatDelta(change.delta)}`);
    }
  }
  const anomalyTypes = result.anomalies.map(({ type }) => type).join(", ");
  console.log(`  检出异常: ${anomalyTypes || "none"}`);
}

function printReport(result) {
  printAuthorization(result.authorization);
  printAccounting(result.accounting);
  printConsistency(result.consistency);

  console.log("\n综合判定");
  for (const correlation of result.correlations) {
    console.log(`  ${correlation.type}`);
  }
  if (result.correlations.length === 0) {
    console.log("  none");
  }
}

async function main() {
  const inputPath = resolve(process.argv[2] ?? "evidence/security-observations.json");
  const dataset = JSON.parse(await readFile(inputPath, "utf8"));
  printReport(analyzeEvidenceSet(dataset));
}

main().catch((error) => {
  console.error(`分析失败: ${error.message}`);
  process.exitCode = 1;
});
