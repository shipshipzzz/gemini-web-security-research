import test from "node:test";
import assert from "node:assert/strict";
import {
  EvidenceValidationError,
  analyzeAccountingExperiment,
  analyzeAuthorizationBoundary,
  analyzeCounterConsistency,
  analyzeEvidenceSet,
  diffSnapshots,
  normalizeSnapshot,
} from "../src/security-analysis.js";

const authorizationBypass = {
  id: "F-01",
  subject: {
    subscriptionClass: "lower-tier",
    advancedCapabilityEntitled: false,
  },
  expected: { decision: "deny", stage: "entitlement-check" },
  observed: {
    httpAccepted: true,
    permissionDenial: false,
    advancedCapabilitySignal: true,
    stage: "capacity-control",
    repeatable: true,
  },
};

const accountingGap = {
  id: "F-02",
  baseline: {
    Thinking: { remaining: 80, total: 80 },
    Pro: { remaining: 25, total: 25 },
  },
  afterControl: {
    Thinking: { remaining: 75, total: 80 },
    Pro: { remaining: 24, total: 25 },
  },
  afterTestedPath: {
    Thinking: { remaining: 75, total: 80 },
    Pro: { remaining: 24, total: 25 },
  },
};

const counterMismatch = {
  id: "F-03",
  primary: "Deep Think",
  related: "Thinking",
  before: {
    "Deep Think": { remaining: 10, total: 10 },
    Thinking: { remaining: 1499, total: 1500 },
  },
  after: {
    "Deep Think": { remaining: 10, total: 10 },
    Thinking: { remaining: 1497, total: 1500 },
  },
};

test("normalizeSnapshot validates and freezes quota data", () => {
  const snapshot = normalizeSnapshot({ Thinking: { remaining: 80, total: 80 } });

  assert.deepEqual(snapshot.Thinking, { remaining: 80, total: 80 });
  assert.ok(Object.isFrozen(snapshot));
  assert.ok(Object.isFrozen(snapshot.Thinking));
});

test("normalizeSnapshot rejects impossible quota values", () => {
  assert.throws(
    () => normalizeSnapshot({ Thinking: { remaining: 81, total: 80 } }),
    EvidenceValidationError,
  );
  assert.throws(() => normalizeSnapshot({}), /at least one quota/);
});

test("diffSnapshots calculates deltas and reports missing buckets", () => {
  const diffs = diffSnapshots(
    {
      Pro: { remaining: 25, total: 25 },
      Thinking: { remaining: 80, total: 80 },
    },
    {
      Deep: { remaining: 10, total: 10 },
      Thinking: { remaining: 75, total: 80 },
    },
  );

  assert.deepEqual(diffs, [
    { quotaName: "Deep", status: "missing-before", delta: null },
    { quotaName: "Pro", status: "missing-after", delta: null },
    { quotaName: "Thinking", status: "decreased", delta: -5 },
  ]);
});

test("authorization analysis detects a non-entitled subject reaching a downstream stage", () => {
  const result = analyzeAuthorizationBoundary(authorizationBypass);

  assert.equal(result.entitled, false);
  assert.deepEqual(result.anomalies, [
    {
      type: "cross-tier-authorization-bypass",
      reachedStage: "capacity-control",
      repeatable: true,
    },
  ]);
});

test("authorization analysis does not flag a request denied at the entitlement gate", () => {
  const result = analyzeAuthorizationBoundary({
    ...authorizationBypass,
    observed: {
      httpAccepted: false,
      permissionDenial: true,
      advancedCapabilitySignal: false,
      stage: "entitlement-check",
      repeatable: true,
    },
  });

  assert.deepEqual(result.anomalies, []);
});

test("accounting analysis detects deductions missing from the tested path", () => {
  const result = analyzeAccountingExperiment(accountingGap);

  assert.equal(result.anomalies.length, 2);
  assert.deepEqual(
    result.anomalies.map(({ type, quotaName }) => ({ type, quotaName })),
    [
      { type: "missing-deduction", quotaName: "Pro" },
      { type: "missing-deduction", quotaName: "Thinking" },
    ],
  );
});

test("counter analysis detects an unchanged primary and decreased related quota", () => {
  const result = analyzeCounterConsistency(counterMismatch);

  assert.deepEqual(result.anomalies, [
    {
      type: "counter-mismatch",
      primary: "Deep Think",
      primaryDelta: 0,
      related: "Thinking",
      relatedDelta: -2,
    },
  ]);
});

test("counter analysis requires both counters in both snapshots", () => {
  assert.throws(
    () =>
      analyzeCounterConsistency({
        ...counterMismatch,
        after: { Thinking: { remaining: 1497, total: 1500 } },
      }),
    /must exist in both snapshots/,
  );
});

test("evidence analysis correlates authorization bypass with missing metering", () => {
  const result = analyzeEvidenceSet({
    authorizationBoundary: authorizationBypass,
    quotaAccounting: accountingGap,
    counterConsistency: counterMismatch,
  });

  assert.deepEqual(result.correlations, [
    {
      type: "cross-tier-access-with-missing-metering",
      evidence: ["F-01", "F-02"],
    },
  ]);
});
