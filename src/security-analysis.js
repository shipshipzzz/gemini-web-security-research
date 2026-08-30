export class EvidenceValidationError extends Error {
  constructor(message) {
    super(message);
    this.name = "EvidenceValidationError";
  }
}

function assertRecord(value, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new EvidenceValidationError(`${label} must be an object`);
  }
}

function assertNonEmptyString(value, label) {
  if (typeof value !== "string" || value.trim() === "") {
    throw new EvidenceValidationError(`${label} must be a non-empty string`);
  }
}

function assertBoolean(value, label) {
  if (typeof value !== "boolean") {
    throw new EvidenceValidationError(`${label} must be a boolean`);
  }
}

export function normalizeSnapshot(snapshot, label = "snapshot") {
  assertRecord(snapshot, label);

  const entries = Object.entries(snapshot);
  if (entries.length === 0) {
    throw new EvidenceValidationError(`${label} must contain at least one quota`);
  }

  const normalized = Object.fromEntries(
    entries.map(([quotaName, quota]) => {
      assertNonEmptyString(quotaName, `${label} quota name`);
      assertRecord(quota, `${label}.${quotaName}`);

      const { remaining, total } = quota;
      if (!Number.isInteger(total) || total <= 0) {
        throw new EvidenceValidationError(`${label}.${quotaName}.total must be a positive integer`);
      }
      if (!Number.isInteger(remaining) || remaining < 0 || remaining > total) {
        throw new EvidenceValidationError(
          `${label}.${quotaName}.remaining must be an integer between 0 and total`,
        );
      }

      return [quotaName, Object.freeze({ remaining, total })];
    }),
  );

  return Object.freeze(normalized);
}

export function diffSnapshots(beforeInput, afterInput) {
  const before = normalizeSnapshot(beforeInput, "before");
  const after = normalizeSnapshot(afterInput, "after");
  const quotaNames = [...new Set([...Object.keys(before), ...Object.keys(after)])].sort();

  return Object.freeze(
    quotaNames.map((quotaName) => {
      const previous = before[quotaName];
      const current = after[quotaName];

      if (!previous) {
        return Object.freeze({ quotaName, status: "missing-before", delta: null });
      }
      if (!current) {
        return Object.freeze({ quotaName, status: "missing-after", delta: null });
      }

      const delta = current.remaining - previous.remaining;
      const status = delta === 0 ? "unchanged" : delta < 0 ? "decreased" : "increased";
      return Object.freeze({ quotaName, status, delta });
    }),
  );
}

function indexByQuota(diffs) {
  return new Map(diffs.map((diff) => [diff.quotaName, diff]));
}

export function analyzeAuthorizationBoundary(observation) {
  assertRecord(observation, "authorizationBoundary");
  assertNonEmptyString(observation.id, "authorizationBoundary.id");
  assertRecord(observation.subject, "authorizationBoundary.subject");
  assertRecord(observation.expected, "authorizationBoundary.expected");
  assertRecord(observation.observed, "authorizationBoundary.observed");

  const { subject, expected, observed } = observation;
  assertNonEmptyString(subject.subscriptionClass, "subject.subscriptionClass");
  assertBoolean(subject.advancedCapabilityEntitled, "subject.advancedCapabilityEntitled");
  assertNonEmptyString(expected.decision, "expected.decision");
  assertNonEmptyString(observed.stage, "observed.stage");
  assertBoolean(observed.httpAccepted, "observed.httpAccepted");
  assertBoolean(observed.permissionDenial, "observed.permissionDenial");
  assertBoolean(observed.advancedCapabilitySignal, "observed.advancedCapabilitySignal");
  assertBoolean(observed.repeatable, "observed.repeatable");

  const downstreamStages = new Set(["capability-routing", "capacity-control", "inference"]);
  const gateBypassed =
    !subject.advancedCapabilityEntitled &&
    expected.decision === "deny" &&
    observed.httpAccepted &&
    !observed.permissionDenial &&
    observed.advancedCapabilitySignal &&
    downstreamStages.has(observed.stage);

  const anomalies = gateBypassed
    ? [
        Object.freeze({
          type: "cross-tier-authorization-bypass",
          reachedStage: observed.stage,
          repeatable: observed.repeatable,
        }),
      ]
    : [];

  return Object.freeze({
    id: observation.id,
    entitled: subject.advancedCapabilityEntitled,
    expectedDecision: expected.decision,
    observedStage: observed.stage,
    anomalies: Object.freeze(anomalies),
  });
}

export function analyzeAccountingExperiment(experiment) {
  assertRecord(experiment, "quotaAccounting");
  assertNonEmptyString(experiment.id, "quotaAccounting.id");

  const control = diffSnapshots(experiment.baseline, experiment.afterControl);
  const testedPath = diffSnapshots(experiment.afterControl, experiment.afterTestedPath);
  const testedPathByQuota = indexByQuota(testedPath);

  const anomalies = control
    .filter(({ quotaName, delta }) => delta < 0 && testedPathByQuota.get(quotaName)?.delta === 0)
    .map(({ quotaName, delta: controlDelta }) =>
      Object.freeze({
        type: "missing-deduction",
        quotaName,
        controlDelta,
        testedPathDelta: 0,
      }),
    );

  return Object.freeze({
    id: experiment.id,
    control,
    testedPath,
    anomalies: Object.freeze(anomalies),
  });
}

export function analyzeCounterConsistency(experiment) {
  assertRecord(experiment, "counterConsistency");
  assertNonEmptyString(experiment.id, "counterConsistency.id");
  assertNonEmptyString(experiment.primary, "counterConsistency.primary");
  assertNonEmptyString(experiment.related, "counterConsistency.related");

  const changes = diffSnapshots(experiment.before, experiment.after);
  const changesByQuota = indexByQuota(changes);
  const primary = changesByQuota.get(experiment.primary);
  const related = changesByQuota.get(experiment.related);

  if (!primary || !related || primary.delta === null || related.delta === null) {
    throw new EvidenceValidationError("primary and related quotas must exist in both snapshots");
  }

  const anomalies = [];
  if (primary.delta === 0 && related.delta < 0) {
    anomalies.push(
      Object.freeze({
        type: "counter-mismatch",
        primary: experiment.primary,
        primaryDelta: primary.delta,
        related: experiment.related,
        relatedDelta: related.delta,
      }),
    );
  }

  return Object.freeze({
    id: experiment.id,
    changes,
    anomalies: Object.freeze(anomalies),
  });
}

export function analyzeEvidenceSet(dataset) {
  assertRecord(dataset, "dataset");

  const authorization = analyzeAuthorizationBoundary(dataset.authorizationBoundary);
  const accounting = analyzeAccountingExperiment(dataset.quotaAccounting);
  const consistency = analyzeCounterConsistency(dataset.counterConsistency);
  const correlations = [];

  if (authorization.anomalies.length > 0 && accounting.anomalies.length > 0) {
    correlations.push(
      Object.freeze({
        type: "cross-tier-access-with-missing-metering",
        evidence: Object.freeze([authorization.id, accounting.id]),
      }),
    );
  }

  return Object.freeze({
    authorization,
    accounting,
    consistency,
    correlations: Object.freeze(correlations),
  });
}
