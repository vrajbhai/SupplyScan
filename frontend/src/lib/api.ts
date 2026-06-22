const BASE_URL = (process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000").replace(/\/$/, "");

export type Severity = "CLEAN" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type ScanStatus = "Allowed" | "Blocked";

export interface Signal {
  message: string;
  severity: Severity;
  detector?: string;
  url?: string;
}

export interface ScanResult {
  package: string;
  version: string;
  ecosystem: string;
  severity: Severity;
  status: ScanStatus;
  isClean: boolean;
  timestamp: string;
  duration_ms: number;
  signals: Signal[];
  explanation?: string;
  action?: string;
  ai_analysis_used?: boolean;
  metadata?: Record<string, any>;
}

export interface MetricStats {
  total_scans: number;
  threats_blocked: number;
  clean_today: number;
  avg_scan_time: string;
}

interface BackendStats {
  total?: number;
  threats?: number;
  clean?: number;
  avg_ms?: number;
  total_scans?: number;
  threats_blocked?: number;
  clean_packages?: number;
}

export class ApiNetworkError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ApiNetworkError";
  }
}

export function isApiNetworkError(error: unknown): error is ApiNetworkError {
  return error instanceof ApiNetworkError || (error instanceof Error && error.name === "ApiNetworkError");
}

export const mockColouramaResult: ScanResult = {
  package: "colourama",
  version: "0.4.5",
  ecosystem: "PyPI",
  severity: "CRITICAL",
  status: "Blocked",
  isClean: false,
  timestamp: "demo fallback",
  duration_ms: 1245,
  signals: [
    { message: "Typosquat of 'colorama' (distance: 1)", severity: "CRITICAL", detector: "typosquat" },
    { message: "Network call found in setup.py to attacker.com", severity: "CRITICAL", detector: "network" },
    { message: "Base64 encoded reverse shell payload in __init__.py", severity: "CRITICAL", detector: "entropy" },
    { message: "Environment variable dump detected before HTTP exfiltration", severity: "HIGH", detector: "ast" },
  ],
  explanation:
    "This package mimics colorama with a one-character substitution. It exfiltrates environment variables during installation and contains an encoded reverse shell payload. Do not install this package.",
  action: "Do not install. Investigate the dependency source and replace it with the legitimate colorama package.",
};

export const offlineStats: MetricStats = {
  total_scans: 0,
  threats_blocked: 0,
  clean_today: 0,
  avg_scan_time: "0ms",
};

export async function getStats(): Promise<MetricStats> {
  try {
    const data = await fetchJson<BackendStats>(`${BASE_URL}/api/stats`);
    return normalizeStats(data);
  } catch (error) {
    if (isApiNetworkError(error)) return offlineStats;
    throw error;
  }
}

export async function fetchStats(): Promise<MetricStats> {
  return getStats();
}

export async function fetchRecentActivity(): Promise<ScanResult[]> {
  try {
    return await fetchHistoryFromApi(5);
  } catch (error) {
    if (isApiNetworkError(error)) return [];
    throw error;
  }
}

export async function fetchHistory(): Promise<ScanResult[]> {
  try {
    return await fetchHistoryFromApi(20);
  } catch (error) {
    if (isApiNetworkError(error)) return [];
    throw error;
  }
}

export async function scanPackage(
  name: string,
  version?: string,
  ecosystem: string = "PyPI",
  mode: string = "all",
): Promise<ScanResult> {
  const packageName = name.trim() || "colourama";
  const url = new URL(`${BASE_URL}/api/scan/${encodeURIComponent(packageName)}`);
  const selectedVersion = version?.trim();
  if (selectedVersion) url.searchParams.set("version", selectedVersion);
  if (ecosystem) url.searchParams.set("source", ecosystem.toLowerCase());
  if (mode && mode !== "all") url.searchParams.set("mode", mode);

  try {
    const data = await fetchJson<unknown>(url.toString(), {
      headers: { Accept: "application/json" },
    });
    return normalizeApiScanResult(data, packageName, selectedVersion, ecosystem);
  } catch (error) {
    if (isApiNetworkError(error)) {
      if (mode === "known") {
        return {
          package: packageName,
          version: selectedVersion || "latest",
          ecosystem,
          severity: "CLEAN",
          status: "Allowed",
          isClean: true,
          timestamp: "demo fallback",
          duration_ms: 310,
          signals: [],
          explanation: "No known CVEs or advisories found in database registries.",
          action: "Allowed for installation.",
        };
      }
      return { ...mockColouramaResult, ecosystem };
    }
    throw error;
  }
}

async function fetchHistoryFromApi(limit: number): Promise<ScanResult[]> {
  const url = new URL(`${BASE_URL}/api/history`);
  url.searchParams.set("limit", String(limit));
  const data = await fetchJson<{ reports?: unknown[]; items?: unknown[] }>(url.toString());
  const reports = Array.isArray(data.reports) ? data.reports : Array.isArray(data.items) ? data.items : [];
  return reports.map((report) => normalizeApiScanResult(report, "unknown", undefined, "PyPI"));
}

async function fetchJson<T>(url: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetchNoStore(url, init);
  } catch (error) {
    const fallbackUrl = loopbackFallbackUrl(url);
    if (fallbackUrl) {
      try {
        response = await fetchNoStore(fallbackUrl, init);
      } catch (fallbackError) {
        throw new ApiNetworkError(networkErrorMessage(fallbackError));
      }
    } else {
      throw new ApiNetworkError(networkErrorMessage(error));
    }
  }

  if (!response.ok) {
    const body = await response.text().catch(() => "");
    throw new Error(`SupplyScan API returned HTTP ${response.status}${body ? `: ${body.slice(0, 160)}` : ""}`);
  }

  try {
    return (await response.json()) as T;
  } catch {
    throw new Error("SupplyScan API returned a non-JSON response");
  }
}

async function fetchNoStore(url: string, init?: RequestInit): Promise<Response> {
  return fetch(url, {
    ...init,
    cache: "no-store",
  });
}

function loopbackFallbackUrl(url: string): string | null {
  try {
    const parsed = new URL(url);
    if (parsed.hostname !== "localhost") return null;
    parsed.hostname = "127.0.0.1";
    return parsed.toString();
  } catch {
    return null;
  }
}

function networkErrorMessage(error: unknown): string {
  if (error instanceof Error && error.message) {
    return `SupplyScan API is unreachable: ${error.message}`;
  }
  return "SupplyScan API is unreachable. Start the backend with `supplyscan dashboard`.";
}

function normalizeApiScanResult(
  data: unknown,
  fallbackName: string,
  fallbackVersion: string | undefined,
  ecosystem: string,
): ScanResult {
  const wrapped = asRecord(data);
  const report = asRecord(wrapped.report ?? data);
  const target = asRecord(report.target);
  const detectorResults = Array.isArray(report.detector_results) ? report.detector_results : [];
  const directSignals = Array.isArray(report.signals) ? report.signals : [];
  const severity = normalizeSeverity(report.overall_severity ?? report.severity);
  const clean = Boolean(report.clean ?? severity === "CLEAN");
  const effectiveSeverity = clean ? "CLEAN" : severity;
  const explanation = report.explanation;
  const explanationRecord = asRecord(explanation);
  const source = stringValue(target.source ?? report.source, "");
  const inferredEcosystem = source.toLowerCase().includes("npm") ? "npm" : ecosystem;

  return {
    package: stringValue(target.name ?? report.package, fallbackName),
    version: stringValue(target.version ?? report.version, fallbackVersion || "latest"),
    ecosystem: inferredEcosystem,
    severity: effectiveSeverity,
    status: effectiveSeverity === "CRITICAL" || effectiveSeverity === "HIGH" ? "Blocked" : "Allowed",
    isClean: clean,
    timestamp: stringValue(report.scanned_at ?? report.timestamp, "just now"),
    duration_ms: numberValue(report.duration_ms, 0),
    signals: directSignals.length
      ? directSignals.map((signal) => normalizeDirectSignal(signal))
      : detectorResults.flatMap((detector) => normalizeDetectorSignals(detector)),
    explanation:
      typeof explanation === "string"
        ? explanation
        : stringValue(explanationRecord.explanation, ""),
    action: stringValue(explanationRecord.recommended_action ?? explanationRecord.action, ""),
    ai_analysis_used: Boolean(report.ai_analysis_used ?? explanation),
    metadata: report.metadata ? asRecord(report.metadata) : undefined,
  };
}

function normalizeDirectSignal(signal: unknown): Signal {
  const signalRecord = asRecord(signal);
  return {
    message: stringValue(signalRecord.message, "Detector reported an unnamed finding"),
    severity: normalizeSeverity(signalRecord.severity),
    detector: stringValue(signalRecord.detector, ""),
    url: stringValue(signalRecord.url, "") || undefined,
  };
}

function normalizeDetectorSignals(detector: unknown): Signal[] {
  const detectorRecord = asRecord(detector);
  const findings = Array.isArray(detectorRecord.findings) ? detectorRecord.findings : [];
  const evidenceList = Array.isArray(detectorRecord.evidence) ? detectorRecord.evidence : [];

  return findings.map((finding) => {
    const cleanFinding = stringValue(finding, "Detector reported an unnamed finding");
    let url: string | undefined = undefined;

    // Vulnerability IDs usually prefix the findings list, e.g., "CVE-XXXX-XXXX:"
    const match = cleanFinding.match(/^([A-Z0-9-]+):/);
    const id = match ? match[1] : "";

    if (id) {
      const ev = evidenceList.find((e) => asRecord(e).label === id);
      if (ev) {
        const val = stringValue(asRecord(ev).value, "");
        const urlMatch = val.match(/url=([^;]+)/);
        if (urlMatch) {
          url = urlMatch[1].trim();
        }
      }
    }

    return {
      message: cleanFinding,
      severity: normalizeSeverity(detectorRecord.severity),
      detector: stringValue(detectorRecord.name, ""),
      url,
    };
  });
}

function normalizeStats(data: BackendStats): MetricStats {
  const total = numberValue(data.total ?? data.total_scans, 0);
  const threats = numberValue(data.threats ?? data.threats_blocked, 0);
  const clean = numberValue(data.clean ?? data.clean_packages, 0);
  const avgMs = numberValue(data.avg_ms, 0);
  return {
    total_scans: total,
    threats_blocked: threats,
    clean_today: clean,
    avg_scan_time: formatDuration(avgMs),
  };
}

function normalizeSeverity(value: unknown): Severity {
  if (value === "INFO") return "CLEAN";
  if (value === "LOW" || value === "MEDIUM" || value === "HIGH" || value === "CRITICAL" || value === "CLEAN") {
    return value;
  }
  return "CLEAN";
}

function formatDuration(ms: number): string {
  if (ms <= 0) return "0ms";
  if (ms < 1000) return `${Math.round(ms)}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

function asRecord(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" ? (value as Record<string, unknown>) : {};
}

function stringValue(value: unknown, fallback: string): string {
  return typeof value === "string" && value.length > 0 ? value : fallback;
}

function numberValue(value: unknown, fallback: number): number {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}
