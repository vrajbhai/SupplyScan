"use client";

import { useEffect, useState, useRef } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Skeleton } from "@/components/ui/skeleton";
import { Search, ShieldAlert, ShieldX, Terminal, ArrowRight, CheckCircle2, AlertTriangle } from "lucide-react";
import { scanPackage, ScanResult, Signal } from "@/lib/api";
import { toast } from "sonner";

const COMMON_NPM_PACKAGES = new Set([
  "angular",
  "axios",
  "chalk",
  "commander",
  "debug",
  "express",
  "lodash",
  "moment",
  "mongoose",
  "next",
  "react",
  "typescript",
  "vue",
  "webpack",
]);

export default function ScanPage() {
  const [pkgName, setPkgName] = useState("");
  const [pkgVersion, setPkgVersion] = useState("");
  const [ecosystem, setEcosystem] = useState("PyPI");
  const [scanning, setScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [scanStatusText, setScanStatusText] = useState("Initializing static scanner...");
  const [result, setResult] = useState<ScanResult | null>(null);

  const timerRef = useRef<number | null>(null);

  useEffect(() => {
    return () => {
      if (timerRef.current !== null) {
        window.clearInterval(timerRef.current);
      }
    };
  }, []);

  const handlePkgNameChange = (value: string) => {
    setPkgName(value);
    const lower = value.trim().toLowerCase();
    if (lower) {
      if (lower.startsWith("@") || lower.includes("/") || COMMON_NPM_PACKAGES.has(lower)) {
        setEcosystem("npm");
      } else {
        setEcosystem("PyPI");
      }
    }
  };

  const handleScan = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!pkgName.trim()) return;

    if (timerRef.current !== null) {
      window.clearInterval(timerRef.current);
      timerRef.current = null;
    }

    setScanning(true);
    setProgress(10);
    setScanStatusText("Loading package signatures...");
    const interval = window.setInterval(() => {
      setProgress((value) => {
        const nextValue = Math.min(value + 12, 92);
        if (nextValue < 30) setScanStatusText("Checking typosquatting heuristics...");
        else if (nextValue < 50) setScanStatusText("Parsing AST code nodes...");
        else if (nextValue < 70) setScanStatusText("Executing YARA signature checks...");
        else if (nextValue < 85) setScanStatusText("Auditing Semgrep security rules...");
        else setScanStatusText("Requesting AI threat explanation...");
        return nextValue;
      });
    }, 250);
    timerRef.current = interval;

    try {
      const scan = await scanPackage(pkgName, pkgVersion, ecosystem);
      setProgress(100);
      setResult(scan);
      if (scan.timestamp === "demo fallback") {
        toast.error("API unreachable. Showing colourama demo result.", {
          description: "Start the FastAPI backend with supplyscan dashboard for real scans.",
        });
      } else if (scan.status === "Blocked") {
        toast.error(`Threat detected in ${scan.package}`, {
          description: "Installation would be blocked automatically.",
        });
      } else {
        toast.success(`${scan.package} is clean`, {
          description: "No blocking signals were detected.",
        });
      }

      // OS Desktop Notifications
      if (scan.status === "Blocked") {
        let notifyEnabled = true;
        try {
          const storedPrefs = localStorage.getItem("supplyscan:prefs");
          if (storedPrefs) {
            const parsed = JSON.parse(storedPrefs);
            if (parsed && typeof parsed.notify === "boolean") {
              notifyEnabled = parsed.notify;
            }
          }
        } catch (e) {}

        if (notifyEnabled && typeof window !== "undefined" && "Notification" in window) {
          if (Notification.permission === "granted") {
            new Notification(`SupplyScan: Blocked ${scan.package}`, {
              body: `Threat detected with severity ${scan.severity}. Installation has been blocked.`,
            });
          }
        }
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : "The scan request failed.";
      setResult({
        package: pkgName.trim(),
        version: pkgVersion.trim() || "latest",
        ecosystem,
        severity: "LOW",
        status: "Allowed",
        isClean: false,
        timestamp: "scan failed",
        duration_ms: 0,
        signals: [{ message, severity: "LOW", detector: "api" }],
        explanation: "The backend responded, but the frontend could not parse a valid SupplyScan report.",
        action: "Check the FastAPI logs, then rerun the scan.",
      });
      toast.error("Scan failed", {
        description: message,
      });
    } finally {
      if (timerRef.current !== null) {
        window.clearInterval(timerRef.current);
        timerRef.current = null;
      }
      setScanning(false);
      setProgress(100);
    }
  };

  return (
    <div className="mx-auto max-w-5xl space-y-9 animate-in fade-in duration-500">
      <div className="space-y-4 text-center">
        <div className="page-kicker mx-auto w-fit">
          <CheckCircle2 className="h-3.5 w-3.5" />
          Ready to verify
        </div>
        <h1 className="page-title">Scan a package</h1>
        <p className="page-subtitle mx-auto">
          Verify the current package version or pin an exact release before it reaches your environment.
        </p>
      </div>

      <Card className="surface-card">
        <CardContent className="p-7 md:p-9">
          <form onSubmit={handleScan} className="grid gap-4 md:grid-cols-[1fr_150px_150px_auto]">
            <Input
              placeholder="Package name (e.g. requests, lodash)"
              className="h-13 rounded-2xl border-emerald-100 dark:border-emerald-900 bg-emerald-50/30 dark:bg-emerald-950/40 px-4 text-base font-semibold text-emerald-950 dark:text-emerald-50 shadow-sm focus-visible:ring-emerald-500"
              value={pkgName}
              onChange={(event) => handlePkgNameChange(event.target.value)}
              disabled={scanning}
              required
            />
            <Input
              placeholder="Latest"
              className="h-13 rounded-2xl border-emerald-100 dark:border-emerald-900 bg-emerald-50/30 dark:bg-emerald-950/40 px-4 text-base font-semibold text-emerald-950 dark:text-emerald-50 shadow-sm focus-visible:ring-emerald-500"
              value={pkgVersion}
              onChange={(event) => setPkgVersion(event.target.value)}
              disabled={scanning}
            />
            <Select value={ecosystem} onValueChange={(value) => value && setEcosystem(value)} disabled={scanning}>
              <SelectTrigger className="h-13 w-full rounded-2xl border-emerald-100 dark:border-emerald-900 bg-emerald-50/30 dark:bg-emerald-950/40 px-4 text-base font-semibold text-emerald-950 dark:text-emerald-50 shadow-sm focus-visible:ring-emerald-500">
                <SelectValue placeholder="Ecosystem" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="PyPI">PyPI</SelectItem>
                <SelectItem value="npm">npm</SelectItem>
              </SelectContent>
            </Select>
            <Button
              type="submit"
              className="h-13 rounded-2xl bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white font-extrabold shadow-[0_4px_20px_rgba(16,185,129,0.25)] hover:shadow-[0_4px_25px_rgba(16,185,129,0.35)] active:scale-[0.98] transition-all duration-200 px-8 text-base cursor-pointer"
              disabled={scanning || !pkgName.trim()}
            >
              <Search className="mr-2 h-4 w-4" />
              {scanning ? "Scanning..." : "Scan Now"}
            </Button>
          </form>

          {scanning && (
            <div className="mt-8 space-y-6 animate-in fade-in duration-300">
              <div className="flex flex-col items-center justify-center py-6 text-center space-y-4">
                <div className="relative flex h-20 w-20 items-center justify-center rounded-full bg-emerald-100 dark:bg-emerald-900/50 text-emerald-600 dark:text-emerald-400">
                  <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 dark:bg-emerald-600 opacity-20" />
                  <Search className="h-8 w-8 animate-pulse" />
                </div>
                <div className="space-y-1">
                  <h4 className="text-lg font-black text-emerald-950 dark:text-emerald-50">Scanning {pkgName}...</h4>
                  <p className="text-sm font-bold text-emerald-600 dark:text-emerald-400 animate-pulse">{scanStatusText}</p>
                </div>
              </div>
              
              <div className="space-y-2">
                <div className="flex justify-between text-xs font-bold text-emerald-900/70 dark:text-emerald-400">
                  <span>Overall progress</span>
                  <span>{progress}%</span>
                </div>
                <Progress value={progress} className="h-2" />
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {result && !scanning && (
        <div className="space-y-6 pt-4 animate-in slide-in-from-bottom-4 duration-500">
          <ScanResultPanel result={result} />
        </div>
      )}
    </div>
  );
}

function ScanResultPanel({ result }: { result: ScanResult }) {
  const [currentStatus, setCurrentStatus] = useState(result.status);
  const [actionDone, setActionDone] = useState(false);

  useEffect(() => {
    setCurrentStatus(result.status);
    setActionDone(false);

    try {
      const stored = localStorage.getItem("supplyscan:manual-actions");
      if (stored) {
        const actions = JSON.parse(stored) as Record<string, "Blocked" | "Reviewed">;
        const key = `${result.package}@${result.version}`;
        if (actions[key]) {
          setCurrentStatus(actions[key] === "Blocked" ? "Blocked" : "Allowed");
          setActionDone(true);
        }
      }
    } catch (e) {}
  }, [result]);

  const handleAction = () => {
    setActionDone(true);
    const key = `${result.package}@${result.version}`;
    const nextBlocked = currentStatus === "Blocked";

    try {
      const stored = localStorage.getItem("supplyscan:manual-actions");
      const actions = stored ? JSON.parse(stored) : {};
      actions[key] = nextBlocked ? "Blocked" : "Reviewed";
      localStorage.setItem("supplyscan:manual-actions", JSON.stringify(actions));
    } catch (e) {}

    if (nextBlocked) {
      toast.error(`Reported and blocked ${result.package}`, {
        description: `Manually added to your system's blocklist.`,
      });
    } else {
      toast.success(`Cleared ${result.package}`, {
        description: `Manually approved and marked as reviewed.`,
      });
    }
  };

  const blocked = currentStatus === "Blocked";

  return (
    <>
      <div className="surface-card p-6 md:p-7">
      <div className="flex flex-col gap-3 border-b border-emerald-100 dark:border-emerald-900 pb-5 md:flex-row md:items-center md:justify-between">
        <div>
          <h2 className="flex items-center text-2xl font-black text-emerald-950 dark:text-emerald-50 font-display">
            {result.package} <span className="ml-2 font-semibold text-emerald-700/70 dark:text-emerald-400/70">{result.version}</span>
          </h2>
          <div className="mt-1.5 flex items-center gap-2">
            <span className="inline-flex items-center rounded-md bg-emerald-50 dark:bg-emerald-950/50 px-2.5 py-0.5 text-xs font-bold text-emerald-700 dark:text-emerald-300 border border-emerald-100 dark:border-emerald-900/60 uppercase tracking-wider">
              Registry: {result.ecosystem}
            </span>
          </div>
        </div>
        <Badge className={`${blocked ? "border-rose-200 dark:border-rose-900/60 bg-rose-50 dark:bg-rose-950/40 text-rose-700 dark:text-rose-400" : "border-emerald-200 dark:border-emerald-900/60 bg-emerald-100 dark:bg-emerald-900/50 text-emerald-800 dark:text-emerald-300"} rounded-full px-3 py-1 text-sm shadow-none`}>
          {blocked ? "CRITICAL" : result.severity} - {blocked ? "Install Blocked" : "Allowed"}
        </Badge>
      </div>

      {result.metadata?.dual_registry && (
        <div className="mt-6 rounded-2xl border border-amber-200 dark:border-amber-900/60 bg-gradient-to-br from-amber-50 to-orange-50/50 dark:from-amber-950/20 dark:to-orange-950/10 p-5 shadow-sm animate-in fade-in slide-in-from-top-2 duration-300">
          <div className="flex items-start">
            <AlertTriangle className="mr-3 mt-0.5 h-6 w-6 flex-shrink-0 text-amber-500 dark:text-amber-400" />
            <div className="space-y-1">
              <h4 className="text-base font-black text-amber-900 dark:text-amber-300 font-display">
                Dependency Confusion Risk Detected
              </h4>
              <p className="text-sm font-semibold text-amber-800/80 dark:text-amber-400/80 leading-relaxed">
                This package name exists on both <span className="font-bold">npm</span> and <span className="font-bold">PyPI</span>. 
                Attackers can exploit this using dependency confusion by publishing malicious higher-version packages to public registries.
                Ensure you are fetching from the correct registry and verify your internal dependency configuration.
              </p>
            </div>
          </div>
        </div>
      )}

      <div className="mt-6 space-y-4">
        <h3 className="text-lg font-black text-emerald-950 dark:text-emerald-50 font-display">Signals detected</h3>
        <ul className="space-y-3">
          {(result.signals.length ? result.signals : [{ message: "No malicious signals detected", severity: "CLEAN" } as Signal]).map((signal, index) => (
            <li key={index} className="flex flex-col items-start rounded-2xl border border-emerald-100 dark:border-emerald-900 bg-emerald-50/40 dark:bg-emerald-950/30 p-4">
              <div className="flex items-start w-full">
                {signal.severity === "CLEAN" ? (
                  <ShieldAlert className="mr-3 mt-0.5 h-5 w-5 flex-shrink-0 text-emerald-500 dark:text-emerald-400" />
                ) : signal.severity === "CRITICAL" || signal.severity === "HIGH" ? (
                  <ShieldX className="mr-3 mt-0.5 h-5 w-5 flex-shrink-0 text-rose-500" />
                ) : (
                  <ShieldAlert className="mr-3 mt-0.5 h-5 w-5 flex-shrink-0 text-amber-500" />
                )}
                <div className="flex-1">
                  <span className="text-emerald-950/80 dark:text-emerald-200">{signal.message}</span>
                  {signal.url && (
                    <a
                      href={signal.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="block mt-1 text-xs font-bold text-emerald-600 dark:text-emerald-400 hover:underline cursor-pointer"
                    >
                      View Advisory Details →
                    </a>
                  )}
                </div>
              </div>
            </li>
          ))}
        </ul>
      </div>

      {result.explanation && (
        <div className="mt-6 rounded-2xl border border-emerald-100 dark:border-emerald-900 bg-emerald-50/60 dark:bg-emerald-950/30 p-6">
          <div className="mb-3 flex items-center">
            <Terminal className="mr-2 h-5 w-5 text-primary" />
            <h3 className="font-black text-emerald-950 dark:text-emerald-50">AI Explanation</h3>
          </div>
          <p className="whitespace-pre-wrap break-words leading-relaxed text-emerald-950/75 dark:text-emerald-300">{result.explanation}</p>
          {result.action && <p className="mt-3 whitespace-pre-wrap break-words text-sm font-bold text-emerald-900 dark:text-emerald-400">Recommended action: {result.action}</p>}
        </div>
      )}

      <div className="pt-4">
        <Button
          variant={blocked ? "destructive" : "outline"}
          className="rounded-2xl font-bold shadow-sm cursor-pointer transition-all active:scale-[0.98]"
          onClick={handleAction}
          disabled={actionDone}
        >
          {actionDone ? (blocked ? "Manually Blocked & Reported" : "Reviewed & Cleared") : (blocked ? "Block & Report Package" : "Mark as Reviewed")}
          <ArrowRight className="ml-2 h-4 w-4" />
        </Button>
      </div>
      </div>
    </>
  );
}
