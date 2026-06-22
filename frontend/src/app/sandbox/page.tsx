"use client";

import { useEffect, useState, useRef } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { 
  Search, ShieldAlert, ShieldCheck, ShieldX, Terminal, ArrowRight, 
  CheckCircle2, AlertTriangle, Layers, Cpu, Database, Check, Play 
} from "lucide-react";
import { scanPackage, ScanResult, Signal } from "@/lib/api";
import { toast } from "sonner";

const COMMON_NPM_PACKAGES = new Set([
  "angular", "axios", "chalk", "commander", "debug", "express", 
  "lodash", "moment", "mongoose", "next", "react", "typescript", 
  "vue", "webpack"
]);

interface DetectionLayer {
  id: string;
  name: string;
  description: string;
  type: "known" | "unknown";
}

const DETECTION_LAYERS: DetectionLayer[] = [
  { id: "cve", name: "CVE Database Lookup", description: "Queries global database sources for known CVE publications.", type: "known" },
  { id: "feed", name: "Threat Intelligence Feed", description: "Audits against local curated indicators and compromised versions.", type: "known" },
  { id: "typo", name: "Typosquatting Audits", description: "Inspects name distance and mimicry patterns against top dependencies.", type: "unknown" },
  { id: "metadata", name: "Maintainer Risk Evaluation", description: "Assesses account hijacking, new package owners, and release anomaly signals.", type: "unknown" },
  { id: "ast", name: "AST Semantic Analysis", description: "Checks code syntax trees for base64 shell injections and file modifications.", type: "unknown" },
  { id: "entropy", name: "Code Obfuscation Check", description: "Measures Shannon entropy of strings to find hidden payload blocks.", type: "unknown" },
  { id: "network", name: "Outbound Call Heuristics", description: "Detects socket calls, raw IPs, and dns lookup vectors in setup files.", type: "unknown" },
  { id: "yara", name: "YARA Malware Rules", description: "Runs signature matching targeting trojans, ransomware, and miners.", type: "unknown" },
  { id: "semgrep", name: "Custom Semgrep Rules", description: "Applies specialized security rules for execution patterns (eval, popen).", type: "unknown" },
];

export default function SandboxPage() {
  const [pkgName, setPkgName] = useState("");
  const [pkgVersion, setPkgVersion] = useState("");
  const [ecosystem, setEcosystem] = useState("PyPI");
  const [scanMode, setScanMode] = useState<"known" | "unknown">("unknown");
  
  const [scanning, setScanning] = useState(false);
  const [activeLayerIndex, setActiveLayerIndex] = useState(-1);
  const [completedLayers, setCompletedLayers] = useState<string[]>([]);
  const [progress, setProgress] = useState(0);
  
  const [result, setResult] = useState<ScanResult | null>(null);

  const timerRef = useRef<NodeJS.Timeout | null>(null);

  useEffect(() => {
    return () => {
      if (timerRef.current) {
        clearInterval(timerRef.current);
      }
    };
  }, []);

  const activeLayers = DETECTION_LAYERS.filter(l => l.type === scanMode);
  const bypassedLayers = DETECTION_LAYERS.filter(l => l.type !== scanMode);

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

    if (timerRef.current) {
      clearInterval(timerRef.current);
      timerRef.current = null;
    }

    setScanning(true);
    setProgress(0);
    setResult(null);
    setCompletedLayers([]);
    
    // Animate scan layers step-by-step
    let currentIdx = 0;
    setActiveLayerIndex(0);
    
    const layerCount = activeLayers.length;
    const intervalTime = 600; // time per layer animation
    
    const animationPromise = new Promise<void>((resolve) => {
      const timer = setInterval(() => {
        if (currentIdx >= layerCount || !activeLayers[currentIdx]) {
          clearInterval(timer);
          setActiveLayerIndex(-1);
          resolve();
          return;
        }
        
        const layerId = activeLayers[currentIdx].id;
        setCompletedLayers(prev => [...prev, layerId]);
        currentIdx++;
        setProgress(Math.round((currentIdx / layerCount) * 100));
        
        if (currentIdx >= layerCount) {
          clearInterval(timer);
          setActiveLayerIndex(-1);
          resolve();
        } else {
          setActiveLayerIndex(currentIdx);
        }
      }, intervalTime);
      timerRef.current = timer;
    });

    try {
      // Run the scan API query concurrently with visual animation
      const [scan] = await Promise.all([
        scanPackage(pkgName, pkgVersion, ecosystem, scanMode),
        animationPromise
      ]);

      setResult(scan);

      if (scan.timestamp === "demo fallback") {
        toast.error("API offline. Displaying sandbox demo results.", {
          description: "Start backend server to receive live database evaluations."
        });
      } else if (scan.status === "Blocked") {
        toast.error(`Blocked: Malware/Vulnerability detected in ${scan.package}`, {
          description: "Threat scores exceeded sandbox thresholds."
        });
      } else {
        toast.success(`Sandbox clean: ${scan.package} passed all layers.`, {
          description: "No threats flagged under selected detection filters."
        });
      }
    } catch (error) {
      const msg = error instanceof Error ? error.message : "Request timed out.";
      toast.error("Sandbox evaluation failed", { description: msg });
      setResult({
        package: pkgName.trim(),
        version: pkgVersion.trim() || "latest",
        ecosystem,
        severity: "LOW",
        status: "Allowed",
        isClean: false,
        timestamp: "scan failed",
        duration_ms: 0,
        signals: [{ message: msg, severity: "LOW", detector: "sandbox" }],
        explanation: "The backend sandbox analysis timed out or could not be completed.",
        action: "Verify API connection status, and verify that the package exists on the registry."
      });
    } finally {
      setScanning(false);
      setProgress(100);
    }
  };

  return (
    <div className="mx-auto max-w-5xl space-y-9 animate-in fade-in duration-500">
      <div className="space-y-4 text-center">
        <div className="page-kicker mx-auto w-fit">
          <Layers className="h-3.5 w-3.5" />
          Multi-Layer Threat Evaluation
        </div>
        <h1 className="page-title">Threat Sandbox</h1>
        <p className="page-subtitle mx-auto">
          Test dependencies using focused scans. Compare database vulnerability lookups against behavioral zero-day protection layers.
        </p>
      </div>

      <div className="grid gap-7 lg:grid-cols-[1fr_380px]">
        {/* Left Side: Scan Inputs & Result Panel */}
        <div className="space-y-7">
          <Card className="surface-card">
            <CardHeader className="pb-4">
              <CardTitle className="flex items-center gap-2 text-xl font-bold">
                <Play className="h-5 w-5 text-emerald-500" />
                Configure Test Scan
              </CardTitle>
              <CardDescription>
                Toggle the scanning mode to isolate CVE database audits from behavioral checks.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              {/* Scan Mode Toggle buttons */}
              <div className="grid grid-cols-2 gap-3 p-1 bg-emerald-50/50 dark:bg-emerald-950/20 rounded-2xl border border-emerald-100/50 dark:border-emerald-900/30">
                <button
                  type="button"
                  onClick={() => !scanning && setScanMode("unknown")}
                  className={`flex items-center justify-center gap-2 py-3.5 px-4 rounded-xl text-sm font-extrabold cursor-pointer transition-all ${
                    scanMode === "unknown"
                      ? "bg-white dark:bg-emerald-900/80 text-emerald-800 dark:text-emerald-200 shadow-sm border border-emerald-100/50 dark:border-emerald-800/40"
                      : "text-emerald-900/60 dark:text-emerald-400 hover:text-emerald-900 hover:bg-emerald-500/5"
                  }`}
                  disabled={scanning}
                >
                  <Cpu className="h-4 w-4" />
                  Behavioral Scan
                </button>
                <button
                  type="button"
                  onClick={() => !scanning && setScanMode("known")}
                  className={`flex items-center justify-center gap-2 py-3.5 px-4 rounded-xl text-sm font-extrabold cursor-pointer transition-all ${
                    scanMode === "known"
                      ? "bg-white dark:bg-emerald-900/80 text-emerald-800 dark:text-emerald-200 shadow-sm border border-emerald-100/50 dark:border-emerald-800/40"
                      : "text-emerald-900/60 dark:text-emerald-400 hover:text-emerald-900 hover:bg-emerald-500/5"
                  }`}
                  disabled={scanning}
                >
                  <Database className="h-4 w-4" />
                  Known Vulns Scan
                </button>
              </div>

              <form onSubmit={handleScan} className="grid gap-3 sm:grid-cols-[1fr_120px_130px_auto]">
                <Input
                  placeholder="Package name (e.g. colourama, express)"
                  className="h-12 rounded-xl border-emerald-100 dark:border-emerald-900 bg-emerald-50/30 dark:bg-emerald-950/40 px-4 text-base font-semibold text-emerald-950 dark:text-emerald-50"
                  value={pkgName}
                  onChange={(event) => handlePkgNameChange(event.target.value)}
                  disabled={scanning}
                  required
                />
                <Input
                  placeholder="Version (opt)"
                  className="h-12 rounded-xl border-emerald-100 dark:border-emerald-900 bg-emerald-50/30 dark:bg-emerald-950/40 px-4 text-base font-semibold text-emerald-950 dark:text-emerald-50"
                  value={pkgVersion}
                  onChange={(event) => setPkgVersion(event.target.value)}
                  disabled={scanning}
                />
                <Select value={ecosystem} onValueChange={(value) => value && setEcosystem(value)} disabled={scanning}>
                  <SelectTrigger className="h-12 w-full rounded-xl border-emerald-100 dark:border-emerald-900 bg-emerald-50/30 dark:bg-emerald-950/40 px-4 text-base font-semibold text-emerald-950 dark:text-emerald-50">
                    <SelectValue placeholder="Registry" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="PyPI">PyPI</SelectItem>
                    <SelectItem value="npm">npm</SelectItem>
                  </SelectContent>
                </Select>
                <Button
                  type="submit"
                  className="h-12 rounded-xl bg-gradient-to-r from-emerald-600 to-teal-600 text-white font-extrabold shadow-md hover:from-emerald-500 hover:to-teal-500 cursor-pointer active:scale-[0.98] transition-all duration-150 px-6 text-sm"
                  disabled={scanning || !pkgName.trim()}
                >
                  {scanning ? "Analyzing..." : "Evaluate"}
                </Button>
              </form>

              {scanning && (
                <div className="space-y-2 pt-2 animate-in fade-in duration-300">
                  <div className="flex justify-between text-xs font-bold text-emerald-800/80 dark:text-emerald-400">
                    <span>Sandbox engine progress</span>
                    <span>{progress}%</span>
                  </div>
                  <Progress value={progress} className="h-2" />
                </div>
              )}
            </CardContent>
          </Card>

          {result && !scanning && (
            <div className="space-y-6 animate-in slide-in-from-bottom-4 duration-500">
              <SandboxResultPanel result={result} />
            </div>
          )}
        </div>

        {/* Right Side: Interactive Layers Visual Checklist */}
        <div className="space-y-6">
          <Card className="surface-card">
            <CardHeader className="pb-3 border-b border-emerald-100/50 dark:border-emerald-900/30">
              <CardTitle className="text-lg font-bold flex items-center gap-2">
                <Layers className="h-4.5 w-4.5 text-emerald-600" />
                Active Protection Layers
              </CardTitle>
              <CardDescription>
                Visualizing how filters map to the selected scanner mode.
              </CardDescription>
            </CardHeader>
            <CardContent className="p-5 space-y-4">
              {/* Active Layers list */}
              <div className="space-y-3">
                <div className="text-xs font-extrabold text-emerald-600 uppercase tracking-widest">
                  Active in Scan:
                </div>
                {activeLayers.map((layer, idx) => {
                  const isActive = scanning && idx === activeLayerIndex;
                  const isCompleted = completedLayers.includes(layer.id);
                  
                  return (
                    <div 
                      key={layer.id}
                      className={`relative flex items-start p-3 rounded-xl border transition-all duration-300 ${
                        isActive 
                          ? "border-emerald-500 bg-emerald-500/10 scale-[1.02] shadow-[0_0_15px_rgba(16,185,129,0.15)]"
                          : isCompleted
                          ? "border-emerald-100 dark:border-emerald-900 bg-emerald-50/20 dark:bg-emerald-950/20"
                          : "border-emerald-100/40 dark:border-emerald-900/10 bg-transparent opacity-85"
                      }`}
                    >
                      <div className="mr-3 flex h-5 w-5 items-center justify-center rounded-full bg-emerald-100 dark:bg-emerald-900/50 text-emerald-600">
                        {isCompleted ? (
                          <Check className="h-3 w-3 stroke-[3px]" />
                        ) : isActive ? (
                          <span className="flex h-2 w-2 relative">
                            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                            <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500" />
                          </span>
                        ) : (
                          <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
                        )}
                      </div>
                      <div className="space-y-0.5">
                        <span className={`block text-xs font-black transition-colors ${isActive ? "text-emerald-700 dark:text-emerald-300" : "text-emerald-950 dark:text-emerald-50"}`}>
                          {layer.name}
                        </span>
                        <span className="block text-[11px] font-semibold text-emerald-800/60 dark:text-emerald-400/60 leading-normal">
                          {layer.description}
                        </span>
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* Bypassed Layers list */}
              <div className="space-y-3 pt-2">
                <div className="text-xs font-extrabold text-emerald-950/40 dark:text-emerald-500/40 uppercase tracking-widest">
                  Bypassed / Not Checked:
                </div>
                <div className="space-y-2.5">
                  {bypassedLayers.map((layer) => (
                    <div 
                      key={layer.id}
                      className="flex items-start p-2.5 rounded-xl border border-dashed border-emerald-100/40 dark:border-emerald-900/10 bg-emerald-50/5 dark:bg-transparent opacity-50"
                    >
                      <div className="mr-3 flex h-5 w-5 items-center justify-center text-emerald-950/30 dark:text-emerald-500/30">
                        <span className="text-[10px] font-extrabold">✕</span>
                      </div>
                      <div className="space-y-0.5">
                        <span className="block text-xs font-bold text-emerald-950/60 dark:text-emerald-400/60 line-through">
                          {layer.name}
                        </span>
                        <span className="block text-[10px] font-medium text-emerald-950/40 dark:text-emerald-500/40">
                          {layer.description}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}

function SandboxResultPanel({ result }: { result: ScanResult }) {
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
  const scanModeLabel = result.metadata?.scan_mode === "known" 
    ? "Known Vulnerability Lookup" 
    : result.metadata?.scan_mode === "unknown" 
    ? "Zero-Day Behavioral Scan" 
    : "Full Deep Scan";

  return (
    <div className="surface-card p-6 md:p-8">
      {/* Title Header */}
      <div className="flex flex-col gap-3 border-b border-emerald-100 dark:border-emerald-900 pb-5 md:flex-row md:items-center md:justify-between">
        <div>
          <h2 className="flex items-center text-2xl font-black text-emerald-950 dark:text-emerald-50 font-display">
            {result.package} <span className="ml-2 font-semibold text-emerald-700/70 dark:text-emerald-400/70">{result.version}</span>
          </h2>
          <div className="mt-1.5 flex flex-wrap gap-2">
            <span className="inline-flex items-center rounded-md bg-emerald-50 dark:bg-emerald-950/50 px-2.5 py-0.5 text-xs font-bold text-emerald-700 dark:text-emerald-300 border border-emerald-100 dark:border-emerald-900/60 uppercase tracking-wider">
              {result.ecosystem}
            </span>
            <span className="inline-flex items-center rounded-md bg-emerald-50 dark:bg-emerald-950/50 px-2.5 py-0.5 text-xs font-bold text-emerald-700 dark:text-emerald-300 border border-emerald-100/60 dark:border-emerald-900/60">
              Filter: {scanModeLabel}
            </span>
          </div>
        </div>
        <Badge className={`${blocked ? "border-rose-200 dark:border-rose-900/60 bg-rose-50 dark:bg-rose-950/40 text-rose-700 dark:text-rose-400" : "border-emerald-200 dark:border-emerald-900/60 bg-emerald-100 dark:bg-emerald-900/50 text-emerald-800 dark:text-emerald-300"} rounded-full px-3 py-1 text-sm shadow-none`}>
          {blocked ? "CRITICAL" : result.severity} - {blocked ? "Blocked" : "Passed Sandbox"}
        </Badge>
      </div>

      {/* Dual Registry Warning Alert box */}
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

      {/* Sandbox Signals Section */}
      <div className="mt-6 space-y-4">
        <h3 className="text-lg font-black text-emerald-950 dark:text-emerald-50 font-display flex items-center gap-2">
          {blocked ? (
            <ShieldX className="h-5 w-5 text-rose-500" />
          ) : (
            <ShieldCheck className="h-5 w-5 text-emerald-500" />
          )}
          Evaluation Findings
        </h3>
        <ul className="space-y-3">
          {(result.signals.length ? result.signals : [{ message: "No threat vectors triggered under selected sandbox mode", severity: "CLEAN" } as Signal]).map((signal, index) => (
            <li key={index} className="flex flex-col items-start rounded-2xl border border-emerald-100 dark:border-emerald-900 bg-emerald-50/40 dark:bg-emerald-950/30 p-4">
              <div className="flex items-start w-full">
                {signal.severity === "CLEAN" ? (
                  <ShieldCheck className="mr-3 mt-0.5 h-5 w-5 flex-shrink-0 text-emerald-500 dark:text-emerald-400" />
                ) : signal.severity === "CRITICAL" || signal.severity === "HIGH" ? (
                  <ShieldX className="mr-3 mt-0.5 h-5 w-5 flex-shrink-0 text-rose-500" />
                ) : (
                  <ShieldAlert className="mr-3 mt-0.5 h-5 w-5 flex-shrink-0 text-amber-500" />
                )}
                <div className="flex-1">
                  <span className="text-emerald-950/80 dark:text-emerald-200 block text-sm font-semibold">{signal.message}</span>
                  {signal.detector && (
                    <span className="text-[10px] mt-1 font-bold text-emerald-600 dark:text-emerald-400/60 uppercase tracking-widest block">
                      Detector: {signal.detector}
                    </span>
                  )}
                  {signal.url && (
                    <a
                      href={signal.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-block mt-2 text-xs font-bold text-emerald-600 dark:text-emerald-400 hover:underline cursor-pointer"
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

      {/* AI Explanation Section */}
      {result.explanation && (
        <div className="mt-6 rounded-2xl border border-emerald-100 dark:border-emerald-900 bg-emerald-50/60 dark:bg-emerald-950/30 p-6">
          <div className="mb-3 flex items-center">
            <Terminal className="mr-2 h-5 w-5 text-primary" />
            <h3 className="font-black text-emerald-950 dark:text-emerald-50">AI Explanation</h3>
          </div>
          <p className="whitespace-pre-wrap break-words leading-relaxed text-emerald-950/75 dark:text-emerald-300 text-sm font-semibold">{result.explanation}</p>
          {result.action && <p className="mt-3 whitespace-pre-wrap break-words text-xs font-bold text-emerald-950 dark:text-emerald-400 bg-emerald-100/50 dark:bg-emerald-900/30 py-2 px-3.5 rounded-xl border border-emerald-100/40 dark:border-emerald-800/30 w-fit">Recommended Action: {result.action}</p>}
        </div>
      )}

      {/* Block & Report Button */}
      <div className="pt-6 border-t border-emerald-100/50 dark:border-emerald-900/30 mt-6">
        <Button
          variant={blocked ? "destructive" : "outline"}
          className="rounded-xl font-extrabold shadow-xs cursor-pointer transition-all active:scale-[0.98] py-5 px-5 text-sm"
          onClick={handleAction}
          disabled={actionDone}
        >
          {actionDone ? (blocked ? "Manually Blocked & Reported" : "Reviewed & Cleared") : (blocked ? "Block & Report Package" : "Mark as Reviewed")}
          <ArrowRight className="ml-2 h-4 w-4" />
        </Button>
      </div>
    </div>
  );
}
