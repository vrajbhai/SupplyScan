"use client";

import { useEffect, useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { Shield, Key, Bell, AlertTriangle, Eye, EyeOff } from "lucide-react";
import { toast } from "sonner";

const DEFAULT_PREFS = {
  blockCritical: true,
  blockHigh: true,
  blockMedium: false,
  notify: true,
};

function readStoredJson<T>(key: string, fallback: T): T {
  if (typeof window === "undefined") return fallback;
  const value = window.localStorage.getItem(key);
  if (!value) return fallback;
  try {
    return JSON.parse(value) as T;
  } catch {
    return fallback;
  }
}

function readStoredString(key: string): string {
  if (typeof window === "undefined") return "";
  return window.localStorage.getItem(key) || "";
}

export default function SettingsPage() {
  const [claudeKey, setClaudeKey] = useState("");
  const [openRouterKey, setOpenRouterKey] = useState("");
  const [showClaude, setShowClaude] = useState(false);
  const [showOpenRouter, setShowOpenRouter] = useState(false);
  const [hooks, setHooks] = useState({ pip: true, npm: true });
  const [prefs, setPrefs] = useState(DEFAULT_PREFS);
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setClaudeKey(readStoredString("supplyscan:claude-key"));
    setOpenRouterKey(readStoredString("supplyscan:openrouter-key"));
    setHooks(readStoredJson("supplyscan:hooks", { pip: true, npm: true }));
    setPrefs(readStoredJson("supplyscan:prefs", DEFAULT_PREFS));
    setMounted(true);
  }, []);

  useEffect(() => {
    if (!mounted) return;
    localStorage.setItem("supplyscan:prefs", JSON.stringify(prefs));
  }, [prefs, mounted]);

  useEffect(() => {
    if (!mounted) return;
    localStorage.setItem("supplyscan:hooks", JSON.stringify(hooks));
  }, [hooks, mounted]);

  const handleSaveKeys = () => {
    localStorage.setItem("supplyscan:claude-key", claudeKey);
    localStorage.setItem("supplyscan:openrouter-key", openRouterKey);
    toast.success("API keys saved successfully");
  };

  const handleRemoveHooks = () => {
    setHooks({ pip: false, npm: false });
    toast.info("Global hooks removed");
  };

  return (
    <div className="max-w-4xl space-y-8 animate-in fade-in duration-500">
      <div className="border-b border-emerald-100 dark:border-emerald-900 pb-6">
        <h1 className="mb-2 text-3xl font-extrabold tracking-tight text-emerald-950 dark:text-emerald-50">Settings</h1>
        <p className="text-emerald-900/60 dark:text-emerald-400">Manage AI configuration, system hooks, and detection preferences.</p>
      </div>

      <div className="grid gap-8">
        <Card className="surface-card dark:border-emerald-900 dark:bg-emerald-950/40">
          <CardHeader className="border-b border-emerald-50 dark:border-emerald-900/60 bg-emerald-50/50 dark:bg-emerald-900/20 pb-4">
            <CardTitle className="flex items-center text-lg dark:text-emerald-50"><Key className="mr-2 h-5 w-5 text-emerald-600 dark:text-emerald-400" />AI Explainer Keys</CardTitle>
            <CardDescription className="dark:text-emerald-300/80">Provide API keys to get natural-language threat explanations.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-6 p-6">
            <KeyInput label="Anthropic Claude API Key" value={claudeKey} onChange={setClaudeKey} visible={showClaude} onToggle={() => setShowClaude((value) => !value)} />
            <KeyInput label="OpenRouter API Key" value={openRouterKey} onChange={setOpenRouterKey} visible={showOpenRouter} onToggle={() => setShowOpenRouter((value) => !value)} placeholder="sk-or-v1-..." />
            <Button onClick={handleSaveKeys} variant="outline" className="rounded-2xl border-emerald-200 dark:border-emerald-900 bg-white dark:bg-emerald-950 text-emerald-800 dark:text-emerald-400 shadow-sm hover:bg-emerald-50 dark:hover:bg-emerald-900/50 font-bold">Save Keys</Button>
          </CardContent>
        </Card>

        <Card className="surface-card dark:border-emerald-900 dark:bg-emerald-950/40">
          <CardHeader className="border-b border-emerald-50 dark:border-emerald-900/60 bg-emerald-50/50 dark:bg-emerald-900/20 pb-4">
            <CardTitle className="flex items-center text-lg dark:text-emerald-50"><Shield className="mr-2 h-5 w-5 text-emerald-600 dark:text-emerald-400" />System Hooks</CardTitle>
            <CardDescription className="dark:text-emerald-300/80">Global interceptors that block malicious installs in your terminal.</CardDescription>
          </CardHeader>
          <CardContent className="p-6">
            <div className="flex flex-col justify-between gap-6 sm:flex-row sm:items-center">
              <div className="space-y-4">
                <HookStatus label="Pip Hook" active={hooks.pip} />
                <HookStatus label="NPM Hook" active={hooks.npm} />
              </div>
              <Button onClick={handleRemoveHooks} variant="outline" className="rounded-2xl border-red-200 dark:border-red-900 bg-white dark:bg-emerald-950/20 text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-950/30 font-bold">
                <AlertTriangle className="mr-2 h-4 w-4" />Remove Hooks
              </Button>
            </div>
          </CardContent>
        </Card>

        <Card className="surface-card dark:border-emerald-900 dark:bg-emerald-950/40">
          <CardHeader className="border-b border-emerald-50 dark:border-emerald-900/60 bg-emerald-50/50 dark:bg-emerald-900/20 pb-4">
            <CardTitle className="flex items-center text-lg dark:text-emerald-50"><Shield className="mr-2 h-5 w-5 text-emerald-600 dark:text-emerald-400" />Scan Preferences</CardTitle>
            <CardDescription className="dark:text-emerald-300/80">Configure how SupplyScan responds to detected threats.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-6 p-6">
            <PreferenceRow label="Auto-block CRITICAL threats" description="Immediately abort installation of known malware." checked={prefs.blockCritical} onChange={(checked) => setPrefs({ ...prefs, blockCritical: checked })} />
            <PreferenceRow label="Auto-block HIGH threats" description="Abort installation for highly suspicious signals." checked={prefs.blockHigh} onChange={(checked) => setPrefs({ ...prefs, blockHigh: checked })} />
            <PreferenceRow label="Auto-block MEDIUM threats" description="Strict mode. Often causes false positives." checked={prefs.blockMedium} onChange={(checked) => setPrefs({ ...prefs, blockMedium: checked })} />
            <div className="border-t border-slate-100 pt-4">
              <PreferenceRow
                label="Desktop Notifications"
                description="Show OS notifications when a threat is blocked."
                checked={prefs.notify}
                onChange={(checked) => {
                  setPrefs({ ...prefs, notify: checked });
                  if (checked && typeof window !== "undefined" && "Notification" in window) {
                    if (Notification.permission === "default") {
                      Notification.requestPermission().then((permission) => {
                        if (permission === "granted") {
                          toast.success("Desktop notifications enabled successfully");
                        }
                      });
                    } else if (Notification.permission === "denied") {
                      toast.warning("Notifications are blocked by your browser settings");
                    }
                  }
                }}
                icon
              />
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

function KeyInput({
  label,
  value,
  onChange,
  visible,
  onToggle,
  placeholder,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  visible: boolean;
  onToggle: () => void;
  placeholder?: string;
}) {
  return (
    <label className="block space-y-3">
      <span className="text-sm font-medium text-emerald-900/80 dark:text-emerald-300">{label}</span>
      <div className="flex max-w-md gap-2">
        <Input type={visible ? "text" : "password"} value={value} onChange={(event) => onChange(event.target.value)} placeholder={placeholder} className="shadow-sm dark:border-emerald-900 dark:bg-emerald-950/40 dark:text-emerald-100" />
        <Button type="button" variant="outline" size="icon" onClick={onToggle} aria-label={visible ? "Hide key" : "Show key"} className="dark:border-emerald-900 dark:bg-emerald-950/40 dark:text-emerald-400 dark:hover:bg-emerald-900/50">
          {visible ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
        </Button>
      </div>
    </label>
  );
}

function HookStatus({ label, active }: { label: string; active: boolean }) {
  return (
    <div className="flex items-center space-x-3">
      <span className="relative flex h-2.5 w-2.5">
        {active && <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75" />}
        <span className={`relative inline-flex h-2.5 w-2.5 rounded-full ${active ? "bg-emerald-500" : "bg-emerald-300 dark:bg-emerald-900"}`} />
      </span>
      <span className="font-medium text-emerald-900/80 dark:text-emerald-300">{label} ({active ? "Active" : "Inactive"})</span>
    </div>
  );
}

function PreferenceRow({
  label,
  description,
  checked,
  onChange,
  icon = false,
}: {
  label: string;
  description: string;
  checked: boolean;
  onChange: (checked: boolean) => void;
  icon?: boolean;
}) {
  return (
    <div className="flex items-center justify-between gap-4">
      <div className="space-y-0.5">
        <div className="flex items-center text-base font-medium text-emerald-950 dark:text-emerald-100">
          {icon && <Bell className="mr-2 h-4 w-4 text-emerald-600 dark:text-emerald-400" />}
          {label}
        </div>
        <p className="text-sm text-emerald-900/60 dark:text-emerald-400">{description}</p>
      </div>
      <Switch checked={checked} onCheckedChange={onChange} />
    </div>
  );
}
