import React, { useState } from "react";
import { Node, Edge } from "@xyflow/react";
import { DependencyGraphCanvas } from "./components/DependencyGraphCanvas";
import { GraphNodeSummary } from "./types/api.gen";

const INITIAL_NODES: Node<GraphNodeSummary>[] = [
  {
    id: "pkg-root",
    type: "accessiblePackage",
    position: { x: 350, y: 30 },
    data: {
      purl: "pkg:npm/payment-service@1.0.0",
      package_name: "payment-service",
      version: "1.0.0",
      depth: 0,
      composite_score: 95.0,
      risk_tier: "CLEAN",
      risk_reason: "Root application module",
      should_emphasize: false,
      vuln_count: 0,
      reachability: "DIRECT_IMPORTED",
    },
  },
  {
    id: "pkg-express",
    type: "accessiblePackage",
    position: { x: 120, y: 180 },
    data: {
      purl: "pkg:npm/express@4.18.2",
      package_name: "express",
      version: "4.18.2",
      depth: 1,
      composite_score: 88.0,
      risk_tier: "LOW",
      risk_reason: "Healthy ecosystem activity, no known exploits",
      should_emphasize: false,
      vuln_count: 0,
      reachability: "DIRECT_IMPORTED",
    },
  },
  {
    id: "pkg-log4j",
    type: "accessiblePackage",
    position: { x: 420, y: 180 },
    data: {
      purl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
      package_name: "log4j-core",
      version: "2.14.1",
      depth: 1,
      composite_score: 12.0,
      risk_tier: "CRITICAL",
      risk_reason: "CVE-2021-44228 Remote Code Execution reachable via JNDI lookup",
      should_emphasize: true,
      vuln_count: 2,
      reachability: "DIRECT_IMPORTED",
    },
  },
  {
    id: "pkg-jwt",
    type: "accessiblePackage",
    position: { x: 720, y: 180 },
    data: {
      purl: "pkg:npm/jsonwebtoken@8.5.1",
      package_name: "jsonwebtoken",
      version: "8.5.1",
      depth: 1,
      composite_score: 52.0,
      risk_tier: "HIGH",
      risk_reason: "High severity key confusion vulnerability in algorithm verification",
      should_emphasize: true,
      vuln_count: 1,
      reachability: "DIRECT_IMPORTED",
    },
  },
  {
    id: "pkg-body-parser",
    type: "accessiblePackage",
    position: { x: 50, y: 350 },
    data: {
      purl: "pkg:npm/body-parser@1.20.1",
      package_name: "body-parser",
      version: "1.20.1",
      depth: 2,
      composite_score: 68.0,
      risk_tier: "MODERATE",
      risk_reason: "Moderate unhandled payload denial-of-service advisory",
      should_emphasize: false,
      vuln_count: 1,
      reachability: "TRANSITIVE_REQUIRED",
    },
  },
  {
    id: "pkg-clean-cluster",
    type: "accessiblePackage",
    position: { x: 260, y: 350 },
    data: {
      purl: "cluster:clean-deps",
      package_name: "Clean Dependencies Cluster",
      version: "1.0.0",
      depth: 2,
      composite_score: 96.0,
      risk_tier: "CLEAN",
      risk_reason: "Aggregated clean transitive dependencies",
      should_emphasize: false,
      vuln_count: 0,
      reachability: "UNREFERENCED_LATENT",
      is_aggregate_cluster: true,
      aggregated_count: 18,
    },
  },
];

const INITIAL_EDGES: Edge[] = [
  { id: "e-root-express", source: "pkg-root", target: "pkg-express", animated: true },
  { id: "e-root-log4j", source: "pkg-root", target: "pkg-log4j", animated: true, style: { stroke: "#e11d48", strokeWidth: 2 } },
  { id: "e-root-jwt", source: "pkg-root", target: "pkg-jwt", animated: true, style: { stroke: "#e11d48", strokeWidth: 2 } },
  { id: "e-express-bodyparser", source: "pkg-express", target: "pkg-body-parser" },
  { id: "e-express-cluster", source: "pkg-express", target: "pkg-clean-cluster", style: { strokeDasharray: "4 4" } },
];

export const App: React.FC = () => {
  const [selectedPackage, setSelectedPackage] = useState<GraphNodeSummary | null>(INITIAL_NODES[2].data);

  return (
    <div className="flex flex-col h-screen w-screen bg-slate-950 text-slate-100 font-sans">
      {/* Header */}
      <header className="h-16 px-6 bg-slate-900 border-b border-slate-800 flex items-center justify-between shrink-0 shadow-sm">
        <div className="flex items-center gap-3">
          <span className="text-2xl" aria-hidden="true">🛡️</span>
          <div>
            <h1 className="text-base font-bold text-slate-100 tracking-tight">
              Supply Chain Guardian
            </h1>
            <p className="text-xs text-slate-400">
              Interactive Dependency Risk Graph &amp; Reachability Visualizer
            </p>
          </div>
        </div>

        <div className="flex items-center gap-4 text-xs">
          <div className="flex items-center gap-1.5 px-3 py-1 rounded bg-slate-800 text-slate-300">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
            <span>Scan Complete: 24 Dependencies</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="px-2 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800 font-medium">
              1 Critical
            </span>
            <span className="px-2 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-800 font-medium">
              1 Moderate
            </span>
            <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800 font-medium">
              22 Clean
            </span>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <div className="flex-1 flex overflow-hidden relative">
        {/* Canvas Area */}
        <main className="flex-1 h-full w-full relative">
          <DependencyGraphCanvas
            nodes={INITIAL_NODES}
            edges={INITIAL_EDGES}
            onSelectPackage={setSelectedPackage}
            className="w-full h-full"
          />
        </main>

        {/* Selected Package Details Side Drawer */}
        <aside className="w-80 bg-slate-900 border-l border-slate-800 p-5 flex flex-col gap-4 shrink-0 overflow-y-auto">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <h2 className="text-sm font-semibold tracking-wide uppercase text-slate-400">
              Package Details
            </h2>
            {selectedPackage && (
              <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                Depth {selectedPackage.depth ?? 0}
              </span>
            )}
          </div>

          {selectedPackage ? (
            <div className="space-y-4 text-xs">
              <div>
                <span className="text-slate-400 block text-[11px] mb-0.5">Package Name</span>
                <span className="font-bold text-sm text-slate-100">{selectedPackage.package_name}</span>
                <span className="text-slate-400 ml-1.5 font-mono text-[11px]">v{selectedPackage.version}</span>
              </div>

              <div>
                <span className="text-slate-400 block text-[11px] mb-0.5">Canonical PURL</span>
                <span className="font-mono text-[11px] text-slate-300 bg-slate-950 px-2 py-1 rounded block truncate">
                  {selectedPackage.purl}
                </span>
              </div>

              <div className="grid grid-cols-2 gap-2 pt-1">
                <div className="bg-slate-950/60 p-2.5 rounded border border-slate-800">
                  <span className="text-slate-400 block text-[10px] uppercase font-semibold">Trust Score</span>
                  <span className="text-base font-black text-slate-100">{selectedPackage.composite_score}</span>
                  <span className="text-[10px] text-slate-500"> / 100</span>
                </div>
                <div className="bg-slate-950/60 p-2.5 rounded border border-slate-800">
                  <span className="text-slate-400 block text-[10px] uppercase font-semibold">Risk Tier</span>
                  <span className={`text-xs font-bold ${
                    selectedPackage.risk_tier === "CRITICAL" ? "text-rose-400" :
                    selectedPackage.risk_tier === "HIGH" ? "text-rose-300" :
                    selectedPackage.risk_tier === "MODERATE" ? "text-amber-400" : "text-emerald-400"
                  }`}>
                    {selectedPackage.risk_tier}
                  </span>
                </div>
              </div>

              <div>
                <span className="text-slate-400 block text-[11px] mb-0.5">Static Reachability</span>
                <span className="px-2 py-1 rounded bg-slate-800 text-slate-200 font-mono text-[11px] inline-block">
                  {selectedPackage.reachability}
                </span>
              </div>

              {selectedPackage.vuln_count > 0 && (
                <div>
                  <span className="text-slate-400 block text-[11px] mb-0.5">Vulnerabilities</span>
                  <div className="px-2.5 py-1.5 rounded bg-rose-950/40 border border-rose-900/60 text-rose-300 text-[11px]">
                    ⚠️ {selectedPackage.vuln_count} security advisories detected
                  </div>
                </div>
              )}

              <div>
                <span className="text-slate-400 block text-[11px] mb-0.5">Risk Reason</span>
                <p className="text-slate-300 bg-slate-950/60 p-2.5 rounded border border-slate-800 leading-relaxed text-[11px]">
                  {selectedPackage.risk_reason}
                </p>
              </div>

              {selectedPackage.is_aggregate_cluster && (
                <div className="p-2.5 rounded bg-emerald-950/40 border border-emerald-900 text-emerald-300 text-[11px]">
                  Collapsed view for {selectedPackage.aggregated_count} clean dependencies.
                </div>
              )}
            </div>
          ) : (
            <div className="text-center py-10 text-slate-500 text-xs">
              Click any node in the graph to inspect risk details.
            </div>
          )}

          <div className="mt-auto pt-4 border-t border-slate-800 text-[11px] text-slate-500">
            Keyboard navigation: Tab through nodes, press <kbd className="px-1 py-0.5 bg-slate-800 rounded text-slate-300 font-mono">Enter</kbd> to select.
          </div>
        </aside>
      </div>
    </div>
  );
};
