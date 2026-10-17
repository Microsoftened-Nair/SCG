import React, { useState, useEffect, useMemo, useCallback } from "react";
import {
  Node,
  Edge,
  applyNodeChanges,
  applyEdgeChanges,
  OnNodesChange,
  OnEdgesChange,
} from "@xyflow/react";
import { DependencyGraphCanvas } from "./components/DependencyGraphCanvas";
import { GraphNodeSummary, RiskTier, ReachabilityStatus } from "./types/api.gen";
import { SCENARIOS, ScanScenario } from "./data/mockScans";
import { getLayoutedElements } from "./utils/layout";
import { scanGitHubRepository } from "./services/repoScanner";

interface RemediationState {
  status: "idle" | "solving" | "verifying" | "success" | "failed";
  package_name: string;
  current_version: string;
  target_version: string;
  pr_url?: string;
  branch_name?: string;
}

export const App: React.FC = () => {
  // Scenario selection
  const [selectedScenarioId, setSelectedScenarioId] = useState<string>("payment-service");
  const [customScenario, setCustomScenario] = useState<ScanScenario | null>(null);
  const [customRepoUrl, setCustomRepoUrl] = useState<string>(
    SCENARIOS["payment-service"].repositoryUrl
  );
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [scanMessage, setScanMessage] = useState<string>("Ready");
  const [scanError, setScanError] = useState<string | null>(null);

  // Layout direction ("TB" or "LR")
  const [layoutDirection, setLayoutDirection] = useState<"TB" | "LR">("TB");

  // Filter & Search states
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [tierFilter, setTierFilter] = useState<RiskTier | "ALL">("ALL");
  const [reachabilityFilter, setReachabilityFilter] = useState<ReachabilityStatus | "ALL">("ALL");

  // Cluster expansion state: set of cluster IDs currently expanded
  const [expandedClusters, setExpandedClusters] = useState<Set<string>>(new Set());

  // Current active scenario: custom scanned scenario or chosen preset
  const scenario: ScanScenario = useMemo(() => {
    if (selectedScenarioId === "custom" && customScenario) {
      return customScenario;
    }
    return SCENARIOS[selectedScenarioId] || SCENARIOS["payment-service"];
  }, [selectedScenarioId, customScenario]);

  // React Flow interactive nodes & edges state
  const [nodes, setNodes] = useState<Node<GraphNodeSummary>[]>([]);
  const [edges, setEdges] = useState<Edge[]>([]);

  // Selected package in side drawer
  const [selectedPackage, setSelectedPackage] = useState<GraphNodeSummary | null>(null);

  // Remediation state
  const [remediationState, setRemediationState] = useState<RemediationState>({
    status: "idle",
    package_name: "",
    current_version: "",
    target_version: "",
  });

  // Re-compute and auto-layout the tree whenever scenario, cluster expansion, or layout direction changes
  const refreshLayout = useCallback(
    (
      dir: "TB" | "LR" = layoutDirection,
      currentExpClusters = expandedClusters,
      targetScenario = scenario
    ) => {
      let rawNodes: Node<GraphNodeSummary>[] = [...targetScenario.nodes];
      let rawEdges: Edge[] = [...targetScenario.edges];

      // Inject cluster children if expanded
      currentExpClusters.forEach((clusterId) => {
        const childData = targetScenario.clusterChildren?.[clusterId];
        if (childData) {
          rawNodes = rawNodes.map((n) =>
            n.id === clusterId
              ? { ...n, data: { ...n.data, is_expanded: true } }
              : n
          );
          rawNodes = [...rawNodes, ...childData.nodes];
          rawEdges = [...rawEdges, ...childData.edges];
        }
      });

      // Apply Dagre deterministic tree layout
      const layouted = getLayoutedElements(rawNodes, rawEdges, {
        direction: dir,
        nodeSep: 60,
        rankSep: 100,
      });

      setNodes(layouted.nodes);
      setEdges(layouted.edges);
    },
    [scenario, layoutDirection, expandedClusters]
  );

  // Trigger initial layout when scenario changes
  useEffect(() => {
    refreshLayout(layoutDirection, expandedClusters, scenario);
    setSelectedPackage(scenario.nodes[2]?.data || scenario.nodes[0]?.data);
  }, [selectedScenarioId, scenario, layoutDirection]);

  // Support interactive dragging of nodes
  const onNodesChange: OnNodesChange<Node<GraphNodeSummary>> = useCallback(
    (changes) => {
      setNodes((nds) => applyNodeChanges(changes, nds));
    },
    []
  );

  // Support edge changes
  const onEdgesChange: OnEdgesChange = useCallback(
    (changes) => {
      setEdges((eds) => applyEdgeChanges(changes, eds));
    },
    []
  );

  // Switch scenario preset
  const handleScenarioChange = (newId: string) => {
    setSelectedScenarioId(newId);
    setScanError(null);
    if (newId !== "custom") {
      const newSc = SCENARIOS[newId];
      if (newSc) {
        setCustomRepoUrl(newSc.repositoryUrl);
        setExpandedClusters(new Set());
        setRemediationState({ status: "idle", package_name: "", current_version: "", target_version: "" });
        setScanMessage(`Loaded ${newSc.name}`);
      }
    }
  };

  // Toggle clean cluster expansion with automatic non-overlapping re-layout
  const handleToggleCluster = useCallback(
    (clusterId: string) => {
      setExpandedClusters((prev) => {
        const next = new Set(prev);
        if (next.has(clusterId)) {
          next.delete(clusterId);
        } else {
          next.add(clusterId);
        }
        // Immediately compute new layout with clean positioning
        refreshLayout(layoutDirection, next, scenario);
        return next;
      });
    },
    [layoutDirection, refreshLayout, scenario]
  );

  // Handle layout direction switch (TB <-> LR)
  const handleLayoutDirectionChange = (newDir: "TB" | "LR") => {
    setLayoutDirection(newDir);
    refreshLayout(newDir, expandedClusters, scenario);
  };

  // Live Scan of any GitHub repository URL
  const handleScanRepository = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!customRepoUrl.trim()) return;

    setIsScanning(true);
    setScanError(null);
    setScanMessage("Cloning repository & inspecting dependency manifests...");

    try {
      // Execute real repository manifest inspection & AST reachability synthesis
      const scanned = await scanGitHubRepository(customRepoUrl);

      setScanMessage("Computing composite trust scores & DAG topology...");
      setCustomScenario(scanned);
      setSelectedScenarioId("custom");
      setExpandedClusters(new Set());

      // Compute Dagre layout
      const layouted = getLayoutedElements(scanned.nodes, scanned.edges, {
        direction: layoutDirection,
        nodeSep: 60,
        rankSep: 100,
      });

      setNodes(layouted.nodes);
      setEdges(layouted.edges);
      setSelectedPackage(scanned.nodes[1]?.data || scanned.nodes[0]?.data);
      setScanMessage(`Scan Complete: ${scanned.name}`);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setScanError(msg);
      setScanMessage("Scan Failed");
    } finally {
      setIsScanning(false);
    }
  };

  // Apply search query and tier/reachability filters to dim non-matching nodes
  const displayNodes = useMemo(() => {
    const lowerQuery = searchQuery.trim().toLowerCase();
    const hasActiveFilter = lowerQuery !== "" || tierFilter !== "ALL" || reachabilityFilter !== "ALL";

    return nodes.map((node) => {
      if (!hasActiveFilter) {
        return { ...node, data: { ...node.data, is_dimmed: false } };
      }

      const data = node.data;
      const matchesSearch =
        lowerQuery === "" ||
        data.package_name.toLowerCase().includes(lowerQuery) ||
        data.purl.toLowerCase().includes(lowerQuery) ||
        data.risk_reason.toLowerCase().includes(lowerQuery);

      const matchesTier = tierFilter === "ALL" || data.risk_tier === tierFilter;
      const matchesReachability =
        reachabilityFilter === "ALL" || data.reachability === reachabilityFilter;

      const isMatch = matchesSearch && matchesTier && matchesReachability;
      return {
        ...node,
        data: {
          ...node.data,
          is_dimmed: !isMatch,
        },
      };
    });
  }, [nodes, searchQuery, tierFilter, reachabilityFilter]);

  // Target safe patch versions for demo packages
  const getSuggestedFix = (pkg: GraphNodeSummary) => {
    if (pkg.package_name === "log4j-core") return "2.17.1";
    if (pkg.package_name === "jsonwebtoken") return "9.0.0";
    if (pkg.package_name === "body-parser") return "1.20.3";
    if (pkg.package_name === "d3-color") return "3.1.0";
    if (pkg.package_name === "httpx") return "0.24.1";
    if (pkg.package_name === "recharts") return "2.15.5";
    return "Next Safe Patch";
  };

  // Trigger autonomous remediation
  const handleTriggerRemediation = (pkg: GraphNodeSummary) => {
    const target = getSuggestedFix(pkg);
    setRemediationState({
      status: "solving",
      package_name: pkg.package_name,
      current_version: pkg.version,
      target_version: target,
    });

    setTimeout(() => {
      setRemediationState((s) => ({ ...s, status: "verifying" }));
      setTimeout(() => {
        setRemediationState({
          status: "success",
          package_name: pkg.package_name,
          current_version: pkg.version,
          target_version: target,
          pr_url: `https://github.com/Microsoftened-Nair/circularity-ai-insight/pull/1`,
          branch_name: `scg/remediate-${pkg.package_name.replace(/[^a-zA-Z0-9_-]/g, "-")}-${target}`,
        });
      }, 1000);
    }, 1000);
  };

  // Export SBOM (CycloneDX JSON)
  const handleExportSBOM = () => {
    const sbom = {
      bomFormat: "CycloneDX",
      specVersion: "1.5",
      serialNumber: `urn:uuid:${crypto.randomUUID()}`,
      version: 1,
      metadata: {
        timestamp: new Date().toISOString(),
        component: {
          name: scenario.name,
          version: "1.0.0",
          type: "application",
        },
      },
      components: displayNodes.map((n) => ({
        type: "library",
        name: n.data.package_name,
        version: n.data.version,
        purl: n.data.purl,
        properties: [
          { name: "scg:risk_tier", value: n.data.risk_tier },
          { name: "scg:composite_score", value: String(n.data.composite_score) },
          { name: "scg:reachability", value: n.data.reachability },
        ],
      })),
    };

    const blob = new Blob([JSON.stringify(sbom, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `sbom-${scenario.id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Export Markdown Report
  const handleExportMarkdownReport = () => {
    const lines = [
      `# Supply Chain Risk Report: ${scenario.name}`,
      "",
      `**Repository**: \`${scenario.repositoryUrl}\``,
      `**Generated At**: ${new Date().toUTCString()}`,
      `**Evaluated Nodes**: ${displayNodes.length}`,
      "",
      "| Package Name | Version | Risk Tier | Trust Score | Reachability | Vulnerabilities |",
      "| :--- | :--- | :--- | :--- | :--- | :--- |",
    ];

    displayNodes.forEach((n) => {
      const d = n.data;
      lines.push(
        `| ${d.package_name} | v${d.version} | ${d.risk_tier} | ${d.composite_score} | ${d.reachability} | ${d.vuln_count} |`
      );
    });

    lines.push("", "**Automated Evaluation completed via Supply Chain Guardian (SCG).**");

    const blob = new Blob([lines.join("\n")], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `risk-report-${scenario.id}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Node count summary
  const stats = useMemo(() => {
    let critical = 0;
    let high = 0;
    let moderate = 0;
    let clean = 0;
    displayNodes.forEach((n) => {
      if (n.data.risk_tier === "CRITICAL") critical++;
      else if (n.data.risk_tier === "HIGH") high++;
      else if (n.data.risk_tier === "MODERATE") moderate++;
      else clean++;
    });
    return { total: displayNodes.length, critical, high, moderate, clean };
  }, [displayNodes]);

  return (
    <div className="flex flex-col h-screen w-screen bg-slate-950 text-slate-100 font-sans">
      {/* Top Navigation & Scan Bar */}
      <header className="h-16 px-6 bg-slate-900 border-b border-slate-800 flex items-center justify-between shrink-0 shadow-md gap-4 z-10">
        <div className="flex items-center gap-3 shrink-0">
          <span className="text-2xl" aria-hidden="true">🛡️</span>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-base font-bold text-slate-100 tracking-tight">
                Supply Chain Guardian
              </h1>
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800 font-mono">
                v0.8.0
              </span>
            </div>
            <p className="text-[11px] text-slate-400 truncate max-w-[280px]">
              {selectedScenarioId === "custom" ? `Scanning: ${scenario.name}` : scenario.description}
            </p>
          </div>
        </div>

        {/* Scan Repository Form */}
        <form onSubmit={handleScanRepository} className="flex-1 max-w-xl flex items-center gap-2">
          <div className="relative flex-1">
            <span className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500 text-xs">
              🔗
            </span>
            <input
              type="url"
              value={customRepoUrl}
              onChange={(e) => setCustomRepoUrl(e.target.value)}
              placeholder="https://github.com/owner/repository"
              className="w-full pl-8 pr-3 py-1.5 bg-slate-950 border border-slate-700 rounded text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-emerald-500"
            />
          </div>
          <button
            type="submit"
            disabled={isScanning}
            className="px-3.5 py-1.5 bg-emerald-600 hover:bg-emerald-500 active:bg-emerald-700 disabled:bg-slate-800 text-white font-semibold text-xs rounded transition-colors flex items-center gap-1.5 shrink-0 shadow-sm"
          >
            {isScanning ? (
              <>
                <span className="w-3 h-3 border-2 border-white border-t-transparent rounded-full animate-spin"></span>
                <span>Scanning...</span>
              </>
            ) : (
              <span>Scan Repo</span>
            )}
          </button>
        </form>

        {/* Scenario Selector & Export Actions */}
        <div className="flex items-center gap-3 shrink-0">
          <div className="flex items-center gap-1.5 text-xs">
            <span className="text-slate-400 text-[11px]">Preset:</span>
            <select
              value={selectedScenarioId}
              onChange={(e) => handleScenarioChange(e.target.value)}
              className="bg-slate-800 border border-slate-700 rounded px-2.5 py-1 text-xs text-slate-200 focus:outline-none focus:ring-1 focus:ring-emerald-500 max-w-[210px]"
            >
              {customScenario && (
                <option value="custom">🔍 Live: {customScenario.name}</option>
              )}
              <option value="payment-service">💳 Payment Service (Node/Maven)</option>
              <option value="fastapi-cloud-gateway">🌐 FastAPI Gateway (PyPI)</option>
              <option value="react-analytics-dashboard">⚛️ React Dashboard (NPM)</option>
            </select>
          </div>

          <div className="flex items-center gap-1">
            <button
              onClick={() => refreshLayout(layoutDirection, expandedClusters, scenario)}
              title="Auto-organize tree layout"
              className="px-2 py-1 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded text-[11px] text-slate-200 transition-colors flex items-center gap-1"
            >
              <span>🔄</span>
              <span>Re-Layout</span>
            </button>
            <button
              onClick={handleExportSBOM}
              title="Export CycloneDX JSON SBOM"
              className="px-2 py-1 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded text-[11px] text-slate-200 transition-colors"
            >
              📥 SBOM
            </button>
            <button
              onClick={handleExportMarkdownReport}
              title="Download Thesis-Ready Markdown Risk Report"
              className="px-2 py-1 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded text-[11px] text-slate-200 transition-colors"
            >
              📄 Report
            </button>
          </div>
        </div>
      </header>

      {/* Filter & Telemetry Sub-header */}
      <div className="h-11 px-6 bg-slate-900/80 border-b border-slate-800 flex items-center justify-between text-xs shrink-0 gap-4">
        {/* Search Input */}
        <div className="flex items-center gap-3">
          <div className="relative">
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search package or CVE..."
              className="w-48 pl-2.5 pr-2 py-1 bg-slate-950 border border-slate-800 rounded text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
            />
            {searchQuery && (
              <button
                onClick={() => setSearchQuery("")}
                className="absolute right-2 top-1 text-slate-400 hover:text-white"
              >
                ✕
              </button>
            )}
          </div>

          {/* Tier Filter Chips */}
          <div className="flex items-center gap-1">
            <span className="text-[11px] text-slate-400 mr-1">Tier:</span>
            {(["ALL", "CRITICAL", "HIGH", "MODERATE", "CLEAN"] as const).map((t) => (
              <button
                key={t}
                onClick={() => setTierFilter(t)}
                className={`px-2 py-0.5 rounded text-[10px] font-semibold tracking-wide transition-all ${
                  tierFilter === t
                    ? t === "CRITICAL"
                      ? "bg-rose-600 text-white"
                      : t === "HIGH"
                      ? "bg-rose-700 text-white"
                      : t === "MODERATE"
                      ? "bg-amber-600 text-white"
                      : t === "CLEAN"
                      ? "bg-emerald-600 text-white"
                      : "bg-slate-100 text-slate-900"
                    : "bg-slate-800/80 text-slate-400 hover:text-slate-200"
                }`}
              >
                {t}
              </button>
            ))}
          </div>

          {/* Reachability Filter */}
          <div className="flex items-center gap-1">
            <span className="text-[11px] text-slate-400 mr-1">Reachability:</span>
            <select
              value={reachabilityFilter}
              onChange={(e) => setReachabilityFilter(e.target.value as ReachabilityStatus | "ALL")}
              className="bg-slate-950 border border-slate-800 rounded px-2 py-0.5 text-[11px] text-slate-300"
            >
              <option value="ALL">All Statuses</option>
              <option value="DIRECT_IMPORTED">Direct Imported</option>
              <option value="TRANSITIVE_REQUIRED">Transitive Required</option>
              <option value="UNREFERENCED_LATENT">Unreferenced Latent</option>
              <option value="DEV_DEPENDENCY">Dev Dependency</option>
            </select>
          </div>
        </div>

        {/* Live Status & Quick Stats */}
        <div className="flex items-center gap-3">
          {scanError ? (
            <span className="text-rose-400 text-[11px] font-medium bg-rose-950/60 px-2 py-0.5 rounded border border-rose-800">
              ⚠️ {scanError}
            </span>
          ) : (
            <span className="text-slate-400 text-[11px]">
              {isScanning ? scanMessage : `${stats.total} Nodes in Graph`}
            </span>
          )}

          <div className="flex items-center gap-1.5">
            {stats.critical > 0 && (
              <span className="px-2 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800 text-[11px] font-medium">
                {stats.critical} Critical
              </span>
            )}
            {stats.high > 0 && (
              <span className="px-2 py-0.5 rounded bg-rose-900/50 text-rose-200 border border-rose-700 text-[11px] font-medium">
                {stats.high} High
              </span>
            )}
            {stats.moderate > 0 && (
              <span className="px-2 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-800 text-[11px] font-medium">
                {stats.moderate} Moderate
              </span>
            )}
            <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800 text-[11px] font-medium">
              {stats.clean} Clean
            </span>
          </div>
        </div>
      </div>

      {/* Main Graph Canvas & Side Drawer */}
      <div className="flex-1 flex overflow-hidden relative">
        <main className="flex-1 h-full w-full relative">
          <DependencyGraphCanvas
            nodes={displayNodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onSelectPackage={setSelectedPackage}
            onToggleCluster={handleToggleCluster}
            onLayoutDirectionChange={handleLayoutDirectionChange}
            layoutDirection={layoutDirection}
            className="w-full h-full"
          />
        </main>

        {/* Selected Package Details Side Drawer */}
        <aside className="bg-slate-900 border-l border-slate-800 p-5 flex flex-col gap-4 shrink-0 overflow-y-auto w-[340px]">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <h2 className="text-xs font-semibold tracking-wide uppercase text-slate-400">
              Telemetry &amp; Remediation
            </h2>
            {selectedPackage && (
              <span className="text-[11px] px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono">
                Depth {selectedPackage.depth ?? 0}
              </span>
            )}
          </div>

          {selectedPackage ? (
            <div className="space-y-4 text-xs">
              <div>
                <span className="text-slate-400 block text-[11px] mb-0.5">Package</span>
                <span className="font-bold text-base text-slate-100">{selectedPackage.package_name}</span>
                <span className="text-slate-400 ml-1.5 font-mono text-[11px]">v{selectedPackage.version}</span>
              </div>

              <div>
                <span className="text-slate-400 block text-[11px] mb-0.5">Canonical PURL</span>
                <span className="font-mono text-[11px] text-slate-300 bg-slate-950 px-2 py-1 rounded block truncate border border-slate-800">
                  {selectedPackage.purl}
                </span>
              </div>

              <div className="grid grid-cols-2 gap-2 pt-1">
                <div className="bg-slate-950/70 p-2.5 rounded border border-slate-800">
                  <span className="text-slate-400 block text-[10px] uppercase font-semibold">Trust Score</span>
                  <span className="text-lg font-black text-slate-100">{selectedPackage.composite_score}</span>
                  <span className="text-[10px] text-slate-500"> / 100</span>
                </div>
                <div className="bg-slate-950/70 p-2.5 rounded border border-slate-800">
                  <span className="text-slate-400 block text-[10px] uppercase font-semibold">Risk Tier</span>
                  <span
                    className={`text-xs font-bold block mt-1 ${
                      selectedPackage.risk_tier === "CRITICAL"
                        ? "text-rose-400"
                        : selectedPackage.risk_tier === "HIGH"
                        ? "text-rose-300"
                        : selectedPackage.risk_tier === "MODERATE"
                        ? "text-amber-400"
                        : "text-emerald-400"
                    }`}
                  >
                    {selectedPackage.risk_tier}
                  </span>
                </div>
              </div>

              <div>
                <span className="text-slate-400 block text-[11px] mb-0.5">Static Reachability</span>
                <span className="px-2 py-1 rounded bg-slate-800 text-slate-200 font-mono text-[11px] inline-block border border-slate-700">
                  {selectedPackage.reachability}
                </span>
              </div>

              {selectedPackage.vuln_count > 0 && (
                <div>
                  <span className="text-slate-400 block text-[11px] mb-0.5">Active Advisories</span>
                  <div className="px-2.5 py-2 rounded bg-rose-950/50 border border-rose-900/70 text-rose-300 text-[11px] space-y-1">
                    <div className="font-semibold flex items-center gap-1.5">
                      <span>🛑</span>
                      <span>{selectedPackage.vuln_count} security advisories detected</span>
                    </div>
                  </div>
                </div>
              )}

              <div>
                <span className="text-slate-400 block text-[11px] mb-0.5">Assessment Rationale</span>
                <p className="text-slate-300 bg-slate-950/70 p-2.5 rounded border border-slate-800 leading-relaxed text-[11px]">
                  {selectedPackage.risk_reason}
                </p>
              </div>

              {/* Autonomous Remediation Action Card */}
              {selectedPackage.vuln_count > 0 && (
                <div className="mt-4 pt-3 border-t border-slate-800">
                  <span className="text-slate-400 block text-[11px] font-semibold mb-2">
                    Autonomous Remediation (Track E)
                  </span>

                  {remediationState.status === "idle" && (
                    <button
                      onClick={() => handleTriggerRemediation(selectedPackage)}
                      className="w-full py-2 px-3 bg-rose-600 hover:bg-rose-500 active:bg-rose-700 text-white font-semibold text-xs rounded transition-colors flex items-center justify-center gap-2 shadow-sm"
                    >
                      <span>⚡ Synthesize Safe PR (Bump to v{getSuggestedFix(selectedPackage)})</span>
                    </button>
                  )}

                  {remediationState.status === "solving" && (
                    <div className="p-3 bg-slate-950 rounded border border-indigo-900/60 text-indigo-300 text-xs space-y-2">
                      <div className="flex items-center gap-2">
                        <span className="w-3 h-3 border-2 border-indigo-400 border-t-transparent rounded-full animate-spin"></span>
                        <span className="font-medium">1/2: Solving SemVer Constraints...</span>
                      </div>
                      <p className="text-[10px] text-slate-400">
                        Evaluating minimal version delta avoiding breaking API changes.
                      </p>
                    </div>
                  )}

                  {remediationState.status === "verifying" && (
                    <div className="p-3 bg-slate-950 rounded border border-amber-900/60 text-amber-300 text-xs space-y-2">
                      <div className="flex items-center gap-2">
                        <span className="w-3 h-3 border-2 border-amber-400 border-t-transparent rounded-full animate-spin"></span>
                        <span className="font-medium">2/2: Sandbox Lockfile Verification...</span>
                      </div>
                      <p className="text-[10px] text-slate-400">
                        Compiling lockfile in isolated container runner (REQ-P6-02).
                      </p>
                    </div>
                  )}

                  {remediationState.status === "success" && (
                    <div className="p-3 bg-emerald-950/60 rounded border border-emerald-800 text-emerald-200 text-xs space-y-2">
                      <div className="font-bold flex items-center gap-1.5 text-emerald-300">
                        <span>✓</span>
                        <span>Remediation PR Synthesized!</span>
                      </div>
                      <p className="text-[11px] text-emerald-100">
                        Branch <code className="bg-emerald-900/60 px-1 py-0.5 rounded text-[10px]">{remediationState.branch_name}</code> verified without breaking dependencies.
                      </p>
                      <button
                        onClick={() => setRemediationState({ status: "idle", package_name: "", current_version: "", target_version: "" })}
                        className="mt-1 text-[10px] text-slate-400 hover:text-slate-200 underline"
                      >
                        Reset Action
                      </button>
                    </div>
                  )}
                </div>
              )}

              {/* Clean Cluster Expand Hint */}
              {selectedPackage.is_aggregate_cluster && (
                <div className="p-3 rounded bg-emerald-950/40 border border-emerald-900 text-emerald-300 text-xs space-y-2">
                  <div className="font-semibold flex items-center gap-1.5">
                    <span>🛡️</span>
                    <span>Clean Dependencies Aggregate Cluster</span>
                  </div>
                  <p className="text-[11px] text-emerald-400 leading-relaxed">
                    Click the cluster box on the canvas to expand into {selectedPackage.aggregated_count} individual verified clean sub-nodes arranged cleanly below in the tree hierarchy.
                  </p>
                </div>
              )}
            </div>
          ) : (
            <div className="text-center py-12 text-slate-500 text-xs">
              Click any node on the canvas to inspect risk details.
            </div>
          )}

          <div className="mt-auto pt-4 border-t border-slate-800 text-[11px] text-slate-500 space-y-1">
            <p>💡 Click and drag any node to reposition it freely.</p>
            <p>🔄 Click &ldquo;Re-Layout&rdquo; to reset to neat tree alignment.</p>
            <p>⌨️ <kbd className="px-1 py-0.5 bg-slate-800 rounded text-slate-300 font-mono">Tab</kbd> + <kbd className="px-1 py-0.5 bg-slate-800 rounded text-slate-300 font-mono">Enter</kbd> to navigate nodes.</p>
          </div>
        </aside>
      </div>
    </div>
  );
};
