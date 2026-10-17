/**
 * Accessible Dependency Graph Canvas and Node Components.
 *
 * Conforms to IEEE Std 830-1998, RFC 2119, and SCG-SRS-PHASE-8 (REQ-P8-02, P8-03).
 * Strictly renders styling directly from backend RiskTier enums with multi-channel
 * accessibility (borders, icons, text badges, motion-safe pulse).
 */

import React, { createContext, useContext, useMemo, useCallback } from "react";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  Handle,
  Position,
  Node,
  Edge,
  NodeProps,
  NodeTypes,
  OnNodesChange,
  OnEdgesChange,
  Panel,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";

import { GraphNodeSummary, RiskTier } from "../types/api.gen";

/**
 * Visual styling token structure mapped directly from backend risk tiers.
 */
export interface TierStyling {
  border: string;
  badge: string;
  icon: string;
  color: string;
}

/**
 * Pure mapping function translating backend RiskTier to multi-channel styling tokens.
 *
 * Per REQ-P8-02 and P8-03:
 * - Does NOT calculate or alter risk scores locally.
 * - CRITICAL / HIGH: border="border-double border-4 border-rose-600 bg-rose-50 text-rose-950",
 *   badge="bg-rose-700 text-white", icon="🛑"
 * - MODERATE: border="border-dashed border-2 border-amber-600 bg-amber-50 text-amber-950",
 *   badge="bg-amber-600 text-white", icon="⚠️"
 * - LOW / CLEAN: border="border-solid border-2 border-emerald-600 bg-emerald-50 text-emerald-950",
 *   badge="bg-emerald-700 text-white", icon="🛡️"
 */
export function getTierStyling(tier: RiskTier): TierStyling {
  switch (tier) {
    case "CRITICAL":
    case "HIGH":
      return {
        border: "border-double border-4 border-rose-600 bg-rose-50 text-rose-950",
        badge: "bg-rose-700 text-white",
        icon: "🛑",
        color: "#e11d48",
      };
    case "MODERATE":
      return {
        border: "border-dashed border-2 border-amber-600 bg-amber-50 text-amber-950",
        badge: "bg-amber-600 text-white",
        icon: "⚠️",
        color: "#d97706",
      };
    case "LOW":
    case "CLEAN":
      return {
        border: "border-solid border-2 border-emerald-600 bg-emerald-50 text-emerald-950",
        badge: "bg-emerald-700 text-white",
        icon: "🛡️",
        color: "#059669",
      };
    default:
      return {
        border: "border-solid border-2 border-gray-400 bg-gray-50 text-gray-900",
        badge: "bg-gray-600 text-white",
        icon: "ℹ️",
        color: "#4b5563",
      };
  }
}

/** Context allowing nodes to notify canvas consumers when selected */
export const NodeSelectionContext = createContext<
  ((node: GraphNodeSummary) => void) | undefined
>(undefined);

/** Context allowing aggregate cluster nodes to trigger expand / collapse */
export const NodeClusterToggleContext = createContext<
  ((clusterId: string) => void) | undefined
>(undefined);

/**
 * AccessiblePackageNode component implementing multi-channel visual risk encoding
 * and WCAG AA accessibility (P8-02, P8-03).
 */
export const AccessiblePackageNode: React.FC<NodeProps<Node<GraphNodeSummary>>> = ({
  id,
  data,
  selected,
  targetPosition = Position.Top,
  sourcePosition = Position.Bottom,
}) => {
  const onSelectPackage = useContext(NodeSelectionContext);
  const onToggleCluster = useContext(NodeClusterToggleContext);

  const handleClick = useCallback(() => {
    if (data.is_aggregate_cluster && onToggleCluster) {
      onToggleCluster(id);
    }
    onSelectPackage?.(data);
  }, [id, data, onSelectPackage, onToggleCluster]);

  const handleKeyDown = useCallback(
    (event: React.KeyboardEvent<HTMLDivElement>) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        if (data.is_aggregate_cluster && onToggleCluster) {
          onToggleCluster(id);
        }
        onSelectPackage?.(data);
      }
    },
    [id, data, onSelectPackage, onToggleCluster]
  );

  const isDimmed = Boolean(data.is_dimmed);
  const dimClass = isDimmed ? "opacity-25 filter grayscale" : "opacity-100";
  const selectedClass = selected
    ? "ring-2 ring-indigo-400 ring-offset-2 ring-offset-slate-950 shadow-2xl scale-[1.02]"
    : "hover:shadow-lg";

  // Handle collapsed / expanded aggregate cluster
  if (data.is_aggregate_cluster) {
    const clusterCount = data.aggregated_count ?? 0;
    const isExpanded = Boolean(data.is_expanded);
    const clusterAriaLabel = isExpanded
      ? `- Collapse ${clusterCount} Clean Dependencies`
      : `+ ${clusterCount} Clean Dependencies`;

    return (
      <div
        role="button"
        tabIndex={0}
        aria-label={clusterAriaLabel}
        className={`w-[240px] px-4 py-3 rounded-xl border-dashed border-2 border-emerald-600 bg-emerald-50 text-emerald-950 font-semibold text-xs tracking-wide shadow-md hover:bg-emerald-100 focus:outline-none focus:ring-2 focus:ring-emerald-500 cursor-grab active:cursor-grabbing transition-all select-none ${selectedClass} ${dimClass}`}
        onClick={handleClick}
        onKeyDown={handleKeyDown}
      >
        <Handle
          type="target"
          position={targetPosition}
          className="!w-3 !h-3 !bg-emerald-700 !border-2 !border-white rounded-full transition-transform hover:scale-125"
        />
        <div className="flex flex-col gap-0.5">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-1.5 font-bold">
              <span aria-hidden="true">{isExpanded ? "📂" : "🛡️"}</span>
              <span>{clusterAriaLabel}</span>
            </div>
            <span className="text-[10px] bg-emerald-200/80 text-emerald-900 px-1.5 py-0.5 rounded-full font-mono">
              {clusterCount}
            </span>
          </div>
          <span className="text-[10px] text-emerald-700 font-normal">
            {isExpanded ? "Click to collapse cluster" : "Click to expand in tree"}
          </span>
        </div>
        <Handle
          type="source"
          position={sourcePosition}
          className="!w-3 !h-3 !bg-emerald-700 !border-2 !border-white rounded-full transition-transform hover:scale-125"
        />
      </div>
    );
  }

  // Standard dependency package node
  const styling = getTierStyling(data.risk_tier);
  const pulseClass = data.should_emphasize ? "motion-safe:animate-pulse" : "";
  const descriptiveAriaLabel = `${data.package_name} v${data.version}, Risk: ${data.risk_tier}, Score: ${data.composite_score}, Reachability: ${data.reachability}, Vulnerabilities: ${data.vuln_count}`;

  return (
    <div
      role="button"
      tabIndex={0}
      aria-label={descriptiveAriaLabel}
      className={`w-[260px] p-3 rounded-xl shadow-md transition-all cursor-grab active:cursor-grabbing focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 select-none ${styling.border} ${pulseClass} ${selectedClass} ${dimClass}`}
      onClick={handleClick}
      onKeyDown={handleKeyDown}
    >
      <Handle
        type="target"
        position={targetPosition}
        className="!w-3 !h-3 !bg-slate-600 !border-2 !border-white rounded-full transition-transform hover:scale-125"
      />

      {/* Header: Icon, Name, and Numeric High-Contrast Badge */}
      <div className="flex items-start justify-between gap-2 mb-1.5">
        <div className="flex items-center gap-1.5 overflow-hidden flex-1 min-w-0">
          <span className="text-base select-none shrink-0" aria-hidden="true">
            {styling.icon}
          </span>
          <span
            className="font-bold text-sm truncate"
            title={`${data.package_name} v${data.version}`}
          >
            {data.package_name}
          </span>
        </div>
        {/* Numeric score badge as text with verified high contrast */}
        <span
          className={`shrink-0 px-2 py-0.5 rounded-md text-xs font-black tracking-tight shadow-sm ${styling.badge}`}
          aria-label={`Score ${data.composite_score}`}
        >
          {data.composite_score}
        </span>
      </div>

      {/* Details Meta */}
      <div className="text-xs space-y-1">
        <div className="flex justify-between items-center text-[11px]">
          <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-black/10 text-slate-800">
            v{data.version}
          </span>
          <span className="font-bold uppercase tracking-wider text-[10px] opacity-90">
            {data.risk_tier}
          </span>
        </div>

        <div className="text-[11px] truncate flex items-center gap-1 opacity-90" title={data.reachability}>
          <span className="text-slate-500 text-[10px]">Reach:</span>
          <span className="font-medium truncate">{data.reachability}</span>
        </div>

        {data.vuln_count > 0 && (
          <div className="text-[10px] font-bold text-rose-900 bg-rose-100/80 px-1.5 py-0.5 rounded flex items-center justify-between border border-rose-300">
            <span>⚠️ {data.vuln_count} {data.vuln_count === 1 ? "Advisory" : "Advisories"}</span>
            <span className="underline decoration-dotted text-[9px]">Fix Available</span>
          </div>
        )}
      </div>

      <Handle
        type="source"
        position={sourcePosition}
        className="!w-3 !h-3 !bg-slate-600 !border-2 !border-white rounded-full transition-transform hover:scale-125"
      />
    </div>
  );
};

export interface DependencyGraphCanvasProps {
  nodes: Node<GraphNodeSummary>[];
  edges: Edge[];
  onNodesChange?: OnNodesChange<Node<GraphNodeSummary>>;
  onEdgesChange?: OnEdgesChange;
  onSelectPackage?: (node: GraphNodeSummary) => void;
  onToggleCluster?: (clusterId: string) => void;
  onLayoutDirectionChange?: (dir: "TB" | "LR") => void;
  layoutDirection?: "TB" | "LR";
  className?: string;
}

/**
 * DependencyGraphCanvas component wrapping ReactFlow with accessible node rendering,
 * custom minimap colors, drag-and-drop node positioning, and automatic layout.
 */
export const DependencyGraphCanvas: React.FC<DependencyGraphCanvasProps> = ({
  nodes,
  edges,
  onNodesChange,
  onEdgesChange,
  onSelectPackage,
  onToggleCluster,
  onLayoutDirectionChange,
  layoutDirection = "TB",
  className = "w-full h-[600px]",
}) => {
  const nodeTypes: NodeTypes = useMemo(
    () => ({
      accessiblePackage: AccessiblePackageNode,
      default: AccessiblePackageNode,
    }),
    []
  );

  const handleKeyDown = useCallback(
    (event: React.KeyboardEvent<HTMLDivElement>) => {
      if (event.key === "Enter" && onSelectPackage) {
        // If Enter is pressed while a node is selected, trigger selection
        const selected = nodes.find((n) => n.selected);
        if (selected?.data) {
          event.preventDefault();
          onSelectPackage(selected.data);
        }
      }
    },
    [nodes, onSelectPackage]
  );

  return (
    <NodeSelectionContext.Provider value={onSelectPackage}>
      <NodeClusterToggleContext.Provider value={onToggleCluster}>
        <div
          className={`relative ${className}`}
          onKeyDown={handleKeyDown}
          tabIndex={-1}
        >
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            nodeTypes={nodeTypes}
            fitView
            nodesDraggable={true}
            nodesConnectable={false}
            elementsSelectable={true}
            onNodeClick={(_event, node) => {
              if (node.data && onSelectPackage) {
                onSelectPackage(node.data as GraphNodeSummary);
              }
            }}
            aria-label="Software Dependency Risk Graph"
          >
            <Background color="#334155" gap={20} size={1.5} />
            <Controls className="!bg-slate-900 !border-slate-800 !text-slate-200 !shadow-xl [&>button]:!bg-slate-900 [&>button]:!border-slate-800 [&>button]:!text-slate-200 hover:[&>button]:!bg-slate-800" />

            {/* Layout Direction Toggle Panel */}
            {onLayoutDirectionChange && (
              <Panel position="top-right" className="flex items-center gap-1.5 bg-slate-900/90 border border-slate-800 p-1.5 rounded-lg shadow-xl backdrop-blur-sm text-xs">
                <span className="text-slate-400 text-[10px] px-1 font-medium">Layout:</span>
                <button
                  type="button"
                  onClick={() => onLayoutDirectionChange("TB")}
                  className={`px-2 py-1 rounded text-[11px] font-semibold transition-colors ${
                    layoutDirection === "TB"
                      ? "bg-indigo-600 text-white shadow-sm"
                      : "text-slate-300 hover:bg-slate-800"
                  }`}
                  title="Top-to-Bottom Hierarchical Tree"
                >
                  Vertical (TB)
                </button>
                <button
                  type="button"
                  onClick={() => onLayoutDirectionChange("LR")}
                  className={`px-2 py-1 rounded text-[11px] font-semibold transition-colors ${
                    layoutDirection === "LR"
                      ? "bg-indigo-600 text-white shadow-sm"
                      : "text-slate-300 hover:bg-slate-800"
                  }`}
                  title="Left-to-Right Hierarchical Tree"
                >
                  Horizontal (LR)
                </button>
              </Panel>
            )}

            <MiniMap
              className="!bg-slate-900/90 !border !border-slate-800 !rounded-lg !shadow-xl"
              nodeColor={(node) => {
                const summary = node.data as GraphNodeSummary | undefined;
                if (summary?.risk_tier) {
                  return getTierStyling(summary.risk_tier).color;
                }
                return "#64748b";
              }}
              nodeStrokeWidth={2}
              zoomable
              pannable
            />
          </ReactFlow>
        </div>
      </NodeClusterToggleContext.Provider>
    </NodeSelectionContext.Provider>
  );
};
