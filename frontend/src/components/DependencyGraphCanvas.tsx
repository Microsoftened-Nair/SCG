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
        className={`px-4 py-2.5 rounded-lg border-dashed border-2 border-emerald-600 bg-emerald-50 text-emerald-950 font-semibold text-xs tracking-wide shadow-sm hover:bg-emerald-100 focus:outline-none focus:ring-2 focus:ring-emerald-500 cursor-pointer transition-all select-none ${dimClass}`}
        onClick={handleClick}
        onKeyDown={handleKeyDown}
      >
        <Handle
          type="target"
          position={Position.Top}
          className="w-2.5 h-2.5 bg-emerald-700 border-2 border-white"
        />
        <div className="flex items-center gap-1.5">
          <span aria-hidden="true">{isExpanded ? "📂" : "🛡️"}</span>
          <span>{clusterAriaLabel}</span>
          <span className="text-[10px] text-emerald-800 ml-1 underline decoration-dotted">
            {isExpanded ? "(click to collapse)" : "(click to expand)"}
          </span>
        </div>
        <Handle
          type="source"
          position={Position.Bottom}
          className="w-2.5 h-2.5 bg-emerald-700 border-2 border-white"
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
      className={`relative min-w-[200px] max-w-[260px] p-3 rounded-lg shadow-md transition-all cursor-pointer focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 ${styling.border} ${pulseClass} ${dimClass}`}
      onClick={handleClick}
      onKeyDown={handleKeyDown}
    >
      <Handle
        type="target"
        position={Position.Top}
        className="w-2.5 h-2.5 bg-slate-600 border-2 border-white"
      />

      <div className="flex items-start justify-between gap-2 mb-1.5">
        <div className="flex items-center gap-1.5 overflow-hidden">
          <span className="text-base select-none" aria-hidden="true">
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
          className={`shrink-0 px-2 py-0.5 rounded text-xs font-bold tracking-tight shadow-sm ${styling.badge}`}
          aria-label={`Score ${data.composite_score}`}
        >
          {data.composite_score}
        </span>
      </div>

      <div className="text-xs space-y-0.5 opacity-90">
        <div className="flex justify-between items-center text-[11px]">
          <span className="font-medium text-slate-600">v{data.version}</span>
          <span className="font-semibold uppercase tracking-wider text-[10px]">
            {data.risk_tier}
          </span>
        </div>
        <div className="text-[11px] truncate text-slate-700">
          Reachability: <span className="font-medium">{data.reachability}</span>
        </div>
        {data.vuln_count > 0 && (
          <div className="text-[11px] font-semibold text-rose-800">
            {data.vuln_count} {data.vuln_count === 1 ? "Vulnerability" : "Vulnerabilities"}
          </div>
        )}
      </div>

      <Handle
        type="source"
        position={Position.Bottom}
        className="w-2.5 h-2.5 bg-slate-600 border-2 border-white"
      />
    </div>
  );
};

export interface DependencyGraphCanvasProps {
  nodes: Node<GraphNodeSummary>[];
  edges: Edge[];
  onSelectPackage?: (node: GraphNodeSummary) => void;
  onToggleCluster?: (clusterId: string) => void;
  className?: string;
}

/**
 * DependencyGraphCanvas component wrapping ReactFlow with accessible node rendering,
 * custom minimap colors, and keyboard accessibility.
 */
export const DependencyGraphCanvas: React.FC<DependencyGraphCanvasProps> = ({
  nodes,
  edges,
  onSelectPackage,
  onToggleCluster,
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
            nodeTypes={nodeTypes}
            fitView
            onNodeClick={(_event, node) => {
              if (node.data && onSelectPackage) {
                onSelectPackage(node.data as GraphNodeSummary);
              }
            }}
            aria-label="Software Dependency Risk Graph"
          >
            <Background color="#94a3b8" gap={16} />
            <Controls />
            <MiniMap
              nodeColor={(node) => {
                const summary = node.data as GraphNodeSummary | undefined;
                if (summary?.risk_tier) {
                  return getTierStyling(summary.risk_tier).color;
                }
                return "#64748b";
              }}
              nodeStrokeWidth={3}
              zoomable
              pannable
            />
          </ReactFlow>
        </div>
      </NodeClusterToggleContext.Provider>
    </NodeSelectionContext.Provider>
  );
};
