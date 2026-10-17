import dagre from "dagre";
import { Node, Edge, Position } from "@xyflow/react";
import { GraphNodeSummary } from "../types/api.gen";

export interface LayoutOptions {
  direction?: "TB" | "LR";
  nodeWidth?: number;
  nodeHeight?: number;
  nodeSep?: number;
  rankSep?: number;
}

const DEFAULT_NODE_WIDTH = 260;
const DEFAULT_NODE_HEIGHT = 115;
const CLUSTER_NODE_WIDTH = 240;
const CLUSTER_NODE_HEIGHT = 50;

/**
 * Computes deterministic, non-overlapping hierarchical tree coordinates
 * using Dagre layout algorithm.
 */
export function getLayoutedElements(
  nodes: Node<GraphNodeSummary>[],
  edges: Edge[],
  options: LayoutOptions = {}
): { nodes: Node<GraphNodeSummary>[]; edges: Edge[] } {
  const direction = options.direction || "TB";
  const isHorizontal = direction === "LR";

  const dagreGraph = new dagre.graphlib.Graph();
  dagreGraph.setDefaultEdgeLabel(() => ({}));

  dagreGraph.setGraph({
    rankdir: direction,
    nodesep: options.nodeSep ?? 60,
    ranksep: options.rankSep ?? 90,
    marginx: 40,
    marginy: 40,
  });

  // Register nodes with their actual dimensions
  nodes.forEach((node) => {
    const isCluster = Boolean(node.data?.is_aggregate_cluster);
    const width = isCluster ? CLUSTER_NODE_WIDTH : (options.nodeWidth ?? DEFAULT_NODE_WIDTH);
    const height = isCluster ? CLUSTER_NODE_HEIGHT : (options.nodeHeight ?? DEFAULT_NODE_HEIGHT);

    dagreGraph.setNode(node.id, { width, height });
  });

  // Register edges
  edges.forEach((edge) => {
    dagreGraph.setEdge(edge.source, edge.target);
  });

  // Execute Dagre layout
  dagre.layout(dagreGraph);

  // Map computed coordinates back to nodes
  const layoutedNodes: Node<GraphNodeSummary>[] = nodes.map((node) => {
    const nodeWithPosition = dagreGraph.node(node.id);
    const isCluster = Boolean(node.data?.is_aggregate_cluster);
    const width = isCluster ? CLUSTER_NODE_WIDTH : (options.nodeWidth ?? DEFAULT_NODE_WIDTH);
    const height = isCluster ? CLUSTER_NODE_HEIGHT : (options.nodeHeight ?? DEFAULT_NODE_HEIGHT);

    // Dagre uses node center as (x, y), whereas React Flow uses top-left corner
    const x = nodeWithPosition.x - width / 2;
    const y = nodeWithPosition.y - height / 2;

    return {
      ...node,
      targetPosition: isHorizontal ? Position.Left : Position.Top,
      sourcePosition: isHorizontal ? Position.Right : Position.Bottom,
      position: { x, y },
      style: {
        width,
        height,
      },
    };
  });

  return { nodes: layoutedNodes, edges };
}
