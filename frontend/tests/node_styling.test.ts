/**
 * Vitest test suite for node styling and accessibility verification (UI-TC-01).
 *
 * Conforms to IEEE Std 830-1998, RFC 2119, and SCG-SRS-PHASE-8 (REQ-P8-02, REQ-P8-03).
 * Verifies:
 * - Pure mapping from backend RiskTier to multi-channel styling tokens.
 * - Absence of client-side risk score recalculation / arithmetic.
 * - Rendering of AccessiblePackageNode, aggregate clusters, ARIA attributes, and keyboard selection.
 */

import { describe, it, expect, vi } from "vitest";
import React from "react";
import { render, screen, fireEvent } from "@testing-library/react";
import { NodeProps, Node, ReactFlowProvider } from "@xyflow/react";

import {
  getTierStyling,
  AccessiblePackageNode,
  DependencyGraphCanvas,
  NodeSelectionContext,
  NodeClusterToggleContext,
} from "../src/components/DependencyGraphCanvas";
import { GraphNodeSummary, RiskTier } from "../src/types/api.gen";

describe("UI-TC-01: Node Styling Pure Mapping Verification", () => {
  it("maps CRITICAL tier directly to double rose border, badge, and stop icon", () => {
    const styling = getTierStyling("CRITICAL");
    expect(styling.border).toBe(
      "border-double border-4 border-rose-600 bg-rose-50 text-rose-950"
    );
    expect(styling.badge).toBe("bg-rose-700 text-white");
    expect(styling.icon).toBe("🛑");
    expect(styling.color).toBe("#e11d48");
  });

  it("maps HIGH tier directly to double rose border, badge, and stop icon", () => {
    const styling = getTierStyling("HIGH");
    expect(styling.border).toBe(
      "border-double border-4 border-rose-600 bg-rose-50 text-rose-950"
    );
    expect(styling.badge).toBe("bg-rose-700 text-white");
    expect(styling.icon).toBe("🛑");
    expect(styling.color).toBe("#e11d48");
  });

  it("maps MODERATE tier directly to dashed amber border, badge, and warning icon", () => {
    const styling = getTierStyling("MODERATE");
    expect(styling.border).toBe(
      "border-dashed border-2 border-amber-600 bg-amber-50 text-amber-950"
    );
    expect(styling.badge).toBe("bg-amber-600 text-white");
    expect(styling.icon).toBe("⚠️");
    expect(styling.color).toBe("#d97706");
  });

  it("maps CLEAN tier directly to solid emerald border, badge, and shield icon", () => {
    const styling = getTierStyling("CLEAN");
    expect(styling.border).toBe(
      "border-solid border-2 border-emerald-600 bg-emerald-50 text-emerald-950"
    );
    expect(styling.badge).toBe("bg-emerald-700 text-white");
    expect(styling.icon).toBe("🛡️");
    expect(styling.color).toBe("#059669");
  });

  it("maps LOW tier directly to solid emerald border, badge, and shield icon", () => {
    const styling = getTierStyling("LOW");
    expect(styling.border).toBe(
      "border-solid border-2 border-emerald-600 bg-emerald-50 text-emerald-950"
    );
    expect(styling.badge).toBe("bg-emerald-700 text-white");
    expect(styling.icon).toBe("🛡️");
    expect(styling.color).toBe("#059669");
  });

  it("executes zero client-side arithmetic or score re-computation", () => {
    // Spying on global Math functions to guarantee purity
    const mathSpyFloor = vi.spyOn(Math, "floor");
    const mathSpyRound = vi.spyOn(Math, "round");
    const mathSpyCeil = vi.spyOn(Math, "ceil");

    const tiers: RiskTier[] = ["CRITICAL", "HIGH", "MODERATE", "LOW", "CLEAN"];
    tiers.forEach((tier) => {
      const res = getTierStyling(tier);
      expect(res).toBeDefined();
    });

    expect(mathSpyFloor).not.toHaveBeenCalled();
    expect(mathSpyRound).not.toHaveBeenCalled();
    expect(mathSpyCeil).not.toHaveBeenCalled();

    mathSpyFloor.mockRestore();
    mathSpyRound.mockRestore();
    mathSpyCeil.mockRestore();
  });
});

describe("UI-TC-02: AccessiblePackageNode WCAG AA Accessibility Verification", () => {
  const baseNodeData: GraphNodeSummary = {
    purl: "pkg:npm/lodash@4.17.21",
    package_name: "lodash",
    version: "4.17.21",
    depth: 1,
    composite_score: 92.5,
    risk_tier: "CLEAN",
    risk_reason: "Verified clean, no known vulnerabilities",
    should_emphasize: false,
    vuln_count: 0,
    reachability: "DIRECT_IMPORTED",
  };

  const createMockNodeProps = (
    data: GraphNodeSummary,
    id = "test-node"
  ): NodeProps<Node<GraphNodeSummary>> => ({
    id,
    data,
    type: "accessiblePackage",
    selected: false,
    selectable: true,
    deletable: true,
    draggable: true,
    zIndex: 1,
    isConnectable: true,
    positionAbsoluteX: 0,
    positionAbsoluteY: 0,
    dragging: false,
  });

  it("renders collapsed aggregate cluster with '+ N Clean Dependencies' aria-label", () => {
    const clusterData: GraphNodeSummary = {
      ...baseNodeData,
      is_aggregate_cluster: true,
      aggregated_count: 14,
    };

    render(
      React.createElement(
        ReactFlowProvider,
        null,
        React.createElement(
          AccessiblePackageNode,
          createMockNodeProps(clusterData, "cluster-1")
        )
      )
    );

    const clusterButton = screen.getByRole("button", {
      name: "+ 14 Clean Dependencies",
    });
    expect(clusterButton).toBeDefined();
    expect(clusterButton.getAttribute("tabIndex")).toBe("0");
    expect(clusterButton.className).toContain("border-dashed");
    expect(clusterButton.textContent).toContain("+ 14 Clean Dependencies");
  });

  it("renders high-contrast numeric score badge as text and multi-channel indicators", () => {
    const criticalNodeData: GraphNodeSummary = {
      ...baseNodeData,
      package_name: "log4j-core",
      version: "2.14.1",
      composite_score: 12.0,
      risk_tier: "CRITICAL",
      vuln_count: 2,
      should_emphasize: true,
    };

    render(
      React.createElement(
        ReactFlowProvider,
        null,
        React.createElement(
          AccessiblePackageNode,
          createMockNodeProps(criticalNodeData, "node-critical")
        )
      )
    );

    const nodeButton = screen.getByRole("button");
    expect(nodeButton.getAttribute("tabIndex")).toBe("0");
    expect(nodeButton.getAttribute("aria-label")).toContain("log4j-core v2.14.1");
    expect(nodeButton.getAttribute("aria-label")).toContain("Risk: CRITICAL");
    expect(nodeButton.getAttribute("aria-label")).toContain("Score: 12");

    // Border styling
    expect(nodeButton.className).toContain("border-double");
    expect(nodeButton.className).toContain("border-rose-600");

    // Motion-safe pulse animation conditional on should_emphasize
    expect(nodeButton.className).toContain("motion-safe:animate-pulse");

    // Score badge text
    const scoreBadge = screen.getByLabelText("Score 12");
    expect(scoreBadge).toBeDefined();
    expect(scoreBadge.textContent).toBe("12");
    expect(scoreBadge.className).toContain("bg-rose-700");
    expect(scoreBadge.className).toContain("text-white");
  });

  it("does not apply pulse animation when should_emphasize is false", () => {
    render(
      React.createElement(
        ReactFlowProvider,
        null,
        React.createElement(
          AccessiblePackageNode,
          createMockNodeProps(baseNodeData, "node-clean")
        )
      )
    );

    const nodeButton = screen.getByRole("button");
    expect(nodeButton.className).not.toContain("motion-safe:animate-pulse");
  });

  it("supports keyboard selection via Enter and click interaction", () => {
    const onSelect = vi.fn();

    render(
      React.createElement(
        ReactFlowProvider,
        null,
        React.createElement(
          NodeSelectionContext.Provider,
          { value: onSelect },
          React.createElement(
            AccessiblePackageNode,
            createMockNodeProps(baseNodeData, "node-keyboard")
          )
        )
      )
    );

    const nodeButton = screen.getByRole("button");

    // Keyboard trigger: Enter
    fireEvent.keyDown(nodeButton, { key: "Enter" });
    expect(onSelect).toHaveBeenCalledTimes(1);
    expect(onSelect).toHaveBeenCalledWith(baseNodeData);

    // Mouse trigger: Click
    fireEvent.click(nodeButton);
    expect(onSelect).toHaveBeenCalledTimes(2);
  });

  it("triggers onToggleCluster when aggregate cluster is clicked", () => {
    const onToggle = vi.fn();
    const clusterData: GraphNodeSummary = {
      ...baseNodeData,
      is_aggregate_cluster: true,
      aggregated_count: 8,
    };

    render(
      React.createElement(
        ReactFlowProvider,
        null,
        React.createElement(
          NodeClusterToggleContext.Provider,
          { value: onToggle },
          React.createElement(
            AccessiblePackageNode,
            createMockNodeProps(clusterData, "cluster-toggle-test")
          )
        )
      )
    );

    const clusterButton = screen.getByRole("button", { name: /\+ 8 Clean Dependencies/ });
    fireEvent.click(clusterButton);
    expect(onToggle).toHaveBeenCalledTimes(1);
    expect(onToggle).toHaveBeenCalledWith("cluster-toggle-test");
  });

  it("applies dimmed style when is_dimmed is true", () => {
    const dimmedData: GraphNodeSummary = {
      ...baseNodeData,
      is_dimmed: true,
    };

    render(
      React.createElement(
        ReactFlowProvider,
        null,
        React.createElement(
          AccessiblePackageNode,
          createMockNodeProps(dimmedData, "node-dimmed")
        )
      )
    );

    const nodeButton = screen.getByRole("button");
    expect(nodeButton.className).toContain("opacity-25");
  });
});

describe("UI-TC-03: DependencyGraphCanvas Canvas Component Verification", () => {
  const sampleNode: Node<GraphNodeSummary> = {
    id: "pkg-1",
    type: "accessiblePackage",
    position: { x: 100, y: 100 },
    selected: true,
    data: {
      purl: "pkg:npm/express@4.18.2",
      package_name: "express",
      version: "4.18.2",
      depth: 0,
      composite_score: 85.0,
      risk_tier: "LOW",
      risk_reason: "Low risk dependency",
      should_emphasize: false,
      vuln_count: 0,
      reachability: "DIRECT_IMPORTED",
    },
  };

  it("renders DependencyGraphCanvas with accessible wrapper and triggers selection on Enter", () => {
    // Mock ResizeObserver for jsdom
    global.ResizeObserver = class ResizeObserver {
      observe() {}
      unobserve() {}
      disconnect() {}
    };

    const onSelect = vi.fn();
    const { container } = render(
      React.createElement(DependencyGraphCanvas, {
        nodes: [sampleNode],
        edges: [],
        onSelectPackage: onSelect,
      })
    );

    const canvasRoot = container.firstChild as HTMLElement;
    expect(canvasRoot).toBeDefined();

    // Trigger Enter key on canvas container with selected node
    fireEvent.keyDown(canvasRoot, { key: "Enter" });
    expect(onSelect).toHaveBeenCalledTimes(1);
    expect(onSelect).toHaveBeenCalledWith(sampleNode.data);
  });
});
