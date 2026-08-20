/**
 * APT Simulator — Simulation State Store (Zustand)
 * 
 * Central state management for the entire dashboard. All components
 * read from this store and the WebSocket connection writes to it.
 */

import { create } from 'zustand';

// MITRE ATT&CK stages in order
export const ATTACK_STAGES = [
  { id: 'reconnaissance', name: 'Reconnaissance', technique: 'T0846', tactic: 'Discovery', icon: '🔍' },
  { id: 'initial_access', name: 'Initial Access', technique: 'T0859', tactic: 'Initial Access', icon: '🔓' },
  { id: 'persistence', name: 'Persistence', technique: 'T1098', tactic: 'Persistence', icon: '⚓' },
  { id: 'lateral_movement', name: 'Lateral Movement', technique: 'T0886', tactic: 'Lateral Movement', icon: '↔️' },
  { id: 'command_control', name: 'Command & Control', technique: 'T0869', tactic: 'C2', icon: '📡' },
  { id: 'impact', name: 'Impact', technique: 'T0826', tactic: 'Impact', icon: '💥' },
];

const useSimulationStore = create((set, get) => ({
  // ─── Connection State ───────────────────────────────────
  connected: true, // Optimistic default, useWebSocket handles grace period disconnects
  setConnected: (val) => set({ connected: val }),

  // ─── Detection Toggle ──────────────────────────────────
  detectionEnabled: true,
  toggleDetection: () => set((s) => ({ detectionEnabled: !s.detectionEnabled })),
  setDetectionEnabled: (val) => set({ detectionEnabled: val }),

  // ─── Simulation State ──────────────────────────────────
  isRunning: false,
  isPaused: false,
  isDemoMode: false,
  simulationState: 'idle', // 'idle' | 'running' | 'blocked' | 'failed' | 'succeeded'
  setRunning: (val) => set({ isRunning: val }),
  setPaused: (val) => set({ isPaused: val }),
  setDemoMode: (val) => set({ isDemoMode: val }),
  setSimulationState: (val) => set({ simulationState: val }),
  
  // ─── Scrubber State ────────────────────────────────────
  isScrubbing: false,
  scrubIndex: 0,
  setScrubbing: (val) => set({ isScrubbing: val }),
  setScrubIndex: (val) => set({ scrubIndex: val }),

  // ─── Attack Stages ─────────────────────────────────────
  stageStatuses: {},  // { stage_id: 'pending' | 'active' | 'complete' | 'error' }
  setStageStatus: (stageId, status) => set((s) => ({
    stageStatuses: { ...s.stageStatuses, [stageId]: status },
  })),
  resetStages: () => set({ stageStatuses: {} }),

  // ─── Risk Score ────────────────────────────────────────
  riskScore: 0,
  riskHistory: [],
  signals: {},
  hasAlerted: false,
  hasBlocked: false,
  updateRiskScore: (data) => set((s) => {
    if (s.isDemoMode && !data.isLocalDemoUpdate) return s; // Ignore backend risk score updates during local UI demo

    const newRisk = data.risk_score ?? s.riskScore;
    
    // Safety check: Risk score should not change during idle, nor should it decay (unless reset to 0)
    if (newRisk !== s.riskScore) {
      if (s.simulationState === 'idle' && newRisk !== 0) {
        console.warn(`[Risk Consistency] Risk score changed to ${newRisk} during idle state!`);
      }
      if (newRisk < s.riskScore && newRisk !== 0) {
        console.warn(`[Risk Consistency] Risk score improperly decayed from ${s.riskScore} to ${newRisk}.`);
      }
    }

    return {
      riskScore: newRisk,
      signals: data.signals ?? s.signals,
      hasAlerted: data.has_alerted ?? s.hasAlerted,
      hasBlocked: data.has_blocked ?? s.hasBlocked,
      riskHistory: [
        ...s.riskHistory.slice(-200),
        { 
          time: Date.now(), 
          score: newRisk,
          snapshot: {
            simulationState: s.simulationState,
            stageStatuses: { ...s.stageStatuses },
            meterStatuses: { ...s.meterStatuses },
            disconnectedCount: s.disconnectedCount,
            alerts: [...s.alerts],
            signals: data.signals ?? s.signals,
            riskScore: newRisk,
            hasAlerted: data.has_alerted ?? s.hasAlerted,
            hasBlocked: data.has_blocked ?? s.hasBlocked,
          }
        },
      ],
    };
  }),

  // ─── Alerts ────────────────────────────────────────────
  alerts: [],
  addAlert: (alert) => set((s) => ({
    alerts: [...s.alerts, { ...alert, id: Date.now() }],
  })),
  setAlerts: (alerts) => set({ alerts }),
  clearAlerts: () => set({ alerts: [] }),

  // ─── Attack Events ────────────────────────────────────
  attackEvents: [],
  addAttackEvent: (event) => set((s) => ({
    attackEvents: [...s.attackEvents.slice(-100), event],
  })),

  // ─── Meter Statuses ───────────────────────────────────
  // { zone: { total, connected, disconnected } }
  meterStatuses: {},
  updateMeterStatus: (data) => set((s) => {
    if (data.zones) {
      return { meterStatuses: data.zones };
    }
    return s;
  }),
  totalMeters: 500,
  disconnectedCount: 0,
  updateDisconnectedCount: () => {
    const statuses = get().meterStatuses;
    const count = Object.values(statuses).reduce(
      (sum, z) => sum + (z.disconnected || 0), 0
    );
    set({ disconnectedCount: count });
  },

  // ─── Graph Data ────────────────────────────────────────
  graphData: { nodes: [], edges: [] },
  setGraphData: (data) => set({ graphData: data }),

  // ─── Timeline ──────────────────────────────────────────
  timelinePosition: 0,
  setTimelinePosition: (pos) => set({ timelinePosition: pos }),

  reset: () => set({
    isRunning: false,
    isPaused: false,
    isDemoMode: false,
    simulationState: 'idle',
    isScrubbing: false,
    scrubIndex: 0,
    stageStatuses: {},
    riskScore: 0,
    riskHistory: [],
    signals: {},
    hasAlerted: false,
    hasBlocked: false,
    alerts: [],
    attackEvents: [],
    meterStatuses: {},
    disconnectedCount: 0,
    graphData: { nodes: [], edges: [] },
    timelinePosition: 0,
  }),
  // ─── Demo Mode ─────────────────────────────────────────
  triggerDemoMode: () => {
    const state = get();
    state.reset(); // clear existing state
    state.setDemoMode(true);
    state.setRunning(true);
    state.setSimulationState('running');
    
    const stages = ATTACK_STAGES.map(s => s.id);
    let stageIdx = 0;
    // Track which stage is currently active (separate from progression counter)
    // stageIdx points to the NEXT stage to start; activeStageIdx is the one currently running
    let activeStageIdx = -1;
    let blocked = false;

    let currentRisk = 0;
    const riskInterval = setInterval(() => {
      if (blocked) return; // stop updating risk after block
      
      currentRisk += 92 / (12000 / 500); // reach 92 over ~12 seconds; hits 75 at ~t=9.8s (during C2)
      
      // Detection ON: block when score crosses threshold
      if (get().detectionEnabled && currentRisk >= 75) {
        currentRisk = 75;
        blocked = true;
        clearInterval(riskInterval);
        
        // Block the CURRENTLY ACTIVE stage (not the next one)
        const blockedStageIdx = activeStageIdx >= 0 ? activeStageIdx : 0;
        get().setStageStatus(stages[blockedStageIdx], 'blocked');
        get().setSimulationState('blocked');
        set({ hasBlocked: true });
        get().addAlert({
          title: "APT Attack BLOCKED — Automated Response Triggered",
          severity: "critical",
          confidence: 0.75,
          technique_id: ATTACK_STAGES[blockedStageIdx]?.technique || 'T0826',
          message: `Composite risk score (75) exceeded block threshold during ${stages[blockedStageIdx].replace('_', ' ')}. Blocking compromised operator sessions and preventing further meter commands.`,
          timestamp: new Date().toISOString()
        });
        
        // Halt all downstream stages (everything after the blocked one)
        for (let i = blockedStageIdx + 1; i < stages.length; i++) {
           get().setStageStatus(stages[i], 'halted');
        }
      } else if (currentRisk >= 92) {
        currentRisk = 92;
        clearInterval(riskInterval);
      }
      
      // Always push risk score and signals — even with Detection OFF.
      // This enables the "passive monitoring" narrative: the audience sees the
      // score climbing dangerously with nothing in place to act on it.
      get().updateRiskScore({
        isLocalDemoUpdate: true,
        risk_score: Math.round(currentRisk * 100) / 100,
        signals: {
          isolation_forest: currentRisk > 60 ? 80 : Math.min(30, currentRisk),
          graph_anomaly: currentRisk > 50 ? 85 : Math.min(20, currentRisk * 0.5),
          beacon_detection: currentRisk > 70 ? 90 : Math.min(10, currentRisk * 0.3),
          login_anomaly: currentRisk > 40 ? 75 : Math.min(15, currentRisk * 0.4),
          mass_command: currentRisk > 85 ? 95 : Math.min(5, currentRisk * 0.1),
        },
        has_alerted: currentRisk >= 65,
        has_blocked: blocked,
      });
    }, 500);

    const nextStage = () => {
      // Complete previous stage (only if not already blocked/halted)
      if (stageIdx > 0) {
        const prevStatus = get().stageStatuses[stages[stageIdx - 1]];
        if (prevStatus === 'active') {
          get().setStageStatus(stages[stageIdx - 1], 'complete');
        }
      }
      
      // If the simulation was blocked by the risk interval, stop progression
      if (blocked || get().simulationState === 'blocked') return;
      
      if (stageIdx < stages.length) {
        const currentStage = stages[stageIdx];
        activeStageIdx = stageIdx; // Track which stage is actually running
        get().setStageStatus(currentStage, 'active');
        get().addAttackEvent({
          stage: currentStage,
          action: `Executing ${currentStage.replace('_', ' ')} phase...`,
          timestamp: new Date().toISOString()
        });
        
        

        
        if (currentStage === 'impact') {
          const currentZones = get().meterStatuses;
          const newZones = {};
          
          const impactFractions = { A: 0, B: 0.3, C: 0, D: 0.5, E: 0.45, F: 0 };
          const totalMeters = get().totalMeters;
          const zones = ['A', 'B', 'C', 'D', 'E', 'F'];
          
          zones.forEach((zone, idx) => {
            const defaultTotal = Math.floor(totalMeters / 6) + (idx < (totalMeters % 6) ? 1 : 0);
            const total = currentZones[zone]?.total || defaultTotal;
            const disconnected = Math.floor(total * impactFractions[zone]);
            newZones[zone] = {
              total: total,
              connected: total - disconnected,
              disconnected: disconnected
            };
          });

          get().updateMeterStatus({ zones: newZones });
          get().updateDisconnectedCount();
          get().addAlert({
            title: "CRITICAL ATTACK ACTIVE: Power Grid Tripping",
            severity: "critical",
            message: "Mass disconnect command authorized via HES.",
            timestamp: new Date().toISOString()
          });
        }
        
        stageIdx++;
        setTimeout(nextStage, 2500);
      } else {
        // Complete the final stage
        get().setStageStatus('impact', 'complete');
        get().setSimulationState('succeeded');
      }
    };
    
    nextStage();
  },
}));

export default useSimulationStore;
