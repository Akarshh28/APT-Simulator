/**
 * APT Simulator — WebSocket Hook
 * 
 * Manages WebSocket connections to the backend services:
 * - Detection engine (port 8003) for alerts and risk scores
 * - HES (port 8001) for live telemetry and meter status
 * 
 * Automatically reconnects on disconnect.
 */

import { useEffect, useRef, useCallback } from 'react';
import useSimulationStore from '../store/simulationStore';

const DETECTOR_WS_URL = 'ws://localhost:8003/ws/alerts';
const HES_WS_URL = 'ws://localhost:8001/ws/live';
const RECONNECT_DELAY = 3000;

export function useWebSocket() {
  const detectorWs = useRef(null);
  const hesWs = useRef(null);
  const reconnectTimer = useRef(null);

  const store = useSimulationStore();

  const connectDetector = useCallback(() => {
    if (detectorWs.current?.readyState === WebSocket.OPEN) return;

    try {
      const ws = new WebSocket(DETECTOR_WS_URL);

      ws.onopen = () => {
        console.log('[WS] Detector connected');
        store.setConnected(true);
      };

      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          handleDetectorMessage(msg);
        } catch (e) {
          console.error('[WS] Parse error:', e);
        }
      };

      ws.onclose = () => {
        console.log('[WS] Detector disconnected');
        // Grace period before showing disconnected
        setTimeout(() => {
          if (detectorWs.current?.readyState !== WebSocket.OPEN) {
            store.setConnected(false);
          }
        }, 4000);
        reconnectTimer.current = setTimeout(connectDetector, RECONNECT_DELAY);
      };

      ws.onerror = (e) => {
        console.error('[WS] Detector error:', e);
      };

      detectorWs.current = ws;
    } catch (e) {
      console.error('[WS] Connection failed:', e);
      setTimeout(() => {
        if (detectorWs.current?.readyState !== WebSocket.OPEN) {
          store.setConnected(false);
        }
      }, 4000);
      reconnectTimer.current = setTimeout(connectDetector, RECONNECT_DELAY);
    }
  }, []);

  const connectHES = useCallback(() => {
    if (hesWs.current?.readyState === WebSocket.OPEN) return;

    try {
      const ws = new WebSocket(HES_WS_URL);

      ws.onopen = () => {
        console.log('[WS] HES connected');
      };

      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          handleHESMessage(msg);
        } catch (e) { /* ignore parse errors from HES */ }
      };

      ws.onclose = () => {
        setTimeout(connectHES, RECONNECT_DELAY);
      };

      hesWs.current = ws;
    } catch (e) {
      setTimeout(connectHES, RECONNECT_DELAY);
    }
  }, []);

  // Message handlers
  const handleDetectorMessage = useCallback((msg) => {
    if (useSimulationStore.getState().isDemoMode) return;
    const { type, payload } = msg;

    switch (type) {
      case 'risk_score':
        useSimulationStore.getState().updateRiskScore(payload);
        break;

      case 'alert':
        useSimulationStore.getState().addAlert(payload);
        break;

      case 'attack_event':
        useSimulationStore.getState().addAttackEvent(payload);
        break;

      case 'attack_stage':
        useSimulationStore.getState().setStageStatus(payload.stage, payload.status);
        if (payload.status === 'active') {
          useSimulationStore.getState().setRunning(true);
          useSimulationStore.getState().setSimulationState('running');
        }
        break;

      case 'simulation_state':
        useSimulationStore.getState().setSimulationState(payload.state);
        if (payload.scenario_metadata) {
          useSimulationStore.getState().setScenarioMetadata(payload.scenario_metadata);
        }
        break;

      case 'system':
        if (payload.event === 'connected') {
          useSimulationStore.getState().setDetectionEnabled(payload.detection_enabled ?? true);
          if (payload.alerts) {
            useSimulationStore.getState().setAlerts(payload.alerts);
          }
          if (payload.scenario_metadata) {
            useSimulationStore.getState().setScenarioMetadata(payload.scenario_metadata);
          }
        }
        break;
    }
  }, []);

  const handleHESMessage = useCallback((msg) => {
    if (useSimulationStore.getState().isDemoMode) return;
    const { type, payload } = msg;

    switch (type) {
      case 'meter_status':
        if (payload.zones || payload.event === 'mass_disconnect') {
          useSimulationStore.getState().updateMeterStatus(payload);
          useSimulationStore.getState().updateDisconnectedCount();
        }
        break;

      case 'telemetry':
        useSimulationStore.getState().updateMeterTelemetry(payload);
        break;
      case 'meter_event':
        useSimulationStore.getState().addMeterEvent(payload);
        break;

      case 'system':
        if (payload.fleet) {
          useSimulationStore.getState().updateMeterStatus(payload.fleet);
        }
        break;
    }
  }, []);

  // Send messages
  const sendToDetector = useCallback((message) => {
    if (detectorWs.current?.readyState === WebSocket.OPEN) {
      detectorWs.current.send(JSON.stringify(message));
    }
  }, []);

  // Connect on mount
  useEffect(() => {
    connectDetector();
    connectHES();

    return () => {
      clearTimeout(reconnectTimer.current);
      detectorWs.current?.close();
      hesWs.current?.close();
    };
  }, [connectDetector, connectHES]);

  return { sendToDetector };
}

export default useWebSocket;
