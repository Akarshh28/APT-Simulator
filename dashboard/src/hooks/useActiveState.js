import useSimulationStore from '../store/simulationStore';
import { useMemo } from 'react';

/**
 * Custom hook to get the active UI state.
 * If the user is currently scrubbing the timeline, it returns the snapshot
 * of the state at that point in time. Otherwise, it returns the live state.
 */
export default function useActiveState() {
  const s = useSimulationStore(state => state);
  
  return useMemo(() => {
    if (s.isScrubbing && s.riskHistory[s.scrubIndex]?.snapshot) {
      return {
        ...s,
        ...s.riskHistory[s.scrubIndex].snapshot
      };
    }
    return s;
  }, [s]);
}
