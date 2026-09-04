export const scenarios = {
  credential_intrusion: {
    id: 'credential_intrusion',
    name: 'Credential Intrusion (Default)',
    description: 'External attacker phishes operator1, standard pacing',
    narrative: 'An external threat actor successfully spear-phishes operator1, gaining initial access to the IT network before moving laterally into the OT environment to disrupt smart grid operations.',
    entryZone: 'External',
    compromisedIdentity: 'operator1',
    stages: ['reconnaissance', 'initial_access', 'persistence', 'lateral_movement', 'command_control', 'impact'],
    baseDelay: 3000,
    signalEmphasis: {
      isolation_forest: 'high',
      graph_anomaly: 'medium',
      beacon_detection: 'high',
      login_anomaly: 'high',
      mass_command: 'high'
    },
    stageEvents: {
      reconnaissance: 'External scanning and enumeration of remote access portals.',
      initial_access: 'Successful spear-phishing payload execution. Credential theft of operator1.',
      persistence: 'Establishing backdoor access using compromised credentials.',
      lateral_movement: 'Pivoting from IT network to OT environment (HES/MDMS).',
      command_control: 'Deploying C2 beaconing payload for persistent external command.',
      impact: 'Mass disconnect commands authorized via HES.'
    }
  },
  insider_threat: {
    id: 'insider_threat',
    name: 'Insider Threat',
    description: 'Skips Recon/Initial Access, rogue field tech starts at Persistence',
    narrative: 'A disgruntled field technician with existing physical and network access deploys persistence mechanisms directly, bypassing initial access controls to sabotage operations.',
    entryZone: 'Internal/OT',
    compromisedIdentity: 'admin',
    stages: ['persistence', 'lateral_movement', 'command_control', 'impact'],
    baseDelay: 3000,
    signalEmphasis: {
      isolation_forest: 'medium',
      graph_anomaly: 'high',
      beacon_detection: 'low',
      login_anomaly: 'low', // Crucial: legitimate login
      mass_command: 'high'
    },
    stageEvents: {
      persistence: 'Rogue scheduled task installed on OT management server by authenticated insider.',
      lateral_movement: 'Internal mapping and unauthorized lateral access from rogue device to MDMS.',
      command_control: 'Setting up internal proxy/beacon for automated sabotage scripts.',
      impact: 'Mass disconnect commands authorized via HES.'
    }
  },
  slow_burn_apt: {
    id: 'slow_burn_apt',
    name: 'Slow-Burn APT',
    description: 'Full kill-chain, long delays, low-intensity signals rising gradually',
    narrative: 'A sophisticated state-sponsored actor executes a slow and low campaign over months, deliberately pacing actions to evade volumetric detections and threshold-based alerts.',
    entryZone: 'External',
    compromisedIdentity: 'field_tech',
    stages: ['reconnaissance', 'initial_access', 'persistence', 'lateral_movement', 'command_control', 'impact'],
    baseDelay: 10000, // Very slow pacing
    signalEmphasis: {
      isolation_forest: 'low',
      graph_anomaly: 'low',
      beacon_detection: 'medium',
      login_anomaly: 'low',
      mass_command: 'high'
    },
    stageEvents: {
      reconnaissance: 'Low-and-slow credential stuffing to evade lockout thresholds.',
      initial_access: 'Stealthy initial payload drop masking as legitimate software update.',
      persistence: 'Deep persistence established via subtle registry modifications over days.',
      lateral_movement: 'Periodic, stealthy lateral movement queries mimicking administrative behavior.',
      command_control: 'Intermittent beaconing with high jitter to avoid pattern detection.',
      impact: 'Gradual mass disconnect using small batches to avoid sudden spikes.'
    }
  },
  false_positive: {
    id: 'false_positive',
    name: 'False Positive (Normal Ops)',
    description: 'No attacker kill-chain runs, benign anomaly event only',
    narrative: 'A misconfigured automated maintenance script triggers unusual login patterns, but no malicious payload or C2 activity is present. Risk score remains safely below the blocking threshold.',
    entryZone: 'IT',
    compromisedIdentity: 'maintenance_svc',
    stages: [], // No attacker kill-chain runs
    baseDelay: 2500,
    signalEmphasis: {
      isolation_forest: 'low',
      graph_anomaly: 'low',
      beacon_detection: 'none',
      login_anomaly: 'medium',
      mass_command: 'none'
    },
    stageEvents: {}
  }
};
