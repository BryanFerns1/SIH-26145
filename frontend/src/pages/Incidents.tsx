
// Fake incident data for the prototype
const INCIDENTS = [
  {
    id: 'INC-20261004-8991',
    severity: 'CRITICAL',
    title: 'Multi-stage Ransomware Precursor',
    status: 'ACTIVE',
    target: '10.2.4.17',
    start_time: '2026-10-04T13:40:02Z',
    kill_chain: [
      { phase: 'Initial Access', technique: 'T1190', desc: 'Exploit Public-Facing App', time: '13:40:02Z', status: 'CONFIRMED' },
      { phase: 'Execution', technique: 'T1059', desc: 'Command and Scripting', time: '13:45:11Z', status: 'CONFIRMED' },
      { phase: 'Persistence', technique: 'T1543', desc: 'Create or Modify System Process', time: '13:48:20Z', status: 'SUSPECTED' },
      { phase: 'Privilege Escalation', technique: 'T1068', desc: 'Exploitation for Privilege Escalation', time: '14:01:05Z', status: 'BLOCKED' },
      { phase: 'C2', technique: 'T1071', desc: 'Application Layer Protocol', time: '--', status: 'PENDING' },
    ]
  },
  {
    id: 'INC-20261004-8982',
    severity: 'HIGH',
    title: 'Automated Portscan to SSH Brute Force',
    status: 'CONTAINED',
    target: '192.168.1.55',
    start_time: '2026-10-04T10:15:00Z',
    kill_chain: [
      { phase: 'Discovery', technique: 'T1046', desc: 'Network Service Scanning', time: '10:15:00Z', status: 'CONFIRMED' },
      { phase: 'Credential Access', technique: 'T1110', desc: 'Brute Force', time: '10:22:15Z', status: 'CONFIRMED' },
    ]
  }
]

export default function Incidents() {
  return (
    <div className="p-4 flex flex-col h-full space-y-4">
      <div className="pane-header flex justify-between">
        <span>[ ACTIVE INCIDENTS ]</span>
        <span className="text-dim">AUTO-CORRELATED EVENT SEQUENCES</span>
      </div>

      <div className="flex-1 overflow-y-auto space-y-6 pb-8">
        {INCIDENTS.map((inc, i) => (
          <div key={i} className="pane flex flex-col">
            <div className="pane-header flex justify-between">
              <span className="font-mono text-text">{inc.id} | {inc.title}</span>
              <span className={inc.status === 'ACTIVE' ? 'text-critical' : 'text-accent'}>{inc.status}</span>
            </div>
            
            <div className="p-4">
              <div className="flex justify-between text-[10px] text-dim font-mono mb-8 uppercase tracking-wider">
                <div>TARGET: {inc.target}</div>
                <div>T0: {inc.start_time}</div>
              </div>

              {/* Kill Chain Timeline */}
              <div className="relative flex justify-between items-start pt-2">
                {/* Connecting Line */}
                <div className="absolute top-4 left-4 right-4 h-[1px] bg-border z-0" />
                
                {inc.kill_chain.map((step, j) => (
                  <div key={j} className="flex flex-col items-center w-32 z-10 relative">
                    <div className={`w-3 h-3 mb-3 border ${
                      step.status === 'CONFIRMED' ? 'bg-critical border-critical' :
                      step.status === 'SUSPECTED' ? 'bg-medium border-medium' :
                      step.status === 'BLOCKED' ? 'bg-accent border-accent' :
                      'bg-panel border-dim'
                    }`} />
                    
                    <div className="text-center font-mono">
                      <div className="text-text font-bold text-[11px] mb-1 leading-tight">{step.phase}</div>
                      <div className="text-accent text-[10px] mb-1">{step.technique}</div>
                      <div className="text-dim text-[10px] leading-tight px-2">{step.desc}</div>
                      <div className="text-dim text-[10px] mt-2 bg-base px-1 inline-block border border-border">{step.time}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
