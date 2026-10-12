
export default function Settings() {
  return (
    <div className="p-4 flex flex-col h-full space-y-4 max-w-3xl">
      <div className="pane-header">[ SYSTEM CONFIGURATION ]</div>
      
      <div className="pane">
        <div className="p-4 space-y-6">
          
          <div className="space-y-2">
            <div className="text-dim text-[10px] uppercase tracking-wider">Engine Mode</div>
            <div className="flex items-center space-x-4">
              <label className="flex items-center space-x-2 cursor-pointer">
                <input type="radio" name="mode" className="accent-accent" defaultChecked />
                <span>Passive Monitoring (Promiscuous)</span>
              </label>
              <label className="flex items-center space-x-2 cursor-pointer opacity-50">
                <input type="radio" name="mode" disabled />
                <span className="line-through">Active Mitigation</span>
              </label>
            </div>
            <p className="text-dim text-[10px]">Note: Active mitigation is permanently disabled at the kernel level for prototype compliance.</p>
          </div>

          <div className="space-y-2">
            <div className="text-dim text-[10px] uppercase tracking-wider">Thresholds</div>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="text-dim text-[10px] mb-1 block">Critical Alert Confidence</label>
                <input type="text" className="bg-base border border-border px-2 py-1 text-xs w-full focus:border-accent outline-none" defaultValue="0.95" />
              </div>
              <div>
                <label className="text-dim text-[10px] mb-1 block">High Alert Confidence</label>
                <input type="text" className="bg-base border border-border px-2 py-1 text-xs w-full focus:border-accent outline-none" defaultValue="0.80" />
              </div>
            </div>
          </div>

          <div className="space-y-2">
            <div className="text-dim text-[10px] uppercase tracking-wider">Storage</div>
            <div className="flex items-center space-x-2">
              <input type="checkbox" defaultChecked className="accent-accent" />
              <span>Retain full PCAP for CRITICAL alerts</span>
            </div>
            <div className="flex items-center space-x-2">
              <input type="checkbox" defaultChecked className="accent-accent" />
              <span>Forward telemetry to upstream SIEM</span>
            </div>
          </div>
          
          <div className="pt-4 border-t border-border flex justify-end">
            <button className="px-4 py-1.5 bg-accent text-base text-xs uppercase font-bold tracking-wider hover:bg-accent/80">Apply Config</button>
          </div>

        </div>
      </div>
    </div>
  )
}
