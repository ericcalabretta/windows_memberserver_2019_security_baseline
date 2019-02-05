registry_key 'Configure SMB v1 client driver' do
  key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MrxSmb10'
  values [{ name: 'Start', type: :dword, data: '4' },
  ]
  recursive true
  action :create
end

registry_key 'Configure SMB v1 server' do
  key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
  values [{ name: 'SMB1', type: :dword, data: '0' },
  ]
  recursive true
  action :create
end

registry_key 'Enable Structured Exception Handling Overwrite Protection (SEHOP)' do
  key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel'
  values [{ name: 'DisableExceptionChainValidation', type: :dword, data: '0' },
  ]
  recursive true
  action :create
end

registry_key 'Encryption Oracle Remediation' do
  key 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters'
  values [{ name: 'AllowEncryptionOracle', type: :dword, data: '0' },
  ]
  recursive true
  action :create
end

registry_key 'Remote host allows delegation of non-exportable credentials' do
  key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CredentialsDelegation'
  values [{ name: 'AllowProtectedCreds', type: :dword, data: '1' },
  ]
  recursive true
  action :create
end

registry_key 'Turn On Virtualization Based Security' do
  key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
  values [{ name: 'ConfigureSystemGuardLaunch', type: :dword, data: '1' },
          { name: 'HVCIMATRequired', type: :dword, data: '0' },
]
  recursive true
  action :create
end

registry_key 'Enumeration policy for external devices incompatible with Kernel DMA Protection' do
  key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Kernel DMA Protection'
  values [{ name: 'DeviceEnumerationPolicy', type: :dword, data: '0' },
  ]
  recursive true
  action :create
end

registry_key 'Turn off encryption support' do
  key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
  values [{ name: 'SecureProtocols', type: :dword, data: '2560' },
  ]
  recursive true
  action :create
end

registry_key 'Allow font downloads & Allow VBScript to run in Internet Explorer' do
  key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
  values [{ name: '1604', type: :dword, data: '0' },
         { name: '140C', type: :dword, data: '0' },
  ]
  recursive true
  action :create
end

registry_key 'Allow font downloads & Allow VBScript to run in Internet Explorer #2' do
  key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
  values [{ name: '1604', type: :dword, data: '0' },
         { name: '140C', type: :dword, data: '0' },
  ]
  recursive true
  action :create
end

registry_key 'Configure detection for potentially unwanted applications & Turn off Windows Defender Antivirus' do
  key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender'
  values [{ name: 'PUAProtection', type: :dword, data: '1' },
         { name: 'DisableAntiSpyware', type: :dword, data: '0' },
  ]
  recursive true
  action :create
end

registry_key 'Configure Attack Surface Reduction rules #1' do
  key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR'
  values [{ name: 'ExploitGuard_ASR_Rules', type: :dword, data: '1' },
  ]
  recursive true
  action :create
end

registry_key 'Configure Attack Surface Reduction rules' do
  key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
  values [{ name: '26190899-1602-49e8-8b27-eb1d0a1ce869', type: :string, data: '1' },
         { name: '3b576869-a4ec-4529-8536-b80a7769e899', type: :string, data: '1' },
         { name: '5beb7efe-fd9a-4556-801d-275e5ffc04cc', type: :string, data: '1' },
         { name: '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84', type: :string, data: '1' },
         { name: '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c', type: :string, data: '1' },
         { name: '92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B', type: :string, data: '1' },
         { name: '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2', type: :string, data: '1' },
         { name: 'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4', type: :string, data: '1' },
         { name: 'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550', type: :string, data: '1' },
         { name: 'd3e037e1-3eb8-44c8-a917-57927947596d', type: :string, data: '1' },
         { name: 'd3e037e1-3eb8-44c8-a917-57927947596d', type: :string, data: '1' },
  ]
  recursive true
  action :create
end

registry_key 'Prevent users and apps from accessing dangerous websites' do
  key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection'
  values [{ name: 'EnableNetworkProtection', type: :dword, data: '1' },
  ]
  recursive true
  action :create
end

registry_key 'Allow Windows Ink Workspace' do
  key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsInkWorkspace'
  values [{ name: 'AllowWindowsInkWorkspace', type: :dword, data: '1' },
  ]
  recursive true
  action :create
end

registry_key 'Configure Windows Defender SmartScreen' do
  key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System'
  values [{ name: 'ShellSmartScreenLevel', type: :string, data: 'Block' },
  ]
  recursive true
  action :create
end