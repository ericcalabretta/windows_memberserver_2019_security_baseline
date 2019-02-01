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
