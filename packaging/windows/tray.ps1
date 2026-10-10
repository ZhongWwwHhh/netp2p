Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$icon = New-Object System.Windows.Forms.NotifyIcon
$icon.Icon = [System.Drawing.SystemIcons]::Application
$icon.Text = "NetP2P"
$icon.Visible = $true

$menu = New-Object System.Windows.Forms.ContextMenuStrip
[void]$menu.Items.Add("Status", $null, { & "$PSScriptRoot\netp2p.exe" status })
[void]$menu.Items.Add("Up", $null, { & "$PSScriptRoot\netp2p.exe" up })
[void]$menu.Items.Add("Down", $null, { & "$PSScriptRoot\netp2p.exe" down })
[void]$menu.Items.Add("Doctor", $null, { & "$PSScriptRoot\netp2p.exe" doctor })
[void]$menu.Items.Add("-")
[void]$menu.Items.Add("Exit", $null, {
  $icon.Visible = $false
  $menu.Dispose()
  [System.Environment]::Exit(0)
})
$icon.ContextMenuStrip = $menu

while ($true) {
  Start-Sleep -Milliseconds 200
}
