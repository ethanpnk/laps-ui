# LAPS-UI.ps1 - WPF Dark, PS 5.1 (STA)
# LDAP by default, optional LDAPS, modern dark UI, 20s countdown
# "LAPS password" field is read-only + reliable green message at the end of the countdown
# + Checkboxes "Remember user" and "Remember controller/domain" (local persistence %LOCALAPPDATA%\LAPS-UI\prefs.json)

# --- Config ---
$UseLdaps = $false
$ClipboardAutoClearSeconds = 20
$CurrentVersion = '1.0.3'

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
Add-Type -AssemblyName System.DirectoryServices
Add-Type -AssemblyName System.Runtime.WindowsRuntime -ErrorAction SilentlyContinue | Out-Null

# ---------- Helpers LDAP ----------
function Convert-FileTime { param([object]$Value)
  if (-not $Value) { return $null }
  try { [DateTime]::FromFileTimeUtc([int64]$Value).ToLocalTime() } catch { $null } }

function Escape-LdapFilterValue { param([string]$Value)
  if ($null -eq $Value) { return "" }
  $sb = New-Object System.Text.StringBuilder
  foreach ($ch in $Value.ToCharArray()) {
    switch ($ch) {
      '(' { $sb.Append('\28') | Out-Null }
      ')' { $sb.Append('\29') | Out-Null }
      '*' { $sb.Append('\2a') | Out-Null }
      '\' { $sb.Append('\5c') | Out-Null }
      ([char]0) { $sb.Append('\00') | Out-Null }
      default { $sb.Append($ch) | Out-Null }
    } }
  $sb.ToString() }

function Get-PropValueCI { param($Props,[string]$Name)
  foreach ($n in $Props.PropertyNames) { if ($n -ieq $Name) { return $Props[$n] } }
  $null }

function Get-FirstValue { param($v)
  if ($null -eq $v) { return $null }
  if ($v -is [System.DirectoryServices.ResultPropertyValueCollection]) { if ($v.Count -gt 0) { return $v[0] } else { return $null } }
  if ($v -is [System.Collections.IList]) { if ($v.Count -gt 0) { return $v[0] } else { return $null } }
  if ($v -is [object[]]) { if ($v.Length -gt 0) { return $v[0] } else { return $null } }
  return $v }

function New-DirectoryEntry {
  param([string]$Path,[System.Management.Automation.PSCredential]$Credential,[System.DirectoryServices.AuthenticationTypes]$Auth)
  if (-not $Auth) {
    $Auth = [System.DirectoryServices.AuthenticationTypes]::Secure -bor `
            [System.DirectoryServices.AuthenticationTypes]::Signing -bor `
            [System.DirectoryServices.AuthenticationTypes]::Sealing }
  if ($Credential) {
    $pwd = $Credential.GetNetworkCredential().Password
    New-Object System.DirectoryServices.DirectoryEntry($Path, $Credential.UserName, $pwd, $Auth)
  } else {
    New-Object System.DirectoryServices.DirectoryEntry($Path, $null, $null, $Auth) } }

function Get-DirectorySearcher {
  param([System.Management.Automation.PSCredential]$Credential,[string]$ServerOrDomain)
  if ($PSBoundParameters.ContainsKey('ServerOrDomain')) {
    if ([string]::IsNullOrWhiteSpace($ServerOrDomain)) { $ServerOrDomain = $null } else { $ServerOrDomain = $ServerOrDomain.Trim() } }

  $authBase  = [System.DirectoryServices.AuthenticationTypes]::Secure -bor `
               [System.DirectoryServices.AuthenticationTypes]::Signing -bor `
               [System.DirectoryServices.AuthenticationTypes]::Sealing
  $authLdaps = $authBase -bor [System.DirectoryServices.AuthenticationTypes]::SecureSocketsLayer
  $useLdapsNow = ($script:UseLdaps -and $ServerOrDomain)

  $rootPath = if ($ServerOrDomain) { if ($useLdapsNow) { "LDAP://$ServerOrDomain:636/RootDSE" } else { "LDAP://$ServerOrDomain/RootDSE" } } else { "LDAP://RootDSE" }
  $root = New-DirectoryEntry -Path $rootPath -Credential $Credential -Auth ($(if ($useLdapsNow){$authLdaps}else{$authBase}))
  try { [void]$root.RefreshCache() } catch {
    throw "Failed to bind to AD (RootDSE) on '$rootPath': $($_.Exception.Message)`n- If LDAPS is checked, verify the cert/port 636, or uncheck to test in signed LDAP." }

  $defaultNC = Get-FirstValue $root.Properties["defaultNamingContext"]
  if ([string]::IsNullOrWhiteSpace($defaultNC)) { throw "Unable to determine the 'defaultNamingContext' via RootDSE." }

  $searchRootPath = if ($ServerOrDomain) { if ($useLdapsNow) { "LDAP://$ServerOrDomain:636/$defaultNC" } else { "LDAP://$ServerOrDomain/$defaultNC" } } else { "LDAP://$defaultNC" }
  $searchRoot = New-DirectoryEntry -Path $searchRootPath -Credential $Credential -Auth ($(if ($useLdapsNow){$authLdaps}else{$authBase}))

  $ds = New-Object System.DirectoryServices.DirectorySearcher($searchRoot)
  $ds.PageSize = 1; $ds.CacheResults = $true
  $ds.ClientTimeout = [TimeSpan]::FromSeconds(20)
  $ds.ServerTimeLimit = [TimeSpan]::FromSeconds(20)
  $null = $ds.PropertiesToLoad.AddRange(@(
      'distinguishedName','cn','dNSHostName','sAMAccountName',
      'msLAPS-Password','msLAPS-PasswordExpirationTime',
      'ms-Mcs-AdmPwd','ms-Mcs-AdmPwdExpirationTime'))
  $ds }

function Normalize-ComputerName { param([string]$InputName)
  if ([string]::IsNullOrWhiteSpace($InputName)) { return "" }
  $name = $InputName.Trim()
  if ($name -like "*@*") { $name = $name.Split("@")[0] }
  if ($name -like "*.*") { $name = $name.Split(".")[0] }
  if ($name.EndsWith('$')) { $name = $name.Substring(0,$name.Length-1) }
  $name }

function Find-ComputerEntry { param([System.DirectoryServices.DirectorySearcher]$Searcher,[string]$ComputerName)
  $raw = if ($ComputerName) { $ComputerName } else { "" }
  $name = Normalize-ComputerName -InputName $raw
  if ([string]::IsNullOrWhiteSpace($name)) { throw "Please enter a computer name." }
  $v = Escape-LdapFilterValue $name
  $Searcher.Filter = "(&(objectCategory=computer)(|(sAMAccountName=$v$)(cn=$v)(dNSHostName=$v)))"
  $Searcher.FindOne() }

function Parse-WindowsLapsJson { param([string]$JsonText)
  if ([string]::IsNullOrWhiteSpace($JsonText)) { return $null }
  try {
    $obj = $JsonText | ConvertFrom-Json
    $pwd = $obj.p; if (-not $pwd) { $pwd = $obj.P }; if (-not $pwd) { $pwd = $obj.password }; if (-not $pwd) { $pwd = $obj.Password }; if (-not $pwd) { $pwd = $obj.clearText }
    $acct= $obj.n; if (-not $acct){ $acct= $obj.N }; if (-not $acct){ $acct= $obj.account }; if (-not $acct){ $acct= $obj.Account }
    $t   = $obj.t; if (-not $t)   { $t   = $obj.T }; if (-not $t)   { $t   = $obj.expirationTimestamp }
    $exp = $null; if ($t) { try { $exp = ([DateTime]::Parse($t)).ToLocalTime() } catch { $exp = $null } }
    [pscustomobject]@{ Password=$pwd; Account=$acct; Expiration=$exp }
  } catch { [pscustomobject]@{ Password=$JsonText; Account=$null; Expiration=$null } } }

function Get-LapsPasswordFromEntry { param($Result)
  if (-not $Result) { return $null }
  $props = $Result.Properties
  $dn    = Get-FirstValue (Get-PropValueCI $props 'distinguishedName')

  $lapsRaw = Get-FirstValue (Get-PropValueCI $props 'msLAPS-Password')
  if ($lapsRaw) {
    $json = if ($lapsRaw -is [byte[]]) { [System.Text.Encoding]::UTF8.GetString($lapsRaw) } else { [string]$lapsRaw }
    $parsed = Parse-WindowsLapsJson -JsonText $json
    $expFT  = Get-FirstValue (Get-PropValueCI $props 'msLAPS-PasswordExpirationTime')
    $exp    = if ($parsed -and $parsed.Expiration) { $parsed.Expiration } elseif ($expFT) { Convert-FileTime $expFT } else { $null }
    if ($parsed -and $parsed.Password) {
      return [pscustomobject]@{ Type='Windows LAPS'; Password=[string]$parsed.Password; Account=$parsed.Account; Expires=$exp; DN=[string]$dn } } }

  $legacyPwd = Get-FirstValue (Get-PropValueCI $props 'ms-Mcs-AdmPwd')
  if ($legacyPwd) {
    $expFT = Get-FirstValue (Get-PropValueCI $props 'ms-Mcs-AdmPwdExpirationTime')
    $exp   = if ($expFT) { Convert-FileTime $expFT } else { $null }
    return [pscustomobject]@{ Type='Legacy LAPS'; Password=[string]$legacyPwd; Account=$null; Expires=$exp; DN=[string]$dn } }

  $null }

# ---------- Update helpers ----------

function Check-ForUpdates {
  param([string]$CurrentVersion)
  $uri = 'https://api.github.com/repos/ethanpnk/laps-ui/releases/latest'
  try {
    $release = Invoke-RestMethod -Uri $uri -Headers @{ 'User-Agent' = 'LAPS-UI' } -ErrorAction Stop
  } catch {
    Write-Verbose "Update check failed: $_"
    return $null
  }
  $latest = $release.tag_name.TrimStart('v')
  if ([version]$latest -le [version]$CurrentVersion) { return $null }
  if ($script:Prefs.IgnoreVersion -eq $latest) { return $null }
  $asset = $release.assets | Where-Object { $_.name -eq 'LAPS-UI.exe' } | Select-Object -First 1
  if (-not $asset) { return $null }
  $sha256 = $null
  if ($release.body -match 'SHA256[:\s]+(?<hash>[A-Fa-f0-9]{64})') { $sha256 = $Matches['hash'] }
  [pscustomobject]@{ Version=$latest; Url=$asset.browser_download_url; Sha256=$sha256 }
}

function Start-AppUpdate {
  param($Info, $Window)
  try {
    $tmp = Join-Path ([IO.Path]::GetTempPath()) "LAPS-UI-$($Info.Version).exe"
    Invoke-WebRequest -Uri $Info.Url -OutFile $tmp -UseBasicParsing
    if ($Info.Sha256) {
      $h = (Get-FileHash -Path $tmp -Algorithm SHA256).Hash
      if ($h -ne $Info.Sha256) { throw "SHA256 mismatch" }
    }
    $exe = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    $script = @"
Start-Sleep -Seconds 1
Copy-Item -Path '$tmp' -Destination '$exe' -Force
Start-Process -FilePath '$exe'
"@
    $ps = Join-Path ([IO.Path]::GetTempPath()) 'laps-ui-update.ps1'
    Set-Content -Path $ps -Value $script -Encoding UTF8
    Start-Process -FilePath 'powershell' -ArgumentList '-ExecutionPolicy Bypass','-File', $ps -Verb RunAs
    $Window.Close()
  } catch {
    [System.Windows.MessageBox]::Show("Update failed: $($_.Exception.Message)", 'Update', 'OK', 'Error') | Out-Null
  }
}

# ---------- XAML (Dark) ----------
[xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="LAPS UI (Windows &amp; Legacy) - v1.0.3"
        Height="640" Width="1000" MinHeight="640" MinWidth="1000"
        WindowStartupLocation="CenterScreen"
        Background="#1E1E1E" Foreground="#EEEEEE" FontFamily="Segoe UI" FontSize="13">
  <Window.Resources>
    <Style x:Key="AccentButton" TargetType="Button">
      <Setter Property="Background" Value="#0A84FF"/>
      <Setter Property="Foreground" Value="White"/>
      <Setter Property="FontSize"   Value="14"/>
      <Setter Property="MinHeight"  Value="36"/>
      <Setter Property="MinWidth"   Value="110"/>
      <Setter Property="Padding"    Value="16,10"/>
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="HorizontalAlignment" Value="Right"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border Background="{TemplateBinding Background}"
                    CornerRadius="6" Padding="{TemplateBinding Padding}">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
      <Style.Triggers>
        <Trigger Property="IsMouseOver" Value="True">
          <Setter Property="Background" Value="#0C60C0"/>
        </Trigger>
        <Trigger Property="IsEnabled" Value="False">
          <Setter Property="Opacity" Value="0.5"/>
        </Trigger>
      </Style.Triggers>
    </Style>

    <Style TargetType="TextBox">
      <Setter Property="Background" Value="#2D2D2D"/>
      <Setter Property="Foreground" Value="#EEEEEE"/>
      <Setter Property="BorderBrush" Value="#3E3E42"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Padding" Value="8,6"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="TextBox">
            <Border Background="{TemplateBinding Background}"
                    BorderBrush="{TemplateBinding BorderBrush}"
                    BorderThickness="{TemplateBinding BorderThickness}"
                    CornerRadius="4">
              <ScrollViewer x:Name="PART_ContentHost"/>
            </Border>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style TargetType="PasswordBox">
      <Setter Property="Background" Value="#2D2D2D"/>
      <Setter Property="Foreground" Value="#EEEEEE"/>
      <Setter Property="BorderBrush" Value="#3E3E42"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Padding" Value="8,6"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="PasswordBox">
            <Border Background="{TemplateBinding Background}"
                    BorderBrush="{TemplateBinding BorderBrush}"
                    BorderThickness="{TemplateBinding BorderThickness}"
                    CornerRadius="4">
              <ScrollViewer x:Name="PART_ContentHost"/>
            </Border>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style TargetType="GroupBox">
      <Setter Property="Foreground" Value="#E0E0E0"/>
      <Setter Property="BorderBrush" Value="#3E3E42"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Padding" Value="12"/>
      <Setter Property="Margin" Value="0,0,0,14"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="{x:Type GroupBox}">
            <Border CornerRadius="8"
                    Background="#252526"
                    BorderBrush="{TemplateBinding BorderBrush}"
                    BorderThickness="{TemplateBinding BorderThickness}"
                    Margin="0,8,0,0">
              <Border.Effect>
                <DropShadowEffect Color="#000000" BlurRadius="10" ShadowDepth="2" Opacity="0.4"/>
              </Border.Effect>
              <DockPanel LastChildFill="True">
                <Border DockPanel.Dock="Top" Background="#2B2B2B" Padding="8,4" CornerRadius="8,8,0,0">
                  <TextBlock Text="{TemplateBinding Header}" FontWeight="SemiBold" Foreground="#BEBEBE"/>
                </Border>
                <ContentPresenter Margin="{TemplateBinding Padding}"/>
              </DockPanel>
            </Border>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style TargetType="CheckBox">
      <Setter Property="Foreground" Value="#E0E0E0"/>
      <Setter Property="Margin" Value="0,4,0,0"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="CheckBox">
            <StackPanel Orientation="Horizontal">
              <Border x:Name="box" Width="16" Height="16" CornerRadius="3"
                      Background="#2D2D2D" BorderBrush="#3E3E42" BorderThickness="1" Margin="0,0,8,0">
                <Path x:Name="check" Data="M2,8 L6,12 L14,4" Stroke="White" StrokeThickness="2" Visibility="Collapsed"/>
              </Border>
              <ContentPresenter VerticalAlignment="Center"/>
            </StackPanel>
            <ControlTemplate.Triggers>
              <Trigger Property="IsChecked" Value="True">
                <Setter TargetName="box" Property="Background" Value="#0A84FF"/>
                <Setter TargetName="check" Property="Visibility" Value="Visible"/>
              </Trigger>
              <Trigger Property="IsEnabled" Value="False">
                <Setter TargetName="box" Property="Opacity" Value="0.5"/>
                <Setter Property="Foreground" Value="#888"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
  </Window.Resources>

  <ScrollViewer VerticalScrollBarVisibility="Auto">
    <Grid Margin="16">
      <Grid.RowDefinitions>
        <RowDefinition Height="Auto"/>
        <RowDefinition Height="Auto"/>
        <RowDefinition Height="Auto"/>
        <RowDefinition Height="Auto"/>
        <RowDefinition Height="Auto"/>
      </Grid.RowDefinitions>

      <!-- Top forms: credentials & AD target side by side -->
      <Grid Grid.Row="0" Margin="0,0,0,14">
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="*"/>
          <ColumnDefinition Width="*"/>
        </Grid.ColumnDefinitions>

        <!-- Credentials -->
        <GroupBox Grid.Column="0" Header="Credentials" Margin="0,0,8,14">
          <Grid>
            <Grid.ColumnDefinitions>
              <ColumnDefinition Width="Auto"/>
              <ColumnDefinition Width="*"/>
            </Grid.ColumnDefinitions>
            <Grid.RowDefinitions>
              <RowDefinition Height="Auto"/>
              <RowDefinition Height="Auto"/>
              <RowDefinition Height="Auto"/>
            </Grid.RowDefinitions>

            <TextBlock Grid.Row="0" Grid.Column="0" Text="User (user@domain)" Margin="0,0,12,0" VerticalAlignment="Center" Foreground="#BEBEBE"/>
            <TextBox   Grid.Row="0" Grid.Column="1" x:Name="tbUser"/>

            <TextBlock  Grid.Row="1" Grid.Column="0" Text="Password" Margin="0,8,12,0" VerticalAlignment="Center" Foreground="#BEBEBE"/>
            <PasswordBox Grid.Row="1" Grid.Column="1" x:Name="pbPass" Margin="0,8,0,0"/>

            <CheckBox Grid.Row="2" Grid.Column="1" x:Name="cbRememberUser" Content="Remember user" Margin="0,8,0,0"/>
          </Grid>
        </GroupBox>

        <!-- AD Target -->
        <GroupBox Grid.Column="1" Header="Active Directory Target" Margin="8,0,0,14">
          <Grid>
            <Grid.ColumnDefinitions>
              <ColumnDefinition Width="Auto"/>
              <ColumnDefinition Width="*"/>
              <ColumnDefinition Width="Auto"/>
            </Grid.ColumnDefinitions>
            <Grid.RowDefinitions>
              <RowDefinition Height="Auto"/>
              <RowDefinition Height="Auto"/>
            </Grid.RowDefinitions>
            <TextBlock Grid.Row="0" Grid.Column="0" VerticalAlignment="Center" Text="Controller/Domain" Margin="0,0,12,0" Foreground="#BEBEBE"/>
            <TextBox   Grid.Row="0" Grid.Column="1" x:Name="tbServer" Text=""/>
            <CheckBox  Grid.Row="0" Grid.Column="2" x:Name="cbLdaps" Content="Use LDAPS (TLS 636)" Margin="12,0,0,0" VerticalAlignment="Center"/>
            <CheckBox  Grid.Row="1" Grid.Column="1" Grid.ColumnSpan="2" x:Name="cbRememberServer" Content="Remember controller/domain" Margin="0,8,0,0"/>
          </Grid>
        </GroupBox>
      </Grid>

      <!-- Search -->
      <GroupBox Grid.Row="1" Header="Search">
        <Grid>
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="Auto"/>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="Auto"/>
          </Grid.ColumnDefinitions>
          <TextBlock Grid.Column="0" VerticalAlignment="Center" Text="Computer name" Margin="0,0,12,0" Foreground="#BEBEBE"/>
          <TextBox   Grid.Column="1" x:Name="tbComp"/>
          <Button    Grid.Column="2" x:Name="btnGet" Content="Retrieve" Style="{StaticResource AccentButton}"
                     IsDefault="True" Margin="12,0,0,0"/>
        </Grid>
      </GroupBox>

      <!-- Details -->
      <GroupBox Grid.Row="2" Header="Details">
        <TextBox x:Name="txtDetails" Height="80" AcceptsReturn="True" IsReadOnly="True"
                 VerticalScrollBarVisibility="Auto" FontFamily="Consolas" FontSize="12"/>
      </GroupBox>

      <!-- Password -->
      <GroupBox Grid.Row="3" Header="LAPS Password">
        <Grid>
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="Auto"/>
            <ColumnDefinition Width="Auto"/>
          </Grid.ColumnDefinitions>
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
          </Grid.RowDefinitions>

          <TextBox     Grid.Row="0" Grid.Column="0" x:Name="txtPwdOut"
                       FontFamily="Consolas" FontSize="20"
                       Visibility="Collapsed" IsReadOnly="True" Focusable="False"/>
          <PasswordBox Grid.Row="0" Grid.Column="0" x:Name="pbPwdOut"
                       FontFamily="Consolas" FontSize="20"
                       IsHitTestVisible="False" Focusable="False"/>

          <CheckBox Grid.Row="0" Grid.Column="1" x:Name="cbShow" Content="Show"
                    Margin="12,6,12,0" VerticalAlignment="Center"/>
          <Button   Grid.Row="0" Grid.Column="2" x:Name="btnCopy" Content="Copy"
                    Style="{StaticResource AccentButton}" IsEnabled="False"/>

          <TextBlock Grid.Row="1" Grid.Column="0" x:Name="lblCountdown"
                     Margin="0,8,0,0" Foreground="#FFA07A" Visibility="Collapsed"/>
        </Grid>
      </GroupBox>

      <StackPanel Grid.Row="4" Orientation="Horizontal">
        <Button x:Name="btnUpdate" Content="Update" Style="{StaticResource AccentButton}" Visibility="Collapsed"/>
        <Button x:Name="btnIgnore" Content="Ignore" Style="{StaticResource AccentButton}" Margin="8,0,0,0" Visibility="Collapsed"/>
      </StackPanel>

      </Grid>
  </ScrollViewer>
</Window>
"@

# ---------- Build UI ----------
$reader = (New-Object System.Xml.XmlNodeReader $xaml)
$window = [Windows.Markup.XamlReader]::Load($reader)

# Controls
$tbUser         = $window.FindName("tbUser")
$pbPass         = $window.FindName("pbPass")
$tbServer       = $window.FindName("tbServer")
$cbLdaps        = $window.FindName("cbLdaps")
$tbComp         = $window.FindName("tbComp")
$btnGet         = $window.FindName("btnGet")
$txtDetails     = $window.FindName("txtDetails")
$txtPwdOut      = $window.FindName("txtPwdOut")
$pbPwdOut       = $window.FindName("pbPwdOut")
$cbShow         = $window.FindName("cbShow")
$btnCopy        = $window.FindName("btnCopy")
$lblCountdown   = $window.FindName("lblCountdown")
$cbRememberUser = $window.FindName("cbRememberUser")
$cbRememberServer = $window.FindName("cbRememberServer")
$btnUpdate     = $window.FindName("btnUpdate")
$btnIgnore     = $window.FindName("btnIgnore")

# Init
$cbLdaps.IsChecked = $UseLdaps
$script:UseLdaps   = [bool]$cbLdaps.IsChecked
$script:CurrentLapsPassword = ""
$script:DoneTimer = $null

# --- Preferences (only the user and the controller, never the password; DPAPI-encrypted values) ---
$PrefDir  = Join-Path $env:LOCALAPPDATA 'LAPS-UI'
$PrefFile = Join-Path $PrefDir 'prefs.json'
New-Item -Path $PrefDir -ItemType Directory -Force | Out-Null
$script:Prefs = @{}

function Protect-String {
  param([string]$Text)
  if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
  $sec = ConvertTo-SecureString $Text -AsPlainText -Force
  ConvertFrom-SecureString $sec
}

function Unprotect-String {
  param([string]$Cipher)
  if ([string]::IsNullOrWhiteSpace($Cipher)) { return $null }
  try {
    $sec = ConvertTo-SecureString $Cipher
    [Runtime.InteropServices.Marshal]::PtrToStringUni(
      [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
    )
  } catch { $Cipher }
}

function Save-Prefs {
  $script:Prefs = @{
    RememberUser  = [bool]$cbRememberUser.IsChecked
    UserName      = $(if ($cbRememberUser.IsChecked) { Protect-String $tbUser.Text } else { $null })
    RememberServer = [bool]$cbRememberServer.IsChecked
    ServerName      = $(if ($cbRememberServer.IsChecked) { Protect-String $tbServer.Text } else { $null })
    IgnoreVersion   = $script:Prefs.IgnoreVersion
  }
  ($script:Prefs | ConvertTo-Json -Compress) | Set-Content -Path $PrefFile -Encoding UTF8
}

function Load-Prefs {
  $script:Prefs = @{}
  if (Test-Path $PrefFile) {
    try {
      $script:Prefs = Get-Content $PrefFile -Raw | ConvertFrom-Json
      if ($script:Prefs.RememberUser) {
        $cbRememberUser.IsChecked = $true
        if ($script:Prefs.UserName) { $tbUser.Text = Unprotect-String $script:Prefs.UserName }
      }
      if ($script:Prefs.RememberServer) {
        $cbRememberServer.IsChecked = $true
        if ($script:Prefs.ServerName) { $tbServer.Text = Unprotect-String $script:Prefs.ServerName }
      }
    } catch { $script:Prefs = @{} }
  }
}
Load-Prefs
$cbRememberUser.Add_Checked({ Save-Prefs })
$cbRememberUser.Add_Unchecked({ Save-Prefs })
$tbUser.Add_LostFocus({ if ($cbRememberUser.IsChecked) { Save-Prefs } })
$cbRememberServer.Add_Checked({ Save-Prefs })
$cbRememberServer.Add_Unchecked({ Save-Prefs })
$tbServer.Add_LostFocus({ if ($cbRememberServer.IsChecked) { Save-Prefs } })
$window.Add_Closed({ Save-Prefs })

$cbLdaps.Add_Checked({   $script:UseLdaps = $true  })
$cbLdaps.Add_Unchecked({ $script:UseLdaps = $false })

$updateInfo = Check-ForUpdates -CurrentVersion $CurrentVersion
if ($updateInfo) {
  $btnUpdate.Content = "Update to v$($updateInfo.Version)"
  $btnUpdate.Visibility = 'Visible'
  $btnIgnore.Visibility = 'Visible'
  $btnUpdate.Add_Click({ Start-AppUpdate -Info $updateInfo -Window $window })
  $btnIgnore.Add_Click({
    $script:Prefs.IgnoreVersion = $updateInfo.Version
    Save-Prefs
    $btnUpdate.Visibility = 'Collapsed'
    $btnIgnore.Visibility = 'Collapsed'
  })
}

# Show/Hide output
$cbShow.Add_Checked({
  $txtPwdOut.Text = $script:CurrentLapsPassword
  $txtPwdOut.Visibility = 'Visible'
  $pbPwdOut.Visibility  = 'Collapsed'
})
$cbShow.Add_Unchecked({
  $pbPwdOut.Password = $script:CurrentLapsPassword
  $pbPwdOut.Visibility  = 'Visible'
  $txtPwdOut.Visibility = 'Collapsed'
})

# Countdown timer
$script:CountdownRemaining = 0
$timer = New-Object System.Windows.Threading.DispatcherTimer
$timer.Interval = [TimeSpan]::FromSeconds(1)
$timer.Add_Tick({
  if ($script:CountdownRemaining -gt 0) {
    $script:CountdownRemaining--
    $lblCountdown.Text = "Clipboard cleared in $($script:CountdownRemaining)s"
    if ($script:CountdownRemaining -le 0) {
      try {
        if ([System.Windows.Clipboard]::ContainsText()) {
          $txt = [System.Windows.Clipboard]::GetText()
          if (($txt) -and ($txt -eq $script:CurrentLapsPassword)) {
            [System.Windows.Clipboard]::Clear()
          }
        }
      } catch {}
      $timer.Stop()
      $lblCountdown.Text = "Clipboard cleared"
      $lblCountdown.Foreground = 'LimeGreen'
      $script:DoneTimer = New-Object System.Windows.Threading.DispatcherTimer
      $script:DoneTimer.Interval = [TimeSpan]::FromSeconds(2)
      $script:DoneTimer.Add_Tick({
        param($sender,$e)
        $sender.Stop()
        $lblCountdown.Visibility = 'Collapsed'
        $lblCountdown.Foreground = '#FFA07A'
      })
      $script:DoneTimer.Start()
    }
  } else {
    $timer.Stop()
    $lblCountdown.Visibility = 'Collapsed'
  }
})

# COPY (best effort without Win+V)
$btnCopy.Add_Click({
  if ([string]::IsNullOrWhiteSpace($script:CurrentLapsPassword)) { return }

  $usedWinRT = $false
  $winRtSupported = $false
  try {
    $winRtSupported = [Windows.Foundation.Metadata.ApiInformation]::IsMethodPresent(
      "Windows.ApplicationModel.DataTransfer.Clipboard", "SetContentWithOptions"
    )
  } catch {}

  if ($winRtSupported) {
    try {
      $dp = New-Object Windows.ApplicationModel.DataTransfer.DataPackage
      $dp.RequestedOperation = [Windows.ApplicationModel.DataTransfer.DataPackageOperation]::Copy
      $dp.SetText($script:CurrentLapsPassword)

      $opt = New-Object Windows.ApplicationModel.DataTransfer.ClipboardContentOptions
      $opt.IsAllowedInHistory = $false
      $opt.IsRoamingEnabled   = $false

      [Windows.ApplicationModel.DataTransfer.Clipboard]::SetContentWithOptions($dp, $opt)
      [Windows.ApplicationModel.DataTransfer.Clipboard]::Flush()
      $usedWinRT = $true
    } catch { $usedWinRT = $false }
  }

  if (-not $usedWinRT) {
    [System.Windows.Clipboard]::SetText($script:CurrentLapsPassword)
  }

  [System.Windows.MessageBox]::Show(
    ("Password copied {0} clipboard history." -f ($(if($usedWinRT){'without entering'}else{'into'}))),
    "Copied",'OK','Information') | Out-Null

  $script:CountdownRemaining = $ClipboardAutoClearSeconds
  $lblCountdown.Text = "Clipboard cleared in $($script:CountdownRemaining)s"
  $lblCountdown.Foreground = '#FFA07A'
  $lblCountdown.Visibility = 'Visible'
  $timer.Stop(); $timer.Start()
})

# Retrieve
$btnGet.Add_Click({
  try {
    $btnGet.IsEnabled = $false
    $window.Cursor = 'Wait'

    $cred = $null
    if (-not [string]::IsNullOrWhiteSpace($tbUser.Text)) {
      if ([string]::IsNullOrWhiteSpace($pbPass.Password)) {
        throw "You entered a username without a password."
      }
      $secure = ConvertTo-SecureString -String $pbPass.Password -AsPlainText -Force
      $cred = New-Object System.Management.Automation.PSCredential ($tbUser.Text, $secure)
      if ($cbRememberUser.IsChecked -or $cbRememberServer.IsChecked) { Save-Prefs } # in case the user or server changes now
    }

    $ds  = Get-DirectorySearcher -Credential $cred -ServerOrDomain $tbServer.Text
    $res = Find-ComputerEntry -Searcher $ds -ComputerName $tbComp.Text
    if (-not $res) { throw "Computer not found in AD (check spelling or OU)." }

    $item = Get-LapsPasswordFromEntry -Result $res
    if ($item -and $item.Password) {
      $script:CurrentLapsPassword = [string]$item.Password
      $pbPwdOut.Password = $script:CurrentLapsPassword
      $txtPwdOut.Text    = $script:CurrentLapsPassword
      $btnCopy.IsEnabled = $true

      $lines = @()
      $lines += ("Type       : {0}" -f $item.Type)
      if ($item.Account) { $lines += ("Compte     : {0}" -f $item.Account) }
      if ($item.Expires) { $lines += ("Expiration : {0}" -f $item.Expires) }
      if ($item.DN)      { $lines += ("DN         : {0}" -f $item.DN) }
      $txtDetails.Text = ($lines -join [Environment]::NewLine)
    } else {
      $dn = Get-FirstValue (Get-PropValueCI $res.Properties 'distinguishedName')
      $txtDetails.Text = "No readable LAPS attribute on this computer.`r`nDN: $dn`r`n- LAPS not applied`r`n- No read permission`r`n- Rotation not yet performed."
      $script:CurrentLapsPassword = ""
      $pbPwdOut.Password = ""
      $txtPwdOut.Text = ""
      $btnCopy.IsEnabled = $false
    }
  } catch {
    $txtDetails.Text = "Error: $($_.Exception.Message)"
  } finally {
    $window.Cursor = 'Arrow'
    $btnGet.IsEnabled = $true
  }
})

# Enter -> Retrieve
$tbComp.Add_KeyDown({ if ($_.Key -eq 'Return') { $btnGet.RaiseEvent((New-Object System.Windows.RoutedEventArgs([Windows.Controls.Button]::ClickEvent))) } })

[void]$window.ShowDialog()
