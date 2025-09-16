param(
  [int]$LockoutResetSeconds = 60
)

# LAPS-UI.ps1 - WPF Dark, PS 5.1 (STA)
# LDAP by default, optional LDAPS, modern dark UI, 20s countdown
# Read-only "LAPS password" field + reliable green "cleared" message
# Remember user & controller/domain (local JSON), update checker
# NEW: Cascadia Code font, expiration indicator, autocomplete & colorized password

# --- Config ---
$UseLdaps = $false
$script:ClipboardAutoClearSeconds = 20
$script:LockoutResetSeconds = $LockoutResetSeconds
$CurrentVersion = '1.0.6'
$script:LockoutTimer = $null
$script:MaxAuthAttempts = 3
$script:FailedAuthCount = 0

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
Add-Type -AssemblyName System.DirectoryServices
Add-Type -AssemblyName System.DirectoryServices.AccountManagement
Add-Type -AssemblyName System.Runtime.WindowsRuntime -ErrorAction SilentlyContinue | Out-Null

Add-Type @"
using System;
using System.Runtime.InteropServices;
public class DwmApi {
  [DllImport("dwmapi.dll")]
  public static extern int DwmSetWindowAttribute(IntPtr hWnd, int attr, ref int attrValue, int attrSize);
}
"@

# ---------- LDAP helpers ----------
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

function Test-AdCredential {
  param(
    [string]$User,
    [string]$Password,
    [string]$ServerOrDomain)
  if ([string]::IsNullOrWhiteSpace($User) -or [string]::IsNullOrWhiteSpace($Password)) { return $true }
  try {
    $ctxType = [System.DirectoryServices.AccountManagement.ContextType]::Domain
    $ctx = if ([string]::IsNullOrWhiteSpace($ServerOrDomain)) {
      New-Object System.DirectoryServices.AccountManagement.PrincipalContext($ctxType)
    } else {
      New-Object System.DirectoryServices.AccountManagement.PrincipalContext($ctxType,$ServerOrDomain)
    }
    $ctx.ValidateCredentials($User,$Password)
  } catch {
    $false
  }
}

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

function Update-ComputerSuggestions {
  param([string]$Prefix)
  if ([string]::IsNullOrWhiteSpace($Prefix) -or $Prefix.Length -lt 2) {
    $lbCompSuggest.ItemsSource = @()
    $popCompSuggest.IsOpen = $false
    return }
  try {
    $cred = $null
    if (-not [string]::IsNullOrWhiteSpace($tbUser.Text) -and -not [string]::IsNullOrWhiteSpace($pbPass.Password)) {
      $secure = ConvertTo-SecureString -String $pbPass.Password -AsPlainText -Force
      $cred = New-Object System.Management.Automation.PSCredential ($tbUser.Text, $secure) }
    $ds = Get-DirectorySearcher -Credential $cred -ServerOrDomain $tbServer.Text
    $v = Escape-LdapFilterValue $Prefix
    $ds.PageSize = 50
    $ds.Filter = "(&(objectCategory=computer)(|(sAMAccountName=$v*)(cn=$v*)(dNSHostName=$v*)))"
    $ds.PropertiesToLoad.Clear(); $ds.PropertiesToLoad.Add('sAMAccountName') | Out-Null
    $res = $ds.FindAll()
    $names = @{}
    foreach ($r in $res) {
      $n = Get-FirstValue ($r.Properties['sAMAccountName'])
      if ($n) { $names[(Normalize-ComputerName $n)] = $true }
    }
    if ($script:Prefs.AdHistory) {
      foreach ($h in $script:Prefs.AdHistory) {
        if ($h -like "$Prefix*") { $names[$h] = $true }
      }
    }
    $items = @($names.Keys | Sort-Object | Select-Object -First 50)
    $lbCompSuggest.ItemsSource = $items
    $popCompSuggest.IsOpen = ($items.Count -gt 0)
  } catch {
    $lbCompSuggest.ItemsSource = @(); $popCompSuggest.IsOpen = $false }
}

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
function Get-LatestReleaseInfo {
  $uri = 'https://api.github.com/repos/ethanpnk/laps-ui/releases/latest'
  try {
    Invoke-RestMethod -Uri $uri -Headers @{ 'User-Agent' = 'LAPS-UI' } -ErrorAction Stop
  } catch {
    return $null
  }
}

function Check-ForUpdates {
  param([string]$CurrentVersion)
  $release = Get-LatestReleaseInfo
  if (-not $release) { return $null }

  $latest = $release.tag_name.TrimStart('v')
  if ([version]$latest -le [version]$CurrentVersion) { return $null }
  if ($script:Prefs.IgnoreVersion -eq $latest) { return $null }

  $asset = $release.assets | Where-Object { $_.name -eq 'LAPS-UI.exe' } | Select-Object -First 1
  if (-not $asset) { return $null }

  $sha256 = $null
  if ($release.body -match 'SHA256[:\s]+(?<hash>[A-Fa-f0-9]{64})') {
    $sha256 = $Matches['hash']
  }

  [pscustomobject]@{
    Version = $latest
    Url     = $asset.browser_download_url
    Sha256  = $sha256
  }
}

function Start-AppUpdate {
  param($Info, $Window)
  try {
    if (-not $Info -or [string]::IsNullOrWhiteSpace($Info.Url)) {
      throw "Update information is missing a download URL"
    }
    $tmp = Join-Path ([IO.Path]::GetTempPath()) "LAPS-UI-$($Info.Version).exe"
    Invoke-WebRequest -Uri $Info.Url -OutFile $tmp -UseBasicParsing -Headers @{ 'User-Agent' = 'LAPS-UI' }
    Unblock-File -Path $tmp -ErrorAction SilentlyContinue
    if ($Info.Sha256) {
      $h = (Get-FileHash -Path $tmp -Algorithm SHA256).Hash
      if ($h -ne $Info.Sha256) { throw "SHA256 mismatch" }
    }
    $exe = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    $appPid = $PID
    $script = @'
param([string]$Tmp,[string]$Exe,[int]$AppPid)
while (Get-Process -Id $AppPid -ErrorAction SilentlyContinue) {
  Start-Sleep -Milliseconds 200
}
Copy-Item -Path $Tmp -Destination $Exe -Force
Unblock-File -Path $Exe -ErrorAction SilentlyContinue
Start-Process -FilePath $Exe
'@
    $ps = Join-Path ([IO.Path]::GetTempPath()) 'laps-ui-update.ps1'
    Set-Content -Path $ps -Value $script -Encoding UTF8
    Start-Process -FilePath 'powershell' -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File',$ps,'-Tmp',$tmp,'-Exe',$exe,'-AppPid',$appPid -WindowStyle Hidden
    $Window.Close()
  } catch {
    [System.Windows.MessageBox]::Show("Update failed: $($_.Exception.Message)", 'Update', 'OK', 'Error') | Out-Null
  }
}

function Show-UpdatePrompt {
  param($Info)
  $script:LastUpdateInfo = $Info
  if ($btnUpdate.Tag) { $btnUpdate.Remove_Click($btnUpdate.Tag) }
  if ($btnIgnore.Tag) { $btnIgnore.Remove_Click($btnIgnore.Tag) }
  $btnUpdate.Content = ($t.btnUpdateTo -f $Info.Version)
  $btnUpdate.Visibility = 'Visible'
  $btnIgnore.Visibility = 'Visible'
  $btnUpdate.Tag = { Start-AppUpdate -Info $script:LastUpdateInfo -Window $window }
  $btnUpdate.Add_Click($btnUpdate.Tag)
  $btnIgnore.Tag = {
    $script:Prefs.IgnoreVersion = $Info.Version
    Save-Prefs
    $btnUpdate.Visibility='Collapsed'
    $btnIgnore.Visibility='Collapsed'
    $lblUpdateStatus.Text = ''
  }
  $btnIgnore.Add_Click($btnIgnore.Tag)
}
# ---------- XAML (Dark) ----------
[xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="LAPS UI (Windows &amp; Legacy) - v$CurrentVersion"
        Width="1000" MinWidth="1000" SizeToContent="Height"
        WindowStartupLocation="CenterScreen"
        Background="#1E1E1E" Foreground="#EEEEEE" FontFamily="Segoe UI" FontSize="13">
  <Window.Resources>
    <SolidColorBrush x:Key="LabelBrush" Color="#BEBEBE"/>
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
        <Trigger Property="IsMouseOver" Value="True"><Setter Property="Background" Value="#0C60C0"/></Trigger>
        <Trigger Property="IsEnabled" Value="False"><Setter Property="Opacity" Value="0.5"/></Trigger>
      </Style.Triggers>
    </Style>

    <Style x:Key="IconButton" TargetType="Button" BasedOn="{StaticResource AccentButton}">
      <Setter Property="Width"    Value="32"/>
      <Setter Property="Height"   Value="32"/>
      <Setter Property="MinWidth" Value="0"/>
      <Setter Property="MinHeight" Value="0"/>
      <Setter Property="Padding"  Value="0"/>
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
            <Border Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}"
                    BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="4">
              <ScrollViewer x:Name="PART_ContentHost"/>
            </Border>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <!-- NEW: RichTextBox style for colorized password -->
    <Style TargetType="RichTextBox">
      <Setter Property="Background" Value="#2D2D2D"/>
      <Setter Property="Foreground" Value="#EEEEEE"/>
      <Setter Property="BorderBrush" Value="#3E3E42"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Padding" Value="4"/>
      <Setter Property="FontFamily" Value="Cascadia Code,Consolas"/>
      <Setter Property="FontSize" Value="20"/>
      <Setter Property="IsReadOnly" Value="True"/>
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
            <Border Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}"
                    BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="4">
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
            <Border CornerRadius="8" Background="#252526" BorderBrush="{TemplateBinding BorderBrush}"
                    BorderThickness="{TemplateBinding BorderThickness}" Margin="0,8,0,0">
              <DockPanel LastChildFill="True">
                <Border DockPanel.Dock="Top" Background="#2B2B2B" Padding="8,4" CornerRadius="8,8,0,0">
                  <TextBlock Text="{TemplateBinding Header}" FontWeight="SemiBold" Foreground="{DynamicResource LabelBrush}"/>
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
    </Style>

    <Style TargetType="TabItem">
      <Setter Property="Foreground" Value="#EEEEEE"/>
      <Setter Property="Padding" Value="14,8"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="FocusVisualStyle" Value="{x:Null}"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="TabItem">
            <Border x:Name="Bd"
                    Background="#2D2D2D"
                    CornerRadius="8"
                    Margin="0,0,8,0"
                    Padding="{TemplateBinding Padding}"
                    SnapsToDevicePixels="True">
              <ContentPresenter ContentSource="Header"
                                HorizontalAlignment="Center"
                                VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="Bd" Property="Background" Value="#3E3E42"/>
              </Trigger>
              <Trigger Property="IsEnabled" Value="False">
                <Setter Property="Opacity" Value="0.5"/>
              </Trigger>
              <Trigger Property="IsSelected" Value="True">
                <Setter Property="Foreground" Value="White"/>
                <Setter TargetName="Bd" Property="Background" Value="#0A84FF"/>
                <Setter TargetName="Bd" Property="Effect">
                  <Setter.Value>
                    <DropShadowEffect BlurRadius="10" ShadowDepth="0" Opacity="0.35"/>
                  </Setter.Value>
                </Setter>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

<Style TargetType="TabControl">
  <Setter Property="Background" Value="{Binding RelativeSource={RelativeSource AncestorType=Window}, Path=Background}"/>
  <Setter Property="BorderThickness" Value="0"/>
  <Setter Property="Template">
    <Setter.Value>
      <ControlTemplate TargetType="TabControl">
        <Grid SnapsToDevicePixels="True">
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
          </Grid.RowDefinitions>

          <!-- Barre d'onglets -->
          <TabPanel x:Name="HeaderPanel"
                    IsItemsHost="True"
                    Margin="12,12,20,0"
                    KeyboardNavigation.TabIndex="1"
                    Panel.ZIndex="1"
                    Background="{TemplateBinding Background}"/>

          <!-- Zone de contenu -->
          <Border Grid.Row="1"
                  Margin="12"
                  Background="{Binding RelativeSource={RelativeSource AncestorType=Window}, Path=Background}"
                  CornerRadius="10"
                  BorderBrush="#3E3E42"
                  BorderThickness="1"
                  Padding="12">
            <ContentPresenter x:Name="PART_SelectedContentHost"
                              Margin="0"
                              ContentSource="SelectedContent"
                              SnapsToDevicePixels="{TemplateBinding SnapsToDevicePixels}"/>
          </Border>
        </Grid>
      </ControlTemplate>
    </Setter.Value>
  </Setter>
</Style>
  </Window.Resources>

  <TabControl Margin="0" Background="{Binding RelativeSource={RelativeSource AncestorType=Window}, Path=Background}" BorderThickness="0">
  <TabItem Header="LAPS (AD)" x:Name="tabMain">
      <Grid Background="{Binding RelativeSource={RelativeSource AncestorType=Window}, Path=Background}">
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

      <!-- Credentials & AD target side by side -->
      <Grid Grid.Row="0" Margin="0,0,0,14">
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="*"/>
          <ColumnDefinition Width="*"/>
        </Grid.ColumnDefinitions>

        <GroupBox Grid.Column="0" Header="Credentials" Margin="0,0,8,0" x:Name="gbCreds">
          <Grid>
            <Grid.ColumnDefinitions>
              <ColumnDefinition Width="Auto"/><ColumnDefinition Width="*"/>
            </Grid.ColumnDefinitions>
            <Grid.RowDefinitions>
              <RowDefinition Height="Auto"/><RowDefinition Height="Auto"/>
            </Grid.RowDefinitions>
            <TextBlock Grid.Row="0" Grid.Column="0" Text="User (user@domain)" Margin="0,0,12,0" VerticalAlignment="Center" Foreground="{DynamicResource LabelBrush}" x:Name="lblUser"/>
            <TextBox   Grid.Row="0" Grid.Column="1" x:Name="tbUser"/>
            <TextBlock Grid.Row="1" Grid.Column="0" Text="Password" Margin="0,8,12,0" VerticalAlignment="Center" Foreground="{DynamicResource LabelBrush}" x:Name="lblPass"/>
            <PasswordBox Grid.Row="1" Grid.Column="1" x:Name="pbPass" Margin="0,8,0,0"/>
          </Grid>
        </GroupBox>

        <GroupBox Grid.Column="1" Header="Active Directory Target" Margin="8,0,0,0" x:Name="gbAD">
          <Grid>
            <Grid.ColumnDefinitions>
              <ColumnDefinition Width="Auto"/><ColumnDefinition Width="*"/>
            </Grid.ColumnDefinitions>
            <Grid.RowDefinitions>
              <RowDefinition Height="Auto"/>
            </Grid.RowDefinitions>
            <TextBlock Grid.Row="0" Grid.Column="0" VerticalAlignment="Center" Text="Controller/Domain" Margin="0,0,12,0" Foreground="{DynamicResource LabelBrush}" x:Name="lblController"/>
            <TextBox   Grid.Row="0" Grid.Column="1" x:Name="tbServer" Text=""/>
          </Grid>
        </GroupBox>
      </Grid>

      <!-- Search -->
      <GroupBox Grid.Row="1" Header="Search" x:Name="gbSearch">
        <Grid>
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="Auto"/><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/><ColumnDefinition Width="Auto"/><ColumnDefinition Width="Auto"/>
          </Grid.ColumnDefinitions>
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
          </Grid.RowDefinitions>
          <TextBlock Grid.Row="0" Grid.Column="0" VerticalAlignment="Center" Text="Computer name" Margin="0,0,12,0" Foreground="{DynamicResource LabelBrush}" x:Name="lblCompName"/>
          <TextBox   Grid.Row="0" Grid.Column="1" x:Name="tbComp"/>
          <Button   Grid.Row="0" Grid.Column="2" x:Name="btnHistory" Content="&#xE81C;" FontFamily="Segoe MDL2 Assets" Style="{StaticResource IconButton}" Margin="12,0,0,0" ToolTip="History"/>
          <Button   Grid.Row="0" Grid.Column="3" x:Name="btnGet" Content="Retrieve" Style="{StaticResource AccentButton}" IsDefault="True" Margin="12,0,0,0"/>
          <Button   Grid.Row="0" Grid.Column="4" x:Name="btnRetry" Content="Retry" Style="{StaticResource AccentButton}" Margin="12,0,0,0" Visibility="Collapsed"/>
          <Popup    x:Name="popCompSuggest" PlacementTarget="{Binding ElementName=tbComp}" Placement="Bottom" StaysOpen="False">
            <Border BorderBrush="#3E3E42" BorderThickness="1" Background="#2D2D2D">
              <ListBox x:Name="lbCompSuggest" MaxHeight="200" Width="{Binding ElementName=tbComp, Path=ActualWidth}" Background="#2D2D2D" Foreground="#EEEEEE"/>
            </Border>
          </Popup>
        </Grid>
      </GroupBox>

      <!-- Details -->
      <GroupBox Grid.Row="2" Header="Details" x:Name="gbDetails" Visibility="Collapsed">
        <Grid>
          <Grid.RowDefinitions>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
          </Grid.RowDefinitions>
          <TextBox Grid.Row="0" x:Name="txtDetails" Height="80" AcceptsReturn="True" IsReadOnly="True"
                   VerticalScrollBarVisibility="Auto" FontFamily="Cascadia Code,Consolas" FontSize="12"/>
          <StackPanel Grid.Row="1" Orientation="Horizontal" Margin="0,8,0,0" x:Name="spExpire" Visibility="Collapsed">
            <Ellipse Width="10" Height="10" Margin="0,0,8,0" x:Name="ellExpire"/>
            <TextBlock VerticalAlignment="Center" x:Name="lblExpire"/>
          </StackPanel>
        </Grid>
      </GroupBox>

      <!-- LAPS Password -->
      <GroupBox Grid.Row="3" Header="LAPS Password" x:Name="gbPwd">
        <Grid>
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/><ColumnDefinition Width="Auto"/>
          </Grid.ColumnDefinitions>
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/><RowDefinition Height="Auto"/>
          </Grid.RowDefinitions>

          <!-- NEW: RichTextBox for colorized clear text -->
          <RichTextBox Grid.Row="0" Grid.Column="0" x:Name="rtbPwdOut" Visibility="Collapsed" Focusable="False" IsHitTestVisible="False"/>

          <PasswordBox Grid.Row="0" Grid.Column="0" x:Name="pbPwdOut" FontFamily="Cascadia Code,Consolas" FontSize="20"
                       IsHitTestVisible="False" Focusable="False"/>

          <CheckBox Grid.Row="0" Grid.Column="1" x:Name="cbShow" Content="Show" Margin="12,6,12,0" VerticalAlignment="Center"/>
          <Button   Grid.Row="0" Grid.Column="2" x:Name="btnCopy" Content="Copy" Style="{StaticResource AccentButton}" IsEnabled="False"/>

          <TextBlock Grid.Row="1" Grid.Column="0" x:Name="lblCountdown" Margin="0,8,0,0" Foreground="#FFA07A" Visibility="Collapsed"/>
        </Grid>
      </GroupBox>

      <StackPanel Grid.Row="4" Orientation="Horizontal">
        <Button x:Name="btnUpdate" Content="Update" Style="{StaticResource AccentButton}" Visibility="Collapsed"/>
        <Button x:Name="btnIgnore" Content="Ignore" Style="{StaticResource AccentButton}" Margin="8,0,0,0" Visibility="Collapsed"/>
      </StackPanel>
    </Grid>
  </TabItem>
  <TabItem Header="LAPS (Intune)" x:Name="tabAzure">
    <Grid Margin="20" Background="{Binding RelativeSource={RelativeSource AncestorType=Window}, Path=Background}">
      <Grid.RowDefinitions>
        <RowDefinition Height="Auto"/>
        <RowDefinition Height="Auto"/>
        <RowDefinition Height="Auto"/>
        <RowDefinition Height="Auto"/>
        <RowDefinition Height="Auto"/>
      </Grid.RowDefinitions>

      <GroupBox Grid.Row="0" Header="Authentication" x:Name="gbAzureAuth">
        <Grid>
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="Auto"/>
            <ColumnDefinition Width="Auto"/>
          </Grid.ColumnDefinitions>
          <TextBlock Grid.Column="0" x:Name="lblAzureStatus" Text="Not signed in" VerticalAlignment="Center" Foreground="{DynamicResource LabelBrush}"/>
          <Button Grid.Column="1" x:Name="btnAzureSignIn" Content="Sign in" Style="{StaticResource AccentButton}" Margin="12,0,0,0"/>
          <Button Grid.Column="2" x:Name="btnAzureSignOut" Content="Sign out" Style="{StaticResource AccentButton}" Margin="12,0,0,0" Visibility="Collapsed"/>
        </Grid>
      </GroupBox>

      <GroupBox Grid.Row="1" Header="Search" x:Name="gbAzureSearch">
        <Grid>
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="Auto"/>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="Auto"/>
            <ColumnDefinition Width="Auto"/>
          </Grid.ColumnDefinitions>
          <TextBlock Grid.Column="0" VerticalAlignment="Center" Text="Device name" Margin="0,0,12,0" Foreground="{DynamicResource LabelBrush}" x:Name="lblAzureDeviceName"/>
          <TextBox Grid.Column="1" x:Name="tbAzureDevice"/>
          <Button Grid.Column="2" x:Name="btnAzureHistory" Content="&#xE81C;" FontFamily="Segoe MDL2 Assets" Style="{StaticResource IconButton}" Margin="12,0,0,0" ToolTip="History"/>
          <Button Grid.Column="3" x:Name="btnAzureSearch" Content="Retrieve" Style="{StaticResource AccentButton}" Margin="12,0,0,0"/>
          <Popup x:Name="popAzureDevice" PlacementTarget="{Binding ElementName=tbAzureDevice}" Placement="Bottom" StaysOpen="False">
            <Border BorderBrush="#3E3E42" BorderThickness="1" Background="#2D2D2D">
              <ListBox x:Name="lbAzureDeviceHistory" MaxHeight="200" Width="{Binding ElementName=tbAzureDevice, Path=ActualWidth}" Background="#2D2D2D" Foreground="#EEEEEE"/>
            </Border>
          </Popup>
        </Grid>
      </GroupBox>

      <GroupBox Grid.Row="2" Header="Devices" x:Name="gbAzureDevices" Visibility="Collapsed">
        <Grid>
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
          </Grid.RowDefinitions>
          <ListBox x:Name="lbAzureDevices" Height="140" DisplayMemberPath="DisplayName" Background="#2D2D2D" Foreground="#EEEEEE"/>
        </Grid>
      </GroupBox>

      <GroupBox Grid.Row="3" Header="Details" x:Name="gbAzureDetails" Visibility="Collapsed">
        <Grid>
          <Grid.RowDefinitions>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
          </Grid.RowDefinitions>
          <TextBox Grid.Row="0" x:Name="txtAzureDetails" Height="80" AcceptsReturn="True" IsReadOnly="True" VerticalScrollBarVisibility="Auto" FontFamily="Cascadia Code,Consolas" FontSize="12"/>
          <StackPanel Grid.Row="1" Orientation="Horizontal" Margin="0,8,0,0" x:Name="spAzureExpire" Visibility="Collapsed">
            <Ellipse Width="10" Height="10" Margin="0,0,8,0" x:Name="ellAzureExpire"/>
            <TextBlock VerticalAlignment="Center" x:Name="lblAzureExpire"/>
          </StackPanel>
        </Grid>
      </GroupBox>

      <GroupBox Grid.Row="4" Header="LAPS Password" x:Name="gbAzurePwd">
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

          <RichTextBox Grid.Row="0" Grid.Column="0" x:Name="rtbAzurePwd" Visibility="Collapsed" Focusable="False" IsHitTestVisible="False"/>

          <PasswordBox Grid.Row="0" Grid.Column="0" x:Name="pbAzurePwd" FontFamily="Cascadia Code,Consolas" FontSize="20" IsHitTestVisible="False" Focusable="False"/>

          <CheckBox Grid.Row="0" Grid.Column="1" x:Name="cbAzureShow" Content="Show" Margin="12,6,12,0" VerticalAlignment="Center"/>
          <Button Grid.Row="0" Grid.Column="2" x:Name="btnAzureCopy" Content="Copy" Style="{StaticResource AccentButton}" IsEnabled="False"/>

          <TextBlock Grid.Row="1" Grid.Column="0" x:Name="lblAzureCountdown" Margin="0,8,0,0" Foreground="#FFA07A" Visibility="Collapsed"/>
        </Grid>
      </GroupBox>
    </Grid>
  </TabItem>
  <TabItem Header="Settings" x:Name="tabSettings">
    <StackPanel Margin="0" Background="{Binding RelativeSource={RelativeSource AncestorType=Window}, Path=Background}">
      <GroupBox Header="Security" x:Name="gbSecurity">
        <StackPanel>
          <CheckBox x:Name="cbLdaps" Content="Use LDAPS (TLS 636)" Margin="0,0,0,8"/>
          <CheckBox x:Name="cbClipboardAutoClear" Content="Enable clipboard auto-clear" IsChecked="True" Margin="0,0,0,8"/>
          <StackPanel Orientation="Horizontal" Margin="20,0,0,0">
            <TextBlock Text="Clipboard delay (s)" Margin="0,0,8,0" VerticalAlignment="Center" Foreground="{DynamicResource LabelBrush}" x:Name="lblClipboardDelay"/>
            <TextBox x:Name="tbClipboardSecs" Width="50"/>
          </StackPanel>
        </StackPanel>
      </GroupBox>
      <GroupBox Header="Preferences" x:Name="gbPrefs">
        <StackPanel>
          <CheckBox x:Name="cbRememberUser" Content="Remember user"/>
          <CheckBox x:Name="cbRememberServer" Content="Remember controller/domain"/>
          <StackPanel Orientation="Horizontal">
            <CheckBox x:Name="cbAutoUpdate" Content="Check for updates on launch" IsChecked="True"/>
            <Button x:Name="btnCheckUpdate" Margin="8,0,0,0" Style="{StaticResource IconButton}">
              <TextBlock FontFamily="Segoe MDL2 Assets" Text="&#xE72C;"/>
            </Button>
            <TextBlock x:Name="lblUpdateStatus" Margin="8,0,0,0" VerticalAlignment="Center" Foreground="{DynamicResource LabelBrush}"/>
          </StackPanel>
          <CheckBox x:Name="cbConfirmCopy" Content="Confirm before copying"/>
        </StackPanel>
      </GroupBox>
      <GroupBox Header="Appearance" x:Name="gbAppearance">
        <StackPanel>
          <StackPanel Orientation="Horizontal" Margin="0,0,0,8">
            <TextBlock Text="Theme" Margin="0,0,8,0" VerticalAlignment="Center" Foreground="{DynamicResource LabelBrush}" x:Name="lblTheme"/>
            <ComboBox x:Name="cmbTheme" Width="120" SelectedIndex="0">
              <ComboBoxItem Content="Dark" Tag="Dark"/>
              <ComboBoxItem Content="Light" Tag="Light"/>
            </ComboBox>
          </StackPanel>
          <StackPanel Orientation="Horizontal">
            <TextBlock Text="Language" Margin="0,0,8,0" VerticalAlignment="Center" Foreground="{DynamicResource LabelBrush}" x:Name="lblLanguage"/>
            <ComboBox x:Name="cmbLanguage" Width="120" SelectedIndex="0">
              <ComboBoxItem Content="English" Tag="English"/>
              <ComboBoxItem Content="French" Tag="French"/>
              <ComboBoxItem Content="Spanish" Tag="Spanish"/>
              <ComboBoxItem Content="Italian" Tag="Italian"/>
              <ComboBoxItem Content="German" Tag="German"/>
              <ComboBoxItem Content="Portuguese" Tag="Portuguese"/>
              <ComboBoxItem Content="Chinese" Tag="Chinese"/>
              <ComboBoxItem Content="Arabic" Tag="Arabic"/>
            </ComboBox>
          </StackPanel>
        </StackPanel>
      </GroupBox>
    </StackPanel>
  </TabItem>
  </TabControl>
</Window>
"@

# ---------- Build UI ----------
$reader = (New-Object System.Xml.XmlNodeReader $xaml)
$window = [Windows.Markup.XamlReader]::Load($reader)

$script:DarkResources = $window.Resources
$lightThemeXaml = @"
<ResourceDictionary xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml">
  <SolidColorBrush x:Key="LabelBrush" Color="#333333"/>
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
      <Trigger Property="IsMouseOver" Value="True"><Setter Property="Background" Value="#0C60C0"/></Trigger>
      <Trigger Property="IsEnabled" Value="False"><Setter Property="Opacity" Value="0.5"/></Trigger>
    </Style.Triggers>
  </Style>

  <Style x:Key="IconButton" TargetType="Button" BasedOn="{StaticResource AccentButton}">
    <Setter Property="Width"    Value="32"/>
    <Setter Property="Height"   Value="32"/>
    <Setter Property="MinWidth" Value="0"/>
    <Setter Property="MinHeight" Value="0"/>
    <Setter Property="Padding"  Value="0"/>
  </Style>

  <Style TargetType="TextBox">
    <Setter Property="Background" Value="#FFFFFF"/>
    <Setter Property="Foreground" Value="#1E1E1E"/>
    <Setter Property="BorderBrush" Value="#CCCCCC"/>
    <Setter Property="BorderThickness" Value="1"/>
    <Setter Property="Padding" Value="8,6"/>
    <Setter Property="Template">
      <Setter.Value>
        <ControlTemplate TargetType="TextBox">
          <Border Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}"
                  BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="4">
            <ScrollViewer x:Name="PART_ContentHost"/>
          </Border>
        </ControlTemplate>
      </Setter.Value>
    </Setter>
  </Style>

  <Style TargetType="RichTextBox">
    <Setter Property="Background" Value="#FFFFFF"/>
    <Setter Property="Foreground" Value="#1E1E1E"/>
    <Setter Property="BorderBrush" Value="#CCCCCC"/>
    <Setter Property="BorderThickness" Value="1"/>
    <Setter Property="Padding" Value="4"/>
    <Setter Property="FontFamily" Value="Cascadia Code,Consolas"/>
    <Setter Property="FontSize" Value="20"/>
    <Setter Property="IsReadOnly" Value="True"/>
  </Style>

  <Style TargetType="PasswordBox">
    <Setter Property="Background" Value="#FFFFFF"/>
    <Setter Property="Foreground" Value="#1E1E1E"/>
    <Setter Property="BorderBrush" Value="#CCCCCC"/>
    <Setter Property="BorderThickness" Value="1"/>
    <Setter Property="Padding" Value="8,6"/>
    <Setter Property="Template">
      <Setter.Value>
        <ControlTemplate TargetType="PasswordBox">
          <Border Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}"
                  BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="4">
            <ScrollViewer x:Name="PART_ContentHost"/>
          </Border>
        </ControlTemplate>
      </Setter.Value>
    </Setter>
  </Style>

  <Style TargetType="GroupBox">
    <Setter Property="Foreground" Value="#1E1E1E"/>
    <Setter Property="BorderBrush" Value="#CCCCCC"/>
    <Setter Property="BorderThickness" Value="1"/>
    <Setter Property="Padding" Value="12"/>
    <Setter Property="Margin" Value="0,0,0,14"/>
    <Setter Property="Template">
      <Setter.Value>
        <ControlTemplate TargetType="{x:Type GroupBox}">
          <Border CornerRadius="8" Background="#FFFFFF" BorderBrush="{TemplateBinding BorderBrush}"
                  BorderThickness="{TemplateBinding BorderThickness}" Margin="0,8,0,0">
            <DockPanel LastChildFill="True">
              <Border DockPanel.Dock="Top" Background="#F0F0F0" Padding="8,4" CornerRadius="8,8,0,0">
                <TextBlock Text="{TemplateBinding Header}" FontWeight="SemiBold" Foreground="{DynamicResource LabelBrush}"/>
              </Border>
              <ContentPresenter Margin="{TemplateBinding Padding}"/>
            </DockPanel>
          </Border>
        </ControlTemplate>
      </Setter.Value>
    </Setter>
  </Style>

  <Style TargetType="CheckBox">
    <Setter Property="Foreground" Value="#1E1E1E"/>
    <Setter Property="Margin" Value="0,4,0,0"/>
  </Style>
  <Style TargetType="TabControl">
    <Setter Property="Background" Value="{Binding RelativeSource={RelativeSource AncestorType=Window}, Path=Background}"/>
    <Setter Property="BorderThickness" Value="0"/>
    <Setter Property="Template">
      <Setter.Value>
        <ControlTemplate TargetType="TabControl">
          <Grid SnapsToDevicePixels="True">
            <Grid.RowDefinitions>
              <RowDefinition Height="Auto"/>
              <RowDefinition Height="*"/>
            </Grid.RowDefinitions>

            <TabPanel x:Name="HeaderPanel"
                      IsItemsHost="True"
                      Margin="12,12,20,0"
                      KeyboardNavigation.TabIndex="1"
                      Panel.ZIndex="1"
                      Background="{TemplateBinding Background}"/>

            <Border Grid.Row="1"
                    Margin="12"
                    Background="{Binding RelativeSource={RelativeSource AncestorType=Window}, Path=Background}"
                    CornerRadius="10"
                    BorderBrush="#CCCCCC"
                    BorderThickness="1"
                    Padding="12">
              <ContentPresenter x:Name="PART_SelectedContentHost"
                                Margin="0"
                                ContentSource="SelectedContent"
                                SnapsToDevicePixels="{TemplateBinding SnapsToDevicePixels}"/>
            </Border>
          </Grid>
        </ControlTemplate>
      </Setter.Value>
    </Setter>
  </Style>

  <Style TargetType="TabItem">
    <Setter Property="Foreground" Value="#333333"/>
    <Setter Property="Padding" Value="14,8"/>
    <Setter Property="Cursor" Value="Hand"/>
    <Setter Property="FocusVisualStyle" Value="{x:Null}"/>
    <Setter Property="Template">
      <Setter.Value>
        <ControlTemplate TargetType="TabItem">
          <Border x:Name="Bd"
                  Background="#F0F0F0"
                  BorderBrush="#CCCCCC"
                  BorderThickness="1"
                  CornerRadius="8"
                  Margin="0,0,8,0"
                  Padding="{TemplateBinding Padding}"
                  SnapsToDevicePixels="True">
            <ContentPresenter ContentSource="Header"
                              HorizontalAlignment="Center"
                              VerticalAlignment="Center"/>
          </Border>
          <ControlTemplate.Triggers>
            <Trigger Property="IsMouseOver" Value="True">
              <Setter TargetName="Bd" Property="Background" Value="#E5E5E5"/>
            </Trigger>
            <Trigger Property="IsEnabled" Value="False">
              <Setter Property="Opacity" Value="0.5"/>
            </Trigger>
            <Trigger Property="IsSelected" Value="True">
              <Setter Property="Foreground" Value="White"/>
              <Setter TargetName="Bd" Property="Background" Value="#0A84FF"/>
              <Setter TargetName="Bd" Property="BorderBrush" Value="#0A84FF"/>
              <Setter TargetName="Bd" Property="Effect">
                <Setter.Value>
                  <DropShadowEffect BlurRadius="10" ShadowDepth="0" Opacity="0.35"/>
                </Setter.Value>
              </Setter>
            </Trigger>
          </ControlTemplate.Triggers>
        </ControlTemplate>
      </Setter.Value>
    </Setter>
  </Style>
</ResourceDictionary>
"@
$lightReader = New-Object System.Xml.XmlNodeReader ([xml]$lightThemeXaml)
$script:LightResources = [Windows.Markup.XamlReader]::Load($lightReader)

function Apply-Theme {
  param([string]$Theme)
  if ($Theme -eq 'Light') {
    $window.Resources = $script:LightResources
    $window.Background = [Windows.Media.Brushes]::White
    $window.Foreground = [Windows.Media.Brushes]::Black
    $useDark = 0
  } else {
    $window.Resources = $script:DarkResources
    $window.Background = New-Object Windows.Media.SolidColorBrush ([Windows.Media.ColorConverter]::ConvertFromString('#1E1E1E'))
    $window.Foreground = [Windows.Media.Brushes]::White
    $useDark = 1
  }

  $helper = New-Object System.Windows.Interop.WindowInteropHelper($window)
  $hWnd = $helper.EnsureHandle()
  [DwmApi]::DwmSetWindowAttribute($hWnd, 19, [ref]$useDark, 4) | Out-Null
  [DwmApi]::DwmSetWindowAttribute($hWnd, 20, [ref]$useDark, 4) | Out-Null
}

# Localization
$translations = @{
  English = @{
    tabMain         = 'LAPS (AD)'
    tabAzure        = 'LAPS (Intune)'
    tabSettings     = 'Settings'
    gbCreds         = 'Credentials'
    gbAD            = 'Active Directory Target'
    gbAzureAuth     = 'Authentication'
    gbAzureDevices  = 'Devices'
    gbSearch        = 'Search'
    gbDetails       = 'Details'
    gbPwd           = 'LAPS Password'
    lblUser         = 'User (user@domain)'
    lblPass         = 'Password'
    lblController   = 'Controller/Domain'
    lblCompName     = 'Computer name'
    btnGet          = 'Retrieve'
    btnRetry        = 'Retry'
    btnUpdate       = 'Update'
    btnUpdateTo     = 'Update to v{0}'
    btnIgnore       = 'Ignore'
    cbShow          = 'Show'
    btnCopy         = 'Copy'
    btnAzureSignIn  = 'Sign in'
    btnAzureSignOut = 'Sign out'
    gbSecurity      = 'Security'
    cbLdaps         = 'Use LDAPS (TLS 636)'
    cbClipboardAutoClear = 'Enable clipboard auto-clear'
    lblClipboardDelay = 'Clipboard delay (s)'
    gbPrefs         = 'Preferences'
    cbRememberUser  = 'Remember user'
    cbRememberServer= 'Remember controller/domain'
    cbAutoUpdate    = 'Check for updates on launch'
    btnCheckUpdate_ToolTip  = 'Check now'
    msgNoUpdate     = 'You are up to date.'
    msgUpdateAvailable = 'Update available: v{0}'
    cbConfirmCopy   = 'Confirm before copying'
    gbAppearance    = 'Appearance'
    lblTheme        = 'Theme'
    lblLanguage     = 'Language'
    themeDark       = 'Dark'
    themeLight      = 'Light'
    langEnglish     = 'English'
    langFrench      = 'French'
    langSpanish     = 'Spanish'
    langItalian     = 'Italian'
    langGerman      = 'German'
    langPortuguese  = 'Portuguese'
    langChinese     = 'Chinese'
    langArabic      = 'Arabic'
    btnHistory_ToolTip = 'History'
    lblAzureStatusSignedOut = 'Not signed in'
    lblAzureStatusSignedIn  = 'Connected as {0}'
    msgAzureConnectFirst = 'Please sign in to Microsoft Graph first.'
    msgAzureNoDevices = 'No Intune devices matched your query.'
    msgAzureMultipleDevices = 'Select a device to retrieve the password.'
    msgAzureInstallModule = 'Microsoft.Graph PowerShell module is required.'
  }
  French = @{
    tabMain         = 'LAPS (AD)'
    tabAzure        = 'LAPS (Intune)'
    tabSettings     = 'Paramètres'
    gbCreds         = 'Identifiants'
    gbAD            = 'Cible Active Directory'
    gbAzureAuth     = 'Authentification'
    gbAzureDevices  = 'Appareils'
    gbSearch        = 'Recherche'
    gbDetails       = 'Détails'
    gbPwd           = 'Mot de passe LAPS'
    lblUser         = 'Utilisateur (utilisateur@domaine)'
    lblPass         = 'Mot de passe'
    lblController   = 'Contrôleur/Domaine'
    lblCompName     = "Nom de l'ordinateur"
    btnGet          = 'Récupérer'
    btnRetry        = 'Réessayer'
    btnUpdate       = 'Mettre à jour'
    btnUpdateTo     = 'Mettre à jour vers v{0}'
    btnIgnore       = 'Ignorer'
    cbShow          = 'Afficher'
    btnCopy         = 'Copier'
    btnAzureSignIn  = 'Se connecter'
    btnAzureSignOut = 'Se déconnecter'
    gbSecurity      = 'Sécurité'
    cbLdaps         = 'Utiliser LDAPS (TLS 636)'
    cbClipboardAutoClear = "Activer l'effacement automatique du presse-papiers"
    lblClipboardDelay = 'Délai presse-papiers (s)'
    gbPrefs         = 'Préférences'
    cbRememberUser  = "Mémoriser l'utilisateur"
    cbRememberServer= 'Mémoriser le contrôleur/domaine'
    cbAutoUpdate    = 'Vérifier les mises à jour au lancement'
    btnCheckUpdate_ToolTip  = 'Vérifier maintenant'
    msgNoUpdate     = 'Vous êtes à jour.'
    msgUpdateAvailable = 'Nouvelle version v{0} disponible.'
    cbConfirmCopy   = 'Confirmer avant de copier'
    gbAppearance    = 'Apparence'
    lblTheme        = 'Thème'
    lblLanguage     = 'Langue'
    themeDark       = 'Sombre'
    themeLight      = 'Clair'
    langEnglish     = 'Anglais'
    langFrench      = 'Français'
    langSpanish     = 'Espagnol'
    langItalian     = 'Italien'
    langGerman      = 'Allemand'
    langPortuguese  = 'Portugais'
    langChinese     = 'Chinois'
    langArabic      = 'Arabe'
    btnHistory_ToolTip = 'Historique'
    lblAzureStatusSignedOut = 'Non connecté'
    lblAzureStatusSignedIn  = 'Connecté en tant que {0}'
    msgAzureConnectFirst = "Veuillez d'abord vous connecter à Microsoft Graph."
    msgAzureNoDevices = 'Aucun appareil Intune ne correspond à votre requête.'
    msgAzureMultipleDevices = 'Sélectionnez un appareil pour récupérer le mot de passe.'
    msgAzureInstallModule = 'Le module PowerShell Microsoft.Graph est requis.'
  }
  Spanish = @{
    tabMain         = 'LAPS (AD)'
    tabAzure        = 'LAPS (Intune)'
    tabSettings     = 'Configuración'
    gbCreds         = 'Credenciales'
    gbAD            = 'Destino de Active Directory'
    gbAzureAuth     = 'Autenticación'
    gbAzureDevices  = 'Dispositivos'
    gbSearch        = 'Búsqueda'
    gbDetails       = 'Detalles'
    gbPwd           = 'Contraseña LAPS'
    lblUser         = 'Usuario (usuario@dominio)'
    lblPass         = 'Contraseña'
    lblController   = 'Controlador/Dominio'
    lblCompName     = 'Nombre del equipo'
    btnGet          = 'Obtener'
    btnRetry        = 'Reintentar'
    btnUpdate       = 'Actualizar'
    btnUpdateTo     = 'Actualizar a v{0}'
    btnIgnore       = 'Ignorar'
    cbShow          = 'Mostrar'
    btnCopy         = 'Copiar'
    btnAzureSignIn  = 'Iniciar sesión'
    btnAzureSignOut = 'Cerrar sesión'
    gbSecurity      = 'Seguridad'
    cbLdaps         = 'Usar LDAPS (TLS 636)'
    cbClipboardAutoClear = 'Habilitar borrado automático del portapapeles'
    lblClipboardDelay = 'Retraso del portapapeles (s)'
    gbPrefs         = 'Preferencias'
    cbRememberUser  = 'Recordar usuario'
    cbRememberServer= 'Recordar controlador/dominio'
    cbAutoUpdate    = 'Buscar actualizaciones al iniciar'
    btnCheckUpdate_ToolTip  = 'Buscar ahora'
    msgNoUpdate     = 'Ya está actualizado.'
    msgUpdateAvailable = 'Nueva versión v{0} disponible.'
    cbConfirmCopy   = 'Confirmar antes de copiar'
    gbAppearance    = 'Apariencia'
    lblTheme        = 'Tema'
    lblLanguage     = 'Idioma'
    themeDark       = 'Oscuro'
    themeLight      = 'Claro'
    langEnglish     = 'Inglés'
    langFrench      = 'Francés'
    langSpanish     = 'Español'
    langItalian     = 'Italiano'
    langGerman      = 'Alemán'
    langPortuguese  = 'Portugués'
    langChinese     = 'Chino'
    langArabic      = 'Árabe'
    btnHistory_ToolTip = 'Historial'
    lblAzureStatusSignedOut = 'No conectado'
    lblAzureStatusSignedIn  = 'Conectado como {0}'
    msgAzureConnectFirst = 'Inicie sesión en Microsoft Graph primero.'
    msgAzureNoDevices = 'Ningún dispositivo de Intune coincide con la búsqueda.'
    msgAzureMultipleDevices = 'Seleccione un dispositivo para obtener la contraseña.'
    msgAzureInstallModule = 'Se requiere el módulo de PowerShell Microsoft.Graph.'
  }
  Italian = @{
    tabMain         = 'LAPS (AD)'
    tabAzure        = 'LAPS (Intune)'
    tabSettings     = 'Impostazioni'
    gbCreds         = 'Credenziali'
    gbAD            = 'Destinazione Active Directory'
    gbAzureAuth     = 'Autenticazione'
    gbAzureDevices  = 'Dispositivi'
    gbSearch        = 'Ricerca'
    gbDetails       = 'Dettagli'
    gbPwd           = 'Password LAPS'
    lblUser         = 'Utente (utente@dominio)'
    lblPass         = 'Password'
    lblController   = 'Controller/Dominio'
    lblCompName     = 'Nome del computer'
    btnGet          = 'Recupera'
    btnRetry        = 'Riprova'
    btnUpdate       = 'Aggiorna'
    btnUpdateTo     = 'Aggiorna a v{0}'
    btnIgnore       = 'Ignora'
    cbShow          = 'Mostra'
    btnCopy         = 'Copia'
    btnAzureSignIn  = 'Accedi'
    btnAzureSignOut = 'Disconnetti'
    gbSecurity      = 'Sicurezza'
    cbLdaps         = 'Usa LDAPS (TLS 636)'
    cbClipboardAutoClear = 'Abilita pulizia automatica degli appunti'
    lblClipboardDelay = 'Ritardo appunti (s)'
    gbPrefs         = 'Preferenze'
    cbRememberUser  = 'Ricorda utente'
    cbRememberServer= 'Ricorda controller/dominio'
    cbAutoUpdate    = 'Verifica aggiornamenti all avvio'
    btnCheckUpdate_ToolTip  = 'Verifica ora'
    msgNoUpdate     = 'Sei aggiornato.'
    msgUpdateAvailable = 'Nuova versione v{0} disponibile.'
    cbConfirmCopy   = 'Conferma prima di copiare'
    gbAppearance    = 'Aspetto'
    lblTheme        = 'Tema'
    lblLanguage     = 'Lingua'
    themeDark       = 'Scuro'
    themeLight      = 'Chiaro'
    langEnglish     = 'Inglese'
    langFrench      = 'Francese'
    langSpanish     = 'Spagnolo'
    langItalian     = 'Italiano'
    langGerman      = 'Tedesco'
    langPortuguese  = 'Portoghese'
    langChinese     = 'Cinese'
    langArabic      = 'Arabo'
    btnHistory_ToolTip = 'Cronologia'
    lblAzureStatusSignedOut = 'Non connesso'
    lblAzureStatusSignedIn  = 'Connesso come {0}'
    msgAzureConnectFirst = 'Accedere prima a Microsoft Graph.'
    msgAzureNoDevices = 'Nessun dispositivo Intune corrisponde alla ricerca.'
    msgAzureMultipleDevices = 'Seleziona un dispositivo per recuperare la password.'
    msgAzureInstallModule = 'È necessario il modulo Microsoft.Graph per PowerShell.'
  }
  German = @{
    tabMain         = 'LAPS (AD)'
    tabAzure        = 'LAPS (Intune)'
    tabSettings     = 'Einstellungen'
    gbCreds         = 'Anmeldedaten'
    gbAD            = 'Active Directory Ziel'
    gbAzureAuth     = 'Authentifizierung'
    gbAzureDevices  = 'Geräte'
    gbSearch        = 'Suche'
    gbDetails       = 'Details'
    gbPwd           = 'LAPS Passwort'
    lblUser         = 'Benutzer (benutzer@domäne)'
    lblPass         = 'Passwort'
    lblController   = 'Controller/Domäne'
    lblCompName     = 'Computername'
    btnGet          = 'Abrufen'
    btnRetry        = 'Erneut versuchen'
    btnUpdate       = 'Aktualisieren'
    btnUpdateTo     = 'Aktualisieren auf v{0}'
    btnIgnore       = 'Ignorieren'
    cbShow          = 'Anzeigen'
    btnCopy         = 'Kopieren'
    btnAzureSignIn  = 'Anmelden'
    btnAzureSignOut = 'Abmelden'
    gbSecurity      = 'Sicherheit'
    cbLdaps         = 'LDAPS verwenden (TLS 636)'
    cbClipboardAutoClear = 'Zwischenablage automatisch löschen aktivieren'
    lblClipboardDelay = 'Zwischenablage-Verzögerung (s)'
    gbPrefs         = 'Voreinstellungen'
    cbRememberUser  = 'Benutzer speichern'
    cbRememberServer= 'Controller/Domäne speichern'
    cbAutoUpdate    = 'Beim Start nach Updates suchen'
    btnCheckUpdate_ToolTip  = 'Jetzt prüfen'
    msgNoUpdate     = 'Sie sind auf dem neuesten Stand.'
    msgUpdateAvailable = 'Neue Version v{0} verfügbar.'
    cbConfirmCopy   = 'Vor dem Kopieren bestätigen'
    gbAppearance    = 'Darstellung'
    lblTheme        = 'Design'
    lblLanguage     = 'Sprache'
    themeDark       = 'Dunkel'
    themeLight      = 'Hell'
    langEnglish     = 'Englisch'
    langFrench      = 'Französisch'
    langSpanish     = 'Spanisch'
    langItalian     = 'Italienisch'
    langGerman      = 'Deutsch'
    langPortuguese  = 'Portugiesisch'
    langChinese     = 'Chinesisch'
    langArabic      = 'Arabisch'
    btnHistory_ToolTip = 'Verlauf'
    lblAzureStatusSignedOut = 'Nicht angemeldet'
    lblAzureStatusSignedIn  = 'Als {0} verbunden'
    msgAzureConnectFirst = 'Bitte melden Sie sich zuerst bei Microsoft Graph an.'
    msgAzureNoDevices = 'Keine Intune-Geräte entsprechen Ihrer Suche.'
    msgAzureMultipleDevices = 'Wählen Sie ein Gerät aus, um das Kennwort abzurufen.'
    msgAzureInstallModule = 'Das Microsoft.Graph PowerShell-Modul ist erforderlich.'
  }
  Portuguese = @{
    tabMain         = 'LAPS (AD)'
    tabAzure        = 'LAPS (Intune)'
    tabSettings     = 'Configurações'
    gbCreds         = 'Credenciais'
    gbAD            = 'Destino do Active Directory'
    gbAzureAuth     = 'Autenticação'
    gbAzureDevices  = 'Dispositivos'
    gbSearch        = 'Pesquisar'
    gbDetails       = 'Detalhes'
    gbPwd           = 'Senha LAPS'
    lblUser         = 'Usuário (usuario@domínio)'
    lblPass         = 'Senha'
    lblController   = 'Controlador/Domínio'
    lblCompName     = 'Nome do computador'
    btnGet          = 'Obter'
    btnRetry        = 'Tentar novamente'
    btnUpdate       = 'Atualizar'
    btnUpdateTo     = 'Atualizar para v{0}'
    btnIgnore       = 'Ignorar'
    cbShow          = 'Mostrar'
    btnCopy         = 'Copiar'
    btnAzureSignIn  = 'Entrar'
    btnAzureSignOut = 'Sair'
    gbSecurity      = 'Segurança'
    cbLdaps         = 'Usar LDAPS (TLS 636)'
    cbClipboardAutoClear = 'Ativar limpeza automática da área de transferência'
    lblClipboardDelay = 'Atraso da área de transferência (s)'
    gbPrefs         = 'Preferências'
    cbRememberUser  = 'Lembrar usuário'
    cbRememberServer= 'Lembrar controlador/domínio'
    cbAutoUpdate    = 'Verificar atualizações ao iniciar'
    btnCheckUpdate_ToolTip  = 'Verificar agora'
    msgNoUpdate     = 'Você está atualizado.'
    msgUpdateAvailable = 'Nova versão v{0} disponível.'
    cbConfirmCopy   = 'Confirmar antes de copiar'
    gbAppearance    = 'Aparência'
    lblTheme        = 'Tema'
    lblLanguage     = 'Idioma'
    themeDark       = 'Escuro'
    themeLight      = 'Claro'
    langEnglish     = 'Inglês'
    langFrench      = 'Francês'
    langSpanish     = 'Espanhol'
    langItalian     = 'Italiano'
    langGerman      = 'Alemão'
    langPortuguese  = 'Português'
    langChinese     = 'Chinês'
    langArabic      = 'Árabe'
    btnHistory_ToolTip = 'Histórico'
    lblAzureStatusSignedOut = 'Não conectado'
    lblAzureStatusSignedIn  = 'Conectado como {0}'
    msgAzureConnectFirst = 'Conecte-se primeiro ao Microsoft Graph.'
    msgAzureNoDevices = 'Nenhum dispositivo do Intune corresponde à sua consulta.'
    msgAzureMultipleDevices = 'Selecione um dispositivo para obter a senha.'
    msgAzureInstallModule = 'É necessário o módulo Microsoft.Graph PowerShell.'
  }
  Chinese = @{
    tabMain         = 'LAPS (AD)'
    tabAzure        = 'LAPS (Intune)'
    tabSettings     = '设置'
    gbCreds         = '凭据'
    gbAD            = 'Active Directory 目标'
    gbAzureAuth     = '身份验证'
    gbAzureDevices  = '设备'
    gbSearch        = '搜索'
    gbDetails       = '详细信息'
    gbPwd           = 'LAPS 密码'
    lblUser         = '用户 (用户@域)'
    lblPass         = '密码'
    lblController   = '控制器/域'
    lblCompName     = '计算机名'
    btnGet          = '获取'
    btnRetry        = '重试'
    btnUpdate       = '更新'
    btnUpdateTo     = '更新到 v{0}'
    btnIgnore       = '忽略'
    cbShow          = '显示'
    btnCopy         = '复制'
    btnAzureSignIn  = '登录'
    btnAzureSignOut = '注销'
    gbSecurity      = '安全'
    cbLdaps         = '使用 LDAPS (TLS 636)'
    cbClipboardAutoClear = '启用剪贴板自动清除'
    lblClipboardDelay = '剪贴板延迟 (秒)'
    gbPrefs         = '首选项'
    cbRememberUser  = '记住用户'
    cbRememberServer= '记住控制器/域'
    cbAutoUpdate    = '启动时检查更新'
    btnCheckUpdate_ToolTip  = '立即检查'
    msgNoUpdate     = '已是最新版本。'
    msgUpdateAvailable = '发现新版本 v{0}。'
    cbConfirmCopy   = '复制前确认'
    gbAppearance    = '外观'
    lblTheme        = '主题'
    lblLanguage     = '语言'
    themeDark       = '深色'
    themeLight      = '浅色'
    langEnglish     = '英语'
    langFrench      = '法语'
    langSpanish     = '西班牙语'
    langItalian     = '意大利语'
    langGerman      = '德语'
    langPortuguese  = '葡萄牙语'
    langChinese     = '中文'
    langArabic      = '阿拉伯语'
    btnHistory_ToolTip = '历史'
    lblAzureStatusSignedOut = '未登录'
    lblAzureStatusSignedIn  = '已连接为 {0}'
    msgAzureConnectFirst = '请先登录 Microsoft Graph。'
    msgAzureNoDevices = '没有匹配的 Intune 设备。'
    msgAzureMultipleDevices = '选择一个设备以检索密码。'
    msgAzureInstallModule = '需要 Microsoft.Graph PowerShell 模块。'
  }
  Arabic = @{
    tabMain         = 'LAPS (AD)'
    tabAzure        = 'LAPS (Intune)'
    tabSettings     = 'الإعدادات'
    gbCreds         = 'بيانات الاعتماد'
    gbAD            = 'هدف Active Directory'
    gbAzureAuth     = 'المصادقة'
    gbAzureDevices  = 'الأجهزة'
    gbSearch        = 'بحث'
    gbDetails       = 'تفاصيل'
    gbPwd           = 'كلمة مرور LAPS'
    lblUser         = 'المستخدم (المستخدم@المجال)'
    lblPass         = 'كلمة المرور'
    lblController   = 'المراقب/المجال'
    lblCompName     = 'اسم الكمبيوتر'
    btnGet          = 'استرجاع'
    btnRetry        = 'إعادة المحاولة'
    btnUpdate       = 'تحديث'
    btnUpdateTo     = 'التحديث إلى v{0}'
    btnIgnore       = 'تجاهل'
    cbShow          = 'إظهار'
    btnCopy         = 'نسخ'
    btnAzureSignIn  = 'تسجيل الدخول'
    btnAzureSignOut = 'تسجيل الخروج'
    gbSecurity      = 'الأمان'
    cbLdaps         = 'استخدام LDAPS ‏(TLS 636)'
    cbClipboardAutoClear = 'تمكين المسح التلقائي للحافظة'
    lblClipboardDelay = 'تأخير الحافظة (ث)'
    gbPrefs         = 'التفضيلات'
    cbRememberUser  = 'تذكر المستخدم'
    cbRememberServer= 'تذكر المراقب/المجال'
    cbAutoUpdate    = 'التحقق من التحديثات عند التشغيل'
    btnCheckUpdate_ToolTip  = 'تحقق الآن'
    msgNoUpdate     = 'النظام محدث.'
    msgUpdateAvailable = 'إصدار جديد v{0} متاح.'
    cbConfirmCopy   = 'التأكيد قبل النسخ'
    gbAppearance    = 'المظهر'
    lblTheme        = 'السمة'
    lblLanguage     = 'اللغة'
    themeDark       = 'داكن'
    themeLight      = 'فاتح'
    langEnglish     = 'الإنجليزية'
    langFrench      = 'الفرنسية'
    langSpanish     = 'الإسبانية'
    langItalian     = 'الإيطالية'
    langGerman      = 'الألمانية'
    langPortuguese  = 'البرتغالية'
    langChinese     = 'الصينية'
    langArabic      = 'العربية'
    btnHistory_ToolTip = 'السجل'
    lblAzureStatusSignedOut = 'غير مسجل الدخول'
    lblAzureStatusSignedIn  = 'متصل باسم {0}'
    msgAzureConnectFirst = 'يرجى تسجيل الدخول إلى Microsoft Graph أولاً.'
    msgAzureNoDevices = 'لا توجد أجهزة Intune مطابقة لطلبك.'
    msgAzureMultipleDevices = 'حدد جهازًا لاسترجاع كلمة المرور.'
    msgAzureInstallModule = 'مطلوب وحدة Microsoft.Graph الخاصة بـ PowerShell.'
  }
}

function Apply-Language {
  param([string]$Language)
  if (-not $Language -or -not $translations.ContainsKey($Language)) { $Language = 'English' }
  $script:t = $translations[$Language]
  $tabMain.Header       = $t.tabMain
  if ($tabAzure) { $tabAzure.Header = $t.tabAzure }
  $tabSettings.Header   = $t.tabSettings
  $gbCreds.Header       = $t.gbCreds
  $gbAD.Header          = $t.gbAD
  $gbSearch.Header      = $t.gbSearch
  $gbDetails.Header     = $t.gbDetails
  $gbPwd.Header         = $t.gbPwd
  if ($gbAzureAuth) { $gbAzureAuth.Header = $t.gbAzureAuth }
  if ($gbAzureSearch) { $gbAzureSearch.Header = $t.gbSearch }
  if ($gbAzureDevices) { $gbAzureDevices.Header = $t.gbAzureDevices }
  if ($gbAzureDetails) { $gbAzureDetails.Header = $t.gbDetails }
  if ($gbAzurePwd) { $gbAzurePwd.Header = $t.gbPwd }
  $lblUser.Text         = $t.lblUser
  $lblPass.Text         = $t.lblPass
  $lblController.Text   = $t.lblController
  $lblCompName.Text     = $t.lblCompName
  if ($lblAzureDeviceName) { $lblAzureDeviceName.Text = $t.lblCompName }
  $btnGet.Content       = $t.btnGet
  $btnRetry.Content     = $t.btnRetry
  $btnUpdate.Content    = $t.btnUpdate
  $btnIgnore.Content    = $t.btnIgnore
  $cbShow.Content       = $t.cbShow
  $btnCopy.Content      = $t.btnCopy
  if ($btnAzureSearch) { $btnAzureSearch.Content = $t.btnGet }
  if ($btnAzureCopy) { $btnAzureCopy.Content = $t.btnCopy }
  if ($cbAzureShow) { $cbAzureShow.Content = $t.cbShow }
  if ($btnAzureSignIn) { $btnAzureSignIn.Content = $t.btnAzureSignIn }
  if ($btnAzureSignOut) { $btnAzureSignOut.Content = $t.btnAzureSignOut }
  $gbSecurity.Header    = $t.gbSecurity
  $cbLdaps.Content      = $t.cbLdaps
  $cbClipboardAutoClear.Content = $t.cbClipboardAutoClear
  $lblClipboardDelay.Text = $t.lblClipboardDelay
  $gbPrefs.Header       = $t.gbPrefs
  $cbRememberUser.Content = $t.cbRememberUser
  $cbRememberServer.Content = $t.cbRememberServer
  $cbAutoUpdate.Content = $t.cbAutoUpdate
  $btnCheckUpdate.ToolTip = $t.btnCheckUpdate_ToolTip
  $cbConfirmCopy.Content = $t.cbConfirmCopy
  $gbAppearance.Header  = $t.gbAppearance
  $lblTheme.Text        = $t.lblTheme
  $lblLanguage.Text     = $t.lblLanguage
  ($cmbTheme.Items[0]).Content = $t.themeDark
  ($cmbTheme.Items[1]).Content = $t.themeLight
  foreach ($item in $cmbLanguage.Items) {
    switch ($item.Tag) {
      'English'    { $item.Content = $t.langEnglish }
      'French'     { $item.Content = $t.langFrench }
      'Spanish'    { $item.Content = $t.langSpanish }
      'Italian'    { $item.Content = $t.langItalian }
      'German'     { $item.Content = $t.langGerman }
      'Portuguese' { $item.Content = $t.langPortuguese }
      'Chinese'    { $item.Content = $t.langChinese }
      'Arabic'     { $item.Content = $t.langArabic }
    }
  }
  $btnHistory.ToolTip   = $t.btnHistory_ToolTip
  if ($btnAzureHistory) { $btnAzureHistory.ToolTip = $t.btnHistory_ToolTip }
  Update-AzureStatusLabel
  if ($btnUpdate.Visibility -eq 'Visible' -and $script:LastUpdateInfo) {
    $btnUpdate.Content = $t.btnUpdateTo -f $script:LastUpdateInfo.Version
    $lblUpdateStatus.Text = $t.msgUpdateAvailable -f $script:LastUpdateInfo.Version
  } elseif ($lblUpdateStatus.Text) {
    $lblUpdateStatus.Text = $t.msgNoUpdate
  }
}

# Controls
$tabMain       = $window.FindName("tabMain")
$tabAzure      = $window.FindName("tabAzure")
$tabSettings   = $window.FindName("tabSettings")
$gbCreds       = $window.FindName("gbCreds")
$gbAD          = $window.FindName("gbAD")
$gbSearch      = $window.FindName("gbSearch")
$gbPwd         = $window.FindName("gbPwd")
$gbAzureAuth   = $window.FindName("gbAzureAuth")
$gbAzureSearch = $window.FindName("gbAzureSearch")
$gbAzureDevices= $window.FindName("gbAzureDevices")
$gbAzureDetails= $window.FindName("gbAzureDetails")
$gbAzurePwd    = $window.FindName("gbAzurePwd")
$gbSecurity    = $window.FindName("gbSecurity")
$gbPrefs       = $window.FindName("gbPrefs")
$gbAppearance  = $window.FindName("gbAppearance")
$lblUser       = $window.FindName("lblUser")
$lblPass       = $window.FindName("lblPass")
$lblController = $window.FindName("lblController")
$lblCompName   = $window.FindName("lblCompName")
$lblAzureDeviceName = $window.FindName("lblAzureDeviceName")
$lblAzureStatus = $window.FindName("lblAzureStatus")
$lblClipboardDelay = $window.FindName("lblClipboardDelay")
$lblTheme      = $window.FindName("lblTheme")
$lblLanguage   = $window.FindName("lblLanguage")
$tbUser         = $window.FindName("tbUser")
$pbPass         = $window.FindName("pbPass")
$tbServer       = $window.FindName("tbServer")
$cbLdaps        = $window.FindName("cbLdaps")
$tbComp         = $window.FindName("tbComp")
$popCompSuggest = $window.FindName("popCompSuggest")
$lbCompSuggest  = $window.FindName("lbCompSuggest")
$btnHistory     = $window.FindName("btnHistory")
$btnGet         = $window.FindName("btnGet")
$btnRetry       = $window.FindName("btnRetry")
$tbAzureDevice  = $window.FindName("tbAzureDevice")
$btnAzureHistory= $window.FindName("btnAzureHistory")
$popAzureDevice = $window.FindName("popAzureDevice")
$lbAzureDeviceHistory = $window.FindName("lbAzureDeviceHistory")
$btnAzureSearch = $window.FindName("btnAzureSearch")
$lbAzureDevices = $window.FindName("lbAzureDevices")
$gbDetails      = $window.FindName("gbDetails")
$txtDetails     = $window.FindName("txtDetails")
$spExpire       = $window.FindName("spExpire")
$ellExpire      = $window.FindName("ellExpire")
$lblExpire      = $window.FindName("lblExpire")
$txtAzureDetails= $window.FindName("txtAzureDetails")
$spAzureExpire  = $window.FindName("spAzureExpire")
$ellAzureExpire = $window.FindName("ellAzureExpire")
$lblAzureExpire = $window.FindName("lblAzureExpire")
$rtbAzurePwd    = $window.FindName("rtbAzurePwd")
$pbAzurePwd     = $window.FindName("pbAzurePwd")
$cbAzureShow    = $window.FindName("cbAzureShow")
$btnAzureCopy   = $window.FindName("btnAzureCopy")
$lblAzureCountdown = $window.FindName("lblAzureCountdown")
$btnAzureSignIn = $window.FindName("btnAzureSignIn")
$btnAzureSignOut= $window.FindName("btnAzureSignOut")
$rtbPwdOut      = $window.FindName("rtbPwdOut")   # NEW
$pbPwdOut       = $window.FindName("pbPwdOut")
$cbShow         = $window.FindName("cbShow")
$btnCopy        = $window.FindName("btnCopy")
$lblCountdown   = $window.FindName("lblCountdown")
$tbClipboardSecs = $window.FindName("tbClipboardSecs")
$cbClipboardAutoClear = $window.FindName("cbClipboardAutoClear")
$cbRememberUser = $window.FindName("cbRememberUser")
$cbRememberServer = $window.FindName("cbRememberServer")
$cbAutoUpdate   = $window.FindName("cbAutoUpdate")
$btnCheckUpdate = $window.FindName("btnCheckUpdate")
$lblUpdateStatus = $window.FindName("lblUpdateStatus")
$cbConfirmCopy  = $window.FindName("cbConfirmCopy")
$cmbTheme       = $window.FindName("cmbTheme")
$cmbLanguage    = $window.FindName("cmbLanguage")
$btnUpdate     = $window.FindName("btnUpdate")
$btnIgnore     = $window.FindName("btnIgnore")

# Init
$cbLdaps.IsChecked = $UseLdaps
$script:UseLdaps   = [bool]$cbLdaps.IsChecked
$script:LastUpdateInfo = $null
$tbClipboardSecs.Text = $script:ClipboardAutoClearSeconds
$script:AdState = New-LapsUiState -Name 'AD' -PasswordBox $pbPwdOut -RichTextBox $rtbPwdOut -ShowCheckBox $cbShow -CopyButton $btnCopy -CountdownLabel $lblCountdown -ExpirePanel $spExpire -ExpireEllipse $ellExpire -ExpireLabel $lblExpire
$script:AzureState = New-LapsUiState -Name 'Azure' -PasswordBox $pbAzurePwd -RichTextBox $rtbAzurePwd -ShowCheckBox $cbAzureShow -CopyButton $btnAzureCopy -CountdownLabel $lblAzureCountdown -ExpirePanel $spAzureExpire -ExpireEllipse $ellAzureExpire -ExpireLabel $lblAzureExpire
$script:AzureState | Add-Member -NotePropertyName IsConnected -NotePropertyValue $false
$script:AzureState | Add-Member -NotePropertyName Account -NotePropertyValue $null
$script:AzureState | Add-Member -NotePropertyName TenantId -NotePropertyValue $null
$script:AzureState | Add-Member -NotePropertyName DeviceResults -NotePropertyValue @()
$script:AzureState | Add-Member -NotePropertyName IsConnecting -NotePropertyValue $false
Refresh-LapsDisplay $script:AdState
Refresh-LapsDisplay $script:AzureState
if ($script:AdState.CopyButton) { $script:AdState.CopyButton.IsEnabled = $false }
if ($script:AzureState.CopyButton) { $script:AzureState.CopyButton.IsEnabled = $false }

# --- Prefs (unchanged from your version) ---
$PrefDir  = Join-Path $env:LOCALAPPDATA 'LAPS-UI'
$PrefFile = Join-Path $PrefDir 'prefs.json'
New-Item -Path $PrefDir -ItemType Directory -Force | Out-Null
$script:Prefs = @{}

function Protect-String { param([string]$Text) if ([string]::IsNullOrWhiteSpace($Text)) { return $null } $sec = ConvertTo-SecureString $Text -AsPlainText -Force; ConvertFrom-SecureString $sec }
function Unprotect-String {
  param([string]$Cipher)
  if ([string]::IsNullOrWhiteSpace($Cipher)) { return $null }
  try {
    $sec = ConvertTo-SecureString $Cipher -ErrorAction Stop
    [Runtime.InteropServices.Marshal]::PtrToStringUni(
      [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
    )
  } catch {
    $Cipher
  }
}

function Save-Prefs {
  $secs = 0
  if ([int]::TryParse($tbClipboardSecs.Text, [ref]$secs) -and $secs -gt 0) {
    $script:ClipboardAutoClearSeconds = $secs
  }
  $adHistory = $script:Prefs.AdHistory
  $azureHistory = $script:Prefs.AzureHistory
  $ignore  = $script:Prefs.IgnoreVersion
  $script:Prefs = @{
    RememberUser        = [bool]$cbRememberUser.IsChecked
    UserName            = $(if ($cbRememberUser.IsChecked)   { Protect-String $tbUser.Text } else { $null })
    RememberServer      = [bool]$cbRememberServer.IsChecked
    ServerName          = $(if ($cbRememberServer.IsChecked) { Protect-String $tbServer.Text } else { $null })
    UseLdaps            = [bool]$cbLdaps.IsChecked
    AutoClearClipboard  = [bool]$cbClipboardAutoClear.IsChecked
    ClipboardSeconds    = $script:ClipboardAutoClearSeconds
    AutoUpdate          = [bool]$cbAutoUpdate.IsChecked
    ConfirmCopy         = [bool]$cbConfirmCopy.IsChecked
    Theme               = $cmbTheme.SelectedItem.Tag
    Language            = $cmbLanguage.SelectedItem.Tag
    AdHistory           = $adHistory
    AzureHistory        = $azureHistory
    IgnoreVersion       = $ignore
  }
  $persist = $script:Prefs.Clone()
  $persist.AdHistory = @($adHistory | ForEach-Object { Protect-String $_ })
  $persist.AzureHistory = @($azureHistory | ForEach-Object { Protect-String $_ })
  ($persist | ConvertTo-Json -Compress) | Set-Content -Path $PrefFile -Encoding UTF8
}
function Load-Prefs {
  $script:Prefs = @{}
  if (Test-Path $PrefFile) {
    try {
      $loaded = Get-Content $PrefFile -Raw | ConvertFrom-Json
      if ($loaded.RememberUser) { $cbRememberUser.IsChecked = $true; if ($loaded.UserName) { $tbUser.Text = Unprotect-String $loaded.UserName } }
      if ($loaded.RememberServer) { $cbRememberServer.IsChecked = $true; if ($loaded.ServerName) { $tbServer.Text = Unprotect-String $loaded.ServerName } }
      if ($null -ne $loaded.UseLdaps) { $cbLdaps.IsChecked = [bool]$loaded.UseLdaps }
      if ($null -ne $loaded.AutoClearClipboard) { $cbClipboardAutoClear.IsChecked = [bool]$loaded.AutoClearClipboard }
      if ($loaded.ClipboardSeconds) { $script:ClipboardAutoClearSeconds = [int]$loaded.ClipboardSeconds }
      if ($null -ne $loaded.AutoUpdate) { $cbAutoUpdate.IsChecked = [bool]$loaded.AutoUpdate }
      if ($null -ne $loaded.ConfirmCopy) { $cbConfirmCopy.IsChecked = [bool]$loaded.ConfirmCopy }
      if ($loaded.Theme) { $cmbTheme.SelectedItem = $cmbTheme.Items | Where-Object { $_.Tag -eq $loaded.Theme } }
      if ($loaded.Language) { $cmbLanguage.SelectedItem = $cmbLanguage.Items | Where-Object { $_.Tag -eq $loaded.Language } }
      $adHist = @()
      $rawAd = if ($loaded.PSObject.Properties.Name -contains 'AdHistory') { $loaded.AdHistory } else { $loaded.History }
      if ($rawAd -is [System.Collections.IEnumerable]) {
        foreach ($enc in $rawAd) {
          $dec = Unprotect-String $enc
          if ($dec) { $adHist += $dec }
        }
      }
      $azureHist = @()
      if ($loaded.AzureHistory -is [System.Collections.IEnumerable]) {
        foreach ($enc in $loaded.AzureHistory) {
          $dec = Unprotect-String $enc
          if ($dec) { $azureHist += $dec }
        }
      }
      $script:Prefs = $loaded
      $script:Prefs.AdHistory = $adHist
      $script:Prefs.AzureHistory = $azureHist
    } catch { $script:Prefs = @{} }
  }
  if (-not $script:Prefs.AdHistory) { $script:Prefs.AdHistory = @() }
  if (-not $script:Prefs.AzureHistory) { $script:Prefs.AzureHistory = @() }
  $tbClipboardSecs.Text = $script:ClipboardAutoClearSeconds
  $script:UseLdaps = [bool]$cbLdaps.IsChecked
}
Load-Prefs
Apply-Theme $cmbTheme.SelectedItem.Tag
Apply-Language $(if ($cmbLanguage.SelectedItem) { $cmbLanguage.SelectedItem.Tag } else { 'English' })
$tbComp.IsEnabled     = -not [string]::IsNullOrWhiteSpace($pbPass.Password)
$btnHistory.IsEnabled = -not [string]::IsNullOrWhiteSpace($pbPass.Password)
$pbPass.Add_PasswordChanged({
    $tbComp.IsEnabled     = -not [string]::IsNullOrWhiteSpace($pbPass.Password)
    $btnHistory.IsEnabled = -not [string]::IsNullOrWhiteSpace($pbPass.Password)
})
$cbRememberUser.Add_Checked({ Save-Prefs })
$cbRememberUser.Add_Unchecked({ Save-Prefs })
$tbUser.Add_LostFocus({ if ($cbRememberUser.IsChecked) { Save-Prefs } })
$cbRememberServer.Add_Checked({ Save-Prefs })
$cbRememberServer.Add_Unchecked({ Save-Prefs })
$tbServer.Add_LostFocus({ if ($cbRememberServer.IsChecked) { Save-Prefs } })
$window.Add_Closed({ Save-Prefs })

$cbLdaps.Add_Checked({   $script:UseLdaps = $true;  Save-Prefs })
$cbLdaps.Add_Unchecked({ $script:UseLdaps = $false; Save-Prefs })
$tbClipboardSecs.Add_LostFocus({ Save-Prefs })
$cbClipboardAutoClear.Add_Checked({ Save-Prefs })
$cbClipboardAutoClear.Add_Unchecked({ Save-Prefs })
$cbAutoUpdate.Add_Checked({ Save-Prefs })
$cbAutoUpdate.Add_Unchecked({ Save-Prefs })
$btnCheckUpdate.Add_Click({
  $info = Check-ForUpdates -CurrentVersion $CurrentVersion
  if ($info) {
    Show-UpdatePrompt $info
    $lblUpdateStatus.Text = $t.msgUpdateAvailable -f $info.Version
  } else {
    $script:LastUpdateInfo = $null
    $btnUpdate.Visibility='Collapsed'
    $btnIgnore.Visibility='Collapsed'
    $lblUpdateStatus.Text = $t.msgNoUpdate
  }
})
$cbConfirmCopy.Add_Checked({ Save-Prefs })
$cbConfirmCopy.Add_Unchecked({ Save-Prefs })
$cmbTheme.Add_SelectionChanged({ Apply-Theme $cmbTheme.SelectedItem.Tag; Save-Prefs })
$cmbLanguage.Add_SelectionChanged({ Apply-Language $cmbLanguage.SelectedItem.Tag; Save-Prefs })
$tbComp.Add_TextChanged({
    Update-ComputerSuggestions $tbComp.Text
    if ($gbDetails.Visibility -ne 'Collapsed') {
        $gbDetails.Visibility = 'Collapsed'
    }
    $txtDetails.Text = ""
    Clear-LapsPassword $script:AdState
    Update-ExpirationIndicator $script:AdState $null
    $window.UpdateLayout()
})
$lbCompSuggest.Add_MouseLeftButtonUp({
    if ($lbCompSuggest.SelectedItem) {
        $tbComp.Text = $lbCompSuggest.SelectedItem
        $popCompSuggest.IsOpen = $false
        $tbComp.Focus(); $tbComp.CaretIndex = $tbComp.Text.Length
    }
})
$lbCompSuggest.Add_KeyDown({
    if ($_.Key -eq 'Return' -and $lbCompSuggest.SelectedItem) {
        $tbComp.Text = $lbCompSuggest.SelectedItem
        $popCompSuggest.IsOpen = $false
        $tbComp.Focus(); $tbComp.CaretIndex = $tbComp.Text.Length
    } elseif ($_.Key -eq 'Escape') {
        $popCompSuggest.IsOpen = $false
        $tbComp.Focus()
    }
})

$btnHistory.Add_Click({
    if ($script:Prefs.AdHistory -and $script:Prefs.AdHistory.Count -gt 0) {
        $lbCompSuggest.ItemsSource = $script:Prefs.AdHistory
        $lbCompSuggest.SelectedIndex = 0
        $popCompSuggest.IsOpen = $true
        $lbCompSuggest.Focus()
    }
})

# ---------- NEW: colorized clear-text rendering ----------
# Pre-create brushes
$bc = New-Object Windows.Media.BrushConverter
$BrushDigits   = $bc.ConvertFromString("#81D4FA")   # light blue
$BrushLetters  = $bc.ConvertFromString("#C5E1A5")   # light green
$BrushSymbols  = $bc.ConvertFromString("#FFB74D")   # orange
$BrushDefault  = $bc.ConvertFromString("#EEEEEE")

function New-LapsUiState {
  param(
    [string]$Name,
    [System.Windows.Controls.PasswordBox]$PasswordBox,
    [System.Windows.Controls.RichTextBox]$RichTextBox,
    [System.Windows.Controls.CheckBox]$ShowCheckBox,
    [System.Windows.Controls.Button]$CopyButton,
    [System.Windows.Controls.TextBlock]$CountdownLabel,
    [System.Windows.Controls.StackPanel]$ExpirePanel,
    [System.Windows.Shapes.Ellipse]$ExpireEllipse,
    [System.Windows.Controls.TextBlock]$ExpireLabel)

  $state = [pscustomobject]@{
    Name               = $Name
    CurrentPassword    = ""
    ClipboardSnapshot  = ""
    PasswordBox        = $PasswordBox
    RichTextBox        = $RichTextBox
    ShowCheckBox       = $ShowCheckBox
    CopyButton         = $CopyButton
    CountdownLabel     = $CountdownLabel
    CountdownRemaining = 0
    Timer              = New-Object System.Windows.Threading.DispatcherTimer
    DoneTimer          = $null
    ExpirePanel        = $ExpirePanel
    ExpireEllipse      = $ExpireEllipse
    ExpireLabel        = $ExpireLabel
  }
  $state.Timer.Interval = [TimeSpan]::FromSeconds(1)
  $state.Timer.Tag = $state
  $state.Timer.Add_Tick({
    param($sender,$eventArgs)
    $st = $sender.Tag
    if (-not $st) { return }
    if ($st.CountdownRemaining -gt 0) {
      $st.CountdownRemaining--
      if ($st.CountdownLabel) {
        $st.CountdownLabel.Text = "Clipboard cleared in $($st.CountdownRemaining)s"
      }
      if ($st.CountdownRemaining -le 0) {
        try {
          if ([System.Windows.Clipboard]::ContainsText()) {
            $txt = [System.Windows.Clipboard]::GetText()
            if ($txt -and $txt -eq $st.ClipboardSnapshot) {
              [System.Windows.Clipboard]::Clear()
            }
          }
        } catch {}
        $sender.Stop()
        if ($st.CountdownLabel) {
          $st.CountdownLabel.Text = 'Clipboard cleared'
          $st.CountdownLabel.Foreground = 'LimeGreen'
        }
        if ($st.DoneTimer) { $st.DoneTimer.Stop(); $st.DoneTimer = $null }
        $st.DoneTimer = New-Object System.Windows.Threading.DispatcherTimer
        $st.DoneTimer.Interval = [TimeSpan]::FromSeconds(2)
        $st.DoneTimer.Tag = $st
        $st.DoneTimer.Add_Tick({
          param($s,$e)
          $stateRef = $s.Tag
          $s.Stop()
          if ($stateRef -and $stateRef.CountdownLabel) {
            $stateRef.CountdownLabel.Visibility = 'Collapsed'
            $stateRef.CountdownLabel.Foreground = '#FFA07A'
          }
          if ($stateRef) {
            $stateRef.DoneTimer = $null
          }
        })
        $st.DoneTimer.Start()
      }
    } else {
      $sender.Stop()
      if ($st.CountdownLabel) {
        $st.CountdownLabel.Visibility = 'Collapsed'
      }
    }
  })
  $state
}

function Update-LapsPasswordDisplay {
  param([pscustomobject]$State,[string]$Password)
  if (-not $State -or -not $State.RichTextBox) { return }
  $pwd = if ($Password) { [string]$Password } else { "" }
  $doc = New-Object System.Windows.Documents.FlowDocument
  $doc.PagePadding = [Windows.Thickness]::new(0)
  $p = New-Object System.Windows.Documents.Paragraph
  $p.Margin = [Windows.Thickness]::new(0)
  $p.LineHeight = 28
  if ($pwd.Length -gt 0) {
    foreach ($ch in $pwd.ToCharArray()) {
      $run = New-Object System.Windows.Documents.Run ($ch)
      switch -regex ($ch) {
        '^[0-9]$'        { $run.Foreground = $BrushDigits;  break }
        '^[A-Za-z]$'     { $run.Foreground = $BrushLetters; break }
        default          { $run.Foreground = $BrushSymbols; break }
      }
      $p.Inlines.Add($run) | Out-Null
    }
  }
  $doc.Blocks.Clear()
  if ($pwd.Length -gt 0) {
    $doc.Blocks.Add($p) | Out-Null
  }
  $State.RichTextBox.Document = $doc
}

function Refresh-LapsDisplay {
  param([pscustomobject]$State)
  if (-not $State) { return }
  $pwd = if ($State.CurrentPassword) { $State.CurrentPassword } else { "" }
  if ($State.PasswordBox) { $State.PasswordBox.Password = $pwd }
  if ($State.ShowCheckBox -and $State.ShowCheckBox.IsChecked) {
    Update-LapsPasswordDisplay $State $pwd
    if ($State.RichTextBox) { $State.RichTextBox.Visibility = 'Visible' }
    if ($State.PasswordBox) { $State.PasswordBox.Visibility = 'Collapsed' }
  } else {
    if ($State.PasswordBox) { $State.PasswordBox.Visibility = 'Visible' }
    if ($State.RichTextBox) { $State.RichTextBox.Visibility = 'Collapsed' }
  }
}

function Set-LapsPassword {
  param([pscustomobject]$State,[string]$Password)
  if (-not $State) { return }
  $State.CurrentPassword = if ($Password) { [string]$Password } else { "" }
  Refresh-LapsDisplay $State
  if ($State.CopyButton) {
    $State.CopyButton.IsEnabled = -not [string]::IsNullOrWhiteSpace($State.CurrentPassword)
  }
}

function Clear-LapsPassword {
  param([pscustomobject]$State)
  if (-not $State) { return }
  $State.CurrentPassword = ""
  if ($State.PasswordBox) { $State.PasswordBox.Password = "" }
  if ($State.RichTextBox) { $State.RichTextBox.Document.Blocks.Clear() }
  Refresh-LapsDisplay $State
  if ($State.CopyButton) { $State.CopyButton.IsEnabled = $false }
  Stop-LapsCountdown $State
}

function Stop-LapsCountdown {
  param([pscustomobject]$State)
  if (-not $State) { return }
  if ($State.Timer) { $State.Timer.Stop() }
  if ($State.DoneTimer) { $State.DoneTimer.Stop(); $State.DoneTimer = $null }
  $State.CountdownRemaining = 0
  $State.ClipboardSnapshot = ""
  if ($State.CountdownLabel) {
    $State.CountdownLabel.Visibility = 'Collapsed'
    $State.CountdownLabel.Foreground = '#FFA07A'
    $State.CountdownLabel.Text = ""
  }
}

function Copy-LapsPassword {
  param([pscustomobject]$State)
  if (-not $State) { return }
  $pwd = $State.CurrentPassword
  if ([string]::IsNullOrWhiteSpace($pwd)) { return }
  if ($cbConfirmCopy.IsChecked) {
    $res = [System.Windows.MessageBox]::Show("Copy password to clipboard?","Confirm",'YesNo','Question')
    if ($res -ne 'Yes') { return }
  }
  $usedWinRT = $false
  try {
    $winRtSupported = [Windows.Foundation.Metadata.ApiInformation]::IsMethodPresent(
      "Windows.ApplicationModel.DataTransfer.Clipboard", "SetContentWithOptions")
    if ($winRtSupported) {
      $dp = New-Object Windows.ApplicationModel.DataTransfer.DataPackage
      $dp.RequestedOperation = [Windows.ApplicationModel.DataTransfer.DataPackageOperation]::Copy
      $dp.SetText($pwd)
      $opt = New-Object Windows.ApplicationModel.DataTransfer.ClipboardContentOptions
      $opt.IsAllowedInHistory = $false; $opt.IsRoamingEnabled = $false
      [Windows.ApplicationModel.DataTransfer.Clipboard]::SetContentWithOptions($dp,$opt)
      [Windows.ApplicationModel.DataTransfer.Clipboard]::Flush()
      $usedWinRT = $true
    }
  } catch {}
  if (-not $usedWinRT) { [System.Windows.Clipboard]::SetText($pwd) }

  [System.Windows.MessageBox]::Show(("Password copied {0} clipboard history." -f ($(if($usedWinRT){'without entering'}else{'into'}))),
    "Copied",'OK','Information') | Out-Null

  if ($cbClipboardAutoClear.IsChecked) {
    Stop-LapsCountdown $State
    $State.ClipboardSnapshot = $pwd
    $State.CountdownRemaining = $script:ClipboardAutoClearSeconds
    if ($State.CountdownLabel) {
      $State.CountdownLabel.Text = "Clipboard cleared in $($State.CountdownRemaining)s"
      $State.CountdownLabel.Foreground = '#FFA07A'
      $State.CountdownLabel.Visibility = 'Visible'
    }
    if ($State.Timer) { $State.Timer.Stop(); $State.Timer.Start() }
  } else {
    Stop-LapsCountdown $State
  }
}

function Update-ExpirationIndicator {
  param([pscustomobject]$State,[nullable[DateTime]]$Expiration)
  if (-not $State -or -not $State.ExpirePanel) { return }
  if ($null -eq $Expiration) {
    $State.ExpirePanel.Visibility = 'Collapsed'
    if ($State.ExpireLabel) { $State.ExpireLabel.Text = '' }
    return
  }
  $now = Get-Date
  $State.ExpirePanel.Visibility = 'Visible'
  if ($Expiration -lt $now) {
    if ($State.ExpireEllipse) { $State.ExpireEllipse.Fill = 'Red' }
    if ($State.ExpireLabel) { $State.ExpireLabel.Text = "Expired on $Expiration" }
  } elseif (($Expiration - $now).TotalDays -le 2) {
    if ($State.ExpireEllipse) { $State.ExpireEllipse.Fill = 'Orange' }
    if ($State.ExpireLabel) { $State.ExpireLabel.Text = "Expires soon ($Expiration)" }
  } else {
    if ($State.ExpireEllipse) { $State.ExpireEllipse.Fill = 'LimeGreen' }
    if ($State.ExpireLabel) { $State.ExpireLabel.Text = "Expires on $Expiration" }
  }
}

function Reset-FailedAuthCount {
  $script:FailedAuthCount = 0
  if ($script:LockoutTimer) {
    $script:LockoutTimer.Stop()
    $script:LockoutTimer.Dispose()
    $script:LockoutTimer = $null
  }
  if ($btnRetry) {
    $window.Dispatcher.Invoke({
      $btnRetry.Visibility = 'Collapsed'
      $btnGet.IsEnabled = $true
    })
  }
}

# Show/Hide clear text
if ($cbShow) {
  $cbShow.Tag = $script:AdState
  $cbShow.Add_Checked({ param($sender,$e) Refresh-LapsDisplay $sender.Tag })
  $cbShow.Add_Unchecked({ param($sender,$e) Refresh-LapsDisplay $sender.Tag })
}
if ($cbAzureShow) {
  $cbAzureShow.Tag = $script:AzureState
  $cbAzureShow.Add_Checked({ param($sender,$e) Refresh-LapsDisplay $sender.Tag })
  $cbAzureShow.Add_Unchecked({ param($sender,$e) Refresh-LapsDisplay $sender.Tag })
}

# ---------- Copy handlers ----------
if ($btnCopy) {
  $btnCopy.Tag = $script:AdState
  $btnCopy.Add_Click({ param($sender,$e) Copy-LapsPassword $sender.Tag })
}
if ($btnAzureCopy) {
  $btnAzureCopy.Tag = $script:AzureState
  $btnAzureCopy.Add_Click({ param($sender,$e) Copy-LapsPassword $sender.Tag })
}

# ---------- Azure helpers ----------
function Update-AzureStatusLabel {
  if (-not $lblAzureStatus -or -not $script:t) { return }
  $connected = ($script:AzureState -and $script:AzureState.IsConnected)
  if ($connected) {
    $acct = $script:AzureState.Account
    if ([string]::IsNullOrWhiteSpace($acct)) { $acct = '' }
    $lblAzureStatus.Text = $script:t.lblAzureStatusSignedIn -f $acct
    if ($btnAzureSignIn) { $btnAzureSignIn.Visibility = 'Collapsed' }
    if ($btnAzureSignOut) { $btnAzureSignOut.Visibility = 'Visible'; $btnAzureSignOut.IsEnabled = $true }
    if ($btnAzureSearch) { $btnAzureSearch.IsEnabled = $true }
  } else {
    $lblAzureStatus.Text = $script:t.lblAzureStatusSignedOut
    if ($btnAzureSignIn) { $btnAzureSignIn.Visibility = 'Visible'; $btnAzureSignIn.IsEnabled = -not ($script:AzureState -and $script:AzureState.IsConnecting) }
    if ($btnAzureSignOut) { $btnAzureSignOut.Visibility = 'Collapsed' }
    if ($btnAzureSearch) { $btnAzureSearch.IsEnabled = $false }
  }
  if ($btnAzureSignIn -and $script:AzureState -and $script:AzureState.IsConnecting) {
    $btnAzureSignIn.IsEnabled = $false
  }
  if ($btnAzureSearch -and $script:AzureState -and $script:AzureState.IsConnecting) {
    $btnAzureSearch.IsEnabled = $false
  }
}

# Azure events
if ($btnAzureSignIn) {
  $btnAzureSignIn.Add_Click({
    try {
      if ($script:AzureState) { $script:AzureState.IsConnecting = $true }
      Update-AzureStatusLabel
      $window.Cursor = 'Wait'
      Connect-IntuneGraph -Scopes @('DeviceManagementManagedDevices.Read.All') | Out-Null
    } catch {
      $msg = $_.Exception.Message
      if ($msg -eq 'GraphModuleMissing') { $msg = $script:t.msgAzureInstallModule }
      [System.Windows.MessageBox]::Show("Graph sign-in failed: $msg", 'Microsoft Graph', 'OK', 'Error') | Out-Null
      if ($script:AzureState) { $script:AzureState.IsConnected = $false }
    } finally {
      $window.Cursor = 'Arrow'
      if ($script:AzureState) { $script:AzureState.IsConnecting = $false }
      Update-AzureStatusLabel
    }
  })
}

if ($btnAzureSignOut) {
  $btnAzureSignOut.Add_Click({
    Disconnect-IntuneGraph
    Clear-LapsPassword $script:AzureState
    Update-ExpirationIndicator $script:AzureState $null
    if ($txtAzureDetails) { $txtAzureDetails.Text = '' }
    if ($gbAzureDetails) { $gbAzureDetails.Visibility = 'Collapsed' }
    if ($gbAzureDevices) { $gbAzureDevices.Visibility = 'Collapsed' }
    if ($lbAzureDevices) { $lbAzureDevices.ItemsSource = @() }
    if ($script:AzureState) { $script:AzureState.DeviceResults = @() }
    if ($popAzureDevice) { $popAzureDevice.IsOpen = $false }
  })
}

if ($tbAzureDevice) {
  $tbAzureDevice.Add_TextChanged({
    if ($gbAzureDetails) { $gbAzureDetails.Visibility = 'Collapsed' }
    if ($gbAzureDevices) { $gbAzureDevices.Visibility = 'Collapsed' }
    if ($txtAzureDetails) { $txtAzureDetails.Text = '' }
    Clear-LapsPassword $script:AzureState
    Update-ExpirationIndicator $script:AzureState $null
    if ($popAzureDevice) { $popAzureDevice.IsOpen = $false }
    if ($script:AzureState) { $script:AzureState.DeviceResults = @() }
  })
  $tbAzureDevice.Add_KeyDown({
    if ($_.Key -eq 'Return') {
      if ($btnAzureSearch -and $btnAzureSearch.IsEnabled) {
        $btnAzureSearch.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Button]::ClickEvent)))
      }
    } elseif ($_.Key -eq 'Down' -and $popAzureDevice -and $popAzureDevice.IsOpen -and $lbAzureDeviceHistory -and $lbAzureDeviceHistory.Items.Count -gt 0) {
      $lbAzureDeviceHistory.Focus()
      if ($lbAzureDeviceHistory.SelectedIndex -lt 0) { $lbAzureDeviceHistory.SelectedIndex = 0 }
    } elseif ($_.Key -eq 'Escape') {
      if ($popAzureDevice) { $popAzureDevice.IsOpen = $false }
    }
  })
}

if ($btnAzureHistory) {
  $btnAzureHistory.Add_Click({
    if ($script:Prefs.AzureHistory -and $script:Prefs.AzureHistory.Count -gt 0) {
      $lbAzureDeviceHistory.ItemsSource = $script:Prefs.AzureHistory
      $lbAzureDeviceHistory.SelectedIndex = 0
      $popAzureDevice.IsOpen = $true
      $lbAzureDeviceHistory.Focus()
    }
  })
}

if ($lbAzureDeviceHistory) {
  $lbAzureDeviceHistory.Add_MouseLeftButtonUp({
    if ($lbAzureDeviceHistory.SelectedItem) {
      $tbAzureDevice.Text = $lbAzureDeviceHistory.SelectedItem
      $popAzureDevice.IsOpen = $false
      $tbAzureDevice.Focus(); $tbAzureDevice.CaretIndex = $tbAzureDevice.Text.Length
    }
  })
  $lbAzureDeviceHistory.Add_KeyDown({
    if ($_.Key -eq 'Return' -and $lbAzureDeviceHistory.SelectedItem) {
      $tbAzureDevice.Text = $lbAzureDeviceHistory.SelectedItem
      $popAzureDevice.IsOpen = $false
      $tbAzureDevice.Focus(); $tbAzureDevice.CaretIndex = $tbAzureDevice.Text.Length
    } elseif ($_.Key -eq 'Escape') {
      $popAzureDevice.IsOpen = $false
      $tbAzureDevice.Focus()
    }
  })
}

if ($btnAzureSearch) {
  $btnAzureSearch.Add_Click({
    $popAzureDevice.IsOpen = $false
    Clear-LapsPassword $script:AzureState
    Update-ExpirationIndicator $script:AzureState $null
    if ($txtAzureDetails) { $txtAzureDetails.Text = '' }
    if ($gbAzureDetails) { $gbAzureDetails.Visibility = 'Collapsed' }
    if ($gbAzureDevices) { $gbAzureDevices.Visibility = 'Collapsed' }
    if ($lbAzureDevices) { $lbAzureDevices.ItemsSource = @() }
    if ($script:AzureState) { $script:AzureState.DeviceResults = @() }
    $deviceName = if ($tbAzureDevice) { $tbAzureDevice.Text.Trim() } else { '' }
    if (-not ($script:AzureState -and $script:AzureState.IsConnected)) {
      [System.Windows.MessageBox]::Show($script:t.msgAzureConnectFirst, 'Microsoft Graph', 'OK', 'Warning') | Out-Null
      return
    }
    if ([string]::IsNullOrWhiteSpace($deviceName)) { return }
    try {
      $window.Cursor = 'Wait'
      if ($btnAzureSearch) { $btnAzureSearch.IsEnabled = $false }
      $devices = Search-IntuneDevices -DeviceName $deviceName
      if (-not $devices -or $devices.Count -eq 0) {
        [System.Windows.MessageBox]::Show($script:t.msgAzureNoDevices, 'Intune', 'OK', 'Information') | Out-Null
        return
      }
      $norm = Normalize-ComputerName -InputName $deviceName
      if ($norm) {
        if (-not $script:Prefs.AzureHistory) { $script:Prefs.AzureHistory = @() }
        $script:Prefs.AzureHistory = @($norm) + @($script:Prefs.AzureHistory | Where-Object { $_ -ne $norm })
        if ($script:Prefs.AzureHistory.Count -gt 50) { $script:Prefs.AzureHistory = $script:Prefs.AzureHistory[0..49] }
        Save-Prefs
      }
      $items = @()
      foreach ($dev in $devices) {
        $display = if ($dev.deviceName) { $dev.deviceName } else { $dev.id }
        if ($dev.userPrincipalName) { $display = "$display ($($dev.userPrincipalName))" }
        $items += [pscustomobject]@{ DisplayName = $display; Device = $dev }
      }
      $script:AzureState.DeviceResults = $items
      if ($lbAzureDevices) { $lbAzureDevices.ItemsSource = $items }
      if ($gbAzureDevices) { $gbAzureDevices.Visibility = 'Visible' }
      if ($items.Count -gt 0) {
        if ($items.Count -gt 1) {
          if ($lbAzureDevices) { $lbAzureDevices.SelectedIndex = -1 }
          if ($txtAzureDetails) { $txtAzureDetails.Text = $script:t.msgAzureMultipleDevices }
          if ($gbAzureDetails) { $gbAzureDetails.Visibility = 'Visible' }
          Clear-LapsPassword $script:AzureState
          Update-ExpirationIndicator $script:AzureState $null
        } else {
          if ($lbAzureDevices) { $lbAzureDevices.SelectedIndex = 0 }
          Show-AzureDeviceDetails $items[0]
        }
      }
    } catch {
      $msg = $_.Exception.Message
      if ($msg -eq 'GraphModuleMissing') { $msg = $script:t.msgAzureInstallModule }
      [System.Windows.MessageBox]::Show("Graph query failed: $msg", 'Microsoft Graph', 'OK', 'Error') | Out-Null
    } finally {
      $window.Cursor = 'Arrow'
      if ($btnAzureSearch) { $btnAzureSearch.IsEnabled = $true }
    }
  })
}

if ($lbAzureDevices) {
  $lbAzureDevices.Add_SelectionChanged({
    if ($lbAzureDevices.SelectedItem) {
      Show-AzureDeviceDetails $lbAzureDevices.SelectedItem
    }
  })
}

function Ensure-GraphModules {
  if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
    throw [System.Exception]::new('GraphModuleMissing')
  }
  Import-Module Microsoft.Graph.Authentication -ErrorAction Stop | Out-Null
  try { Import-Module Microsoft.Graph.DeviceManagement -ErrorAction SilentlyContinue | Out-Null } catch {}
}

function Connect-IntuneGraph {
  param([string[]]$Scopes)
  Ensure-GraphModules
  Connect-MgGraph -Scopes $Scopes -ContextScope Process -NoWelcome -ErrorAction Stop | Out-Null
  $ctx = Get-MgContext
  if (-not $ctx) { throw "Unable to obtain Microsoft Graph context." }
  if ($script:AzureState) {
    $script:AzureState.IsConnected = $true
    $script:AzureState.Account = $ctx.Account
    $script:AzureState.TenantId = $ctx.TenantId
  }
  Update-AzureStatusLabel
  $ctx
}

function Disconnect-IntuneGraph {
  try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch {}
  if ($script:AzureState) {
    $script:AzureState.IsConnected = $false
    $script:AzureState.Account = $null
    $script:AzureState.TenantId = $null
  }
  Update-AzureStatusLabel
}

function Search-IntuneDevices {
  param([string]$DeviceName)
  Ensure-GraphModules
  $safe = if ($DeviceName) { $DeviceName.Replace("'","''") } else { "" }
  $filters = @()
  if ($safe) {
    $filters += "deviceName eq '$safe'"
    $filters += "startsWith(deviceName,'$safe')"
  }
  $results = @()
  foreach ($filter in $filters) {
    $encodedFilter = [uri]::EscapeDataString($filter)
    $uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=$encodedFilter&`$top=25"
    try {
      $resp = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
      if ($resp.value) { $results += $resp.value }
    } catch {
      throw $_
    }
  }
  $unique = @{}
  foreach ($dev in $results) {
    if ($dev.id -and -not $unique.ContainsKey($dev.id)) {
      $unique[$dev.id] = $dev
    }
  }
  @($unique.Values)
}

function Get-IntuneLapsPassword {
  param([string]$DeviceId)
  if ([string]::IsNullOrWhiteSpace($DeviceId)) { return $null }
  Ensure-GraphModules
  $uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$DeviceId/windowsLapsManagedDeviceInformation"
  $resp = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
  $pwd = $resp.password
  $exp = $null
  if ($resp.passwordExpirationDateTime) {
    try { $exp = ([DateTime]::Parse($resp.passwordExpirationDateTime)).ToLocalTime() } catch {}
  }
  [pscustomobject]@{
    Password  = $pwd
    Expiration= $exp
    Account   = $resp.administratorAccountName
    Raw       = $resp
  }
}

function Show-AzureDeviceDetails {
  param($Entry)
  if (-not $Entry -or -not $Entry.Device) { return }
  $device = $Entry.Device
  $lines = @()
  if ($device.deviceName) { $lines += ("Device   : {0}" -f $device.deviceName) }
  if ($device.userPrincipalName) { $lines += ("User     : {0}" -f $device.userPrincipalName) }
  if ($device.enrolledDateTime) { try { $lines += ("Enrolled : {0}" -f ([DateTime]$device.enrolledDateTime).ToLocalTime()) } catch {} }
  if ($device.complianceState) { $lines += ("Compliance: {0}" -f $device.complianceState) }
  if ($device.operatingSystem) { $lines += ("OS       : {0}" -f $device.operatingSystem) }
  if ($device.id) { $lines += ("ID       : {0}" -f $device.id) }
  $txtAzureDetails.Text = ($lines -join [Environment]::NewLine)
  $gbAzureDetails.Visibility = 'Visible'
  $window.UpdateLayout()
  Clear-LapsPassword $script:AzureState
  Update-ExpirationIndicator $script:AzureState $null
  try {
    $laps = Get-IntuneLapsPassword -DeviceId $device.id
    if ($laps -and $laps.Password) {
      Set-LapsPassword $script:AzureState $laps.Password
      if ($laps.Account) { $txtAzureDetails.Text += "`nAccount  : $($laps.Account)" }
      Update-ExpirationIndicator $script:AzureState $laps.Expiration
    } else {
      Update-ExpirationIndicator $script:AzureState $(if ($laps) { $laps.Expiration } else { $null })
      $txtAzureDetails.Text += "`nNo LAPS password available."
    }
  } catch {
    $txtAzureDetails.Text += "`nError: $($_.Exception.Message)"
  }
}

# ---------- Retrieve ----------
$updateInfo = $null
if ($cbAutoUpdate.IsChecked) {
  $updateInfo = Check-ForUpdates -CurrentVersion $CurrentVersion
}
if ($updateInfo) {
  Show-UpdatePrompt $updateInfo
  $lblUpdateStatus.Text = $t.msgUpdateAvailable -f $updateInfo.Version
}

$btnGet.Add_Click({
  $lockout = $false
  try {
    $popCompSuggest.IsOpen = $false
    $gbDetails.Visibility = 'Collapsed'
    $txtDetails.Text = ""
    Clear-LapsPassword $script:AdState
    Update-ExpirationIndicator $script:AdState $null
    $window.UpdateLayout()
    $btnGet.IsEnabled = $false
    $window.Cursor = 'Wait'

    $cred = $null
    if (-not [string]::IsNullOrWhiteSpace($tbUser.Text)) {
      if ([string]::IsNullOrWhiteSpace($pbPass.Password)) { throw "You entered a username without a password." }
      if ($script:FailedAuthCount -ge $script:MaxAuthAttempts) { throw "Too many invalid credential attempts." }
      if (-not (Test-AdCredential -User $tbUser.Text -Password $pbPass.Password -ServerOrDomain $tbServer.Text)) {
        $script:FailedAuthCount++
        $remaining = $script:MaxAuthAttempts - $script:FailedAuthCount
        if ($remaining -le 0) {
          throw "Too many invalid credential attempts."
        } else {
          throw ("Invalid credentials. {0} attempt(s) remaining." -f $remaining)
        }
      } else {
        $script:FailedAuthCount = 0
      }
      $secure = ConvertTo-SecureString -String $pbPass.Password -AsPlainText -Force
      $cred = New-Object System.Management.Automation.PSCredential ($tbUser.Text, $secure)
      if ($cbRememberUser.IsChecked -or $cbRememberServer.IsChecked) { Save-Prefs }
    }

    $ds  = Get-DirectorySearcher -Credential $cred -ServerOrDomain $tbServer.Text
    $res = Find-ComputerEntry -Searcher $ds -ComputerName $tbComp.Text
    if (-not $res) { throw "Computer not found in AD (check spelling or OU)." }

    $norm = Normalize-ComputerName -InputName $tbComp.Text
    if ($norm) {
      if (-not $script:Prefs.AdHistory) { $script:Prefs.AdHistory = @() }
      $script:Prefs.AdHistory = @($norm) + @($script:Prefs.AdHistory | Where-Object { $_ -ne $norm })
      if ($script:Prefs.AdHistory.Count -gt 50) { $script:Prefs.AdHistory = $script:Prefs.AdHistory[0..49] }
      Save-Prefs
    }

    $item = Get-LapsPasswordFromEntry -Result $res
    if ($item -and $item.Password) {
      Set-LapsPassword $script:AdState $item.Password

      $lines = @()
      $lines += ("Type       : {0}" -f $item.Type)
      if ($item.Account) { $lines += ("Compte     : {0}" -f $item.Account) }
      if ($item.Expires) { $lines += ("Expiration : {0}" -f $item.Expires) }
      if ($item.DN)      { $lines += ("DN         : {0}" -f $item.DN) }
      $txtDetails.Text = ($lines -join [Environment]::NewLine)
      $gbDetails.Visibility = 'Visible'
      $window.UpdateLayout()
      Update-ExpirationIndicator $script:AdState $item.Expires
    } else {
      $dn = Get-FirstValue (Get-PropValueCI $res.Properties 'distinguishedName')
      $txtDetails.Text = "No readable LAPS attribute on this computer.`r`nDN: $dn`r`n- LAPS not applied`r`n- No read permission`r`n- Rotation not yet performed."
      $gbDetails.Visibility = 'Visible'
      $window.UpdateLayout()
      Clear-LapsPassword $script:AdState
      Update-ExpirationIndicator $script:AdState $null
    }
  } catch {
    $msg = $_.Exception.Message
    $txtDetails.Text = "Error: $msg"
    $gbDetails.Visibility = 'Visible'
    $window.UpdateLayout()
    Update-ExpirationIndicator $script:AdState $null
    if ($msg -eq 'Too many invalid credential attempts.') {
      if ($script:LockoutTimer) { $script:LockoutTimer.Stop(); $script:LockoutTimer.Dispose() }
      $script:LockoutTimer = New-Object System.Timers.Timer ($script:LockoutResetSeconds * 1000)
      $script:LockoutTimer.AutoReset = $false
      $script:LockoutTimer.Add_Elapsed({ Reset-FailedAuthCount })
      $script:LockoutTimer.Start()
      $btnRetry.Visibility = 'Visible'
      $btnGet.IsEnabled = $false
      $lockout = $true
    }
  } finally {
    $window.Cursor = 'Arrow'
    if (-not $lockout) { $btnGet.IsEnabled = $true }
  }
})
$btnRetry.Add_Click({ Reset-FailedAuthCount })

# Enter -> Retrieve
$tbComp.Add_KeyDown({
    if ($_.Key -eq 'Return') {
        $popCompSuggest.IsOpen = $false
        $btnGet.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Button]::ClickEvent)))
    } elseif ($_.Key -eq 'Down' -and $popCompSuggest.IsOpen -and $lbCompSuggest.Items.Count -gt 0) {
        $lbCompSuggest.Focus()
        if ($lbCompSuggest.SelectedIndex -lt 0) { $lbCompSuggest.SelectedIndex = 0 }
    } elseif ($_.Key -eq 'Escape') {
        $popCompSuggest.IsOpen = $false
    }
})

$window.Add_KeyDown({
    if ($_.Key -eq 'C' -and ([System.Windows.Input.Keyboard]::Modifiers -band [System.Windows.Input.ModifierKeys]::Control)) {
        if ($btnCopy.IsEnabled) {
            $btnCopy.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Button]::ClickEvent)))
        }
    }
})

[void]$window.ShowDialog()
