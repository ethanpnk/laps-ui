# LAPS-UI.ps1 - WPF Dark, PS 5.1 (STA)
# LDAP by default, optional LDAPS, modern dark UI, 20s countdown
# Read-only "LAPS password" field + reliable green "cleared" message
# Remember user & controller/domain (local JSON), update checker
# NEW: Cascadia Code font, expiration indicator, autocomplete & colorized password

# --- Config ---
$UseLdaps = $false
$script:ClipboardAutoClearSeconds = 20
$CurrentVersion = '1.0.5'

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
Add-Type -AssemblyName System.DirectoryServices
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
    if ($script:Prefs.History) {
      foreach ($h in $script:Prefs.History) {
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
    $tmp = Join-Path ([IO.Path]::GetTempPath()) "LAPS-UI-$($Info.Version).exe"
    Invoke-WebRequest -Uri $Info.Url -OutFile $tmp -UseBasicParsing -Headers @{ 'User-Agent' = 'LAPS-UI' }
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
      <Setter Property="Margin" Value="0"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="FocusVisualStyle" Value="{x:Null}"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="TabItem">
            <Border x:Name="Bd"
                    Background="#2D2D2D"
                    CornerRadius="8"
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

  <TabControl Margin="16" Background="{Binding RelativeSource={RelativeSource AncestorType=Window}, Path=Background}" BorderThickness="0">
    <TabItem Header="Main">
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

        <GroupBox Grid.Column="0" Header="Credentials" Margin="0,0,8,0">
          <Grid>
            <Grid.ColumnDefinitions>
              <ColumnDefinition Width="Auto"/><ColumnDefinition Width="*"/>
            </Grid.ColumnDefinitions>
            <Grid.RowDefinitions>
              <RowDefinition Height="Auto"/><RowDefinition Height="Auto"/>
            </Grid.RowDefinitions>
            <TextBlock Grid.Row="0" Grid.Column="0" Text="User (user@domain)" Margin="0,0,12,0" VerticalAlignment="Center" Foreground="{DynamicResource LabelBrush}"/>
            <TextBox   Grid.Row="0" Grid.Column="1" x:Name="tbUser"/>
            <TextBlock Grid.Row="1" Grid.Column="0" Text="Password" Margin="0,8,12,0" VerticalAlignment="Center" Foreground="{DynamicResource LabelBrush}"/>
            <PasswordBox Grid.Row="1" Grid.Column="1" x:Name="pbPass" Margin="0,8,0,0"/>
          </Grid>
        </GroupBox>

        <GroupBox Grid.Column="1" Header="Active Directory Target" Margin="8,0,0,0">
          <Grid>
            <Grid.ColumnDefinitions>
              <ColumnDefinition Width="Auto"/><ColumnDefinition Width="*"/>
            </Grid.ColumnDefinitions>
            <Grid.RowDefinitions>
              <RowDefinition Height="Auto"/>
            </Grid.RowDefinitions>
            <TextBlock Grid.Row="0" Grid.Column="0" VerticalAlignment="Center" Text="Controller/Domain" Margin="0,0,12,0" Foreground="{DynamicResource LabelBrush}"/>
            <TextBox   Grid.Row="0" Grid.Column="1" x:Name="tbServer" Text=""/>
          </Grid>
        </GroupBox>
      </Grid>

      <!-- Search -->
      <GroupBox Grid.Row="1" Header="Search">
        <Grid>
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="Auto"/><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/><ColumnDefinition Width="Auto"/>
          </Grid.ColumnDefinitions>
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
          </Grid.RowDefinitions>
          <TextBlock Grid.Row="0" Grid.Column="0" VerticalAlignment="Center" Text="Computer name" Margin="0,0,12,0" Foreground="{DynamicResource LabelBrush}"/>
          <TextBox   Grid.Row="0" Grid.Column="1" x:Name="tbComp"/>
          <Button   Grid.Row="0" Grid.Column="2" x:Name="btnHistory" Content="&#xE81C;" FontFamily="Segoe MDL2 Assets" Style="{StaticResource IconButton}" Margin="12,0,0,0" ToolTip="History"/>
          <Button   Grid.Row="0" Grid.Column="3" x:Name="btnGet" Content="Retrieve" Style="{StaticResource AccentButton}" IsDefault="True" Margin="12,0,0,0"/>
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
      <GroupBox Grid.Row="3" Header="LAPS Password">
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
  <TabItem Header="Settings">
    <StackPanel Margin="10" Background="{Binding RelativeSource={RelativeSource AncestorType=Window}, Path=Background}">
      <GroupBox Header="Security">
        <StackPanel>
          <CheckBox x:Name="cbLdaps" Content="Use LDAPS (TLS 636)" Margin="0,0,0,8"/>
          <CheckBox x:Name="cbClipboardAutoClear" Content="Enable clipboard auto-clear" IsChecked="True" Margin="0,0,0,8"/>
          <StackPanel Orientation="Horizontal" Margin="20,0,0,0">
            <TextBlock Text="Clipboard delay (s)" Margin="0,0,8,0" VerticalAlignment="Center" Foreground="{DynamicResource LabelBrush}"/>
            <TextBox x:Name="tbClipboardSecs" Width="50"/>
          </StackPanel>
        </StackPanel>
      </GroupBox>
      <GroupBox Header="Preferences">
        <StackPanel>
          <CheckBox x:Name="cbRememberUser" Content="Remember user"/>
          <CheckBox x:Name="cbRememberServer" Content="Remember controller/domain"/>
          <CheckBox x:Name="cbAutoUpdate" Content="Check for updates on launch" IsChecked="True"/>
          <CheckBox x:Name="cbConfirmCopy" Content="Confirm before copying"/>
        </StackPanel>
      </GroupBox>
      <GroupBox Header="Appearance">
        <StackPanel>
          <StackPanel Orientation="Horizontal" Margin="0,0,0,8">
            <TextBlock Text="Theme" Margin="0,0,8,0" VerticalAlignment="Center" Foreground="{DynamicResource LabelBrush}"/>
            <ComboBox x:Name="cmbTheme" Width="120" SelectedIndex="0">
              <ComboBoxItem Content="Dark"/>
              <ComboBoxItem Content="Light"/>
            </ComboBox>
          </StackPanel>
          <StackPanel Orientation="Horizontal">
            <TextBlock Text="Language" Margin="0,0,8,0" VerticalAlignment="Center" Foreground="{DynamicResource LabelBrush}"/>
            <ComboBox x:Name="cmbLanguage" Width="120">
              <ComboBoxItem Content="English"/>
              <ComboBoxItem Content="French"/>
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
    <Setter Property="Margin" Value="0"/>
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

# Controls
$tbUser         = $window.FindName("tbUser")
$pbPass         = $window.FindName("pbPass")
$tbServer       = $window.FindName("tbServer")
$cbLdaps        = $window.FindName("cbLdaps")
$tbComp         = $window.FindName("tbComp")
$popCompSuggest = $window.FindName("popCompSuggest")
$lbCompSuggest  = $window.FindName("lbCompSuggest")
$btnHistory     = $window.FindName("btnHistory")
$btnGet         = $window.FindName("btnGet")
$gbDetails      = $window.FindName("gbDetails")
$txtDetails     = $window.FindName("txtDetails")
$spExpire       = $window.FindName("spExpire")
$ellExpire      = $window.FindName("ellExpire")
$lblExpire      = $window.FindName("lblExpire")
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
$cbConfirmCopy  = $window.FindName("cbConfirmCopy")
$cmbTheme       = $window.FindName("cmbTheme")
$cmbLanguage    = $window.FindName("cmbLanguage")
$btnUpdate     = $window.FindName("btnUpdate")
$btnIgnore     = $window.FindName("btnIgnore")

# Init
$cbLdaps.IsChecked = $UseLdaps
$script:UseLdaps   = [bool]$cbLdaps.IsChecked
$tbClipboardSecs.Text = $script:ClipboardAutoClearSeconds
$script:CurrentLapsPassword = ""
$script:DoneTimer = $null

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
  $history = $script:Prefs.History
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
    Theme               = $cmbTheme.SelectedItem.Content
    Language            = $cmbLanguage.Text
    History             = $history
    IgnoreVersion       = $ignore
  }
  $persist = $script:Prefs.Clone()
  $persist.History = @($history | ForEach-Object { Protect-String $_ })
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
      if ($loaded.Theme) { $cmbTheme.SelectedItem = $cmbTheme.Items | Where-Object { $_.Content -eq $loaded.Theme } }
      if ($loaded.Language) { $cmbLanguage.Text = $loaded.Language }
      $hist = @()
      if ($loaded.History -is [System.Collections.IEnumerable]) {
        foreach ($enc in $loaded.History) {
          $dec = Unprotect-String $enc
          if ($dec) { $hist += $dec }
        }
      }
      $script:Prefs = $loaded
      $script:Prefs.History = $hist
    } catch { $script:Prefs = @{} }
  }
  if (-not $script:Prefs.History) { $script:Prefs.History = @() }
  $tbClipboardSecs.Text = $script:ClipboardAutoClearSeconds
  $script:UseLdaps = [bool]$cbLdaps.IsChecked
}
Load-Prefs
Apply-Theme $cmbTheme.SelectedItem.Content
$tbComp.IsEnabled = -not [string]::IsNullOrWhiteSpace($pbPass.Password)
$pbPass.Add_PasswordChanged({
    $tbComp.IsEnabled = -not [string]::IsNullOrWhiteSpace($pbPass.Password)
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
$cbConfirmCopy.Add_Checked({ Save-Prefs })
$cbConfirmCopy.Add_Unchecked({ Save-Prefs })
$cmbTheme.Add_SelectionChanged({ Apply-Theme $cmbTheme.SelectedItem.Content; Save-Prefs })
$cmbLanguage.Add_SelectionChanged({ Save-Prefs })
$tbComp.Add_TextChanged({
    Update-ComputerSuggestions $tbComp.Text
    if ($gbDetails.Visibility -ne 'Collapsed') {
        $gbDetails.Visibility = 'Collapsed'
    }
    $txtDetails.Text = ""
    $script:CurrentLapsPassword = ""
    $pbPwdOut.Password = ""
    $rtbPwdOut.Document.Blocks.Clear()
    $btnCopy.IsEnabled = $false
    Update-ExpirationIndicator $null
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
    if ($script:Prefs.History -and $script:Prefs.History.Count -gt 0) {
        $lbCompSuggest.ItemsSource = $script:Prefs.History
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

function Update-PasswordDisplay([string]$pwd) {
  # Build a single-line FlowDocument with per-char coloring
  $doc = New-Object System.Windows.Documents.FlowDocument
  $doc.PagePadding = [Windows.Thickness]::new(0)
  $p = New-Object System.Windows.Documents.Paragraph
  $p.Margin = [Windows.Thickness]::new(0)
  $p.LineHeight = 28

  foreach ($ch in $pwd.ToCharArray()) {
    $run = New-Object System.Windows.Documents.Run ($ch)
    switch -regex ($ch) {
      '^[0-9]$'        { $run.Foreground = $BrushDigits;  break }
      '^[A-Za-z]$'     { $run.Foreground = $BrushLetters; break }
      default          { $run.Foreground = $BrushSymbols; break }
    }
    $p.Inlines.Add($run) | Out-Null
  }

  $doc.Blocks.Clear()
  $doc.Blocks.Add($p) | Out-Null
  $rtbPwdOut.Document = $doc
}

function Update-ExpirationIndicator([nullable[DateTime]]$exp) {
  if ($null -eq $exp) { $spExpire.Visibility = 'Collapsed'; return }
  $now = Get-Date
  $spExpire.Visibility = 'Visible'
  if ($exp -lt $now) {
    $ellExpire.Fill = 'Red'
    $lblExpire.Text = "Expired on $exp"
  } elseif (($exp - $now).TotalDays -le 2) {
    $ellExpire.Fill = 'Orange'
    $lblExpire.Text = "Expires soon ($exp)"
  } else {
    $ellExpire.Fill = 'LimeGreen'
    $lblExpire.Text = "Expires on $exp"
  }
}

# Show/Hide clear text
$cbShow.Add_Checked({
  Update-PasswordDisplay $script:CurrentLapsPassword
  $rtbPwdOut.Visibility = 'Visible'
  $pbPwdOut.Visibility  = 'Collapsed'
})
$cbShow.Add_Unchecked({
  $pbPwdOut.Password = $script:CurrentLapsPassword
  $pbPwdOut.Visibility  = 'Visible'
  $rtbPwdOut.Visibility = 'Collapsed'
})

# ---------- Countdown & copy ----------
$script:CountdownRemaining = 0
$timer = New-Object System.Windows.Threading.DispatcherTimer
$timer.Interval = [TimeSpan]::FromSeconds(1)
$timer.Add_Tick({
  if ($script:CountdownRemaining -gt 0) {
    $script:CountdownRemaining--
    $lblCountdown.Text = "Clipboard cleared in $($script:CountdownRemaining)s"
    if ($script:CountdownRemaining -le 0) {
      try { if ([System.Windows.Clipboard]::ContainsText()) {
        $txt = [System.Windows.Clipboard]::GetText()
        if ($txt -and $txt -eq $script:CurrentLapsPassword) { [System.Windows.Clipboard]::Clear() } } } catch {}
      $timer.Stop()
      $lblCountdown.Text = "Clipboard cleared"
      $lblCountdown.Foreground = 'LimeGreen'
      $script:DoneTimer = New-Object System.Windows.Threading.DispatcherTimer
      $script:DoneTimer.Interval = [TimeSpan]::FromSeconds(2)
      $script:DoneTimer.Add_Tick({ param($sender,$e) $sender.Stop(); $lblCountdown.Visibility='Collapsed'; $lblCountdown.Foreground='#FFA07A' })
      $script:DoneTimer.Start()
    }
  } else { $timer.Stop(); $lblCountdown.Visibility = 'Collapsed' }
})

$btnCopy.Add_Click({
  if ([string]::IsNullOrWhiteSpace($script:CurrentLapsPassword)) { return }
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
      $dp.SetText($script:CurrentLapsPassword)
      $opt = New-Object Windows.ApplicationModel.DataTransfer.ClipboardContentOptions
      $opt.IsAllowedInHistory = $false; $opt.IsRoamingEnabled = $false
      [Windows.ApplicationModel.DataTransfer.Clipboard]::SetContentWithOptions($dp,$opt)
      [Windows.ApplicationModel.DataTransfer.Clipboard]::Flush()
      $usedWinRT = $true
    }
  } catch {}
  if (-not $usedWinRT) { [System.Windows.Clipboard]::SetText($script:CurrentLapsPassword) }

  [System.Windows.MessageBox]::Show(("Password copied {0} clipboard history." -f ($(if($usedWinRT){'without entering'}else{'into'}))),
    "Copied",'OK','Information') | Out-Null

  if ($cbClipboardAutoClear.IsChecked) {
    $script:CountdownRemaining = $script:ClipboardAutoClearSeconds
    $lblCountdown.Text = "Clipboard cleared in $($script:CountdownRemaining)s"
    $lblCountdown.Foreground = '#FFA07A'
    $lblCountdown.Visibility = 'Visible'
    $timer.Stop(); $timer.Start()
  } else {
    $lblCountdown.Visibility = 'Collapsed'
  }
})

# ---------- Retrieve ----------
$updateInfo = $null
if ($cbAutoUpdate.IsChecked) {
  $updateInfo = Check-ForUpdates -CurrentVersion $CurrentVersion
}
if ($updateInfo) {
  $btnUpdate.Content = "Update to v$($updateInfo.Version)"
  $btnUpdate.Visibility = 'Visible'
  $btnIgnore.Visibility = 'Visible'
  $btnUpdate.Add_Click({ Start-AppUpdate -Info $updateInfo -Window $window })
  $btnIgnore.Add_Click({ $script:Prefs.IgnoreVersion = $updateInfo.Version; Save-Prefs; $btnUpdate.Visibility='Collapsed'; $btnIgnore.Visibility='Collapsed' })
}

$btnGet.Add_Click({
  try {
    $popCompSuggest.IsOpen = $false
    $gbDetails.Visibility = 'Collapsed'
    $txtDetails.Text = ""
    $btnCopy.IsEnabled = $false
    $pbPwdOut.Password = ""
    $rtbPwdOut.Document.Blocks.Clear()
    $script:CurrentLapsPassword = ""
    Update-ExpirationIndicator $null
    $window.UpdateLayout()
    $btnGet.IsEnabled = $false
    $window.Cursor = 'Wait'

    $cred = $null
    if (-not [string]::IsNullOrWhiteSpace($tbUser.Text)) {
      if ([string]::IsNullOrWhiteSpace($pbPass.Password)) { throw "You entered a username without a password." }
      $secure = ConvertTo-SecureString -String $pbPass.Password -AsPlainText -Force
      $cred = New-Object System.Management.Automation.PSCredential ($tbUser.Text, $secure)
      if ($cbRememberUser.IsChecked -or $cbRememberServer.IsChecked) { Save-Prefs }
    }

    $ds  = Get-DirectorySearcher -Credential $cred -ServerOrDomain $tbServer.Text
    $res = Find-ComputerEntry -Searcher $ds -ComputerName $tbComp.Text
    if (-not $res) { throw "Computer not found in AD (check spelling or OU)." }

    $norm = Normalize-ComputerName -InputName $tbComp.Text
    if ($norm) {
      if (-not $script:Prefs.History) { $script:Prefs.History = @() }
      $script:Prefs.History = @($norm) + @($script:Prefs.History | Where-Object { $_ -ne $norm })
      if ($script:Prefs.History.Count -gt 50) { $script:Prefs.History = $script:Prefs.History[0..49] }
      Save-Prefs
    }

    $item = Get-LapsPasswordFromEntry -Result $res
    if ($item -and $item.Password) {
      $script:CurrentLapsPassword = [string]$item.Password
      $pbPwdOut.Password = $script:CurrentLapsPassword
      if ($cbShow.IsChecked) { Update-PasswordDisplay $script:CurrentLapsPassword }
      $btnCopy.IsEnabled = $true

      $lines = @()
      $lines += ("Type       : {0}" -f $item.Type)
      if ($item.Account) { $lines += ("Compte     : {0}" -f $item.Account) }
      if ($item.Expires) { $lines += ("Expiration : {0}" -f $item.Expires) }
      if ($item.DN)      { $lines += ("DN         : {0}" -f $item.DN) }
      $txtDetails.Text = ($lines -join [Environment]::NewLine)
      $gbDetails.Visibility = 'Visible'
      $window.UpdateLayout()
      Update-ExpirationIndicator $item.Expires
    } else {
      $dn = Get-FirstValue (Get-PropValueCI $res.Properties 'distinguishedName')
      $txtDetails.Text = "No readable LAPS attribute on this computer.`r`nDN: $dn`r`n- LAPS not applied`r`n- No read permission`r`n- Rotation not yet performed."
      $gbDetails.Visibility = 'Visible'
      $window.UpdateLayout()
      $script:CurrentLapsPassword = ""
      $pbPwdOut.Password = ""
      if ($cbShow.IsChecked) { Update-PasswordDisplay "" }
      $btnCopy.IsEnabled = $false
      Update-ExpirationIndicator $null
    }
  } catch {
    $txtDetails.Text = "Error: $($_.Exception.Message)"
    $gbDetails.Visibility = 'Visible'
    $window.UpdateLayout()
    Update-ExpirationIndicator $null
  } finally {
    $window.Cursor = 'Arrow'
    $btnGet.IsEnabled = $true
  }
})

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
