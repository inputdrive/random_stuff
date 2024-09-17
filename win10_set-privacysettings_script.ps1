# Function to set registry value
function Set-RegistryValue {
    param (
        [string]$Path,
        [string]$Name,
        [string]$Value
    )
    Set-ItemProperty -Path $Path -Name $Name -Value $Value
}

# Function to enable or disable privacy settings
function Set-PrivacySettings {
    param (
        [string]$State  # Accepts 'Enable' or 'Disable'
    )

    # Set corresponding value based on State
    $enableValue = if ($State -eq "Enable") { "Allow" } else { "Deny" }
    $telemetryValue = if ($State -eq "Enable") { 3 } else { 1 }
    $advertisingIdValue = if ($State -eq "Enable") { 1 } else { 0 }

    # Telemetry (Diagnostics & Feedback)
    Write-Host "Setting Telemetry to $State..."
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Value $telemetryValue

    # Location Services
    Write-Host "Setting Location Services to $State..."
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Value $enableValue

    # Advertising ID
    Write-Host "Setting Advertising ID to $State..."
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Value $advertisingIdValue

    # Camera Access
    Write-Host "Setting Camera Access to $State..."
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" -Name "Value" -Value $enableValue

    # Microphone Access
    Write-Host "Setting Microphone Access to $State..."
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" -Name "Value" -Value $enableValue

    # Speech Recognition
    Write-Host "Setting Speech Recognition to $State..."
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" -Name "HasAccepted" -Value $telemetryValue

    # Diagnostics (Device history)
    Write-Host "Setting Device History to $State..."
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\diagnostics" -Name "Value" -Value $enableValue

    Write-Host "Privacy settings updated successfully to $State."
}

# Toggle between Enable or Disable
$choice = Read-Host "Enter 'Enable' to turn on privacy settings or 'Disable' to turn them off"

# Call the function with user input
Set-PrivacySettings -State $choice
