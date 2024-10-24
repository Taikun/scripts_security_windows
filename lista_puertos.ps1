# Este script revisa las conexiones TCP y UDP activas, obtiene la información del proceso asociado,
# verifica el hash del archivo ejecutable del proceso en VirusTotal y genera reportes de posibles amenazas.

# Ruta al archivo de configuración que contiene la clave API de VirusTotal
$configFilePath = ".\config.json"

# Verificar si el archivo de configuración existe
if (-Not (Test-Path $configFilePath)) {
    Write-Error "El archivo de configuración '$configFilePath' no existe. Por favor, crea el archivo con tu clave API."
    exit
}

# Leer el archivo de configuración y obtener la clave API
try {
    $configContent = Get-Content -Path $configFilePath -Raw | ConvertFrom-Json
} catch {
    Write-Error "No se pudo leer o parsear el archivo de configuración. Verifica que esté en formato JSON válido."
    exit
}

# Obtener la clave API de VirusTotal
$VirusTotalApiKey = $configContent.VirusTotalApiKey

# Verificar si la clave API está definida en el archivo de configuración
if (-Not $VirusTotalApiKey) {
    Write-Error "La clave API de VirusTotal no está definida en el archivo de configuración."
    exit
}

# Función para convertir un PSCustomObject a un Hashtable
function ConvertTo-Hashtable {
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Object
    )

    $hashtable = @{}
    foreach ($property in $Object.PSObject.Properties) {
        $hashtable[$property.Name] = $property.Value
    }
    return $hashtable
}

# Ruta al archivo de caché para almacenar resultados previos
$cacheFilePath = ".\vt_cache.json"

# Cargar la caché si existe, o crear una nueva si no
if (Test-Path $cacheFilePath) {
    try {
        $cacheJson = Get-Content -Path $cacheFilePath -Raw
        $cacheDataObj = $cacheJson | ConvertFrom-Json
        $cacheData = ConvertTo-Hashtable -Object $cacheDataObj
    } catch {
        Write-Warning "No se pudo leer o parsear el archivo de caché. Se creará uno nuevo."
        $cacheData = @{}
    }
} else {
    $cacheData = @{}
}

# Inicializar variables para controlar el límite de solicitudes a la API de VirusTotal
$apiCallCount = 0
$apiCallStartTime = Get-Date

# Función para controlar la tasa de solicitudes (4 por minuto)
function Control-RateLimit {
    param (
        [int]$CallCount,
        [datetime]$StartTime
    )
    $elapsedTime = (Get-Date) - $StartTime
    if ($CallCount -ge 4) {
        if ($elapsedTime.TotalSeconds -lt 60) {
            $sleepTime = [int](60 - $elapsedTime.TotalSeconds)
            Write-Host "Límite alcanzado: Pausando por $sleepTime segundos para respetar la tasa de la API..."
            Start-Sleep -Seconds $sleepTime
        }
        # Reiniciar el contador de llamadas
        $script:apiCallCount = 0
        $script:apiCallStartTime = Get-Date
    }
}

# Función para verificar un archivo en VirusTotal usando su hash SHA256
function Check-VirusTotal {
    param (
        [string]$FilePath
    )
    # Verificar si el archivo existe
    if (-Not (Test-Path $FilePath)) {
        return "Archivo no encontrado"
    }

    # Calcular el hash SHA256 del archivo
    $sha256 = (Get-FileHash -Algorithm SHA256 -Path $FilePath).Hash

    # Verificar si el hash ya está en la caché
    if ($cacheData.ContainsKey($sha256)) {
        return $cacheData[$sha256]
    }

    # Controlar la tasa de solicitudes a la API
    Control-RateLimit -CallCount $apiCallCount -StartTime $apiCallStartTime

    # URL de la API de VirusTotal
    $url = "https://www.virustotal.com/api/v3/files/$sha256"

    # Encabezados con la clave API
    $headers = @{
        "x-apikey" = $VirusTotalApiKey
    }

    # Realizar la solicitud a la API
    try {
        $response = Invoke-RestMethod -Method Get -Uri $url -Headers $headers -ErrorAction Stop
        $script:apiCallCount++

        # Analizar el resultado de VirusTotal
        $maliciousCount = $response.data.attributes.last_analysis_stats.malicious
        $suspiciousCount = $response.data.attributes.last_analysis_stats.suspicious

        if ($maliciousCount -gt 0 -or $suspiciousCount -gt 0) {
            $vtResult = "Posible amenaza detectada ($maliciousCount maliciosos, $suspiciousCount sospechosos)"
        } else {
            $vtResult = "Limpio"
        }
    } catch {
        $vtResult = "No hay información en VirusTotal"
    }

    # Guardar el resultado en la caché
    $cacheData[$sha256] = $vtResult

    return $vtResult
}

# Obtener todas las conexiones TCP y UDP activas
$netConnections = Get-NetTCPConnection -ErrorAction SilentlyContinue
$netConnections += Get-NetUDPEndpoint -ErrorAction SilentlyContinue

# Listas para almacenar los resultados y reportes
$resultList = @()
$maliciousProcesses = @()
$unknownProcesses = @()

# Recorrer cada conexión y verificar el proceso asociado en VirusTotal
foreach ($conn in $netConnections) {
    $process = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $($conn.OwningProcess)" -ErrorAction SilentlyContinue

    $processName = $process.Name
    $processPath = $process.ExecutablePath

    if (!$processName) { $processName = "Desconocido" }
    if (!$processPath) { 
        $processPath = "Desconocido"
        $vtResult = "No se pudo verificar"
    } else {
        $vtResult = Check-VirusTotal -FilePath $processPath
    }

    # Crear un objeto con los detalles de la conexión
    $obj = [PSCustomObject]@{
        'Protocolo'        = $conn.GetType().Name -match 'TCP' ? 'TCP' : 'UDP'
        'Dirección Local'  = "$($conn.LocalAddress):$($conn.LocalPort)"
        'Dirección Remota' = if ($conn.RemoteAddress -and $conn.RemotePort) { "$($conn.RemoteAddress):$($conn.RemotePort)" } else { 'N/A' }
        'Estado'           = if ($conn.State) { $conn.State } else { 'N/A' }
        'Proceso'          = $processName
        'ProcesoID'        = $conn.OwningProcess
        'Ruta'             = $processPath
        'VirusTotal'       = $vtResult
    }

    # Agregar a la lista de resultados
    $resultList += $obj

    # Agregar a los reportes si corresponde
    if ($vtResult -like "Posible amenaza detectada*") {
        $maliciousProcesses += $obj
    } elseif ($vtResult -eq "No hay información en VirusTotal") {
        $unknownProcesses += $obj
    }
}

# Guardar la caché actualizada en el disco
try {
    $cacheData | ConvertTo-Json | Set-Content -Path $cacheFilePath -Encoding UTF8
} catch {
    Write-Warning "No se pudo guardar la caché en disco."
}

# Mostrar los resultados agrupados por proceso
$groupedResults = $resultList | Group-Object -Property Proceso, ProcesoID, Ruta, VirusTotal
foreach ($group in $groupedResults) {
    Write-Host "Proceso: $($group.Group[0].Proceso) (PID: $($group.Group[0].ProcesoID))"
    Write-Host "Ruta: $($group.Group[0].Ruta)"
    Write-Host "Estado en VirusTotal: $($group.Group[0].VirusTotal)"
    Write-Host "Puertos:"
    foreach ($item in $group.Group) {
        Write-Host "`tProtocolo: $($item.Protocolo), Dirección Local: $($item.'Dirección Local'), Dirección Remota: $($item.'Dirección Remota'), Estado: $($item.Estado)"
    }
    Write-Host "---------------------------------------------------------"
}

# Generar reportes de procesos maliciosos
if ($maliciousProcesses.Count -gt 0) {
    Write-Host "`n**** Reporte de Procesos Maliciosos Detectados ****`n" -ForegroundColor Red
    foreach ($group in ($maliciousProcesses | Group-Object -Property Proceso, ProcesoID, Ruta, VirusTotal)) {
        Write-Host "Proceso: $($group.Group[0].Proceso) (PID: $($group.Group[0].ProcesoID))"
        Write-Host "Ruta: $($group.Group[0].Ruta)"
        Write-Host "Estado en VirusTotal: $($group.Group[0].VirusTotal)"
        Write-Host "---------------------------------------------------------"
    }
} else {
    Write-Host "`nNo se detectaron procesos maliciosos según VirusTotal.`n"
}

# Generar reportes de procesos desconocidos
if ($unknownProcesses.Count -gt 0) {
    Write-Host "`n**** Reporte de Procesos Desconocidos en VirusTotal ****`n" -ForegroundColor Yellow
    foreach ($group in ($unknownProcesses | Group-Object -Property Proceso, ProcesoID, Ruta, VirusTotal)) {
        Write-Host "Proceso: $($group.Group[0].Proceso) (PID: $($group.Group[0].ProcesoID))"
        Write-Host "Ruta: $($group.Group[0].Ruta)"
        Write-Host "Estado en VirusTotal: $($group.Group[0].VirusTotal)"
        Write-Host "---------------------------------------------------------"
    }
} else {
    Write-Host "`nNo hay procesos desconocidos en VirusTotal.`n"
}
