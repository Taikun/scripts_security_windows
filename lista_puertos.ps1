# Ruta al archivo de configuración
$configFilePath = ".\config.json"

# Verificar si el archivo de configuración existe
if (-Not (Test-Path $configFilePath)) {
    Write-Error "El archivo de configuración '$configFilePath' no existe. Por favor, crea el archivo con tu clave API."
    exit
}

# Leer el archivo de configuración
try {
    $configContent = Get-Content -Path $configFilePath -Raw | ConvertFrom-Json
} catch {
    Write-Error "No se pudo leer o parsear el archivo de configuración. Verifica que esté en formato JSON válido."
    exit
}

# Obtener la clave API de VirusTotal desde el archivo de configuración
$VirusTotalApiKey = $configContent.VirusTotalApiKey

# Verificar si la clave API está presente
if (-Not $VirusTotalApiKey) {
    Write-Error "La clave API de VirusTotal no está definida en el archivo de configuración."
    exit
}

# Función para convertir un PSCustomObject a Hashtable
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

# Ruta al archivo de caché
$cacheFilePath = ".\vt_cache.json"

# Cargar la caché desde el disco
if (Test-Path $cacheFilePath) {
    try {
        $cacheJson = Get-Content -Path $cacheFilePath -Raw
        $cacheDataObj = $cacheJson | ConvertFrom-Json

        # Convertir el objeto en un Hashtable
        $cacheData = ConvertTo-Hashtable -Object $cacheDataObj
    } catch {
        Write-Warning "No se pudo leer o parsear el archivo de caché. Se creará uno nuevo."
        $cacheData = @{}
    }
} else {
    $cacheData = @{}
}

# Inicializar variables para el control de la tasa de solicitudes
$apiCallCount = 0
$apiCallStartTime = Get-Date

# Función para controlar la tasa de solicitudes
function Control-RateLimit {
    param (
        [int]$CallCount,
        [datetime]$StartTime
    )
    $elapsedTime = (Get-Date) - $StartTime
    if ($CallCount -ge 4) {
        if ($elapsedTime.TotalSeconds -lt 60) {
            $sleepTime = [int](60 - $elapsedTime.TotalSeconds)
            Write-Host "Se alcanzó el límite de 4 solicitudes por minuto. Pausando por $sleepTime segundos para respetar la tasa de la API..."
            Start-Sleep -Seconds $sleepTime
        }
        # Reiniciar el contador y el tiempo de inicio
        $script:apiCallCount = 0
        $script:apiCallStartTime = Get-Date
    }
}

# Función para consultar VirusTotal
function Check-VirusTotal {
    param (
        [string]$FilePath
    )
    # Verificar si el archivo existe
    if (-Not (Test-Path $FilePath)) {
        return "Archivo no encontrado"
    }

    # Obtener el hash SHA256 del archivo
    $sha256 = (Get-FileHash -Algorithm SHA256 -Path $FilePath).Hash

    # Verificar si el hash ya está en la caché
    if ($cacheData.ContainsKey($sha256)) {
        return $cacheData[$sha256]
    }

    # Controlar la tasa de solicitudes
    Control-RateLimit -CallCount $apiCallCount -StartTime $apiCallStartTime

    # Construir la URL de la API
    $url = "https://www.virustotal.com/api/v3/files/$sha256"

    # Configurar el encabezado con la clave de API
    $headers = @{
        "x-apikey" = $VirusTotalApiKey
    }

    # Realizar la solicitud a la API
    try {
        $response = Invoke-RestMethod -Method Get -Uri $url -Headers $headers -ErrorAction Stop

        # Incrementar el contador de llamadas a la API
        $script:apiCallCount++

        # Analizar la respuesta
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

    # Devolver el resultado
    return $vtResult
}

# Obtener todas las conexiones TCP y UDP
$netConnections = Get-NetTCPConnection -ErrorAction SilentlyContinue
$netConnections += Get-NetUDPEndpoint -ErrorAction SilentlyContinue

# Crear una lista para almacenar los resultados
$resultList = @()

# Listas para los reportes
$maliciousProcesses = @()
$unknownProcesses = @()

# Recorrer cada conexión y obtener el nombre del proceso y la ruta
foreach ($conn in $netConnections) {
    # Obtener el proceso basado en el PID (OwningProcess)
    $process = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $($conn.OwningProcess)" -ErrorAction SilentlyContinue

    # Obtener el nombre del proceso y la ruta
    $processName = $process.Name
    $processPath = $process.ExecutablePath

    # Si no se puede obtener el nombre del proceso, asignar "Desconocido"
    if (!$processName) {
        $processName = "Desconocido"
    }

    # Si no se puede obtener la ruta del proceso, asignar "Desconocido"
    if (!$processPath) {
        $processPath = "Desconocido"
        $vtResult = "No se pudo verificar"
    } else {
        # Consultar VirusTotal
        $vtResult = Check-VirusTotal -FilePath $processPath
    }

    # Crear un objeto con la información recopilada
    $obj = [PSCustomObject]@{
        'Protocolo'       = $conn.GetType().Name -match 'TCP' ? 'TCP' : 'UDP'
        'Dirección Local' = "$($conn.LocalAddress):$($conn.LocalPort)"
        'Dirección Remota' = if ($conn.RemoteAddress -and $conn.RemotePort) { "$($conn.RemoteAddress):$($conn.RemotePort)" } else { 'N/A' }
        'Estado'          = if ($conn.State) { $conn.State } else { 'N/A' }
        'Proceso'         = $processName
        'ProcesoID'       = $conn.OwningProcess
        'Ruta'            = $processPath
        'VirusTotal'      = $vtResult
    }

    # Agregar el objeto a la lista de resultados
    $resultList += $obj

    # Agregar a las listas de reportes si corresponde
    if ($vtResult -like "Posible amenaza detectada*") {
        $maliciousProcesses += $obj
    } elseif ($vtResult -eq "No hay información en VirusTotal") {
        $unknownProcesses += $obj
    }
}

# Guardar la caché actualizada en disco
try {
    $cacheData | ConvertTo-Json | Set-Content -Path $cacheFilePath -Encoding UTF8
} catch {
    Write-Warning "No se pudo guardar la caché en disco."
}

# Agrupar los resultados por Proceso, ProcesoID, Ruta y VirusTotal
$groupedResults = $resultList | Group-Object -Property Proceso, ProcesoID, Ruta, VirusTotal

# Mostrar los resultados
foreach ($group in $groupedResults) {
    $processName = $group.Group[0].Proceso
    $processId = $group.Group[0].ProcesoID
    $processPath = $group.Group[0].Ruta
    $vtStatus = $group.Group[0].VirusTotal

    Write-Host "Proceso: $processName (PID: $processId)"
    Write-Host "Ruta: $processPath"
    Write-Host "Estado en VirusTotal: $vtStatus"
    Write-Host "Puertos:"

    foreach ($item in $group.Group) {
        Write-Host "`tProtocolo: $($item.Protocolo), Dirección Local: $($item.'Dirección Local'), Dirección Remota: $($item.'Dirección Remota'), Estado: $($item.Estado)"
    }

    Write-Host "---------------------------------------------------------"
}

# Generar el reporte de procesos maliciosos
if ($maliciousProcesses.Count -gt 0) {
    Write-Host "`n**** Reporte de Procesos Maliciosos Detectados ****`n" -ForegroundColor Red
    $maliciousGrouped = $maliciousProcesses | Group-Object -Property Proceso, ProcesoID, Ruta, VirusTotal
    foreach ($group in $maliciousGrouped) {
        $processName = $group.Group[0].Proceso
        $processId = $group.Group[0].ProcesoID
        $processPath = $group.Group[0].Ruta
        $vtStatus = $group.Group[0].VirusTotal

        Write-Host "Proceso: $processName (PID: $processId)"
        Write-Host "Ruta: $processPath"
        Write-Host "Estado en VirusTotal: $vtStatus"
        Write-Host "---------------------------------------------------------"
    }
} else {
    Write-Host "`nNo se detectaron procesos maliciosos según VirusTotal.`n"
}

# Generar el reporte de procesos desconocidos
if ($unknownProcesses.Count -gt 0) {
    Write-Host "`n**** Reporte de Procesos Desconocidos en VirusTotal ****`n" -ForegroundColor Yellow
    $unknownGrouped = $unknownProcesses | Group-Object -Property Proceso, ProcesoID, Ruta, VirusTotal
    foreach ($group in $unknownGrouped) {
        $processName = $group.Group[0].Proceso
        $processId = $group.Group[0].ProcesoID
        $processPath = $group.Group[0].Ruta
        $vtStatus = $group.Group[0].VirusTotal

        Write-Host "Proceso: $processName (PID: $processId)"
        Write-Host "Ruta: $processPath"
        Write-Host "Estado en VirusTotal: $vtStatus"
        Write-Host "---------------------------------------------------------"
    }
} else {
    Write-Host "`nNo hay procesos desconocidos en VirusTotal.`n"
}
