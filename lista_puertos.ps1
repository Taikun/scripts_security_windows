# Obtener todas las conexiones TCP y UDP
$netConnections = Get-NetTCPConnection -ErrorAction SilentlyContinue
$netConnections += Get-NetUDPEndpoint -ErrorAction SilentlyContinue

# Crear una lista para almacenar los resultados
$resultList = @()

# Recorrer cada conexión y obtener el nombre del proceso
foreach ($conn in $netConnections) {
    # Obtener el nombre del proceso basado en el PID (OwningProcess)
    $processName = (Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue).ProcessName

    # Si no se puede obtener el nombre del proceso, asignar "Desconocido"
    if (!$processName) {
        $processName = "Desconocido"
    }

    # Crear un objeto con la información recopilada
    $obj = [PSCustomObject]@{
        'Protocolo'      = $conn.GetType().Name -match 'TCP' ? 'TCP' : 'UDP'
        'Dirección Local'  = "$($conn.LocalAddress):$($conn.LocalPort)"
        'Dirección Remota' = if ($conn.RemoteAddress -and $conn.RemotePort) { "$($conn.RemoteAddress):$($conn.RemotePort)" } else { 'N/A' }
        'Estado'         = if ($conn.State) { $conn.State } else { 'N/A' }
        'Proceso'        = $processName
        'PID'            = $conn.OwningProcess
    }

    # Agregar el objeto a la lista de resultados
    $resultList += $obj
}

# Mostrar los resultados en una tabla formateada
$resultList | Sort-Object Proceso | Format-Table -AutoSize
