# Filtrar conexiones por los puertos 8080 y 6666
$port8080 = Get-NetTCPConnection -LocalPort 8080 -ErrorAction SilentlyContinue
$port6666 = Get-NetTCPConnection -LocalPort 6666 -ErrorAction SilentlyContinue
$port26777 = Get-NetTCPConnection -LocalPort 26777 -ErrorAction SilentlyContinue
$port57549 = Get-NetTCPConnection -LocalPort 57549 -ErrorAction SilentlyContinue

# Si existe una conexión en el puerto 8080, obtener el proceso asociado
if ($port8080) {
    $process8080 = Get-Process -Id $port8080.OwningProcess
    Write-Host "Puerto 8080 está siendo utilizado por el proceso: $($process8080.ProcessName), PID: $($port8080.OwningProcess)"
} else {
    Write-Host "No se encontró ningún proceso utilizando el puerto 8080"
}

# Si existe una conexión en el puerto 6666, obtener el proceso asociado
if ($port6666) {
    $process6666 = Get-Process -Id $port6666.OwningProcess
    Write-Host "Puerto 6666 está siendo utilizado por el proceso: $($process6666.ProcessName), PID: $($port6666.OwningProcess)"
} else {
    Write-Host "No se encontró ningún proceso utilizando el puerto 6666"
}


if ($port26777) {
    $port26777 = Get-Process -Id $port26777.OwningProcess
    Write-Host "Puerto 26777 está siendo utilizado por el proceso: $($port26777.ProcessName), PID: $($port26777.OwningProcess)"
} else {
    Write-Host "No se encontró ningún proceso utilizando el puerto 26777"
}

if ($port57549) {
    $port57549 = Get-Process -Id $port57549.OwningProcess
    Write-Host "Puerto 57549 está siendo utilizado por el proceso: $($port57549.ProcessName), PID: $($port57549.OwningProcess)"  
} else {
    Write-Host "No se encontró aquí proceso utilizando el puerto 57549"
}