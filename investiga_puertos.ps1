# Filtrar conexiones por los puertos 8080 y 6666
$port8080 = Get-NetTCPConnection -LocalPort 8080 -ErrorAction SilentlyContinue
$port6666 = Get-NetTCPConnection -LocalPort 6666 -ErrorAction SilentlyContinue

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
