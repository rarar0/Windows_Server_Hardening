"Running"
while ($true){
    $getproc = Get-Process Ps* | Select Id
    $id = $getproc.Id 
    if ($getproc){
        $id
        Stop-Process $id -Force -EA SilentlyContinue
    }
}
