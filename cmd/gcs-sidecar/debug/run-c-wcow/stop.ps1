echo stop
C:\ContainerPlat\crictl.exe stop $env:containerID

echo rm
C:\ContainerPlat\crictl.exe rm $env:containerID
$env:containerID = $null

echo stopp
C:\ContainerPlat\crictl.exe stopp $env:podID

echo rmp
C:\ContainerPlat\crictl.exe rmp $env:podID
$env:podID = $null
exit 0
