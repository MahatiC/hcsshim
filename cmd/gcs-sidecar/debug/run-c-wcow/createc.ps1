echo create
$env:containerID = C:\ContainerPlat\crictl.exe create --no-pull $env:podID .\wcow-container.json .\conf-pod.json
echo "Container ID = $env:containerID"