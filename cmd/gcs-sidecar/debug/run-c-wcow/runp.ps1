echo runp
if ($env:podID -eq $null) {
  $env:podID = C:\ContainerPlat\crictl.exe runp --runtime runhcs-wcow-hypervisor-17763 .\conf-pod.json
  echo "POD ID = $env:podID"
}
  else
{
  echo 'There is alread a pod running, ID = $env:podID'
}

