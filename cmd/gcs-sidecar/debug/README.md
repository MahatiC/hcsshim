# Debugging and capturing msgs

This branch has hcsshim changes to enable payload capturing on msgs between hcsshim and gcs

Follow the instructions below to capture the msgs and turn them into JSON

- Install ContainerPlat by following instructions from [here](https://eng.ms/docs/cloud-ai-platform/azure-edge-platform-aep/aep-core-os/kvs/container-platform/container-platform-documentation/get-started/install-container-platform#install-container-platform-internal-package)
    - Use the dev version `containerplat-confidential-aci-prerelease 0.2.4-rc.3` from [here](https://dev.azure.com/msazure/ContainerPlatform/_artifacts/feed/ContainerPlat-Dev)

- Build the executables at the root folder of hcsshim - if you're running on WSL, set `export GOOS=windows`
    - `go build ./cmd/gcs-sidecar`
    - `go build ./cmd/containerd-shim-runhcs-v1`
- Copy `gcs-sidecar.exe` which is now in your local folder into `C:\` folder
- Copy `containerd-shim-runhcs-v1.exe` into `C:\ContainerPlat`
- On elevated powershell run, `wpr.exe -start C:\ContainerPlat\ContainerPlatform.wprp`
- On a different elevated powershell, start containerd
    - `C:\ContainerPlat\containerd.exe --config C:\ContainerPlat\containerd.toml --log-level trace`
- On another elevated powershell, create/stop/remove pods, containers
- On the terminal running wpr, run these commands
    - `wpr.exe -stop captured-logs.etl`
    - `tracerpt.exe captured-logs.etl -o captured-logs.xml -of XML -lr`
- Copy over the `captured-logs.xml` into this current folder and run below commands to generate a json version of payload data
    - `cd gcs-sidecar/debug`
    - `python3 payload-xml-json.py`
