# Convert ETL logs and capture messages

This outlines the approach to capture messages over the bridge between hcsshim and gcs.

Run `wcow/scripts/log-start.ps1` as admin before creating a pod/container or performing any other container operations. To end logging, run `wcow/scripts/log-end.ps1.ps1`. This will capture the logs in `trace-log.etl` file by default.

This Powershell command below converts an ETL log into an XML file. `tracerpt` usually comes installed in windows and shouldn't need any more dependencies.

`tracerpt.exe .\trace-log.etl -o output-log.xml -of XML -lr`

The linux command below extracts payload messages from the xml file into a output.json file in the present working directory by default.

`python3 wcow/scripts/payload-xml-json.py`