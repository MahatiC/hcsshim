package policy

api_version := "0.11.0"
framework_version := "0.4.0"

containers := [
    {
        "command": ["cmd.exe","/c","echo hello"],
        "env_rules": [{"pattern": `PATH`, "strategy": "string", "required": false}],
        "layers": ["layer1","layer2"],
        "exec_processes": [],
        "signals": [],
        "user": "testuser",
        "working_dir": "C:\\",
        "allow_stdio_access": false,
    },
]
allow_properties_access := false
allow_dump_stacks := false
allow_runtime_logging := false
allow_environment_variable_dropping := false
allow_unencrypted_scratch := false
allow_capability_dropping := false


mount_device := data.framework.mount_device
unmount_device := data.framework.unmount_device
mount_overlay := data.framework.mount_overlay
unmount_overlay := data.framework.unmount_overlay
mount_cims:= data.framework.mount_cims
create_container := data.framework.create_container
exec_in_container := data.framework.exec_in_container
exec_external := data.framework.exec_external
shutdown_container := data.framework.shutdown_container
signal_container_process := data.framework.signal_container_process
plan9_mount := data.framework.plan9_mount
plan9_unmount := data.framework.plan9_unmount
get_properties := data.framework.get_properties
dump_stacks := data.framework.dump_stacks
runtime_logging := data.framework.runtime_logging
load_fragment := data.framework.load_fragment
scratch_mount := data.framework.scratch_mount
scratch_unmount := data.framework.scratch_unmount
reason := data.framework.reason
