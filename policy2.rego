package policy

api_version := "0.11.0"
framework_version := "0.4.0"

containers := [
    {
        "command": ["ping","-t", "127.0.0.1"],
        "layers": ["OEL1o9JBTcmE5K67dubh6Lp6TILbCyxULFUTz3cgXEnd4XJCMPvKQyDPxJu5TwVn","juIyiAvoJ03tSH3V3hpIFDaR8Lf6tDflkWnmQRDLY0hAekosJXvROGkaq2PYXAap","sLaq5b82ttMuiQy89u1lubYVTsKvvezX0s0gz47NzoyqmtLzidFaWgJMKO8vPqRP"],
        "mounts": [{"destination": "ycxovWMSH6VMjw9cd9c4TwZVOzw", "options": ["wbwauHZ0x4YZ"], "source": ".\sandbox:\gRGtmqhxJ8", "type": "bind"},{"destination": "M19utCT2aLoE0", "options": ["KiE7RrGBAiv0E9EX8KXzOeQAbgYWVSh","pGYcSyy1RMiY7","M4gUYclld2mZmynHZMZYjx"], "source": ".\hugepages:\fBgJh5HsaI", "type": "bind"}],
        "signals": [36,17,25,41,32,12,23,29,22,31,24,4],
        "user": {
            "user_idname": {"pattern": `BiLp2p7fhT`, "strategy": "name"},
            "group_idnames": [{"pattern": `1470985490`, "strategy": "id"},{"pattern": `1191798648`, "strategy": "id"},{"pattern": `c5w93NZz6F`, "strategy": "name"}],
            "umask": "0374"
        },
        "capabilities": {
            "bounding": ["vVThtSN3SPk6","mi3SrDOH0V","L9JMKIJMzvccjUvvpPgoju00","zA7e3O2fEomQhbd8rJFNcAS","cz0XpjTgNL","clclLp7YsN7zxKwTUq6p","DGfgIrLwUZ"],
            "effective": ["9EiUgcQ51QL42","HxbgcunCVNoCZHt","44CmdQRsJPjU","WuGpe6dPqN","CZ6aJFQY7nlyMj1","jB0fUOdwccfOlDhd","WTUvK2GjHqBFkNukYFt5S","6HMRpKoqxg","Wv7tS3FKWTLigrIQiVwrI","D96qCFC8Ogrjc","yaboEhWsC7"],
            "inheritable": ["Cca07vNngP","c4aXhsc35XUyqw","glfakFFjYI"],
            "permitted": ["YuYrCXSA7UZ7HDsmvPZiplc","jos93twRjm0qd8X","9VAPvavNbQ","pgGeZQZKMwySKYwcLxkv89S2","0SeOKrqe8qRKWHmgLyBZ54wD","6OTGnFEttDiNkj0","Aj5PZo5ZnF"],
            "ambient": ["keKCUSxT9eNnLIEYvB4r","TNnq0j9oPWV","7AwyWqNlj49iE","t7mieuNBR0czLUfdxCbN","oVpAayGQkeveaJ0","4ViJgaIrHA","LpTg4oqN45","i3pEaIjhS6W8s7hOEY","iUlSVxxBi9","75APuoROzIR","x2YiEQnstk"],
        },
        "seccomp_profile_sha256": "",
        "allow_elevated": false,
        "working_dir": "UObMiyn12cgteALqEuBne4TGnwsNcZlDciIzeT4oaR9NbnQ",
        "allow_stdio_access": false,
        "no_new_privileges": true,
    },
]

allow_properties_access := false
allow_dump_stacks := true
allow_runtime_logging := false
allow_environment_variable_dropping := false
allow_unencrypted_scratch := true
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
