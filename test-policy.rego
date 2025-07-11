package policy

api_version := "0.11.0"
framework_version := "0.4.0"

fragments := [
    {"issuer": "QSTDM4WPL1jbCoUN", "feed": "m4DpLtpMZsbflMBmrtzY0hLN5Hmr7NwqPcWG73OKNFdKfHB5rAi6et5wSC3X2FwXytX1q3qGoqFsWs0S5Xz42Ya8xc02zzw265qUOviRrl1dojwR3NcxKVdkoSGIvISTZPCaOnX9Wl8XvU3rqdDrzG4Jk1hFNIFCFVyoxG6FxtcBfom5rzR1lOEiYfhJfhfCdCEbtqVYQeY5S7BMEWq1RPQevoWQTWGl0I5FrSUKTlZ0h9UyljVDxd1h6vj5lQZM", "minimum_svn": "7", "includes": ["containers","external_processes"]},
    {"issuer": "EtZ7sMJl6nr3lXsk", "feed": "1QPmNuwSwHDUMmWjHMtIcnSBnA44hLWUEA3fvX8obPr2hSVOpcMoW9dKW67855slgHcdl4oo5doPHJWMpvELE0nY2xFH0axL7zNMIUkKoslwKNxpfq5QjJfQY9UDv10OLZKojDdYg00RSGvCMuoXQOqovOVFgkexhVeD0NDuX7iC5W5aVl658TcwwyiJPqwTM30WxCJNVD5lwrMtTqq6NL8tdPGxFW5SX62MVozacbEBFrgRvYwx3qydEMOCAYwR", "minimum_svn": "5", "includes": ["fragments","external_processes"]},
    {"issuer": "oPPrQIZvv3LhpfMT", "feed": "Zt0ZcYmf6xMJZ9rKXTMKGvaQCcl3T2tywQHVlu9MItNA4OCxWzsuxj1ziFJzSxtdpfZPhuIevA1o2rbVVXYjjbIux6qoFchPjZQchILCHPOiC9vK4AKcLydqmfR5fb1TCqwNWWNeMzhAJRrOGeNInKPVZXyGWdps12MREYUDrvRe4yPBGfKffnXcQ4KEMNbSlWtEbT6PNPimtzgbhoGZFiqWSizNtrmNnsOn5q1iuASjDKzCDwDi7Pe6AfMDTad3", "minimum_svn": "2", "includes": ["external_processes","containers","fragments"]},
],
containers := [
    {
        "command": ["WcuOV7k6PF5hMCCl6hVU","36yiU8N6g2JUFoKKwEzHSr","6CSehBnQ4drisiDaM0WCNAAWTWHaZs0osJNvE53PFINMPndyRO3LbCVMsTxfS1PRsYvffddjqbJbHqDFXkbXd"],
        "env_rules": [{"pattern": `cOQBu0b2Ri`, "strategy": "string", "required": false},{"pattern": `zuZORaF6t4cVtBBOr8ekAJikd3jGMMyoS16umyMXAE9YSMHC`, "strategy": "string", "required": false},{"pattern": `piGhx2aKEHbBCOmfJV72uk3wfmIpvzpQXBGK6CQfacHy8CxvF`, "strategy": "string", "required": false},{"pattern": `Ji3jDS1T7NM6XwdpTv6ZVdP95P9`, "strategy": "string", "required": false},{"pattern": `MdE2RZoLG8x7dfcj91CMOVHQnYKcN9a6tMrHyVthX7f`, "strategy": "string", "required": false},{"pattern": `IWMkR0nEEmFCJi06KzZAZlagbI9Rau6J`, "strategy": "string", "required": false},{"pattern": `RBv9tj4aQeXVVYOiBYHUy8EbJvnUcrVc`, "strategy": "string", "required": false},{"pattern": `JAwYjQapTDa2LLDCcPMskkZLKH8z4oprP8RnfnwViOCWC60jm37AQ6UTTr`, "strategy": "string", "required": false}],
        "layers": ["OEL1o9JBTcmE5K67dubh6Lp6TILbCyxULFUTz3cgXEnd4XJCMPvKQyDPxJu5TwVn","juIyiAvoJ03tSH3V3hpIFDaR8Lf6tDflkWnmQRDLY0hAekosJXvROGkaq2PYXAap","sLaq5b82ttMuiQy89u1lubYVTsKvvezX0s0gz47NzoyqmtLzidFaWgJMKO8vPqRP","ppCjT0tiRAJEVnjdNAWMSjlgoIOpSTSzOi0eUZ5nR2gFlEZLtCGNy7HwAzhNjfGh"],
        "mounts": [{"destination": "ycxovWMSH6VMjw9cd9c4TwZVOzw", "options": ["wbwauHZ0x4YZ"], "source": ".\sandbox:\gRGtmqhxJ8", "type": "bind"},{"destination": "M19utCT2aLoE0", "options": ["KiE7RrGBAiv0E9EX8KXzOeQAbgYWVSh","pGYcSyy1RMiY7","M4gUYclld2mZmynHZMZYjx"], "source": ".\hugepages:\fBgJh5HsaI", "type": "bind"}],
        "exec_processes": [{"command": ["yzNIhaUF7KjXDfm3wjtUEHMI8gesUiGXlNzlwXOh9Z1nGVPEqQh1vbwb2CoU0LFPaPBi"], "signals": [47,1,57,11,44,64,45,43,17,40,4,25,33,12,26,62,24,20,50,42,60,7,27]},{"command": ["HcI67fyuuKZXnP3Dbfyec2BvWkgXr74CmQX9Pwz3nuS7ngRFs6TRwIr","eM6K4rrdiFNofJKij636Iv"], "signals": [34,24,29,52,61,11,25,40,38,39,15,62,26,19,1,36,54,30,5,10,4,2,44,28,47,41,35,48,59]},{"command": ["xlNdyE00rmkEw2UNi1eVUOJGLU2GffjA4CtNE8VIS8hgIudb5xaCu6jgJqTsq4QJ85cHQJmjTu4kRk13uZxXBcJN0FmwQXuHZ","rektBLC7zSmqioxNv84ZfCL6pIcTPVDFfrV2wQWWkXe481PegF5kA","JF7uSO1ec7QYsBxRc8kLDDfRvYDr6uDUgxkU2FTAJAitzPGzLNqLfzypNhALLn0jcXgtoUvuvKIyhiY3wPLmxfvAXsbv","Vom2VzQ00YDuEw4zJXZSdHe9u0DTSkCWf","ylLpJqmjIUFVcyi06UYbC3ljPzRJ3qcMR2wmYUYIGlNnuK9vQJsD1w1vCmOeoL4iYx","eKItrR8dNrai2Pga8c67pZllXYyIRGoJc40N","gKUq3d3JJxlgb9g3IhNZZWqD4N1YAHkAWdrBq1SYH0ywkZEuvsTdGjuVzHDk5Bf8SR8qJEywjGYNr3cjbGsTpP28w7DWip78ET5d","C1U3S9VjRId5hhWosLj2qAQBMT0GFKJ9n264aZBVfSbilsPCL51RGzxdv8zCztKAR0mpbxOZiyudCPchakeCwQ4Jc8tZkLjdsViKQK9Vbn2i2ikEX"], "signals": [2,12,23,35,55,34,15,41,13,45,64,61,11,48,14,53,38,59,57,1,58,28,31,40,30,56,25,32,7,62,10,49,42,22,60,6,9,21,46]},{"command": ["g0fBu3PQ0BikFy6AknFaDJzeTKze2sytMbcSb6jchmJVlXI3o","7mxkKrtwc4","zKY8gUxQ9JXNHJJFhbHVghqYdoZNGYy9c0","swPtDYJNd1Y3fNNqm1A9j4Ryls80ErRNcqiKsrXjLIsJeiitBvVbBDRmaIY2mNI9pciR3KETQM9ekqXbAh53rNwzefm6LXF88wdoY","ZPnMpbIbJM","udrthnzkzWrDGC139pfjLK0S3sanEUDvszzvppVV00xdtx19UQgzxWz06N6VIjZIzu6Wlmi1EGxUzHVVKqgIXYeaWoQc9ic","KadO9m9mtaykUEfhWx0b9JO2bN46c9kmhkVwU2f3qwyvVJ4iK5FY9Ca148coPZvJQRXg6h43X3scxzbYPauAn0AghJGs2OZk03ABsyYN3sHm7eCo2f3qzzk","3MOsdwzRoXryCLA0VzluWzPrYY"], "signals": [36,52,27,40,42,19,31,46,18,34,24,35,61,58,41,54,6,13,2,38,23,15,25,39,48,56,51,1,59,60,5,16,8,55,10,11,33]}],
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

external_processes := [
    {"command": ["fqqp3bvKpw","9nWCur79M3iun7XX3whGVGZptAunhaAF7XBHaPnNHXXAEq8","X9BFm1X1QhF2CD1VXCm4j6B4pZ8iKPd6rKaSreHQKPfBWe1O2u0rrb2qypA2TLdwVFSaHz6EnEOQBgaiI7mG6MsUk5d8kFlww3TqydRJo16j4u2uEYUR2","kYPOvYkuVlK1","XH0ijOnCsAYezeohRuNZBFx6U8lhbXtV5zgWMdMkZdd5LxGPYWq8zEoOqOFQldTdynQeX1E1taDCj1uvrpRAlYcW2j1Wjge5OoXRbtCtUNGFU5","MbAYOsgq2IhjtikeYD5qeOWY8ZeELYmwj85gX1xWvE4GAwNnPxXyipkIzXnC4UJi732DNyRvNuUfnBZIv0sO6AdrqG1AzV5M3zI9AF6Oiyhdy","AfIc5EH55DlxbiburHLwVyH0SSZewslUJGtHr8EegkRST6LYrDHvzU437SmfFUA0OOdI3YL6XU","SI3k0gLSPxkTFt1vS3CTjlwMy6nfvBk1e4vGuf1uWO41nbB7ZbAPLfoC2xQq","RAEFN78xddQ0i3CnMGTjQSelvxFheql3As7JjyZYcGbYUbbW8S45WOdWgYAgcmvdTwf6Uq3AHAP9PUySjr2NV9pWhPNQzPR4XbIUuiLimqgwGDrBnYQSVY4kU","hfrv0eNAHL"], "env_rules": [{"pattern": `PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`, "strategy": "string", "required": true}], "working_dir": "F26VZl7jlJWZ1QFnTqGRZ2gTfS6vo9ocVWm73eFxfbT7X6ayOEhmON1NUeEzDTvNgXTZk3WEniVJOkARS6WRY9e74FFXXvXnKrBQ8mrycQN", "allow_stdio_access": false},
    {"command": ["Kc0H0Gg2pCZZ1pX95ypW5fzdOWDwjeGnnWEA7CD","1VwUPkD9EjqTjZRRbCc7XlQIN4OrTnaR9KJiepl","UnwMgH2vckdlmZ74zistBzN8VdfMHtjPXn5WMz0kgsaRXBjj2OuNUJzodnBKpiGc2YRGl7lx8bg1jWEaDRKar9r1eCQfEqboSOp"], "env_rules": [{"pattern": `PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`, "strategy": "string", "required": true}], "working_dir": "BucPbHG9YiT1DbjulVnIxl4MNmnAdFuYTsO6wegnQcR", "allow_stdio_access": true},
    {"command": ["mWC9MueUkeBwphQ386vnDg2H21MQbQZ1cNNDzYVZjWAXBS2saEIUa5FW92CaoDZ9OVTFF2","eZpXQT2pHeoMtZlCJrd0AEU8296ZBZBYw2WqURF5Y","gJ5GuApWSz","BpHRDZ6EQSBO2dVCktSTbTOwZM5NFnTQ88OrH035k29VkAIDGwo1nBlA","JTbuwG69iPu1WRmEjs1U5FdwRvpuRDnkYy","cGofhTQaauSMCWoQP6OHfFJqbnqe","RwiHPYnBMgaPJkW8razKPqFIG5weAopYEJ2SeDOjknd4MRYHMiwUgNhg8gq24w8of9mWO5REIFJ7c","LSWejtLVeq5OXQMusLHg5TJA","qYzf0fyND9azCOlgS4kM1S85bxS7bO8lHr3T8wxKKuVIxPvTkmX64Fbvd","18QV0C6vr2f9TVl6yyL94sQq85hKqHbMg870cVDcz","bZ5ysvl2rO2SArZ3TloItLb5uz0BCiq","lvr8Zl6a1nKo8IfGTX5YVwqjaynGci04TwA5CbcEMS2S72zyvXcKgcf5G9HYQjnUmJIGoNUSDSwDF8pVut7RDJhPw"], "env_rules": [{"pattern": `PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`, "strategy": "string", "required": true}], "working_dir": "MYLvKRdPSfyHHZT0q9dw2UvEkdv0hO1ZNmokc7ETy3Y1ab3FbwGBOWRsN3XmQYEmj9qgc4yEQnXKbft0GX9BZg4p1TUHLNqSmERvFBr3FAyYOEj7y2mrWxyy", "allow_stdio_access": true},
    {"command": ["uBXdYEaK8R8XC3Sp93kAh1WMfJByzO77GLf24v7F6lhXhLoyuk24DZV0da2KcsTSnMKSwSpRzFuSF6c6tLGeplp9L00aCPT6LRzh9jiW86jt","Ep4L5yuDT3ZVU8SYgR3NXJYwbd3nDK0b8hvCf1IXjG6lLgQQWRdoHrtUnS83qqcPPcu7T0dgOG3AyJreTrooPCDaUcH1QKJ0pLS9W4UbsPQc9ZPSU","mkXFfARyGtZSJ6qvuCxsKihK0EvfFt6z7yvBjskidTXtK9h08SP4","ceps33zAxKIcVmoh6gguPTi69","GTwuTlw8jsmpVNY5VJy5LvALQv7N5Ep","IP1is1Nbeq1QvccaXr9MUqKawBCXmHWNHAwafpFGdxtdrOvZnOSpDJsMiKBUpkDZ","3tcv18nvkJD8DDFKHVXB3l3cy1nQdDNTBpXpGQK2qILQ","VpMN9jaUad","nGcrZarLosdQoP07WvHVksMSXr2ugv","39pTdDwYgtT8FtvzUVydjnS7JlBhnhmuuT0A0X2nTo7zp7iPRHPDELn22bMEifz9vttYp3gIvibYGcLUdGj","OwVRyct8KBw1OEXMEMgpuHm1fITqV7gscrNUt1hMmhtMLb50CX5UnVijc1hvNAb2jJkR"], "env_rules": [{"pattern": `PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`, "strategy": "string", "required": true}], "working_dir": "TkHthN4mQZwZmQ3AC9jnHwBDC43P6FUf3Sjo9Z0bnRS", "allow_stdio_access": false},
    {"command": ["yUgy8i1hzfn1SfKwzUpcZv08ppHcwM9PgY1VrH2qj","UQoUgyR2Gjz54z1pPkkHnqduZXL1XHpjxdQvtiC8L2VF3E34Uaqxt2","ILgc1ALHTH5PiZ1iYJDmQ3NayR1tETz2bzCSbG92nlG4D3uoXvCV98wp75mPqjhXjnQz3wULo6UTnlscOs6hIB"], "env_rules": [{"pattern": `PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`, "strategy": "string", "required": true}], "working_dir": "PVvOGc8Z6b6Z0AnC", "allow_stdio_access": false},
    {"command": ["0oLSbqlTknCIhefZlR2MetCcoqXoDCfwqvuIXLZmWWlyBSER3RC8hjXyQuLqCfZ0K9cBTOwpOfTrIp5UVQgUf7DynJU2oGjizlKF5vnto4Nn9GX2Eip0TVzwZZh","SfWnelArRxh15vaPtsdM3BgtxOR1VRat3CCLetw5A2LFfTU2HZjZb3v50DeK1VFQVOeoSN6oWBOWBH465QkcdhQu2xgnI716gwhB26KZufwwh2HDvq","jqTR2fvR1zZRycdf7ed83EpLxYgnUyydxMSGWJA931Zg40urTEbi0GWzbDHO62StT6RKNoKYw9cByUs6jNLLS7OgbLoK0OsyVuPgg5NCUH","ry5wryfbu7Spshp6ufe3OqCgjkfAxZqS7IMszvBt0vAqTOyT2D7GYCxHPZf4PIKJXBR"], "env_rules": [{"pattern": `PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`, "strategy": "string", "required": true}], "working_dir": "cP30JQztuz97hOGAfbM1h8VUDzzMMgMDoHPyCFSSV7MEWBPyaUH1mqS5kwfT81LvKHunTH19lR7ViuaDVwG", "allow_stdio_access": true},
    {"command": ["U46KCMeb2lMoVRUarRnbP5dpTJH1","SxfP25CRSZI4VDguwafStaaJNCH2OAiqbELIQNJAO8L309BajWtpa3vixhwL7aewB8mCd7LypjqFxc","YGjq3LWO4T2MjLzfyoh9ta","s6DmOx6aatGVwzCz7wCAhtLr0tQMdH06cCNGD2hmiBkebZ32PsXR1gYGqPANBlHGjhVvBDuGzSQNtd6lSeVSBc7B207zew","XfurkNnuxsO9sXs9qfU7sD6sdDciuHGUueFzXQjV7CglldRy1jw1o1CxdJhBZUbzvG1b9pVQAD8mZY6MDSXVekPVs4CIuktBb1d5vr7PtYkshBQ","OHcQowz8eS0wnk46GO4Ivbmye25OTQOCmWhjOlRaa8bEZ0mKlz1CHpKjaYXPiqK3MJpKJmnJHYML3GPcJE295kM03OTQ79iJk2VP5LSXBrmvWuB5ad","RkEgZVc27X73EyZIxDaYnn7wnEeQLJbW8AraLT3JgTL2RFFhz5RfBJapHz9fCuSJr2ow977rMZSY1kua","dsenVKrnj4WiVoU781tR4R7H6HAVx59NDOLTz8tiAGRg8Iz","MNGqqLgjflhD"], "env_rules": [{"pattern": `PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`, "strategy": "string", "required": true}], "working_dir": "HT9llbycO9", "allow_stdio_access": true},
    {"command": ["NHdvpnfH1Nl27jeNPxL5ejXzH2T7tHVBRyIKzg4Z2jHZedjrpk7F4jDY1ZwD0n0oPTcMA8R4SLkXqfMzvsZ2zdsQXAmG8Ir9306pzCKYdwMk","cHx4xuQGU5gQHjqYKQDJcnIJoHSs5P7iZ91sOTkVT1eGjY3BLkGMFu0QYJ9NV7iWz6LWyUwHGMjZw6D7jP6fh","ufF6sJvJ9lYPT9w4HE1H60JhEBeUInxP7LZozuh","Ug9zEF1noZvoHZjSRi","eLzPkVrj7D"], "env_rules": [{"pattern": `PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`, "strategy": "string", "required": true}], "working_dir": "sSxun2Crz7cVF3ku7gVwDBjrBC", "allow_stdio_access": false},
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
