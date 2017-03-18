
[IPIP.NET](https://www.ipip.net/)

## Example result

IP in URI

```shell
curl localhost:9527/114.114.114.114
114DNS  114DNS          %
```

Client IP

```shell
curl localhost:9527
本机地址        本机地址                %
```

## Example config

```nginx
server {
    listen 9527;
    server_name _;
    location / {
        ipip_file /path/to/ipip_db.dat;
    }
}
```
