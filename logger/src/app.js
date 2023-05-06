const express = require("express");
const morgan = require("morgan");

const PORT = parseInt(process.env.PORT) || 8000;
const HOST = process.env.HOST || "0.0.0.0";
const FLAG1 = process.env.FLAG1
const FLAG2 = process.env.FLAG2
const creds = {
    "admin": {
        "password": process.env.ADMINPW,
        "is_admin": true
    }
};

const logs = [];

const app = express();
app.use(morgan());

const isObject = (obj) => obj && obj.constructor && obj.constructor === Object;

// Recursive merge
const merge = (dst, src)=>{
    for(key in src) {
        if(isObject(src[key]) && isObject(dst[key])) {
            merge(dst[key], src[key]);
        } else {
            dst[key] = src[key];
        }
    }
};

app.use((req, res, next)=>{
    if(logs.length > 10) {
        logs = []
    }
    next();
});

app.get("/", (req, res)=>{
    res.json({result: true});
});

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

app.listen(PORT, HOST, ()=>{
    console.log(`Server running on port ${PORT}.`);
});