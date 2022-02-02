const express = require("express");
const fs = require("fs");
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const saltRounds = 10;
const app = express();


// It return all the users except loggein user
app.get("/users" ,(req,res)=>{
    fs.readFile("data.json" , "utf8", (error, data) =>{
        if(error){
            res.send("Something went wrong");
        }
        else{
            let token = req.headers.token.split(' ')[1]
            var decoded = jwt.verify(token, 'thisismystrongsecretkey');

            const d = JSON.parse(data);
            const ind = d.findIndex(p => p.Email == decoded.Email);
            d.splice(ind, 1);
            for(let i=0; i<d.length; i++){
                delete d[i].Password;
            }
            return res.send(d);       
        }
    })
})

app.use(express.json())

// It is used to update the information
app.put("/updatedetail", (req,res)=>{
    
    fs.readFile("data.json", "utf8", (error, data) =>{
        if(error){
            res.send("Something went wrong");
        }
        else{
            let token = req.headers.token.split(' ')[1]
            var decoded = jwt.verify(token, 'thisismystrongsecretkey');
            const d = JSON.parse(data);
            const ind = d.findIndex(p => p.Email == decoded.Email);
            var datas = d.splice(ind, 1);
            const keyss =  Object.keys(req.body)
            for(let i=0; i<keyss.length;i++){
                if (keyss[i] == "Name"){
                    datas[0].Name = req.body.Name;
                }
                else if (keyss[i] == "Mobile"){
                    datas[0].Mobile = req.body.Mobile;
                }
                else if (keyss[i] == "ProfilePicture"){
                    datas[0].Mobile = req.body.ProfilePic;
                }
            }
            d[ind] = datas[0];
            const d1 = JSON.stringify(d);
            fs.writeFile("data.json", d1, error=>{
                if(error){
                    return res.send("Something went wrong");
                }
                else{
                    res.send("Information is successfully added");
                }
            })
        }
    })
})


// It is used to update the password
app.put("/updatepass", (req,res)=>{
    
    fs.readFile("data.json", "utf8", (error, data) =>{
        if(error){
            res.send("Something went wrong");
        }
        else{
            let token = req.headers.token.split(' ')[1]
            var decoded = jwt.verify(token, 'thisismystrongsecretkey');
            const d = JSON.parse(data);
            const ind = d.findIndex(p => p.Email == decoded.Email);
            var datas = d.splice(ind, 1);

            if (bcrypt.compareSync(req.body.CurPass, datas[0].Password )  && req.body.NewPass == req.body.ConfirmPass && req.body.NewPass.length >=7) {
                const hash = bcrypt.hashSync(req.body.NewPass, saltRounds);
                datas[0].Password = hash;
                d[ind] = datas[0];
                const d1 = JSON.stringify(d);
                fs.writeFile("data.json", d1, error=>{
                    if(error){
                        return res.send("Something went wrong");
                    }
                    else{
                        return res.send("Password Changed Successfully");
                        }
                    }) 
                }
            else{
                return res.send("Something went wrong");   
                }
    }})});




// It return details of logged in user
app.get("/mydetail", (req,res)=>{
    fs.readFile("data.json", "utf8", (error, data) =>{
        if(error){
            res.send("Something went wrong");
        }
        else{
            let token = req.headers.token.split(' ')[1]
            var decoded = jwt.verify(token, 'thisismystrongsecretkey');

            const d = JSON.parse(data);
            const ind = d.findIndex(p => p.Email == decoded.Email);
            var me = d.splice(ind, 1);
            return res.send(me);       
        }
    })
})


// It is used to save the user.
app.post("/register", (req,res) =>{
    fs.readFile("data.json", "utf8", (error, data) =>{
    if(error){
        return res.send("Something went wrong");
    }
    else{
        if (data.length <1){
            if (req.body.Password.length >=7){

                const hash = bcrypt.hashSync(req.body.Password, saltRounds);
                req.body.Password = hash
                console.log("Inter")
                const d1 = JSON.stringify([req.body]);
                console.log(d1);
                fs.writeFile("data.json", d1, error=>{
                    if(error){
                        return res.send("Something went wrong");
                    }
                    else{
                        return res.send({Message:"User Registered Successfully"});
                    }
                })
            }
            

        }

        else{
            const d = JSON.parse(data); 
            
            if (req.body.Password.length >=7){

                const hash = bcrypt.hashSync(req.body.Password, saltRounds);
                req.body.Password = hash
                d[d.length] = req.body;
                const d1 = JSON.stringify(d);
                fs.writeFile("data.json", d1, error=>{
                    if(error){
                        return res.send("Something went wrong");
                    }
                    else{
                        return res.send({Message:"User Registered Successfully"});
                    }
                })
            }
            else{
                return res.send("Password Should be greater than 7 characters");
            }
        }
    }
})
});


// It is used to login the user
app.post("/login" ,(req,res)=>{
    // console.log(req.body)
    fs.readFile("data.json", "utf8", (error, data) =>{
        if(error){
            res.send("Something went wrong");
        }
        else{
            const d = JSON.parse(data); 
            for(let i=0; i<d.length; i++){
                if (d[i].Email === req.body.Email && bcrypt.compareSync(req.body.Password, d[i].Password ) )
                {    
                    
                    
                    let token = jwt.sign( {Email:req.body.Email} , "thisismystrongsecretkey", { expiresIn:"10h"})
                    console.log(token)
                    return res.send({Status: "Logged in", Token:token}); 
                }
                   
            }
            return res.send("Invalid Credentials"); 
        }     
} )
});

app.listen(5000);