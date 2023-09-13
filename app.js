import 'dotenv/config';
import express from "express";
import mongoose from "mongoose";
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import findOrCreate from 'mongoose-findorcreate';
import session from "express-session";
import passport from "passport";
import passportLocalMongoose from "passport-local-mongoose";
// import bcrypt from "bcrypt";
// const saltRounds = 10;
// import md5 from "md5";
// import encrypt from "mongoose-encryption";

mongoose.connect('mongodb://127.0.0.1:27017/userDB');

const app= express();
const port = 3000;

app.use(express.urlencoded({extended:true}));
app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(session({
    secret:"our little secret",
    resave: false,
    saveUninitialized: true,
}));
app.use(passport.initialize());
app.use(passport.session());

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId:String,
    secret:String
});
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
// userSchema.plugin(encrypt, {secret: process.env.SECRET , encryptedFields: ["password"] });
const User= mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done){
    done(null, user.id);
});
passport.deserializeUser(function(id, cb){
    User.findById(id).then(()=>{
        return cb(null, id);
    });
}); 

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/",(req,res)=>{
    res.render("home");
});
app.get("/auth/google",
  passport.authenticate('google', { scope: ["profile"] }));

app.get("/auth/google/secrets", 
  passport.authenticate('google', { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
});

  
app.get("/login",(req,res)=>{
    res.render("login");
});
app.get("/register",(req,res)=>{
    res.render("register");
});
app.get("/secrets",(req,res)=>{
    User.find({"secret":{$ne:null}}).then((found)=>{
        if(found){
            res.render("secrets",{u:found});
        }
    }).catch((err)=>{
        console.log(err);
    });
});
app.get("/submit",(req,res)=>{
    if(req.isAuthenticated()){
        res.render("submit");
    }
    else{
        res.redirect("/login");
    } 
});
app.post("/submit",(req,res)=>{
    const newsecret=req.body.secret;
    console.log(req.user);

    User.findById(req.user.toString() ).then((found)=>{
        if(found){
            found.secret=newsecret;
            found.save().then(()=>{
                res.redirect("/secrets");
            })}
    }).catch((err)=>{
        console.log(fffffff);
    });
});

app.get("/logout",(req,res)=>{
    req.logout(function(err) {
        if (err) { return next(err); }});
    res.redirect("/");
});

app.post("/register",(req,res)=>{
    // bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
    //     // Store hash in your password DB.
        
    //     const newUser= new User({
    //         email: req.body.username,
    //     //     password: md5(req.body.password)
    //         password: hash
    //     });
    //     newUser.save().then(()=>{
    //         res.render("secrets");
    //     }).catch((err)=>{
    //         console.log(err);
    //     });
    // });
    User.register({username:req.body.username, active: false}, req.body.password, function(err, user) {
        if (err) {
            console.log(err);
            res.redirect("/register");

        } else {
            passport.authenticate("local")(req,res, function(){
                res.redirect("/secrets");
            });
        }
      
});
});

app.post("/login",(req,res)=>{
    // const username= req.body.username;
    // // const password=md5(req.body.password);
    // const password=req.body.password;
    // User.findOne({email: username}).then((found)=>{
    //     if(found){
    //         bcrypt.compare(password,found.password, function(err, result) {
    //             if(result == true){
    //                 res.render("secrets");
    //             }
    //             else{
    //                 res.send("incorrect password");
    //             }
    //         });
    //     }
    // }).catch((err)=>{
    //     console.log(err);
    // });
    const user=new User({
        username:req.body.username,
        password:req.body.password
    });
    req.login(user,(err)=>{
        if (err) {
            console.log(err);

        } else {
            passport.authenticate("local")(req,res, function(){
                res.redirect("/secrets");
            });
        }
    })
});

app.listen(port,()=>{
    console.log("Server has started at port 3000");
});