const path = require("node:path");
const { Pool } = require("pg");
const express = require("express");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require("bcryptjs");

const pool = new Pool({
  host : "localhost",
  user : "abhi",
  database : "auth",
  password : "abcd",
  port : 5432
});

const app = express();
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");

app.use(session({ secret: "cats", resave: false, saveUninitialized: false }));
app.use(passport.session());
app.use(express.urlencoded({ extended: false }));

// app.get("/", (req, res) => res.render("index"));
app.get("/sign-up", (req,res)=>{
    res.render("sign-up-form");
})

app.get("/log-out",(req,res, next)=>{
    req.logout((err) => {
        if ( err ){
            return next(err);
        }
        res.redirect("/");
    })
    
})

app.post("/sign-up", async(req,res,next)=>{
    try{
        const hashedpwd = await bcrypt.hash(req.body.password, 10);
        await pool.query("Insert into users ( username, password) values ($1, $2)",
            [
                req.body.username,
                hashedpwd,
            ]
        );
        res.redirect("/");
    }
    catch(err){
        console.log(err);
        return next(err);
    }
});


app.post("/log-in",
    passport.authenticate("local", {
        successRedirect : "/",
        failureRedirect : "/"
    })
)

app.get("/", ( req,res) =>{
    res.render("index", {user: req.user});
})


passport.use(
    new LocalStrategy(async ( username, password, done) =>{
        try{
            const {rows} = await pool.query("SELECT * FROM users where username = $1", [username]);
            const user = rows[0];

            if (!user){
                return done(null, false, {message: "incorrect username"});
            }

            const match = bcrypt.compare(password, user.password);
            if ( !match ){
                return done(null, false, {message: "Incorrect password"});
            }
            
            return done(null, user);
        }
        catch(err){
            return done(err);
        }
    })
)

passport.serializeUser((user,done)=>{
    done(null, user.id);
})


passport.deserializeUser(async(id,done) => {
    try{
        const {rows} = await pool.query("SELECT * FROM users WHERE id = $1", [id]);
        const user = rows[0];

        done(null,user);
    }
    catch(err){
        done(err);
    }
})



app.listen(3000, (error) => {
  if (error) {
    throw error;
  }
  console.log("app listening on port 3000!");
});