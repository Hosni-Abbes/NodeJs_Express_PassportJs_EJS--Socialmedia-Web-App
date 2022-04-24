//Require express router
const router = require("express").Router();

//Require Secret Model
const Secret = require("../models/Secret");


//Create Routes
//Get home page 
router.get("/", (req, res)=>{
  if(req.isAuthenticated()){
    res.redirect("/secrets");
  }else{
    res.render("home");
  }
});

//Get Register page 
router.get("/register", (req, res)=>{
  if(req.isAuthenticated()){
    res.redirect("/secrets");
  }else{
    res.render("register");
  }
});

//Get Login page 
router.get("/login", (req, res)=>{
  if(req.isAuthenticated()){
    res.redirect("/secrets");
  }else{
    res.render("login");
  }
});

//Get Secrets page 
router.get("/secrets", async (req, res)=>{
  try{
    const allSecrets = await Secret.find();
    res.render("secrets", {allSecrets, isAuth:req.isAuthenticated()});
  }catch(err){
    res.send(err);
  }
});

//Get Submit page
router.get("/submit", (req, res)=>{
  if(req.isAuthenticated()){
    res.render("submit");
  }else{
    res.redirect("/login");
  }
});


//Submit Secret to database
router.post("/submit", async (req, res)=>{
  try{
    const secret = new Secret({
      secret: req.body.secret,
      bgcolor: req.body.bgcolor.substring(1)
    });
    const saveSecret = secret.save();
    //if post request failed
    !saveSecret && res.redirect("/submit");
    //if secret saved to database
    res.redirect("/secrets");

  }catch(err){
    res.send(err);
  }
});


//Like Secret
router.post("/secrets/like", async (req, res)=>{
  try{
    //find the post to like
    const findSecret = await Secret.findById(req.body.likesBtn);
    //update Likes
    const updateSecretLikes = await findSecret.updateOne({likes: findSecret.likes+1});
    //redirect to secrets page
    res.redirect("/secrets");

  }catch(err){
    res.send(err);
  }
})


//Export router
module.exports = router;