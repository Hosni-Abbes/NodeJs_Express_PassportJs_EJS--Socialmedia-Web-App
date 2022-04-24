//Require mongoose, assport-local-mongoose, mongoose-findorcreate
const mongoose = require("mongoose");
const passportLocalMongoose = require("passport-local-mongoose");
const findOrCreate = require("mongoose-findorcreate");


//Create User Schema
const userSchema = new mongoose.Schema({
  username:{
    type:String,
    unique:true,
    trim:true,
    lowercase:true,
    validate:{
      validator: function(email){
        return /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/.test(email);
      },
      message: "Please enter a valid email."
    }
  },
  password:{
    type:String,
    trim:true,
    min:6
  },
  googleId:{
    type:String
  },
  facebookId:{
    type:String
  }
});


//Add passportLocalMongoose Plugin to hash and salt user password
userSchema.plugin(passportLocalMongoose);

//Add findOrCreate mongoose Plugin
userSchema.plugin(findOrCreate);


//Export User Model
module.exports = mongoose.model("User", userSchema);