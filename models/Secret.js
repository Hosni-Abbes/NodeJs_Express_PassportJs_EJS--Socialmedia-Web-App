//Require mongoose
const mongoose = require("mongoose");


//Create Secret Schema
const secretSchema = new mongoose.Schema(
  {
    secret:{
      type:String,
      required:true
    },
    bgcolor:{
      type:String,
      default:"46244c"
    },
    likes:{
      type:Number,
      default:0
    }
  },
  {timestamps: true}
);


//Export Secret Model
module.exports = mongoose.model("Secret", secretSchema);